//! The supervisor's Prometheus textfile. The unit has no network, so it cannot serve
//! /metrics; it writes this file for node exporter's textfile collector instead.
//!
//! Counters are rebuilt from the two logs, so they carry on across restarts and a rate()
//! over them is right from the first scrape after one. The ones marked "since start" are
//! the exception: nothing in the logs says how often a worker waited for disk.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::sched::{Sched, index, rate};
use crate::state::{ChosenBy, Outcome, State, TargetStats};
use crate::status::{DEFAULT_QUANTUM_S, features_per_hour};
use crate::targets::{Target, TargetsFile};
use crate::util::{parse_rfc3339, unix_now};

/// How often the file is rewritten when nothing else prompts it, so its timestamp shows
/// the supervisor is alive even while every target is blocked.
pub const WRITE_EVERY: Duration = Duration::from_secs(60);
/// A broken metrics file would otherwise print a line every minute.
const NOTE_EVERY: Duration = Duration::from_secs(600);

// Listed here, not derived from the enums, so a series exists for every value from the
// first sample; the tests fail if a variant is added and missing.
const OUTCOMES: [Outcome; 6] = [Outcome::Ok, Outcome::Crash, Outcome::Timeout, Outcome::Oom, Outcome::Leak, Outcome::Error];
const CHOSEN: [ChosenBy; 3] = [ChosenBy::Cold, ChosenBy::Starved, ChosenBy::Index];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snapshot {
    pub version: String,
    /// `None` where the process is not the supervisor (`status --prometheus`).
    pub start_time: Option<f64>,
    pub written: f64,
    pub workers: u64,
    pub workers_busy: u64,
    pub quantum_s: f64,
    pub quanta: u64,
    pub seconds: f64,
    pub execs: u64,
    pub damaged_lines: u64,
    pub disk_waits: u64,
    pub targets: Vec<TargetMetrics>,
    pub findings: Vec<FindingMetrics>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TargetMetrics {
    pub id: String,
    pub rank: u64,
    pub rate: f64,
    pub index: f64,
    pub quanta: u64,
    pub seconds: f64,
    pub execs: u64,
    pub features: Option<u64>,
    pub exec_per_second: Option<f64>,
    pub features_per_hour: Option<f64>,
    pub share: f64,
    pub corpus_files: Option<u64>,
    pub last_quantum_end: Option<f64>,
    pub open_findings: u64,
    /// `None` when the binary's identity is not known: the logs alone cannot say.
    pub blocked: Option<bool>,
    pub faulted: bool,
    pub faults_total: u64,
    pub outcomes: BTreeMap<&'static str, u64>,
    pub chosen: BTreeMap<&'static str, u64>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FindingMetrics {
    pub target: String,
    pub kind: String,
    pub key: String,
    pub times_seen: u64,
    /// `None` when the recorded time does not parse.
    pub first_seen: Option<f64>,
}

/// Everything the logs can say. `quantum_s` is the configured one when the supervisor
/// asks; without it the latest recorded one, as `status` does. `blocked` is by target id.
/// The fields that live only in a running process (workers, disk waits, start time, the
/// write time) are left for the caller.
pub fn collect(state: &State, targets: Option<&[Target]>, quantum_s: Option<f64>, blocked: &BTreeMap<String, bool>) -> Snapshot {
    let q = quantum_s.unwrap_or_else(|| {
        state.stats.values().max_by_key(|s| s.last_seq).map(|s| s.last_quantum_s).filter(|q| *q > 0.0).unwrap_or(DEFAULT_QUANTUM_S)
    });
    // As in `status`: every listed target, then any that only the logs know, so the
    // per-target counters still add up to the totals after a target leaves the bundle.
    let mut ids: Vec<(String, u64)> = targets.unwrap_or_default().iter().map(|t| (t.id.clone(), t.rank)).collect();
    let known: BTreeSet<String> = ids.iter().map(|t| t.0.clone()).collect();
    ids.extend(state.stats.iter().filter(|(k, _)| !known.contains(*k)).map(|(k, s)| (k.clone(), s.last_rank)));
    let empty = TargetStats::default();
    let rows = ids
        .into_iter()
        .map(|(id, rank)| {
            let st = state.stats.get(&id).unwrap_or(&empty);
            let r = rate(&st.hist, q);
            TargetMetrics {
                rank,
                rate: r,
                index: index(rank, r),
                quanta: st.quanta,
                seconds: st.seconds,
                execs: st.execs,
                features: st.last_ft,
                exec_per_second: st.last_exec_per_sec,
                features_per_hour: features_per_hour(st),
                share: if state.seconds > 0.0 { st.seconds / state.seconds } else { 0.0 },
                corpus_files: st.last_corpus_files,
                last_quantum_end: st.last_end,
                open_findings: state.findings.open_for(&id) as u64,
                blocked: blocked.get(&id).copied(),
                // The scheduler's to know; Sched::snapshot fills them in.
                faulted: false,
                faults_total: 0,
                outcomes: st.outcomes.clone(),
                chosen: st.chosen.clone(),
                id,
            }
        })
        .collect();
    let findings = state
        .findings
        .by_key
        .values()
        .map(|f| FindingMetrics {
            target: f.target.clone(),
            kind: f.kind.clone(),
            key: f.key.clone(),
            times_seen: f.times_seen,
            first_seen: parse_rfc3339(&f.first_seen),
        })
        .collect();
    Snapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        quantum_s: q,
        quanta: state.quanta,
        seconds: state.seconds,
        execs: state.execs,
        damaged_lines: state.damaged_lines,
        targets: rows,
        findings,
        ..Snapshot::default()
    }
}

/// What `keel-judge status --prometheus` prints: the logs alone, so no worker is busy and
/// nothing is known of faults, disk waits or whether a binary has changed.
pub fn from_logs(state: &State, targets: Option<&TargetsFile>) -> Snapshot {
    let mut s = collect(state, targets.map(|t| t.targets.as_slice()), None, &BTreeMap::new());
    s.written = unix_now();
    s
}

/// A label value in the exposition format's quoting; `expect` writes series the same way.
pub(crate) fn escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn num(x: f64) -> String {
    if x.is_nan() {
        "NaN".into()
    } else if x.is_infinite() {
        if x > 0.0 { "+Inf".into() } else { "-Inf".into() }
    } else {
        x.to_string()
    }
}

#[derive(Default)]
struct Out(String);

impl Out {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], v: f64) {
        self.0.push_str(name);
        if !labels.is_empty() {
            let parts: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{}\"", escape(v))).collect();
            let _ = write!(self.0, "{{{}}}", parts.join(","));
        }
        let _ = writeln!(self.0, " {}", num(v));
    }

    fn one(&mut self, name: &str, kind: &str, help: &str, v: Option<f64>) {
        self.family(name, kind, help);
        if let Some(v) = v {
            self.sample(name, &[], v);
        }
    }

    /// A family with one series per target, for the targets `f` has a value for.
    fn per_target(&mut self, ts: &[TargetMetrics], name: &str, kind: &str, help: &str, f: impl Fn(&TargetMetrics) -> Option<f64>) {
        self.family(name, kind, help);
        for t in ts {
            if let Some(v) = f(t) {
                self.sample(name, &[("target", &t.id)], v);
            }
        }
    }
}

pub fn render(m: &Snapshot) -> String {
    let mut o = Out::default();
    o.family("keel_judge_info", "gauge", "Build information about the running keel-judge; the value is always 1.");
    o.sample("keel_judge_info", &[("version", &m.version)], 1.0);
    o.one("keel_judge_start_time_seconds", "gauge", "Unix time at which this keel-judge process started.", m.start_time);
    o.one("keel_judge_metrics_written_timestamp_seconds", "gauge", "Unix time at which this file was written; it stops advancing if the supervisor does.", Some(m.written));
    o.one("keel_judge_workers", "gauge", "Configured number of workers.", Some(m.workers as f64));
    o.one("keel_judge_workers_busy", "gauge", "Workers inside a quantum now.", Some(m.workers_busy as f64));
    o.one("keel_judge_quantum_seconds", "gauge", "Configured length of one quantum in seconds.", Some(m.quantum_s));
    o.one("keel_judge_quanta_total", "counter", "Quanta recorded in the state log, over all restarts.", Some(m.quanta as f64));
    o.one("keel_judge_fuzz_seconds_total", "counter", "Seconds of fuzzing recorded in the state log, over all restarts.", Some(m.seconds));
    o.one("keel_judge_execs_total", "counter", "Executions recorded in the state log, over all restarts.", Some(m.execs as f64));
    o.one("keel_judge_state_damaged_lines", "gauge", "State log lines dropped when this process started.", Some(m.damaged_lines as f64));
    o.one("keel_judge_disk_waits_total", "counter", "Times a worker waited for free disk space, since this process started.", Some(m.disk_waits as f64));

    let ts = &m.targets;
    o.per_target(ts, "keel_judge_target_rank", "gauge", "Rank of the target: complexity times gap times blast from the fuzz bundle.", |t| Some(t.rank as f64));
    o.per_target(ts, "keel_judge_target_rate", "gauge", "Estimated new coverage features per second, as the scheduler computes it.", |t| Some(t.rate));
    o.per_target(ts, "keel_judge_target_index", "gauge", "Scheduling index: rank times rate.", |t| Some(t.index));
    o.per_target(ts, "keel_judge_target_quanta_total", "counter", "Quanta recorded for the target, over all restarts.", |t| Some(t.quanta as f64));
    o.per_target(ts, "keel_judge_target_fuzz_seconds_total", "counter", "Seconds of fuzzing recorded for the target, over all restarts.", |t| Some(t.seconds));
    o.per_target(ts, "keel_judge_target_execs_total", "counter", "Executions recorded for the target, over all restarts.", |t| Some(t.execs as f64));
    o.per_target(ts, "keel_judge_target_features", "gauge", "Coverage features at the end of the target's newest quantum.", |t| t.features.map(|v| v as f64));
    o.per_target(ts, "keel_judge_target_exec_per_second", "gauge", "Executions per second in the target's newest quantum.", |t| t.exec_per_second);
    o.per_target(ts, "keel_judge_target_features_per_hour", "gauge", "New features per hour over the target's last four quanta.", |t| t.features_per_hour);
    o.per_target(ts, "keel_judge_target_share", "gauge", "Fraction of all recorded fuzz seconds spent on the target.", |t| Some(t.share));
    o.per_target(ts, "keel_judge_target_corpus_files", "gauge", "Files in the target's corpus after its newest quantum.", |t| t.corpus_files.map(|v| v as f64));
    o.per_target(ts, "keel_judge_target_last_quantum_timestamp_seconds", "gauge", "Unix time at which the target's newest quantum ended.", |t| t.last_quantum_end);
    o.per_target(ts, "keel_judge_target_open_findings", "gauge", "Distinct findings recorded for the target; nothing closes one.", |t| Some(t.open_findings as f64));
    o.per_target(ts, "keel_judge_target_blocked", "gauge", "1 while a finding is recorded against the target's current binary, so it is not scheduled.", |t| t.blocked.map(|b| f64::from(u8::from(b))));
    o.per_target(ts, "keel_judge_target_faulted", "gauge", "1 while the target is backed off: it could not be run, or its last quantum ended in error.", |t| Some(f64::from(u8::from(t.faulted))));
    o.per_target(ts, "keel_judge_target_faults_total", "counter", "Faults of the target (could not be run, or a quantum ended in error), since this process started.", |t| Some(t.faults_total as f64));

    // Every value for every target that has run, zeros too, so rate() works from the first sample.
    o.family("keel_judge_target_outcomes_total", "counter", "Quanta of the target by how they ended, over all restarts.");
    for t in ts.iter().filter(|t| t.quanta > 0) {
        for v in OUTCOMES {
            o.sample("keel_judge_target_outcomes_total", &[("target", &t.id), ("outcome", v.as_str())], t.outcomes.get(v.as_str()).copied().unwrap_or(0) as f64);
        }
    }
    o.family("keel_judge_target_chosen_total", "counter", "Quanta of the target by why it was chosen, over all restarts.");
    for t in ts.iter().filter(|t| t.quanta > 0) {
        for v in CHOSEN {
            o.sample("keel_judge_target_chosen_total", &[("target", &t.id), ("chosen_by", v.as_str())], t.chosen.get(v.as_str()).copied().unwrap_or(0) as f64);
        }
    }

    let mut kinds: BTreeMap<(&str, &str), (u64, u64)> = BTreeMap::new();
    for f in &m.findings {
        let e = kinds.entry((f.target.as_str(), f.kind.as_str())).or_default();
        e.0 += 1;
        e.1 += f.times_seen;
    }
    o.family("keel_judge_findings", "gauge", "Distinct findings by target and kind.");
    for ((target, kind), (n, _)) in &kinds {
        o.sample("keel_judge_findings", &[("target", target), ("kind", kind)], *n as f64);
    }
    o.family("keel_judge_finding_sightings_total", "counter", "Times findings were seen, by target and kind, repeats included.");
    for ((target, kind), (_, seen)) in &kinds {
        o.sample("keel_judge_finding_sightings_total", &[("target", target), ("kind", kind)], *seen as f64);
    }
    o.family("keel_judge_finding_first_seen_timestamp_seconds", "gauge", "Unix time at which each distinct finding was first seen.");
    for f in &m.findings {
        if let Some(t) = f.first_seen {
            o.sample("keel_judge_finding_first_seen_timestamp_seconds", &[("target", &f.target), ("kind", &f.kind), ("key", &f.key)], t);
        }
    }
    let unparsed = m.findings.iter().filter(|f| f.first_seen.is_none()).count();
    o.one("keel_judge_findings_unparsed_time", "gauge", "Findings left out of the first-seen series because their recorded time does not parse.", Some(unparsed as f64));
    o.0
}

/// Writes `text` to `path` so a reader sees the old file or the new one, never half of
/// either: a sibling temporary file, fsynced, then renamed over.
pub fn write_atomic(path: &Path, text: &str) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let write = || -> std::io::Result<()> {
        let mut f = File::create(&tmp)?;
        // The unit's umask makes new files 0640, which node exporter's user cannot read.
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write()
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
        .with_context(|| {
            format!(
                "cannot write {} (the metrics file, through {}); make its directory writable by this user and on one filesystem, or fix --metrics",
                path.display(),
                tmp.display()
            )
        })
}

/// Owns the metrics file of a running supervisor. One lock covers the snapshot and the
/// write, so an older snapshot cannot land over a newer one and the threads that write
/// (every worker, and the timer) cannot trample one temporary file.
pub struct Publisher {
    path: PathBuf,
    workers: u64,
    start_time: f64,
    disk_waits: AtomicU64,
    last_note: Mutex<Option<Instant>>,
}

impl Publisher {
    pub fn new(path: PathBuf, workers: usize) -> Publisher {
        Publisher { path, workers: workers as u64, start_time: unix_now(), disk_waits: AtomicU64::new(0), last_note: Mutex::new(None) }
    }

    pub fn disk_wait(&self) {
        self.disk_waits.fetch_add(1, Ordering::Relaxed);
    }

    /// Never fails the supervisor: a stale metrics file is a lesser harm than a stopped fuzzer.
    pub fn publish(&self, sched: &Mutex<Sched>) {
        let mut last_note = self.last_note.lock().unwrap();
        let mut snap = sched.lock().unwrap().snapshot();
        snap.workers = self.workers;
        snap.start_time = Some(self.start_time);
        snap.disk_waits = self.disk_waits.load(Ordering::Relaxed);
        snap.written = unix_now();
        if let Err(e) = write_atomic(&self.path, &render(&snap))
            && last_note.is_none_or(|t| t.elapsed() >= NOTE_EVERY)
        {
            eprintln!("keel-judge: {e:#}; the metrics stay stale until then, and this note repeats at most every {} minutes", NOTE_EVERY.as_secs() / 60);
            *last_note = Some(Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{FINDING_SCHEMA, FindingRecord, QUANTUM_SCHEMA, Quantum, StoppedBy};

    fn fixture() -> Snapshot {
        let counts = |pairs: &[(&'static str, u64)]| pairs.iter().copied().collect::<BTreeMap<_, _>>();
        Snapshot {
            version: "0.1.0".into(),
            start_time: Some(1_763_160_000.0),
            written: 1_763_164_800.5,
            workers: 2,
            workers_busy: 1,
            quantum_s: 60.0,
            quanta: 3,
            seconds: 170.5,
            execs: 12_000_000,
            damaged_lines: 0,
            disk_waits: 4,
            targets: vec![
                TargetMetrics {
                    id: "pack-decode".into(),
                    rank: 9000,
                    rate: 0.25,
                    index: 2250.0,
                    quanta: 3,
                    seconds: 170.5,
                    execs: 12_000_000,
                    features: Some(480),
                    exec_per_second: Some(70_000.5),
                    features_per_hour: Some(36.0),
                    share: 1.0,
                    corpus_files: Some(210),
                    last_quantum_end: Some(1_763_164_790.5),
                    open_findings: 2,
                    blocked: Some(true),
                    outcomes: counts(&[("ok", 2), ("crash", 1)]),
                    chosen: counts(&[("cold", 1), ("index", 2)]),
                    ..TargetMetrics::default()
                },
                TargetMetrics { id: "ref-parse".into(), rank: 600, rate: 0.015625, index: 9.375, blocked: Some(false), ..TargetMetrics::default() },
            ],
            findings: vec![
                FindingMetrics { target: "pack-decode".into(), kind: "rust-panic".into(), key: "3fa9c1".into(), times_seen: 2, first_seen: Some(1_763_164_000.25) },
                FindingMetrics { target: "pack-decode".into(), kind: "timeout".into(), key: "b07e22".into(), times_seen: 1, first_seen: None },
            ],
        }
    }

    /// Kept as a file so a reviewer reads the exposition text as a scraper gets it. Checked
    /// by eye against the metric list the dashboards are written to.
    const EXPECTED: &str = include_str!("../tests/data/metrics.prom");

    #[test]
    fn a_two_target_snapshot_renders_exactly() {
        assert_eq!(render(&fixture()), EXPECTED);
    }

    #[test]
    fn label_values_are_escaped() {
        let mut m = fixture();
        m.targets[1].id = "a\\b\"c\nd".into();
        let text = render(&m);
        assert!(text.contains(r#"keel_judge_target_rank{target="a\\b\"c\nd"} 600"#), "{text}");
        check_exposition(&text).unwrap();
        assert_eq!(escape("plain-id_1"), "plain-id_1");
    }

    #[test]
    fn every_variant_has_a_series() {
        // An exhaustive match: a new variant stops compiling here until it is listed above.
        for o in OUTCOMES {
            match o {
                Outcome::Ok | Outcome::Crash | Outcome::Timeout | Outcome::Oom | Outcome::Leak | Outcome::Error => {}
            }
        }
        for c in CHOSEN {
            match c {
                ChosenBy::Cold | ChosenBy::Starved | ChosenBy::Index => {}
            }
        }
        let names: BTreeSet<_> = OUTCOMES.iter().map(|o| o.as_str()).collect();
        assert_eq!(names.len(), 6);
        let names: BTreeSet<_> = CHOSEN.iter().map(|o| o.as_str()).collect();
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn the_output_is_exposition_format() {
        check_exposition(&render(&fixture())).unwrap();
        check_exposition(&render(&Snapshot::default())).unwrap();
        // The checker itself must refuse what it exists to catch.
        let bad = |t: &str| check_exposition(t).unwrap_err();
        assert!(bad("x 1\n").contains("before"));
        assert!(bad("# HELP x h\n# TYPE x gauge\nx one\n").contains("value"));
        assert!(bad("# HELP x h\n# TYPE x gauge\nx 1\n# HELP x h\n# TYPE x gauge\n").contains("twice"));
        assert!(bad("# HELP x h\n# TYPE x gauge\nx{a=\"b} 1\n").contains("label"));
        assert!(bad("# HELP x h\n# TYPE x counter\nx 1\n").contains("_total"));
    }

    #[test]
    fn an_unrun_target_has_no_outcome_series_and_a_run_one_has_all_six() {
        let text = render(&fixture());
        assert!(!text.contains(r#"outcomes_total{target="ref-parse""#) && !text.contains(r#"chosen_total{target="ref-parse""#));
        for o in ["ok", "crash", "timeout", "oom", "leak", "error"] {
            assert!(text.contains(&format!("keel_judge_target_outcomes_total{{target=\"pack-decode\",outcome=\"{o}\"}} ")), "{o}");
        }
    }

    #[test]
    fn collect_reads_the_logs_the_way_the_scheduler_and_status_do() {
        let mut st = State::default();
        let mk = |target: &str, seq, secs: f64, delta: u64, outcome| Quantum {
            schema: QUANTUM_SCHEMA.into(),
            target: target.into(),
            worker: 0,
            seq,
            identity: "i".into(),
            started: "2026-11-15T00:00:00.000Z".into(),
            seconds: secs,
            quantum_s: 60.0,
            chosen_by: ChosenBy::Index,
            rank: 10,
            rate: 0.1,
            index: 1.0,
            inited_s: None,
            cov: None,
            ft_inited: Some(10),
            ft: Some(10 + delta),
            delta_ft: delta,
            execs: Some(1000),
            exec_per_sec: Some(100.0),
            new_units: None,
            peak_rss_mb: None,
            corpus_files_before: 1,
            corpus_files_after: 2,
            exit: Default::default(),
            stopped_by: StoppedBy::Deadline,
            outcome,
            finding: None,
            slow_units: 0,
            log: String::new(),
        };
        st.apply_quantum(&mk("a", 1, 60.0, 6, Outcome::Ok));
        st.apply_quantum(&mk("a", 2, 30.0, 0, Outcome::Crash));
        st.apply_quantum(&mk("gone", 3, 10.0, 1, Outcome::Ok));
        let tf: TargetsFile = serde_json::from_str(
            r#"{"schema":"keel.judge.targets.v1","targets":[{"id":"a","rank":100,"argv":["x"],"corpus":"c","artifacts":"a"},{"id":"new","rank":600,"argv":["x"],"corpus":"c","artifacts":"a"}]}"#,
        )
        .unwrap();
        let blocked = BTreeMap::from([("a".to_string(), true)]);
        let s = collect(&st, Some(&tf.targets), Some(60.0), &blocked);
        assert_eq!((s.quanta, s.execs, s.workers_busy), (3, 3000, 0));
        assert!((s.seconds - 100.0).abs() < 1e-9);
        // The listed targets in file order, then the one only the logs know.
        assert_eq!(s.targets.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(), ["a", "new", "gone"]);
        let a = &s.targets[0];
        assert_eq!((a.quanta, a.rank, a.blocked, a.corpus_files), (2, 100, Some(true), Some(2)));
        assert_eq!((a.outcomes["ok"], a.outcomes["crash"], a.chosen["index"]), (1, 1, 2));
        // The same figures as the scheduler (rate), `status` (share, ft/hour).
        assert!((a.rate - rate(&st.stats["a"].hist, 60.0)).abs() < 1e-12);
        assert!((a.index - index(100, a.rate)).abs() < 1e-9);
        assert!((a.share - 0.9).abs() < 1e-9);
        assert!((a.features_per_hour.unwrap() - 6.0 / 90.0 * 3600.0).abs() < 1e-9);
        // started "2026-11-15T00:00:00.000Z" plus 30 s.
        assert_eq!(a.last_quantum_end, Some(parse_rfc3339("2026-11-15T00:00:30Z").unwrap()));
        let new = &s.targets[1];
        assert_eq!((new.quanta, new.blocked, new.features, new.corpus_files, new.share), (0, None, None, None, 0.0));
        assert!((new.rate - 1.0 / 60.0).abs() < 1e-12);
        assert_eq!(s.targets[2].rank, 10);
        check_exposition(&render(&s)).unwrap();
    }

    #[test]
    fn findings_with_an_unreadable_time_are_counted_not_dated() {
        let mut st = State::default();
        let rec = |key: &str, first: &str| FindingRecord {
            schema: FINDING_SCHEMA.into(),
            target: "t".into(),
            key: key.into(),
            kind: "rust-panic".into(),
            frames: vec![],
            source: "panic".into(),
            identity: "i".into(),
            first_seen: Some(first.into()),
            seen_again: None,
            input: None,
        };
        st.findings.apply(&rec("good", "2026-11-15T01:00:00.000Z"));
        st.findings.apply(&rec("bad", "yesterday"));
        st.findings.apply(&rec("good", "2026-11-15T02:00:00.000Z"));
        let text = render(&collect(&st, None, Some(60.0), &BTreeMap::new()));
        assert!(text.contains("keel_judge_findings_unparsed_time 1\n"), "{text}");
        assert!(text.contains("keel_judge_findings{target=\"t\",kind=\"rust-panic\"} 2\n"));
        assert!(text.contains("keel_judge_finding_sightings_total{target=\"t\",kind=\"rust-panic\"} 3\n"));
        assert!(text.contains("keel_judge_finding_first_seen_timestamp_seconds{target=\"t\",kind=\"rust-panic\",key=\"good\"} 1794704400\n"), "{text}");
        assert!(!text.contains("key=\"bad\""));
    }

    #[test]
    fn the_atomic_write_leaves_no_temporary_file_and_a_readable_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keel_judge.prom");
        write_atomic(&path, "first\n").unwrap();
        write_atomic(&path, "second\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second\n");
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, ["keel_judge.prom"]);
        // Whatever the umask, node exporter's user must be able to read it.
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);
    }

    #[test]
    fn a_failing_directory_gives_an_error_naming_the_path_and_the_fix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent/keel_judge.prom");
        let err = format!("{:#}", write_atomic(&path, "x").unwrap_err());
        assert!(err.contains(&path.display().to_string()) && err.contains("--metrics") && err.contains("writable"), "{err}");
        assert!(!path.exists());
    }

    /// The parts of the text exposition format a scraper would reject, checked by hand:
    /// `# HELP`/`# TYPE` before a family's samples, each family once and contiguous, label
    /// values quoted and escaped, a float at the end, `_total` on counters.
    fn check_exposition(text: &str) -> Result<(), String> {
        let (mut helped, mut typed, mut done) = (BTreeSet::new(), BTreeMap::new(), BTreeSet::new());
        let mut current: Option<String> = None;
        for (n, line) in text.lines().enumerate() {
            let at = |m: &str| format!("line {}: {m}: {line:?}", n + 1);
            if let Some(rest) = line.strip_prefix("# HELP ") {
                let name = rest.split(' ').next().unwrap();
                if !helped.insert(name.to_string()) {
                    return Err(at("family helped twice"));
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let (name, kind) = rest.split_once(' ').ok_or_else(|| at("TYPE without a kind"))?;
                if typed.insert(name.to_string(), kind.to_string()).is_some() {
                    return Err(at("family typed twice"));
                }
                if kind == "counter" && !name.ends_with("_total") {
                    return Err(at("counter without _total"));
                }
                if !helped.contains(name) {
                    return Err(at("TYPE before HELP"));
                }
                continue;
            }
            if line.starts_with('#') || line.is_empty() {
                return Err(at("stray comment or blank line"));
            }
            let name_end = line.find(['{', ' ']).ok_or_else(|| at("no value"))?;
            let name = &line[..name_end];
            if !(name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')) {
                return Err(at("bad metric name"));
            }
            if !typed.contains_key(name) {
                return Err(at("sample before its HELP and TYPE"));
            }
            if current.as_deref() != Some(name) {
                if let Some(prev) = current.take() {
                    done.insert(prev);
                }
                if done.contains(name) {
                    return Err(at("family appears twice"));
                }
                current = Some(name.to_string());
            }
            let mut rest = &line[name_end..];
            if let Some(body) = rest.strip_prefix('{') {
                // Bytes, since every character the format gives meaning to is ASCII.
                let b = body.as_bytes();
                let mut i = 0;
                loop {
                    let eq = body[i..].find("=\"").ok_or_else(|| at("label without =\""))? + i;
                    let label = &body[i..eq];
                    if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                        return Err(at("bad label name"));
                    }
                    i = eq + 2;
                    loop {
                        match b.get(i) {
                            None => return Err(at("unterminated label value")),
                            Some(b'"') => break,
                            Some(b'\n') => return Err(at("raw newline in label value")),
                            Some(b'\\') if matches!(b.get(i + 1), Some(b'\\' | b'"' | b'n')) => i += 2,
                            Some(b'\\') => return Err(at("bad escape in label value")),
                            Some(_) => i += 1,
                        }
                    }
                    match b.get(i + 1) {
                        Some(b',') => i += 2,
                        Some(b'}') => {
                            rest = &body[i + 2..];
                            break;
                        }
                        _ => return Err(at("label set not closed by }")),
                    }
                }
            }
            let value = rest.strip_prefix(' ').ok_or_else(|| at("no space before the value"))?;
            if value.parse::<f64>().is_err() && !matches!(value, "NaN" | "+Inf" | "-Inf") {
                return Err(at("value is not a float"));
            }
        }
        Ok(())
    }
}
