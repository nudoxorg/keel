//! The two append-only logs and the in-memory state rebuilt from them. No other file is
//! authoritative.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::util::parse_rfc3339;

pub const QUANTUM_SCHEMA: &str = "keel.judge.quantum.v1";
pub const FINDING_SCHEMA: &str = "keel.judge.finding.v1";

/// Quanta kept per target for the rate. A quantum's weight is 2^(-age/4), so beyond 64 it
/// is below 2^-16 and cannot move the estimate.
const HISTORY: usize = 64;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChosenBy {
    Cold,
    Starved,
    Index,
}

impl ChosenBy {
    pub fn as_str(self) -> &'static str {
        match self {
            ChosenBy::Cold => "cold",
            ChosenBy::Starved => "starved",
            ChosenBy::Index => "index",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StoppedBy {
    Deadline,
    Target,
    Supervisor,
    Kill,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Ok,
    Crash,
    Timeout,
    Oom,
    Leak,
    Error,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Crash => "crash",
            Outcome::Timeout => "timeout",
            Outcome::Oom => "oom",
            Outcome::Leak => "leak",
            Outcome::Error => "error",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExitInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Quantum {
    pub schema: String,
    pub target: String,
    pub worker: usize,
    /// Pick order over all quanta ever; the starve rule counts it.
    pub seq: u64,
    pub identity: String,
    pub started: String,
    pub seconds: f64,
    /// The configured quantum Q the rate was computed with, so the index can be recomputed.
    pub quantum_s: f64,
    pub chosen_by: ChosenBy,
    pub rank: u64,
    pub rate: f64,
    pub index: f64,
    pub inited_s: Option<f64>,
    pub cov: Option<u64>,
    pub ft_inited: Option<u64>,
    pub ft: Option<u64>,
    pub delta_ft: u64,
    pub execs: Option<u64>,
    pub exec_per_sec: Option<f64>,
    pub new_units: Option<u64>,
    pub peak_rss_mb: Option<u64>,
    pub corpus_files_before: u64,
    pub corpus_files_after: u64,
    pub exit: ExitInfo,
    pub stopped_by: StoppedBy,
    pub outcome: Outcome,
    pub finding: Option<String>,
    /// New `slow-unit-` artifacts: recorded here, not findings.
    #[serde(default)]
    pub slow_units: u64,
    pub log: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FindingRecord {
    pub schema: String,
    pub target: String,
    pub key: String,
    pub kind: String,
    pub frames: Vec<String>,
    pub source: String,
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_again: Option<String>,
    pub input: Option<String>,
}

/// Marks the error of a failed append to a state log. The loop treats it as fatal: a
/// record that cannot be written is one the index would never learn from, and the restart
/// rebuilds the logs. Any other error of a quantum is that target's alone.
#[derive(Debug)]
pub struct LogAppendFailed {
    pub path: PathBuf,
    /// What became of the partial line, as a clause for the message.
    pub how: String,
}

impl std::fmt::Display for LogAppendFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot append to {} (an append-only state log); {}; free space or fix the permissions under --state, then restart", self.path.display(), self.how)
    }
}

/// An append-only JSON-lines file. Every record is flushed and fsynced before the caller
/// goes on, so a crash loses at most the record being written.
pub struct Jsonl {
    file: File,
    path: PathBuf,
}

impl Jsonl {
    pub fn open(path: &Path) -> Result<Jsonl> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("cannot open {} for appending (an append-only log of the supervisor state); fix the permissions of --state", path.display()))?;
        Ok(Jsonl { file, path: path.to_path_buf() })
    }

    /// A failed append cuts the log back to its length before it. A full disk stops
    /// `write_all` midway, and the partial line would be left for the next append to bury
    /// in the middle of the file, where the next start would refuse to load it.
    pub fn append<T: Serialize>(&mut self, value: &T) -> Result<()> {
        self.append_with(value, |file, bytes| file.write_all(bytes))
    }

    fn append_with<T: Serialize>(&mut self, value: &T, write: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>) -> Result<()> {
        let mut line = serde_json::to_string(value).context("cannot serialise a record")?;
        line.push('\n');
        let failed = |how: String| LogAppendFailed { path: self.path.clone(), how };
        let before = match self.file.metadata() {
            Ok(m) => m.len(),
            Err(e) => return Err(anyhow::Error::new(e).context(failed("its length could not be read, so nothing was written".into()))),
        };
        let wrote = write(&mut self.file, line.as_bytes()).and_then(|()| self.file.flush()).and_then(|()| self.file.sync_all());
        let Err(e) = wrote else { return Ok(()) };
        let how = match self.file.set_len(before).and_then(|()| self.file.sync_all()) {
            Ok(()) => format!("the partial record was cut off at byte {before}, so the next start loads cleanly"),
            Err(cut) => format!("cutting the partial record off at byte {before} also failed ({cut}); delete everything after byte {before} of that file before restarting"),
        };
        Err(anyhow::Error::new(e).context(failed(how)))
    }
}

/// How the last line of a log ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tail {
    Clean,
    /// A complete record without its newline.
    MissingNewline,
    /// An unparseable last line (a torn write) starting at this byte offset.
    Torn(u64),
}

/// The `schema` of a line that is JSON but not a record this build reads.
fn schema_of(line: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(line).ok()?.get("schema")?.as_str().map(str::to_string)
}

/// Streams `path`, calling `f` for each record. One unparseable last line without a
/// newline is a torn write and is ignored; anything else unparseable is corruption.
pub fn read_jsonl<T: for<'de> Deserialize<'de>>(path: &Path, f: impl FnMut(T) -> Result<()>) -> Result<Tail> {
    scan_jsonl(path, None, None, f)
}

/// Like `read_jsonl`, but a line that does not parse as a record is skipped and its number
/// pushed to `damaged`, for the caller to quarantine. A line that is JSON with another
/// `schema` than `schema` is never skipped: a newer build wrote it, and dropping it would
/// lose data.
pub fn read_jsonl_lenient<T: for<'de> Deserialize<'de>>(path: &Path, schema: &str, damaged: &mut Vec<usize>, f: impl FnMut(T) -> Result<()>) -> Result<Tail> {
    scan_jsonl(path, Some(schema), Some(damaged), f)
}

fn scan_jsonl<T: for<'de> Deserialize<'de>>(
    path: &Path,
    schema: Option<&str>,
    mut damaged: Option<&mut Vec<usize>>,
    mut f: impl FnMut(T) -> Result<()>,
) -> Result<Tail> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Tail::Clean),
        Err(e) => bail!("cannot read {} (a supervisor state log): {e}; fix the permissions of --state", path.display()),
    };
    let mut r = BufReader::new(file);
    let (mut offset, mut lineno, mut buf) = (0u64, 0usize, Vec::new());
    loop {
        buf.clear();
        let n = r.read_until(b'\n', &mut buf).with_context(|| format!("cannot read {}", path.display()))?;
        if n == 0 {
            return Ok(Tail::Clean);
        }
        lineno += 1;
        let start = offset;
        offset += n as u64;
        let complete = buf.last() == Some(&b'\n');
        let body = if complete { &buf[..n - 1] } else { &buf[..] };
        if body.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<T>(body) {
            Ok(v) => {
                f(v).with_context(|| format!("{} line {lineno}", path.display()))?;
                if !complete {
                    return Ok(Tail::MissingNewline);
                }
            }
            Err(_) if !complete && r.fill_buf()?.is_empty() => return Ok(Tail::Torn(start)),
            Err(e) => {
                // Damage is bytes that are not a record at all. A whole JSON object naming a
                // schema was written by some build on purpose: if it is our schema and still
                // does not fit, the record's fields changed between builds, and every line
                // would fail the same way, so quarantining would drop the whole history.
                if let (Some(want), Some(found)) = (schema, schema_of(body)) {
                    if found != want {
                        bail!("{} line {lineno} has schema {found:?}, expected {want:?}; a newer build wrote it and this one cannot read it, so run that build or keep the file", path.display());
                    }
                    bail!(
                        "{} line {lineno} is a {found:?} record this build cannot read: {e}; a build with other fields wrote it, so run that build, or give the new field a serde default",
                        path.display()
                    );
                }
                match damaged.as_deref_mut() {
                    Some(d) => d.push(lineno),
                    None => bail!(
                        "cannot parse {} line {lineno}: {e}; the file is append-only and a line in the middle is damaged, so remove or repair that line (state is rebuilt from this file)",
                        path.display()
                    ),
                }
            }
        }
    }
}

/// Makes the next append start on a fresh line.
pub fn repair_tail(path: &Path, tail: Tail) -> Result<()> {
    match tail {
        Tail::Clean => {}
        Tail::MissingNewline => {
            OpenOptions::new().append(true).open(path)?.write_all(b"\n")?;
        }
        Tail::Torn(offset) => {
            eprintln!("keel-judge: {} ends in a torn record from offset {offset}; dropping it", path.display());
            OpenOptions::new().write(true).open(path)?.set_len(offset)?;
        }
    }
    Ok(())
}

#[derive(Debug, Default, Clone)]
pub struct TargetStats {
    pub quanta: u64,
    pub seconds: f64,
    pub execs: u64,
    pub last_seq: u64,
    pub last_exec_per_sec: Option<f64>,
    pub last_ft: Option<u64>,
    pub last_chosen_by: Option<ChosenBy>,
    pub last_rank: u64,
    pub last_quantum_s: f64,
    /// (seconds, delta_ft) of the newest quanta, oldest first.
    pub hist: VecDeque<(f64, f64)>,
    /// Quanta per `Outcome::as_str` and per `ChosenBy::as_str`, for the metrics counters.
    pub outcomes: BTreeMap<&'static str, u64>,
    pub chosen: BTreeMap<&'static str, u64>,
    pub last_corpus_files: Option<u64>,
    /// Unix seconds at which the newest quantum ended; `None` when its `started` does not parse.
    pub last_end: Option<f64>,
    /// How many of the newest quanta in a row ended in `error`; the backoff after a restart
    /// starts from this, so restarting does not hand a target that cannot fuzz a fresh run.
    pub trailing_errors: u32,
}

#[derive(Debug, Clone)]
pub struct FindingState {
    pub target: String,
    pub key: String,
    pub kind: String,
    pub frames: Vec<String>,
    pub source: String,
    pub first_seen: String,
    pub times_seen: u64,
    pub input: Option<String>,
}

#[derive(Debug, Default)]
pub struct FindingStore {
    pub by_key: BTreeMap<(String, String), FindingState>,
    blocked: HashSet<(String, String)>,
}

impl FindingStore {
    /// A target is blocked while a finding is recorded against its current identity: it
    /// would crash again at once. A new build changes the identity and unblocks it.
    pub fn is_blocked(&self, target: &str, identity: &str) -> bool {
        self.blocked.contains(&(target.to_string(), identity.to_string()))
    }

    pub fn get(&self, target: &str, key: &str) -> Option<&FindingState> {
        self.by_key.get(&(target.to_string(), key.to_string()))
    }

    pub fn open_for(&self, target: &str) -> usize {
        self.by_key.keys().filter(|(t, _)| t == target).count()
    }

    pub fn apply(&mut self, r: &FindingRecord) {
        self.blocked.insert((r.target.clone(), r.identity.clone()));
        let k = (r.target.clone(), r.key.clone());
        if let Some(f) = self.by_key.get_mut(&k) {
            f.times_seen += 1;
            return;
        }
        self.by_key.insert(
            k,
            FindingState {
                target: r.target.clone(),
                key: r.key.clone(),
                kind: r.kind.clone(),
                frames: r.frames.clone(),
                source: r.source.clone(),
                first_seen: r.first_seen.clone().or_else(|| r.seen_again.clone()).unwrap_or_default(),
                times_seen: 1,
                input: r.input.clone(),
            },
        );
    }
}

/// Lines of one log that are not records, found at load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogDamage {
    pub path: PathBuf,
    /// 1-based, ascending.
    pub lines: Vec<usize>,
    /// Where the original went, once `load_for_run` has quarantined it.
    pub kept_as: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct State {
    pub stats: BTreeMap<String, TargetStats>,
    pub findings: FindingStore,
    pub max_seq: u64,
    pub quanta: u64,
    pub seconds: f64,
    pub execs: u64,
    pub quanta_tail: Option<Tail>,
    pub findings_tail: Option<Tail>,
    /// Lines found damaged in the two logs at this load and left out of the state.
    pub damaged_lines: u64,
    pub damage: Vec<LogDamage>,
}

/// Δft of a quantum: features at the end minus features at INITED; the new-units count
/// when either is missing; 0 when both are.
pub fn delta_ft(ft_inited: Option<u64>, ft: Option<u64>, new_units: Option<u64>) -> u64 {
    match (ft_inited, ft) {
        (Some(a), Some(b)) => b.saturating_sub(a),
        _ => new_units.unwrap_or(0),
    }
}

/// How many damaged line numbers a message names.
const DAMAGE_SHOWN: usize = 5;

/// Replaces `path` with a copy without the `bad` lines (1-based, ascending) and keeps the
/// original as `<name>.damaged-<stamp>`. The copy is fsynced before it takes the name, and
/// the original stays reachable under its own name until then (a hard link, not a rename),
/// so a crash at any step leaves a log that loads.
fn quarantine(path: &Path, bad: &[usize], stamp: &str) -> Result<PathBuf> {
    let name = path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let kept = path.with_file_name(format!("{name}.damaged-{stamp}"));
    let tmp = path.with_file_name(format!("{name}.tmp"));
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let ctx = |what: &str| format!("cannot {what} while quarantining the damaged lines of {} (the state log); fix the permissions of --state or free space there", path.display());

    let mut src = BufReader::new(File::open(path).with_context(|| ctx("read it"))?);
    let mut out = File::create(&tmp).with_context(|| ctx(&format!("create {}", tmp.display())))?;
    let (mut lineno, mut buf) = (0usize, Vec::new());
    loop {
        buf.clear();
        if src.read_until(b'\n', &mut buf).with_context(|| ctx("read it"))? == 0 {
            break;
        }
        lineno += 1;
        if bad.binary_search(&lineno).is_err() {
            out.write_all(&buf).with_context(|| ctx(&format!("write {}", tmp.display())))?;
        }
    }
    out.sync_all().with_context(|| ctx(&format!("fsync {}", tmp.display())))?;
    drop(out);
    std::fs::hard_link(path, &kept).with_context(|| ctx(&format!("keep the original as {} (is there one from this second already?)", kept.display())))?;
    std::fs::rename(&tmp, path).with_context(|| ctx(&format!("rename {} over it", tmp.display())))?;
    File::open(dir).and_then(|d| d.sync_all()).with_context(|| ctx(&format!("fsync the directory {}", dir.display())))?;
    Ok(kept)
}

fn lines_shown(lines: &[usize]) -> String {
    let first: Vec<_> = lines.iter().take(DAMAGE_SHOWN).map(usize::to_string).collect();
    match lines.len().saturating_sub(DAMAGE_SHOWN) {
        0 => first.join(", "),
        more => format!("{} and {more} more", first.join(", ")),
    }
}

impl State {
    /// Rebuilds the state without changing anything on disk. A line in the middle that is
    /// not a record is left out and listed in `damage`; a record of another schema refuses.
    pub fn load(dir: &Path) -> Result<State> {
        let mut s = State::default();
        let qpath = quanta_path(dir);
        let mut qbad = Vec::new();
        let tail = read_jsonl_lenient::<Quantum>(&qpath, QUANTUM_SCHEMA, &mut qbad, |q| {
            if q.schema != QUANTUM_SCHEMA {
                bail!("schema is {:?}, expected {QUANTUM_SCHEMA:?}; this build cannot read it", q.schema);
            }
            s.apply_quantum(&q);
            Ok(())
        })?;
        s.quanta_tail = Some(tail);
        let fpath = findings_path(dir);
        let mut findings = FindingStore::default();
        let mut fbad = Vec::new();
        let tail = read_jsonl_lenient::<FindingRecord>(&fpath, FINDING_SCHEMA, &mut fbad, |r| {
            if r.schema != FINDING_SCHEMA {
                bail!("schema is {:?}, expected {FINDING_SCHEMA:?}; this build cannot read it", r.schema);
            }
            findings.apply(&r);
            Ok(())
        })?;
        s.findings = findings;
        s.findings_tail = Some(tail);
        for (path, lines) in [(qpath, qbad), (fpath, fbad)] {
            if !lines.is_empty() {
                s.damaged_lines += lines.len() as u64;
                s.damage.push(LogDamage { path, lines, kept_as: None });
            }
        }
        Ok(s)
    }

    /// `load` for the supervisor, which is about to append: a log with damaged lines is
    /// replaced by one with only its records, so the service starts instead of failing
    /// on the same line at every restart. The original is kept next to it, never deleted.
    pub fn load_for_run(dir: &Path) -> Result<State> {
        let first = State::load(dir)?;
        if first.damage.is_empty() {
            return Ok(first);
        }
        let stamp = crate::util::compact_utc(std::time::SystemTime::now());
        let mut damage = first.damage;
        for d in &mut damage {
            let kept = quarantine(&d.path, &d.lines, &stamp)?;
            eprintln!(
                "keel-judge: {} had {} damaged line(s) that are not records (lines {}); dropped them and kept the original as {}",
                d.path.display(),
                d.lines.len(),
                lines_shown(&d.lines),
                kept.display()
            );
            d.kept_as = Some(kept);
        }
        let mut s = State::load(dir)?;
        s.damaged_lines = first.damaged_lines;
        s.damage = damage;
        Ok(s)
    }

    pub fn apply_quantum(&mut self, q: &Quantum) {
        self.max_seq = self.max_seq.max(q.seq);
        self.quanta += 1;
        self.seconds += q.seconds;
        self.execs += q.execs.unwrap_or(0);
        let t = self.stats.entry(q.target.clone()).or_default();
        t.quanta += 1;
        t.seconds += q.seconds;
        t.execs += q.execs.unwrap_or(0);
        t.last_seq = t.last_seq.max(q.seq);
        t.last_exec_per_sec = q.exec_per_sec;
        t.last_ft = q.ft;
        t.last_chosen_by = Some(q.chosen_by);
        t.last_rank = q.rank;
        t.last_quantum_s = q.quantum_s;
        *t.outcomes.entry(q.outcome.as_str()).or_default() += 1;
        *t.chosen.entry(q.chosen_by.as_str()).or_default() += 1;
        t.last_corpus_files = Some(q.corpus_files_after);
        t.last_end = parse_rfc3339(&q.started).map(|start| start + q.seconds);
        t.trailing_errors = if q.outcome == Outcome::Error { t.trailing_errors.saturating_add(1) } else { 0 };
        t.hist.push_back((q.seconds, q.delta_ft as f64));
        while t.hist.len() > HISTORY {
            t.hist.pop_front();
        }
    }
}

pub fn quanta_path(dir: &Path) -> PathBuf {
    dir.join("quanta.jsonl")
}

pub fn findings_path(dir: &Path) -> PathBuf {
    dir.join("findings.jsonl")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn quantum(target: &str, seq: u64, seconds: f64, delta: u64) -> Quantum {
        Quantum {
            schema: QUANTUM_SCHEMA.into(),
            target: target.into(),
            worker: 0,
            seq,
            identity: "id".into(),
            started: "2026-11-15T00:00:00.000Z".into(),
            seconds,
            quantum_s: 60.0,
            chosen_by: ChosenBy::Index,
            rank: 10,
            rate: 0.1,
            index: 1.0,
            inited_s: Some(0.1),
            cov: Some(5),
            ft_inited: Some(10),
            ft: Some(10 + delta),
            delta_ft: delta,
            execs: Some(1000),
            exec_per_sec: Some(100.0),
            new_units: Some(delta),
            peak_rss_mb: Some(40),
            corpus_files_before: 1,
            corpus_files_after: 2,
            exit: ExitInfo { code: Some(72), signal: None },
            stopped_by: StoppedBy::Deadline,
            outcome: Outcome::Ok,
            finding: None,
            slow_units: 0,
            log: "x.log".into(),
        }
    }

    fn lines(qs: &[Quantum]) -> String {
        qs.iter().map(|q| serde_json::to_string(q).unwrap() + "\n").collect()
    }

    #[test]
    fn delta_ft_falls_back_to_new_units_then_zero() {
        assert_eq!(delta_ft(Some(10), Some(14), Some(9)), 4);
        assert_eq!(delta_ft(None, Some(14), Some(9)), 9);
        assert_eq!(delta_ft(Some(10), None, Some(9)), 9);
        assert_eq!(delta_ft(None, None, None), 0);
        assert_eq!(delta_ft(Some(10), Some(8), None), 0);
    }

    #[test]
    fn state_is_rebuilt_and_a_truncated_last_line_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut text = lines(&[quantum("a", 1, 60.0, 3), quantum("b", 2, 30.0, 0), quantum("a", 3, 60.0, 5)]);
        let torn = serde_json::to_string(&quantum("a", 4, 60.0, 1)).unwrap();
        text.push_str(&torn[..torn.len() / 2]);
        std::fs::write(quanta_path(dir.path()), &text).unwrap();
        let s = State::load(dir.path()).unwrap();
        assert_eq!(s.quanta, 3);
        assert_eq!(s.max_seq, 3);
        assert_eq!(s.stats["a"].quanta, 2);
        assert_eq!(s.stats["a"].hist.iter().map(|h| h.1).collect::<Vec<_>>(), vec![3.0, 5.0]);
        assert!(matches!(s.quanta_tail, Some(Tail::Torn(_))));

        repair_tail(&quanta_path(dir.path()), s.quanta_tail.unwrap()).unwrap();
        let mut w = Jsonl::open(&quanta_path(dir.path())).unwrap();
        w.append(&quantum("b", 4, 60.0, 1)).unwrap();
        let again = State::load(dir.path()).unwrap();
        assert_eq!((again.quanta, again.quanta_tail), (4, Some(Tail::Clean)));
    }

    fn damaged_files(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).filter(|p| p.to_string_lossy().contains(".damaged-")).collect();
        v.sort();
        v
    }

    #[test]
    fn outcomes_and_choices_are_counted_and_the_newest_quantum_is_remembered() {
        let mut s = State::default();
        let mut crash = quantum("a", 2, 30.0, 0);
        crash.outcome = Outcome::Crash;
        crash.chosen_by = ChosenBy::Starved;
        crash.corpus_files_after = 9;
        crash.started = "not a time".into();
        s.apply_quantum(&quantum("a", 1, 60.0, 3));
        let a = &s.stats["a"];
        assert_eq!((a.outcomes["ok"], a.chosen["index"], a.last_corpus_files), (1, 1, Some(2)));
        // 2026-11-15T00:00:00Z plus the quantum's 60 s.
        assert_eq!(a.last_end, parse_rfc3339("2026-11-15T00:01:00Z"));
        s.apply_quantum(&crash);
        let a = &s.stats["a"];
        assert_eq!((a.outcomes["ok"], a.outcomes["crash"], a.chosen["starved"], a.last_corpus_files), (1, 1, 1, Some(9)));
        assert_eq!(a.last_end, None);
    }

    #[test]
    fn load_reports_a_damaged_line_with_its_number_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let good = serde_json::to_string(&quantum("a", 1, 1.0, 0)).unwrap();
        let text = format!("{good}\n{{broken\n{good}\n");
        std::fs::write(quanta_path(dir.path()), &text).unwrap();
        let s = State::load(dir.path()).unwrap();
        assert_eq!((s.quanta, s.damaged_lines), (2, 1));
        assert_eq!(s.damage, vec![LogDamage { path: quanta_path(dir.path()), lines: vec![2], kept_as: None }]);
        assert_eq!(std::fs::read_to_string(quanta_path(dir.path())).unwrap(), text);
        assert!(damaged_files(dir.path()).is_empty());
    }

    #[test]
    fn a_damaged_line_is_quarantined_and_the_next_load_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let rec = |seq| serde_json::to_string(&quantum("a", seq, 1.0, 0)).unwrap();
        let text = format!("{}\n{{broken\n{}\n\u{0}\u{0}garbage\n{}\n", rec(1), rec(2), rec(3));
        std::fs::write(quanta_path(dir.path()), &text).unwrap();
        let finding = serde_json::to_string(&FindingRecord {
            schema: FINDING_SCHEMA.into(),
            target: "a".into(),
            key: "k".into(),
            kind: "rust-panic".into(),
            frames: vec![],
            source: "panic".into(),
            identity: "id".into(),
            first_seen: Some("t".into()),
            seen_again: None,
            input: None,
        })
        .unwrap();
        let ftext = format!("not json at all\n{finding}\n");
        std::fs::write(findings_path(dir.path()), &ftext).unwrap();

        let s = State::load_for_run(dir.path()).unwrap();
        assert_eq!((s.quanta, s.max_seq, s.damaged_lines), (3, 3, 3));
        assert_eq!(s.findings.open_for("a"), 1);
        let kept = damaged_files(dir.path());
        assert_eq!(kept.len(), 2, "{kept:?}");
        let name = |p: &PathBuf| p.file_name().unwrap().to_string_lossy().into_owned();
        let (qkept, fkept) = (kept.iter().find(|p| name(p).starts_with("quanta.jsonl.damaged-")).unwrap(), kept.iter().find(|p| name(p).starts_with("findings.jsonl.damaged-")).unwrap());
        // 20261115T231500Z: eight digits, T, six digits, Z.
        let stamp = name(qkept).strip_prefix("quanta.jsonl.damaged-").unwrap().to_string();
        assert!(stamp.len() == 16 && stamp.as_bytes()[8] == b'T' && stamp.ends_with('Z'), "{stamp}");
        assert_eq!(std::fs::read_to_string(qkept).unwrap(), text, "the original must be kept byte for byte");
        assert_eq!(std::fs::read_to_string(fkept).unwrap(), ftext);
        assert_eq!(std::fs::read_to_string(quanta_path(dir.path())).unwrap(), format!("{}\n{}\n{}\n", rec(1), rec(2), rec(3)));
        assert_eq!(std::fs::read_to_string(findings_path(dir.path())).unwrap(), format!("{finding}\n"));
        assert!(!dir.path().join("quanta.jsonl.tmp").exists() && !dir.path().join("findings.jsonl.tmp").exists());

        let again = State::load(dir.path()).unwrap();
        assert_eq!((again.quanta, again.damaged_lines), (3, 0));
        // And the log takes appends after the rewrite.
        Jsonl::open(&quanta_path(dir.path())).unwrap().append(&quantum("b", 4, 1.0, 0)).unwrap();
        assert_eq!(State::load(dir.path()).unwrap().quanta, 4);
    }

    #[test]
    fn an_unparseable_last_line_with_a_newline_is_damage_and_a_torn_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let good = serde_json::to_string(&quantum("a", 1, 1.0, 0)).unwrap();
        std::fs::write(quanta_path(dir.path()), format!("{good}\n{{broken\n")).unwrap();
        let s = State::load(dir.path()).unwrap();
        assert_eq!((s.quanta, s.damaged_lines), (1, 1));
        std::fs::write(quanta_path(dir.path()), format!("{good}\n{{broken")).unwrap();
        let s = State::load(dir.path()).unwrap();
        assert_eq!((s.damaged_lines, s.quanta_tail), (0, Some(Tail::Torn(good.len() as u64 + 1))));
    }

    #[test]
    fn a_schema_mismatch_still_refuses_to_start_and_nothing_is_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let good = serde_json::to_string(&quantum("a", 1, 1.0, 0)).unwrap();
        // A record that parses, and one of a newer build whose shape this build cannot parse.
        let mut newer = serde_json::to_value(quantum("a", 2, 1.0, 0)).unwrap();
        newer["schema"] = "keel.judge.quantum.v2".into();
        let parses = serde_json::to_string(&newer).unwrap();
        let unparseable = r#"{"schema":"keel.judge.quantum.v2","target":"a","shape":"new"}"#;
        for (name, body) in [("parses", parses.as_str()), ("unparseable", unparseable)] {
            // Damage elsewhere in the file must not change the answer.
            std::fs::write(quanta_path(dir.path()), format!("{good}\n{{broken\n{body}\n{good}\n")).unwrap();
            let before = std::fs::read_to_string(quanta_path(dir.path())).unwrap();
            let err = format!("{:#}", State::load_for_run(dir.path()).unwrap_err());
            assert!(err.contains("keel.judge.quantum.v2") && err.contains(QUANTUM_SCHEMA), "{name}: {err}");
            assert_eq!(std::fs::read_to_string(quanta_path(dir.path())).unwrap(), before, "{name}: the log was touched");
            assert!(damaged_files(dir.path()).is_empty(), "{name}");
        }
    }

    #[test]
    fn a_record_of_our_schema_with_other_fields_refuses_and_is_not_quarantined() {
        // An upgrade that adds a field without a serde default makes every old line fail
        // to parse; treating them as damage would quarantine the whole history.
        let dir = tempfile::tempdir().unwrap();
        let good = serde_json::to_string(&quantum("a", 1, 1.0, 0)).unwrap();
        let mut old = serde_json::to_value(quantum("a", 2, 1.0, 0)).unwrap();
        old.as_object_mut().unwrap().remove("seq");
        let old = serde_json::to_string(&old).unwrap();
        std::fs::write(quanta_path(dir.path()), format!("{good}\n{old}\n{good}\n")).unwrap();
        let before = std::fs::read_to_string(quanta_path(dir.path())).unwrap();
        let err = format!("{:#}", State::load_for_run(dir.path()).unwrap_err());
        assert!(err.contains("line 2") && err.contains("other fields") && err.contains("seq"), "{err}");
        assert_eq!(std::fs::read_to_string(quanta_path(dir.path())).unwrap(), before);
        assert!(damaged_files(dir.path()).is_empty());
    }

    #[test]
    fn strict_reading_still_names_file_and_line() {
        let dir = tempfile::tempdir().unwrap();
        let good = serde_json::to_string(&quantum("a", 1, 1.0, 0)).unwrap();
        std::fs::write(quanta_path(dir.path()), format!("{good}\n{{broken\n{good}\n")).unwrap();
        let err = format!("{:#}", read_jsonl::<Quantum>(&quanta_path(dir.path()), |_| Ok(())).unwrap_err());
        assert!(err.contains("quanta.jsonl line 2"), "{err}");
    }

    #[test]
    fn a_failed_append_is_cut_off_and_the_next_load_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = quanta_path(dir.path());
        let mut log = Jsonl::open(&path).unwrap();
        log.append(&quantum("a", 1, 1.0, 0)).unwrap();
        let len = std::fs::metadata(&path).unwrap().len();
        // The disk fills after half of the record.
        let err = log
            .append_with(&quantum("a", 2, 1.0, 0), |f, bytes| {
                f.write_all(&bytes[..bytes.len() / 2])?;
                Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
            })
            .unwrap_err();
        assert!(err.downcast_ref::<LogAppendFailed>().is_some_and(|e| e.how.contains("cut off")), "{err:#}");
        let msg = format!("{err:#}");
        assert!(msg.contains("quanta.jsonl") && msg.contains("restart"), "{msg}");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len, "the partial record must be gone");
        let s = State::load(dir.path()).unwrap();
        assert_eq!((s.quanta, s.damaged_lines, s.quanta_tail), (1, 0, Some(Tail::Clean)));
        // The log is still usable by whoever holds it.
        log.append(&quantum("a", 3, 1.0, 0)).unwrap();
        assert_eq!(State::load(dir.path()).unwrap().quanta, 2);
    }

    #[test]
    fn a_failed_cut_is_said_in_the_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = quanta_path(dir.path());
        std::fs::write(&path, "").unwrap();
        // Opened for reading only: the write fails, and so does cutting back.
        let mut log = Jsonl { file: File::open(&path).unwrap(), path: path.clone() };
        let err = log.append(&quantum("a", 1, 1.0, 0)).unwrap_err();
        let failed = err.downcast_ref::<LogAppendFailed>().expect("marked as a log failure");
        assert!(failed.how.contains("also failed") && failed.how.contains("byte 0"), "{}", failed.how);
    }

    #[test]
    fn findings_block_by_identity_and_count_sightings() {
        let mut s = FindingStore::default();
        let rec = |again: bool, identity: &str| FindingRecord {
            schema: FINDING_SCHEMA.into(),
            target: "t".into(),
            key: "k".into(),
            kind: "rust-panic".into(),
            frames: vec!["src/decode.rs:41:9".into()],
            source: "panic".into(),
            identity: identity.into(),
            first_seen: (!again).then(|| "t0".to_string()),
            seen_again: again.then(|| "t1".to_string()),
            input: Some("p".into()),
        };
        s.apply(&rec(false, "v1"));
        assert!(s.is_blocked("t", "v1") && !s.is_blocked("t", "v2") && !s.is_blocked("u", "v1"));
        s.apply(&rec(true, "v2"));
        assert!(s.is_blocked("t", "v2"));
        assert_eq!(s.get("t", "k").unwrap().times_seen, 2);
        assert_eq!(s.get("t", "k").unwrap().first_seen, "t0");
        assert_eq!(s.open_for("t"), 1);
    }
}
