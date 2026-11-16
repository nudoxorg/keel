//! `keel-judge status`: what the logs say, for a human or as JSON.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::sched::{index, rate};
use crate::state::{State, TargetStats};
use crate::targets::TargetsFile;
use crate::util::{per_sec, sci};

/// Quanta of one target that the features-per-hour figure looks at.
const RECENT: usize = 4;
pub const DEFAULT_QUANTUM_S: f64 = 60.0;

#[derive(Serialize, Debug)]
pub struct Totals {
    pub quanta: u64,
    pub seconds: f64,
    pub execs: u64,
}

#[derive(Serialize, Debug)]
pub struct TargetRow {
    pub id: String,
    pub rank: u64,
    pub quanta: u64,
    pub seconds: f64,
    pub share: f64,
    pub execs: u64,
    pub last_exec_per_sec: Option<f64>,
    pub last_ft: Option<u64>,
    pub features_per_hour: Option<f64>,
    pub index: f64,
    pub chosen_by: Option<String>,
    pub open_findings: usize,
}

#[derive(Serialize, Debug)]
pub struct FindingRow {
    pub target: String,
    pub key: String,
    pub kind: String,
    pub first_seen: String,
    pub times_seen: u64,
    pub input: Option<String>,
}

/// A log with lines that are not records. `status` only reads, so these are left in the
/// file and left out of every figure here; `keel-judge run` quarantines them at its start.
#[derive(Serialize, Debug)]
pub struct DamagedLog {
    pub file: String,
    pub lines: Vec<usize>,
}

#[derive(Serialize, Debug)]
pub struct Report {
    pub schema: &'static str,
    pub totals: Totals,
    pub targets: Vec<TargetRow>,
    pub findings: Vec<FindingRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<crate::checks::Summary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub damaged: Vec<DamagedLog>,
}

/// New features per hour over the target's last `RECENT` quanta; shared with the metrics
/// file so the two never disagree.
pub fn features_per_hour(st: &TargetStats) -> Option<f64> {
    let recent: Vec<_> = st.hist.iter().rev().take(RECENT).collect();
    let (secs, dft) = recent.iter().fold((0.0, 0.0), |(s, d), (a, b)| (s + a, d + b));
    (secs > 0.0).then(|| dft / secs * 3600.0)
}

/// With a targets file every listed target appears, run or not, with its configured rank;
/// without, the targets are those in the logs, with the rank of their latest quantum.
/// Every finding is open: nothing here closes one, a new build only lets its target run.
pub fn build(state: &State, targets: Option<&TargetsFile>) -> Report {
    let ids: Vec<(String, Option<u64>)> = match targets {
        Some(t) => {
            let mut v: Vec<_> = t.targets.iter().map(|t| (t.id.clone(), Some(t.rank))).collect();
            let known: BTreeSet<_> = v.iter().map(|x| x.0.clone()).collect();
            v.extend(state.stats.keys().filter(|k| !known.contains(*k)).map(|k| (k.clone(), None)));
            v
        }
        None => state.stats.keys().map(|k| (k.clone(), None)).collect(),
    };
    let rows = ids
        .into_iter()
        .map(|(id, rank)| {
            let st = state.stats.get(&id).cloned().unwrap_or_default();
            let rank = rank.unwrap_or(st.last_rank);
            let q = if st.last_quantum_s > 0.0 { st.last_quantum_s } else { DEFAULT_QUANTUM_S };
            TargetRow {
                share: if state.seconds > 0.0 { st.seconds / state.seconds } else { 0.0 },
                features_per_hour: features_per_hour(&st),
                index: index(rank, rate(&st.hist, q)),
                chosen_by: st.last_chosen_by.map(|c| c.as_str().to_string()),
                open_findings: state.findings.open_for(&id),
                quanta: st.quanta,
                seconds: st.seconds,
                execs: st.execs,
                last_exec_per_sec: st.last_exec_per_sec,
                last_ft: st.last_ft,
                rank,
                id,
            }
        })
        .collect();
    let findings = state
        .findings
        .by_key
        .values()
        .map(|f| FindingRow {
            target: f.target.clone(),
            key: f.key.clone(),
            kind: f.kind.clone(),
            first_seen: f.first_seen.clone(),
            times_seen: f.times_seen,
            input: f.input.clone(),
        })
        .collect();
    let damaged = state.damage.iter().map(|d| DamagedLog { file: d.path.display().to_string(), lines: d.lines.clone() }).collect();
    Report { schema: "keel.judge.status.v1", totals: Totals { quanta: state.quanta, seconds: state.seconds, execs: state.execs }, targets: rows, findings, checks: None, damaged }
}

/// Columns padded to their widest cell; `left` lists the columns that are text.
fn table(headers: &[&str], rows: &[Vec<String>], left: &[usize]) -> String {
    let widths: Vec<usize> = (0..headers.len()).map(|c| rows.iter().map(|r| r[c].chars().count()).chain([headers[c].len()]).max().unwrap_or(0)).collect();
    let line = |cells: &[String]| {
        let parts: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(c, s)| if left.contains(&c) { format!("{s:<w$}", w = widths[c]) } else { format!("{s:>w$}", w = widths[c]) })
            .collect();
        parts.join("  ").trim_end().to_string() + "\n"
    };
    let mut out = line(&headers.iter().map(|h| h.to_string()).collect::<Vec<_>>());
    for r in rows {
        out.push_str(&line(r));
    }
    out
}

pub fn render(r: &Report) -> String {
    let opt = |v: Option<String>| v.unwrap_or_else(|| "-".into());
    let rows: Vec<Vec<String>> = r
        .targets
        .iter()
        .map(|t| {
            vec![
                t.id.clone(),
                t.rank.to_string(),
                t.quanta.to_string(),
                format!("{:.0}", t.seconds),
                format!("{:.1}%", t.share * 100.0),
                sci(t.execs),
                opt(t.last_exec_per_sec.map(per_sec)),
                opt(t.last_ft.map(|f| f.to_string())),
                opt(t.features_per_hour.map(|f| format!("{f:.1}"))),
                format!("{:.1}", t.index),
                opt(t.chosen_by.clone()),
                t.open_findings.to_string(),
            ]
        })
        .collect();
    let mut out = format!("{} quanta, {:.0} s, {} execs\n\n", r.totals.quanta, r.totals.seconds, sci(r.totals.execs));
    out.push_str(&table(
        &["target", "rank", "quanta", "seconds", "share", "execs", "exec/s", "ft", "ft/hour", "index", "chosen by", "findings"],
        &rows,
        &[0, 10],
    ));
    out.push('\n');
    if r.findings.is_empty() {
        out.push_str("open findings: none\n");
    } else {
        out.push_str("open findings:\n");
        let rows: Vec<Vec<String>> = r
            .findings
            .iter()
            .map(|f| vec![f.target.clone(), f.key.clone(), f.kind.clone(), f.first_seen.clone(), f.times_seen.to_string(), opt(f.input.clone())])
            .collect();
        out.push_str(&table(&["target", "key", "kind", "first seen", "seen", "input"], &rows, &[0, 1, 2, 3, 5]));
    }
    for d in &r.damaged {
        let lines: Vec<_> = d.lines.iter().map(usize::to_string).collect();
        out.push_str(&format!(
            "\nWARNING: {} has {} line(s) that are not records (lines {}); the figures above leave them out. `keel-judge run` moves them aside at its next start.\n",
            d.file,
            d.lines.len(),
            lines.join(", ")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ChosenBy, FINDING_SCHEMA, FindingRecord};

    #[test]
    fn rows_show_shares_recent_feature_rates_and_the_current_index() {
        let mut s = State::default();
        let mk = |seq, secs: f64, delta: u64| crate::state::Quantum {
            schema: crate::state::QUANTUM_SCHEMA.into(),
            target: "a".into(),
            worker: 0,
            seq,
            identity: "i".into(),
            started: "t".into(),
            seconds: secs,
            quantum_s: 60.0,
            chosen_by: ChosenBy::Cold,
            rank: 100,
            rate: 0.0,
            index: 0.0,
            inited_s: None,
            cov: None,
            ft_inited: None,
            ft: Some(50),
            delta_ft: delta,
            execs: Some(1000),
            exec_per_sec: Some(10.0),
            new_units: None,
            peak_rss_mb: None,
            corpus_files_before: 0,
            corpus_files_after: 0,
            exit: Default::default(),
            stopped_by: crate::state::StoppedBy::Deadline,
            outcome: crate::state::Outcome::Ok,
            finding: None,
            slow_units: 0,
            log: String::new(),
        };
        s.apply_quantum(&mk(1, 60.0, 6));
        let mut b = mk(2, 60.0, 0);
        b.target = "b".into();
        s.apply_quantum(&b);
        s.findings.apply(&FindingRecord {
            schema: FINDING_SCHEMA.into(),
            target: "b".into(),
            key: "k1".into(),
            kind: "rust-panic".into(),
            frames: vec![],
            source: "panic".into(),
            identity: "i".into(),
            first_seen: Some("t".into()),
            seen_again: None,
            input: Some("/in".into()),
        });
        let r = build(&s, None);
        assert_eq!(r.totals.quanta, 2);
        let a = &r.targets[0];
        assert_eq!((a.id.as_str(), a.rank, a.quanta), ("a", 100, 1));
        assert!((a.share - 0.5).abs() < 1e-9 && (a.features_per_hour.unwrap() - 360.0).abs() < 1e-9);
        assert!((a.index - 100.0 * 7.0 / 120.0).abs() < 1e-9);
        assert_eq!(r.targets[1].open_findings, 1);
        let text = render(&r);
        assert!(text.contains("open findings:") && text.contains("k1") && text.contains("chosen by"), "{text}");
    }

    #[test]
    fn damaged_lines_are_reported_and_a_clean_report_says_nothing_of_them() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(crate::state::quanta_path(dir.path()), "{broken\n").unwrap();
        let r = build(&State::load(dir.path()).unwrap(), None);
        assert!(render(&r).contains("WARNING") && render(&r).contains("quanta.jsonl"), "{}", render(&r));
        assert_eq!(serde_json::to_value(&r).unwrap()["damaged"][0]["lines"][0], 1);
        assert!(serde_json::to_value(build(&State::default(), None)).unwrap().get("damaged").is_none());
    }

    #[test]
    fn a_listed_target_never_run_appears_with_the_prior_index() {
        let tf: TargetsFile = serde_json::from_str(
            r#"{"schema":"keel.judge.targets.v1","targets":[{"id":"n","rank":600,"argv":["x"],"corpus":"c","artifacts":"a"}]}"#,
        )
        .unwrap();
        let r = build(&State::default(), Some(&tf));
        assert_eq!((r.targets[0].quanta, r.targets[0].index), (0, 10.0));
        assert!(render(&r).contains("open findings: none"));
    }
}
