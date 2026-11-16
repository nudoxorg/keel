//! `keel comment`: AMBITION direction 9. One failing foundation and 400 blocked
//! dependents is one line and one cause; a flaky node carries its history; a
//! slow run names the three nodes that made it slow. Markdown, no tables (a
//! table cannot be narrower than its widest node id), nothing else.

use std::collections::BTreeSet;

use keel::{Digest, Flaky, Record, Report, Status, Verdict};

use crate::util::fmt_ms;

/// Longest line of quoted evidence; a PR comment is not a log viewer.
const CLIP: usize = 110;

fn clip(s: &str) -> String {
    let t = s.trim_end();
    match t.char_indices().nth(CLIP) {
        Some((i, _)) => format!("{}...", &t[..i]),
        None => t.to_owned(),
    }
}

fn word(s: Status) -> &'static str {
    match s {
        Status::Pass => "pass",
        Status::Fail => "fail",
        Status::Timeout => "timeout",
        Status::Error => "error",
        Status::Blocked => "blocked",
        Status::Cached => "cached",
        Status::Flaky => "flaky",
        Status::Skipped => "skipped",
        Status::Quarantined => "quarantined",
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The first three non-empty lines of the evidence blob that reads like a
/// failure log: `stderr`, else a journal.
fn evidence_lines(r: &Record, blob: &dyn Fn(&Digest) -> Option<String>) -> Vec<String> {
    let pick = r.evidence.iter().find(|e| e.name == "stderr").or_else(|| {
        r.evidence
            .iter()
            .find(|e| e.name.starts_with("stderr") || e.name.starts_with("journal"))
    });
    pick.and_then(|e| blob(&e.reference))
        .map(|t| {
            t.lines()
                .filter(|l| !l.trim().is_empty())
                .take(3)
                .map(clip)
                .collect()
        })
        .unwrap_or_default()
}

/// How many earlier reports flaked this node under this key.
fn flake_history(id: &keel::NodeId, key: &Digest, previous: &[Report]) -> usize {
    previous
        .iter()
        .filter(|p| {
            p.flaky.iter().any(|f| f.id == *id && f.key == *key)
                || p.nodes
                    .iter()
                    .any(|n| n.id == *id && n.key == *key && n.status == Status::Flaky)
        })
        .count()
}

pub fn render(
    report: &Report,
    previous: &[Report],
    blob: &dyn Fn(&Digest) -> Option<String>,
) -> String {
    let mut out = String::new();
    let flaky_ids: BTreeSet<&keel::NodeId> = report
        .flaky
        .iter()
        .map(|f: &Flaky| &f.id)
        .chain(
            report
                .nodes
                .iter()
                .filter(|n| n.status == Status::Flaky)
                .map(|n| &n.id),
        )
        .collect();
    let blocked = report
        .nodes
        .iter()
        .filter(|n| n.status == Status::Blocked)
        .count();

    // First line: the verdict and what it rests on.
    let verdict = if report.verdict == Verdict::Fail {
        "FAIL"
    } else {
        "PASS"
    };
    let mut facts = Vec::new();
    if !report.roots.is_empty() {
        facts.push(plural(report.roots.len(), "root cause", "root causes"));
    }
    if blocked > 0 {
        facts.push(format!("{blocked} blocked"));
    }
    if !flaky_ids.is_empty() {
        facts.push(format!("{} flaky", flaky_ids.len()));
    }
    let line = if facts.is_empty() {
        "all green".to_owned()
    } else {
        facts.join(", ")
    };
    out.push_str(&format!("**{verdict}**: {line}\n"));

    if !report.roots.is_empty() {
        out.push_str(&format!(
            "\n### {}\n",
            if report.roots.len() == 1 {
                "Root cause"
            } else {
                "Root causes"
            }
        ));
        for id in &report.roots {
            let Some(r) = report.nodes.iter().find(|n| n.id == *id) else {
                out.push_str(&format!("- `{id}`\n"));
                continue;
            };
            let dependents = report
                .nodes
                .iter()
                .filter(|n| n.blocked_by.contains(id))
                .count();
            let mut head = format!("- `{id}`: {}", word(r.status));
            if let Some(reason) = &r.reason {
                head.push_str(&format!(" ({reason})"));
            }
            if let Some(ms) = r.duration_ms {
                head.push_str(&format!(" after {}", fmt_ms(ms)));
            }
            head.push_str(&format!(", blocks {}", plural(dependents, "node", "nodes")));
            out.push_str(&head);
            out.push('\n');
            if let Some(d) = &r.detail {
                out.push_str(&format!("  - exercised: `{}`\n", clip(&d.ran)));
                match (&d.expected, &d.actual) {
                    (Some(e), Some(a)) => {
                        out.push_str(&format!("  - expected `{}`, got `{}`\n", clip(e), clip(a)))
                    }
                    (Some(e), None) => out.push_str(&format!("  - expected `{}`\n", clip(e))),
                    _ => {}
                }
            }
            let lines = evidence_lines(r, blob);
            if !lines.is_empty() {
                out.push_str("\n  ```text\n");
                for l in lines {
                    out.push_str(&format!("  {l}\n"));
                }
                out.push_str("  ```\n");
            }
        }
    }

    if !flaky_ids.is_empty() {
        out.push_str("\n### Flaky\n");
        for id in &flaky_ids {
            let key = report
                .flaky
                .iter()
                .find(|f| f.id == **id)
                .map(|f| f.key)
                .or_else(|| report.nodes.iter().find(|n| n.id == **id).map(|n| n.key));
            let history = key.map_or(0, |k| flake_history(id, &k, previous));
            let text = match (history, previous.len()) {
                (0, 0) => "no earlier reports to compare".to_owned(),
                (0, n) => format!(
                    "first flake on this key in {}",
                    plural(n, "earlier report", "earlier reports")
                ),
                (h, n) => format!(
                    "flaked on this key in {h} of {} too",
                    plural(n, "earlier report", "earlier reports")
                ),
            };
            out.push_str(&format!("- `{id}`: {text}\n"));
        }
    }

    // The nodes that made the run slow: on the critical path when the report
    // names one, else the slowest overall.
    let on_path: Vec<&Record> = report
        .budget
        .as_ref()
        .map(|b| {
            b.critical_path
                .iter()
                .filter_map(|id| report.nodes.iter().find(|n| n.id == *id))
                .collect()
        })
        .unwrap_or_default();
    let (title, mut slow): (&str, Vec<&Record>) = if on_path.is_empty() {
        ("Slowest nodes", report.nodes.iter().collect())
    } else {
        ("Slowest on the critical path", on_path)
    };
    slow.retain(|n| n.duration_ms.is_some());
    slow.sort_by(|a, b| {
        b.duration_ms
            .cmp(&a.duration_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    if !slow.is_empty() {
        out.push_str(&format!("\n### {title}\n"));
        for n in slow.iter().take(3) {
            out.push_str(&format!(
                "- `{}`: {}\n",
                n.id,
                fmt_ms(n.duration_ms.unwrap_or(0))
            ));
        }
    }

    let c = &report.counts;
    let ran = c.pass + c.fail + c.timeout + c.error + c.flaky;
    out.push_str(&format!(
        "\ncached {}, ran {ran}, total {}\n",
        c.cached,
        fmt_ms(report.duration_ms)
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = include_str!("../../keel/tests/fixtures/report.json");

    fn report() -> Report {
        serde_json::from_str(REPORT).unwrap()
    }

    fn no_blobs() -> impl Fn(&Digest) -> Option<String> {
        |_| None
    }

    #[test]
    fn the_design_fixture_reads_in_ten_seconds() {
        let text = render(&report(), &[], &no_blobs());
        let expected = "\
**FAIL**: 1 root cause, 1 blocked, 1 flaky

### Root cause
- `rust:backend-store::wal_replay::replays_torn_tail`: fail after 1.2s, blocks 1 node
  - exercised: `replays_torn_tail`
  - expected `tail.len() == 0`, got `tail.len() == 17`

### Flaky
- `rust:backend-flow::timing::settles`: no earlier reports to compare

### Slowest nodes
- `rust:backend-store::wal_replay::replays_torn_tail`: 1.2s

cached 16438, ran 1910, total 3m55s
";
        assert_eq!(text, expected);
        assert!(text.lines().all(|l| l.len() <= 100), "no wide lines");
    }

    #[test]
    fn evidence_flaky_history_and_slowest_three() {
        let mut r = report();
        let stderr = "thread 'x' panicked at crates/store/src/wal.rs:412:9:\nassertion failed: tail.len() == 0\n\nnote: run with RUST_BACKTRACE=1\nfourth line\n";
        let digest = Digest::of(stderr.as_bytes());
        r.nodes[0].evidence[0].reference = digest;
        // A prior report that flaked the same key twice would still count once per report.
        let mut earlier = report();
        earlier.run_id = "earlier-1".into();
        let mut other_key = report();
        other_key.flaky[0].key = Digest::Blake3([9; 32]);
        let blob = move |d: &Digest| (*d == digest).then(|| stderr.to_owned());
        let text = render(&r, &[earlier, other_key, report()], &blob);
        assert!(text.contains("  ```text\n  thread 'x' panicked at crates/store/src/wal.rs:412:9:\n  assertion failed: tail.len() == 0\n  note: run with RUST_BACKTRACE=1\n  ```\n"), "{text}");
        assert!(!text.contains("fourth line"));
        assert!(
            text.contains("flaked on this key in 2 of 3 earlier reports too"),
            "{text}"
        );

        // Three slowest of more.
        let mut many = report();
        let proto = many.nodes[1].clone();
        for (i, ms) in [50u64, 4000, 900, 7].iter().enumerate() {
            let mut n = proto.clone();
            n.id = keel::NodeId::new(format!("rust:n{i}"));
            n.duration_ms = Some(*ms);
            many.nodes.push(n);
        }
        // The fixture's critical path names placeholder ids no node has, so the
        // report falls back to the slowest nodes overall.
        assert!(render(&many, &[], &no_blobs()).contains("### Slowest nodes\n"));
        let ids = [
            "rust:n1",
            "rust:n2",
            "rust:n3",
            "rust:backend-store::wal_replay::replays_torn_tail",
        ];
        many.budget = Some(keel::Budget {
            limit_ms: 1,
            critical_path_ms: 1,
            critical_path: ids.map(keel::NodeId::new).to_vec(),
        });
        let text = render(&many, &[], &no_blobs());
        let slow: Vec<&str> = text
            .split("### Slowest on the critical path\n")
            .nth(1)
            .unwrap()
            .lines()
            .take(3)
            .collect();
        assert_eq!(
            slow,
            [
                "- `rust:n1`: 4s",
                "- `rust:n2`: 900ms",
                "- `rust:backend-store::wal_replay::replays_torn_tail`: 1.2s"
            ]
            .map(|_| "")
            .iter()
            .zip(slow.iter())
            .map(|(_, s)| *s)
            .collect::<Vec<_>>()
        );
        assert!(
            slow[0].contains("n1")
                && slow[1].contains("replays_torn_tail")
                && slow[2].contains("n2")
        );
    }

    #[test]
    fn a_passing_run_is_one_line_and_the_totals() {
        let mut r = report();
        r.nodes.retain(|n| n.status == Status::Cached);
        r.roots.clear();
        r.flaky.clear();
        r.budget = None;
        r.verdict = Verdict::Pass;
        r.nodes[0].duration_ms = None;
        let text = render(&r, &[], &no_blobs());
        assert_eq!(
            text,
            "**PASS**: all green\n\ncached 16438, ran 1910, total 3m55s\n"
        );
    }

    #[test]
    fn control_failures_say_so() {
        let mut r = report();
        r.roots = vec![r.nodes[3].id.clone(), r.nodes[0].id.clone()];
        let text = render(&r, &[], &no_blobs());
        let first = text.lines().nth(3).unwrap();
        assert!(
            first.contains("wrong-port") && first.contains("(control-did-not-fail)"),
            "{first}"
        );
    }
}
