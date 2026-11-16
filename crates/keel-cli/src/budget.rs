//! `keel budget`: the critical path and total thread time of a run, and
//! whether the run fits a limit (DESIGN §5.4 item 2).

use std::collections::HashMap;

use anyhow::Result;
use keel::{Manifest, NodeId, Plan, Report};

pub struct Summary {
    pub thread_ms: u64,
    pub wall_ms: u64,
    pub critical_ms: u64,
    /// The path with each node's duration.
    pub path: Vec<(NodeId, u64)>,
    pub source: &'static str,
}

fn dur(report: &Report) -> HashMap<&NodeId, u64> {
    report
        .nodes
        .iter()
        .map(|r| (&r.id, r.duration_ms.unwrap_or(0)))
        .collect()
}

/// The longest chain of `stands_on` edges by node duration, from the manifest's graph.
fn longest_chain(report: &Report, manifest: &Manifest) -> Result<(u64, Vec<NodeId>)> {
    let plan = Plan::new(&manifest.nodes)?;
    let d = dur(report);
    let mut best: HashMap<&NodeId, (u64, Option<&NodeId>)> = HashMap::new();
    for id in plan.order() {
        let up = plan.upstream(id).unwrap_or_default();
        let (via, base) = up
            .iter()
            .filter_map(|u| best.get(u).map(|(t, _)| (*u, *t)))
            .max_by_key(|(_, t)| *t)
            .map_or((None, 0), |(u, t)| (Some(u), t));
        best.insert(id, (base + d.get(id).copied().unwrap_or(0), via));
    }
    let Some((&end, &(total, _))) = best
        .iter()
        .max_by_key(|(id, (t, _))| (*t, std::cmp::Reverse(id.as_str())))
    else {
        return Ok((0, vec![]));
    };
    let mut path = vec![end.clone()];
    let mut cur = end;
    while let Some(prev) = best[cur].1 {
        path.push(prev.clone());
        cur = prev;
    }
    path.reverse();
    Ok((total, path))
}

pub fn summarise(report: &Report, manifest: Option<&Manifest>) -> Result<Summary> {
    let d = dur(report);
    let thread_ms = d.values().sum();
    let (critical_ms, ids, source) = match (&report.budget, manifest) {
        (Some(b), _) if !b.critical_path.is_empty() => (
            b.critical_path_ms,
            b.critical_path.clone(),
            "the report's budget",
        ),
        (_, Some(m)) => {
            let (t, p) = longest_chain(report, m)?;
            (t, p, "the manifest's stands_on graph")
        }
        _ => {
            // Without a graph the best honest lower bound is the slowest node.
            let top = report
                .nodes
                .iter()
                .max_by_key(|r| r.duration_ms.unwrap_or(0));
            (
                top.and_then(|r| r.duration_ms).unwrap_or(0),
                top.map(|r| r.id.clone()).into_iter().collect(),
                "the slowest single node (the report has no critical path; pass --manifest for the graph)",
            )
        }
    };
    let path = ids
        .into_iter()
        .map(|id| {
            let t = d.get(&id).copied().unwrap_or(0);
            (id, t)
        })
        .collect();
    Ok(Summary {
        thread_ms,
        wall_ms: report.duration_ms,
        critical_ms,
        path,
        source,
    })
}

pub fn over_limit(s: &Summary, limit_ms: u64) -> Option<String> {
    if s.wall_ms > limit_ms {
        Some(format!(
            "the run took {} of a {} limit",
            crate::util::fmt_ms(s.wall_ms),
            crate::util::fmt_ms(limit_ms)
        ))
    } else if s.critical_ms > limit_ms {
        Some(format!(
            "the critical path alone is {}, over the {} limit; no amount of parallelism fixes that, split the nodes below",
            crate::util::fmt_ms(s.critical_ms),
            crate::util::fmt_ms(limit_ms)
        ))
    } else {
        None
    }
}

pub fn render(s: &Summary, limit_ms: u64) -> String {
    use crate::util::fmt_ms;
    let mut out = format!(
        "wall {} of {}; total thread time {}; critical path {} (from {})\n",
        fmt_ms(s.wall_ms),
        fmt_ms(limit_ms),
        fmt_ms(s.thread_ms),
        fmt_ms(s.critical_ms),
        s.source
    );
    for (id, ms) in &s.path {
        out.push_str(&format!("  {:>8}  {id}\n", fmt_ms(*ms)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel::{Digest, Record, Status};

    fn node(id: &str, stands_on: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "id": id, "kind": "rust-test", "group": "unit(p)", "stands_on": stands_on,
            "key": format!("blake3:{}", "ab".repeat(32))
        })
    }

    fn setup() -> (Report, Manifest) {
        let mut m: Manifest =
            serde_json::from_str(include_str!("../../keel/tests/fixtures/manifest.json")).unwrap();
        m.nodes = ["a", "b", "c", "d"]
            .iter()
            .zip([
                vec![],
                vec!["rust:a"],
                vec!["rust:a"],
                vec!["rust:b", "rust:c"],
            ])
            .map(|(n, up)| serde_json::from_value(node(&format!("rust:{n}"), &up)).unwrap())
            .collect();
        let mut r: Report =
            serde_json::from_str(include_str!("../../keel/tests/fixtures/report.json")).unwrap();
        r.budget = None;
        r.duration_ms = 5_000;
        r.nodes = [("a", 1000), ("b", 500), ("c", 3000), ("d", 200)]
            .iter()
            .map(|(n, ms)| Record {
                id: NodeId::new(format!("rust:{n}")),
                key: Digest::Blake3([1; 32]),
                status: Status::Pass,
                reason: None,
                blocked_by: vec![],
                duration_ms: Some(*ms),
                attempt: None,
                detail: None,
                evidence: vec![],
                cached_from: None,
            })
            .collect();
        (r, m)
    }

    #[test]
    fn critical_path_follows_the_slowest_chain_and_thread_time_sums() {
        let (r, m) = setup();
        let s = summarise(&r, Some(&m)).unwrap();
        assert_eq!(s.thread_ms, 4700);
        assert_eq!(s.critical_ms, 4200);
        let ids: Vec<&str> = s.path.iter().map(|(i, _)| i.as_str()).collect();
        assert_eq!(ids, ["rust:a", "rust:c", "rust:d"]);
    }

    #[test]
    fn limits_apply_to_wall_time_and_to_the_critical_path() {
        let (r, m) = setup();
        let s = summarise(&r, Some(&m)).unwrap();
        assert!(over_limit(&s, 10_000).is_none());
        assert!(over_limit(&s, 4_500).unwrap().contains("took"));
        let mut quick = r.clone();
        quick.duration_ms = 100;
        let s = summarise(&quick, Some(&m)).unwrap();
        assert!(over_limit(&s, 4_000).unwrap().contains("critical path"));
        assert!(render(&s, 4_000).contains("rust:c"));
    }

    #[test]
    fn the_reports_own_critical_path_wins_and_no_graph_degrades_loudly() {
        let (mut r, _) = setup();
        r.budget = Some(keel::Budget {
            limit_ms: 1,
            critical_path_ms: 777,
            critical_path: vec![NodeId::new("rust:b")],
        });
        let s = summarise(&r, None).unwrap();
        assert_eq!((s.critical_ms, s.path.len()), (777, 1));
        r.budget = None;
        let s = summarise(&r, None).unwrap();
        assert!(s.source.contains("slowest single node") && s.critical_ms == 3000);
    }
}
