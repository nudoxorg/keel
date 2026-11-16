//! Coverage: is every stands-on edge exercised together by something?
//!
//! An edge A -> B (derived from the code, or declared with `on`) is covered
//! when some test has both A and B among its parts, or when a matrix check on
//! both has a control twin or fault instance that `breaks` A, B or the pair:
//! taking one away makes the check fail, which shows the check depends on it.
//! A check that merely lists both in `on` shows nothing about the pair; it is
//! counted as "declared only" and does not satisfy `policy.uncovered`.
//! `policy.joins` pairs are covered the same way. `of` (instance-of) edges are
//! never coverage edges.
//!
//! A node that owns no code of its own, under package reach, can never be a
//! part of any test, so an uncovered edge from it is reported as
//! unverifiable, not as missing a test.
//!
//! With `policy.uncovered = "report"` the uncovered edges are a ratchet: the
//! ones already in the last accepted lock are infos, a new one is an error.

use crate::finding::{Finding, Severity, short_at};
use crate::model::Model;
use crate::parts::TestParts;
use crate::resolve::Resolution;
use crate::testset::TestTable;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize, Default)]
pub struct CoverageSummary {
    pub policy: String,
    pub edges: usize,
    pub covered_by_tests: usize,
    /// Covered by a matrix check whose twin or fault breaks one of the pair, or the pair.
    pub covered_by_breaking_twin: usize,
    /// Only a matrix check lists both in `on`; it breaks neither, so it is not evidence.
    pub declared_only: usize,
    pub uncovered: usize,
    pub unverifiable: usize,
    /// Uncovered or unverifiable edges missing from the last accepted lock
    /// (only counted under "report" when that lock records them).
    pub new_uncovered: usize,
    /// Edges reported with no accepted baseline to compare against.
    pub no_baseline: usize,
    /// Whether this run was allowed to change the baseline.
    pub accepting: bool,
    pub join_pairs: usize,
    pub joins_uncovered: usize,
}

fn label(res: &Resolution<'_>, n: usize) -> String {
    match &res.nodes[n].at {
        Some(at) => format!("{} ({})", res.nodes[n].id, short_at(at)),
        None => res.nodes[n].id.clone(),
    }
}

pub struct Outcome {
    pub findings: Vec<Finding>,
    pub summary: CoverageSummary,
    /// Every uncovered or unverifiable edge, for the lock.
    pub uncovered: Vec<[String; 2]>,
}

pub fn run(
    model: &Model,
    res: &Resolution<'_>,
    table: &TestTable,
    previous: Option<&BTreeSet<(String, String)>>,
    accept: bool,
) -> Outcome {
    let parts = TestParts::build(res, table);
    let sets: Vec<&BTreeSet<usize>> = parts.distinct().collect();
    let has = |set: &BTreeSet<usize>, n: usize| res.subtree[n].iter().any(|m| set.contains(m));
    let by_tests = |a: usize, b: usize| sets.iter().any(|s| has(s, a) && has(s, b));
    let cargo = !res.index.packages.is_empty();
    let owns_nothing = |n: usize| res.subtree[n].iter().all(|&m| res.nodes[m].own_files == 0);

    // Pairs two nodes are `on` together in some check (declared), and the ones a twin or fault
    // of the same cell breaks (evidence).
    let mut declared: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut broken: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut cells: BTreeMap<(&str, &str), Vec<&crate::model::CheckCell>> = BTreeMap::new();
    for (g, grp) in &model.checks {
        for cell in &grp.checks {
            cells.entry((g.as_str(), cell.cell.as_str())).or_default().push(cell);
        }
    }
    for instances in cells.values() {
        let on: BTreeSet<usize> = instances.iter().flat_map(|c| c.on.iter()).filter_map(|id| res.node_index(id)).collect();
        let on: Vec<usize> = on.into_iter().collect();
        let breaks: Vec<&crate::model::Breaks> = instances.iter().filter_map(|c| c.breaks.as_ref()).collect();
        for (i, &x) in on.iter().enumerate() {
            for &y in &on[i + 1..] {
                declared.insert((x, y));
                let hit = breaks.iter().any(|b| match b {
                    crate::model::Breaks::Node { node } => res.node_index(node).is_some_and(|n| n == x || n == y),
                    crate::model::Breaks::Edge { edge } => {
                        let e: Vec<Option<usize>> = edge.iter().map(|id| res.node_index(id)).collect();
                        e == [Some(x), Some(y)] || e == [Some(y), Some(x)]
                    }
                });
                if hit {
                    broken.insert((x, y));
                }
            }
        }
    }
    let key = |a: usize, b: usize| (a.min(b), a.max(b));

    let edges = crate::enforce::stands_on_edges(res);

    let policy = model.policy.uncovered.clone();
    let mut out = Outcome {
        findings: Vec::new(),
        summary: CoverageSummary {
            policy: policy.clone(),
            edges: edges.len(),
            accepting: accept,
            ..CoverageSummary::default()
        },
        uncovered: Vec::new(),
    };
    for &(a, b) in &edges {
        if by_tests(a, b) {
            out.summary.covered_by_tests += 1;
            continue;
        }
        if broken.contains(&key(a, b)) {
            out.summary.covered_by_breaking_twin += 1;
            continue;
        }
        let declared_only = declared.contains(&key(a, b));
        let unverifiable = cargo && owns_nothing(a);
        if declared_only {
            out.summary.declared_only += 1;
        } else if unverifiable {
            out.summary.unverifiable += 1;
        } else {
            out.summary.uncovered += 1;
        }
        let pair = (res.nodes[a].id.clone(), res.nodes[b].id.clone());
        out.uncovered.push([pair.0.clone(), pair.1.clone()]);
        let known = previous.is_some_and(|p| p.contains(&pair));
        let kind = if unverifiable { "unverifiable-edge" } else { "uncovered-edge" };
        // "fail" makes every one an error. "report" is a ratchet whose baseline only
        // a run with --accept sets or changes: known edges are infos, anything else
        // is an error until it is reviewed and accepted.
        let (severity, code, prefix) = if policy != "report" {
            (Severity::Error, kind, "")
        } else if known {
            (Severity::Info, kind, "")
        } else if accept {
            (Severity::Info, kind, "accepted into the baseline: ")
        } else if previous.is_some() {
            out.summary.new_uncovered += 1;
            (Severity::Error, "new-uncovered-edge", "new uncovered edge: ")
        } else {
            out.summary.no_baseline += 1;
            (Severity::Error, "no-accepted-baseline", "no accepted baseline: review the list and rerun with --accept. ")
        };
        let body = if unverifiable {
            format!(
                "unverifiable: entry-only node under package reach: {} stands on {}, but {} owns no code of its own, \
                 so no test can have it among its parts; only a matrix check whose control or fault `breaks` one of the two would cover the edge.",
                label(res, a),
                label(res, b),
                res.nodes[a].id
            )
        } else if declared_only {
            format!(
                "{} stands on {}, and a matrix check lists both in `on` but no control or fault of it `breaks` either, so the check shows nothing about the pair. \
                 Give the cell a control or fault with `breaks = m.<node>` (or `{{ edge = [ .. ]; }}`) naming one of them.",
                label(res, a),
                label(res, b)
            )
        } else {
            format!(
                "{} stands on {}, and no test has both among its parts and no matrix check has a control or fault that breaks one of them. \
                 Add a test, or a matrix cell whose control `breaks` one of the two.",
                label(res, a),
                label(res, b)
            )
        };
        // What the edges of one kind have in common, for the text report to say once.
        let advice = if unverifiable {
            "Entry-only nodes under package reach own no code, so no test can have them among its parts; only a matrix check whose control or fault `breaks` one of the two would cover the edge."
        } else if declared_only {
            "A matrix check lists both nodes in `on` but no control or fault of it `breaks` either, so it shows nothing about the pair. Give the cell a control or fault with `breaks = m.<node>` (or `{ edge = [ .. ]; }`) naming one of them."
        } else {
            "No test has both nodes among its parts and no matrix check has a control or fault that breaks one of them. Add a test, or a matrix cell whose control `breaks` one of the two."
        };
        let advice = if code == "no-accepted-baseline" { format!("Review the list and rerun with --accept. {advice}") } else { advice.to_owned() };
        let mut f = Finding::new(severity, code, format!("{prefix}{body}"))
            .sharing(format!("{} stands on {}", res.nodes[a].id, res.nodes[b].id), advice);
        f.node = Some(res.nodes[a].id.clone());
        f.at = res.nodes[a].at.clone();
        out.findings.push(f);
    }

    {
        for join in &model.policy.joins {
            let ids: Vec<usize> = join.iter().filter_map(|id| res.node_index(id)).collect();
            for (i, &x) in ids.iter().enumerate() {
                for &y in &ids[i + 1..] {
                    out.summary.join_pairs += 1;
                    if !by_tests(x, y) && !broken.contains(&key(x, y)) {
                        out.summary.joins_uncovered += 1;
                        let mut f = Finding::error(
                            "uncovered-join",
                            format!(
                                "policy.joins asks that {} and {} be exercised together, but no test has both among its parts and no matrix check has a control or fault that breaks one of them{}. \
                                 Add a test or a matrix cell whose control `breaks` one of the two.",
                                label(res, x),
                                label(res, y),
                                if declared.contains(&key(x, y)) { " (a check lists both in `on`, which shows nothing about the pair)" } else { "" }
                            ),
                        );
                        f.node = Some(res.nodes[x].id.clone());
                        f.at = res.nodes[x].at.clone();
                        out.findings.push(f);
                    }
                }
            }
        }
    }
    out
}
