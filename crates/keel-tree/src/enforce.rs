//! Policy the model states that `check` holds the code to, and the account of what it reads
//! but does not hold anyone to yet.
//!
//! * `policy.faults`: a stands-on edge A -> B asks whether anything has ever taken B away.
//! * `policy.inert`: files that can change nothing, each with its reason and what it matches.
//! * "read and not yet enforced": every part of the model that has a typed home and no rule.

use crate::finding::{Finding, Severity};
use crate::model::{Breaks, Model, Selector};
use crate::resolve::Resolution;
use globset::GlobBuilder;
use serde::Serialize;
use std::collections::BTreeSet;

/// Every stands-on edge A -> B the code or an `on` law gives, as node indices. `unowned` is not
/// part of an edge: it stands on nothing and everything stands on it.
pub fn stands_on_edges(res: &Resolution<'_>) -> BTreeSet<(usize, usize)> {
    let mut edges: BTreeSet<(usize, usize)> = res
        .derived_pairs
        .iter()
        .copied()
        .filter(|&(a, b)| a != res.unowned && b != res.unowned)
        .collect();
    for (a, n) in res.nodes.iter().enumerate().take(res.unowned) {
        for &x in &n.on {
            if x != a {
                edges.insert((a, x));
            }
        }
    }
    edges
}

#[derive(Debug, Serialize, Default)]
pub struct FaultSummary {
    pub policy: String,
    pub edges: usize,
    /// Edges whose lower end some fault check instance takes away.
    pub faulted: usize,
    /// Edges excused by a `policy.unfaulted` entry.
    pub excused: usize,
    pub unfaulted: usize,
}

/// `policy.faults`: for every edge A -> B, some fault check instance must `break` B (or the
/// edge), else the edge is a finding, an error under "fail" and an info under "report", unless
/// an `unfaulted` entry excuses it. An entry that names no edge is an error.
pub fn fault_findings(model: &Model, res: &Resolution<'_>) -> (Vec<Finding>, FaultSummary) {
    let edges = stands_on_edges(res);
    let mut out = Vec::new();
    let mut summary = FaultSummary { policy: model.policy.faults.clone(), edges: edges.len(), ..FaultSummary::default() };
    // What fault instances take away: nodes, and edges as written.
    let mut broken_nodes: BTreeSet<usize> = BTreeSet::new();
    let mut broken_edges: BTreeSet<(usize, usize)> = BTreeSet::new();
    for cell in model.checks.values().flat_map(|g| g.checks.iter()).filter(|c| !c.faults.is_empty()) {
        match &cell.breaks {
            Some(Breaks::Node { node }) => broken_nodes.extend(res.node_index(node)),
            Some(Breaks::Edge { edge }) => {
                if let (Some(a), Some(b)) = (res.node_index(&edge[0]), res.node_index(&edge[1])) {
                    broken_edges.insert((a, b));
                    broken_edges.insert((b, a));
                }
            }
            None => {}
        }
    }
    // A node is taken away when a fault breaks it or any node inside it.
    let node_faulted = |n: usize| res.subtree[n].iter().any(|m| broken_nodes.contains(m));
    let mut excuses: Vec<(usize, usize, &str, bool)> = Vec::new();
    for u in &model.policy.unfaulted {
        match (res.node_index(&u.from), res.node_index(&u.to)) {
            (Some(a), Some(b)) if edges.contains(&(a, b)) => excuses.push((a, b, u.reason.as_str(), false)),
            (a, b) => {
                let why = if a.is_none() || b.is_none() {
                    format!("{} is not a node of the model", if a.is_none() { &u.from } else { &u.to })
                } else {
                    format!("{} does not stand on {}", u.from, u.to)
                };
                out.push(Finding::error(
                    "unfaulted-names-no-edge",
                    format!(
                        "policy.unfaulted excuses \"{} stands on {}\" ({}), but {why}. An excuse for an edge that is not there would silently excuse it if it came back; remove the entry.",
                        u.from, u.to, u.reason
                    ),
                ));
            }
        }
    }
    for &(a, b) in &edges {
        if node_faulted(b) || broken_edges.contains(&(a, b)) {
            summary.faulted += 1;
            continue;
        }
        if let Some(e) = excuses.iter_mut().find(|e| e.0 == a && e.1 == b) {
            e.3 = true;
            summary.excused += 1;
            continue;
        }
        summary.unfaulted += 1;
        let (na, nb) = (&res.nodes[a], &res.nodes[b]);
        let severity = if model.policy.faults == "report" { Severity::Info } else { Severity::Error };
        let mut f = Finding::new(
            severity,
            "edge-never-faulted",
            format!(
                "{} stands on {}; nothing has ever taken {} away. Add a fault check whose `breaks` names {} (or the edge), or excuse the edge in `policy.unfaulted` with a reason.",
                na.id, nb.id, nb.id, nb.id
            ),
        )
        .sharing(
            format!("{} stands on {}", na.id, nb.id),
            "Nothing has ever taken the lower node of these edges away. Add a fault check whose `breaks` names the lower node (or the edge), or excuse the edge in `policy.unfaulted` with a reason.".to_owned(),
        );
        f.node = Some(na.id.clone());
        f.at = na.at.clone();
        out.push(f);
    }
    (out, summary)
}

#[derive(Debug, Serialize)]
pub struct InertLine {
    pub glob: String,
    pub reason: String,
    /// Tracked files the glob matches.
    pub files: usize,
}

/// Each `policy.inert` entry with its reason and how many tracked files it matches.
pub fn inert_report(model: &Model, res: &Resolution<'_>) -> Vec<InertLine> {
    model
        .policy
        .inert
        .iter()
        .filter_map(|s| match s {
            Selector::Path { glob, reason } => {
                let m = GlobBuilder::new(glob).literal_separator(true).build().ok()?.compile_matcher();
                Some(InertLine {
                    glob: glob.clone(),
                    reason: reason.clone().unwrap_or_else(|| "(no reason given)".to_owned()),
                    files: res.tracked_files().iter().filter(|f| m.is_match(f)).count(),
                })
            }
            _ => None,
        })
        .collect()
}

#[derive(Debug, Serialize)]
pub struct Unenforced {
    /// The part of the model, by the name the library uses.
    pub name: String,
    /// How many times the model uses it.
    pub count: usize,
    pub what: &'static str,
}

/// Parts of the model that are read into typed fields and that no rule of `check`, `plan` or
/// `explain` acts on yet, with how often the model uses each. Listing them is what keeps a read
/// field from being mistaken for an enforced one.
pub fn unenforced(model: &Model) -> Vec<Unenforced> {
    let mut out = Vec::new();
    let mut add = |name: &str, count: usize, what: &'static str| {
        if count > 0 {
            out.push(Unenforced { name: name.to_owned(), count, what });
        }
    };
    let w = &model.worlds;
    add("world.step", w.iter().filter(|w| !w.step.is_empty()).count(), "the command that builds the world is not run or checked");
    add("world.keep", w.iter().filter(|w| w.keep.is_some()).count(), "what is kept of the built state");
    add("world.about", w.iter().filter(|w| w.about.is_some()).count(), "prose");
    add("world.maxAgeMinutes", w.iter().filter(|w| w.max_age_minutes.is_some()).count(), "snapshot age limit is not applied");
    add("world.machines", w.iter().filter(|w| w.machines.is_some()).count(), "machine names are not checked against fault targets here (the library checks them)");
    add("world.env", w.iter().filter(|w| !w.env.is_empty()).count(), "environment, including `within` and `state` selectors, is resolved by the driver, not here");
    add("world.tools", w.iter().filter(|w| !w.tools.is_empty()).count(), "tools on PATH are not resolved or checked");
    add("world.network", w.iter().filter(|w| w.network).count(), "network access is not enforced");
    add("world.readyWithin", w.iter().filter(|w| w.ready_within.is_some()).count(), "the step's time limit is not applied");
    let cells: Vec<&crate::model::CheckCell> = model.checks.values().flat_map(|g| g.checks.iter()).collect();
    add("check.run", cells.iter().filter(|c| !c.run.is_empty()).count(), "the command is not run by keel-tree");
    add("check.expect", cells.iter().filter(|c| !c.expect.is_null()).count(), "expectations are read by the driver");
    add("check.at", cells.iter().filter(|c| c.at.is_some()).count(), "the machine a check runs on");
    add("check.as", cells.iter().filter(|c| c.run_as.is_some()).count(), "the identity a check runs as");
    add("check.together", cells.iter().filter(|c| c.together.is_some()).count(), "cells sharing one run are not grouped");
    add("check.dims", cells.iter().filter(|c| !c.dims.is_empty()).count(), "cell dimensions beyond the cell's name");
    let faults: Vec<&crate::model::Fault> = cells.iter().flat_map(|c| c.faults.iter()).collect();
    add("fault.kind/target/hold/during/after/recoverWithin", faults.len(), "only that a fault exists and what it breaks is used (policy.faults); injection is the driver's");
    add("fault.inject/heal", faults.iter().filter(|f| f.inject.is_some() || f.heal.is_some()).count(), "custom commands are not run");
    add("census.observe", model.census.iter().filter(|c| c.observe.is_some()).count(), "observation commands are not run (see `census-not-run`)");
    add("census.declared/ignore/axes/world", model.census.iter().filter(|c| !c.declared.is_empty() || !c.ignore.is_empty() || !c.axes.is_empty() || c.world.is_some()).count(), "compared by the library when observed in the model; for a command only the driver can");
    add("census.inputs", model.census.iter().filter(|c| !c.inputs.is_empty()).count(), "not used to decide when a census must rerun");
    add("census.on", model.census.iter().filter(|c| !c.on.is_empty()).count(), "not used to attribute census findings to nodes");
    add("place[].world", model.place.iter().filter(|r| r.world.is_some()).count(), "the world a placed test starts in");
    add("policy.idle", usize::from(model.policy.idle.is_some()), "idle-time mutation and `recheckOneIn` are the scheduler's");
    add("policy.deployGate", usize::from(model.policy.deploy_gate.is_some()), "the set is counted and must select something; nothing gates a deploy here");
    out
}

/// A one-line finding for keys the typed model could not place.
pub fn unread_finding(model: &Model) -> Option<Finding> {
    if model.unread.is_empty() {
        return None;
    }
    let shown: Vec<&str> = model.unread.iter().take(8).map(String::as_str).collect();
    Some(Finding::warning(
        "model-field-unread",
        format!(
            "the model has {} keys no typed field of keel-tree reads, so nothing here acts on or lists them: {}{}. \
             nix/keel/lib.nix is newer than this keel-tree; add the fields to crates/keel-tree/src/model.rs.",
            model.unread.len(),
            shown.join(", "),
            if model.unread.len() > shown.len() { ", ..." } else { "" }
        ),
    ))
}
