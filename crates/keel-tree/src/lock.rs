//! The lock: the derived graph, written sorted so a pull request that changes
//! the shape of the product shows it as a plain diff.
//!
//! It is written only when `check` has no errors; a run with errors writes
//! `<lock>.rejected` and leaves the last accepted lock alone, so the diff is
//! always against something that was accepted.

use crate::resolve::{EdgeKind, Resolution};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lock {
    pub schema: u32,
    pub nodes: BTreeMap<String, LockNode>,
    /// Stands-on edges nothing exercises together (`[from, to]`), the ratchet's
    /// baseline. Absent in locks written before the ratchet existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncovered: Option<Vec<[String; 2]>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockNode {
    pub parent: Option<String>,
    /// The package `nodesFromCrates` made the node for. A node the model writes has none, so a
    /// node that moves between the two shows in the diff even though its edges do not move.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_crate: Option<String>,
    /// Files the node owns itself. Independent of cargo.
    #[serde(default)]
    pub files: Option<usize>,
    /// sha256 over the sorted owned paths, one per line, so a changed owned
    /// set shows in the diff even when the count does not move.
    #[serde(default)]
    pub files_digest: Option<String>,
    /// Pattern matches the node owns (`code`) or starts from (`entry`), counted and hashed by what
    /// they are (path, kind, name), not by line, so editing above a match does not move the lock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ranges: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ranges_digest: Option<String>,
    /// `option` and `drv` selectors the node carries, as written; keel-tree
    /// cannot resolve them, so they are recorded rather than dropped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unsupported: Vec<serde_json::Value>,
    /// Only when the cargo index was loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packages: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_packages: Option<Vec<String>>,
    pub stands_on: Vec<LockEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockEdge {
    pub to: String,
    pub kind: EdgeKind,
    /// Kept after transitive reduction: the edge the tree shows.
    pub reduced: bool,
    /// The edge exists only because of an `of` (instance-of) law.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub of: bool,
}

fn digest(paths: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in paths {
        h.update(p.as_bytes());
        h.update(b"\n");
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl<'a> Resolution<'a> {
    pub fn lock(&self, uncovered: &[[String; 2]]) -> Lock {
        let cargo = !self.index.packages.is_empty();
        let mut nodes = BTreeMap::new();
        for (i, n) in self.nodes.iter().enumerate() {
            let pk = |s: &BTreeSet<u32>| -> Vec<String> {
                let mut v: Vec<String> = s.iter().map(|&p| self.pkg_name(p).to_owned()).collect();
                v.sort();
                v
            };
            let mut stands_on: Vec<LockEdge> = self
                .edges
                .range((i, 0)..(i + 1, 0))
                .map(|(&(_, b), e)| LockEdge {
                    to: self.nodes[b].id.clone(),
                    kind: e.kind,
                    reduced: e.kind == EdgeKind::Product && self.reduced.contains(&(i, b)),
                    of: self.is_instance_only(i, b),
                })
                .collect();
            stands_on.sort();
            let owned = self.owned_paths(i);
            let mut sites: Vec<String> =
                self.sites.iter().filter(|s| s.node == i).map(|s| format!("{}\t{}", if s.entry { "entry" } else { "code" }, s.key)).collect();
            sites.sort();
            sites.dedup();
            nodes.insert(
                n.id.clone(),
                LockNode {
                    parent: n.parent.map(|p| self.nodes[p].id.clone()),
                    from_crate: n.from_crate.clone(),
                    files: Some(owned.len()),
                    files_digest: Some(digest(&owned)),
                    ranges: (!sites.is_empty()).then_some(sites.len()),
                    ranges_digest: (!sites.is_empty()).then(|| digest(&sites.iter().map(String::as_str).collect::<Vec<_>>())),
                    unsupported: n.unsupported.clone(),
                    packages: cargo.then(|| pk(&n.own_pkgs)),
                    entry_packages: cargo.then(|| pk(&n.entry_pkgs)),
                    stands_on,
                },
            );
        }
        let mut uncovered = uncovered.to_vec();
        uncovered.sort();
        uncovered.dedup();
        Lock {
            schema: 2,
            nodes,
            uncovered: Some(uncovered),
        }
    }
}

/// Human lines describing how `new` differs from `old`; empty when equal.
pub fn diff(old: &Lock, new: &Lock) -> Vec<String> {
    let mut out = Vec::new();
    for id in old.nodes.keys().filter(|k| !new.nodes.contains_key(*k)) {
        out.push(format!("node removed: {id}"));
    }
    for (id, n) in &new.nodes {
        let Some(o) = old.nodes.get(id) else {
            out.push(format!("node added: {id}"));
            continue;
        };
        match (&o.from_crate, &n.from_crate) {
            (None, Some(p)) => out.push(format!("{id}: now derived from package {p} (nodesFromCrates), no longer written by hand")),
            (Some(p), None) => out.push(format!("{id}: no longer derived from package {p}; the model writes it")),
            (Some(a), Some(b)) if a != b => out.push(format!("{id}: now derived from package {b}, not {a}")),
            _ => {}
        }
        let set = |v: &Option<Vec<String>>| v.iter().flatten().cloned().collect::<BTreeSet<_>>();
        if o.packages.is_some() && n.packages.is_some() {
            for p in set(&n.packages).difference(&set(&o.packages)) {
                out.push(format!("{id}: now owns package {p}"));
            }
            for p in set(&o.packages).difference(&set(&n.packages)) {
                out.push(format!("{id}: no longer owns package {p}"));
            }
        }
        if let (Some(of), Some(nf), Some(od), Some(nd)) = (o.files, n.files, &o.files_digest, &n.files_digest)
            && od != nd
        {
            out.push(format!(
                "{id}: owned files changed ({of} -> {nf}, digest {} -> {})",
                &od[..od.len().min(12)],
                &nd[..nd.len().min(12)]
            ));
        }
        if o.ranges_digest != n.ranges_digest {
            out.push(format!(
                "{id}: pattern matches changed ({} -> {})",
                o.ranges.unwrap_or(0),
                n.ranges.unwrap_or(0)
            ));
        }
        if o.unsupported != n.unsupported {
            out.push(format!("{id}: unsupported selectors changed ({} -> {})", o.unsupported.len(), n.unsupported.len()));
        }
        let key = |e: &LockEdge| (e.to.clone(), e.kind, e.of);
        let oe: BTreeSet<_> = o.stands_on.iter().map(key).collect();
        let ne: BTreeSet<_> = n.stands_on.iter().map(key).collect();
        let how = |kind: &EdgeKind, of: &bool| if *of { "instance of".to_owned() } else { format!("stands on ({kind:?})") };
        for (to, kind, of) in ne.difference(&oe) {
            out.push(format!("{id}: now {} {to}", how(kind, of)));
        }
        for (to, kind, of) in oe.difference(&ne) {
            out.push(format!("{id}: no longer {} {to}", how(kind, of)));
        }
    }
    if let (Some(ou), Some(nu)) = (&o_unc(old), &o_unc(new)) {
        for e in nu.difference(ou) {
            out.push(format!("uncovered edge added: {} -> {}", e.0, e.1));
        }
        for e in ou.difference(nu) {
            out.push(format!("uncovered edge gone: {} -> {}", e.0, e.1));
        }
    }
    out
}

fn o_unc(l: &Lock) -> Option<BTreeSet<(String, String)>> {
    l.uncovered
        .as_ref()
        .map(|v| v.iter().map(|e| (e[0].clone(), e[1].clone())).collect())
}

/// The uncovered edges of a lock as pairs, if it records them.
pub fn uncovered_set(l: &Lock) -> Option<BTreeSet<(String, String)>> {
    o_unc(l)
}
