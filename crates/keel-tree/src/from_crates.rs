//! `nodesFromCrates`: the nodes nobody wrote because a crate says all there is to say about them.
//!
//! A node of one `crate` selector and nothing else is the package's name over again. The model
//! asks for those to be made, and says how the name becomes an id; what has more to say than a
//! package (an `about`, several crates, children, `on` laws) is still written by hand.

use crate::finding::Finding;
use crate::model::{Model, ModelNode, NodesFromCrates, Selector};
use crate::resolve::UNOWNED;
use globset::{GlobBuilder, GlobMatcher};
use keel_index::CodeIndex;
use std::collections::{BTreeMap, BTreeSet};

/// `backend-store` and `backend_store` are the same crate to Rust.
fn norm(name: &str) -> String {
    name.replace('-', "_")
}

/// The id a package gets: its name without `strip` at the front, and as it is when it does not
/// start with it.
pub fn id_of(strip: &str, package: &str) -> String {
    package.strip_prefix(strip).unwrap_or(package).to_owned()
}

/// One top-level node for every workspace member that no node claims with a `crate` selector and
/// whose manifest directory matches one of `under`, in package-name order so the lock and the reports do not depend on the index's order. A
/// package that cannot become a node is a finding that names it, and gets none.
///
/// A path or module selector does not claim a crate: such a package still gets its node, and
/// the more specific selector keeps the files it names, as it does against any crate selector.
pub fn nodes(model: &Model, index: &CodeIndex, no_cargo: Option<&str>) -> (Vec<ModelNode>, Vec<Finding>) {
    let Some(NodesFromCrates { strip, under, at }) = &model.nodes_from_crates else {
        return (Vec::new(), Vec::new());
    };
    let at = at.clone().unwrap_or_else(|| "nodesFromCrates".to_owned());
    if let Some(why) = no_cargo {
        return (
            Vec::new(),
            vec![Finding::error(
                "cargo-required",
                format!(
                    "nodesFromCrates ({at}) makes a node for each workspace package, and the cargo package index is not available ({why}). \
                     Run on a cargo workspace, or write the nodes by hand and remove nodesFromCrates."
                ),
            )],
        );
    }
    // A glob that cannot match is a typo that would silently leave packages out.
    let mut dirs: Vec<GlobMatcher> = Vec::new();
    let mut findings = Vec::new();
    for glob in under {
        let matcher = match GlobBuilder::new(glob).literal_separator(true).build() {
            Ok(g) => g.compile_matcher(),
            Err(e) => {
                let mut f = Finding::error("bad-glob", format!("nodesFromCrates.under \"{glob}\" does not parse ({e}); fix the glob."));
                f.at = Some(at.clone());
                findings.push(f);
                continue;
            }
        };
        if !index.packages.iter().any(|p| p.member && matcher.is_match(&p.dir)) {
            let mut f = Finding::error(
                "selector-matches-nothing",
                format!("nodesFromCrates.under \"{glob}\" is not the directory of any workspace package, so it makes no node. Fix the glob or remove it."),
            );
            f.at = Some(at.clone());
            findings.push(f);
        }
        dirs.push(matcher);
    }
    let claimed: BTreeSet<String> = model
        .nodes
        .iter()
        .flat_map(|n| &n.code)
        .filter_map(|s| match s {
            Selector::Crate { name } => Some(norm(name)),
            _ => None,
        })
        .collect();
    let written: BTreeMap<&str, &ModelNode> = model.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut packages: Vec<&str> =
        index.packages.iter().filter(|p| p.member && dirs.iter().any(|d| d.is_match(&p.dir))).map(|p| p.name.as_str()).collect();
    packages.sort_unstable();
    let mut out = Vec::<ModelNode>::new();
    for package in packages.into_iter().filter(|p| !claimed.contains(&norm(p))) {
        let id = id_of(strip, package);
        let collision = if id.is_empty() {
            Some(format!(
                "package \"{package}\" is all of `strip` (\"{strip}\"), so its node would have no name. Claim the crate in a node written by hand, or choose a `strip` that leaves a name."
            ))
        } else if id == UNOWNED {
            Some(format!(
                "package \"{package}\" would become node \"{id}\", the name the engine gives to the files no node claims. Claim the crate in a node written by hand under another name."
            ))
        } else if let Some(n) = written.get(id.as_str()) {
            Some(format!(
                "package \"{package}\" would become node \"{id}\", which the model already writes ({}). Claim the crate in that node with `crate \"{package}\"`, or write a node for it by hand under another name.",
                n.source.as_deref().unwrap_or(&n.at)
            ))
        } else {
            out.iter().find(|d| d.id == id).map(|d| {
                format!(
                    "packages \"{}\" and \"{package}\" would both become node \"{id}\". Claim one of them in a node written by hand under another name.",
                    d.from_crate.as_deref().unwrap_or_default()
                )
            })
        };
        if let Some(why) = collision {
            let mut f = Finding::error("node-from-crate-collision", format!("nodesFromCrates ({at}): {why}"));
            f.at = Some(at.clone());
            findings.push(f);
            continue;
        }
        out.push(ModelNode {
            id,
            at: at.clone(),
            source: None,
            parent: None,
            about: None,
            code: vec![Selector::Crate { name: package.to_owned() }],
            entry: Vec::new(),
            on: Vec::new(),
            never: Vec::new(),
            of: Vec::new(),
            ship: None,
            lag: None,
            moved_by: Vec::new(),
            unmoved_by: Vec::new(),
            from_crate: Some(package.to_owned()),
        });
    }
    (out, findings)
}
