//! Where the repository's files come from.
//!
//! The cargo index is one adapter, not a precondition: git and the model are
//! enough for path selectors, worlds, matrices, place rules by `under`, joins
//! and coverage. The cargo index (packages, dependencies, test binaries) is
//! loaded only when the model names crates, modules or `reaching`, and when it
//! cannot be, the fallback below stands in with no packages at all.

use crate::model::{Model, Selector, TestSet};
use anyhow::{Context, Result};
use keel_index::{CodeIndex, Item, SourceFile, Target};
use rayon::prelude::*;
use std::path::Path;
use std::process::Command;

pub enum Source {
    Cargo,
    /// Git only. `reason` says why the cargo index was not used.
    GitOnly { reason: String },
}

fn selector_needs_cargo(s: &Selector) -> bool {
    match s {
        Selector::Within { of, .. } => selector_needs_cargo(of),
        _ => matches!(s, Selector::Crate { .. } | Selector::Module { .. }),
    }
}

fn set_needs_cargo(s: &TestSet) -> bool {
    match s {
        TestSet::Reaching { .. } | TestSet::Package { .. } => true,
        TestSet::Union { sets } | TestSet::Both { sets } => sets.iter().any(set_needs_cargo),
        TestSet::Minus { left, right } => set_needs_cargo(left) || set_needs_cargo(right),
        _ => false,
    }
}

fn policy_needs_cargo(p: &crate::model::Policy) -> bool {
    p.deploy_gate.iter().chain(p.idle.iter().filter_map(|i| i.mutate.as_ref())).any(set_needs_cargo)
}

/// Whether the model says anything only the cargo package graph can answer.
/// Patterns do not: ast-grep reads the tracked files, and Rust matches map to index functions only when the index is loaded.
pub fn needs_cargo(model: &Model) -> bool {
    model.nodes_from_crates.is_some()
        || model
            .nodes
            .iter()
            .any(|n| n.code.iter().chain(&n.entry).any(selector_needs_cargo))
        || model.worlds.iter().any(|w| w.inputs.iter().any(selector_needs_cargo))
        || model
            .checks
            .values()
            .any(|g| g.checks.iter().any(|c| c.inputs.iter().any(selector_needs_cargo)))
        || model.place.iter().any(|r| set_needs_cargo(&r.tests))
        || policy_needs_cargo(&model.policy)
}

/// Loads the cargo index when `want_cargo`; falls back to git alone when it
/// is not wanted or cannot be built.
pub fn load(root: &Path, cache: Option<&Path>, want_cargo: bool) -> Result<(CodeIndex, Source)> {
    if want_cargo {
        match CodeIndex::build(root, cache) {
            Ok(index) => return Ok((index, Source::Cargo)),
            Err(e) => {
                let index = git_only(root)?;
                return Ok((index, Source::GitOnly { reason: e.to_string() }));
            }
        }
    }
    Ok((
        git_only(root)?,
        Source::GitOnly {
            reason: "the model names no crate, module or reaching set, so the cargo index was not loaded".to_owned(),
        },
    ))
}

/// Prefix of the `parse_error` of a file that is tracked and cannot be read.
pub const UNREADABLE: &str = "unreadable";

/// Tracked Rust files the index could not read, with why.
pub fn unreadable(index: &CodeIndex) -> Vec<(&str, &str)> {
    index
        .files
        .iter()
        .filter_map(|f| f.parse_error.as_deref().filter(|e| e.starts_with(UNREADABLE) || e.starts_with("cannot read the file")).map(|e| (f.path.as_str(), e)))
        .collect()
}

/// Every tracked file, no packages, and the tests found by parsing tracked
/// `.rs` files (nothing about which binary they belong to).
pub fn git_only(root: &Path) -> Result<CodeIndex> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .with_context(|| format!("cannot run git in {}", root.display()))?;
    if !out.status.success() {
        anyhow::bail!(
            "{} is not a git checkout ({}); keel-tree reads files with `git ls-files`, so run it on a repository",
            root.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let mut paths: Vec<String> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    paths.sort();
    paths.dedup();
    let pool = rayon::ThreadPoolBuilder::new()
        .stack_size(64 << 20)
        .build()
        .context("cannot start the parser pool")?;
    let scans: Vec<Option<keel_index::parse::FileScan>> = pool.install(|| {
        paths
            .par_iter()
            .map(|p| {
                if !p.ends_with(".rs") {
                    return None;
                }
                // A file git lists and the disk cannot give is kept, with why, not dropped: `check`
                // counts these (see `unreadable`).
                Some(match std::fs::read(root.join(p)) {
                    Ok(b) => keel_index::parse::scan_bytes(&b),
                    Err(e) => {
                        let mut scan = keel_index::parse::scan_source("");
                        scan.parse_error = Some(format!("{UNREADABLE}: {e}"));
                        scan
                    }
                })
            })
            .collect()
    });
    let mut files = Vec::with_capacity(paths.len());
    let mut items = Vec::new();
    for (i, (p, scan)) in paths.iter().zip(&scans).enumerate() {
        files.push(SourceFile {
            path: p.clone(),
            package: None,
            target: Target::Other,
            content: [0; 32],
            parse_error: scan.as_ref().and_then(|s| s.parse_error.clone()),
        });
        for it in scan.iter().flat_map(|s| &s.items).filter(|it| it.is_test) {
            items.push(Item {
                file: i as u32,
                path: it.path.clone(),
                start_line: it.start_line,
                end_line: it.end_line,
                tokens: it.tokens,
                signature: it.signature,
                branches: it.branches,
                is_test: true,
                ignored: it.ignored,
                in_test_code: true,
            });
        }
    }
    Ok(CodeIndex {
        root: root.to_path_buf(),
        packages: Vec::new(),
        files,
        items,
        graph_note: None,
    })
}
