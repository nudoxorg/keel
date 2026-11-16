//! `keel plan`: DESIGN §5.2, Stage 0. Answer "everything is cached" from the
//! canonical manifest and the diff alone, or say exactly why Stage 1 must run.
//!
//! The default answer is "run Stage 1". Every path below that returns "cached"
//! has to prove two things. First, that the changed bytes cannot reach any
//! node's key: every changed path must be owned (a source set, the toolchain
//! list, a package root or a declared glob) and one of the equivalence rules
//! (`lexrule`, `lockrule`, `nixrule`) must prove the change does not alter
//! what the key is computed from; a path nothing owns is an objection, because
//! the sidecar listing the owners may be incomplete. Second, that a pass for
//! each node's key exists: the store is asked, and "cached" is only ever built
//! from the pass it returns.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use keel::{FilesInput, Kind, Manifest, Node, NodeId, Record, Report, SCHEMA, Stages, Status};
use serde::Deserialize;

use crate::git::{DiffEntry, Git, Merge};
use crate::store::Store;
use crate::{lexrule, lockrule, nixrule, util};

/// The sidecar the nextest fork writes next to the manifest (`<manifest>.sources.json`).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    pub schema: u32,
    pub revision: String,
    /// Node id to the repo-relative, forward-slash paths that can affect its key.
    pub source_sets: BTreeMap<String, Vec<String>>,
    /// Package directories; adds, deletes and mode changes under them are inputs.
    pub package_roots: Vec<String>,
    /// Toolchain-level files: `Cargo.lock`, `rust-toolchain.toml`, cargo config.
    pub toolchain: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Installables for the Nix rule (`--nix-check`).
    pub nix_checks: Vec<String>,
    /// Lockfile and regenerating command for the Nickel rule.
    pub nickel: Option<(String, String)>,
}

/// One reason Stage 0 cannot answer; printed as `path: rule: detail`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason {
    pub path: String,
    pub rule: &'static str,
    pub detail: String,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: {}", self.path, self.rule, self.detail)
    }
}

pub enum Outcome {
    Cached {
        report: Box<Report>,
        /// `(path, rule)` for every change an equivalence rule proved harmless.
        accepted: Vec<(String, &'static str)>,
    },
    Stage1(Vec<Reason>),
}

fn stage1(path: &str, rule: &'static str, detail: String) -> Result<Outcome> {
    Ok(Outcome::Stage1(vec![Reason {
        path: path.into(),
        rule,
        detail,
    }]))
}

fn norm_dir(p: &str) -> String {
    let p = p.trim_start_matches("./").trim_end_matches('/');
    if p == "." {
        String::new()
    } else {
        p.to_owned()
    }
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Files whose change can alter how cargo or nextest builds or runs anything,
/// wherever they live: these are never accepted on the ground of a source set.
fn is_builtin_toolchain(p: &str) -> bool {
    let name = basename(p);
    let in_dir = |d: &str| {
        p.rsplit_once('/')
            .is_some_and(|(dir, _)| dir == d || dir.ends_with(&format!("/{d}")))
    };
    matches!(name, "Cargo.toml" | "Cargo.lock")
        || name == "rust-toolchain"
        || name.starts_with("rust-toolchain.")
        || (in_dir(".cargo") && name.starts_with("config"))
        || (in_dir(".config") && matches!(name, "keel.toml" | "nextest.toml"))
}

/// Everything the diff is judged against.
struct Index<'a> {
    nodes: HashMap<&'a str, &'a Node>,
    owners: HashMap<&'a str, Vec<&'a str>>,
    roots: Vec<String>,
    toolchain: HashSet<&'a str>,
    globs: Vec<(String, GlobMatcher)>,
}

impl<'a> Index<'a> {
    fn new(manifest: &'a Manifest, src: &'a Sources) -> Result<Self, String> {
        let nodes: HashMap<&str, &Node> =
            manifest.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        let mut owners: HashMap<&str, Vec<&str>> = HashMap::new();
        for (id, paths) in &src.source_sets {
            if !nodes.contains_key(id.as_str()) {
                return Err(format!(
                    "the sources sidecar lists node `{id}`, which the manifest does not have; regenerate both from the same run"
                ));
            }
            for p in paths {
                owners
                    .entry(p.trim_start_matches("./"))
                    .or_default()
                    .push(id);
            }
        }
        if let Some(n) = manifest
            .nodes
            .iter()
            .find(|n| !src.source_sets.contains_key(n.id.as_str()))
        {
            return Err(format!(
                "node `{}` has no source set in the sidecar, so what can change its key is unknown; the fork must write an entry (even an empty one) for every node",
                n.id
            ));
        }
        let mut globs = Vec::new();
        for n in &manifest.nodes {
            if let Some(FilesInput::Globs(gs)) = &n.inputs.files {
                for g in gs {
                    let m = Glob::new(g).map_err(|e| {
                        format!("node `{}` declares the invalid input glob `{g}`: {e}", n.id)
                    })?;
                    globs.push((g.clone(), m.compile_matcher()));
                }
            }
        }
        Ok(Index {
            nodes,
            owners,
            roots: src.package_roots.iter().map(|r| norm_dir(r)).collect(),
            toolchain: src
                .toolchain
                .iter()
                .map(|t| t.trim_start_matches("./"))
                .collect(),
            globs,
        })
    }

    fn under_root(&self, path: &str) -> Option<&str> {
        self.roots
            .iter()
            .find(|r| {
                r.is_empty()
                    || path
                        .strip_prefix(r.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            })
            .map(|r| if r.is_empty() { "." } else { r.as_str() })
    }

    fn glob(&self, path: &str) -> Option<&str> {
        self.globs
            .iter()
            .find(|(_, m)| m.is_match(path))
            .map(|(g, _)| g.as_str())
    }

    fn owners_text(&self, path: &str) -> String {
        let o = &self.owners[path];
        format!(
            "{} node{} (first: {})",
            o.len(),
            if o.len() == 1 { "" } else { "s" },
            o[0]
        )
    }
}

/// The equivalence rules, with their expensive evaluations done once.
struct Rules<'a> {
    git: &'a Git,
    base: &'a str,
    tree: &'a str,
    opts: &'a Options,
    nix: Option<Result<nixrule::NixComparison, String>>,
    nickel: Option<Result<(), String>>,
    include_literals: Option<Vec<String>>,
}

impl Rules<'_> {
    /// `None`: no rule applies to this path. `Some(Ok(rule))`: proved harmless.
    /// `Some(Err(why))`: a rule applies and refuses.
    fn judge(&mut self, e: &DiffEntry, owners: &[&Node]) -> Option<Result<&'static str, String>> {
        let name = basename(&e.path);
        if name.ends_with(".rs") {
            return Some(
                self.rs(e)
                    .map(|()| "position-preserving")
                    .map_err(|w| format!("position-preserving rule refused: {w}")),
            );
        }
        if name == "Cargo.lock" {
            let r = self
                .blobs(e)
                .and_then(|(a, b)| lockrule::resolves_identically(&a, &b));
            return Some(
                r.map(|()| "lockfile-resolves-identically")
                    .map_err(|w| format!("lockfile rule refused: {w}")),
            );
        }
        if (name.ends_with(".nix") || name == "flake.lock") && !self.opts.nix_checks.is_empty() {
            return Some(
                self.nix(owners)
                    .map(|()| "nix-derivation-unchanged")
                    .map_err(|w| format!("nix rule refused: {w}")),
            );
        }
        if name.ends_with(".ncl")
            && let Some((lock, cmd)) = &self.opts.nickel
        {
            return Some(
                self.nickel(lock, cmd, owners)
                    .map(|()| "nickel-lock-unchanged")
                    .map_err(|w| format!("nickel rule refused: {w}")),
            );
        }
        None
    }

    fn blobs(&self, e: &DiffEntry) -> Result<(Vec<u8>, Vec<u8>), String> {
        let get = |sha: &str| self.git.blob(sha).map_err(|e| e.to_string());
        Ok((get(&e.old_sha)?, get(&e.new_sha)?))
    }

    fn rs(&mut self, e: &DiffEntry) -> Result<(), String> {
        // A file that is also included as bytes or text is observable as data
        // (a golden test comparing against its own source), where a comment is content.
        if self.included_as_data(&e.path)? {
            return Err(format!(
                "`{}` is named in an include_str!/include_bytes!/include! literal, so its text is data some test can read",
                basename(&e.path)
            ));
        }
        let (a, b) = self.blobs(e)?;
        lexrule::position_preserving(&a, &b)
    }

    fn included_as_data(&mut self, path: &str) -> Result<bool, String> {
        if self.include_literals.is_none() {
            let mut lits = Vec::new();
            let files = self
                .git
                .grep_files(self.base, r"include(_str|_bytes)?!", "*.rs")
                .map_err(|e| e.to_string())?;
            for f in files {
                if let Some(bytes) = self.git.blob_at(self.base, &f).map_err(|e| e.to_string())? {
                    let text = String::from_utf8_lossy(&bytes);
                    lits.extend(
                        lexrule::string_literals(&text)
                            .into_iter()
                            .map(str::to_owned),
                    );
                }
            }
            self.include_literals = Some(lits);
        }
        let name = basename(path);
        Ok(self
            .include_literals
            .iter()
            .flatten()
            .any(|l| l.contains(name)))
    }

    /// Every node reading the file must be a Nix node whose derivation the
    /// operator's installables account for; otherwise "the derivation did not
    /// change" says nothing about that node.
    fn covers(owners: &[&Node], drvs: &[String]) -> Result<(), String> {
        for n in owners {
            match (&n.kind, &n.inputs.drv) {
                (Kind::NixCheck, Some(d)) if drvs.contains(d) => {}
                (Kind::NixCheck, _) => {
                    return Err(format!(
                        "node `{}` reads this file but its derivation is not one of the --nix-check installables; list the installable it comes from",
                        n.id
                    ));
                }
                _ => {
                    return Err(format!(
                        "node `{}` ({:?}) reads this file as data, which a derivation path does not describe",
                        n.id, n.kind
                    ));
                }
            }
        }
        Ok(())
    }

    fn nix(&mut self, owners: &[&Node]) -> Result<(), String> {
        if self.nix.is_none() {
            self.nix = Some(nixrule::compare_nix(
                self.git,
                self.base,
                self.tree,
                &self.opts.nix_checks,
            ));
        }
        let c = self.nix.as_ref().unwrap().as_ref().map_err(Clone::clone)?;
        c.unchanged.clone()?;
        Self::covers(owners, &c.base_drvs)
    }

    fn nickel(&mut self, lock: &str, cmd: &str, owners: &[&Node]) -> Result<(), String> {
        for n in owners {
            if n.kind != Kind::NixCheck {
                return Err(format!(
                    "node `{}` ({:?}) reads this file directly, not through {lock}",
                    n.id, n.kind
                ));
            }
        }
        if self.nickel.is_none() {
            self.nickel = Some(nixrule::nickel_unchanged(
                self.git, self.base, self.tree, lock, cmd,
            ));
        }
        self.nickel.clone().unwrap()
    }
}

/// Paths a symlink in `base` points at, resolved lexically from the link's
/// directory; absolute and escaping targets cannot be a repo path and are dropped.
fn symlink_targets(git: &Git, base: &str) -> Result<Vec<(String, String)>> {
    let links = git.symlinks(base)?;
    let shas: Vec<String> = links.iter().map(|(_, s)| s.clone()).collect();
    let blobs = git.small_blobs(&shas, 4096)?;
    let mut out = Vec::new();
    for (path, sha) in links {
        let Some(t) = blobs
            .get(&sha)
            .map(|b| String::from_utf8_lossy(b).into_owned())
        else {
            continue;
        };
        if t.starts_with('/') {
            continue;
        }
        let mut parts: Vec<&str> = path.split('/').collect();
        parts.pop();
        let mut escaped = false;
        for seg in t.split('/') {
            match seg {
                "" | "." => {}
                ".." => escaped |= parts.pop().is_none(),
                s => parts.push(s),
            }
        }
        if !escaped {
            let resolved = parts.join("/");
            out.push((path, resolved));
        }
    }
    Ok(out)
}

pub fn plan(
    repo: &Path,
    base: &str,
    head: &str,
    manifest: Result<Manifest, String>,
    sources: Result<Sources, String>,
    opts: &Options,
    passes: &Store,
) -> Result<Outcome> {
    let started = Instant::now();
    let started_at = util::rfc3339(util::now_secs());
    let git = Git::new(repo);
    let base = git.rev_parse_commit(base)?;
    let head = git.rev_parse_commit(head)?;

    let manifest = match manifest {
        Ok(m) => m,
        Err(why) => {
            return stage1(
                "(manifest)",
                "no-manifest",
                format!("{why}; run Stage 1 to build and key everything"),
            );
        }
    };
    // 1. The manifest must describe exactly the commit the merge is built on.
    if manifest.revision != base
        && git.rev_parse_commit(&manifest.revision).ok().as_deref() != Some(&base)
    {
        return stage1(
            "(manifest)",
            "manifest-revision",
            format!(
                "the manifest is for revision {} but --base is {base}; Stage 0 only answers against the exact canonical tip, so run Stage 1 (it will write a manifest for the new tip)",
                manifest.revision
            ),
        );
    }
    let sources = match sources {
        Ok(s) => s,
        Err(why) => {
            return stage1(
                "(sources)",
                "no-source-sets",
                format!(
                    "{why}; until the fork writes source sets Stage 0 cannot answer, run Stage 1"
                ),
            );
        }
    };
    if sources.schema != SCHEMA || sources.revision != manifest.revision {
        return stage1(
            "(sources)",
            "sources-revision",
            format!(
                "the sidecar is schema {} for revision {} but the manifest is for {}; regenerate both from one canonical run",
                sources.schema, sources.revision, manifest.revision
            ),
        );
    }
    let ix = match Index::new(&manifest, &sources) {
        Ok(ix) => ix,
        Err(why) => return stage1("(sources)", "sources-inconsistent", why),
    };
    // Nodes that never cache cannot be reported cached.
    if let Some(n) = manifest.nodes.iter().find(|n| n.policy.network) {
        return stage1(
            "(manifest)",
            "network-node",
            format!(
                "node `{}` needs the network and never caches (DESIGN §4.4), so it must run; run Stage 1",
                n.id
            ),
        );
    }

    // 2. The merge result.
    let tree = match git.merge_tree(&base, &head)? {
        Merge::Clean { tree } => tree,
        Merge::Conflict { files } => {
            let first = files.first().cloned().unwrap_or_default();
            return stage1(
                &first,
                "merge-conflict",
                format!(
                    "head {head} does not merge onto base {base}; conflicts in {}; Stage 1 will report it, or rebase the PR",
                    files.join(", ")
                ),
            );
        }
    };

    // 3. The diff, and the blobs that could be LFS pointers.
    let diff = git.diff_raw(&base, &tree)?;
    let shas: Vec<String> = diff
        .iter()
        .filter(|e| e.old_mode != 0o160000 && e.new_mode != 0o160000)
        .flat_map(|e| [e.old_sha.clone(), e.new_sha.clone()])
        .filter(|s| s.bytes().any(|b| b != b'0'))
        .collect();
    let small = git.small_blobs(&shas, 1024)?;
    let is_lfs = |sha: &str| {
        small
            .get(sha)
            .is_some_and(|b| b.starts_with(b"version https://git-lfs"))
    };

    // 4. Judge every entry.
    let mut reasons = Vec::new();
    let mut accepted = Vec::new();
    let mut rules = Rules {
        git: &git,
        base: &base,
        tree: &tree,
        opts,
        nix: None,
        nickel: None,
        include_literals: None,
    };
    for e in &diff {
        let mut why = |rule: &'static str, detail: String| {
            reasons.push(Reason {
                path: e.path.clone(),
                rule,
                detail,
            })
        };
        let name = basename(&e.path);
        if e.non_utf8 {
            why("path-encoding", "the path is not valid UTF-8, so it cannot be compared with the source sets; run Stage 1".into());
        } else if e.old_mode == 0o160000 || e.new_mode == 0o160000 {
            why(
                "submodule",
                "a submodule pointer changed; its commit is not in any source set, run Stage 1"
                    .into(),
            );
        } else if e.old_mode == 0o120000 || e.new_mode == 0o120000 {
            why("symlink", "a symlink was added, removed or retargeted; what it points at is not tracked by the source sets".into());
        } else if name == ".gitattributes" || name == ".gitmodules" {
            why(
                "git-config-file",
                format!(
                    "{name} changed; it can change how every file is checked out (filters, eol, submodules)"
                ),
            );
        } else if is_lfs(&e.old_sha) || is_lfs(&e.new_sha) {
            why("lfs-pointer", "the file is a Git LFS pointer, so the bytes a test reads are not the bytes git compared".into());
        } else {
            match judge_entry(e, &ix, &mut rules) {
                Ok(acc) => accepted.push((e.path.clone(), acc)),
                Err((rule, detail)) => why(rule, detail),
            }
        }
    }

    // A modified file that a symlink points at is read through the link.
    if !diff.is_empty() {
        for (link, target) in symlink_targets(&git, &base)? {
            let hit = diff.iter().find(|e| {
                e.path == target
                    || e.path
                        .strip_prefix(&target)
                        .is_some_and(|r| r.starts_with('/'))
            });
            if let Some(e) = hit.filter(|_| !target.is_empty()) {
                reasons.push(Reason { path: e.path.clone(), rule: "symlink-target", detail: format!("changed, and the symlink {link} points at it; a test may read it through the link") });
            }
        }
    }
    if !reasons.is_empty() {
        return Ok(Outcome::Stage1(reasons));
    }

    // 5. The diff cannot reach any key, so every node's manifest key is still
    // its key. "Cached" is a claim about the store, not about the manifest: it
    // is made only from a pass the store returned for that exact key (which it
    // withholds when any run under the key failed, flaked or timed out).
    let mut nodes = Vec::with_capacity(manifest.nodes.len());
    let mut unproven = Vec::new();
    for n in &manifest.nodes {
        let pass = passes.pass(&n.key).with_context(|| {
            format!(
                "cannot ask the store for the pass of node `{}` under key {}; Stage 0 will not report a node cached without it, so fix the store or run Stage 1",
                n.id, n.key
            )
        })?;
        let Some(pass) = pass else {
            unproven.push(Reason {
                path: "(store)".into(),
                rule: "no-stored-pass",
                detail: format!(
                    "node `{}` has no stored pass under key {} (never run, or run under that key with a failing, flaky or timed-out result); Stage 1 must run it",
                    n.id, n.key
                ),
            });
            continue;
        };
        if pass.key != n.key || pass.id != n.id {
            unproven.push(Reason {
                path: "(store)".into(),
                rule: "stored-pass-mismatch",
                detail: format!(
                    "asked for the pass of `{}` under {}, the store returned `{}` under {}; the store is inconsistent, run Stage 1",
                    n.id, n.key, pass.id, pass.key
                ),
            });
            continue;
        }
        nodes.push(Record {
            id: NodeId::new(n.id.as_str()),
            key: n.key,
            status: Status::Cached,
            reason: None,
            blocked_by: vec![],
            duration_ms: None,
            attempt: None,
            detail: None,
            evidence: pass.evidence,
            cached_from: Some(pass.run_id),
        });
    }
    if !unproven.is_empty() {
        return Ok(Outcome::Stage1(unproven));
    }
    let stage0_ms = started.elapsed().as_millis() as u64;
    let mut report = Report {
        schema: SCHEMA,
        run_id: format!(
            "stage0-{}-{}",
            &base[..12.min(base.len())],
            &head[..12.min(head.len())]
        ),
        repo: manifest.repo.clone(),
        revision: tree,
        head: Some(head),
        base: Some(base),
        platform: manifest.platform.clone(),
        verdict: keel::Verdict::Pass,
        started_at,
        duration_ms: stage0_ms,
        budget: None,
        stages: Some(Stages {
            stage0_ms,
            ..Stages::default()
        }),
        counts: keel::Counts::default(),
        roots: vec![],
        nodes,
        flaky: vec![],
        interactions: vec![],
    };
    let expected: Vec<NodeId> = manifest
        .nodes
        .iter()
        .map(|n| NodeId::new(n.id.as_str()))
        .collect();
    report.derive_against(&expected);
    Ok(Outcome::Cached {
        report: Box::new(report),
        accepted,
    })
}

/// `Ok(rule)`: the change was proved harmless by that rule. `Err`: Stage 0
/// cannot answer. There is no third state: a change nothing speaks for is an
/// objection, never silence, because the source sets are only as complete as
/// the sidecar the fork wrote and "no source set names it" does not prove that
/// no test reads it.
type Verdict = Result<&'static str, (&'static str, String)>;

/// The §5.2 conditions for one ordinary entry (not a submodule, symlink,
/// attributes file or LFS pointer, which `plan` has already handled).
fn judge_entry(e: &DiffEntry, ix: &Index, rules: &mut Rules) -> Verdict {
    let path = e.path.as_str();
    let owned = ix.owners.contains_key(path);
    let tool = ix.toolchain.contains(path) || is_builtin_toolchain(path);
    let root = ix.under_root(path);
    let glob = ix.glob(path);

    if e.status != 'M' {
        let what = match e.status {
            'A' => "added",
            'D' => "deleted (or renamed away; renames are off, so a move is a delete and an add)",
            'T' => "changed type",
            _ => "changed in a way Stage 0 does not model",
        };
        let place = if owned {
            format!("is in the source set of {}", ix.owners_text(path))
        } else if tool {
            "is a toolchain or cargo input".into()
        } else if let Some(r) = root {
            format!(
                "is under the package root `{r}`, where cargo auto-discovers targets and build scripts"
            )
        } else if let Some(g) = glob {
            format!("matches the declared input glob `{g}`")
        } else {
            return Err(unowned(what));
        };
        return Err(("path-set-changed", format!("{what}, and {place}")));
    }
    if !(owned || tool || glob.is_some()) {
        return Err(match (e.old_mode != e.new_mode, root) {
            (true, Some(r)) => (
                "mode-changed",
                format!(
                    "the mode changed from {:o} to {:o} under the package root `{r}`",
                    e.old_mode, e.new_mode,
                ),
            ),
            _ => unowned("modified"),
        });
    }
    if e.old_mode != e.new_mode {
        return Err((
            "mode-changed",
            format!(
                "the mode changed from {:o} to {:o} on a file Stage 0 treats as an input",
                e.old_mode, e.new_mode
            ),
        ));
    }
    if let Some(g) = glob {
        return Err((
            "declared-input",
            format!("modified, and matches the declared input glob `{g}`"),
        ));
    }
    let owner_nodes: Vec<&Node> = ix
        .owners
        .get(path)
        .into_iter()
        .flatten()
        .filter_map(|id| ix.nodes.get(id).copied())
        .collect();
    let fallback = || {
        if owned {
            format!(
                "modified, and in the source set of {}",
                ix.owners_text(path)
            )
        } else {
            "modified, and a toolchain or cargo input".to_owned()
        }
    };
    match rules.judge(e, &owner_nodes) {
        Some(Ok(rule)) => Ok(rule),
        Some(Err(why)) => Err(("source-modified", format!("{}; {why}", fallback()))),
        None => Err(("source-modified", fallback())),
    }
}

/// The objection for a changed path that no source set, toolchain list, package
/// root or declared glob accounts for.
fn unowned(what: &str) -> (&'static str, String) {
    (
        "unowned-change",
        format!(
            "{what}, and no source set, toolchain list, package root or declared input glob owns it, so Stage 0 cannot show that no test reads it; run Stage 1, whose exact keys decide"
        ),
    )
}

/// Loads the sidecar for `manifest_path`: `<manifest>.sources.json`.
pub fn read_sources(path: &Path) -> Result<Sources, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!("cannot read the sources sidecar {}: {e}; the nextest fork must write it next to the manifest", path.display())
    })?;
    serde_json::from_str(&text)
        .map_err(|e| format!("{} is not a valid sources sidecar: {e}", path.display()))
}

pub fn read_manifest(path: &Path) -> Result<Manifest> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "cannot read the manifest {}; pass --manifest <file> or --store",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "{} is not a Keel node manifest (DESIGN §8.1)",
            path.display()
        )
    })
}
