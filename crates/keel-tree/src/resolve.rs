//! Resolution: joins the model to a code index.
//!
//! Order of work, because each step stands on the previous one:
//! 1. compile selectors and give every source file at most one owning node;
//! 2. derive which node stands on which from the package graph;
//! 3. check the laws the model states about those facts.
//!
//! Everything errs toward "more is related": a package that has one file owned
//! by a node contributes all of its dependencies to that node, because the
//! index cannot see which file uses which dependency.

use crate::finding::{Finding, Severity, short_at};
use crate::model::{Model, Selector};
use crate::text::{list, near};
use globset::{GlobBuilder, GlobMatcher};
use keel_index::{CodeIndex, SourceFile};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::Path;
use std::rc::Rc;

mod sites;
use sites::{pattern_coverage, scanned};

/// The synthetic node for workspace-package files no node claims.
pub const UNOWNED: &str = "unowned";

#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    /// None for the synthetic `unowned` node.
    pub at: Option<String>,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    pub about: Option<String>,
    /// The package `nodesFromCrates` made this node for; None for a node the model writes.
    pub from_crate: Option<String>,
    pub ship: Option<String>,
    /// (at most minutes, confidence) of a `may-lag` node.
    pub lag: Option<(u64, f64)>,
    pub on: Vec<usize>,
    pub never: Vec<usize>,
    /// Instance-of targets: stands-on edges that are never coverage edges.
    pub of: Vec<usize>,
    /// `option` and `drv` selectors the node carries, raw, for the lock.
    pub unsupported: Vec<serde_json::Value>,
    pub moved_by: Vec<String>,
    pub unmoved_by: Vec<String>,
    /// Files this node owns itself, not through descendants.
    pub own_files: usize,
    /// Packages with at least one file this node owns itself.
    pub own_pkgs: BTreeSet<u32>,
    /// Packages holding files that this node's `entry` selectors matched.
    pub entry_pkgs: BTreeSet<u32>,
    pub entry_files: Vec<u32>,
}

/// One match of a pattern selector: a range of a file that a node owns (`code`) or starts
/// from (`entry`).
#[derive(Debug, Clone)]
pub struct Site {
    pub node: usize,
    pub entry: bool,
    pub path: String,
    /// 1-based, inclusive.
    pub start_line: u32,
    pub end_line: u32,
    /// The named item the match is or lies in, in the language's own words.
    pub enclosing: Option<crate::pattern::Enclosing>,
    /// The keel-index function the range lies in, for Rust files the cargo index holds.
    pub item: Option<u32>,
    /// What identifies the match in the lock: stable while the range only moves.
    pub key: String,
    pub pkg: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// Matched by `policy.inert` and claimed by no node: the one way a tracked
    /// file may belong to nothing.
    Inert,
    Node(usize),
    /// Two nodes claimed it at the same specificity; it counts for neither.
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EdgeKind {
    Product,
    Dev,
}

/// Why an edge exists, so a violated law can name a real dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Witness {
    /// `from` depends on `to`.
    Packages(u32, u32),
    /// An entry selector matched this file, which `to` owns (a path selector).
    Entry(u32),
    /// An entry pattern matched this site (an index into `Resolution::sites`), whose range `to` owns.
    Site(u32),
    /// Declared by an `on` law, used when there is no package graph to derive from.
    Declared,
    /// Declared by an `of` (instance-of) law.
    Instance,
}

#[derive(Debug, Clone)]
pub struct Edge {
    pub kind: EdgeKind,
    pub witness: Witness,
}

/// How specific a selector is, most specific greatest: a pattern beats a module,
/// a module beats a path, a path beats a crate; among paths the longer literal
/// prefix of the glob wins.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Spec {
    rank: u8,
    prefix: usize,
}

impl Spec {
    const CRATE: Spec = Spec { rank: 1, prefix: 0 };
    const MODULE: Spec = Spec { rank: 3, prefix: 0 };
    const PATTERN: Spec = Spec { rank: 4, prefix: 0 };
    fn path(glob: &str) -> Spec {
        let prefix = glob.find(['*', '?', '[', '{']).unwrap_or(glob.len());
        Spec { rank: 2, prefix }
    }
    fn name(self) -> &'static str {
        match self.rank {
            1 => "crate",
            2 => "path",
            3 => "module",
            _ => "pattern",
        }
    }
}

enum Matcher {
    Crate(u32),
    /// Crate then module segments, with the crate normalised to `_` spelling.
    Module(u32, Vec<String>),
    Path(GlobMatcher),
    /// A resolved pattern. It selects ranges of files, not files, so it is never asked
    /// about a whole file: `assign_pattern_sites` places its matches.
    Pattern(Rc<crate::pattern::Hits>),
}

struct Compiled {
    node: usize,
    entry: bool,
    /// Glob text for path selectors, so a miss can say what it looked for.
    glob: String,
    spec: Spec,
    matcher: Matcher,
    matched: usize,
}

pub struct Resolution<'a> {
    pub index: &'a CodeIndex,
    pub nodes: Vec<Node>,
    pub unowned: usize,
    pub file_owner: Vec<Owner>,
    /// Nodes owning any file of each package.
    pub pkg_owners: Vec<BTreeSet<usize>>,
    pub edges: BTreeMap<(usize, usize), Edge>,
    /// Product edges only / product and dev edges.
    pub prod: Vec<BTreeSet<usize>>,
    pub all: Vec<BTreeSet<usize>>,
    /// Product edges after transitive reduction (edges inside a cycle stay).
    pub reduced: BTreeSet<(usize, usize)>,
    /// Node pairs the code, an entry or an `on` law gives (coverage edges).
    pub derived_pairs: BTreeSet<(usize, usize)>,
    /// Node pairs given by `of`.
    pub instance_pairs: BTreeSet<(usize, usize)>,
    /// Packages with files no node claims; vertex `unowned + k` of the
    /// dependency graph stands for `upkgs[k]`.
    pub upkgs: Vec<u32>,
    /// Strongly connected components of the product graph between nodes.
    pub scc_of: Vec<usize>,
    pub scc_members: Vec<Vec<usize>>,
    pub vedges: BTreeMap<(usize, usize), Edge>,
    pub vprod: Vec<BTreeSet<usize>>,
    pub vall: Vec<BTreeSet<usize>>,
    /// Longest chain of product edges below the node; foundations are 0.
    pub layer: Vec<usize>,
    pub subtree: Vec<Vec<usize>>,
    pub findings: Vec<Finding>,
    pub conflict_files: usize,
    /// Every place a pattern selector matched, entry and code alike.
    pub sites: Vec<Site>,
    /// Indexes into `sites` of the code patterns, by file: the ranges that override the file's owner.
    code_sites: BTreeMap<String, Vec<u32>>,
    selectors: Vec<Compiled>,
    pkg_by_name: HashMap<String, u32>,
    path_to_file: HashMap<&'a str, u32>,
    root: std::path::PathBuf,
    no_cargo: Option<String>,
    /// `policy.inert`: path globs of files that belong to nothing and change nothing.
    inert: Vec<GlobMatcher>,
    /// Per compiled selector: files matched, whether any is in a package, and the
    /// top-level directories they sit in.
    selector_files: Vec<(usize, bool, BTreeSet<String>, Option<String>)>,
    pattern_cache: std::cell::RefCell<HashMap<(String, String), PatternResult>>,
    items_by_file: std::cell::OnceCell<HashMap<u32, Vec<u32>>>,
    tracked: std::cell::OnceCell<Result<Vec<String>, String>>,
    owned_cache: std::cell::OnceCell<Vec<Vec<String>>>,
}

/// A pattern's matches, or why it has none to give.
type PatternResult = Result<Rc<crate::pattern::Hits>, crate::pattern::Failure>;

/// `backend-store` and `backend_store` are the same crate to Rust.
fn norm(name: &str) -> String {
    name.replace('-', "_")
}

/// Module path of a file inside its crate, from where it sits. Same rule as the
/// index's own test ids (`#[path]` is not followed), repeated here because the
/// index keeps that function private.
pub fn module_prefix(rel_to_pkg: &str) -> Vec<String> {
    let parts: Vec<&str> = rel_to_pkg.split('/').collect();
    let rest: &[&str] = match parts.as_slice() {
        ["src", "bin", _] => return Vec::new(),
        ["src", "bin", _, rest @ ..] => rest,
        ["src", rest @ ..] => rest,
        ["tests" | "benches" | "examples", _] => return Vec::new(),
        [_, _, rest @ ..] if matches!(parts[0], "tests" | "benches" | "examples") => rest,
        all => all,
    };
    let mut segs: Vec<String> = rest.iter().map(|s| (*s).to_owned()).collect();
    if let Some(last) = segs.last_mut() {
        *last = last.trim_end_matches(".rs").to_owned();
    }
    match segs.last().map(String::as_str) {
        Some("mod") => {
            segs.pop();
        }
        Some("lib" | "main") if segs.len() == 1 => segs.clear(),
        _ => {}
    }
    segs
}

impl<'a> Resolution<'a> {
    pub fn build(model: &Model, index: &'a CodeIndex, root: &Path) -> Resolution<'a> {
        Self::build_with(model, index, root, None)
    }

    /// `no_cargo` says why the cargo package index is absent, so selectors that
    /// need it are reported as needing it rather than as naming nothing.
    pub fn build_with(model: &Model, index: &'a CodeIndex, root: &Path, no_cargo: Option<&str>) -> Resolution<'a> {
        let mut findings = Vec::new();
        // The nodes `nodesFromCrates` asks for need the packages, so they are made here and join
        // the model's own before anything is resolved: from then on they are nodes like the rest.
        let (made, made_findings) = crate::from_crates::nodes(model, index, no_cargo);
        findings.extend(made_findings);
        let with_made;
        let model = if made.is_empty() {
            model
        } else {
            let mut m = model.clone();
            m.nodes.extend(made);
            with_made = m;
            &with_made
        };
        let mut nodes = model_nodes(model, &mut findings);
        let unowned = nodes.len();
        nodes.push(Node {
            id: UNOWNED.to_owned(),
            at: None,
            parent: None,
            children: Vec::new(),
            about: Some("workspace packages no node claims".to_owned()),
            from_crate: None,
            // Everything moves when an unowned file changes, so it ships as required.
            ship: Some("required".to_owned()),
            lag: None,
            on: Vec::new(),
            never: Vec::new(),
            of: Vec::new(),
            unsupported: Vec::new(),
            moved_by: Vec::new(),
            unmoved_by: Vec::new(),
            own_files: 0,
            own_pkgs: BTreeSet::new(),
            entry_pkgs: BTreeSet::new(),
            entry_files: Vec::new(),
        });

        let pkg_by_name: HashMap<String, u32> = index
            .packages
            .iter()
            .enumerate()
            .map(|(i, p)| (norm(&p.name), i as u32))
            .collect();
        let path_to_file: HashMap<&str, u32> = index
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| (f.path.as_str(), i as u32))
            .collect();

        let mut r = Resolution {
            index,
            nodes,
            unowned,
            file_owner: Vec::new(),
            pkg_owners: vec![BTreeSet::new(); index.packages.len()],
            edges: BTreeMap::new(),
            prod: Vec::new(),
            all: Vec::new(),
            reduced: BTreeSet::new(),
            derived_pairs: BTreeSet::new(),
            instance_pairs: BTreeSet::new(),
            upkgs: Vec::new(),
            scc_of: Vec::new(),
            scc_members: Vec::new(),
            vedges: BTreeMap::new(),
            vprod: Vec::new(),
            vall: Vec::new(),
            layer: Vec::new(),
            subtree: Vec::new(),
            findings,
            conflict_files: 0,
            sites: Vec::new(),
            code_sites: BTreeMap::new(),
            items_by_file: Default::default(),
            selectors: Vec::new(),
            pkg_by_name,
            path_to_file,
            root: root.to_path_buf(),
            pattern_cache: Default::default(),
            no_cargo: no_cargo.map(str::to_owned),
            inert: inert_globs(model),
            selector_files: Vec::new(),
            tracked: Default::default(),
            owned_cache: Default::default(),
        };
        r.compile_selectors(model);
        r.assign_owners();
        r.assign_pattern_sites();
        r.report_unmatched_selectors();
        r.report_moves_nothing();
        r.derive_edges();
        r.check_laws();
        r.findings.sort_by(|a, b| {
            (a.severity, a.code, &a.node, &a.message).cmp(&(b.severity, b.code, &b.node, &b.message))
        });
        r
    }

    // ── Selectors ────────────────────────────────────────────────────────

    fn compile_selectors(&mut self, model: &Model) {
        let mut out = Vec::new();
        let mut findings = Vec::new();
        for (ni, mn) in model.nodes.iter().enumerate() {
            let at = Some(mn.source.as_deref().unwrap_or(&mn.at));
            for (entry, sels) in [(false, &mn.code), (true, &mn.entry)] {
                let field = if entry { "entry" } else { "code" };
                for sel in sels.iter() {
                    // `within` is its outer selector narrowed; `state` selects no repository file.
                    let narrowed;
                    let sel = if matches!(sel, Selector::Within { .. } | Selector::State { .. }) {
                        match self.narrowed(sel) {
                            Ok(s) => {
                                narrowed = s;
                                &narrowed
                            }
                            Err(why) => {
                                let code = if matches!(why, SelectorProblem::Missing(_)) { "selector-matches-nothing" } else { "unsupported-selector" };
                                findings.push(
                                    Finding::error(code, format!("`{field}` {}: {why}. Name the files with a path or crate selector.", sel.describe()))
                                        .of(&model.nodes[ni].id, at),
                                );
                                continue;
                            }
                        }
                    } else {
                        sel
                    };
                    match sel {
                        Selector::Crate { name } => match self.pkg_by_name.get(&norm(name)) {
                            Some(&p) => out.push(Compiled {
                                node: ni,
                                entry,
                                glob: String::new(),
                                spec: Spec::CRATE,
                                matcher: Matcher::Crate(p),
                                matched: 0,
                            }),
                            None => findings.push(self.missing_crate(ni, field, name, at)),
                        },
                        Selector::Module { path } => {
                            let mut segs = path.split("::").map(norm);
                            let krate = segs.next().unwrap_or_default();
                            match self.pkg_by_name.get(&krate) {
                                Some(&p) => out.push(Compiled {
                                    node: ni,
                                    entry,
                                    glob: String::new(),
                                    spec: Spec::MODULE,
                                    matcher: Matcher::Module(p, segs.collect()),
                                    matched: 0,
                                }),
                                None => {
                                    let mut f = self.missing_crate(ni, field, &krate, at);
                                    f.message = format!(
                                        "{} Module selectors start with the crate: write \"<crate>::<module>\".",
                                        f.message
                                    );
                                    findings.push(f);
                                }
                            }
                        }
                        Selector::Path { glob, .. } => {
                            match GlobBuilder::new(glob).literal_separator(true).build() {
                                Ok(g) => out.push(Compiled {
                                    node: ni,
                                    entry,
                                    glob: glob.clone(),
                                    spec: Spec::path(glob),
                                    matcher: Matcher::Path(g.compile_matcher()),
                                    matched: 0,
                                }),
                                Err(e) => findings.push(
                                    Finding::error(
                                        "bad-glob",
                                        format!(
                                            "`{field}` path glob \"{glob}\" does not parse ({e}); fix the glob in the selector."
                                        ),
                                    )
                                    .of(&model.nodes[ni].id, at),
                                ),
                            }
                        }
                        Selector::Pattern { language, pattern } => match self.pattern_hits(language, pattern) {
                            Err(why) => findings.push(self.pattern_failure(ni, field, sel, &why, at)),
                            Ok(h) if h.count() == 0 => findings.push(
                                Finding::error(
                                    "selector-matches-nothing",
                                    format!(
                                        "`{field}` selector matches nothing: {} matched no {} code. {} Fix the pattern or delete it.",
                                        sel.describe(),
                                        h.language,
                                        scanned(&h),
                                    ),
                                )
                                .of(&model.nodes[ni].id, at),
                            ),
                            Ok(h) => {
                                findings.extend(pattern_coverage(&h, sel, field).into_iter().map(|f| f.of(&model.nodes[ni].id, at)));
                                out.push(Compiled {
                                    node: ni,
                                    entry,
                                    glob: sel.describe(),
                                    spec: Spec::PATTERN,
                                    matcher: Matcher::Pattern(h),
                                    matched: 0,
                                });
                            }
                        },
                        Selector::Within { .. } | Selector::State { .. } => unreachable!("narrowed above"),
                        Selector::Option { .. } | Selector::Drv { .. } => findings.push(
                            Finding::error(
                                "unsupported-selector",
                                format!(
                                    "`{field}` has {}: selectors of this kind name Nix outputs, not source files, and keel-tree cannot resolve them, so the node owns nothing through it. \
                                     Add a crate or path selector for the code it covers.",
                                    sel.describe()
                                ),
                            )
                            .of(&model.nodes[ni].id, at),
                        ),
                    }
                }
            }
        }
        self.selectors = out;
        self.findings.extend(findings);
    }

    fn missing_crate(&self, ni: usize, field: &str, name: &str, at: Option<&str>) -> Finding {
        if let Some(why) = &self.no_cargo {
            return Finding::error(
                "cargo-required",
                format!(
                    "`{field}` has crate \"{name}\": crate and module selectors need the cargo package index, which is not available ({why}). \
                     Use path selectors, or run on a cargo workspace."
                ),
            )
            .of(&self.nodes[ni].id, at);
        }
        let names: Vec<&str> = self.index.packages.iter().map(|p| p.name.as_str()).collect();
        let nearest = near(&name.replace('_', "-"), names.iter().copied(), 5);
        Finding::error(
            "selector-matches-nothing",
            format!(
                "`{field}` names a crate that does not exist in this repository: \"{name}\" (the workspace has {} packages; nearest: {}). \
                 Fix the name; a crate outside the cargo workspace is not a package here, own its files with a path selector instead.",
                names.len(),
                list(&nearest)
            ),
        )
        .of(&self.nodes[ni].id, at)
    }

    fn matches(&self, c: &Compiled, path: &str, pkg: Option<u32>, modpath: &[String]) -> bool {
        match &c.matcher {
            Matcher::Crate(p) => pkg == Some(*p),
            Matcher::Module(p, segs) => pkg == Some(*p) && modpath.starts_with(segs),
            Matcher::Path(g) => g.is_match(path),
            // Ranges, not files: placed by assign_pattern_sites.
            Matcher::Pattern(_) => false,
        }
    }

    fn module_of(&self, path: &str, pkg: Option<u32>) -> Vec<String> {
        match pkg {
            Some(p) => module_prefix(strip_dir(path, &self.index.packages[p as usize].dir)),
            None => Vec::new(),
        }
    }

    /// The package whose directory is the longest prefix of `path`.
    pub fn package_of_path(&self, path: &str) -> Option<u32> {
        let mut best: Option<(usize, u32)> = None;
        for (i, p) in self.index.packages.iter().enumerate() {
            let inside = p.dir.is_empty()
                || path == p.dir
                || path.strip_prefix(p.dir.as_str()).is_some_and(|r| r.starts_with('/'));
            if inside && best.is_none_or(|(len, _)| p.dir.len() > len) {
                best = Some((p.dir.len(), i as u32));
            }
        }
        best.map(|(_, i)| i)
    }

    /// Ownership of one path under the model's selectors, without recording
    /// matches. Used for files the index never saw (deleted, renamed, new).
    pub fn owner_of_path(&self, path: &str, pkg: Option<u32>) -> Owner {
        let modpath = self.module_of(path, pkg);
        let mut best: Option<Spec> = None;
        let mut claimants: BTreeSet<usize> = BTreeSet::new();
        for c in self.selectors.iter().filter(|c| !c.entry) {
            if !self.matches(c, path, pkg, &modpath) {
                continue;
            }
            if best.is_none_or(|s| c.spec > s) {
                best = Some(c.spec);
                claimants.clear();
            }
            if best == Some(c.spec) {
                claimants.insert(c.node);
            }
        }
        match (claimants.len(), pkg) {
            (0, _) => self.unclaimed(path),
            (1, _) => Owner::Node(*claimants.iter().next().expect("one claimant")),
            _ => Owner::Conflict,
        }
    }

    /// A file no node claims is inert if `policy.inert` says so, else it belongs
    /// to `unowned`: every tracked file has an owner.
    fn unclaimed(&self, path: &str) -> Owner {
        if self.inert.iter().any(|g| g.is_match(path)) {
            Owner::Inert
        } else {
            Owner::Node(self.unowned)
        }
    }

    // ── Ownership ────────────────────────────────────────────────────────

    fn assign_owners(&mut self) {
        let index = self.index;
        let mut owners = Vec::with_capacity(index.files.len());
        // Pairs that clashed: files and a few examples, reported once per pair.
        let mut clashes: BTreeMap<(usize, usize, Spec), (usize, Vec<String>)> = BTreeMap::new();
        let mut matched = vec![0usize; self.selectors.len()];
        let mut touched: Vec<(bool, BTreeSet<String>, Option<String>)> = vec![(false, BTreeSet::new(), None); self.selectors.len()];
        let mut entry_hits: Vec<(usize, u32)> = Vec::new();
        for (fi, f) in index.files.iter().enumerate() {
            let modpath = self.module_of(&f.path, f.package);
            let mut best: Option<Spec> = None;
            let mut claimants: BTreeSet<usize> = BTreeSet::new();
            for (ci, c) in self.selectors.iter().enumerate() {
                if !self.matches(c, &f.path, f.package, &modpath) {
                    continue;
                }
                matched[ci] += 1;
                touched[ci].0 |= f.package.is_some();
                if touched[ci].1.len() < 4 {
                    touched[ci].1.insert(f.path.split('/').take(2).collect::<Vec<_>>().join("/"));
                }
                touched[ci].2.get_or_insert_with(|| f.path.clone());
                if c.entry {
                    entry_hits.push((c.node, fi as u32));
                    continue;
                }
                match best {
                    Some(s) if s > c.spec => {}
                    Some(s) if s == c.spec => {
                        claimants.insert(c.node);
                    }
                    _ => {
                        best = Some(c.spec);
                        claimants.clear();
                        claimants.insert(c.node);
                    }
                }
            }
            let owner = match (claimants.len(), f.package) {
                (0, _) => self.unclaimed(&f.path),
                (1, _) => Owner::Node(*claimants.iter().next().expect("one claimant")),
                _ => {
                    let v: Vec<usize> = claimants.iter().copied().collect();
                    for (i, &a) in v.iter().enumerate() {
                        for &b in &v[i + 1..] {
                            let e = clashes
                                .entry((a, b, best.unwrap_or(Spec::CRATE)))
                                .or_default();
                            e.0 += 1;
                            if e.1.len() < 3 {
                                e.1.push(f.path.clone());
                            }
                        }
                    }
                    self.conflict_files += 1;
                    Owner::Conflict
                }
            };
            owners.push(owner);
        }
        for (c, n) in self.selectors.iter_mut().zip(matched) {
            c.matched = n;
        }
        self.selector_files = touched.into_iter().zip(self.selectors.iter()).map(|((p, d, first), c)| (c.matched, p, d, first)).collect();
        for (fi, o) in owners.iter().enumerate() {
            if let Owner::Node(n) = *o {
                let f = &index.files[fi];
                self.nodes[n].own_files += 1;
                if let Some(p) = f.package {
                    self.nodes[n].own_pkgs.insert(p);
                    self.pkg_owners[p as usize].insert(n);
                }
            }
        }
        for (n, fi) in entry_hits {
            self.nodes[n].entry_files.push(fi);
            if let Some(p) = index.files[fi as usize].package {
                self.nodes[n].entry_pkgs.insert(p);
            }
        }
        for ((a, b, spec), (count, examples)) in clashes {
            let (na, nb) = (&self.nodes[a], &self.nodes[b]);
            let spec = spec.name();
            self.findings.push(
                Finding::error(
                    "ownership-conflict",
                    format!(
                        "nodes `{}` ({}) and `{}` ({}) both claim {count} files at the same specificity ({spec}), for example {}. \
                         Neither owns them until one selector is narrowed: make one a path selector, or drop the overlap.",
                        na.id,
                        na.at.as_deref().map(short_at).unwrap_or_default(),
                        nb.id,
                        nb.at.as_deref().map(short_at).unwrap_or_default(),
                        examples.join(", ")
                    ),
                )
                .of(&na.id.clone(), na.at.clone().as_deref()),
            );
        }
        self.file_owner = owners;
    }

    fn report_unmatched_selectors(&mut self) {
        let mut out = Vec::new();
        for c in self.selectors.iter().filter(|c| c.matched == 0) {
            let n = &self.nodes[c.node];
            let field = if c.entry { "entry" } else { "code" };
            let what = match &c.matcher {
                Matcher::Crate(p) => format!(
                    "crate \"{}\" exists but has no indexed source file",
                    self.index.packages[*p as usize].name
                ),
                Matcher::Module(p, segs) => format!(
                    "module \"{}::{}\" matches no file; the crate has {} indexed files, so check the module path",
                    norm(&self.index.packages[*p as usize].name),
                    segs.join("::"),
                    self.index.files.iter().filter(|f| f.package == Some(*p)).count()
                ),
                Matcher::Pattern(_) => format!("{} matches no file", c.glob),
                Matcher::Path(_) => {
                    let glob = c.glob.clone();
                    format!("path \"{glob}\" matches no indexed file ({})", self.path_hint(&glob))
                }
            };
            out.push(
                Finding::error(
                    "selector-matches-nothing",
                    format!("`{field}` selector matches nothing: {what}. Fix the selector or delete it."),
                )
                .of(&n.id.clone(), n.at.clone().as_deref()),
            );
        }
        self.findings.extend(out);
    }

    fn path_hint(&self, glob: &str) -> String {
        let literal: Vec<&str> = glob
            .split('/')
            .take_while(|s| !s.contains(['*', '?', '[', '{']))
            .collect();
        let mut dir = literal.join("/");
        loop {
            if dir.is_empty() || self.root.join(&dir).is_dir() {
                break;
            }
            match dir.rfind('/') {
                Some(i) => dir.truncate(i),
                None => dir.clear(),
            }
        }
        let shown = if dir.is_empty() { "the repository root".to_owned() } else { dir.clone() };
        let mut entries: Vec<String> = std::fs::read_dir(self.root.join(&dir))
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| !n.starts_with('.'))
                    .collect()
            })
            .unwrap_or_default();
        entries.sort();
        entries.truncate(8);
        format!(
            "deepest existing directory on that path is {shown}, which holds: {}; only git-tracked Rust files are indexed",
            list(&entries)
        )
    }
}

fn strip_dir<'p>(path: &'p str, dir: &str) -> &'p str {
    if dir.is_empty() {
        path
    } else {
        path.strip_prefix(dir).map_or(path, |r| r.trim_start_matches('/'))
    }
}

fn model_nodes(model: &Model, findings: &mut Vec<Finding>) -> Vec<Node> {
    let ids: HashMap<&str, usize> = model
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.id.as_str(), i))
        .collect();
    let mut nodes: Vec<Node> = Vec::new();
    for mn in &model.nodes {
        let mut refs = |field: &str, targets: &[String]| -> Vec<usize> {
            targets
                .iter()
                .filter_map(|t| match ids.get(t.as_str()) {
                    Some(&i) => Some(i),
                    None => {
                        findings.push(
                            Finding::error(
                                "unknown-node",
                                format!(
                                    "`{field}` refers to node \"{t}\", which the model does not define; \
                                     the Nix library should have refused this, so the library and this crate disagree"
                                ),
                            )
                            .of(&mn.id, Some(mn.source.as_deref().unwrap_or(&mn.at))),
                        );
                        None
                    }
                })
                .collect()
        };
        nodes.push(Node {
            id: mn.id.clone(),
            at: Some(mn.source.clone().unwrap_or_else(|| mn.at.clone())),
            parent: mn.parent.as_ref().and_then(|p| ids.get(p.as_str()).copied()),
            children: Vec::new(),
            about: mn.about.clone(),
            from_crate: mn.from_crate.clone(),
            ship: mn.ship_label(),
            lag: mn.lag.as_ref().map(|l| (l.at_most_minutes, l.confidence)),
            on: refs("on", &mn.on),
            never: refs("never", &mn.never),
            of: refs("of", &mn.of),
            unsupported: mn
                .code
                .iter()
                .chain(&mn.entry)
                .filter(|s| s.names_nix_output())
                .filter_map(|s| serde_json::to_value(s).ok())
                .collect(),
            moved_by: mn.moved_by.clone(),
            unmoved_by: mn.unmoved_by.clone(),
            own_files: 0,
            own_pkgs: BTreeSet::new(),
            entry_pkgs: BTreeSet::new(),
            entry_files: Vec::new(),
        });
    }
    for i in 0..nodes.len() {
        if let Some(p) = nodes[i].parent {
            nodes[p].children.push(i);
        }
    }
    nodes
}

impl<'a> Resolution<'a> {
    pub fn node_index(&self, id: &str) -> Option<usize> {
        self.nodes.iter().position(|n| n.id == id)
    }

    pub fn pkg_name(&self, p: u32) -> &str {
        &self.index.packages[p as usize].name
    }

    pub fn file(&self, f: u32) -> &SourceFile {
        &self.index.files[f as usize]
    }

    pub fn file_index(&self, path: &str) -> Option<u32> {
        self.path_to_file.get(path).copied()
    }

    // ── Derived edges ────────────────────────────────────────────────────

    fn derive_edges(&mut self) {
        let n = self.nodes.len();
        let u = self.unowned;
        let mut subtree: Vec<Vec<usize>> = vec![Vec::new(); n];
        for i in 0..n {
            let mut cur = Some(i);
            while let Some(c) = cur {
                subtree[c].push(i);
                cur = self.nodes[c].parent;
            }
        }
        for s in &mut subtree {
            s.sort_unstable();
        }
        self.subtree = subtree;

        // `unowned` is one node for ownership and reporting, but it is not one
        // piece of code: chaining dependencies through it would invent paths
        // between packages that never meet. For following dependencies each
        // unowned package is its own vertex (numbered from `unowned` upward).
        self.upkgs = self.nodes[u].own_pkgs.iter().copied().collect();
        let vert_of_upkg: HashMap<u32, usize> =
            self.upkgs.iter().enumerate().map(|(k, &p)| (p, u + k)).collect();
        let nv = u + self.upkgs.len();

        let mut vedges: BTreeMap<(usize, usize), Edge> = BTreeMap::new();
        for v in 0..nv {
            let pkgs: BTreeSet<u32> = if v < u {
                self.nodes[v].own_pkgs.union(&self.nodes[v].entry_pkgs).copied().collect()
            } else {
                BTreeSet::from([self.upkgs[v - u]])
            };
            for &p in &pkgs {
                let pkg = &self.index.packages[p as usize];
                for &q in &pkg.deps {
                    let kind = if pkg.dev_only_deps.contains(&q) {
                        EdgeKind::Dev
                    } else {
                        EdgeKind::Product
                    };
                    for &b in &self.pkg_owners[q as usize] {
                        let w = if b == u { vert_of_upkg[&q] } else { b };
                        if w == v {
                            continue;
                        }
                        add_edge(&mut vedges, (v, w), kind, Witness::Packages(p, q));
                    }
                }
            }
            // With no package graph the only stands-on edges are the declared laws.
            if v < u && self.index.packages.is_empty() {
                for &x in &self.nodes[v].on {
                    if x != v {
                        add_edge(&mut vedges, (v, x), EdgeKind::Product, Witness::Declared);
                    }
                }
            }
            // An entry selector starts a feature inside someone else's code;
            // the feature stands on whoever owns the file it starts in.
            if v < u {
                for &fi in &self.nodes[v].entry_files {
                    if let Owner::Node(b) = self.file_owner[fi as usize] {
                        let q = self.file(fi).package;
                        // `unowned` is a vertex only per package: code of no package has none to stand on.
                        let w = match (b == u, q.and_then(|q| vert_of_upkg.get(&q).copied())) {
                            (true, Some(w)) => Some(w),
                            (true, None) => None,
                            _ => Some(b),
                        };
                        if let Some(w) = w.filter(|&w| w != v) {
                            add_edge(&mut vedges, (v, w), EdgeKind::Product, Witness::Entry(fi));
                        }
                    }
                }
                for (si, s) in self.sites.iter().enumerate().filter(|(_, s)| s.entry && s.node == v) {
                    if let Owner::Node(b) = self.owner_at(&s.path, s.start_line) {
                        // A file outside the index can sit in a package whose indexed files are all owned,
                        // and `unowned` outside every package is no vertex (see above).
                        let w = match (b == u, s.pkg.and_then(|q| vert_of_upkg.get(&q).copied())) {
                            (true, w) => w,
                            _ => Some(b),
                        };
                        if let Some(w) = w.filter(|&w| w != v) {
                            add_edge(&mut vedges, (v, w), EdgeKind::Product, Witness::Site(si as u32));
                        }
                    }
                }
            }
        }
        let vnode0 = |v: usize| if v < u { v } else { u };
        // The pairs the code (or a declared law, or an entry) gives. `of` edges are
        // added after, so they move and blame but never become coverage edges.
        self.derived_pairs = vedges
            .iter()
            .filter(|(_, e)| e.kind == EdgeKind::Product)
            .map(|(&(v, w), _)| (vnode0(v), vnode0(w)))
            .filter(|(a, b)| a != b && *a != u)
            .collect();
        for a in 0..u {
            for &x in &self.nodes[a].of {
                if x != a {
                    add_edge(&mut vedges, (a, x), EdgeKind::Product, Witness::Instance);
                    self.instance_pairs.insert((a, x));
                }
            }
        }
        let vnode = |v: usize| if v < u { v } else { u };
        let mut vprod = vec![BTreeSet::new(); nv];
        let mut vall = vec![BTreeSet::new(); nv];
        let mut edges: BTreeMap<(usize, usize), Edge> = BTreeMap::new();
        for (&(v, w), e) in &vedges {
            vall[v].insert(w);
            if e.kind == EdgeKind::Product {
                vprod[v].insert(w);
            }
            let (a, b) = (vnode(v), vnode(w));
            // What `unowned` stands on is not drawn as a node edge (see above).
            if a != b && a != u {
                add_edge(&mut edges, (a, b), e.kind, e.witness);
            }
        }
        let mut prod = vec![BTreeSet::new(); n];
        let mut all = vec![BTreeSet::new(); n];
        for (&(a, b), e) in &edges {
            all[a].insert(b);
            if e.kind == EdgeKind::Product {
                prod[a].insert(b);
            }
        }
        self.vedges = vedges;
        self.vprod = vprod;
        self.vall = vall;
        self.edges = edges;
        self.prod = prod;
        self.all = all;

        let (scc_of, order) = self.sccs();
        self.scc_of = scc_of.clone();
        self.scc_members = order.clone();
        let mut layer = vec![0usize; n];
        // `order` lists components dependencies-first, so one pass suffices.
        let mut comp_layer = vec![0usize; order.len()];
        for (ci, members) in order.iter().enumerate() {
            let mut l = 0;
            for &m in members {
                for &t in &self.prod[m] {
                    if scc_of[t] != ci {
                        l = l.max(comp_layer[scc_of[t]] + 1);
                    }
                }
            }
            comp_layer[ci] = l;
            for &m in members {
                layer[m] = l;
            }
        }
        self.layer = layer;

        for members in order.iter().filter(|m| m.len() > 1) {
            let ids: Vec<String> = members.iter().map(|&m| self.nodes[m].id.clone()).collect();
            let first = members[0];
            self.findings.push(
                Finding::warning(
                    "stands-on-cycle",
                    format!(
                        "nodes {} stand on each other through package dependencies, so no order of them is foundation-first. \
                         Split the packages between them differently, or merge the nodes; their edges are kept in the tree.",
                        ids.join(", ")
                    ),
                )
                .of(&self.nodes[first].id.clone(), self.nodes[first].at.clone().as_deref()),
            );
        }

        // Transitive reduction, done on the graph of components so that nodes
        // standing on each other cannot justify each other's edges away. An edge
        // between components is redundant when another component that the
        // source stands on already reaches the target component; edges inside a
        // component are all kept (they are the cycle).
        let nc = order.len();
        let mut cadj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); nc];
        for (a, targets) in self.prod.iter().enumerate() {
            for &b in targets {
                if scc_of[a] != scc_of[b] {
                    cadj[scc_of[a]].insert(scc_of[b]);
                }
            }
        }
        // Components come dependencies-first, so one pass computes reachability.
        let mut creach: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); nc];
        for c in 0..nc {
            let mut r = BTreeSet::new();
            for &d in &cadj[c] {
                r.insert(d);
                r.extend(creach[d].iter().copied());
            }
            creach[c] = r;
        }
        let mut reduced = BTreeSet::new();
        for (a, targets) in self.prod.iter().enumerate() {
            for &b in targets {
                let (ca, cb) = (scc_of[a], scc_of[b]);
                let redundant = ca != cb && cadj[ca].iter().any(|&d| d != cb && creach[d].contains(&cb));
                if !redundant {
                    reduced.insert((a, b));
                }
            }
        }
        self.reduced = reduced;
    }

    pub fn reaches(&self, from: usize, to: usize, skip: Option<(usize, usize)>) -> bool {
        let mut seen = vec![false; self.nodes.len()];
        let mut stack = vec![from];
        while let Some(x) = stack.pop() {
            if x == to {
                return true;
            }
            if std::mem::replace(&mut seen[x], true) {
                continue;
            }
            for &t in &self.prod[x] {
                if Some((x, t)) != skip {
                    stack.push(t);
                }
            }
        }
        false
    }

    /// Tarjan's algorithm. Returns each node's component and the components
    /// in dependency-first order (a component appears after everything it
    /// stands on).
    fn sccs(&self) -> (Vec<usize>, Vec<Vec<usize>>) {
        struct St<'g> {
            adj: &'g [BTreeSet<usize>],
            idx: Vec<Option<usize>>,
            low: Vec<usize>,
            on: Vec<bool>,
            stack: Vec<usize>,
            next: usize,
            comps: Vec<Vec<usize>>,
        }
        fn go(s: &mut St<'_>, v: usize) {
            s.idx[v] = Some(s.next);
            s.low[v] = s.next;
            s.next += 1;
            s.stack.push(v);
            s.on[v] = true;
            let adj = s.adj;
            for &w in &adj[v] {
                match s.idx[w] {
                    None => {
                        go(s, w);
                        s.low[v] = s.low[v].min(s.low[w]);
                    }
                    Some(iw) if s.on[w] => s.low[v] = s.low[v].min(iw),
                    _ => {}
                }
            }
            if Some(s.low[v]) == s.idx[v] {
                let mut comp = Vec::new();
                while let Some(w) = s.stack.pop() {
                    s.on[w] = false;
                    comp.push(w);
                    if w == v {
                        break;
                    }
                }
                comp.sort_unstable();
                s.comps.push(comp);
            }
        }
        let n = self.nodes.len();
        let mut s = St {
            adj: &self.prod,
            idx: vec![None; n],
            low: vec![0; n],
            on: vec![false; n],
            stack: Vec::new(),
            next: 0,
            comps: Vec::new(),
        };
        for v in 0..n {
            if s.idx[v].is_none() {
                go(&mut s, v);
            }
        }
        let mut of = vec![0; n];
        for (ci, c) in s.comps.iter().enumerate() {
            for &m in c {
                of[m] = ci;
            }
        }
        (of, s.comps)
    }

    // ── Cones ────────────────────────────────────────────────────────────

    pub fn vnode(&self, v: usize) -> usize {
        if v < self.unowned { v } else { self.unowned }
    }

    /// Readable name of a dependency-graph vertex.
    pub fn vname(&self, v: usize) -> String {
        if v < self.unowned {
            self.nodes[v].id.clone()
        } else {
            format!("{UNOWNED}/{}", self.pkg_name(self.upkgs[v - self.unowned]))
        }
    }

    fn vroots(&self, node: usize) -> Vec<usize> {
        if node == self.unowned {
            (self.unowned..self.unowned + self.upkgs.len()).collect()
        } else {
            self.subtree[node].clone()
        }
    }

    /// The node, its descendants, and everything they transitively stand on,
    /// with the unowned packages reached on the way. With `dev`, dev-only
    /// edges are followed too.
    pub fn cone_with_unowned(&self, node: usize, dev: bool) -> (BTreeSet<usize>, BTreeSet<u32>) {
        let adj = if dev { &self.vall } else { &self.vprod };
        let mut seen: BTreeSet<usize> = self.vroots(node).into_iter().collect();
        let mut queue: VecDeque<usize> = seen.iter().copied().collect();
        while let Some(x) = queue.pop_front() {
            for &t in &adj[x] {
                if seen.insert(t) {
                    queue.push_back(t);
                }
            }
        }
        let mut nodes: BTreeSet<usize> = self.subtree[node].iter().copied().collect();
        let mut pkgs = BTreeSet::new();
        for &v in &seen {
            nodes.insert(self.vnode(v));
            if v >= self.unowned {
                pkgs.insert(self.upkgs[v - self.unowned]);
            }
        }
        (nodes, pkgs)
    }

    /// Real nodes that the given unowned packages depend on, directly.
    pub fn unowned_targets(&self, upkgs: &BTreeSet<u32>) -> BTreeSet<usize> {
        let mut out = BTreeSet::new();
        for (k, p) in self.upkgs.iter().enumerate() {
            if upkgs.contains(p) {
                out.extend(self.vprod[self.unowned + k].iter().map(|&w| self.vnode(w)).filter(|&n| n != self.unowned));
            }
        }
        out
    }

    pub fn cone(&self, node: usize, dev: bool) -> BTreeSet<usize> {
        self.cone_with_unowned(node, dev).0
    }

    /// Shortest chain of product edges from `from`'s subtree to `to`'s
    /// subtree, as dependency-graph vertices (see `vname`).
    pub fn product_path(&self, from: usize, to: usize) -> Option<Vec<usize>> {
        let goal: BTreeSet<usize> = self.subtree[to].iter().copied().collect();
        let mut parent: HashMap<usize, Option<usize>> = HashMap::new();
        let mut queue = VecDeque::new();
        for s in self.vroots(from) {
            parent.insert(s, None);
            queue.push_back(s);
        }
        while let Some(x) = queue.pop_front() {
            if goal.contains(&self.vnode(x)) {
                let mut path = vec![x];
                let mut cur = x;
                while let Some(Some(p)) = parent.get(&cur) {
                    path.push(*p);
                    cur = *p;
                }
                path.reverse();
                return Some(path);
            }
            for &t in &self.vprod[x] {
                if let std::collections::hash_map::Entry::Vacant(e) = parent.entry(t) {
                    e.insert(Some(x));
                    queue.push_back(t);
                }
            }
        }
        None
    }

    /// The dependency that makes vertex `a` stand on vertex `b`.
    pub fn describe_edge(&self, a: usize, b: usize) -> String {
        match self.vedges.get(&(a, b)).map(|e| e.witness) {
            Some(Witness::Packages(p, q)) => format!("{} -> {}", self.pkg_name(p), self.pkg_name(q)),
            Some(Witness::Entry(f)) => format!("entry in {}", self.file(f).path),
            Some(Witness::Site(s)) => {
                let s = &self.sites[s as usize];
                format!("entry in {}:{}", s.path, s.start_line)
            }
            Some(Witness::Declared) => String::from("declared `on` law"),
            Some(Witness::Instance) => String::from("instance-of (`of`)"),
            None => String::from("?"),
        }
    }

    // ── Laws ─────────────────────────────────────────────────────────────

    fn check_laws(&mut self) {
        let mut out = Vec::new();
        for a in 0..self.unowned {
            let node = self.nodes[a].clone();
            let at = node.at.as_deref();
            let cone = self.cone(a, false);
            let cone_dev = self.cone(a, true);

            for &x in &node.on {
                let xs = &self.subtree[x];
                if xs.iter().any(|t| cone.contains(t)) {
                    continue;
                }
                let target = &self.nodes[x].id;
                let why = if xs.iter().any(|t| cone_dev.contains(t)) {
                    format!(
                        "only dev-dependencies reach it (a test of {} depends on {target}, shipped code does)",
                        node.id
                    )
                } else {
                    let pkgs: Vec<String> = self.packages_of(a).iter().map(|&p| self.pkg_name(p).to_owned()).collect();
                    if pkgs.is_empty() {
                        format!("{} has no package at all (its selectors matched no file, see the selector findings), so nothing of it can depend on anything", node.id)
                    } else {
                        format!(
                            "none of its packages ({}) depends, directly or through other nodes, on code {target} owns",
                            list(&pkgs)
                        )
                    }
                };
                out.push(
                    Finding::error(
                        "on-not-derived",
                        format!(
                            "`on` declares that {} stands on {target} but no code of it depends on {target}'s code: {why}. \
                             Remove the law or check the selectors of both nodes.",
                            node.id
                        ),
                    )
                    .of(&node.id, at),
                );
            }

            for &x in &node.never {
                let xs = &self.subtree[x];
                if xs.iter().any(|t| self.subtree[a].contains(t)) {
                    continue;
                }
                if let Some(path) = self.product_path(a, x) {
                    let mut chain = self.vname(path[0]);
                    for w in path.windows(2) {
                        chain.push_str(&format!(
                            " -[{}]-> {}",
                            self.describe_edge(w[0], w[1]),
                            self.vname(w[1])
                        ));
                    }
                    out.push(
                        Finding::error(
                            "never-violated",
                            format!(
                                "`never` says {} must not stand on {}, but it does: {chain}. \
                                 Cut the first dependency on that path or drop the law.",
                                node.id, self.nodes[x].id
                            ),
                        )
                        .of(&node.id, at),
                    );
                } else if xs.iter().any(|t| cone_dev.contains(t)) {
                    out.push(
                        Finding::warning(
                            "never-dev-only",
                            format!(
                                "`never` says {} must not stand on {}; only dev-dependencies reach it, so shipped code obeys the law. \
                                 Keep the law if tests may use it, or move the dev-dependency.",
                                node.id, self.nodes[x].id
                            ),
                        )
                        .of(&node.id, at),
                    );
                }
            }

            for (field, paths, must_move) in [
                ("movedBy", &node.moved_by, true),
                ("unmovedBy", &node.unmoved_by, false),
            ] {
                for p in paths {
                    if let Some(f) = self.check_path_law(a, field, p, must_move, &cone, &cone_dev) {
                        out.push(f);
                    }
                }
            }
        }
        self.findings.extend(out);
    }

    fn packages_of(&self, a: usize) -> BTreeSet<u32> {
        let mut s = self.nodes[a].own_pkgs.clone();
        s.extend(&self.nodes[a].entry_pkgs);
        for &c in &self.subtree[a] {
            s.extend(&self.nodes[c].own_pkgs);
            s.extend(&self.nodes[c].entry_pkgs);
        }
        s
    }

    /// Owner nodes of a repository path, `Err` with a reason when it cannot be
    /// resolved.
    pub fn owners_of_repo_path(&self, p: &str) -> Result<BTreeSet<usize>, String> {
        let p = p.trim_start_matches("./").trim_end_matches('/');
        let prefix = format!("{p}/");
        let indexed: Vec<usize> = (0..self.index.files.len())
            .filter(|&i| {
                let fp = &self.index.files[i].path;
                fp == p || fp.starts_with(&prefix)
            })
            .collect();
        if !indexed.is_empty() {
            return Ok(indexed
                .iter()
                .filter_map(|&i| match self.file_owner[i] {
                    Owner::Node(n) => Some(n),
                    _ => None,
                })
                .collect());
        }
        let full = self.root.join(p);
        if !full.exists() {
            return Err(self.missing_path_hint(p));
        }
        let pkg = self.package_of_path(p);
        if full.is_dir() {
            return Ok(pkg
                .map(|q| self.pkg_owners[q as usize].clone())
                .unwrap_or_default());
        }
        Ok(match self.owner_of_path(p, pkg) {
            Owner::Node(n) => BTreeSet::from([n]),
            _ => BTreeSet::new(),
        })
    }

    fn missing_path_hint(&self, p: &str) -> String {
        let mut dir = p.to_owned();
        while let Some(i) = dir.rfind('/') {
            dir.truncate(i);
            if self.root.join(&dir).is_dir() {
                break;
            }
        }
        if !self.root.join(&dir).is_dir() {
            dir.clear();
        }
        let leaf = p.rsplit('/').next().unwrap_or(p);
        let names: Vec<String> = std::fs::read_dir(self.root.join(&dir))
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let nearest = near(leaf, names.iter().map(String::as_str), 5);
        let mut shown: Vec<String> = names.iter().filter(|n| !n.starts_with('.')).cloned().collect();
        shown.sort();
        shown.truncate(8);
        format!(
            "does not exist in this repository; the deepest directory that does is {}, which holds: {}{}",
            if dir.is_empty() { "the repository root" } else { dir.as_str() },
            list(&shown),
            if nearest.is_empty() {
                String::new()
            } else {
                format!("; nearest names: {}", list(&nearest))
            }
        )
    }

    fn check_path_law(
        &self,
        a: usize,
        field: &str,
        p: &str,
        must_move: bool,
        cone: &BTreeSet<usize>,
        cone_dev: &BTreeSet<usize>,
    ) -> Option<Finding> {
        let node = &self.nodes[a];
        let at = node.at.as_deref();
        let owners = match self.owners_of_repo_path(p) {
            Ok(o) => o,
            Err(why) => {
                return Some(
                    Finding::error(
                        "path-law-missing-path",
                        format!(
                            "`{field}` names {p}, which {why}. Fix the path; a law about a file that is gone checks nothing."
                        ),
                    )
                    .of(&node.id, at),
                );
            }
        };
        let names = |s: &BTreeSet<usize>| -> String {
            list(&s.iter().map(|&n| self.nodes[n].id.clone()).collect::<Vec<_>>())
        };
        let inside: BTreeSet<usize> = owners.intersection(cone).copied().collect();
        if must_move && inside.is_empty() {
            let dev_only = owners.iter().any(|o| cone_dev.contains(o));
            let reason = if owners.is_empty() {
                "it is owned by no node (outside every package or in conflict)".to_owned()
            } else if dev_only {
                format!("its owner {} is reached only through dev-dependencies", names(&owners))
            } else {
                format!("its owner {} is not in the cone of {}", names(&owners), node.id)
            };
            return Some(
                Finding::error(
                    "moved-by-not-in-cone",
                    format!(
                        "`movedBy` says a change to {p} must move {}, but {reason}. \
                         Pick a path owned by code {} stands on, or fix the selectors.",
                        node.id, node.id
                    ),
                )
                .of(&node.id, at),
            );
        }
        if !must_move && !inside.is_empty() {
            return Some(
                Finding::error(
                    "unmoved-by-in-cone",
                    format!(
                        "`unmovedBy` says a change to {p} must not move {}, but {} owns it and {} stands on it. \
                         Pick a path outside the cone, or cut the dependency.",
                        node.id,
                        names(&inside),
                        node.id
                    ),
                )
                .of(&node.id, at),
            );
        }
        None
    }

    // ── Queries ──────────────────────────────────────────────────────────

    pub fn errors(&self) -> usize {
        self.findings.iter().filter(|f| f.severity == Severity::Error).count()
    }

    pub fn files_owned(&self) -> usize {
        self.file_owner
            .iter()
            .enumerate()
            .filter(|(_, o)| matches!(o, Owner::Node(n) if *n != self.unowned))
            .count()
    }

    /// Per package: files owned by `unowned` (packages no node claims at all
    /// have every file here).
    pub fn unowned_by_package(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for (i, f) in self.index.files.iter().enumerate() {
            if self.file_owner[i] == Owner::Node(self.unowned)
                && let Some(p) = f.package
            {
                *m.entry(self.pkg_name(p).to_owned()).or_insert(0) += 1;
            }
        }
        m
    }
}

/// Inserts an edge, keeping the stronger kind (product over dev) and the first
/// witness of that kind; callers iterate in sorted order so this is stable.
fn add_edge(map: &mut BTreeMap<(usize, usize), Edge>, key: (usize, usize), kind: EdgeKind, witness: Witness) {
    let e = map.entry(key).or_insert(Edge { kind, witness });
    if kind < e.kind {
        *e = Edge { kind, witness };
    }
}

impl<'a> Resolution<'a> {
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Pattern matches, computed once per pattern.
    pub fn pattern_hits(&self, language: &str, pattern: &str) -> PatternResult {
        let key = (language.to_owned(), pattern.to_owned());
        if let Some(r) = self.pattern_cache.borrow().get(&key) {
            return r.clone();
        }
        let r = crate::pattern::find(&self.root, self.tracked_files(), language, pattern).map(Rc::new);
        self.pattern_cache.borrow_mut().insert(key, r.clone());
        r
    }

    /// Every git-tracked file, not only Rust: world inputs name data files too. Empty when git
    /// fails; `tracked_error` says why, and `check` reports it, so an empty list is never mistaken
    /// for an empty repository.
    pub fn tracked_files(&self) -> &[String] {
        self.tracked_result().as_ref().map_or(&[], Vec::as_slice)
    }

    fn tracked_result(&self) -> &Result<Vec<String>, String> {
        self.tracked.get_or_init(|| {
            // A root that is not a directory is an in-memory fixture: the index is all there is.
            if !self.root.is_dir() {
                return Ok(Vec::new());
            }
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(["ls-files", "-z"])
                .output()
                .map_err(|e| format!("cannot run git in {}: {e}. Put git on PATH.", self.root.display()))?;
            if !out.status.success() {
                return Err(format!(
                    "`git ls-files` failed in {}: {}. keel-tree reads files through git, so --root must be a git checkout.",
                    self.root.display(),
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            Ok(out
                .stdout
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect())
        })
    }

    /// Why the tracked file list could not be read, if it could not.
    pub fn tracked_error(&self) -> Option<&str> {
        self.tracked_result().as_ref().err().map(String::as_str)
    }

    /// A `within` selector as the path selector it narrows to, resolved like the selector it is
    /// inside; every other selector as itself. `Err` says why a selector selects no repository
    /// files here: it names a Nix output, or the state of a world that does not exist yet.
    pub fn narrowed(&self, sel: &Selector) -> Result<Selector, SelectorProblem> {
        match sel {
            Selector::State { path } => Err(SelectorProblem::Unsupported(format!(
                "state \"{path}\" names a path inside a world's own state, which exists only once the world is built, so it selects no file of the repository"
            ))),
            Selector::Within { of, path } => {
                let dir = match self.narrowed(of)? {
                    Selector::Path { glob, .. } => {
                        let dir = glob.strip_suffix("/**").or_else(|| glob.strip_suffix("/*")).unwrap_or(&glob).to_owned();
                        if dir.contains(['*', '?', '[', '{']) {
                            return Err(SelectorProblem::Unsupported(format!(
                                "within ({}) \"{path}\": the outer path glob \"{glob}\" has wildcards inside it, so there is no one directory to look in; name the directory",
                                of.describe()
                            )));
                        }
                        dir
                    }
                    Selector::Crate { name } => match self.pkg_by_name.get(&norm(&name)) {
                        Some(&p) => self.index.packages[p as usize].dir.clone(),
                        None => return Err(SelectorProblem::Missing(self.no_such_crate(&name))),
                    },
                    other => {
                        return Err(SelectorProblem::Unsupported(format!(
                            "within ({}) \"{path}\": {} selects {}, not a directory the path could lie in",
                            of.describe(),
                            other.describe(),
                            if matches!(other, Selector::Module { .. }) { "part of a crate's code" } else { "ranges of code" }
                        )));
                    }
                };
                let glob = if dir.is_empty() { path.clone() } else { format!("{dir}/{path}") };
                Ok(Selector::Path { glob, reason: None })
            }
            Selector::Option { .. } | Selector::Drv { .. } => Err(SelectorProblem::Unsupported(format!(
                "{} names a Nix output, which keel-tree cannot resolve",
                sel.describe()
            ))),
            other => Ok(other.clone()),
        }
    }

    fn no_such_crate(&self, name: &str) -> String {
        let names: Vec<&str> = self.index.packages.iter().map(|p| p.name.as_str()).collect();
        format!(
            "names a crate that does not exist in this repository (nearest: {})",
            list(&near(&name.replace('_', "-"), names.iter().copied(), 5))
        )
    }

    /// How many files or functions a selector names; `Err` says why it cannot
    /// be counted (unsupported, or names something that does not exist).
    pub fn count_selector(&self, sel: &Selector) -> Result<usize, SelectorProblem> {
        match self.narrowed(sel)? {
            Selector::Crate { name } | Selector::Module { path: name } => {
                let krate = norm(name.split("::").next().unwrap_or(&name));
                match self.pkg_by_name.get(&krate) {
                    Some(&p) => Ok(self.index.files.iter().filter(|f| f.package == Some(p)).count()),
                    None => Err(SelectorProblem::Missing(self.no_such_crate(&name))),
                }
            }
            Selector::Path { glob, .. } => {
                let g = GlobBuilder::new(&glob)
                    .literal_separator(true)
                    .build()
                    .map_err(|e| SelectorProblem::Unsupported(format!("glob does not parse ({e})")))?
                    .compile_matcher();
                Ok(self.tracked_files().iter().filter(|f| g.is_match(f)).count())
            }
            Selector::Pattern { language, pattern } => match self.pattern_hits(&language, &pattern) {
                Ok(h) => Ok(h.count()),
                Err(crate::pattern::Failure::UnknownLanguage(s)) => Err(SelectorProblem::Unsupported(s)),
                Err(crate::pattern::Failure::Unparsable(s)) => Err(SelectorProblem::BadPattern(s)),
            },
            // `narrowed` has already refused these.
            Selector::Option { .. } | Selector::Drv { .. } | Selector::Within { .. } | Selector::State { .. } => {
                Err(SelectorProblem::Unsupported("selector kind not resolvable here".to_owned()))
            }
        }
    }
}

/// Why a selector cannot be counted or resolved, by kind, so reports choose their code from the
/// kind and not from the wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorProblem {
    /// Names something keel-tree cannot resolve (a Nix output, a world's state, an unknown language).
    Unsupported(String),
    /// Names something that does not exist.
    Missing(String),
    /// A pattern that is not code in its language.
    BadPattern(String),
}

impl std::fmt::Display for SelectorProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectorProblem::Unsupported(s) | SelectorProblem::Missing(s) | SelectorProblem::BadPattern(s) => f.write_str(s),
        }
    }
}

impl Node {
    /// The ship policy as people should read it. A `may-lag` declaration is
    /// intent only: the engine holds the node at `required` until its
    /// predictions pass a calibration gate, and says so every time.
    pub fn ship_text(&self) -> Option<String> {
        self.ship.as_ref().map(|s| {
            if s == "may-lag" {
                let detail = self
                    .lag
                    .map(|(m, c)| format!("; asks for at most {m} min behind at confidence {c}"))
                    .unwrap_or_default();
                format!("declared may-lag, held required: uncalibrated{detail}")
            } else {
                s.clone()
            }
        })
    }
}

impl<'a> Resolution<'a> {
    pub fn no_cargo(&self) -> Option<&str> {
        self.no_cargo.as_deref()
    }

    /// The nearest directory at or above `path` holding a Cargo.toml, if any.
    fn nearest_manifest(&self, path: &str) -> Option<String> {
        let mut dir = path.rsplit_once('/').map_or("", |x| x.0).to_owned();
        loop {
            if self.root.join(&dir).join("Cargo.toml").is_file() {
                return Some(if dir.is_empty() { "Cargo.toml".to_owned() } else { format!("{dir}/Cargo.toml") });
            }
            match dir.rfind('/') {
                Some(i) => dir.truncate(i),
                None if dir.is_empty() => return None,
                None => dir.clear(),
            }
        }
    }

    /// An `entry` or `code` selector whose files lie in no package adds no
    /// package, no dependency and no edge: the node would claim a start or an
    /// owner and still move nothing. Only meaningful with a package index.
    fn report_moves_nothing(&mut self) {
        if self.index.packages.is_empty() {
            return;
        }
        let mut out = Vec::new();
        for (c, (n, in_pkg, dirs, first)) in self.selectors.iter().zip(&self.selector_files) {
            if *n == 0 || *in_pkg || matches!(c.matcher, Matcher::Crate(_) | Matcher::Module(..)) {
                continue;
            }
            let field = if c.entry { "entry" } else { "code" };
            let node = &self.nodes[c.node];
            let manifest = first
                .as_deref()
                .and_then(|f| self.nearest_manifest(f))
                .map_or_else(
                    || "no Cargo.toml above them".to_owned(),
                    |m| format!("the nearest manifest is {m}, which the cargo workspace does not include (excluded, or a nested workspace)"),
                );
            out.push(
                Finding::error(
                    "entry-moves-nothing",
                    format!(
                        "`{field}` {} moves nothing: its {} matched {} lie in no cargo package (under {}; {manifest}), \
                         so they add no package, dependency or edge to the cone of {}. \
                         Bring that directory into the workspace, or add a crate selector for the code the node should stand on.",
                        if c.glob.is_empty() { "selector".to_owned() } else { c.glob.clone() },
                        n,
                        if *n == 1 { "file" } else { "files" },
                        list(&dirs.iter().cloned().collect::<Vec<_>>()),
                        node.id
                    ),
                )
                .of(&node.id.clone(), node.at.clone().as_deref()),
            );
        }
        self.findings.extend(out);
    }

    /// Owner of a tracked path: from the index when it knows the file, else
    /// from the selectors and the package directory it lies in.
    pub fn owner_of_tracked(&self, path: &str) -> Owner {
        match self.file_index(path) {
            Some(i) => self.file_owner[i as usize],
            None => self.owner_of_path(path, self.package_of_path(path)),
        }
    }

    /// Every tracked file is owned by a node, `unowned`, or `policy.inert`.
    /// The unowned ones are described by top-level directory, with how many
    /// look like Rust test or fixture sources.
    pub fn census(&self) -> Census {
        let mut with_tests: BTreeSet<&str> = BTreeSet::new();
        for (_, item) in self.index.tests() {
            with_tests.insert(self.index.files[item.file as usize].path.as_str());
        }
        let mut c = Census::default();
        for path in self.tracked_files() {
            c.tracked += 1;
            match self.owner_of_tracked(path) {
                Owner::Node(n) if n != self.unowned => c.owned += 1,
                Owner::Inert => c.inert += 1,
                Owner::Conflict => c.conflict += 1,
                Owner::Node(_) => {
                    c.unowned += 1;
                    let top = path.split('/').next().unwrap_or("").to_owned();
                    let e = c.unowned_by_dir.entry(top).or_default();
                    e.0 += 1;
                    let rust = path.ends_with(".rs");
                    let fixture = path
                        .split('/')
                        .any(|s| matches!(s, "tests" | "test" | "fixtures" | "fixture" | "testdata" | "__tests__"));
                    if rust && fixture {
                        c.unowned_rust_test_dir += 1;
                        e.1 += 1;
                    }
                    if rust && with_tests.contains(path.as_str()) {
                        c.unowned_rust_with_test_fns += 1;
                    }
                    if self.package_of_path(path).is_none() {
                        c.unowned_outside_packages += 1;
                    }
                }
            }
        }
        c
    }
}

fn inert_globs(model: &Model) -> Vec<GlobMatcher> {
    model
        .policy
        .inert
        .iter()
        .filter_map(|s| match s {
            Selector::Path { glob, .. } => GlobBuilder::new(glob).literal_separator(true).build().ok().map(|g| g.compile_matcher()),
            _ => None,
        })
        .collect()
}

/// Tracked files by owner: owned + unowned + inert (+ conflict) = tracked.
#[derive(Debug, Default, serde::Serialize)]
pub struct Census {
    pub tracked: usize,
    pub owned: usize,
    pub unowned: usize,
    pub inert: usize,
    pub conflict: usize,
    /// Of the unowned, those in no cargo package at all.
    pub unowned_outside_packages: usize,
    /// Unowned files by top-level directory: (files, Rust test or fixture files).
    pub unowned_by_dir: BTreeMap<String, (usize, usize)>,
    pub unowned_rust_test_dir: usize,
    pub unowned_rust_with_test_fns: usize,
}

impl<'a> Resolution<'a> {
    /// Repo-relative paths a node owns itself (not through descendants), sorted.
    pub fn owned_paths(&self, node: usize) -> Vec<&str> {
        // Every tracked file, not only the Rust ones the index knows.
        let map = self.owned_cache.get_or_init(|| {
            let mut v: Vec<Vec<String>> = vec![Vec::new(); self.nodes.len()];
            // Without a git checkout to list (in-memory fixtures) the index is all there is.
            let listed: Vec<&String> = if self.tracked_files().is_empty() {
                self.index.files.iter().map(|f| &f.path).collect()
            } else {
                self.tracked_files().iter().collect()
            };
            for p in listed {
                if let Owner::Node(n) = self.owner_of_tracked(p) {
                    v[n].push(p.clone());
                }
            }
            for list in &mut v {
                list.sort_unstable();
            }
            v
        });
        map[node].iter().map(String::as_str).collect()
    }

    /// Whether the edge exists only because of an `of` law.
    pub fn is_instance_only(&self, a: usize, b: usize) -> bool {
        self.instance_pairs.contains(&(a, b)) && !self.derived_pairs.contains(&(a, b))
    }
}
