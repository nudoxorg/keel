//! `explain`: describe a CI run's failures in the fewest words.

use crate::model::Model;
use crate::resolve::Resolution;
use crate::testset::{Placement, TestTable, cone_tests};
use crate::text::{list, near, num};
use anyhow::{Context, Result};
use keel_index::{CodeIndex, RoaringBitmap};
use keel_infer::{Attr, ExplainOptions, Universe, explain};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;

/// One test named by a line of a status file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Named {
    /// A keel-index id: `binary$module::path`.
    Id { binary: String, path: String },
    /// A nextest status line.
    Status { status: String, binary: String, path: String },
    /// `check:<group>:<cell>`: a matrix check cell that failed.
    Check { name: String },
}

impl Named {
    pub fn binary(&self) -> &str {
        match self {
            Named::Id { binary, .. } | Named::Status { binary, .. } => binary,
            Named::Check { .. } => "check",
        }
    }
    pub fn path(&self) -> &str {
        match self {
            Named::Id { path, .. } | Named::Status { path, .. } => path,
            Named::Check { name } => name,
        }
    }
    /// A test nextest reports as skipped: known not to have run.
    pub fn is_skip(&self) -> bool {
        matches!(self, Named::Status { status, .. } if status == "SKIP")
    }

    pub fn is_failure(&self) -> bool {
        match self {
            Named::Id { .. } | Named::Check { .. } => true,
            Named::Status { status, .. } => !matches!(status.as_str(), "PASS" | "SLOW" | "RETRY" | "SKIP"),
        }
    }
}

const STATUSES: [&str; 9] = ["FAIL", "TIMEOUT", "SIGABRT", "SIGSEGV", "ABORT", "LEAK-FAIL", "PASS", "FLAKY-FAIL", "SKIP"];

/// Parses one line; `None` when it names no test (timing lines, summaries, logs).
pub fn parse_line(line: &str) -> Option<Named> {
    let line = line.split("==").next().unwrap_or(line);
    let toks: Vec<&str> = line.split_whitespace().collect();
    let first = *toks.first()?;
    if let Some(name) = first.strip_prefix("check:") {
        return Some(Named::Check { name: name.to_owned() });
    }
    if let Some((binary, path)) = first.split_once('$') {
        return Some(Named::Id {
            binary: binary.to_owned(),
            path: clean(path),
        });
    }
    if !STATUSES.contains(&first) {
        return None;
    }
    // "[   1.742s] (44/46) binary path": the counter may be split by padding
    // ("( 1/46)"), so find it by its closing parenthesis.
    let close = toks.iter().position(|t| t.ends_with(')'))?;
    let binary = toks.get(close + 1)?;
    let path = toks.get(close + 2)?;
    Some(Named::Status {
        status: first.to_owned(),
        binary: (*binary).to_owned(),
        path: clean(path),
    })
}

/// Trailing dashes are the remains of a separator glued onto the name; no Rust
/// identifier ends in one.
fn clean(path: &str) -> String {
    path.trim_end_matches(['-', ' ']).to_owned()
}

#[derive(Serialize, Debug, Clone)]
pub struct Unmapped {
    pub line: String,
    pub reason: String,
}

pub struct Mapping {
    pub tests: RoaringBitmap,
    pub lines_seen: usize,
    pub mapped_lines: usize,
    pub unmapped: Vec<Unmapped>,
    pub ignored_lines: usize,
    /// Tests the file lists as SKIP: known not to have run.
    pub skipped: RoaringBitmap,
    /// Mapped although only the tail of the module path agreed with the log.
    pub partial_lines: usize,
}

struct Candidate {
    segs: Vec<String>,
    table_id: Option<u32>,
    ignored: bool,
}

/// Maps names from a file onto index tests by binary and, within the binary,
/// by the longest common suffix of the module path (the index derives the
/// module prefix from the file's location, which `#[path]` and macros can
/// make differ from what nextest prints).
pub struct Mapper<'a> {
    by_binary: HashMap<String, Vec<Candidate>>,
    packages: BTreeSet<String>,
    index: &'a CodeIndex,
    /// Matrix check cells by `group:cell`, numbered after the tests.
    checks: HashMap<String, u32>,
}

impl<'a> Mapper<'a> {
    pub fn new(index: &'a CodeIndex, table: &TestTable) -> Mapper<'a> {
        let mut table_of: HashMap<u32, u32> = HashMap::new();
        for (t, &item) in table.items.iter().enumerate() {
            table_of.insert(item, t as u32);
        }
        let mut by_binary: HashMap<String, Vec<Candidate>> = HashMap::new();
        for (n, item) in index.tests() {
            let id = index.test_id(n);
            let Some((binary, path)) = id.split_once('$') else { continue };
            by_binary.entry(binary.to_owned()).or_default().push(Candidate {
                segs: path.split("::").map(str::to_owned).collect(),
                table_id: table_of.get(&n).copied(),
                ignored: item.ignored,
            });
        }
        Mapper {
            by_binary,
            packages: index.packages.iter().map(|p| p.name.clone()).collect(),
            index,
            checks: HashMap::new(),
        }
    }

    /// The test and whether only part of its module path agreed with the log.
    pub fn with_checks(mut self, cells: &[(String, &crate::model::CheckCell)], first_id: usize) -> Self {
        self.checks = cells.iter().enumerate().map(|(k, (n, _))| (n.clone(), (first_id + k) as u32)).collect();
        self
    }

    pub fn map(&self, named: &Named) -> Result<(u32, bool), String> {
        if let Named::Check { name } = named {
            return self.checks.get(name).map(|&id| (id, false)).ok_or_else(|| {
                format!("check cell {name} is not in the model (cells are named group:cell, for example surface:project=polyglot,query=0,transport=cli)")
            });
        }
        let binary = named.binary();
        let Some(cands) = self.by_binary.get(binary) else {
            let pkg = binary.split("::").next().unwrap_or(binary);
            return Err(if self.packages.contains(pkg) {
                let mut mine: Vec<&str> = self
                    .by_binary
                    .keys()
                    .filter(|b| b.split("::").next() == Some(pkg))
                    .map(String::as_str)
                    .collect();
                mine.sort_unstable();
                mine.truncate(5);
                format!(
                    "binary {binary} has no indexed test in package {pkg}; its indexed test binaries are: {}. \
                     The target may be generated or its tests macro-defined",
                    list(&mine.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
                )
            } else {
                let _ = self.index;
                format!(
                    "package {pkg} is not a workspace package of this checkout (nearest: {}); \
                     the run may predate it or come from another repository",
                    list(&near(pkg, self.packages.iter().map(String::as_str), 3))
                )
            });
        };
        let want: Vec<&str> = named.path().split("::").collect();
        let leaf = *want.last().unwrap_or(&"");
        let mut best = 0usize;
        let mut winners: Vec<(&Candidate, bool)> = Vec::new();
        for c in cands {
            if c.segs.last().map(String::as_str) != Some(leaf) {
                continue;
            }
            let common = want
                .iter()
                .rev()
                .zip(c.segs.iter().rev())
                .take_while(|(a, b)| **a == b.as_str())
                .count();
            match common.cmp(&best) {
                std::cmp::Ordering::Greater => {
                    best = common;
                    winners = vec![(c, common < want.len().min(c.segs.len()))];
                }
                std::cmp::Ordering::Equal => winners.push((c, common < want.len().min(c.segs.len()))),
                std::cmp::Ordering::Less => {}
            }
        }
        match winners.as_slice() {
            [] => Err(format!(
                "no test named {leaf} in {binary} ({} indexed there); it may be generated by a macro or compiled out",
                cands.len()
            )),
            [(one, partial)] => match one.table_id {
                Some(t) => Ok((t, *partial)),
                None if one.ignored => Err(format!(
                    "{leaf} is #[ignore]d in the source and left out of the test table; pass --include-ignored if the run included it"
                )),
                None => Err(format!("{leaf} is indexed but outside the test table")),
            },
            many => Err(format!(
                "{} tests in {binary} end with {}; the module path in the log does not tell them apart",
                many.len(),
                want.join("::")
            )),
        }
    }

    pub fn map_text(&self, text: &str) -> Mapping {
        let mut m = Mapping {
            tests: RoaringBitmap::new(),
            lines_seen: 0,
            mapped_lines: 0,
            unmapped: Vec::new(),
            ignored_lines: 0,
            skipped: RoaringBitmap::new(),
            partial_lines: 0,
        };
        for line in text.lines() {
            let Some(named) = parse_line(line) else {
                m.ignored_lines += 1;
                continue;
            };
            if let (true, Ok((t, _))) = (named.is_skip(), self.map(&named)) {
                m.skipped.insert(t);
            }
            if !named.is_failure() {
                m.ignored_lines += 1;
                continue;
            }
            m.lines_seen += 1;
            match self.map(&named) {
                Ok((t, partial)) => {
                    m.mapped_lines += 1;
                    m.partial_lines += usize::from(partial);
                    m.tests.insert(t);
                }
                Err(reason) => m.unmapped.push(Unmapped {
                    line: format!("{} {}", named.binary(), named.path()),
                    reason,
                }),
            }
        }
        m
    }
}

/// Executed tests from a file in which any status counts (a PASS line ran).
pub fn executed_from(mapper: &Mapper<'_>, text: &str) -> (RoaringBitmap, usize) {
    let mut set = RoaringBitmap::new();
    let mut unmapped = 0;
    for line in text.lines() {
        if let Some(n) = parse_line(line) {
            match mapper.map(&n) {
                Ok((t, _)) => {
                    set.insert(t);
                }
                Err(_) => unmapped += 1,
            }
        }
    }
    (set, unmapped)
}

/// Module path of a test (without the function), from its index id.
fn module_segments(id: &str) -> Vec<&str> {
    let path = id.split_once('$').map_or(id, |x| x.1);
    let mut segs: Vec<&str> = path.split("::").collect();
    segs.pop();
    segs
}

/// Matrix check cells numbered after the tests: cell k of `cells` is universe
/// test `table.len() + k`. They carry the attributes of what they exercise.
pub fn check_cells(model: &Model) -> Vec<(String, &crate::model::CheckCell)> {
    model
        .checks
        .iter()
        .flat_map(|(g, grp)| grp.checks.iter().map(move |c| (c.id(g), c)))
        .collect()
}

pub fn universe(res: &Resolution<'_>, table: &TestTable, placement: &Placement, model: &Model, include_checks: bool, use_tops: bool) -> Universe {
    let mut attrs: Vec<Attr> = Vec::new();
    let tops = crate::parts::TestParts::build(res, table);
    // What matrix check cells add to attributes, by attribute name.
    let mut extra: HashMap<String, RoaringBitmap> = HashMap::new();
    let cells = if include_checks { check_cells(model) } else { Vec::new() };
    for (k, (_, cell)) in cells.iter().enumerate() {
        let id = (table.len() + k) as u32;
        for on in cell.on.iter().filter_map(|n| res.node_index(n)) {
            extra.entry(format!("top:{}", res.nodes[on].id)).or_default().insert(id);
            let mut cur = Some(on);
            while let Some(a) = cur {
                extra.entry(format!("node:{}", res.nodes[a].id)).or_default().insert(id);
                cur = res.nodes[a].parent;
            }
        }
        for (axis, v) in &cell.coordinates {
            extra.entry(format!("{axis}:{v}")).or_default().insert(id);
        }
    }
    let made = std::cell::RefCell::new(BTreeSet::<String>::new());
    let push = |name: String, kind: &str, mut tests: RoaringBitmap, attrs: &mut Vec<Attr>| -> Option<u32> {
        if let Some(e) = extra.get(&name) {
            tests |= e;
        }
        // Below two tests nothing can be "down", and names cost description bits.
        if tests.len() < 2 {
            return None;
        }
        made.borrow_mut().insert(name.clone());
        attrs.push(Attr {
            name,
            kind: kind.to_owned(),
            tests,
            stands_on: Vec::new(),
        });
        Some(attrs.len() as u32 - 1)
    };

    // Node attributes first: they carry the stands-on edges.
    let mut node_attr: HashMap<usize, u32> = HashMap::new();
    for n in 0..res.nodes.len() {
        let sub = &res.subtree[n];
        let tests = table.filter(|i| table.home[i].is_some_and(|h| sub.contains(&h)));
        if let Some(id) = push(format!("node:{}", res.nodes[n].id), "node", tests, &mut attrs) {
            node_attr.insert(n, id);
        }
    }
    let mut edges: BTreeSet<(u32, u32)> = BTreeSet::new();
    for (&a, &aid) in &node_attr {
        for &m in &res.subtree[a] {
            for &t in &res.prod[m] {
                if res.subtree[a].contains(&t) {
                    continue;
                }
                if let Some(&tid) = node_attr.get(&t) {
                    edges.insert((aid, tid));
                }
            }
        }
    }
    // The graph must be a DAG; a cycle between nodes (also reported by `check`)
    // has no direction to explain along, so edges inside one are dropped.
    for (a, b) in drop_cyclic(&edges, attrs.len()) {
        attrs[a as usize].stands_on.push(b);
    }
    for a in &mut attrs {
        a.stands_on.sort_unstable();
    }

    // `unowned` ships as required but its cone reaches every test, so as a feature it
    // would explain any failure and say nothing; it stays a node attribute.
    for f in crate::tree::features(res).into_iter().filter(|&f| f != res.unowned) {
        push(format!("feature:{}", res.nodes[f].id), "feature", cone_tests(res, table, f), &mut attrs);
    }
    for (axis, vals) in &placement.by_value {
        for (v, b) in vals {
            // Only what a rule placed (or a check cell says) is evidence about a test.
            let mut chosen = b.clone();
            if let Some(by_default) = placement.by_default.get(axis) {
                chosen -= by_default;
            }
            push(format!("{axis}:{v}"), "axis", chosen, &mut attrs);
        }
    }

    let group = |kind: &str, key: &dyn Fn(usize) -> Option<String>, attrs: &mut Vec<Attr>| {
        let mut m: BTreeMap<String, RoaringBitmap> = BTreeMap::new();
        for i in 0..table.len() {
            if let Some(k) = key(i) {
                m.entry(k).or_default().insert(i as u32);
            }
        }
        for (k, b) in m {
            push(format!("{kind}:{k}"), kind, b, attrs);
        }
    };
    let index = res.index;
    group("package", &|i| Some(index.packages[table.pkg[i] as usize].name.clone()), &mut attrs);
    group(
        "target",
        &|i| table.ids[i].split_once('$').map(|x| x.0.to_owned()),
        &mut attrs,
    );
    group(
        "module",
        &|i| {
            let segs = module_segments(&table.ids[i]);
            if segs.is_empty() {
                return None;
            }
            let pkg = &index.packages[table.pkg[i] as usize].name;
            Some(format!("{pkg}::{}", segs.iter().take(2).copied().collect::<Vec<_>>().join("::")))
        },
        &mut attrs,
    );
    group("file", &|i| Some(index.files[table.file[i] as usize].path.clone()), &mut attrs);
    // A test's tops: the parts no other part stands on.
    let mut by_top: BTreeMap<usize, RoaringBitmap> = BTreeMap::new();
    for i in 0..table.len() {
        for &t in tops.tops(i) {
            by_top.entry(t).or_default().insert(i as u32);
        }
    }
    for (t, b) in by_top.into_iter().filter(|_| use_tops) {
        push(format!("top:{}", res.nodes[t].id), "top", b, &mut attrs);
    }
    // Names only check cells reach still become attributes if they cover two cells.
    for (name, bits) in &extra {
        if !made.borrow().contains(name) {
            let kind = name.split(':').next().unwrap_or("axis");
            let kind = if matches!(kind, "node" | "top") { kind } else { "axis" };
            push(name.clone(), kind, RoaringBitmap::new(), &mut attrs);
            let _ = bits;
        }
    }
    Universe {
        tests: (table.len() + cells.len()) as u32,
        attrs,
    }
}

/// Edges not inside a strongly connected component of the graph.
fn drop_cyclic(edges: &BTreeSet<(u32, u32)>, n: usize) -> Vec<(u32, u32)> {
    let mut adj = vec![Vec::new(); n];
    for &(a, b) in edges {
        adj[a as usize].push(b as usize);
    }
    let mut reach: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    for s in 0..n {
        let mut stack = adj[s].clone();
        while let Some(x) = stack.pop() {
            if reach[s].insert(x) {
                stack.extend(adj[x].iter().copied());
            }
        }
    }
    edges
        .iter()
        .copied()
        .filter(|&(a, b)| !reach[b as usize].contains(&(a as usize)))
        .collect()
}

#[derive(Serialize)]
pub struct CauseOut {
    pub attr: String,
    pub executed: u64,
    pub failed: u64,
    /// Tests indexed with the attribute, less any the file lists as SKIP.
    pub indexed: u64,
    pub newly_explained: u64,
    pub exceptions: usize,
    pub consequences: Vec<String>,
}

#[derive(Serialize)]
pub struct RunOut {
    pub purity: f64,
    pub causes: Vec<CauseOut>,
    pub residue: usize,
    /// Distinct failed tests some cause covers.
    pub covered: u64,
    pub residue_examples: Vec<String>,
    pub bits_listed: f64,
    pub bits_explained: f64,
}

#[derive(Serialize)]
pub struct ExplainReport {
    pub executed_note: String,
    pub failure_lines: usize,
    pub mapped_lines: usize,
    pub partial_lines: usize,
    pub unmapped_lines: usize,
    pub non_test_lines: usize,
    pub distinct_failed_tests: u64,
    pub unmapped: Vec<Unmapped>,
    pub unmapped_reasons: BTreeMap<String, usize>,
    pub attributes: usize,
    /// Only the failures were given: no passes, no purity.
    pub failures_only: bool,
    pub skipped_tests: u64,
    pub runs: Vec<RunOut>,
}

/// What a run reads besides the repository.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    pub failures: &'a str,
    pub executed: Option<&'a str>,
    pub max_causes: usize,
    /// Include the `top:<node>` attributes.
    pub use_tops: bool,
    /// Describe the failures alone; passes are unknown.
    pub failures_only: bool,
}

pub fn run(
    res: &Resolution<'_>,
    table: &TestTable,
    placement: &Placement,
    model: &Model,
    inputs: &Inputs<'_>,
) -> Result<ExplainReport> {
    let Inputs { failures, executed, max_causes, use_tops, failures_only } = *inputs;
    if executed.is_none() && !failures_only {
        anyhow::bail!(
            "explain needs to know what ran: pass --executed FILE (one test per line with its status, PASS and SKIP lines included), \
             or pass --failures-only to describe the failures alone with no claim about the tests that passed"
        );
    }
    let include_checks = failures.lines().chain(executed.unwrap_or_default().lines()).any(|l| l.trim_start().starts_with("check:"));
    let cells = if include_checks { check_cells(model) } else { Vec::new() };
    let mapper = Mapper::new(res.index, table).with_checks(&cells, table.len());
    let m = mapper.map_text(failures);
    let (mut executed_set, mut executed_note) = match executed {
        Some(text) => {
            let (set, unmapped) = executed_from(&mapper, text);
            (
                set.clone(),
                format!(
                    "executed set: {} tests from --executed ({unmapped} lines unmapped), plus every failed test",
                    num(set.len())
                ),
            )
        }
        None => (
            RoaringBitmap::new(),
            String::new(),
        ),
    };
    executed_set |= &m.tests;
    // Only what the input says ran counts as executed: a check cell the input does not list
    // was not run, and calling it a pass would hide the failures it could have shown.
    if !cells.is_empty() && executed.is_some() {
        let ran = executed_set.range(table.len() as u32..).count();
        executed_note.push_str(&format!("; {ran} of {} check cells executed", cells.len()));
    }
    let u = universe(res, table, placement, model, include_checks, use_tops);
    let mut runs = Vec::new();
    // With failures only the executed set is the failures: every attribute is then
    // "pure" over what is known, so no purity is claimed and one listing is made.
    let purities: &[f64] = if failures_only { &[1.0] } else { &[1.0, 0.9] };
    for &purity in purities {
        let opts = ExplainOptions {
            purity,
            max_causes,
            ..ExplainOptions::default()
        };
        let e = explain(&u, &executed_set, &m.tests, &opts)
            .context("explain rejected the universe; this is a bug in how keel-tree builds attributes")?;
        runs.push(RunOut {
            purity,
            causes: e
                .causes
                .iter()
                .map(|c| CauseOut {
                    attr: u.attrs[c.attr as usize].name.clone(),
                    executed: c.executed,
                    failed: c.failed,
                    indexed: u.attrs[c.attr as usize].tests.len() - u.attrs[c.attr as usize].tests.intersection_len(&m.skipped),
                    newly_explained: c.newly_explained,
                    exceptions: c.exceptions.len(),
                    consequences: c.consequences.iter().map(|&a| u.attrs[a as usize].name.clone()).collect(),
                })
                .collect(),
            residue: e.residue.len(),
            covered: m.tests.len() - e.residue.len() as u64,
            // Check cells are numbered after the tests, so a residue id can be one of them.
            residue_examples: e
                .residue
                .iter()
                .take(5)
                .map(|&t| match table.ids.get(t as usize) {
                    Some(id) => id.clone(),
                    None => cells.get(t as usize - table.len()).map_or_else(|| format!("#{t}"), |(id, _)| format!("check:{id}")),
                })
                .collect(),
            bits_listed: e.bits_listed,
            bits_explained: e.bits_explained,
        });
    }
    if failures_only {
        executed_note = format!(
            "{} causes over the failures only; passes unknown",
            runs.first().map_or(0, |r: &RunOut| r.causes.len())
        );
    }
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for un in &m.unmapped {
        // Group by the shape of the reason, not by the names inside it.
        let key = if un.reason.starts_with("package ") {
            "package not in the index".to_owned()
        } else if un.reason.starts_with("binary ") {
            "binary has no indexed tests".to_owned()
        } else if un.reason.contains("no test named") {
            "no test of that name in the binary".to_owned()
        } else if un.reason.contains("#[ignore]") {
            "ignored in source".to_owned()
        } else {
            "ambiguous".to_owned()
        };
        *reasons.entry(key).or_default() += 1;
    }
    Ok(ExplainReport {
        executed_note,
        failure_lines: m.lines_seen,
        mapped_lines: m.mapped_lines,
        partial_lines: m.partial_lines,
        unmapped_lines: m.unmapped.len(),
        non_test_lines: m.ignored_lines,
        distinct_failed_tests: m.tests.len(),
        unmapped: m.unmapped,
        unmapped_reasons: reasons,
        attributes: u.attrs.len(),
        failures_only,
        skipped_tests: m.skipped.len(),
        runs,
    })
}

impl ExplainReport {
    pub fn render(&self) -> String {
        let mut o = String::new();
        let _ = writeln!(o, "{}", self.executed_note);
        let _ = writeln!(
            o,
            "failure lines: {} mapped ({} of them by the tail of the module path only), {} unmapped ({} other lines ignored); {} distinct tests failed",
            self.mapped_lines,
            self.partial_lines,
            self.unmapped_lines,
            self.non_test_lines,
            num(self.distinct_failed_tests)
        );
        if !self.unmapped_reasons.is_empty() {
            let _ = writeln!(o, "unmapped by reason:");
            for (r, n) in &self.unmapped_reasons {
                let _ = writeln!(o, "  {n:>5}  {r}");
            }
            let mut seen = BTreeSet::new();
            let distinct: Vec<&Unmapped> = self.unmapped.iter().filter(|u| seen.insert(u.line.clone())).collect();
            let _ = writeln!(o, "first {} of {} distinct unmapped tests:", distinct.len().min(10), distinct.len());
            for u in distinct.iter().take(10) {
                let _ = writeln!(o, "  {}", u.line);
                let _ = writeln!(o, "      {}", u.reason);
            }
        }
        let _ = writeln!(o, "universe: {} attributes (node, feature, axis, package, target, module, file)", num(self.attributes as u64));
        if self.skipped_tests > 0 {
            let _ = writeln!(o, "{} tests are listed SKIP and are left out of every indexed count", num(self.skipped_tests));
        }
        if self.failures_only {
            self.render_failures_only(&mut o);
            return o;
        }
        for r in &self.runs {
            let _ = writeln!(o);
            let _ = writeln!(
                o,
                "purity {:.1}: {} failed tests described by {} causes",
                r.purity,
                num(self.distinct_failed_tests),
                r.causes.len()
            );
            for (i, c) in r.causes.iter().enumerate() {
                let _ = writeln!(
                    o,
                    "  {:>2}. {}  failed {} of {} executed  newly explained {}  exceptions {}",
                    i + 1,
                    c.attr,
                    num(c.failed),
                    num(c.executed),
                    num(c.newly_explained),
                    c.exceptions
                );
                if !c.consequences.is_empty() {
                    let shown: Vec<String> = c.consequences.iter().take(8).cloned().collect();
                    let more = c.consequences.len() - shown.len();
                    let _ = writeln!(
                        o,
                        "        consequences ({}): {}{}",
                        c.consequences.len(),
                        shown.join(", "),
                        if more > 0 { format!(", and {more} more") } else { String::new() }
                    );
                }
            }
            let _ = writeln!(o, "  covered: {} of {} failed tests", num(r.covered), num(self.distinct_failed_tests));
            let _ = writeln!(o, "  residue: {} tests no cause covers", r.residue);
            for t in &r.residue_examples {
                let _ = writeln!(o, "      {t}");
            }
            let _ = writeln!(
                o,
                "  description length: {:.0} bits as a list, {:.0} bits as causes, exceptions and residue",
                r.bits_listed, r.bits_explained
            );
        }
        o
    }

    /// One listing, no purity, no description length: without the passes neither means anything.
    fn render_failures_only(&self, o: &mut String) {
        let Some(r) = self.runs.first() else { return };
        let _ = writeln!(o);
        for (i, c) in r.causes.iter().enumerate() {
            let _ = writeln!(
                o,
                "  {:>2}. {}  {} failed of {} indexed with this attribute (whether the other {} ran is unknown)  newly described {}",
                i + 1,
                c.attr,
                num(c.failed),
                num(c.indexed),
                num(c.indexed.saturating_sub(c.failed)),
                num(c.newly_explained)
            );
            if !c.consequences.is_empty() {
                let shown: Vec<String> = c.consequences.iter().take(8).cloned().collect();
                let more = c.consequences.len() - shown.len();
                let _ = writeln!(
                    o,
                    "        shared by ({}): {}{}",
                    c.consequences.len(),
                    shown.join(", "),
                    if more > 0 { format!(", and {more} more") } else { String::new() }
                );
            }
        }
        let _ = writeln!(o, "  described: {} of {} failed tests", num(r.covered), num(self.distinct_failed_tests));
        let _ = writeln!(o, "  failures no shared attribute describes: {} tests", r.residue);
        for t in &r.residue_examples {
            let _ = writeln!(o, "      {t}");
        }
    }
}
