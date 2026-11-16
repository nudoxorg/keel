//! Tests as the resolver sees them, and the model's test-set algebra
//! evaluated against them.

use crate::finding::Finding;
use crate::model::{Model, PlaceRule, Selector, TestSet};
use crate::resolve::{Owner, Resolution};
use crate::text::{near, num};
use globset::GlobBuilder;
use keel_index::{RoaringBitmap, Target};
use std::collections::BTreeSet;
use serde::Serialize;
use std::collections::BTreeMap;

/// Package of a test in a repository with no cargo index.
pub const NO_PKG: u32 = u32::MAX;

/// Dense test numbering `0..len`, in index order, shared by planning and
/// explaining so their bitmaps mean the same tests.
pub struct TestTable {
    /// Index item of each test.
    pub items: Vec<u32>,
    /// `CodeIndex::test_id`.
    pub ids: Vec<String>,
    pub file: Vec<u32>,
    pub pkg: Vec<u32>,
    /// Owner of the test's file. Conflicted files have no home.
    pub home: Vec<Option<usize>>,
    pub integration: Vec<bool>,
    pub excluded_ignored: usize,
    pub excluded_outside: usize,
    /// Tests of packages that are no workspace member: compiled into the product when something
    /// depends on them, but not run by the workspace's test run.
    pub excluded_nonmember: usize,
}

impl TestTable {
    pub fn build(res: &Resolution<'_>, include_ignored: bool) -> TestTable {
        let index = res.index;
        let mut t = TestTable {
            items: Vec::new(),
            ids: Vec::new(),
            file: Vec::new(),
            pkg: Vec::new(),
            home: Vec::new(),
            integration: Vec::new(),
            excluded_ignored: 0,
            excluded_outside: 0,
            excluded_nonmember: 0,
        };
        for (n, item) in index.tests() {
            let f = &index.files[item.file as usize];
            let pkg = match f.package {
                Some(p) => p,
                // With no package index every test is outside one, and counting none
                // would leave nothing to place.
                None if index.packages.is_empty() => NO_PKG,
                None => {
                    t.excluded_outside += 1;
                    continue;
                }
            };
            if !index.packages.get(pkg as usize).is_none_or(|p| p.member) {
                t.excluded_nonmember += 1;
                continue;
            }
            if item.ignored && !include_ignored {
                t.excluded_ignored += 1;
                continue;
            }
            t.items.push(n);
            t.ids.push(index.test_id(n));
            t.file.push(item.file);
            t.pkg.push(pkg);
            t.home.push(match res.file_owner[item.file as usize] {
                Owner::Node(n) => Some(n),
                _ => None,
            });
            t.integration.push(matches!(f.target, Target::IntegrationTest(_)));
        }
        t
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn full(&self) -> RoaringBitmap {
        let mut b = RoaringBitmap::new();
        b.insert_range(0..self.len() as u32);
        b
    }

    pub fn filter(&self, mut keep: impl FnMut(usize) -> bool) -> RoaringBitmap {
        (0..self.len()).filter(|&i| keep(i)).map(|i| i as u32).collect()
    }
}

/// Per-package bitmaps of the nodes that own any file in its package closure
/// ("by package closure": a syntactic over-approximation of what a test reaches).
pub fn package_reach(res: &Resolution<'_>) -> Vec<RoaringBitmap> {
    (0..res.index.packages.len())
        .map(|p| {
            let mut nodes = RoaringBitmap::new();
            for q in &res.index.package_closure(p as u32) {
                for &n in &res.pkg_owners[q as usize] {
                    nodes.insert(n as u32);
                }
            }
            nodes
        })
        .collect()
}

pub struct Evaluator<'r, 'a> {
    pub res: &'r Resolution<'a>,
    pub table: &'r TestTable,
    pub findings: Vec<Finding>,
    /// Parts and tops of every test, built on first use.
    parts: Option<crate::parts::TestParts>,
    /// Matrix check cells, numbered after the tests: the `on` nodes of each.
    checks: Vec<Vec<usize>>,
    standing: Option<Vec<Vec<bool>>>,
}

impl<'r, 'a> Evaluator<'r, 'a> {
    pub fn new(res: &'r Resolution<'a>, table: &'r TestTable) -> Self {
        Evaluator {
            res,
            table,
            findings: Vec::new(),
            parts: None,
            checks: Vec::new(),
            standing: None,
        }
    }

    /// Sets then range over matrix checks too: `all` is tests and checks, and
    /// `node` and `only` use a check's `on` list as its parts.
    pub fn with_checks(mut self, checks: Vec<Vec<usize>>) -> Self {
        self.checks = checks;
        self
    }

    /// (tests, checks) in a set.
    pub fn split(&self, set: &RoaringBitmap) -> (u64, u64) {
        let tests = set.range_cardinality(..self.table.len() as u32);
        (tests, set.len() - tests)
    }

    fn check_ids(&self, mut keep: impl FnMut(&[usize]) -> bool) -> impl Iterator<Item = u32> {
        let base = self.table.len() as u32;
        self.checks.iter().enumerate().filter(move |(_, on)| keep(on)).map(move |(k, _)| base + k as u32).collect::<Vec<_>>().into_iter()
    }

    /// Evaluates a set. A leaf operation that selects no test is an error
    /// finding naming it: a set that selects nothing checks nothing.
    pub fn eval(&mut self, set: &TestSet, ctx: &str) -> RoaringBitmap {
        let before = self.findings.len();
        let r = self.eval_inner(set, ctx);
        let leaf = !matches!(
            set,
            TestSet::Union { .. } | TestSet::Both { .. } | TestSet::Minus { .. }
        );
        if leaf && r.is_empty() && self.findings.len() == before {
            self.findings.push(Finding::error(
                "selector-matches-nothing",
                format!(
                    "{ctx}: `{}` selects none of the {} tests and {} checks. Fix the selector or remove it from the set.",
                    set.describe(),
                    self.table.len(),
                    self.checks.len()
                ),
            ));
        }
        r
    }

    fn eval_inner(&mut self, set: &TestSet, ctx: &str) -> RoaringBitmap {
        let t = self.table;
        match set {
            TestSet::All => {
                let mut all = t.full();
                all.insert_range(t.len() as u32..(t.len() + self.checks.len()) as u32);
                all
            }
            TestSet::Under { glob } => match path_glob(glob) {
                Some(g) => {
                    let fits: Vec<bool> = self
                        .res
                        .index
                        .files
                        .iter()
                        .map(|f| g.is_match(&f.path))
                        .collect();
                    t.filter(|i| fits[t.file[i] as usize])
                }
                None => self.bad_glob(glob, ctx),
            },
            TestSet::Named { glob } => match GlobBuilder::new(glob).build() {
                Ok(g) => {
                    let g = g.compile_matcher();
                    t.filter(|i| g.is_match(&t.ids[i]))
                }
                Err(_) => self.bad_glob(glob, ctx),
            },
            TestSet::Package { name } => {
                let norm = |s: &str| s.replace('-', "_");
                match self.res.index.packages.iter().position(|p| norm(&p.name) == norm(name)) {
                    Some(p) => t.filter(|i| t.pkg[i] == p as u32),
                    None => {
                        self.missing_package(name, ctx);
                        RoaringBitmap::new()
                    }
                }
            }
            TestSet::Reaching { selector } => self.reaching(selector, ctx),
            TestSet::Node { node } => match self.node(node, ctx) {
                Some(n) => {
                    let sub = &self.res.subtree[n];
                    let mut set = t.filter(|i| t.home[i].is_some_and(|h| sub.contains(&h)));
                    set.extend(self.check_ids(|on| on.iter().any(|x| sub.contains(x))));
                    set
                }
                None => RoaringBitmap::new(),
            },
            TestSet::Only { node } => match self.node(node, ctx) {
                Some(n) => {
                    let sub = &self.res.subtree[n];
                    let (res, table) = (self.res, self.table);
                    let parts = self.parts.get_or_insert_with(|| crate::parts::TestParts::build(res, table));
                    let mut set = t.filter(|i| {
                        let tp = parts.tops(i);
                        !tp.is_empty() && tp.iter().all(|x| sub.contains(x))
                    });
                    // A check's parts are its `on` nodes; its tops are those no other `on` node stands on.
                    let standing = self.standing.get_or_insert_with(|| crate::parts::standing(res));
                    let checks = self.checks.clone();
                    let base = t.len() as u32;
                    for (k, on) in checks.iter().enumerate() {
                        let tops: Vec<usize> = on
                            .iter()
                            .copied()
                            .filter(|&x| !on.iter().any(|&o| o != x && standing[o][x] && !standing[x][o]))
                            .collect();
                        if !tops.is_empty() && tops.iter().all(|x| sub.contains(x)) {
                            set.insert(base + k as u32);
                        }
                    }
                    set
                }
                None => RoaringBitmap::new(),
            },
            TestSet::Union { sets } => {
                let mut acc = RoaringBitmap::new();
                for s in sets {
                    acc |= self.eval(s, ctx);
                }
                acc
            }
            TestSet::Both { sets } => {
                let mut it = sets.iter();
                let Some(first) = it.next() else {
                    return RoaringBitmap::new();
                };
                let mut acc = self.eval(first, ctx);
                for s in it {
                    acc &= self.eval(s, ctx);
                }
                acc
            }
            TestSet::Minus { left, right } => {
                let mut l = self.eval(left, ctx);
                l -= self.eval(right, ctx);
                l
            }
        }
    }

    fn node(&mut self, id: &str, ctx: &str) -> Option<usize> {
        let n = self.res.node_index(id);
        if n.is_none() {
            self.findings.push(Finding::error(
                "unknown-node",
                format!("{ctx}: test set names node \"{id}\", which the model does not define; fix the node name."),
            ));
        }
        n
    }

    fn bad_glob(&mut self, glob: &str, ctx: &str) -> RoaringBitmap {
        self.findings.push(Finding::error(
            "bad-glob",
            format!("{ctx}: glob \"{glob}\" does not parse; fix the glob in the test set."),
        ));
        RoaringBitmap::new()
    }

    fn missing_package(&mut self, name: &str, ctx: &str) {
        let names = self.res.index.packages.iter().map(|p| p.name.as_str());
        self.findings.push(Finding::error(
            "selector-matches-nothing",
            format!(
                "{ctx}: names a crate that does not exist in this repository: \"{name}\" (nearest: {}). Fix the name.",
                crate::text::list(&near(name, names, 5))
            ),
        ));
    }

    fn reaching(&mut self, selector: &Selector, ctx: &str) -> RoaringBitmap {
        let res = self.res;
        let mut pkgs: Vec<u32> = Vec::new();
        let narrowed = match res.narrowed(selector) {
            Ok(s) => s,
            Err(why) => {
                self.findings.push(Finding::error(
                    "unsupported-selector",
                    format!("{ctx}: {}: {why}, so `reaching` matches no test", selector.describe()),
                ));
                return RoaringBitmap::new();
            }
        };
        match &narrowed {
            Selector::Crate { name } | Selector::Module { path: name } => {
                let krate = name.split("::").next().unwrap_or(name).replace('_', "-");
                match res
                    .index
                    .packages
                    .iter()
                    .position(|p| p.name.replace('_', "-") == krate)
                {
                    Some(p) => pkgs.push(p as u32),
                    None => self.missing_package(name, ctx),
                }
            }
            Selector::Path { glob, .. } => match path_glob(glob) {
                Some(g) => {
                    let mut set = BTreeSet::new();
                    for f in &res.index.files {
                        if let Some(p) = f.package
                            && g.is_match(&f.path)
                        {
                            set.insert(p);
                        }
                    }
                    if set.is_empty() {
                        self.findings.push(Finding::error(
                            "selector-matches-nothing",
                            format!("{ctx}: path \"{glob}\" matches no file inside a package, so nothing reaches it; fix the glob."),
                        ));
                    }
                    pkgs.extend(set);
                }
                None => return self.bad_glob(glob, ctx),
            },
            Selector::Pattern { language, pattern } => match res.pattern_hits(language, pattern) {
                Ok(h) => {
                    for f in &h.files {
                        let p = match res.file_index(f) {
                            Some(i) => res.index.files[i as usize].package,
                            None => res.package_of_path(f),
                        };
                        pkgs.extend(p);
                    }
                    if pkgs.is_empty() {
                        self.findings.push(Finding::error(
                            "selector-matches-nothing",
                            format!(
                                "{ctx}: pattern matched {} places in {}, none inside a cargo package, so no test reaches it",
                                h.count(),
                                crate::text::list(&h.files)
                            ),
                        ));
                    }
                }
                Err(why) => self.findings.push(Finding::error(
                    if matches!(why, crate::pattern::Failure::Unparsable(_)) { "bad-pattern" } else { "unsupported-selector" },
                    format!("{ctx}: {}: {why}", selector.describe()),
                )),
            },
            Selector::Option { .. } | Selector::Drv { .. } | Selector::Within { .. } | Selector::State { .. } => self.findings.push(Finding::error(
                "unsupported-selector",
                format!(
                    "{ctx}: {} names a Nix output, which keel-tree cannot resolve, so `reaching` matches no test",
                    selector.describe()
                ),
            )),
        }
        // A test reaches a crate when the crate is in its package closure,
        // i.e. the test's package is among the crate's dependents.
        let mut reaching = RoaringBitmap::new();
        for p in pkgs {
            reaching |= res.index.dependents_closure(p);
        }
        self.table.filter(|i| reaching.contains(self.table.pkg[i]))
    }
}

fn path_glob(glob: &str) -> Option<globset::GlobMatcher> {
    GlobBuilder::new(glob)
        .literal_separator(true)
        .build()
        .ok()
        .map(|g| g.compile_matcher())
}

#[derive(Debug, Serialize)]
pub struct AxisCount {
    pub value: String,
    pub tests: u64,
}

#[derive(Debug, Serialize)]
pub struct AxisSummary {
    pub axis: String,
    pub values: Vec<AxisCount>,
    pub unplaced: u64,
    /// The value the axis gives a test no rule places, and how many tests have it for that reason.
    pub default: Option<String>,
    pub defaulted: u64,
    /// The same per axis for the check cells, which carry coordinates too.
    pub checks: Vec<AxisCount>,
    pub checks_unplaced: u64,
}

pub struct Placement {
    pub summary: Vec<AxisSummary>,
    pub placed: u64,
    pub findings: Vec<Finding>,
    /// Per axis and value, the tests with that coordinate.
    pub by_value: BTreeMap<String, BTreeMap<String, RoaringBitmap>>,
    /// Per axis with a default, the tests that have its value only because no rule placed them,
    /// and are in `by_value` for that reason alone. A value nobody chose for a test says nothing
    /// about it, so whatever ranks causes by axis value leaves these out.
    pub by_default: BTreeMap<String, RoaringBitmap>,
}

/// Evaluates every placement rule and builds the per-axis picture.
pub fn place(model: &Model, res: &Resolution<'_>, table: &TestTable) -> Placement {
    let mut ev = Evaluator::new(res, table).with_checks(check_on_nodes(model, res));
    let mut by_value: BTreeMap<String, BTreeMap<String, RoaringBitmap>> = model
        .axes
        .iter()
        .map(|(a, vals)| {
            (
                a.clone(),
                vals.iter().map(|v| (v.clone(), RoaringBitmap::new())).collect(),
            )
        })
        .collect();
    let mut rule_sets: Vec<RoaringBitmap> = Vec::new();
    let mut findings = Vec::new();
    for (i, rule) in model.place.iter().enumerate() {
        let ctx = format!("placement rule {} ({})", i + 1, rule_label(rule));
        let before = ev.findings.len();
        let set = ev.eval(&rule.tests, &ctx);
        let empty = set.is_empty();
        // Coordinates are for tests; a rule that selects only checks places no test.
        let mut set = set;
        set.remove_range(table.len() as u32..);
        if empty && ev.findings.len() == before {
            findings.push(Finding::error(
                "rule-matches-no-tests",
                format!(
                    "{ctx} matches no test among the {} indexed; the rule places nothing. Fix its test set or delete the rule.",
                    table.len()
                ),
            ));
        }
        for (axis, value) in &rule.coordinates {
            *by_value
                .entry(axis.clone())
                .or_default()
                .entry(value.clone())
                .or_default() |= &set;
        }
        rule_sets.push(set);
    }
    findings.append(&mut ev.findings);

    // Two rules that put one test on different values of one axis.
    for (i, a) in model.place.iter().enumerate() {
        for (j, b) in model.place.iter().enumerate().skip(i + 1) {
            for (axis, va) in &a.coordinates {
                let Some(vb) = b.coordinates.get(axis) else { continue };
                if va == vb {
                    continue;
                }
                let both = &rule_sets[i] & &rule_sets[j];
                if both.is_empty() {
                    continue;
                }
                let examples: Vec<&str> = both.iter().take(5).map(|t| table.ids[t as usize].as_str()).collect();
                findings.push(Finding::error(
                    "placement-conflict",
                    format!(
                        "{} tests sit on axis `{axis}` as both {va} (rule {}: {}) and {vb} (rule {}: {}); examples: {}. \
                         A test has one position per axis: narrow one rule with `tests.minus`.",
                        both.len(),
                        i + 1,
                        a.tests.describe(),
                        j + 1,
                        b.tests.describe(),
                        examples.join("; ")
                    ),
                ));
            }
        }
    }

    let mut placed = RoaringBitmap::new();
    let mut summary = Vec::new();
    let cells: Vec<&crate::model::CheckCell> = model.checks.values().flat_map(|g| g.checks.iter()).collect();
    // What the rules place, before any default: a default is a value, but not a placement, and
    // `placed` and the account of where the rest sit are about the rules.
    let by_rule: BTreeMap<String, RoaringBitmap> = by_value
        .iter()
        .map(|(axis, vals)| (axis.clone(), vals.values().fold(RoaringBitmap::new(), |acc, b| acc | b)))
        .collect();
    let mut by_default: BTreeMap<String, RoaringBitmap> = BTreeMap::new();
    for (axis, any) in &by_rule {
        placed |= any;
        let Some(default) = model.axis_defaults.get(axis) else { continue };
        let rest = table.full() - any;
        *by_value.entry(axis.clone()).or_default().entry(default.clone()).or_default() |= &rest;
        by_default.insert(axis.clone(), rest);
    }
    for (axis, vals) in &by_value {
        let rest = table.full() - &by_rule[axis];
        let default = model.axis_defaults.get(axis);
        let values: Vec<AxisCount> = vals.iter().map(|(v, b)| AxisCount { value: v.clone(), tests: b.len() }).collect();
        let checks: Vec<AxisCount> = vals
            .keys()
            .map(|v| AxisCount {
                value: v.clone(),
                tests: cells.iter().filter(|c| c.coordinates.get(axis) == Some(v)).count() as u64,
            })
            .collect();
        let checks_unplaced = (cells.len() as u64) - checks.iter().map(|c| c.tests).sum::<u64>().min(cells.len() as u64);
        let on_cells = format!("{} of {} check cells have none", num(checks_unplaced), num(cells.len() as u64));
        match default {
            // Placed, and still said: a default that takes most tests is a decision the model made once.
            Some(d) => findings.push(Finding::info(
                "axis-defaulted",
                format!(
                    "axis `{axis}`: {} of {} tests are on `{d}` because it is the axis's default and no placement rule gives them a value; {} are placed by rules, and {on_cells} (a default is for tests; a check cell says where it sits itself)",
                    num(rest.len()),
                    num(table.len() as u64),
                    num(table.len() as u64 - rest.len())
                ),
            )),
            None => findings.push(Finding::info(
                "axis-unplaced",
                format!(
                    "axis `{axis}`: {} of {} tests have no value on it, and {on_cells}{}",
                    num(rest.len()),
                    num(table.len() as u64),
                    unplaced_where(res, table, axis, model.axes.get(axis).map_or(&[], Vec::as_slice), &rest)
                ),
            )),
        }
        summary.push(AxisSummary {
            axis: axis.clone(),
            values,
            unplaced: if default.is_some() { 0 } else { rest.len() },
            default: default.cloned(),
            defaulted: if default.is_some() { rest.len() } else { 0 },
            checks,
            checks_unplaced,
        });
    }
    Placement {
        summary,
        placed: placed.len(),
        findings,
        by_value,
        by_default,
    }
}

/// Directory groups an unplaced axis names.
const WHERE: usize = 5;

/// The first two directories above a test's file: `crates/engine` for
/// `crates/engine/tests/a.rs`, `tests` for `tests/a.rs`, `.` for a file at the root. Two is where
/// this kind of repository keeps one thing (a crate, a frontend); deeper is the thing's own layout.
pub(crate) fn directory_prefix(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let dirs = &parts[..parts.len() - 1];
    if dirs.is_empty() { ".".to_owned() } else { dirs[..dirs.len().min(2)].join("/") }
}

/// A placement rule for the tests of one directory, as the model would write it.
pub(crate) fn suggested_rule(axis: &str, dir: &str) -> String {
    let glob = if dir == "." { "*.rs".to_owned() } else { format!("{dir}/**") };
    format!("{{ tests = tests.under \"{glob}\"; {axis} = \"<value>\"; }}")
}

/// The sentence that says where the tests that sit nowhere on an axis are: the largest
/// directories, and the rule that would place the largest, so that the next edit is a paste.
fn unplaced_where(
    res: &Resolution<'_>,
    table: &TestTable,
    axis: &str,
    values: &[String],
    rest: &RoaringBitmap,
) -> String {
    let mut groups: BTreeMap<String, u64> = BTreeMap::new();
    for i in rest {
        *groups.entry(directory_prefix(&res.index.files[table.file[i as usize] as usize].path)).or_default() += 1;
    }
    let mut groups: Vec<(String, u64)> = groups.into_iter().collect();
    groups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let Some((largest, _)) = groups.first() else { return String::new() };
    let shown: Vec<String> = groups.iter().take(WHERE).map(|(dir, n)| format!("{dir} {}", num(*n))).collect();
    format!(
        ". Largest directories among them: {}. A rule for the largest, to paste into `place` (its value is one of {}): {}. \
         Or give the axis a `default` (`{axis} = {{ values = [ .. ]; default = \"..\"; }};`) for the tests no rule places.",
        shown.join(", "),
        values.join(", "),
        suggested_rule(axis, largest)
    )
}

fn rule_label(rule: &PlaceRule) -> String {
    let coords: Vec<String> = rule.coordinates.iter().map(|(a, v)| format!("{a}={v}")).collect();
    format!("{}: {}", coords.join(","), rule.tests.describe())
}

/// Tests whose home node lies in the product cone of `node`. Tests homed in
/// `unowned` count only for the unowned packages the cone actually reaches.
pub fn cone_tests(res: &Resolution<'_>, table: &TestTable, node: usize) -> RoaringBitmap {
    let (nodes, upkgs) = res.cone_with_unowned(node, false);
    table.filter(|i| match table.home[i] {
        Some(h) if h == res.unowned => upkgs.contains(&table.pkg[i]),
        Some(h) => nodes.contains(&h),
        None => false,
    })
}

/// The `on` nodes of every matrix check cell, in universe order (groups by
/// name, cells in model order), as node indices.
pub fn check_on_nodes(model: &Model, res: &Resolution<'_>) -> Vec<Vec<usize>> {
    model
        .checks
        .values()
        .flat_map(|g| g.checks.iter())
        .map(|c| c.on.iter().filter_map(|id| res.node_index(id)).collect())
        .collect()
}
