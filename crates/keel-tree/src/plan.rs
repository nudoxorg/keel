//! `plan`: what a change touches, which tests it makes worth running, and in
//! what order to run them.
//!
//! The index describes the checkout, not `head`: packages, owners and tests
//! are those of the working tree, and the diff says what changed between two
//! revisions. For revisions near the checkout that is the same thing; for old
//! ones, files and tests that have since moved are mapped by their path.

use crate::resolve::{Owner, Resolution};
use crate::testset::{TestTable, cone_tests};
use crate::text::{counted, num, plural, table};
use crate::tree::features;
use anyhow::{Context, Result};
use crate::changes::{Facts, Gone};
use keel_index::{Change, FileStatus, RoaringBitmap};
use keel_infer::{Planner, TestModel, Unit};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Instant;

/// Every number the plan invents, in one place. They are placeholders until
/// mutation data exists, which is why each probability printed from them
/// carries the word `uncalibrated`.
pub mod assumptions {
    /// Chance a changed function is wrong: `BASE + PER_BRANCH * branches +
    /// PER_LINE * lines_changed`, clamped to `[MIN, MAX]`.
    pub const PRIOR_BASE: f64 = 0.02;
    pub const PRIOR_PER_BRANCH: f64 = 0.01;
    pub const PRIOR_PER_LINE: f64 = 0.005;
    pub const PRIOR_MIN: f64 = 0.02;
    pub const PRIOR_MAX: f64 = 0.5;
    /// A file changed outside any function (use, const, struct, macro, a file
    /// that does not parse, a non-Rust file in a package) is one unit.
    pub const PRIOR_OUTSIDE_ITEMS: f64 = 0.2;
    /// Chance a test fails when a unit is wrong, by how the test relates to it.
    pub const NOTICE_SAME_FILE: f32 = 0.5;
    pub const NOTICE_SAME_PACKAGE: f32 = 0.2;
    pub const NOTICE_DIRECT_DEP: f32 = 0.05;
    pub const NOTICE_TRANSITIVE_DEP: f32 = 0.02;
    /// Global inputs (lockfiles, root configs) are one unit every test may notice.
    pub const NOTICE_GLOBAL: f32 = 0.02;
    pub const COST_UNIT_TEST_MS: u32 = 100;
    pub const COST_INTEGRATION_TEST_MS: u32 = 2000;
    /// Notice entries a plan may hold before the weakest relations are dropped
    /// (12 bytes each in the planner, plus the copy while it is built).
    pub const MAX_NOTICES: u64 = 3_000_000;
    /// Tests the greedy order is computed over; the planner's order is
    /// quadratic in tests sharing a unit.
    pub const MAX_CANDIDATES: usize = 1_500;
    /// The candidate pool shrinks until its notice entries fit this budget, because
    /// the planner's order costs time in (candidates x notices per test).
    pub const CANDIDATE_NOTICE_BUDGET: u64 = 150_000;
}

use assumptions as a;

pub fn prior(branches: u32, lines_changed: u32) -> f64 {
    (a::PRIOR_BASE + a::PRIOR_PER_BRANCH * f64::from(branches) + a::PRIOR_PER_LINE * f64::from(lines_changed))
        .clamp(a::PRIOR_MIN, a::PRIOR_MAX)
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// Matches an inert rule: affects nothing.
    Inert,
    /// A Rust file whose tokens did not change: affects nothing.
    PositionOnly,
    /// In a workspace package: affects tests that depend on the package.
    Package,
    /// Owned by a node in a repository with no package graph: affects what stands on it.
    Node,
    /// Unowned (or owned but in no package): affects every test and every check.
    Global,
}

#[derive(Serialize)]
pub struct ChangedFile {
    pub path: String,
    pub status: String,
    pub class: Class,
    /// The rule that decided it, in words.
    pub rule: String,
    pub package: Option<String>,
    pub owner: Option<String>,
    pub functions: usize,
}

#[derive(Serialize)]
pub struct Touch {
    pub node: String,
    /// Longest chain of nodes it stands on; 0 is a foundation.
    pub layer: usize,
    pub files: usize,
    pub functions: usize,
}

#[derive(Serialize)]
pub struct FeaturePlan {
    pub node: String,
    pub tests_in_cone: u64,
    pub to_run: u64,
    pub untouched: bool,
    pub touched_by: Vec<String>,
    /// Set for `may-lag` nodes: the policy is intent, the engine runs them as required.
    pub held: Option<String>,
}

#[derive(Serialize)]
pub struct ScheduledTest {
    pub test: String,
    pub cost_ms: u32,
    /// Share of all the doubt this plan can remove (uncalibrated).
    pub expected_share: f64,
    pub cumulative_ms: u64,
    pub residual_risk: f64,
    pub cut_here: bool,
}

#[derive(Serialize)]
pub struct TargetLine {
    /// Test binary: `package` for lib tests, `package::target` otherwise.
    pub target: String,
    pub affected: usize,
    /// Packages in the binary's link closure.
    pub packages_linked: usize,
    /// Its own package changed, as opposed to reached only through dependencies.
    pub own_package_changed: bool,
}

#[derive(Serialize)]
pub struct RiskPoint {
    pub after_tests: usize,
    pub residual_risk: f64,
    pub cumulative_ms: u64,
}

#[derive(Serialize)]
pub struct PlanReport {
    pub base: String,
    pub head: String,
    pub index_note: String,
    pub files: Vec<ChangedFile>,
    pub touches: Vec<Touch>,
    pub tests_total: usize,
    pub tests_affected: usize,
    pub checks_affected: usize,
    /// Of those, affected only through a declared input of the check or its world.
    pub checks_by_inputs: usize,
    pub checks_total: usize,
    /// Pattern matches the change reached.
    pub site_touches: Vec<SiteTouch>,
    /// Tests that were in files the change deleted or moved away.
    pub gone_tests: Vec<Gone>,
    /// Why there is no ordering, when there is none.
    pub order_note: Option<String>,
    pub targets: Vec<TargetLine>,
    pub shared_link_units: Vec<String>,
    pub features: Vec<FeaturePlan>,
    pub units: usize,
    pub notices_kept: u64,
    pub notices_dropped_tiers: Vec<String>,
    pub initial_risk: f64,
    pub schedule_len: usize,
    pub first: Vec<ScheduledTest>,
    pub risk_after: Vec<RiskPoint>,
    pub cut: Option<CutReport>,
    pub diff_ms: u128,
    pub plan_ms: u128,
    /// Of `plan_ms`: building units and notices, `Planner::new`, `schedule`.
    pub phase_ms: [u128; 4],
    /// Tests the order was computed over (all affected tests when few).
    pub candidates: usize,
    pub assumptions: Vec<String>,
}

#[derive(Serialize)]
pub struct CutReport {
    pub by_seconds: f64,
    pub tests_before_cut: usize,
    pub residual_risk: f64,
}

/// What a change does, before any ordering: which files count and how, which
/// nodes they move, and which tests and matrix checks they make worth running.
pub struct Effects {
    pub files: Vec<ChangedFile>,
    pub(crate) units: Vec<(UnitInfo, f64)>,
    pub changed_pkgs: BTreeSet<u32>,
    /// Owners of every effective change (`unowned` included).
    pub changed_nodes: BTreeSet<usize>,
    pub global: bool,
    pub(crate) effective: Vec<(Owner, Option<u32>, String)>,
    pub touches: Vec<Touch>,
    pub affected: RoaringBitmap,
    /// Indices of the matrix check cells (universe order) that are affected.
    pub checks_affected: RoaringBitmap,
    /// Of those, the ones affected only because a declared input (of the check or of a world
    /// it starts in) changed, not because a node it exercises did.
    pub checks_by_inputs: usize,
    pub checks_total: usize,
    pub site_touches: Vec<SiteTouch>,
    pub(crate) closures: Vec<RoaringBitmap>,
}

/// A pattern match whose lines a change reached.
#[derive(Serialize, Clone, Debug)]
pub struct SiteTouch {
    pub node: String,
    /// An entry (the feature starts here) or code (the node owns these lines).
    pub entry: bool,
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    /// The named item the match is in, as the language calls it.
    pub item: Option<String>,
    /// The Rust function of the index that changed, when it did.
    pub changed_function: Option<String>,
    pub why: String,
}

/// One side of a changed file. A rename is two: the file is gone from its old path and new at
/// the other, and each path has its own owner and package.
struct Side<'c> {
    path: &'c str,
    status: String,
    change: &'c keel_index::FileChange,
    /// The side that holds the new content (the only one with function changes to count).
    new_side: bool,
    renamed: bool,
}

fn sides(f: &keel_index::FileChange) -> Vec<Side<'_>> {
    let status = |s: &str| s.to_owned();
    match &f.status {
        FileStatus::Added => vec![Side { path: &f.path, status: status("added"), change: f, new_side: true, renamed: false }],
        FileStatus::Deleted => vec![Side { path: &f.path, status: status("deleted"), change: f, new_side: false, renamed: false }],
        FileStatus::Modified => vec![Side { path: &f.path, status: status("modified"), change: f, new_side: true, renamed: false }],
        FileStatus::Renamed { from } => vec![
            Side { path: from, status: format!("deleted (renamed to {})", f.path), change: f, new_side: false, renamed: true },
            Side { path: &f.path, status: format!("added (renamed from {from})"), change: f, new_side: true, renamed: true },
        ],
    }
}

/// Whether the changed `path` is one of the things a selector names. `None` when the selector
/// cannot be resolved here, which callers must read as "may be".
fn selector_hits(res: &Resolution<'_>, sel: &crate::model::Selector, path: &str) -> Option<bool> {
    use crate::model::Selector as S;
    let norm = |s: &str| s.replace('-', "_");
    let in_crate = |name: &str| -> Option<bool> {
        let want = norm(name.split("::").next().unwrap_or(name));
        let p = res.index.packages.iter().position(|p| norm(&p.name) == want)?;
        // The program a check runs is built from the crate and everything it depends on.
        Some(res.package_of_path(path).is_some_and(|q| res.index.package_closure(p as u32).contains(q)))
    };
    let sel = &res.narrowed(sel).ok()?;
    match sel {
        S::Path { glob, .. } => {
            let g = globset::GlobBuilder::new(glob).literal_separator(true).build().ok()?;
            Some(g.compile_matcher().is_match(path))
        }
        S::Crate { name } => in_crate(name),
        S::Module { path: m } => in_crate(m),
        S::Pattern { language, pattern } => {
            let h = res.pattern_hits(language, pattern).ok()?;
            Some(h.files.binary_search_by(|f| f.as_str().cmp(path)).is_ok())
        }
        S::Option { .. } | S::Drv { .. } | S::Within { .. } | S::State { .. } => None,
    }
}

/// The selectors a check instance reads: its own `inputs`, and the inputs of the world it
/// starts in and of every world that one is built from.
fn check_inputs<'m>(model: &'m crate::model::Model, cell: &'m crate::model::CheckCell) -> Vec<&'m crate::model::Selector> {
    let mut out: Vec<&crate::model::Selector> = cell.inputs.iter().collect();
    let mut seen = BTreeSet::new();
    let mut cur = cell.world.as_deref();
    while let Some(name) = cur {
        if !seen.insert(name) {
            break;
        }
        let Some(w) = model.worlds.iter().find(|w| w.name == name) else { break };
        out.extend(w.inputs.iter());
        cur = w.from.as_deref();
    }
    out
}

/// Classifies every changed file by who owns it. A file nobody owns belongs to
/// `unowned`, and anything it could change is unknown, so it moves every test
/// and every matrix check; `policy.inert` files move nothing. A file in a
/// package moves what its package closure reaches.
pub fn effects(res: &Resolution<'_>, table_: &TestTable, model: &crate::model::Model, change: &Change) -> Effects {
    effects_with(res, table_, model, change, &Facts::none())
}

pub fn effects_with(res: &Resolution<'_>, table_: &TestTable, model: &crate::model::Model, change: &Change, facts: &Facts) -> Effects {
    let index = res.index;
    let cargo = !index.packages.is_empty();
    let mut files: Vec<ChangedFile> = Vec::new();
    let mut units: Vec<(UnitInfo, f64)> = Vec::new();
    let mut changed_pkgs: BTreeSet<u32> = BTreeSet::new();
    let mut changed_nodes: BTreeSet<usize> = BTreeSet::new();
    let mut global = false;
    let mut effective: Vec<(Owner, Option<u32>, String)> = Vec::new();
    // Paths whose content differs between the revisions, inert ones included: an input a
    // check declares is a promise that it matters, whatever `policy.inert` says.
    let mut touched_paths: Vec<&str> = Vec::new();
    for fc in &change.files {
        for side in sides(fc) {
            let f = side.change;
            let pkg = res.package_of_path(side.path);
            let owner = res.owner_of_tracked(side.path);
            let owner_name = match owner {
                Owner::Node(n) => Some(res.nodes[n].id.clone()),
                Owner::Conflict => Some("(ownership conflict)".to_owned()),
                Owner::Inert => None,
            };
            let owned_by_node = matches!(owner, Owner::Node(n) if n != res.unowned);
            // The index never calls a rename or a doc-comment edit position-only (both are code to
            // it: a rename is a deletion and an addition, a doctest is a test), so this is a plain read.
            let position_only = f.position_only;
            let (class, rule) = if owner == Owner::Inert {
                (Class::Inert, "inert (policy.inert): belongs to nothing and cannot change what a test or check does".to_owned())
            } else if position_only {
                (Class::PositionOnly, "comment or whitespace only: no token changed, so nothing is affected".to_owned())
            } else if pkg.is_some() {
                let why = if side.renamed {
                    "a rename is a deletion at the old path and an addition at the new one"
                } else {
                    "in a package: affects the tests whose package closure contains it"
                };
                (Class::Package, why.to_owned())
            } else if owned_by_node && !cargo {
                (Class::Node, "owned by a node: affects the tests and checks of nodes that stand on it".to_owned())
            } else if owned_by_node {
                (
                    Class::Global,
                    "owned by a node but in no cargo package, so nothing says what reaches it: every test and every check is affected"
                        .to_owned(),
                )
            } else {
                (
                    Class::Global,
                    "unowned: no node owns it and it is not inert, so any build or check may depend on it: every test and every check is affected"
                        .to_owned(),
                )
            };
            match class {
                Class::Package => {
                    if let Some(q) = pkg {
                        changed_pkgs.insert(q);
                    }
                }
                Class::Global => global = true,
                Class::Inert | Class::PositionOnly | Class::Node => {}
            }
            if class != Class::PositionOnly {
                touched_paths.push(side.path);
            }
            if matches!(class, Class::Package | Class::Node | Class::Global) {
                if let Owner::Node(n) = owner {
                    changed_nodes.insert(n);
                }
                effective.push((owner, pkg, side.path.to_owned()));
                if matches!(class, Class::Package | Class::Node) {
                    let items: &[keel_index::ItemChange] = if side.new_side { &f.items } else { &[] };
                    if items.is_empty() || f.outside_items {
                        units.push((UnitInfo { pkg, file: Some(side.path.to_owned()) }, a::PRIOR_OUTSIDE_ITEMS));
                    }
                    for it in items {
                        units.push((UnitInfo { pkg, file: Some(side.path.to_owned()) }, prior(it.branches, it.lines_changed)));
                    }
                }
            }
            files.push(ChangedFile {
                path: side.path.to_owned(),
                status: side.status,
                class,
                rule,
                package: pkg.map(|p| res.pkg_name(p).to_owned()),
                owner: owner_name,
                functions: if side.new_side { f.items.len() } else { 0 },
            });
        }
    }
    if global {
        units.push((UnitInfo { pkg: None, file: None }, a::PRIOR_OUTSIDE_ITEMS));
    }

    // Pattern sites: the lines a node owns, or an entry starts from, that the change reached.
    let mut site_touches: Vec<SiteTouch> = Vec::new();
    for site in &res.sites {
        let Some(fc) = change.files.iter().find(|c| c.path == site.path && c.status != FileStatus::Deleted) else { continue };
        let reached = files.iter().any(|f| f.path == site.path && f.class != Class::PositionOnly && f.class != Class::Inert);
        if !reached {
            continue;
        }
        let function = site.item.map(|i| index.items[i as usize].path.clone());
        let by_function = function.as_ref().is_some_and(|p| fc.items.iter().any(|it| &it.path == p));
        let exact = facts.checkout_is_head.get(&site.path).copied().unwrap_or(false);
        let by_lines = exact
            && facts
                .lines
                .get(&site.path)
                .is_some_and(|rs| rs.iter().any(|&(s, e)| s <= site.end_line && site.start_line <= e));
        let (touched, why) = if by_function {
            (true, "the function changed".to_owned())
        } else if by_lines {
            (true, "a changed line lies in the range".to_owned())
        } else if !exact || !facts.lines.contains_key(&site.path) {
            (true, "the changed lines are not known against the checkout's ranges, so the whole file counts".to_owned())
        } else {
            (false, String::new())
        };
        if touched {
            changed_nodes.insert(site.node);
            effective.push((Owner::Node(site.node), site.pkg, site.path.clone()));
            site_touches.push(SiteTouch {
                node: res.nodes[site.node].id.clone(),
                entry: site.entry,
                path: site.path.clone(),
                start_line: site.start_line,
                end_line: site.end_line,
                item: site.enclosing.as_ref().map(|e| match &e.name {
                    Some(n) => format!("{} {n}", e.kind),
                    None => e.kind.clone(),
                }),
                changed_function: by_function.then_some(function).flatten(),
                why,
            });
        }
    }

    // Touches, foundation-first. `unowned` is layer 0: everything stands on it.
    let mut by_node: BTreeMap<usize, (usize, usize)> = BTreeMap::new();
    for cf in &files {
        if !matches!(cf.class, Class::Package | Class::Node | Class::Global) {
            continue;
        }
        if let Some(n) = cf.owner.as_deref().and_then(|id| res.node_index(id)) {
            let e = by_node.entry(n).or_default();
            e.0 += 1;
            e.1 += cf.functions;
        }
    }
    let mut counted: BTreeSet<(usize, &str)> = BTreeSet::new();
    for s in &site_touches {
        let Some(n) = res.node_index(&s.node) else { continue };
        let e = by_node.entry(n).or_default();
        if counted.insert((n, s.path.as_str())) && !files.iter().any(|f| f.path == s.path && f.owner.as_deref() == Some(s.node.as_str())) {
            e.0 += 1;
        }
        e.1 += usize::from(s.changed_function.is_some());
    }
    let mut touches: Vec<Touch> = by_node
        .iter()
        .map(|(&n, &(fs, fns))| Touch {
            node: res.nodes[n].id.clone(),
            layer: if n == res.unowned { 0 } else { res.layer[n] },
            files: fs,
            functions: fns,
        })
        .collect();
    touches.sort_by(|x, y| (x.layer, &x.node).cmp(&(y.layer, &y.node)));

    // Affected tests.
    let closures: Vec<RoaringBitmap> = (0..index.packages.len() as u32).map(|p| index.package_closure(p)).collect();
    let affected: RoaringBitmap = if global {
        table_.full()
    } else if cargo {
        let hit_pkg: Vec<bool> = closures
            .iter()
            .map(|c| changed_pkgs.iter().any(|&p| c.contains(p)))
            .collect();
        table_.filter(|i| hit_pkg[table_.pkg[i] as usize])
    } else {
        // No package graph: a test is affected when what its home node stands on
        // (declared laws) includes a node that changed. A test with no home node belongs to
        // `unowned`, which everything stands on, so any effective change reaches it.
        let any_change = !effective.is_empty();
        let mut cones: HashMap<usize, bool> = HashMap::new();
        table_.filter(|i| match table_.home[i] {
            Some(h) if h != res.unowned => *cones
                .entry(h)
                .or_insert_with(|| res.cone(h, false).iter().any(|n| changed_nodes.contains(n))),
            _ => any_change,
        })
    };
    let cells: Vec<&crate::model::CheckCell> = model.checks.values().flat_map(|g| g.checks.iter()).collect();
    let mut checks_affected = RoaringBitmap::new();
    let mut checks_by_inputs = 0;
    let mut by_inputs: HashMap<Vec<String>, bool> = HashMap::new();
    for (k, cell) in cells.iter().enumerate() {
        let on_hit = global
            || cell
                .on
                .iter()
                .filter_map(|id| res.node_index(id))
                .any(|n| res.cone(n, false).iter().any(|m| changed_nodes.contains(m)));
        let inputs = check_inputs(model, cell);
        let key: Vec<String> = inputs.iter().map(|s| s.describe()).collect();
        let input_hit = *by_inputs.entry(key).or_insert_with(|| {
            inputs.iter().any(|s| touched_paths.iter().any(|p| selector_hits(res, s, p).unwrap_or(true)))
        });
        if on_hit || input_hit {
            checks_affected.insert(k as u32);
            checks_by_inputs += usize::from(!on_hit);
        }
    }
    Effects {
        files,
        units,
        changed_pkgs,
        changed_nodes,
        global,
        effective,
        touches,
        affected,
        checks_affected,
        checks_by_inputs,
        checks_total: cells.len(),
        site_touches,
        closures,
    }
}

pub(crate) struct UnitInfo {
    pkg: Option<u32>,
    file: Option<String>,
}

/// Knobs of one plan.
#[derive(Clone, Copy)]
pub struct Options {
    /// Mark where the order would be cut after this many seconds.
    pub by_seconds: Option<f64>,
    pub max_notices: u64,
    pub max_candidates: usize,
}

pub fn run(
    res: &Resolution<'_>,
    table_: &TestTable,
    model: &crate::model::Model,
    root: &Path,
    base: &str,
    head: &str,
    opts: &Options,
) -> Result<PlanReport> {
    let Options { by_seconds, max_notices, max_candidates } = *opts;
    let t0 = Instant::now();
    let change: Change = keel_index::diff(root, base, head).with_context(|| {
        format!("cannot diff {base}..{head} in {}; both must be revisions of that repository", root.display())
    })?;
    let diff_ms = t0.elapsed().as_millis();
    let t1 = Instant::now();
    let index = res.index;
    let cargo = !index.packages.is_empty();
    let facts = Facts::gather(root, base, head, &change, res);
    let Effects {
        files,
        units,
        changed_pkgs,
        global,
        effective,
        touches,
        affected,
        checks_affected,
        checks_by_inputs,
        checks_total,
        site_touches,
        closures,
        ..
    } = effects_with(res, table_, model, &change, &facts);

    // 3b. Test binaries: tests of one binary share one link unit, so a change
    // anywhere in its closure rebuilds it once for all of them.
    let mut per_target: BTreeMap<String, (usize, u32)> = BTreeMap::new();
    for t in affected.iter().filter(|_| cargo) {
        let id = &table_.ids[t as usize];
        let e = per_target.entry(id.split_once('$').map_or(id.as_str(), |x| x.0).to_owned()).or_insert((0, table_.pkg[t as usize]));
        e.0 += 1;
    }
    let mut targets: Vec<TargetLine> = per_target
        .into_iter()
        .map(|(target, (affected, pkg))| TargetLine {
            target,
            affected,
            packages_linked: closures[pkg as usize].len() as usize,
            own_package_changed: changed_pkgs.contains(&pkg),
        })
        .collect();
    targets.sort_by(|a, b| b.affected.cmp(&a.affected).then(a.target.cmp(&b.target)));
    let mut shared_link_units = Vec::new();
    for t in targets.iter().filter(|t| t.affected > 1000 && !t.own_package_changed) {
        let pkg = t.target.split("::").next().unwrap_or(&t.target);
        let Some(p) = index.packages.iter().position(|x| x.name == pkg) else { continue };
        let causes: Vec<String> = changed_pkgs
            .iter()
            .filter(|&&c| closures[p].contains(c))
            .map(|&c| res.pkg_name(c).to_owned())
            .collect();
        shared_link_units.push(format!(
            "these {} tests share one link unit ({}, linking {} packages) and are reached only through dependencies, with changed code in {}{}",
            num(t.affected as u64),
            t.target,
            t.packages_linked,
            if causes.is_empty() { "an unowned file".to_owned() } else { causes.iter().take(4).cloned().collect::<Vec<_>>().join(", ") },
            if causes.len() > 4 { format!(" and {} more", causes.len() - 4) } else { String::new() }
        ));
    }

    // 4. Features.
    let mut feature_plans = Vec::new();
    for f in features(res) {
        let cone_prod = res.cone_with_unowned(f, true);
        let in_cone = cone_tests(res, table_, f);
        let to_run = (&in_cone & &affected).len();
        let touched_by: Vec<String> = effective
            .iter()
            .filter_map(|(o, p, _)| match o {
                Owner::Node(n) if *n == res.unowned => {
                    p.filter(|p| cone_prod.1.contains(p)).map(|_| res.nodes[*n].id.clone())
                }
                Owner::Node(n) if cone_prod.0.contains(n) => Some(res.nodes[*n].id.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        feature_plans.push(FeaturePlan {
            node: res.nodes[f].id.clone(),
            tests_in_cone: in_cone.len(),
            to_run,
            untouched: touched_by.is_empty() && !global,
            touched_by,
            held: (res.nodes[f].ship.as_deref() == Some("may-lag")).then(|| "declared may-lag, held required: uncalibrated".to_owned()),
        });
    }

    // 5. The planner.
    let plan_tests: Vec<u32> = affected.iter().collect();
    let mut by_pkg: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut by_file: HashMap<&str, Vec<u32>> = HashMap::new();
    let mut global_unit = None;
    for (u, (info, _)) in units.iter().enumerate() {
        match (info.pkg, &info.file) {
            (Some(p), Some(f)) => {
                by_pkg.entry(p).or_default().push(u as u32);
                by_file.entry(f.as_str()).or_default().push(u as u32);
            }
            _ => global_unit = Some(u as u32),
        }
    }
    let cu = |p: u32| by_pkg.get(&p).map_or(0u64, |v| v.len() as u64);
    // Without a package graph (git alone) a test has no package: only the global unit can notice.
    let no_closure = RoaringBitmap::new();
    let closure_of = |p: u32| closures.get(p as usize).unwrap_or(&no_closure);
    let direct_of = |p: u32| index.packages.get(p as usize).map_or(&[][..], |x| x.deps.as_slice());
    // Entries per relation, to decide which relations fit the budget.
    let mut tier_count = [0u64; 4];
    for &t in &plan_tests {
        let tp = table_.pkg[t as usize];
        let path = index.files[table_.file[t as usize] as usize].path.as_str();
        let same_file = by_file.get(path).map_or(0, |v| v.len() as u64);
        tier_count[0] += same_file;
        tier_count[1] += cu(tp) - same_file;
        let direct = direct_of(tp);
        for q in closure_of(tp) {
            if q == tp {
                continue;
            }
            tier_count[if direct.contains(&q) { 2 } else { 3 }] += cu(q);
        }
    }
    let tier_names = ["same file", "same package", "direct dependency", "transitive dependency"];
    let mut keep_tiers = 0usize;
    let mut total = 0u64;
    for (i, c) in tier_count.iter().enumerate() {
        if i < 2 || total + c <= max_notices {
            total += c;
            keep_tiers = i + 1;
        } else {
            break;
        }
    }
    let dropped: Vec<String> = (keep_tiers..4)
        .filter(|&i| tier_count[i] > 0)
        .map(|i| format!("{} ({} entries)", tier_names[i], num(tier_count[i])))
        .collect();

    let mut models: Vec<TestModel> = Vec::with_capacity(plan_tests.len());
    for &t in &plan_tests {
        let tp = table_.pkg[t as usize];
        let path = index.files[table_.file[t as usize] as usize].path.as_str();
        let mut notices: Vec<(u32, f32)> = Vec::new();
        let direct = direct_of(tp);
        for q in closure_of(tp) {
            let Some(us) = by_pkg.get(&q) else { continue };
            for &u in us {
                let same_file = units[u as usize].0.file.as_deref() == Some(path);
                let (tier, p) = if q == tp {
                    if same_file { (0, a::NOTICE_SAME_FILE) } else { (1, a::NOTICE_SAME_PACKAGE) }
                } else if direct.contains(&q) {
                    (2, a::NOTICE_DIRECT_DEP)
                } else {
                    (3, a::NOTICE_TRANSITIVE_DEP)
                };
                if tier < keep_tiers {
                    notices.push((u, p));
                }
            }
        }
        if let Some(g) = global_unit {
            notices.push((g, a::NOTICE_GLOBAL));
        }
        notices.sort_by_key(|n| n.0);
        models.push(TestModel {
            cost_ms: if table_.integration[t as usize] {
                a::COST_INTEGRATION_TEST_MS
            } else {
                a::COST_UNIT_TEST_MS
            },
            notices,
        });
    }
    let notices_kept: u64 = models.iter().map(|m| m.notices.len() as u64).sum();
    let mut report = PlanReport {
        base: base.to_owned(),
        head: head.to_owned(),
        index_note: String::new(),
        files,
        touches,
        tests_total: table_.len(),
        tests_affected: plan_tests.len(),
        checks_affected: checks_affected.len() as usize,
        checks_by_inputs,
        site_touches,
        gone_tests: facts.gone.clone(),
        checks_total,
        order_note: (!cargo).then(|| "there is no cargo package graph here, so no test binaries, no package closures and no ordering; what is affected comes from node ownership alone".to_owned()),
        targets,
        shared_link_units,
        features: feature_plans,
        units: units.len(),
        notices_kept,
        notices_dropped_tiers: dropped,
        initial_risk: 0.0,
        schedule_len: 0,
        first: Vec::new(),
        risk_after: Vec::new(),
        cut: None,
        diff_ms,
        plan_ms: 0,
        phase_ms: [t1.elapsed().as_millis(), 0, 0, 0],
        candidates: 0,
        assumptions: assumption_lines(),
    };
    if cargo && !plan_tests.is_empty() && !units.is_empty() {
        let costs: Vec<u32> = models.iter().map(|m| m.cost_ms).collect();
        let priors: Vec<f64> = units.iter().map(|(_, p)| *p).collect();

        // The planner's greedy order costs time quadratic in the number of
        // tests that share a unit, which is every test of a foundation crate.
        // So the order is computed over a candidate pool: the best tests by
        // initial doubt per millisecond, plus the best few for every unit so no
        // unit is left without a test. Risk is then measured over *all*
        // affected tests by replaying the order on a planner that knows them all.
        let avg_notices = (notices_kept / models.len().max(1) as u64).max(1);
        let limit = max_candidates.min((a::CANDIDATE_NOTICE_BUDGET / avg_notices).max(200) as usize);
        let pool = candidate_pool(&models, &priors, limit);
        report.candidates = pool.len();
        let cand_models: Vec<TestModel> = pool.iter().map(|&i| models[i].clone()).collect();
        let units_for = |p: &[f64]| p.iter().map(|&prior| Unit { prior }).collect::<Vec<_>>();
        let t_new = Instant::now();
        let candidate_planner = Planner::new(units_for(&priors), cand_models)
            .context("the planner rejected the inputs; this is a bug in how keel-tree builds units or notices")?;
        let mut full = Planner::new(units_for(&priors), models)
            .context("the planner rejected the inputs; this is a bug in how keel-tree builds units or notices")?;
        report.phase_ms[1] = t_new.elapsed().as_millis();
        let t_sched = Instant::now();
        let all: RoaringBitmap = (0..plan_tests.len() as u32).collect();
        report.initial_risk = full.residual_risk(&all);
        let schedule = candidate_planner.schedule();
        report.phase_ms[2] = t_sched.elapsed().as_millis();
        let t_replay = Instant::now();
        let removed_total: f64 = schedule.iter().map(|s| s.expected_removed).sum();
        report.schedule_len = schedule.len();
        let cut_ms = by_seconds.map(|s| (s * 1000.0) as u64);
        let cut_index = cut_ms.map(|ms| schedule.iter().take_while(|s| s.cumulative_ms <= ms).count());
        let mut want: BTreeSet<usize> = [10usize, 100, 1000, schedule.len()]
            .into_iter()
            .map(|n| n.min(schedule.len()))
            .filter(|&n| n > 0)
            .collect();
        want.extend(cut_index.filter(|&k| k > 0));
        want.extend(1..=15.min(schedule.len()));
        let mut risk_at: BTreeMap<usize, f64> = BTreeMap::new();
        for (i, s) in schedule.iter().enumerate() {
            full.observe(pool[s.test as usize] as u32, true);
            if want.contains(&(i + 1)) {
                risk_at.insert(i + 1, full.residual_risk(&all));
            }
        }
        for (i, s) in schedule.iter().take(15).enumerate() {
            let g = pool[s.test as usize];
            report.first.push(ScheduledTest {
                test: table_.ids[plan_tests[g] as usize].clone(),
                cost_ms: costs[g],
                expected_share: if removed_total > 0.0 { s.expected_removed / removed_total } else { 0.0 },
                cumulative_ms: s.cumulative_ms,
                residual_risk: risk_at[&(i + 1)],
                cut_here: cut_index == Some(i + 1),
            });
        }
        for n in [10usize, 100, 1000, schedule.len()] {
            let n = n.min(schedule.len());
            if n > 0 && !report.risk_after.iter().any(|r| r.after_tests == n) {
                report.risk_after.push(RiskPoint {
                    after_tests: n,
                    residual_risk: risk_at[&n],
                    cumulative_ms: schedule[n - 1].cumulative_ms,
                });
            }
        }
        if let (Some(s), Some(k)) = (by_seconds, cut_index) {
            report.cut = Some(CutReport {
                by_seconds: s,
                tests_before_cut: k,
                residual_risk: if k == 0 { report.initial_risk } else { risk_at[&k] },
            });
        }
        report.phase_ms[3] = t_replay.elapsed().as_millis();
    }
    report.plan_ms = t1.elapsed().as_millis();
    Ok(report)
}

fn assumption_lines() -> Vec<String> {
    vec![
        format!(
            "prior of a changed function = clamp({} + {}*branches + {}*lines_changed, {}, {}) (uncalibrated)",
            a::PRIOR_BASE, a::PRIOR_PER_BRANCH, a::PRIOR_PER_LINE, a::PRIOR_MIN, a::PRIOR_MAX
        ),
        format!("prior of a file changed outside functions, a non-Rust file, or global inputs = {} (uncalibrated)", a::PRIOR_OUTSIDE_ITEMS),
        format!(
            "a wrong unit is noticed by a test with probability {} in the test's own file, {} in its package, {} in a direct dependency, {} in a transitive one, {} for global inputs (all uncalibrated)",
            a::NOTICE_SAME_FILE, a::NOTICE_SAME_PACKAGE, a::NOTICE_DIRECT_DEP, a::NOTICE_TRANSITIVE_DEP, a::NOTICE_GLOBAL
        ),
        format!("cost {} ms per unit test, {} ms per integration test (assumed)", a::COST_UNIT_TEST_MS, a::COST_INTEGRATION_TEST_MS),
    ]
}

fn pct(p: f64) -> String {
    let p = p.max(0.0);
    if p >= 0.0001 { format!("{:.2}%", p * 100.0) } else { format!("{:.4}%", p * 100.0) }
}

fn secs(ms: u64) -> String {
    format!("{:.1}s", ms as f64 / 1000.0)
}

/// The text of a PR's `keel/plan` status: the nodes the change touches in the report's
/// order (foundation first), then how many tests it puts in doubt.
pub fn status_description(touched: &[&str], affected: usize, total: usize) -> String {
    let head = if touched.is_empty() { "touches no node".to_owned() } else { format!("touches {}", touched.join(", ")) };
    crate::verdict::clip_status(format!("{head}; {} of {} tests in doubt", num(affected as u64), num(total as u64)))
}

impl PlanReport {
    /// One commit status for a PR before anything is built. Informational, so always
    /// `success`: a plan says what is in doubt, never that anything passed.
    pub fn status(&self) -> crate::verdict::Status {
        let touched: Vec<&str> = self.touches.iter().map(|t| t.node.as_str()).collect();
        crate::verdict::Status {
            context: "keel/plan".to_owned(),
            state: "success",
            description: status_description(&touched, self.tests_affected, self.tests_total),
        }
    }

    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut o = String::new();
        let _ = writeln!(o, "plan {}..{}", self.base, self.head);
        let _ = writeln!(o, "{}", self.index_note);
        let _ = writeln!(o);

        let count = |c: Class| self.files.iter().filter(|f| f.class == c).count();
        let _ = writeln!(
            o,
            "changed files: {} ({} in packages, {} position-only, {} inert, {} global inputs)",
            self.files.len(),
            count(Class::Package),
            count(Class::PositionOnly),
            count(Class::Inert),
            count(Class::Global)
        );
        let global: Vec<&ChangedFile> = self.files.iter().filter(|f| f.class == Class::Global).collect();
        if !global.is_empty() {
            let _ = writeln!(o, "unowned files (every test and every matrix check is affected):");
            for f in global.iter().take(10) {
                let _ = writeln!(o, "  {}  {}", f.path, f.rule);
            }
            if global.len() > 10 {
                let _ = writeln!(o, "  ... and {} more with the same rule", global.len() - 10);
            }
        }
        let inert: Vec<&ChangedFile> = self.files.iter().filter(|f| f.class == Class::Inert).collect();
        if !inert.is_empty() {
            let mut by_rule: BTreeMap<&str, usize> = BTreeMap::new();
            for f in &inert {
                *by_rule.entry(f.rule.as_str()).or_default() += 1;
            }
            for (rule, n) in by_rule {
                let _ = writeln!(o, "{n} files: {rule}");
            }
        }
        let po = count(Class::PositionOnly);
        if po > 0 {
            let _ = writeln!(o, "{po} Rust files changed comments or whitespace only: they affect nothing");
        }

        if self.touches.is_empty() {
            let _ = writeln!(o, "\ntouches: no node owns an effective change");
        } else {
            let _ = writeln!(o, "\ntouches (foundation-first: layer 0 stands on nothing):");
            let mut rows = vec![vec!["  layer".to_owned(), "node".to_owned(), "files".to_owned(), "functions".to_owned()]];
            for t in &self.touches {
                rows.push(vec![format!("  {}", t.layer), t.node.clone(), t.files.to_string(), t.functions.to_string()]);
            }
            o.push_str(&table(&rows));
        }
        let unowned_files = self.files.iter().filter(|f| f.class == Class::Package && f.owner.is_none()).count();
        if unowned_files > 0 {
            let _ = writeln!(o, "  {unowned_files} changed files are owned by no node");
        }

        let _ = writeln!(
            o,
            "\ntests affected (by package closure): {} of {}",
            num(self.tests_affected as u64),
            num(self.tests_total as u64)
        );
        let _ = writeln!(o, "matrix checks affected: {} of {}", num(self.checks_affected as u64), num(self.checks_total as u64));
        if self.checks_by_inputs > 0 {
            let _ = writeln!(o, "  {} of them only because a declared input of the check or of its world changed", num(self.checks_by_inputs as u64));
        }
        for g in &self.gone_tests {
            let _ = writeln!(
                o,
                "tests that went away from {}{}: {}",
                g.path,
                g.moved_to.as_deref().map(|t| format!(" (the file moved to {t}, where they are new tests)")).unwrap_or_default(),
                g.tests.len()
            );
            for t in g.tests.iter().take(12) {
                let _ = writeln!(o, "  {t}");
            }
            if g.tests.len() > 12 {
                let _ = writeln!(o, "  ... and {} more", g.tests.len() - 12);
            }
        }
        if !self.site_touches.is_empty() {
            let _ = writeln!(o, "pattern sites reached ({}):", self.site_touches.len());
            for s in self.site_touches.iter().take(20) {
                let _ = writeln!(
                    o,
                    "  {} node `{}`: {}:{}-{}{}  {}",
                    if s.entry { "entry of" } else { "code of" },
                    s.node,
                    s.path,
                    s.start_line,
                    s.end_line,
                    s.item.as_deref().map(|i| format!(" ({i})")).unwrap_or_default(),
                    match &s.changed_function {
                        Some(f) => format!("the changed function `{f}` is {} of node `{}`", if s.entry { "an entry" } else { "code" }, s.node),
                        None => s.why.clone(),
                    }
                );
            }
        }
        if let Some(n) = &self.order_note {
            let _ = writeln!(o, "  note: {n}");
        }
        if !self.targets.is_empty() {
            let _ = writeln!(o, "affected test binaries, most tests first ({} binaries):", self.targets.len());
            let mut rows = vec![vec!["  affected".to_owned(), "packages linked".to_owned(), "reached".to_owned(), "binary".to_owned()]];
            for t in self.targets.iter().take(12) {
                rows.push(vec![
                    format!("  {}", num(t.affected as u64)),
                    t.packages_linked.to_string(),
                    if t.own_package_changed { "own package changed".to_owned() } else { "through dependencies".to_owned() },
                    t.target.clone(),
                ]);
            }
            o.push_str(&table(&rows));
            for l in &self.shared_link_units {
                let _ = writeln!(o, "  finding: {l}");
            }
        }
        let _ = writeln!(o, "features:");
        let mut rows = Vec::new();
        for f in &self.features {
            let verdict = if f.untouched {
                format!("untouched: 0 of {} to run, no input in its cone changed", num(f.tests_in_cone))
            } else if f.to_run == 0 {
                format!(
                    "0 of {} to run (touched via {}, but no test of the feature depends on a changed package)",
                    num(f.tests_in_cone),
                    f.touched_by.join(", ")
                )
            } else {
                format!("{} of {} to run", num(f.to_run), num(f.tests_in_cone))
            };
            rows.push(vec![format!("  {}", f.node), format!("{verdict}{}", f.held.as_deref().map(|h| format!("  [{h}]")).unwrap_or_default())]);
        }
        o.push_str(&table(&rows));

        let _ = writeln!(o, "\norder:");
        for l in &self.assumptions {
            let _ = writeln!(o, "  assumption: {l}");
        }
        let _ = writeln!(
            o,
            "  units: {} changed units; {} notice entries kept",
            num(self.units as u64),
            num(self.notices_kept)
        );
        if !self.notices_dropped_tiers.is_empty() {
            let _ = writeln!(
                o,
                "  too many (unit, test) pairs for one plan: dropped the weakest relations: {}",
                self.notices_dropped_tiers.join("; ")
            );
        }
        if self.schedule_len == 0 {
            let _ = writeln!(o, "  nothing to schedule: no affected test or no unit that a test could notice");
        } else {
            let _ = writeln!(
                o,
                "  risk before running anything: {} (uncalibrated)",
                pct(self.initial_risk)
            );
            let mut rows = vec![vec![
                "  #".to_owned(),
                "expected share (uncalibrated)".to_owned(),
                "ms".to_owned(),
                "cumulative".to_owned(),
                "risk left (uncalibrated)".to_owned(),
                "test".to_owned(),
            ]];
            for (i, s) in self.first.iter().enumerate() {
                rows.push(vec![
                    format!("  {}", i + 1),
                    pct(s.expected_share),
                    s.cost_ms.to_string(),
                    secs(s.cumulative_ms),
                    pct(s.residual_risk),
                    format!("{}{}", s.test, if s.cut_here { "   <- cut here" } else { "" }),
                ]);
            }
            o.push_str(&table(&rows));
            let _ = writeln!(o, "  residual risk after N tests (uncalibrated):");
            for r in &self.risk_after {
                let _ = writeln!(
                    o,
                    "    after {:>6} tests ({:>8}): {}",
                    num(r.after_tests as u64),
                    secs(r.cumulative_ms),
                    pct(r.residual_risk)
                );
            }
            let _ = writeln!(
                o,
                "  the order covers {} tests, chosen from a pool of {} candidates among the {} affected tests; the risk figures count all affected tests",
                num(self.schedule_len as u64),
                num(self.candidates as u64),
                num(self.tests_affected as u64)
            );
            if let Some(c) = &self.cut {
                let _ = writeln!(
                    o,
                    "  --by {}s: {} before the cut, residual risk {} (uncalibrated)",
                    c.by_seconds,
                    plural(c.tests_before_cut, "test", "tests"),
                    pct(c.residual_risk)
                );
            }
        }
        let _ = writeln!(o, "\ntiming: diff {} ms, planning {} ms (units and notices {} ms, planner setup {} ms, order {} ms, risk replay {} ms)", self.diff_ms, self.plan_ms, self.phase_ms[0], self.phase_ms[1], self.phase_ms[2], self.phase_ms[3]);
        o
    }
}

impl PlanReport {
    /// The PR comment before any test has run (Markdown, no tables: see keel-cli's
    /// comment.rs). It says what the change touches and how much is in doubt, and says
    /// plainly that a plan never claims a pass.
    pub fn comment(&self) -> String {
        use std::fmt::Write;
        let unowned = crate::resolve::UNOWNED;
        let total = self.tests_total as u64;
        let affected = self.tests_affected as u64;
        let global: Vec<&ChangedFile> = self.files.iter().filter(|f| f.class == Class::Global).collect();
        let nodes: Vec<&str> = self.touches.iter().map(|t| t.node.as_str()).filter(|n| global.is_empty() || *n != unowned).collect();

        // A file outside every cargo package is what puts everything in doubt; it is nearly
        // always one no node owns, and the head says so when that is all there is.
        let unowned_global = global.iter().filter(|f| f.owner.as_deref().is_none_or(|o| o == unowned)).count();
        let where_ = if unowned_global == global.len() { "no node owns" } else { "outside every cargo package" };
        let mut o = String::from("**Keel plan: this change touches ");
        if !global.is_empty() && nodes.is_empty() {
            let _ = writeln!(o, "only files {where_}; all {} tests are in doubt.**", num(total));
        } else if !global.is_empty() {
            let _ = writeln!(o, "{} and {} {where_}; all {} tests are in doubt.**", nodes.join(", "), counted(global.len() as u64, "file", "files"), num(total));
        } else if nodes.is_empty() {
            let _ = writeln!(o, "no node; {} of {} tests {} in doubt.**", num(affected), num(total), if affected == 1 { "is" } else { "are" });
        } else {
            let _ = writeln!(o, "{}; {} of {} tests {} in doubt.**", nodes.join(", "), num(affected), num(total), if affected == 1 { "is" } else { "are" });
        }
        o.push_str(
            "\nThis is a plan, not a result: no test has run, and nothing here says that any test passed or will pass. \
             A test is in doubt when the change can reach it through the packages it depends on.\n",
        );
        if !global.is_empty() {
            let shown: Vec<String> = global.iter().take(5).map(|f| format!("`{}`", f.path)).collect();
            let owners = if unowned_global == global.len() {
                format!(", and no node owns {}", if global.len() == 1 { "it" } else { "them" })
            } else if unowned_global > 0 {
                format!(", {unowned_global} of them owned by no node")
            } else {
                String::new()
            };
            let _ = write!(
                o,
                "\nEvery test and every matrix check is in doubt because {} outside every cargo package ({}{}){owners}. Nothing in the model says what depends on code there, \
                 so Keel treats it as reachable from anywhere. To narrow this, mark the files that cannot change what a test does as inert (`policy.inert`, with `keel.inert <glob> <reason>`); \
                 code inside a cargo package is followed through the packages that depend on it instead.\n",
                counted(global.len() as u64, "changed file lies", "changed files lie"),
                shown.join(", "),
                if global.len() > 5 { format!(" and {} more", global.len() - 5) } else { String::new() }
            );
        } else if self.touches.is_empty() {
            if self.files.is_empty() {
                o.push_str("\nThe two revisions do not differ in any file.\n");
            } else {
                let _ = write!(
                    o,
                    "\n{} changed, and none can change what a test does: they are inert (`policy.inert`) or changed comments and whitespace only.\n",
                    counted(self.files.len() as u64, "file", "files")
                );
            }
        }

        if !self.touches.is_empty() {
            o.push_str("\n### What it touches, foundation first\n");
            for t in &self.touches {
                let reaches: Vec<&str> = self.features.iter().filter(|f| f.touched_by.contains(&t.node)).map(|f| f.node.as_str()).collect();
                let sites = self.site_touches.iter().filter(|s| s.node == t.node).count();
                let mut line = if t.node == unowned {
                    let mut s = format!("- `{}` (layer 0): {} no node owns", t.node, counted(t.files as u64, "changed file", "changed files"));
                    // The rest lie in packages, where the closure says what they reach.
                    if unowned_global > 0 && unowned_global < t.files {
                        let _ = write!(s, ", {unowned_global} of them outside every cargo package");
                    }
                    s
                } else {
                    format!(
                        "- `{}` (layer {}): {} and {} changed",
                        t.node,
                        t.layer,
                        counted(t.files as u64, "file", "files"),
                        counted(t.functions as u64, "function", "functions")
                    )
                };
                if sites > 0 {
                    let _ = write!(line, ", {} reached", counted(sites as u64, "pattern site", "pattern sites"));
                }
                if t.node != unowned {
                    if reaches.is_empty() {
                        line.push_str("; no feature stands on it");
                    } else {
                        let _ = write!(line, "; features that stand on it: {}", reaches.iter().map(|f| format!("`{f}`")).collect::<Vec<_>>().join(", "));
                    }
                }
                o.push_str(&line);
                o.push('\n');
            }
        }

        if !self.features.is_empty() {
            o.push_str("\n### Features\n");
            let mut ordered: Vec<&FeaturePlan> = self.features.iter().collect();
            // Untouched ones last: the reader looks for what is in doubt.
            ordered.sort_by_key(|f| (f.untouched, std::cmp::Reverse(f.to_run)));
            for f in ordered {
                let what = if f.untouched {
                    format!("untouched, 0 of {} tests in doubt: no input in its cone changed", num(f.tests_in_cone))
                } else if f.to_run == 0 {
                    format!(
                        "0 of {} tests in doubt: touched via {}, but no test of the feature depends on a changed package",
                        num(f.tests_in_cone),
                        f.touched_by.join(", ")
                    )
                } else {
                    format!("{} of {} tests in doubt", num(f.to_run), num(f.tests_in_cone))
                };
                let _ = writeln!(o, "- `{}`: {what}{}", f.node, f.held.as_deref().map(|h| format!(" ({h})")).unwrap_or_default());
            }
        }

        let mut also: Vec<String> = Vec::new();
        if self.checks_total > 0 {
            also.push(format!("{} of {} matrix checks are in doubt", num(self.checks_affected as u64), num(self.checks_total as u64)));
        }
        for g in self.gone_tests.iter().take(3) {
            also.push(format!(
                "{} went away from `{}`{}: they are not run, and nothing says what replaced them",
                counted(g.tests.len() as u64, "test", "tests"),
                g.path,
                g.moved_to.as_deref().map(|t| format!(" (the file moved to `{t}`, where they are new tests)")).unwrap_or_default()
            ));
        }
        if self.gone_tests.len() > 3 {
            also.push(format!("{} more files lost tests; the full plan lists them", self.gone_tests.len() - 3));
        }
        if let Some(n) = &self.order_note {
            also.push(n.clone());
        }
        if !self.notices_dropped_tiers.is_empty() {
            also.push(format!(
                "the change was too big to order in full, so the weakest relations were dropped: {}",
                self.notices_dropped_tiers.join("; ")
            ));
        }
        if self.schedule_len > 0 {
            also.push(format!(
                // The risk figure stays in the folded plan: its probabilities are placeholders
                // until mutation data exists, and a percentage in a PR comment reads as measured.
                "{} are ordered by how much doubt each removes per second, chosen from {} candidates",
                counted(self.schedule_len as u64, "test", "tests"),
                num(self.candidates as u64)
            ));
        }
        if !also.is_empty() {
            o.push_str("\n### Also\n");
            for a in also {
                let _ = writeln!(o, "- {a}");
            }
        }
        crate::comment::assemble(&o, "The full plan", "plan", &self.render(), "")
    }
}

/// `rev` as `<short hash> <subject>`, for the header; falls back to the name.
pub fn describe_rev(root: &Path, rev: &str) -> String {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["log", "-1", "--format=%h %s", rev])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().chars().take(100).collect(),
        _ => rev.to_owned(),
    }
}

pub fn head_note(root: &Path) -> String {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["log", "-1", "--format=%h"])
        .output();
    let h = out
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    format!(
        "index: the checkout at {h}, not the revisions compared. Packages, owners and tests are the checkout's; \
         a file the checkout no longer has is placed by the package directory it lay in."
    )
}

/// Indices of the tests worth ordering: the `limit` best by initial doubt per
/// millisecond, plus for every unit the test that notices it best per
/// millisecond (the pool never exceeds twice `limit`). Ties break by the smaller index, so the pool is deterministic.
fn candidate_pool(models: &[TestModel], priors: &[f64], limit: usize) -> Vec<usize> {
    if models.len() <= limit {
        return (0..models.len()).collect();
    }
    let score = |m: &TestModel| -> f64 {
        m.notices.iter().map(|&(u, d)| priors[u as usize] * f64::from(d)).sum::<f64>() / f64::from(m.cost_ms)
    };
    let mut order: Vec<(f64, usize)> = models.iter().enumerate().map(|(i, m)| (score(m), i)).collect();
    order.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut keep: BTreeSet<usize> = order.iter().take(limit).map(|&(_, i)| i).collect();
    let mut best: Vec<[(f64, usize); 2]> = vec![[(0.0, usize::MAX); 2]; priors.len()];
    for (i, m) in models.iter().enumerate() {
        for &(u, d) in &m.notices {
            let s = f64::from(d) / f64::from(m.cost_ms);
            let slot = &mut best[u as usize];
            if s > slot[0].0 {
                slot[1] = slot[0];
                slot[0] = (s, i);
            } else if s > slot[1].0 {
                slot[1] = (s, i);
            }
        }
    }
    keep.extend(best.iter().map(|b| b[0]).filter(|(_, i)| *i != usize::MAX).map(|(_, i)| i));
    // Per-unit extras must not grow the pool without bound on a merge that changes
    // thousands of functions: keep the best twice-`limit` by initial score.
    let rank: HashMap<usize, usize> = order.iter().enumerate().map(|(r, &(_, i))| (i, r)).collect();
    let mut pool: Vec<usize> = keep.into_iter().collect();
    if pool.len() > 2 * limit {
        pool.sort_by_key(|i| rank[i]);
        pool.truncate(2 * limit);
        pool.sort_unstable();
    }
    pool
}

#[cfg(test)]
mod comment_tests {
    use super::*;

    fn file(path: &str, class: Class, owner: Option<&str>) -> ChangedFile {
        ChangedFile { path: path.to_owned(), status: "modified".to_owned(), class, rule: "rule".to_owned(), package: None, owner: owner.map(str::to_owned), functions: 0 }
    }

    fn feature(node: &str, in_cone: u64, to_run: u64, touched_by: &[&str], held: bool) -> FeaturePlan {
        FeaturePlan {
            node: node.to_owned(),
            tests_in_cone: in_cone,
            to_run,
            untouched: touched_by.is_empty(),
            touched_by: touched_by.iter().map(|s| (*s).to_owned()).collect(),
            held: held.then(|| "declared may-lag, held required: uncalibrated".to_owned()),
        }
    }

    /// A plan with nothing in it; each test fills in what it is about.
    fn report() -> PlanReport {
        PlanReport {
            base: "aaaa111 base".to_owned(),
            head: "bbbb222 head".to_owned(),
            index_note: "index: the checkout".to_owned(),
            files: Vec::new(),
            touches: Vec::new(),
            tests_total: 15_496,
            tests_affected: 0,
            checks_affected: 0,
            checks_by_inputs: 0,
            checks_total: 256,
            site_touches: Vec::new(),
            gone_tests: Vec::new(),
            order_note: None,
            targets: Vec::new(),
            shared_link_units: Vec::new(),
            features: Vec::new(),
            units: 0,
            notices_kept: 0,
            notices_dropped_tiers: Vec::new(),
            initial_risk: 0.0,
            schedule_len: 0,
            first: Vec::new(),
            risk_after: Vec::new(),
            cut: None,
            diff_ms: 1,
            plan_ms: 1,
            phase_ms: [0; 4],
            candidates: 0,
            assumptions: Vec::new(),
        }
    }

    fn touch(node: &str, layer: usize, files: usize, functions: usize) -> Touch {
        Touch { node: node.to_owned(), layer, files, functions }
    }

    #[test]
    fn a_change_to_owned_code_names_the_nodes_foundation_first_and_what_is_in_doubt() {
        let mut r = report();
        r.tests_affected = 10_554;
        r.files = vec![file("crates/engine/src/a.rs", Class::Package, Some("engine")), file("crates/service/src/b.rs", Class::Package, Some("service"))];
        r.touches = vec![touch("engine", 8, 3, 17), touch("service", 9, 1, 2)];
        r.features = vec![
            feature("indexing", 11_022, 0, &[], false),
            feature("cli", 11_022, 8_235, &["engine", "service"], false),
            feature("desktop", 14_784, 9_905, &["service"], true),
        ];
        let c = r.comment();
        let lines: Vec<&str> = c.lines().collect();
        assert_eq!(lines[0], "**Keel plan: this change touches engine, service; 10,554 of 15,496 tests are in doubt.**");
        assert!(c.contains("This is a plan, not a result: no test has run, and nothing here says that any test passed or will pass."));
        assert!(lines.contains(&"- `engine` (layer 8): 3 files and 17 functions changed; features that stand on it: `cli`"), "{c}");
        assert!(lines.contains(&"- `service` (layer 9): 1 file and 2 functions changed; features that stand on it: `cli`, `desktop`"), "{c}");
        // Foundation first; features in doubt before the untouched one.
        assert!(c.find("`engine` (layer 8)").unwrap() < c.find("`service` (layer 9)").unwrap());
        let f: Vec<&str> = lines.iter().copied().filter(|l| l.starts_with("- `cli`: ") || l.starts_with("- `desktop`: ") || l.starts_with("- `indexing`: ")).collect();
        assert_eq!(
            f,
            [
                "- `desktop`: 9,905 of 14,784 tests in doubt (declared may-lag, held required: uncalibrated)",
                "- `cli`: 8,235 of 11,022 tests in doubt",
                "- `indexing`: untouched, 0 of 11,022 tests in doubt: no input in its cone changed",
            ]
        );
        assert!(c.contains("<details><summary>The full plan</summary>\n\n```text\nplan aaaa111 base..bbbb222 head\n"));
        assert!(!c.contains("no node owns"));
    }

    #[test]
    fn a_change_to_files_no_node_owns_says_why_everything_is_in_doubt() {
        let mut r = report();
        r.tests_affected = 15_496;
        r.files = vec![file(".config/ci/linux.nu", Class::Global, Some("unowned")), file(".config/nix/checks.nix", Class::Global, Some("unowned"))];
        r.touches = vec![touch("unowned", 0, 2, 0)];
        r.features = vec![feature("cli", 11_022, 11_022, &["unowned"], false)];
        let c = r.comment();
        let lines: Vec<&str> = c.lines().collect();
        assert_eq!(lines[0], "**Keel plan: this change touches only files no node owns; all 15,496 tests are in doubt.**");
        assert!(c.contains("Every test and every matrix check is in doubt because 2 changed files lie outside every cargo package (`.config/ci/linux.nu`, `.config/nix/checks.nix`), and no node owns them."), "{c}");
        assert!(c.contains("Nothing in the model says what depends on code there"));
        assert!(c.contains("`policy.inert`"));
        assert!(lines.contains(&"- `unowned` (layer 0): 2 changed files no node owns"), "{c}");
        assert!(lines.contains(&"- `cli`: 11,022 of 11,022 tests in doubt"));
        // With owned code beside it the head names both.
        r.touches = vec![touch("unowned", 0, 2, 0), touch("engine", 8, 1, 3)];
        assert_eq!(r.comment().lines().next().unwrap(), "**Keel plan: this change touches engine and 2 files no node owns; all 15,496 tests are in doubt.**");
        // Unowned files inside packages are followed through the closure; only the two outside
        // every package put everything in doubt, and the bullet says which are which.
        r.touches = vec![touch("unowned", 0, 7, 0)];
        assert!(r.comment().lines().any(|l| l == "- `unowned` (layer 0): 7 changed files no node owns, 2 of them outside every cargo package"));
        // A file a node owns but no package holds is outside every package all the same.
        r.files.push(file("docs/guide.md", Class::Global, Some("library")));
        assert_eq!(r.comment().lines().next().unwrap(), "**Keel plan: this change touches only files outside every cargo package; all 15,496 tests are in doubt.**");
    }

    #[test]
    fn a_change_no_test_can_notice_says_so() {
        let mut r = report();
        r.files = vec![file("README.md", Class::Inert, None), file("crates/engine/src/a.rs", Class::PositionOnly, Some("engine"))];
        let c = r.comment();
        assert_eq!(c.lines().next().unwrap(), "**Keel plan: this change touches no node; 0 of 15,496 tests are in doubt.**");
        assert!(c.contains("2 files changed, and none can change what a test does"), "{c}");
        assert!(!c.contains("### What it touches"));
        assert!(report().comment().contains("The two revisions do not differ in any file."));
        r.tests_affected = 1;
        r.touches = vec![touch("engine", 8, 1, 1)];
        assert_eq!(r.comment().lines().next().unwrap(), "**Keel plan: this change touches engine; 1 of 15,496 tests is in doubt.**");
    }

    #[test]
    fn a_plan_over_the_limit_loses_plan_text_and_keeps_its_head() {
        let mut r = report();
        r.tests_affected = 10;
        r.touches = vec![touch("engine", 8, 1, 1)];
        r.targets = (0..3_000)
            .map(|i| TargetLine { target: format!("backend-engine::integration_test_number_{i}"), affected: 5, packages_linked: 41, own_package_changed: false })
            .collect();
        r.shared_link_units = (0..3_000).map(|i| format!("these {i} tests share one link unit and are reached only through dependencies")).collect();
        assert!(r.render().chars().count() > 100_000);
        let c = r.comment();
        assert!(c.chars().count() <= 60_000, "{} characters", c.chars().count());
        assert!(c.starts_with("**Keel plan: this change touches engine; 10 of 15,496 tests are in doubt.**\n"));
        assert!(c.contains("The full plan (the first ") && c.contains("The whole plan is in the CI log"));
    }
}
