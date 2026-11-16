//! `check`: evaluate, resolve, and say what is wrong with the model.

use crate::finding::{Finding, Severity, short_at};
use crate::lock::{self, Lock};
use crate::model::Model;
use crate::resolve::Resolution;
use crate::testset::{AxisSummary, TestTable, place};
use crate::text::{num, plural, wrap};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::Path;

#[derive(Serialize)]
pub struct CheckReport {
    pub findings: Vec<Finding>,
    pub summary: Summary,
    pub lock: Option<LockReport>,
}

/// A test set from `policy`, with how many tests and matrix checks it selects.
#[derive(Serialize)]
pub struct PolicySet {
    pub path: String,
    pub set: String,
    pub tests: u64,
    pub checks: u64,
}

#[derive(Serialize)]
pub struct LockReport {
    pub path: String,
    /// Where the lock went: `path`, or `path.rejected` when check had errors.
    pub written_to: String,
    pub rejected: bool,
    pub existed: bool,
    pub changes: Vec<String>,
}

#[derive(Serialize)]
pub struct Summary {
    pub nodes: usize,
    pub nodes_with_ship: usize,
    /// Nodes `nodesFromCrates` made, one per workspace package no node claimed.
    pub nodes_from_crates: usize,
    /// Nodes with a ship policy, not counting the synthetic `unowned`: the trees people ask about.
    pub features: usize,
    /// Every tracked file by owner: owned + unowned + inert = tracked.
    pub census: crate::resolve::Census,
    pub files_indexed: usize,
    pub unowned_packages: BTreeMap<String, usize>,
    pub tests_in_table: usize,
    pub tests_excluded_ignored: usize,
    pub tests_excluded_outside_packages: usize,
    /// Tests of packages that are no workspace member.
    pub tests_excluded_nonmember: usize,
    /// Packages under the root, and how many of them are workspace members.
    pub packages: usize,
    pub packages_members: usize,
    pub tests_without_home: usize,
    pub tests_placed: u64,
    pub axes: Vec<AxisSummary>,
    pub check_cells: usize,
    pub coverage: crate::coverage::CoverageSummary,
    /// Censuses whose observation was a value, compared with what was declared.
    pub census_compared: usize,
    /// Censuses observed at run time by a command: nothing here ran them.
    pub census_not_run: Vec<String>,
    pub faults: crate::enforce::FaultSummary,
    /// `policy.inert` entries, each with its reason and the tracked files it matches.
    pub inert: Vec<crate::enforce::InertLine>,
    /// Parts of the model read into typed fields that no rule acts on yet.
    pub read_not_enforced: Vec<crate::enforce::Unenforced>,
    pub policy_sets: Vec<PolicySet>,
    pub source: String,
}

pub fn run(
    model: &Model,
    res: &Resolution<'_>,
    table: &TestTable,
    lock_path: Option<&Path>,
    accept: bool,
) -> Result<CheckReport> {
    run_with(model, res, table, lock_path, accept, false)
}

/// `strict`: a census nothing here ran is an error, not a warning, for a gate that requires
/// every census to have been compared.
pub fn run_with(
    model: &Model,
    res: &Resolution<'_>,
    table: &TestTable,
    lock_path: Option<&Path>,
    accept: bool,
    strict: bool,
) -> Result<CheckReport> {
    let mut findings = res.findings.clone();
    // The last accepted lock: the baseline of the diff and of the uncovered ratchet.
    let old: Option<Lock> = match lock_path {
        None => None,
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) => Some(serde_json::from_str(&text).with_context(|| {
                format!("the lock at {} is not a keel-tree lock; delete it or point --lock elsewhere", path.display())
            })?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("cannot read the lock at {}", path.display())),
        },
    };
    // A check cell that says it exercises a node the model lacks would be
    // silently unattributed in every later report.
    for (name, group) in &model.checks {
        let mut unknown: BTreeMap<&str, usize> = BTreeMap::new();
        for cell in &group.checks {
            for n in &cell.on {
                if res.node_index(n).is_none() {
                    *unknown.entry(n.as_str()).or_default() += 1;
                }
            }
        }
        for (n, count) in unknown {
            findings.push(Finding::error(
                "unknown-node",
                format!(
                    "checks.{name}: {count} cells list node \"{n}\" in `on`, which the model does not define; fix the node reference in the matrix."
                ),
            ));
        }
    }
    findings.extend(input_findings(model, res));
    let (census_f, census_summary) = census_findings(model, res, strict);
    findings.extend(census_f);
    if let Some(why) = res.tracked_error() {
        findings.push(Finding::error("git-failed", why.to_owned()));
    }
    findings.extend(crate::enforce::unread_finding(model));
    if let Some(note) = &res.index.graph_note {
        findings.push(Finding::warning("package-graph-unresolved", note.clone()));
    }
    let unreadable = crate::source::unreadable(res.index);
    if !unreadable.is_empty() {
        let shown: Vec<String> = unreadable.iter().take(5).map(|(p, e)| format!("{p} ({e})")).collect();
        findings.push(Finding::warning(
            "files-unreadable",
            format!(
                "git lists {} Rust files that cannot be read, so their tests and functions are not in the index: {}{}. Restore or remove them (a deleted file still tracked shows as `D` in git status).",
                unreadable.len(),
                shown.join(", "),
                if unreadable.len() > shown.len() { ", ..." } else { "" }
            ),
        ));
    }
    let (fault_f, fault_summary) = crate::enforce::fault_findings(model, res);
    findings.extend(fault_f);
    let (policy_f, policy_sets) = policy_findings(model, res, table);
    findings.extend(policy_f);
    let previous = old.as_ref().and_then(lock::uncovered_set);
    let crate::coverage::Outcome { findings: cov_findings, summary: coverage, uncovered } =
        crate::coverage::run(model, res, table, previous.as_ref(), accept);
    findings.extend(cov_findings);
    // The baseline moves only on --accept. Without it the lock keeps the accepted one,
    // even when edges got covered, and says so.
    let kept_baseline: Option<Vec<[String; 2]>> = if accept {
        None
    } else {
        old.as_ref().and_then(|o| o.uncovered.clone())
    };
    if let (Some(base), false) = (&kept_baseline, accept) {
        let now: BTreeSet<&[String; 2]> = uncovered.iter().collect();
        let gone = base.iter().filter(|e| !now.contains(e)).count();
        if gone > 0 {
            findings.push(Finding::info(
                "baseline-can-tighten",
                format!("{gone} edges in the accepted baseline are no longer uncovered; rerun with --accept to tighten it."),
            ));
        }
    }
    let placement = place(model, res, table);
    findings.extend(placement.findings.clone());
    findings.sort_by(|a, b| (a.severity, a.code, &a.node, &a.message).cmp(&(b.severity, b.code, &b.node, &b.message)));

    let unowned_packages = res.unowned_by_package();
    let summary = Summary {
        nodes: res.nodes.len(),
        nodes_with_ship: res.nodes.iter().filter(|n| n.ship.is_some()).count(),
        nodes_from_crates: res.nodes.iter().filter(|n| n.from_crate.is_some()).count(),
        features: crate::tree::features(res).into_iter().filter(|&f| f != res.unowned).count(),
        census: res.census(),
        files_indexed: res.index.files.len(),
        unowned_packages,
        tests_in_table: table.len(),
        tests_excluded_ignored: table.excluded_ignored,
        tests_excluded_outside_packages: table.excluded_outside,
        tests_excluded_nonmember: table.excluded_nonmember,
        packages: res.index.packages.len(),
        packages_members: res.index.packages.iter().filter(|p| p.member).count(),
        tests_without_home: table.home.iter().filter(|h| h.is_none()).count(),
        tests_placed: placement.placed,
        axes: placement.summary,
        check_cells: model.checks.values().map(|g| g.checks.len()).sum(),
        coverage,
        census_compared: census_summary.0,
        census_not_run: census_summary.1,
        faults: fault_summary,
        inert: crate::enforce::inert_report(model, res),
        read_not_enforced: crate::enforce::unenforced(model),
        policy_sets,
        source: res.no_cargo().map_or_else(|| "cargo index".to_owned(), |why| format!("git only ({why})")),
    };

    let lock = match lock_path {
        None => None,
        Some(path) => {
            // An empty set admits nothing, so it may be recorded without the flag.
            let recorded = match &kept_baseline {
                Some(base) => base.clone(),
                None => uncovered.clone(),
            };
            let mut new = res.lock(&recorded);
            if !accept && kept_baseline.is_none() && !uncovered.is_empty() {
                // No accepted baseline and edges to review: the lock carries the current
                // list only as a rejected lock (check has errors in that case).
                new = res.lock(&uncovered);
            }
            let changes = old.as_ref().map(|o| lock::diff(o, &new)).unwrap_or_default();
            let rejected = findings.iter().any(|f| f.severity == Severity::Error);
            let target = if rejected {
                let mut p = path.as_os_str().to_owned();
                p.push(".rejected");
                std::path::PathBuf::from(p)
            } else {
                path.to_path_buf()
            };
            let mut text = serde_json::to_string_pretty(&new)?;
            text.push('\n');
            std::fs::write(&target, text)
                .with_context(|| format!("cannot write the lock to {}; choose a writable --lock path", target.display()))?;
            Some(LockReport {
                path: path.display().to_string(),
                written_to: target.display().to_string(),
                rejected,
                existed: old.is_some(),
                changes,
            })
        }
    };
    Ok(CheckReport {
        findings,
        summary,
        lock,
    })
}

/// Examples a folded entry shows; the rest are one flag away.
const EXAMPLES: usize = 3;

/// One line of the text report: a finding as it is, or the findings of one kind that share their
/// advice.
pub enum Entry<'a> {
    One(&'a Finding),
    Many { advice: &'a str, members: Vec<&'a Finding> },
}

/// Folds the findings of one severity. A finding joins the group of its code and advice; one that
/// says nothing shareable, or has no sibling, stays whole. Smaller entries come first: the kinds
/// that fill a report are the ones a person has already decided about, and the odd one out is
/// the one to read.
pub fn fold<'a>(findings: &[&'a Finding], all: bool) -> Vec<Entry<'a>> {
    if all {
        return findings.iter().map(|&f| Entry::One(f)).collect();
    }
    let mut groups: Vec<(&'static str, Option<&'a str>, Vec<&'a Finding>)> = Vec::new();
    for &f in findings {
        let advice = f.shared.as_ref().map(|s| s.advice.as_str());
        match groups.iter_mut().find(|g| advice.is_some() && g.0 == f.code && g.1 == advice) {
            Some(g) => g.2.push(f),
            None => groups.push((f.code, advice, vec![f])),
        }
    }
    groups.sort_by_key(|g| g.2.len());
    groups
        .into_iter()
        .flat_map(|(_, advice, members)| match (advice, members.len()) {
            (Some(advice), n) if n > 1 => vec![Entry::Many { advice, members }],
            _ => members.into_iter().map(Entry::One).collect(),
        })
        .collect()
}

impl CheckReport {
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Error)
    }

    /// The line a reader needs before any finding: whether the model holds, how big it is, and
    /// how much there is to read. `unowned` is the engine's, not the model's, so it is not counted.
    pub fn headline(&self) -> String {
        let s = &self.summary;
        let count = |sev: Severity| self.findings.iter().filter(|f| f.severity == sev).count();
        let errors = count(Severity::Error);
        let kinds: BTreeSet<(Severity, &str)> = self.findings.iter().map(|f| (f.severity, f.code)).collect();
        let verdict = if errors == 0 { "model ok".to_owned() } else { format!("model has {}", plural(errors, "error", "errors")) };
        let mut kinds_of_node = Vec::new();
        if s.nodes_from_crates > 0 {
            kinds_of_node.push(format!("{} from crates", s.nodes_from_crates));
        }
        kinds_of_node.push(plural(s.features, "feature", "features"));
        format!(
            "{verdict}: {} nodes ({}), {} tests, {} check cells; {}, {}, {} in {}",
            s.nodes.saturating_sub(1),
            kinds_of_node.join(", "),
            num(s.tests_in_table as u64),
            num(s.check_cells as u64),
            plural(errors, "error", "errors"),
            plural(count(Severity::Warning), "warning", "warnings"),
            plural(count(Severity::Info), "info", "infos"),
            plural(kinds.len(), "kind", "kinds"),
        )
    }

    pub fn render(&self) -> String {
        self.render_with(false)
    }

    /// `all`: one entry per finding. Without it, findings of one kind and severity that say the
    /// same thing about different subjects are folded into one entry with a few examples.
    pub fn render_with(&self, all: bool) -> String {
        let mut o = String::new();
        let _ = writeln!(o, "{}\n", self.headline());
        for sev in [Severity::Error, Severity::Warning, Severity::Info] {
            let fs: Vec<&Finding> = self.findings.iter().filter(|f| f.severity == sev).collect();
            if fs.is_empty() {
                continue;
            }
            let _ = writeln!(o, "{}s ({})", sev.label(), fs.len());
            for entry in fold(&fs, all) {
                match entry {
                    Entry::One(f) => {
                        let mut head = format!("  {}  {}", sev.label(), f.code);
                        if let Some(n) = &f.node {
                            let _ = write!(head, "  node {n}");
                        }
                        if let Some(at) = &f.at {
                            let _ = write!(head, "  at {}", short_at(at));
                        }
                        let _ = writeln!(o, "{head}");
                        o.push_str(&wrap(&f.message, "      ", 110));
                    }
                    Entry::Many { advice, members } => {
                        let nodes: BTreeSet<&str> = members.iter().filter_map(|f| f.node.as_deref()).collect();
                        let mut head = format!("  {}  {}  {}", sev.label(), members[0].code, plural(members.len(), "entry", "entries"));
                        if !nodes.is_empty() {
                            let _ = write!(head, " on {}", plural(nodes.len(), "node", "nodes"));
                        }
                        let _ = writeln!(o, "{head}");
                        o.push_str(&wrap(advice, "      ", 110));
                        for f in members.iter().take(EXAMPLES) {
                            let shared = f.shared.as_ref().expect("a folded finding is a shared one");
                            let at = f.at.as_deref().map(|a| format!("  at {}", short_at(a))).unwrap_or_default();
                            let _ = writeln!(o, "        {}{at}", shared.entry);
                        }
                        if members.len() > EXAMPLES {
                            let _ = writeln!(o, "        and {} more; --all lists every entry", members.len() - EXAMPLES);
                        }
                    }
                }
            }
            o.push('\n');
        }
        if self.findings.is_empty() {
            o.push_str("no findings\n\n");
        }
        let s = &self.summary;
        let _ = writeln!(o, "summary");
        let _ = writeln!(
            o,
            "  nodes      {} ({} made from crates by nodesFromCrates, {} with a ship policy, including the synthetic `unowned`)",
            s.nodes, s.nodes_from_crates, s.nodes_with_ship
        );
        let c = &s.census;
        let _ = writeln!(
            o,
            "  files      {} tracked = {} owned by a node + {} unowned + {} inert{}",
            num(c.tracked as u64),
            num(c.owned as u64),
            num(c.unowned as u64),
            num(c.inert as u64),
            if c.conflict > 0 { format!("  (+ {} in ownership conflict)", c.conflict) } else { String::new() }
        );
        let _ = writeln!(
            o,
            "  unowned    {} files: {} in {} (see below), {} in no cargo package; {} Rust files under a tests or fixtures directory, {} Rust files holding test functions",
            num(c.unowned as u64),
            num(c.unowned.saturating_sub(c.unowned_outside_packages) as u64),
            plural(s.unowned_packages.len(), "unowned package", "unowned packages"),
            num(c.unowned_outside_packages as u64),
            num(c.unowned_rust_test_dir as u64),
            num(c.unowned_rust_with_test_fns as u64)
        );
        let mut dirs: Vec<(&String, &(usize, usize))> = c.unowned_by_dir.iter().collect();
        dirs.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(a.0.cmp(b.0)));
        for (d, (n, t)) in dirs {
            let _ = writeln!(o, "    {d:28}  {:>6} files  {:>5} Rust test or fixture files", num(*n as u64), num(*t as u64));
        }
        if !s.unowned_packages.is_empty() {
            let _ = writeln!(o, "  unowned packages (workspace packages no node claims, with their file counts):");
            let mut rows: Vec<(&String, &usize)> = s.unowned_packages.iter().collect();
            rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            let width = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
            for (name, count) in rows {
                let _ = writeln!(o, "    {name:width$}  {count}");
            }
        }
        let _ = writeln!(
            o,
            "  tests      {} in the table (by package closure; {} ignored, {} outside every package and {} in packages that are no workspace member left out); {} have no home node; {} placed on at least one axis",
            num(s.tests_in_table as u64),
            num(s.tests_excluded_ignored as u64),
            num(s.tests_excluded_outside_packages as u64),
            num(s.tests_excluded_nonmember as u64),
            s.tests_without_home,
            num(s.tests_placed),
        );
        for a in &s.axes {
            let values: Vec<String> = a.values.iter().map(|v| format!("{}={}", v.value, num(v.tests))).collect();
            let by_default = a.default.as_ref().map(|d| format!("; {} of them by the axis default `{d}`", num(a.defaulted))).unwrap_or_default();
            let _ = writeln!(o, "  axis {}: tests {}; no value={}{by_default}", a.axis, values.join(" "), num(a.unplaced));
            let cv: Vec<String> = a.checks.iter().map(|v| format!("{}={}", v.value, num(v.tests))).collect();
            let _ = writeln!(o, "  axis {}: check cells {}; no value={}", a.axis, cv.join(" "), num(a.checks_unplaced));
        }
        let _ = writeln!(o, "  packages   {} under the repository root, {} of them workspace members", s.packages, s.packages_members);
        let _ = writeln!(o, "  checks     {} cells in the model", s.check_cells);
        if s.census_compared + s.census_not_run.len() > 0 {
            let _ = writeln!(
                o,
                "  census     {} compared; {} NOT RUN{}",
                s.census_compared,
                s.census_not_run.len(),
                if s.census_not_run.is_empty() { String::new() } else { format!(" ({})", s.census_not_run.join(", ")) }
            );
        }
        let c = &s.coverage;
        let _ = writeln!(
            o,
            "  coverage   {} stands-on edges (policy.uncovered = {}): {} covered by a test, {} covered by a breaking twin, {} declared only (a check lists both in `on`, no control or fault breaks either: not evidence), {} uncovered, {} unverifiable (entry-only node under package reach), {} new against the last accepted lock, {} with no accepted baseline; {} join pairs, {} uncovered",
            c.edges, c.policy, c.covered_by_tests, c.covered_by_breaking_twin, c.declared_only, c.uncovered, c.unverifiable, c.new_uncovered, c.no_baseline, c.join_pairs, c.joins_uncovered
        );
        let f = &s.faults;
        let _ = writeln!(
            o,
            "  faults     {} stands-on edges (policy.faults = {}): {} with a fault check that takes the lower end away, {} excused in policy.unfaulted, {} never faulted",
            f.edges, f.policy, f.faulted, f.excused, f.unfaulted
        );
        if !s.inert.is_empty() {
            let _ = writeln!(o, "  inert      {} entries in policy.inert:", s.inert.len());
            for i in &s.inert {
                let _ = writeln!(o, "    {}  ({} tracked files)  {}", i.glob, num(i.files as u64), i.reason);
            }
        }
        if !s.read_not_enforced.is_empty() {
            let _ = writeln!(o, "  read and not yet enforced (parsed into typed fields; no rule acts on them yet):");
            for u in &s.read_not_enforced {
                let _ = writeln!(o, "    {}  x{}  {}", u.name, u.count, u.what);
            }
        }
        for p in &s.policy_sets {
            let _ = writeln!(o, "  {}: {} tests, {} checks  ({})", p.path, num(p.tests), num(p.checks), p.set);
        }
        let _ = writeln!(o, "  files from {}", s.source);
        if let Some(l) = &self.lock {
            let _ = writeln!(o);
            if l.rejected {
                let _ = writeln!(
                    o,
                    "lock NOT updated: check has errors, so the lock this run would have written is {} and {} {}",
                    l.written_to,
                    l.path,
                    if l.existed { "stays the last accepted lock" } else { "does not exist (no lock has been accepted yet)" }
                );
                if l.existed && l.changes.is_empty() {
                    let _ = writeln!(o, "  it would not differ from the accepted lock");
                }
                for c in &l.changes {
                    let _ = writeln!(o, "  against the accepted lock: {c}");
                }
            } else if !l.existed {
                let _ = writeln!(o, "lock written to {} (no previous lock)", l.path);
            } else if l.changes.is_empty() {
                let _ = writeln!(o, "lock written to {}: unchanged", l.path);
            } else {
                let _ = writeln!(o, "lock written to {}: {} changed", l.path, plural(l.changes.len(), "line", "lines"));
                for c in &l.changes {
                    let _ = writeln!(o, "  {c}");
                }
            }
        }
        o
    }
}

/// Every record a census found on one side only. A census whose observation is a command has no
/// result until the driver runs it; that is said, not skipped.
fn census_findings(model: &Model, res: &Resolution<'_>, strict: bool) -> (Vec<Finding>, (usize, Vec<String>)) {
    let mut out = Vec::new();
    let (mut compared, mut not_run) = (0, Vec::new());
    // The sites are read once, and only if some census takes a boundary class as its source.
    let mut sites: Option<Result<Vec<crate::boundaries::Site>, String>> = None;
    for c in &model.census {
        let at = c.at.as_deref().map(short_at);
        let computed;
        let result = match (&c.result, &c.boundary) {
            (Some(r), _) => Some(r),
            (None, Some(class)) => {
                let all = sites.get_or_insert_with(|| production_sites(res));
                match all.as_ref().map_err(Clone::clone).and_then(|s| boundary_result(c, class, s)) {
                    Ok(r) => {
                        computed = r;
                        Some(&computed)
                    }
                    Err(why) => {
                        let mut f = Finding::error("census-boundary", format!("census `{}`{}: {why}", c.name, at.as_deref().map(|a| format!(" ({a})")).unwrap_or_default()));
                        f.at = c.at.clone();
                        out.push(f);
                        continue;
                    }
                }
            }
            (None, None) => None,
        };
        let Some(result) = result else {
            not_run.push(c.name.clone());
            let msg = format!(
                "census `{}`{}: NOT RUN. Its records are observed at run time by a command and nothing here ran it, so nothing was compared with the declared ones. {}",
                c.name,
                at.as_deref().map(|a| format!(" ({a})")).unwrap_or_default(),
                if strict { "`check --strict` fails on a census that was not run; run it and pass its result, or drop --strict where that is understood." } else { "Pass --strict where a gate requires every census to have been compared." }
            );
            let mut f = if strict { Finding::error("census-not-run", msg) } else { Finding::warning("census-not-run", msg) };
            f.at = c.at.clone();
            out.push(f);
            continue;
        };
        compared += 1;
        for (code, side, what, records) in [
            ("census-extra", &c.extra, "observed but not declared", &result.extra),
            ("census-missing", &c.missing, "declared but not observed", &result.missing),
        ] {
            for r in records {
                let key: Vec<String> = c
                    .key
                    .iter()
                    .map(|k| format!("{k}={}", r.get(k).map_or("?".to_owned(), |v| v.as_str().map_or(v.to_string(), str::to_owned))))
                    .collect();
                let advice = if side == "fail" {
                    "Declare it in the census, remove the thing, or add an `ignore` entry with a reason."
                } else {
                    "The census reports it without failing."
                };
                let msg = format!(
                    "census `{}`{}: record {what}: {} ({r}). {advice}",
                    c.name,
                    at.as_deref().map(|a| format!(" ({a})")).unwrap_or_default(),
                    key.join(","),
                );
                let f = if side == "fail" { Finding::error(code, msg) } else { Finding::info(code, msg) };
                let mut f = f.sharing(format!("census `{}`: {}", c.name, key.join(",")), advice.to_owned());
                f.at = c.at.clone();
                out.push(f);
            }
        }
    }
    (out, (compared, not_run))
}

fn selector_finding(res: &Resolution<'_>, sel: &crate::model::Selector, what: &str, at: Option<&str>) -> Option<Finding> {
    use crate::resolve::SelectorProblem as P;
    let (code, msg) = match res.count_selector(sel) {
        Ok(0) => (
            "selector-matches-nothing",
            format!("{what}: {} matches nothing in this repository. Fix the selector or remove it.", sel.describe()),
        ),
        Ok(_) => return None,
        // An input that names a Nix output keys a world or a check by a store path the driver
        // computes; there is no repository file here to find, so it is said and not failed.
        Err(P::Unsupported(why)) if sel.names_nix_output() => {
            let mut f = Finding::info("input-names-nix-output", format!("{what}: {}: {why}; the driver resolves it, so nothing here can check that it exists.", sel.describe()));
            f.at = at.map(str::to_owned);
            return Some(f);
        }
        Err(P::Unsupported(why)) => ("unsupported-selector", format!("{what}: {}: {why}", sel.describe())),
        Err(P::BadPattern(why)) => ("bad-pattern", format!("{what}: {}: {why}", sel.describe())),
        Err(P::Missing(why)) => ("selector-matches-nothing", format!("{what}: {} {why}. Fix the selector or remove it.", sel.describe())),
    };
    let mut f = Finding::error(code, msg);
    f.at = at.map(str::to_owned);
    Some(f)
}

/// Selectors in worlds (`inputs`) and in checks (`inputs`): each that names
/// nothing is an error, because an input that never changes a cache key hides
/// a stale world.
fn input_findings(model: &Model, res: &Resolution<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    // policy.inert: a selector that matches no tracked file is a dead exception.
    for sel in &model.policy.inert {
        out.extend(selector_finding(res, sel, "policy.inert", None));
    }
    for w in &model.worlds {
        for sel in &w.inputs {
            out.extend(selector_finding(res, sel, &format!("world `{}` input", w.name), w.at.as_deref()));
        }
    }
    for (name, group) in &model.checks {
        let mut seen = std::collections::BTreeSet::new();
        for cell in &group.checks {
            for sel in &cell.inputs {
                if seen.insert(sel.describe()) {
                    out.extend(selector_finding(
                        res,
                        sel,
                        &format!("checks.{name} input (first used by cell {})", cell.cell),
                        None,
                    ));
                }
            }
        }
    }
    out
}

/// Test sets inside `policy` are evaluated like placement rules; `joins` must
/// name nodes.
fn policy_findings(model: &Model, res: &Resolution<'_>, table: &TestTable) -> (Vec<Finding>, Vec<PolicySet>) {
    let mut sets: Vec<(String, crate::model::TestSet)> = Vec::new();
    if let Some(s) = &model.policy.deploy_gate {
        sets.push(("policy.deployGate".to_owned(), s.clone()));
    }
    if let Some(s) = model.policy.idle.as_ref().and_then(|i| i.mutate.as_ref()) {
        sets.push(("policy.idle.mutate".to_owned(), s.clone()));
    }
    let mut ev = crate::testset::Evaluator::new(res, table).with_checks(crate::testset::check_on_nodes(model, res));
    let mut out = Vec::new();
    let mut counts = Vec::new();
    for (path, set) in sets {
        let r = ev.eval(&set, &path);
        let (tests, checks) = ev.split(&r);
        counts.push(PolicySet { path: path.clone(), set: set.describe(), tests, checks });
        if r.is_empty() && ev.findings.is_empty() {
            out.push(Finding::error(
                "selector-matches-nothing",
                format!("{path}: `{}` selects neither a test nor a matrix check. Fix the set.", set.describe()),
            ));
        }
    }
    out.append(&mut ev.findings);
    {
        for join in &model.policy.joins {
            for id in join {
                if res.node_index(id).is_none() {
                    out.push(Finding::error(
                        "unknown-node",
                        format!("policy.joins names node \"{id}\", which the model does not define; fix the node name."),
                    ));
                }
            }
        }
    }
    (out, counts)
}

/// The fields a boundary census can supply for a record.
const BOUNDARY_FIELDS: [&str; 3] = ["file", "node", "line"];

/// Production sites only (test code is a different fact, as in `keel-tree boundaries`). A tracked-file
/// list that could not be read is an error here, not an empty census: nothing would be observed and
/// everything declared would be "missing" for the wrong reason.
fn production_sites(res: &Resolution<'_>) -> Result<Vec<crate::boundaries::Site>, String> {
    if let Some(why) = res.tracked_error() {
        return Err(format!("the tracked file list could not be read ({why}), so the code cannot be searched for boundaries; fix git in the repository and rerun"));
    }
    Ok(crate::boundaries::run(res, &res.index.root, &crate::boundaries::Options { include_tests: false }).sites)
}

/// The two differences of a census whose source is a boundary class, by the rule `nix/keel/lib.nix`
/// applies to a census observed in the model: records are compared by `key`, an `ignore` entry
/// excuses an observed record whose fields it matches, and what is left of either side is `extra`
/// (observed, not declared) or `missing` (declared, not observed).
///
/// One record per distinct combination of the `key` fields, which for `key = ["file"]` is one per
/// file. The record also carries `file`, so an `ignore` can name it; `line` is the first site's line
/// of that combination and exists only when `key` asks for it, which makes it one record per site.
fn boundary_result(c: &crate::model::Census, class: &str, sites: &[crate::boundaries::Site]) -> Result<crate::model::CensusResult, String> {
    use serde_json::{Value, json};
    if !crate::boundaries::CLASSES.iter().any(|k| k.id == class) {
        let known: Vec<&str> = crate::boundaries::CLASSES.iter().map(|k| k.id).collect();
        return Err(format!("`boundary = \"{class}\"` is not a class this engine computes. Classes: {}.", known.join(", ")));
    }
    if let Some(bad) = c.key.iter().find(|k| !BOUNDARY_FIELDS.contains(&k.as_str())) {
        return Err(format!(
            "its `key` names `{bad}`, which a boundary census cannot supply. The fields available are: {}. Change `key` to some of them.",
            BOUNDARY_FIELDS.join(", ")
        ));
    }
    let id_of = |r: &Value| -> Option<String> {
        c.key
            .iter()
            .map(|k| r.get(k).map(|v| format!("{k}={}", v.as_str().map_or_else(|| v.to_string(), str::to_owned))))
            .collect::<Option<Vec<_>>>()
            .map(|parts| parts.join(","))
    };
    let wants = |f: &str| c.key.iter().any(|k| k == f);
    let mut seen: BTreeMap<String, Value> = BTreeMap::new();
    for s in sites.iter().filter(|s| s.class == class && !s.test) {
        let mut r = json!({ "file": s.path });
        if wants("node") {
            r["node"] = json!(s.node);
        }
        if wants("line") {
            r["line"] = json!(s.line);
        }
        let id = id_of(&r).expect("every key field was added above");
        seen.entry(id).or_insert(r);
    }
    let ignored = |r: &Value| c.ignore.iter().any(|e| e.matches.as_object().is_some_and(|m| m.iter().all(|(f, v)| r.get(f) == Some(v))));
    seen.retain(|_, r| !ignored(r));
    let mut said: BTreeMap<String, Value> = BTreeMap::new();
    for d in &c.declared {
        let Some(id) = id_of(d) else {
            return Err(format!("the declared record {d} lacks a field of `key` ({}). Every declared record carries every key field.", c.key.join(", ")));
        };
        said.insert(id, d.clone());
    }
    Ok(crate::model::CensusResult {
        extra: seen.iter().filter(|(k, _)| !said.contains_key(*k)).map(|(_, v)| v.clone()).collect(),
        missing: said.iter().filter(|(k, _)| !seen.contains_key(*k)).map(|(_, v)| v.clone()).collect(),
    })
}
