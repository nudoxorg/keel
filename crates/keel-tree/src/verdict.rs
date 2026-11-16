//! `tree --results`: every feature's cone with one CI run's outcome on each node. This is
//! the shape CI reports in (one commit status per feature, the annotated tree in the log),
//! and it splits the failing nodes into roots and the nodes that stand on a failing one,
//! so 400 failures under one broken foundation read as one cause (DESIGN §2.5, §7).
//!
//! A legacy run executes everything, so "stands on a failing node" is a reading of the
//! model, not proof that the root caused the failure above it: the node above may also
//! be broken in its own right. The tree says which nodes to look at first.

use crate::explain::{Mapper, Unmapped, parse_line};
use crate::resolve::Resolution;
use crate::testset::{TestTable, cone_tests};
use crate::text::{counted, num};
use crate::tree::FeatureTree;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write;

/// What a results file said about one test.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Seen {
    Pass,
    Fail,
    Skip,
}

pub struct Results {
    /// Per test-table row; `None` when no line named it.
    pub seen: Vec<Option<Seen>>,
    /// Lines that named a test.
    pub lines: usize,
    pub mapped: usize,
    pub unmapped: Vec<Unmapped>,
    /// The file lists failures only, so a test it does not name may have passed.
    pub failures_only: bool,
}

/// nextest's JUnit as status lines `read` takes: `<testcase classname=binary name=path>`
/// with a `failure` or `error` child failed, with `skipped` skipped, otherwise passed.
/// A test that failed and then passed on a retry (`flakyFailure` children only) passed,
/// as nextest itself reports it.
pub fn junit_status_lines(xml: &str, what: &str) -> anyhow::Result<String> {
    use anyhow::Context;
    let doc = roxmltree::Document::parse(xml).with_context(|| format!("{what} is not well-formed XML; pass nextest's junit.xml or a file of status lines"))?;
    let mut out = String::new();
    let mut cases = 0usize;
    for case in doc.descendants().filter(|n| n.has_tag_name("testcase")) {
        let (Some(binary), Some(path)) = (case.attribute("classname"), case.attribute("name")) else { continue };
        cases += 1;
        let has = |tag: &str| case.children().any(|c| c.has_tag_name(tag));
        let status = if has("failure") || has("error") {
            "FAIL"
        } else if has("skipped") {
            "SKIP"
        } else {
            "PASS"
        };
        let _ = writeln!(out, "{status} [ 0s] (0/0) {binary} {path}");
    }
    if cases == 0 {
        anyhow::bail!("{what} has no <testcase classname=... name=...> element; is it nextest's JUnit (.local/nextest/runs/<profile>/junit.xml)?");
    }
    Ok(out)
}

pub fn read(mapper: &Mapper<'_>, table: &TestTable, text: &str, failures_only: bool) -> Results {
    let mut r = Results { seen: vec![None; table.len()], lines: 0, mapped: 0, unmapped: Vec::new(), failures_only };
    for line in text.lines() {
        let Some(named) = parse_line(line) else { continue };
        r.lines += 1;
        let s = if named.is_skip() {
            Seen::Skip
        } else if named.is_failure() {
            Seen::Fail
        } else {
            Seen::Pass
        };
        match mapper.map(&named) {
            Ok((t, _)) => {
                // Matrix check cells are numbered past the tests; they have no home node.
                let Some(slot) = r.seen.get_mut(t as usize) else { continue };
                r.mapped += 1;
                *slot = Some(merge(*slot, s));
            }
            Err(reason) => r.unmapped.push(Unmapped { line: format!("{} {}", named.binary(), named.path()), reason }),
        }
    }
    r
}

/// A second line about the same test (a retry, a rerun) never hides a failure, and a
/// skip never hides a pass.
fn merge(prev: Option<Seen>, s: Seen) -> Seen {
    match (prev, s) {
        (Some(Seen::Fail), _) | (_, Seen::Fail) => Seen::Fail,
        (Some(Seen::Pass), Seen::Skip) => Seen::Pass,
        (_, s) => s,
    }
}

#[derive(Default, Clone, Copy, Serialize, Debug, PartialEq, Eq)]
pub struct Tally {
    pub tests: u64,
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    /// Indexed here but named by no line: not run, or (failures-only) passed or not run.
    pub unlisted: u64,
}

impl Tally {
    fn add(&mut self, s: Option<Seen>) {
        self.tests += 1;
        match s {
            Some(Seen::Pass) => self.pass += 1,
            Some(Seen::Fail) => self.fail += 1,
            Some(Seen::Skip) => self.skip += 1,
            None => self.unlisted += 1,
        }
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Fails, and stands on no other failing node of the cone.
    Root,
    /// Fails, and stands on these failing roots.
    StandsOnFailing(Vec<String>),
}

#[derive(Serialize)]
pub struct VerdictLine {
    pub depth: usize,
    pub node: String,
    pub relation: &'static str,
    pub tally: Tally,
    pub role: Option<Role>,
    pub repeated: bool,
}

#[derive(Serialize, Default, Clone)]
pub struct CheckCounts {
    pub pass: u64,
    pub fail: u64,
    pub blocked: u64,
    pub unknown: u64,
}

#[derive(Serialize)]
pub struct FeatureVerdict {
    pub feature: String,
    pub ship: Option<String>,
    /// "failure", "success", or "unknown" when no line named a test of the cone.
    pub state: &'static str,
    pub cone: Tally,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<CheckCounts>,
    /// Failing roots and how many failing tests are homed in each.
    pub roots: Vec<(String, u64)>,
    /// Failing tests homed in nodes that stand on a failing root.
    pub above_roots: u64,
    pub lines: Vec<VerdictLine>,
    /// One line for a commit status, at most 140 characters.
    pub description: String,
}

#[derive(Serialize)]
pub struct Verdict {
    pub results_lines: usize,
    pub mapped: usize,
    pub unmapped: Vec<Unmapped>,
    pub failures_only: bool,
    pub features: Vec<FeatureVerdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_evidence: Option<crate::driver::Evidence>,
    /// Failing tests by the node they are homed in, as nextest names them. Only the PR
    /// comment quotes names; the JSON carries counts and the CI log has the rest.
    #[serde(skip)]
    pub failing: BTreeMap<String, Vec<String>>,
    /// Every test of any feature's cone, once, however many cones it is in.
    #[serde(skip)]
    pub overall: Tally,
}

/// A commit status per feature, for a CI poster: `keel/<feature>`.
#[derive(Serialize)]
pub struct Status {
    pub context: String,
    pub state: &'static str,
    pub description: String,
}

pub fn run(res: &Resolution<'_>, table: &TestTable, trees: &[FeatureTree], results: &Results) -> Verdict {
    run_with_checks(res, table, trees, results, None)
}

pub fn run_with_checks(res: &Resolution<'_>, table: &TestTable, trees: &[FeatureTree], results: &Results, checks: Option<&crate::driver::Evidence>) -> Verdict {
    let mut features: Vec<FeatureVerdict> = trees.iter().filter_map(|t| res.node_index(&t.node).map(|f| feature(res, table, t, f, results))).collect();
    let mut overall = Tally::default();
    let mut in_a_cone = keel_index::RoaringBitmap::new();
    for t in trees {
        if let Some(f) = res.node_index(&t.node) {
            in_a_cone |= cone_tests(res, table, f);
        }
    }
    for t in &in_a_cone {
        overall.add(results.seen[t as usize]);
    }
    let mut failing: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (t, s) in results.seen.iter().enumerate() {
        if let (Some(Seen::Fail), Some(h)) = (s, table.home[t]) {
            failing.entry(res.nodes[h].id.clone()).or_default().push(crate::comment::test_name(&table.ids[t]));
        }
    }
    if let Some(evidence) = checks {
        for f in &mut features {
            let Some(index) = res.node_index(&f.feature) else { continue };
            let cone_nodes = res.cone(index, false);
            let mut counts = CheckCounts::default();
            let mut failures: BTreeMap<String, u64> = BTreeMap::new();
            let mut worlds: BTreeMap<String, u64> = BTreeMap::new();
            for check in &evidence.checks {
                if !check.nodes.iter().any(|n| res.node_index(n).is_some_and(|i| cone_nodes.contains(&i))) { continue; }
                match check.state.as_str() {
                    "pass" => counts.pass += 1,
                    "fail" => {
                        counts.fail += 1;
                        for node in &check.nodes {
                            if res.node_index(node).is_some_and(|i| cone_nodes.contains(&i)) {
                                *failures.entry(node.clone()).or_default() += 1;
                            }
                        }
                    },
                    "blocked" => {
                        counts.blocked += 1;
                        if let Some(world) = &check.blocked_by { *worlds.entry(world.clone()).or_default() += 1; }
                    },
                    _ => counts.unknown += 1,
                }
            }
            if counts.pass + counts.fail + counts.blocked + counts.unknown == 0 { continue; }
            if f.state == "failure" || counts.fail > 0 || counts.blocked > 0 {
                f.state = "failure";
                for (node, count) in &failures {
                    if let Some((_, n)) = f.roots.iter_mut().find(|(name, _)| name == node) { *n += count; }
                    else { f.roots.push((node.clone(), *count)); }
                }
                for (world, count) in worlds { f.roots.push((format!("world:{world}"), count)); }
                let all = f.roots.clone();
                f.roots.retain(|(node, _)| {
                    let Some(n) = res.node_index(node) else { return true; };
                    !all.iter().filter_map(|(other, _)| res.node_index(other)).any(|m| n != m && res.reaches(n, m, None) && !res.reaches(m, n, None))
                });
            } else if counts.unknown > 0 || (f.cone.tests > 0 && f.cone.pass == 0) {
                f.state = "unknown";
            } else if counts.pass > 0 {
                f.state = "success";
            }
            f.checks = Some(counts);
            f.description = describe(f, results.failures_only);
        }
        for check in evidence.checks.iter().filter(|c| c.state == "fail") {
            for node in &check.nodes { failing.entry(node.clone()).or_default().push(check.id.clone()); }
        }
    }
    Verdict {
        results_lines: results.lines,
        mapped: results.mapped,
        unmapped: results.unmapped.clone(),
        failures_only: results.failures_only,
        features,
        check_evidence: checks.cloned(),
        failing,
        overall,
    }
}

fn feature(res: &Resolution<'_>, table: &TestTable, tree: &FeatureTree, f: usize, r: &Results) -> FeatureVerdict {
    // Tallies over the cone's own tests, so `unowned` counts only the packages this cone
    // reaches, as the plain tree does.
    let mut cone = Tally::default();
    let mut by_node: BTreeMap<usize, Tally> = BTreeMap::new();
    for t in cone_tests(res, table, f) {
        let s = r.seen[t as usize];
        cone.add(s);
        if let Some(h) = table.home[t as usize] {
            by_node.entry(h).or_default().add(s);
        }
    }
    let failing: Vec<usize> = by_node.iter().filter(|(_, t)| t.fail > 0).map(|(&n, _)| n).collect();
    // A failing node is a root unless it stands on another failing node that does not
    // stand back on it (members of a cycle are each other's peers, so each is a root).
    let below = |n: usize, m: usize| m != n && res.reaches(n, m, None) && !res.reaches(m, n, None);
    let roots: Vec<usize> = failing.iter().copied().filter(|&n| !failing.iter().any(|&m| below(n, m))).collect();
    let role = |n: usize| -> Option<Role> {
        if !failing.contains(&n) {
            return None;
        }
        let under: Vec<String> = roots.iter().filter(|&&m| below(n, m)).map(|&m| res.nodes[m].id.clone()).collect();
        Some(if under.is_empty() { Role::Root } else { Role::StandsOnFailing(under) })
    };
    let lines = tree
        .lines
        .iter()
        .map(|l| {
            let n = res.node_index(&l.node);
            VerdictLine {
                depth: l.depth,
                node: l.node.clone(),
                relation: l.relation,
                tally: n.and_then(|n| by_node.get(&n).copied()).unwrap_or_default(),
                role: n.and_then(role),
                repeated: l.repeated,
            }
        })
        .collect();
    let root_counts: Vec<(String, u64)> = roots.iter().map(|&n| (res.nodes[n].id.clone(), by_node[&n].fail)).collect();
    let above_roots = cone.fail - root_counts.iter().map(|(_, c)| c).sum::<u64>();
    let state = if cone.fail > 0 {
        "failure"
    } else if cone.pass == 0 && !r.failures_only {
        "unknown"
    } else {
        "success"
    };
    let mut v = FeatureVerdict {
        feature: tree.node.clone(),
        ship: tree.ship.clone(),
        state,
        cone,
        checks: None,
        roots: root_counts,
        above_roots,
        lines,
        description: String::new(),
    };
    v.description = describe(&v, r.failures_only);
    v
}

/// The commit-status line: the roots first, then what stands on them, then the passes.
fn describe(v: &FeatureVerdict, failures_only: bool) -> String {
    // The policy as `ship_text` writes it: a may-lag feature is held to required until its lag
    // is calibrated, and a status that said only "may lag" would excuse a failure it does not.
    let lag = match v.ship.as_deref() {
        Some(s) if s.contains("may-lag") && s.contains("held required") => " (may lag, held required)",
        Some(s) if s.contains("may-lag") => " (may lag)",
        _ => "",
    };
    if let Some(c) = &v.checks {
        let result = match v.state { "failure" => "FAIL", "unknown" => "unknown", _ => "pass" };
        return format!("{result}{lag}: checks {} pass, {} fail, {} blocked, {} unknown", c.pass, c.fail, c.blocked, c.unknown);
    }
    let mut s = match v.state {
        "failure" => {
            let roots: Vec<String> = v.roots.iter().map(|(n, c)| format!("{n} ({})", num(*c))).collect();
            let mut s = format!("FAIL{lag}: {} {}", if v.roots.len() == 1 { "root" } else { "roots" }, roots.join(", "));
            if v.above_roots > 0 {
                let _ = write!(s, "; {} failing above", num(v.above_roots));
            }
            s
        }
        "unknown" => format!("no result for the {} tests in the cone{lag}", num(v.cone.tests)),
        _ if failures_only => format!("no failure listed in {} tests{lag}; passes not reported", num(v.cone.tests)),
        _ => format!("pass{lag}: {} of {} ran", num(v.cone.pass), num(v.cone.tests)),
    };
    if v.state == "failure" && !failures_only {
        let _ = write!(s, "; {} pass", num(v.cone.pass));
    }
    clip_status(s)
}

/// Commit-status descriptions are cut at 140 characters (GitHub's limit; Forgejo's is
/// longer), so a line that says the roots first keeps them.
pub fn clip_status(s: String) -> String {
    if s.chars().count() > 140 { s.chars().take(137).collect::<String>() + "..." } else { s }
}

impl Verdict {
    pub fn statuses(&self) -> Vec<Status> {
        self.features
            .iter()
            .map(|f| Status { context: format!("keel/{}", f.feature), state: f.state, description: f.description.clone() })
            .collect()
    }

    pub fn render(&self) -> String {
        let mut o = String::new();
        let _ = writeln!(
            o,
            "tree with results: {} result lines, {} mapped to indexed tests, {} unmapped{}",
            num(self.results_lines as u64),
            num(self.mapped as u64),
            num(self.unmapped.len() as u64),
            if self.failures_only { "; the file lists failures only, so 'unlisted' tests may have passed" } else { "" }
        );
        o.push_str(
            "legend: as `tree`; per node pass/fail/skip of the tests homed there, ROOT a failing node that stands on no failing node,\n\
             'stands on failing X' a failing node above the root X (look at X first).\n",
        );
        for f in &self.features {
            let _ = writeln!(o, "\n{}  {}  {}", f.feature, f.ship.as_deref().unwrap_or("no ship policy"), f.description);
            let _ = writeln!(o, "  cone: {}", tally_text(&f.cone, self.failures_only));
            if let Some(c) = &f.checks { let _ = writeln!(o, "  checks: {} pass, {} fail, {} blocked, {} unknown", c.pass, c.fail, c.blocked, c.unknown); }
            for l in &f.lines {
                let mark = match l.relation {
                    "part" => "+",
                    "stands-on" => ">",
                    "mutual" => "=",
                    "instance-of" => "~",
                    _ => " ",
                };
                let mut line = format!("  {}{mark} {}", "  ".repeat(l.depth), l.node);
                if l.repeated {
                    line.push_str("  (shown above)");
                } else {
                    let _ = write!(line, "  [{}]", tally_text(&l.tally, self.failures_only));
                    match &l.role {
                        Some(Role::Root) => line.push_str("  ROOT"),
                        Some(Role::StandsOnFailing(r)) => {
                            let _ = write!(line, "  stands on failing {}", r.join(", "));
                        }
                        None => {}
                    }
                }
                o.push_str(&line);
                o.push('\n');
            }
        }
        if !self.unmapped.is_empty() {
            let _ = writeln!(o, "\nunmapped result lines (first 5 of {}):", self.unmapped.len());
            for u in self.unmapped.iter().take(5) {
                let _ = writeln!(o, "  {}: {}", u.line, u.reason);
            }
        }
        o
    }

    /// The PR comment (Markdown, no tables: see keel-cli's comment.rs). The same root under
    /// five features is one bullet, because that is the point of rooting: 400 failures under
    /// one broken foundation read as one cause.
    pub fn comment(&self) -> String {
        if let Some(evidence) = &self.check_evidence {
            let mut out = String::from("**Keel: test and executable check results**\n\n");
            for f in &self.features {
                let _ = writeln!(out, "- `{}`: {}", f.feature, f.description);
            }
            if !evidence.failed_worlds.is_empty() {
                out.push_str("\nFailed prerequisite worlds (dependent checks were blocked):\n");
                for (world, error) in &evidence.failed_worlds {
                    let _ = writeln!(out, "- `{world}`: {error}");
                }
            }
            return out;
        }
        use crate::comment::first_of;
        let features = self.features.len();
        let failing = self.features.iter().filter(|f| f.state == "failure").count();
        let unknown = self.features.iter().filter(|f| f.state == "unknown").count();

        // A node can be a root in one cone and sit above another root in a bigger one;
        // the feature's own list of roots decides which feature it is a root of.
        let mut roots: BTreeMap<&str, RootCause<'_>> = BTreeMap::new();
        for f in &self.features {
            for (node, fail) in &f.roots {
                let r = roots.entry(node).or_default();
                r.fail = r.fail.max(*fail);
                r.features.push(&f.feature);
            }
            for l in f.lines.iter().filter(|l| !l.repeated) {
                if let Some(Role::StandsOnFailing(under)) = &l.role {
                    for root in under {
                        let n = roots.entry(root).or_default().above.entry(&l.node).or_default();
                        *n = (*n).max(l.tally.fail);
                    }
                }
            }
        }
        let mut roots: Vec<(&str, RootCause<'_>)> = roots.into_iter().filter(|(_, r)| r.fail > 0).collect();
        roots.sort_by(|a, b| b.1.fail.cmp(&a.1.fail).then(a.0.cmp(b.0)));

        let mut head = String::from("**Keel: ");
        if features == 0 {
            head.push_str("the model has no feature to report on.**\n");
        } else if failing > 0 {
            let _ = write!(head, "{failing} of {} {}", counted(features as u64, "feature", "features"), if failing == 1 { "fails" } else { "fail" });
            if unknown > 0 {
                let _ = write!(head, ", {unknown} {} no result", if unknown == 1 { "has" } else { "have" });
            }
            let named: Vec<String> = roots
                .iter()
                .take(HEAD_ROOTS)
                .enumerate()
                .map(|(i, (n, r))| if i == 0 { format!("{n} ({})", counted(r.fail, "failing test", "failing tests")) } else { format!("{n} ({})", num(r.fail)) })
                .collect();
            let _ = write!(head, ". Fix first: {}", named.join(", "));
            if roots.len() > HEAD_ROOTS {
                let _ = write!(head, " and {} more roots", roots.len() - HEAD_ROOTS);
            }
            head.push_str(".**\n");
        } else if unknown > 0 {
            let _ = writeln!(
                head,
                "no failure, but {unknown} of {} {} no result: no line of the results names a test in {}. Check that the results file is this run's.**",
                counted(features as u64, "feature", "features"),
                if unknown == 1 { "has" } else { "have" },
                if unknown == 1 { "its cone" } else { "their cones" }
            );
        } else if self.failures_only {
            let _ = writeln!(
                head,
                "no failing test listed for {}; the results list failures only, so this does not say anything passed.**",
                if features == 1 { "the feature".to_owned() } else { format!("any of {features} features") }
            );
        } else {
            let o = &self.overall;
            let which = if features == 1 { "the feature passes".to_owned() } else { format!("all {features} features pass") };
            let mut s = format!("{which} ({} passed", counted(o.pass, "test", "tests"));
            if o.skip > 0 {
                let _ = write!(s, ", {} skipped", num(o.skip));
            }
            if o.unlisted > 0 {
                let _ = write!(s, ", {} not run", num(o.unlisted));
            }
            let _ = writeln!(head, "{s}).**");
        }

        if !roots.is_empty() {
            head.push_str("\n### Root causes\n");
            for (node, r) in roots.iter().take(MAX_ROOTS) {
                let names = self.failing.get(*node).map_or(&[][..], Vec::as_slice);
                let mut line = format!("- `{node}`: {}", counted(r.fail, "failing test", "failing tests"));
                let _ = write!(line, ", under {} {}.", if r.features.len() == 1 { "feature" } else { "features" }, list_of(&r.features, 6, true));
                if !names.is_empty() {
                    let _ = write!(line, " {} {}.", if names.len() > 3 { "First failing:" } else { "Failing:" }, first_of(names, 3));
                }
                if r.above.is_empty() {
                    line.push_str(" Nothing that stands on it fails.");
                } else {
                    let mut above: Vec<(&&str, &u64)> = r.above.iter().collect();
                    above.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                    let total: u64 = above.iter().map(|(_, c)| **c).sum();
                    let shown: Vec<String> = above.iter().take(6).map(|(n, c)| format!("{n} ({})", num(**c))).collect();
                    let _ = write!(line, " {} above it, in {}", counted(total, "failing test", "failing tests"), shown.join(", "));
                    if above.len() > 6 {
                        let _ = write!(line, " and {} more nodes", above.len() - 6);
                    }
                    line.push('.');
                }
                head.push_str(&line);
                head.push('\n');
            }
            if roots.len() > MAX_ROOTS {
                let _ = writeln!(head, "- and {} more roots with fewer failing tests; the trees below name them all.", roots.len() - MAX_ROOTS);
            }
            if roots.iter().any(|(_, r)| !r.above.is_empty()) {
                head.push_str("\nA node above a root may fail for its own reasons as well: this is the model's reading of what stands on what, not proof of cause. Fix the roots, then run again.\n");
            }
        }

        if features > 0 {
            head.push_str("\n### Features\n");
            let mut ordered: Vec<&FeatureVerdict> = self.features.iter().collect();
            ordered.sort_by_key(|f| match f.state {
                "failure" => 0,
                "unknown" => 1,
                _ => 2,
            });
            for f in ordered {
                let what = match f.state {
                    "failure" => {
                        let names: Vec<String> = f.roots.iter().map(|(n, _)| n.clone()).collect();
                        let mut s = format!("fail ({} {}", if names.len() == 1 { "root" } else { "roots" }, list_of(&names, 6, false));
                        if f.above_roots > 0 {
                            let _ = write!(s, "; {} failing above", num(f.above_roots));
                        }
                        s.push(')');
                        s
                    }
                    "unknown" => format!("no result: no line of the results names any of its {} tests", num(f.cone.tests)),
                    _ if self.failures_only => format!("no failure listed in {}; passes not reported", counted(f.cone.tests, "test", "tests")),
                    _ => format!("pass ({} of {} ran)", num(f.cone.pass), counted(f.cone.tests, "test", "tests")),
                };
                let _ = writeln!(head, "- `{}`: {what}{}", f.feature, f.ship.as_deref().map(ship_policy).unwrap_or_default());
            }
        }

        let mut tail = String::new();
        if !self.unmapped.is_empty() {
            // The same line twice (a retry) is one line to show.
            let mut distinct: Vec<&str> = Vec::new();
            for u in &self.unmapped {
                if !distinct.contains(&u.line.as_str()) {
                    distinct.push(&u.line);
                }
            }
            let first: Vec<String> = distinct.iter().take(3).map(|l| format!("`{}`", l.chars().take(120).collect::<String>())).collect();
            let _ = writeln!(
                tail,
                "Unmapped: {} name{} no test the model knows, so no feature counts {} ({}{}). The CI log has the reasons.",
                counted(self.unmapped.len() as u64, "result line", "result lines"),
                if self.unmapped.len() == 1 { "s" } else { "" },
                if self.unmapped.len() == 1 { "it" } else { "them" },
                if distinct.len() > 3 { "first 3: " } else { "" },
                first.join(", ")
            );
        }
        crate::comment::assemble(&head, "The trees", "tree", &self.render(), &tail)
    }
}

/// Most root causes the head of a comment names; the rest are counted.
const HEAD_ROOTS: usize = 5;
/// Most root-cause bullets: the head is never cut for size, so it has to be bounded.
const MAX_ROOTS: usize = 30;

/// One failing root across every feature that has it.
#[derive(Default)]
struct RootCause<'v> {
    fail: u64,
    features: Vec<&'v str>,
    /// Failing nodes that stand on it, and how many tests fail in each.
    above: BTreeMap<&'v str, u64>,
}

/// The ship policy as a comment line ends with it. The model's text for `may-lag` also says
/// the engine holds it to `required` until a lag is calibrated, which a reader needs: the
/// feature's failure still blocks.
fn ship_policy(text: &str) -> String {
    if text.contains("may-lag") {
        let held = if text.contains("held required") { " (held to required until its lag is calibrated)" } else { "" };
        format!(", ship policy `may-lag`{held}")
    } else {
        format!(", ship policy `{text}`")
    }
}

/// The first `k` names, backticked when they stand inside a sentence about code.
fn list_of<S: AsRef<str>>(items: &[S], k: usize, ticks: bool) -> String {
    let tick = if ticks { "`" } else { "" };
    let mut s: Vec<String> = items.iter().take(k).map(|i| format!("{tick}{}{tick}", i.as_ref())).collect();
    if items.len() > k {
        s.push(format!("and {} more", items.len() - k));
    }
    s.join(", ")
}

fn tally_text(t: &Tally, failures_only: bool) -> String {
    if t.tests == 0 {
        return "0 tests".to_owned();
    }
    let mut parts = Vec::new();
    if t.fail > 0 {
        parts.push(format!("{} fail", num(t.fail)));
    }
    if !failures_only || t.pass > 0 {
        parts.push(format!("{} pass", num(t.pass)));
    }
    if t.skip > 0 {
        parts.push(format!("{} skip", num(t.skip)));
    }
    if t.unlisted > 0 {
        parts.push(format!("{} unlisted", num(t.unlisted)));
    }
    format!("{} tests: {}", num(t.tests), parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn v(state: &'static str, roots: Vec<(&str, u64)>, above: u64, pass: u64, ship: Option<&str>) -> FeatureVerdict {
        FeatureVerdict {
            feature: "search".into(),
            ship: ship.map(str::to_owned),
            state,
            cone: Tally { tests: 100, pass, fail: roots.iter().map(|r| r.1).sum::<u64>() + above, skip: 0, unlisted: 0 },
            checks: None,
            roots: roots.into_iter().map(|(n, c)| (n.to_owned(), c)).collect(),
            above_roots: above,
            lines: Vec::new(),
            description: String::new(),
        }
    }

    #[test]
    fn the_status_line_names_the_roots_first() {
        assert_eq!(describe(&v("failure", vec![("engine", 3)], 40, 57, Some("required")), false), "FAIL: root engine (3); 40 failing above; 57 pass");
        assert_eq!(describe(&v("failure", vec![("store", 1), ("platform", 2)], 0, 0, None), true), "FAIL: roots store (1), platform (2)");
        assert_eq!(describe(&v("success", vec![], 0, 100, Some("may-lag (at most 60 min, 0.9)")), false), "pass (may lag): 100 of 100 ran");
        // What `ship_text` writes for desktop today; the old prefix test never matched it.
        let held = "declared may-lag, held required: uncalibrated; asks for at most 120 min behind at confidence 0.95";
        assert_eq!(describe(&v("failure", vec![("engine", 3)], 40, 0, Some(held)), true), "FAIL (may lag, held required): root engine (3); 40 failing above");
        assert_eq!(describe(&v("success", vec![], 0, 0, None), true), "no failure listed in 100 tests; passes not reported");
    }

    #[test]
    fn nextest_junit_becomes_status_lines() {
        // The shape nextest writes (testsuite per binary, classname the binary id).
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="4" failures="1" errors="0">
  <testsuite name="backend-engine" tests="3" disabled="1" errors="0" failures="1">
    <testcase name="driver::tests::lowers" classname="backend-engine" time="0.012"/>
    <testcase name="driver::tests::breaks" classname="backend-engine" time="0.4"><failure type="test failure">assertion failed</failure><system-out>x</system-out></testcase>
    <testcase name="driver::tests::slow" classname="backend-engine" time="0"><skipped/></testcase>
  </testsuite>
  <testsuite name="backend-engine::python_x" tests="1"><testcase name="retried" classname="backend-engine::python_x" time="1"><flakyFailure type="test failure">once</flakyFailure></testcase></testsuite>
</testsuites>"#;
        let lines = junit_status_lines(xml, "junit.xml").unwrap();
        assert_eq!(
            lines,
            "PASS [ 0s] (0/0) backend-engine driver::tests::lowers\nFAIL [ 0s] (0/0) backend-engine driver::tests::breaks\nSKIP [ 0s] (0/0) backend-engine driver::tests::slow\nPASS [ 0s] (0/0) backend-engine::python_x retried\n"
        );
        let parsed: Vec<_> = lines.lines().filter_map(parse_line).collect();
        assert_eq!(parsed.len(), 4);
        assert!(parsed[1].is_failure() && parsed[2].is_skip() && !parsed[3].is_failure());
        assert!(junit_status_lines("<testsuites/>", "empty.xml").unwrap_err().to_string().contains("no <testcase"));
    }

    #[test]
    fn the_plan_status_names_what_the_change_touches_and_what_is_in_doubt() {
        assert_eq!(crate::plan::status_description(&["store", "engine"], 1346, 15496), "touches store, engine; 1,346 of 15,496 tests in doubt");
        assert_eq!(crate::plan::status_description(&[], 0, 15496), "touches no node; 0 of 15,496 tests in doubt");
    }

    #[test]
    fn a_long_status_line_is_cut_to_140_characters() {
        let many: Vec<(&str, u64)> = std::iter::repeat_n(("frontends.typescript", 1), 12).collect();
        let d = describe(&v("failure", many, 0, 0, None), true);
        assert_eq!(d.chars().count(), 140);
        assert!(d.ends_with("..."));
    }

    #[test]
    fn a_second_line_about_a_test_never_hides_its_failure() {
        assert_eq!(merge(Some(Seen::Fail), Seen::Pass), Seen::Fail);
        assert_eq!(merge(Some(Seen::Pass), Seen::Fail), Seen::Fail);
        assert_eq!(merge(Some(Seen::Pass), Seen::Skip), Seen::Pass);
        assert_eq!(merge(Some(Seen::Skip), Seen::Pass), Seen::Pass);
        assert_eq!(merge(None, Seen::Skip), Seen::Skip);
    }
}

#[cfg(test)]
mod on_a_fixture {
    use super::*;
    use crate::explain::Mapper;
    use crate::fixtures::{model, standard};
    use crate::resolve::Resolution;
    use crate::testset::TestTable;
    use std::path::Path;

    fn node(id: &str, krate: &str, ship: &str) -> String {
        format!(
            r#"{{"id":"{id}","at":"/m/keel.nix:1","parent":null,"about":null,"code":[{{"by":"crate","name":"{krate}"}}],"entry":[],"on":[],"never":[],"of":[],"ship":{ship},"movedBy":[],"unmovedBy":[]}}"#
        )
    }

    /// core <- mid <- top (top also on core): `top` is the feature.
    fn verdict(results: &str, failures_only: bool) -> Verdict {
        verdict_shipping(results, failures_only, "null")
    }

    /// As `verdict`, with `mid` shipping too: `core` is then under two features.
    fn verdict_shipping(results: &str, failures_only: bool, mid_ship: &str) -> Verdict {
        let idx = standard().index();
        let json = format!(
            r#"{{"schema":2,"nodes":[{},{},{}],"policy":{{"faults":"report"}}}}"#,
            node("core", "core", "null"),
            node("mid", "mid", mid_ship),
            node("top", "top", r#""required""#)
        );
        let mdl = model(&json);
        let res = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
        let table = TestTable::build(&res, false);
        let trees = crate::tree::run(&res, &table, None).unwrap();
        let mapper = Mapper::new(&idx, &table);
        run(&res, &table, &trees, &read(&mapper, &table, results, failures_only))
    }

    #[test]
    fn a_failure_above_a_failing_foundation_stands_on_it_and_the_foundation_is_the_root() {
        let v = verdict(
            "FAIL [ 1s] (1/3) core tests::roundtrip\nPASS [ 1s] (2/3) core wal::tests::replays\nFAIL [ 1s] (3/3) top::journey walks_everything\n",
            false,
        );
        let top = v.features.iter().find(|f| f.feature == "top").expect("top is a feature");
        assert_eq!(top.state, "failure");
        assert_eq!(top.roots, vec![("core".to_owned(), 1)]);
        assert_eq!(top.above_roots, 1);
        assert_eq!(top.description, "FAIL: root core (1); 1 failing above; 1 pass");
        let role = |n: &str| top.lines.iter().find(|l| l.node == n && !l.repeated).and_then(|l| l.role.clone());
        assert_eq!(role("core"), Some(Role::Root));
        assert_eq!(role("top"), Some(Role::StandsOnFailing(vec!["core".to_owned()])));
        assert_eq!(role("mid"), None);
        let s = v.statuses();
        assert_eq!((s[0].context.as_str(), s[0].state), ("keel/top", "failure"));
    }

    #[test]
    fn with_no_line_about_the_cone_the_state_is_unknown_not_success() {
        let v = verdict("", false);
        let top = v.features.iter().find(|f| f.feature == "top").unwrap();
        assert_eq!(top.state, "unknown");
        // A failures-only file that names nothing in the cone does claim no failure.
        let v = verdict("", true);
        assert_eq!(v.features.iter().find(|f| f.feature == "top").unwrap().state, "success");
    }

    // `unowned` is a feature too (it ships), with the one test of `tooling` in its cone, so a
    // run that passes everything outside `top`'s cone has to say so for it to pass.
    const BROKEN_CORE: &str = "FAIL [ 1s] (1/4) core tests::roundtrip\nPASS [ 1s] (2/4) core wal::tests::replays\nFAIL [ 1s] (3/4) top::journey walks_everything\nPASS [ 1s] (4/4) tooling tests::tool\n";

    #[test]
    fn the_comment_names_the_root_what_stands_on_it_and_folds_the_trees() {
        let c = verdict(BROKEN_CORE, false).comment();
        let lines: Vec<&str> = c.lines().collect();
        assert_eq!(lines[0], "**Keel: 1 of 2 features fails. Fix first: core (1 failing test).**");
        assert!(lines.contains(&"- `core`: 1 failing test, under feature `top`. Failing: `core tests::roundtrip`. 1 failing test above it, in top (1)."), "{c}");
        // Failing features first, the passing one last.
        let i = |s: &str| lines.iter().position(|l| *l == s).unwrap_or_else(|| panic!("{s}\n{c}"));
        assert!(i("- `top`: fail (root core; 1 failing above), ship policy `required`") < i("- `unowned`: pass (1 of 1 test ran), ship policy `required`"));
        assert!(c.contains("<details><summary>The trees</summary>\n\n```text\ntree with results: 4 result lines"), "{c}");
        assert!(c.ends_with("```\n\n</details>\n"));
        // No table (a table cannot be narrower than its widest node id).
        assert!(!c.contains("|---") && !c.contains("| ---"));
    }

    #[test]
    fn a_root_under_two_features_is_one_line_with_both_features() {
        let v = verdict_shipping(BROKEN_CORE, false, r#""required""#);
        assert_eq!(v.features.iter().filter(|f| f.state == "failure").count(), 2);
        let c = v.comment();
        assert_eq!(c.lines().next().unwrap(), "**Keel: 2 of 3 features fail. Fix first: core (1 failing test).**");
        let root_lines: Vec<&str> = c.lines().filter(|l| l.starts_with("- `core`")).collect();
        assert_eq!(root_lines.len(), 1, "{c}");
        assert!(root_lines[0].starts_with("- `core`: 1 failing test, under features `mid`, `top`."), "{}", root_lines[0]);
        // Two feature bullets, one per feature.
        assert!(c.lines().any(|l| l.starts_with("- `mid`: fail (root core")) && c.lines().any(|l| l.starts_with("- `top`: fail (root core")));
    }

    #[test]
    fn with_every_test_passing_the_comment_says_how_many_passed() {
        let all = "PASS [ 1s] (1/4) core tests::roundtrip\nPASS [ 1s] (2/4) core wal::tests::replays\nPASS [ 1s] (3/4) top::journey walks_everything\nPASS [ 1s] (4/4) tooling tests::tool\n";
        // `mid` ships here, so core's two tests are in three cones and still count once.
        let c = verdict_shipping(all, false, r#""required""#).comment();
        assert_eq!(c.lines().next().unwrap(), "**Keel: all 3 features pass (4 tests passed).**");
        assert!(!c.contains("Root causes"));
        assert!(c.contains("- `top`: pass (3 of 3 tests ran), ship policy `required`"), "{c}");
        assert!(c.contains("- `unowned`: pass (1 of 1 test ran)"), "{c}");
        let v = verdict("PASS [ 1s] (1/3) core tests::roundtrip\nSKIP [ 1s] (2/3) core wal::tests::replays\nPASS [ 1s] (3/3) tooling tests::tool\n", false);
        assert_eq!(v.comment().lines().next().unwrap(), "**Keel: all 2 features pass (2 tests passed, 1 skipped, 1 not run).**");
    }

    #[test]
    fn a_failures_only_file_never_claims_a_pass() {
        let c = verdict("FAIL [ 1s] (1/1) core tests::roundtrip\n", true).comment();
        assert_eq!(c.lines().next().unwrap(), "**Keel: 1 of 2 features fails. Fix first: core (1 failing test).**");
        let before_trees = c.split("<details>").next().unwrap();
        assert!(before_trees.contains("- `top`: fail (root core), ship policy `required`"), "{c}");
        assert!(!before_trees.contains(" ran)") && !before_trees.contains("tests passed"), "{c}");
        assert!(before_trees.contains("- `unowned`: no failure listed in 1 test; passes not reported"), "{c}");
        let c = verdict("", true).comment();
        assert_eq!(
            c.lines().next().unwrap(),
            "**Keel: no failing test listed for any of 2 features; the results list failures only, so this does not say anything passed.**"
        );
        assert!(c.contains("- `top`: no failure listed in 3 tests; passes not reported"), "{c}");
        // A results file that names nothing of the cone is not a pass either.
        let c = verdict("", false).comment();
        assert!(c.starts_with("**Keel: no failure, but 2 of 2 features have no result"), "{c}");
    }

    #[test]
    fn result_lines_no_test_matches_get_one_line_with_the_count_and_the_first_three() {
        let results = format!("{BROKEN_CORE}FAIL [ 1s] (5/8) nosuch a::one\nFAIL [ 1s] (6/8) nosuch a::two\nPASS [ 1s] (7/8) nosuch a::three\nPASS [ 1s] (8/8) nosuch a::four\n");
        let c = verdict(&results, false).comment();
        let tail = c.rsplit("</details>\n\n").next().unwrap();
        assert!(tail.starts_with("Unmapped: 4 result lines name no test the model knows, so no feature counts them (first 3: `nosuch a::one`, `nosuch a::two`, `nosuch a::three`)."), "{tail}");
        assert!(!tail.contains("a::four") && tail.lines().count() == 1);
        let c = verdict(&format!("{BROKEN_CORE}FAIL [ 1s] (5/5) nosuch a::one\n"), false).comment();
        assert!(c.contains("Unmapped: 1 result line names no test the model knows, so no feature counts it (`nosuch a::one`)."), "{c}");
        assert!(!verdict(BROKEN_CORE, false).comment().contains("Unmapped"));
    }

    #[test]
    fn a_comment_over_the_limit_loses_trees_and_keeps_its_head_and_its_unmapped_line() {
        // Four thousand repeated nodes: the rendered trees are far past 60,000 characters.
        let mut f = super::tests::v("failure", vec![("engine", 3)], 0, 0, Some("required"));
        f.lines = (0..4_000)
            .map(|i| VerdictLine { depth: 3, node: format!("frontends.language{i}"), relation: "stands-on", tally: Tally { tests: 10, pass: 0, fail: 0, skip: 0, unlisted: 10 }, role: None, repeated: false })
            .collect();
        let v = Verdict {
            results_lines: 5,
            mapped: 4,
            unmapped: vec![Unmapped { line: "nosuch a::one".into(), reason: "no binary".into() }],
            failures_only: true,
            features: vec![f],
            check_evidence: None,
            failing: [("engine".to_owned(), vec!["backend-engine x::y".to_owned()])].into(),
            overall: Tally::default(),
        };
        assert!(v.render().chars().count() > 200_000);
        let c = v.comment();
        assert!(c.chars().count() <= 60_000, "{} characters", c.chars().count());
        assert!(c.starts_with("**Keel: 1 of 1 feature fails. Fix first: engine (3 failing tests).**\n\n### Root causes\n- `engine`: 3 failing tests, under feature `search`."), "{}", &c[..300]);
        assert!(c.contains("### Features\n- `search`: fail (root engine"));
        assert!(c.contains("The trees (the first ") && c.contains(" lines are left out so that this comment stays under the size limit. The whole tree is in the CI log"));
        assert!(c.ends_with("Unmapped: 1 result line names no test the model knows, so no feature counts it (`nosuch a::one`). The CI log has the reasons.\n"));
    }
}
