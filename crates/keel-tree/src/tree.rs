//! `tree`: what each feature stands on, as an indented tree.

use crate::finding::short_at;
use crate::resolve::Resolution;
use crate::testset::{TestTable, cone_tests};
use crate::text::{list, near, num};
use anyhow::{Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

#[derive(Serialize)]
pub struct FeatureTree {
    pub node: String,
    pub ship: Option<String>,
    pub about: Option<String>,
    pub at: Option<String>,
    pub tests_in_cone: u64,
    pub nodes_in_cone: usize,
    pub lines: Vec<TreeLine>,
    /// Nodes reached only through dev-dependencies.
    pub dev_only: Vec<String>,
    /// Nodes in the cone that no drawn edge reaches because the path runs
    /// through an unowned package.
    pub via_unowned: Vec<String>,
}

#[derive(Serialize)]
pub struct TreeLine {
    pub depth: usize,
    pub node: String,
    /// The package `nodesFromCrates` made this node for.
    pub from_crate: Option<String>,
    /// "root", "part" (a child node of the line above) or "stands-on".
    pub relation: &'static str,
    /// Tests whose home is exactly this node.
    pub tests: u64,
    /// Other features whose cones also contain it.
    pub also_in: Vec<String>,
    /// Already printed above in this tree, not expanded again.
    pub repeated: bool,
    /// For `unowned`: the packages the cone reaches.
    pub packages: Vec<String>,
}

pub fn features(res: &Resolution<'_>) -> Vec<usize> {
    (0..=res.unowned).filter(|&i| res.nodes[i].ship.is_some()).collect()
}

pub fn run(res: &Resolution<'_>, table: &TestTable, only: Option<&str>) -> Result<Vec<FeatureTree>> {
    let wanted: Vec<usize> = match only {
        None => features(res),
        Some(id) => match res.node_index(id) {
            Some(n) => vec![n],
            None => {
                let ids: Vec<&str> = res.nodes.iter().map(|n| n.id.as_str()).collect();
                bail!(
                    "no node named \"{id}\" in the model; nearest: {}. Run `tree` without a name to list every feature.",
                    list(&near(id, ids.iter().copied(), 5))
                );
            }
        },
    };
    let feats = features(res);
    let cones: Vec<(usize, BTreeSet<usize>)> = feats.iter().map(|&f| (f, res.cone(f, false))).collect();
    let mut own = vec![0u64; res.nodes.len()];
    for h in table.home.iter().flatten() {
        own[*h] += 1;
    }
    Ok(wanted
        .into_iter()
        .map(|n| build(res, table, n, &cones, &own))
        .collect())
}

fn build(
    res: &Resolution<'_>,
    table: &TestTable,
    root: usize,
    cones: &[(usize, BTreeSet<usize>)],
    own: &[u64],
) -> FeatureTree {
    let (cone, upkgs) = res.cone_with_unowned(root, false);
    let (dev_cone, _) = res.cone_with_unowned(root, true);
    let node = &res.nodes[root];
    let mut t = FeatureTree {
        node: node.id.clone(),
        ship: node.ship_text(),
        about: node.about.clone(),
        at: node.at.clone(),
        tests_in_cone: cone_tests(res, table, root).len(),
        nodes_in_cone: cone.len(),
        lines: Vec::new(),
        dev_only: dev_cone.difference(&cone).map(|&n| res.nodes[n].id.clone()).collect(),
        via_unowned: Vec::new(),
    };
    let upkg_names: Vec<String> = upkgs.iter().map(|&p| res.pkg_name(p).to_owned()).collect();
    let mut drawn: BTreeSet<usize> = BTreeSet::new();
    let ctx = Ctx {
        res,
        cone: &cone,
        cones,
        own,
        root,
        table,
        upkg_names: &upkg_names,
        upkgs: &upkgs,
    };
    walk(&ctx, root, 0, "root", &mut drawn, &mut t.lines);
    t.via_unowned = cone
        .iter()
        .filter(|n| !drawn.contains(n))
        .map(|&n| res.nodes[n].id.clone())
        .collect();
    t
}

struct Ctx<'r, 'a> {
    res: &'r Resolution<'a>,
    cone: &'r BTreeSet<usize>,
    cones: &'r [(usize, BTreeSet<usize>)],
    own: &'r [u64],
    root: usize,
    table: &'r TestTable,
    upkg_names: &'r [String],
    upkgs: &'r BTreeSet<u32>,
}

fn walk(c: &Ctx<'_, '_>, n: usize, depth: usize, relation: &'static str, drawn: &mut BTreeSet<usize>, out: &mut Vec<TreeLine>) {
    let res = c.res;
    let repeated = !drawn.insert(n);
    out.push(line(c, n, depth, relation, repeated));
    if repeated {
        return;
    }
    // Nodes that stand on each other have no order, so a tree over them would
    // nest arbitrarily and repeat itself. They are listed flat, once, and the
    // group stands on whatever any member stands on outside the group.
    let group: Vec<usize> = if n != res.unowned && res.scc_members[res.scc_of[n]].len() > 1 {
        res.scc_members[res.scc_of[n]].clone()
    } else {
        vec![n]
    };
    for &m in group.iter().filter(|&&m| m != n && c.cone.contains(&m)) {
        drawn.insert(m);
        out.push(line(c, m, depth + 1, "mutual", false));
    }
    let mut next: Vec<(usize, &'static str)> = Vec::new();
    for &m in &group {
        for &child in &res.nodes[m].children {
            if c.cone.contains(&child) && !group.contains(&child) {
                next.push((child, "part"));
            }
        }
    }
    let mut targets: BTreeMap<usize, &'static str> = BTreeMap::new();
    for &m in &group {
        if m == res.unowned {
            let all = res.unowned_targets(c.upkgs);
            // Its packages are separate pieces of code; what they stand on is
            // drawn here, reduced among themselves, so the cone has no
            // unexplained members.
            for b in all.iter().copied().filter(|&b| {
                !all.iter().any(|&w| w != b && res.reaches(w, b, None) && !res.reaches(b, w, None))
            }) {
                targets.insert(b, "stands-on");
            }
        } else {
            for &(_, b) in res.reduced.range((m, 0)..(m + 1, 0)).filter(|(_, b)| !group.contains(b)) {
                let rel = if res.is_instance_only(m, b) { "instance-of" } else { "stands-on" };
                // A real dependency wins over an `of` law when both give the edge.
                let e = targets.entry(b).or_insert(rel);
                if rel == "stands-on" {
                    *e = rel;
                }
            }
        }
    }
    next.extend(targets);
    for (b, rel) in next {
        // A second edge into a cycle already listed adds nothing to read.
        if drawn.contains(&b) && res.scc_members[res.scc_of[b]].len() > 1 && b != res.unowned {
            continue;
        }
        walk(c, b, depth + 1, rel, drawn, out);
    }
}

fn line(c: &Ctx<'_, '_>, n: usize, depth: usize, relation: &'static str, repeated: bool) -> TreeLine {
    let res = c.res;
    let is_unowned = n == res.unowned;
    let tests = if is_unowned {
        (0..c.table.len())
            .filter(|&i| c.table.home[i] == Some(n) && c.upkgs.contains(&c.table.pkg[i]))
            .count() as u64
    } else {
        c.own[n]
    };
    let also_in = if n == c.root {
        Vec::new()
    } else {
        c.cones
            .iter()
            .filter(|(f, cone)| *f != c.root && !res.subtree[c.root].contains(f) && cone.contains(&n))
            .map(|(f, _)| res.nodes[*f].id.clone())
            .collect()
    };
    TreeLine {
        depth,
        node: res.nodes[n].id.clone(),
        from_crate: res.nodes[n].from_crate.clone(),
        relation,
        tests,
        also_in,
        repeated,
        packages: if is_unowned { c.upkg_names.to_vec() } else { Vec::new() },
    }
}

impl FeatureTree {
    pub fn render(&self) -> String {
        let mut o = String::new();
        let _ = write!(
            o,
            "{}  {}  {} tests in cone ({} nodes)",
            self.node,
            self.ship.as_deref().unwrap_or("no ship policy"),
            num(self.tests_in_cone),
            self.nodes_in_cone
        );
        if let Some(a) = &self.about {
            let _ = write!(o, "  {a}");
        }
        o.push('\n');
        if let Some(at) = &self.at {
            let _ = writeln!(o, "  at {}", short_at(at));
        }
        for l in &self.lines {
            let mark = match l.relation {
                "part" => "+",
                "stands-on" => ">",
                "mutual" => "=",
                "instance-of" => "~",
                _ => " ",
            };
            let mut line = format!("  {}{mark} {}{}", "  ".repeat(l.depth), l.node, if l.from_crate.is_some() { "*" } else { "" });
            let _ = write!(line, "  [{} tests]", num(l.tests));
            if !l.packages.is_empty() {
                let _ = write!(line, "  packages: {}", l.packages.join(", "));
            }
            if !l.also_in.is_empty() {
                let _ = write!(line, "  also in: {}", l.also_in.join(", "));
            }
            if l.repeated {
                line.push_str("  (shown above)");
            }
            o.push_str(&line);
            o.push('\n');
        }
        if !self.via_unowned.is_empty() {
            let _ = writeln!(
                o,
                "  also in the cone, reached only through unowned packages: {}",
                self.via_unowned.join(", ")
            );
        }
        if !self.dev_only.is_empty() {
            let _ = writeln!(o, "  dev-only (reached through dev-dependencies, not shipped): {}", self.dev_only.join(", "));
        }
        o
    }
}

pub fn render_all(trees: &[FeatureTree]) -> String {
    let mut o = String::from(
        "tree: each feature's cone over the transitively reduced stands-on edges.\n\
         legend: '+' part of the line above (child node), '>' stands on, '=' stands on each other with the line above (a cycle, listed flat), '~' is an instance of (an `of` law: it moves and blames like stands-on, but is never coverage), '[N tests]' tests homed in exactly that node, '*' after a name: the node is made from its crate by `nodesFromCrates`, not written in the model,\n\
         'also in' other features whose cones contain it; a node shown twice in one tree is expanded once.\n\n",
    );
    for (i, t) in trees.iter().enumerate() {
        if i > 0 {
            o.push('\n');
        }
        o.push_str(&t.render());
    }
    o
}
