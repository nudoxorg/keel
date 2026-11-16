//! The parts and tops of tests.
//!
//! A test's parts are the nodes whose code it reaches; its tops are the parts
//! no other part stands on. With a cargo index the reach is the test package's
//! closure ("by package closure", an over-approximation). Without one it is
//! the test's home node and what that node stands on, by the declared `on`
//! laws.

use crate::resolve::Resolution;
use crate::testset::{NO_PKG, TestTable};
use std::collections::{BTreeSet, HashMap};

pub struct TestParts {
    key_of: Vec<usize>,
    parts: Vec<BTreeSet<usize>>,
    tops: Vec<Vec<usize>>,
}

/// For each node, whether it stands on each other node through product edges. A chain may run
/// through unowned packages: a node that stands on a package no node claims, which stands on
/// another node, stands on that node. (Following node edges alone would leave the last node
/// unrelated to the first, and a test that reaches both would count it as a second top.)
pub fn standing(res: &Resolution<'_>) -> Vec<Vec<bool>> {
    let n = res.nodes.len();
    (0..n)
        .map(|a| {
            let mut seen = vec![false; n];
            // `unowned` stands on nothing as a node: it is many unrelated packages.
            if a == res.unowned {
                return seen;
            }
            let mut visited = vec![false; res.vprod.len()];
            let mut stack: Vec<usize> = res.vprod[a].iter().copied().collect();
            while let Some(x) = stack.pop() {
                if !std::mem::replace(&mut visited[x], true) {
                    seen[res.vnode(x)] = true;
                    stack.extend(res.vprod[x].iter().copied());
                }
            }
            seen
        })
        .collect()
}

impl TestParts {
    pub fn build(res: &Resolution<'_>, table: &TestTable) -> TestParts {
        let stand = standing(res);
        let cargo = !res.index.packages.is_empty();
        let mut ids: HashMap<usize, usize> = HashMap::new();
        let mut out = TestParts {
            key_of: Vec::with_capacity(table.len()),
            parts: Vec::new(),
            tops: Vec::new(),
        };
        for i in 0..table.len() {
            // Tests of one package share all their parts; tests without a
            // package share them by home node.
            let key = if cargo && table.pkg[i] != NO_PKG {
                table.pkg[i] as usize
            } else {
                usize::MAX / 2 + table.home[i].unwrap_or(usize::MAX / 4)
            };
            let slot = *ids.entry(key).or_insert_with(|| {
                let parts: BTreeSet<usize> = if cargo && table.pkg[i] != NO_PKG {
                    let mut s = BTreeSet::new();
                    for q in &res.index.package_closure(table.pkg[i]) {
                        s.extend(res.pkg_owners[q as usize].iter().copied().filter(|&n| n != res.unowned));
                    }
                    s
                } else {
                    match table.home[i] {
                        // Without reach evidence a test is about the node
                        // its file lies in and nothing more. Adding what
                        // that node stands on would cover every declared
                        // edge by declaration alone.
                        Some(h) if h != res.unowned => BTreeSet::from([h]),
                        _ => BTreeSet::new(),
                    }
                };
                // Parts that stand on each other are one cycle and neither
                // hides the other; otherwise a cycle would leave no top at all.
                let tops: Vec<usize> = parts
                    .iter()
                    .copied()
                    .filter(|&t| !parts.iter().any(|&o| o != t && stand[o][t] && !stand[t][o]))
                    .collect();
                out.parts.push(parts);
                out.tops.push(tops);
                out.parts.len() - 1
            });
            out.key_of.push(slot);
        }
        out
    }

    pub fn parts(&self, test: usize) -> &BTreeSet<usize> {
        &self.parts[self.key_of[test]]
    }

    pub fn tops(&self, test: usize) -> &[usize] {
        &self.tops[self.key_of[test]]
    }

    /// Distinct part sets with how many tests have each.
    pub fn distinct(&self) -> impl Iterator<Item = &BTreeSet<usize>> {
        self.parts.iter()
    }
}
