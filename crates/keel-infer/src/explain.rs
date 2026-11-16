//! Explain: describe the failures of a run in the fewest words.
//!
//! # The description-length model
//!
//! Imagine sending someone the list of failed tests, counting the bits it
//! takes. There are two ways to say things:
//!
//! * Name a failed test on its own: `log2(tests)` bits (its position).
//! * Name an attribute ("store.wal", "language:python"): `log2(attrs)` bits.
//!   Saying "this attribute is down" means every executed test with that
//!   attribute failed, so its failures need no further words. If a few tests
//!   with the attribute passed anyway, each is named as an exception at
//!   `log2(tests)` bits.
//!
//! The cost of an explanation is the sum of the attribute names, the
//! exceptions, and every failure that no chosen attribute covers (the
//! residue). Listing every failure individually is the baseline
//! (`bits_listed`). A cause is worth naming only when the failures it covers
//! cost more to list than the name plus its exceptions; the greedy cover
//! stops when no remaining candidate pays for itself.
//!
//! # Which attributes are candidates
//!
//! An attribute is *down* when it has at least `min_tests` executed tests and
//! failed/executed reaches `purity`. A down attribute is *explained by*
//! another when it stands on it (through `stands_on`, transitively), or when
//! its failing tests are a strict subset of the other's (equal sets: the
//! node-kind, then smaller id, is the explainer). Where the two rules
//! contradict each other (a dependant whose failures are a strict subset of
//! its dependency's is still explained by the dependency; chains can even
//! close a loop) the loop is collapsed and its largest member stands for it.
//! Down attributes nothing else explains are the roots; only roots are named.
//!
//! A root covers its own failing tests and those of every attribute it
//! explains, directly or through a chain. That is what lets "indexing is down
//! because store.wal is down" count indexing's failures as store.wal's, even
//! though no indexing test has the store.wal attribute.

use std::collections::VecDeque;

use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};

use crate::TestId;

pub type AttrId = u32;

/// One attribute tests can have. `kind` is free-form, but `"node"` is special:
/// only node attributes take part in `stands_on` and win ties.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attr {
    /// "node:store.wal", "language:python", "package:backend-store".
    pub name: String,
    /// "node", "axis", "package", "module", ...
    pub kind: String,
    /// Every test that has this attribute.
    pub tests: RoaringBitmap,
    /// Direct edges: this attribute's code stands on those attributes' code.
    /// A DAG, only meaningful among "node" attributes.
    pub stands_on: Vec<AttrId>,
}

/// Tests are `0..tests`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Universe {
    pub tests: u32,
    pub attrs: Vec<Attr>,
}

#[derive(Clone, Debug)]
pub struct ExplainOptions {
    /// An attribute is down when failed/executed among its tests is at least this.
    pub purity: f64,
    /// Attributes with fewer executed tests than this are ignored.
    pub min_tests: u32,
    pub max_causes: usize,
}

impl Default for ExplainOptions {
    fn default() -> Self {
        Self { purity: 1.0, min_tests: 2, max_causes: 12 }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Cause {
    pub attr: AttrId,
    /// Among this attribute's tests.
    pub executed: u64,
    pub failed: u64,
    /// Failures this cause covers that earlier causes (earlier in `causes`) did not.
    pub newly_explained: u64,
    /// Executed tests with the attribute that passed; empty at purity 1.0.
    pub exceptions: Vec<TestId>,
    /// Other down attributes this cause explains, ascending.
    pub consequences: Vec<AttrId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Explanation {
    /// In the order the greedy cover chose them, which is by tests explained
    /// descending except where a cause's exceptions made a smaller one cheaper.
    pub causes: Vec<Cause>,
    /// Failed tests no chosen cause covers, ascending.
    pub residue: Vec<TestId>,
    /// Bits to list every failure individually.
    pub bits_listed: f64,
    /// Bits for this explanation: names, exceptions and residue.
    pub bits_explained: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum ExplainError {
    #[error(
        "test {test} is in `failed` but not in `executed`: a test cannot fail without running; \
         pass only executed tests as failed"
    )]
    FailedNotExecuted { test: TestId },
    #[error(
        "test {test} in `{which}` is outside the universe 0..{tests}; build the bitmaps from the \
         same test numbering as the Universe"
    )]
    TestOutOfRange { which: &'static str, test: TestId, tests: u32 },
    #[error(
        "attribute {attr} ({name}) has a test beyond the universe's {tests} tests; \
         build the attribute bitmaps from the same test numbering as the Universe"
    )]
    AttrTestOutOfRange { attr: AttrId, name: String, tests: u32 },
    #[error(
        "attribute {attr} ({name}) stands on {target}, but there are only {attrs} attributes; \
         fix the stands_on edge"
    )]
    UnknownEdge { attr: AttrId, name: String, target: AttrId, attrs: usize },
    #[error(
        "stands_on has a cycle through attribute {attr} ({name}); the edges must form a DAG, \
         remove one edge of the cycle"
    )]
    Cycle { attr: AttrId, name: String },
    #[error("purity must be in (0, 1], got {0}; use 1.0 to require every executed test to fail")]
    BadPurity(f64),
}

const NODE: &str = "node";

fn is_node(a: &Attr) -> bool {
    a.kind == NODE
}

/// Only node-to-node edges are meaningful; the rest are ignored on purpose so
/// a stray edge on an axis attribute cannot hide a real cause.
fn live_edges(u: &Universe, from: usize) -> impl Iterator<Item = usize> + '_ {
    let a = &u.attrs[from];
    a.stands_on
        .iter()
        .map(|&t| t as usize)
        .filter(move |&t| is_node(a) && is_node(&u.attrs[t]))
}

fn validate(
    u: &Universe,
    executed: &RoaringBitmap,
    failed: &RoaringBitmap,
    opts: &ExplainOptions,
) -> Result<(), ExplainError> {
    if !(opts.purity > 0.0 && opts.purity <= 1.0) {
        return Err(ExplainError::BadPurity(opts.purity));
    }
    for (which, bm) in [("executed", executed), ("failed", failed)] {
        if let Some(max) = bm.max()
            && max >= u.tests
        {
            return Err(ExplainError::TestOutOfRange { which, test: max, tests: u.tests });
        }
    }
    if !failed.is_subset(executed) {
        let test = (failed - executed).min().unwrap_or(0);
        return Err(ExplainError::FailedNotExecuted { test });
    }
    let n = u.attrs.len();
    for (i, a) in u.attrs.iter().enumerate() {
        if a.tests.max().is_some_and(|m| m >= u.tests) {
            return Err(ExplainError::AttrTestOutOfRange {
                attr: i as AttrId,
                name: a.name.clone(),
                tests: u.tests,
            });
        }
        if let Some(&target) = a.stands_on.iter().find(|&&t| t as usize >= n) {
            return Err(ExplainError::UnknownEdge {
                attr: i as AttrId,
                name: a.name.clone(),
                target,
                attrs: n,
            });
        }
    }
    // Kahn's algorithm: whatever cannot be peeled lies on or behind a cycle.
    let mut indeg = vec![0usize; n];
    for i in 0..n {
        for t in live_edges(u, i) {
            indeg[t] += 1;
        }
    }
    let mut queue: VecDeque<usize> = (0..n).filter(|&i| indeg[i] == 0).collect();
    let mut peeled = 0;
    while let Some(i) = queue.pop_front() {
        peeled += 1;
        for t in live_edges(u, i) {
            indeg[t] -= 1;
            if indeg[t] == 0 {
                queue.push_back(t);
            }
        }
    }
    if peeled < n {
        let i = (0..n).find(|&i| indeg[i] > 0).unwrap_or(0);
        return Err(ExplainError::Cycle { attr: i as AttrId, name: u.attrs[i].name.clone() });
    }
    Ok(())
}

/// Iterative Tarjan: component id per node, ids in reverse topological order.
fn components(adj: &[Vec<usize>]) -> Vec<usize> {
    const NONE: usize = usize::MAX;
    let n = adj.len();
    let (mut index, mut low) = (vec![NONE; n], vec![0usize; n]);
    let (mut on_stack, mut comp) = (vec![false; n], vec![NONE; n]);
    let (mut stack, mut next_index, mut next_comp) = (Vec::new(), 0usize, 0usize);
    for s in 0..n {
        if index[s] != NONE {
            continue;
        }
        index[s] = next_index;
        low[s] = next_index;
        next_index += 1;
        stack.push(s);
        on_stack[s] = true;
        let mut calls: Vec<(usize, usize)> = vec![(s, 0)];
        while let Some(&(v, ei)) = calls.last() {
            if ei < adj[v].len() {
                calls.last_mut().expect("nonempty").1 += 1;
                let w = adj[v][ei];
                if index[w] == NONE {
                    index[w] = next_index;
                    low[w] = next_index;
                    next_index += 1;
                    stack.push(w);
                    on_stack[w] = true;
                    calls.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(index[w]);
                }
            } else {
                calls.pop();
                if low[v] == index[v] {
                    while let Some(w) = stack.pop() {
                        on_stack[w] = false;
                        comp[w] = next_comp;
                        if w == v {
                            break;
                        }
                    }
                    next_comp += 1;
                }
                if let Some(&(parent, _)) = calls.last() {
                    low[parent] = low[parent].min(low[v]);
                }
            }
        }
    }
    comp
}

fn bits(n: usize) -> f64 {
    (n.max(2) as f64).log2()
}

/// A down attribute: all numbers are about this run.
struct Down {
    attr: usize,
    executed: u64,
    failed: u64,
    fail: RoaringBitmap,
}

pub fn explain(
    u: &Universe,
    executed: &RoaringBitmap,
    failed: &RoaringBitmap,
    opts: &ExplainOptions,
) -> Result<Explanation, ExplainError> {
    validate(u, executed, failed, opts)?;
    let test_bits = bits(u.tests as usize);
    let name_bits = bits(u.attrs.len());
    let bits_listed = failed.len() as f64 * test_bits;

    // 1. Candidates.
    let mut down: Vec<Down> = Vec::new();
    for (i, a) in u.attrs.iter().enumerate() {
        let ex = a.tests.intersection_len(executed);
        let fl = a.tests.intersection_len(failed);
        if ex < u64::from(opts.min_tests.max(1)) || fl == 0 {
            continue;
        }
        // The tolerance keeps 9/10 >= 0.9 true; at purity 1.0 it still demands every test.
        if (fl as f64 / ex as f64) < opts.purity - 1e-12 {
            continue;
        }
        down.push(Down { attr: i, executed: ex, failed: fl, fail: &a.tests & failed });
    }
    let d = down.len();

    // 2. Who explains whom. `stands[i]` holds everything attribute i stands on,
    // transitively, through attributes that are not themselves down.
    let stands: Vec<RoaringBitmap> = down
        .iter()
        .map(|x| {
            let mut seen = RoaringBitmap::new();
            let mut work: Vec<usize> = live_edges(u, x.attr).collect();
            while let Some(t) = work.pop() {
                if seen.insert(t as u32) {
                    work.extend(live_edges(u, t));
                }
            }
            seen
        })
        .collect();
    let prefer = |j: usize, i: usize| {
        // j beats i among equal failing sets: node kind first, then smaller id.
        let (nj, ni) = (is_node(&u.attrs[down[j].attr]), is_node(&u.attrs[down[i].attr]));
        if nj != ni { nj } else { down[j].attr < down[i].attr }
    };
    // explainers[i] = slots that explain i.
    let mut explainers: Vec<Vec<usize>> = vec![Vec::new(); d];
    let mut explained: Vec<Vec<usize>> = vec![Vec::new(); d];
    for i in 0..d {
        for j in 0..d {
            if i == j {
                continue;
            }
            let yes = if stands[i].contains(down[j].attr as u32) {
                true
            } else if stands[j].contains(down[i].attr as u32) {
                false
            } else if down[i].failed < down[j].failed {
                down[i].fail.is_subset(&down[j].fail)
            } else if down[i].failed == down[j].failed {
                down[i].fail == down[j].fail && prefer(j, i)
            } else {
                false
            };
            if yes {
                explainers[i].push(j);
                explained[j].push(i);
            }
        }
    }

    // Roots: one per source component of the explained-by graph.
    let comp = components(&explainers);
    let ncomp = comp.iter().copied().max().map_or(0, |m| m + 1);
    let mut has_outside_explainer = vec![false; ncomp];
    for i in 0..d {
        if explainers[i].iter().any(|&j| comp[j] != comp[i]) {
            has_outside_explainer[comp[i]] = true;
        }
    }
    let mut rep: Vec<Option<usize>> = vec![None; ncomp];
    for i in 0..d {
        let c = comp[i];
        if has_outside_explainer[c] {
            continue;
        }
        let better = match rep[c] {
            None => true,
            Some(r) => {
                down[i].failed > down[r].failed
                    || (down[i].failed == down[r].failed && prefer(i, r))
            }
        };
        if better {
            rep[c] = Some(i);
        }
    }
    let mut roots: Vec<usize> = rep.into_iter().flatten().collect();
    roots.sort_by_key(|&r| down[r].attr);

    // What each root covers: its own failures plus those of everything that
    // reaches it along explained-by edges.
    let cover_of = |root: usize| -> (RoaringBitmap, Vec<usize>) {
        let mut seen = vec![false; d];
        seen[root] = true;
        let mut work = vec![root];
        let mut cover = down[root].fail.clone();
        let mut others = Vec::new();
        while let Some(x) = work.pop() {
            for &y in &explained[x] {
                if !seen[y] {
                    seen[y] = true;
                    cover |= &down[y].fail;
                    others.push(y);
                    work.push(y);
                }
            }
        }
        (cover, others)
    };
    let covers: Vec<(RoaringBitmap, Vec<usize>)> = roots.iter().map(|&r| cover_of(r)).collect();

    // 3. Greedy minimum-description-length cover.
    let mut covered = RoaringBitmap::new();
    let mut taken = vec![false; roots.len()];
    let mut causes = Vec::new();
    let mut bits_explained = 0.0;
    while causes.len() < opts.max_causes {
        let mut best: Option<(usize, f64, u64)> = None;
        for (k, &r) in roots.iter().enumerate() {
            if taken[k] {
                continue;
            }
            let newly = covers[k].0.difference_len(&covered);
            let exc = down[r].executed - down[r].failed;
            let gain = (newly as f64 - exc as f64) * test_bits - name_bits;
            // Strict: ties keep the earlier (smaller attribute id) root.
            if gain > 0.0 && best.is_none_or(|(_, g, _)| gain > g) {
                best = Some((k, gain, newly));
            }
        }
        let Some((k, _, newly)) = best else { break };
        taken[k] = true;
        let r = roots[k];
        let a = &u.attrs[down[r].attr];
        let exceptions: Vec<TestId> = ((&a.tests & executed) - failed).iter().collect();
        bits_explained += name_bits + exceptions.len() as f64 * test_bits;
        let mut consequences: Vec<AttrId> =
            covers[k].1.iter().map(|&y| down[y].attr as AttrId).collect();
        consequences.sort_unstable();
        covered |= &covers[k].0;
        causes.push(Cause {
            attr: down[r].attr as AttrId,
            executed: down[r].executed,
            failed: down[r].failed,
            newly_explained: newly,
            exceptions,
            consequences,
        });
    }
    let residue: Vec<TestId> = (failed - &covered).iter().collect();
    bits_explained += residue.len() as f64 * test_bits;
    Ok(Explanation { causes, residue, bits_listed, bits_explained })
}
