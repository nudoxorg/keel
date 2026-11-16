//! Plan: run the tests that remove the most doubt per second, first.
//!
//! # The model
//!
//! Each changed *unit* is wrong with some probability (its belief), starting at
//! its prior. A test *notices* a unit with probability `d` (it fails with that
//! chance if the unit is wrong). Several wrong units and several tests combine
//! as a noisy-OR: a test fails if any wrong unit it notices is detected, and
//! detections are independent.
//!
//! * Doubt a test would remove: `sum over units a it notices of p_a * d_ta`,
//!   the probability mass of faults it would expose. The score is that divided
//!   by the test's cost in milliseconds.
//! * A pass is exact Bayes per unit: `p' = p (1 - d) / (1 - p d)`. Pass events
//!   factor over units, so units stay independent after any number of passes.
//! * A failure raises the beliefs of the units it notices. The exact noisy-OR
//!   posterior is used, `p'_a = p_a * P(fail | a wrong) / P(fail)`, with
//!   `P(fail) = 1 - prod_b (1 - p_b d_b)`; then units are treated as
//!   independent again, which is an approximation (a failure really makes the
//!   noticed units negatively correlated: "one of them is wrong"). Beliefs are
//!   capped just below 1 so they stay valid inputs.
//! * A test may also fail with nothing wrong: its *leak*, the rate at which it
//!   fails on unchanged code (a flake, a broken environment). With a leak the
//!   failure probability is `1 - (1 - leak) * prod_b (1 - p_b d_b)`, and a
//!   failure of a leaky test moves the beliefs less: part of it is explained
//!   by the test itself. Leaks default to 0. A pass is unaffected: the leak
//!   multiplies both the numerator and the denominator of the update.
//! * Two risks, which answer different questions and must not be confused:
//!   - *Worth running* (`residual_risk`): the chance at least one of a set of
//!     not-yet-run tests fails, `1 - prod_a (1 - p_a * (1 - prod_{t notices a}
//!     (1 - d_ta)))`. It reaches 0 when everything has run, however weak the
//!     tests are.
//!   - *Could escape* (`could_escape`): the chance some unit is still wrong,
//!     `1 - prod_a (1 - p_a)`. It stays high for a unit nothing notices, and
//!     it is the number a decision to ship has to look at.
//!
//! The risk number is only as good as its inputs: it assumes tests notice
//! independently of each other and that the notice probabilities are right.
//! Nothing here measures either.

use std::cmp::Ordering;

use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};

use crate::TestId;

pub type UnitId = u32;

/// Beliefs never reach 1: a certain fault would make every later Bayes update
/// divide by zero, and nothing observed here can prove a unit wrong.
const BELIEF_CAP: f64 = 1.0 - 1e-9;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Unit {
    /// Chance this changed unit is wrong before any test; in (0, 1).
    pub prior: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestModel {
    /// Greater than 0.
    pub cost_ms: u32,
    /// P(test fails | unit is wrong), strictly increasing by unit, each in (0, 1].
    pub notices: Vec<(UnitId, f32)>,
}

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("unit {unit} has prior {prior}, which is not in (0, 1); give a probability strictly between 0 and 1")]
    PriorOutOfRange { unit: UnitId, prior: f64 },
    #[error("test {test} has cost_ms 0; every test needs a positive cost (use 1 for negligible)")]
    ZeroCost { test: TestId },
    #[error("test {test} notices unit {unit}, but only {units} units exist; fix the unit id or add the unit")]
    UnknownUnit { test: TestId, unit: UnitId, units: usize },
    #[error("test {test} lists unit {unit} out of order or twice; sort `notices` by unit and merge duplicates")]
    NoticesNotSorted { test: TestId, unit: UnitId },
    #[error("test {test} notices unit {unit} with probability {detect}, which is not in (0, 1]; use a positive probability or drop the entry")]
    DetectOutOfRange { test: TestId, unit: UnitId, detect: f32 },
    #[error("{count} tests exceed the u32 test id space; split the suite")]
    TooManyTests { count: usize },
    #[error("{given} leaks were given for {tests} tests; give one per test, in test order")]
    LeakCount { given: usize, tests: usize },
    #[error("test {test} has leak {leak}, which is not in [0, 1); a test that always fails carries no evidence and should be removed from the plan")]
    LeakOutOfRange { test: TestId, leak: f64 },
}

/// One position of the assume-everything-passes order.
#[derive(Clone, Debug, PartialEq)]
pub struct Step {
    pub test: TestId,
    pub cumulative_ms: u64,
    /// Risk over all tests still unrun after this step, beliefs updated as if it passed.
    pub residual_risk: f64,
    /// The doubt this test removed at the moment it was chosen.
    pub expected_removed: f64,
}

/// Planner state: beliefs, plus which tests have been observed. Notices are
/// stored flat (CSR) so 200,000 tests do not mean 200,000 small allocations.
#[derive(Clone, Debug)]
pub struct Planner {
    belief: Vec<f64>,
    cost: Vec<u32>,
    off: Vec<usize>,
    unit: Vec<UnitId>,
    detect: Vec<f64>,
    done: Vec<bool>,
    failed: RoaringBitmap,
    /// P(test fails | no unit is wrong), per test.
    leak: Vec<f64>,
    /// Failures the model had given probability zero.
    contradictions: Vec<TestId>,
    /// The largest P(some noticed unit is wrong | that failure) over the
    /// failures seen: a floor under `could_escape`.
    escape_floor: f64,
}

/// Neumaier-compensated running sum. Risk is kept as a sum of per-unit logs
/// that are added and withdrawn for hundreds of thousands of steps; a plain sum
/// would drift by more than the late-schedule risks it must resolve.
#[derive(Clone, Copy, Default)]
struct Sum {
    sum: f64,
    comp: f64,
}

impl Sum {
    fn add(&mut self, x: f64) {
        let t = self.sum + x;
        if self.sum.abs() >= x.abs() {
            self.comp += (self.sum - t) + x;
        } else {
            self.comp += (x - t) + self.sum;
        }
        self.sum = t;
    }
    fn get(&self) -> f64 {
        self.sum + self.comp
    }
}

/// Posterior after a pass. `min` keeps beliefs monotone even where rounding
/// would nudge the quotient up by an ulp; lazy greedy depends on that monotonicity.
fn after_pass(p: f64, d: f64) -> f64 {
    if p <= 0.0 {
        return 0.0;
    }
    (p * (1.0 - d) / (1.0 - p * d)).min(p)
}

/// A scored test. Orders by score, then by the smaller test id.
#[derive(Clone, Copy)]
struct Entry {
    removed: f64,
    score: f64,
    test: u32,
}

impl PartialEq for Entry {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}
impl Eq for Entry {}
impl PartialOrd for Entry {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Entry {
    fn cmp(&self, o: &Self) -> Ordering {
        self.score.total_cmp(&o.score).then_with(|| o.test.cmp(&self.test))
    }
}

impl Planner {
    pub fn new(units: Vec<Unit>, tests: Vec<TestModel>) -> Result<Planner, PlanError> {
        for (i, u) in units.iter().enumerate() {
            if !(u.prior > 0.0 && u.prior < 1.0) {
                return Err(PlanError::PriorOutOfRange { unit: i as UnitId, prior: u.prior });
            }
        }
        if tests.len() > u32::MAX as usize {
            return Err(PlanError::TooManyTests { count: tests.len() });
        }
        let mut cost = Vec::with_capacity(tests.len());
        let mut off = Vec::with_capacity(tests.len() + 1);
        let (mut unit, mut detect) = (Vec::new(), Vec::new());
        off.push(0);
        for (t, m) in tests.iter().enumerate() {
            let test = t as TestId;
            if m.cost_ms == 0 {
                return Err(PlanError::ZeroCost { test });
            }
            let mut prev: Option<UnitId> = None;
            for &(a, d) in &m.notices {
                if a as usize >= units.len() {
                    return Err(PlanError::UnknownUnit { test, unit: a, units: units.len() });
                }
                if prev.is_some_and(|q| q >= a) {
                    return Err(PlanError::NoticesNotSorted { test, unit: a });
                }
                if !(d > 0.0 && d <= 1.0) {
                    return Err(PlanError::DetectOutOfRange { test, unit: a, detect: d });
                }
                prev = Some(a);
                unit.push(a);
                detect.push(f64::from(d));
            }
            cost.push(m.cost_ms);
            off.push(unit.len());
        }
        Ok(Planner {
            belief: units.iter().map(|u| u.prior).collect(),
            done: vec![false; cost.len()],
            leak: vec![0.0; cost.len()],
            contradictions: Vec::new(),
            escape_floor: 0.0,
            cost,
            off,
            unit,
            detect,
            failed: RoaringBitmap::new(),
        })
    }

    /// Sets each test's leak: how often it fails when nothing it notices is
    /// wrong. Taken from the test's own history on unchanged code.
    pub fn with_leaks(mut self, leaks: &[f64]) -> Result<Planner, PlanError> {
        if leaks.len() != self.cost.len() {
            return Err(PlanError::LeakCount { given: leaks.len(), tests: self.cost.len() });
        }
        for (t, &leak) in leaks.iter().enumerate() {
            if !(0.0..1.0).contains(&leak) {
                return Err(PlanError::LeakOutOfRange { test: t as TestId, leak });
            }
        }
        self.leak = leaks.to_vec();
        Ok(self)
    }

    /// The chance at least one unit is still wrong under current beliefs.
    /// Unlike `residual_risk` this does not fall to zero when the tests run
    /// out: a unit no test notices keeps its prior.
    ///
    /// After a failure the beliefs are no longer independent ("one of these
    /// is wrong"), and multiplying them understates the chance: two units at
    /// 0.1 under one certain test that fails give 0.776 by the product and 1
    /// in truth. So the product is never allowed below what the failures
    /// themselves established. That floor is not lowered by later passes,
    /// which errs on the side of doubt.
    pub fn could_escape(&self) -> f64 {
        let mut total = Sum::default();
        for &p in &self.belief {
            total.add((-p).ln_1p());
        }
        (-total.get().exp_m1()).clamp(0.0, 1.0).max(self.escape_floor)
    }

    /// Tests that failed although the model gave their failure probability
    /// zero: every unit they notice had been cleared by a certain test and
    /// they have no leak. The model is wrong about something (a notice
    /// probability, a leak, or a key that hides a changed input), and the
    /// caller must say so, not carry on.
    pub fn contradictions(&self) -> &[TestId] {
        &self.contradictions
    }

    pub fn tests(&self) -> usize {
        self.cost.len()
    }

    pub fn units(&self) -> usize {
        self.belief.len()
    }

    /// Tests observed to fail so far.
    pub fn failed(&self) -> &RoaringBitmap {
        &self.failed
    }

    fn span(&self, t: usize) -> std::ops::Range<usize> {
        self.off[t]..self.off[t + 1]
    }

    /// Expected doubt removed by test `t` under `belief`. The one place this is
    /// computed, in a fixed summation order, so naive and lazy greedy agree bit for bit.
    fn removed(&self, belief: &[f64], t: usize) -> f64 {
        let mut s = 0.0;
        for k in self.span(t) {
            s += belief[self.unit[k] as usize] * self.detect[k];
        }
        s
    }

    /// The not-yet-run test with the largest expected doubt removed per
    /// millisecond under current beliefs; `None` when every remaining test has
    /// zero expected effect or none remain. Ties go to the smaller id.
    pub fn next(&self) -> Option<TestId> {
        let mut best: Option<(usize, f64)> = None;
        for t in 0..self.cost.len() {
            if self.done[t] {
                continue;
            }
            let score = self.removed(&self.belief, t) / f64::from(self.cost[t]);
            if score > 0.0 && best.is_none_or(|(_, b)| score > b) {
                best = Some((t, score));
            }
        }
        best.map(|(t, _)| t as TestId)
    }

    /// Record a result. Observing a test twice, or a test that does not exist,
    /// changes nothing: a repeat would count the same evidence twice.
    pub fn observe(&mut self, test: TestId, passed: bool) {
        let t = test as usize;
        if t >= self.cost.len() || self.done[t] {
            return;
        }
        self.done[t] = true;
        let span = self.span(t);
        if passed {
            for k in span {
                let a = self.unit[k] as usize;
                self.belief[a] = after_pass(self.belief[a], self.detect[k]);
            }
            return;
        }
        self.failed.insert(test);
        // ln P(no noticed unit is detected), summed once; each unit's share is withdrawn below.
        let ln_miss = |p: f64, d: f64| (-p * d).ln_1p();
        // The leak is one more way to fail that blames no unit.
        let total: f64 = (-self.leak[t]).ln_1p()
            + span.clone().map(|k| ln_miss(self.belief[self.unit[k] as usize], self.detect[k])).sum::<f64>();
        let p_fail = -total.exp_m1();
        if p_fail <= 0.0 {
            // The model said this failure was impossible. There is nothing to
            // apportion the blame to, but the observation is kept: it is the
            // evidence that the model itself is wrong, and something did fail.
            self.contradictions.push(test);
            self.escape_floor = 1.0;
            return;
        }
        // P(no noticed unit is wrong | this failure): only the leak is left.
        let ln_all_fine: f64 =
            span.clone().map(|k| (-self.belief[self.unit[k] as usize]).ln_1p()).sum();
        let only_leak = self.leak[t] * ln_all_fine.exp() / p_fail;
        self.escape_floor = self.escape_floor.max((1.0 - only_leak).clamp(0.0, 1.0));
        for k in span {
            let a = self.unit[k] as usize;
            let (p, d) = (self.belief[a], self.detect[k]);
            if p <= 0.0 {
                continue;
            }
            // P(fail | a wrong) = 1 - (1 - leak) * (1 - d) * prod_{b != a} (1 - p_b d_b)
            let p_fail_given_a = -((-d).ln_1p() + total - ln_miss(p, d)).exp_m1();
            let posterior = p * p_fail_given_a / p_fail;
            self.belief[a] = posterior.min(BELIEF_CAP).max(p);
        }
    }

    /// Current chance that `unit` is wrong. Panics on an unknown unit id.
    pub fn belief(&self, unit: UnitId) -> f64 {
        assert!(
            (unit as usize) < self.belief.len(),
            "unit {unit} does not exist: the planner has {} units",
            self.belief.len()
        );
        self.belief[unit as usize]
    }

    /// P(at least one of these not-yet-run tests would fail) under current
    /// beliefs and noisy-OR. Tests already observed, and ids beyond the suite,
    /// are skipped: their evidence is already in the beliefs.
    pub fn residual_risk(&self, tests: &RoaringBitmap) -> f64 {
        // Per unit: sum of ln(1 - d) over the set's tests that notice it, and
        // whether one of them is certain to notice (d = 1, ln would be -inf).
        let mut ln_miss = vec![0.0f64; self.belief.len()];
        let mut certain = vec![false; self.belief.len()];
        let mut touched: Vec<usize> = Vec::new();
        let mut seen = vec![false; self.belief.len()];
        for t in tests {
            let t = t as usize;
            if t >= self.cost.len() || self.done[t] {
                continue;
            }
            for k in self.span(t) {
                let a = self.unit[k] as usize;
                if !seen[a] {
                    seen[a] = true;
                    touched.push(a);
                }
                if self.detect[k] >= 1.0 {
                    certain[a] = true;
                } else {
                    ln_miss[a] += (-self.detect[k]).ln_1p();
                }
            }
        }
        let mut total = Sum::default();
        for a in touched {
            let cover = if certain[a] { 1.0 } else { -ln_miss[a].exp_m1() };
            total.add((-self.belief[a] * cover).ln_1p());
        }
        (-total.get().exp_m1()).clamp(0.0, 1.0)
    }

    /// Full greedy order assuming every test passes, with the residual risk
    /// over all remaining tests after each step and the cumulative cost.
    /// Does not mutate the planner. Tests that remove no doubt are left out,
    /// exactly as `next` would stop at them.
    ///
    /// This is lazy greedy for submodular maximisation, in a windowed form.
    /// A pass only lowers beliefs, so a test's score never rises, and a score
    /// computed earlier is an upper bound on the true one. Plain lazy greedy
    /// (re-score the top heap entry, re-push, repeat) is exact but, when
    /// thousands of tests share units, it re-scores the same tests once per
    /// selection that nudges them: 3x10^8 re-scorings, about 100 s, for
    /// 200,000 tests over 5,000 units. Here a window of the best tests is kept
    /// up to date by cheap per-unit deltas instead, and everything outside it
    /// is covered by the same bound argument: those tests ranked strictly
    /// below the window's last member when it was cut, and ranks only fall, so
    /// while the best window test still ranks at or above the cut it is the
    /// true best. When it does not, the window is re-cut from a full re-score.
    /// Ranks are (score, smaller id), and the chosen test's score is always
    /// recomputed with the same function `next` uses before it is trusted
    /// (the deltas only decide which few tests to recompute), so the order is
    /// the one `next` followed by `observe(pass)` in a loop would give.
    pub fn schedule(&self) -> Vec<Step> {
        self.schedule_windowed((self.cost.len() / 32).max(64))
    }

    /// `schedule` with an explicit window size. Public only so tests can
    /// force tiny windows and so exercise the re-cut path on small inputs.
    #[doc(hidden)]
    pub fn schedule_windowed(&self, window: usize) -> Vec<Step> {
        let n = self.cost.len();
        let nu = self.belief.len();
        let mut belief = self.belief.clone();

        // Risk bookkeeping over the unrun tests: per unit, the compensated sum
        // of ln(1 - d), how many unrun tests notice it, and how many of those
        // are certain. term[a] is the unit's current share of the total log.
        let mut ln_miss = vec![Sum::default(); nu];
        let mut noticing = vec![0u32; nu];
        let mut certain = vec![0u32; nu];
        for t in (0..n).filter(|&t| !self.done[t]) {
            for k in self.span(t) {
                let a = self.unit[k] as usize;
                noticing[a] += 1;
                if self.detect[k] >= 1.0 {
                    certain[a] += 1;
                } else {
                    ln_miss[a].add((-self.detect[k]).ln_1p());
                }
            }
        }
        let term_of = |p: f64, noticing: u32, certain: u32, ln_miss: &Sum| {
            let cover = if noticing == 0 {
                0.0
            } else if certain > 0 {
                1.0
            } else {
                -ln_miss.get().exp_m1()
            };
            (-p * cover).ln_1p()
        };
        let mut term: Vec<f64> =
            (0..nu).map(|a| term_of(belief[a], noticing[a], certain[a], &ln_miss[a])).collect();
        let mut total = Sum::default();
        for &x in &term {
            total.add(x);
        }

        // `dead`: observed, chosen, or provably zero effect (scores never
        // rise, so zero stays zero).
        let mut dead = self.done.clone();
        let mut win = Window::new(window.max(1), nu, (0..n).map(|t| self.span(t).len()).max().unwrap_or(0));
        let mut steps: Vec<Step> = Vec::new();
        let mut cumulative_ms = 0u64;
        let mut last_risk = f64::INFINITY;
        let mut fresh = false;
        loop {
            let picked = win.pick(self, &belief, &mut dead);
            let trusted = match (&picked, win.cut) {
                (Some(_), None) => true,
                (Some((e, _)), Some(c)) => fresh || *e >= c,
                (None, _) => false,
            };
            let Some((chosen, slot)) = picked.filter(|_| trusted) else {
                if !win.rebuild(self, &belief, &mut dead) {
                    break;
                }
                fresh = true;
                continue;
            };
            fresh = false;

            let t = chosen.test as usize;
            dead[t] = true;
            win.retire(slot);
            cumulative_ms += u64::from(self.cost[t]);
            for k in self.span(t) {
                let a = self.unit[k] as usize;
                noticing[a] -= 1;
                if self.detect[k] >= 1.0 {
                    certain[a] -= 1;
                } else {
                    ln_miss[a].add(-(-self.detect[k]).ln_1p());
                }
                let before = belief[a];
                belief[a] = after_pass(before, self.detect[k]);
                win.lower(a, before - belief[a]);
                let moved = term_of(belief[a], noticing[a], certain[a], &ln_miss[a]);
                total.add(-term[a]);
                total.add(moved);
                term[a] = moved;
            }
            // Mathematically non-increasing; the clamp only absorbs rounding.
            let risk = (-total.get().exp_m1()).clamp(0.0, 1.0).min(last_risk);
            last_risk = risk;
            steps.push(Step {
                test: chosen.test,
                cumulative_ms,
                residual_risk: risk,
                expected_removed: chosen.removed,
            });
        }
        steps
    }
}

/// The best tests, kept current by deltas. `score` is approximate: when a
/// unit's belief falls by `delta`, every window test noticing it loses
/// `delta * d / cost`, one multiply instead of re-summing 20 terms. That is
/// only used to find the few candidates near the top; they are then re-scored
/// exactly, so rounding drift in `score` cannot change which test is chosen
/// as long as the candidate band covers the drift (see `band`).
struct Window {
    width: usize,
    max_notices: usize,
    test: Vec<u32>,
    /// Approximate score per slot; -inf once the slot is retired or useless.
    score: Vec<f64>,
    /// Per unit: (slot, d / cost) for window tests noticing it.
    by_unit: Vec<Vec<(u32, f64)>>,
    /// The last member of the window when it was cut; everything outside ranks below it.
    cut: Option<Entry>,
    /// Largest score at the last cut, and steps taken since: they bound the drift.
    top: f64,
    steps: usize,
}

impl Window {
    fn new(width: usize, units: usize, max_notices: usize) -> Window {
        Window {
            width,
            max_notices,
            test: Vec::new(),
            score: Vec::new(),
            by_unit: vec![Vec::new(); units],
            cut: None,
            top: 0.0,
            steps: 0,
        }
    }

    /// Re-cut from a full exact re-score of every live test. False when no live
    /// test has any effect left.
    fn rebuild(&mut self, pl: &Planner, belief: &[f64], dead: &mut [bool]) -> bool {
        for &t in &self.test {
            for k in pl.span(t as usize) {
                self.by_unit[pl.unit[k] as usize].clear();
            }
        }
        let mut scored: Vec<Entry> = Vec::new();
        for (t, gone) in dead.iter_mut().enumerate() {
            if *gone {
                continue;
            }
            let removed = pl.removed(belief, t);
            if removed <= 0.0 {
                *gone = true;
                continue;
            }
            scored.push(Entry { removed, score: removed / f64::from(pl.cost[t]), test: t as u32 });
        }
        self.test.clear();
        self.score.clear();
        self.steps = 0;
        if scored.is_empty() {
            self.cut = None;
            return false;
        }
        if scored.len() > self.width {
            // Descending by rank; the element left at `width - 1` is the cut.
            scored.select_nth_unstable_by(self.width - 1, |a, b| b.cmp(a));
            self.cut = Some(scored[self.width - 1]);
            scored.truncate(self.width);
        } else {
            self.cut = None;
        }
        // Slot order follows test id so the layout does not depend on selection internals.
        scored.sort_unstable_by_key(|e| e.test);
        self.top = scored.iter().map(|e| e.score).fold(0.0, f64::max);
        for (slot, e) in scored.iter().enumerate() {
            self.test.push(e.test);
            self.score.push(e.score);
            let w = 1.0 / f64::from(pl.cost[e.test as usize]);
            for k in pl.span(e.test as usize) {
                self.by_unit[pl.unit[k] as usize].push((slot as u32, pl.detect[k] * w));
            }
        }
        true
    }

    /// Half-width of the band below the approximate maximum that must be
    /// re-scored exactly: each slot has taken at most `max_notices` deltas per
    /// step since the cut, each good to a few ulps of the largest score.
    fn band(&self, max: f64) -> f64 {
        let ulps = 8.0 * f64::EPSILON * (self.top + max.abs());
        ulps * (self.steps as f64 * self.max_notices as f64 + 2.0)
    }

    /// The best test in the window by exact score, with its slot. Candidates
    /// are every slot whose approximate score is within `band` of the maximum.
    fn pick(&mut self, pl: &Planner, belief: &[f64], dead: &mut [bool]) -> Option<(Entry, usize)> {
        loop {
            // Two flat passes over a few hundred KB beat any bookkeeping: the
            // deltas land on scattered slots, so a block-wise maximum would
            // have to be re-derived for almost every block each step anyway.
            let max = self.score.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            if max == f64::NEG_INFINITY {
                return None;
            }
            let floor = max - self.band(max);
            let mut best: Option<(Entry, usize)> = None;
            let mut killed = false;
            for slot in 0..self.score.len() {
                if self.score[slot] < floor {
                    continue;
                }
                let t = self.test[slot] as usize;
                let removed = pl.removed(belief, t);
                if removed <= 0.0 {
                    dead[t] = true;
                    self.score[slot] = f64::NEG_INFINITY;
                    killed = true;
                    continue;
                }
                let score = removed / f64::from(pl.cost[t]);
                self.score[slot] = score;
                let e = Entry { removed, score, test: t as u32 };
                if best.is_none_or(|(c, _)| e > c) {
                    best = Some((e, slot));
                }
            }
            // A retired candidate may have been the maximum the band was cut around.
            if !killed && best.is_some() {
                return best;
            }
        }
    }
    fn retire(&mut self, slot: usize) {
        self.score[slot] = f64::NEG_INFINITY;
        self.steps += 1;
    }

    /// Unit `a`'s belief fell by `delta`.
    fn lower(&mut self, a: usize, delta: f64) {
        if delta == 0.0 {
            return;
        }
        for &(slot, w) in &self.by_unit[a] {
            self.score[slot as usize] -= delta * w;
        }
    }
}
