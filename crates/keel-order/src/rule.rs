//! The bundle rule: what a free worker starts next.
//!
//! A *group* is a set of probes that need the same builds and world. Probes
//! behind a gate probe form the gate's own group, which exists only once the
//! gate has passed. The rule keeps one heap of groups keyed by the density of
//! their best bundle; the probes inside a group are ordered by a lazy greedy of
//! their own.

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

use crate::inputs::{DoubtInputs, Id, NONE, StepIx};
use crate::order::Order;

// Step states.
const COLD: u8 = 0;
const COMING: u8 = 1;
const UP: u8 = 2;
const FAILED: u8 = 3;

// Group states. A group has a heap entry only while it is `G_ACTIVE`.
const G_ACTIVE: u8 = 0;
/// Positive density, but a step of its builds is being set up.
const G_HELD: u8 = 1;
/// A child group whose gate is running.
const G_PENDING: u8 = 2;
/// A child group whose gate has not started; its probes are priced inside the
/// gate's bundle.
const G_LATENT: u8 = 3;
/// No probe left can detect anything.
const G_EMPTY: u8 = 4;
/// Its builds or its gate failed.
const G_DEAD: u8 = 5;

/// What a free worker should start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pick {
    /// Bring this step up (build, link, boot). The step counts as coming up
    /// from this call on; report [`Rule::up`] or [`Rule::failed_setup`] when it
    /// is settled. A gate probe is never a `SetUp`: it is a `Run`.
    SetUp(StepIx),
    /// Run this probe. It counts as done from this call on, so that no other
    /// worker duplicates what it will detect. A gate probe is reported through
    /// `up` when it passes and `failed_setup` when it does not.
    Run(Id),
    /// Probes remain but none can start until a step that is coming up
    /// settles. Ask again after the next `up` or `failed_setup`.
    Idle,
    /// Every probe has been started or stranded.
    Finished,
}

/// A probe in a probe heap: its density (an upper bound while stale) and its
/// number. Twelve bytes, because a hundred thousand of them are the bulk of the
/// rule's state; the reach that breaks ties is read from the inputs by number.
#[derive(Clone, Copy, Debug)]
struct UEnt {
    hi: u32,
    lo: u32,
    id: u32,
}

impl UEnt {
    fn new(d: f64, id: u32) -> UEnt {
        let b = d.to_bits();
        UEnt {
            hi: (b >> 32) as u32,
            lo: b as u32,
            id,
        }
    }
    fn d(self) -> f64 {
        f64::from_bits(u64::from(self.hi) << 32 | u64::from(self.lo))
    }
}

/// `a` ranks above `b`: greater density, then smaller reach, then smaller id.
fn above(a: UEnt, b: UEnt, reach: &[u32]) -> bool {
    a.d()
        .total_cmp(&b.d())
        .then_with(|| reach[b.id as usize].cmp(&reach[a.id as usize]))
        .then_with(|| b.id.cmp(&a.id))
        == Ordering::Greater
}

/// A max-heap of probes under [`above`]. `std`'s heap cannot look the reach up
/// by number, so this is the textbook array heap with the comparison given the table.
#[derive(Default)]
struct UHeap(Vec<UEnt>);

impl UHeap {
    fn from_vec(v: Vec<UEnt>, reach: &[u32]) -> UHeap {
        let mut h = UHeap(v);
        for i in (0..h.0.len() / 2).rev() {
            h.sift_down(i, reach);
        }
        h
    }

    fn peek(&self) -> Option<UEnt> {
        self.0.first().copied()
    }

    fn push(&mut self, e: UEnt, reach: &[u32]) {
        self.0.push(e);
        let mut i = self.0.len() - 1;
        while i > 0 {
            let p = (i - 1) / 2;
            if !above(self.0[i], self.0[p], reach) {
                break;
            }
            self.0.swap(i, p);
            i = p;
        }
    }

    fn pop(&mut self, reach: &[u32]) -> Option<UEnt> {
        let last = self.0.pop()?;
        if self.0.is_empty() {
            return Some(last);
        }
        let top = std::mem::replace(&mut self.0[0], last);
        self.sift_down(0, reach);
        Some(top)
    }

    fn sift_down(&mut self, mut i: usize, reach: &[u32]) {
        let n = self.0.len();
        loop {
            let l = 2 * i + 1;
            if l >= n {
                return;
            }
            let m = if l + 1 < n && above(self.0[l + 1], self.0[l], reach) {
                l + 1
            } else {
                l
            };
            if !above(self.0[m], self.0[i], reach) {
                return;
            }
            self.0.swap(i, m);
            i = m;
        }
    }
}

/// A group in the heap. `epoch` says which state of the miss masses the
/// density was computed under: an entry from an earlier epoch is an upper bound.
#[derive(Clone, Copy, Debug)]
struct GEnt {
    d: f64,
    reach: u32,
    id: u32,
    gid: u32,
    ver: u32,
    epoch: u64,
}

impl PartialEq for GEnt {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}
impl Eq for GEnt {}
impl PartialOrd for GEnt {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for GEnt {
    fn cmp(&self, o: &Self) -> Ordering {
        self.d
            .total_cmp(&o.d)
            .then_with(|| o.reach.cmp(&self.reach))
            .then_with(|| o.id.cmp(&self.id))
            .then_with(|| o.gid.cmp(&self.gid))
            .then_with(|| self.epoch.cmp(&o.epoch))
            .then_with(|| self.ver.cmp(&o.ver))
    }
}

#[derive(Clone, Debug, Default)]
struct Bits(Vec<u64>);

impl Bits {
    fn new(n: usize) -> Bits {
        Bits(vec![0; n.div_ceil(64)])
    }
    #[inline]
    fn get(&self, i: u32) -> bool {
        self.0[(i >> 6) as usize] >> (i & 63) & 1 == 1
    }
    #[inline]
    fn set(&mut self, i: u32) {
        self.0[(i >> 6) as usize] |= 1 << (i & 63);
    }
}

/// The probes that detect nothing any more, which a required surface must
/// still run: ready ones first, cheapest first. A probe is named here by its
/// place in `order`, so that a heap entry is 4 bytes.
struct Tail {
    /// The probes still to run, by cost, then reach, then number.
    order: Vec<u32>,
    ready: BinaryHeap<Reverse<u32>>,
    /// Per step, the places of the probes whose first unfinished step it is.
    park: Vec<Vec<u32>>,
    /// Per step, the least place among its parked probes (or `NONE`).
    least: Vec<u32>,
    /// Cold build steps with a probe waiting for them, as (place of the cheapest, step).
    cands: BinaryHeap<Reverse<(u32, u32)>>,
}

/// The rule, in motion. See the crate documentation for what it promises.
///
/// It borrows the inputs: the kill table of a large change is megabytes and
/// the executor already holds it, so the rule's own state is a few bytes per
/// class, step and probe on top.
pub struct Rule<'a> {
    inp: &'a DoubtInputs,
    /// Miss mass per class: the chance mass not yet covered by probes started.
    miss: Vec<f32>,
    /// `miss` plus the tentative picks of the bundle being priced; equal to
    /// `miss` whenever no pricing is in progress.
    tent: Vec<f32>,
    undo: Vec<(u32, f32)>,
    done: Bits,
    strand_bit: Bits,
    stranded: Vec<Id>,
    remaining: u32,
    step_state: Vec<u8>,
    /// Order in which a probe's unfinished steps are started: builds by number,
    /// then gates from the outermost in.
    step_rank: Vec<u32>,
    gate_unit_of_step: Vec<u32>,
    // Groups: the roots first (by their builds), then one per gate that has probes behind it.
    base_off: Vec<u32>,
    base: Vec<u32>,
    live_off: Vec<u32>,
    live_len: Vec<u32>,
    live: Vec<u32>,
    g_state: Vec<u8>,
    g_ver: Vec<u32>,
    g_warm: Vec<Option<UHeap>>,
    /// Root groups by build step, as a Csr.
    sg_off: Vec<u32>,
    sg: Vec<u32>,
    /// `(gate probe, its child group)`, ascending.
    child_of: Vec<(u32, u32)>,
    heap: BinaryHeap<GEnt>,
    epoch: u64,
    /// Groups with positive density that cannot start yet.
    n_wait: u32,
    tail: Option<Tail>,
    evals: u64,
    pool: Vec<Vec<UEnt>>,
    plan: Vec<u32>,
    /// Running totals of the outermost cold bundle being priced (§4.8); `(0, 0)` at rest.
    ctx: (f64, f64),
    /// The largest scratch buffer a bundle evaluation has held, in bytes, including those given back and freed.
    peak_scratch: usize,
}

impl<'a> Rule<'a> {
    /// Starts a run over `inputs` with the steps in `already_up` ready.
    ///
    /// # Panics
    /// If the inputs fail [`DoubtInputs::validate`], or a step in `already_up`
    /// is not below `inputs.steps`. The message says which; an executor that
    /// prefers to refuse the file calls `validate` first.
    pub fn new(inputs: &'a DoubtInputs, already_up: &[StepIx]) -> Rule<'a> {
        let gates = inputs
            .analyse()
            .unwrap_or_else(|e| panic!("keel-order: these inputs cannot be ordered: {e}"));
        let (n, s) = (inputs.units as usize, inputs.steps as usize);
        let mut step_state = vec![COLD; s];
        for &x in already_up {
            assert!(
                x < inputs.steps,
                "keel-order: `already_up` names step {x} but the inputs have {} steps; pass the steps of this plan only",
                inputs.steps
            );
            step_state[x as usize] = UP;
        }

        let is_gate_step = |x: u32| gates.gate_unit_of_step[x as usize] != NONE;
        // A gate step's depth is how many gates its probe waits for.
        let mut step_rank: Vec<u32> = (0..inputs.steps).collect();
        for x in 0..inputs.steps {
            let g = gates.gate_unit_of_step[x as usize];
            if g != NONE {
                let depth = inputs
                    .needs
                    .row(g as usize)
                    .iter()
                    .filter(|&&y| is_gate_step(y))
                    .count();
                step_rank[x as usize] = 0x8000_0000 + depth as u32;
            }
        }

        // The builds of each probe, sorted, and the roots grouped by them.
        let mut base_rows: Vec<Vec<u32>> = Vec::new();
        let mut base_of = vec![u32::MAX; n];
        let mut roots: Vec<u32> = Vec::new();
        let mut children: Vec<u32> = Vec::new();
        for u in 0..n as u32 {
            if gates.parent[u as usize] == NONE {
                roots.push(u);
                let mut b: Vec<u32> = inputs
                    .needs
                    .row(u as usize)
                    .iter()
                    .copied()
                    .filter(|&x| !is_gate_step(x))
                    .collect();
                b.sort_unstable();
                b.dedup();
                base_of[u as usize] = base_rows.len() as u32;
                base_rows.push(b);
            } else {
                children.push(u);
            }
        }
        roots.sort_by(|&a, &b| {
            base_rows[base_of[a as usize] as usize]
                .cmp(&base_rows[base_of[b as usize] as usize])
                .then(a.cmp(&b))
        });
        children.sort_by_key(|&u| (gates.parent[u as usize], u));

        let mut rule = Rule {
            inp: inputs,
            miss: inputs.class_mass.clone(),
            tent: inputs.class_mass.clone(),
            undo: Vec::new(),
            done: Bits::new(n),
            strand_bit: Bits::new(n),
            stranded: Vec::new(),
            remaining: inputs.units,
            step_state,
            step_rank,
            gate_unit_of_step: gates.gate_unit_of_step.clone(),
            base_off: vec![0],
            base: Vec::new(),
            live_off: vec![0],
            live_len: Vec::new(),
            live: Vec::with_capacity(n),
            g_state: Vec::new(),
            g_ver: Vec::new(),
            g_warm: Vec::new(),
            sg_off: Vec::new(),
            sg: Vec::new(),
            child_of: Vec::new(),
            heap: BinaryHeap::new(),
            epoch: 0,
            n_wait: 0,
            tail: None,
            evals: 0,
            pool: Vec::new(),
            plan: Vec::new(),
            ctx: (0.0, 0.0),
            peak_scratch: 0,
        };

        // Root groups.
        let mut i = 0;
        while i < roots.len() {
            let key = &base_rows[base_of[roots[i] as usize] as usize];
            let mut j = i;
            while j < roots.len() && &base_rows[base_of[roots[j] as usize] as usize] == key {
                j += 1;
            }
            rule.base.extend_from_slice(key);
            rule.base_off.push(rule.base.len() as u32);
            rule.live.extend_from_slice(&roots[i..j]);
            rule.live_off.push(rule.live.len() as u32);
            rule.live_len.push((j - i) as u32);
            i = j;
        }
        let n_roots = rule.live_len.len();
        // Child groups, one per gate that has probes behind it.
        let mut i = 0;
        while i < children.len() {
            let gate = gates.parent[children[i] as usize];
            let mut j = i;
            while j < children.len() && gates.parent[children[j] as usize] == gate {
                j += 1;
            }
            rule.child_of.push((gate, rule.live_len.len() as u32));
            rule.base_off.push(rule.base.len() as u32);
            rule.live.extend_from_slice(&children[i..j]);
            rule.live_off.push(rule.live.len() as u32);
            rule.live_len.push((j - i) as u32);
            i = j;
        }
        let groups = rule.live_len.len();
        rule.g_state = vec![G_LATENT; groups];
        rule.g_ver = vec![0; groups];
        rule.g_warm = (0..groups).map(|_| None).collect();

        // Root groups by build step.
        let mut counts = vec![0u32; s + 1];
        for g in 0..n_roots {
            for &x in &rule.base[rule.base_off[g] as usize..rule.base_off[g + 1] as usize] {
                counts[x as usize + 1] += 1;
            }
        }
        for x in 0..s {
            counts[x + 1] += counts[x];
        }
        let mut fill = counts.clone();
        rule.sg = vec![0; counts[s] as usize];
        for g in 0..n_roots {
            for k in rule.base_off[g] as usize..rule.base_off[g + 1] as usize {
                let x = rule.base[k] as usize;
                rule.sg[fill[x] as usize] = g as u32;
                fill[x] += 1;
            }
        }
        rule.sg_off = counts;

        for g in 0..n_roots {
            rule.activate(g);
        }
        for k in 0..rule.child_of.len() {
            let (gate, cg) = rule.child_of[k];
            if let Some(x) = inputs.gate_step(gate)
                && rule.step_state[x as usize] == UP
            {
                rule.activate(cg as usize);
            }
        }
        rule
    }

    /// A worker is free: what should it start? `Run` and `SetUp` are committed
    /// by this call: the probe counts as done, the step as coming up.
    ///
    /// While any group of probes that can still detect something is waiting for
    /// a step to come up, the answer is `Idle` rather than a probe that detects
    /// nothing: the worker is better left free for the group that is about to
    /// become startable.
    // The name is the executor contract (`next()` where the scheduler dequeues); this is not an iterator, it also
    // answers `Idle` and goes on after it.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Pick {
        if self.remaining == 0 {
            return Pick::Finished;
        }
        if let Some(top) = self.select_group() {
            let g = top.gid as usize;
            if let Some(x) = self.first_cold_base(g) {
                self.set_coming(x);
                return Pick::SetUp(x);
            }
            self.dispatch(top.id);
            // The group's best is now at most what it was: keep the old entry as a bound.
            self.heap.push(top);
            return Pick::Run(top.id);
        }
        if self.n_wait > 0 {
            return Pick::Idle;
        }
        self.tail_next()
    }

    /// A step finished coming up (for a gate probe: it passed). Its probes may
    /// now be picked.
    ///
    /// Reporting a step that is already up, or one that failed, does nothing.
    ///
    /// # Panics
    /// If `step` is not below the inputs' step count.
    pub fn up(&mut self, step: StepIx) {
        self.check_step(step, "up");
        if matches!(self.step_state[step as usize], UP | FAILED) {
            return;
        }
        self.step_state[step as usize] = UP;
        let gate = self.gate_unit_of_step[step as usize];
        if gate != NONE
            && let Some(cg) = self.child_group(gate)
        {
            match self.g_state[cg] {
                G_PENDING => {
                    self.n_wait -= 1;
                    self.activate(cg);
                }
                G_LATENT => self.activate(cg),
                _ => {}
            }
        }
        let (lo, hi) = (
            self.sg_off[step as usize] as usize,
            self.sg_off[step as usize + 1] as usize,
        );
        for k in lo..hi {
            let g = self.sg[k] as usize;
            match self.g_state[g] {
                G_HELD => {
                    if !self
                        .base_of(g)
                        .iter()
                        .any(|&x| self.step_state[x as usize] == COMING)
                    {
                        self.n_wait -= 1;
                        self.activate(g);
                    }
                }
                // Its set-up cost just fell, so its stale entry is no longer a bound.
                G_ACTIVE => self.activate(g),
                _ => {}
            }
        }
        if self.tail.is_some() {
            self.tail_on_up(step);
        }
    }

    /// A step failed to come up (for a gate probe: it failed). Every probe that
    /// needs it, directly or through a gate, is listed by [`stranded`] and is
    /// never picked.
    ///
    /// The executor writes a `Blocked { by: step }` record for each stranded
    /// probe; without it the settle stage would report a missing result.
    ///
    /// Reporting a step that already failed does nothing.
    ///
    /// [`stranded`]: Rule::stranded
    ///
    /// # Panics
    /// If `step` is not below the inputs' step count.
    pub fn failed_setup(&mut self, step: StepIx) {
        self.check_step(step, "failed_setup");
        if self.step_state[step as usize] == FAILED {
            return;
        }
        self.step_state[step as usize] = FAILED;
        let (lo, hi) = (
            self.sg_off[step as usize] as usize,
            self.sg_off[step as usize + 1] as usize,
        );
        for k in lo..hi {
            self.kill(self.sg[k] as usize);
        }
        let gate = self.gate_unit_of_step[step as usize];
        if gate != NONE
            && let Some(cg) = self.child_group(gate)
        {
            self.kill(cg);
        }
        // A probe that needs a failed step cannot start; so cannot anything behind it,
        // and every probe behind a gate lists the steps of all the gates above it.
        let mut newly = Vec::new();
        for u in 0..self.inp.units {
            if self.done.get(u) || self.strand_bit.get(u) {
                continue;
            }
            if self
                .inp
                .needs
                .row(u as usize)
                .iter()
                .any(|&x| self.step_state[x as usize] == FAILED)
            {
                self.strand_bit.set(u);
                newly.push(u);
            }
        }
        for &u in &newly {
            if let Some(x) = self.inp.gate_step(u) {
                self.step_state[x as usize] = FAILED;
                if let Some(cg) = self.child_group(u) {
                    self.kill(cg);
                }
            }
        }
        self.remaining -= newly.len() as u32;
        self.stranded.extend_from_slice(&newly);
    }

    /// The probes that can never start because a step they need failed, in the
    /// order they were stranded (ascending within one `failed_setup` call).
    pub fn stranded(&self) -> &[Id] {
        &self.stranded
    }

    fn check_step(&self, step: StepIx, call: &str) {
        assert!(
            step < self.inp.steps,
            "keel-order: `{call}` was given step {step} but the inputs have {} steps; report only steps this plan listed",
            self.inp.steps
        );
    }

    // ---- the state the pricing reads and writes -------------------------------------------

    #[inline]
    fn base_of(&self, g: usize) -> &[u32] {
        &self.base[self.base_off[g] as usize..self.base_off[g + 1] as usize]
    }

    fn child_group(&self, gate: u32) -> Option<usize> {
        self.child_of
            .binary_search_by_key(&gate, |p| p.0)
            .ok()
            .map(|i| self.child_of[i].1 as usize)
    }

    /// A gate probe that has not started and whose step is not up: its bundle
    /// is itself plus the best prefix of the probes behind it.
    fn is_cold_gate(&self, u: u32) -> bool {
        self.inp
            .gate_step(u)
            .is_some_and(|x| self.step_state[x as usize] == COLD && !self.done.get(u))
    }

    fn first_cold_base(&self, g: usize) -> Option<StepIx> {
        self.base_of(g)
            .iter()
            .copied()
            .find(|&x| self.step_state[x as usize] != UP)
    }

    /// The detection gain of probe `u` under the tentative masses: the sum over
    /// its classes, in class order, of miss mass times kill probability.
    fn tent_gain(&self, u: u32) -> f64 {
        let mut g = 0.0f64;
        for &(c, q) in self.inp.kills.row(u as usize) {
            g += f64::from(self.tent[c as usize]) * f64::from(q);
        }
        g
    }

    /// Tentatively counts probe `u` as run, remembering how to undo it.
    fn apply(&mut self, u: u32) {
        for &(c, q) in self.inp.kills.row(u as usize) {
            let old = self.tent[c as usize];
            self.undo.push((c, old));
            self.tent[c as usize] = (f64::from(old) * (1.0 - f64::from(q))) as f32;
        }
    }

    fn rollback(&mut self, mark: usize) {
        while self.undo.len() > mark {
            let (c, old) = self.undo.pop().expect("length checked");
            self.tent[c as usize] = old;
        }
    }

    /// Makes probe `u`'s run real: it is done and its classes are covered.
    fn dispatch(&mut self, u: u32) {
        debug_assert!(!self.done.get(u) && self.undo.is_empty());
        self.done.set(u);
        self.remaining -= 1;
        for &(c, q) in self.inp.kills.row(u as usize) {
            let m = (f64::from(self.miss[c as usize]) * (1.0 - f64::from(q))) as f32;
            self.miss[c as usize] = m;
            self.tent[c as usize] = m;
        }
        self.epoch += 1;
        if let Some(x) = self.inp.gate_step(u)
            && self.step_state[x as usize] == COLD
        {
            self.step_state[x as usize] = COMING;
            if let Some(cg) = self.child_group(u)
                && self.g_state[cg] == G_LATENT
            {
                // Its probes wait for the pass; they count as positive only if something is left to detect.
                if self.eval_group(cg).is_some() {
                    self.g_state[cg] = G_PENDING;
                    self.n_wait += 1;
                } else {
                    self.g_state[cg] = G_EMPTY;
                }
            }
        }
    }

    /// A build step is being set up: every group waiting for it leaves the running.
    fn set_coming(&mut self, x: StepIx) {
        self.step_state[x as usize] = COMING;
        let (lo, hi) = (
            self.sg_off[x as usize] as usize,
            self.sg_off[x as usize + 1] as usize,
        );
        for k in lo..hi {
            let g = self.sg[k] as usize;
            if self.g_state[g] == G_ACTIVE {
                self.g_state[g] = G_HELD;
                self.g_ver[g] += 1;
                self.n_wait += 1;
            }
        }
    }

    fn kill(&mut self, g: usize) {
        if matches!(self.g_state[g], G_HELD | G_PENDING) {
            self.n_wait -= 1;
        }
        self.g_state[g] = G_DEAD;
        self.g_ver[g] += 1;
    }

    // ---- pricing --------------------------------------------------------------------------

    /// Drops from group `g` the probes that are done and those that can no
    /// longer detect anything. Gains only fall, so a probe dropped here is
    /// never wanted by the bundle again; the tail finds it by itself.
    fn compact(&mut self, g: usize) -> u32 {
        let off = self.live_off[g] as usize;
        let len = self.live_len[g] as usize;
        let mut w = 0;
        for i in 0..len {
            let u = self.live[off + i];
            if self.done.get(u) || self.strand_bit.get(u) {
                continue;
            }
            let keep = self.tent_gain(u) > 0.0
                || (self.is_cold_gate(u)
                    && self.child_group(u).is_some_and(|cg| self.compact(cg) > 0));
            if keep {
                self.live[off + w] = u;
                w += 1;
            }
        }
        self.live_len[g] = w as u32;
        w as u32
    }

    /// The key probe `u` is ordered by inside a bundle (§4.8, point 2), under the
    /// tentative masses; zero if it offers nothing. For a probe, gain over cost.
    /// For a cold gate, the greatest value over `k` of the gain of the gate and its
    /// first `k` children over their own costs: its own bundle, with no enclosing
    /// totals (`ctx` is `(0, 0)` here whatever bundle it is being ordered in), so
    /// that rich twins are not hidden behind a poor plain cell. How far the order
    /// is followed, and how many children the gate brings, is cut by the enclosing
    /// quotient, not by this key.
    fn key(&mut self, u: u32) -> f64 {
        if !self.is_cold_gate(u) {
            return self.tent_gain(u) / self.inp.cost(u);
        }
        let saved = std::mem::replace(&mut self.ctx, (0.0, 0.0));
        let mark = self.undo.len();
        let mut scratch = Vec::new();
        let (g, c) = self.take_item(u, &mut scratch);
        self.rollback(mark);
        self.ctx = saved;
        if g > 0.0 { g / c } else { 0.0 }
    }

    /// Adds probe `u`, as an item, to the tentative picks, and returns its gain
    /// and cost. A cold gate is taken with the best prefix of what waits behind it.
    fn take_item(&mut self, u: u32, picks: &mut Vec<u32>) -> (f64, f64) {
        let c = self.inp.cost(u);
        let g = self.tent_gain(u);
        self.apply(u);
        picks.push(u);
        if self.is_cold_gate(u)
            && let Some(cg) = self.child_group(u)
        {
            return self.greedy(cg, g, c, picks);
        }
        (g, c)
    }

    fn take_buf(&mut self) -> Vec<UEnt> {
        self.pool.pop().unwrap_or_default()
    }

    fn give_buf(&mut self, mut buf: Vec<UEnt>) {
        self.peak_scratch = self
            .peak_scratch
            .max(buf.capacity() * std::mem::size_of::<UEnt>());
        buf.clear();
        if buf.capacity() <= 1 << 16 {
            self.pool.push(buf);
        }
    }

    /// Lazy density-greedy over the probes of group `g`, starting from a bundle
    /// that already holds gain `g0` at cost `c0`. Leaves the tentative masses
    /// and `picks` at the prefix of greatest gain over cost and returns that
    /// prefix's gain and cost.
    ///
    /// Items are *ordered* by `key` (a probe: gain over cost; a gate: its own bundle,
    /// with no enclosing totals) and *cut* by the quotient below.
    ///
    /// "Greatest gain over cost" is judged for the outermost cold bundle that
    /// contains this one (§4.8, "How a nested bundle is priced"): `self.ctx` holds
    /// the running totals `(G, C)` of everything already in that bundle, set-ups
    /// included, and the quotient maximised, and the early stop compared against,
    /// is `(G + g) / (C + c)`. A gate's children are chosen under the totals that
    /// include the gate and everything the enclosing bundle took before it, and a
    /// child that is itself a gate passes those totals, with itself added, to its
    /// own children, so the same quotient is used at every depth. With nothing
    /// enclosing cold, `ctx` is `(0, 0)` and this is the gate's own bundle.
    fn greedy(&mut self, g: usize, g0: f64, c0: f64, picks: &mut Vec<u32>) -> (f64, f64) {
        let reach: &'a [u32] = &self.inp.reach;
        let off = self.live_off[g] as usize;
        let len = self.live_len[g] as usize;
        let (xg, xc) = self.ctx;
        let mut buf = self.take_buf();
        for i in 0..len {
            let u = self.live[off + i];
            if self.done.get(u) {
                continue;
            }
            let d = self.key(u);
            if d > 0.0 {
                buf.push(UEnt::new(d, u));
            }
        }
        let mut heap = UHeap::from_vec(buf, reach);
        let (mut g_sum, mut c_sum) = (g0, c0);
        let mut best = if xg + g0 > 0.0 && xc + c0 > 0.0 {
            (xg + g0) / (xc + c0)
        } else {
            0.0
        };
        let (mut best_picks, mut best_undo) = (picks.len(), self.undo.len());
        let (mut best_g, mut best_c) = (g0, c0);
        while let Some(top) = heap.pop(reach) {
            // Every density still in the heap is at most this one, now and later, and a
            // probe no denser than the bundle can only dilute it.
            if xg + g_sum > 0.0 && top.d() <= (xg + g_sum) / (xc + c_sum) {
                break;
            }
            // Refresh the ordering key, which does not depend on the bundle, and accept the item
            // only if it is greater on the whole key than the next (possibly stale) entry.
            let fresh = self.key(top.id);
            if fresh <= 0.0 {
                continue;
            }
            let cand = UEnt::new(fresh, top.id);
            if heap.peek().is_some_and(|nx| above(nx, cand, reach)) {
                heap.push(cand, reach);
                continue;
            }
            // Taken: a gate brings the children the enclosing quotient cuts.
            let mark = (picks.len(), self.undo.len());
            self.ctx = (xg + g_sum, xc + c_sum);
            let (gain, cost) = self.take_item(top.id, picks);
            self.ctx = (xg, xc);
            if gain <= 0.0 {
                self.rollback(mark.1);
                picks.truncate(mark.0);
                continue;
            }
            g_sum += gain;
            c_sum += cost;
            if (xg + g_sum) / (xc + c_sum) > best {
                best = (xg + g_sum) / (xc + c_sum);
                best_picks = picks.len();
                best_undo = self.undo.len();
                best_g = g_sum;
                best_c = c_sum;
            }
        }
        self.ctx = (xg, xc);
        self.rollback(best_undo);
        picks.truncate(best_picks);
        self.give_buf(heap.0);
        (best_g, best_c)
    }

    /// The best single item of a group with nothing cold, by a heap that lives
    /// as long as the group does.
    fn eval_warm(&mut self, g: usize) -> Option<(f64, u32)> {
        let reach: &'a [u32] = &self.inp.reach;
        if self.g_warm[g].is_none() {
            self.compact(g);
            let off = self.live_off[g] as usize;
            let len = self.live_len[g] as usize;
            let mut v: Vec<UEnt> = Vec::new();
            v.reserve_exact(len);
            for i in 0..len {
                let u = self.live[off + i];
                let d = self.key(u);
                if d > 0.0 {
                    v.push(UEnt::new(d, u));
                }
            }
            v.shrink_to_fit();
            self.g_warm[g] = Some(UHeap::from_vec(v, reach));
            // The heap holds the group from here on.
            self.live_len[g] = 0;
        }
        let mut heap = self.g_warm[g].take().expect("built above");
        let res = loop {
            let Some(top) = heap.pop(reach) else {
                break None;
            };
            if self.done.get(top.id) || self.strand_bit.get(top.id) {
                continue;
            }
            let d = self.key(top.id);
            if d <= 0.0 {
                continue;
            }
            let fresh = UEnt::new(d, top.id);
            let beaten = heap.peek().is_some_and(|nx| above(nx, fresh, reach));
            heap.push(fresh, reach);
            if !beaten {
                break Some((d, top.id));
            }
        };
        self.g_warm[g] = Some(heap);
        res
    }

    /// The density of group `g`'s best bundle and the probe it would start with,
    /// under the current masses and steps; `None` if it can detect nothing.
    fn eval_group(&mut self, g: usize) -> Option<(f64, u32)> {
        self.evals += 1;
        let mut set_up = 0.0;
        let mut cold = false;
        for k in self.base_off[g] as usize..self.base_off[g + 1] as usize {
            let x = self.base[k];
            if self.step_state[x as usize] != UP {
                cold = true;
                set_up += self.inp.setup_ms[x as usize].millis();
            }
        }
        if !cold {
            return self.eval_warm(g);
        }
        self.compact(g);
        let mut picks = std::mem::take(&mut self.plan);
        picks.clear();
        let (gain, cost) = self.greedy(g, 0.0, set_up, &mut picks);
        self.rollback(0);
        let res = picks.first().map(|&u| (gain / cost, u));
        self.plan = picks;
        res
    }

    /// Prices group `g` and puts it in the heap, or retires it if it detects nothing.
    fn activate(&mut self, g: usize) {
        self.g_ver[g] += 1;
        match self.eval_group(g) {
            Some((d, first)) => {
                self.g_state[g] = G_ACTIVE;
                self.heap.push(GEnt {
                    d,
                    reach: self.inp.reach[first as usize],
                    id: first,
                    gid: g as u32,
                    ver: self.g_ver[g],
                    epoch: self.epoch,
                });
            }
            None => self.g_state[g] = G_EMPTY,
        }
    }

    fn entry_is_live(&self, e: &GEnt) -> bool {
        e.ver == self.g_ver[e.gid as usize] && self.g_state[e.gid as usize] == G_ACTIVE
    }

    /// Takes the group of greatest density out of the heap. Its entry is exact
    /// for the current masses and no other group can beat it; the group stays
    /// `G_ACTIVE` without an entry and the caller decides what happens to it.
    fn select_group(&mut self) -> Option<GEnt> {
        loop {
            let top = self.heap.pop()?;
            if !self.entry_is_live(&top) {
                continue;
            }
            if top.epoch != self.epoch {
                self.activate(top.gid as usize);
                continue;
            }
            while self.heap.peek().is_some_and(|nx| !self.entry_is_live(nx)) {
                self.heap.pop();
            }
            // A stale rival whose bound ties or beats the top may still beat it on
            // its real density or its tie-break, so it is priced before the top is taken.
            if let Some(nx) = self.heap.peek().copied()
                && nx.epoch != self.epoch
                && nx.d.total_cmp(&top.d) != Ordering::Less
            {
                self.heap.pop();
                self.heap.push(top);
                self.activate(nx.gid as usize);
                continue;
            }
            return Some(top);
        }
    }

    // ---- the zero-gain tail ---------------------------------------------------------------

    /// The first step probe `u` still waits for, or `None` if it can start.
    fn first_unready(&self, u: u32) -> Option<StepIx> {
        self.inp
            .needs
            .row(u as usize)
            .iter()
            .copied()
            .filter(|&x| self.step_state[x as usize] != UP)
            .min_by_key(|&x| (self.step_rank[x as usize], x))
    }

    fn tail_place(&mut self, place: u32) {
        let u = self.tail.as_ref().expect("tail exists").order[place as usize];
        let waiting = self.first_unready(u);
        let build_cold = |x: StepIx| {
            self.step_state[x as usize] == COLD && self.gate_unit_of_step[x as usize] == NONE
        };
        let cold = waiting.is_some_and(build_cold);
        let tail = self.tail.as_mut().expect("tail exists");
        match waiting {
            None => tail.ready.push(Reverse(place)),
            Some(x) => {
                tail.park[x as usize].push(place);
                if cold && place < tail.least[x as usize] {
                    tail.least[x as usize] = place;
                    tail.cands.push(Reverse((place, x)));
                }
            }
        }
    }

    fn tail_on_up(&mut self, x: StepIx) {
        let parked = std::mem::take(&mut self.tail.as_mut().expect("tail exists").park[x as usize]);
        for place in parked {
            let u = self.tail.as_ref().expect("tail exists").order[place as usize];
            if !self.done.get(u) && !self.strand_bit.get(u) {
                self.tail_place(place);
            }
        }
    }

    /// Probes that detect nothing any more still have to run. Ready ones go
    /// first, cheapest first; when none is ready, the step that unblocks the
    /// cheapest waiting probe comes up.
    fn tail_next(&mut self) -> Pick {
        if self.tail.is_none() {
            // The main heaps are spent; give their memory back before the tail takes its own.
            self.g_warm.iter_mut().for_each(|w| *w = None);
            self.live = Vec::new();
            self.live_len.iter_mut().for_each(|l| *l = 0);
            let inp = self.inp;
            let mut order: Vec<u32> = (0..inp.units)
                .filter(|&u| !self.done.get(u) && !self.strand_bit.get(u))
                .collect();
            order.sort_unstable_by_key(|&u| (inp.cost(u).to_bits(), inp.reach[u as usize], u));
            let places = order.len() as u32;
            self.tail = Some(Tail {
                order,
                ready: BinaryHeap::new(),
                park: vec![Vec::new(); inp.steps as usize],
                least: vec![NONE; inp.steps as usize],
                cands: BinaryHeap::new(),
            });
            for place in 0..places {
                self.tail_place(place);
            }
        }
        while let Some(Reverse(place)) = self.tail.as_mut().expect("tail exists").ready.pop() {
            let u = self.tail.as_ref().expect("tail exists").order[place as usize];
            if self.done.get(u) || self.strand_bit.get(u) {
                continue;
            }
            self.dispatch(u);
            return Pick::Run(u);
        }
        while let Some(Reverse((place, x))) = self.tail.as_mut().expect("tail exists").cands.pop() {
            if self.step_state[x as usize] != COLD {
                continue;
            }
            let tail = self.tail.as_ref().expect("tail exists");
            let u = tail.order[place as usize];
            if self.done.get(u) || self.strand_bit.get(u) {
                // The cheapest waiting probe was stranded: the next cheapest takes its place.
                let next = tail.park[x as usize]
                    .iter()
                    .copied()
                    .filter(|&p| {
                        let v = tail.order[p as usize];
                        !self.done.get(v) && !self.strand_bit.get(v)
                    })
                    .min();
                let tail = self.tail.as_mut().expect("tail exists");
                tail.least[x as usize] = next.unwrap_or(NONE);
                if let Some(p) = next {
                    tail.cands.push(Reverse((p, x)));
                }
                continue;
            }
            self.set_coming(x);
            return Pick::SetUp(x);
        }
        if self.remaining == 0 {
            Pick::Finished
        } else {
            Pick::Idle
        }
    }

    // ---- the offline order ----------------------------------------------------------------

    /// The `Run` picks of this rule driven by one worker: every `SetUp` is
    /// followed at once by `up`, every gate probe passes. This is the
    /// definition of the offline order, not a second procedure.
    fn offline_drive(&mut self) -> Vec<u32> {
        let mut out = Vec::with_capacity(self.inp.units as usize);
        loop {
            match self.next() {
                Pick::SetUp(x) => self.up(x),
                Pick::Run(u) => {
                    out.push(u);
                    if let Some(x) = self.inp.gate_step(u) {
                        self.up(x);
                    }
                }
                // With one worker and every step coming up at once nothing is ever in flight.
                Pick::Idle | Pick::Finished => break,
            }
        }
        out
    }
}

/// The order one worker follows when every set-up succeeds at once and every
/// gate probe passes: the `Run` picks of the rule driven by one worker. This
/// is the order a plan prints and the order an executor without the rule
/// follows; it is the same sequence as the rule's own, by construction.
///
/// # Panics
/// If the inputs fail [`DoubtInputs::validate`].
pub fn offline(inputs: &DoubtInputs) -> Order {
    let mut rule = Rule::new(inputs, &[]);
    let seq = rule.offline_drive();
    let all: Vec<Id> = (0..inputs.units).collect();
    Order::new(&all, seq).expect("a lone worker driving the rule starts every probe exactly once")
}

#[cfg(test)]
impl Rule<'_> {
    pub(crate) fn evals(&self) -> u64 {
        self.evals
    }

    pub(crate) fn peak_scratch(&self) -> usize {
        self.peak_scratch
    }

    pub(crate) fn offline_for_test(&mut self) -> Vec<u32> {
        self.offline_drive()
    }

    /// Counts probe `u` as run without asking the rule, for properties that quantify over all pick sequences.
    pub(crate) fn force_run(&mut self, u: u32) {
        self.dispatch(u);
    }

    /// Bytes held by the rule's own tables and heaps, by capacity, borrowed
    /// inputs not counted.
    pub(crate) fn state_bytes(&self) -> usize {
        use std::mem::size_of;
        let heaps: usize = self
            .g_warm
            .iter()
            .flatten()
            .map(|h| h.0.capacity() * size_of::<UEnt>())
            .sum();
        let pool: usize = self
            .pool
            .iter()
            .map(|b| b.capacity() * size_of::<UEnt>())
            .sum();
        let tail = self.tail.as_ref().map_or(0, |t| {
            t.order.capacity() * 4
                + t.least.capacity() * 4
                + t.ready.capacity() * 4
                + t.cands.capacity() * 8
                + t.park
                    .iter()
                    .map(|p| p.capacity() * 4 + size_of::<Vec<u32>>())
                    .sum::<usize>()
        });
        self.miss.capacity() * 4
            + self.tent.capacity() * 4
            + self.undo.capacity() * 8
            + (self.done.0.capacity() + self.strand_bit.0.capacity()) * 8
            + self.stranded.capacity() * 4
            + self.step_state.capacity()
            + self.step_rank.capacity() * 4
            + self.gate_unit_of_step.capacity() * 4
            + (self.base_off.capacity() + self.base.capacity()) * 4
            + (self.live_off.capacity() + self.live_len.capacity() + self.live.capacity()) * 4
            + self.g_state.capacity()
            + self.g_ver.capacity() * 4
            + self.g_warm.capacity() * size_of::<Option<UHeap>>()
            + (self.sg_off.capacity() + self.sg.capacity()) * 4
            + self.child_of.capacity() * 8
            + self.heap.capacity() * size_of::<GEnt>()
            + self.plan.capacity() * 4
            + heaps
            + pool
            + tail
    }

    pub(crate) fn group_count(&self) -> usize {
        self.live_len.len()
    }

    pub(crate) fn group_has_step(&self, g: usize, x: StepIx) -> bool {
        self.base_of(g).contains(&x)
    }

    /// The density of group `g` as the rule prices it now (0 if it detects nothing).
    pub(crate) fn group_density(&mut self, g: usize) -> f64 {
        if self.g_state[g] == G_DEAD {
            return 0.0;
        }
        self.eval_group(g).map_or(0.0, |(d, _)| d)
    }

    pub(crate) fn unit_gain(&self, u: u32) -> f64 {
        self.tent_gain(u)
    }

    /// The bundle group `g` would take now, in the order the greedy takes it (empty if it detects nothing).
    pub(crate) fn bundle_plan(&mut self, g: usize) -> Vec<u32> {
        if self.eval_group(g).is_some() {
            self.plan.clone()
        } else {
            Vec::new()
        }
    }

    pub(crate) fn miss(&self) -> &[f32] {
        &self.miss
    }

    pub(crate) fn unit_done(&self, u: u32) -> bool {
        self.done.get(u)
    }

    pub(crate) fn step_is_up(&self, x: StepIx) -> bool {
        self.step_state[x as usize] == UP
    }
}
