// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The gated scheduler of DESIGN.md §2.6.
//!
//! A [`KeelGate`] is shared by the dispatcher, which records what happened to
//! each test, and a [`ReadyStream`], which replaces the plain priority queue
//! in the run loop. A test is yielded only when every node it stands on is
//! terminal; a test with a stored pass is yielded as cached without running;
//! a test that stands on a failed root is yielded as blocked.

use super::plan::KeelPlan;
use crate::{
    config::elements::{FlakyResult, SlowTimeoutResult},
    list::{TestInstance, TestInstanceWithSettings},
    output_spec::LiveSpec,
    reporter::events::{
        ChildExecutionOutputDescription, ChildOutputDescription, ExecuteStatus,
        ExecutionDescription, ExecutionResultDescription, ExecutionStatuses,
    },
};
use futures::Stream;
use keel::{NodeId, Status};
use nextest_metadata::{RustBinaryId, TestCaseName};
use std::{
    collections::{BTreeMap, BTreeSet},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::Duration,
};

/// How many lines of a failed test's output the final summary shows.
const SUMMARY_LINES: usize = 4;

/// The longest line the final summary shows.
const SUMMARY_LINE_WIDTH: usize = 200;

/// What happened to one test during the run.
#[derive(Clone, Debug)]
pub(crate) enum Outcome {
    /// A stored pass exists for the test's key.
    Cached {
        /// The run that stored the pass.
        from: String,
    },

    /// The test was not run because roots it stands on failed.
    Blocked {
        /// The roots.
        by: Vec<NodeId>,
    },

    /// The test ran.
    Ran(RanOutcome),
}

impl Outcome {
    /// Returns the Keel status of the outcome.
    pub(crate) fn status(&self) -> Status {
        match self {
            Outcome::Cached { .. } => Status::Cached,
            Outcome::Blocked { .. } => Status::Blocked,
            Outcome::Ran(ran) => ran.status,
        }
    }
}

/// The result of running a test.
#[derive(Clone, Debug)]
pub(crate) struct RanOutcome {
    pub(crate) status: Status,
    pub(crate) duration: Duration,
    pub(crate) attempts: Vec<AttemptOutcome>,
    pub(crate) summary: Option<String>,
}

/// One attempt at running a test.
#[derive(Clone, Debug)]
pub(crate) struct AttemptOutcome {
    pub(crate) status: Status,
    /// Named output of the attempt; kept only for attempts that did not pass.
    pub(crate) outputs: Vec<(String, Vec<u8>)>,
}

impl RanOutcome {
    /// Summarizes the statuses of a finished test.
    pub(crate) fn from_statuses(statuses: &ExecutionStatuses<LiveSpec>) -> Self {
        let status = match statuses.describe() {
            ExecutionDescription::Success { .. } => Status::Pass,
            ExecutionDescription::Flaky {
                result: FlakyResult::Pass,
                ..
            } => Status::Flaky,
            ExecutionDescription::Flaky {
                result: FlakyResult::Fail,
                ..
            } => Status::Fail,
            ExecutionDescription::Failure { last_status, .. } => match last_status.result {
                ExecutionResultDescription::Timeout {
                    result: SlowTimeoutResult::Fail,
                } => Status::Timeout,
                ExecutionResultDescription::ExecFail => Status::Error,
                _ => Status::Fail,
            },
        };
        let attempts: Vec<AttemptOutcome> = statuses
            .iter()
            .map(|attempt| {
                let attempt_status = if attempt.result.is_success() {
                    Status::Pass
                } else {
                    Status::Fail
                };
                AttemptOutcome {
                    status: attempt_status,
                    outputs: if attempt_status == Status::Pass {
                        Vec::new()
                    } else {
                        named_outputs(attempt)
                    },
                }
            })
            .collect();
        let last = statuses.last_status();
        let summary = (!status.gates_as_pass() && status != Status::Flaky)
            .then(|| failure_summary(last))
            .flatten();
        Self {
            status,
            duration: last.time_taken,
            attempts,
            summary,
        }
    }
}

fn named_outputs(status: &ExecuteStatus<LiveSpec>) -> Vec<(String, Vec<u8>)> {
    match &status.output {
        ChildExecutionOutputDescription::Output { output, .. } => match output {
            ChildOutputDescription::Split { stdout, stderr } => {
                [("stdout", stdout), ("stderr", stderr)]
                    .into_iter()
                    .filter_map(|(name, out)| {
                        out.as_ref()
                            .map(|out| (name.to_owned(), out.buf().to_vec()))
                    })
                    .collect()
            }
            ChildOutputDescription::Combined { output } => {
                vec![("output".to_owned(), output.buf().to_vec())]
            }
            ChildOutputDescription::NotLoaded => Vec::new(),
        },
        ChildExecutionOutputDescription::StartError(_) => Vec::new(),
    }
}

fn failure_summary(status: &ExecuteStatus<LiveSpec>) -> Option<String> {
    let text = if let Some(slice) = &status.output_error_slice {
        slice.slice.clone()
    } else if let ChildExecutionOutputDescription::Output { output, .. } = &status.output {
        match output {
            ChildOutputDescription::Split { stderr, .. } => {
                stderr.as_ref()?.as_str_lossy().to_owned()
            }
            ChildOutputDescription::Combined { output } => output.as_str_lossy().to_owned(),
            ChildOutputDescription::NotLoaded => return None,
        }
    } else {
        status.error_summary.as_ref()?.short_message.to_string()
    };
    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(SUMMARY_LINES)
        .map(|line| match line.char_indices().nth(SUMMARY_LINE_WIDTH) {
            Some((end, _)) => format!("{}…", &line[..end]),
            None => line.to_owned(),
        })
        .collect();
    (!lines.is_empty()).then(|| lines.join("\n"))
}

#[derive(Debug)]
struct GateState {
    outcomes: Vec<Option<Outcome>>,
    remaining: Vec<usize>,
    dependents: Vec<Vec<usize>>,
    order: Vec<usize>,
    ready: BTreeSet<(u32, usize, usize)>,
    blocked: BTreeMap<usize, BTreeSet<usize>>,
    ran_blocked_by: BTreeMap<usize, BTreeSet<usize>>,
    roots: Vec<usize>,
    cancelled: bool,
    waker: Option<Waker>,
}

/// What the gate says to do with the next test.
#[derive(Debug)]
pub(crate) enum Gated {
    /// Run the test.
    Run(usize),

    /// Do not run the test: these roots block it.
    Blocked(usize, Vec<NodeId>),
}

/// The result of asking the gate for the next test.
#[derive(Debug)]
pub(crate) enum NextGated {
    Item(Gated),
    Cancelled,
    Pending,
}

/// The state shared by the dispatcher and the scheduler.
#[derive(Debug)]
pub struct KeelGate {
    plan: Arc<KeelPlan>,
    no_block: bool,
    state: Mutex<GateState>,
}

/// The final state of a run.
#[derive(Debug)]
pub(crate) struct GateSummary {
    pub(crate) outcomes: Vec<Option<Outcome>>,
    pub(crate) ran_blocked_by: BTreeMap<usize, Vec<NodeId>>,
}

impl KeelGate {
    /// Creates the gate for `plan`.
    ///
    /// With `no_block`, tests whose upstream roots failed run anyway; the
    /// roots that would have blocked them are still recorded.
    pub fn new(plan: Arc<KeelPlan>, no_block: bool) -> Arc<Self> {
        let count = plan.tests.len();
        let mut dependents = vec![Vec::new(); count];
        let mut remaining = vec![0; count];
        for (i, test) in plan.tests.iter().enumerate() {
            let upstream = plan.plan.upstream(&test.node.id).unwrap_or_default();
            remaining[i] = upstream.len();
            for id in upstream {
                if let Some(&j) = plan.index.get(id) {
                    dependents[j].push(i);
                }
            }
        }
        let mut state = GateState {
            outcomes: vec![None; count],
            remaining,
            dependents,
            order: (0..count).collect(),
            ready: BTreeSet::new(),
            blocked: BTreeMap::new(),
            ran_blocked_by: BTreeMap::new(),
            roots: Vec::new(),
            cancelled: false,
            waker: None,
        };
        for (i, test) in plan.tests.iter().enumerate() {
            if let Some(pass) = &test.cached {
                state.outcomes[i] = Some(Outcome::Cached {
                    from: pass.run_id.clone(),
                });
            }
        }
        for i in 0..count {
            if state.outcomes[i].is_some() {
                state.release_dependents(i, &plan);
            }
        }
        let gate = Arc::new(Self {
            plan,
            no_block,
            state: Mutex::new(state),
        });
        gate.lock().rebuild_ready(&gate.plan);
        gate
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().expect("keel gate lock is never poisoned")
    }

    /// Returns the plan the gate was built for.
    pub fn plan(&self) -> &Arc<KeelPlan> {
        &self.plan
    }

    /// Returns whether blocked tests run anyway.
    pub fn no_block(&self) -> bool {
        self.no_block
    }

    /// Returns the index of the planned node for a test, if it is planned.
    pub(crate) fn node_index(
        &self,
        binary_id: &RustBinaryId,
        name: &TestCaseName,
    ) -> Option<usize> {
        let id = NodeId::new(format!("rust:{binary_id}::{}", name.as_str()));
        self.plan.index.get(&id).copied()
    }

    /// Fixes the scheduling order of nodes: `order[node]` is the node's
    /// position in nextest's priority queue.
    pub(crate) fn bind_order(&self, order: Vec<usize>) {
        let mut state = self.lock();
        state.order = order;
        state.rebuild_ready(&self.plan);
    }

    /// Takes the next test whose gate is resolved.
    pub(crate) fn next(&self, waker: &Waker) -> NextGated {
        let mut state = self.lock();
        if state.cancelled {
            return NextGated::Cancelled;
        }
        let Some(entry) = state.ready.pop_first() else {
            state.waker = Some(waker.clone());
            return NextGated::Pending;
        };
        let idx = entry.2;
        let roots = state.blocked.get(&idx).cloned().unwrap_or_default();
        if roots.is_empty() {
            return NextGated::Item(Gated::Run(idx));
        }
        if self.no_block {
            state.ran_blocked_by.insert(idx, roots);
            return NextGated::Item(Gated::Run(idx));
        }
        let ids = roots
            .into_iter()
            .map(|root| self.plan.tests[root].node.id.clone())
            .collect();
        NextGated::Item(Gated::Blocked(idx, ids))
    }

    /// Marks the run as cancelled: every remaining test is released.
    pub(crate) fn cancel(&self) {
        let waker = {
            let mut state = self.lock();
            state.cancelled = true;
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Records that a test finished running.
    pub(crate) fn on_finished(
        &self,
        binary_id: &RustBinaryId,
        name: &TestCaseName,
        statuses: &ExecutionStatuses<LiveSpec>,
    ) {
        if let Some(idx) = self.node_index(binary_id, name) {
            self.record(idx, Outcome::Ran(RanOutcome::from_statuses(statuses)));
        }
    }

    /// Records that a test was blocked.
    pub(crate) fn on_blocked(&self, instance: &TestInstance<'_>, by: &[String]) {
        if let Some(idx) = self.node_index(&instance.suite_info.binary_id, instance.name) {
            let by = by.iter().map(|id| NodeId::new(id.as_str())).collect();
            self.record(idx, Outcome::Blocked { by });
        }
    }

    /// Records that a test was served from the store.
    pub(crate) fn on_cached(&self, instance: &TestInstance<'_>, from: &str) {
        if let Some(idx) = self.node_index(&instance.suite_info.binary_id, instance.name) {
            self.record(
                idx,
                Outcome::Cached {
                    from: from.to_owned(),
                },
            );
        }
    }

    fn record(&self, idx: usize, outcome: Outcome) {
        let waker = {
            let mut state = self.lock();
            if state.outcomes[idx].is_some() {
                return;
            }
            let status = outcome.status();
            state.outcomes[idx] = Some(outcome);
            let symptom = state
                .ran_blocked_by
                .get(&idx)
                .is_some_and(|roots| !roots.is_empty());
            if matches!(status, Status::Fail | Status::Timeout | Status::Error) && !symptom {
                state.roots.push(idx);
                if self.plan.tests[idx].node.policy.blocks {
                    state.block_dependents_of(idx, &self.plan);
                }
            }
            state.release_dependents(idx, &self.plan);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Returns the final state of the run.
    pub(crate) fn summary(&self) -> GateSummary {
        let state = self.lock();
        GateSummary {
            outcomes: state.outcomes.clone(),
            ran_blocked_by: state
                .ran_blocked_by
                .iter()
                .map(|(&idx, roots)| {
                    (
                        idx,
                        roots
                            .iter()
                            .map(|&root| self.plan.tests[root].node.id.clone())
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

impl GateState {
    fn rebuild_ready(&mut self, plan: &KeelPlan) {
        self.ready = (0..plan.tests.len())
            .filter(|&i| self.outcomes[i].is_none() && self.remaining[i] == 0)
            .map(|i| (self.level(plan, i), self.order[i], i))
            .collect();
    }

    fn level(&self, plan: &KeelPlan, idx: usize) -> u32 {
        plan.plan.level(&plan.tests[idx].node.id).unwrap_or(0)
    }

    /// Lets every node that stands on `idx` take one step toward its gate
    /// resolving.
    fn release_dependents(&mut self, idx: usize, plan: &KeelPlan) {
        for position in 0..self.dependents[idx].len() {
            let dependent = self.dependents[idx][position];
            self.remaining[dependent] -= 1;
            if self.remaining[dependent] == 0 && self.outcomes[dependent].is_none() {
                let entry = (
                    self.level(plan, dependent),
                    self.order[dependent],
                    dependent,
                );
                self.ready.insert(entry);
            }
        }
    }

    fn block_dependents_of(&mut self, root: usize, plan: &KeelPlan) {
        let id = &plan.tests[root].node.id;
        let blocked = plan
            .plan
            .blocked_by(std::slice::from_ref(id), plan.reach.as_ref());
        for node in blocked.keys() {
            if let Some(&idx) = plan.index.get(node) {
                self.blocked.entry(idx).or_default().insert(root);
            }
        }
    }
}

/// A test as the scheduler hands it to the run loop.
#[derive(Debug)]
pub(crate) enum ReadyTest<'a> {
    /// Run the test.
    Run(TestInstanceWithSettings<'a>),

    /// Do not run the test; roots block it.
    Blocked {
        test: TestInstanceWithSettings<'a>,
        blocked_by: Vec<String>,
    },

    /// Do not run the test; a stored pass exists for it.
    Cached {
        test: TestInstanceWithSettings<'a>,
        cached_from: String,
    },
}

/// The stream the run loop consumes when Keel is on.
///
/// It scans for any test whose gate is resolved, so a test that waits on a
/// slow upstream never holds up the tests behind it.
pub(crate) struct ReadyStream<'a> {
    gate: Arc<KeelGate>,
    unplanned: Vec<TestInstanceWithSettings<'a>>,
    cached: Vec<usize>,
    pending: Vec<Option<TestInstanceWithSettings<'a>>>,
    left: usize,
}

impl<'a> ReadyStream<'a> {
    /// Splits the tests of the priority queue into unplanned (filtered out),
    /// cached and gated tests.
    pub(crate) fn new(
        gate: Arc<KeelGate>,
        queue: impl IntoIterator<Item = TestInstanceWithSettings<'a>>,
    ) -> Self {
        let count = gate.plan.tests.len();
        let mut unplanned = Vec::new();
        let mut pending: Vec<Option<TestInstanceWithSettings<'a>>> =
            std::iter::repeat_with(|| None).take(count).collect();
        let mut order = vec![usize::MAX; count];
        for (position, test) in queue.into_iter().enumerate() {
            match gate.node_index(&test.instance.suite_info.binary_id, test.instance.name) {
                Some(idx) => {
                    order[idx] = position;
                    pending[idx] = Some(test);
                }
                None => unplanned.push(test),
            }
        }
        unplanned.reverse();
        let cached: Vec<usize> = (0..count)
            .filter(|&i| gate.plan.tests[i].cached.is_some() && pending[i].is_some())
            .rev()
            .collect();
        let left = (0..count)
            .filter(|&i| gate.plan.tests[i].cached.is_none() && pending[i].is_some())
            .count();
        for (idx, position) in order.iter_mut().enumerate() {
            if *position == usize::MAX {
                *position = count + idx;
            }
        }
        gate.bind_order(order);
        Self {
            gate,
            unplanned,
            cached,
            pending,
            left,
        }
    }

    fn take(&mut self, idx: usize) -> TestInstanceWithSettings<'a> {
        self.pending[idx]
            .take()
            .expect("the gate yields each node once, and only planned ones")
    }
}

impl<'a> Stream for ReadyStream<'a> {
    type Item = ReadyTest<'a>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if let Some(test) = this.unplanned.pop() {
            return Poll::Ready(Some(ReadyTest::Run(test)));
        }
        if let Some(idx) = this.cached.pop() {
            let from = match &this.gate.plan.tests[idx].cached {
                Some(pass) => pass.run_id.clone(),
                None => String::new(),
            };
            let test = this.take(idx);
            return Poll::Ready(Some(ReadyTest::Cached {
                test,
                cached_from: from,
            }));
        }
        if this.left == 0 {
            return Poll::Ready(None);
        }
        match this.gate.next(cx.waker()) {
            NextGated::Item(Gated::Run(idx)) => {
                this.left -= 1;
                Poll::Ready(Some(ReadyTest::Run(this.take(idx))))
            }
            NextGated::Item(Gated::Blocked(idx, roots)) => {
                this.left -= 1;
                Poll::Ready(Some(ReadyTest::Blocked {
                    test: this.take(idx),
                    blocked_by: roots.iter().map(|id| id.to_string()).collect(),
                }))
            }
            NextGated::Cancelled => {
                let Some(idx) = this.pending.iter().position(Option::is_some) else {
                    return Poll::Ready(None);
                };
                this.left = this.left.saturating_sub(1);
                Poll::Ready(Some(ReadyTest::Run(this.take(idx))))
            }
            NextGated::Pending => Poll::Pending,
        }
    }
}
