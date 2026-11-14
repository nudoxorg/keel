// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The gated scheduler of DESIGN.md §2.6.
//!
//! A [`KeelGate`] is shared by the dispatcher, which records what happened to
//! each test, and a [`ReadyStream`], which replaces the plain priority queue
//! in the run loop. A test is yielded only when every node it stands on is
//! terminal; a test with a stored pass is yielded as cached without running;
//! a test that stands on a failed root is yielded as blocked.
//!
//! The gate does not need to know every test up front. Nodes are added as the
//! binaries they belong to are built, and a node waits for the groups it stands
//! on until each of them is complete: every binary that is expected to
//! contribute members has been added, and every member is terminal. A run that
//! plans everything before it starts is the special case in which the gate is
//! sealed right after the first and only batch of nodes.

use super::{
    feed::{Drained, FedBinary, KeelFeed},
    history::{HistoryEntry, KeelHistory},
    plan::{KeelPlan, PlannedTest},
    session::{RootBlock, write_root_block},
};
use crate::{
    config::elements::{FlakyResult, SlowTimeoutResult},
    list::{TestInstance, TestInstanceWithSettings},
    output_spec::LiveSpec,
    reporter::events::{
        AbortDescription, ChildExecutionOutputDescription, ChildOutputDescription, ExecuteStatus,
        ExecutionDescription, ExecutionResultDescription, ExecutionStatuses, FailureDescription,
    },
};
use futures::Stream;
use keel::{GroupId, NodeId, Status, Upstream};
use nextest_metadata::{RustBinaryId, TestCaseName};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
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

/// Returns true if the last attempt of a test ended because a signal that asks a
/// process to stop was delivered to it.
fn was_terminated(statuses: &ExecutionStatuses<LiveSpec>) -> bool {
    matches!(
        statuses.last_status().result,
        ExecutionResultDescription::Fail {
            failure: FailureDescription::Abort {
                abort: AbortDescription::UnixSignal {
                    signal: 2 | 9 | 15,
                    ..
                },
            },
            ..
        }
    )
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

/// A node as it is handed to the gate.
#[derive(Debug)]
pub(crate) struct GateNode {
    pub(crate) planned: PlannedTest,

    /// The level of the node in the hierarchy.
    pub(crate) level: u32,

    /// The position of the node in nextest's priority order. Lower runs first.
    pub(crate) order: u64,
}

/// The order in which ready tests are taken, lowest first: tests that failed in
/// the most recent run that executed them, then the lowest level, then the
/// shortest recorded duration, then nextest's priority order, then the node's
/// position, which makes the order total.
type ReadyKey = (u8, u32, u64, u64, usize);

#[derive(Debug)]
struct NodeState {
    planned: PlannedTest,
    group: usize,
    level: u32,
    order: u64,
    outcome: Option<Outcome>,

    /// How many things the node still waits for: groups that are not complete,
    /// nodes that are not terminal, and nodes that are not known yet.
    remaining: usize,

    /// Whether every edge of the node has been looked at. Until then the node
    /// cannot become ready, because its count of waits may still grow.
    armed: bool,

    /// Whether the node was handed to the scheduler.
    dispatched: bool,

    /// Nodes that wait for this node to be terminal.
    waiters: Vec<usize>,

    /// Nodes that stand on this node, whether or not it is terminal.
    standing: Vec<usize>,

    /// The roots this node transitively stands on.
    blockers: BTreeSet<usize>,
}

#[derive(Debug, Default)]
struct GroupState {
    /// Binaries that are expected to contribute members but have not been added.
    expected: usize,

    /// Members that are not terminal.
    nonterminal: usize,

    /// Whether every expected binary was added and every member is terminal.
    satisfied: bool,

    /// Nodes that wait for the group.
    waiting: Vec<usize>,

    /// Members that stand on their own group. They wait for the other members.
    self_waiting: Vec<usize>,

    /// Nodes that stand on the group.
    standing: Vec<usize>,

    /// The roots that some member is, or transitively stands on.
    blockers: BTreeSet<usize>,
}

/// The announcement of a root, made as soon as the root is final.
#[derive(Clone, Debug)]
pub(crate) struct RootAnnouncement {
    /// The text of the root block.
    pub(crate) text: String,
}

/// When the milestones of the run happened, as time since the run started.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GateTimings {
    pub(crate) first_test: Option<Duration>,
    pub(crate) first_root: Option<Duration>,
    pub(crate) cargo_exit: Option<Duration>,
}

#[derive(Debug)]
struct GateState {
    nodes: Vec<NodeState>,
    index: HashMap<NodeId, usize>,
    groups: Vec<GroupState>,
    group_index: HashMap<GroupId, usize>,

    /// Nodes that wait for a node that has not been added yet.
    unresolved: HashMap<NodeId, Vec<usize>>,
    ready: BTreeSet<ReadyKey>,
    roots: Vec<usize>,
    blocking_roots: Vec<usize>,
    ran_blocked_by: BTreeMap<usize, BTreeSet<usize>>,

    /// The nodes in the order in which they became terminal.
    terminal_order: Vec<usize>,

    /// Nodes that have no outcome and were not handed to the scheduler.
    pending: usize,

    /// Nodes handed to the scheduler that have no outcome.
    in_flight: usize,
    sealed: bool,
    cancelled: bool,
    stuck: bool,
    waker: Option<Waker>,
    history: Arc<KeelHistory>,
    binaries_keyed: usize,
    key_time: Duration,
    timings: GateTimings,
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

    /// Everything is known, nothing is running, and the tests that are left wait
    /// for each other.
    Stalled,
    Pending,
}

/// Options for a gate.
#[derive(Clone, Debug)]
pub struct GateOptions {
    /// Run tests whose upstream roots failed anyway.
    pub no_block: bool,

    /// Cancel the run when the first root is final.
    pub fail_fast_verdict: bool,

    /// How the tests fared in earlier runs.
    pub history: Arc<KeelHistory>,

    /// When the run started.
    pub started: Instant,
}

/// The state shared by the dispatcher and the scheduler.
#[derive(Debug)]
pub struct KeelGate {
    options: GateOptions,
    state: Mutex<GateState>,
}

/// The final state of a run.
#[derive(Debug)]
pub(crate) struct GateFinal {
    pub(crate) tests: Vec<PlannedTest>,
    pub(crate) outcomes: Vec<Option<Outcome>>,
    pub(crate) ran_blocked_by: BTreeMap<usize, Vec<NodeId>>,

    /// The nodes in the order in which they became terminal.
    pub(crate) terminal_order: Vec<usize>,
    pub(crate) binaries_keyed: usize,
    pub(crate) key_time: Duration,
    pub(crate) timings: GateTimings,

    /// The nodes that never became ready, if the gate stalled.
    pub(crate) stalled: Vec<NodeId>,
}

impl KeelGate {
    /// Creates a gate with no nodes.
    pub fn streaming(options: GateOptions) -> Arc<Self> {
        let history = options.history.clone();
        Arc::new(Self {
            options,
            state: Mutex::new(GateState {
                nodes: Vec::new(),
                index: HashMap::new(),
                groups: Vec::new(),
                group_index: HashMap::new(),
                unresolved: HashMap::new(),
                ready: BTreeSet::new(),
                roots: Vec::new(),
                blocking_roots: Vec::new(),
                ran_blocked_by: BTreeMap::new(),
                terminal_order: Vec::new(),
                pending: 0,
                in_flight: 0,
                sealed: false,
                cancelled: false,
                stuck: false,
                waker: None,
                history,
                binaries_keyed: 0,
                key_time: Duration::ZERO,
                timings: GateTimings::default(),
            }),
        })
    }

    /// Creates the gate for a plan that was built before the run started.
    ///
    /// With `no_block`, tests whose upstream roots failed run anyway; the
    /// roots that would have blocked them are still recorded.
    pub fn from_plan(plan: KeelPlan, options: GateOptions) -> Arc<Self> {
        let gate = Self::streaming(options);
        let KeelPlan {
            tests,
            plan,
            key_duration,
            binaries_keyed,
            ..
        } = plan;
        let nodes: Vec<GateNode> = tests
            .into_iter()
            .enumerate()
            .map(|(position, planned)| GateNode {
                level: plan.level(&planned.node.id).unwrap_or(0),
                order: position as u64,
                planned,
            })
            .collect();
        {
            let mut state = gate.lock();
            state.add_nodes(nodes);
            state.key_time = key_duration;
            state.binaries_keyed = binaries_keyed;
            state.seal();
        }
        gate
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().expect("keel gate lock is never poisoned")
    }

    /// Returns whether blocked tests run anyway.
    pub fn no_block(&self) -> bool {
        self.options.no_block
    }

    /// Returns whether the run is cancelled when the first root is final.
    pub fn fail_fast_verdict(&self) -> bool {
        self.options.fail_fast_verdict
    }

    /// Returns the time since the run started.
    pub fn elapsed(&self) -> Duration {
        self.options.started.elapsed()
    }

    /// Declares that a binary will contribute members to each of `groups`.
    ///
    /// A group is complete only after every binary declared for it has been
    /// added, so the declarations must be made before the first binary is.
    pub fn expect_binaries(&self, groups: impl IntoIterator<Item = GroupId>) {
        let mut state = self.lock();
        for group in groups {
            let index = state.group_idx(&group);
            state.groups[index].expected += 1;
        }
    }

    /// Records that Cargo exited, at the current time.
    pub fn set_cargo_exit(&self) {
        let elapsed = self.elapsed();
        self.lock().timings.cargo_exit.get_or_insert(elapsed);
    }

    /// Records that Cargo exited at `at` after the start of the run.
    pub fn set_cargo_exit_at(&self, at: Duration) {
        self.lock().timings.cargo_exit.get_or_insert(at);
    }

    /// Adds the nodes of one binary. Returns the index of the first of them;
    /// the others follow in order.
    pub(crate) fn add_binary(&self, binary: &mut FedBinary<'_>) -> usize {
        let nodes = std::mem::take(&mut binary.nodes);
        let keyed = !nodes.is_empty();
        let mut state = self.lock();
        let base = state.add_nodes(nodes);
        state.key_time += binary.key_time;
        if keyed {
            state.binaries_keyed += 1;
        }
        if let Some(group) = binary.expected.take() {
            let index = state.group_idx(&group);
            state.groups[index].expected = state.groups[index].expected.saturating_sub(1);
            state.maybe_satisfy(index);
        }
        base
    }

    /// Declares that no more nodes will be added.
    ///
    /// Groups that still wait for binaries stop waiting: those binaries were
    /// expected but were never built.
    pub(crate) fn seal(&self) {
        self.lock().seal();
    }

    /// Returns the index of the planned node for a test, if it is planned.
    pub(crate) fn node_index(
        &self,
        binary_id: &RustBinaryId,
        name: &TestCaseName,
    ) -> Option<usize> {
        let id = NodeId::new(format!("rust:{binary_id}::{}", name.as_str()));
        self.lock().index.get(&id).copied()
    }

    /// Returns the ID of the run that stored a pass for the node, if it has one.
    pub(crate) fn cached_from(&self, idx: usize) -> Option<String> {
        self.lock().nodes[idx]
            .planned
            .cached
            .as_ref()
            .map(|pass| pass.run_id.clone())
    }

    /// Fixes the scheduling order of nodes: `order[node]` is the node's
    /// position in nextest's priority queue.
    pub(crate) fn bind_order(&self, order: Vec<usize>) {
        let mut state = self.lock();
        for (node, position) in state.nodes.iter_mut().zip(order) {
            node.order = position as u64;
        }
        state.rebuild_ready();
    }

    /// Takes the next test whose gate is resolved.
    pub(crate) fn next(&self, waker: &Waker) -> NextGated {
        let mut state = self.lock();
        let next = state.next(self.options.no_block);
        if matches!(next, NextGated::Pending) {
            state.waker = Some(waker.clone());
        }
        next
    }

    /// Remembers `waker`, and returns whether the run is cancelled.
    pub(crate) fn park(&self, waker: &Waker) -> bool {
        let mut state = self.lock();
        if !state.cancelled {
            state.waker = Some(waker.clone());
        }
        state.cancelled
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

    /// Records that a test started running.
    pub(crate) fn on_started(&self) {
        let elapsed = self.elapsed();
        self.lock().timings.first_test.get_or_insert(elapsed);
    }

    /// Records that a test finished running. Returns the announcement of the
    /// test if it is a root.
    ///
    /// A test that the cancellation of the run terminated says nothing about the
    /// test, so it is not recorded and stays unfinished.
    pub(crate) fn on_finished(
        &self,
        binary_id: &RustBinaryId,
        name: &TestCaseName,
        statuses: &ExecutionStatuses<LiveSpec>,
        run_cancelled: bool,
    ) -> Option<RootAnnouncement> {
        if run_cancelled && was_terminated(statuses) {
            return None;
        }
        let idx = self.node_index(binary_id, name)?;
        self.record(idx, Outcome::Ran(RanOutcome::from_statuses(statuses)))
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

    fn record(&self, idx: usize, outcome: Outcome) -> Option<RootAnnouncement> {
        let elapsed = self.elapsed();
        let (announcement, waker) = {
            let mut state = self.lock();
            let announcement = state.record(idx, outcome, elapsed);
            (announcement, state.waker.take())
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        announcement
    }

    /// Takes the final state of the run.
    pub(crate) fn finish(&self) -> GateFinal {
        let mut state = self.lock();
        let stalled = if state.stuck {
            state
                .nodes
                .iter()
                .filter(|node| node.outcome.is_none())
                .map(|node| node.planned.node.id.clone())
                .collect()
        } else {
            Vec::new()
        };
        let ran_blocked_by = std::mem::take(&mut state.ran_blocked_by)
            .into_iter()
            .map(|(idx, roots)| {
                (
                    idx,
                    roots
                        .into_iter()
                        .map(|root| state.nodes[root].planned.node.id.clone())
                        .collect(),
                )
            })
            .collect();
        let mut tests = Vec::with_capacity(state.nodes.len());
        let mut outcomes = Vec::with_capacity(state.nodes.len());
        for node in std::mem::take(&mut state.nodes) {
            outcomes.push(node.outcome);
            tests.push(node.planned);
        }
        GateFinal {
            tests,
            outcomes,
            ran_blocked_by,
            terminal_order: std::mem::take(&mut state.terminal_order),
            binaries_keyed: state.binaries_keyed,
            key_time: state.key_time,
            timings: state.timings,
            stalled,
        }
    }
}

impl GateState {
    fn group_idx(&mut self, group: &GroupId) -> usize {
        if let Some(&index) = self.group_index.get(group) {
            return index;
        }
        let index = self.groups.len();
        self.groups.push(GroupState::default());
        self.group_index.insert(group.clone(), index);
        index
    }

    fn ready_key(&self, idx: usize) -> ReadyKey {
        let node = &self.nodes[idx];
        let entry = self.history.get(node.planned.node.id.as_str());
        let failed_last_time = entry.is_some_and(|entry: HistoryEntry| entry.failed);
        (
            u8::from(!failed_last_time),
            node.level,
            entry.map_or(0, |entry| entry.duration_ms),
            node.order,
            idx,
        )
    }

    fn make_ready(&mut self, idx: usize) {
        let key = self.ready_key(idx);
        self.ready.insert(key);
    }

    fn rebuild_ready(&mut self) {
        self.ready.clear();
        for idx in 0..self.nodes.len() {
            let node = &self.nodes[idx];
            if node.armed && node.outcome.is_none() && !node.dispatched && node.remaining == 0 {
                self.make_ready(idx);
            }
        }
    }

    /// Adds nodes, resolving what they stand on against everything added so
    /// far and against each other. Returns the index of the first node.
    fn add_nodes(&mut self, nodes: Vec<GateNode>) -> usize {
        let base = self.nodes.len();
        let mut touched = Vec::new();
        for gate_node in nodes {
            let idx = self.nodes.len();
            let group = self.group_idx(&gate_node.planned.node.group);
            let outcome = gate_node
                .planned
                .cached
                .as_ref()
                .map(|pass| Outcome::Cached {
                    from: pass.run_id.clone(),
                });
            if outcome.is_none() {
                self.groups[group].nonterminal += 1;
                self.pending += 1;
            } else {
                self.terminal_order.push(idx);
            }
            self.index.insert(gate_node.planned.node.id.clone(), idx);
            touched.push(group);
            self.nodes.push(NodeState {
                planned: gate_node.planned,
                group,
                level: gate_node.level,
                order: gate_node.order,
                outcome,
                remaining: 0,
                armed: false,
                dispatched: false,
                waiters: Vec::new(),
                standing: Vec::new(),
                blockers: BTreeSet::new(),
            });
        }
        let end = self.nodes.len();

        for idx in base..end {
            let id = self.nodes[idx].planned.node.id.clone();
            let Some(waiters) = self.unresolved.remove(&id) else {
                continue;
            };
            for waiter in waiters {
                self.nodes[idx].standing.push(waiter);
                if self.nodes[idx].outcome.is_none() {
                    self.nodes[idx].waiters.push(waiter);
                } else {
                    self.release(waiter);
                }
            }
        }

        for idx in base..end {
            self.resolve_upstream(idx);
            self.nodes[idx].armed = true;
        }
        for idx in base..end {
            self.inherit_blockers(idx);
        }
        for idx in base..end {
            let node = &self.nodes[idx];
            if node.outcome.is_none() && node.remaining == 0 {
                self.make_ready(idx);
            }
        }
        touched.sort_unstable();
        touched.dedup();
        for group in touched {
            self.maybe_satisfy(group);
        }
        base
    }

    fn resolve_upstream(&mut self, idx: usize) {
        let own_group = self.nodes[idx].group;
        let upstream = self.nodes[idx].planned.node.stands_on.clone();
        let own_id = self.nodes[idx].planned.node.id.clone();
        let waits = self.nodes[idx].outcome.is_none();
        for edge in upstream {
            match edge {
                Upstream::Group(group) => {
                    let target = self.group_idx(&group);
                    self.groups[target].standing.push(idx);
                    if !waits {
                        continue;
                    }
                    if target == own_group {
                        self.groups[target].self_waiting.push(idx);
                        self.nodes[idx].remaining += 1;
                        self.maybe_satisfy(target);
                        continue;
                    }
                    self.maybe_satisfy(target);
                    if !self.groups[target].satisfied {
                        self.groups[target].waiting.push(idx);
                        self.nodes[idx].remaining += 1;
                    }
                }
                Upstream::Node(id) => {
                    if id == own_id {
                        continue;
                    }
                    match self.index.get(&id).copied() {
                        Some(target) => {
                            self.nodes[target].standing.push(idx);
                            if waits && self.nodes[target].outcome.is_none() {
                                self.nodes[target].waiters.push(idx);
                                self.nodes[idx].remaining += 1;
                            }
                        }
                        None => {
                            self.unresolved.entry(id).or_default().push(idx);
                            if waits {
                                self.nodes[idx].remaining += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Lets one waiting edge of `idx` go.
    fn release(&mut self, idx: usize) {
        let node = &mut self.nodes[idx];
        node.remaining = node.remaining.saturating_sub(1);
        if node.remaining == 0 && node.armed && node.outcome.is_none() && !node.dispatched {
            self.make_ready(idx);
        }
    }

    /// Marks a group complete when it is, and lets what waits for it go.
    fn maybe_satisfy(&mut self, group: usize) {
        if !self.groups[group].satisfied
            && self.groups[group].expected == 0
            && self.groups[group].nonterminal == 0
        {
            self.groups[group].satisfied = true;
            for waiter in std::mem::take(&mut self.groups[group].waiting) {
                self.release(waiter);
            }
        }
        // A member that stands on its own group waits for the other members,
        // and is itself one of the members that are not terminal.
        if self.groups[group].expected == 0 && self.groups[group].nonterminal <= 1 {
            for waiter in std::mem::take(&mut self.groups[group].self_waiting) {
                self.release(waiter);
            }
        }
    }

    fn seal(&mut self) {
        if self.sealed {
            return;
        }
        self.sealed = true;
        for group in 0..self.groups.len() {
            self.groups[group].expected = 0;
            self.maybe_satisfy(group);
        }
        for (_, waiters) in std::mem::take(&mut self.unresolved) {
            for waiter in waiters {
                self.release(waiter);
            }
        }
    }

    fn record(
        &mut self,
        idx: usize,
        outcome: Outcome,
        elapsed: Duration,
    ) -> Option<RootAnnouncement> {
        if self.nodes[idx].outcome.is_some() {
            return None;
        }
        let status = outcome.status();
        if self.nodes[idx].dispatched {
            self.in_flight -= 1;
        } else {
            self.pending -= 1;
        }
        let announcement_source = match &outcome {
            Outcome::Ran(ran) => Some((ran.duration, ran.summary.clone())),
            _ => None,
        };
        self.nodes[idx].outcome = Some(outcome);
        self.terminal_order.push(idx);
        let group = self.nodes[idx].group;
        self.groups[group].nonterminal = self.groups[group].nonterminal.saturating_sub(1);

        let symptom = self
            .ran_blocked_by
            .get(&idx)
            .is_some_and(|roots| !roots.is_empty());
        let mut announcement = None;
        if matches!(status, Status::Fail | Status::Timeout | Status::Error) && !symptom {
            self.roots.push(idx);
            self.timings.first_root.get_or_insert(elapsed);
            if let Some((duration, summary)) = announcement_source {
                announcement = Some(self.announce_root(idx, status, duration, summary));
            }
            if self.nodes[idx].planned.node.policy.blocks {
                self.blocking_roots.push(idx);
                self.spread(idx, idx);
            }
        }

        for waiter in std::mem::take(&mut self.nodes[idx].waiters) {
            self.release(waiter);
        }
        self.maybe_satisfy(group);
        announcement
    }

    fn announce_root(
        &self,
        idx: usize,
        status: Status,
        duration: Duration,
        summary: Option<String>,
    ) -> RootAnnouncement {
        let planned = &self.nodes[idx].planned;
        let mut text = String::new();
        write_root_block(
            &mut text,
            &RootBlock {
                id: &planned.node.id,
                status,
                duration_ms: Some(duration.as_millis().try_into().unwrap_or(u64::MAX)),
                exercised: planned.exercised.as_ref().map(BTreeSet::len),
                group: planned.node.group.name(),
                blocked: &[],
                stderr: summary.as_deref(),
            },
        );
        RootAnnouncement { text }
    }

    /// Records that `source`, a blocking root, is upstream of `from` and of
    /// everything that stands on `from`.
    ///
    /// `from` is `source` itself or a node that has `source` in its blockers.
    fn spread(&mut self, source: usize, from: usize) {
        let mut stack = vec![from];
        while let Some(at) = stack.pop() {
            let group = self.nodes[at].group;
            if self.groups[group].blockers.insert(source) {
                for dependent in self.groups[group].standing.clone() {
                    if dependent != source && self.nodes[dependent].blockers.insert(source) {
                        stack.push(dependent);
                    }
                }
            }
            for dependent in self.nodes[at].standing.clone() {
                if dependent != source && self.nodes[dependent].blockers.insert(source) {
                    stack.push(dependent);
                }
            }
        }
    }

    /// Works out which roots a node that has just arrived stands on, from what
    /// it stands on.
    fn inherit_blockers(&mut self, idx: usize) {
        if self.blocking_roots.is_empty() {
            return;
        }
        let mut inherited = BTreeSet::new();
        for edge in self.nodes[idx].planned.node.stands_on.clone() {
            match edge {
                Upstream::Group(group) => {
                    if let Some(&target) = self.group_index.get(&group) {
                        inherited.extend(self.groups[target].blockers.iter().copied());
                    }
                }
                Upstream::Node(id) => {
                    if let Some(&target) = self.index.get(&id) {
                        if self.blocking_roots.contains(&target) {
                            inherited.insert(target);
                        }
                        inherited.extend(self.nodes[target].blockers.iter().copied());
                    }
                }
            }
        }
        inherited.remove(&idx);
        for source in inherited {
            self.nodes[idx].blockers.insert(source);
            self.spread(source, idx);
        }
    }

    /// Returns the blocking roots that block a node, as DESIGN.md §2.5 defines
    /// blocking: by reach where both sides have reach information, else by
    /// standing on the root.
    fn blockers_for(&self, idx: usize) -> BTreeSet<usize> {
        let node = &self.nodes[idx];
        self.blocking_roots
            .iter()
            .copied()
            .filter(|&root| root != idx)
            .filter(
                |&root| match (&self.nodes[root].planned.exercised, &node.planned.reach) {
                    (Some(exercised), Some(reach)) => !exercised.is_disjoint(reach),
                    _ => node.blockers.contains(&root),
                },
            )
            .collect()
    }

    fn next(&mut self, no_block: bool) -> NextGated {
        if self.cancelled {
            return NextGated::Cancelled;
        }
        let Some(key) = self.ready.pop_first() else {
            if self.sealed && self.in_flight == 0 && self.pending > 0 {
                self.stuck = true;
                return NextGated::Stalled;
            }
            return NextGated::Pending;
        };
        let idx = key.4;
        self.nodes[idx].dispatched = true;
        self.pending -= 1;
        self.in_flight += 1;
        let roots = self.blockers_for(idx);
        if roots.is_empty() {
            return NextGated::Item(Gated::Run(idx));
        }
        if no_block {
            self.ran_blocked_by.insert(idx, roots);
            return NextGated::Item(Gated::Run(idx));
        }
        let ids = roots
            .into_iter()
            .map(|root| self.nodes[root].planned.node.id.clone())
            .collect();
        NextGated::Item(Gated::Blocked(idx, ids))
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
/// slow upstream never holds up the tests behind it. With a feed, the set of
/// tests grows while the stream is being polled, and the stream ends only when
/// the feed is closed and every test it ever received has been handed out.
pub(crate) struct ReadyStream<'a> {
    gate: Arc<KeelGate>,
    feed: Option<Arc<KeelFeed<'a>>>,
    feed_closed: bool,
    unplanned: Vec<TestInstanceWithSettings<'a>>,
    cached: Vec<usize>,
    pending: Vec<Option<TestInstanceWithSettings<'a>>>,
    left: usize,
}

impl<'a> ReadyStream<'a> {
    /// Splits the tests of the priority queue into unplanned (filtered out),
    /// cached and gated tests. Every planned test is in the gate already.
    pub(crate) fn new(
        gate: Arc<KeelGate>,
        queue: impl IntoIterator<Item = TestInstanceWithSettings<'a>>,
    ) -> Self {
        let count = gate.lock().nodes.len();
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
        let mut cached = Vec::new();
        let mut left = 0;
        for (idx, test) in pending.iter().enumerate() {
            if test.is_none() {
                continue;
            }
            if gate.cached_from(idx).is_some() {
                cached.push(idx);
            } else {
                left += 1;
            }
        }
        cached.reverse();
        for (idx, position) in order.iter_mut().enumerate() {
            if *position == usize::MAX {
                *position = count + idx;
            }
        }
        gate.bind_order(order);
        Self {
            gate,
            feed: None,
            feed_closed: false,
            unplanned,
            cached,
            pending,
            left,
        }
    }

    /// Creates a stream whose tests come from `feed`.
    pub(crate) fn from_feed(gate: Arc<KeelGate>, feed: Arc<KeelFeed<'a>>) -> Self {
        Self {
            gate,
            feed: Some(feed),
            feed_closed: false,
            unplanned: Vec::new(),
            cached: Vec::new(),
            pending: Vec::new(),
            left: 0,
        }
    }

    fn take(&mut self, idx: usize) -> TestInstanceWithSettings<'a> {
        self.pending[idx]
            .take()
            .expect("the gate yields each node once, and only planned ones")
    }

    /// Moves everything the feed has received into the gate and the stream.
    fn pump(&mut self, waker: &Waker) {
        let Some(feed) = &self.feed else {
            return;
        };
        let Drained { binaries, closed } = feed.drain(waker);
        for mut binary in binaries {
            let node_count = binary.nodes.len();
            let base = self.gate.add_binary(&mut binary);
            let count = base + node_count;
            if self.pending.len() < count {
                self.pending.resize_with(count, || None);
            }
            for (position, test) in binary.tests {
                let idx = base + position;
                if self.gate.cached_from(idx).is_some() {
                    self.cached.push(idx);
                } else {
                    self.left += 1;
                }
                self.pending[idx] = Some(test);
            }
            self.unplanned.extend(binary.unplanned);
        }
        if closed && !self.feed_closed {
            self.feed_closed = true;
            self.gate.seal();
        }
    }
}

impl<'a> Stream for ReadyStream<'a> {
    type Item = ReadyTest<'a>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        this.pump(cx.waker());
        if let Some(test) = this.unplanned.pop() {
            return Poll::Ready(Some(ReadyTest::Run(test)));
        }
        if let Some(idx) = this.cached.pop() {
            let from = this.gate.cached_from(idx).unwrap_or_default();
            let test = this.take(idx);
            return Poll::Ready(Some(ReadyTest::Cached {
                test,
                cached_from: from,
            }));
        }
        if this.left == 0 {
            if this.feed.is_none() || this.feed_closed {
                return Poll::Ready(None);
            }
            if this.gate.park(cx.waker()) {
                return Poll::Ready(None);
            }
            return Poll::Pending;
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
            NextGated::Stalled => Poll::Ready(None),
            NextGated::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keel::history::KeelHistory;
    use futures::task::noop_waker;
    use keel::{Digest, Inputs, Kind, NetMode, Node, Plan, Platform, Policy, StoredPass, SymbolId};

    fn node(id: &str, group: &str, stands_on: &[&str]) -> Node {
        Node {
            id: NodeId::new(id),
            kind: Kind::RustTest,
            group: group.parse::<GroupId>().unwrap(),
            stands_on: stands_on.iter().map(|s| s.parse().unwrap()).collect(),
            joins: Vec::new(),
            inputs: Inputs::default(),
            produces: Vec::new(),
            via: None,
            key: Digest::of(id.as_bytes()),
            policy: Policy::default(),
        }
    }

    fn platform() -> Platform {
        Platform::new("x86_64-unknown-linux-gnu", "rustc 1.0.0", NetMode::Open)
    }

    fn planned(node: Node, cached: bool) -> PlannedTest {
        let cached = cached.then(|| StoredPass {
            key: node.key,
            id: node.id.clone(),
            run_id: "run-0".to_owned(),
            recorded_at: String::new(),
            platform: platform(),
            evidence: Vec::new(),
        });
        PlannedTest {
            node,
            cached,
            reach: None,
            exercised: None,
        }
    }

    fn options(no_block: bool, history: KeelHistory) -> GateOptions {
        GateOptions {
            no_block,
            fail_fast_verdict: false,
            history: Arc::new(history),
            started: Instant::now(),
        }
    }

    fn plan_of(nodes: Vec<Node>, cached: &[&str]) -> KeelPlan {
        let plan = Plan::new(&nodes).unwrap();
        let tests = nodes
            .into_iter()
            .map(|node| {
                let cached = cached.contains(&node.id.as_str());
                planned(node, cached)
            })
            .collect();
        KeelPlan {
            tests,
            plan,
            platform: platform(),
            key_duration: Duration::ZERO,
            binaries_keyed: 0,
        }
    }

    fn gate_of(nodes: Vec<Node>, cached: &[&str], no_block: bool) -> Arc<KeelGate> {
        KeelGate::from_plan(
            plan_of(nodes, cached),
            options(no_block, KeelHistory::empty()),
        )
    }

    fn ran(status: Status) -> Outcome {
        Outcome::Ran(RanOutcome {
            status,
            duration: Duration::from_millis(10),
            attempts: Vec::new(),
            summary: None,
        })
    }

    fn next(gate: &KeelGate) -> NextGated {
        gate.next(&noop_waker())
    }

    fn run_index(next: NextGated) -> usize {
        match next {
            NextGated::Item(Gated::Run(idx)) => idx,
            other => panic!("expected a test to run, got {other:?}"),
        }
    }

    fn gate_node(node: Node, level: u32, order: u64) -> GateNode {
        GateNode {
            planned: planned(node, false),
            level,
            order,
        }
    }

    /// `a` and `d` are in `unit(p)` and `unit(q)`; `b` stands on `unit(p)` and
    /// `c` stands on `unit(q)`.
    fn two_chains() -> Vec<Node> {
        vec![
            node("rust:p::a", "unit(p)", &[]),
            node("rust:q::d", "unit(q)", &[]),
            node("rust:r::b", "unit(r)", &["unit(p)"]),
            node("rust:s::c", "unit(s)", &["unit(q)"]),
        ]
    }

    #[test]
    fn a_test_waits_for_everything_it_stands_on() {
        let gate = gate_of(two_chains(), &[], false);
        let first = [run_index(next(&gate)), run_index(next(&gate))];
        assert_eq!(first, [0, 1], "level 0 runs in original order");
        assert!(matches!(next(&gate), NextGated::Pending));

        gate.record(1, ran(Status::Pass));
        assert_eq!(run_index(next(&gate)), 3, "c is free, b still waits for a");
        assert!(matches!(next(&gate), NextGated::Pending));

        gate.record(0, ran(Status::Pass));
        assert_eq!(run_index(next(&gate)), 2);
    }

    #[test]
    fn a_root_blocks_what_stands_on_it_and_nothing_else() {
        let gate = gate_of(two_chains(), &[], false);
        let (a, d) = (run_index(next(&gate)), run_index(next(&gate)));
        gate.record(a, ran(Status::Fail));
        gate.record(d, ran(Status::Pass));
        let mut seen = Vec::new();
        for _ in 0..2 {
            match next(&gate) {
                NextGated::Item(Gated::Blocked(idx, by)) => seen.push((idx, by)),
                NextGated::Item(Gated::Run(idx)) => seen.push((idx, Vec::new())),
                other => panic!("unexpected {other:?}"),
            }
        }
        seen.sort();
        assert_eq!(
            seen,
            [(2, vec![NodeId::new("rust:p::a")]), (3, Vec::new())],
            "b is blocked by a, c runs"
        );
    }

    #[test]
    fn no_block_runs_the_test_and_remembers_the_root() {
        let gate = gate_of(two_chains(), &[], true);
        let (a, d) = (run_index(next(&gate)), run_index(next(&gate)));
        gate.record(a, ran(Status::Fail));
        gate.record(d, ran(Status::Pass));
        let (b, c) = (run_index(next(&gate)), run_index(next(&gate)));
        assert_eq!((b, c), (2, 3));
        gate.record(b, ran(Status::Fail));
        assert_eq!(gate.lock().roots, [0], "only a is a root");
        let fin = gate.finish();
        assert_eq!(
            fin.ran_blocked_by[&2],
            [NodeId::new("rust:p::a")],
            "b failed as a symptom of a"
        );
        assert!(!fin.ran_blocked_by.contains_key(&3));
    }

    #[test]
    fn cached_tests_release_what_stands_on_them_at_once() {
        let gate = gate_of(two_chains(), &["rust:p::a"], false);
        assert!(matches!(
            gate.lock().nodes[0].outcome,
            Some(Outcome::Cached { .. })
        ));
        let ready = [run_index(next(&gate)), run_index(next(&gate))];
        assert_eq!(ready, [1, 2], "d runs, and b no longer waits for a");
    }

    #[test]
    fn flaky_tests_do_not_block() {
        let gate = gate_of(two_chains(), &[], false);
        let (a, _d) = (run_index(next(&gate)), run_index(next(&gate)));
        gate.record(a, ran(Status::Flaky));
        assert_eq!(run_index(next(&gate)), 2);
    }

    #[test]
    fn cancelling_wakes_the_scheduler_and_releases_everything() {
        let gate = gate_of(two_chains(), &[], false);
        let _ = (run_index(next(&gate)), run_index(next(&gate)));
        assert!(matches!(next(&gate), NextGated::Pending));
        gate.cancel();
        assert!(matches!(next(&gate), NextGated::Cancelled));
    }

    #[test]
    fn recording_a_terminal_status_wakes_a_pending_scheduler() {
        use std::{
            sync::atomic::{AtomicBool, Ordering},
            task::Wake,
        };
        struct Flag(AtomicBool);
        impl Wake for Flag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());

        let gate = gate_of(two_chains(), &[], false);
        let (a, d) = (run_index(next(&gate)), run_index(next(&gate)));
        assert!(matches!(gate.next(&waker), NextGated::Pending));
        assert!(!flag.0.load(Ordering::SeqCst));
        gate.record(a, ran(Status::Pass));
        assert!(flag.0.load(Ordering::SeqCst), "the scheduler was woken");
        let _ = d;
    }

    #[test]
    fn a_test_that_does_not_block_is_still_a_root() {
        let mut nodes = two_chains();
        nodes[0].policy.blocks = false;
        let gate = gate_of(nodes, &[], false);
        let (a, d) = (run_index(next(&gate)), run_index(next(&gate)));
        gate.record(a, ran(Status::Fail));
        gate.record(d, ran(Status::Pass));
        assert_eq!(run_index(next(&gate)), 2, "b runs despite a failing");
        assert_eq!(gate.lock().roots, [0]);
    }

    #[test]
    fn a_failure_blocks_through_a_chain_of_groups() {
        let nodes = vec![
            node("rust:p::a", "unit(p)", &[]),
            node("rust:r::b", "unit(r)", &["unit(p)"]),
            node("rust:s::c", "unit(s)", &["unit(r)"]),
        ];
        let gate = gate_of(nodes, &[], false);
        gate.record(run_index(next(&gate)), ran(Status::Fail));
        match next(&gate) {
            NextGated::Item(Gated::Blocked(1, by)) => {
                assert_eq!(by, [NodeId::new("rust:p::a")]);
            }
            other => panic!("expected b to be blocked, got {other:?}"),
        }
        gate.record(
            1,
            Outcome::Blocked {
                by: vec![NodeId::new("rust:p::a")],
            },
        );
        match next(&gate) {
            NextGated::Item(Gated::Blocked(2, by)) => {
                assert_eq!(by, [NodeId::new("rust:p::a")], "c is blocked by the root");
            }
            other => panic!("expected c to be blocked, got {other:?}"),
        }
    }

    #[test]
    fn reach_decides_blocking_where_both_sides_have_it() {
        let mut nodes = two_chains();
        nodes.push(node("rust:t::e", "unit(t)", &["unit(p)"]));
        let mut plan = plan_of(nodes, &[]);
        let set = |symbols: &[u64]| -> Option<BTreeSet<SymbolId>> {
            Some(symbols.iter().copied().map(SymbolId).collect())
        };
        plan.tests[0].exercised = set(&[1, 2]);
        plan.tests[2].reach = set(&[2, 9]);
        plan.tests[4].reach = set(&[9]);
        let gate = KeelGate::from_plan(plan, options(false, KeelHistory::empty()));
        let (a, d) = (run_index(next(&gate)), run_index(next(&gate)));
        gate.record(a, ran(Status::Fail));
        gate.record(d, ran(Status::Pass));
        let mut blocked = Vec::new();
        let mut running = Vec::new();
        for _ in 0..3 {
            match next(&gate) {
                NextGated::Item(Gated::Blocked(idx, _)) => blocked.push(idx),
                NextGated::Item(Gated::Run(idx)) => running.push(idx),
                other => panic!("unexpected {other:?}"),
            }
        }
        blocked.sort();
        running.sort();
        assert_eq!(blocked, [2], "b reaches the code a exercised");
        assert_eq!(running, [3, 4], "e stands on a but cannot reach its code");
    }

    #[test]
    fn nodes_that_arrive_later_wait_for_every_expected_binary() {
        let gate = KeelGate::streaming(options(false, KeelHistory::empty()));
        gate.expect_binaries([GroupId::unit("p"), GroupId::unit("r")]);

        // r's binary arrives first; its test stands on unit(p), which is not
        // complete because p's binary has not arrived.
        let mut r = FedBinary::without_tests(Some(GroupId::unit("r")), Vec::new(), Duration::ZERO);
        r.nodes = vec![gate_node(node("rust:r::b", "unit(r)", &["unit(p)"]), 1, 0)];
        let base_r = gate.add_binary(&mut r);
        assert_eq!(base_r, 0);
        assert!(matches!(next(&gate), NextGated::Pending));

        let mut p = FedBinary::without_tests(Some(GroupId::unit("p")), Vec::new(), Duration::ZERO);
        p.nodes = vec![
            gate_node(node("rust:p::a", "unit(p)", &[]), 0, 1),
            gate_node(node("rust:p::z", "unit(p)", &[]), 0, 2),
        ];
        let base_p = gate.add_binary(&mut p);
        assert_eq!(base_p, 1);
        let first = [run_index(next(&gate)), run_index(next(&gate))];
        assert_eq!(first, [1, 2], "p's tests run, r's test still waits");
        assert!(matches!(next(&gate), NextGated::Pending));

        gate.record(1, ran(Status::Pass));
        assert!(
            matches!(next(&gate), NextGated::Pending),
            "z is not terminal"
        );
        gate.record(2, ran(Status::Pass));
        assert_eq!(run_index(next(&gate)), 0);
    }

    #[test]
    fn a_binary_that_is_never_built_stops_blocking_when_the_gate_is_sealed() {
        let gate = KeelGate::streaming(options(false, KeelHistory::empty()));
        gate.expect_binaries([GroupId::unit("p"), GroupId::unit("r")]);
        let mut r = FedBinary::without_tests(Some(GroupId::unit("r")), Vec::new(), Duration::ZERO);
        r.nodes = vec![gate_node(node("rust:r::b", "unit(r)", &["unit(p)"]), 1, 0)];
        gate.add_binary(&mut r);
        assert!(matches!(next(&gate), NextGated::Pending));
        gate.seal();
        assert_eq!(
            run_index(next(&gate)),
            0,
            "unit(p) has no members to wait for"
        );
    }

    #[test]
    fn a_binary_without_tests_completes_its_group() {
        let gate = KeelGate::streaming(options(false, KeelHistory::empty()));
        gate.expect_binaries([GroupId::unit("p"), GroupId::unit("r")]);
        let mut r = FedBinary::without_tests(Some(GroupId::unit("r")), Vec::new(), Duration::ZERO);
        r.nodes = vec![gate_node(node("rust:r::b", "unit(r)", &["unit(p)"]), 1, 0)];
        gate.add_binary(&mut r);
        let mut p = FedBinary::without_tests(Some(GroupId::unit("p")), Vec::new(), Duration::ZERO);
        gate.add_binary(&mut p);
        assert_eq!(run_index(next(&gate)), 0);
    }

    #[test]
    fn a_failure_blocks_a_dependent_that_arrives_after_it() {
        let gate = KeelGate::streaming(options(false, KeelHistory::empty()));
        gate.expect_binaries([GroupId::unit("p"), GroupId::unit("r")]);
        let mut p = FedBinary::without_tests(Some(GroupId::unit("p")), Vec::new(), Duration::ZERO);
        p.nodes = vec![gate_node(node("rust:p::a", "unit(p)", &[]), 0, 0)];
        gate.add_binary(&mut p);
        let a = run_index(next(&gate));
        let announcement = gate.record(a, ran(Status::Fail));
        assert!(
            announcement.is_some(),
            "a root is announced when it is final"
        );

        let mut r = FedBinary::without_tests(Some(GroupId::unit("r")), Vec::new(), Duration::ZERO);
        r.nodes = vec![gate_node(node("rust:r::b", "unit(r)", &["unit(p)"]), 1, 1)];
        gate.add_binary(&mut r);
        match next(&gate) {
            NextGated::Item(Gated::Blocked(1, by)) => {
                assert_eq!(by, [NodeId::new("rust:p::a")]);
            }
            other => panic!("expected b to be blocked, got {other:?}"),
        }
    }

    #[test]
    fn only_a_root_is_announced() {
        let gate = gate_of(two_chains(), &[], true);
        let (a, d) = (run_index(next(&gate)), run_index(next(&gate)));
        assert!(gate.record(d, ran(Status::Pass)).is_none());
        assert!(gate.record(a, ran(Status::Fail)).is_some());
        let (b, _c) = (run_index(next(&gate)), run_index(next(&gate)));
        assert!(
            gate.record(b, ran(Status::Fail)).is_none(),
            "a failure that stands on a root is a symptom, not a root"
        );
    }

    #[test]
    fn ready_tests_are_taken_failed_first_then_by_level_duration_and_priority() {
        let mut entries = Vec::new();
        for (id, failed, duration_ms) in [
            ("rust:x::slow", false, 900),
            ("rust:x::quick", false, 5),
            ("rust:x::broken", true, 5000),
        ] {
            entries.push((
                id.to_owned(),
                crate::keel::history::HistoryEntry {
                    failed,
                    duration_ms,
                },
            ));
        }
        let history = KeelHistory::empty().with_executed(entries);
        let gate = KeelGate::streaming(options(false, history));
        let mut binary = FedBinary::without_tests(None, Vec::new(), Duration::ZERO);
        binary.nodes = vec![
            gate_node(node("rust:x::slow", "unit(x)", &[]), 0, 0),
            gate_node(node("rust:x::quick", "unit(x)", &[]), 0, 1),
            gate_node(node("rust:x::broken", "unit(x)", &[]), 0, 2),
            gate_node(node("rust:x::unseen", "unit(x)", &[]), 0, 3),
            gate_node(node("rust:y::deep", "unit(y)", &["unit(x)"]), 1, 4),
        ];
        gate.add_binary(&mut binary);
        let order: Vec<usize> = (0..4).map(|_| run_index(next(&gate))).collect();
        assert_eq!(
            order,
            [2, 3, 1, 0],
            "the test that failed last time, then the one never seen, then by duration"
        );
    }

    #[test]
    fn the_gate_reports_a_stall_instead_of_waiting_forever() {
        let nodes = vec![
            node("rust:p::a", "unit(p)", &["unit(q)"]),
            node("rust:q::b", "unit(q)", &["unit(p)"]),
        ];
        let plan = Plan::new(&nodes);
        assert!(plan.is_err(), "a cycle is a plan error in a batch run");

        let gate = KeelGate::streaming(options(false, KeelHistory::empty()));
        let mut binary = FedBinary::without_tests(None, Vec::new(), Duration::ZERO);
        binary.nodes = nodes
            .into_iter()
            .enumerate()
            .map(|(i, n)| gate_node(n, 0, i as u64))
            .collect();
        gate.add_binary(&mut binary);
        assert!(matches!(next(&gate), NextGated::Pending));
        gate.seal();
        assert!(matches!(next(&gate), NextGated::Stalled));
        assert_eq!(gate.finish().stalled.len(), 2);
    }

    #[test]
    fn a_node_that_stands_on_its_own_group_waits_for_the_others() {
        let nodes = vec![
            node("rust:p::a", "unit(p)", &["unit(p)"]),
            node("rust:p::b", "unit(p)", &[]),
        ];
        let gate = KeelGate::streaming(options(false, KeelHistory::empty()));
        let mut binary = FedBinary::without_tests(None, Vec::new(), Duration::ZERO);
        binary.nodes = nodes
            .into_iter()
            .enumerate()
            .map(|(i, n)| gate_node(n, 0, i as u64))
            .collect();
        gate.add_binary(&mut binary);
        gate.seal();
        assert_eq!(run_index(next(&gate)), 1, "b has nothing to wait for");
        assert!(matches!(next(&gate), NextGated::Pending));
        gate.record(1, ran(Status::Pass));
        assert_eq!(run_index(next(&gate)), 0);
    }

    #[test]
    fn a_node_waits_for_a_declared_node_that_arrives_later() {
        let gate = KeelGate::streaming(options(false, KeelHistory::empty()));
        let mut first = FedBinary::without_tests(None, Vec::new(), Duration::ZERO);
        first.nodes = vec![gate_node(
            node("rust:r::b", "unit(r)", &["rust:p::a"]),
            1,
            0,
        )];
        gate.add_binary(&mut first);
        assert!(matches!(next(&gate), NextGated::Pending));

        let mut second = FedBinary::without_tests(None, Vec::new(), Duration::ZERO);
        second.nodes = vec![gate_node(node("rust:p::a", "unit(p)", &[]), 0, 1)];
        gate.add_binary(&mut second);
        assert_eq!(run_index(next(&gate)), 1);
        assert!(matches!(next(&gate), NextGated::Pending));
        gate.record(1, ran(Status::Pass));
        assert_eq!(run_index(next(&gate)), 0);
    }
}
