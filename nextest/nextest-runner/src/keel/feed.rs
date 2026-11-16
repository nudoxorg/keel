// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The channel through which tests reach the scheduler while Cargo is still
//! building.
//!
//! A producer, which lists and keys each test binary as Cargo reports it, pushes
//! one [`FedBinary`] per binary and closes the feed when Cargo has exited and
//! every binary has been pushed. The consumer is the [`ReadyStream`], which
//! hands the nodes to the gate and holds the test instances until the gate says
//! they may run.
//!
//! Nodes and instances travel together, in one message, so that the gate never
//! knows a node whose instance the stream does not yet have.
//!
//! [`ReadyStream`]: super::gate::ReadyStream

use super::gate::GateNode;
use crate::list::TestInstanceWithSettings;
use keel::GroupId;
use std::{
    sync::{Arc, Mutex, MutexGuard},
    task::Waker,
    time::Duration,
};

/// The tests of one test binary, ready for the scheduler.
#[derive(Debug)]
pub struct FedBinary<'a> {
    /// The group the binary was expected to belong to, if it was expected.
    ///
    /// The scheduler counts the binary off against this group once its nodes are
    /// registered, so the group is complete when every expected binary has been
    /// counted off and every member is terminal.
    pub(crate) expected: Option<GroupId>,

    /// The nodes of the binary's selected tests.
    pub(crate) nodes: Vec<GateNode>,

    /// The instance of each node, by its position in `nodes`.
    pub(crate) tests: Vec<(usize, TestInstanceWithSettings<'a>)>,

    /// Tests that are not planned, because the filter excludes them. The runner
    /// reports them as skipped.
    pub(crate) unplanned: Vec<TestInstanceWithSettings<'a>>,

    /// How long listing the binary's keys took.
    pub(crate) key_time: Duration,
}

impl<'a> FedBinary<'a> {
    /// Returns a binary with no tests to schedule.
    pub(crate) fn without_tests(
        expected: Option<GroupId>,
        unplanned: Vec<TestInstanceWithSettings<'a>>,
        key_time: Duration,
    ) -> Self {
        Self {
            expected,
            nodes: Vec::new(),
            tests: Vec::new(),
            unplanned,
            key_time,
        }
    }
}

#[derive(Debug)]
struct FeedState<'a> {
    binaries: Vec<FedBinary<'a>>,
    closed: bool,
    waker: Option<Waker>,
}

/// The tests that have been keyed so far and are waiting for the scheduler.
#[derive(Debug)]
pub struct KeelFeed<'a> {
    state: Mutex<FeedState<'a>>,
}

/// What the scheduler takes from the feed.
#[derive(Debug)]
pub(crate) struct Drained<'a> {
    pub(crate) binaries: Vec<FedBinary<'a>>,
    pub(crate) closed: bool,
}

impl<'a> KeelFeed<'a> {
    /// Creates an open, empty feed.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FeedState {
                binaries: Vec::new(),
                closed: false,
                waker: None,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, FeedState<'a>> {
        self.state.lock().expect("keel feed lock is never poisoned")
    }

    /// Hands the tests of a binary to the scheduler.
    pub fn push(&self, binary: FedBinary<'a>) {
        let waker = {
            let mut state = self.lock();
            state.binaries.push(binary);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Closes the feed: no more binaries will come.
    pub fn close(&self) {
        let waker = {
            let mut state = self.lock();
            state.closed = true;
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Takes everything pushed so far, and arranges for `waker` to be woken when
    /// more arrives.
    ///
    /// `closed` is true once the feed is closed and everything pushed has been
    /// taken.
    pub(crate) fn drain(&self, waker: &Waker) -> Drained<'a> {
        let mut state = self.lock();
        let binaries = std::mem::take(&mut state.binaries);
        if !state.closed {
            state.waker = Some(waker.clone());
        }
        Drained {
            binaries,
            closed: state.closed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::Wake,
    };

    struct Counter(AtomicUsize);

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn binary() -> FedBinary<'static> {
        FedBinary::without_tests(None, Vec::new(), Duration::ZERO)
    }

    #[test]
    fn a_push_wakes_the_consumer_that_drained_last_and_a_drain_takes_everything() {
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let feed = KeelFeed::new();

        let first = feed.drain(&waker);
        assert!(first.binaries.is_empty());
        assert!(!first.closed);

        feed.push(binary());
        feed.push(binary());
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            1,
            "one wake: the consumer is woken once and then drains everything"
        );
        let second = feed.drain(&waker);
        assert_eq!(second.binaries.len(), 2);
        assert!(feed.drain(&waker).binaries.is_empty());
    }

    #[test]
    fn closing_wakes_the_consumer_and_is_seen_after_the_last_binary() {
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let feed = KeelFeed::new();
        feed.drain(&waker);
        feed.push(binary());
        feed.close();
        let drained = feed.drain(&waker);
        assert_eq!(
            drained.binaries.len(),
            1,
            "a binary pushed before close is kept"
        );
        assert!(drained.closed);
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    }
}
