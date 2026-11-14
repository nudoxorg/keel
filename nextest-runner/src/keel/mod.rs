// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The nextest side of the Keel incremental, hierarchical test framework.
//!
//! Keel places every test on a node with an input key and a set of nodes it
//! stands on. A test runs only if no stored pass exists for its key, only after
//! everything it stands on is terminal, and not at all if a root it stands on
//! failed. See `DESIGN.md` in the Keel repository.
//!
//! None of this is active unless `--keel` is passed: without it, the runner
//! behaves exactly like upstream nextest.
//!
//! # Running while Cargo builds
//!
//! The tests of a binary are listed, keyed and scheduled as soon as Cargo
//! reports the binary, while the rest of the workspace is still compiling (see
//! [`KeelStreamPlanner`], [`KeelFeed`] and [`KeelGate`]). What a test stands on
//! is a set of groups, and a group is complete only when every binary expected
//! to contribute members has been added and every member is terminal. The
//! binaries expected are predicted from the package graph and the build scope
//! before the build starts ([`predict_test_binaries`]), with a bias towards too
//! many: a predicted binary that Cargo never builds delays the groups it
//! belongs to until Cargo exits, and never makes a group look complete too early.
//!
//! # Order of ready tests
//!
//! When more tests are ready than there are slots, the next test is the one
//! that is smallest under this order, from most to least significant:
//!
//! 1. Tests that failed in the most recent run that executed them. The index is
//!    `last-status.json`, next to the result store (by default
//!    `.local/keel/last-status.json`; see [`KeelHistory`]), is keyed by node ID
//!    and not by key, and is written at the end of each run. A test that failed
//!    before it was edited is therefore tried first after the edit.
//! 2. The lowest topological level. A foundation runs before what stands on it,
//!    and its failure blocks the most. The level is exact for a run planned
//!    before it starts; for a streamed run it is the length of the longest
//!    chain of workspace dependencies under the test's package, plus the levels
//!    that declared edges add.
//! 3. The shortest duration the index records for the test. A test with no
//!    recorded duration counts as zero, so a new test runs before tests whose
//!    cost is known: it is the more likely to be the one that changed.
//! 4. Nextest's own priority (`priority` in the profile overrides), then the
//!    order in which nextest lists the tests.
//!
//! The order only chooses among tests that are ready. A test is never ready
//! before everything it stands on is terminal, whatever its rank.
//!
//! # Early verdict
//!
//! A failure is announced when it is final, which is when its last retry
//! has finished: the root block is printed then, not at the end of the run. With
//! `--keel-fail-fast-verdict` the run is cancelled at that moment, and tests that
//! the cancellation terminates are not recorded as failures.

mod config;
mod feed;
mod gate;
mod history;
mod keyer;
mod plan;
mod scope;
mod session;
mod setup;

pub use config::{
    DEFAULT_KEEL_CONFIG_PATH, DEFAULT_KEEL_STORE_DIR, KEEL_CONFIG_SCHEMA, KeelConfig,
};
pub use feed::{FedBinary, KeelFeed};
pub use gate::{GateOptions, KeelGate};
pub(crate) use gate::{ReadyStream, ReadyTest};
pub use history::KeelHistory;
pub use keyer::{BinaryCodeKeys, CodeKeyer, ExecutableKeyer, TestCodeKey};
pub use plan::{KeelPlan, KeelPlanInputs, KeelStreamPlanner};
pub use scope::{ExpectedBinary, predict_test_binaries};
pub use session::{KeelFinish, KeelReportOptions, KeelRunFacts, KeelSession, KeelTimings};
pub use setup::{KeelSettings, KeelSetup};
