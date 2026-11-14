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

mod config;
mod gate;
mod keyer;
mod plan;
mod session;
mod setup;

pub use config::{
    DEFAULT_KEEL_CONFIG_PATH, DEFAULT_KEEL_STORE_DIR, KEEL_CONFIG_SCHEMA, KeelConfig,
};
pub use gate::KeelGate;
pub(crate) use gate::{ReadyStream, ReadyTest};
pub use keyer::{BinaryCodeKeys, CodeKeyer, ExecutableKeyer, TestCodeKey};
pub use plan::{KeelPlan, KeelPlanInputs};
pub use session::{KeelFinish, KeelReportOptions, KeelRunFacts, KeelSession};
pub use setup::{KeelSettings, KeelSetup};
