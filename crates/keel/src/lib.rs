//! Keel core: the node graph, input keys, verdicts, report documents and the
//! local result store of the Keel test framework (see `DESIGN.md`).
//!
//! # What this crate does
//!
//! - Defines the vocabulary: [`NodeId`], [`GroupId`], [`PartId`], [`Node`],
//!   [`Inputs`], [`Policy`] and the two protocol documents, [`Manifest`]
//!   (runner to conductor) and [`Report`] (the run record). Both are strict on
//!   read: an unknown field is an error, except inside [`Platform`].
//! - Computes keys: [`key()`] over declared inputs, [`executable_key`] over a
//!   binary's loadable sections, [`files_key`] over declared runtime files and
//!   [`env_key`] over the environment contract; and builds the clean
//!   environment a test process receives, [`clean_environment`].
//! - Answers graph questions as pure functions: [`Plan`] (cycles, levels,
//!   group expansion) and [`Plan::blocked_by`] (the §2.5 blocking rule, by
//!   reach intersection when reach information exists and by group otherwise).
//! - Decides outcomes: [`roots`] and [`verdict`] (§2.4), [`Report::merge`]
//!   (§8.2).
//! - Stores results: [`LocalStore`], a filesystem [`ResultStore`].
//!
//! # What it does not do
//!
//! It does not run cargo or rustc, does not run or schedule tests, does not
//! compute reach (that is `keel-reach`), does not talk to a network and does
//! not read configuration. The nextest fork owns building and running Rust
//! tests, and the conductor owns everything that crosses a repository or a
//! machine boundary. Anything this crate touches on disk is a path it was
//! handed, plus the store directory.

pub mod digest;
pub mod env;
pub mod executable;
pub mod files;
pub mod graph;
pub mod key;
pub mod node;
pub mod report;
pub mod runner;
pub mod status;
pub mod store;

mod frame;
#[cfg(test)]
mod testutil;

pub use digest::{Digest, DigestParseError};
pub use env::{EnvContract, clean_environment, env_key};
pub use executable::{ExecutableKeyError, executable_key};
pub use files::{FileSpec, FilesError, files_key};
pub use graph::{Plan, PlanError, ReachInfo, SymbolId};
pub use key::{Domain, KEY_SCHEMA, Key, KeyError, NetMode, Platform, key};
pub use node::{
    CodeKind, Control, FilesInput, GroupId, GroupKind, Inputs, Kind, Node, NodeId, PartId,
    PartKind, Policy, Sensitivity, Upstream,
};
pub use report::{
    Attempt, Budget, Counts, Detail, Evidence, Flaky, Interaction, Manifest, MergeError, Record,
    Report, SCHEMA, Stages,
};
pub use runner::{Launch, Limits, RUNNER_PROTOCOL, Runner, RunnerSpec, SandboxProfile, Stdin};
pub use status::{
    CONTROL_DID_NOT_FAIL, RAN_NOTHING, Status, Verdict, roots, verdict, verdict_expecting,
};
pub use store::{LocalStore, ResultStore, StoreError, StoredPass, StoredRecord};
