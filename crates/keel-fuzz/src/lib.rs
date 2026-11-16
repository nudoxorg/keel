//! keel-fuzz: gate-mode replay and idle-mode exploration of libFuzzer-ABI targets.
//!
//! The target contract is the libFuzzer ABI (`LLVMFuzzerTestOneInput`), packaged as a
//! shared library. Coverage is LLVM SanitizerCoverage from both Rust and C in one
//! edge space. The exploration engine is LibAFL; everything deterministic (replay,
//! cmin, tmin, coverage export) is ours and does not need an engine.

pub mod dedup;
pub mod events;
pub mod explore;
pub mod ops;
pub mod runner;
pub mod sancov;
pub mod store;
pub mod symbols;
pub mod target;
