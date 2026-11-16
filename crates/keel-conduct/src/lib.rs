//! The Keel conductor: everything that is not a Rust test (DESIGN §8).
//!
//! Four node sources feed one `keel::Plan` (Go packages from `go list`,
//! nushell and command nodes and artifact producers from `keel.toml`, Nix
//! derivations), the scheduler runs what the result store cannot answer
//! behind the §2.6 gate, and `attest`/`verify` turn a report into signed,
//! offline-checkable evidence.
//!
//! It does not build or run Rust tests (the nextest fork does), does not
//! sandbox the processes it runs (the host units of §6.2 do), and does not
//! compute reach.

pub mod attest;
pub mod cmd;
pub mod config;
pub mod go;
pub mod model;
pub mod nix;
pub mod pins;
pub mod run;
pub mod store;
pub mod util;
