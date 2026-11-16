//! The Keel result-store service (DESIGN.md §6) and its client.
//!
//! The service is an HTTP front for the filesystem CAS that
//! [`keel::store::LocalStore`] already defines, so a directory written by the
//! service is readable by the local tooling and the other way round. Writes
//! need the writer token; reads need the read token (or the writer token), except
//! `/v1/health` (§6).
//!
//! Cargo features: `server` (the service, gc and the `keel-store` binary) and
//! `client` (the blocking [`client::Client`]). The runner takes only `client`.

pub mod job;
pub mod wire;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod conduct;
#[cfg(feature = "server")]
pub mod gc;
#[cfg(feature = "server")]
pub mod ingest;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod slot;
