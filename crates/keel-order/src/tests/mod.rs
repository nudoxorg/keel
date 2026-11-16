//! Tests live inside the crate because B1 to B3 look at the rule's pricing, which is not public.

mod bench;
mod bridge;
mod differential;
mod frequencies;
mod gates;
mod invariants;
mod quality;
mod reference;
mod reference_sim;
mod shared;
mod support;
mod ties;
