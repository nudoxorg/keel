//! keel-judge: the idle-loop supervisor of design/doubt.md section 5.6, starting with its
//! fuzz share. It keeps libFuzzer targets running in quanta, chooses the next target by an
//! index, and records everything it observes so the index can be checked against reality.
//!
//! The only authoritative state is `<state>/quanta.jsonl` and `<state>/findings.jsonl`.

pub mod checks;
pub mod expect;
pub mod findings;
pub mod guidance;
pub mod metrics;
pub mod parse;
pub mod quantum;
pub mod related;
mod related_chain;
pub mod run;
pub mod sched;
pub mod state;
pub mod status;
pub mod targets;
pub mod util;
