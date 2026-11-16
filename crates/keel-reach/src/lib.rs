//! Per-test reach keys from link inputs: see DESIGN.md section 3.2.

pub mod atoms;
pub mod cache;
pub mod compare;
pub mod elf;
pub mod entry;
pub mod fallback;
pub mod graph;
pub mod link;
pub mod load;
pub mod macho;
pub mod model;
pub mod query;
pub mod reach;
pub mod record;
pub mod report;
pub mod shim;
pub mod store;

pub use fallback::{Culprit, Fallback, Via};
pub use load::Loader;
pub use reach::{Options, analyze, analyze_record};
pub use record::LinkInputs;
pub use report::{
    AtomId, AtomInfo, AtomTable, Atoms, BinaryReach, EntrySource, Stats, TestReach, intersects,
};
