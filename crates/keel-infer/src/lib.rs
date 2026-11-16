//! Inference core of the Keel test framework: pure algorithms over bitmaps.
//!
//! No IO, no clocks, no randomness. The same inputs give the same outputs bit
//! for bit, whatever the thread count; every tie is broken by the smaller index.
//!
//! * [`explain`] describes a set of failures with the fewest attributes.
//! * [`plan`] orders tests by expected doubt removed per millisecond and keeps
//!   a belief per changed unit as results arrive.

pub mod explain;
pub mod plan;

pub use explain::{
    Attr, AttrId, Cause, ExplainError, ExplainOptions, Explanation, Universe, explain,
};
pub use plan::{PlanError, Planner, Step, TestModel, Unit, UnitId};
pub use roaring::RoaringBitmap;

/// A test's position in the suite, `0..tests`. Shared by both halves.
pub type TestId = u32;
