//! Plan, executed list and settling for one test binary (design/ir.md section 11, slice 1).
//!
//! The plan is what must have a result; the executed list is what the runner says happened;
//! `settle` compares them and is the only code that says Pass. Nothing here reads a test
//! report, a store or a model.

pub mod digest;
pub mod error;
pub mod executed;
pub mod plan;
pub mod producer;
pub mod settle;

pub use digest::Digest;
pub use error::InputError;
pub use executed::{Ended, Executed, Header, Line, Listed, Record, Source, Status};
pub use plan::{Binary, BinaryKind, Disposition, GitOid, Plan, Selected, Unit, What};
pub use settle::{Cap, Failure, Reason, Report, Verdict, settle};
