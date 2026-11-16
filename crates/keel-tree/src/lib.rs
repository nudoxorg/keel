//! Keel tree: the product model, the code index and the inference core,
//! joined and made to answer questions about one repository.

pub mod boundaries;
pub mod changes;
pub mod check;
pub mod comment;
pub mod coverage;
pub mod driver;
pub mod emit;
pub mod enforce;
pub mod explain;
#[cfg(test)]
mod fixtures;
pub mod finding;
pub mod from_crates;
pub mod lock;
pub mod model;
pub mod parts;
pub mod pattern;
pub mod plan;
pub mod resolve;
pub mod source;
pub mod tree;
pub mod verdict;
pub mod watch;
#[cfg(test)]
mod tests;
pub mod testset;
#[cfg(test)]
mod tests_from_crates;
#[cfg(test)]
mod tests_git;
#[cfg(test)]
mod tests_report;
pub mod text;
