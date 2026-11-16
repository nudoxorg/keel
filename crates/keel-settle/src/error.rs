//! Input that cannot be judged. It exits 2; a judgement of well-formed input never does.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("cannot read {path}: {source}. Check the path, and that the file was written by keel-tree (plan) or the producer (executed list).")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("cannot write {path}: {source}. Check that the directory exists and is writable.")]
    Write { path: PathBuf, source: std::io::Error },
    #[error("{path}:{line}: {what}. {advice}")]
    Malformed { path: PathBuf, line: usize, what: String, advice: &'static str },
    #[error("{0}")]
    Other(String),
}

pub const REGENERATE_PLAN: &str = "Regenerate it with `keel-tree plan --emit`.";
pub const RERUN_PRODUCER: &str = "Rerun the producer; do not repair an executed list by hand.";
