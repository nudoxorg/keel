//! One error type for the whole crate. Every variant says what failed, what it
//! depends on, and what to do, because the callers are CI jobs where nobody is
//! watching a debugger.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error(
        "cannot run `{command}` in {dir}: {source}. The index needs `git` on PATH and a git checkout at the root; install git or pass the repository root with --root"
    )]
    Spawn {
        command: String,
        dir: PathBuf,
        source: std::io::Error,
    },

    #[error(
        "`{command}` failed in {dir} ({status}): {stderr}. Check that {dir} is a git checkout and that the revisions you named exist (a shallow clone lacks older revisions: fetch them first)"
    )]
    Git {
        command: String,
        dir: PathBuf,
        status: String,
        stderr: String,
    },

    #[error(
        "`cargo metadata` failed in {dir} ({detail}). The index reads workspace members, targets and path dependencies from `cargo metadata --offline --no-deps`, which needs a Cargo.lock and a workspace that resolves without network access: run `cargo generate-lockfile` (or `cargo fetch`) once while online, then retry"
    )]
    Metadata { dir: PathBuf, detail: String },

    #[error(
        "cannot read or write {path}: {source}. Check that the path exists and is writable by this user"
    )]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error(
        "cannot (de)serialise {what}: {source}. The file is probably from an incompatible keel-index version or truncated; rebuild it with `keel-index build`"
    )]
    Json {
        what: String,
        source: serde_json::Error,
    },

    #[error(
        "cannot build the worker thread pool: {0}. Reduce the thread count with RAYON_NUM_THREADS or free memory"
    )]
    Pool(String),
}

pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> IndexError {
    IndexError::Io {
        path: path.into(),
        source,
    }
}
