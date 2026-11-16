//! Thin wrappers over the `git` binary. The index reads git-tracked content
//! only, so untracked build output and vendored scratch never leak in.

use crate::error::IndexError;
use std::path::Path;
use std::process::{Command, Output};

pub fn run(root: &Path, args: &[&str]) -> Result<Output, IndexError> {
    let command = format!("git {}", args.join(" "));
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|source| IndexError::Spawn {
            command: command.clone(),
            dir: root.to_path_buf(),
            source,
        })?;
    if !out.status.success() {
        return Err(IndexError::Git {
            command,
            dir: root.to_path_buf(),
            status: out.status.to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        });
    }
    Ok(out)
}

/// Tracked `*.rs` paths relative to `root`, sorted and deduplicated.
pub fn ls_rs_files(root: &Path) -> Result<Vec<String>, IndexError> {
    let out = run(root, &["ls-files", "-z", "--", "*.rs"])?;
    let mut v: Vec<String> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    v.sort();
    v.dedup();
    Ok(v)
}
