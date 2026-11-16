// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The index of how each test fared in the most recent run that executed it.
//!
//! The scheduler orders ready tests by this index (see the module documentation
//! of [`crate::keel`]). It is a cache: the result store stays the only source
//! of truth about passes, and a missing, unreadable or outdated index costs
//! scheduling quality, never correctness.
//!
//! The index lives next to the result store, in `last-status.json` (by default,
//! `.local/keel/last-status.json`). It is keyed by node ID and not by key, so a
//! test that failed before it was edited is still scheduled first after the edit.

use crate::errors::KeelError;
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Write as _};
use tracing::warn;

/// The schema of `last-status.json`.
const HISTORY_SCHEMA: u32 = 1;

/// The file name of the index, next to the result store directory.
pub(crate) const HISTORY_FILE_NAME: &str = "last-status.json";

/// How a test fared the last time it was executed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct HistoryEntry {
    /// Whether the test failed, timed out or could not run.
    pub(crate) failed: bool,

    /// How long the test took, in milliseconds.
    pub(crate) duration_ms: u64,
}

/// The on-disk form of the index.
#[derive(Debug, Deserialize, Serialize)]
struct HistoryFile {
    schema: u32,
    nodes: BTreeMap<String, HistoryFileEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct HistoryFileEntry {
    status: HistoryStatus,
    duration_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum HistoryStatus {
    Pass,
    Fail,
}

/// The index of the last executed status and duration of each node.
#[derive(Clone, Debug, Default)]
pub struct KeelHistory {
    path: Option<Utf8PathBuf>,
    entries: BTreeMap<String, HistoryEntry>,
}

impl KeelHistory {
    /// Returns an empty index that is never written.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Reads the index at `path`.
    ///
    /// A file that does not exist, cannot be read or has another schema gives
    /// an empty index; the last two are logged.
    pub fn load(path: &Utf8Path) -> Self {
        let entries = match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<HistoryFile>(&bytes) {
                Ok(file) if file.schema == HISTORY_SCHEMA => file
                    .nodes
                    .into_iter()
                    .map(|(id, entry)| {
                        (
                            id,
                            HistoryEntry {
                                failed: entry.status == HistoryStatus::Fail,
                                duration_ms: entry.duration_ms,
                            },
                        )
                    })
                    .collect(),
                Ok(file) => {
                    warn!(
                        "ignoring the Keel history at `{path}`: it has schema {} and this build \
                         reads schema {HISTORY_SCHEMA}",
                        file.schema
                    );
                    BTreeMap::new()
                }
                Err(error) => {
                    warn!("ignoring the unreadable Keel history at `{path}`: {error}");
                    BTreeMap::new()
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => {
                warn!("ignoring the unreadable Keel history at `{path}`: {error}");
                BTreeMap::new()
            }
        };
        Self {
            path: Some(path.to_owned()),
            entries,
        }
    }

    /// Returns how the node last fared, if it was ever executed.
    pub(crate) fn get(&self, id: &str) -> Option<HistoryEntry> {
        self.entries.get(id).copied()
    }

    /// Returns the number of nodes in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the index holds no nodes.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the index with `executed` folded in: each executed node replaces
    /// its entry, and every other node keeps the one it had.
    pub(crate) fn with_executed(
        &self,
        executed: impl IntoIterator<Item = (String, HistoryEntry)>,
    ) -> Self {
        let mut entries = self.entries.clone();
        entries.extend(executed);
        Self {
            path: self.path.clone(),
            entries,
        }
    }

    /// Writes the index to the path it was loaded from, if any.
    ///
    /// The file is replaced atomically, so a reader sees the old index or the new
    /// one.
    pub(crate) fn write(&self) -> Result<(), KeelError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = HistoryFile {
            schema: HISTORY_SCHEMA,
            nodes: self
                .entries
                .iter()
                .map(|(id, entry)| {
                    (
                        id.clone(),
                        HistoryFileEntry {
                            status: if entry.failed {
                                HistoryStatus::Fail
                            } else {
                                HistoryStatus::Pass
                            },
                            duration_ms: entry.duration_ms,
                        },
                    )
                })
                .collect(),
        };
        let write_error = |error| KeelError::HistoryWrite {
            path: path.clone(),
            error,
        };
        let json = serde_json::to_vec(&file).map_err(KeelError::ReportSerialize)?;
        if let Some(parent) = path.parent().filter(|parent| !parent.as_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(write_error)?;
        }
        let temp = path.with_extension(format!("tmp-{}", std::process::id()));
        let result = std::fs::File::create(&temp)
            .and_then(|mut file| file.write_all(&json))
            .and_then(|()| std::fs::rename(&temp, path));
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result.map_err(write_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> camino_tempfile::Utf8TempDir {
        camino_tempfile::tempdir().expect("created a temporary directory")
    }

    #[test]
    fn a_missing_index_is_empty() {
        let dir = temp_dir();
        let history = KeelHistory::load(&dir.path().join(HISTORY_FILE_NAME));
        assert!(history.is_empty());
    }

    #[test]
    fn executed_nodes_replace_their_entry_and_others_are_kept() {
        let dir = temp_dir();
        let path = dir.path().join(HISTORY_FILE_NAME);
        let first = KeelHistory::load(&path).with_executed([
            (
                "rust:a::x".to_owned(),
                HistoryEntry {
                    failed: true,
                    duration_ms: 40,
                },
            ),
            (
                "rust:a::y".to_owned(),
                HistoryEntry {
                    failed: false,
                    duration_ms: 7,
                },
            ),
        ]);
        first.write().expect("wrote the index");

        let second = KeelHistory::load(&path);
        assert_eq!(second.len(), 2);
        assert!(second.get("rust:a::x").expect("entry").failed);

        let third = second.with_executed([(
            "rust:a::x".to_owned(),
            HistoryEntry {
                failed: false,
                duration_ms: 41,
            },
        )]);
        assert!(!third.get("rust:a::x").expect("entry").failed);
        assert_eq!(third.get("rust:a::y").expect("kept").duration_ms, 7);
    }

    #[test]
    fn an_unreadable_or_foreign_index_is_ignored() {
        let dir = temp_dir();
        let path = dir.path().join(HISTORY_FILE_NAME);
        std::fs::write(&path, b"not json").expect("wrote the file");
        assert!(KeelHistory::load(&path).is_empty());
        std::fs::write(&path, br#"{"schema": 99, "nodes": {}}"#).expect("wrote the file");
        assert!(KeelHistory::load(&path).is_empty());
    }
}
