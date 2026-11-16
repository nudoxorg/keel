//! The machine-readable result: JSON lines, one event per line, appended as events
//! happen. Every event is a single `write` to an `O_APPEND` file, so a run killed
//! at any point leaves a file whose every complete line is valid, and the
//! supervisor and its restarted workers can share one file.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

pub const ENGINE_NAME: &str = "keel-fuzz";
/// The engine is LibAFL used as a library; its version is part of every result.
pub const LIBAFL_VERSION: &str = "0.16.1";

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

const T0_ENV: &str = "KEEL_FUZZ_T0_MS";

/// Writes events with a `t_ms` relative to the start of the whole run, which is
/// carried across restarts of the worker process in the environment.
pub struct EventLog {
    file: Option<File>,
    t0_ms: u64,
}

impl EventLog {
    /// Opens (appending) the log at `path`; `None` makes a log that drops events.
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let t0_ms = std::env::var(T0_ENV).ok().and_then(|v| v.parse().ok()).unwrap_or_else(|| {
            let now = now_ms();
            // SAFETY: called while the process is still single-threaded, before any worker is forked.
            unsafe { std::env::set_var(T0_ENV, now.to_string()) };
            now
        });
        let file = match path {
            Some(p) => {
                if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent)?;
                }
                Some(
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(p)
                        .with_context(|| format!("opening the result file {}: check that the directory is writable", p.display()))?,
                )
            }
            None => None,
        };
        Ok(Self { file, t0_ms })
    }

    pub fn elapsed_ms(&self) -> u64 {
        now_ms().saturating_sub(self.t0_ms)
    }

    pub fn emit<T: Serialize>(&self, event: &T) -> Result<()> {
        let Some(file) = &self.file else { return Ok(()) };
        let mut value = serde_json::to_value(event)?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("t_ms".into(), self.elapsed_ms().into());
        }
        let mut line = serde_json::to_vec(&value)?;
        line.push(b'\n');
        // `&File` implements Write; one write call per line keeps lines whole.
        (&*file).write_all(&line).context("appending to the result file")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn events_are_whole_lines_with_a_relative_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.jsonl");
        let log = EventLog::open(Some(&path)).unwrap();
        log.emit(&json!({"event": "a", "n": 1})).unwrap();
        log.emit(&json!({"event": "b"})).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], "a");
        assert!(lines[0]["t_ms"].is_u64());
    }

    #[test]
    fn a_second_handle_appends_instead_of_truncating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.jsonl");
        EventLog::open(Some(&path)).unwrap().emit(&json!({"event": "first"})).unwrap();
        EventLog::open(Some(&path)).unwrap().emit(&json!({"event": "second"})).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }
}
