//! The executed list as a file (design/ir.md 7.3, 11): JSON lines.
//!
//! Line 1 names the plan. A `Listed` line per binary carries every name the binary's own
//! `--list` printed. A `Record` line per unit follows as the unit finishes. There is no
//! status for "skipped": a unit with no outcome has no line.

use crate::digest::Digest;
use crate::error::{InputError, RERUN_PRODUCER};
use crate::plan::Binary;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The seven statuses of design/ir.md 7.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Pass,
    Fail,
    Timeout,
    Hung,
    Blocked,
    Flaky,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Source {
    Ran { attempt: u32, duration_ms: u64 },
    Reused { record: Digest },
}

/// How the process ended, when it was a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ended {
    Exit(i32),
    Signal(i32),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub binary: Binary,
    pub name: String,
    pub status: Status,
    pub source: Source,
    /// Not in design/ir.md 11's `{ binary, name, status, source }`: what a person needs to
    /// tell a failed test from a crashed one without opening a log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<Ended>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listed {
    pub binary: Binary,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub plan: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Line {
    Listed(Listed),
    Record(Record),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Executed {
    pub plan: Digest,
    pub listed: Vec<Listed>,
    pub records: Vec<Record>,
    /// Bytes of a final line that has no newline and is not a whole line: the writer was
    /// stopped mid-write. Reported, never guessed at.
    pub torn_tail: Option<usize>,
}

impl Executed {
    pub fn read(path: &Path) -> Result<Executed, InputError> {
        let bytes = std::fs::read(path).map_err(|source| InputError::Read { path: path.to_owned(), source })?;
        Executed::parse(&bytes).map_err(|(line, what)| InputError::Malformed { path: path.to_owned(), line, what, advice: RERUN_PRODUCER })
    }

    /// `Err((line, what))` for input that is not an executed list at all.
    pub fn parse(bytes: &[u8]) -> Result<Executed, (usize, String)> {
        let mut segments: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
        // `split` yields an empty last segment after a final newline; otherwise the last
        // segment is a line the writer did not finish, or finished without a newline.
        let tail = segments.pop().filter(|s| !s.is_empty());
        let mut lines: Vec<(usize, &[u8])> = segments.into_iter().enumerate().map(|(i, s)| (i + 1, s)).collect();
        let tail_no = lines.len() + 1;
        let mut torn_tail = None;
        if let Some(t) = tail {
            if serde_json::from_slice::<serde_json::Value>(t).is_ok() {
                lines.push((tail_no, t));
            } else if lines.is_empty() {
                return Err((1, "the first line (the plan digest) is cut short; the producer stopped before it finished writing the header".to_owned()));
            } else {
                torn_tail = Some(t.len());
            }
        }
        let Some(&(_, first)) = lines.first() else {
            return Err((1, "the file is empty: it has no first line naming the plan".to_owned()));
        };
        let header: Header = serde_json::from_slice(first).map_err(|e| (1, format!("the first line must be {{\"plan\":\"<digest>\"}}: {e}")))?;
        let mut out = Executed { plan: header.plan, listed: Vec::new(), records: Vec::new(), torn_tail };
        for &(no, raw) in &lines[1..] {
            if raw.is_empty() {
                return Err((no, "blank line".to_owned()));
            }
            match serde_json::from_slice::<Line>(raw).map_err(|e| (no, format!("not a Listed or Record line: {e}")))? {
                Line::Listed(l) => out.listed.push(l),
                Line::Record(r) => out.records.push(r),
            }
        }
        Ok(out)
    }
}
