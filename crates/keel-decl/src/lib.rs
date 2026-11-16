//! The record format for test declarations stored in the `.keel` link
//! section, and the reader that extracts them from a built binary.
//!
//! `keel-macros` writes records at compile time; [`read_declarations`] reads
//! them back from the executable without running it. Both sides use this
//! crate for the layout and for entry validation, so they cannot drift.
//!
//! One record is
//!
//! ```text
//! <module_path>::<fn> NUL stands_on=<a,b,..> NUL joins=<c,d,..> NUL LF
//! ```
//!
//! Records are concatenated. The linker may pad between them with zero bytes,
//! so the decoder skips zeros at a record boundary and uses `LF` as the only
//! terminator. Keys may come in any order and an absent key is an empty list.

mod read;

use std::collections::HashMap;

pub use read::{ReadError, read_declarations};

/// Name of the section on ELF and PE/COFF.
pub const SECTION_NAME: &str = ".keel";
/// Mach-O segment that holds [`MACHO_SECTION_NAME`].
pub const MACHO_SEGMENT_NAME: &str = "__DATA";
/// Mach-O section name (Mach-O limits section names to 16 bytes).
pub const MACHO_SECTION_NAME: &str = "__keel";

const KEY_STANDS_ON: &str = "stands_on";
const KEY_JOINS: &str = "joins";

/// One test's declared edges.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Declaration {
    /// `module_path!()` at the test function, crate root included.
    pub module_path: String,
    pub test_fn: String,
    /// Upstream groups or nodes: `unit(x)`, `integration(x)` or a node id.
    pub stands_on: Vec<String>,
    /// Crates whose interaction this test covers.
    pub joins: Vec<String>,
}

/// A [`Declaration`] that cannot be encoded without corrupting the section.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "cannot encode declaration {name}: {reason}. The record format reserves NUL, newline and, \
     inside list entries, comma; rename the offending item"
)]
pub struct InvalidDeclaration {
    pub name: String,
    pub reason: String,
}

/// Why a section could not be decoded. Offsets are byte offsets into the
/// section bytes handed to [`decode_section`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error(
        "keel section: the record starting at byte offset {offset} has no terminating newline. \
         The section is cut short or was not written by keel-macros; rebuild the test binary, and \
         if it persists check whether a post-link tool truncated the section"
    )]
    TruncatedRecord { offset: usize },

    #[error(
        "keel section: the record starting at byte offset {offset} is malformed: {reason}. The \
         section was not written by this version of keel-macros; rebuild the test binary with the \
         keel-macros that matches keel-decl"
    )]
    MalformedRecord { offset: usize, reason: String },

    #[error(
        "keel section: {name} is declared twice with different edges (byte offsets {first} and \
         {second}). Keeping one would silently drop edges; give the two functions distinct names \
         or remove the stale attribute"
    )]
    ConflictingRecords {
        name: String,
        first: usize,
        second: usize,
    },
}

impl Declaration {
    /// Checks that every field survives an encode/decode round trip.
    pub fn check(&self) -> Result<(), InvalidDeclaration> {
        let name = format!("{}::{}", self.module_path, self.test_fn);
        let bad = |reason: String| InvalidDeclaration {
            name: name.clone(),
            reason,
        };
        if self.module_path.is_empty() || self.test_fn.is_empty() {
            return Err(bad("module path and function name must be non-empty".into()));
        }
        if self.test_fn.contains("::") {
            return Err(bad(
                "the function name contains `::`, so the module path could not be recovered".into(),
            ));
        }
        for field in [&self.module_path, &self.test_fn] {
            if field.contains(['\0', '\n']) {
                return Err(bad(format!(
                    "`{}` contains NUL or newline",
                    field.escape_debug()
                )));
            }
        }
        for (key, list) in [(KEY_STANDS_ON, &self.stands_on), (KEY_JOINS, &self.joins)] {
            for entry in list {
                if entry.is_empty() || entry.contains(['\0', '\n', ',']) {
                    return Err(bad(format!(
                        "{key} entry `{}` is empty or contains NUL, newline or comma",
                        entry.escape_debug()
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Everything in a record after the name: `NUL stands_on=.. NUL joins=.. NUL LF`.
///
/// The macro cannot know `module_path!()` at expansion time, so it builds the
/// record as `concat!(module_path!(), "::", fn, <this>)`. Entries must already
/// be valid (see [`validate_stands_on`], [`validate_join`]).
pub fn encode_tail<S: AsRef<str>>(stands_on: &[S], joins: &[S]) -> String {
    let list = |l: &[S]| l.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(",");
    format!(
        "\0{KEY_STANDS_ON}={}\0{KEY_JOINS}={}\0\n",
        list(stands_on),
        list(joins)
    )
}

/// Encodes one record, or says why the declaration cannot be represented.
pub fn try_encode(decl: &Declaration) -> Result<String, InvalidDeclaration> {
    decl.check()?;
    Ok(format!(
        "{}::{}{}",
        decl.module_path,
        decl.test_fn,
        encode_tail(&decl.stands_on, &decl.joins)
    ))
}

/// Encodes one record.
///
/// # Panics
/// If the declaration fails [`Declaration::check`]; use [`try_encode`] for
/// input that is not already known to be valid.
pub fn encode(decl: &Declaration) -> String {
    try_encode(decl).unwrap_or_else(|e| panic!("{e}"))
}

/// Splits a section into declarations.
///
/// Tolerates zero padding at record boundaries and drops exact duplicate
/// records, keeping the first. A record cut off before its newline is an
/// error naming its offset. Two records for the same function with different
/// edges are an error, because keeping either would drop declared edges.
pub fn decode_section(bytes: &[u8]) -> Result<Vec<Declaration>, DecodeError> {
    let mut out = Collector::default();
    out.decode(bytes)?;
    Ok(out.into_decls())
}

/// Accumulates declarations from one or more sections, deduplicating.
#[derive(Default)]
pub(crate) struct Collector {
    decls: Vec<Declaration>,
    first_seen: HashMap<(String, String), (usize, usize)>,
}

impl Collector {
    pub(crate) fn into_decls(self) -> Vec<Declaration> {
        self.decls
    }

    pub(crate) fn decode(&mut self, bytes: &[u8]) -> Result<(), DecodeError> {
        let mut pos = 0;
        while pos < bytes.len() {
            if bytes[pos] == 0 {
                pos += 1;
                continue;
            }
            let start = pos;
            let Some(len) = bytes[start..].iter().position(|&b| b == b'\n') else {
                return Err(DecodeError::TruncatedRecord { offset: start });
            };
            let decl = parse_record(&bytes[start..start + len], start)?;
            self.push(decl, start)?;
            pos = start + len + 1;
        }
        Ok(())
    }

    fn push(&mut self, decl: Declaration, offset: usize) -> Result<(), DecodeError> {
        let key = (decl.module_path.clone(), decl.test_fn.clone());
        match self.first_seen.get(&key) {
            None => {
                self.first_seen.insert(key, (self.decls.len(), offset));
                self.decls.push(decl);
            }
            Some(&(idx, _)) if self.decls[idx] == decl => {}
            Some(&(_, first)) => {
                return Err(DecodeError::ConflictingRecords {
                    name: format!("{}::{}", decl.module_path, decl.test_fn),
                    first,
                    second: offset,
                });
            }
        }
        Ok(())
    }
}

/// `body` is one record without its newline: `name NUL k=v NUL k=v NUL`.
fn parse_record(body: &[u8], offset: usize) -> Result<Declaration, DecodeError> {
    let bad = |reason: String| DecodeError::MalformedRecord { offset, reason };
    let Some(body) = body.strip_suffix(&[0]) else {
        return Err(bad(
            "the record does not end with a NUL before its newline".into()
        ));
    };
    let mut segments = body
        .split(|&b| b == 0)
        .map(|s| std::str::from_utf8(s).map_err(|_| bad("a field is not valid UTF-8".into())));
    let name = segments
        .next()
        .expect("split yields at least one segment")?;
    let (module_path, test_fn) = match name.rsplit_once("::") {
        Some((m, f)) if !m.is_empty() && !f.is_empty() => (m, f),
        _ => {
            return Err(bad(format!(
                "the name `{}` is not `<module path>::<fn>`",
                name.escape_debug()
            )));
        }
    };

    let (mut stands_on, mut joins) = (None, None);
    for segment in segments {
        let segment = segment?;
        let Some((key, value)) = segment.split_once('=') else {
            return Err(bad(format!(
                "field `{}` is not `key=value`",
                segment.escape_debug()
            )));
        };
        let slot = match key {
            KEY_STANDS_ON => &mut stands_on,
            KEY_JOINS => &mut joins,
            other => return Err(bad(format!("unknown key `{}`", other.escape_debug()))),
        };
        if slot.replace(parse_list(value, key, offset)?).is_some() {
            return Err(bad(format!("key `{key}` appears twice")));
        }
    }
    Ok(Declaration {
        module_path: module_path.to_owned(),
        test_fn: test_fn.to_owned(),
        stands_on: stands_on.unwrap_or_default(),
        joins: joins.unwrap_or_default(),
    })
}

fn parse_list(value: &str, key: &str, offset: usize) -> Result<Vec<String>, DecodeError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|entry| {
            if entry.is_empty() {
                Err(DecodeError::MalformedRecord {
                    offset,
                    reason: format!("{key} has an empty entry"),
                })
            } else {
                Ok(entry.to_owned())
            }
        })
        .collect()
}

/// Checks a `stands_on` entry: `unit(<crate>)`, `integration(<crate>)`, or a
/// bare node id containing `::`. The error text says what is accepted.
pub fn validate_stands_on(entry: &str) -> Result<(), String> {
    let accepted = "accepted forms are `unit(<crate>)`, `integration(<crate>)`, or a node id \
                    containing `::` such as `rust:backend-store::wal::replays_torn_tail`; crate \
                    names use only a-z, 0-9, `_` and `-`";
    for group in ["unit", "integration"] {
        if let Some(inner) = entry
            .strip_prefix(group)
            .and_then(|r| r.strip_prefix('('))
            .and_then(|r| r.strip_suffix(')'))
        {
            return if is_crate_name(inner) {
                Ok(())
            } else {
                Err(format!(
                    "`{inner}` is not a crate name inside `{group}(..)`; {accepted}"
                ))
            };
        }
    }
    let node_id_ok = entry.contains("::")
        && !entry.contains(|c: char| c.is_whitespace() || c.is_control() || "(),".contains(c));
    if node_id_ok {
        Ok(())
    } else {
        Err(format!(
            "`{entry}` is not a recognised stands_on entry; {accepted}"
        ))
    }
}

/// Checks a `joins` entry: a crate name, `[a-z0-9_-]+`.
pub fn validate_join(entry: &str) -> Result<(), String> {
    if is_crate_name(entry) {
        Ok(())
    } else {
        Err(format!(
            "`{entry}` is not a crate name; joins entries use only a-z, 0-9, `_` and `-`, for \
             example `backend-store` or the identifier `backend_store`"
        ))
    }
}

fn is_crate_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

/// The name nextest gives this test inside its binary.
///
/// nextest identifies a test by its path inside the test binary, without the
/// binary's own crate root. `module_path!()` always starts with that root:
/// the crate name for a lib (or bin) test binary, the file stem for an
/// integration test binary. The first `::` segment is therefore removed and
/// the function name appended. The segment is expected to equal
/// `binary_crate_name` with `-` turned into `_`, which is how rustc spells
/// crate names.
///
/// ```
/// use keel_decl::{Declaration, nextest_test_name};
/// let d = |m: &str, f: &str| Declaration {
///     module_path: m.into(), test_fn: f.into(), stands_on: vec![], joins: vec![],
/// };
/// // lib test binary of package `backend-store`
/// assert_eq!(
///     nextest_test_name(&d("backend_store::wal::tests", "replays_torn_tail"), "backend-store"),
///     "wal::tests::replays_torn_tail"
/// );
/// // integration test binary tests/surface_matrix.rs
/// assert_eq!(
///     nextest_test_name(&d("surface_matrix::cases", "lists_empty"), "surface_matrix"),
///     "cases::lists_empty"
/// );
/// // test directly in the crate root: nothing left but the function name
/// assert_eq!(nextest_test_name(&d("backend_store", "smoke"), "backend-store"), "smoke");
/// ```
///
///
/// # A declaration applies to a family of names
///
/// The record carries the function name only, but one function can expand into
/// several tests (`rstest` produces `<fn>::case_1`, `<fn>::case_2`, and
/// parametrised names after them). Consumers must therefore treat a declaration
/// as applying to every test whose nextest name is equal to the name computed
/// here, or starts with it followed by `::`. [`applies_to`] is that rule;
/// do not compare names with `==`.
///
/// # Foreign declarations
///
/// A first segment that does not match `binary_crate_name` means the
/// declaration came from another binary; it panics in debug builds and is
/// stripped regardless in release builds. Use [`try_nextest_test_name`] when
/// the pairing is not already known.
pub fn nextest_test_name(decl: &Declaration, binary_crate_name: &str) -> String {
    let (root, rest) = split_root(&decl.module_path);
    debug_assert_eq!(
        root,
        binary_crate_name.replace('-', "_"),
        "declaration {}::{} does not belong to binary `{binary_crate_name}`; pair each \
         declaration with the binary it was read from",
        decl.module_path,
        decl.test_fn
    );
    join_name(rest, &decl.test_fn)
}

/// Like [`nextest_test_name`], but `None` when the module path's first
/// segment is not `binary_crate_name` (with `-` as `_`).
///
/// The result is a prefix, not always the full test name: see the section on
/// families of names on [`nextest_test_name`], and match with [`applies_to`].
pub fn try_nextest_test_name(decl: &Declaration, binary_crate_name: &str) -> Option<String> {
    let (root, rest) = split_root(&decl.module_path);
    (root == binary_crate_name.replace('-', "_")).then(|| join_name(rest, &decl.test_fn))
}

/// Whether a declaration whose computed name is `decl_name` (from
/// [`nextest_test_name`]) covers the test called `nextest_name`.
///
/// True when the names are equal or `nextest_name` starts with `decl_name`
/// followed by `::`. A bare prefix does not count: `wal::replay` does not cover
/// `wal::replay_torn_tail`.
///
/// ```
/// use keel_decl::applies_to;
/// assert!(applies_to("tests::param", "tests::param"));
/// assert!(applies_to("tests::param", "tests::param::case_1"));
/// assert!(!applies_to("tests::param", "tests::param_other"));
/// ```
pub fn applies_to(decl_name: &str, nextest_name: &str) -> bool {
    nextest_name
        .strip_prefix(decl_name)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
}

fn split_root(module_path: &str) -> (&str, &str) {
    module_path.split_once("::").unwrap_or((module_path, ""))
}

fn join_name(rest: &str, test_fn: &str) -> String {
    if rest.is_empty() {
        test_fn.to_owned()
    } else {
        format!("{rest}::{test_fn}")
    }
}

#[cfg(test)]
mod tests;
