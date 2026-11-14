// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Code keys for test binaries (DESIGN.md §3.1 and §3.2).
//!
//! The runner depends on the [`CodeKeyer`] trait rather than on a particular
//! analysis, so a sharper key than the executable key can be plugged in
//! without touching any call site.

use crate::errors::CodeKeyError;
use camino::Utf8Path;
use keel::{CodeKind, Digest};
use std::collections::{BTreeMap, BTreeSet};

/// Computes the code keys of the tests of one test binary.
pub trait CodeKeyer: Send + Sync {
    /// Returns the keys for the tests of one binary.
    ///
    /// `tests` are the nextest test names, without the binary ID. A test that
    /// has no entry in [`BinaryCodeKeys::per_test`] is keyed by the executable
    /// key.
    fn keys(
        &self,
        exe: &Utf8Path,
        crate_name: &str,
        tests: &[&str],
    ) -> Result<BinaryCodeKeys, CodeKeyError>;
}

/// The code keys of one test binary.
#[derive(Clone, Debug)]
pub struct BinaryCodeKeys {
    /// The executable key of the binary (DESIGN.md §3.1).
    pub executable: Digest,

    /// Per-test keys, by nextest test name.
    pub per_test: BTreeMap<String, TestCodeKey>,
}

/// The code key of one test.
#[derive(Clone, Debug)]
pub struct TestCodeKey {
    /// The key.
    pub key: Digest,

    /// Which analysis produced the key.
    pub kind: CodeKind,

    /// The workspace crates the test can reach.
    pub crates: BTreeSet<String>,

    /// The symbols of the test's own package that the test exercises, if
    /// known.
    pub exercised: Option<BTreeSet<u32>>,

    /// Every symbol the test can reach, if known.
    pub reach: Option<BTreeSet<u32>>,
}

/// A [`CodeKeyer`] that keys every test of a binary with the binary's
/// executable key.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutableKeyer;

impl CodeKeyer for ExecutableKeyer {
    fn keys(
        &self,
        exe: &Utf8Path,
        _crate_name: &str,
        _tests: &[&str],
    ) -> Result<BinaryCodeKeys, CodeKeyError> {
        let executable =
            keel::executable_key(exe.as_std_path()).map_err(|error| CodeKeyError::Executable {
                path: exe.to_owned(),
                error,
            })?;
        Ok(BinaryCodeKeys {
            executable,
            per_test: BTreeMap::new(),
        })
    }
}

impl BinaryCodeKeys {
    /// Returns the key of `test` and the analysis that produced it.
    pub(crate) fn key_for(&self, test: &str) -> (Digest, CodeKind) {
        match self.per_test.get(test) {
            Some(per_test) => (per_test.key, per_test.kind),
            None => (self.executable, CodeKind::Executable),
        }
    }
}
