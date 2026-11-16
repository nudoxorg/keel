// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Predicts which test binaries Cargo will report, before it builds anything.
//!
//! A test is gated on groups, such as `unit(backend-store)`, and a group is
//! complete only when every one of its binaries is known. When tests are
//! scheduled while Cargo is still building, "every binary" has to come from
//! somewhere other than Cargo's output, so it comes from the package graph and
//! the build scope.
//!
//! The prediction errs on the side of too many binaries. A binary that is
//! predicted but never built only delays the groups it belongs to until Cargo
//! exits; a binary that is built but was not predicted would let a group look
//! complete too early, so every rule here is a superset of what Cargo selects.

use crate::build_scope::{BuildScope, PackageSelection, TargetSelection};
use guppy::graph::{BuildTargetId, BuildTargetKind, PackageGraph, PackageMetadata};
use keel::GroupId;
use nextest_metadata::{RustBinaryId, RustTestBinaryKind};

/// A test binary that Cargo may report, and the group its tests belong to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedBinary {
    /// The ID the binary has if Cargo reports it.
    pub id: RustBinaryId,

    /// The group the binary's tests are members of.
    pub group: GroupId,
}

/// Returns the test binaries that Cargo may report for `scope`.
pub fn predict_test_binaries(graph: &PackageGraph, scope: &BuildScope) -> Vec<ExpectedBinary> {
    let mut expected = Vec::new();
    for package in graph.workspace().iter() {
        if !package_may_be_selected(&package, scope.packages()) {
            continue;
        }
        for target in package.build_targets() {
            let (kind, name) = match (target.id(), target.kind()) {
                (BuildTargetId::Library, BuildTargetKind::ProcMacro) => {
                    (RustTestBinaryKind::PROC_MACRO, package.name())
                }
                (BuildTargetId::Library, _) => (RustTestBinaryKind::LIB, package.name()),
                (BuildTargetId::Binary(name), _) => (RustTestBinaryKind::BIN, name),
                (BuildTargetId::Test(name), _) => (RustTestBinaryKind::TEST, name),
                (BuildTargetId::Example(name), _) => (RustTestBinaryKind::EXAMPLE, name),
                (BuildTargetId::Benchmark(name), _) => (RustTestBinaryKind::BENCH, name),
                (BuildTargetId::BuildScript, _) => continue,
                // BuildTargetId is non-exhaustive. A target kind this code does
                // not know cannot be predicted, so be safe: it will be reported
                // as unexpected, and the groups it affects wait for Cargo to exit
                // only if another binary of the group is also unexpected.
                _ => continue,
            };
            if !target_may_be_selected(&target, scope.targets()) {
                continue;
            }
            let group = if kind == RustTestBinaryKind::LIB
                || kind == RustTestBinaryKind::BIN
                || kind == RustTestBinaryKind::PROC_MACRO
            {
                GroupId::unit(package.name())
            } else {
                GroupId::integration(package.name())
            };
            expected.push(ExpectedBinary {
                id: RustBinaryId::from_parts(package.name(), &kind, name),
                group,
            });
        }
    }
    expected
}

fn target_may_be_selected(
    target: &guppy::graph::BuildTarget<'_>,
    selection: &TargetSelection,
) -> bool {
    if selection.is_empty() {
        // Cargo's default: the targets that are tested by default.
        return target.test_by_default();
    }
    if selection.all_targets {
        return true;
    }
    let by_kind = match target.id() {
        BuildTargetId::Library => selection.lib,
        BuildTargetId::Binary(_) => !selection.bins.is_empty(),
        BuildTargetId::Example(_) => !selection.examples.is_empty(),
        BuildTargetId::Test(_) => !selection.tests.is_empty(),
        BuildTargetId::Benchmark(_) => !selection.benches.is_empty(),
        _ => true,
    };
    // `--tests` also tests the library and the binaries, and `--benches` also
    // builds them in test mode.
    let with_all_tests = selection.tests.all && target.test_by_default();
    let with_all_benches = selection.benches.all
        && matches!(
            target.id(),
            BuildTargetId::Library | BuildTargetId::Binary(_) | BuildTargetId::Benchmark(_)
        );
    by_kind || with_all_tests || with_all_benches
}

fn package_may_be_selected(package: &PackageMetadata<'_>, selection: &PackageSelection) -> bool {
    if selection.workspace || selection.specs.is_empty() {
        // `--exclude` removes a package only when it names it exactly. A pattern
        // might match fewer packages than it appears to, and removing a package
        // that Cargo builds would make its groups look complete too early.
        return !selection
            .exclude
            .iter()
            .any(|spec| spec_name(spec.as_str()) == Some(package.name()));
    }
    selection
        .specs
        .iter()
        .any(|spec| spec_may_match(spec.as_str(), package.name()))
}

/// Returns the package name in `spec` if it is a plain `name` or `name@version`.
fn spec_name(spec: &str) -> Option<&str> {
    let name = spec.split_once('@').map_or(spec, |(name, _)| name);
    (!name.is_empty() && !name.contains(['*', '?', '[', ':', '/', '#'])).then_some(name)
}

/// Returns false only if `spec` certainly does not select the package named
/// `name`.
fn spec_may_match(spec: &str, name: &str) -> bool {
    match spec_name(spec) {
        Some(spec_name) => spec_name == name,
        None => {
            // A glob or a URL: match as a glob if it is a simple one, else assume
            // it selects the package.
            let pattern = spec.split_once('@').map_or(spec, |(pattern, _)| pattern);
            if pattern.contains(['[', ':', '/', '#']) {
                return true;
            }
            glob_matches(pattern.as_bytes(), name.as_bytes())
        }
    }
}

/// Matches `text` against a pattern with `*` and `?`.
fn glob_matches(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => (0..=text.len()).any(|skip| glob_matches(rest, &text[skip..])),
        Some((b'?', rest)) => !text.is_empty() && glob_matches(rest, &text[1..]),
        Some((byte, rest)) => text.first() == Some(byte) && glob_matches(rest, &text[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_scope::{FeatureSelection, NamedTargets, PackageSpec};
    use guppy::CargoMetadata;

    fn fixture_graph() -> PackageGraph {
        static FIXTURE_JSON: &str = include_str!("../../../fixtures/cargo-metadata.json");
        CargoMetadata::parse_json(FIXTURE_JSON)
            .expect("fixture is valid JSON")
            .build_graph()
            .expect("fixture is a valid package graph")
    }

    fn scope(packages: PackageSelection, targets: TargetSelection) -> BuildScope {
        BuildScope::new(
            packages,
            targets,
            FeatureSelection {
                features: Vec::new(),
                all_features: false,
                no_default_features: false,
            },
        )
    }

    fn specs(specs: &[&str]) -> Vec<PackageSpec> {
        specs
            .iter()
            .map(|spec| PackageSpec::new(spec).expect("valid package spec"))
            .collect()
    }

    fn packages(selected: &[&str], workspace: bool, exclude: &[&str]) -> PackageSelection {
        PackageSelection {
            specs: specs(selected),
            workspace,
            exclude: specs(exclude),
        }
    }

    fn no_targets() -> TargetSelection {
        TargetSelection {
            lib: false,
            bins: NamedTargets::empty(),
            examples: NamedTargets::empty(),
            tests: NamedTargets::empty(),
            benches: NamedTargets::empty(),
            all_targets: false,
        }
    }

    fn ids(graph: &PackageGraph, scope: &BuildScope) -> Vec<(String, String)> {
        predict_test_binaries(graph, scope)
            .into_iter()
            .map(|binary| (binary.id.to_string(), binary.group.to_string()))
            .collect()
    }

    #[test]
    fn the_default_scope_expects_the_library_of_every_package() {
        let graph = fixture_graph();
        assert_eq!(
            ids(&graph, &scope(packages(&[], false, &[]), no_targets())),
            [("metadata-base".to_owned(), "unit(metadata-base)".to_owned())]
        );
    }

    #[test]
    fn packages_outside_the_selection_expect_nothing() {
        let graph = fixture_graph();
        let other = scope(packages(&["something-else"], false, &[]), no_targets());
        assert!(ids(&graph, &other).is_empty());
        let named = scope(packages(&["metadata-base@0.1.0"], false, &[]), no_targets());
        assert_eq!(ids(&graph, &named).len(), 1);
        let excluded = scope(packages(&[], true, &["metadata-base"]), no_targets());
        assert!(ids(&graph, &excluded).is_empty());
        let pattern_excluded = scope(packages(&[], true, &["metadata-*"]), no_targets());
        assert_eq!(
            ids(&graph, &pattern_excluded).len(),
            1,
            "a pattern never removes a package, because it might match fewer than it seems"
        );
    }

    #[test]
    fn target_flags_narrow_the_expected_binaries() {
        let graph = fixture_graph();
        let lib = TargetSelection {
            lib: true,
            ..no_targets()
        };
        assert_eq!(ids(&graph, &scope(packages(&[], false, &[]), lib)).len(), 1);
        let tests_only = TargetSelection {
            tests: NamedTargets {
                names: vec!["it".to_owned()],
                all: false,
            },
            ..no_targets()
        };
        assert!(ids(&graph, &scope(packages(&[], false, &[]), tests_only)).is_empty());
        let all_tests = TargetSelection {
            tests: NamedTargets {
                names: Vec::new(),
                all: true,
            },
            ..no_targets()
        };
        assert_eq!(
            ids(&graph, &scope(packages(&[], false, &[]), all_tests)).len(),
            1,
            "--tests also tests the library"
        );
    }

    #[test]
    fn plain_specs_select_exactly_their_package() {
        assert!(spec_may_match("foo", "foo"));
        assert!(spec_may_match("foo@1.2.3", "foo"));
        assert!(!spec_may_match("foo", "foo-bar"));
        assert!(!spec_may_match("foo@1.2.3", "bar"));
    }

    #[test]
    fn globs_and_urls_never_exclude_a_package_they_might_select() {
        assert!(spec_may_match("foo-*", "foo-bar"));
        assert!(!spec_may_match("foo-*", "bar"));
        assert!(spec_may_match("ba?", "bar"));
        assert!(
            spec_may_match("[ab]ar", "xyz"),
            "a class is assumed to match"
        );
        assert!(
            spec_may_match("https://example.com/foo#foo@1.0.0", "other"),
            "a URL is assumed to match"
        );
    }

    #[test]
    fn only_plain_names_exclude() {
        assert_eq!(spec_name("foo"), Some("foo"));
        assert_eq!(spec_name("foo@1.0.0"), Some("foo"));
        assert_eq!(spec_name("foo*"), None);
        assert_eq!(spec_name("https://example.com/foo"), None);
    }

    #[test]
    fn glob_matching() {
        assert!(glob_matches(b"*", b""));
        assert!(glob_matches(b"a*c", b"abbbc"));
        assert!(!glob_matches(b"a*c", b"abbbd"));
        assert!(glob_matches(b"a?c", b"abc"));
        assert!(!glob_matches(b"a?c", b"ac"));
    }
}
