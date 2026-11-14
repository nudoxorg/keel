// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Keel config file, `.config/keel.toml`.
//!
//! The file is strict: an unknown key is an error, because a misspelled
//! declaration that is silently ignored would make a cached pass unsound.

use crate::errors::KeelError;
use camino::{Utf8Path, Utf8PathBuf};
use indexmap::IndexMap;
use keel::{PartId, Upstream};
use nextest_filtering::{Filterset, FiltersetKind, KnownGroups, ParseContext};
use serde::Deserialize;
use std::{fs, io, time::Duration};

/// The schema of the Keel config this build understands.
pub const KEEL_CONFIG_SCHEMA: u32 = 1;

/// The default location of the Keel config, relative to the workspace root.
pub const DEFAULT_KEEL_CONFIG_PATH: &str = ".config/keel.toml";

/// The default location of the local result store, relative to the workspace
/// root.
pub const DEFAULT_KEEL_STORE_DIR: &str = ".local/keel/store";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeelConfig {
    schema: u32,
    #[serde(default)]
    store: RawStore,
    #[serde(default)]
    budget: RawBudget,
    #[serde(default)]
    hierarchy: Vec<RawHierarchy>,
    #[serde(default)]
    package: IndexMap<String, RawInputs>,
    #[serde(default, rename = "override")]
    overrides: IndexMap<String, RawInputs>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStore {
    dir: Option<Utf8PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBudget {
    #[serde(default, with = "humantime_serde")]
    run: Option<Duration>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHierarchy {
    filter: String,
    #[serde(default, rename = "stands-on")]
    stands_on: Vec<String>,
    #[serde(default)]
    joins: Vec<String>,
    #[serde(default, rename = "stands-on-only")]
    stands_on_only: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInputs {
    #[serde(default)]
    inputs: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    tools: Vec<String>,
    network: Option<bool>,
    blocks: Option<bool>,
}

/// Input declarations for a package or a filterset (DESIGN.md §3.3 to §3.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct InputDecl {
    /// Globs of extra runtime files, relative to the package directory unless
    /// they begin with `/`, in which case they are relative to the workspace
    /// root.
    pub(crate) inputs: Vec<String>,

    /// Names of ambient environment variables the test may observe.
    pub(crate) env: Vec<String>,

    /// Names of external programs the test runs.
    pub(crate) tools: Vec<String>,

    /// Whether the test needs the network, which makes it uncacheable.
    pub(crate) network: Option<bool>,

    /// Whether a failure of the test blocks the tests above it.
    pub(crate) blocks: Option<bool>,
}

impl InputDecl {
    fn from_raw(raw: RawInputs) -> Self {
        Self {
            inputs: raw.inputs,
            env: raw.env,
            tools: raw.tools,
            network: raw.network,
            blocks: raw.blocks,
        }
    }

    /// Merges `later` over `self`: lists are united, scalars are overridden.
    pub(crate) fn merge(&mut self, later: &InputDecl) {
        extend_unique(&mut self.inputs, &later.inputs);
        extend_unique(&mut self.env, &later.env);
        extend_unique(&mut self.tools, &later.tools);
        self.network = later.network.or(self.network);
        self.blocks = later.blocks.or(self.blocks);
    }
}

fn extend_unique(target: &mut Vec<String>, more: &[String]) {
    for item in more {
        if !target.contains(item) {
            target.push(item.clone());
        }
    }
}

/// A `[[hierarchy]]` entry whose filterset has been compiled.
#[derive(Debug)]
pub(crate) struct HierarchyEntry {
    pub(crate) filter: Filterset,
    pub(crate) stands_on: Vec<Upstream>,
    pub(crate) joins: Vec<PartId>,
    pub(crate) stands_on_only: bool,
}

/// An `[override.<filterset>]` entry whose filterset has been compiled.
#[derive(Debug)]
pub(crate) struct OverrideEntry {
    pub(crate) filter: Filterset,
    pub(crate) decl: InputDecl,
}

/// The parsed and compiled Keel config.
#[derive(Debug)]
pub struct KeelConfig {
    path: Utf8PathBuf,
    store_dir: Option<Utf8PathBuf>,
    budget: Option<Duration>,
    pub(crate) hierarchy: Vec<HierarchyEntry>,
    pub(crate) packages: IndexMap<String, InputDecl>,
    pub(crate) overrides: Vec<OverrideEntry>,
}

impl KeelConfig {
    /// Loads the config at `path`.
    ///
    /// If `required` is false and the file does not exist, an empty config is
    /// returned: Keel then runs with derived edges and default inputs only.
    pub fn load(
        path: &Utf8Path,
        required: bool,
        pcx: &ParseContext<'_>,
    ) -> Result<Self, KeelError> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound && !required => {
                return Ok(Self::empty(path));
            }
            Err(error) => {
                return Err(KeelError::ConfigRead {
                    path: path.to_owned(),
                    error,
                });
            }
        };
        Self::parse(path, &text, pcx)
    }

    fn empty(path: &Utf8Path) -> Self {
        Self {
            path: path.to_owned(),
            store_dir: None,
            budget: None,
            hierarchy: Vec::new(),
            packages: IndexMap::new(),
            overrides: Vec::new(),
        }
    }

    /// Parses config text. `path` is used in error messages only.
    pub(crate) fn parse(
        path: &Utf8Path,
        text: &str,
        pcx: &ParseContext<'_>,
    ) -> Result<Self, KeelError> {
        let raw: RawKeelConfig = toml::from_str(text).map_err(|error| KeelError::ConfigParse {
            path: path.to_owned(),
            error,
        })?;
        if raw.schema != KEEL_CONFIG_SCHEMA {
            return Err(KeelError::ConfigSchema {
                path: path.to_owned(),
                found: raw.schema,
                supported: KEEL_CONFIG_SCHEMA,
            });
        }

        let compile = |section: String, filter: &str| {
            Filterset::parse(
                filter.to_owned(),
                pcx,
                FiltersetKind::OverrideFilter,
                &KnownGroups::Unavailable,
            )
            .map_err(|errors| KeelError::ConfigFilterset {
                path: path.to_owned(),
                section,
                filter: filter.to_owned(),
                reason: errors
                    .errors
                    .iter()
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            })
        };
        let entry_error = |section: &str, value: &str, reason: String| KeelError::ConfigEntry {
            path: path.to_owned(),
            section: section.to_owned(),
            value: value.to_owned(),
            reason,
        };

        let mut hierarchy = Vec::with_capacity(raw.hierarchy.len());
        for (index, entry) in raw.hierarchy.iter().enumerate() {
            let section = format!("hierarchy[{index}]");
            let filter = compile(section.clone(), &entry.filter)?;
            let stands_on = entry
                .stands_on
                .iter()
                .map(|text| {
                    text.parse::<Upstream>()
                        .map_err(|error| entry_error(&section, text, error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let joins = entry
                .joins
                .iter()
                .map(|text| {
                    text.parse::<PartId>()
                        .map_err(|error| entry_error(&section, text, error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            hierarchy.push(HierarchyEntry {
                filter,
                stands_on,
                joins,
                stands_on_only: entry.stands_on_only,
            });
        }

        let mut overrides = Vec::with_capacity(raw.overrides.len());
        for (filter_text, decl) in raw.overrides {
            let filter = compile(format!("override.{filter_text}"), &filter_text)?;
            overrides.push(OverrideEntry {
                filter,
                decl: InputDecl::from_raw(decl),
            });
        }

        Ok(Self {
            path: path.to_owned(),
            store_dir: raw.store.dir,
            budget: raw.budget.run,
            hierarchy,
            packages: raw
                .package
                .into_iter()
                .map(|(name, decl)| (name, InputDecl::from_raw(decl)))
                .collect(),
            overrides,
        })
    }

    /// Returns the path this config was loaded from.
    pub fn path(&self) -> &Utf8Path {
        &self.path
    }

    /// Returns the `[store] dir` setting, if present.
    pub fn store_dir(&self) -> Option<&Utf8Path> {
        self.store_dir.as_deref()
    }

    /// Returns the run budget, if present.
    pub fn budget(&self) -> Option<Duration> {
        self.budget
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guppy::graph::PackageGraph;

    fn empty_graph() -> PackageGraph {
        let package_id = "path+file:///test-package#test-package@0.1.0";
        let metadata = serde_json::json!({
            "packages": [{
                "name": "test-package",
                "version": "0.1.0",
                "id": package_id,
                "license": null,
                "license_file": null,
                "description": null,
                "source": null,
                "dependencies": [],
                "targets": [{
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "name": "test_package",
                    "src_path": "/tmp/ws/src/lib.rs",
                    "edition": "2024",
                    "doc": true,
                    "doctest": true,
                    "test": true,
                }],
                "features": {},
                "manifest_path": "/tmp/ws/Cargo.toml",
                "metadata": null,
                "publish": null,
                "authors": [],
                "categories": [],
                "keywords": [],
                "readme": null,
                "repository": null,
                "homepage": null,
                "documentation": null,
                "edition": "2024",
                "links": null,
                "default_run": null,
                "rust_version": null,
            }],
            "workspace_members": [package_id],
            "workspace_default_members": [package_id],
            "resolve": {
                "nodes": [{
                    "id": package_id,
                    "dependencies": [],
                    "deps": [],
                    "features": [],
                }],
                "root": package_id,
            },
            "target_directory": "/tmp/ws/target",
            "build_directory": "/tmp/ws/target",
            "version": 1,
            "workspace_root": "/tmp/ws",
            "metadata": null,
        });
        PackageGraph::from_json(metadata.to_string()).expect("graph builds")
    }

    const FULL: &str = r#"
        schema = 1
        [store]
        dir = ".local/keel/store"
        [budget]
        run = "10m"
        [[hierarchy]]
        filter = "binary_id(test-package)"
        stands-on = ["unit(backend-local-service)", "integration(backend-store)"]
        joins = ["crate:backend-local-service", "crate:backend-client"]
        stands-on-only = false
        [package.backend-store]
        inputs = ["../../.config/fixtures/**"]
        env = ["NUDOX_GO_COMPILER"]
        tools = ["go"]
        network = false
        [override."test(/corpus/)"]
        blocks = true
    "#;

    #[test]
    fn parses_the_documented_example() {
        let graph = empty_graph();
        let pcx = ParseContext::new(&graph);
        let config = KeelConfig::parse(Utf8Path::new("keel.toml"), FULL, &pcx).unwrap();
        assert_eq!(config.store_dir(), Some(Utf8Path::new(".local/keel/store")));
        assert_eq!(config.budget(), Some(Duration::from_secs(600)));
        assert_eq!(config.hierarchy.len(), 1);
        assert_eq!(config.hierarchy[0].stands_on.len(), 2);
        assert_eq!(config.packages["backend-store"].tools, ["go"]);
        assert_eq!(config.overrides.len(), 1);
        assert_eq!(config.overrides[0].decl.blocks, Some(true));
    }

    #[test]
    fn unknown_keys_are_errors() {
        let graph = empty_graph();
        let pcx = ParseContext::new(&graph);
        for text in [
            "schema = 1\nbogus = 1\n",
            "schema = 1\n[package.a]\ninputz = []\n",
            "schema = 1\n[[hierarchy]]\nfilter = \"all()\"\nstands_on = []\n",
        ] {
            let err = KeelConfig::parse(Utf8Path::new("keel.toml"), text, &pcx).unwrap_err();
            assert!(
                matches!(err, KeelError::ConfigParse { .. }),
                "unexpected result for {text:?}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_other_schemas_and_bad_entries() {
        let graph = empty_graph();
        let pcx = ParseContext::new(&graph);
        let err = KeelConfig::parse(Utf8Path::new("keel.toml"), "schema = 2\n", &pcx).unwrap_err();
        assert!(
            matches!(err, KeelError::ConfigSchema { found: 2, .. }),
            "{err:?}"
        );

        let bad_part = "schema = 1\n[[hierarchy]]\nfilter = \"all()\"\njoins = [\"nope\"]\n";
        let err = KeelConfig::parse(Utf8Path::new("keel.toml"), bad_part, &pcx).unwrap_err();
        assert!(matches!(err, KeelError::ConfigEntry { .. }), "{err:?}");

        let bad_filter = "schema = 1\n[override.\"nonsense(\"]\nblocks = false\n";
        let err = KeelConfig::parse(Utf8Path::new("keel.toml"), bad_filter, &pcx).unwrap_err();
        assert!(matches!(err, KeelError::ConfigFilterset { .. }), "{err:?}");
    }

    #[test]
    fn merge_unites_lists_and_overrides_scalars() {
        let mut base = InputDecl {
            env: vec!["A".into()],
            blocks: Some(true),
            ..InputDecl::default()
        };
        base.merge(&InputDecl {
            env: vec!["A".into(), "B".into()],
            blocks: Some(false),
            ..InputDecl::default()
        });
        assert_eq!(base.env, ["A", "B"]);
        assert_eq!(base.blocks, Some(false));
    }
}
