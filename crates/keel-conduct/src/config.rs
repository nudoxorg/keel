//! The `keel.toml` the conductor reads: a `[go]` table that turns on the Go
//! source, and `[[node]]` entries for nushell, command, artifact and Nix nodes.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// The whole file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `owner/repo` for the report; defaults to the repository directory's name.
    pub repo: Option<String>,
    /// Present (or `--go` given) turns on the Go source.
    pub go: Option<GoConfig>,
    /// Hand-declared nodes.
    #[serde(default, rename = "node")]
    pub nodes: Vec<NodeConfig>,
}

/// `[go]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoConfig {
    /// Directory holding `go.mod`, relative to the repository root.
    pub root: Option<String>,
    /// Extra files every Go node reads at runtime (globs relative to the
    /// repository root), for fixtures a test opens outside `testdata/`.
    #[serde(default)]
    pub inputs: Vec<String>,
    /// Ambient variables Go tests may see.
    #[serde(default)]
    pub env: Vec<String>,
    /// Extra programs on the test `PATH` (a C compiler for cgo packages);
    /// their content is in the key.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Per-package timeout in seconds.
    pub timeout_s: Option<u64>,
}

/// `env = ["NAME", ...]` allows ambient variables; `env = { NAME = "value" }`
/// sets them (and keys them).
#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
pub enum EnvSpec {
    /// Allowed ambient names.
    List(Vec<String>),
    /// Fixed values.
    Table(BTreeMap<String, String>),
    /// Not given.
    #[default]
    None,
}

/// One `[[node]]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Node id; `nu:` (or `nix:` for `drv`) is prepended when no namespace is given.
    pub id: Option<String>,
    /// `nu-check` (default), `command` or `artifact`; implied by `drv` and `produces`.
    pub kind: Option<String>,
    /// argv.
    #[serde(default)]
    pub command: Vec<String>,
    /// Working directory relative to the repository root.
    pub cwd: Option<String>,
    /// Runtime input globs relative to the repository root.
    #[serde(default)]
    pub inputs: Vec<String>,
    /// See [`EnvSpec`].
    #[serde(default)]
    pub env: EnvSpec,
    /// Programs on `PATH`; their content is in the key.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Nodes or groups this one stands on.
    #[serde(default)]
    pub stands_on: Vec<String>,
    /// Artifact nodes whose outputs this one reads.
    #[serde(default)]
    pub consumes: Vec<String>,
    /// Files (relative to `cwd`) an artifact node leaves behind.
    #[serde(default)]
    pub produces: Vec<String>,
    /// Part ids this node exercises.
    #[serde(default)]
    pub joins: Vec<String>,
    /// `unit(..)`, `integration(..)` or `scenario(..)`.
    pub group: Option<String>,
    /// A Nix installable (a flake attribute or `.drv` path).
    pub drv: Option<String>,
    /// Timeout in seconds.
    pub timeout_s: Option<u64>,
    /// `negative` for a wrong-configuration twin.
    pub control: Option<String>,
    /// For a negative control: the exit codes that count as failing in the way it
    /// declares. 0 is never one, and neither are 126 and 127 (the shell's "not
    /// executable" and "not found"), which mean the command did not run.
    #[serde(default)]
    pub expect_exit: Vec<i32>,
    /// For a negative control: text that must appear in its stdout or stderr
    /// when it fails. At least one of `expect_exit` and `expect_output` is required.
    pub expect_output: Option<String>,
    /// The twin's id, for a control.
    pub twin: Option<String>,
    /// Whether a failure blocks what stands on it (default true).
    pub blocks: Option<bool>,
    /// Whether the node needs the network; such nodes never cache.
    pub network: Option<bool>,
}

impl Config {
    /// Reads and validates a config file.
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| {
            format!(
                "cannot read the config {}; pass --config <keel.toml>",
                path.display()
            )
        })?;
        Config::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    /// Parses and validates config text.
    pub fn parse(text: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(text).context(
            "not a valid keel config; it takes `repo`, a `[go]` table and `[[node]]` entries",
        )?;
        for (i, n) in cfg.nodes.iter().enumerate() {
            let label = n.id.clone().unwrap_or_else(|| format!("#{}", i + 1));
            if n.drv.is_none() && n.command.is_empty() {
                bail!(
                    "[[node]] {label} has neither `command` nor `drv`; give it an argv to run or a Nix installable"
                );
            }
            if n.drv.is_some() && !n.command.is_empty() {
                bail!(
                    "[[node]] {label} has both `command` and `drv`; a Nix node is built, not run, so drop one"
                );
            }
            if n.id.is_none() && n.drv.is_none() {
                bail!(
                    "[[node]] {label} needs an `id`; ids are how reports and `stands_on` name a node"
                );
            }
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_env_forms_and_rejects_unknown_keys() {
        let cfg: Config = toml::from_str(
            r#"
            [[node]]
            id = "a"
            command = ["nu", "a.nu"]
            env = ["HOME_FOO"]
            [[node]]
            id = "b"
            command = ["nu", "b.nu"]
            env = { K = "v" }
            "#,
        )
        .unwrap();
        assert!(matches!(cfg.nodes[0].env, EnvSpec::List(_)));
        assert!(matches!(cfg.nodes[1].env, EnvSpec::Table(_)));
        assert!(toml::from_str::<Config>("surprise = 1").is_err());
    }
}
