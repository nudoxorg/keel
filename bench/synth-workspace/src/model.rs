//! The synth.json schema: the single source of truth that `mutate` and
//! `summarize` read, so they never re-derive anything from generated source.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Asserts {
    Combined,
    Filler,
    Fixture,
    /// A line-shift oracle test: calls one source-position-sensitive feature of a root crate.
    Line,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CrateInfo {
    pub name: String,
    pub level: usize,
    pub deps: Vec<String>,
    pub probe: u32,
    /// What `combined()` returns in the pristine workspace.
    pub combined: u64,
    pub unit_tests: usize,
    pub integration_tests: usize,
    pub integration_bins: usize,
    pub fixtures: usize,
    pub fillers: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestInfo {
    /// `<binary id> <test name>`, the form nextest lists.
    pub id: String,
    pub binary: String,
    pub name: String,
    #[serde(rename = "crate")]
    pub krate: String,
    pub kind: String,
    pub asserts: Asserts,
    /// Fixture index for `Asserts::Fixture` tests.
    pub fixture: Option<usize>,
    /// For `Asserts::Line`: the feature (see `generate::LINE_FEATURES`) and the root crate it calls.
    #[serde(default)]
    pub feature: Option<String>,
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Synth {
    pub version: u32,
    /// Parameters as resolved (shape defaults applied, flags overriding).
    pub params: serde_json::Value,
    pub crates: Vec<CrateInfo>,
    pub tests: Vec<TestInfo>,
}

impl Synth {
    pub fn load(ws: &Path) -> Result<Synth> {
        let p = ws.join("synth.json");
        let bytes = std::fs::read(&p).with_context(|| {
            format!("cannot read {}; run `synth-workspace generate` first or pass the generated workspace root", p.display())
        })?;
        serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "{} is not valid synth.json; regenerate the workspace",
                p.display()
            )
        })
    }

    /// `name` plus every crate that depends on it, directly or not. Crates are
    /// stored in topological order, so one forward pass suffices.
    pub fn dependents_closure(&self, name: &str) -> Vec<String> {
        let mut set = vec![name.to_string()];
        for c in &self.crates {
            if !set.contains(&c.name) && c.deps.iter().any(|d| set.contains(d)) {
                set.push(c.name.clone());
            }
        }
        set
    }
}
