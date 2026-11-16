//! The JSON that `nix-instantiate --eval --strict --json eval.nix` emits.
//!
//! Every key the library emits has a typed field here, even where the engine does not act on
//! it yet: a field with no home would be dropped without a word. Free-form values the model
//! author writes (what a check expects, a census record, a fault's target) stay `Value`.
//!
//! The model is read leniently and checked strictly. `Model::from_json` accepts a key it has no
//! field for, because a newer library must not stop the engine, and reports it by path in
//! `Model::unread`, which `check` prints. The contract test (`tests/contract.rs`) fails on any
//! unread key, which is how a library change reaches this file. The reader finds unread keys by
//! reading the model into the typed form, writing it back out, and listing every input key the
//! output lacks; that works through internally tagged enums, which `serde_ignored` cannot see into.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Model {
    /// Required: a model without one is not what this crate reads (see `SCHEMA`).
    pub schema: u32,
    pub nodes: Vec<ModelNode>,
    #[serde(default)]
    pub axes: BTreeMap<String, Vec<String>>,
    /// Per axis, the value a test has when no placement rule gives it one. An axis not named
    /// here leaves such a test without a value on it.
    #[serde(default, rename = "axisDefaults")]
    pub axis_defaults: BTreeMap<String, String>,
    #[serde(default)]
    pub place: Vec<PlaceRule>,
    #[serde(default)]
    pub checks: BTreeMap<String, CheckGroup>,
    #[serde(default)]
    pub worlds: Vec<World>,
    #[serde(default)]
    pub policy: Policy,
    /// Enumerations the model compares with what exists (see `Census`).
    #[serde(default)]
    pub census: Vec<Census>,
    /// One node for every workspace package no node's `crate` claims, made at resolve time.
    #[serde(default, rename = "nodesFromCrates")]
    pub nodes_from_crates: Option<NodesFromCrates>,
    /// Keys of the JSON that no typed field read, as paths (`worlds[2].frobnicate`). Not part of
    /// the model; set by `from_json`.
    #[serde(skip)]
    pub unread: Vec<String>,
}

/// `nodesFromCrates = { strip = "backend-"; }`: the id of the node made for a package is its name
/// with `strip` taken off the front.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodesFromCrates {
    #[serde(default)]
    pub strip: String,
    /// Directory globs, relative to the root: only a package whose manifest directory matches
    /// one becomes a node. An allow-list, so that a test suite or a dev tool is not a node
    /// because it is a workspace member.
    #[serde(default)]
    pub under: Vec<String>,
    /// `file:line` of the model source that wrote it.
    #[serde(default)]
    pub at: Option<String>,
}

/// The one model schema this crate reads, the one `nix/keel/lib.nix` emits.
pub const SCHEMA: u32 = 2;

/// What the library lets a model say about the whole product.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    /// The tests a deploy waits for.
    #[serde(default)]
    pub deploy_gate: Option<TestSet>,
    #[serde(default)]
    pub idle: Option<Idle>,
    /// `"fail"` or `"report"`: what an edge no test or breaking twin covers is.
    #[serde(default = "fail")]
    pub uncovered: String,
    #[serde(default)]
    pub joins: Vec<Vec<String>>,
    /// Files that can change no build and no test, each with why (`inert "<glob>" "<reason>"`).
    #[serde(default)]
    pub inert: Vec<Selector>,
    /// `"fail"` or `"report"`: what an edge nothing has ever taken the lower end of is.
    #[serde(default = "fail")]
    pub faults: String,
    #[serde(default)]
    pub unfaulted: Vec<Unfaulted>,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy { deploy_gate: None, idle: None, uncovered: fail(), joins: Vec::new(), inert: Vec::new(), faults: fail(), unfaulted: Vec::new() }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Idle {
    #[serde(default)]
    pub mutate: Option<TestSet>,
    #[serde(default)]
    pub recheck_one_in: Option<u64>,
}

/// An edge excused from `policy.faults`, with the reason.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Unfaulted {
    pub from: String,
    pub to: String,
    pub reason: String,
}

/// A census asks whether the model's list of things is the list of things. Its `result` is
/// known at evaluation when the observation is a value, and null when a command observes it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Census {
    pub name: String,
    #[serde(default)]
    pub at: Option<String>,
    #[serde(default)]
    pub about: Option<String>,
    /// The world the observing command runs in.
    #[serde(default)]
    pub world: Option<String>,
    /// The command that prints one JSON record per line, when the source is a command.
    #[serde(default)]
    pub observe: Option<Vec<String>>,
    /// A class of `keel-tree boundaries` (production sites only) as the source, when the engine finds
    /// the records itself: one per file, keyed by `file`, `node` or `line`.
    #[serde(default)]
    pub boundary: Option<String>,
    #[serde(default)]
    pub key: Vec<String>,
    /// The records the model says exist.
    #[serde(default)]
    pub declared: Vec<Value>,
    /// Observed records excused, each with a reason.
    #[serde(default)]
    pub ignore: Vec<CensusIgnore>,
    /// `"fail"` or `"report"`: what a record only observed is.
    #[serde(default = "fail")]
    pub extra: String,
    /// What a record only declared is.
    #[serde(default = "fail")]
    pub missing: String,
    /// Axis name to the record field that holds its value.
    #[serde(default)]
    pub axes: BTreeMap<String, String>,
    /// Nodes the census is about.
    #[serde(default)]
    pub on: Vec<String>,
    /// What the observation reads or runs.
    #[serde(default)]
    pub inputs: Vec<Selector>,
    #[serde(default)]
    pub result: Option<CensusResult>,
}

fn fail() -> String {
    "fail".to_owned()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CensusIgnore {
    #[serde(rename = "match")]
    pub matches: Value,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CensusResult {
    #[serde(default)]
    pub extra: Vec<Value>,
    #[serde(default)]
    pub missing: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelNode {
    pub id: String,
    /// `file:line` of the model source that wrote the node.
    pub at: String,
    /// Schema 2: where the node is written when that is not its Nix position; shown instead of `at`.
    #[serde(default)]
    pub source: Option<String>,
    pub parent: Option<String>,
    pub about: Option<String>,
    #[serde(default)]
    pub code: Vec<Selector>,
    #[serde(default)]
    pub entry: Vec<Selector>,
    #[serde(default)]
    pub on: Vec<String>,
    #[serde(default)]
    pub never: Vec<String>,
    /// Schema 2: instance-of edges. Moves and blames like `on`, is never coverage.
    #[serde(default)]
    pub of: Vec<String>,
    /// `"required"` or `"may-lag"` in the current library; kept as a value so
    /// a richer policy object from a later library prints rather than fails.
    pub ship: Option<Value>,
    /// Schema 2: how far a node may lag, when it is `may-lag`.
    #[serde(default)]
    pub lag: Option<Lag>,
    #[serde(default, rename = "movedBy")]
    pub moved_by: Vec<String>,
    #[serde(default, rename = "unmovedBy")]
    pub unmoved_by: Vec<String>,
    /// The package this node was made for by `nodesFromCrates`. Never in the JSON: the
    /// library cannot know the packages.
    #[serde(skip)]
    pub from_crate: Option<String>,
}

impl ModelNode {
    pub fn ship_label(&self) -> Option<String> {
        self.ship.as_ref().map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "by", rename_all = "lowercase")]
pub enum Selector {
    Crate { name: String },
    /// `reason` is set on `policy.inert` entries only.
    Path {
        glob: String,
        #[serde(default)]
        reason: Option<String>,
    },
    Module { path: String },
    Pattern { language: String, pattern: String },
    /// Schema 2 selectors the engine cannot resolve: reported, never guessed.
    Option { path: String },
    Drv { attr: String },
    /// A path inside what `of` names; resolved like `of`, narrowed.
    Within { of: Box<Selector>, path: String },
    /// A path inside a world's own state, which exists only once the world is built. Valid in
    /// a world's `env`; it never names files of the repository.
    State { path: String },
}

impl Selector {
    /// Whether this is, or is inside, a selector of a Nix output (`option`, `drv`).
    pub fn names_nix_output(&self) -> bool {
        match self {
            Selector::Option { .. } | Selector::Drv { .. } => true,
            Selector::Within { of, .. } => of.names_nix_output(),
            _ => false,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Selector::Crate { name } => format!("crate \"{name}\""),
            Selector::Path { glob, .. } => format!("path \"{glob}\""),
            Selector::Module { path } => format!("module \"{path}\""),
            Selector::Pattern { language, pattern } => {
                format!("pattern ({language}) \"{pattern}\"")
            }
            Selector::Option { path } => format!("option \"{path}\""),
            Selector::Drv { attr } => format!("drv \"{attr}\""),
            Selector::Within { of, path } => format!("within ({}) \"{path}\"", of.describe()),
            Selector::State { path } => format!("state \"{path}\""),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PlaceRule {
    pub tests: TestSet,
    #[serde(default)]
    pub coordinates: BTreeMap<String, String>,
    pub world: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum TestSet {
    All,
    Under { glob: String },
    Named { glob: String },
    Package { name: String },
    Reaching { selector: Selector },
    Node { node: String },
    /// Tests whose tops all lie at or under the node (schema 2).
    Only { node: String },
    Union { sets: Vec<TestSet> },
    Both { sets: Vec<TestSet> },
    Minus { left: Box<TestSet>, right: Box<TestSet> },
}

impl TestSet {
    pub fn describe(&self) -> String {
        match self {
            TestSet::All => "all".into(),
            TestSet::Under { glob } => format!("under {glob}"),
            TestSet::Named { glob } => format!("named {glob}"),
            TestSet::Package { name } => format!("package {name}"),
            TestSet::Reaching { selector } => format!("reaching {}", selector.describe()),
            TestSet::Node { node } => format!("node {node}"),
            TestSet::Only { node } => format!("only {node}"),
            TestSet::Union { sets } => format!(
                "union({})",
                sets.iter().map(TestSet::describe).collect::<Vec<_>>().join(", ")
            ),
            TestSet::Both { sets } => format!(
                "both({})",
                sets.iter().map(TestSet::describe).collect::<Vec<_>>().join(", ")
            ),
            TestSet::Minus { left, right } => {
                format!("{} minus {}", left.describe(), right.describe())
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CheckGroup {
    #[serde(default)]
    pub checks: Vec<CheckCell>,
    /// Dimension name to how many values it has.
    #[serde(default)]
    pub dimensions: BTreeMap<String, u64>,
    #[serde(default)]
    pub uncontrolled: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Lag {
    pub at_most_minutes: u64,
    pub confidence: f64,
}

/// A start state, built once and forked.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct World {
    pub name: String,
    pub at: Option<String>,
    #[serde(default)]
    pub about: Option<String>,
    pub from: Option<String>,
    /// The command that turns the parent world into this one.
    #[serde(default)]
    pub step: Vec<String>,
    /// What is kept of the built state (`"directory"`, `"service"`, ...).
    #[serde(default)]
    pub keep: Option<String>,
    #[serde(default)]
    pub inputs: Vec<Selector>,
    pub max_age_minutes: Option<u64>,
    /// The machines of the world; null when it does not say.
    #[serde(default)]
    pub machines: Option<Vec<String>>,
    /// Environment of every process in the world: text, or a selector the driver resolves
    /// (a path inside a toolchain, or inside the world's own state).
    #[serde(default)]
    pub env: BTreeMap<String, EnvValue>,
    /// Programs a process in the world may find on its PATH.
    #[serde(default)]
    pub tools: Vec<Selector>,
    #[serde(default)]
    pub network: bool,
    /// Whole seconds the world's step may take before it is given up as hung.
    #[serde(default)]
    pub ready_within: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum EnvValue {
    Text(String),
    Selector(Selector),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckCell {
    #[serde(default)]
    pub on: Vec<String>,
    #[serde(default)]
    pub coordinates: BTreeMap<String, String>,
    #[serde(default)]
    pub inputs: Vec<Selector>,
    #[serde(default)]
    pub cell: String,
    /// The dimensions of the cell and the value on each.
    #[serde(default)]
    pub dims: BTreeMap<String, Value>,
    /// The command the check runs.
    #[serde(default)]
    pub run: Vec<String>,
    /// How the check's result must look: free-form, read by the driver.
    #[serde(default)]
    pub expect: Value,
    /// The machine the command runs on.
    #[serde(default)]
    pub at: Option<String>,
    /// The identity the command runs as.
    #[serde(default, rename = "as")]
    pub run_as: Option<String>,
    /// The name of the run this cell shares with others.
    #[serde(default)]
    pub together: Option<String>,
    /// The name of the control this instance is the twin of, when it is one.
    #[serde(default)]
    pub control: Option<String>,
    /// The faults this instance injects; one today, a list because faults compose.
    #[serde(default)]
    pub faults: Vec<Fault>,
    /// The name of the world the instance starts in.
    #[serde(default)]
    pub world: Option<String>,
    /// What a control or fault takes away: the node whose loss must make the check fail, or the
    /// edge between two nodes. Only this makes a check evidence for a stands-on edge.
    #[serde(default)]
    pub breaks: Option<Breaks>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Breaks {
    Node { node: String },
    Edge { edge: [String; 2] },
}

/// A change to the world under a correct request.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fault {
    pub name: String,
    #[serde(default)]
    pub kind: String,
    /// What the fault acts on; its shape depends on `kind`.
    #[serde(default)]
    pub target: Value,
    #[serde(default)]
    pub at: Option<String>,
    /// Whole seconds the fault lasts.
    #[serde(default)]
    pub hold: Option<u64>,
    /// What must be true while it lasts.
    #[serde(default)]
    pub during: During,
    /// What must be true again after it is healed.
    #[serde(default)]
    pub after: Value,
    /// Whole seconds the system has to be right again after the heal.
    #[serde(default)]
    pub recover_within: Option<u64>,
    #[serde(default)]
    pub inject: Option<Vec<String>>,
    #[serde(default)]
    pub heal: Option<Vec<String>>,
}

/// Exactly one is set.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct During {
    /// The check keeps passing.
    #[serde(default)]
    pub holds: Option<bool>,
    /// Nothing answers while the fault lasts (`reboot` and `power-loss` only); `after` says everything.
    #[serde(default)]
    pub down: Option<bool>,
    /// The system answers in a degraded way, within a deadline.
    #[serde(default)]
    pub degrades_to: Option<Verdict>,
    /// The system refuses, within a deadline.
    #[serde(default)]
    pub refuses: Option<Verdict>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Verdict {
    pub expect: Value,
    pub within: u64,
}

impl CheckCell {
    /// `<group>:<cell>`, with `#control=<name>` or `#fault=<name>` for the twins and fault
    /// checks of a cell, which share its `cell` text and are still different checks.
    pub fn id(&self, group: &str) -> String {
        let mut id = format!("{group}:{}", self.cell);
        if let Some(c) = &self.control {
            id.push_str(&format!("#control={c}"));
        }
        if !self.faults.is_empty() {
            let names: Vec<&str> = self.faults.iter().map(|f| f.name.as_str()).collect();
            id.push_str(&format!("#fault={}", names.join("+")));
        }
        id
    }
}

/// Paths of the keys in `input` that `output` does not have. `_keel` is the library's own
/// constructor tag and belongs to no field.
fn missing_keys(input: &Value, output: &Value, at: &str, out: &mut Vec<String>) {
    match (input, output) {
        (Value::Object(i), Value::Object(o)) => {
            for (k, v) in i {
                if k == "_keel" {
                    continue;
                }
                let here = if at.is_empty() { k.clone() } else { format!("{at}.{k}") };
                match o.get(k) {
                    None => out.push(here),
                    Some(ov) => missing_keys(v, ov, &here, out),
                }
            }
        }
        (Value::Array(i), Value::Array(o)) => {
            for (n, (iv, ov)) in i.iter().zip(o).enumerate() {
                missing_keys(iv, ov, &format!("{at}[{n}]"), out);
            }
        }
        _ => {}
    }
}

impl Model {
    pub fn from_json(text: &str) -> Result<Model> {
        let raw: Value = serde_json::from_str(text).context("the model is not JSON; check what nix-instantiate printed")?;
        let mut model: Model = serde_json::from_value(raw.clone()).map_err(|e| {
            anyhow::anyhow!(
                "the model JSON has a shape keel-tree does not read ({e}). \
                 nix/keel/lib.nix and this crate are different versions: rebuild keel-tree from the revision that has the library, \
                 or teach crates/keel-tree/src/model.rs the new variant"
            )
        })?;
        let mut unread = Vec::new();
        missing_keys(&raw, &serde_json::to_value(&model)?, "", &mut unread);
        model.unread = unread;
        model.validate()?;
        Ok(model)
    }

    /// What must hold before anything is resolved: a schema this crate knows, and one id per
    /// check instance, because reports and `explain` name checks by id.
    fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA {
            bail!(
                "the model is schema {}, which this keel-tree does not read: it reads schema {SCHEMA} only. \
                 Use the keel-tree built from the same revision as nix/keel/lib.nix, which emits schema {SCHEMA}.",
                self.schema
            );
        }
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for (group, g) in &self.checks {
            for c in &g.checks {
                *seen.entry(c.id(group)).or_default() += 1;
            }
        }
        let dup: Vec<String> = seen.into_iter().filter(|(_, n)| *n > 1).map(|(id, n)| format!("{id} ({n} instances)")).collect();
        if !dup.is_empty() {
            bail!(
                "{} check ids are shared by more than one check instance, so reports could not tell them apart: {}. \
                 Give the cells, controls or faults distinct names in the matrix.",
                dup.len(),
                dup.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
            );
        }
        Ok(())
    }

    /// Evaluates the entry point. It is a subprocess because Nix is the only
    /// thing that can run the model; it takes tens of milliseconds.
    pub fn evaluate(eval_nix: &Path) -> Result<Model> {
        let out = Command::new("nix-instantiate")
            .args(["--eval", "--strict", "--json"])
            .arg(eval_nix)
            .output()
            .with_context(|| {
                "could not run nix-instantiate; put nix on PATH to evaluate the model".to_owned()
            })?;
        if !out.status.success() {
            bail!(
                "evaluating {} failed; the Nix message follows and names the model line to fix:\n{}",
                eval_nix.display(),
                String::from_utf8_lossy(&out.stderr).trim_end()
            );
        }
        Model::from_json(&String::from_utf8_lossy(&out.stdout))
    }
}
