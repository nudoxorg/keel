// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Acceptance test for `cargo nextest run --keel`.
//!
//! The test generates the shape-S synthetic workspace of the Keel benchmark
//! suite, runs the fork on it, mutates it one change at a time, and checks the
//! `report.json` of every run against the flips the mutation predicts.
//!
//! The workspace is regenerated at the same path before each mutation, because
//! a test that reads a fixture through `env!("CARGO_MANIFEST_DIR")` embeds the
//! checkout path in its binary, and so has a different key at another path.
//!
//! This test needs the Keel repository around the fork (it runs the generator
//! at `../../Cargo.toml`) and a network-free cargo. It takes a few minutes.

use camino::{Utf8Path, Utf8PathBuf};
use keel::{NodeId, Report, Status};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    process::{Command, Output},
    time::{Duration, Instant},
};

const SEED: &str = "1";

struct Harness {
    root: Utf8PathBuf,
    workspace: Utf8PathBuf,
    store: Utf8PathBuf,
    target: Utf8PathBuf,
    rows: Vec<Row>,
}

struct Row {
    scenario: &'static str,
    ran: u64,
    cached: u64,
    blocked: u64,
    failed: u64,
    roots: usize,
    wall: Duration,
}

struct Run {
    report: Report,
    stderr: String,
    wall: Duration,
    exit_code: Option<i32>,
}

impl Harness {
    fn new() -> Self {
        let root = Utf8PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("keel-acceptance");
        let workspace = root.join("ws");
        let store = root.join("store");
        let target = root.join("target");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&store);
        fs::create_dir_all(&root).expect("create the scratch directory");
        Self {
            root,
            workspace,
            store,
            target,
            rows: Vec::new(),
        }
    }

    fn generate(&self) {
        let _ = fs::remove_dir_all(&self.workspace);
        let manifest = Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
        let out = cargo_stock(
            &[
                "run",
                "--quiet",
                "--manifest-path",
                manifest.as_str(),
                "-p",
                "synth-workspace",
                "--",
                "generate",
                "--shape",
                "S",
                "--seed",
                SEED,
                "--out",
                self.workspace.as_str(),
            ],
            None,
        );
        assert_success(&out, "generate the synthetic workspace");
        let config = self.workspace.join(".config");
        fs::create_dir_all(&config).expect("create .config");
        fs::write(config.join("keel.toml"), "schema = 1\n").expect("write keel.toml");
    }

    fn mutate(&self, pattern: &str) -> Value {
        let manifest = Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
        let out = cargo_stock(
            &[
                "run",
                "--quiet",
                "--manifest-path",
                manifest.as_str(),
                "-p",
                "synth-workspace",
                "--",
                "mutate",
                "--workspace",
                self.workspace.as_str(),
                "--pattern",
                pattern,
                "--seed",
                SEED,
            ],
            None,
        );
        assert_success(&out, "mutate the synthetic workspace");
        let text = fs::read_to_string(self.workspace.join("mutation.json"))
            .expect("mutation.json is written");
        serde_json::from_str(&text).expect("mutation.json is JSON")
    }

    fn run_keel(&self, report_name: &str) -> Run {
        let report_path = self.root.join(report_name);
        let _ = fs::remove_file(&report_path);
        let started = Instant::now();
        let output = Command::new(env!("CARGO_BIN_EXE_cargo-nextest"))
            .args([
                "nextest",
                "run",
                "--keel",
                "--color=never",
                "--no-input-handler",
                "--status-level=all",
            ])
            .arg("--manifest-path")
            .arg(self.workspace.join("Cargo.toml"))
            .arg("--keel-store")
            .arg(&self.store)
            .arg("--keel-report")
            .arg(&report_path)
            .env("RUSTC_WRAPPER", "")
            .env("CARGO_TARGET_DIR", &self.target)
            .env("CARGO_INCREMENTAL", "0")
            .env_remove("NEXTEST_PROFILE")
            .output()
            .expect("run cargo-nextest");
        let wall = started.elapsed();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let report_text = fs::read_to_string(&report_path).unwrap_or_else(|err| {
            panic!(
                "no report at {report_path} ({err}); exit {:?}\n{stderr}",
                output.status.code()
            )
        });
        let report: Report = serde_json::from_str(&report_text).expect("report.json parses");
        Run {
            report,
            stderr,
            wall,
            exit_code: output.status.code(),
        }
    }

    fn record(&mut self, scenario: &'static str, run: &Run) {
        let c = &run.report.counts;
        self.rows.push(Row {
            scenario,
            ran: c.pass + c.fail + c.flaky + c.timeout + c.error,
            cached: c.cached,
            blocked: c.blocked,
            failed: c.fail + c.timeout + c.error,
            roots: run.report.roots.len(),
            wall: run.wall,
        });
    }
}

fn cargo_stock(args: &[&str], dir: Option<&Utf8Path>) -> Output {
    let mut command = Command::new("cargo-stock");
    command.args(args).env("RUSTC_WRAPPER", "");
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    match command.output() {
        Ok(output) => output,
        Err(_) => {
            let mut command =
                Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()));
            command.args(args).env("RUSTC_WRAPPER", "");
            command.output().expect("run cargo")
        }
    }
}

fn assert_success(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "failed to {what}: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn node_id(synth_test_id: &str) -> NodeId {
    let (binary, name) = synth_test_id
        .split_once(' ')
        .expect("synth.json ids are `<binary> <name>`");
    NodeId::new(format!("rust:{binary}::{name}"))
}

fn statuses(report: &Report) -> BTreeMap<&NodeId, Status> {
    report.nodes.iter().map(|r| (&r.id, r.status)).collect()
}

fn dependents_closure(synth: &Value, name: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::from([name.to_owned()]);
    for c in synth["crates"].as_array().expect("crates") {
        let deps: Vec<&str> = c["deps"]
            .as_array()
            .expect("deps")
            .iter()
            .map(|d| d.as_str().expect("dep"))
            .collect();
        if deps.iter().any(|d| set.contains(*d)) {
            set.insert(c["name"].as_str().expect("name").to_owned());
        }
    }
    set
}

#[test]
fn keel_acceptance() {
    let mut h = Harness::new();
    h.generate();
    let synth: Value = serde_json::from_str(
        &fs::read_to_string(h.workspace.join("synth.json")).expect("synth.json"),
    )
    .expect("synth.json parses");
    let tests = synth["tests"].as_array().expect("tests").clone();
    let total = tests.len() as u64;
    let crate_of: BTreeMap<NodeId, String> = tests
        .iter()
        .map(|t| {
            (
                node_id(t["id"].as_str().expect("id")),
                t["crate"].as_str().expect("crate").to_owned(),
            )
        })
        .collect();
    let all_ids: BTreeSet<NodeId> = tests
        .iter()
        .map(|t| node_id(t["id"].as_str().expect("id")))
        .collect();

    // Run 1: everything runs.
    let first = h.run_keel("report-1.json");
    h.record("run 1 (cold)", &first);
    assert_eq!(
        first.report.verdict,
        keel::Verdict::Pass,
        "{}",
        first.stderr
    );
    assert_eq!(first.exit_code, Some(0), "{}", first.stderr);
    assert_eq!(first.report.counts.cached, 0);
    assert_eq!(first.report.counts.pass, total, "{}", first.stderr);
    assert_eq!(
        first
            .report
            .nodes
            .iter()
            .map(|r| r.id.clone())
            .collect::<BTreeSet<_>>(),
        all_ids
    );

    // Run 2: nothing changed, nothing runs.
    let second = h.run_keel("report-2.json");
    h.record("run 2 (no change)", &second);
    assert_eq!(second.report.counts.cached, total, "{}", second.stderr);
    assert_eq!(second.exit_code, Some(0), "{}", second.stderr);
    assert!(
        second.stderr.contains("CACHED [ run "),
        "cached tests are listed:\n{}",
        second.stderr
    );
    assert!(
        !second.stderr.contains(" PASS ["),
        "no test should have been spawned:\n{}",
        second.stderr
    );
    assert!(
        second.wall < first.wall / 2,
        "run 2 ({:?}) should take well under run 1 ({:?})",
        second.wall,
        first.wall
    );

    // body-root: a root crate's probe changes.
    h.generate();
    let mutation = h.mutate("body-root");
    let mutated = mutation["crate"]
        .as_str()
        .expect("mutated crate")
        .to_owned();
    let flips: BTreeSet<NodeId> = mutation["expected_flips"]
        .as_array()
        .expect("expected_flips")
        .iter()
        .map(|id| node_id(id.as_str().expect("flip id")))
        .collect();
    let run = h.run_keel("report-body-root.json");
    h.record("body-root", &run);
    let by_id = statuses(&run.report);
    for id in &flips {
        assert!(
            matches!(by_id[id], Status::Fail | Status::Blocked),
            "{id} should have failed or been blocked, was {:?}\n{}",
            by_id[id],
            run.stderr
        );
    }
    for root in &run.report.roots {
        assert!(flips.contains(root), "root {root} is not an expected flip");
    }
    assert_eq!(run.report.verdict, keel::Verdict::Fail);
    assert_ne!(run.exit_code, Some(0), "a run with roots must fail");
    assert!(
        run.stderr.contains("BLOCKED [ by rust:") && run.stderr.contains("ROOT  rust:"),
        "blocked tests and roots are printed:\n{}",
        run.stderr
    );
    assert!(!run.report.roots.is_empty());
    let closure = dependents_closure(&synth, &mutated);
    let root_set: BTreeSet<&NodeId> = run.report.roots.iter().collect();
    let blocked_in_dependent = run.report.nodes.iter().any(|record| {
        record.status == Status::Blocked
            && crate_of[&record.id] != mutated
            && record.blocked_by.iter().any(|by| {
                root_set.contains(by) && by.as_str().starts_with(&format!("rust:{mutated}"))
            })
    });
    assert!(
        closure.len() == 1 || blocked_in_dependent,
        "a test in a dependent crate of {mutated} should be blocked by a root in {mutated}\n{}",
        run.stderr
    );
    for t in &tests {
        let krate = t["crate"].as_str().expect("crate");
        if !closure.contains(krate) {
            let id = node_id(t["id"].as_str().expect("id"));
            assert_eq!(
                by_id[&id],
                Status::Cached,
                "{id} does not depend on {mutated}"
            );
        }
    }

    // docs: nothing that is keyed changes.
    h.generate();
    h.mutate("docs");
    let run = h.run_keel("report-docs.json");
    h.record("docs", &run);
    assert_eq!(run.report.counts.cached, total, "{}", run.stderr);

    // fixture: only the mutated package's files key changes.
    h.generate();
    let mutation = h.mutate("fixture");
    let mutated = mutation["crate"]
        .as_str()
        .expect("mutated crate")
        .to_owned();
    let flips: BTreeSet<NodeId> = mutation["expected_flips"]
        .as_array()
        .expect("expected_flips")
        .iter()
        .map(|id| node_id(id.as_str().expect("flip id")))
        .collect();
    let run = h.run_keel("report-fixture.json");
    h.record("fixture", &run);
    let by_id = statuses(&run.report);
    let own: BTreeSet<NodeId> = tests
        .iter()
        .filter(|t| t["crate"] == mutated.as_str())
        .map(|t| node_id(t["id"].as_str().expect("id")))
        .collect();
    for (id, status) in &by_id {
        if own.contains(*id) {
            assert_ne!(
                *status,
                Status::Cached,
                "{id} is in {mutated} and must rerun"
            );
        } else {
            assert_eq!(*status, Status::Cached, "{id} is outside {mutated}");
        }
    }
    for id in &flips {
        assert_eq!(by_id[id], Status::Fail, "{id} reads the mutated fixture");
    }

    println!(
        "\n{:<20} {:>5} {:>7} {:>8} {:>6} {:>6} {:>9}",
        "scenario", "ran", "cached", "blocked", "failed", "roots", "wall"
    );
    for row in &h.rows {
        println!(
            "{:<20} {:>5} {:>7} {:>8} {:>6} {:>6} {:>8.1}s",
            row.scenario,
            row.ran,
            row.cached,
            row.blocked,
            row.failed,
            row.roots,
            row.wall.as_secs_f64()
        );
    }
}
