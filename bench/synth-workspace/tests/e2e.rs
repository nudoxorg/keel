//! End-to-end checks: generate a real workspace, build and run it with stock
//! cargo, and compare what actually failed with what `mutate` predicted.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

/// Builds share one target directory (serde_json compiles once), so they must
/// not overlap.
static CARGO_LOCK: Mutex<()> = Mutex::new(());

fn tmp(name: &str) -> PathBuf {
    let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn synth(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_synth-workspace"))
        .args(args)
        .output()
        .expect("spawn synth-workspace")
}

fn synth_ok(args: &[&str]) {
    let o = synth(args);
    assert!(
        o.status.success(),
        "synth-workspace {args:?} failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

fn generate_s(name: &str) -> PathBuf {
    let ws = tmp(name);
    synth_ok(&[
        "generate",
        "--out",
        ws.to_str().unwrap(),
        "--shape",
        "S",
        "--seed",
        "7",
    ]);
    ws
}

fn mutate(ws: &Path, pattern: &str) -> Vec<String> {
    synth_ok(&[
        "mutate",
        "--workspace",
        ws.to_str().unwrap(),
        "--pattern",
        pattern,
        "--seed",
        "3",
    ]);
    let rec: Value =
        serde_json::from_slice(&std::fs::read(ws.join("mutation.json")).unwrap()).unwrap();
    rec["expected_flips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

fn cargo(ws: &Path, args: &[&str]) -> (bool, String) {
    let (mut reader, writer) = std::io::pipe().unwrap();
    let mut child = {
        let mut c = Command::new("cargo-stock");
        c.args(args)
            .current_dir(ws)
            .env("RUSTC_WRAPPER", "")
            // Debuginfo only costs compile time here; the generated profile is still exercised.
            .env("CARGO_PROFILE_TEST_DEBUG", "0")
            .env("CARGO_PROFILE_DEV_DEBUG", "0")
            .env(
                "CARGO_TARGET_DIR",
                Path::new(env!("CARGO_TARGET_TMPDIR")).join("shared-target"),
            )
            .stdout(writer.try_clone().unwrap())
            .stderr(writer);
        c.spawn().expect("spawn cargo-stock; it must be on PATH")
    };
    // One pipe for both streams keeps cargo's `Running` headers in order with the test output.
    let mut out = String::new();
    reader.read_to_string(&mut out).unwrap();
    (child.wait().unwrap().success(), out)
}

/// Executable file name -> nextest binary id, from cargo's build messages.
fn binary_ids(ws: &Path) -> BTreeMap<String, String> {
    let (ok, out) = cargo(ws, &["test", "--no-run", "--message-format", "json"]);
    assert!(ok, "test build failed:\n{out}");
    let mut map = BTreeMap::new();
    for line in out.lines().filter(|l| l.starts_with('{')) {
        let m: Value = serde_json::from_str(line).unwrap();
        if m["reason"] != "compiler-artifact"
            || m["profile"]["test"] != true
            || m["executable"].is_null()
        {
            continue;
        }
        let pkg_id = m["package_id"].as_str().unwrap();
        // `path+file:///dir/c000#0.1.0` omits the name when it equals the directory name.
        let (head, frag) = pkg_id.rsplit_once('#').unwrap();
        let pkg = frag
            .split_once('@')
            .map_or_else(|| head.rsplit('/').next().unwrap(), |(n, _)| n)
            .to_string();
        let file = Path::new(m["executable"].as_str().unwrap())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let id = if m["target"]["kind"][0] == "lib" {
            pkg
        } else {
            format!("{pkg}::{}", m["target"]["name"].as_str().unwrap())
        };
        map.insert(file, id);
    }
    map
}

/// Runs the whole suite without stopping at failures; returns id -> passed.
fn run_all(ws: &Path) -> BTreeMap<String, bool> {
    let ids = binary_ids(ws);
    let (_, out) = cargo(ws, &["test", "--no-fail-fast"]);
    let mut current: Option<String> = None;
    let mut results = BTreeMap::new();
    for line in out.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("Running ") {
            let exe = rest
                .rsplit_once('(')
                .map(|(_, p)| p.trim_end_matches(')'))
                .unwrap();
            current = ids
                .get(Path::new(exe).file_name().unwrap().to_str().unwrap())
                .cloned();
            assert!(current.is_some(), "unknown test binary in header: {line}");
        } else if line.starts_with("Doc-tests") {
            current = None;
        } else if let Some(rest) = line
            .strip_prefix("test ")
            .filter(|r| !r.starts_with("result:"))
        {
            let (name, status) = rest.rsplit_once(" ... ").unwrap();
            if let Some(b) = &current {
                results.insert(format!("{b} {name}"), status == "ok");
            }
        }
    }
    results
}

fn synth_ids(ws: &Path) -> BTreeSet<String> {
    let s: Value = serde_json::from_slice(&std::fs::read(ws.join("synth.json")).unwrap()).unwrap();
    s["tests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap().to_string())
        .collect()
}

/// Mutate (or not), run everything, require failures == predicted flips and
/// the test population == synth.json's.
fn check(pattern: Option<&str>, name: &str, expect_flips: bool) {
    let _guard = CARGO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ws = generate_s(name);
    let expected: BTreeSet<String> = pattern
        .map(|p| mutate(&ws, p))
        .unwrap_or_default()
        .into_iter()
        .collect();
    assert_eq!(
        !expected.is_empty(),
        expect_flips,
        "{name}: unexpected prediction size {}",
        expected.len()
    );
    let results = run_all(&ws);
    let ran: BTreeSet<String> = results.keys().cloned().collect();
    let listed = synth_ids(&ws);
    assert!(
        ran == listed,
        "{name}: tests that ran differ from synth.json; ran-only {:?}, listed-only {:?}",
        ran.difference(&listed).take(5).collect::<Vec<_>>(),
        listed.difference(&ran).take(5).collect::<Vec<_>>()
    );
    let failed: BTreeSet<String> = results
        .iter()
        .filter(|(_, ok)| !**ok)
        .map(|(k, _)| k.clone())
        .collect();
    assert!(
        failed == expected,
        "{name}: failing tests differ from expected_flips; failed-only {:?}, expected-only {:?}",
        failed.difference(&expected).take(5).collect::<Vec<_>>(),
        expected.difference(&failed).take(5).collect::<Vec<_>>()
    );
}

#[test]
fn pristine_shape_s_passes() {
    check(None, "pristine", false);
}

#[test]
fn body_root_flips_exactly_the_predicted_tests() {
    check(Some("body-root"), "body-root", true);
}

#[test]
fn comment_root_flips_nothing() {
    check(Some("comment-root"), "comment-root", false);
}

#[test]
fn docs_flips_nothing() {
    check(Some("docs"), "docs", false);
}

#[test]
fn fixture_flips_exactly_the_predicted_tests() {
    check(Some("fixture"), "fixture", true);
}

#[test]
fn body_leaf_flips_exactly_the_predicted_tests() {
    check(Some("body-leaf"), "body-leaf", true);
}

#[test]
fn comment_leaf_flips_nothing() {
    check(Some("comment-leaf"), "comment-leaf", false);
}

#[test]
fn signature_root_keeps_every_test_passing() {
    check(Some("signature-root"), "signature-root", false);
}

#[test]
fn dep_add_keeps_every_test_passing() {
    check(Some("dep-add"), "dep-add", false);
}

#[test]
fn same_seed_same_workspace() {
    let (a, b) = (tmp("det-a"), tmp("det-b"));
    for d in [&a, &b] {
        synth_ok(&[
            "generate",
            "--out",
            d.to_str().unwrap(),
            "--shape",
            "S",
            "--seed",
            "11",
        ]);
    }
    for f in [
        "synth.json",
        "crates/c003/src/lib.rs",
        "crates/c005/tests/bin01.rs",
        "crates/c000/fixtures/f1.txt",
    ] {
        assert_eq!(
            std::fs::read(a.join(f)).unwrap(),
            std::fs::read(b.join(f)).unwrap(),
            "{f} differs between runs"
        );
    }
}

#[test]
fn mutate_refuses_twice_without_force() {
    let ws = generate_s("twice");
    synth_ok(&[
        "mutate",
        "--workspace",
        ws.to_str().unwrap(),
        "--pattern",
        "docs",
    ]);
    let again = synth(&[
        "mutate",
        "--workspace",
        ws.to_str().unwrap(),
        "--pattern",
        "docs",
    ]);
    assert!(!again.status.success(), "second mutate should be refused");
    synth_ok(&[
        "mutate",
        "--workspace",
        ws.to_str().unwrap(),
        "--pattern",
        "docs",
        "--force",
    ]);
}

#[test]
fn structure_matches_the_request() {
    let ws = tmp("structure");
    synth_ok(&[
        "generate",
        "--out",
        ws.to_str().unwrap(),
        "--crates",
        "20",
        "--depth",
        "7",
        "--fan-in",
        "3",
        "--tests-per-crate",
        "10",
        "--integration-bins-per-crate",
        "2",
        "--fixtures-per-crate",
        "3",
    ]);
    let s: Value = serde_json::from_slice(&std::fs::read(ws.join("synth.json")).unwrap()).unwrap();
    let crates = s["crates"].as_array().unwrap();
    assert_eq!(crates.len(), 20);
    let level_of: BTreeMap<&str, u64> = crates
        .iter()
        .map(|c| (c["name"].as_str().unwrap(), c["level"].as_u64().unwrap()))
        .collect();
    // Longest chain is exactly depth, every level is populated, and each edge goes strictly down with a level-1 anchor.
    for l in 0..7 {
        assert!(level_of.values().any(|&v| v == l), "level {l} is empty");
    }
    for c in crates {
        let l = c["level"].as_u64().unwrap();
        let deps: Vec<u64> = c["deps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| level_of[d.as_str().unwrap()])
            .collect();
        assert!(deps.iter().all(|&d| d < l));
        if l > 0 {
            let below = level_of.values().filter(|&&v| v < l).count();
            assert!(
                deps.contains(&(l - 1)) && deps.len() == 3.min(below),
                "crate {} lacks a level-{} dependency",
                c["name"],
                l - 1
            );
        }
    }
    assert_eq!(s["tests"].as_array().unwrap().len(), 200);
}
