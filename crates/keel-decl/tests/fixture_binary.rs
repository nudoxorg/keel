//! Compiles `tests/fixture` (a crate that uses keel-macros) with cargo and
//! checks that `read_declarations` recovers exactly what the attributes
//! declared, from the finished test executables, in debug and release.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use keel_decl::{Declaration, applies_to, nextest_test_name, read_declarations};

fn decl(m: &str, f: &str, s: &[&str], j: &[&str]) -> Declaration {
    Declaration {
        module_path: m.into(),
        test_fn: f.into(),
        stands_on: s.iter().map(|x| x.to_string()).collect(),
        joins: j.iter().map(|x| x.to_string()).collect(),
    }
}

/// Test executables by binary crate name (as nextest would name the binary).
fn build_fixture(release: bool) -> BTreeMap<String, PathBuf> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fixture-target");

    let mut cmd = Command::new("cargo-stock");
    cmd.args([
        "test",
        "--no-run",
        "--message-format=json",
        "--manifest-path",
    ])
    .arg(fixture.join("Cargo.toml"));
    if release {
        cmd.arg("--release");
    }
    let out = cmd
        // The ambient wrapper would wrap rustc for the fixture too.
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "")
        .env("CARGO_TARGET_DIR", &target)
        .output()
        .expect("cannot run `cargo-stock`; it must be on PATH to build the fixture crate");
    assert!(
        out.status.success(),
        "fixture build failed ({}):\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let mut found = BTreeMap::new();
    for line in String::from_utf8(out.stdout).unwrap().lines() {
        let msg: serde_json::Value = serde_json::from_str(line).expect("cargo emits JSON lines");
        if msg["reason"] != "compiler-artifact" || msg["profile"]["test"] != true {
            continue;
        }
        let Some(exe) = msg["executable"].as_str() else {
            continue;
        };
        let name = msg["target"]["name"].as_str().unwrap().to_owned();
        found.insert(name, PathBuf::from(exe));
    }
    found
}

fn sorted(mut v: Vec<Declaration>) -> Vec<Declaration> {
    v.sort_by(|a, b| (&a.module_path, &a.test_fn).cmp(&(&b.module_path, &b.test_fn)));
    v
}

fn check(release: bool) {
    let exes = build_fixture(release);
    assert_eq!(
        exes.keys().map(String::as_str).collect::<Vec<_>>(),
        ["flow", "keel_fixture"],
        "fixture should yield one lib and one integration test executable"
    );

    let lib = sorted(read_declarations(&exes["keel_fixture"]).unwrap());
    assert_eq!(
        lib,
        sorted(vec![
            decl(
                "keel_fixture::tests",
                "both_stands_on_first",
                &["unit(backend-version)", "unit(backend-platform)"],
                &["backend-store", "backend-flow"],
            ),
            decl(
                "keel_fixture::tests",
                "both_joins_first",
                &["integration(backend-flow)"],
                &["backend-store", "backend-flow"],
            ),
            decl(
                "keel_fixture::tests",
                "only_stands_on",
                &["unit(backend-version)"],
                &[]
            ),
            decl("keel_fixture::tests", "only_joins", &[], &["backend-store"]),
            decl(
                "keel_fixture::tests",
                "node_id_and_should_panic",
                &["rust:backend-store::wal::replays_torn_tail"],
                &[],
            ),
            decl(
                "keel_fixture::tests",
                "async_tokio_outer",
                &["unit(backend-version)"],
                &[]
            ),
            decl(
                "keel_fixture::tests",
                "async_keel_outer_should_panic",
                &["unit(backend-version)"],
                &[]
            ),
            decl(
                "keel_fixture::tests",
                "param",
                &["unit(backend-version)"],
                &[]
            ),
            decl("keel_fixture::tests::a", "t", &["unit(a)"], &[]),
            decl("keel_fixture::tests::b", "t", &["unit(b)"], &[]),
            decl(
                "keel_fixture::tests::nested",
                "deep",
                &["unit(backend-version)"],
                &[]
            ),
            decl(
                "keel_fixture",
                "at_crate_root",
                &["unit(backend-platform)"],
                &[]
            ),
        ])
    );

    let flow = sorted(read_declarations(&exes["flow"]).unwrap());
    assert_eq!(
        flow,
        sorted(vec![
            decl(
                "flow",
                "top_level",
                &["unit(keel-fixture)"],
                &["keel-fixture", "backend-flow"]
            ),
            decl(
                "flow::cases",
                "inside_module",
                &["integration(keel-fixture)"],
                &[]
            ),
        ])
    );

    // The names must be the ones libtest (and therefore nextest) lists.
    for (crate_name, decls) in [("keel_fixture", &lib), ("flow", &flow)] {
        let listing = Command::new(&exes[crate_name])
            .args(["--list", "--format", "terse"])
            .output()
            .unwrap();
        let listing = String::from_utf8(listing.stdout).unwrap();
        let listed: Vec<&str> = listing
            .lines()
            .filter_map(|l| l.strip_suffix(": test"))
            .collect();
        for d in decls {
            let name = nextest_test_name(d, crate_name);
            assert!(
                listed.iter().any(|l| applies_to(&name, l)),
                "{name} applies to no test in the binary's own list:\n{listing}"
            );
        }
        if crate_name == "keel_fixture" {
            // rstest expands `param` into `param::case_N`; the record names `param`.
            assert!(listed.contains(&"tests::param::case_1"), "{listing}");
            assert!(!listed.contains(&"tests::param"), "{listing}");
        }
    }
}

#[test]
fn declarations_survive_debug_build() {
    check(false);
}

#[test]
fn declarations_survive_release_build() {
    check(true);
}
