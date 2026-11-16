//! Attestations (sign, verify, refuse) and report merging, through the real binary.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::Tmp;
use keel::Report;

const REV: &str = "0123456789abcdef0123456789abcdef01234567";

fn bin(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_keel-conduct"))
        .args(args)
        .output()
        .unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn text(o: &[u8]) -> String {
    String::from_utf8_lossy(o).into_owned()
}

/// A report with the given `(id, status)` nodes; roots and verdict are derived.
fn report(repo: &str, revision: &str, nodes: &[(&str, &str)]) -> Report {
    let nodes: Vec<_> = nodes
        .iter()
        .map(|(id, st)| serde_json::json!({"id": id, "key": format!("blake3:{}", "11".repeat(32)), "status": st}))
        .collect();
    let mut r: Report = serde_json::from_value(serde_json::json!({
        "schema": 1, "run_id": "run-1", "repo": repo, "revision": revision,
        "platform": {"triple": "aarch64-darwin", "toolchain": "t", "net": "open"},
        "verdict": "pass", "started_at": "2026-11-14T08:00:00Z", "duration_ms": 10,
        "counts": {}, "roots": [], "nodes": nodes
    }))
    .unwrap();
    r.derive();
    r
}

struct Setup {
    dir: Tmp,
}

impl Setup {
    fn new() -> Setup {
        let dir = Tmp::new("attest");
        for name in ["a", "b"] {
            let o = bin(&[
                "keygen",
                "--secret",
                s(&dir.path().join(format!("{name}.key"))),
                "--public",
                s(&dir.path().join(format!("{name}.pub"))),
            ]);
            assert!(o.status.success(), "{}", text(&o.stderr));
        }
        dir.write(
            "policy.toml",
            "name = \"deploy-main\"\nrequire = [\"go:m/api\", \"nu:web-contract\"]\n",
        );
        Setup { dir }
    }

    fn put_report(&self, r: &Report) {
        self.dir
            .write("report.json", &serde_json::to_string_pretty(r).unwrap());
    }

    fn p(&self, name: &str) -> String {
        self.dir.path().join(name).to_str().unwrap().to_owned()
    }

    fn attest(&self, key: &str) -> Output {
        bin(&[
            "attest",
            "--report",
            &self.p("report.json"),
            "--key",
            &self.p(key),
            "--policy",
            &self.p("policy.toml"),
            "--out",
            &self.p("att.json"),
        ])
    }

    fn verify(&self, public: &str, policy: &str) -> Output {
        bin(&[
            "verify",
            "--attestation",
            &self.p("att.json"),
            "--report",
            &self.p("report.json"),
            "--public-key",
            &self.p(public),
            "--require-policy",
            policy,
        ])
    }
}

const GREEN: &[(&str, &str)] = &[
    ("go:m/api", "pass"),
    ("nu:web-contract", "cached"),
    ("go:m/db", "pass"),
];

#[test]
fn round_trip_signs_and_verifies_offline() {
    let t = Setup::new();
    t.put_report(&report("Nudox/x", REV, GREEN));
    let o = t.attest("a.key");
    assert!(o.status.success(), "{}", text(&o.stderr));
    let att: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(t.p("att.json")).unwrap()).unwrap();
    assert_eq!(att["verdict"], "pass");
    assert_eq!(att["nodes_green"], 3);
    assert_eq!(att["revision"], REV);
    assert!(
        att["report_digest"]
            .as_str()
            .unwrap()
            .starts_with("blake3:")
    );
    assert_eq!(att["policy"]["name"], "deploy-main");
    let o = t.verify("a.pub", "deploy-main");
    assert!(o.status.success(), "{}", text(&o.stderr));
    let o = bin(&[
        "verify",
        "--attestation",
        &t.p("att.json"),
        "--report",
        &t.p("report.json"),
        "--public-key",
        &t.p("a.pub"),
        "--require-policy",
        "deploy-main",
        "--revision",
        REV,
        "--policy",
        &t.p("policy.toml"),
    ]);
    assert!(o.status.success(), "{}", text(&o.stderr));
}

#[test]
fn a_tampered_report_fails_the_digest_check() {
    let t = Setup::new();
    let mut r = report("Nudox/x", REV, GREEN);
    t.put_report(&r);
    assert!(t.attest("a.key").status.success());
    // Same verdict, different bytes: an unrelated node's duration.
    r.nodes[2].duration_ms = Some(999);
    t.put_report(&r);
    let o = t.verify("a.pub", "deploy-main");
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o.stderr).contains("`report-digest`"),
        "{}",
        text(&o.stderr)
    );
}

#[test]
fn a_whitespace_only_change_to_the_report_is_not_tampering() {
    let t = Setup::new();
    let r = report("Nudox/x", REV, GREEN);
    t.put_report(&r);
    assert!(t.attest("a.key").status.success());
    t.dir
        .write("report.json", &serde_json::to_string(&r).unwrap());
    assert!(t.verify("a.pub", "deploy-main").status.success());
}

#[test]
fn the_wrong_key_fails_the_signature_check() {
    let t = Setup::new();
    t.put_report(&report("Nudox/x", REV, GREEN));
    assert!(t.attest("a.key").status.success());
    let o = t.verify("b.pub", "deploy-main");
    assert_eq!(o.status.code(), Some(1));
    let err = text(&o.stderr);
    assert!(
        err.contains("`signature`") && err.contains("different key"),
        "{err}"
    );
}

#[test]
fn an_edited_attestation_fails_the_signature_check() {
    let t = Setup::new();
    t.put_report(&report("Nudox/x", REV, GREEN));
    assert!(t.attest("a.key").status.success());
    let raw = std::fs::read_to_string(t.p("att.json")).unwrap();
    t.dir.write("att.json", &raw.replace(REV, &"f".repeat(40)));
    let o = t.verify("a.pub", "deploy-main");
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o.stderr).contains("`signature`"),
        "{}",
        text(&o.stderr)
    );
}

#[test]
fn a_missing_or_red_required_node_refuses_to_sign() {
    let t = Setup::new();
    t.put_report(&report(
        "Nudox/x",
        REV,
        &[("go:m/api", "pass"), ("go:m/db", "pass")],
    ));
    let o = t.attest("a.key");
    assert!(!o.status.success());
    let err = text(&o.stderr);
    assert!(
        err.contains("nu:web-contract")
            && err.contains("missing")
            && err.contains("refusing to sign"),
        "{err}"
    );
    assert!(!Path::new(&t.p("att.json")).exists());

    t.put_report(&report(
        "Nudox/x",
        REV,
        &[("go:m/api", "fail"), ("nu:web-contract", "pass")],
    ));
    let err = text(&t.attest("a.key").stderr);
    assert!(err.contains("go:m/api is fail"), "{err}");
}

#[test]
fn a_failed_run_can_be_attested_but_never_verified() {
    let t = Setup::new();
    // The required nodes are green, but an unrelated node is a root.
    t.put_report(&report(
        "Nudox/x",
        REV,
        &[
            ("go:m/api", "pass"),
            ("nu:web-contract", "pass"),
            ("go:m/other", "fail"),
        ],
    ));
    assert!(t.attest("a.key").status.success());
    let o = t.verify("a.pub", "deploy-main");
    assert_eq!(o.status.code(), Some(1));
    let err = text(&o.stderr);
    assert!(
        err.contains("`verdict`") && err.contains("go:m/other"),
        "{err}"
    );
}

#[test]
fn the_policy_name_is_checked() {
    let t = Setup::new();
    t.put_report(&report("Nudox/x", REV, GREEN));
    assert!(t.attest("a.key").status.success());
    let o = t.verify("a.pub", "deploy-prod");
    assert_eq!(o.status.code(), Some(1));
    assert!(text(&o.stderr).contains("`policy`"), "{}", text(&o.stderr));
}

#[test]
fn a_report_whose_header_lies_is_not_attested() {
    let t = Setup::new();
    let mut r = report(
        "Nudox/x",
        REV,
        &[("go:m/api", "fail"), ("nu:web-contract", "pass")],
    );
    r.verdict = keel::Verdict::Pass;
    r.roots.clear();
    t.put_report(&r);
    let o = t.attest("a.key");
    assert!(!o.status.success());
    assert!(
        text(&o.stderr).contains("cannot be attested"),
        "{}",
        text(&o.stderr)
    );
}

#[test]
fn groups_resolve_through_the_manifest() {
    let t = Setup::new();
    t.put_report(&report(
        "Nudox/x",
        REV,
        &[
            ("go:m/api", "pass"),
            ("go:m/db", "pass"),
            ("nu:web-contract", "pass"),
        ],
    ));
    t.dir
        .write("policy.toml", "name = \"g\"\nrequire = [\"unit(go:m)\"]\n");
    let nodes: Vec<_> = ["go:m/api", "go:m/db"]
        .iter()
        .map(|id| serde_json::json!({
            "id": id, "kind": "go-test", "group": "unit(go:m)", "key": format!("blake3:{}", "11".repeat(32))
        }))
        .collect();
    let manifest = serde_json::json!({
        "schema": 1, "producer": "t", "repo": "Nudox/x", "revision": REV,
        "platform": {"triple": "t", "toolchain": "t", "net": "open"},
        "nodes": nodes
    });
    t.dir.write("manifest.json", &manifest.to_string());
    let without = t.attest("a.key");
    assert!(!without.status.success() && text(&without.stderr).contains("--manifest"));
    let o = bin(&[
        "attest",
        "--report",
        &t.p("report.json"),
        "--key",
        &t.p("a.key"),
        "--policy",
        &t.p("policy.toml"),
        "--manifest",
        &t.p("manifest.json"),
        "--out",
        &t.p("att.json"),
    ]);
    assert!(o.status.success(), "{}", text(&o.stderr));
}

#[test]
fn merge_rederives_roots_and_checks_pins() {
    let t = Setup::new();
    let a = report("Nudox/Backend", REV, &[("rust:a", "pass")]);
    let mut b = report(
        "Nudox/nudox-auth",
        "b".repeat(40).as_str(),
        &[("go:x", "fail")],
    );
    b.run_id = "run-2".into();
    t.dir.write("a.json", &serde_json::to_string(&a).unwrap());
    t.dir.write("b.json", &serde_json::to_string(&b).unwrap());
    t.dir.write(
        "pins.json",
        &format!(
            "{{\"Nudox/Backend\": \"{REV}\", \"Nudox/nudox-auth\": \"{}\"}}",
            "b".repeat(40)
        ),
    );
    let o = bin(&[
        "merge",
        &t.p("a.json"),
        &t.p("b.json"),
        "--out",
        &t.p("m.json"),
        "--pins",
        &t.p("pins.json"),
    ]);
    assert_eq!(
        o.status.code(),
        Some(1),
        "merged verdict follows the failed root: {}",
        text(&o.stderr)
    );
    let m: Report = serde_json::from_str(&std::fs::read_to_string(t.p("m.json")).unwrap()).unwrap();
    assert_eq!(m.nodes.len(), 2);
    assert_eq!(m.roots, vec!["go:x".into()]);

    // A report of a revision other than the pinned one is refused.
    t.dir.write(
        "pins.json",
        &format!("{{\"Nudox/Backend\": \"{}\"}}", "c".repeat(40)),
    );
    let o = bin(&[
        "merge",
        &t.p("a.json"),
        &t.p("b.json"),
        "--out",
        &t.p("m2.json"),
        "--pins",
        &t.p("pins.json"),
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o.stderr).contains("pins"), "{}", text(&o.stderr));
}
