//! nushell, command and artifact nodes.

mod common;

use common::*;
use keel::Status;
use keel_conduct::config::Config;
use keel_conduct::run::plan_all;

fn fixture() -> Tmp {
    let t = Tmp::new("nu");
    t.write("checks/lib.nu", "export def answer [] { 42 }\n");
    // The check also asserts the clean environment: PATH is the one directory
    // of declared tools, and an ambient variable is invisible.
    t.write(
        "checks/ok.nu",
        "use lib.nu\nif (lib answer) != 42 { exit 1 }\nif ($env.PATH | length) != 1 { error make {msg: 'PATH is not just the tools'} }\nif ($env | get -o KEEL_TEST_LEAK) != null { error make {msg: 'ambient variable leaked'} }\n",
    );
    t.write(
        "checks/bad.nu",
        "print 'about to fail'\nerror make {msg: 'the check is red'}\n",
    );
    t.write(
        "keel.toml",
        r#"
[[node]]
id = "ok"
command = ["nu", "checks/ok.nu"]

[[node]]
id = "bad"
command = ["nu", "checks/bad.nu"]
timeout_s = 60

[[node]]
id = "above-bad"
command = ["nu", "checks/ok.nu"]
stands_on = ["nu:bad"]
"#,
    );
    t
}

fn key_of(t: &Tmp, id: &str) -> keel::Digest {
    let cfg = Config::load(&t.path().join("keel.toml")).unwrap();
    plan_all(&cfg, t.path(), None)
        .unwrap()
        .iter()
        .find(|p| p.node.id.as_str() == id)
        .unwrap()
        .node
        .key
}

#[test]
fn nushell_nodes_run_cache_and_follow_used_modules() {
    if !nu_available() {
        return;
    }
    let t = fixture();
    let store = Tmp::new("nu-store");
    let r1 = conduct(t.path(), store.path(), None);
    assert_eq!(
        status(&r1, "nu:ok"),
        Status::Pass,
        "{:?}",
        rec(&r1, "nu:ok").detail
    );
    assert_eq!(status(&r1, "nu:bad"), Status::Fail);
    assert!(
        rec(&r1, "nu:bad")
            .detail
            .as_ref()
            .unwrap()
            .actual
            .as_ref()
            .unwrap()
            .contains("the check is red")
    );
    assert_eq!(status(&r1, "nu:above-bad"), Status::Blocked);
    assert_eq!(rec(&r1, "nu:above-bad").blocked_by, vec!["nu:bad".into()]);
    assert_eq!(r1.verdict, keel::Verdict::Fail);

    let r2 = conduct(t.path(), store.path(), None);
    assert_eq!(status(&r2, "nu:ok"), Status::Cached);
    assert_eq!(
        status(&r2, "nu:bad"),
        Status::Fail,
        "a stored failure is never a cache hit"
    );

    // An edit to a module the script `use`s changes the script's key, and
    // only the scripts that load it.
    let (ok, bad) = (key_of(&t, "nu:ok"), key_of(&t, "nu:bad"));
    t.write("checks/lib.nu", "export def answer [] { 42 }\n# touched\n");
    assert_ne!(key_of(&t, "nu:ok"), ok);
    assert_eq!(key_of(&t, "nu:bad"), bad);
}

#[test]
fn a_missing_used_module_is_a_plan_error() {
    if !nu_available() {
        return;
    }
    let t = fixture();
    t.write("checks/ok.nu", "use gone.nu\n");
    let cfg = Config::load(&t.path().join("keel.toml")).unwrap();
    let err = plan_all(&cfg, t.path(), None)
        .err()
        .expect("must fail")
        .to_string();
    assert!(
        err.contains("gone.nu") && err.contains("cannot be keyed"),
        "{err}"
    );
}

#[test]
fn artifacts_flow_from_producer_to_consumer() {
    if !nu_available() {
        return;
    }
    let t = Tmp::new("artifact");
    t.write("gen.nu", "mkdir out\n'payload-v1' | save -f out/data.txt\n");
    t.write(
        "use.nu",
        "let got = (open --raw ($env.KEEL_CONSUMED | path join 'nu:producer' 'out' 'data.txt') | str trim)\nif $got != 'payload-v1' { error make {msg: $'consumer saw ($got)'} }\n",
    );
    t.write(
        "keel.toml",
        r#"
[[node]]
id = "producer"
command = ["nu", "gen.nu"]
produces = ["out"]

[[node]]
id = "consumer"
command = ["nu", "use.nu"]
consumes = ["producer"]
"#,
    );
    let store = Tmp::new("artifact-store");
    let r1 = conduct(t.path(), store.path(), None);
    assert_eq!(
        status(&r1, "nu:producer"),
        Status::Pass,
        "{:?}",
        rec(&r1, "nu:producer").detail
    );
    assert_eq!(
        status(&r1, "nu:consumer"),
        Status::Pass,
        "{:?}",
        rec(&r1, "nu:consumer").detail
    );
    assert!(
        rec(&r1, "nu:producer")
            .evidence
            .iter()
            .any(|e| e.name == "artifact:out/data.txt")
    );

    // Everything cached: the consumer still receives the producer's files
    // from the store because the producer's blobs are there.
    let (pk, ck) = (key_of(&t, "nu:producer"), key_of(&t, "nu:consumer"));
    let r2 = conduct(t.path(), store.path(), None);
    assert_eq!(status(&r2, "nu:producer"), Status::Cached);
    assert_eq!(status(&r2, "nu:consumer"), Status::Cached);

    // A producer edit changes the consumer's key although its own files did not move.
    t.write(
        "gen.nu",
        "mkdir out\n'payload-v1' | save -f out/data.txt\n# touched\n",
    );
    assert_ne!(key_of(&t, "nu:producer"), pk);
    assert_ne!(key_of(&t, "nu:consumer"), ck);
    let r3 = conduct(t.path(), store.path(), None);
    assert_eq!(status(&r3, "nu:producer"), Status::Pass);
    assert_eq!(status(&r3, "nu:consumer"), Status::Pass);
}

#[test]
fn a_negative_control_must_fail() {
    if !nu_available() {
        return;
    }
    let t = Tmp::new("control");
    t.write("good.nu", "print 'fine'\n");
    t.write("bad.nu", "error make {msg: 'refused'}\n");
    t.write(
        "keel.toml",
        r#"
[[node]]
id = "twin"
command = ["nu", "good.nu"]

[[node]]
id = "control-ok"
command = ["nu", "bad.nu"]
control = "negative"
expect_exit = [1]
expect_output = "refused"
twin = "twin"

[[node]]
id = "control-bad"
command = ["nu", "good.nu"]
control = "negative"
expect_exit = [1]
twin = "twin"
"#,
    );
    let r = conduct(t.path(), Tmp::new("control-store").path(), None);
    assert_eq!(status(&r, "nu:control-ok"), Status::Pass);
    assert_eq!(status(&r, "nu:control-bad"), Status::Fail);
    assert_eq!(
        rec(&r, "nu:control-bad").reason.as_deref(),
        Some(keel::CONTROL_DID_NOT_FAIL)
    );
    assert_eq!(r.roots, vec!["nu:control-bad".into()]);
}

#[test]
fn a_node_standing_on_a_failed_foreign_node_is_blocked_at_the_pinned_revision() {
    if !nu_available() {
        return;
    }
    use keel_conduct::pins::Pins;
    use keel_conduct::run::{self, RunOpts};
    let t = Tmp::new("foreign");
    t.write("ok.nu", "print 'fine'\n");
    t.write(
        "keel.toml",
        "[[node]]\nid = \"web\"\ncommand = [\"nu\", \"ok.nu\"]\nstands_on = [\"rust:backend-store::wal::replays\"]\n",
    );
    let rev = "b".repeat(40);
    let upstream: keel::Report = serde_json::from_value(serde_json::json!({
        "schema": 1, "run_id": "r", "repo": "Nudox/Backend", "revision": rev,
        "platform": {"triple": "t", "toolchain": "t", "net": "open"},
        "verdict": "fail", "started_at": "2026-11-14T08:00:00Z", "duration_ms": 1,
        "counts": {}, "roots": [],
        "nodes": [{"id": "rust:backend-store::wal::replays", "key": format!("blake3:{}", "11".repeat(32)), "status": "fail"}]
    }))
    .unwrap();
    let cfg = Config::load(&t.path().join("keel.toml")).unwrap();
    let store =
        keel_conduct::store::Store::open(Tmp::new("foreign-store").path().to_str().unwrap())
            .unwrap();
    let opts = |pin: &str| RunOpts {
        repo_root: t.path().to_path_buf(),
        revision: "a".repeat(40),
        jobs: 1,
        no_block: false,
        go: None,
        work_dir: None,
        upstream: vec![upstream.clone()],
        pins: Some(Pins([("Nudox/Backend".to_owned(), pin.to_owned())].into())),
    };
    let out = run::run(&cfg, &store, &opts(&rev)).unwrap();
    let web = rec(&out.report, "nu:web");
    assert_eq!(web.status, Status::Blocked);
    assert_eq!(
        web.blocked_by,
        vec!["rust:backend-store::wal::replays".into()]
    );
    // Pinned to another revision, the same report is refused rather than trusted.
    let err = run::run(&cfg, &store, &opts(&"c".repeat(40)))
        .err()
        .expect("must refuse")
        .to_string();
    assert!(err.contains("pins"), "{err}");
}

#[test]
fn a_negative_control_that_could_not_run_is_not_a_pass() {
    if !nu_available() {
        return;
    }
    let t = Tmp::new("control-unrunnable");
    t.write("good.nu", "print 'fine'\n");
    // 127: the shell could not find the program. 126: found, not executable.
    // A signal: the process died, it did not fail by its own logic.
    t.write(
        "keel.toml",
        r#"
[[node]]
id = "twin"
command = ["nu", "good.nu"]

[[node]]
id = "not-found"
command = ["sh", "-c", "exit 127"]
control = "negative"
expect_exit = [1]
twin = "twin"

[[node]]
id = "not-executable"
command = ["sh", "-c", "exit 126"]
control = "negative"
expect_exit = [1]
twin = "twin"

[[node]]
id = "signalled"
command = ["sh", "-c", "kill -9 $$"]
control = "negative"
expect_exit = [1]
twin = "twin"

[[node]]
id = "other-code"
command = ["sh", "-c", "echo refused >&2; exit 2"]
control = "negative"
expect_exit = [1]
twin = "twin"

[[node]]
id = "other-text"
command = ["sh", "-c", "echo something else; exit 1"]
control = "negative"
expect_exit = [1]
expect_output = "refused"
twin = "twin"

[[node]]
id = "declared"
command = ["sh", "-c", "echo refused >&2; exit 3"]
control = "negative"
expect_exit = [3, 4]
expect_output = "refused"
twin = "twin"
"#,
    );
    let r = conduct(t.path(), Tmp::new("control-unrunnable-store").path(), None);
    for id in ["nu:not-found", "nu:not-executable", "nu:signalled"] {
        assert_eq!(status(&r, id), Status::Error, "{id}: {:?}", rec(&r, id));
        let d = rec(&r, id).detail.as_ref().unwrap().actual.clone().unwrap();
        assert!(d.contains("could not run"), "{id}: {d}");
    }
    // It ran and failed, but not the declared way: a failure, and a distinct one.
    for id in ["nu:other-code", "nu:other-text"] {
        assert_eq!(status(&r, id), Status::Fail, "{id}");
        assert_eq!(
            rec(&r, id).reason.as_deref(),
            Some("control-failed-differently"),
            "{id}"
        );
    }
    assert_eq!(status(&r, "nu:declared"), Status::Pass);
}

#[test]
fn a_negative_control_must_declare_how_it_fails() {
    let t = Tmp::new("control-undeclared");
    t.write("good.nu", "print 'fine'\n");
    let plan = |extra: &str| {
        t.write(
            "keel.toml",
            &format!(
                "[[node]]\nid = \"twin\"\ncommand = [\"nu\", \"good.nu\"]\n\n[[node]]\nid = \"c\"\ncommand = [\"nu\", \"good.nu\"]\ncontrol = \"negative\"\ntwin = \"twin\"\n{extra}\n"
            ),
        );
        let cfg = Config::load(&t.path().join("keel.toml")).unwrap();
        plan_all(&cfg, t.path(), None).map(|p| p.len())
    };
    if !nu_available() {
        return;
    }
    let msg = format!("{:#}", plan("").unwrap_err());
    assert!(
        msg.contains("expect_exit")
            && msg.contains("expect_output")
            && msg.contains("any non-zero exit"),
        "{msg}"
    );
    for bad in [
        "expect_exit = [0]",
        "expect_exit = [126]",
        "expect_exit = [127]",
        "expect_exit = [256]",
    ] {
        let msg = format!("{:#}", plan(bad).unwrap_err());
        assert!(msg.contains("not a way to fail"), "{bad}: {msg}");
    }
    assert_eq!(plan("expect_exit = [1]").unwrap(), 2);
    assert_eq!(plan("expect_output = \"refused\"").unwrap(), 2);
    // Expectations on a node that is not a control are a mistake, not a no-op.
    t.write(
        "keel.toml",
        "[[node]]\nid = \"a\"\ncommand = [\"nu\", \"good.nu\"]\nexpect_exit = [1]\n",
    );
    let cfg = Config::load(&t.path().join("keel.toml")).unwrap();
    let msg = format!("{:#}", plan_all(&cfg, t.path(), None).err().unwrap());
    assert!(msg.contains("not a negative control"), "{msg}");
}
