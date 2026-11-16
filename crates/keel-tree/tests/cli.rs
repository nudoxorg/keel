//! The command line, as a person runs it.

use std::process::Command;

fn have(program: &str) -> bool {
    Command::new(program).arg("--version").output().is_ok_and(|o| o.status.success())
}

#[test]
fn the_index_cache_defaults_to_a_directory_inside_the_root_and_help_says_so() {
    let help = Command::new(env!("CARGO_BIN_EXE_keel-tree")).args(["check", "--help"]).output().expect("keel-tree runs");
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains(".local/keel-index-cache") && help.contains("inside --root"), "{help}");

    if !have("nix-instantiate") || !have("git") {
        eprintln!("SKIPPED: nix-instantiate and git are needed to run keel-tree on a repository");
        return;
    }
    // A repository with a crate selector, so the cargo index (and with it the cache) is used.
    let repo = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let write = |rel: &str, text: &str| {
        let p = repo.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    };
    write("Cargo.toml", "[package]\nname = \"solo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n");
    write("src/lib.rs", "pub fn f() {}\n");
    for args in [&["init", "-q"][..], &["add", "-A"], &["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "x"]] {
        let ok = Command::new("git").arg("-C").arg(repo.path()).args(args).output().unwrap().status.success();
        assert!(ok, "git {args:?}");
    }
    let model = elsewhere.path().join("eval.nix");
    let lib = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../nix/keel/lib.nix");
    std::fs::write(
        &model,
        format!(
            "let keel = import {}; in keel.model (m: with keel; {{ root = {}; solo = node {{ code = [ (crate \"solo\") ]; }}; }})",
            lib.canonicalize().unwrap().display(),
            repo.path().display()
        ),
    )
    .unwrap();
    // Run from a different directory: a relative default would put the cache there.
    let out = Command::new(env!("CARGO_BIN_EXE_keel-tree"))
        .current_dir(elsewhere.path())
        .args(["--root"])
        .arg(repo.path())
        .arg("--model")
        .arg(&model)
        .arg("check")
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(repo.path().join(".local/keel-index-cache").is_dir(), "no cache in the root:\n{text}");
    assert!(!elsewhere.path().join(".local").exists(), "a cache was made in the current directory:\n{text}");
}

#[test]
fn plan_emit_writes_a_verifiable_plan_of_one_binary_and_refuses_what_it_cannot_stand_on() {
    if !have("nix-instantiate") || !have("git") {
        eprintln!("SKIPPED: nix-instantiate and git are needed to run keel-tree on a repository");
        return;
    }
    let repo = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let write = |rel: &str, text: &str| {
        let p = repo.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    };
    write("Cargo.toml", "[package]\nname = \"solo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n");
    write("src/lib.rs", "pub fn f() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn one() {}\n    #[test]\n    fn two() {}\n}\n");
    // A current lock file, or `cargo metadata --locked` fails and the index is degraded (which is itself refused).
    write("Cargo.lock", "version = 4\n\n[[package]]\nname = \"solo\"\nversion = \"0.1.0\"\n");
    write("tests/it.rs", "#[test]\nfn integration() {}\n");
    let git = |args: &[&str]| {
        let ok = Command::new("git").arg("-C").arg(repo.path()).args(args).output().unwrap().status.success();
        assert!(ok, "git {args:?}");
    };
    for args in [&["init", "-q"][..], &["add", "-A"], &["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "x"]] {
        git(args);
    }
    let model = elsewhere.path().join("eval.nix");
    let lib = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../nix/keel/lib.nix");
    std::fs::write(
        &model,
        format!(
            "let keel = import {}; in keel.model (m: with keel; {{ root = {}; solo = node {{ code = [ (crate \"solo\") ]; }}; }})",
            lib.canonicalize().unwrap().display(),
            repo.path().display()
        ),
    )
    .unwrap();
    let plan_path = elsewhere.path().join("plan.json");
    let emit = |binary: &str| {
        Command::new(env!("CARGO_BIN_EXE_keel-tree"))
            .current_dir(elsewhere.path())
            .arg("--root")
            .arg(repo.path())
            .arg("--model")
            .arg(&model)
            .args(["plan", "--base", "HEAD", "--head", "HEAD", "--binary", binary, "--emit"])
            .arg(&plan_path)
            .output()
            .unwrap()
    };
    let out = emit("solo");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let plan = keel_settle::Plan::read(&plan_path).expect("the plan verifies against its own digest");
    let names: Vec<&str> = plan.units().iter().map(|u| u.what.test_name()).collect();
    assert_eq!(names, ["tests::one", "tests::two"]);
    assert!(plan.units().iter().all(|u| u.expect == keel_settle::Disposition::ReuseIfKeyHolds));

    // The integration target is its own binary.
    assert!(emit("solo::it").status.success());
    assert_eq!(keel_settle::Plan::read(&plan_path).unwrap().units().len(), 1);

    // A binary the index does not know is a refusal that names what it does know, and writes nothing new.
    std::fs::remove_file(&plan_path).unwrap();
    let out = emit("solo::missing");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no tests for binary solo::missing") && !plan_path.exists());

    // A checkout with uncommitted changes is not the head commit, so no plan.
    write("src/lib.rs", "pub fn f() { /* edited */ }\n");
    let out = emit("solo");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("uncommitted"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!plan_path.exists());
}

#[test]
fn check_watch_runs_again_on_a_model_edit_survives_a_model_that_does_not_evaluate_and_recovers() {
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc;
    use std::time::Duration;

    if !have("nix-instantiate") || !have("git") {
        eprintln!("SKIPPED: nix-instantiate and git are needed to run keel-tree on a repository");
        return;
    }
    let repo = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("Cargo.toml"), "[package]\nname = \"solo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n").unwrap();
    std::fs::create_dir(repo.path().join("src")).unwrap();
    std::fs::write(repo.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    for args in [&["init", "-q"][..], &["add", "-A"], &["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "x"]] {
        assert!(Command::new("git").arg("-C").arg(repo.path()).args(args).output().unwrap().status.success(), "git {args:?}");
    }
    let model = elsewhere.path().join("eval.nix");
    let lib = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../nix/keel/lib.nix").canonicalize().unwrap();
    let source = |node: &str| {
        format!(
            "let keel = import {}; in keel.model (m: with keel; {{ root = {}; {node} = node {{ code = [ (crate \"solo\") ]; }}; }})",
            lib.display(),
            repo.path().display()
        )
    };
    std::fs::write(&model, source("solo")).unwrap();
    // Standard output and standard error go into one pipe, so the lines come in the order the
    // tool wrote them: the error of a run is read before the separator that ends it. Two pipes
    // read by two threads gave no such order, and the error sometimes arrived after the separator.
    let (reader, writer) = std::io::pipe().unwrap();
    let mut child = {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_keel-tree"));
        cmd.current_dir(elsewhere.path())
            .arg("--root")
            .arg(repo.path())
            .arg("--model")
            .arg(&model)
            .args(["check", "--watch"])
            .stdout(writer.try_clone().unwrap())
            .stderr(writer);
        cmd.spawn().unwrap()
    };
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    // Everything up to and including the next separator, with a deadline.
    let mut seen = String::new();
    let mut run = || {
        let mut text = String::new();
        loop {
            let line = rx.recv_timeout(Duration::from_secs(120)).unwrap_or_else(|_| panic!("no separator in time; saw:\n{seen}{text}"));
            text.push_str(&line);
            text.push('\n');
            if line.starts_with("---- ") {
                seen.push_str(&text);
                return text;
            }
        }
    };
    let first = run();
    assert!(first.contains("model ok") && first.contains("check took"), "{first}");
    // An edit that renames the node runs the check again.
    std::fs::write(&model, source("renamed")).unwrap();
    let second = run();
    assert!(second.contains("model ok"), "{second}");
    // A model that does not evaluate prints the error and waits instead of ending the watch.
    std::fs::write(&model, "this is { not nix").unwrap();
    let third = run();
    assert!(third.contains("keel-tree: evaluating") && !third.contains("model ok"), "{third}");
    assert!(child.try_wait().unwrap().is_none(), "the watch ended on a model that does not evaluate");
    // And it recovers when the model is mended.
    std::fs::write(&model, source("mended")).unwrap();
    let fourth = run();
    assert!(fourth.contains("model ok"), "{fourth}");
    child.kill().unwrap();
    let _ = child.wait();
}
