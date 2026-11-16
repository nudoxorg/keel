//! The `keel-store` executable: how it consumes KEEL_STORE_PORT and
//! KEEL_STORE_TOKEN_FILE, and that its log never holds the token.

mod common;

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};

use common::*;
use keel_store::client::Client;

fn spawn(dir: &TempDir, envs: &[(&str, String)], extra: &[&str]) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keel-store"));
    cmd.arg("serve")
        .arg("--dir")
        .arg(dir.path().join("store"))
        .args(extra);
    cmd.env_remove("KEEL_STORE_PORT")
        .env_remove("KEEL_STORE_TOKEN_FILE")
        .env_remove("KEEL_STORE_READ_TOKEN_FILE");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap()
}

fn token_file(dir: &TempDir, token: &str) -> String {
    secret_file(dir, "token", token)
}

fn secret_file(dir: &TempDir, name: &str, token: &str) -> String {
    let p = dir.path().join(name);
    std::fs::write(&p, format!("{token}\n")).unwrap();
    // Owner-only, or the service warns that the token file is too open.
    std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    p.to_string_lossy().into_owned()
}

/// Waits for the "listening on" line and returns the address.
fn listening(err: &mut BufReader<std::process::ChildStderr>) -> String {
    let mut line = String::new();
    while !line.contains("listening on ") {
        line.clear();
        assert!(
            err.read_line(&mut line).unwrap() > 0,
            "the service exited before listening"
        );
    }
    line.split("listening on ")
        .nth(1)
        .unwrap_or_else(|| panic!("no listen line: {line}"))
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

#[test]
fn it_reads_the_token_from_the_file_and_logs_requests_without_it() {
    let dir = TempDir::new("bin");
    let token = token();
    let mut child = spawn(
        &dir,
        &[
            ("KEEL_STORE_TOKEN_FILE", token_file(&dir, &token)),
            (
                "KEEL_STORE_READ_TOKEN_FILE",
                secret_file(&dir, "read", &read_token(&token)),
            ),
        ],
        &[],
    );
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let addr = listening(&mut err);
    assert!(
        addr.starts_with("127.0.0.1:"),
        "default bind is loopback: {addr}"
    );

    let client = Client::new(&format!("http://{addr}"), Some(token.clone()));
    let d = client.put_blob(b"hello").unwrap();
    assert_eq!(client.get_blob(&d).unwrap().unwrap(), b"hello");
    assert!(
        Client::new(
            &format!("http://{addr}"),
            Some("wrong-wrong-wrong-wrong".into())
        )
        .put_blob(b"x")
        .is_err()
    );

    child.kill().unwrap();
    let mut log = String::new();
    err.read_to_string(&mut log).unwrap();
    child.wait().unwrap();
    assert!(
        !log.contains(&token) && !log.contains(&read_token(&token)),
        "no token may reach the log:\n{log}"
    );
    assert!(
        log.contains("method=PUT path=/v1/blob status=200 bytes="),
        "{log}"
    );
    assert!(log.contains("method=PUT path=/v1/blob status=401"), "{log}");
    assert_eq!(
        log.lines()
            .filter(|l| l.contains("method=") && l.contains(" ms="))
            .count(),
        3,
        "{log}"
    );
}

#[test]
fn the_port_comes_from_keel_store_port_when_listen_is_absent() {
    let dir = TempDir::new("bin-port");
    // Find a free port, release it, and ask the service for exactly that.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let envs = [
        ("KEEL_STORE_TOKEN_FILE", token_file(&dir, &token())),
        (
            "KEEL_STORE_READ_TOKEN_FILE",
            secret_file(&dir, "read", &token()),
        ),
        ("KEEL_STORE_PORT", port.to_string()),
    ];
    let mut child = spawn(&dir, &envs, &[]);
    let mut err = BufReader::new(child.stderr.take().unwrap());
    assert_eq!(listening(&mut err), format!("127.0.0.1:{port}"));
    child.kill().unwrap();
    child.wait().unwrap();

    // --listen wins over the environment.
    let mut child = spawn(&dir, &envs, &["--listen", "127.0.0.1:0"]);
    let mut err = BufReader::new(child.stderr.take().unwrap());
    assert_ne!(listening(&mut err), format!("127.0.0.1:{port}"));
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn it_refuses_to_start_without_a_usable_token_file() {
    let dir = TempDir::new("bin-notoken");
    let out = |envs: &[(&str, String)]| {
        let child = spawn(&dir, envs, &[]);
        let o = child.wait_with_output().unwrap();
        assert!(!o.status.success());
        String::from_utf8_lossy(&o.stderr).into_owned()
    };
    assert!(out(&[]).contains("KEEL_STORE_TOKEN_FILE is not set"));
    assert!(
        out(&[("KEEL_STORE_TOKEN_FILE", "/no/such/file".into())])
            .contains("cannot read the writer token file")
    );
    assert!(
        out(&[("KEEL_STORE_TOKEN_FILE", token_file(&dir, "short"))]).contains("shorter than 16")
    );
    let no_read = out(&[("KEEL_STORE_TOKEN_FILE", token_file(&dir, &token()))]);
    assert!(
        no_read.contains("KEEL_STORE_READ_TOKEN_FILE is not set"),
        "{no_read}"
    );
    let bad_port = out(&[
        ("KEEL_STORE_TOKEN_FILE", token_file(&dir, &token())),
        (
            "KEEL_STORE_READ_TOKEN_FILE",
            secret_file(&dir, "read", &token()),
        ),
        ("KEEL_STORE_PORT", "http".into()),
    ]);
    assert!(bad_port.contains("KEEL_STORE_PORT=`http`"), "{bad_port}");
}

#[test]
fn validate_job_is_what_the_units_call() {
    let dir = TempDir::new("bin-job");
    let run = |args: &[&str], envs: &[(&str, &str)]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_keel-store"));
        cmd.args(args).envs(envs.iter().copied());
        let o = cmd.output().unwrap();
        (
            o.status.success(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    };
    assert!(run(&["validate-job", "smoke"], &[]).0);
    let (ok, err) = run(&["validate-job", "Smoke/../x"], &[]);
    assert!(!ok && err.contains("lowercase letters, digits"), "{err}");

    let env = dir.path().join("smoke.env");
    let prog = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-coreutils-9/bin/true";
    std::fs::write(
        &env,
        format!("KEEL_PROGRAM={prog}\nKEEL_ARGS=run smoke 0\n"),
    )
    .unwrap();
    let e = env.to_str().unwrap();
    assert!(run(&["validate-job", "smoke", "--env-file", e], &[]).0);
    std::fs::write(&env, "KEEL_PROGRAM=/bin/sh\nKEEL_ARGS=run\n").unwrap();
    let (ok, err) = run(&["validate-job", "smoke", "--env-file", e], &[]);
    assert!(!ok && err.contains("KEEL_PROGRAM"), "{err}");
    assert!(
        !run(
            &["validate-job", "smoke", "--env-file", "/no/such.env"],
            &[]
        )
        .0
    );
}
