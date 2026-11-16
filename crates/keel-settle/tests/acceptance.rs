//! The acceptance table of design/ir.md section 11, run through the real `keel-settle` binary.
//!
//! The "test binary" here is a SHELL SCRIPT written by the test: it answers
//! `--list --format terse` and `--exact NAME --test-threads 1` the way libtest does, with
//! outcomes the test chooses. A cargo project would need a compile per case (and network on a
//! cold machine); the script is enough because the producer and `settle` only ever see
//! libtest's text and exit codes.
#![cfg(unix)]

use keel_settle::{Binary, Disposition, GitOid, Plan, Unit};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const SETTLE: &str = env!("CARGO_BIN_EXE_keel-settle");

struct Dir(PathBuf);
impl Dir {
    fn new(label: &str) -> Dir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!("keel-settle-{}-{}-{label}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }
    fn path(&self, f: &str) -> PathBuf {
        self.0.join(f)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
enum Does {
    Pass,
    Fail,
    /// Blocks until this file exists, so a test can hold a unit open and then let it go.
    WaitFor(PathBuf),
}

fn script(dir: &Dir, listed: &[&str], does: &[(&str, Does)]) -> PathBuf {
    let mut s = String::from("#!/bin/sh\n# stand-in for a libtest binary; see tests/acceptance.rs\n");
    s.push_str("case \"$1\" in --list) ");
    for n in listed {
        s.push_str(&format!("echo '{n}: test'; "));
    }
    s.push_str("exit 0;; esac\nname=\"\"\nwhile [ $# -gt 0 ]; do case \"$1\" in --test-threads) shift 2;; -*) shift;; *) name=\"$1\"; shift;; esac; done\n");
    let ok = "echo 'running 1 test'; echo \"test $name ... ok\"; echo; echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'; exit 0";
    s.push_str("case \"$name\" in\n");
    for (n, d) in does {
        match d {
            Does::Pass => s.push_str(&format!("'{n}') {ok};;\n")),
            Does::Fail => s.push_str(&format!(
                "'{n}') echo 'running 1 test'; echo \"thread '{n}' panicked at src/lib.rs:1:1:\"; echo 'assertion failed'; echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'; exit 101;;\n"
            )),
            Does::WaitFor(g) => s.push_str(&format!("'{n}') while [ ! -e '{}' ]; do sleep 0.05; done; {ok};;\n", g.display())),
        }
    }
    s.push_str("*) echo 'running 0 tests'; echo 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s'; exit 0;;\nesac\n");
    let p = dir.path("fixture-test-binary.sh");
    std::fs::write(&p, s).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn oid(c: char) -> GitOid {
    GitOid::new(&c.to_string().repeat(40)).unwrap()
}

fn plan_file(dir: &Dir, file: &str, names: &[&str]) -> (PathBuf, Plan) {
    let b = Binary::parse("fixture").unwrap();
    let units = names.iter().map(|n| Unit::test(b.clone(), (*n).to_owned(), Disposition::ReuseIfKeyHolds)).collect();
    let plan = Plan::new("fixture-repo".to_owned(), oid('a'), oid('b'), units).unwrap();
    let p = dir.path(file);
    plan.write(&p).unwrap();
    (p, plan)
}

fn produce(plan: &Path, exe: &Path, out: &Path) -> Output {
    Command::new(SETTLE).args(["run-binary", "--plan"]).arg(plan).arg("--exe").arg(exe).arg("--out").arg(out).args(["--jobs", "2", "--timeout-secs", "20"]).output().unwrap()
}

fn settle(plan: &Path, executed: &Path) -> (i32, String) {
    let o = Command::new(SETTLE).arg("settle").arg(plan).arg(executed).output().unwrap();
    (o.status.code().unwrap(), String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr))
}

/// Plan [a b c], a binary that lists exactly those and runs them as told.
fn run_all(dir: &Dir, does: &[(&str, Does)]) -> (PathBuf, PathBuf) {
    let (plan, _) = plan_file(dir, "plan.json", &["a", "b", "c"]);
    let exe = script(dir, &["a", "b", "c"], does);
    let out = dir.path("executed.jsonl");
    let o = produce(&plan, &exe, &out);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    (plan, out)
}

const ALL_PASS: [(&str, Does); 3] = [("a", Does::Pass), ("b", Does::Pass), ("c", Does::Pass)];

#[test]
fn all_pass() {
    let d = Dir::new("pass");
    let (plan, out) = run_all(&d, &ALL_PASS);
    let (code, text) = settle(&plan, &out);
    assert_eq!((code, text.starts_with("pass")), (0, true), "{text}");
}

#[test]
fn one_fails() {
    let d = Dir::new("fail");
    let (plan, out) = run_all(&d, &[("a", Does::Pass), ("b", Does::Fail), ("c", Does::Pass)]);
    let (code, text) = settle(&plan, &out);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("fail: fixture$b"), "{text}");
    assert!(!text.contains("fixture$a"), "{text}");
}

#[test]
fn cancelled_after_the_first_record() {
    let d = Dir::new("killed");
    let (plan, _) = plan_file(&d, "plan.json", &["a", "b", "c"]);
    let gate = d.path("gate");
    // One job and sorted order: `a` finishes, `b` holds until the gate opens, which only happens after the kill.
    let exe = script(&d, &["a", "b", "c"], &[("a", Does::Pass), ("b", Does::WaitFor(gate.clone())), ("c", Does::Pass)]);
    let out = d.path("executed.jsonl");
    let mut child = Command::new(SETTLE)
        .args(["run-binary", "--plan"])
        .arg(&plan)
        .arg("--exe")
        .arg(&exe)
        .arg("--out")
        .arg(&out)
        .args(["--jobs", "1"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let t0 = Instant::now();
    while std::fs::read_to_string(&out).map_or(true, |s| !s.contains("\"Record\"")) {
        assert!(t0.elapsed() < Duration::from_secs(20), "no record appeared");
        std::thread::sleep(Duration::from_millis(20));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    std::fs::write(&gate, "").unwrap(); // lets the orphaned script end
    let (code, text) = settle(&plan, &out);
    assert_eq!(code, 3, "{text}");
    assert!(text.contains("incomplete: 2 units have no result (first: fixture$b, fixture$c)"), "{text}");
    assert!(!text.contains("pass"), "{text}");
}

#[test]
fn filtered_the_plan_has_a_test_the_binary_did_not_list() {
    let d = Dir::new("filtered");
    let (plan, _) = plan_file(&d, "plan.json", &["a", "b", "c"]);
    let exe = script(&d, &["a", "b"], &ALL_PASS);
    let out = d.path("executed.jsonl");
    assert!(produce(&plan, &exe, &out).status.success());
    let (code, text) = settle(&plan, &out);
    assert_eq!(code, 3, "{text}");
    assert!(text.contains("incomplete: fixture$c is in the plan and the binary did not list it"), "{text}");
}

#[test]
fn generated_the_binary_lists_a_test_the_plan_lacks() {
    let d = Dir::new("generated");
    let (plan, _) = plan_file(&d, "plan.json", &["a", "b", "c"]);
    let exe = script(&d, &["a", "b", "c", "gen::case_1"], &ALL_PASS);
    let out = d.path("executed.jsonl");
    assert!(produce(&plan, &exe, &out).status.success());
    let (code, text) = settle(&plan, &out);
    assert_eq!(code, 3, "{text}");
    assert!(text.contains("incomplete: fixture$gen::case_1 is listed by the binary and not in the plan"), "{text}");
}

#[test]
fn foreign_a_record_for_a_name_the_plan_lacks() {
    let d = Dir::new("foreign");
    let (plan, out) = run_all(&d, &ALL_PASS);
    let mut text = std::fs::read_to_string(&out).unwrap();
    text.push_str("{\"Record\":{\"binary\":{\"package\":\"fixture\",\"kind\":\"lib\",\"target\":\"fixture\"},\"name\":\"zzz\",\"status\":\"Pass\",\"source\":{\"Ran\":{\"attempt\":1,\"duration_ms\":1}}}}\n");
    std::fs::write(&out, text).unwrap();
    let (code, text) = settle(&plan, &out);
    assert_eq!(code, 3, "{text}");
    assert!(text.contains("incomplete: a result for fixture$zzz, which the plan does not have"), "{text}");
}

#[test]
fn stale_an_executed_list_from_another_plan() {
    let d = Dir::new("stale");
    let (_, out) = run_all(&d, &ALL_PASS);
    // A different plan: one more unit, hence another digest.
    let (other, other_plan) = plan_file(&d, "other.json", &["a", "b", "c", "d"]);
    let (code, text) = settle(&other, &out);
    assert_eq!(code, 3, "{text}");
    assert!(text.contains("incomplete: this executed list answers plan "), "{text}");
    assert!(text.contains(&format!(", not {}", other_plan.digest())), "{text}");
}

#[test]
fn a_plan_edited_after_it_was_written_is_unreadable_not_a_verdict() {
    let d = Dir::new("edited");
    let (plan, out) = run_all(&d, &ALL_PASS);
    let text = std::fs::read_to_string(&plan).unwrap().replace("fixture-repo", "fixture-rep0");
    std::fs::write(&plan, text).unwrap();
    let (code, text) = settle(&plan, &out);
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("plan.json") && text.contains("digest"), "{text}");
}

#[test]
fn a_malformed_executed_line_names_the_file_and_the_line() {
    let d = Dir::new("malformed");
    let (plan, out) = run_all(&d, &ALL_PASS);
    let mut lines: Vec<String> = std::fs::read_to_string(&out).unwrap().lines().map(str::to_owned).collect();
    lines[2] = "{\"Record\":{\"nonsense\":1}}".to_owned();
    std::fs::write(&out, lines.join("\n") + "\n").unwrap();
    let (code, text) = settle(&plan, &out);
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("executed.jsonl:3:"), "{text}");
}

#[test]
fn a_partial_last_line_is_incomplete_not_a_crash() {
    let d = Dir::new("torn");
    let (plan, out) = run_all(&d, &ALL_PASS);
    let mut bytes = std::fs::read(&out).unwrap();
    bytes.extend_from_slice(b"{\"Record\":{\"binary\":{\"pack");
    std::fs::write(&out, bytes).unwrap();
    let (code, text) = settle(&plan, &out);
    assert_eq!(code, 3, "{text}");
    assert!(text.contains("partial line"), "{text}");
}

#[test]
fn json_output_has_exactly_the_three_verdicts() {
    let d = Dir::new("json");
    let (plan, out) = run_all(&d, &ALL_PASS);
    let o = Command::new(SETTLE).arg("settle").arg(&plan).arg(&out).arg("--json").output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["verdict"], "Pass");
    assert_eq!(v["units"], 3);
}

#[test]
fn a_test_that_ends_without_a_libtest_result_is_an_error_record_not_a_pass() {
    // `c` is listed and planned but the script answers it as an unmatched filter (0 tests, exit 0).
    let d = Dir::new("unmatched");
    let (plan, out) = run_all(&d, &[("a", Does::Pass), ("b", Does::Pass)]);
    let (code, text) = settle(&plan, &out);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("fail: fixture$c (Error"), "{text}");
}
