//! Acceptance: build the synthetic workspace with `keel-linker` as the linker,
//! compute every test's reach key, mutate, rebuild, and check the keys against
//! the oracles the generator records in `mutation.json`:
//!
//! * `expected_flips`: tests whose outcome changes. Their key must change (or be
//!   in fallback). Soundness; this must never fail.
//! * `expected_key_changes`: tests that pass before and after but observe the
//!   changed thing (a moved source line). Their key must change as well.
//! * `expected_key_stable`: tests that cannot observe the change. Their key must not.
//!
//! The Mach-O runs need a native build. The ELF runs cross-compile for
//! x86_64-unknown-linux-gnu through a cc-style linker wrapper named by
//! `KEEL_ELF_LINKER` (for example `zig cc -target x86_64-linux-gnu.2.34`); they
//! are skipped, with a printed reason, when it is unset. The ELF binaries cannot
//! be executed here, so their test names come from `synth.json` and the mutation
//! record. Slow variants are `#[ignore]`d with the reason on the attribute.

use keel_reach::{BinaryReach, Loader, Options, analyze_record};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::new(());

const LINKER: &str = env!("CARGO_BIN_EXE_keel-linker");
const ELF_TARGET: &str = "x86_64-unknown-linux-gnu";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn scratch() -> PathBuf {
    let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join("keel-reach-synthetic");
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn run(cmd: &mut Command) -> (bool, String, String) {
    let o = cmd.output().unwrap_or_else(|e| panic!("cannot spawn {cmd:?}: {e}; cargo-stock must be on PATH"));
    (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

/// The generator, run through cargo as the task prescribes, in a target
/// directory of its own so it cannot wait on the lock this test run holds.
fn synth(args: &[&str]) {
    let (ok, _, err) = run(Command::new("cargo-stock")
        .args(["run", "-q", "-p", "synth-workspace", "--"])
        .args(args)
        .current_dir(root())
        .env("RUSTC_WRAPPER", "")
        .env("CARGO_TARGET_DIR", scratch().join("generator-target")));
    assert!(ok, "synth-workspace {args:?} failed:\n{err}");
}

#[derive(Clone, Copy, PartialEq)]
enum Flavor {
    MachO,
    Elf,
}

/// `Backend` is the real backend's dev profile: `debug = 1`, incremental, and
/// `opt-level = 2` for the level-0 crates.
#[derive(Clone, Copy, PartialEq)]
enum Profile {
    Default,
    Backend,
}

#[derive(Clone, Copy)]
struct Cfg {
    flavor: Flavor,
    profile: Profile,
}

impl Cfg {
    fn tag(self) -> String {
        format!("{}-{}", if self.flavor == Flavor::MachO { "macho" } else { "elf" }, if self.profile == Profile::Default { "default" } else { "backend" })
    }
}

fn generate(ws: &Path, cfg: Cfg) {
    let _ = std::fs::remove_dir_all(ws);
    let profile = if cfg.profile == Profile::Default { "default" } else { "backend" };
    synth(&["generate", "--shape", "S", "--seed", "7", "--line-oracle", "--profile", profile, "--out", ws.to_str().unwrap()]);
}

fn mutate(ws: &Path, pattern: &str, seed: u32) -> Value {
    synth(&["mutate", "--workspace", ws.to_str().unwrap(), "--pattern", pattern, "--seed", &seed.to_string()]);
    serde_json::from_slice(&std::fs::read(ws.join("mutation.json")).unwrap()).unwrap()
}

/// Build every test executable of the workspace with the shim and return
/// executable path -> (binary id, crate name of the test crate).
fn build(ws: &Path, target_dir: &Path, cfg: Cfg, extra_env: &[(&str, &str)]) -> BTreeMap<PathBuf, (String, String)> {
    let sysroot = String::from_utf8(Command::new("rustc").args(["--print", "sysroot"]).output().unwrap().stdout).unwrap();
    let home = std::env::var("HOME").unwrap();
    let flags = format!(
        "-C linker={LINKER} --remap-path-prefix={}=/src --remap-path-prefix={home}/.cargo=/cargo --remap-path-prefix={}=/sysroot",
        ws.display(),
        sysroot.trim()
    );
    let mut cmd = Command::new("cargo-stock");
    cmd.args(["test", "--no-run", "--message-format=json"]).current_dir(ws);
    if cfg.flavor == Flavor::Elf {
        cmd.args(["--target", ELF_TARGET]);
        cmd.env("KEEL_REAL_LINKER", std::env::var("KEEL_ELF_LINKER").unwrap());
    }
    cmd.env("RUSTC_WRAPPER", "").env("RUSTFLAGS", flags).env("CARGO_TARGET_DIR", target_dir);
    if cfg.profile == Profile::Default {
        // Debuginfo only costs compile time here; the reach key never reads it. The backend
        // profile keeps its own `debug = 1` because parity is the point of that run.
        cmd.env("CARGO_PROFILE_TEST_DEBUG", "0");
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let (ok, out, err) = run(&mut cmd);
    assert!(ok, "test build failed:\n{err}");
    let mut map = BTreeMap::new();
    for line in out.lines().filter(|l| l.starts_with('{')) {
        let m: Value = serde_json::from_str(line).unwrap();
        if m["reason"] != "compiler-artifact" || m["profile"]["test"] != true || m["executable"].is_null() {
            continue;
        }
        let pkg_id = m["package_id"].as_str().unwrap();
        let (head, frag) = pkg_id.rsplit_once('#').unwrap();
        let pkg = frag.split_once('@').map_or_else(|| head.rsplit('/').next().unwrap(), |(n, _)| n).to_string();
        let tname = m["target"]["name"].as_str().unwrap().to_string();
        let is_lib = m["target"]["kind"][0] == "lib";
        let id = if is_lib { pkg.clone() } else { format!("{pkg}::{tname}") };
        map.insert(PathBuf::from(m["executable"].as_str().unwrap()), (id, tname));
    }
    assert!(!map.is_empty(), "cargo reported no test executables:\n{out}");
    map
}

#[derive(Clone, Debug)]
struct Summary {
    key: Option<[u8; 32]>,
    fallback: Option<String>,
    spawns: bool,
}

struct Analysis {
    /// `<binary id> <test name>` -> summary.
    tests: BTreeMap<String, Summary>,
    unverifiable: Vec<String>,
    wall_ms: Vec<(String, u64)>,
    reports: BTreeMap<String, BinaryReach>,
}

/// Test names of one binary. ELF binaries cannot run here, so the names come from
/// the generator's record plus the additions and renames the mutation made.
fn test_names(synth_json: &Value, binary: &str, exe: &Path, cfg: Cfg, edit: Option<&Value>) -> Vec<String> {
    match cfg.flavor {
        Flavor::Elf => {
            let mut names: Vec<String> = synth_json["tests"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|t| t["binary"] == binary)
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect();
            if let Some(e) = edit {
                for id in e["new_tests"].as_array().into_iter().flatten() {
                    if let Some((_, n)) = id.as_str().unwrap().split_once(' ').filter(|(b, _)| *b == binary) {
                        names.push(n.to_string());
                    }
                }
                for (old, new) in e["renamed"].as_object().into_iter().flatten() {
                    let (ob, on) = old.split_once(' ').unwrap();
                    if ob == binary {
                        let nn = new.as_str().unwrap().split_once(' ').unwrap().1.to_string();
                        names.iter_mut().filter(|n| **n == on).for_each(|n| *n = nn.clone());
                    }
                }
            }
            names
        }
        Flavor::MachO => {
            let (ok, out, err) = run(Command::new(exe).args(["--list", "--format", "terse"]));
            assert!(ok, "{} --list failed: {err}", exe.display());
            out.lines().filter_map(|l| l.strip_suffix(": test")).map(str::to_string).collect()
        }
    }
}

fn analyze_all(ws: &Path, exes: &BTreeMap<PathBuf, (String, String)>, loader: &Loader, cfg: Cfg, edit: Option<&Value>) -> Analysis {
    let synth_json: Value = serde_json::from_slice(&std::fs::read(ws.join("synth.json")).unwrap()).unwrap();
    let mut a = Analysis { tests: BTreeMap::new(), unverifiable: vec![], wall_ms: vec![], reports: BTreeMap::new() };
    for (exe, (id, crate_name)) in exes {
        let names = test_names(&synth_json, id, exe, cfg, edit);
        let mut rec = exe.as_os_str().to_os_string();
        rec.push(".keel-link.json");
        let r = analyze_record(loader, Path::new(&rec), &Options { crate_name: crate_name.clone(), tests: names.clone(), ..Default::default() });
        if let Err(why) = &r.verifiable {
            a.unverifiable.push(format!("{id}: {why}"));
        }
        assert!(r.missing_tests.is_empty(), "{id}: no entry symbol for {:?}", r.missing_tests);
        for (n, t) in &r.tests {
            a.tests.insert(format!("{id} {n}"), Summary { key: t.key().copied(), fallback: t.fallback().map(|f| f.to_string()), spawns: t.spawns_processes });
        }
        a.wall_ms.push((id.clone(), r.stats.wall_ms));
        a.reports.insert(id.clone(), r);
    }
    a
}

#[derive(Default)]
struct Cmp {
    changed: BTreeSet<String>,
    same: BTreeSet<String>,
    fallback: BTreeSet<String>,
    /// In `before` but absent from `after` (a renamed test).
    gone: BTreeSet<String>,
}

fn compare(before: &Analysis, after: &Analysis) -> Cmp {
    let mut c = Cmp::default();
    for (id, b) in &before.tests {
        let Some(a) = after.tests.get(id) else {
            c.gone.insert(id.clone());
            continue;
        };
        if a.fallback.is_some() || b.fallback.is_some() {
            c.fallback.insert(id.clone());
        } else if a.key != b.key {
            c.changed.insert(id.clone());
        } else {
            c.same.insert(id.clone());
        }
    }
    c
}

fn row(label: &str, n: usize, c: &Cmp) -> String {
    format!("{label:<22} {n:>6} {:>8} {:>6} {:>9}", c.changed.len(), c.same.len(), c.fallback.len())
}

fn source_of(ws: &Path, synth_json: &Value, id: &str) -> String {
    let t = synth_json["tests"].as_array().unwrap().iter().find(|t| t["id"] == id).unwrap_or_else(|| panic!("{id} is not in synth.json"));
    let krate = t["crate"].as_str().unwrap();
    let binary = t["binary"].as_str().unwrap();
    let file = match binary.split_once("::") {
        Some((_, stem)) => format!("crates/{krate}/tests/{stem}.rs"),
        None => format!("crates/{krate}/src/lib.rs"),
    };
    std::fs::read_to_string(ws.join(file)).unwrap()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().map(|x| x.as_str().unwrap().to_string()).collect()
}

struct Run<'a> {
    ws: PathBuf,
    target: PathBuf,
    cfg: Cfg,
    loader: &'a Loader,
    failures: Vec<String>,
    table: Vec<String>,
}

impl Run<'_> {
    fn pristine(&self) -> (BTreeMap<PathBuf, (String, String)>, Analysis) {
        generate(&self.ws, self.cfg);
        let exes = build(&self.ws, &self.target, self.cfg, &[]);
        let a = analyze_all(&self.ws, &exes, self.loader, self.cfg, None);
        (exes, a)
    }

    /// Apply the pattern with the first seed whose target crate has dependents, so the
    /// soundness check covers flips that cross crate boundaries, not just the target's own tests.
    fn pick_mutation(&self, pattern: &str) -> Value {
        let synth_json: Value = serde_json::from_slice(&std::fs::read(self.ws.join("synth.json")).unwrap()).unwrap();
        let crates = synth_json["crates"].as_array().unwrap();
        for seed in 3..60u32 {
            let rec = mutate(&self.ws, pattern, seed);
            let Some(name) = rec["crate"].as_str() else { return rec };
            let has_dependents = crates.iter().any(|c| c["deps"].as_array().unwrap().iter().any(|d| d == name));
            if has_dependents || !matches!(pattern, "body-root" | "signature-root" | "comment-root") {
                return rec;
            }
            generate(&self.ws, self.cfg);
        }
        panic!("no seed below 60 picks a level-0 crate with dependents for {pattern}; regenerate with another shape");
    }

    fn fail(&mut self, pattern: &str, msg: String) {
        self.failures.push(format!("{pattern}: {msg}"));
    }

    fn pattern(&mut self, pattern: &str, base: &Analysis) {
        // Restore: regenerate the pristine tree over the same paths and rebuild
        // incrementally. Keys must come back to the baseline exactly.
        let (exes, restored) = self.pristine();
        let back = compare(base, &restored);
        if !back.changed.is_empty() {
            self.fail(pattern, format!("restoring the pristine tree changed {} keys, e.g. {:?}", back.changed.len(), back.changed.iter().take(3).collect::<Vec<_>>()));
        }
        let rec = self.pick_mutation(pattern);
        let flips = strings(&rec["expected_flips"]);
        let must_change = strings(&rec["expected_key_changes"]);
        let must_stay = strings(&rec["expected_key_stable"]);
        let exes2 = build(&self.ws, &self.target, self.cfg, &[]);
        assert_eq!(exes.len(), exes2.len());
        let after = analyze_all(&self.ws, &exes2, self.loader, self.cfg, Some(&rec));
        for u in &after.unverifiable {
            self.fail(pattern, format!("unverifiable binary {u}"));
        }
        let c = compare(base, &after);
        self.table.push(row(pattern, base.tests.len(), &c));
        let synth_json: Value = serde_json::from_slice(&std::fs::read(self.ws.join("synth.json")).unwrap()).unwrap();

        // Fixture reads at runtime are covered by the files term of the key, not by code.
        let (code_flips, runtime_reads): (Vec<&String>, Vec<&String>) = if pattern == "fixture" {
            flips.iter().partition(|id| source_of(&self.ws, &synth_json, id).contains("include_str!"))
        } else {
            (flips.iter().collect(), vec![])
        };
        for id in code_flips {
            if !c.changed.contains(id) && !c.fallback.contains(id) {
                self.fail(pattern, format!("SOUNDNESS: {id} must flip but its reach key is unchanged"));
            }
        }
        for id in &runtime_reads {
            if c.changed.contains(*id) {
                self.fail(pattern, format!("{id} reads its fixture at runtime; its code is unchanged so its reach key must be too"));
            }
        }
        for id in &must_change {
            if !c.changed.contains(id) && !c.fallback.contains(id) {
                self.fail(pattern, format!("SOUNDNESS: {id} observes the change (expected_key_changes) but its reach key is unchanged"));
            }
        }
        for id in &must_stay {
            if c.changed.contains(id) {
                self.fail(pattern, format!("{id} cannot observe the change (expected_key_stable) but its reach key changed"));
            }
        }
        for id in strings(&rec["new_tests"]) {
            match after.tests.get(&id) {
                Some(t) if t.fallback.is_none() && t.key.is_some() => {}
                other => self.fail(pattern, format!("new test {id} has no key: {other:?}")),
            }
        }
        for (old, new) in rec["renamed"].as_object().into_iter().flatten() {
            let new = new.as_str().unwrap();
            match (base.tests.get(old), after.tests.get(new)) {
                (Some(o), Some(n)) if o.key != n.key => {}
                other => self.fail(pattern, format!("renaming {old} to {new} must change that test's key: {other:?}")),
            }
        }
        println!(
            "{pattern}: {} expected flips, {} expected key changes, {} expected stable, {} keys changed ({} fixture reads at runtime covered by the files key)",
            flips.len(),
            must_change.len(),
            must_stay.len(),
            c.changed.len(),
            runtime_reads.len()
        );
        match pattern {
            "docs" if !c.changed.is_empty() => {
                self.fail(pattern, format!("{} keys changed, e.g. {:?}", c.changed.len(), c.changed.iter().take(3).collect::<Vec<_>>()));
            }
            "fixture" => {
                let expect: BTreeSet<String> = flips.iter().filter(|id| source_of(&self.ws, &synth_json, id).contains("include_str!")).cloned().collect();
                if c.changed != expect {
                    self.fail(pattern, format!("changed {:?}, expected exactly the include_str! tests {:?}", c.changed, expect));
                }
            }
            "body-root" => {
                let target = rec["crate"].as_str().unwrap();
                if c.changed.len() >= base.tests.len() {
                    self.fail(pattern, format!("every one of {} keys changed; the key is no sharper than the executable", base.tests.len()));
                }
                // Filler-only unit tests of the mutated crate never reach probe().
                for t in synth_json["tests"].as_array().unwrap() {
                    if t["crate"] == target && t["kind"] == "unit" && t["asserts"] == "filler" {
                        let id = t["id"].as_str().unwrap();
                        if c.changed.contains(id) {
                            self.fail(pattern, format!("{id} only calls fillers but its key changed"));
                        }
                    }
                }
                println!("body-root: crate {target}; {} of {} keys changed", c.changed.len(), base.tests.len());
            }
            "comment-root" | "comment-leaf" => {
                println!("{pattern}: {} keys changed. Panic locations embed line numbers, so every test that reaches code below the inserted line changes, which is correct.", c.changed.len());
            }
            "line-shift" => {
                let target = rec["crate"].as_str().unwrap();
                let expected: BTreeSet<&String> = must_change.iter().collect();
                let others: Vec<&String> = c.changed.iter().filter(|id| !expected.contains(id)).collect();
                println!("line-shift: root {target}; {} of {} oracle tests changed; {} others changed (the root's own tests and any dependent code that reaches shifted constants)", must_change.iter().filter(|i| c.changed.contains(*i)).count(), must_change.len(), others.len());
                for (feature, ids) in rec["expected_key_changes_by_feature"].as_object().unwrap() {
                    let ids = strings(ids);
                    let n = ids.iter().filter(|i| c.changed.contains(*i)).count();
                    println!("  {feature:<16} {n}/{} changed", ids.len());
                }
                let stable_changed = must_stay.iter().filter(|i| c.changed.contains(*i)).count();
                println!("  {:<16} {}/{} changed (control: both levels forward the caller's location)", "track_caller", stable_changed, must_stay.len());
                let by_binary: BTreeMap<String, usize> = others.iter().fold(BTreeMap::new(), |mut m, id| {
                    *m.entry(id.split(' ').next().unwrap().to_string()).or_default() += 1;
                    m
                });
                println!("  others by binary: {by_binary:?}");
            }
            "add-test" | "rename-test" => {
                println!("{pattern}: {} pre-existing tests of the binary stay, {} changed; new/renamed: {:?} {:?}", must_stay.len(), c.changed.len() + c.gone.len(), strings(&rec["new_tests"]), rec["renamed"]);
            }
            _ => {}
        }
    }
}

fn exercise(cfg: Cfg, patterns: &[&str], determinism: bool) {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let tag = cfg.tag();
    let base_dir = scratch().join(&tag);
    let _ = std::fs::remove_dir_all(&base_dir);
    let loader = Loader::new();
    let mut r = Run { ws: base_dir.join("ws-a"), target: base_dir.join("target-a"), cfg, loader: &loader, failures: vec![], table: vec![] };
    let (_, base) = r.pristine();
    assert!(base.unverifiable.is_empty(), "{tag}: pristine binaries unverifiable: {:#?}", base.unverifiable);
    let fallbacks: Vec<_> = base.tests.iter().filter(|(_, s)| s.fallback.is_some()).collect();
    println!("[{tag}] pristine: {} tests in {} binaries, {} in fallback, {} spawn processes", base.tests.len(), base.reports.len(), fallbacks.len(), base.tests.values().filter(|s| s.spawns).count());
    let total_ms: u64 = base.wall_ms.iter().map(|(_, m)| m).sum();
    let max = base.wall_ms.iter().max_by_key(|(_, m)| *m).unwrap();
    println!("[{tag}] analysis wall: sum {total_ms} ms over {} binaries, slowest {} ({} ms)", base.wall_ms.len(), max.0, max.1);

    let mut table = vec![];
    if determinism {
        let b = Run { ws: base_dir.join("ws-b"), target: base_dir.join("target-b"), cfg, loader: &loader, failures: vec![], table: vec![] };
        let (_, second) = b.pristine();
        let c = compare(&base, &second);
        table.push(row("determinism (A vs B)", base.tests.len(), &c));
        // `env!("CARGO_MANIFEST_DIR")` is baked into the test that reads its fixture at
        // runtime, and rustc does not remap it, so that one test legitimately differs
        // between checkouts at different paths. Nothing else may.
        let synth_json: Value = serde_json::from_slice(&std::fs::read(r.ws.join("synth.json")).unwrap()).unwrap();
        let (allowed, bad): (Vec<&String>, Vec<&String>) = c.changed.iter().partition(|id| source_of(&r.ws, &synth_json, id).contains("CARGO_MANIFEST_DIR"));
        println!("[{tag}] determinism: {} keys differ between checkouts, all {} embed CARGO_MANIFEST_DIR; {} others differ", c.changed.len(), allowed.len(), bad.len());
        if !bad.is_empty() {
            r.failures.push(format!("determinism: {} keys differ between two checkouts for reasons other than CARGO_MANIFEST_DIR, e.g. {:?}", bad.len(), bad.iter().take(5).collect::<Vec<_>>()));
        }
    }
    for p in patterns {
        r.pattern(p, &base);
    }
    table.extend(r.table.iter().cloned());
    println!("\n[{tag}] {:<22} {:>6} {:>8} {:>6} {:>9}", "pattern", "tests", "changed", "same", "fallback");
    for t in &table {
        println!("[{tag}] {t}");
    }
    assert!(r.failures.is_empty(), "[{tag}] acceptance failures:\n{}", r.failures.join("\n"));
}

const ALL_PATTERNS: &[&str] = &["docs", "comment-leaf", "comment-root", "body-leaf", "body-root", "fixture", "signature-root", "dep-add", "line-shift", "add-test", "rename-test"];
const ELF_PATTERNS: &[&str] = &["body-root", "docs", "line-shift", "add-test", "rename-test"];

fn macho_only() -> bool {
    if !cfg!(target_os = "macos") {
        eprintln!("skipped: the native run is Mach-O and needs macOS");
        return false;
    }
    true
}

fn elf_ready() -> bool {
    if std::env::var_os("KEEL_ELF_LINKER").is_none() {
        eprintln!("skipped: set KEEL_ELF_LINKER to a cc-style linker wrapper targeting x86_64-unknown-linux-gnu (e.g. `zig cc -target x86_64-linux-gnu.2.34`)");
        return false;
    }
    true
}

#[test]
fn macho_synthetic_workspace() {
    if macho_only() {
        exercise(Cfg { flavor: Flavor::MachO, profile: Profile::Default }, ALL_PATTERNS, true);
    }
}

#[test]
#[ignore = "second full table under the backend's dev profile (about 10 minutes); run with --ignored"]
fn macho_synthetic_workspace_backend_profile() {
    if macho_only() {
        exercise(Cfg { flavor: Flavor::MachO, profile: Profile::Backend }, ALL_PATTERNS, true);
    }
}

#[test]
fn elf_synthetic_workspace() {
    if elf_ready() {
        exercise(Cfg { flavor: Flavor::Elf, profile: Profile::Default }, ELF_PATTERNS, false);
    }
}

#[test]
#[ignore = "ELF under the backend's dev profile (about 5 minutes); run with --ignored"]
fn elf_synthetic_workspace_backend_profile() {
    if elf_ready() {
        exercise(Cfg { flavor: Flavor::Elf, profile: Profile::Backend }, ELF_PATTERNS, false);
    }
}

// ---------------------------------------------------------------------------
// Partition invariance: the key must not depend on which codegen unit or object a
// function lands in, nor on incremental versus cold compilation.

/// Demangled names (hash stripped) of the functions in a test's full reach.
fn reach_names(r: &BinaryReach, test: &str) -> BTreeSet<String> {
    r.full_reach(test)
        .iter()
        .filter_map(|&i| {
            let s = r.atom_table.symbol(i);
            rustc_demangle::try_demangle(s).ok().map(|d| format!("{d:#}"))
        })
        .collect()
}

fn invariance(profile: Profile) {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let cfg = Cfg { flavor: Flavor::MachO, profile };
    let dir = scratch().join(format!("invariance-{}", cfg.tag()));
    let _ = std::fs::remove_dir_all(&dir);
    let loader = Loader::new();
    let ws = dir.join("ws");
    generate(&ws, cfg);
    let cold = build(&ws, &dir.join("target-cold"), cfg, &[]);
    let k0 = analyze_all(&ws, &cold, &loader, cfg, None);
    assert!(k0.unverifiable.is_empty(), "{:?}", k0.unverifiable);
    let mut failures = Vec::new();

    // (1) Unrelated edit, body edit, revert, all incremental: keys return to the cold keys exactly.
    let synth_json: Value = serde_json::from_slice(&std::fs::read(ws.join("synth.json")).unwrap()).unwrap();
    let leaf = synth_json["crates"].as_array().unwrap().last().unwrap()["name"].as_str().unwrap().to_string();
    let readme = ws.join(format!("crates/{leaf}/README.md"));
    let mut text = std::fs::read_to_string(&readme).unwrap();
    text.push_str("\nNothing to see.\n");
    std::fs::write(&readme, text).unwrap();
    let e1 = build(&ws, &dir.join("target-cold"), cfg, &[]);
    let after_readme = analyze_all(&ws, &e1, &loader, cfg, None);
    let c = compare(&k0, &after_readme);
    println!("[{}] README edit in {leaf}, incremental: {} of {} keys changed", cfg.tag(), c.changed.len(), k0.tests.len());
    if !c.changed.is_empty() {
        failures.push(format!("a README edit changed {} keys", c.changed.len()));
    }
    let rec = mutate(&ws, "body-leaf", 3);
    let e2 = build(&ws, &dir.join("target-cold"), cfg, &[]);
    let mutated = analyze_all(&ws, &e2, &loader, cfg, Some(&rec));
    let c = compare(&k0, &mutated);
    println!("[{}] body edit, incremental: {} keys changed (sanity: must be non-zero)", cfg.tag(), c.changed.len());
    if c.changed.is_empty() {
        failures.push("the body edit changed no key".into());
    }
    generate(&ws, cfg);
    let e3 = build(&ws, &dir.join("target-cold"), cfg, &[]);
    let reverted = analyze_all(&ws, &e3, &loader, cfg, None);
    let c = compare(&k0, &reverted);
    println!("[{}] revert, incremental: {} of {} keys differ from the cold build", cfg.tag(), c.changed.len(), k0.tests.len());
    if !c.changed.is_empty() {
        failures.push(format!("incremental revert differs from cold in {} keys, e.g. {:?}", c.changed.len(), c.changed.iter().take(3).collect::<Vec<_>>()));
    }

    // (2) and (3): different partitions and incremental versus not, from cold.
    let variants: [(&str, Vec<(&str, &str)>); 3] = [
        ("codegen-units=1", vec![("CARGO_PROFILE_DEV_CODEGEN_UNITS", "1"), ("CARGO_PROFILE_TEST_CODEGEN_UNITS", "1")]),
        ("codegen-units=16", vec![("CARGO_PROFILE_DEV_CODEGEN_UNITS", "16"), ("CARGO_PROFILE_TEST_CODEGEN_UNITS", "16")]),
        ("non-incremental", vec![("CARGO_INCREMENTAL", "0")]),
    ];
    for (label, env) in variants {
        let exes = build(&ws, &dir.join(format!("target-{label}")), cfg, &env);
        let a = analyze_all(&ws, &exes, &loader, cfg, None);
        let c = compare(&k0, &a);
        println!("[{}] {label} vs cold incremental default: {} of {} keys differ", cfg.tag(), c.changed.len(), k0.tests.len());
        let mut inlining = 0;
        let mut leakage = Vec::new();
        for id in &c.changed {
            let (binary, name) = id.split_once(' ').unwrap();
            let (x, y) = (reach_names(&k0.reports[binary], name), reach_names(&a.reports[binary], name));
            if x != y {
                inlining += 1;
                if inlining <= 3 {
                    let only_x: Vec<_> = x.difference(&y).take(3).collect();
                    let only_y: Vec<_> = y.difference(&x).take(3).collect();
                    println!("    {id}: reach functions differ (cold only {only_x:?}, variant only {only_y:?}): different code, acceptable");
                }
            } else {
                leakage.push(id.clone());
            }
        }
        println!("    explained by different functions in the reach (inlining or instantiation): {inlining}; identical function set but different key: {}", leakage.len());
        if !leakage.is_empty() {
            failures.push(format!("{label}: {} keys differ although the reached functions are the same, e.g. {:?}: partitioning leaks into the hash", leakage.len(), leakage.iter().take(3).collect::<Vec<_>>()));
        }
    }
    assert!(failures.is_empty(), "[{}] invariance failures:\n{}", cfg.tag(), failures.join("\n"));
}

#[test]
fn macho_partition_invariance() {
    if macho_only() {
        invariance(Profile::Default);
    }
}

#[test]
#[ignore = "partition invariance under the backend's optimised roots (about 4 minutes); inlining differences are expected and printed; run with --ignored"]
fn macho_partition_invariance_backend_profile() {
    if macho_only() {
        invariance(Profile::Backend);
    }
}
