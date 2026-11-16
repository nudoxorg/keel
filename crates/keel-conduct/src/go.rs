//! Go packages as nodes (`kind: go-test`).
//!
//! `go list -deps -json -test ./...` is the one door into Go's own idea of a
//! package: which files make it up, which packages it imports, which of them
//! belong to this module. The node keys are content hashes of those files, so
//! an edit to `db/users.go` changes the key of `db` and of every package that
//! imports it, and of nothing else.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use keel::{
    EnvContract, FileSpec, FilesInput, GroupId, Inputs, KEY_SCHEMA, Kind, NetMode, Node, NodeId,
    Platform, Policy, Status, Upstream, files_key, key,
};
use serde::Deserialize;

use crate::config::GoConfig;
use crate::model::{CleanEnv, Cx, Outcome, Planned, Runner, evidence_or_skip};
use crate::util::{Spawn, glob_escape, mix, rel_to, resolve_tools, run_captured, tail_text};

/// The fields of `go list -json` the conductor reads. Everything else is
/// ignored: the output format grows with every Go release.
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(default)]
struct Pkg {
    #[serde(rename = "ImportPath")]
    import_path: String,
    #[serde(rename = "Dir")]
    dir: String,
    #[serde(rename = "Module")]
    module: Option<Module>,
    #[serde(rename = "GoFiles")]
    go_files: Vec<String>,
    #[serde(rename = "CgoFiles")]
    cgo_files: Vec<String>,
    #[serde(rename = "CFiles")]
    c_files: Vec<String>,
    #[serde(rename = "CXXFiles")]
    cxx_files: Vec<String>,
    #[serde(rename = "HFiles")]
    h_files: Vec<String>,
    #[serde(rename = "SFiles")]
    s_files: Vec<String>,
    #[serde(rename = "SysoFiles")]
    syso_files: Vec<String>,
    #[serde(rename = "EmbedFiles")]
    embed_files: Vec<String>,
    #[serde(rename = "TestGoFiles")]
    test_go_files: Vec<String>,
    #[serde(rename = "XTestGoFiles")]
    x_test_go_files: Vec<String>,
    #[serde(rename = "TestEmbedFiles")]
    test_embed_files: Vec<String>,
    #[serde(rename = "XTestEmbedFiles")]
    x_test_embed_files: Vec<String>,
    #[serde(rename = "Deps")]
    deps: Vec<String>,
    #[serde(rename = "Standard")]
    standard: bool,
    #[serde(rename = "ForTest")]
    for_test: String,
}

#[derive(Deserialize, Default, Debug, Clone)]
#[serde(default)]
struct Module {
    #[serde(rename = "Main")]
    main: bool,
    #[serde(rename = "Dir")]
    dir: String,
}

impl Pkg {
    fn has_tests(&self) -> bool {
        !self.test_go_files.is_empty() || !self.x_test_go_files.is_empty()
    }

    /// Files compiled into the package for its dependents.
    fn lib_files(&self) -> impl Iterator<Item = &String> {
        [
            &self.go_files,
            &self.cgo_files,
            &self.c_files,
            &self.cxx_files,
            &self.h_files,
            &self.s_files,
            &self.syso_files,
            &self.embed_files,
        ]
        .into_iter()
        .flatten()
    }

    /// Everything the package's own test binary is built from.
    fn all_files(&self) -> impl Iterator<Item = &String> {
        self.lib_files().chain(
            [
                &self.test_go_files,
                &self.x_test_go_files,
                &self.test_embed_files,
                &self.x_test_embed_files,
            ]
            .into_iter()
            .flatten(),
        )
    }
}

/// `pkg [pkg.test]` is the test variant of `pkg`; the dependency is `pkg`.
fn base_path(import_path: &str) -> &str {
    import_path.split(" [").next().unwrap_or(import_path)
}

/// The node id of a package.
pub fn node_id(import_path: &str) -> NodeId {
    NodeId::new(format!("go:{import_path}"))
}

/// What running one package needs.
pub struct GoRun {
    go: PathBuf,
    root: PathBuf,
    /// `./db`, relative to the repository root, so the command line never
    /// depends on the module path.
    target: String,
    env: CleanEnv,
    /// `GOCACHE`, `GOMODCACHE`, `GOPATH`, `GOROOT` of the ambient toolchain:
    /// caches are content-addressed and cannot change a test's outcome, so
    /// they are passed through without being keyed.
    go_dirs: Vec<(String, String)>,
    timeout: Option<Duration>,
}

/// Runs `go` with the ambient environment (planning, not testing).
fn go_output(go: &Path, cwd: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = std::process::Command::new(go)
        .args(args)
        .current_dir(cwd)
        .env("GOFLAGS", "-mod=readonly")
        .env("GOTOOLCHAIN", "local")
        .output()
        .with_context(|| {
            format!(
                "cannot start {}; pass --go <path to the go binary> or run from a shell that provides it",
                go.display()
            )
        })?;
    if !out.status.success() {
        bail!(
            "`go {}` failed in {}: {}; Go packages cannot be planned until this works (is there a go.mod at the repository root, and are the modules in the module cache?)",
            args.join(" "),
            cwd.display(),
            tail_text(&out.stderr, 2000)
        );
    }
    Ok(out.stdout)
}

/// Builds the Go nodes of the module at `repo_root/<cfg.root>`.
pub fn plan(repo_root: &Path, cfg: &GoConfig, go: &Path) -> Result<Vec<Planned>> {
    let repo = repo_root.canonicalize().with_context(|| {
        format!(
            "the repository root {} does not exist; fix --repo-root",
            repo_root.display()
        )
    })?;
    let module_root = repo.join(cfg.root.as_deref().unwrap_or("."));
    let module_root = module_root.canonicalize().with_context(|| {
        format!(
            "the Go root {} does not exist; fix `[go] root` in the config",
            module_root.display()
        )
    })?;
    let listing = go_output(
        go,
        &module_root,
        &["list", "-deps", "-json", "-test", "./..."],
    )?;
    let pkgs: Vec<Pkg> = serde_json::Deserializer::from_slice(&listing)
        .into_iter::<Pkg>()
        .collect::<Result<_, _>>()
        .context("`go list -json` printed something that is not a stream of package objects; is `go` really the Go toolchain?")?;

    let version = String::from_utf8_lossy(&go_output(go, &module_root, &["version"])?)
        .trim()
        .to_owned();
    let go_real = go.canonicalize().unwrap_or_else(|_| go.to_path_buf());
    let go_dirs: Vec<(String, String)> = {
        let text = go_output(
            go,
            &module_root,
            &["env", "GOROOT", "GOCACHE", "GOMODCACHE", "GOPATH"],
        )?;
        let text = String::from_utf8_lossy(&text);
        ["GOROOT", "GOCACHE", "GOMODCACHE", "GOPATH"]
            .iter()
            .zip(text.lines())
            .map(|(k, v)| ((*k).to_owned(), v.trim().to_owned()))
            .collect()
    };
    let mut tool_names = vec![go_real.to_string_lossy().into_owned()];
    tool_names.extend(cfg.tools.iter().cloned());
    let (tools, tools_digest) = resolve_tools(&tool_names, &[("go".to_owned(), version.clone())])?;

    let mut platform = Platform::new(crate::util::host_triple(), version, NetMode::Open);
    platform.extra.clear();
    let ctx = PlanCtx {
        repo: &repo,
        module_root: &module_root,
        cfg,
        go: &go_real,
        tools_digest,
        clean: CleanEnv {
            contract: EnvContract {
                allow: cfg.env.clone(),
                profile_env: BTreeMap::new(),
            },
            tools: tools.into_iter().map(|t| (t.name, t.path)).collect(),
        },
        go_dirs,
        platform,
    };
    build_nodes(&pkgs, &ctx)
}

struct PlanCtx<'a> {
    repo: &'a Path,
    module_root: &'a Path,
    cfg: &'a GoConfig,
    go: &'a Path,
    tools_digest: keel::Digest,
    clean: CleanEnv,
    go_dirs: Vec<(String, String)>,
    platform: Platform,
}

fn build_nodes(pkgs: &[Pkg], cx: &PlanCtx<'_>) -> Result<Vec<Planned>> {
    // The entry without `ForTest` and without a bracketed variant is the
    // package itself; `<pkg>.test` is the generated test main, whose `Deps`
    // also hold what the test files import.
    let mut base: BTreeMap<&str, &Pkg> = BTreeMap::new();
    let mut test_main: BTreeMap<String, &Pkg> = BTreeMap::new();
    for p in pkgs {
        if !p.for_test.is_empty() || p.import_path.contains(" [") {
            continue;
        }
        if let Some(stem) = p.import_path.strip_suffix(".test") {
            test_main.insert(stem.to_owned(), p);
        }
        base.insert(&p.import_path, p);
    }

    let in_repo = |p: &Pkg| -> bool {
        !p.standard
            && p.module.as_ref().is_some_and(|m| m.main)
            && !p.dir.is_empty()
            && Path::new(&p.dir)
                .canonicalize()
                .is_ok_and(|d| d.starts_with(cx.module_root))
    };
    let with_tests: BTreeSet<&str> = base
        .values()
        .filter(|p| in_repo(p) && p.has_tests())
        .map(|p| p.import_path.as_str())
        .collect();

    let mut planned = Vec::new();
    for &path in &with_tests {
        let pkg = base[path];
        // Everything the test binary links: the package's own `Deps` plus the
        // test main's, which add what `_test.go` files import.
        let mut deps: BTreeSet<String> = pkg.deps.iter().map(|d| base_path(d).to_owned()).collect();
        if let Some(tm) = test_main.get(path) {
            deps.extend(tm.deps.iter().map(|d| base_path(d).to_owned()));
        }
        deps.remove(path);
        let module_deps: Vec<&Pkg> = deps
            .iter()
            .filter_map(|d| base.get(d.as_str()).copied())
            .filter(|p| in_repo(p))
            .collect();

        // Listed files, relative to the repository root. `expected` is the
        // exact-file subset used to prove the walk really found each one.
        let mut expected: BTreeSet<String> = BTreeSet::new();
        let mut add = |p: &Pkg, files: &mut dyn Iterator<Item = &String>| -> Result<()> {
            for f in files {
                let abs = Path::new(&p.dir).join(f);
                let abs = abs.canonicalize().with_context(|| {
                    format!("{path} lists {} but it does not exist; run `go list` from a clean checkout", abs.display())
                })?;
                let rel = rel_to(cx.repo, &abs).ok_or_else(|| {
                    anyhow!("{} (listed by package {}) is outside the repository root {}; use --repo-root with the directory that contains it", abs.display(), p.import_path, cx.repo.display())
                })?;
                expected.insert(rel);
            }
            Ok(())
        };
        add(pkg, &mut pkg.all_files())?;
        for d in &module_deps {
            add(d, &mut d.lib_files())?;
        }
        let mod_dir = pkg
            .module
            .as_ref()
            .map_or(cx.module_root.to_path_buf(), |m| PathBuf::from(&m.dir));
        let mut globs: Vec<String> = Vec::new();
        for name in ["go.mod", "go.sum"] {
            if let Some(rel) = rel_to(
                cx.repo,
                &mod_dir.canonicalize().unwrap_or(mod_dir.clone()).join(name),
            ) {
                globs.push(glob_escape(&rel));
            }
        }
        globs.extend(expected.iter().map(|e| glob_escape(e)));
        // Go tests conventionally read `testdata/`; it is not a listed file.
        let own_rel = rel_to(cx.repo, &Path::new(&pkg.dir).canonicalize()?).unwrap_or_default();
        let testdata = if own_rel.is_empty() {
            "testdata/**".to_owned()
        } else {
            format!("{}/testdata/**", glob_escape(&own_rel))
        };
        globs.push(testdata);
        globs.extend(cx.cfg.inputs.iter().cloned());

        let (files, selected) = files_key(
            cx.repo,
            &FileSpec {
                package_dir: None,
                globs,
                ..FileSpec::default()
            },
        )
        .with_context(|| format!("cannot hash the input files of {path}"))?;
        let selected: BTreeSet<&str> = selected.iter().map(|p| p.as_str()).collect();
        // Belt and braces: the walk no longer consults .gitignore, but a Go file
        // that is compiled and yet not keyed is the one unforgivable mistake.
        if let Some(missing) = expected.iter().find(|e| !selected.contains(e.as_str())) {
            bail!(
                "{missing} is part of Go package {path} but the file walk did not select it (is the path escaped wrongly, or was it excluded?); fix that, or the package would be keyed without a file it compiles"
            );
        }

        let stands_on: Vec<Upstream> = deps
            .iter()
            .filter(|d| with_tests.contains(d.as_str()))
            .map(|d| Upstream::Node(node_id(d)))
            .collect();
        // The import path is part of what a package is (embedded paths, the
        // binary's name), so two copies of a directory do not share a key.
        let files = mix(files, &[("package".to_owned(), path.to_owned())]);
        let inputs = Inputs {
            files: Some(FilesInput::Hash(files)),
            tools: Some(cx.tools_digest),
            ..Inputs::default()
        };
        let node = Node {
            id: node_id(path),
            kind: Kind::GoTest,
            group: GroupId::unit(format!("go:{path}")),
            stands_on,
            joins: Vec::new(),
            key: key(KEY_SCHEMA, &inputs, &cx.platform)?,
            inputs,
            produces: Vec::new(),
            via: None,
            policy: Policy {
                timeout: cx.cfg.timeout_s,
                ..Policy::default()
            },
        };
        let target = match Path::new(&pkg.dir)
            .canonicalize()?
            .strip_prefix(cx.module_root)
        {
            Ok(r) if r.as_os_str().is_empty() => ".".to_owned(),
            Ok(r) => format!("./{}", rel_to(Path::new(""), r).unwrap_or_default()),
            Err(_) => path.to_owned(),
        };
        planned.push(Planned {
            node,
            runner: Runner::Go(GoRun {
                go: cx.go.to_path_buf(),
                root: cx.module_root.to_path_buf(),
                target,
                env: cx.clean.clone(),
                go_dirs: cx.go_dirs.clone(),
                timeout: cx.cfg.timeout_s.map(Duration::from_secs),
            }),
        });
    }
    Ok(planned)
}

/// One test's result from `go test -json`.
#[derive(Debug, Clone, PartialEq)]
pub struct TestRecord {
    /// Test name; empty for the package line.
    pub test: String,
    /// `pass`, `fail` or `skip`.
    pub action: String,
    /// Seconds, as Go measured.
    pub elapsed_s: f64,
}

/// Parsed `go test -json` output.
#[derive(Debug, Default)]
pub struct GoResult {
    /// Per-test records, in name order.
    pub tests: Vec<TestRecord>,
    /// The package line's action.
    pub package: Option<String>,
    /// Output lines of failing tests, by name, framework noise removed.
    pub failures: BTreeMap<String, Vec<String>>,
    /// Package-level output (build errors, panics outside a test).
    pub package_output: Vec<String>,
}

/// Parses the JSON event stream of `go test -json`.
pub fn parse_events(stdout: &str) -> GoResult {
    #[derive(Deserialize, Default)]
    #[serde(default, rename_all = "PascalCase")]
    struct Event {
        action: String,
        test: Option<String>,
        elapsed: Option<f64>,
        output: Option<String>,
    }
    let mut tests: BTreeMap<String, TestRecord> = BTreeMap::new();
    let mut output: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut res = GoResult::default();
    for line in stdout.lines() {
        let Ok(ev) = serde_json::from_str::<Event>(line) else {
            // Not an event: `go test` printed a plain line (a setup failure).
            if !line.trim().is_empty() {
                res.package_output.push(line.to_owned());
            }
            continue;
        };
        let name = ev.test.clone().unwrap_or_default();
        match ev.action.as_str() {
            "pass" | "fail" | "skip" => {
                if name.is_empty() {
                    res.package = Some(ev.action.clone());
                } else {
                    tests.insert(
                        name.clone(),
                        TestRecord {
                            test: name,
                            action: ev.action,
                            elapsed_s: ev.elapsed.unwrap_or(0.0),
                        },
                    );
                }
            }
            "build-fail" => res.package = Some("fail".to_owned()),
            "output" | "build-output" => {
                let text = ev.output.unwrap_or_default();
                if name.is_empty() {
                    res.package_output.push(text.trim_end().to_owned());
                } else {
                    output
                        .entry(name)
                        .or_default()
                        .push(text.trim_end().to_owned());
                }
            }
            _ => {}
        }
    }
    const NOISE: [&str; 5] = ["=== RUN", "=== PAUSE", "=== CONT", "=== NAME", "--- "];
    for t in tests.values().filter(|t| t.action == "fail") {
        let lines = output
            .remove(&t.test)
            .unwrap_or_default()
            .into_iter()
            .filter(|l| {
                !NOISE.iter().any(|n| l.trim_start().starts_with(n)) && !l.trim().is_empty()
            })
            .collect();
        res.failures.insert(t.test.clone(), lines);
    }
    res.tests = tests.into_values().collect();
    res
}

impl GoResult {
    /// A short account of what failed, for `detail.actual`.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        // A parent test fails because a subtest did; report the leaves.
        let leaves: Vec<&String> = self
            .failures
            .keys()
            .filter(|k| {
                !self
                    .failures
                    .keys()
                    .any(|o| o.starts_with(&format!("{k}/")))
            })
            .collect();
        for name in leaves.iter().take(5) {
            out.push_str(&format!("FAIL {name}\n"));
            for line in self.failures[*name].iter().take(8) {
                out.push_str(&format!("    {}\n", line.trim()));
            }
        }
        if leaves.len() > 5 {
            out.push_str(&format!(
                "... and {} more failing tests\n",
                leaves.len() - 5
            ));
        }
        for line in self
            .package_output
            .iter()
            .filter(|l| !l.trim().is_empty())
            .take(10)
        {
            out.push_str(&format!("{}\n", line.trim()));
        }
        out.trim().to_owned()
    }
}

/// What a finished `go test -json` means. `skip` is not `pass`: a package that
/// reports `skip` ("no test files"), or whose tests all skipped, or that has
/// no test at all, checked nothing, and storing it as a pass would let a
/// changed key be answered from a result that never tested anything.
fn classify(
    res: &GoResult,
    code: Option<i32>,
    ran: &str,
    stderr: &[u8],
) -> (Status, Option<String>, Option<String>) {
    let nothing = |why: &str| {
        (
            Status::Skipped,
            Some(keel::RAN_NOTHING.to_owned()),
            Some(format!(
                "ran nothing: {why}; a skip is not a pass, so the package stays unverified. Make a test run (unset the condition it skips on) or remove the package from the plan"
            )),
        )
    };
    match res.package.as_deref() {
        Some("pass") if res.tests.iter().any(|t| t.action == "pass") => (Status::Pass, None, None),
        Some("pass") if res.tests.iter().any(|t| t.action == "skip") => {
            nothing("every test in the package skipped")
        }
        Some("pass") => nothing("the package reported pass but no test ran"),
        Some("skip") => nothing("go reported the package as skipped (no test files)"),
        Some(_) => (Status::Fail, None, Some(res.summary())),
        None if code == Some(0) => (
            Status::Error,
            None,
            Some(format!(
                "go test exited 0 but printed no result line; run `{ran}` by hand"
            )),
        ),
        None => (
            Status::Error,
            None,
            Some(format!(
                "go test exited with {code:?} and no result line: {}; run `{ran}` by hand",
                tail_text(stderr, 1500)
            )),
        ),
    }
}

impl GoRun {
    /// Runs `go test -json` for the package.
    pub fn run(&self, node: &Node, cx: &Cx<'_>) -> Outcome {
        let started = Instant::now();
        let ran = format!("go test -json {}", self.target);
        let env = match self.env.build(cx.work, &node.id) {
            Ok(mut env) => {
                env.extend(self.go_dirs.iter().cloned());
                // Reproducible module resolution: no user config file, no
                // download of a different toolchain, no go.mod rewriting.
                env.extend(
                    [
                        ("GOENV", "off"),
                        ("GOFLAGS", "-mod=readonly"),
                        ("GOTOOLCHAIN", "local"),
                    ]
                    .map(|(k, v)| (k.to_owned(), v.to_owned())),
                );
                env
            }
            Err(e) => return Outcome::error(format!("{e:#}"), &ran, started),
        };
        let argv = [
            self.go.to_string_lossy().into_owned(),
            "test".into(),
            "-json".into(),
            "-count=1".into(),
            self.target.clone(),
        ];
        let got = match run_captured(&Spawn {
            argv: &argv,
            cwd: &self.root,
            env: &env,
            timeout: self.timeout,
        }) {
            Ok(g) => g,
            Err(e) => return Outcome::error(format!("{e:#}"), &ran, started),
        };
        let res = parse_events(&String::from_utf8_lossy(&got.stdout));
        let (status, reason, actual) = if got.timed_out {
            (
                Status::Timeout,
                None,
                Some(format!(
                    "killed after {:?}",
                    self.timeout.unwrap_or_default()
                )),
            )
        } else {
            classify(&res, got.code, &ran, &got.stderr)
        };
        let tests_json = serde_json::to_vec_pretty(
            &res.tests
                .iter()
                .map(|t| serde_json::json!({"test": t.test, "action": t.action, "elapsed_s": t.elapsed_s}))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default();
        let mut evidence = evidence_or_skip(cx.store, "go-test.json", &tests_json);
        if status != Status::Pass {
            evidence.extend(evidence_or_skip(cx.store, "stdout", &got.stdout));
            evidence.extend(evidence_or_skip(cx.store, "stderr", &got.stderr));
        }
        Outcome {
            status,
            reason,
            detail: actual.map(|a| keel::Detail {
                ran,
                expected: Some("every test passes".to_owned()),
                actual: Some(a),
            }),
            evidence,
            extra: Vec::new(),
            duration_ms: started.elapsed().as_millis() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel::Status;

    #[test]
    fn parses_pass_fail_and_noise() {
        let out = r#"{"Action":"run","Package":"m/p","Test":"TestA"}
{"Action":"output","Package":"m/p","Test":"TestA","Output":"=== RUN   TestA\n"}
{"Action":"output","Package":"m/p","Test":"TestA","Output":"    a_test.go:9: want 2, got 3\n"}
{"Action":"output","Package":"m/p","Test":"TestA","Output":"--- FAIL: TestA (0.00s)\n"}
{"Action":"fail","Package":"m/p","Test":"TestA","Elapsed":0.01}
{"Action":"pass","Package":"m/p","Test":"TestB","Elapsed":0.02}
{"Action":"fail","Package":"m/p","Elapsed":0.2}
not json at all
"#;
        let r = parse_events(out);
        assert_eq!(r.package.as_deref(), Some("fail"));
        assert_eq!(r.tests.len(), 2);
        assert_eq!(r.failures["TestA"], ["    a_test.go:9: want 2, got 3"]);
        assert!(r.summary().contains("want 2, got 3"));
        assert_eq!(r.package_output, ["not json at all"]);
    }

    #[test]
    fn subtests_report_leaves_only() {
        let out = r#"{"Action":"output","Test":"TestP","Output":"x\n"}
{"Action":"output","Test":"TestP/sub","Output":"boom\n"}
{"Action":"fail","Test":"TestP/sub","Elapsed":0}
{"Action":"fail","Test":"TestP","Elapsed":0}
{"Action":"fail","Elapsed":0}"#;
        let s = parse_events(out).summary();
        assert!(
            s.contains("FAIL TestP/sub") && !s.contains("FAIL TestP\n"),
            "{s}"
        );
    }

    fn run_of(events: &str, code: i32) -> (Status, Option<String>) {
        let res = parse_events(events);
        let (s, reason, _) = classify(&res, Some(code), "go test -json ./p", b"");
        (s, reason)
    }

    #[test]
    fn a_skip_is_never_a_pass() {
        // `go test` on a directory with no test files.
        let none = r#"{"Action":"skip","Package":"m/p"}"#;
        assert_eq!(
            run_of(none, 0),
            (Status::Skipped, Some(keel::RAN_NOTHING.into()))
        );
        // Every test skipped: go still prints package `pass` (the `ok` line).
        let all = r#"{"Action":"skip","Package":"m/p","Test":"TestA","Elapsed":0}
{"Action":"skip","Package":"m/p","Test":"TestB","Elapsed":0}
{"Action":"pass","Package":"m/p","Elapsed":0.1}"#;
        assert_eq!(
            run_of(all, 0),
            (Status::Skipped, Some(keel::RAN_NOTHING.into()))
        );
        // Package pass with no test events at all (only a TestMain, say).
        let bare = r#"{"Action":"pass","Package":"m/p","Elapsed":0.1}"#;
        assert_eq!(
            run_of(bare, 0),
            (Status::Skipped, Some(keel::RAN_NOTHING.into()))
        );
    }

    #[test]
    fn one_passing_test_among_skips_is_a_pass_and_nothing_else_is() {
        let mixed = r#"{"Action":"skip","Package":"m/p","Test":"TestA","Elapsed":0}
{"Action":"pass","Package":"m/p","Test":"TestB","Elapsed":0}
{"Action":"pass","Package":"m/p","Elapsed":0.1}"#;
        assert_eq!(run_of(mixed, 0), (Status::Pass, None));
        let failed = r#"{"Action":"pass","Package":"m/p","Test":"TestB","Elapsed":0}
{"Action":"fail","Package":"m/p","Elapsed":0.1}"#;
        assert_eq!(run_of(failed, 1).0, Status::Fail);
        // No result line is an error whatever the exit code, never a pass.
        assert_eq!(run_of("", 0).0, Status::Error);
        assert_eq!(run_of("go: downloading", 1).0, Status::Error);
        assert!(run_of("", 0).1.is_none());
    }

    #[test]
    fn variants_resolve_to_their_package() {
        assert_eq!(base_path("a/b [a/b.test]"), "a/b");
        assert_eq!(base_path("a/b"), "a/b");
    }
}
