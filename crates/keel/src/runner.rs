//! How a test process is started, and the key of that, design/keys.md §2.5.
//!
//! A [`Runner`] is the only way to get a command line for a test. Its
//! constructor takes the ambient environment *and consumes it*: what comes out
//! is the exact, closed environment the process must be given, and the argv, the
//! working directory and that environment are hashed together into
//! [`Key<Runner>`]. There is no accessor for the arguments without the
//! environment, so a runner cannot start a test with the declared arguments and
//! somebody else's variables: the key it computed is a statement about the
//! environment it hands out.
//!
//! # What the nextest fork must change to use this
//!
//! Today the fork (`nextest-runner/src/keel/plan.rs`, `env_digest`, about :629)
//! hashes only the *declared* variables with `keel::env_key`, then spawns every
//! test with nextest's own command builder, which inherits the whole ambient
//! environment of the nextest process plus the profile env. So an undeclared
//! variable (`NUDOX_CLANG`, `RUST_LOG`) reaches the test and is in no key.
//! To close that:
//!
//! 1. Build one [`Runner`] per test from [`RunnerSpec`], passing the ambient
//!    environment the fork already collects (`self.ambient`) and the profile
//!    table as `contract.profile_env`.
//! 2. Take the per-test key from [`Runner::key`] and fold it into the node's
//!    static key instead of `env_key`.
//! 3. In the executor, replace the construction of the test command (the
//!    `TestCommand`/`LocalExecuteContext` path that calls
//!    `Command::env`/`envs` on top of the inherited environment) with
//!    `Runner::launch(...)`; build the process from
//!    [`Launch::command`], converting with
//!    `tokio::process::Command::from(launch.command())`. That command has had
//!    `env_clear()` applied; nextest must not add `NEXTEST*`, `CARGO_*` or any
//!    other variable afterwards. Anything the test needs (`CARGO_MANIFEST_DIR`,
//!    `CARGO_BIN_EXE_*`) is declared in the contract so it is both visible and
//!    keyed.
//! 4. `HOME` and `TMPDIR` are in the key, so they must be the same on every
//!    run (a fixed path inside the sandbox). A random per-run directory makes
//!    every key new, which fails safe: nothing is ever served from cache.
//!
//! `Platform.net` and `Platform.toolchain` are not part of this key by
//! construction: there is no field to put them in (design/keys.md §2.5, §3.1
//! row 7 and row 12).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::env::{EnvContract, closed_environment};
use crate::key::{Domain, Key};

/// Keel's own contract version for starting tests; bumped by hand when the
/// meaning of an argv, an environment or an exit status changes.
pub const RUNNER_PROTOCOL: u32 = 1;

impl Domain for Runner {
    const NAME: &'static str = "keel/runner/1";
}

/// What the sandbox allows, hashed; the supervisor that enforces it is not part
/// of this crate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SandboxProfile {
    /// Paths the process may read.
    pub read: Vec<String>,
    /// Paths it may write.
    pub write: Vec<String>,
}

impl Domain for SandboxProfile {
    const NAME: &'static str = "keel/sandbox/1";
}

impl SandboxProfile {
    /// The key of this profile; order and duplicates do not matter.
    pub fn key(&self) -> Key<SandboxProfile> {
        let mut f = Key::<SandboxProfile>::begin();
        for (tag, paths) in [(1, &self.read), (2, &self.write)] {
            let mut sorted: Vec<&str> = paths.iter().map(String::as_str).collect();
            sorted.sort_unstable();
            sorted.dedup();
            f.strings(tag, sorted);
        }
        Key::seal(&f)
    }
}

/// What the process sees of its own limits. `None` means unlimited.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// Address-space limit in bytes.
    pub address_space: Option<u64>,
    /// Open-file limit.
    pub open_files: Option<u64>,
    /// The CPU count the process is told it has.
    pub visible_cpus: Option<u32>,
}

/// What the process is given on standard input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Stdin {
    /// `/dev/null`.
    #[default]
    Null,
}

/// Everything needed to start one test, other than the executable.
pub struct RunnerSpec<'a> {
    /// See [`RUNNER_PROTOCOL`].
    pub protocol: u32,
    /// Arguments after the program, e.g. `["--exact", "a::b", "--nocapture"]`.
    /// The test's name enters the key here, because this is how the process
    /// learns it.
    pub argv_tail: Vec<String>,
    /// Working directory, relative to the build root. Hashed as given.
    pub cwd: String,
    /// The model's declared variables.
    pub contract: &'a EnvContract,
    /// The environment of the calling process. It is read here, once, and not
    /// kept: only the declared names survive into the [`Runner`].
    pub ambient: &'a HashMap<String, String>,
    /// The value of `PATH`: a directory of the declared tools.
    pub tools_path: &'a str,
    /// The test's `HOME`; must be the same path on every run, see the module notes.
    pub home: &'a Path,
    /// The test's `TMPDIR`; likewise.
    pub tmpdir: &'a Path,
    /// The sandbox it runs in.
    pub sandbox: Key<SandboxProfile>,
    /// Limits it can observe.
    pub limits: Limits,
}

/// How one test process is started: its arguments, directory, complete
/// environment and the key of all of them.
///
/// The fields are private. The environment is the one [`closed_environment`]
/// built from the spec, and the only ways out are [`Runner::key`], the
/// read-only [`Runner::env`], and [`Runner::launch`], which returns the
/// arguments *together with* that environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Runner {
    protocol: u32,
    argv_tail: Vec<String>,
    cwd: String,
    env: BTreeMap<String, String>,
    sandbox: Key<SandboxProfile>,
    stdin: Stdin,
    limits: Limits,
}

impl Runner {
    /// Builds the runner. The environment is cleared first and then holds,
    /// and only holds: the contract's allow-listed ambient variables that are
    /// set, its profile table, `TZ=UTC` and `LANG=C.UTF-8` unless declared, and
    /// `PATH`, `HOME` and `TMPDIR` from the spec.
    pub fn new(spec: RunnerSpec<'_>) -> Runner {
        Runner {
            protocol: spec.protocol,
            argv_tail: spec.argv_tail,
            cwd: spec.cwd,
            env: closed_environment(
                spec.contract,
                spec.ambient,
                spec.tools_path,
                spec.home,
                spec.tmpdir,
            ),
            sandbox: spec.sandbox,
            stdin: Stdin::Null,
            limits: spec.limits,
        }
    }

    /// The environment the process will be given, nothing added or removed.
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    /// The key of everything above: protocol, argv tail, cwd, environment,
    /// sandbox, stdin and limits. It does not contain the toolchain or the
    /// network mode.
    pub fn key(&self) -> Key<Runner> {
        let mut f = Key::<Runner>::begin();
        f.field(1, &self.protocol.to_le_bytes());
        f.strings(2, self.argv_tail.iter().map(String::as_str));
        f.field(3, self.cwd.as_bytes());
        f.field(4, &(self.env.len() as u64).to_le_bytes());
        for (k, v) in &self.env {
            f.field(5, k.as_bytes()).field(6, v.as_bytes());
        }
        f.field(7, self.sandbox.digest().as_bytes());
        f.field(
            8,
            &[match self.stdin {
                Stdin::Null => 0,
            }],
        );
        for (tag, v) in [
            (9, self.limits.address_space),
            (10, self.limits.open_files),
            (11, self.limits.visible_cpus.map(u64::from)),
        ] {
            f.opt_str(tag, v.map(|n| n.to_string()).as_deref());
        }
        Key::seal(&f)
    }

    /// The command line for running `program` (the test executable) from
    /// `build_root`, with the environment it must run under.
    pub fn launch(&self, program: &Path, build_root: &Path) -> Launch {
        Launch {
            program: program.to_owned(),
            args: self.argv_tail.clone(),
            cwd: build_root.join(&self.cwd),
            env: self.env.clone(),
        }
    }
}

/// A command line that carries its environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    program: PathBuf,
    args: Vec<String>,
    cwd: PathBuf,
    env: BTreeMap<String, String>,
}

impl Launch {
    /// The process to spawn: environment cleared, then exactly [`Runner::env`],
    /// standard input closed. Nothing else may be added to it.
    pub fn command(&self) -> Command {
        let mut c = Command::new(&self.program);
        c.args(&self.args)
            .current_dir(&self.cwd)
            .env_clear()
            .envs(&self.env)
            .stdin(std::process::Stdio::null());
        c
    }

    /// The program and arguments, for display only; do not spawn from these.
    pub fn display(&self) -> String {
        std::iter::once(self.program.to_string_lossy().into_owned())
            .chain(self.args.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ambient() -> HashMap<String, String> {
        [
            ("PATH", "/usr/bin"),
            ("UNDECLARED_SECRET", "hunter2"),
            ("NUDOX_CLANG", "/opt/clang"),
            ("NEXTEST", "1"),
            ("NEXTEST_RUN_ID", "run-1"),
            ("TZ", "Europe/Oslo"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }

    fn contract() -> EnvContract {
        EnvContract {
            allow: vec!["NUDOX_CLANG".into(), "NOT_SET".into()],
            profile_env: [("FIXED".to_owned(), "1".to_owned())].into(),
        }
    }

    fn runner_with(contract: &EnvContract, ambient: &HashMap<String, String>) -> Runner {
        Runner::new(RunnerSpec {
            protocol: RUNNER_PROTOCOL,
            argv_tail: vec!["--exact".into(), "a::b".into(), "--nocapture".into()],
            cwd: "crates/a".into(),
            contract,
            ambient,
            tools_path: "/keel/bin",
            home: Path::new("/keel/home"),
            tmpdir: Path::new("/keel/tmp"),
            sandbox: SandboxProfile::default().key(),
            limits: Limits::default(),
        })
    }

    #[test]
    fn a_variable_nobody_declared_is_absent_from_the_environment() {
        let r = runner_with(&contract(), &ambient());
        let expected: BTreeMap<String, String> = [
            ("FIXED", "1"),
            ("HOME", "/keel/home"),
            ("LANG", "C.UTF-8"),
            ("NUDOX_CLANG", "/opt/clang"),
            ("PATH", "/keel/bin"),
            ("TMPDIR", "/keel/tmp"),
            ("TZ", "UTC"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        assert_eq!(r.env(), &expected);
        for gone in ["UNDECLARED_SECRET", "NEXTEST", "NEXTEST_RUN_ID", "NOT_SET"] {
            assert!(!r.env().contains_key(gone), "{gone}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_spawned_process_sees_exactly_that_environment() {
        let r = runner_with(&contract(), &ambient());
        // `env` prints what the process was given, whatever this process has:
        // an undeclared variable set here must not reach it.
        let mut launch = r.launch(Path::new("/usr/bin/env"), Path::new("/"));
        launch.args = Vec::new();
        launch.cwd = PathBuf::from("/");
        // SAFETY: no other test in this module reads this variable.
        unsafe { std::env::set_var("KEEL_RUNNER_TEST_LEAK", "leaked") };
        let out = launch.command().output().unwrap();
        assert!(out.status.success());
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("NUDOX_CLANG=/opt/clang"), "{text}");
        assert!(
            !text.contains("KEEL_RUNNER_TEST_LEAK") && !text.contains("UNDECLARED"),
            "{text}"
        );
        assert_eq!(text.lines().count(), r.env().len(), "{text}");
    }

    #[test]
    fn changing_a_declared_variables_value_changes_the_key_and_an_undeclared_one_does_not() {
        let base = runner_with(&contract(), &ambient()).key();

        let mut a = ambient();
        a.insert("NUDOX_CLANG".into(), "/opt/clang-2".into());
        assert_ne!(base, runner_with(&contract(), &a).key(), "declared value");

        let mut a = ambient();
        a.insert("UNDECLARED_SECRET".into(), "changed".into());
        a.insert("NEXTEST_RUN_ID".into(), "run-2".into());
        assert_eq!(
            base,
            runner_with(&contract(), &a).key(),
            "undeclared and run-varying"
        );

        // Declaring it is a model change, and it changes the key.
        let mut c = contract();
        c.allow.push("UNDECLARED_SECRET".into());
        assert_ne!(base, runner_with(&c, &ambient()).key());

        // The model's own table is part of it too.
        let mut c = contract();
        c.profile_env.insert("FIXED".into(), "2".into());
        assert_ne!(base, runner_with(&c, &ambient()).key());
    }

    #[test]
    fn the_key_covers_argv_cwd_sandbox_limits_and_the_two_directories() {
        let c = contract();
        let a = ambient();
        let base = runner_with(&c, &a);
        let spec = |f: &dyn Fn(&mut RunnerSpec<'_>)| {
            let mut s = RunnerSpec {
                protocol: RUNNER_PROTOCOL,
                argv_tail: base.argv_tail.clone(),
                cwd: base.cwd.clone(),
                contract: &c,
                ambient: &a,
                tools_path: "/keel/bin",
                home: Path::new("/keel/home"),
                tmpdir: Path::new("/keel/tmp"),
                sandbox: base.sandbox,
                limits: Limits::default(),
            };
            f(&mut s);
            Runner::new(s).key()
        };
        assert_eq!(base.key(), spec(&|_| {}));
        let changes: Vec<Key<Runner>> = vec![
            spec(&|s| s.protocol += 1),
            spec(&|s| s.argv_tail.push("--ignored".into())),
            spec(&|s| s.argv_tail[1] = "a::c".into()),
            spec(&|s| s.cwd = "crates/b".into()),
            spec(&|s| s.tools_path = "/other/bin"),
            spec(&|s| s.home = Path::new("/run-7/home")),
            spec(&|s| s.tmpdir = Path::new("/run-7/tmp")),
            spec(&|s| {
                s.sandbox = SandboxProfile {
                    read: vec!["/etc".into()],
                    write: vec![],
                }
                .key()
            }),
            spec(&|s| s.limits.visible_cpus = Some(4)),
            spec(&|s| s.limits.open_files = Some(1024)),
        ];
        for (i, k) in changes.iter().enumerate() {
            assert_ne!(*k, base.key(), "change {i} left the key as it was");
            assert!(
                changes.iter().skip(i + 1).all(|o| o != k),
                "change {i} collides"
            );
        }
    }

    #[test]
    fn a_launch_carries_the_environment_with_the_command_line() {
        let r = runner_with(&contract(), &ambient());
        let l = r.launch(Path::new("/b/deps/a-123"), Path::new("/ws"));
        assert_eq!(l.display(), "/b/deps/a-123 --exact a::b --nocapture");
        let cmd = l.command();
        assert_eq!(cmd.get_current_dir(), Some(Path::new("/ws/crates/a")));
        let envs: BTreeMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        assert_eq!(&envs, r.env());
    }

    #[test]
    fn domain_names_end_in_a_version() {
        for name in [Runner::NAME, SandboxProfile::NAME] {
            let (_, v) = name.rsplit_once('/').unwrap();
            assert!(v.parse::<u32>().is_ok(), "{name}");
        }
    }

    #[test]
    fn a_declared_tz_overrides_the_default_and_is_keyed() {
        let mut c = contract();
        c.allow.push("TZ".into());
        let r = runner_with(&c, &ambient());
        assert_eq!(r.env()["TZ"], "Europe/Oslo");
        assert_ne!(r.key(), runner_with(&contract(), &ambient()).key());
    }
}
