//! The linker shim's logic, kept in the library so tests can call it.
//!
//! The order of events in one link is fixed, because the record is only worth
//! having if it cannot outlive the binary it describes (design/keys.md §6.1):
//!
//! 1. Any record already beside the output is deleted before anything else. A
//!    link that cannot do that is refused: a missing record is safe, a stale
//!    one is not.
//! 2. The link inputs are classified and the objects rustc will delete are
//!    preserved. Nothing is written to the record path yet.
//! 3. The real linker runs as a *child*, with this process's stdio, so its
//!    stderr is the shim's stderr and its exit code is the shim's.
//! 4. Only if it exited 0 is the record written: with the hash of the file the
//!    linker produced and the identity of every archive it read.
//!
//! Capturing link inputs is best effort by design: a failure in 2 or 4 costs
//! one binary its reach key (it falls back to the executable key) but must
//! never cost the build. A failure in 1 is the one exception.
//!
//! # Chaining to another linker wrapper
//!
//! `KEEL_REAL_LINKER` names the program that does the link. It may be a
//! script: the backend's own `.cargo/config.toml` sets
//! `linker = ".config/scripts/cargo-umask-linker.sh"` for every target, and
//! the fork passes the shim as the linker, so it must set
//! `KEEL_REAL_LINKER` to what that key held (an absolute path; a relative one
//! is resolved against the directory cargo runs the linker in). The shim
//! spawns it like any program, with the original, unexpanded arguments, so a
//! wrapper that ends in `exec cc "$@"` sees what `cc` would have. Unset, the
//! shim falls back to the platform's compiler driver, which *skips* such a
//! wrapper: set the variable whenever a wrapper is configured.

use crate::record::{
    InputId, LinkInputs, deps_path, expand_response_files, find_output, objects_dir, record_path,
};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rayon::prelude::*;

/// What the shim learns from its environment once per invocation.
pub struct Env {
    /// The program that really links.
    pub linker: OsString,
    /// `KEEL_DEPENDENCY_FLAVOUR`: `none`, `make` or `ld64`; unset means "by platform".
    pub flavour: Option<String>,
}

impl Env {
    /// Reads `KEEL_REAL_LINKER` and `KEEL_DEPENDENCY_FLAVOUR`.
    pub fn from_process(args: &[OsString]) -> Env {
        Env {
            linker: real_linker(args),
            flavour: std::env::var("KEEL_DEPENDENCY_FLAVOUR").ok(),
        }
    }
}

/// `KEEL_REAL_LINKER`, else the platform's compiler driver. On macOS the
/// `cc` on PATH may be a wrapper that rewrites arguments, so the system one is
/// named explicitly.
pub fn real_linker(args: &[OsString]) -> OsString {
    if let Some(l) = std::env::var_os("KEEL_REAL_LINKER").filter(|l| !l.is_empty()) {
        return l;
    }
    // rustc picks the linker flavour from the linker's file name, and a name ending
    // in `-ld` is taken to be a bare `ld`; this shim is called `keel-linker` so that
    // it gets the target's compiler-driver default and the cc-style arguments below.
    // If a caller renames the binary or forces `-C linker-flavor=ld`, the arguments
    // are ld-style, which a compiler driver would reject, so forward those to ld.
    let ld_style = args.iter().filter_map(|a| a.to_str()).any(|a| {
        matches!(
            a,
            "-platform_version" | "-syslibroot" | "--eh-frame-hdr" | "-dynamic-linker"
        )
    });
    match (ld_style, cfg!(target_os = "macos")) {
        (true, true) => "/usr/bin/ld".into(),
        (true, false) => "ld".into(),
        (false, true) => "/usr/bin/cc".into(),
        (false, false) => "cc".into(),
    }
}

/// A link whose record is not yet written: the inputs are classified and the
/// objects preserved, and the real linker has not run. The record becomes
/// visible only through [`Pending::finish`], which is called after it exited 0.
pub struct Pending {
    rec: LinkInputs,
    out: PathBuf,
    extra_args: Vec<OsString>,
}

impl Pending {
    /// Arguments to add to the real linker's command line so that it writes the
    /// list of files it read.
    pub fn extra_args(&self) -> &[OsString] {
        &self.extra_args
    }

    /// The output this link produces, absolute.
    pub fn output(&self) -> &Path {
        &self.out
    }

    /// Writes the record, now that the linker has exited 0 and produced the
    /// output: the hash of that file, and the identity of every archive and of
    /// the linker's dependency file. Nothing is written when any of them cannot
    /// be read, because a record that cannot vouch for its inputs is worse than
    /// none.
    pub fn finish(mut self) -> Result<PathBuf, String> {
        let out = self.out.clone();
        self.rec.output_blake3 = Some(
            crate::record::hash_file(&out).map_err(|e| {
                format!(
                    "cannot hash the linked output {}: {e}; the linker exited 0 but left nothing readable there",
                    out.display()
                )
            })?,
        );
        self.rec.archive_ids = self
            .rec
            .archives
            .par_iter()
            .map(|a| {
                InputId::of(a).map_err(|e| {
                    format!(
                        "cannot read archive {} named on the link line: {e}; it is not where the linker found it",
                        a.display()
                    )
                })
            })
            .collect::<Result<_, _>>()?;
        if let Some(dep) = &self.rec.dependency_file {
            // ld64 writes it on a successful link; its absence means this linker
            // ignored the request, which the loader handles by guessing `-l`.
            self.rec.dependency_id = InputId::of(dep).ok();
        }
        let path = record_path(&out);
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(&self.rec).map_err(|e| e.to_string())?;
        fs::write(&tmp, json)
            .and_then(|()| fs::rename(&tmp, &path))
            .map_err(|e| {
                let _ = fs::remove_file(&tmp);
                format!(
                    "cannot write {}: {e}; check permissions next to the output",
                    path.display()
                )
            })?;
        Ok(out)
    }

    /// The link failed: leave nothing of it behind.
    pub fn abandon(self) {
        let _ = fs::remove_dir_all(objects_dir(&self.out));
        let _ = fs::remove_file(deps_path(&self.out));
    }
}

/// Classifies one linker invocation and preserves its objects; `Ok(None)` means
/// the call was not a link (no `-o` and no inputs, e.g. a version probe).
/// Warnings are failures to preserve single objects: the link is still recorded.
///
/// This does not touch the record path. The old record is deleted by [`run`]
/// before this is called, and the new one is written by [`Pending::finish`].
pub fn prepare(
    args: &[OsString],
    cwd: &Path,
    env: &Env,
    warnings: &mut Vec<String>,
) -> Result<Option<Pending>, (Option<PathBuf>, String)> {
    let expanded = expand_response_files(args, cwd).map_err(|e| (None, e.to_string()))?;
    let mut rec = LinkInputs::from_args(cwd, &expanded);
    if rec.output.as_os_str().is_empty() {
        if rec.objects.is_empty() && rec.archives.is_empty() {
            return Ok(None);
        }
        return Err((
            None,
            "the arguments name inputs but no -o output, so there is nowhere to write the record"
                .into(),
        ));
    }
    let out = rec.output.clone();
    let dir = objects_dir(&out);
    // A stale directory from an earlier link of the same output would leak old
    // objects into the new record's neighbourhood.
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| {
            (
                Some(out.clone()),
                format!("cannot clear {}: {e}; remove it by hand", dir.display()),
            )
        })?;
    }
    if !rec.objects.is_empty() {
        fs::create_dir_all(&dir).map_err(|e| {
            (
                Some(out.clone()),
                format!(
                    "cannot create {}: {e}; check permissions next to the output",
                    dir.display()
                ),
            )
        })?;
    }
    for (i, obj) in rec.objects.iter().enumerate() {
        let name = obj
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("object-{i}.o"));
        let mut dst = dir.join(&name);
        if dst.exists() {
            dst = dir.join(format!("{i:04}-{name}"));
        }
        let kept = fs::hard_link(obj, &dst).or_else(|_| fs::copy(obj, &dst).map(|_| ()));
        match kept {
            Ok(()) => {
                rec.preserved_hashes.push(
                    fs::read(&dst)
                        .map(|b| crate::load::hex(blake3::hash(&b).as_bytes()))
                        .unwrap_or_default(),
                );
                rec.preserved_objects.push(dst);
            }
            Err(e) => {
                warnings.push(format!(
                    "cannot preserve {} for {}: {e}",
                    obj.display(),
                    out.display()
                ));
                rec.preserved_hashes.push(String::new());
                rec.preserved_objects.push(obj.clone());
            }
        }
    }
    let dep = deps_path(&out);
    let mut extra_args = Vec::new();
    if let Some((extra, flavour)) = dependency_args_with(env, &dep) {
        // A stale file from the last link must not be read as this link's.
        let _ = fs::remove_file(&dep);
        rec.dependency_file = Some(dep);
        rec.dependency_flavour = flavour.into();
        extra_args = extra;
    }
    Ok(Some(Pending {
        rec,
        out,
        extra_args,
    }))
}

/// Deletes the record beside `out`. A missing record is fine; one that cannot
/// be removed is an error.
fn remove_stale_record(out: &Path) -> Result<(), String> {
    let path = record_path(out);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "cannot delete the old link record {}: {e}; the link is refused because a stale record would describe the wrong binary. Remove it by hand or fix the permissions next to the output",
            path.display()
        )),
    }
}

/// The absolute `-o` of a link line, if it has one.
fn output_of(args: &[OsString], cwd: &Path) -> Option<PathBuf> {
    let expanded = expand_response_files(args, cwd).ok()?;
    let out = find_output(
        &expanded
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
    )?;
    let p = Path::new(&out);
    Some(if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    })
}

/// Entry point of the `keel-linker` binary.
pub fn run(args: Vec<OsString>) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_default();
    let env = Env::from_process(&args);
    run_with(args, &cwd, &env)
}

/// [`run`] with the environment made explicit, so tests do not share process state.
pub fn run_with(mut args: Vec<OsString>, cwd: &Path, env: &Env) -> i32 {
    // 1. Whatever record sits beside the output describes an older link.
    if let Some(out) = output_of(&args, cwd)
        && let Err(why) = remove_stale_record(&out)
    {
        eprintln!("keel-linker: {why}");
        return 1;
    }
    // 2. Classify, preserve; nothing is published yet.
    let mut warnings = Vec::new();
    let pending = match prepare(&args, cwd, env, &mut warnings) {
        Ok(p) => p,
        Err((out, why)) => {
            let out = out.map_or_else(
                || "<unknown output>".to_string(),
                |p| p.display().to_string(),
            );
            eprintln!(
                "keel-linker: could not record link inputs for {out}: {why}; the link continues and this binary's tests fall back to the executable key"
            );
            None
        }
    };
    for w in warnings {
        eprintln!(
            "keel-linker: {w}; if the object is deleted before analysis this binary's tests fall back to the executable key"
        );
    }
    // Ask the linker which files it read, so the analyser need not guess what `-l` named.
    if let Some(p) = &pending {
        args.extend(p.extra_args().iter().cloned());
    }
    // 3. The real linker, as a child with our stdio.
    let code = match link(&args, cwd, env) {
        Ok(code) => code,
        Err(code) => {
            if let Some(p) = pending {
                p.abandon();
            }
            return code;
        }
    };
    // 4. Only a link that succeeded gets a record.
    if let Some(p) = pending {
        if code == 0 {
            let out = p.output().to_owned();
            if let Err(why) = p.finish() {
                eprintln!(
                    "keel-linker: could not record link inputs for {}: {why}; the link succeeded and this binary's tests fall back to the executable key",
                    out.display()
                );
            }
        } else {
            p.abandon();
        }
    }
    code
}

/// How to ask the linker for the list of files it read, as extra arguments, and the
/// flavour of file it writes. `None` where the linker has no such option.
pub fn dependency_args(args: &[OsString], file: &Path) -> Option<(Vec<OsString>, &'static str)> {
    dependency_args_with(&Env::from_process(args), file)
}

fn dependency_args_with(env: &Env, file: &Path) -> Option<(Vec<OsString>, &'static str)> {
    let driver = !linker_is_bare_ld(&env.linker);
    let f = file.as_os_str();
    let join = |pre: &str| -> OsString {
        let mut s = OsString::from(pre);
        s.push(f);
        s
    };
    match env.flavour.as_deref() {
        Some("none") => None,
        Some("make") => Some((
            vec![if driver {
                join("-Wl,--dependency-file=")
            } else {
                join("--dependency-file=")
            }],
            "make",
        )),
        Some("ld64") => Some((ld64_args(driver, f), "ld64")),
        _ if cfg!(target_os = "macos") => Some((ld64_args(driver, f), "ld64")),
        _ => None,
    }
}

fn ld64_args(driver: bool, f: &std::ffi::OsStr) -> Vec<OsString> {
    if driver {
        let mut s = OsString::from("-Wl,-dependency_info,");
        s.push(f);
        vec![s]
    } else {
        vec!["-dependency_info".into(), f.into()]
    }
}

fn linker_is_bare_ld(linker: &OsString) -> bool {
    let name = Path::new(linker)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name == "ld" || name.ends_with("-ld") || name == "ld.lld" || name == "mold"
}

/// Runs the real linker to completion and returns its exit code. `Err` carries
/// the code to exit with when it could not be started at all.
fn link(args: &[OsString], cwd: &Path, env: &Env) -> Result<i32, i32> {
    let mut cmd = Command::new(&env.linker);
    cmd.args(args);
    // The directory the arguments were resolved against; it is the process's own
    // unless a test says otherwise, and an unknown one (empty) is left alone.
    if !cwd.as_os_str().is_empty() {
        cmd.current_dir(cwd);
    }
    match cmd.status() {
        Ok(s) => Ok(exit_code(&s)),
        Err(e) => {
            eprintln!(
                "keel-linker: cannot execute the real linker {}: {e}; set KEEL_REAL_LINKER to a working compiler driver",
                env.linker.to_string_lossy()
            );
            Err(127)
        }
    }
}

/// The child's exit code; a death by signal becomes the shell's `128 + signal`,
/// which rustc reads as failure just as it read the signal when the shim
/// replaced itself with the linker.
fn exit_code(s: &std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = s.signal() {
            return 128 + sig;
        }
    }
    s.code().unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Stale;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("keel-reach-shim-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    #[cfg(unix)]
    fn script(path: &Path, body: &str) -> OsString {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        path.into()
    }

    /// A linker that writes `linked` to its `-o` argument.
    #[cfg(unix)]
    const FAKE_LD: &str = r#"out=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; esac; shift; done; printf linked > "$out""#;

    fn env_with(linker: OsString) -> Env {
        Env {
            linker,
            flavour: Some("none".into()),
        }
    }

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[cfg(unix)]
    fn linked(name: &str) -> (PathBuf, Env, Vec<OsString>) {
        let d = scratch(name);
        fs::write(d.join("a.rcgu.o"), b"obj").unwrap();
        fs::write(d.join("libx.rlib"), b"archive").unwrap();
        let env = env_with(script(&d.join("fake-ld"), FAKE_LD));
        let a = args(&["a.rcgu.o", "libx.rlib", "-o", "out"]);
        (d, env, a)
    }

    #[cfg(unix)]
    #[test]
    fn the_record_is_written_after_the_link_and_binds_the_output_and_inputs() {
        let (d, env, a) = linked("bind");
        assert_eq!(run_with(a, &d, &env), 0);
        let rec = LinkInputs::from_record(&record_path(&d.join("out"))).unwrap();
        assert_eq!(
            rec.output_blake3.as_deref(),
            Some(crate::load::hex(blake3::hash(b"linked").as_bytes()).as_str())
        );
        assert_eq!(rec.archive_ids.len(), 1);
        assert_eq!(rec.archive_ids[0].size, 7);
        assert!(rec.archive_ids[0].blake3.is_some());
        assert_eq!(rec.verify(), Ok(()));

        // A later link without the shim leaves a new binary beside the old record.
        fs::write(d.join("out"), b"relinked elsewhere").unwrap();
        match rec.verify() {
            Err(Stale::OutputChanged { path, .. }) => assert_eq!(path, d.join("out")),
            other => panic!("{other:?}"),
        }
        fs::write(d.join("out"), b"linked").unwrap();
        assert_eq!(rec.verify(), Ok(()));
        fs::remove_file(d.join("out")).unwrap();
        assert!(matches!(rec.verify(), Err(Stale::OutputMissing { .. })));
        fs::write(d.join("out"), b"linked").unwrap();

        // An archive that changed since: named, by path.
        fs::write(d.join("libx.rlib"), b"archive, edited").unwrap();
        match rec.verify() {
            Err(Stale::Input { path, why }) => {
                assert_eq!(path, d.join("libx.rlib"));
                assert!(why.contains("bytes"), "{why}");
            }
            other => panic!("{other:?}"),
        }
        // Same size, different bytes (and a new mtime): caught by the content hash.
        fs::write(d.join("libx.rlib"), b"ARCHIVE").unwrap();
        assert!(matches!(rec.verify(), Err(Stale::Input { why, .. }) if why.contains("content")),);
        // Same bytes rewritten: only the mtime moved, which is not a change.
        fs::write(d.join("libx.rlib"), b"archive").unwrap();
        assert_eq!(rec.verify(), Ok(()));
        // A preserved object that no longer matches what was linked.
        fs::write(&rec.preserved_objects[0], b"tampered").unwrap();
        assert!(matches!(rec.verify(), Err(Stale::Input { .. })));
    }

    #[test]
    fn a_record_without_an_output_hash_is_unbound() {
        let rec = LinkInputs {
            output: PathBuf::from("/nowhere/out"),
            ..LinkInputs::default()
        };
        assert!(matches!(rec.verify(), Err(Stale::Unbound { .. })));
        assert!(
            rec.verify()
                .unwrap_err()
                .to_string()
                .contains("/nowhere/out")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_link_leaves_no_record_and_removes_the_old_one() {
        let (d, _, a) = linked("failed");
        let ok = env_with(script(&d.join("ok-ld"), FAKE_LD));
        assert_eq!(run_with(a.clone(), &d, &ok), 0);
        assert!(record_path(&d.join("out")).exists());
        let bad = env_with(script(&d.join("bad-ld"), "exit 3"));
        assert_eq!(
            run_with(a, &d, &bad),
            3,
            "the linker's exit code is the shim's"
        );
        assert!(
            !record_path(&d.join("out")).exists(),
            "the record of the earlier, successful link must not survive a failed one"
        );
        assert!(!objects_dir(&d.join("out")).exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_killed_by_a_signal_is_a_failure_with_the_shells_code() {
        let (d, _, a) = linked("signal");
        let env = env_with(script(&d.join("kill-ld"), "kill -9 $$"));
        assert_eq!(run_with(a, &d, &env), 137);
        assert!(!record_path(&d.join("out")).exists());
    }

    #[test]
    fn the_old_record_is_deleted_before_the_linker_is_even_started() {
        let d = scratch("first");
        fs::write(record_path(&d.join("out")), b"{}").unwrap();
        let env = env_with(d.join("no-such-linker").into());
        assert_eq!(run_with(args(&["a.o", "-o", "out"]), &d, &env), 127);
        assert!(!record_path(&d.join("out")).exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_record_that_cannot_be_deleted_refuses_the_link() {
        let d = scratch("refuse");
        // A non-empty directory where the record should be: remove_file fails on it.
        let rec = record_path(&d.join("out"));
        fs::create_dir_all(&rec).unwrap();
        fs::write(rec.join("x"), b"x").unwrap();
        let marker = d.join("linker-ran");
        let env = env_with(script(
            &d.join("ld"),
            &format!("touch {}", marker.display()),
        ));
        assert_ne!(run_with(args(&["a.o", "-o", "out"]), &d, &env), 0);
        assert!(
            !marker.exists(),
            "the linker must not run when a stale record cannot go"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_preexisting_linker_wrapper_script_is_chained_with_the_original_arguments() {
        // The shape of the backend's .config/scripts/cargo-umask-linker.sh:
        // a wrapper that adjusts the umask and then execs the compiler driver.
        let (d, _, _) = linked("chain");
        let log = d.join("wrapper.log");
        let fake = d.join("fake-ld");
        let wrapper = script(
            &d.join("cargo-umask-linker.sh"),
            &format!(
                "umask 0022; printf '%s|' \"$@\" > {}; exec {} \"$@\"",
                log.display(),
                fake.display()
            ),
        );
        let env = env_with(wrapper);
        let line = ["a.rcgu.o", "libx.rlib", "-o", "out", "-lm"];
        assert_eq!(run_with(args(&line), &d, &env), 0);
        assert_eq!(
            fs::read_to_string(&log).unwrap(),
            "a.rcgu.o|libx.rlib|-o|out|-lm|",
            "the wrapper sees the original arguments, in order, and nothing extra"
        );
        let rec = LinkInputs::from_record(&record_path(&d.join("out"))).unwrap();
        assert_eq!(rec.verify(), Ok(()));
        // And the wrapper's own exit status is the shim's.
        let failing = env_with(script(&d.join("w2.sh"), "exec /usr/bin/false"));
        assert_eq!(run_with(args(&line), &d, &failing), 1);
    }

    #[test]
    fn large_archives_are_identified_by_stat_alone_and_small_ones_by_content() {
        let d = scratch("ids");
        let small = d.join("small.rlib");
        let big = d.join("big.rlib");
        fs::write(&small, b"small").unwrap();
        fs::write(&big, vec![7u8; crate::record::HASH_UP_TO as usize + 1]).unwrap();
        let (a, b) = (InputId::of(&small).unwrap(), InputId::of(&big).unwrap());
        assert!(a.blake3.is_some() && b.blake3.is_none());
        let rec = |ids: Vec<InputId>| LinkInputs {
            output: d.join("out"),
            output_blake3: Some(crate::load::hex(blake3::hash(b"o").as_bytes())),
            archive_ids: ids,
            ..LinkInputs::default()
        };
        fs::write(d.join("out"), b"o").unwrap();
        let r = rec(vec![a, b]);
        assert_eq!(r.verify(), Ok(()));
        // Same size, new mtime: the small one is re-hashed and found unchanged; the
        // large one cannot be, so a moved mtime is a change.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(&small, b"small").unwrap();
        assert_eq!(r.verify(), Ok(()));
        fs::write(&big, vec![7u8; crate::record::HASH_UP_TO as usize + 1]).unwrap();
        match r.verify() {
            Err(Stale::Input { path, why }) => {
                assert_eq!(path, big);
                assert!(why.contains("too large"), "{why}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_version_probe_is_not_a_link() {
        let mut w = Vec::new();
        let env = env_with("true".into());
        assert!(
            prepare(&["--version".into()], Path::new("/"), &env, &mut w)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn preserved_objects_outlive_the_originals() {
        let (d, env, a) = linked("preserve");
        assert_eq!(run_with(a, &d, &env), 0);
        let rec = LinkInputs::from_record(&record_path(&d.join("out"))).unwrap();
        assert_eq!(rec.objects, [d.join("a.rcgu.o")]);
        assert!(rec.preserved_objects[0].starts_with(objects_dir(&d.join("out"))));
        fs::remove_file(d.join("a.rcgu.o")).unwrap();
        assert_eq!(fs::read(&rec.preserved_objects[0]).unwrap(), b"obj");
        assert_eq!(rec.verify(), Ok(()));
    }
}
