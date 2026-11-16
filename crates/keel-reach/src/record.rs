//! The link record: what the linker shim saw, in the form the loader reads.
//!
//! The shim and the analyser share this file so the two cannot disagree about
//! what `objects` or `libs` mean. Everything here is path arithmetic and JSON;
//! nothing parses object files.

use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

pub const SCHEMA: u32 = 1;
const MAX_RESPONSE_DEPTH: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error(
        "cannot read response file {path}: {source}; the linker was given an @file that no longer exists or is unreadable"
    )]
    ResponseFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "response files nest deeper than {MAX_RESPONSE_DEPTH} levels at {0}; the linker arguments are cyclic or malformed"
    )]
    ResponseDepth(PathBuf),
    #[error(
        "cannot read link record {path}: {source}; rerun the build with -C linker=keel-linker so the record is written"
    )]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("link record {path} is not valid: {source}; delete it and relink")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error(
        "link record {path} has schema {found}, this build understands {SCHEMA}; rebuild with a matching keel-linker"
    )]
    Schema { path: PathBuf, found: u32 },
}

/// `<out>.keel-link.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkInputs {
    pub schema: u32,
    pub cwd: PathBuf,
    /// The `-o` argument, absolute. Not in the schema-1 field list but the
    /// analyser needs to know which executable a record describes.
    #[serde(default)]
    pub output: PathBuf,
    /// Arguments after response-file expansion, lossily UTF-8.
    pub args: Vec<String>,
    pub objects: Vec<PathBuf>,
    pub archives: Vec<PathBuf>,
    pub libs: Vec<String>,
    pub lib_dirs: Vec<PathBuf>,
    /// Parallel to `objects`: where each object can still be read after rustc
    /// deletes the original. An entry equals the original path when preserving
    /// that object failed.
    #[serde(default)]
    pub preserved_objects: Vec<PathBuf>,
    /// blake3 hex of each preserved object at link time, parallel to `objects`. A hard
    /// link shares an inode with the file rustc may rewrite in place on the next
    /// build; the loader refuses an object whose bytes no longer match.
    #[serde(default)]
    pub preserved_hashes: Vec<String>,
    /// File the linker was asked to write its list of inputs to (`-dependency_info` for ld64,
    /// `--dependency-file` for lld and mold). The linker, not a guess at `-l`, says which
    /// libraries it read. Absent when the shim could not ask (GNU ld has no such option).
    #[serde(default)]
    pub dependency_file: Option<PathBuf>,
    /// `ld64` (binary) or `make` (a makefile rule).
    #[serde(default)]
    pub dependency_flavour: String,
    /// blake3 hex of the produced output file, computed by the shim after the real
    /// linker exited 0. This is what binds the record to one binary: a record is
    /// only ever written after a successful link, and [`LinkInputs::verify`] refuses
    /// it beside any other file. `None` for a record from an older shim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_blake3: Option<String>,
    /// Identity of every archive named on the link line, in `archives` order.
    /// Preserved objects are identified by `preserved_hashes` instead, because the
    /// originals are deleted by rustc.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub archive_ids: Vec<InputId>,
    /// Identity of the linker's dependency file, which names every library it read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_id: Option<InputId>,
}

/// What the record knows about one file it depends on: enough to tell, later,
/// whether it is still the file the linker read.
///
/// `size` and `mtime_ns` are a cheap first test (one `stat`). `blake3` is the
/// content hash; when the stat identity has moved the file is re-hashed and may
/// still be the same (a `touch`), when it has not the content is trusted.
/// `blake3` is absent for a file too large to hash on every link (see
/// `HASH_UP_TO`); for those a changed stat identity is final.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputId {
    pub path: PathBuf,
    pub size: u64,
    pub mtime_ns: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
}

/// Files up to this size are content-hashed when the record is written. Above
/// it only the stat identity (size and mtime) is recorded.
///
/// Measured on the backend link line `adapter-ba8e2001e95519d0` (721 archives,
/// 1988 MB, debug, ten cores idle, warm page cache; the
/// `measure_input_identity_on_a_real_link_line` test repeats it): `stat` of all
/// of them 1.3 to 4.8 ms; blake3 of all of them 3.3 to 3.5 s sequentially and
/// 0.43 to 0.49 s in parallel, per link, for several hundred links in a cold
/// build. Archives of at most 1 MiB are 472 of the 721 but only 131 MB, which
/// is about 35 ms in parallel; those get a content hash, the 250 large ones
/// (1.86 GB) do not. The cost of not hashing them: an archive replaced by
/// bytes of the same size with its mtime put back is not noticed here. Cargo
/// replaces rlibs by rename, which changes the mtime, and the loader hashes
/// every archive it opens anyway, so the exposure is a deliberate tamper, not a
/// rebuild. A shared hash cache keyed by (path, size, mtime) would remove the
/// trade; it is the next step if that exposure matters.
pub const HASH_UP_TO: u64 = 1 << 20;

fn mtime_ns(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos() as u64)
}

pub(crate) fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut h = blake3::Hasher::new();
    h.update_reader(fs::File::open(path)?)?;
    Ok(hex(h.finalize().as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl InputId {
    /// Reads the identity of `path` as it is now.
    pub fn of(path: &Path) -> std::io::Result<InputId> {
        let meta = fs::metadata(path)?;
        let size = meta.len();
        Ok(InputId {
            path: path.into(),
            size,
            mtime_ns: mtime_ns(&meta),
            blake3: if size <= HASH_UP_TO {
                Some(hash_file(path)?)
            } else {
                None
            },
        })
    }

    /// `Ok` when the file on disk is still this one.
    fn check(&self) -> Result<(), Stale> {
        let gone = |why: String| Stale::Input {
            path: self.path.clone(),
            why,
        };
        let meta = fs::metadata(&self.path).map_err(|e| {
            gone(format!(
                "cannot be read now ({e}); it was deleted or moved after the link"
            ))
        })?;
        if meta.len() != self.size {
            return Err(gone(format!(
                "is {} bytes now, was {} when linked",
                meta.len(),
                self.size
            )));
        }
        if mtime_ns(&meta) == self.mtime_ns {
            return Ok(());
        }
        match &self.blake3 {
            Some(want) => {
                let got =
                    hash_file(&self.path).map_err(|e| gone(format!("cannot be hashed ({e})")))?;
                if &got == want {
                    Ok(())
                } else {
                    Err(gone(format!("has content {got}, was {want} when linked")))
                }
            }
            None => Err(gone(
                "was modified after the link and was too large to have been hashed".to_owned(),
            )),
        }
    }
}

/// Why a link record cannot be trusted to describe the binary beside it. The
/// first mismatch found; every variant says what to do.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Stale {
    #[error(
        "link record for {output} carries no output hash, so nothing ties it to this binary (it was written by an older keel-linker, or the link failed); relink with the current keel-linker, or use the executable key"
    )]
    Unbound { output: PathBuf },
    #[error(
        "output {path} cannot be read ({why}); the record describes a binary that is no longer there, so relink"
    )]
    OutputMissing { path: PathBuf, why: String },
    #[error(
        "output {path} has content {now} but the record was written for {recorded}: the binary was relinked or rewritten without keel-linker (or something changed it after the link), so the record describes an older binary; relink with keel-linker"
    )]
    OutputChanged {
        path: PathBuf,
        recorded: String,
        now: String,
    },
    #[error(
        "link input {path} {why}; the record describes an older link, so relink with keel-linker"
    )]
    Input { path: PathBuf, why: String },
}

impl LinkInputs {
    /// Checks the record against the disk: the output file is the one the link
    /// produced, and every preserved object, archive and the dependency file
    /// is still what the linker read. Names the first mismatch.
    ///
    /// Cost: one read of the output and of the preserved objects, and one `stat`
    /// per archive (a re-hash only for an archive whose mtime moved).
    pub fn verify(&self) -> Result<(), Stale> {
        let want = self.output_blake3.as_ref().ok_or_else(|| Stale::Unbound {
            output: self.output.clone(),
        })?;
        let now = hash_file(&self.output).map_err(|e| Stale::OutputMissing {
            path: self.output.clone(),
            why: e.to_string(),
        })?;
        if &now != want {
            return Err(Stale::OutputChanged {
                path: self.output.clone(),
                recorded: want.clone(),
                now,
            });
        }
        for (path, want) in self.preserved_objects.iter().zip(&self.preserved_hashes) {
            if want.is_empty() {
                continue;
            }
            let got = hash_file(path).map_err(|e| Stale::Input {
                path: path.clone(),
                why: format!("cannot be read now ({e}); the preserved object is gone"),
            })?;
            if &got != want {
                return Err(Stale::Input {
                    path: path.clone(),
                    why: format!("has content {got}, was {want} when linked"),
                });
            }
        }
        for id in self.archive_ids.iter().chain(&self.dependency_id) {
            id.check()?;
        }
        Ok(())
    }
}

pub fn record_path(out: &Path) -> PathBuf {
    sibling(out, ".keel-link.json")
}

/// Where the linker is asked to write its list of inputs.
pub fn deps_path(out: &Path) -> PathBuf {
    sibling(out, ".keel-deps")
}

pub fn objects_dir(out: &Path) -> PathBuf {
    sibling(out, ".keel-objects")
}

fn sibling(out: &Path, suffix: &str) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

impl LinkInputs {
    pub fn from_record(path: &Path) -> Result<LinkInputs, RecordError> {
        let bytes = fs::read(path).map_err(|source| RecordError::Read {
            path: path.into(),
            source,
        })?;
        let rec: LinkInputs =
            serde_json::from_slice(&bytes).map_err(|source| RecordError::Parse {
                path: path.into(),
                source,
            })?;
        if rec.schema != SCHEMA {
            return Err(RecordError::Schema {
                path: path.into(),
                found: rec.schema,
            });
        }
        Ok(rec)
    }

    /// Classify already-expanded arguments. `cwd` makes every path absolute so
    /// the record means the same thing wherever it is read.
    pub fn from_args(cwd: &Path, args: &[OsString]) -> LinkInputs {
        let abs = |s: &str| -> PathBuf {
            let p = Path::new(s);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                cwd.join(p)
            }
        };
        let strs: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let mut rec = LinkInputs {
            schema: SCHEMA,
            cwd: cwd.into(),
            args: strs.clone(),
            ..Default::default()
        };
        if let Some(o) = find_output(&strs) {
            rec.output = abs(&o);
        }
        let mut i = 0;
        while i < strs.len() {
            let a = strs[i].as_str();
            // `-l foo` and `-L dir` take their value as the next argument.
            let mut value = |prefix: &str| -> Option<String> {
                let rest = a.strip_prefix(prefix)?;
                if rest.is_empty() {
                    i += 1;
                    strs.get(i).cloned()
                } else {
                    Some(rest.to_string())
                }
            };
            if let Some(l) = value("-l") {
                rec.libs.push(l);
            } else if let Some(d) = value("-L") {
                rec.lib_dirs.push(abs(&d));
            } else if let Some(rest) = a.strip_prefix("-Wl,") {
                // ld64's `-force_load <archive>` is how a whole-archive input is spelled
                // when it goes through the compiler driver.
                let parts: Vec<&str> = rest.split(',').collect();
                for w in parts.windows(2) {
                    if w[0] == "-force_load" {
                        rec.archives.push(abs(w[1]));
                    }
                }
            } else if a.ends_with(".rlib") || a.ends_with(".a") {
                rec.archives.push(abs(a));
            } else if a.ends_with(".o") {
                rec.objects.push(abs(a));
            }
            i += 1;
        }
        rec
    }
}

/// The value of the last `-o`. Handles `-o x`, `--output x`, `--output=x`.
pub fn find_output(args: &[String]) -> Option<String> {
    let mut found = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-o" || a == "--output" {
            if let Some(v) = args.get(i + 1) {
                found = Some(v.clone());
            }
            i += 1;
        } else if let Some(v) = a.strip_prefix("--output=") {
            found = Some(v.to_string());
        }
        // The attached form `-oPATH` is not recognised: linker flags such as
        // `-order_file` start with `-o`, and rustc always writes `-o PATH`.
        i += 1;
    }
    found
}

/// Expand `@file` arguments recursively. One argument per line; rustc escapes
/// a backslash or space inside an argument with a backslash, and some drivers
/// wrap the whole argument in double quotes, so both are undone.
pub fn expand_response_files(args: &[OsString], cwd: &Path) -> Result<Vec<OsString>, RecordError> {
    let mut out = Vec::with_capacity(args.len());
    expand_into(args, cwd, 0, &mut out)?;
    Ok(out)
}

fn expand_into(
    args: &[OsString],
    cwd: &Path,
    depth: usize,
    out: &mut Vec<OsString>,
) -> Result<(), RecordError> {
    for a in args {
        let Some(rest) = a
            .to_str()
            .and_then(|s| s.strip_prefix('@'))
            .filter(|r| !r.is_empty())
        else {
            out.push(a.clone());
            continue;
        };
        let p = if Path::new(rest).is_absolute() {
            PathBuf::from(rest)
        } else {
            cwd.join(rest)
        };
        if depth >= MAX_RESPONSE_DEPTH {
            return Err(RecordError::ResponseDepth(p));
        }
        let text = fs::read_to_string(&p).map_err(|source| RecordError::ResponseFile {
            path: p.clone(),
            source,
        })?;
        let inner: Vec<OsString> = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| OsString::from(unescape(l)))
            .collect();
        expand_into(&inner, cwd, depth + 1, out)?;
    }
    Ok(())
}

fn unescape(line: &str) -> String {
    let body = if line.len() >= 2 && line.starts_with('"') && line.ends_with('"') {
        &line[1..line.len() - 1]
    } else {
        line
    };
    let mut s = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(n) => s.push(n),
                None => s.push('\\'),
            }
        } else {
            s.push(c);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    fn scratch(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("keel-reach-record-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// Not a check: the measurement behind `HASH_UP_TO`. Run with
    /// `KEEL_MEASURE_RECORD=<some>.keel-link.json cargo test -p keel-reach
    /// measure_input_identity -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn measure_input_identity_on_a_real_link_line() {
        use rayon::prelude::*;
        let Some(p) = std::env::var_os("KEEL_MEASURE_RECORD") else {
            return;
        };
        let rec = LinkInputs::from_record(Path::new(&p)).unwrap();
        let paths: Vec<_> = rec.archives.iter().filter(|a| a.exists()).collect();
        let t = std::time::Instant::now();
        let bytes: u64 = paths
            .iter()
            .map(|a| fs::metadata(a).map_or(0, |m| m.len()))
            .sum();
        let stat = t.elapsed();
        let t = std::time::Instant::now();
        let seq: Vec<_> = paths.iter().map(|a| hash_file(a).unwrap()).collect();
        let sequential = t.elapsed();
        let t = std::time::Instant::now();
        let par: Vec<_> = paths.par_iter().map(|a| hash_file(a).unwrap()).collect();
        let parallel = t.elapsed();
        assert_eq!(seq, par);
        let t = std::time::Instant::now();
        let ids: Vec<_> = paths.par_iter().map(|a| InputId::of(a).unwrap()).collect();
        let identity = t.elapsed();
        eprintln!(
            "{} archives, {} MB: stat {stat:?}, blake3 sequential {sequential:?}, parallel {parallel:?}, InputId::of (parallel) {identity:?}; {} present",
            rec.archives.len(),
            bytes / 1_000_000,
            ids.len()
        );
    }

    /// Not a check: verifies a record from a real build. `KEEL_VERIFY_RECORD=<x>.keel-link.json`.
    #[test]
    #[ignore]
    fn verify_a_real_record() {
        let Some(p) = std::env::var_os("KEEL_VERIFY_RECORD") else {
            return;
        };
        let rec = LinkInputs::from_record(Path::new(&p)).unwrap();
        eprintln!("verify: {:?}", rec.verify());
        assert_eq!(rec.verify(), Ok(()));
    }

    #[test]
    fn response_files_expand_nested_and_unescape() {
        let d = scratch("rsp");
        fs::write(d.join("inner.rsp"), "-lfoo\n").unwrap();
        fs::write(
            d.join("outer.rsp"),
            "a\\ b.o\n\"quoted arg.o\"\n@inner.rsp\nback\\\\slash\n",
        )
        .unwrap();
        let got = expand_response_files(&os(&["-c", "@outer.rsp", "-x"]), &d).unwrap();
        let got: Vec<_> = got
            .iter()
            .map(|s| s.to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            got,
            ["-c", "a b.o", "quoted arg.o", "-lfoo", "back\\slash", "-x"]
        );
    }

    #[test]
    fn missing_response_file_names_the_path() {
        let d = scratch("missing");
        let e = expand_response_files(&os(&["@nope.rsp"]), &d)
            .unwrap_err()
            .to_string();
        assert!(e.contains("nope.rsp"), "{e}");
    }

    #[test]
    fn cyclic_response_files_stop() {
        let d = scratch("cycle");
        fs::write(d.join("a.rsp"), "@a.rsp\n").unwrap();
        assert!(matches!(
            expand_response_files(&os(&["@a.rsp"]), &d),
            Err(RecordError::ResponseDepth(_))
        ));
    }

    #[test]
    fn output_detection() {
        let s = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            find_output(&s(&["x.o", "-o", "out"])).as_deref(),
            Some("out")
        );
        assert_eq!(find_output(&s(&["--output=out"])).as_deref(), Some("out"));
        assert_eq!(
            find_output(&s(&["-o", "a", "-o", "b"])).as_deref(),
            Some("b")
        );
        assert_eq!(find_output(&s(&["x.o", "-lc"])), None);
    }

    #[test]
    fn classification_makes_paths_absolute() {
        let cwd = Path::new("/w");
        let r = LinkInputs::from_args(
            cwd,
            &os(&[
                "-o",
                "t/out",
                "a.rcgu.o",
                "/abs/libx.rlib",
                "libnative.a",
                "-lfoo",
                "-l",
                "bar",
                "-L/opt/lib",
                "-L",
                "rel",
                "-Wl,-force_load,f.a",
            ]),
        );
        assert_eq!(r.output, Path::new("/w/t/out"));
        assert_eq!(r.objects, [PathBuf::from("/w/a.rcgu.o")]);
        assert_eq!(
            r.archives,
            [
                PathBuf::from("/abs/libx.rlib"),
                "/w/libnative.a".into(),
                "/w/f.a".into()
            ]
        );
        assert_eq!(r.libs, ["foo", "bar"]);
        assert_eq!(r.lib_dirs, [PathBuf::from("/opt/lib"), "/w/rel".into()]);
    }
}
