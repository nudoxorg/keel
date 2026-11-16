//! `boundaries`: every place the product meets code or state it does not control, per
//! owning node, each with `file:line`. A test plan needs this before it can say how each
//! boundary is checked.
//!
//! Syntax is read with ast-grep patterns (Rust source) and structure with `cargo metadata`
//! (links keys, build scripts, `-sys` crates) and the tracked file list (native sources).
//! The census is a lower bound: a pattern sees only the spellings it names, so a
//! boundary reached through a wrapper function, a macro expansion or a re-exported path is
//! not counted, and a name that merely looks like one is. Each class says which of the two
//! it is prone to in `CLASSES`.

use crate::pattern::{self, Compiled, Match, Parsed};
use crate::resolve::{Owner, Resolution};
use crate::text::{num, table};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

pub struct Options {
    pub include_tests: bool,
}

/// One class of boundary: what it is, and how a pattern census of it can be wrong.
pub struct Class {
    pub id: &'static str,
    pub group: &'static str,
    pub what: &'static str,
    /// False positives and false negatives of the pattern, in words.
    pub risk: &'static str,
}

pub const CLASSES: &[Class] = &[
    Class { id: "ffi-extern-block", group: "ffi", what: "`extern \"C\"` / `unsafe extern` blocks of foreign declarations", risk: "FN: none known for written blocks; blocks produced by macros are not seen. FP: none." },
    Class { id: "ffi-extern-fn", group: "ffi", what: "functions with an `extern` ABI (`extern \"C\" fn`, `extern \"system\" fn`)", risk: "FN: functions declared inside macros. FP: a function whose text before `fn` merely contains the word extern (a visibility path or comment on the same line)." },
    Class { id: "ffi-no-mangle", group: "ffi", what: "`#[no_mangle]`, `#[unsafe(no_mangle)]`, `#[export_name]`: symbols other code links against", risk: "FN: attributes applied by a macro. FP: an attribute that only mentions the word in an argument." },
    Class { id: "ffi-link-attr", group: "ffi", what: "`#[link(..)]`, `#[link_name]`, `#[link_section]`: native libraries and symbols named in source", risk: "FN: libraries linked by build.rs (`cargo:rustc-link-lib`) are only seen through native-build-script. FP: none." },
    Class { id: "ffi-dynamic-load", group: "ffi", what: "loading code at run time: `libloading::Library::new`, `dlopen`, `dlsym`", risk: "FN: a Library imported under another name, or opened through a wrapper. FP: `Library::new` in a file that mentions libloading but means another type." },
    Class { id: "native-links-key", group: "native", what: "packages whose manifest has a `links` key (they own a native library by name)", risk: "From cargo metadata: exact for workspace members. FN: dependencies outside the workspace." },
    Class { id: "native-build-script", group: "native", what: "packages with a build script (anything it does happens outside the compiler's view)", risk: "From cargo metadata: exact for workspace members." },
    Class { id: "native-build-tool", group: "native", what: "build scripts that use cc, cmake, bindgen, pkg_config, cxx_build, autocfg or vcpkg", risk: "One site per tool per build script (first use). FN: a tool driven by a script that shells out. FP: a tool named only in a comment string." },
    Class { id: "native-sys-member", group: "native", what: "workspace members named `*-sys`", risk: "Naming convention: FN for bindings crates not named -sys; FP for a -sys crate with no native code." },
    Class { id: "native-sys-dependency", group: "native", what: "direct dependencies of workspace members named `*-sys`", risk: "Naming convention, direct dependencies only: native code reached through a non-sys crate or a transitive -sys crate is not counted." },
    Class { id: "native-source", group: "native", what: "C, C++, Objective-C and assembly files tracked inside package directories (one site per file)", risk: "By extension. FN: native sources outside every package directory, or generated at build time. FP: headers or samples kept as data." },
    Class { id: "process-spawn", group: "process", what: "starting other programs: `std::process::Command::new`, `tokio::process::Command::new`", risk: "FN: a Command built through a wrapper or alias. FP: bare `Command::new` in a file that mentions process::Command but uses another Command (clap's) too." },
    Class { id: "process-current-exe", group: "process", what: "`env::current_exe()`: the product locating or re-running itself", risk: "FN: through a wrapper. FP: none." },
    Class { id: "net-listen", group: "network", what: "listeners and servers: `TcpListener::bind`, `UnixListener::bind`, `UdpSocket::bind`, hyper `Server::bind`", risk: "FN: axum/tonic servers started from an already-bound listener, `serve()` helpers. FP: an unrelated `Server::bind`." },
    Class { id: "net-connect", group: "network", what: "clients: `TcpStream::connect`, `UnixStream::connect`, `reqwest::` and `ureq::` calls", risk: "FN: clients behind wrapper functions or other HTTP crates. FP: `reqwest::` / `ureq::` calls that only configure a client (`Agent::config_builder`, `Client::builder`) and so are counted though nothing connects until the request is sent; Uri, Url, Proxy and Error names are filtered out." },
    Class { id: "fs-env-path", group: "filesystem", what: "reads of environment variables whose literal name looks like a path (PATH, DIR, HOME, ROOT, TMP, TEMP, FILE, CACHE, XDG, SOCK)", risk: "FN: variable names held in constants or built at run time; names not containing those words. FP: a name containing PATH that is not a location." },
    Class { id: "fs-dirs", group: "filesystem", what: "`dirs::` / `directories::` calls (`ProjectDirs::from`, `BaseDirs::new`, `UserDirs::new`)", risk: "FN: dirs_next and hand-rolled lookups through HOME. FP: none." },
    Class { id: "fs-tempfile", group: "filesystem", what: "`tempfile::` calls, `TempDir::new`, `NamedTempFile::new`, `env::temp_dir`", risk: "FN: temp paths built by hand under /tmp. FP: a function of your own named `tempdir`." },
    Class { id: "nondet-time", group: "nondeterminism", what: "clock reads: `SystemTime::now`, `Instant::now`, `Utc::now`, `Local::now`", risk: "FN: clocks read through a trait or a wrapper. FP: none, but most are benign timing." },
    Class { id: "nondet-random", group: "nondeterminism", what: "randomness: `thread_rng`, `OsRng`, `rand::random`, `getrandom`, `Uuid::new_v4`", risk: "FN: `rand::rng()` aliases and seeded generators built elsewhere. FP: a seeded `OsRng`-named type of your own." },
    Class { id: "compile-include", group: "compile-time", what: "`include_str!`, `include_bytes!`, `include!`: files read at compile time", risk: "FN: macros that expand to includes. FP: inside a macro_rules body that is never expanded." },
    Class { id: "compile-env", group: "compile-time", what: "`env!`, `option_env!`: build-environment values baked into the binary", risk: "FN: through macros. FP: inside a macro_rules body." },
];

/// Said in the help and the report: what is deliberately not counted.
pub const SKIPPED: &[&str] = &[
    "`CStr` / `CString` crossing sites: they appear at nearly every FFI call and on pure string handling alike, so the count would measure string code, not boundaries; the extern declarations they cross are counted instead.",
    "Only Rust source is read for syntax boundaries. C, C++ and other languages are counted as files (native-source), not as the calls they make.",
    "Calls through a wrapper, macro expansions and generated code are invisible to a pattern census. Every number here is a lower bound.",
];

#[derive(Serialize, Clone)]
pub struct Site {
    pub class: &'static str,
    pub path: String,
    pub line: u32,
    /// The owning node, `unowned`, `inert` or `conflict`.
    pub node: String,
    /// In `#[cfg(test)]` / `#[test]` code or under a tests, benches or fixtures directory.
    pub test: bool,
    pub text: String,
}

#[derive(Serialize)]
pub struct Report {
    pub root: String,
    pub include_tests: bool,
    /// Sites in test code that this report leaves out (zero when `include_tests`).
    pub test_sites_hidden: usize,
    pub sites: Vec<Site>,
    pub rust_files: usize,
    pub rust_files_parsed: usize,
    pub rust_files_with_syntax_errors: usize,
    pub skipped_files: Vec<pattern::Skipped>,
    pub packages: usize,
    pub notes: Vec<String>,
    pub millis: u128,
}

type Keep = fn(&Match, &str) -> bool;

enum How {
    Pat(Compiled),
    Kind(&'static str),
}

struct Rule {
    class: &'static str,
    how: How,
    keep: Option<Keep>,
    /// The file is parsed for this rule only if it holds every text of one of these lists. Empty: always.
    triggers: Vec<Vec<String>>,
}

fn pat(class: &'static str, pattern: &str, keep: Option<Keep>) -> Rule {
    let c = pattern::compile("rust", pattern).unwrap_or_else(|e| panic!("builtin boundary pattern `{pattern}`: {e}"));
    let triggers = c.prefilter().to_vec();
    Rule { class, how: How::Pat(c), keep, triggers }
}

fn kind(class: &'static str, kind: &'static str, triggers: &[&str], keep: Keep) -> Rule {
    Rule { class, how: How::Kind(kind), keep: Some(keep), triggers: triggers.iter().map(|s| vec![(*s).to_owned()]).collect() }
}

/// `name` bare and under each path prefix, because a pattern matches a spelling.
fn spellings(class: &'static str, names: &[&str], prefixes: &[&str], keep: Option<Keep>) -> Vec<Rule> {
    let mut out = Vec::new();
    for n in names {
        out.push(pat(class, n, keep));
        for p in prefixes {
            out.push(pat(class, &format!("{p}{n}"), keep));
        }
    }
    out
}

fn path_like_env(m: &Match, _: &str) -> bool {
    let h = m.head.to_ascii_uppercase();
    let Some(open) = h.find('"') else { return false };
    let name = &h[open + 1..];
    ["PATH", "DIR", "HOME", "ROOT", "TMP", "TEMP", "FILE", "CACHE", "XDG", "SOCK"].iter().any(|w| name.split('"').next().unwrap_or("").contains(w))
}

fn bare_command(_: &Match, src: &str) -> bool {
    src.contains("process::Command") || (src.contains("process::{") && src.contains("Command"))
}

fn libloading_file(_: &Match, src: &str) -> bool {
    src.contains("libloading")
}

fn rules() -> Vec<Rule> {
    let mut r = vec![
        kind("ffi-extern-block", "foreign_mod_item", &["extern \"", "extern {"], |_, _| true),
        kind("ffi-extern-fn", "function_item", &["extern \"", "extern fn"], |m, _| m.head.split("fn ").next().unwrap_or("").contains("extern")),
        kind("ffi-no-mangle", "attribute_item", &["no_mangle", "export_name"], |m, _| m.head.contains("no_mangle") || m.head.contains("export_name")),
        kind("ffi-link-attr", "attribute_item", &["#[link"], |m, _| ["#[link(", "#[link_name", "#[link_section"].iter().any(|p| m.head.starts_with(p))),
        kind("ffi-link-attr", "inner_attribute_item", &["#![link"], |m, _| m.head.starts_with("#![link(")),
        kind("net-connect", "call_expression", &["reqwest", "ureq"], |m, _| {
            // Naming a type of the crate is not a connection: parsing a Uri or reading a proxy from the environment is not one.
            (m.head.starts_with("reqwest::") || m.head.starts_with("ureq::"))
                && !["::http::", "Uri", "Url", "Proxy", "StatusCode", "Error", "header::", "HeaderValue"].iter().any(|n| m.head.contains(n))
        }),
        kind("fs-dirs", "call_expression", &["dirs", "directories", "ProjectDirs", "BaseDirs", "UserDirs"], |m, _| {
            ["dirs::", "dirs_next::", "directories::", "ProjectDirs::from", "BaseDirs::new", "UserDirs::new"].iter().any(|p| m.head.starts_with(p))
        }),
        kind("fs-tempfile", "call_expression", &["tempfile", "TempDir", "NamedTempFile", "tempdir", "temp_dir"], |m, _| {
            ["tempfile::", "TempDir::new", "NamedTempFile::new", "tempdir(", "env::temp_dir(", "std::env::temp_dir("].iter().any(|p| m.head.starts_with(p))
        }),
    ];
    r.extend(spellings("ffi-dynamic-load", &["Library::new($$$A)"], &["libloading::"], Some(libloading_file)));
    for p in ["dlopen($$$A)", "dlsym($$$A)", "libc::dlopen($$$A)", "libc::dlsym($$$A)"] {
        r.push(pat("ffi-dynamic-load", p, None));
    }
    for p in ["std::process::Command::new($$$A)", "tokio::process::Command::new($$$A)", "async_process::Command::new($$$A)"] {
        r.push(pat("process-spawn", p, None));
    }
    r.push(pat("process-spawn", "Command::new($$$A)", Some(bare_command)));
    r.push(pat("process-spawn", "process::Command::new($$$A)", None));
    for p in ["std::env::current_exe()", "env::current_exe()", "current_exe()"] {
        r.push(pat("process-current-exe", p, None));
    }
    r.extend(spellings("net-listen", &["TcpListener::bind($$$A)", "UnixListener::bind($$$A)", "UdpSocket::bind($$$A)"], &["std::net::", "tokio::net::", "std::os::unix::net::", "tokio::net::unix::"], None));
    r.extend(spellings("net-listen", &["Server::bind($$$A)"], &["hyper::"], None));
    r.extend(spellings("net-connect", &["TcpStream::connect($$$A)", "UnixStream::connect($$$A)"], &["std::net::", "tokio::net::", "std::os::unix::net::"], None));
    for p in ["std::env::var($A)", "env::var($A)", "std::env::var_os($A)", "env::var_os($A)"] {
        r.push(pat("fs-env-path", p, Some(path_like_env)));
    }
    r.extend(spellings("nondet-time", &["SystemTime::now()", "Instant::now()"], &["std::time::", "tokio::time::"], None));
    r.extend(spellings("nondet-time", &["Utc::now()", "Local::now()"], &["chrono::"], None));
    for p in [
        "rand::thread_rng()", "thread_rng()", "rand::rng()", "OsRng", "rand::random()", "rand::random::<$T>()", "getrandom::getrandom($$$A)",
        "Uuid::new_v4()", "uuid::Uuid::new_v4()",
    ] {
        r.push(pat("nondet-random", p, None));
    }
    for p in ["include_str!($$$A)", "include_bytes!($$$A)", "include!($$$A)"] {
        r.push(pat("compile-include", p, None));
    }
    for p in ["env!($$$A)", "option_env!($$$A)"] {
        r.push(pat("compile-env", p, None));
    }
    r
}

fn is_test_attr(a: &str) -> bool {
    if a.contains("not(") {
        return false;
    }
    let words = |s: &str| s.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == "test");
    (a.contains("cfg(") && words(a)) || a == "#[test]" || a.ends_with("::test]") || a.contains("::test(") || a.starts_with("#[test(")
}

/// Directories whose contents are test code or test inputs, not the product.
fn test_path(path: &str) -> bool {
    path.split('/').any(|c| matches!(c, "tests" | "benches" | "fixtures" | "fixture" | "testdata" | "__tests__"))
        || path.rsplit('/').next().is_some_and(|f| f == "tests.rs")
}

struct FileOut {
    sites: Vec<(Match, &'static str, bool)>,
    parsed: bool,
    syntax_error: bool,
    /// Names of out-of-line modules this file declares under `#[cfg(test)]`: their files are test code.
    test_mods: Vec<(String, Option<String>)>,
}

/// `#[cfg(test)] mod name;` declarations, read from the text: an attribute line naming `test`
/// (and not `not(test)`) followed within three lines by `mod name;`, with the `#[path = ".."]`
/// between them if there is one. A parse would be exact but would cost a pass over every file
/// that has an inline test module.
fn test_mods(src: &str) -> Vec<(String, Option<String>)> {
    if !src.contains("cfg(") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut pending = 0;
    let mut path: Option<String> = None;
    for line in src.lines().map(str::trim) {
        if line.starts_with("#[cfg(") && !line.contains("not(") && line.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == "test") {
            pending = 3;
            path = None;
            continue;
        }
        if pending > 0 {
            if let Some(p) = line.strip_prefix("#[path").and_then(|r| r.split('"').nth(1)) {
                path = Some(p.to_owned());
            }
            let rest = line.strip_prefix("pub ").or_else(|| line.strip_prefix("pub(crate) ")).or_else(|| line.strip_prefix("pub(super) ")).unwrap_or(line);
            if let Some(name) = rest.strip_prefix("mod ").and_then(|r| r.strip_suffix(';')) {
                out.push((name.trim().to_owned(), path.take()));
                pending = 0;
                continue;
            }
            pending -= 1;
        }
    }
    out
}

/// The files that `#[cfg(test)] mod name;` in `declaring` pulls in: the module file and, for a
/// directory module, everything below it.
fn test_module_paths(declaring: &str, mods: &[(String, Option<String>)]) -> (Vec<String>, Vec<String>) {
    let (dir, file) = declaring.rsplit_once('/').unwrap_or(("", declaring));
    let stem = file.trim_end_matches(".rs");
    let mdir = if matches!(stem, "mod" | "lib" | "main") { dir.to_owned() } else if dir.is_empty() { stem.to_owned() } else { format!("{dir}/{stem}") };
    let at = |n: &str| if mdir.is_empty() { n.to_owned() } else { format!("{mdir}/{n}") };
    // `#[path]` is relative to the directory of the declaring file.
    let beside = |p: &str| if dir.is_empty() { p.to_owned() } else { format!("{dir}/{p}") };
    let files = mods.iter().map(|(n, p)| p.as_deref().map_or_else(|| format!("{}.rs", at(n)), beside)).collect();
    (files, mods.iter().filter(|m| m.1.is_none()).map(|(n, _)| format!("{}/", at(n))).collect())
}

fn scan_file(rules: &[Rule], path: &str, src: &str) -> FileOut {
    let bytes = src.as_bytes();
    let live: Vec<&Rule> = rules
        .iter()
        .filter(|r| pattern::passes(&r.triggers, bytes))
        .collect();
    let test_mods = test_mods(src);
    if live.is_empty() {
        return FileOut { sites: Vec::new(), parsed: false, syntax_error: false, test_mods };
    }
    let Ok(parsed): Result<Parsed, _> = pattern::parse("rust", src) else {
        return FileOut { sites: Vec::new(), parsed: false, syntax_error: false, test_mods };
    };
    let uses = parsed.ranges_of("use_declaration");
    let tests = parsed.attributed_ranges(&["mod_item", "function_item", "impl_item"], is_test_attr);
    let file_is_test = test_path(path);
    let mut sites = Vec::new();
    for r in live {
        let found = match &r.how {
            How::Pat(c) => c.find_in(&parsed, path),
            How::Kind(k) => parsed.kind_matches(path, k, |_| true),
        };
        for m in found {
            if uses.iter().any(|&(s, e)| s <= m.start_byte && m.end_byte <= e) {
                continue;
            }
            if r.keep.is_some_and(|k| !k(&m, src)) {
                continue;
            }
            let test = file_is_test || tests.iter().any(|&(s, e)| s <= m.start_byte && m.end_byte <= e);
            sites.push((m, r.class, test));
        }
    }
    FileOut { sites, parsed: true, syntax_error: parsed.syntax_error, test_mods }
}

#[derive(Deserialize)]
struct Meta {
    packages: Vec<MPkg>,
}
#[derive(Deserialize)]
struct MPkg {
    name: String,
    manifest_path: String,
    #[serde(default)]
    links: Option<String>,
    targets: Vec<MTarget>,
    dependencies: Vec<MDep>,
}
#[derive(Deserialize)]
struct MTarget {
    kind: Vec<String>,
    src_path: String,
}
#[derive(Deserialize)]
struct MDep {
    name: String,
    kind: Option<String>,
}

fn metadata(root: &Path) -> Result<Meta, String> {
    // `cargo-stock` skips the caching shim `cargo` can be on CI hosts, as keel-index does.
    for exe in ["cargo-stock", "cargo"] {
        match Command::new(exe)
            .args(["metadata", "--format-version", "1", "--offline", "--no-deps"])
            .current_dir(root)
            .env("RUSTC_WRAPPER", "")
            .output()
        {
            Ok(o) if o.status.success() => {
                return serde_json::from_slice(&o.stdout).map_err(|e| format!("unreadable cargo metadata: {e}"));
            }
            Ok(o) => return Err(format!("`{exe} metadata` exited with {}: {}", o.status, String::from_utf8_lossy(&o.stderr).trim())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot run `{exe}`: {e}")),
        }
    }
    Err("neither cargo-stock nor cargo is on PATH".to_owned())
}

/// The first line of `text` that satisfies `hit`, 1-based; 1 when none does.
fn line_of(text: &str, hit: impl Fn(&str) -> bool) -> u32 {
    text.lines().position(hit).map_or(1, |i| i as u32 + 1)
}

const BUILD_TOOLS: &[&str] = &["cc", "cmake", "bindgen", "pkg_config", "cxx_build", "autocfg", "vcpkg"];

fn native_language(path: &str) -> Option<&'static str> {
    let ext = path.rsplit_once('.')?.1;
    Some(match ext {
        "c" | "h" => "C",
        "cc" | "cpp" | "cxx" | "c++" | "hpp" | "hh" | "hxx" => "C++",
        "m" | "mm" => "Objective-C",
        "s" | "S" | "asm" => "assembly",
        _ => return None,
    })
}

pub fn run(res: &Resolution<'_>, root: &Path, opts: &Options) -> Report {
    let started = std::time::Instant::now();
    let tracked = res.tracked_files();
    let rules = rules();
    let mut notes: Vec<String> = Vec::new();
    let owner = |path: &str, line: u32| -> String {
        match res.owner_at(path, line) {
            Owner::Node(n) => res.nodes[n].id.clone(),
            Owner::Inert => "inert".to_owned(),
            Owner::Conflict => "conflict".to_owned(),
        }
    };

    // Syntax: one read and one parse per Rust file, every rule over that parse.
    let rs: Vec<&String> = tracked.iter().filter(|p| p.ends_with(".rs")).collect();
    let outs: Vec<Result<FileOut, pattern::Skipped>> = pattern::pool().install(|| {
        rs.par_iter()
            .map(|p| {
                let skip = |reason: String| pattern::Skipped { path: (*p).clone(), reason };
                let full = root.join(p.as_str());
                let meta = std::fs::symlink_metadata(&full).map_err(|e| skip(format!("unreadable: {e}")))?;
                if !meta.is_file() {
                    return Err(skip("not a regular file".to_owned()));
                }
                if meta.len() > pattern::MAX_FILE_BYTES {
                    return Err(skip(format!("{} bytes, over the {}-byte limit", meta.len(), pattern::MAX_FILE_BYTES)));
                }
                let bytes = std::fs::read(&full).map_err(|e| skip(format!("unreadable: {e}")))?;
                let src = String::from_utf8(bytes).map_err(|_| skip("not valid UTF-8".to_owned()))?;
                Ok(scan_file(&rules, p, &src))
            })
            .collect()
    });
    let mut raw: Vec<(String, u32, &'static str, bool, String)> = Vec::new();
    let (mut parsed, mut syntax, mut skipped) = (0, 0, Vec::new());
    let (mut test_files, mut test_dirs): (BTreeSet<String>, BTreeSet<String>) = (BTreeSet::new(), BTreeSet::new());
    for (p, out) in rs.iter().zip(outs) {
        match out {
            Err(s) => skipped.push(s),
            Ok(o) => {
                parsed += usize::from(o.parsed);
                syntax += usize::from(o.syntax_error);
                let (files, dirs) = test_module_paths(p, &o.test_mods);
                test_files.extend(files);
                test_dirs.extend(dirs);
                for (m, class, test) in o.sites {
                    raw.push(((*p).clone(), m.start_line, class, test, m.head));
                }
            }
        }
    }

    // Files that only exist as `#[cfg(test)] mod name;` are test code wherever they sit.
    let in_test_module = |path: &str| {
        test_files.contains(path) || path.match_indices('/').any(|(i, _)| test_dirs.contains(&path[..=i])) || test_dirs.contains(&format!("{path}/"))
    };
    for r in &mut raw {
        r.3 |= in_test_module(&r.0);
    }

    // Structure: cargo metadata, build scripts, native sources.
    let mut packages = 0;
    match metadata(root) {
        Err(why) => notes.push(format!(
            "cargo metadata is unavailable ({why}), so the native-* classes that come from package structure are not counted; the syntax classes are."
        )),
        Ok(meta) => {
            let canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
            let rel = |abs: &str| -> Option<String> {
                let p = Path::new(abs);
                let p = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
                p.strip_prefix(&canon).ok().map(|r| r.to_string_lossy().replace('\\', "/"))
            };
            let mut dirs: Vec<String> = Vec::new();
            let mut build_scripts: Vec<(String, String)> = Vec::new();
            for p in &meta.packages {
                let Some(manifest) = rel(&p.manifest_path) else { continue };
                packages += 1;
                let dir = manifest.rsplit_once('/').map_or("", |x| x.0).to_owned();
                dirs.push(dir);
                let text = std::fs::read_to_string(root.join(&manifest)).unwrap_or_default();
                if p.links.is_some() {
                    raw.push((manifest.clone(), line_of(&text, |l| l.trim_start().starts_with("links")), "native-links-key", false, format!("links = {:?}", p.links.as_deref().unwrap_or(""))));
                }
                if p.name.ends_with("-sys") {
                    raw.push((manifest.clone(), 1, "native-sys-member", false, p.name.clone()));
                }
                for d in p.dependencies.iter().filter(|d| d.name.ends_with("-sys")) {
                    let line = line_of(&text, |l| {
                        let t = l.trim_start();
                        t.strip_prefix(d.name.as_str()).is_some_and(|r| r.trim_start().starts_with(['=', '.'])) || t.contains(&format!("dependencies.{}]", d.name))
                    });
                    raw.push((manifest.clone(), line, "native-sys-dependency", d.kind.as_deref() == Some("dev"), format!("{} ({})", d.name, d.kind.as_deref().unwrap_or("normal"))));
                }
                for t in p.targets.iter().filter(|t| t.kind.iter().any(|k| k == "custom-build")) {
                    if let Some(s) = rel(&t.src_path) {
                        raw.push((s.clone(), 1, "native-build-script", false, format!("build script of {}", p.name)));
                        build_scripts.push((s, p.name.clone()));
                    }
                }
            }
            for (script, _) in &build_scripts {
                let Ok(src) = std::fs::read_to_string(root.join(script)) else { continue };
                let Ok(parsed) = pattern::parse("rust", &src) else { continue };
                let mut first: BTreeMap<&str, (u32, usize)> = BTreeMap::new();
                for k in ["scoped_identifier", "call_expression"] {
                    for m in parsed.kind_matches(script, k, |_| true) {
                        for tool in BUILD_TOOLS {
                            if m.head.starts_with(&format!("{tool}::")) || (k == "scoped_identifier" && m.head.starts_with(&format!("use {tool}"))) {
                                let e = first.entry(tool).or_insert((m.start_line, 0));
                                e.0 = e.0.min(m.start_line);
                                if k == "call_expression" {
                                    e.1 += 1;
                                }
                            }
                        }
                    }
                }
                for (tool, (line, calls)) in first {
                    raw.push((script.clone(), line, "native-build-tool", false, format!("{tool} ({calls} calls)")));
                }
            }
            dirs.sort_by_key(|d| std::cmp::Reverse(d.len()));
            for p in tracked {
                let Some(lang) = native_language(p) else { continue };
                let inside = dirs.iter().any(|d| d.is_empty() || p == d || p.strip_prefix(d.as_str()).is_some_and(|r| r.starts_with('/')));
                if inside {
                    raw.push((p.clone(), 1, "native-source", test_path(p) || in_test_module(p), format!("{lang} source")));
                }
            }
        }
    }

    raw.sort();
    raw.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1 && a.2 == b.2);
    let all: Vec<Site> = raw
        .into_iter()
        .map(|(path, line, class, test, text)| Site { class, node: owner(&path, line), path, line, test, text })
        .collect();
    let test_sites_hidden = if opts.include_tests { 0 } else { all.iter().filter(|s| s.test).count() };
    let sites: Vec<Site> = all.into_iter().filter(|s| opts.include_tests || !s.test).collect();
    notes.extend(SKIPPED.iter().map(|s| (*s).to_owned()));
    Report {
        root: root.display().to_string(),
        include_tests: opts.include_tests,
        test_sites_hidden,
        sites,
        rust_files: rs.len(),
        rust_files_parsed: parsed,
        rust_files_with_syntax_errors: syntax,
        skipped_files: skipped,
        packages,
        notes,
        millis: started.elapsed().as_millis(),
    }
}

impl Report {
    /// Sites per class, production and test, over `all` (the report may have hidden the tests).
    fn counts(&self) -> BTreeMap<&'static str, (usize, usize)> {
        let mut m: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
        for s in &self.sites {
            let e = m.entry(s.class).or_default();
            if s.test {
                e.1 += 1;
            } else {
                e.0 += 1;
            }
        }
        m
    }

    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut o = String::new();
        let prod = self.sites.iter().filter(|s| !s.test).count();
        let test = self.sites.iter().filter(|s| s.test).count();
        let _ = writeln!(o, "boundaries of {}", self.root);
        let _ = writeln!(
            o,
            "{} production sites{}",
            num(prod as u64),
            if self.include_tests {
                format!(" and {} in test code (shown, --include-tests)", num(test as u64))
            } else {
                format!("; {} more in test code are hidden, pass --include-tests to list them", num(self.test_sites_hidden as u64))
            }
        );
        let _ = writeln!(
            o,
            "read {} Rust files ({} parsed, the rest held no trigger text for any rule), {} packages from cargo metadata, {} ms",
            num(self.rust_files as u64),
            num(self.rust_files_parsed as u64),
            num(self.packages as u64),
            self.millis
        );
        let _ = writeln!(o, "THIS IS A LOWER BOUND: a pattern census sees only the spellings it names. What each class can miss or over-count is under `class notes`.");
        if !self.skipped_files.is_empty() {
            let _ = writeln!(o, "\nNOT READ ({} Rust files, so their boundaries are unknown):", self.skipped_files.len());
            for s in self.skipped_files.iter().take(5) {
                let _ = writeln!(o, "  {} ({})", s.path, s.reason);
            }
        }
        if self.rust_files_with_syntax_errors > 0 {
            let _ = writeln!(o, "{} parsed files had syntax errors that tree-sitter recovered from; a boundary inside the broken region can be missing.", self.rust_files_with_syntax_errors);
        }
        let counts = self.counts();
        let mut rows = vec![vec!["\nclass".to_owned(), "group".to_owned(), "production".to_owned(), "test".to_owned()]];
        for c in CLASSES {
            let (p, t) = counts.get(c.id).copied().unwrap_or((0, 0));
            rows.push(vec![c.id.to_owned(), c.group.to_owned(), p.to_string(), if self.include_tests { t.to_string() } else { "-".to_owned() }]);
        }
        o.push_str(&table(&rows));

        // Per node, per class.
        let mut by_node: BTreeMap<&str, BTreeMap<&str, usize>> = BTreeMap::new();
        for s in self.sites.iter().filter(|s| !s.test) {
            *by_node.entry(s.node.as_str()).or_default().entry(s.class).or_default() += 1;
        }
        let _ = writeln!(o, "\nper owning node (production):");
        let mut rows = vec![vec!["  node".to_owned(), "sites".to_owned(), "by class".to_owned()]];
        let mut nodes: Vec<_> = by_node.iter().collect();
        nodes.sort_by(|a, b| b.1.values().sum::<usize>().cmp(&a.1.values().sum::<usize>()).then(a.0.cmp(b.0)));
        for (n, cls) in nodes {
            let total: usize = cls.values().sum();
            let by: Vec<String> = cls.iter().map(|(c, k)| format!("{c} {k}")).collect();
            rows.push(vec![format!("  {n}"), total.to_string(), by.join(", ")]);
        }
        o.push_str(&table(&rows));

        for c in CLASSES {
            let (p, t) = counts.get(c.id).copied().unwrap_or((0, 0));
            let _ = writeln!(o, "\n{}  [{}]  {} production{}", c.id, c.group, p, if self.include_tests { format!(", {t} test") } else { String::new() });
            let _ = writeln!(o, "  {}", c.what);
            let mut per: BTreeMap<&str, usize> = BTreeMap::new();
            for s in self.sites.iter().filter(|s| s.class == c.id && !s.test) {
                *per.entry(s.node.as_str()).or_default() += 1;
            }
            if per.is_empty() {
                let _ = writeln!(o, "  none found");
                continue;
            }
            let mut per: Vec<_> = per.into_iter().collect();
            per.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            let _ = writeln!(o, "  per node: {}", per.iter().map(|(n, k)| format!("{n} {k}")).collect::<Vec<_>>().join(", "));
            for s in self.sites.iter().filter(|s| s.class == c.id && !s.test).take(3) {
                let _ = writeln!(o, "    {}:{}  [{}]  {}", s.path, s.line, s.node, s.text);
            }
        }
        let _ = writeln!(o, "\nclass notes (false positives FP and false negatives FN):");
        for c in CLASSES {
            let _ = writeln!(o, "  {}: {}", c.id, c.risk);
        }
        let _ = writeln!(o, "\nnot counted, on purpose:");
        for n in &self.notes {
            let _ = writeln!(o, "  {n}");
        }
        let unowned: BTreeSet<&str> = self.sites.iter().filter(|s| s.node == "unowned" && !s.test).map(|s| s.class).collect();
        if !unowned.is_empty() {
            let _ = writeln!(o, "\nsites owned by no node (`unowned`) in: {}", unowned.into_iter().collect::<Vec<_>>().join(", "));
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_pattern_compiles_and_every_rule_class_is_declared() {
        let declared: BTreeSet<&str> = CLASSES.iter().map(|c| c.id).collect();
        for r in rules() {
            assert!(declared.contains(r.class), "rule class {} is not in CLASSES", r.class);
        }
    }

    fn sites_of(src: &str, path: &str) -> Vec<(&'static str, u32, bool)> {
        let rs = rules();
        let mut v: Vec<_> = scan_file(&rs, path, src).sites.into_iter().map(|(m, c, t)| (c, m.start_line, t)).collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn ffi_and_process_and_network_spellings_are_found() {
        let src = r#"
use std::process::Command;
extern "C" { fn puts(s: *const u8); }
#[no_mangle]
pub extern "C" fn exported() {}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn also() {}
#[link(name = "z")]
extern "C" {}
fn run() {
    let _ = Command::new("ls");
    let _ = std::env::current_exe();
    let _ = std::net::TcpListener::bind("0.0.0.0:80");
    let _ = std::env::var("MY_CACHE_DIR");
    let _ = std::env::var("RUST_LOG");
    let _ = std::time::Instant::now();
    let _ = include_str!("a.txt");
}
"#;
        let got: BTreeSet<&str> = sites_of(src, "src/lib.rs").into_iter().map(|s| s.0).collect();
        for want in [
            "ffi-extern-block", "ffi-extern-fn", "ffi-no-mangle", "ffi-link-attr", "process-spawn", "process-current-exe", "net-listen",
            "fs-env-path", "nondet-time", "compile-include",
        ] {
            assert!(got.contains(want), "{want} missing from {got:?}");
        }
        // RUST_LOG is not a path; the name test is on the literal.
        let env: Vec<_> = sites_of(src, "src/lib.rs").into_iter().filter(|s| s.0 == "fs-env-path").collect();
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn out_of_line_test_modules_are_found_from_the_declaring_file() {
        let src = "fn a() {}\n#[cfg(test)]\nmod tests;\n#[cfg(not(test))]\nmod prod;\n#[cfg(all(test, unix))]\npub(crate) mod unix_tests;\n#[cfg(test)]\nmod inline { }\n";
        assert_eq!(test_mods(src), [("tests".to_owned(), None), ("unix_tests".to_owned(), None)]);
        let with_path = "#[cfg(test)]\n#[path = \"remote_http_fixture.rs\"]\nmod remote_http_fixture;\n";
        let mods = test_mods(with_path);
        assert_eq!(test_module_paths("crates/x/src/query/remote.rs", &mods).0, ["crates/x/src/query/remote_http_fixture.rs"]);
        let (files, dirs) = test_module_paths("crates/x/src/query/remote.rs", &[("fixture".to_owned(), None)]);
        assert_eq!((files, dirs), (["crates/x/src/query/remote/fixture.rs".to_owned()].to_vec(), ["crates/x/src/query/remote/fixture/".to_owned()].to_vec()));
        let (files, _) = test_module_paths("crates/x/src/lib.rs", &[("tests".to_owned(), None)]);
        assert_eq!(files, ["crates/x/src/tests.rs"]);
    }

    #[test]
    fn bare_command_new_needs_the_process_import_and_test_code_is_flagged() {
        let clap = "fn app() { let _ = Command::new(\"app\"); }\n";
        assert!(sites_of(clap, "src/cli.rs").is_empty());
        let src = "fn p() { let _ = Instant::now(); }\n#[cfg(test)]\nmod tests {\n    fn t() { let _ = Instant::now(); }\n}\n";
        assert_eq!(sites_of(src, "src/lib.rs"), [("nondet-time", 1, false), ("nondet-time", 4, true)]);
        assert_eq!(sites_of("fn p() { let _ = Instant::now(); }\n", "crates/x/tests/it.rs"), [("nondet-time", 1, true)]);
        // `use` lines are not sites.
        assert!(sites_of("use rand::rngs::OsRng;\n", "src/lib.rs").is_empty());
    }
}
