//! Declared runtime files, DESIGN.md §3.3.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use camino::{Utf8Path, Utf8PathBuf};
use globset::{Glob, GlobBuilder, GlobMatcher, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use rayon::prelude::*;

use crate::digest::Digest;
use crate::frame::Framer;

/// Which files of a workspace are runtime inputs of a node.
///
/// Nothing is left out because of where it lives. `src/` and `tests/*.rs`
/// are compiled into a test binary, but that does not make them unread: a
/// test can open its own source, and `trybuild` reads `tests/**/*.rs` while
/// it runs. The only files the package selection skips are the exact paths a
/// caller lists in [`compiled_in`](Self::compiled_in).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileSpec {
    /// The package directory, relative to the workspace root. Every file under
    /// it is an input, except the exact paths in `compiled_in` and what
    /// `exclude` removes. Cargo's `target/` is not special-cased: the caller
    /// lists it in `exclude` (it holds the build's own outputs, which `code`
    /// already keys).
    pub package_dir: Option<Utf8PathBuf>,
    /// Workspace-relative paths of the source files this binary was compiled
    /// from (rustc dep-info), which the package selection leaves out because
    /// `code` covers them. Exact paths, not patterns, so that a file nobody
    /// listed can never be dropped by a convention. Only sound for files the
    /// test does not also open at run time; `include_str!` is fine (the bytes
    /// are in the binary), `File::open("src/x.rs")` is not.
    pub compiled_in: BTreeSet<Utf8PathBuf>,
    /// Extra inputs, globs relative to the workspace root. A file git ignores
    /// is still hashed when it exists and matches: being ignored does not
    /// make it unread. Only `exclude` removes files from these.
    pub globs: Vec<String>,
    /// Globs relative to the workspace root that remove files selected by
    /// either of the above. A pattern ending in `/**` also stops the walk
    /// from entering that directory.
    pub exclude: Vec<String>,
}

/// Why a file set could not be keyed.
#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    /// A glob in the spec does not compile.
    #[error(
        "glob `{glob}` in the file spec is invalid ({source}); fix the pattern in the package's `inputs` or `exclude`"
    )]
    Glob {
        /// The offending pattern.
        glob: String,
        /// The compiler's complaint.
        source: globset::Error,
    },
    /// Walking the tree failed.
    #[error(
        "cannot walk {root} to collect input files: {source}; check the directory exists and is readable"
    )]
    Walk {
        /// The workspace root.
        root: PathBuf,
        /// The walker's error.
        source: ignore::Error,
    },
    /// A selected file could not be read or hashed.
    #[error(
        "cannot read input file {path}: {source}; it was listed during the walk, so something is modifying the tree while keys are computed"
    )]
    Read {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: io::Error,
    },
    /// Paths are hashed as UTF-8 so keys agree across platforms.
    #[error(
        "input path {0:?} is not valid UTF-8; rename it, or exclude it in the package's `exclude`"
    )]
    NonUtf8(PathBuf),
    /// A symlink in the input set does not lead to anything that can be hashed.
    #[error(
        "symlink {link} -> {target} cannot be resolved: {reason}; the key cannot say what a test that follows it would read, so repair or remove the link, or list it in the package's `exclude`"
    )]
    Link {
        /// The link, as found in the tree.
        link: PathBuf,
        /// What it says it points at.
        target: String,
        /// Dangling, a loop, or the OS error.
        reason: String,
    },
}

fn glob(p: &str) -> Result<Glob, FilesError> {
    // `*` stays within a path component, as in gitignore.
    GlobBuilder::new(p)
        .literal_separator(true)
        .build()
        .map_err(|source| FilesError::Glob {
            glob: p.to_owned(),
            source,
        })
}

fn compile(patterns: &[&str]) -> Result<GlobSet, FilesError> {
    let mut set = GlobSetBuilder::new();
    for p in patterns {
        set.add(glob(p)?);
    }
    set.build().map_err(|source| FilesError::Glob {
        glob: patterns.join(", "),
        source,
    })
}

/// What the key records about one path.
enum Content {
    File {
        hash: Digest,
        executable: bool,
    },
    /// A directory reached through a symlink: its sorted entries, recursively.
    Tree(Digest),
    /// A symlink contributes where it points *and* what is there, so neither
    /// retargeting it nor editing the file behind it can leave the key as it was.
    Link {
        target: String,
        behind: Box<Content>,
    },
}

impl Content {
    fn frame(&self, f: &mut Framer) {
        match self {
            Content::File { hash, executable } => {
                f.field(3, &hash.framed())
                    .field(4, &[u8::from(*executable)]);
            }
            Content::Link { target, behind } => {
                f.field(5, target.as_bytes());
                behind.frame(f);
            }
            Content::Tree(d) => {
                f.field(6, &d.framed());
            }
        }
    }
}

fn read_err(path: &Path) -> impl FnOnce(io::Error) -> FilesError + '_ {
    move |source| FilesError::Read {
        path: path.into(),
        source,
    }
}

/// Hashes whatever `path` is. `open` holds the canonical directories being
/// hashed right now, so a link that leads back into one is a loop, not a
/// walk to infinity.
fn describe(path: &Path, open: &mut Vec<PathBuf>) -> Result<Content, FilesError> {
    let meta = fs::symlink_metadata(path).map_err(read_err(path))?;
    if meta.file_type().is_symlink() {
        let target = fs::read_link(path).map_err(read_err(path))?;
        let target = target
            .to_str()
            .ok_or_else(|| FilesError::NonUtf8(target.clone()))?
            .to_owned();
        let broken = |reason: String| FilesError::Link {
            link: path.into(),
            target: target.clone(),
            reason,
        };
        // `canonicalize` fails on a dangling link and on a loop of links, and
        // the error says which.
        let real = fs::canonicalize(path).map_err(|e| {
            broken(if e.kind() == io::ErrorKind::NotFound {
                "its target does not exist (dangling link)".to_owned()
            } else {
                format!("{e} (a loop of links, or an unreadable target)")
            })
        })?;
        if fs::metadata(&real).map_err(read_err(&real))?.is_dir() {
            if open.contains(&real) {
                return Err(broken(format!(
                    "it leads back into {}, which is already being hashed (a loop)",
                    real.display()
                )));
            }
            let behind = tree(&real, open)?;
            return Ok(Content::Link {
                target,
                behind: Box::new(behind),
            });
        }
        let behind = file(&real)?;
        return Ok(Content::Link {
            target,
            behind: Box::new(behind),
        });
    }
    if meta.is_dir() {
        return tree(path, open);
    }
    file(path)
}

fn file(path: &Path) -> Result<Content, FilesError> {
    let meta = fs::metadata(path).map_err(read_err(path))?;
    // Streamed read rather than a memory map: a test that truncates a file
    // while we hash it must produce a wrong key, not a SIGBUS in the
    // conductor.
    let mut hasher = blake3::Hasher::new();
    hasher
        .update_reader(fs::File::open(path).map_err(read_err(path))?)
        .map_err(read_err(path))?;
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = {
        let _ = meta;
        false
    };
    Ok(Content::File {
        hash: Digest::Blake3(*hasher.finalize().as_bytes()),
        executable,
    })
}

/// A directory reached through a link: every entry, ignore files and all.
fn tree(dir: &Path, open: &mut Vec<PathBuf>) -> Result<Content, FilesError> {
    let real = fs::canonicalize(dir).map_err(read_err(dir))?;
    open.push(real);
    let mut names: Vec<_> = fs::read_dir(dir)
        .map_err(read_err(dir))?
        .map(|e| e.map(|e| e.file_name()).map_err(read_err(dir)))
        .collect::<Result<_, _>>()?;
    names.sort();
    let mut f = Framer::new("keel/files/tree");
    f.field(1, &(names.len() as u64).to_le_bytes());
    for name in names {
        let name_s = name
            .to_str()
            .ok_or_else(|| FilesError::NonUtf8(dir.join(&name)))?;
        f.field(2, name_s.as_bytes());
        describe(&dir.join(&name), open)?.frame(&mut f);
    }
    open.pop();
    Ok(Content::Tree(f.finish()))
}

/// The components of the path that could contain a match of one glob, used to
/// walk only where a declared pattern can reach.
struct Reach {
    parts: Vec<Part>,
    /// Braces can cross components; do not reason about those globs.
    always: bool,
}

enum Part {
    /// `**`
    Any,
    Literal(String),
    Pattern(GlobMatcher),
}

impl Reach {
    fn new(pattern: &str) -> Result<Self, FilesError> {
        let mut parts = Vec::new();
        for comp in pattern.split('/').filter(|c| !c.is_empty() && *c != ".") {
            parts.push(if comp == "**" {
                Part::Any
            } else if comp.contains(['*', '?', '[']) {
                Part::Pattern(glob(comp)?.compile_matcher())
            } else {
                Part::Literal(comp.to_owned())
            });
        }
        Ok(Reach {
            parts,
            always: pattern.contains(['{', '\\']),
        })
    }

    /// Whether a file below `dir` (components from the root) can match.
    fn could_reach(&self, dir: &[&str]) -> bool {
        if self.always {
            return true;
        }
        for (comp, part) in dir.iter().zip(&self.parts) {
            match part {
                Part::Any => return true,
                Part::Literal(l) if l != comp => return false,
                Part::Pattern(m) if !m.is_match(comp) => return false,
                _ => {}
            }
        }
        // A directory as deep as the whole pattern holds only files the
        // pattern's last component cannot reach (`*` stays in a component).
        self.parts.len() > dir.len()
    }
}

/// Hashes the sorted `(relative path, content hash, executable bit)` of every
/// file the spec selects and returns the digest with the sorted path list for
/// the manifest.
///
/// `.gitignore` does not matter: it says what git tracks, not what a test
/// opens, and a generated fixture is usually ignored. The walk therefore
/// enters ignored directories wherever a declared pattern (or the package
/// directory) can reach, and prunes only by `.git` and by the spec's own
/// `exclude`. Hidden files are included. Paths are part of the hash because
/// directory listings are observable (§3.3), so an added empty file changes
/// the key. Empty directories are not recorded. A symlink is hashed as its
/// target text plus whatever it resolves to (a file's bytes, or a whole
/// directory's); one that dangles or loops is an error naming it. Files are
/// hashed in parallel; the order of discovery does not reach the hash.
pub fn files_key(root: &Path, spec: &FileSpec) -> Result<(Digest, Vec<Utf8PathBuf>), FilesError> {
    let globs = compile(&spec.globs.iter().map(String::as_str).collect::<Vec<_>>())?;
    let excluded = compile(&spec.exclude.iter().map(String::as_str).collect::<Vec<_>>())?;
    let reaches = spec
        .globs
        .iter()
        .map(|g| Reach::new(g))
        .collect::<Result<Vec<_>, _>>()?;
    // `dir/**` excludes mean the walk never needs to look inside `dir`.
    let mut pruned = Vec::new();
    for e in &spec.exclude {
        if let Some(dir) = e.strip_suffix("/**") {
            pruned.push(glob(dir)?.compile_matcher());
        }
    }
    let package = spec
        .package_dir
        .as_deref()
        .map(|p| p.as_str().trim_matches('/'))
        .filter(|p| !p.is_empty())
        .map(Utf8Path::new);

    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .parents(false)
        .git_global(false)
        .git_exclude(false)
        .git_ignore(false)
        .ignore(false)
        .follow_links(false);
    let root_owned = root.to_owned();
    let package_owned = package.map(Utf8Path::to_owned);
    builder.filter_entry(move |entry| {
        let rel = match entry.path().strip_prefix(&root_owned) {
            Ok(rel) if !rel.as_os_str().is_empty() => rel,
            _ => return true,
        };
        if !entry.file_type().is_some_and(|t| t.is_dir()) {
            return true;
        }
        if entry.file_name() == ".git" {
            return false;
        }
        if pruned.iter().any(|m| m.is_match(rel)) {
            return false;
        }
        // Descend only where something declared can be: below the package
        // directory (or on the way to it), or where some glob can reach.
        let in_package = package_owned.as_ref().is_some_and(|pkg| {
            rel.starts_with(pkg.as_std_path()) || pkg.as_std_path().starts_with(rel)
        });
        if in_package {
            return true;
        }
        let comps: Vec<&str> = rel.iter().filter_map(|c| c.to_str()).collect();
        reaches.iter().any(|r| r.could_reach(&comps))
    });

    let mut selected: Vec<Utf8PathBuf> = Vec::new();
    for entry in builder.build() {
        let entry = entry.map_err(|source| FilesError::Walk {
            root: root.into(),
            source,
        })?;
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .expect("walk stays under root");
        let rel = Utf8Path::from_path(rel).ok_or_else(|| FilesError::NonUtf8(rel.to_owned()))?;
        let rel = Utf8PathBuf::from(rel.as_str().replace('\\', "/"));

        let in_package = package
            .and_then(|p| rel.strip_prefix(p).ok())
            .is_some_and(|_| !spec.compiled_in.contains(&rel));
        if (in_package || globs.is_match(rel.as_str())) && !excluded.is_match(rel.as_str()) {
            selected.push(rel);
        }
    }
    selected.sort();
    selected.dedup();

    let hashed: Vec<(&Utf8PathBuf, Content)> = selected
        .par_iter()
        .map(|rel| describe(&root.join(rel.as_std_path()), &mut Vec::new()).map(|c| (rel, c)))
        .collect::<Result<_, _>>()?;

    let mut f = Framer::new("keel/files/2");
    f.field(1, &(hashed.len() as u64).to_le_bytes());
    for (rel, content) in &hashed {
        f.field(2, rel.as_str().as_bytes());
        content.frame(&mut f);
    }
    Ok((f.finish(), selected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    fn spec(pkg: &str) -> FileSpec {
        FileSpec {
            package_dir: Some(pkg.into()),
            ..FileSpec::default()
        }
    }

    fn paths(list: &[Utf8PathBuf]) -> Vec<&str> {
        list.iter().map(|p| p.as_str()).collect()
    }

    fn tree() -> TempDir {
        let t = TempDir::new("files");
        t.write("pkg/Cargo.toml", b"[package]");
        t.write("pkg/src/lib.rs", b"fn main() {}");
        t.write("pkg/tests/it.rs", b"#[test] fn t() {}");
        t.write("pkg/tests/data/golden.txt", b"golden");
        t.write("pkg/benches/b.rs", b"");
        t.write("pkg/examples/e.rs", b"");
        t.write("pkg/.hidden", b"dot");
        t.write("other/file.txt", b"elsewhere");
        t
    }

    #[test]
    fn selects_every_file_of_the_package_unless_it_is_listed_as_compiled_in() {
        let t = tree();
        let (_, list) = files_key(t.path(), &spec("pkg")).unwrap();
        assert_eq!(
            paths(&list),
            [
                "pkg/.hidden",
                "pkg/Cargo.toml",
                "pkg/benches/b.rs",
                "pkg/examples/e.rs",
                "pkg/src/lib.rs",
                "pkg/tests/data/golden.txt",
                "pkg/tests/it.rs"
            ]
        );
        // Only the exact paths named are left out; their neighbours stay.
        let s = FileSpec {
            compiled_in: ["pkg/src/lib.rs".into(), "pkg/tests/it.rs".into()].into(),
            ..spec("pkg")
        };
        let (_, list) = files_key(t.path(), &s).unwrap();
        assert!(
            !paths(&list).contains(&"pkg/src/lib.rs") && !paths(&list).contains(&"pkg/tests/it.rs")
        );
        assert!(paths(&list).contains(&"pkg/benches/b.rs"));
        t.write("pkg/src/other.rs", b"new file next to a compiled-in one");
        let (_, list) = files_key(t.path(), &s).unwrap();
        assert!(paths(&list).contains(&"pkg/src/other.rs"), "{list:?}");
    }

    #[test]
    fn a_source_file_a_test_reads_at_run_time_is_in_the_key() {
        // trybuild reads tests/**/*.rs while it runs; a test may open its own src.
        let t = tree();
        t.write("pkg/tests/ui/case.rs", b"fn main() {}");
        let (before, _) = files_key(t.path(), &spec("pkg")).unwrap();
        t.write("pkg/src/lib.rs", b"fn b() {}");
        let (after_src, _) = files_key(t.path(), &spec("pkg")).unwrap();
        assert_ne!(before, after_src, "src/ edit must change the files key");
        t.write("pkg/tests/ui/case.rs", b"fn main() { 1 }");
        assert_ne!(after_src, files_key(t.path(), &spec("pkg")).unwrap().0);
        // A caller who lists src/lib.rs as compiled in accepts that trade, for that file only.
        let s = FileSpec {
            compiled_in: ["pkg/src/lib.rs".into()].into(),
            ..spec("pkg")
        };
        let (a, _) = files_key(t.path(), &s).unwrap();
        t.write("pkg/src/lib.rs", b"fn c() {}");
        assert_eq!(a, files_key(t.path(), &s).unwrap().0);
    }

    #[test]
    fn globs_are_workspace_relative_and_select_source_files_too() {
        let t = tree();
        let s = FileSpec {
            globs: vec!["other/*.txt".into(), "pkg/src/lib.rs".into()],
            ..FileSpec::default()
        };
        let (_, list) = files_key(t.path(), &s).unwrap();
        assert_eq!(paths(&list), ["other/file.txt", "pkg/src/lib.rs"]);
    }

    #[test]
    fn exclude_removes_selected_files() {
        let t = tree();
        let s = FileSpec {
            exclude: vec![
                "pkg/.hidden".into(),
                "pkg/tests/**".into(),
                "pkg/src/**".into(),
                "pkg/benches/**".into(),
                "pkg/examples/**".into(),
            ],
            ..spec("pkg")
        };
        let (_, list) = files_key(t.path(), &s).unwrap();
        assert_eq!(paths(&list), ["pkg/Cargo.toml"]);
    }

    #[cfg(unix)]
    #[test]
    fn an_excluded_directory_is_not_even_entered() {
        use std::os::unix::fs::PermissionsExt;
        let t = tree();
        t.write("pkg/target/debug/x", b"build output");
        let dir = t.path().join("pkg/target");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
        let walked = files_key(
            t.path(),
            &FileSpec {
                exclude: vec!["pkg/target/**".into()],
                ..spec("pkg")
            },
        );
        let unexcluded = files_key(t.path(), &spec("pkg"));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        // (As root the unreadable directory would still be readable; only the first claim is certain.)
        walked.expect("`target/**` excluded: the walk must not need to read it");
        let _ = unexcluded;
    }

    #[test]
    fn adding_an_empty_file_changes_the_key() {
        let t = tree();
        let (before, _) = files_key(t.path(), &spec("pkg")).unwrap();
        t.write("pkg/empty", b"");
        let (after, list) = files_key(t.path(), &spec("pkg")).unwrap();
        assert_ne!(before, after);
        assert!(paths(&list).contains(&"pkg/empty"));
    }

    #[test]
    fn content_change_changes_the_key() {
        let t = tree();
        let (before, _) = files_key(t.path(), &spec("pkg")).unwrap();
        t.write("pkg/tests/data/golden.txt", b"golden!");
        assert_ne!(before, files_key(t.path(), &spec("pkg")).unwrap().0);
    }

    #[cfg(unix)]
    #[test]
    fn mode_change_changes_the_key() {
        use std::os::unix::fs::PermissionsExt;
        let t = tree();
        let (before, _) = files_key(t.path(), &spec("pkg")).unwrap();
        let p = t.path().join("pkg/Cargo.toml");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        assert_ne!(before, files_key(t.path(), &spec("pkg")).unwrap().0);
    }

    #[test]
    fn creation_order_does_not_matter() {
        let (a, b) = (TempDir::new("order-a"), TempDir::new("order-b"));
        let names = ["p/a", "p/z/1", "p/m", "p/z/0", "p/b/c/d"];
        for n in names {
            a.write(n, n.as_bytes());
        }
        for n in names.iter().rev() {
            b.write(n, n.as_bytes());
        }
        let ka = files_key(a.path(), &spec("p")).unwrap();
        let kb = files_key(b.path(), &spec("p")).unwrap();
        assert_eq!(ka, kb);
    }

    #[test]
    fn a_git_ignored_file_is_still_hashed_when_it_matches_a_glob_or_the_package() {
        let t = tree();
        t.write(".gitignore", b"generated/\nignored.txt\n");
        t.write("generated/schema.json", b"{}");
        t.write("pkg/ignored.txt", b"x");
        let s = FileSpec {
            globs: vec!["generated/*.json".into()],
            ..spec("pkg")
        };
        let (before, list) = files_key(t.path(), &s).unwrap();
        assert!(paths(&list).contains(&"generated/schema.json"), "{list:?}");
        assert!(paths(&list).contains(&"pkg/ignored.txt"), "{list:?}");
        t.write("generated/schema.json", b"{\"v\":2}");
        assert_ne!(before, files_key(t.path(), &s).unwrap().0);
    }

    #[test]
    fn dot_git_is_never_walked() {
        let t = tree();
        t.write("pkg/.git/HEAD", b"ref");
        let s = FileSpec {
            globs: vec!["**".into()],
            ..spec("pkg")
        };
        let (_, list) = files_key(t.path(), &s).unwrap();
        assert!(paths(&list).iter().all(|p| !p.contains(".git/")));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_hashed_by_its_target_path_and_what_is_behind_it() {
        let t = tree();
        // Exclude the real files so only the link can carry their bytes.
        let s = FileSpec {
            exclude: vec!["pkg/tests/**".into(), "other/**".into()],
            globs: vec!["pkg/link".into()],
            ..spec("pkg")
        };
        std::os::unix::fs::symlink("tests/data/golden.txt", t.path().join("pkg/link")).unwrap();
        let (a, list) = files_key(t.path(), &s).unwrap();
        assert!(paths(&list).contains(&"pkg/link"));
        // The bytes behind the link.
        t.write("pkg/tests/data/golden.txt", b"changed behind the link");
        let (b, _) = files_key(t.path(), &s).unwrap();
        assert_ne!(a, b, "editing the referent must change the key");
        // The target path, with the bytes held equal.
        t.write("pkg/tests/data/copy.txt", b"changed behind the link");
        fs::remove_file(t.path().join("pkg/link")).unwrap();
        std::os::unix::fs::symlink("tests/data/copy.txt", t.path().join("pkg/link")).unwrap();
        assert_ne!(
            b,
            files_key(t.path(), &s).unwrap().0,
            "retargeting must change the key"
        );
        // A link out of the workspace is followed too.
        let outside = TempDir::new("outside");
        outside.write("secret.txt", b"one");
        fs::remove_file(t.path().join("pkg/link")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret.txt"), t.path().join("pkg/link"))
            .unwrap();
        let (c, _) = files_key(t.path(), &s).unwrap();
        outside.write("secret.txt", b"two");
        assert_ne!(c, files_key(t.path(), &s).unwrap().0);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_directory_hashes_the_directory() {
        let t = tree();
        t.write("shared/a.txt", b"a");
        t.write("shared/sub/b.txt", b"b");
        std::os::unix::fs::symlink("../shared", t.path().join("pkg/shared")).unwrap();
        let s = FileSpec {
            exclude: vec!["shared/**".into()],
            ..spec("pkg")
        };
        let (a, _) = files_key(t.path(), &s).unwrap();
        t.write("shared/sub/b.txt", b"B");
        let (b, _) = files_key(t.path(), &s).unwrap();
        assert_ne!(a, b);
        t.write("shared/sub/new.txt", b"added");
        assert_ne!(b, files_key(t.path(), &s).unwrap().0);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_and_looping_links_are_errors_that_name_the_link() {
        let t = tree();
        std::os::unix::fs::symlink("missing.txt", t.path().join("pkg/dangling")).unwrap();
        let err = files_key(t.path(), &spec("pkg")).unwrap_err().to_string();
        assert!(
            err.contains("pkg/dangling") && err.contains("missing.txt") && err.contains("dangling"),
            "{err}"
        );
        fs::remove_file(t.path().join("pkg/dangling")).unwrap();

        std::os::unix::fs::symlink("b", t.path().join("pkg/a")).unwrap();
        std::os::unix::fs::symlink("a", t.path().join("pkg/b")).unwrap();
        let err = files_key(t.path(), &spec("pkg")).unwrap_err().to_string();
        assert!(err.contains("pkg/a") || err.contains("pkg/b"), "{err}");
        assert!(err.contains("loop"), "{err}");
        fs::remove_file(t.path().join("pkg/a")).unwrap();
        fs::remove_file(t.path().join("pkg/b")).unwrap();

        // A directory link that leads back into the tree being hashed.
        std::os::unix::fs::symlink(".", t.path().join("pkg/self")).unwrap();
        let err = files_key(t.path(), &spec("pkg")).unwrap_err().to_string();
        assert!(err.contains("pkg/self") && err.contains("loop"), "{err}");
    }

    #[test]
    fn invalid_glob_is_named() {
        let t = tree();
        let s = FileSpec {
            globs: vec!["pkg/[".into()],
            ..FileSpec::default()
        };
        let err = files_key(t.path(), &s).unwrap_err().to_string();
        assert!(err.contains("pkg/["), "{err}");
    }

    #[test]
    fn nothing_selected_is_a_stable_key() {
        let t = TempDir::new("empty");
        let a = files_key(t.path(), &FileSpec::default()).unwrap();
        assert!(a.1.is_empty());
        assert_eq!(a, files_key(t.path(), &FileSpec::default()).unwrap());
    }

    #[test]
    fn the_walk_enters_only_directories_a_declared_pattern_can_reach() {
        let r = |p: &str, d: &[&str]| Reach::new(p).unwrap().could_reach(d);
        assert!(r("crates/store/tests/**", &["crates"]));
        assert!(r(
            "crates/store/tests/**",
            &["crates", "store", "tests", "deep"]
        ));
        assert!(!r("crates/store/tests/**", &["crates", "other"]));
        assert!(
            !r("tests/*.json", &["tests", "sub"]),
            "`*` stays in one component"
        );
        assert!(r("tests/*.json", &["tests"]));
        assert!(r("**/fixtures/**", &["anything", "at", "all"]));
        assert!(r("{a,b/c}/x", &["b", "c"]), "braces are not reasoned about");
        assert!(
            !r("a/b", &["a", "b"]),
            "a directory cannot be the file `a/b`"
        );
    }
}
