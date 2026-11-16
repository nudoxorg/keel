//! A compiler-free code index of a Rust repository: which functions and tests
//! exist, which package and file own them, how branchy they are, and which of
//! them a git diff touched. Nothing is built; `syn` parses the git-tracked
//! `*.rs` files and `cargo metadata --no-deps` supplies the package graph.
//!
//! The planner uses it to decide where in a product's test tree to start
//! after a change, so every answer errs toward "more is affected".

mod builder;
mod diff;
mod error;
mod git;
mod hex32;
mod packages;
pub mod parse;

pub use diff::{Change, FileChange, FileStatus, ItemChange, ItemChangeKind, diff};
pub use error::IndexError;
pub use roaring::RoaringBitmap;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CodeIndex {
    pub root: PathBuf,
    pub packages: Vec<Package>,
    pub files: Vec<SourceFile>,
    /// Every fn (free, impl, trait default), sorted by (file, start_line).
    pub items: Vec<Item>,
    /// Why the resolved package graph was not used (only workspace members are packages then).
    #[serde(default)]
    pub graph_note: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Package {
    pub name: String,
    /// Repo-relative directory of its Cargo.toml; empty for the root package.
    pub dir: String,
    /// Dependencies among the packages under the root (normal + build + dev merged), sorted.
    pub deps: Vec<u32>,
    /// The subset of `deps` not reachable through normal or build edges.
    pub dev_only_deps: Vec<u32>,
    /// A workspace member. A package that is not one (a `path` or `[patch]` dependency kept in
    /// the repository) is compiled into the product when something depends on it, but its own
    /// tests are not part of the workspace's test run.
    #[serde(default = "yes")]
    pub member: bool,
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Lib,
    Bin,
    IntegrationTest(String),
    Bench,
    Example,
    BuildScript,
    Other,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SourceFile {
    /// Repo-relative, forward slashes.
    pub path: String,
    pub package: Option<u32>,
    pub target: Target,
    /// blake3 of the file bytes; all zeros if the file could not be read.
    #[serde(with = "hex32")]
    pub content: [u8; 32],
    pub parse_error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Item {
    pub file: u32,
    /// Module path inside the file plus the fn name: `wal::tests::replays`,
    /// `Ledger::open`, and `<Ledger as Display>::fmt` for trait impls.
    pub path: String,
    /// 1-based inclusive, covering attributes and body.
    pub start_line: u32,
    pub end_line: u32,
    /// Hash of the fn's token stream, ignoring whitespace, ordinary comments and
    /// positions. Doc comments are part of it: rustdoc compiles them as tests.
    #[serde(with = "hex32")]
    pub tokens: [u8; 32],
    /// The same over everything except the body block, and without doc comments:
    /// rewording one does not change what callers can write.
    #[serde(with = "hex32")]
    pub signature: [u8; 32],
    pub branches: u32,
    pub is_test: bool,
    pub ignored: bool,
    pub in_test_code: bool,
}

impl CodeIndex {
    /// Indexes all git-tracked `*.rs` files under `root`. With `cache_dir`,
    /// per-file results keyed by content hash are stored there and reused.
    pub fn build(root: &Path, cache_dir: Option<&Path>) -> Result<CodeIndex, IndexError> {
        builder::build(root, cache_dir)
    }

    /// `(item index, item)` for every test.
    pub fn tests(&self) -> impl Iterator<Item = (u32, &Item)> {
        self.items
            .iter()
            .enumerate()
            .filter(|(_, i)| i.is_test)
            .map(|(n, i)| (n as u32, i))
    }

    /// An approximation of the id nextest prints: `<binary>$<module::path::fn>`.
    ///
    /// The binary is the package name for lib unit tests and
    /// `<package>::<name>` for integration tests; binaries, examples and
    /// benches follow nextest's `pkg::bin/name` shape. The module path starts
    /// with the file's own module (from its location, `#[path]` is not
    /// followed), which the item's in-file path does not carry.
    pub fn test_id(&self, item: u32) -> String {
        let it = &self.items[item as usize];
        let f = &self.files[it.file as usize];
        let Some(pkg) = f.package.map(|p| &self.packages[p as usize]) else {
            return format!("{}${}", f.path, it.path);
        };
        let rel = f
            .path
            .strip_prefix(pkg.dir.as_str())
            .map_or(f.path.as_str(), |r| r.trim_start_matches('/'));
        let parts: Vec<&str> = rel.split('/').collect();
        let bin_name = match parts.as_slice() {
            ["src", "bin", x, ..] => x.trim_end_matches(".rs").to_owned(),
            _ => pkg.name.clone(),
        };
        let binary = match &f.target {
            Target::IntegrationTest(n) => format!("{}::{n}", pkg.name),
            Target::Bin => format!("{}::bin/{bin_name}", pkg.name),
            Target::Example => format!(
                "{}::example/{}",
                pkg.name,
                parts.get(1).map_or("", |s| s.trim_end_matches(".rs"))
            ),
            Target::Bench => format!(
                "{}::bench/{}",
                pkg.name,
                parts.get(1).map_or("", |s| s.trim_end_matches(".rs"))
            ),
            Target::BuildScript => format!("{}::build-script", pkg.name),
            Target::Lib | Target::Other => pkg.name.clone(),
        };
        let mut id = format!("{binary}$");
        for seg in packages::module_prefix(rel) {
            id.push_str(&seg);
            id.push_str("::");
        }
        id.push_str(&it.path);
        id
    }

    /// `pkg` plus all transitive dependencies. Edges are the merged `deps`, so
    /// dev-dependency edges of dependencies are followed too: this errs
    /// toward a larger closure. Use `dev_only_deps` to refine.
    pub fn package_closure(&self, pkg: u32) -> RoaringBitmap {
        let mut seen = RoaringBitmap::new();
        let mut stack = vec![pkg];
        while let Some(p) = stack.pop() {
            if seen.insert(p) {
                stack.extend(self.packages[p as usize].deps.iter().copied());
            }
        }
        seen
    }

    /// `pkg` plus everything that transitively depends on it (same edge
    /// caveat as `package_closure`).
    pub fn dependents_closure(&self, pkg: u32) -> RoaringBitmap {
        let mut rev: Vec<Vec<u32>> = vec![Vec::new(); self.packages.len()];
        for (i, p) in self.packages.iter().enumerate() {
            for &d in &p.deps {
                rev[d as usize].push(i as u32);
            }
        }
        let mut seen = RoaringBitmap::new();
        let mut stack = vec![pkg];
        while let Some(p) = stack.pop() {
            if seen.insert(p) {
                stack.extend(rev[p as usize].iter().copied());
            }
        }
        seen
    }

    pub fn save(&self, path: &Path) -> Result<(), IndexError> {
        let file = std::fs::File::create(path).map_err(|e| error::io(path, e))?;
        serde_json::to_writer(std::io::BufWriter::with_capacity(1 << 20, file), self).map_err(
            |source| IndexError::Json {
                what: path.display().to_string(),
                source,
            },
        )
    }

    pub fn load(path: &Path) -> Result<CodeIndex, IndexError> {
        let file = std::fs::File::open(path).map_err(|e| error::io(path, e))?;
        serde_json::from_reader(std::io::BufReader::with_capacity(1 << 20, file)).map_err(
            |source| IndexError::Json {
                what: path.display().to_string(),
                source,
            },
        )
    }
}
