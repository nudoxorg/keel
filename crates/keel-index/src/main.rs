use anyhow::Result;
use clap::{Parser, Subcommand};
use keel_index::{CodeIndex, ItemChangeKind};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "keel-index",
    about = "Compiler-free code index for Rust repositories"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Index the git-tracked Rust files under ROOT and write the index to FILE.
    Build {
        #[arg(long)]
        root: PathBuf,
        /// Per-file result cache, keyed by content hash.
        #[arg(long)]
        cache: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Show which functions changed between two revisions.
    Diff {
        #[arg(long)]
        root: PathBuf,
        base: String,
        head: String,
        #[arg(long)]
        json: bool,
    },
    /// Print test ids, one per line.
    Tests {
        #[arg(long)]
        index: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Build { root, cache, out } => {
            let t = Instant::now();
            let idx = CodeIndex::build(&root, cache.as_deref())?;
            let index_ms = t.elapsed().as_millis();
            idx.save(&out)?;
            println!(
                "files={} parse_errors={} packages={} items={} tests={} index_ms={index_ms} wall_ms={}",
                idx.files.len(),
                idx.files.iter().filter(|f| f.parse_error.is_some()).count(),
                idx.packages.len(),
                idx.items.len(),
                idx.tests().count(),
                t.elapsed().as_millis()
            );
            for f in idx.files.iter().filter(|f| f.parse_error.is_some()).take(5) {
                eprintln!(
                    "parse error: {}: {}",
                    f.path,
                    f.parse_error.as_deref().unwrap_or("")
                );
            }
        }
        Cmd::Diff {
            root,
            base,
            head,
            json,
        } => {
            let t = Instant::now();
            let change = keel_index::diff(&root, &base, &head)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&change)?);
                return Ok(());
            }
            for f in &change.files {
                let flags = match (f.outside_items, f.position_only) {
                    (_, true) => " [position-only]",
                    (true, _) => " [outside-items]",
                    _ => "",
                };
                println!("{:?} {}{flags}", f.status, f.path);
                for i in &f.items {
                    let k = match i.kind {
                        ItemChangeKind::Added => "added",
                        ItemChangeKind::Removed => "removed",
                        ItemChangeKind::Body => "body",
                        ItemChangeKind::Signature => "signature",
                    };
                    println!(
                        "    {k:9} {} branches={} lines={}{}",
                        i.path,
                        i.branches,
                        i.lines_changed,
                        if i.is_test { " [test]" } else { "" }
                    );
                }
            }
            let all = change.files.iter().flat_map(|f| &f.items);
            let count = |k| all.clone().filter(|i| i.kind == k).count();
            println!(
                "files={} added={} removed={} body={} signature={} tests={} wall_ms={}",
                change.files.len(),
                count(ItemChangeKind::Added),
                count(ItemChangeKind::Removed),
                count(ItemChangeKind::Body),
                count(ItemChangeKind::Signature),
                all.filter(|i| i.is_test).count(),
                t.elapsed().as_millis()
            );
        }
        Cmd::Tests { index } => {
            let idx = CodeIndex::load(&index)?;
            for (n, _) in idx.tests() {
                println!("{}", idx.test_id(n));
            }
        }
    }
    Ok(())
}
