//! Synthetic Cargo workspaces for BENCH.md section 2: `generate` them,
//! `mutate` them with exactly one change and a predicted set of test flips,
//! `summarize` what was generated.

mod generate;
mod model;
mod mutate;
mod rng;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write a new workspace.
    Generate(generate::GenerateArgs),
    /// Apply one change pattern and record the tests that must flip.
    Mutate {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long, value_enum)]
        pattern: mutate::Pattern,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Where to write the record (default <workspace>/mutation.json, which is
        /// also written when this is elsewhere, as the already-mutated marker).
        #[arg(long)]
        record: Option<PathBuf>,
        /// Mutate even though mutation.json exists (restore the tree first).
        #[arg(long)]
        force: bool,
    },
    /// Print crates, levels, edges, tests and binaries from synth.json.
    Summarize {
        #[arg(long)]
        workspace: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Generate(a) => generate::run(&a),
        Cmd::Mutate {
            workspace,
            pattern,
            seed,
            record,
            force,
        } => mutate::run(&mutate::Opts {
            workspace,
            pattern,
            seed,
            record,
            force,
        }),
        Cmd::Summarize { workspace } => summarize(&workspace),
    }
}

fn summarize(ws: &std::path::Path) -> Result<()> {
    let s = model::Synth::load(ws)?;
    let edges: usize = s.crates.iter().map(|c| c.deps.len()).sum();
    let bins: usize = s.crates.iter().map(|c| c.integration_bins).sum();
    let unit = s.tests.iter().filter(|t| t.kind == "unit").count();
    println!("params  {}", s.params);
    println!(
        "totals  crates {}  edges {}  tests {} (unit {}, integration {})  integration binaries {}",
        s.crates.len(),
        edges,
        s.tests.len(),
        unit,
        s.tests.len() - unit,
        bins
    );
    println!(
        "{:>5} {:>7} {:>6} {:>7} {:>5}",
        "level", "crates", "edges", "tests", "bins"
    );
    let depth = s.crates.iter().map(|c| c.level).max().map_or(0, |m| m + 1);
    for l in 0..depth {
        let cs: Vec<_> = s.crates.iter().filter(|c| c.level == l).collect();
        let tests: usize = cs.iter().map(|c| c.unit_tests + c.integration_tests).sum();
        println!(
            "{:>5} {:>7} {:>6} {:>7} {:>5}",
            l,
            cs.len(),
            cs.iter().map(|c| c.deps.len()).sum::<usize>(),
            tests,
            cs.iter().map(|c| c.integration_bins).sum::<usize>()
        );
    }
    Ok(())
}
