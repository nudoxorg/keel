//! `keel-reach analyze | compare | query | diff | list-tests`.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use keel_reach::report::{Change, diff};
use keel_reach::{BinaryReach, Loader, Options, analyze_record, compare, query, store};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser)]
#[command(
    version,
    about = "Per-test reach keys from the link inputs recorded by keel-linker"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// A small JSON header plus a zstd side file (`R.json` and `R.atoms`).
    Compact,
    /// The full JSON, readable with jq; hundreds of MB for a large binary.
    Json,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analyse one test binary from its `<exe>.keel-link.json`.
    Analyze {
        #[arg(long)]
        link_record: PathBuf,
        /// Crate name of the test binary (`-` and `_` are equivalent).
        #[arg(long)]
        crate_name: String,
        /// File with one nextest test name per line.
        #[arg(long)]
        tests: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "compact")]
        format: Format,
        /// Print the wall time of each phase to stderr.
        #[arg(long)]
        timings: bool,
        /// Keep parsed objects here, keyed by the blake3 of each object or archive member.
        #[arg(long)]
        cache: Option<PathBuf>,
        /// Do not print one line per test.
        #[arg(long)]
        quiet: bool,
        /// Key tests by the hash of every component they reach (the key before root hashes
        /// were used), to check that the two tell the same builds apart. Slower.
        #[arg(long)]
        closure_key: bool,
        /// Oracle aid: split Mach-O sections at symbols even in objects that do not allow it
        /// (the rule before MH_SUBSECTIONS_VIA_SYMBOLS was read). Unsound; for `compare` only.
        #[arg(long, hide = true)]
        oracle_assume_subsections: bool,
        /// Refuse the record if the output, a preserved object or an archive is not what the
        /// link left (records from a shim that does not hash its output are refused).
        #[arg(long)]
        verify_record: bool,
    },
    /// List every atom of a binary's inputs, reached or not, with its own content hashes and
    /// the Merkle hash of its reach (a `.zst` name writes it compressed).
    Atoms {
        #[arg(long)]
        link_record: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Crate name of the test binary, for its own objects.
        #[arg(long, default_value = "test")]
        crate_name: String,
        #[arg(long)]
        cache: Option<PathBuf>,
    },
    /// Compare two atom listings as multisets by their own content: what changed, split by
    /// class, crate and codegen unit, and how much of the rest is only propagation.
    Changed {
        a: PathBuf,
        b: PathBuf,
        /// Rows to show per breakdown.
        #[arg(long, default_value_t = 15)]
        top: usize,
        /// List this many of the text atoms with new bytes, by name.
        #[arg(long, default_value_t = 0)]
        names: usize,
    },
    /// Compare two reports test by test: key, fallback, and the atoms reached.
    Compare {
        a: PathBuf,
        b: PathBuf,
        /// Categories of difference that are expected and do not fail the command.
        #[arg(long, value_delimiter = ',')]
        allow: Vec<String>,
        /// Tests to show per category.
        #[arg(long, default_value_t = 8)]
        show: usize,
        /// The reports use different key formulas: require the same tests to share keys
        /// instead of equal keys.
        #[arg(long)]
        partition: bool,
        /// Identify atoms without the object file (codegen unit) they are in.
        #[arg(long)]
        ignore_member: bool,
    },
    /// Which tests reach an atom with a name that matches a regular expression.
    Query {
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        symbol_regex: String,
        /// Matching symbols to list after the table.
        #[arg(long, default_value_t = 5)]
        examples: usize,
        /// Print only tests whose reach matches or that fall back.
        #[arg(long)]
        only_must_run: bool,
        /// Match only the name each atom is known by, not the other names of merged functions.
        #[arg(long)]
        primary_only: bool,
    },
    /// Compare two reports' keys test by test (changed, same, fallback).
    Diff { before: PathBuf, after: PathBuf },
    /// Print the tests of an executable (`<exe> --list --format terse`).
    ListTests { executable: PathBuf },
}

fn read_report(p: &Path) -> Result<BinaryReach> {
    store::read(p)
}

/// Test names from `--list --format terse`; benchmarks are not tests.
pub fn list_tests(exe: &Path) -> Result<Vec<String>> {
    let out = Command::new(exe)
        .args(["--list", "--format", "terse"])
        .output()
        .with_context(|| {
            format!(
                "cannot run {}; is it a test executable for this machine?",
                exe.display()
            )
        })?;
    if !out.status.success() {
        bail!(
            "{} --list failed: {}",
            exe.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.strip_suffix(": test"))
        .map(str::to_string)
        .collect())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Analyze {
            link_record,
            crate_name,
            tests,
            out,
            format,
            timings,
            cache,
            quiet,
            closure_key,
            oracle_assume_subsections,
            verify_record,
        } => {
            let names: Vec<String> = std::fs::read_to_string(&tests)
                .with_context(|| {
                    format!(
                        "cannot read test list {}; pass a file with one test name per line",
                        tests.display()
                    )
                })?
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            let mut loader = match cache {
                Some(dir) => Loader::with_cache(dir)?,
                None => Loader::new(),
            };
            loader.assume_subsections = oracle_assume_subsections;
            let r = analyze_record(
                &loader,
                &link_record,
                &Options {
                    crate_name,
                    tests: names,
                    closure_key,
                    verify_record,
                },
            );
            // The objects (mapped from the cache) are not needed to print or write a report.
            drop(loader);
            if let Err(why) = &r.verifiable {
                eprintln!("unverifiable: {why}");
            }
            if !quiet {
                for (name, t) in &r.tests {
                    let n = t.atoms().len() + r.harness_atoms.len();
                    println!(
                        "{} {} {} {}",
                        t.key().map_or("-".repeat(64), |k| keel_reach::load::hex(k)),
                        n,
                        t.fallback()
                            .map_or("-".to_string(), |f| f.to_string().replace('\n', " ")),
                        name
                    );
                }
            }
            let s = &r.stats;
            println!(
                "stats: objects {} archives {} atoms {} relocations {} sccs {} reached {} parsed {} cached {} imports {} wall {} ms",
                s.objects,
                s.archives,
                s.atoms,
                s.relocations,
                s.sccs,
                s.reached_atoms,
                s.members_parsed,
                s.members_from_cache,
                r.unresolved_imports.len(),
                s.wall_ms
            );
            println!(
                "entries: {} from descriptors, {} from names only, {} none; ambiguous definitions {}",
                s.entries_from_descriptors,
                s.entries_from_names,
                r.missing_tests.len(),
                s.ambiguous_definitions
            );
            for (kind, n) in r.fallback_kinds() {
                println!("fallback {kind}: {n}");
            }
            let mut by_caller: Vec<_> = r.fallback_counts().into_iter().collect();
            by_caller.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            for ((kind, caller), n) in by_caller.iter().take(30) {
                println!("fallback {n:>5}  {kind:<12} {caller}");
            }
            for u in r.unkeyed_inputs.iter().take(8) {
                println!("unkeyed input: {u}");
            }
            if r.unkeyed_inputs.len() > 8 {
                println!("unkeyed input: ... {} more (all of them are in the report)", r.unkeyed_inputs.len() - 8);
            }
            for set in &r.section_sets {
                println!(
                    "section set {}: {} atoms, {} first reached through it; via {}",
                    set.section,
                    set.atoms,
                    set.first_reached_by_section,
                    set.symbols.join(", ")
                );
            }
            if timings {
                for t in &r.timings {
                    eprintln!("{:>8} ms  peak {:>5} MB  {}", t.ms, t.peak_rss_mb, t.span);
                }
            }
            for m in &r.missing_tests {
                eprintln!("no entry for test {m}");
            }
            for n in &r.notes {
                eprintln!("note: {n}");
            }
            if let Some(out) = out {
                match format {
                    Format::Json => {
                        let n = store::write_json(&r, &out)?;
                        eprintln!("wrote {} ({n} bytes)", out.display());
                    }
                    Format::Compact => {
                        let (h, side) = store::write_compact(&r, &out)?;
                        eprintln!(
                            "wrote {} ({h} bytes) and {} ({side} bytes)",
                            out.display(),
                            store::side_path(&out).display()
                        );
                    }
                }
            }
        }
        Cmd::Atoms {
            link_record,
            out,
            crate_name,
            cache,
        } => {
            let loader = match cache {
                Some(dir) => Loader::with_cache(dir)?,
                None => Loader::new(),
            };
            let rec = keel_reach::LinkInputs::from_record(&link_record)?;
            let rows = keel_reach::atoms::list(&loader, &rec, &crate_name.replace('-', "_"))?;
            keel_reach::atoms::write(&rows, &out)?;
            eprintln!("wrote {} atoms to {}", rows.len(), out.display());
        }
        Cmd::Changed { a, b, top, names } => {
            let (ra, rb) = (keel_reach::atoms::read(&a)?, keel_reach::atoms::read(&b)?);
            print!("{}", keel_reach::atoms::render_with(&keel_reach::atoms::changed(&ra, &rb), top, names));
        }
        Cmd::Compare { a, b, allow, show, partition, ignore_member } => {
            let (ra, rb) = (read_report(&a)?, read_report(&b)?);
            let c = compare::compare_with(&ra, &rb, compare::CompareOptions { partition, ignore_member });
            print!("{}", compare::render(&c, show));
            let bad = c.unexplained(&allow);
            if bad > 0 {
                bail!(
                    "{bad} differences are outside the allowed categories ({}); read the list above, or pass --allow for the ones you expect",
                    if allow.is_empty() { "none allowed".to_string() } else { allow.join(", ") }
                );
            }
        }
        Cmd::Query {
            report,
            symbol_regex,
            examples,
            only_must_run,
            primary_only,
        } => {
            let r = read_report(&report)?;
            let mut a = query::query(&r, &symbol_regex, primary_only)?;
            if only_must_run {
                let total = a.rows.len();
                a.rows.retain(|h| h.reaches || h.fallback.is_some());
                eprintln!("{} of {total} tests shown", a.rows.len());
            }
            print!("{}", query::render(&r, &a, examples));
        }
        Cmd::Diff { before, after } => {
            let (b, a) = (read_report(&before)?, read_report(&after)?);
            let d = diff(&b, &a);
            for (name, c) in &d.rows {
                println!(
                    "{} {}",
                    match c {
                        Change::Changed => "changed",
                        Change::Same => "same",
                        Change::Fallback => "fallback",
                    },
                    name
                );
            }
            println!(
                "{} tests, {} changed keys, {} same, {} fallback",
                d.rows.len(),
                d.changed,
                d.same,
                d.fallback
            );
        }
        Cmd::ListTests { executable } => {
            for t in list_tests(&executable)? {
                println!("{t}");
            }
        }
    }
    Ok(())
}
