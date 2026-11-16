//! `keel`: the command-line tool around the Keel library (piece 6).
//!
//! Exit codes: 0 success, 2 usage or environment error (git, files, store),
//! 3 Stage 1 required, 4 an interaction has no covering node, 5 the audit found
//! an undeclared read, 6 the run is over its budget.

mod audit;
mod budget;
mod comment;
mod git;
mod interactions;
mod lexrule;
mod lockrule;
mod nixrule;
mod plan;
mod refresh;
mod store;
mod util;

#[cfg(test)]
mod plan_tests;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use keel::{Manifest, Report};

#[derive(Parser)]
#[command(
    name = "keel",
    version,
    about = "Keel: incremental, hierarchical testing"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Stage 0: decide from the diff alone whether every node is cached.
    Plan {
        /// The repository to run git in.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// The canonical tip the manifest was written for.
        #[arg(long)]
        base: String,
        /// The PR head.
        #[arg(long)]
        head: String,
        /// A node manifest to use instead of the store's; `<path>.sources.json` must sit beside it.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// A keel-store URL or directory. Required: a node is reported cached only
        /// from a pass this store returns for its key, never from the manifest alone.
        #[arg(long)]
        store: String,
        /// The sources sidecar, when the manifest does not come with one beside it.
        #[arg(long)]
        sources: Option<PathBuf>,
        /// Installable whose derivation must be unchanged for a Nix edit to be junk (repeatable).
        #[arg(long = "nix-check")]
        nix_check: Vec<String>,
        /// The lockfile a Nickel edit must leave unchanged once regenerated.
        #[arg(long = "nickel-lock", requires = "nickel_cmd")]
        nickel_lock: Option<String>,
        /// The command that regenerates the lockfile in place (run in a checkout of the merge result).
        #[arg(long = "nickel-cmd", requires = "nickel_lock")]
        nickel_cmd: Option<String>,
        /// Where to write report.json when everything is cached.
        #[arg(long, default_value = "report.json")]
        out: PathBuf,
    },
    /// List registered interactions with the number of nodes that cover them.
    Interactions {
        /// The node manifest: `joins` live there, not in the report.
        #[arg(long)]
        manifest: PathBuf,
        /// A run report; only nodes that passed in it count as covering.
        #[arg(long)]
        report: Option<PathBuf>,
        /// Registry files: fleet.lock.json, serving.json, env.json or a generic list.
        #[arg(long)]
        registry: Vec<PathBuf>,
        /// `cargo metadata --format-version 1` output.
        #[arg(long = "cargo-metadata")]
        cargo_metadata: Option<PathBuf>,
        /// Print the report's `interactions` array as JSON.
        #[arg(long)]
        json: bool,
        /// Exit 4 if any interaction has no covering node.
        #[arg(long = "require-covered")]
        require_covered: bool,
        #[arg(long, value_enum, default_value = "auto")]
        color: Color,
    },
    /// Fail when a run is over its time limit; print the critical path.
    Budget {
        #[arg(long)]
        report: PathBuf,
        /// For example `10m`.
        #[arg(long)]
        limit: String,
        /// The manifest, to compute a critical path when the report has none.
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
    /// List cached passes older than a window so the next run re-executes them.
    Refresh {
        #[arg(long)]
        store: String,
        /// For example `7d`.
        #[arg(long = "older-than")]
        older_than: String,
        #[arg(long)]
        report: PathBuf,
        /// The file for `--keel-force`; stdout when absent.
        #[arg(long)]
        out: Option<PathBuf>,
        /// RFC 3339 "now", for reproducible runs.
        #[arg(long)]
        now: Option<String>,
    },
    /// Run tests under strace and report reads outside the declared inputs (Linux).
    Audit {
        /// A built libtest binary.
        #[arg(long)]
        exe: PathBuf,
        /// A file of input globs, one per line, relative to the package directory.
        #[arg(long)]
        declared: PathBuf,
        /// Audit only the tests this report has nodes for.
        #[arg(long)]
        report: Option<PathBuf>,
        #[arg(long = "package-dir", default_value = ".")]
        package_dir: PathBuf,
        /// The workspace root `inputs` globs are relative to; defaults to the package directory.
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        sysroot: Option<String>,
        /// Extra directories a test may read (repeatable).
        #[arg(long)]
        allow: Vec<String>,
        /// Ambient environment variables the test may see (repeatable).
        #[arg(long)]
        env: Vec<String>,
    },
    /// Render a PR comment from a run report.
    Comment {
        #[arg(long)]
        report: PathBuf,
        /// Earlier reports, for flake history (repeatable).
        #[arg(long)]
        previous: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        /// Where evidence blobs live; without it the comment omits stderr.
        #[arg(long)]
        store: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Color {
    Auto,
    Always,
    Never,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read the {what} {}; check the path", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("{} is not a valid {what}", path.display()))
}

fn parse_window(s: &str, flag: &str) -> Result<u64> {
    let d = humantime::parse_duration(s).with_context(|| {
        format!("{flag} {s} is not a duration; write something like 10m, 90s or 7d")
    })?;
    Ok(d.as_millis() as u64)
}

fn run(cli: Cli) -> Result<u8> {
    match cli.cmd {
        Cmd::Plan {
            repo,
            base,
            head,
            manifest,
            store,
            sources,
            nix_check,
            nickel_lock,
            nickel_cmd,
            out,
        } => {
            let opts = plan::Options {
                nix_checks: nix_check,
                nickel: nickel_lock.zip(nickel_cmd),
            };
            let passes = store::Store::open(&store)?;
            let (manifest, sources) = match manifest {
                Some(path) => {
                    let m = plan::read_manifest(&path)?;
                    let mut side = path.clone().into_os_string();
                    side.push(".sources.json");
                    let s = sources.unwrap_or_else(|| PathBuf::from(&side));
                    (Ok(m), plan::read_sources(&s))
                }
                None => {
                    let rev = git::Git::new(&repo).rev_parse_commit(&base)?;
                    let m = passes
                        .manifest(&rev)?
                        .ok_or_else(|| format!("{store} has no manifest for {rev}"));
                    let s = match sources {
                        Some(p) => plan::read_sources(&p),
                        None => Err("with --store the sources sidecar must be passed as --sources <file> (the store does not hold it yet)".to_owned()),
                    };
                    (m, s)
                }
            };
            match plan::plan(&repo, &base, &head, manifest, sources, &opts, &passes)? {
                plan::Outcome::Cached { report, accepted } => {
                    for (path, rule) in &accepted {
                        println!("accepted {path} by rule {rule}");
                    }
                    std::fs::write(&out, serde_json::to_string_pretty(&*report)?).with_context(
                        || {
                            format!(
                                "cannot write {}; check the directory exists and is writable",
                                out.display()
                            )
                        },
                    )?;
                    println!(
                        "stage 0: all {} nodes cached in {} ms; wrote {}",
                        report.nodes.len(),
                        report.stages.map_or(0, |s| s.stage0_ms),
                        out.display()
                    );
                    Ok(0)
                }
                plan::Outcome::Stage1(reasons) => {
                    eprintln!(
                        "keel: Stage 1 required ({} reason{})",
                        reasons.len(),
                        if reasons.len() == 1 { "" } else { "s" }
                    );
                    for r in reasons.iter().take(10) {
                        println!("{r}");
                    }
                    if reasons.len() > 10 {
                        eprintln!("... and {} more", reasons.len() - 10);
                    }
                    Ok(3)
                }
            }
        }
        Cmd::Interactions {
            manifest,
            report,
            registry,
            cargo_metadata,
            json,
            require_covered,
            color,
        } => {
            let manifest: Manifest = read_json(&manifest, "node manifest")?;
            let report: Option<Report> = report.map(|p| read_json(&p, "run report")).transpose()?;
            let mut regs = Vec::new();
            if let Some(p) = cargo_metadata {
                regs.extend(interactions::from_cargo_metadata(&read_json(
                    &p,
                    "cargo metadata file",
                )?)?);
            }
            for p in &registry {
                regs.extend(interactions::from_registry(
                    &read_json(p, "registry file")?,
                    &p.display().to_string(),
                )?);
            }
            if regs.is_empty() {
                bail!(
                    "no interactions registered; pass --cargo-metadata <json> and/or --registry <file>"
                );
            }
            let rows = interactions::sorted(interactions::cover(regs, &manifest, report.as_ref()));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&interactions::to_json(&rows))?
                );
            } else {
                let on = match color {
                    Color::Always => true,
                    Color::Never => false,
                    Color::Auto => std::io::stdout().is_terminal(),
                };
                print!("{}", interactions::render(&rows, on));
            }
            Ok(if require_covered && rows.iter().any(|r| r.nodes == 0) {
                4
            } else {
                0
            })
        }
        Cmd::Budget {
            report,
            limit,
            manifest,
        } => {
            let limit_ms = parse_window(&limit, "--limit")?;
            let report: Report = read_json(&report, "run report")?;
            let manifest: Option<Manifest> = manifest
                .map(|p| read_json(&p, "node manifest"))
                .transpose()?;
            let s = budget::summarise(&report, manifest.as_ref())?;
            print!("{}", budget::render(&s, limit_ms));
            match budget::over_limit(&s, limit_ms) {
                Some(why) => {
                    eprintln!("keel: over budget: {why}");
                    Ok(6)
                }
                None => Ok(0),
            }
        }
        Cmd::Refresh {
            store,
            older_than,
            report,
            out,
            now,
        } => {
            let window = (parse_window(&older_than, "--older-than")? / 1000) as i64;
            let now = match now {
                Some(t) => util::parse_rfc3339(&t).with_context(|| {
                    format!("--now {t} is not an RFC 3339 time like 2026-11-14T08:12:03Z")
                })?,
                None => util::now_secs(),
            };
            let report: Report = read_json(&report, "run report")?;
            let stale = refresh::stale(&store::Store::open(&store)?, &report, window, now)?;
            let text = refresh::force_file(&stale);
            match out {
                Some(p) => std::fs::write(&p, &text)
                    .with_context(|| format!("cannot write {}", p.display()))?,
                None => print!("{text}"),
            }
            let oldest = stale
                .iter()
                .max_by_key(|s| s.age_secs)
                .map_or_else(String::new, |s| {
                    format!(
                        "; oldest is {} from run {} ({} days)",
                        s.id,
                        s.run_id,
                        s.age_secs.min(i64::from(i32::MAX)) / 86_400
                    )
                });
            eprintln!(
                "keel: {} cached pass{} older than {older_than}{oldest}",
                stale.len(),
                if stale.len() == 1 { "" } else { "es" }
            );
            Ok(0)
        }
        Cmd::Audit {
            exe,
            declared,
            report,
            package_dir,
            root,
            sysroot,
            allow,
            env,
        } => {
            if !cfg!(target_os = "linux") {
                println!(
                    "keel audit needs Linux (strace); nothing was audited on this platform, which is not a failure"
                );
                return Ok(0);
            }
            let declared_text = std::fs::read_to_string(&declared).with_context(|| {
                format!(
                    "cannot read --declared {}; pass a file of input globs, one per line",
                    declared.display()
                )
            })?;
            let only = report
                .map(|p| read_json::<Report>(&p, "run report"))
                .transpose()?
                .map(|r| r.nodes.iter().map(|n| n.id.to_string()).collect());
            let root = root.unwrap_or_else(|| package_dir.clone());
            let cfg = audit::Config {
                exe,
                package_dir,
                declared: audit::read_declared(&declared_text),
                extra_allow: allow,
                sysroot,
                env_allow: env,
                only,
            };
            let (n, found) = audit::run(&cfg)?;
            let root_s = root
                .canonicalize()
                .unwrap_or(root)
                .to_string_lossy()
                .into_owned();
            let pkg_s = cfg
                .package_dir
                .canonicalize()
                .unwrap_or_else(|_| cfg.package_dir.clone())
                .to_string_lossy()
                .into_owned();
            let a = audit::Allow::new(&pkg_s, vec![], &[])?;
            for (test, accesses) in &found {
                for x in accesses {
                    println!(
                        "test {test}: reads {} ({}) outside the declared inputs; add {} to its package's inputs, or stop reading it",
                        x.path,
                        x.kind,
                        a.suggestion(&root_s, &x.path)
                    );
                }
            }
            if found.is_empty() {
                println!("audit clean: {n} tests read nothing undeclared");
                Ok(0)
            } else {
                eprintln!(
                    "keel: audit failed: {} of {n} tests read undeclared files",
                    found.len()
                );
                Ok(5)
            }
        }
        Cmd::Comment {
            report,
            previous,
            out,
            store,
        } => {
            let report: Report = read_json(&report, "run report")?;
            let previous: Vec<Report> = previous
                .iter()
                .map(|p| read_json(p, "earlier run report"))
                .collect::<Result<_>>()?;
            let store = store.as_deref().map(store::Store::open).transpose()?;
            let warned = std::cell::Cell::new(false);
            let blob = |d: &keel::Digest| -> Option<String> {
                match store.as_ref()?.blob(d) {
                    Ok(b) => b.map(|b| String::from_utf8_lossy(&b).into_owned()),
                    Err(e) => {
                        if !warned.replace(true) {
                            eprintln!(
                                "keel: warning: evidence is unavailable ({e:#}); the comment omits stderr"
                            );
                        }
                        None
                    }
                }
            };
            let text = comment::render(&report, &previous, &blob);
            std::fs::write(&out, text).with_context(|| {
                format!("cannot write {}; check the directory exists", out.display())
            })?;
            Ok(0)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("keel: error: {e:#}");
            ExitCode::from(2)
        }
    }
}
