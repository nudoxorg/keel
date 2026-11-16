//! `keel-conduct`: run, merge, attest, verify.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use keel::{Report, Upstream, Verdict};
use keel_conduct::attest::{self, AttestArgs, VerifyArgs};
use keel_conduct::config::Config;
use keel_conduct::pins::Pins;
use keel_conduct::run::{self, RunOpts};
use keel_conduct::store::Store;

#[derive(Parser)]
#[command(
    name = "keel-conduct",
    version,
    about = "Keel conductor: non-Rust nodes, cross-repo reports, attestations"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Plan from every source, run what the store cannot answer, write the report.
    Run {
        /// keel.toml.
        #[arg(long)]
        config: PathBuf,
        /// `http://host:port` of keel-store, or a directory.
        #[arg(long)]
        store: String,
        /// Where to write report.json.
        #[arg(long)]
        report: PathBuf,
        /// Pins of other repositories, `{"owner/repo": "revision"}`.
        #[arg(long)]
        pins: Option<PathBuf>,
        /// A report of another repository this run stands on (repeatable); needs --pins.
        #[arg(long)]
        upstream: Vec<PathBuf>,
        /// The checkout; defaults to the config's directory.
        #[arg(long)]
        repo_root: Option<PathBuf>,
        /// The revision certified; defaults to `git rev-parse HEAD`.
        #[arg(long)]
        revision: Option<String>,
        /// The go binary (default: `go` on PATH).
        #[arg(long)]
        go: Option<PathBuf>,
        /// Nodes run in parallel.
        #[arg(long, default_value_t = 4)]
        jobs: usize,
        /// Run nodes whose upstream failed anyway.
        #[arg(long)]
        no_block: bool,
        /// Scratch directory (kept); default is a temporary one.
        #[arg(long)]
        work_dir: Option<PathBuf>,
        /// Also write the manifest of planned nodes (needed to attest groups).
        #[arg(long)]
        manifest_out: Option<PathBuf>,
    },
    /// Print the plan (nodes, keys, edges) without running anything.
    Plan {
        /// keel.toml.
        #[arg(long)]
        config: PathBuf,
        /// The checkout; defaults to the config's directory.
        #[arg(long)]
        repo_root: Option<PathBuf>,
        /// The go binary.
        #[arg(long)]
        go: Option<PathBuf>,
    },
    /// Combine reports of several runners; roots and verdict are re-derived.
    Merge {
        /// The reports.
        #[arg(required = true)]
        reports: Vec<PathBuf>,
        /// Output file.
        #[arg(long)]
        out: PathBuf,
        /// Each report must be the run of its repository's pinned revision.
        #[arg(long)]
        pins: Option<PathBuf>,
    },
    /// Sign a report as evidence that a policy holds.
    Attest {
        /// The report.
        #[arg(long)]
        report: PathBuf,
        /// Secret key file (from `keygen`).
        #[arg(long)]
        key: PathBuf,
        /// Policy file (`name`, `require`).
        #[arg(long)]
        policy: PathBuf,
        /// Manifest of the run, when the policy names groups.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Output file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Check an attestation offline; exit 0 only if every check holds.
    Verify {
        /// The attestation.
        #[arg(long)]
        attestation: PathBuf,
        /// The report it covers.
        #[arg(long)]
        report: PathBuf,
        /// The trusted public key file.
        #[arg(long)]
        public_key: PathBuf,
        /// The policy name the deploy requires.
        #[arg(long)]
        require_policy: String,
        /// The revision being deployed.
        #[arg(long)]
        revision: Option<String>,
        /// The policy file, to check it is the one that was attested.
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Write a new Ed25519 key pair.
    Keygen {
        /// Secret key file (must not exist).
        #[arg(long)]
        secret: PathBuf,
        /// Public key file.
        #[arg(long)]
        public: PathBuf,
    },
}

fn repo_root_of(config: &Path, given: Option<PathBuf>) -> PathBuf {
    given.unwrap_or_else(|| {
        config
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    })
}

fn read_report(path: &Path) -> Result<Report> {
    serde_json::from_slice(
        &std::fs::read(path)
            .with_context(|| format!("cannot read the report {}", path.display()))?,
    )
    .with_context(|| format!("{} is not a keel run report (DESIGN §8.2)", path.display()))
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    std::fs::write(path, text).with_context(|| {
        format!(
            "cannot write {}; check the directory exists",
            path.display()
        )
    })
}

fn main() -> ExitCode {
    match real_main(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("keel-conduct: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn real_main(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Cmd::Run {
            config,
            store,
            report,
            pins,
            upstream,
            repo_root,
            revision,
            go,
            jobs,
            no_block,
            work_dir,
            manifest_out,
        } => {
            let cfg = Config::load(&config)?;
            let repo_root = repo_root_of(&config, repo_root);
            let revision = match revision {
                Some(r) => r,
                None => run::git_revision(&repo_root)?,
            };
            let upstream = upstream
                .iter()
                .map(|p| read_report(p))
                .collect::<Result<Vec<_>>>()?;
            let pins = pins.as_deref().map(Pins::load).transpose()?;
            let store = Store::open(&store)?;
            let out = run::run(
                &cfg,
                &store,
                &RunOpts {
                    repo_root,
                    revision,
                    jobs,
                    no_block,
                    go,
                    work_dir,
                    upstream,
                    pins,
                },
            )?;
            write_json(&report, &out.report)?;
            if let Some(m) = manifest_out {
                write_json(&m, &out.manifest)?;
            }
            match store.publish_report(&out.report) {
                Ok(_) => {}
                Err(e) => eprintln!(
                    "keel-conduct: warning: the report was not published to the store index: {e}"
                ),
            }
            println!("{}", run::summary(&out.report));
            Ok(if out.report.verdict == Verdict::Pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Cmd::Plan {
            config,
            repo_root,
            go,
        } => {
            let cfg = Config::load(&config)?;
            let planned = run::plan_all(&cfg, &repo_root_of(&config, repo_root), go.as_deref())?;
            let edges: usize = planned.iter().map(|p| p.node.stands_on.len()).sum();
            println!("nodes {}  edges {edges}", planned.len());
            for p in &planned {
                println!("{}  {}", p.node.id, p.node.key);
                for up in &p.node.stands_on {
                    let kind = if matches!(up, Upstream::Group(_)) {
                        "group"
                    } else {
                        "node"
                    };
                    println!("    stands_on {kind} {up}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Merge { reports, out, pins } => {
            let pins = pins.as_deref().map(Pins::load).transpose()?;
            let mut loaded = Vec::new();
            for p in &reports {
                let r = read_report(p)?;
                if let Some(pins) = &pins {
                    pins.check(&r, &p.display().to_string(), false)?;
                }
                loaded.push(r);
            }
            let merged = Report::merge(loaded).map_err(|e| anyhow::anyhow!("{e}"))?;
            write_json(&out, &merged)?;
            println!("{}", run::summary(&merged));
            Ok(if merged.verdict == Verdict::Pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Cmd::Attest {
            report,
            key,
            policy,
            manifest,
            out,
        } => {
            let att = attest::attest(&AttestArgs {
                report: &report,
                key: &key,
                policy: &policy,
                manifest: manifest.as_deref(),
            })?;
            write_json(&out, &att)?;
            println!(
                "keel-conduct: attested {} at {} under policy `{}` ({} nodes green) -> {}",
                att.repo,
                att.revision,
                att.policy.name,
                att.nodes_green,
                out.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Verify {
            attestation,
            report,
            public_key,
            require_policy,
            revision,
            policy,
        } => {
            match attest::verify(&VerifyArgs {
                attestation: &attestation,
                report: &report,
                public_key: &public_key,
                require_policy: &require_policy,
                revision: revision.as_deref(),
                policy: policy.as_deref(),
            }) {
                Ok(att) => {
                    println!(
                        "keel-conduct: verified: {} at {} is green under policy `{}`",
                        att.repo, att.revision, att.policy.name
                    );
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("keel-conduct: {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        Cmd::Keygen { secret, public } => {
            attest::keygen(&secret, &public)?;
            println!(
                "keel-conduct: wrote {} (keep private) and {}",
                secret.display(),
                public.display()
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}
