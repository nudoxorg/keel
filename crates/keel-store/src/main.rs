//! `keel-store serve`, `conduct`, `gc` and `validate-job`.

use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use keel_store::conduct;
use keel_store::gc::{self, Policy};
use keel_store::job;
use keel_store::server::{self, Config, Limits};

#[derive(Parser)]
#[command(version, about = "Keel result-store service (DESIGN §6)")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the store over HTTP. The writer token is read from the file
    /// named by KEEL_STORE_TOKEN_FILE, never from an argument.
    Serve {
        /// The store directory (created if missing).
        #[arg(long)]
        dir: PathBuf,
        /// Address to bind, e.g. 192.0.2.1:4817. Without it the service
        /// binds 127.0.0.1 on the port in KEEL_STORE_PORT, or an ephemeral
        /// port if that is unset.
        #[arg(long)]
        listen: Option<SocketAddr>,
    },
    /// The conductor: starts jobs on behalf of pipelines (HTTP skeleton).
    /// Needs a systemd to talk to; it never clones or runs cargo itself.
    Conduct {
        /// Address to bind, the CI bridge address and the conductor's port.
        #[arg(long)]
        listen: SocketAddr,
        /// Where `<job>.env` files are written (/ci/keel/jobs).
        #[arg(long)]
        jobs_dir: PathBuf,
        /// Job output directory (/ci/keel/out); read by later steps, checked at start.
        #[arg(long)]
        out_dir: PathBuf,
        /// The writer token file (the conductor is the only writer to the store).
        #[arg(long)]
        token_file: PathBuf,
        /// JSON map of blake3(pipeline token) to {repo, kinds}.
        #[arg(long)]
        pipeline_tokens_file: PathBuf,
        /// A repo jobs may be for; repeat for each.
        #[arg(long = "repo")]
        repos: Vec<String>,
        /// `phase=/nix/store/…` for fetch, build and test; the program is run as
        /// `<program> <phase> <job> <repo> <revision> <slot>` inside the unit.
        #[arg(long = "program")]
        programs: Vec<String>,
        /// PR slots per lane.
        #[arg(long, default_value_t = 3)]
        slots: u32,
    },
    /// Check a job instance name (the unit's `%i`) and, with --env-file, the
    /// env file the conductor wrote for it. Run by `ExecStartPre` in the
    /// keel-build@ and keel-test@ units; exits non-zero on anything unexpected.
    ValidateJob {
        /// The instance name, escaped form (`%i`, never `%I`).
        name: String,
        /// The job's env file; only KEEL_PROGRAM and KEEL_ARGS are allowed.
        #[arg(long)]
        env_file: Option<PathBuf>,
    },
    /// Remove expired records and unreferenced blobs.
    Gc {
        /// The store directory.
        #[arg(long)]
        dir: PathBuf,
        /// How long `pass` records are kept, by recorded_at (30d, 12h, 2w).
        #[arg(long, default_value = "30d")]
        keep_pass: String,
        /// How long every other status is kept.
        #[arg(long, default_value = "90d")]
        keep_fail: String,
        /// Free space, in GiB, that must remain after pruning; exits 2 if not.
        #[arg(long, default_value_t = 80)]
        reserve_gib: u64,
        /// Blobs younger than this are never removed (a run may not have
        /// written the record that names them yet).
        #[arg(long, default_value = "1d")]
        blob_grace: String,
        /// Print what would be removed and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("keel-store: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Cmd::Serve { dir, listen } => serve(dir, listen).map(|()| ExitCode::SUCCESS),
        Cmd::Conduct {
            listen,
            jobs_dir,
            out_dir,
            token_file,
            pipeline_tokens_file,
            repos,
            programs,
            slots,
        } => conduct(
            listen,
            jobs_dir,
            out_dir,
            token_file,
            pipeline_tokens_file,
            repos,
            programs,
            slots,
        )
        .map(|()| ExitCode::SUCCESS),
        Cmd::ValidateJob { name, env_file } => {
            job::validate_name(&name)?;
            if let Some(path) = env_file {
                let text = std::fs::read_to_string(&path).with_context(|| {
                    format!("cannot read the job env file {}; the conductor must write it before starting the job", path.display())
                })?;
                job::validate_env_file(&text)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Gc {
            dir,
            keep_pass,
            keep_fail,
            reserve_gib,
            blob_grace,
            dry_run,
        } => {
            let dur = |flag: &str, v: &str| {
                gc::parse_duration(v).map_err(|e| anyhow::anyhow!("--{flag}: {e}"))
            };
            let policy = Policy {
                keep_pass: dur("keep-pass", &keep_pass)?,
                keep_fail: dur("keep-fail", &keep_fail)?,
                blob_grace: dur("blob-grace", &blob_grace)?,
                reserve_bytes: reserve_gib.saturating_mul(1 << 30),
            };
            let out = gc::run(&dir, &policy, gc::now(), dry_run)?;
            let verb = if dry_run { "would remove" } else { "removed" };
            for a in &out.actions {
                println!(
                    "{}",
                    if dry_run {
                        format!("would {a}")
                    } else {
                        a.clone()
                    }
                );
            }
            for w in &out.warnings {
                eprintln!("keel-store: warning: {w}");
            }
            println!(
                "{verb}: {} record lines ({} files), {} index entries, {} blobs ({} bytes); free {:.1} GiB, about {:.1} GiB after",
                out.records,
                out.record_files,
                out.index_entries,
                out.blobs,
                out.bytes_freed,
                out.free_before as f64 / (1u64 << 30) as f64,
                out.free_after as f64 / (1u64 << 30) as f64,
            );
            if out.below_reserve(&policy) {
                eprintln!(
                    "keel-store: free space is below the {reserve_gib} GiB reserve even after retention; shorten --keep-pass/--keep-fail, evict checkout slots, or add disk"
                );
                return Ok(ExitCode::from(2));
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn serve(dir: PathBuf, listen: Option<SocketAddr>) -> anyhow::Result<()> {
    let token = secret_from_env("KEEL_STORE_TOKEN_FILE", "writer")?;
    // Reads need a token too (DESIGN §6): without one every task on the
    // bridge could read every stored stdout and stderr.
    let read_token = secret_from_env("KEEL_STORE_READ_TOKEN_FILE", "read")?;
    let addr = match listen {
        Some(a) => a,
        None => {
            // DESIGN §6: the port comes from the fleet model via the
            // environment and is never baked into a binary.
            let port = match std::env::var("KEEL_STORE_PORT") {
                Ok(p) => p.parse::<u16>().with_context(|| {
                    format!("KEEL_STORE_PORT=`{p}` is not a port number (0-65535)")
                })?,
                Err(_) => 0,
            };
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        }
    };
    let config = Config {
        dir,
        token,
        read_token: Some(read_token),
        limits: Limits::default(),
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| {
            format!("cannot listen on {addr}; check the address exists on this host (the bridge may not be up yet) and the port is free")
        })?;
        let app = server::router(&config)?;
        eprintln!(
            "keel-store: listening on {} dir={}",
            listener.local_addr()?,
            config.dir.display()
        );
        server::serve(listener, app, std::future::pending()).await
    })?;
    Ok(())
}

/// Reads a secret from the file named by environment variable `var`. Only the
/// file name travels in the environment, never the secret.
fn secret_from_env(var: &str, what: &str) -> anyhow::Result<String> {
    let file = std::env::var_os(var).with_context(|| {
        format!("{var} is not set; point it at a file holding the {what} token (only the file name goes in the environment, never the token)")
    })?;
    read_secret(std::path::Path::new(&file), what)
}

fn read_secret(file: &std::path::Path, what: &str) -> anyhow::Result<String> {
    let token = std::fs::read_to_string(file).with_context(|| {
        format!("cannot read the {what} token file {file:?}; check the path and that this user may read it")
    })?;
    let token = token.trim().to_owned();
    if token.len() < 16 {
        bail!(
            "the {what} token in {file:?} is shorter than 16 characters; generate a longer random token"
        );
    }
    // Group access is intended (keel-token); access for anyone else is not.
    if let Ok(meta) = std::fs::metadata(file)
        && meta.permissions().mode() & 0o007 != 0
    {
        eprintln!(
            "keel-store: warning: {file:?} is readable by everyone; restrict it to its group"
        );
    }
    Ok(token)
}

#[allow(clippy::too_many_arguments)]
fn conduct(
    listen: SocketAddr,
    jobs_dir: PathBuf,
    out_dir: PathBuf,
    token_file: PathBuf,
    pipeline_tokens_file: PathBuf,
    repos: Vec<String>,
    programs: Vec<String>,
    slots: u32,
) -> anyhow::Result<()> {
    // Held for the record writes the next step adds; reading it now proves
    // the unit can, and that the file is not empty, before accepting work.
    let _writer = read_secret(&token_file, "writer")?;
    for dir in [&jobs_dir, &out_dir] {
        if !dir.is_dir() {
            bail!(
                "{} is not a directory; the host module creates it",
                dir.display()
            );
        }
    }
    let grants = conduct::parse_grants(&std::fs::read_to_string(&pipeline_tokens_file).with_context(|| {
        format!("cannot read the pipeline tokens file {pipeline_tokens_file:?}; check the path and that this user may read it")
    })?)
    .map_err(anyhow::Error::msg)?;
    let programs = programs
        .iter()
        .map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .with_context(|| format!("--program `{p}` must look like fetch=/nix/store/…"))
        })
        .collect::<anyhow::Result<_>>()?;
    let app = conduct::router(conduct::Config {
        jobs_dir,
        repos,
        programs,
        slots,
        grants,
        units: std::sync::Arc::new(conduct::Systemd),
    })
    .map_err(anyhow::Error::msg)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| {
            format!("cannot listen on {listen}; check the address exists on this host (the bridge may not be up yet) and the port is free")
        })?;
        eprintln!("keel-store: conductor listening on {}", listener.local_addr()?);
        server::serve(listener, app, std::future::pending()).await
    })
}
