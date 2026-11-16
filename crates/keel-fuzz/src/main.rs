use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use keel_fuzz::events::EventLog;
use keel_fuzz::ops::{self, CminOptions, CoverageOptions, ReplayOptions, Session, TminOptions};
use keel_fuzz::target::ensure_runtime_preloaded;

#[derive(Parser)]
#[command(name = "keel-fuzz", version, about = "Gate-mode replay and idle-mode exploration of libFuzzer-ABI targets (engine: LibAFL)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Common {
    /// The fuzz target: a shared library exporting LLVMFuzzerTestOneInput, built by bench/fuzz/build-target.nu.
    #[arg(long)]
    target: PathBuf,
    /// Append JSON-lines events to this file as they happen.
    #[arg(long)]
    json: Option<PathBuf>,
}

fn duration(s: &str) -> Result<Duration, humantime::DurationError> {
    humantime::parse_duration(s)
}

#[derive(Subcommand)]
enum Command {
    /// Idle mode: mutate for a time budget with a recorded seed; new coverage goes to the corpus, crashes are minimised and deduplicated.
    Explore {
        #[command(flatten)]
        common: Common,
        /// Content-addressed corpus store (created if absent). Existing inputs are the starting set.
        #[arg(long)]
        corpus: PathBuf,
        /// Output directory for crashes: raw/, minimised/ and crashes.json.
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_parser = duration, default_value = "10s")]
        time: Duration,
        /// Recorded seed; the same seed on the same target and corpus repeats the mutation sequence.
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Largest input the mutators may produce.
        #[arg(long, default_value_t = 4096)]
        max_len: usize,
        /// libFuzzer-format dictionary (as in backend/tests/fuzz/targets/*/dictionary.txt).
        #[arg(long)]
        dict: Option<PathBuf>,
        #[arg(long, value_parser = duration, default_value = "5s")]
        exec_timeout: Duration,
        /// Stop after this many distinct crash inputs (0 = never).
        #[arg(long, default_value_t = 0)]
        stop_after_crashes: usize,
        /// Disable cmplog (input-to-state) mutations; for measuring what they contribute.
        #[arg(long)]
        no_cmplog: bool,
    },
    /// Gate mode: run every corpus input exactly once, deterministically; the verdict is cacheable.
    Replay {
        #[command(flatten)]
        common: Common,
        /// A corpus store, a directory of inputs, or one input file.
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long, value_parser = duration, default_value = "5s")]
        timeout: Duration,
        /// Fail the gate as incomplete if the whole replay takes longer than this.
        #[arg(long, value_parser = duration, default_value = "5m")]
        max_total: Duration,
        /// Directory of verdicts keyed by (target binary, corpus content).
        #[arg(long)]
        cache_dir: Option<PathBuf>,
    },
    /// Minimise a corpus to the smallest subset with the same edge coverage.
    Cmin {
        #[command(flatten)]
        common: Common,
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_parser = duration, default_value = "5s")]
        timeout: Duration,
    },
    /// Minimise one crashing input, keeping the same crash.
    Tmin {
        #[command(flatten)]
        common: Common,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_parser = duration, default_value = "5s")]
        timeout: Duration,
        #[arg(long, default_value_t = 20000)]
        max_trials: usize,
    },
    /// Print the functions an input (or every input of a corpus) executes, by language.
    Coverage {
        #[command(flatten)]
        common: Common,
        /// An input file, a corpus store, or a directory of inputs.
        input: PathBuf,
        #[arg(long, value_parser = duration, default_value = "5s")]
        timeout: Duration,
    },
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let (common, run): (&Common, Box<dyn FnOnce(&Session, &EventLog) -> Result<ExitCode>>) = match &cli.command {
        Command::Replay { common, corpus, timeout, max_total, cache_dir } => {
            let opts = ReplayOptions { corpus: corpus.clone(), timeout: *timeout, max_total: *max_total, cache_dir: cache_dir.clone() };
            (common, Box::new(move |s, log| {
                let r = ops::replay(s, &opts, log)?;
                println!("replay: {}{}", if r.pass { "pass" } else { "FAIL" }, if r.cache_hit { " (cached verdict)" } else { "" });
                Ok(if r.pass { ExitCode::SUCCESS } else { ExitCode::from(1) })
            }))
        }
        Command::Cmin { common, corpus, out, timeout } => {
            let opts = CminOptions { corpus: corpus.clone(), out: out.clone(), timeout: *timeout };
            (common, Box::new(move |s, log| ops::cmin(s, &opts, log).map(|_| ExitCode::SUCCESS)))
        }
        Command::Tmin { common, input, out, timeout, max_trials } => {
            let opts = TminOptions { input: input.clone(), out: out.clone(), timeout: *timeout, max_trials: *max_trials };
            (common, Box::new(move |s, log| ops::tmin(s, &opts, log).map(|_| ExitCode::SUCCESS)))
        }
        Command::Coverage { common, input, timeout } => {
            let opts = CoverageOptions { input: input.clone(), timeout: *timeout };
            (common, Box::new(move |s, log| ops::coverage(s, &opts, log, false).map(|_| ExitCode::SUCCESS)))
        }
        Command::Explore { common, corpus, out, time, seed, max_len, dict, exec_timeout, stop_after_crashes, no_cmplog } => {
            let opts = keel_fuzz::explore::ExploreOptions {
                corpus: corpus.clone(),
                out: out.clone(),
                time: *time,
                seed: *seed,
                max_len: *max_len,
                dict: dict.clone(),
                exec_timeout: *exec_timeout,
                stop_after_crashes: *stop_after_crashes,
                cmplog: !*no_cmplog,
            };
            (common, Box::new(move |s, log| keel_fuzz::explore::explore(s, &opts, log).map(|_| ExitCode::SUCCESS)))
        }
    };
    ensure_runtime_preloaded(&common.target)?;
    let log = EventLog::open(common.json.as_deref())?;
    let session = Session::load(&common.target).with_context(|| format!("loading the target {}", common.target.display()))?;
    run(&session, &log)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("keel-fuzz: error: {e:#}");
            ExitCode::from(2)
        }
    }
}
