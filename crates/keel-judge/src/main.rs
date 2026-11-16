use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Parser};

use keel_judge::expect;
use keel_judge::metrics;
use keel_judge::run::{RunConfig, run};
use keel_judge::state::State;
use keel_judge::status;
use keel_judge::targets::{self, DEFAULT_DURABLE_ROOT, TargetsFile};

#[derive(Parser)]
#[command(name = "keel-judge", version, about = "Idle-loop supervisor: keeps libFuzzer targets running in quanta, chosen by an index, and records what it sees")]
enum Cmd {
    /// Record the typed executable-check evidence in a tree verdict.
    RecordChecks {
        #[arg(long)] tree_verdict: PathBuf,
        #[arg(long)] state: PathBuf,
    },
    /// Order every harness case using captured NuDox observations.
    Guidance {
        #[arg(long)] manifest: PathBuf,
        #[arg(long)] inputs: PathBuf,
        #[arg(short, long)] output: Option<PathBuf>,
    },
    /// Convert a continuous-fuzz bundle's metadata.json into a targets file.
    Targets {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long, default_value = DEFAULT_DURABLE_ROOT)]
        durable_root: String,
        /// Write here instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Run the loop until stopped (SIGTERM or SIGINT) or --quanta quanta have finished.
    Run {
        #[arg(long)]
        targets: PathBuf,
        #[arg(long)]
        state: PathBuf,
        #[arg(long, default_value_t = 1)]
        workers: usize,
        #[arg(long, default_value = "60s", value_parser = parse_duration)]
        quantum: Duration,
        /// Stop after this many quanta have finished in this run, over all workers.
        #[arg(long)]
        quanta: Option<u64>,
        /// Every Nth quantum goes to the least recently served eligible target.
        #[arg(long, default_value_t = 10)]
        starve_every: u64,
        #[arg(long, default_value_t = 5.0)]
        min_free_gib: f64,
        /// Write Prometheus metrics here (a node exporter textfile) at start, after every
        /// quantum and at least once a minute.
        #[arg(long)]
        metrics: Option<PathBuf>,
    },
    /// Show per-target totals and open findings from the state directory.
    Status {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        targets: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Print the Prometheus text that `run --metrics` writes, from the logs alone: no
        /// worker is busy, and faults, disk waits and blocked targets are not known.
        #[arg(long, conflicts_with = "json")]
        prometheus: bool,
    },
    /// Check a service's metrics against expectations written as data (a keel.judge.expect.v1
    /// JSON spec). Exits 0 when all hold, 1 when any does not, 2 when the spec or arguments
    /// cannot be used.
    #[command(group(ArgGroup::new("source").required(true).args(["metrics", "state"])))]
    Expect {
        #[arg(long)]
        spec: PathBuf,
        /// The exposition text the supervisor writes with `run --metrics`.
        #[arg(long)]
        metrics: Option<PathBuf>,
        /// Compute the text from the logs, as `status --prometheus` does: no `target_blocked`
        /// series, no workers busy, and nothing about faults or disk waits.
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long, requires = "state")]
        targets: Option<PathBuf>,
        /// Keep reading until every expectation holds or this much time has passed; the
        /// file may not be written yet, and `increases` needs two reads.
        #[arg(long, default_value = "0s", value_parser = parse_window)]
        within: Duration,
        /// Pause between reads while waiting.
        #[arg(long, default_value = "2s", value_parser = parse_every)]
        every: Duration,
    },
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let d = humantime::parse_duration(s).map_err(|e| format!("{e}; write a duration like 60s or 2m"))?;
    if d.is_zero() { Err("a quantum must be longer than zero".into()) } else { Ok(d) }
}

fn parse_every(s: &str) -> Result<Duration, String> {
    let d = humantime::parse_duration(s).map_err(|e| format!("{e}; write a duration like 2s or 500ms"))?;
    if d.is_zero() { Err("--every 0s would read in a tight loop; use at least 1ms, or --within 0s for a single read".into()) } else { Ok(d) }
}

/// Like `parse_duration` but zero is allowed: it means one read.
fn parse_window(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| format!("{e}; write a duration like 0s, 90s or 5m"))
}

fn go(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::RecordChecks { tree_verdict, state } => keel_judge::checks::record(&tree_verdict, &state)?,
        Cmd::Guidance { manifest, inputs, output } => {
            let result = keel_judge::guidance::order(&manifest, &inputs)?;
            let text = serde_json::to_string_pretty(&result)? + "\n";
            match output { Some(p) => std::fs::write(p, text)?, None => print!("{text}") }
        }
        Cmd::Targets { bundle, durable_root, output } => {
            let f = targets::from_bundle(&bundle, &durable_root)?;
            let mut text = serde_json::to_string_pretty(&f)?;
            text.push('\n');
            match output {
                Some(p) => std::fs::write(&p, text).with_context(|| format!("cannot write {} (the targets file); fix -o", p.display()))?,
                None => print!("{text}"),
            }
        }
        Cmd::Run { targets, state, workers, quantum, quanta, starve_every, min_free_gib, metrics } => {
            if workers == 0 {
                bail!("--workers 0 would run nothing; use at least 1");
            }
            run(RunConfig { targets, state, workers, quantum, quanta, starve_every, min_free_gib, metrics })?;
        }
        Cmd::Status { state, targets, json, prometheus } => {
            let st = State::load(&state)?;
            let tf = targets.map(|p| TargetsFile::load(&p)).transpose()?;
            if prometheus {
                print!("{}", metrics::render(&metrics::from_logs(&st, tf.as_ref())));
                return Ok(());
            }
            let mut report = status::build(&st, tf.as_ref());
            report.checks = keel_judge::checks::latest(&state)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", status::render(&report));
                if let Some(c) = &report.checks { println!("checks: {} pass, {} fail, {} blocked, {} unknown ({} failed worlds)", c.pass, c.fail, c.blocked, c.unknown, c.failed_worlds); }
            }
        }
        // Answered in `main`: its exit status says more than success or failure.
        Cmd::Expect { .. } => unreachable!("main hands `expect` to expect::command"),
    }
    Ok(())
}

fn main() -> ExitCode {
    let cmd = Cmd::parse();
    if let Cmd::Expect { spec, metrics, state, targets, within, every } = cmd {
        let source = match (metrics, state) {
            (Some(m), _) => expect::Source::Metrics(m),
            (None, Some(dir)) => expect::Source::State { dir, targets },
            // The argument group requires one of them.
            (None, None) => unreachable!("clap requires --metrics or --state"),
        };
        return expect::command(expect::Config { spec, source, within, every });
    }
    match go(cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("keel-judge: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
