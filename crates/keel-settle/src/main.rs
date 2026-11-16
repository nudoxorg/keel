use clap::{Parser, Subcommand};
use keel_settle::producer::{self, Options};
use keel_settle::{Binary, Executed, Plan, settle};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "keel-settle", about = "Judge an executed list against a plan (design/ir.md 7.3), and produce one for a single libtest binary")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print pass, fail or incomplete. Exit 0 pass, 1 fail, 3 incomplete, 2 for an unreadable
    /// or malformed input.
    Settle {
        plan: PathBuf,
        executed: PathBuf,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// STAND-IN for the nextest fork's `--keel-plan`, which cannot be built here: run one
    /// libtest binary and write the executed list as JSON lines, one record per test
    /// as it finishes. Runs `<exe> --list --format terse` for the Listed line, then each
    /// planned test that the binary listed in its own process with `--exact <name>
    /// --test-threads 1`. A planned test the binary did not list is not run and has no line.
    RunBinary {
        #[arg(long)]
        plan: PathBuf,
        /// The test binary cargo built.
        #[arg(long)]
        exe: PathBuf,
        /// The executed list to create. It must not exist.
        #[arg(long)]
        out: PathBuf,
        /// Which binary of the plan --exe is, as `<package>[::<target>]`; needed only if the
        /// plan has several.
        #[arg(long)]
        binary: Option<String>,
        /// Tests running at once. Default: the number of CPUs.
        #[arg(long)]
        jobs: Option<usize>,
        /// A test still running after this many seconds is killed and recorded as Timeout.
        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,
        /// Run the tests in this directory (cargo uses the package directory) and set
        /// CARGO_MANIFEST_DIR to it.
        #[arg(long)]
        cwd: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("keel-settle: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<u8, String> {
    match Cli::parse().cmd {
        Cmd::Settle { plan, executed, json } => {
            let plan = Plan::read(&plan).map_err(|e| e.to_string())?;
            let executed = Executed::read(&executed).map_err(|e| e.to_string())?;
            let report = settle(&plan, &executed);
            if json {
                println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
            } else {
                print!("{}", report.render());
            }
            Ok(report.verdict.exit_code())
        }
        Cmd::RunBinary { plan, exe, out, binary, jobs, timeout_secs, cwd } => {
            let plan = Plan::read(&plan).map_err(|e| e.to_string())?;
            let binary = binary.as_deref().map(Binary::parse).transpose()?;
            let jobs = jobs.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from));
            let o = Options { exe, out: out.clone(), binary, jobs, timeout: Duration::from_secs(timeout_secs), cwd };
            let n = producer::run(&plan, &o).map_err(|e| e.to_string())?;
            println!("wrote {n} records and the Listed line to {} (plan {})", out.display(), plan.digest());
            Ok(0)
        }
    }
}
