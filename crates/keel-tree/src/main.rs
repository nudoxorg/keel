use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use keel_tree::check;
use keel_tree::model::Model;
use keel_tree::resolve::Resolution;
use keel_tree::testset::TestTable;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Clone)]
#[command(
    name = "keel-tree",
    about = "Join the Keel product model to a repository: check, tree, plan, explain"
)]
struct Cli {
    #[command(flatten)]
    common: Common,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Common {
    /// The repository to analyse (a git checkout).
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    /// The model entry point, as for `nix-instantiate --eval --strict --json`.
    #[arg(long, global = true)]
    model: Option<PathBuf>,
    /// Per-file cache of the code index, keyed by content hash. Default: `.local/keel-index-cache`
    /// inside --root. A relative path given here is relative to the current directory.
    #[arg(long, global = true)]
    cache: Option<PathBuf>,
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    /// Count `#[ignore]`d tests too.
    #[arg(long, global = true)]
    include_ignored: bool,
}

#[derive(Subcommand, Clone)]
enum Cmd {
    /// Export modeled check identities and merge an executable driver receipt.
    Checks {
        #[arg(long)] manifest: Option<PathBuf>,
        #[arg(long)] report: Option<PathBuf>,
        /// Directory containing the exact binaries named by the receipt.
        #[arg(long)] bin_dir: Option<PathBuf>,
        /// Verify the exact driver executable named by the report.
        #[arg(long)] driver_binary: Option<PathBuf>,
        /// Optional executable driver. It must create --report; --driver-arg is repeatable.
        #[arg(long, requires_all = ["manifest", "report", "bin_dir"])] driver: Option<PathBuf>,
        #[arg(long, requires = "driver", allow_hyphen_values = true)] driver_arg: Vec<String>,
        /// Maximum time in seconds for the driver process.
        #[arg(long, default_value_t = 1800)] driver_timeout: u64,
    },
    /// Evaluate the model, resolve it against the code, report findings.
    Check {
        /// Write the derived graph here and print the diff against the previous file.
        #[arg(long)]
        lock: Option<PathBuf>,
        /// Set or change the uncovered-edge baseline in the lock. Without it a run never
        /// writes a new uncovered edge into the lock, and with no baseline yet every
        /// uncovered edge is an error to review first.
        #[arg(long)]
        accept: bool,
        /// A census that was not run (observed by a command) is an error, not a warning.
        #[arg(long)]
        strict: bool,
        /// Print every finding. Without it, findings of one kind that give the same advice are one
        /// entry with a count and three examples. The JSON always has every finding.
        #[arg(long)]
        all: bool,
        /// Check again whenever a .nix file of the model changes (the model's directory, and the
        /// files it names by relative path), polling every 500 ms. A model that fails to evaluate
        /// prints its error and waits for the next change. Ctrl-C ends it.
        #[arg(long)]
        watch: bool,
    },
    /// Print each feature's cone as a tree (every feature, or just NODE).
    Tree {
        node: Option<String>,
        /// A CI run's test results (nextest's junit.xml, or nextest status lines or keel-index
        /// ids, one per line; repeatable): put each node's pass/fail on the tree and split the
        /// failing nodes into roots and what stands on them.
        #[arg(long)]
        results: Vec<PathBuf>,
        /// Manifest, raw report, and artifact directory for executable checks.
        #[arg(long, requires_all = ["check_report", "check_bin_dir"])]
        check_manifest: Option<PathBuf>,
        #[arg(long, requires_all = ["check_manifest", "check_bin_dir"])]
        check_report: Option<PathBuf>,
        #[arg(long, requires_all = ["check_manifest", "check_report"])]
        check_bin_dir: Option<PathBuf>,
        /// Verify the exact driver executable named by the report.
        #[arg(long, requires = "check_report")]
        check_driver_binary: Option<PathBuf>,
        /// The results file lists failures only: a test it does not name may have passed.
        #[arg(long, requires = "results")]
        failures_only: bool,
        /// Write one commit status per feature (`keel/<feature>`) here, as JSON.
        #[arg(long)]
        statuses: Option<PathBuf>,
        /// Write the PR comment (Markdown) here: the failing roots and what stands on them,
        /// then the annotated trees folded under it, under 60,000 characters.
        #[arg(long)]
        comment: Option<PathBuf>,
    },
    /// Describe a CI run's failures with the fewest causes.
    Explain {
        /// Failed tests, one per line: keel-index ids or nextest status lines.
        #[arg(long)]
        failures: PathBuf,
        /// Executed tests, same formats (any status; SKIP lines count as not run). Required unless --failures-only.
        #[arg(long, conflicts_with = "failures_only")]
        executed: Option<PathBuf>,
        /// Describe the failures alone: no claim about the tests that passed.
        #[arg(long)]
        failures_only: bool,
        #[arg(long, default_value_t = 12)]
        max_causes: usize,
        /// Leave out the `top:<node>` attributes (to compare with the previous universe).
        #[arg(long)]
        no_tops: bool,
    },
    /// Read a model (a .json file, or a .nix entry point to evaluate) and list every key that no
    /// typed field of keel-tree reads. Exits 1 if there is any. This is what the contract test
    /// (tests/contract.nu) runs on a model that uses every constructor of the library.
    ReadModel {
        file: PathBuf,
    },
    /// List every place the product meets code or state it does not control, per owning node.
    ///
    /// Classes: foreign function interfaces (extern blocks and functions, no_mangle and
    /// link attributes, dlopen and libloading), native code in packages (links keys, build
    /// scripts and the tools they use, -sys crates, C/C++/ObjC/assembly files), processes,
    /// network listeners and clients, path-like environment variables and directory lookups,
    /// temporary files, clocks and randomness, and compile-time include!/env!.
    ///
    /// THIS IS A LOWER BOUND. It is made of ast-grep patterns over Rust syntax and of cargo
    /// metadata, so it counts the spellings it names. It misses a boundary reached through a
    /// wrapper function, a macro expansion, generated code or a re-exported alias, and it can
    /// count a name that only looks like one (a bare `Command::new` that is clap's, a
    /// variable named PATH_SEPARATOR). Each class lists its own false-positive and
    /// false-negative risk in the report. `CStr`/`CString` crossing sites are not counted:
    /// they appear at nearly every FFI call and on plain string handling alike.
    ///
    /// Test code (`#[cfg(test)]` modules, `#[test]` functions, files declared as `#[cfg(test)] mod x;`
    /// (found by a text scan of the declaring file), and files under tests,
    /// benches or fixtures directories) is left out unless --include-tests, because the
    /// boundaries a test crosses are a different fact from the ones the product does.
    Boundaries {
        /// List test-code sites too, marked as such.
        #[arg(long)]
        include_tests: bool,
    },
    /// What a change touches and in what order to run the tests it makes worth running.
    Plan {
        #[arg(long)]
        base: String,
        #[arg(long)]
        head: String,
        /// Mark where the schedule would be cut after this many seconds.
        #[arg(long)]
        by: Option<f64>,
        /// Most (unit, test) notice entries one plan may hold.
        #[arg(long, default_value_t = keel_tree::plan::assumptions::MAX_NOTICES)]
        max_notices: u64,
        /// Tests the greedy order is computed over.
        #[arg(long, default_value_t = keel_tree::plan::assumptions::MAX_CANDIDATES)]
        max_candidates: usize,
        /// Write the plan artefact (design/ir.md 7.2, slice 1) here instead of printing a report: every
        /// indexed test of --binary as a unit, all ReuseIfKeyHolds, with the plan's own digest.
        /// Refuses (exit 2) when the resolver has errors, the cargo index is degraded, or the checkout
        /// is not the clean --head commit.
        #[arg(long, requires = "binary")]
        emit: Option<PathBuf>,
        /// The test binary to plan: `<package>` (the lib's tests), `<package>::<target>` (an
        /// integration test), or `<package>::bin/<x>`.
        #[arg(long, requires = "emit")]
        binary: Option<String>,
        /// The repository's name in the plan. Default: the directory name of the checkout.
        #[arg(long, requires = "emit")]
        repository: Option<String>,
        /// Write the PR's `keel/plan` commit status here, as JSON (the same shape as
        /// `tree --statuses`): the touched nodes and the tests in doubt.
        #[arg(long, conflicts_with = "emit")]
        statuses: Option<PathBuf>,
        /// Write the PR comment (Markdown) here: what the change touches and how much is in
        /// doubt, with the whole plan folded under it, under 60,000 characters.
        #[arg(long, conflicts_with = "emit")]
        comment: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("keel-tree: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    if let Cmd::Check { watch: true, .. } = &cli.cmd {
        return watch(&cli);
    }
    execute(cli)
}

/// Runs `check` again whenever a .nix file of the model changes. Whatever one run fails with is
/// printed and waited out, because the point of watching is to fix the model while it is broken.
/// The files are looked at before the run starts, so an edit saved during it runs again.
fn watch(cli: &Cli) -> Result<ExitCode> {
    let Some(model) = &cli.common.model else {
        anyhow::bail!("--watch needs --model <eval.nix>, the file whose directory it watches; pass it before or after the subcommand");
    };
    loop {
        let seen = keel_tree::watch::snapshot(&keel_tree::watch::files(model));
        let began = std::time::Instant::now();
        if let Err(e) = execute(cli.clone()) {
            eprintln!("keel-tree: {e:#}");
        }
        println!("{}", keel_tree::watch::separator(model, seen.len(), began.elapsed()));
        keel_tree::watch::wait_for_change(model, &seen);
    }
}

fn execute(cli: Cli) -> Result<ExitCode> {
    let c = &cli.common;
    if let Cmd::ReadModel { file } = &cli.cmd {
        let model = if file.extension().is_some_and(|e| e == "json") {
            Model::from_json(&std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?)?
        } else {
            Model::evaluate(file)?
        };
        println!(
            "read {}: {} nodes, {} worlds, {} check groups, {} censuses",
            file.display(),
            model.nodes.len(),
            model.worlds.len(),
            model.checks.len(),
            model.census.len()
        );
        for k in &model.unread {
            println!("unread: {k}");
        }
        return Ok(if model.unread.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) });
    }
    let (Some(root), Some(model_path)) = (&c.root, &c.model) else {
        anyhow::bail!("--root <repo> and --model <eval.nix> are both required; pass them before or after the subcommand");
    };
    let cache = c.cache.clone().unwrap_or_else(|| root.join(".local/keel-index-cache"));
    let model = Model::evaluate(model_path)?;
    // Plan and explain are about package closures and test binaries, so they
    // need the cargo index; check and tree need it only if the model does.
    // Mapping result lines to tests needs the test binaries, which come from cargo.
    let needs_packages = matches!(cli.cmd, Cmd::Explain { .. }) || matches!(&cli.cmd, Cmd::Tree { results, check_report, .. } if !results.is_empty() || check_report.is_some());
    let want_cargo = needs_packages || matches!(cli.cmd, Cmd::Plan { .. }) || keel_tree::source::needs_cargo(&model);
    if want_cargo {
        std::fs::create_dir_all(&cache).with_context(|| {
            format!("cannot create the index cache at {}; pass --cache with a writable directory", cache.display())
        })?;
    }
    let (index, src) = keel_tree::source::load(root, Some(&cache), want_cargo)?;
    let no_cargo = match &src {
        keel_tree::source::Source::Cargo => None,
        keel_tree::source::Source::GitOnly { reason } => Some(reason.as_str()),
    };
    if let (true, Some(why)) = (needs_packages, no_cargo) {
        anyhow::bail!(
            "this command needs the cargo package graph (test binaries and package closures), which is not available for {}: {why}. \
             Run it on a cargo workspace; `check` and `tree` work from git and the model alone.",
            root.display()
        );
    }
    let res = Resolution::build_with(&model, &index, root, no_cargo);
    let table = TestTable::build(&res, c.include_ignored);
    match cli.cmd {
        Cmd::Checks { manifest, report, bin_dir, driver_binary, driver, driver_arg, driver_timeout } => {
            let driver_success = if let Some(ref executable) = driver {
                Some(keel_tree::driver::execute(executable, &driver_arg, report.as_deref().expect("clap requires report"), std::time::Duration::from_secs(driver_timeout))?)
            } else { None };
            let evidence = keel_tree::driver::evaluate(&model, &res, manifest.as_deref(), report.as_deref(), bin_dir.as_deref(), driver.as_deref().or(driver_binary.as_deref()))?;
            if driver_success == Some(false) && !evidence.checks.iter().any(|c| c.state == "fail") {
                anyhow::bail!("driver exited unsuccessfully without a failing modeled receipt");
            }
            println!("{}", serde_json::to_string_pretty(&evidence)?);
            Ok(if evidence.checks.iter().any(|c| c.state == "fail") { ExitCode::from(1) }
                else if evidence.checks.iter().any(|c| c.state == "unknown" || c.state == "blocked") { ExitCode::from(2) }
                else { ExitCode::SUCCESS })
        }
        Cmd::Check { lock, accept, strict, all, watch: _ } => {
            let report = check::run_with(&model, &res, &table, lock.as_deref(), accept, strict)?;
            if c.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.render_with(all));
            }
            Ok(if report.has_errors() { ExitCode::from(1) } else { ExitCode::SUCCESS })
        }
        Cmd::Plan { base, head, emit: Some(path), binary, repository, .. } => {
            let binary = binary.expect("clap: --emit requires --binary");
            let req = keel_tree::emit::Request { binary: &binary, repository: repository.as_deref(), base: &base, head: &head, no_cargo };
            let plan = keel_tree::emit::build(&res, &table, root, &req)?;
            plan.write(&path).map_err(anyhow::Error::msg)?;
            println!("wrote {}: {} units of {binary}, plan digest {}", path.display(), plan.units().len(), plan.digest());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Plan { base, head, by, max_notices, max_candidates, statuses, comment, .. } => {
            let mut report = keel_tree::plan::run(
                &res,
                &table,
                &model,
                root,
                &base,
                &head,
                &keel_tree::plan::Options { by_seconds: by, max_notices, max_candidates },
            )?;
            report.index_note = keel_tree::plan::head_note(root);
            report.base = keel_tree::plan::describe_rev(root, &base);
            report.head = keel_tree::plan::describe_rev(root, &head);
            if let Some(path) = &statuses {
                std::fs::write(path, serde_json::to_string_pretty(&[report.status()])? + "\n")
                    .with_context(|| format!("cannot write {} (--statuses); check the directory exists and is writable", path.display()))?;
            }
            if let Some(path) = &comment {
                std::fs::write(path, report.comment())
                    .with_context(|| format!("cannot write {} (--comment); check the directory exists and is writable", path.display()))?;
            }
            if c.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.render());
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Explain { failures, executed, max_causes, no_tops, failures_only } => {
            let read = |p: &PathBuf| std::fs::read_to_string(p).with_context(|| format!("cannot read {}", p.display()));
            let failures = read(&failures)?;
            let executed = executed.as_ref().map(read).transpose()?;
            let placement = keel_tree::testset::place(&model, &res, &table);
            let report = keel_tree::explain::run(
                &res,
                &table,
                &placement,
                &model,
                &keel_tree::explain::Inputs { failures: &failures, executed: executed.as_deref(), max_causes, use_tops: !no_tops, failures_only },
            )?;
            if c.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.render());
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Boundaries { include_tests } => {
            if let Some(why) = res.tracked_error() {
                anyhow::bail!("{why}");
            }
            let report = keel_tree::boundaries::run(&res, root, &keel_tree::boundaries::Options { include_tests });
            if c.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.render());
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::ReadModel { .. } => unreachable!("handled before the repository is loaded"),
        Cmd::Tree { node, results, check_manifest, check_report, check_bin_dir, check_driver_binary, failures_only, statuses, comment } if !results.is_empty() || check_report.is_some() => {
            let trees = keel_tree::tree::run(&res, &table, node.as_deref())?;
            let mut text = String::new();
            for path in &results {
                let what = path.display().to_string();
                let raw = std::fs::read_to_string(path)
                    .with_context(|| format!("cannot read {what} (a --results file); pass nextest's junit.xml or a file of status lines"))?;
                text.push_str(&if raw.trim_start().starts_with('<') { keel_tree::verdict::junit_status_lines(&raw, &what)? } else { raw });
                text.push('\n');
            }
            let mapper = keel_tree::explain::Mapper::new(&index, &table);
            let read = keel_tree::verdict::read(&mapper, &table, &text, failures_only);
            let checks = if check_report.is_some() {
                Some(keel_tree::driver::evaluate(&model, &res, check_manifest.as_deref(), check_report.as_deref(), check_bin_dir.as_deref(), check_driver_binary.as_deref())?)
            } else { None };
            let verdict = keel_tree::verdict::run_with_checks(&res, &table, &trees, &read, checks.as_ref());
            if let Some(path) = &statuses {
                std::fs::write(path, serde_json::to_string_pretty(&verdict.statuses())? + "\n")
                    .with_context(|| format!("cannot write {} (--statuses); check the directory exists and is writable", path.display()))?;
            }
            if let Some(path) = &comment {
                std::fs::write(path, verdict.comment())
                    .with_context(|| format!("cannot write {} (--comment); check the directory exists and is writable", path.display()))?;
            }
            if c.json {
                println!("{}", serde_json::to_string_pretty(&verdict)?);
            } else {
                print!("{}", verdict.render());
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Tree { node, statuses, comment, .. } => {
            if statuses.is_some() || comment.is_some() { anyhow::bail!("--statuses and --comment need test results or check receipts"); }
            let trees = keel_tree::tree::run(&res, &table, node.as_deref())?;
            if c.json {
                println!("{}", serde_json::to_string_pretty(&trees)?);
            } else {
                print!("{}", keel_tree::tree::render_all(&trees));
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
