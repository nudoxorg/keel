// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keel options and the `keel` subcommands.
//!
//! Keel runs tests incrementally and in dependency order. Everything here is
//! inert unless `--keel` is passed (or the `keel` subcommand is used).

use super::{base::BaseApp, filter::TestBuildFilter, run::App};
use crate::{
    ExpectedError, Result,
    cargo_cli::{CargoOptions, KeelBuildFlags},
    reuse_build::ReuseBuildOpts,
};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Args, Subcommand};
use nextest_filtering::{FiltersetKind, ParseContext};
use nextest_runner::{
    errors::KeelError,
    helpers::force_or_new_run_id,
    keel::{KeelPlanInputs, KeelSettings, KeelSetup},
    list::TestExecuteContext,
    run_mode::NextestRunMode,
    runner::VersionEnvVars,
};
use std::{collections::BTreeSet, time::Instant};

/// Options that turn on Keel for `cargo nextest run`.
#[derive(Debug, Default, Args)]
#[command(next_help_heading = "Keel options")]
pub(crate) struct KeelOpts {
    /// Run incrementally and in dependency order, using Keel.
    ///
    /// A test whose inputs are unchanged since a recorded pass is not run. A
    /// test runs only after the tests it stands on have finished, and is not
    /// run at all if a failed test it stands on blocks it. Failures are
    /// reported as root causes rather than cascades.
    ///
    /// This builds test binaries with remapped paths and packed debug info, so
    /// that their keys do not depend on the checkout location. Because the
    /// remap flags are passed in `CARGO_ENCODED_RUSTFLAGS`, `build.rustflags`
    /// from Cargo config files does not apply to the build.
    #[arg(long)]
    pub(crate) keel: bool,

    /// Keel config file [default: workspace-root/.config/keel.toml].
    #[arg(long, value_name = "PATH", requires = "keel")]
    pub(crate) keel_config: Option<Utf8PathBuf>,

    /// Directory of the Keel result store [default: from the Keel config, else
    /// workspace-root/.local/keel/store].
    #[arg(long, value_name = "DIR", requires = "keel")]
    pub(crate) keel_store: Option<Utf8PathBuf>,

    /// Write the Keel run report (report.json) to this path.
    #[arg(long, value_name = "PATH", requires = "keel")]
    pub(crate) keel_report: Option<Utf8PathBuf>,

    /// Run tests even if tests they stand on failed.
    ///
    /// The report still records which tests would have been blocked.
    #[arg(long, requires = "keel")]
    pub(crate) keel_no_block: bool,

    /// End the run as soon as the first root failure is final.
    ///
    /// A root failure is a failed test that no failed test it stands on explains.
    /// With this flag, when one is final (its last retry has finished), the run
    /// is cancelled and exits with a failure, even if Cargo is still compiling;
    /// Cargo is terminated too. Without it, the run continues and prints the
    /// root as soon as it is known.
    #[arg(long, requires = "keel")]
    pub(crate) keel_fail_fast_verdict: bool,

    /// Link test binaries with this linker.
    ///
    /// Used to record what the linker sees for Keel's reach analysis. Sets
    /// `target.<triple>.linker` for the build.
    #[arg(long, value_name = "PATH", requires = "keel")]
    pub(crate) keel_linker: Option<Utf8PathBuf>,
}

impl KeelOpts {
    fn settings(&self) -> KeelSettings {
        KeelSettings {
            config_path: self.keel_config.clone(),
            store_dir: self.keel_store.clone(),
            report_path: self.keel_report.clone(),
            no_block: self.keel_no_block,
            fail_fast_verdict: self.keel_fail_fast_verdict,
        }
    }
}

/// Options for `cargo nextest keel plan`.
#[derive(Debug, Args)]
pub(crate) struct KeelPlanOpts {
    #[clap(flatten)]
    pub(crate) cargo_options: CargoOptions,

    #[clap(flatten)]
    pub(crate) build_filter: TestBuildFilter,

    /// Keel config file [default: workspace-root/.config/keel.toml].
    #[arg(long, value_name = "PATH", help_heading = "Keel options")]
    pub(crate) keel_config: Option<Utf8PathBuf>,

    /// Directory of the Keel result store [default: from the Keel config, else
    /// workspace-root/.local/keel/store].
    #[arg(long, value_name = "DIR", help_heading = "Keel options")]
    pub(crate) keel_store: Option<Utf8PathBuf>,

    /// Link test binaries with this linker.
    #[arg(long, value_name = "PATH", help_heading = "Keel options")]
    pub(crate) keel_linker: Option<Utf8PathBuf>,

    #[clap(flatten)]
    pub(crate) reuse_build: ReuseBuildOpts,
}

/// Keel subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum KeelCommand {
    /// Build, key and print the plan without running anything.
    ///
    /// This builds test binaries and queries them for the tests they contain,
    /// computes every test's key, and prints one line per test: the level of
    /// the test in the hierarchy, its group, the first digits of its key,
    /// `cached` if a stored pass exists or `run` if not, the number of tests it
    /// stands on, and its ID.
    Plan(Box<KeelPlanOpts>),
}

/// Computes the build flags Keel adds to the Cargo invocation.
pub(crate) fn keel_build_flags(
    base: &BaseApp,
    linker: Option<&Utf8Path>,
) -> Result<KeelBuildFlags> {
    let mut remaps = vec![(base.workspace_root.clone(), "/src")];
    if let Some(cargo_home) = cargo_home() {
        remaps.push((cargo_home, "/cargo"));
    }
    remaps.push((rustc_sysroot()?, "/sysroot"));
    Ok(KeelBuildFlags {
        remaps,
        linker: linker.map(|linker| (base.keel_triples(), linker.to_owned())),
    })
}

fn cargo_home() -> Option<Utf8PathBuf> {
    let from_env =
        |name: &str| std::env::var_os(name).and_then(|v| Utf8PathBuf::from_path_buf(v.into()).ok());
    from_env("CARGO_HOME").or_else(|| {
        from_env("HOME")
            .or_else(|| from_env("USERPROFILE"))
            .map(|home| home.join(".cargo"))
    })
}

fn rustc_sysroot() -> Result<Utf8PathBuf> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let message = |message: String| ExpectedError::KeelError {
        err: KeelError::Rustc { message },
    };
    let output = duct::cmd(&rustc, ["--print=sysroot"])
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .map_err(|err| message(format!("could not run `{rustc} --print=sysroot`: {err}")))?;
    if !output.status.success() {
        return Err(message(format!(
            "`{rustc} --print=sysroot` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if sysroot.is_empty() {
        return Err(message(format!(
            "`{rustc} --print=sysroot` printed nothing"
        )));
    }
    Ok(Utf8PathBuf::from(sysroot))
}

impl KeelOpts {
    /// Applies the Keel build flags to the base app if `--keel` is on.
    pub(crate) fn apply_to_base(&self, base: BaseApp) -> Result<BaseApp> {
        if !self.keel {
            return Ok(base);
        }
        let flags = keel_build_flags(&base, self.keel_linker.as_deref())?;
        Ok(base.with_keel_build(flags))
    }

    /// Loads Keel's configuration if `--keel` is on.
    pub(crate) fn load_setup(
        &self,
        base: &BaseApp,
        pcx: &ParseContext<'_>,
        stress: bool,
    ) -> Result<Option<KeelSetup>> {
        if !self.keel {
            return Ok(None);
        }
        if stress {
            return Err(ExpectedError::KeelError {
                err: KeelError::Unsupported {
                    option: "--stress-count or --stress-duration",
                    hint: "a stress run repeats tests whose results Keel has already recorded",
                },
            });
        }
        let setup = KeelSetup::load(self.settings(), &base.workspace_root, pcx)
            .map_err(|err| ExpectedError::KeelError { err })?;
        Ok(Some(setup))
    }
}

impl App {
    pub(crate) fn exec_keel_plan(
        &self,
        keel_config: Option<&Utf8Path>,
        keel_store: Option<&Utf8Path>,
    ) -> Result<()> {
        let pcx = ParseContext::new(self.base.graph());
        let (version_only_config, config) = self.base.load_config(&pcx, &BTreeSet::new())?;
        let profile = self.base.load_profile(&config)?;
        let settings = KeelSettings {
            config_path: keel_config.map(Utf8Path::to_owned),
            store_dir: keel_store.map(Utf8Path::to_owned),
            ..KeelSettings::default()
        };
        let setup = KeelSetup::load(settings, &self.base.workspace_root, &pcx)
            .map_err(|err| ExpectedError::KeelError { err })?;

        let known_groups = profile.known_groups();
        let filter_exprs = crate::dispatch::helpers::build_filtersets(
            &pcx,
            &self.build_filter.filterset,
            FiltersetKind::Test,
            &known_groups,
        )?;
        let test_filter = self
            .build_filter
            .make_test_filter(NextestRunMode::Test, filter_exprs)?
            .test_filter;

        let build_started = Instant::now();
        let binary_list = self.base.build_binary_list("test")?;
        let build_platforms = binary_list.rust_build_meta.build_platforms.clone();
        let double_spawn = self.base.load_double_spawn();
        let target_runner = self.base.load_runner(&build_platforms);
        let profile = profile.apply_build_platforms(&build_platforms);
        let nextest_version_config = version_only_config.nextest_version();
        let version_env_vars = VersionEnvVars {
            current_version: self.base.current_version.clone(),
            required_version: nextest_version_config.required.version().cloned(),
            recommended_version: nextest_version_config.recommended.version().cloned(),
        };
        let ctx = TestExecuteContext {
            run_id: force_or_new_run_id(),
            version_env_vars: &version_env_vars,
            profile_name: profile.name(),
            double_spawn,
            target_runner,
        };
        let resolved_user_config = crate::dispatch::helpers::resolve_user_config(
            self.base.early_args.user_config_location(),
        )?;
        let test_list = self.build_test_list(
            &ctx,
            binary_list,
            &test_filter,
            &profile,
            resolved_user_config.ui.show_progress.into(),
        )?;
        let build_duration = build_started.elapsed();

        let plan = setup
            .plan(&KeelPlanInputs {
                test_list: &test_list,
                profile: &profile,
                graph: self.base.graph(),
                workspace_root: &self.base.workspace_root,
                build_platforms: &build_platforms,
                target_runner,
            })
            .map_err(|err| ExpectedError::KeelError { err })?;

        print!("{}", plan.render());
        eprintln!(
            "keel plan: {} tests in {} binaries, {} to run, {} cached (build {:.1}s, keys {:.1}s)",
            plan.len(),
            plan.binaries_keyed(),
            plan.len() - plan.cached_count(),
            plan.cached_count(),
            build_duration.as_secs_f64(),
            plan.key_duration().as_secs_f64(),
        );
        self.base
            .check_version_config_final(version_only_config.nextest_version())?;
        Ok(())
    }
}
