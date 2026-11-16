// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turns command-line settings into a loaded config, a store and a keyer.

use super::{
    config::{DEFAULT_KEEL_CONFIG_PATH, DEFAULT_KEEL_STORE_DIR, KeelConfig},
    gate::{GateOptions, KeelGate},
    history::{HISTORY_FILE_NAME, KeelHistory},
    keyer::{CodeKeyer, ExecutableKeyer},
    plan::{KeelPlan, KeelPlanInputs, KeelStreamPlanner},
    scope::ExpectedBinary,
    session::{KeelReportOptions, KeelSession},
};
use crate::errors::KeelError;
use camino::{Utf8Path, Utf8PathBuf};
use keel::LocalStore;
use nextest_filtering::ParseContext;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Settings from the command line.
#[derive(Clone, Debug, Default)]
pub struct KeelSettings {
    /// `--keel-config`: the config file, if not the default.
    pub config_path: Option<Utf8PathBuf>,

    /// `--keel-store`: the store directory, overriding the config.
    pub store_dir: Option<Utf8PathBuf>,

    /// `--keel-report`: where to write `report.json`.
    pub report_path: Option<Utf8PathBuf>,

    /// `--keel-no-block`: run blocked tests anyway.
    pub no_block: bool,

    /// `--keel-fail-fast-verdict`: cancel the run when the first root is final.
    pub fail_fast_verdict: bool,
}

/// A loaded Keel configuration, ready to plan and run.
pub struct KeelSetup {
    config: KeelConfig,
    store: LocalStore,
    history: Arc<KeelHistory>,
    settings: KeelSettings,
    workspace_root: Utf8PathBuf,
    keyer: Arc<dyn CodeKeyer>,
}

impl std::fmt::Debug for KeelSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeelSetup")
            .field("config", &self.config)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl KeelSetup {
    /// Loads the config and opens the store.
    ///
    /// A missing default config file means an empty config; a missing file
    /// that was named on the command line is an error.
    pub fn load(
        settings: KeelSettings,
        workspace_root: &Utf8Path,
        pcx: &ParseContext<'_>,
    ) -> Result<Self, KeelError> {
        let (config_path, required) = match &settings.config_path {
            Some(path) => (path.clone(), true),
            None => (workspace_root.join(DEFAULT_KEEL_CONFIG_PATH), false),
        };
        let config = KeelConfig::load(&config_path, required, pcx)?;

        let store_dir = match (&settings.store_dir, config.store_dir()) {
            (Some(dir), _) => dir.clone(),
            (None, Some(dir)) => workspace_root.join(dir),
            (None, None) => workspace_root.join(DEFAULT_KEEL_STORE_DIR),
        };
        let store = LocalStore::open(store_dir.as_std_path()).map_err(KeelError::Store)?;
        let history = match store_dir.parent() {
            Some(parent) => KeelHistory::load(&parent.join(HISTORY_FILE_NAME)),
            None => KeelHistory::empty(),
        };

        Ok(Self {
            config,
            store,
            history: Arc::new(history),
            settings,
            workspace_root: workspace_root.to_owned(),
            keyer: Arc::new(ExecutableKeyer),
        })
    }

    /// Replaces the code keyer.
    pub fn set_keyer(&mut self, keyer: Arc<dyn CodeKeyer>) {
        self.keyer = keyer;
    }

    /// Returns the loaded config.
    pub fn config(&self) -> &KeelConfig {
        &self.config
    }

    /// Returns whether blocked tests run anyway.
    pub fn no_block(&self) -> bool {
        self.settings.no_block
    }

    /// Returns whether the run is cancelled when the first root is final.
    pub fn fail_fast_verdict(&self) -> bool {
        self.settings.fail_fast_verdict
    }

    /// Keys every selected test and looks up stored passes.
    pub fn plan(&self, inputs: &KeelPlanInputs<'_, '_>) -> Result<KeelPlan, KeelError> {
        KeelPlan::build(inputs, &self.config, &self.store, self.keyer.as_ref())
    }

    /// Creates the planner for a run that keys binaries as Cargo reports them.
    ///
    /// `expected` are the binaries Cargo may report; see
    /// [`predict_test_binaries`](super::predict_test_binaries).
    pub fn stream_planner<'a, 'g>(
        &'a self,
        inputs: &KeelPlanInputs<'a, 'g>,
        expected: Vec<ExpectedBinary>,
    ) -> Result<KeelStreamPlanner<'a, 'g>, KeelError> {
        KeelStreamPlanner::new(
            inputs,
            &self.config,
            &self.store,
            self.keyer.as_ref(),
            expected,
        )
    }

    fn gate_options(&self, started: Instant) -> GateOptions {
        GateOptions {
            no_block: self.settings.no_block,
            fail_fast_verdict: self.settings.fail_fast_verdict,
            history: self.history.clone(),
            started,
        }
    }

    fn session(
        &self,
        gate: Arc<KeelGate>,
        platform: keel::Platform,
        started: Instant,
    ) -> KeelSession {
        KeelSession::new(
            gate,
            self.store.clone(),
            self.history.clone(),
            platform,
            KeelReportOptions {
                report_path: self
                    .settings
                    .report_path
                    .as_ref()
                    .map(|path| absolute(path)),
                budget: self.config.budget(),
                workspace_root: self.workspace_root.clone(),
                started,
            },
        )
    }

    /// Starts a session for a plan built after the build finished.
    ///
    /// `started` is when the run started, before the build; `build_duration` is
    /// how long the build took.
    pub fn start(&self, plan: KeelPlan, started: Instant, build_duration: Duration) -> KeelSession {
        let platform = plan.platform.clone();
        let gate = KeelGate::from_plan(plan, self.gate_options(started));
        gate.set_cargo_exit_at(build_duration);
        self.session(gate, platform, started)
    }

    /// Starts a session whose tests arrive while the build is running.
    ///
    /// The groups of the binaries the planner expects are declared to the gate.
    pub fn start_streaming(
        &self,
        planner: &KeelStreamPlanner<'_, '_>,
        started: Instant,
    ) -> KeelSession {
        let gate = KeelGate::streaming(self.gate_options(started));
        gate.expect_binaries(planner.expected_groups());
        self.session(gate, planner.platform().clone(), started)
    }
}

fn absolute(path: &Utf8Path) -> Utf8PathBuf {
    std::path::absolute(path)
        .ok()
        .and_then(|path| Utf8PathBuf::from_path_buf(path).ok())
        .unwrap_or_else(|| path.to_owned())
}
