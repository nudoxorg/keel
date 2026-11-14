// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turns command-line settings into a loaded config, a store and a keyer.

use super::{
    config::{DEFAULT_KEEL_CONFIG_PATH, DEFAULT_KEEL_STORE_DIR, KeelConfig},
    keyer::{CodeKeyer, ExecutableKeyer},
    plan::{KeelPlan, KeelPlanInputs},
    session::{KeelReportOptions, KeelSession},
};
use crate::errors::KeelError;
use camino::{Utf8Path, Utf8PathBuf};
use keel::LocalStore;
use nextest_filtering::ParseContext;
use std::{sync::Arc, time::Duration};

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
}

/// A loaded Keel configuration, ready to plan and run.
pub struct KeelSetup {
    config: KeelConfig,
    store: LocalStore,
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

        Ok(Self {
            config,
            store,
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

    /// Keys every selected test and looks up stored passes.
    pub fn plan(&self, inputs: &KeelPlanInputs<'_, '_>) -> Result<KeelPlan, KeelError> {
        KeelPlan::build(inputs, &self.config, &self.store, self.keyer.as_ref())
    }

    /// Starts a session for a plan.
    pub fn start(&self, plan: KeelPlan, build_duration: Duration) -> KeelSession {
        KeelSession::new(
            plan,
            self.settings.no_block,
            self.store.clone(),
            KeelReportOptions {
                report_path: self
                    .settings
                    .report_path
                    .as_ref()
                    .map(|path| absolute(path)),
                budget: self.config.budget(),
                build_duration,
                workspace_root: self.workspace_root.clone(),
            },
        )
    }
}

fn absolute(path: &Utf8Path) -> Utf8PathBuf {
    std::path::absolute(path)
        .ok()
        .and_then(|path| Utf8PathBuf::from_path_buf(path).ok())
        .unwrap_or_else(|| path.to_owned())
}
