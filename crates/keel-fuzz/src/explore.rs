use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;

use crate::events::EventLog;
use crate::ops::Session;

pub struct ExploreOptions {
    pub corpus: PathBuf,
    pub out: PathBuf,
    pub time: Duration,
    pub seed: u64,
    pub max_len: usize,
    pub dict: Option<PathBuf>,
    pub exec_timeout: Duration,
    pub stop_after_crashes: usize,
    pub cmplog: bool,
}

pub fn explore(_s: &Session, _o: &ExploreOptions, _l: &EventLog) -> Result<()> {
    anyhow::bail!("explore is not built yet")
}
