// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runs tests while Cargo is still building them.
//!
//! Cargo's JSON messages are read as they arrive. When a message reports a test
//! binary, the binary is listed (`--list --format terse`, as nextest does for
//! every run), keyed, and handed to the scheduler, while Cargo goes on
//! compiling. This is `--keel` without `--keel-no-stream`; see the
//! `nextest_runner::keel` module for how the scheduler decides when a test may
//! start.
//!
//! Three kinds of thread take part. The main thread runs the test runner, as in
//! a run that waits for the build. One thread reads Cargo's output and keeps
//! the build metadata. A few worker threads list, key and plan binaries; the
//! reader never waits for them, because a Cargo that cannot write to a full pipe
//! stops compiling.

use super::{base::BinaryStream, run::App};
use crate::{ExpectedError, Result};
use camino::Utf8Path;
use nextest_runner::{
    config::core::{EarlyProfile, EvaluatableProfile},
    keel::{KeelFeed, KeelGate, KeelStreamPlanner},
    list::{BinaryList, BinaryListBuilder, TestExecuteContext, TestList},
    reporter::ShowProgress,
    test_filter::TestFilter,
};
use std::{
    io::{BufRead, BufReader},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};
use tracing::debug;

/// The most worker threads that list and key binaries.
const MAX_PLANNING_THREADS: usize = 16;

/// How long to wait for a binary that Cargo has reported to appear.
const BINARY_WAIT: Duration = Duration::from_secs(5);

/// Reasons a run cannot take tests while Cargo is building.
///
/// A run that cannot is not wrong: it waits for the build, lists every binary,
/// and then runs, as it did before streaming existed.
#[derive(Debug)]
pub(crate) struct StreamEligibility {
    /// `--keel-no-stream` was passed.
    pub(crate) disabled: bool,

    /// The tests are not run: `--no-run`.
    pub(crate) no_run: bool,

    /// Tests are rerun from a recorded run.
    pub(crate) rerun: bool,

    /// A debugger or a tracer is attached.
    pub(crate) interceptor: bool,

    /// The reporter writes something other than the human-readable output.
    pub(crate) machine_output: bool,

    /// The run is recorded, and a recording needs the whole test list at the
    /// start.
    pub(crate) recording: bool,

    /// The binaries come from an archive or a metadata file, not from Cargo.
    pub(crate) reused_build: bool,

    /// The tests are partitioned; a partition is computed over the whole list.
    pub(crate) partitioned: bool,
}

impl StreamEligibility {
    /// Returns why the run cannot stream, if it cannot.
    pub(crate) fn blocker(&self, profile: &EarlyProfile<'_>) -> Option<&'static str> {
        let reasons = [
            (self.disabled, "--keel-no-stream was passed"),
            (self.no_run, "--no-run does not run tests"),
            (self.rerun, "--rerun selects tests from a recorded run"),
            (self.interceptor, "a debugger or tracer is attached"),
            (
                self.machine_output,
                "the message format is not the human-readable one",
            ),
            (self.recording, "the run is recorded"),
            (
                self.reused_build,
                "the binaries come from a reused build, not from Cargo",
            ),
            (self.partitioned, "--partition needs the whole test list"),
            (
                profile.has_scripts(),
                "the profile has scripts, and which setup scripts run depends on the tests",
            ),
        ];
        reasons
            .into_iter()
            .find_map(|(blocked, reason)| blocked.then_some(reason))
    }
}

/// Everything the threads that list and key binaries need.
pub(crate) struct Producer<'t, 'p> {
    pub(crate) app: &'t App,
    pub(crate) stream: &'t BinaryStream,
    pub(crate) planner: &'p KeelStreamPlanner<'p, 't>,
    pub(crate) feed: &'p Arc<KeelFeed<'t>>,
    pub(crate) gate: &'p Arc<KeelGate>,
    pub(crate) profile: &'t EvaluatableProfile<'t>,
    pub(crate) test_filter: &'p TestFilter,
    pub(crate) ctx: &'p TestExecuteContext<'p>,
}

struct Shared {
    /// The first error any thread met. It ends the run.
    error: Mutex<Option<ExpectedError>>,

    /// Whether the run is over and Cargo was terminated on purpose.
    cancelled: AtomicBool,
}

impl<'t, 'p> Producer<'t, 'p> {
    /// Calls `run` while another thread reads Cargo's messages and feeds the
    /// tests of each binary to the scheduler.
    ///
    /// When `run` returns, Cargo is terminated if it is still running and the
    /// threads are joined, so a run that ends early, because of a verdict or a
    /// signal, does not leave a build behind.
    pub(crate) fn drive<R>(&self, run: impl FnOnce() -> R) -> (R, Result<()>)
    where
        R: Send,
    {
        let shared = Shared {
            error: Mutex::new(None),
            cancelled: AtomicBool::new(false),
        };
        std::thread::scope(|scope| {
            let producer = scope.spawn(|| {
                let result = self.read_and_plan(&shared);
                self.feed.close();
                result
            });

            let outcome = run();

            shared.cancelled.store(true, Ordering::SeqCst);
            self.gate.cancel();
            // Ending the build closes the pipe that the reader thread reads.
            self.stream.terminate();
            let read = producer
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic));

            let produced = match shared.error.lock().expect("lock is never poisoned").take() {
                Some(error) => Err(error),
                None => read,
            };
            (outcome, produced)
        })
    }

    fn fail(&self, shared: &Shared, error: ExpectedError) {
        let mut slot = shared.error.lock().expect("lock is never poisoned");
        if slot.is_none() {
            *slot = Some(error);
        }
        drop(slot);
        // A run that cannot be completed is red. Stop spending time on it.
        self.gate.cancel();
        self.stream.terminate();
    }

    fn failed(&self, shared: &Shared) -> bool {
        shared
            .error
            .lock()
            .expect("lock is never poisoned")
            .is_some()
    }

    fn read_and_plan(&self, shared: &Shared) -> Result<()> {
        let threads = std::thread::available_parallelism()
            .map_or(2, |n| n.get())
            .clamp(2, MAX_PLANNING_THREADS);
        let (job_tx, job_rx) = mpsc::channel::<Arc<BinaryList>>();
        let job_rx = Mutex::new(job_rx);
        std::thread::scope(|workers| {
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    workers.spawn(|| {
                        loop {
                            let job = job_rx.lock().expect("lock is never poisoned").recv();
                            let Ok(binary_list) = job else {
                                break;
                            };
                            if self.failed(shared) || shared.cancelled.load(Ordering::SeqCst) {
                                continue;
                            }
                            if let Err(error) = self.plan_binary(binary_list) {
                                self.fail(shared, error);
                            }
                        }
                    })
                })
                .collect();

            let read = self.read_messages(shared, &job_tx);
            drop(job_tx);
            for handle in handles {
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            }
            read
        })
    }

    /// Reads Cargo's messages until it exits.
    fn read_messages(&self, shared: &Shared, jobs: &mpsc::Sender<Arc<BinaryList>>) -> Result<()> {
        let graph = self.app.base.graph();
        let mut builder = BinaryListBuilder::new(graph, self.app.base.build_platforms.clone());
        let command = &self.stream.command;
        let read = (|| -> Result<()> {
            for line in BufReader::new(&self.stream.reader).lines() {
                let line = match line {
                    Ok(line) => line,
                    // Terminating Cargo closes the pipe in the middle of a line.
                    Err(_) if shared.cancelled.load(Ordering::SeqCst) => break,
                    Err(err) => return Err(ExpectedError::build_exec_failed(command, err)),
                };
                if self.stream.forward_json {
                    println!("{line}");
                }
                builder.process_message_line(&line)?;
                for binary in builder.take_new_binaries() {
                    debug!(
                        "keel: Cargo reported {} at {:?}",
                        binary.id,
                        self.gate.elapsed()
                    );
                    wait_for_binary(&binary.path, command)?;
                    let snapshot = builder.snapshot(vec![binary]);
                    if jobs.send(Arc::new(snapshot)).is_err() {
                        // Every worker is gone, which only happens at shutdown.
                        break;
                    }
                }
            }
            Ok(())
        })();

        // The pipe is closed once Cargo is gone, whichever way it went.
        let status = self
            .stream
            .reader
            .try_wait()
            .map_err(|err| ExpectedError::build_exec_failed(command, err));
        self.gate.set_cargo_exit();
        if let Err(error) = read {
            self.fail(shared, error);
            return Ok(());
        }
        if shared.cancelled.load(Ordering::SeqCst) {
            return Ok(());
        }
        let output = status?.expect("Cargo has exited once its output is at the end");
        if !output.status.success() {
            self.gate.cancel();
            return Err(ExpectedError::build_failed(command, output.status.code()));
        }
        Ok(())
    }

    /// Lists, keys and plans one binary, and hands its tests to the scheduler.
    fn plan_binary(&self, binary_list: Arc<BinaryList>) -> Result<()> {
        let binary_id = binary_list.rust_binaries.first().map(|b| b.id.clone());
        debug!(
            "keel: listing {binary_id:?} on {:?} at {:?}",
            std::thread::current().id(),
            self.gate.elapsed()
        );
        let test_list = self.app.build_test_list(
            self.ctx,
            binary_list,
            self.test_filter,
            self.profile,
            ShowProgress::None,
        )?;
        // The tests borrow from their list until the end of the run, and lists
        // arrive throughout it. The lists are small, and the process ends soon
        // after the run does.
        debug!("keel: listed {binary_id:?} at {:?}", self.gate.elapsed());
        let test_list: &'t TestList<'t> = Box::leak(Box::new(test_list));
        let planned = self
            .planner
            .plan_list(test_list, self.profile)
            .map_err(|err| ExpectedError::KeelError { err })?;
        for binary in planned {
            self.feed.push(binary);
        }
        debug!(
            "keel: handed over {binary_id:?} at {:?}",
            self.gate.elapsed()
        );
        Ok(())
    }
}

/// Waits until a binary that Cargo reported can be run.
///
/// Cargo reports an artifact after it has written it, so this returns at once
/// unless a file system lags behind.
fn wait_for_binary(path: &Utf8Path, command: &[String]) -> Result<()> {
    let step = Duration::from_millis(20);
    let mut waited = Duration::ZERO;
    while !path.exists() {
        if waited >= BINARY_WAIT {
            return Err(ExpectedError::build_exec_failed(
                command,
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Cargo reported the test binary {path}, but it does not exist"),
                ),
            ));
        }
        debug!("waiting for the test binary {path}");
        std::thread::sleep(step);
        waited += step;
    }
    Ok(())
}
