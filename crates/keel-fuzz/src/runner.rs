//! Running one input in a forked child.
//!
//! Gate mode, `tmin`, `cmin`, crash triage and the coverage export all need the
//! answer to "what does this input do" without the answer depending on what ran
//! before it. A fork per input gives each run a pristine copy of the loaded
//! target, a private stderr to read the sanitizer report from, a hard timeout,
//! and survival of crashes. The edges hit come back through a shared mapping,
//! including those hit before a crash (the child's fatal-signal handler copies the
//! counters out before re-raising the signal).
//!
//! `explore` does not use this: it needs millions of executions per minute and
//! runs in-process under LibAFL's own crash handling.

use std::ffi::c_int;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use serde::Serialize;

use crate::sancov::EdgeSpace;
use crate::target::Target;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Status {
    Ok,
    Crash { signal: Option<String>, exit_code: Option<i32> },
    Timeout,
}

impl Status {
    pub fn is_ok(&self) -> bool {
        matches!(self, Status::Ok)
    }
    pub fn label(&self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Crash { .. } => "crash",
            Status::Timeout => "timeout",
        }
    }
}

#[derive(Debug)]
pub struct Outcome {
    pub status: Status,
    pub stderr: String,
    pub edges: Vec<u32>,
    pub elapsed: Duration,
}

pub fn signal_name(sig: c_int) -> String {
    match sig {
        libc::SIGSEGV => "SIGSEGV".into(),
        libc::SIGBUS => "SIGBUS".into(),
        libc::SIGILL => "SIGILL".into(),
        libc::SIGFPE => "SIGFPE".into(),
        libc::SIGABRT => "SIGABRT".into(),
        libc::SIGTRAP => "SIGTRAP".into(),
        libc::SIGKILL => "SIGKILL".into(),
        libc::SIGTERM => "SIGTERM".into(),
        other => format!("SIG{other}"),
    }
}

static mut CRASH_SPACE: *const EdgeSpace = std::ptr::null();
static mut CRASH_DST: *mut u8 = std::ptr::null_mut();

extern "C" fn on_fatal_signal(sig: c_int) {
    // SAFETY: both statics are set in the child before any signal handler is installed;
    // `snapshot_into` is async-signal-safe (plain loads and stores).
    unsafe {
        let space = &raw const CRASH_SPACE;
        let dst = &raw const CRASH_DST;
        if !(*space).is_null() && !(*dst).is_null() {
            (**space).snapshot_into(*dst);
        }
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

fn install_fatal_handlers() {
    // SAFETY: plain sigaction/sigaltstack setup in a freshly forked, single-threaded child.
    unsafe {
        // An alternate stack so a stack-overflow SIGSEGV can still run the handler.
        let size = 1 << 16;
        let stack = libc::mmap(std::ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0);
        if stack != libc::MAP_FAILED {
            let ss = libc::stack_t { ss_sp: stack, ss_flags: 0, ss_size: size };
            libc::sigaltstack(&ss, std::ptr::null_mut());
        }
        for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE, libc::SIGABRT, libc::SIGTRAP] {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_fatal_signal as usize;
            action.sa_flags = libc::SA_ONSTACK | libc::SA_NODEFER | libc::SA_RESETHAND;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}

pub struct Isolated<'a> {
    target: &'a Target,
    space: &'a EdgeSpace,
    shared: *mut u8,
}

impl<'a> Isolated<'a> {
    pub fn new(target: &'a Target, space: &'a EdgeSpace) -> Result<Self> {
        // SAFETY: anonymous shared mapping; child and parent see the same bytes.
        let shared = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                space.total.max(1),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if shared == libc::MAP_FAILED {
            bail!("mapping {} bytes of shared memory for the coverage bitmap failed: {}", space.total, std::io::Error::last_os_error());
        }
        Ok(Self { target, space, shared: shared as *mut u8 })
    }

    /// Runs `data` once in a child with a hard `timeout`.
    pub fn run(&self, data: &[u8], timeout: Duration) -> Result<Outcome> {
        let mut fds = [0 as c_int; 2];
        // SAFETY: standard pipe/fork/wait sequence; the child only calls the target and _exit.
        unsafe {
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                bail!("pipe() failed: {}", std::io::Error::last_os_error());
            }
            std::ptr::write_bytes(self.shared, 0, self.space.total);
            let start = Instant::now();
            let pid = libc::fork();
            if pid < 0 {
                bail!("fork() failed: {}", std::io::Error::last_os_error());
            }
            if pid == 0 {
                libc::close(fds[0]);
                libc::dup2(fds[1], 2);
                libc::close(fds[1]);
                CRASH_SPACE = self.space;
                CRASH_DST = self.shared;
                install_fatal_handlers();
                self.space.reset();
                self.target.run(data);
                self.space.snapshot_into(self.shared);
                libc::_exit(0);
            }
            libc::close(fds[1]);
            let mut captured = Vec::new();
            let mut buf = [0u8; 8192];
            let mut timed_out = false;
            loop {
                let left = timeout.saturating_sub(start.elapsed());
                if left.is_zero() {
                    timed_out = true;
                    break;
                }
                let mut pfd = libc::pollfd { fd: fds[0], events: libc::POLLIN, revents: 0 };
                let ms = left.as_millis().min(i32::MAX as u128) as c_int;
                let n = libc::poll(&mut pfd, 1, ms.max(1));
                if n < 0 {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                if n == 0 {
                    timed_out = true;
                    break;
                }
                let r = libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len());
                if r <= 0 {
                    break; // EOF: the child closed stderr by exiting
                }
                if captured.len() < (1 << 20) {
                    captured.extend_from_slice(&buf[..r as usize]);
                }
            }
            if timed_out {
                libc::kill(pid, libc::SIGKILL);
            }
            libc::close(fds[0]);
            let mut status: c_int = 0;
            loop {
                let r = libc::waitpid(pid, &mut status, 0);
                if r >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
            let elapsed = start.elapsed();
            let status = if timed_out {
                Status::Timeout
            } else if libc::WIFSIGNALED(status) {
                Status::Crash { signal: Some(signal_name(libc::WTERMSIG(status))), exit_code: None }
            } else if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) != 0 {
                Status::Crash { signal: None, exit_code: Some(libc::WEXITSTATUS(status)) }
            } else {
                Status::Ok
            };
            let bitmap = std::slice::from_raw_parts(self.shared, self.space.total);
            let edges = bitmap.iter().enumerate().filter(|(_, b)| **b != 0).map(|(i, _)| i as u32).collect();
            Ok(Outcome { status, stderr: String::from_utf8_lossy(&captured).into_owned(), edges, elapsed })
        }
    }
}

impl Drop for Isolated<'_> {
    fn drop(&mut self) {
        // SAFETY: unmapping our own mapping.
        unsafe { libc::munmap(self.shared.cast(), self.space.total.max(1)) };
    }
}
