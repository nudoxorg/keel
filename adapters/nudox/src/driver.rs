//! Artifact-driven integration cases for the Keel product model.
use crate::{assertion, manifest, process};

use manifest::{Case, Manifest, Step};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))
}
fn file_hash(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut file = fs::File::open(path).map_err(|e| format!("hash {}: {e}", path.display()))?;
    let mut digest = Sha256::new();
    let mut bytes = [0u8; 65536];
    loop {
        let n = file
            .read(&mut bytes)
            .map_err(|e| format!("hash {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        digest.update(&bytes[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}
fn write_capture_json(path: &Path, value: &Value, secret: Option<&str>) -> Result<(), String> {
    let mut text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    if let Some(secret) = secret {
        text = text.replace(secret, "***");
    }
    fs::write(path, text).map_err(|e| format!("write {}: {e}", path.display()))
}
fn authority_environment() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    const AUTHORITY_ENV: &[&str] = &[
        "PATH",
        "TMPDIR",
        "RUSTC",
        "COMPILER_STABLE_TOOLCHAIN",
        "COMPILER_PYTHON_COMPILER",
        "NUDOX_CARGO",
        "NUDOX_CARGO_HOME",
        "NUDOX_RUSTC",
        "NUDOX_RUST_SYSROOT",
        "NUDOX_PYTHON",
        "NUDOX_PYREFLY",
        "NUDOX_PYREFLY_BIN",
        "LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "LD_LIBRARY_PATH",
        "SSL_CERT_FILE",
    ];
    for (name, value) in std::env::vars() {
        if AUTHORITY_ENV.contains(&name.as_str())
            || name.starts_with("NIX_CFLAGS_")
            || name.starts_with("NIX_LDFLAGS")
            || name.starts_with("NIX_CC_WRAPPER_TARGET_HOST_")
        {
            env.insert(name, value);
        }
    }
    env
}
// The credential is deliberately outside the serializable environment and reports.
struct AccountKey {
    value: String,
    basename: String,
}
fn account_key() -> Result<Option<Arc<AccountKey>>, String> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::path::Component;
    let Some(path) = std::env::var_os("KEEL_NUDOX_API_KEY_FILE") else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    let fail = || "invalid private account key file or parent permissions".to_owned();
    if !path.is_absolute() {
        return Err(fail());
    }
    let basename = path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(fail)?
        .to_owned();
    let mut dir = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| fail())?;
    let parent = path.parent().ok_or_else(fail)?;
    for component in parent.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                dir = openat(
                    &dir,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| fail())?;
            }
            _ => return Err(fail()),
        }
    }
    let meta = fs::File::from(dir.try_clone().map_err(|_| fail())?)
        .metadata()
        .map_err(|_| fail())?;
    let uid = rustix::process::geteuid().as_raw();
    if meta.uid() != uid || meta.mode() & 0o7777 != 0o700 {
        return Err(fail());
    }
    let fd = openat(
        &dir,
        path.file_name().ok_or_else(fail)?,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| fail())?;
    let file = fs::File::from(fd);
    let meta = file.metadata().map_err(|_| fail())?;
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o7777 != 0o600 {
        return Err(fail());
    }
    let mut bytes = Vec::new();
    file.take(4098)
        .read_to_end(&mut bytes)
        .map_err(|_| fail())?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty()
        || bytes.len() > 4096
        || bytes
            .iter()
            .any(|b| !b.is_ascii_alphanumeric() && !b"_.-".contains(b))
    {
        return Err(fail());
    }
    let value = String::from_utf8(bytes).map_err(|_| fail())?;
    let basename = if basename.contains(&value) {
        "***".to_owned()
    } else {
        basename
    };
    Ok(Some(Arc::new(AccountKey { value, basename })))
}
struct Options {
    manifest: PathBuf,
    bins: PathBuf,
    evidence: PathBuf,
    cases: BTreeSet<String>,
    list: bool,
    inventory: bool,
    order: Option<PathBuf>,
}
fn options() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let mut paths = BTreeMap::new();
    let mut cases = BTreeSet::new();
    let mut list = false;
    let mut inventory = false;
    while let Some(arg) = args.next() {
        if arg == "--inventory" {
            inventory = true;
            continue;
        }
        if arg == "--list" {
            list = true;
            continue;
        }
        if arg == "--help" {
            println!(
                "backend-keel-harness --manifest FILE [--bin-dir DIR --evidence NEW-DIR] [--case ID] [--order FILE] [--list | --inventory]\nEvaluated Nix cases; real CLI/MCP/native-worker processes; no snapshot update mode."
            );
            std::process::exit(0);
        }
        if !["--manifest", "--bin-dir", "--evidence", "--case", "--order"].contains(&arg.as_str()) {
            return Err(format!("unknown argument {arg}"));
        }
        let value = args.next().ok_or_else(|| format!("{arg} needs a value"))?;
        if arg == "--case" {
            if !cases.insert(value) {
                return Err("duplicate --case".into());
            }
        } else if paths.insert(arg, PathBuf::from(value)).is_some() {
            return Err("duplicate option".into());
        }
    }
    let manifest = paths.remove("--manifest").ok_or("--manifest is required")?;
    let bins = paths.remove("--bin-dir").unwrap_or_default();
    let evidence = paths.remove("--evidence").unwrap_or_default();
    if !list && !inventory && (bins.as_os_str().is_empty() || evidence.as_os_str().is_empty()) {
        return Err("--bin-dir and --evidence are required for execution".into());
    }
    Ok(Options {
        manifest,
        bins,
        evidence,
        cases,
        list,
        inventory,
        order: paths.remove("--order"),
    })
}
fn session_pid(sessions: &BTreeMap<String, NamedSession>, name: &str) -> Result<u32, String> {
    sessions
        .get(name)
        .map(|session| session.process.pid())
        .ok_or_else(|| "MCP session is not live".into())
}
struct NamedSession {
    process: process::Session,
    next_id: u64,
}
struct World {
    root: PathBuf,
    project: PathBuf,
    endpoint: PathBuf,
    bins: PathBuf,
    env: BTreeMap<String, String>,
    account_key: Option<Arc<AccountKey>>,
    daemon: Option<process::Daemon>,
    generation: usize,
    bindings: BTreeMap<String, Value>,
    sessions: BTreeMap<String, NamedSession>,
}
impl World {
    fn new(
        case: &Case,
        bins: &Path,
        root: &Path,
        serial: usize,
        account_key: Option<Arc<AccountKey>>,
    ) -> Result<Self, String> {
        let project = root.join("project");
        fs::create_dir_all(&project).map_err(|e| e.to_string())?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        let home = root.join("home");
        let mut env = BTreeMap::new();
        // Native tool authorities are explicit inputs of the Nix world. Application
        // selection, credentials and user state cannot leak into a fresh owner.
        env.extend(authority_environment());
        for (key, sub) in [
            ("HOME", ""),
            ("XDG_CONFIG_HOME", ".config"),
            ("XDG_DATA_HOME", ".local/share"),
            ("XDG_STATE_HOME", ".local/state"),
            ("XDG_CACHE_HOME", ".cache"),
            ("XDG_RUNTIME_DIR", "run"),
        ] {
            let path = home.join(sub);
            fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
            env.insert(key.into(), path.to_string_lossy().into_owned());
        }
        for key in [
            "NUDOX_TSC",
            "NUDOX_TYPESCRIPT_NODE",
            "NUDOX_TYPESCRIPT_MODULE_ROOT",
            "NUDOX_TYPESCRIPT_REPORT_PROGRAM",
        ] {
            env.remove(key);
        }
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace).map_err(|e| e.to_string())?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        let authority = workspace.join("authority.secret");
        fs::write(&authority, [0x5a; 32]).map_err(|e| e.to_string())?;
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        env.insert(
            "BACKEND_LOCALD_BIN".into(),
            bins.join("backend-locald").to_string_lossy().into_owned(),
        );
        env.insert(
            "BACKEND_LOCALD_WORKSPACE".into(),
            workspace.to_string_lossy().into_owned(),
        );
        env.insert(
            "BACKEND_LOCALD_AUTHORITY_SECRET_FILE".into(),
            authority.to_string_lossy().into_owned(),
        );
        env.insert("NO_COLOR".into(), "1".into());
        let endpoint = PathBuf::from(format!("/tmp/nkx-{}-{serial}.sock", std::process::id()));
        if endpoint.exists() {
            return Err(format!("endpoint already exists: {}", endpoint.display()));
        }
        let mut bindings = BTreeMap::new();
        bindings.insert(
            "project".into(),
            Value::String(project.to_string_lossy().into_owned()),
        );
        let mut world = Self {
            root: root.to_path_buf(),
            project,
            endpoint,
            bins: bins.to_path_buf(),
            env,
            account_key,
            daemon: None,
            generation: 0,
            bindings,
            sessions: BTreeMap::new(),
        };
        world.files(&case.files, &[])?;
        Ok(world)
    }
    fn command(&self, binary: &str) -> Command {
        let mut command = Command::new(self.bins.join(binary));
        command
            .env_clear()
            .envs(&self.env)
            .current_dir(&self.project);
        command
    }
    fn account_command(&self, binary: &str) -> Command {
        let mut command = self.command(binary);
        if let Some(key) = &self.account_key {
            command.env("NUDOX_API_KEY", &key.value);
        }
        command
    }
    fn secret(&self) -> Option<&str> {
        self.account_key.as_ref().map(|k| k.value.as_str())
    }
    fn expand(&self, value: &str) -> Result<String, String> {
        let mut out = value.to_owned();
        for (name, value) in &self.bindings {
            if let Some(value) = value.as_str() {
                out = out.replace(&format!("${{{name}}}"), value);
            }
        }
        if out.contains("${") {
            return Err(format!("unbound placeholder in {out:?}"));
        }
        Ok(out)
    }
    fn expand_json(&self, value: &Value) -> Result<Value, String> {
        Ok(match value {
            Value::String(s) => {
                if let Some(name) = s.strip_prefix("${").and_then(|v| v.strip_suffix('}')) {
                    if let Some(value) = self.bindings.get(name) {
                        return Ok(value.clone());
                    }
                }
                Value::String(self.expand(s)?)
            }
            Value::Array(a) => Value::Array(
                a.iter()
                    .map(|v| self.expand_json(v))
                    .collect::<Result<_, _>>()?,
            ),
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(k, v)| Ok((k.clone(), self.expand_json(v)?)))
                    .collect::<Result<_, String>>()?,
            ),
            other => other.clone(),
        })
    }
    fn check(
        &self,
        expect: &manifest::Expect,
        code: Option<i32>,
        stdout: &[u8],
        stderr: &[u8],
        value: Option<&Value>,
    ) -> Result<(), String> {
        let assertions = expect
            .json
            .iter()
            .map(|a| {
                Ok(manifest::Assertion {
                    pointer: a.pointer.clone(),
                    select: a.select.clone(),
                    absent: a.absent,
                    equals: a.equals.as_ref().map(|v| self.expand_json(v)).transpose()?,
                    contains: a
                        .contains
                        .as_ref()
                        .map(|v| self.expand_json(v))
                        .transpose()?,
                    not_contains: a
                        .not_contains
                        .as_ref()
                        .map(|v| self.expand_json(v))
                        .transpose()?,
                    set_equals: a
                        .set_equals
                        .as_ref()
                        .map(|values| {
                            values
                                .iter()
                                .map(|v| self.expand_json(v))
                                .collect::<Result<Vec<_>, _>>()
                        })
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let expanded = manifest::Expect {
            exit: expect.exit,
            json: assertions,
            stdout_contains: expect
                .stdout_contains
                .iter()
                .map(|v| self.expand(v))
                .collect::<Result<_, _>>()?,
            stderr_contains: expect
                .stderr_contains
                .iter()
                .map(|v| self.expand(v))
                .collect::<Result<_, _>>()?,
        };
        assertion::check(&expanded, code, stdout, stderr, value)
    }
    fn files(&mut self, files: &BTreeMap<String, String>, remove: &[String]) -> Result<(), String> {
        for path in remove {
            manifest::relative(path)?;
            fs::remove_file(self.project.join(path))
                .map_err(|e| format!("remove fixture {path}: {e}"))?;
        }
        for (path, contents) in files {
            manifest::relative(path)?;
            let path = self.project.join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(&path, contents)
                .map_err(|e| format!("write fixture {}: {e}", path.display()))?;
        }
        Ok(())
    }
    fn start(&mut self) -> Result<(), String> {
        if let Some(mut daemon) = self.daemon.take() {
            daemon.stop()?;
        }
        if self.endpoint.exists() {
            fs::remove_file(&self.endpoint).map_err(|e| e.to_string())?;
        }
        self.generation += 1;
        let mut command = self.command("backend-locald");
        command
            .args(["--endpoint"])
            .arg(&self.endpoint)
            .arg("--workspace")
            .arg(self.root.join("workspace"))
            .args(["--profile", "builtin", "--authority-secret-file"])
            .arg(self.root.join("workspace/authority.secret"))
            .args([
                "--max-frame",
                "1048576",
                "--timeout-ms",
                "180000",
                "--registry-offline",
                "--registry-discovery-offline",
                "--advisory-offline",
                "--forge-offline",
                "--idle-timeout-ms",
                "0",
            ]);
        let mut daemon = process::Daemon::spawn(
            &mut command,
            &self.root.join(format!("locald-{}.log", self.generation)),
            self.secret(),
        )?;
        let end = Instant::now() + Duration::from_secs(90);
        loop {
            if !daemon.is_running()? {
                return Err("locald exited before readiness; inspect locald log".into());
            }
            if UnixStream::connect(&self.endpoint).is_ok() {
                break;
            }
            if Instant::now() >= end {
                return Err("locald readiness exceeded 90s; inspect locald log".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.daemon = Some(daemon);
        Ok(())
    }
    fn cli(
        &self,
        args: &[String],
        format: &str,
        deadline: Duration,
        prefix: &Path,
    ) -> Result<process::Output, String> {
        let mut command = self.account_command("backend-cli");
        command
            .arg("--endpoint")
            .arg(&self.endpoint)
            .arg("--project")
            .arg(&self.project)
            .args(["--format", format]);
        for arg in args {
            command.arg(self.expand(arg)?);
        }
        process::run(&mut command, None, deadline, prefix, self.secret())
    }
    fn mcp_start(
        &mut self,
        step: &Step,
        prefix: &Path,
        timeout: Duration,
    ) -> Result<Value, String> {
        if self.sessions.contains_key(&step.session) || self.sessions.len() >= 8 {
            return Err("MCP session already live or session limit reached".into());
        }
        let deadline = Instant::now() + timeout;
        let mut command = self.account_command("backend-mcp");
        command
            .arg("--endpoint")
            .arg(&self.endpoint)
            .arg("--project")
            .arg(&self.project);
        let process = process::Session::spawn(&mut command, prefix, self.secret())?;
        self.sessions.insert(
            step.session.clone(),
            NamedSession {
                process,
                next_id: 1,
            },
        );
        let capture_secret = self.secret().map(str::to_owned);
        let process = &mut self
            .sessions
            .get_mut(&step.session)
            .ok_or("new MCP session missing")?
            .process;
        let request = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"keel-session-contract","version":"1"}}});
        write_capture_json(
            &prefix.with_extension("initialize-request.json"),
            &request,
            capture_secret.as_deref(),
        )?;
        let reply =
            process.exchange(&request, deadline.saturating_duration_since(Instant::now()))?;
        write_capture_json(
            &prefix.with_extension("initialize-reply.json"),
            &reply,
            capture_secret.as_deref(),
        )?;
        if reply.get("result").is_none() || reply.get("error").is_some() {
            return Err(format!("MCP initialization refused: {reply}"));
        }
        let notification = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        write_json(
            &prefix.with_extension("initialized-notification.json"),
            &notification,
        )?;
        process.exchange(
            &notification,
            deadline.saturating_duration_since(Instant::now()),
        )?;
        let result = json!({"session":step.session,"pid":process.pid(),"isolation":process.isolation(),"request_sha256":file_hash(&prefix.with_extension("initialize-request.json"))?,"reply_sha256":file_hash(&prefix.with_extension("initialize-reply.json"))?});
        write_json(&prefix.with_extension("json"), &result)?;
        for (name, binding) in &step.bind {
            self.bindings.insert(name.clone(), binding.value(&result)?);
        }
        Ok(result)
    }
    fn mcp_call(&mut self, step: &Step, prefix: &Path, timeout: Duration) -> Result<Value, String> {
        let call = if let Some(call) = &step.call {
            self.expand_json(call)?
        } else {
            json!({"name":step.tool,"arguments":self.expand_json(&step.arguments)?})
        };
        if call.as_object().is_none_or(|map| {
            map.len() != 2
                || !map
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| !name.is_empty())
                || !map.get("arguments").is_some_and(Value::is_object)
        }) {
            return Err("MCP call must be the exact {name, arguments} object".into());
        }
        let capture_secret = self.secret().map(str::to_owned);
        let session = self
            .sessions
            .get_mut(&step.session)
            .ok_or("MCP session is not live")?;
        let id = session.next_id;
        session.next_id = id.checked_add(1).ok_or("MCP request id exhausted")?;
        let request = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":call});
        if serde_json::to_vec(&request)
            .map_err(|error| error.to_string())?
            .len()
            >= 8 * 1024 * 1024
        {
            return Err("MCP request exceeds the bounded session frame".into());
        }
        write_capture_json(
            &prefix.with_extension("request.json"),
            &request,
            capture_secret.as_deref(),
        )?;
        let reply = session.process.exchange(&request, timeout)?;
        write_capture_json(
            &prefix.with_extension("reply.json"),
            &reply,
            capture_secret.as_deref(),
        )?;
        let result = reply
            .get("result")
            .ok_or_else(|| format!("MCP JSON-RPC fault: {reply}"))?;
        let is_error = match result.get("isError") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err("MCP isError must be a boolean".into()),
        };
        if is_error != step.mcp_error {
            return Err(format!(
                "MCP isError differs from expected {}: {result}",
                step.mcp_error
            ));
        }
        let structured = result
            .get("structuredContent")
            .ok_or("MCP result lacks structuredContent")?;
        write_json(&prefix.with_extension("json"), structured)?;
        self.check(
            step.expect.as_ref().ok_or("MCP call lacks expectation")?,
            Some(0),
            &[],
            &[],
            Some(structured),
        )?;
        for (name, binding) in &step.bind {
            self.bindings
                .insert(name.clone(), binding.value(structured)?);
        }
        Ok(
            json!({"session":step.session,"pid":session_pid(&self.sessions, &step.session)?,"request_id":id,"is_error":step.mcp_error,"request_sha256":file_hash(&prefix.with_extension("request.json"))?,"reply_sha256":file_hash(&prefix.with_extension("reply.json"))?}),
        )
    }
    fn mcp_stop(&mut self, step: &Step, prefix: &Path, timeout: Duration) -> Result<Value, String> {
        let mut named = self
            .sessions
            .remove(&step.session)
            .ok_or("MCP session is not live")?;
        let pid = named.process.pid();
        let isolation = named.process.isolation().clone();
        named.process.finish_with_timeout(timeout)?;
        let result = json!({"session":step.session,"pid":pid,"isolation":isolation,"reaped":true});
        write_json(&prefix.with_extension("json"), &result)?;
        Ok(result)
    }
    fn stop_sessions(&mut self) -> Result<(), String> {
        let mut failures = Vec::new();
        for (name, mut session) in std::mem::take(&mut self.sessions) {
            if let Err(error) = session.process.finish_with_timeout(Duration::from_secs(2)) {
                failures.push(format!("{name}: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
    fn pages(&mut self, step: &Step, prefix: &Path) -> Result<Value, String> {
        let deadline = Instant::now() + Duration::from_secs(step.timeout_seconds);
        let remaining = || deadline.saturating_duration_since(Instant::now());
        let mut command = self.account_command("backend-mcp");
        command
            .arg("--endpoint")
            .arg(&self.endpoint)
            .arg("--project")
            .arg(&self.project);
        let mut session = process::Session::spawn(&mut command, prefix, self.secret())?;
        let init = session.exchange(&json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"keel-paged-contract","version":"1"}}}), remaining())?;
        if init.get("result").is_none() {
            return Err(format!("paged MCP initialize refused: {init}"));
        }
        session.exchange(
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            remaining(),
        )?;
        let mut call = json!({"name":step.tool,"arguments":self.expand_json(&step.arguments)?});
        let mut visited = BTreeSet::new();
        let mut records = Vec::new();
        let mut identities = BTreeSet::new();
        let mut first = Value::Null;
        let mut pages = 0usize;
        let mut receipts = Vec::new();
        let mut related =
            (step.tool == "backend.related").then(crate::related_pages::RelatedPages::default);
        let last = loop {
            if pages == step.maximum_pages {
                return Err(format!(
                    "continuation exceeded {} pages",
                    step.maximum_pages
                ));
            }
            if !visited.insert(call.to_string()) {
                return Err("continuation repeated an earlier opaque call".into());
            }
            let request = json!({"jsonrpc":"2.0","id":pages+1,"method":"tools/call","params":call});
            let request_path = prefix.with_extension(format!("page-{pages}.request.json"));
            let reply_path = prefix.with_extension(format!("page-{pages}.json"));
            write_capture_json(&request_path, &request, self.secret())?;
            let reply = session.exchange(&request, remaining())?;
            write_capture_json(&reply_path, &reply, self.secret())?;
            receipts.push(json!({"pid":session.pid(),"request_id":pages+1,"request_sha256":file_hash(&request_path)?,"reply_sha256":file_hash(&reply_path)?}));
            let result = reply
                .get("result")
                .ok_or_else(|| format!("paged JSON-RPC fault: {reply}"))?;
            if result["isError"] == true {
                return Err(format!("paged tool refused: {result}"));
            }
            let structured = result
                .get("structuredContent")
                .ok_or("paged tool lacks structuredContent")?;
            if structured["answer"] == "fault" {
                return Err(format!("paged answer fault: {structured}"));
            }
            let page_records = structured["records"]
                .as_array()
                .ok_or("paged answer lacks records")?;
            if let Some(window) = structured.get("references_page") {
                let offset = window["offset"]
                    .as_u64()
                    .ok_or("references offset absent")? as usize;
                let returned = window["returned"]
                    .as_u64()
                    .ok_or("references returned absent")? as usize;
                let total = window["total"].as_u64().ok_or("references total absent")? as usize;
                let remaining_rows = window["remaining"]
                    .as_u64()
                    .ok_or("references remaining absent")?
                    as usize;
                if offset != records.len()
                    || returned != page_records.len()
                    || offset
                        .checked_add(returned)
                        .and_then(|n| n.checked_add(remaining_rows))
                        != Some(total)
                {
                    return Err(format!("references page lost its exact frontier: {window}"));
                }
                if pages > 0 && first["references_page"]["total"] != window["total"] {
                    return Err("reference total changed during continuation".into());
                }
            }
            if let Some(related) = &mut related {
                related.push(structured, pages)?;
            } else {
                for row in page_records {
                    if !identities.insert(row.to_string()) {
                        return Err("continuation repeated an exact reference/record".into());
                    }
                    records.push(row.clone());
                }
            }
            if pages == 0 {
                first = structured.clone();
            }
            pages += 1;
            match structured.get("continuation_call") {
                None => {
                    if structured.get("nextCursor").is_some_and(|v| !v.is_null()) {
                        return Err("opaque cursor has no exact continuation_call".into());
                    }
                    break structured.clone();
                }
                Some(next) => {
                    if next["name"] != step.tool {
                        return Err("continuation changed tool name".into());
                    }
                    if related.is_none() && page_records.is_empty() {
                        return Err("continuation made no row progress".into());
                    }
                    call = next.clone();
                }
            }
        };
        let isolation = session.isolation().clone();
        session.finish()?;
        if pages < step.minimum_pages {
            return Err(format!(
                "fixture requires at least {} pages, got {pages}",
                step.minimum_pages
            ));
        }
        let aggregate = if let Some(related) = related {
            related.finish(pages, first, last)?
        } else {
            json!({"pages":pages,"records":records,"first":first,"last":last})
        };
        write_json(&prefix.with_extension("aggregate.json"), &aggregate)?;
        self.check(
            step.expect
                .as_ref()
                .ok_or("paged check lacks expectation")?,
            Some(0),
            &[],
            &[],
            Some(&aggregate),
        )?;
        for (name, binding) in &step.bind {
            self.bindings
                .insert(name.clone(), binding.value(&aggregate)?);
        }
        Ok(
            json!({"pages":pages,"records":aggregate["records"].as_array().map_or(0,Vec::len),"isolation":isolation,"page_receipts":receipts}),
        )
    }
    fn source_pages(
        &mut self,
        step: &Step,
        prefix: &Path,
        timeout: Duration,
    ) -> Result<Value, String> {
        let deadline = Instant::now() + timeout;
        let remaining = || deadline.saturating_duration_since(Instant::now());
        let mut command = self.account_command("backend-mcp");
        command
            .arg("--endpoint")
            .arg(&self.endpoint)
            .arg("--project")
            .arg(&self.project);
        let mut session = process::Session::spawn(&mut command, prefix, self.secret())?;
        let init = session.exchange(&json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"keel-source-contract","version":"1"}}}), remaining())?;
        if init.get("result").is_none() {
            return Err("source MCP initialization refused".into());
        }
        session.exchange(
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            remaining(),
        )?;
        let mut call = json!({"name":step.tool,"arguments":self.expand_json(&step.arguments)?});
        let original_arguments = call["arguments"].clone();
        let mut frozen_selector = None::<serde_json::Map<String, Value>>;
        let mut visited = BTreeSet::new();
        let mut aggregate = crate::source_pages::SourcePages::default();
        let mut receipts = Vec::new();
        loop {
            let n = receipts.len();
            if n >= step.maximum_pages {
                return Err("source continuation exceeded maximum pages".into());
            }
            if !visited.insert(call.to_string()) {
                return Err("source continuation repeated an opaque call".into());
            }
            let request = json!({"jsonrpc":"2.0","id":n+1,"method":"tools/call","params":call});
            let request_path = prefix.with_extension(format!("page-{n}.request.json"));
            let reply_path = prefix.with_extension(format!("page-{n}.json"));
            write_capture_json(&request_path, &request, self.secret())?;
            let reply = session.exchange(&request, remaining())?;
            write_capture_json(&reply_path, &reply, self.secret())?;
            receipts.push(json!({"pid":session.pid(),"request_id":n+1,"request_sha256":file_hash(&request_path)?,"reply_sha256":file_hash(&reply_path)?}));
            let result = reply.get("result").ok_or("source JSON-RPC fault")?;
            match result.get("isError") {
                None | Some(Value::Bool(false)) => {}
                Some(Value::Bool(true)) => return Err("source tool refused".into()),
                Some(_) => return Err("source isError must be a boolean".into()),
            }
            let page = result
                .get("structuredContent")
                .ok_or("source structured content missing")?;
            if page["answer"] == "fault" {
                return Err("source returned a fault".into());
            }
            let cursor = aggregate.push(page)?;
            match cursor {
                Some(cursor) => {
                    let next = page
                        .get("continuation_call")
                        .ok_or("source continuation missing")?;
                    if next.as_object().is_none_or(|o| {
                        o.len() != 2
                            || o.get("name") != Some(&json!("backend.source"))
                            || !o.get("arguments").is_some_and(Value::is_object)
                    }) || next["arguments"]["cursor"].as_str() != Some(cursor.as_str())
                    {
                        return Err("source continuation does not match cursor".into());
                    }
                    let arguments = next["arguments"]
                        .as_object()
                        .ok_or("source continuation arguments missing")?;
                    if arguments.get("byte_range") != Some(&Value::Bool(true))
                        || ["coordinate", "selected_symbol", "detail"]
                            .iter()
                            .any(|field| {
                                original_arguments
                                    .get(*field)
                                    .is_some_and(|original| arguments.get(*field) != Some(original))
                            })
                    {
                        return Err("source continuation changed the requested selector".into());
                    }
                    let mut selector = arguments.clone();
                    selector.remove("cursor");
                    if frozen_selector
                        .as_ref()
                        .is_some_and(|frozen| frozen != &selector)
                    {
                        return Err("source continuation changed its frozen selector".into());
                    }
                    frozen_selector.get_or_insert(selector);
                    call = next.clone();
                }
                None => {
                    if page.get("continuation_call").is_some_and(|v| !v.is_null()) {
                        return Err("terminal source has continuation".into());
                    }
                    break;
                }
            }
        }
        let isolation = session.isolation().clone();
        session.finish_with_timeout(remaining())?;
        if receipts.len() < step.minimum_pages {
            return Err("source requires more pages".into());
        }
        let mut value = aggregate.finish()?;
        let mut cli_receipts = Vec::new();
        if !step.cli.is_empty() {
            let mut cli_pages = crate::source_pages::SourcePages::default();
            let mut cursor = None::<String>;
            let mut seen = BTreeSet::new();
            loop {
                let n = cli_receipts.len();
                if n >= step.maximum_pages {
                    return Err("CLI source exceeded maximum pages".into());
                }
                let mut args = step.cli.clone();
                if let Some(token) = &cursor {
                    if !seen.insert(token.clone()) {
                        return Err("CLI source cursor repeated".into());
                    }
                    args.push("--cursor".into());
                    args.push(token.clone());
                }
                let cli_prefix = prefix.with_extension(format!("cli-page-{n}"));
                let request_path = prefix.with_extension(format!("cli-page-{n}.request.json"));
                let expanded = args
                    .iter()
                    .map(|s| self.expand(s))
                    .collect::<Result<Vec<_>, _>>()?;
                write_capture_json(&request_path, &json!(expanded), self.secret())?;
                let output = self.cli(&args, "json", remaining(), &cli_prefix)?;
                if output.code != Some(0) {
                    return Err("CLI source page refused".into());
                }
                let reply: Value = serde_json::from_slice(&output.stdout)
                    .map_err(|e| format!("CLI source page is not JSON: {e}"))?;
                let page = reply
                    .get("declaration_source_range")
                    .ok_or("CLI source range missing")?;
                cursor = cli_pages.push(page)?;
                let mut stdout_name = cli_prefix.as_os_str().to_os_string();
                stdout_name.push(".stdout");
                cli_receipts.push(json!({"request_sha256":file_hash(&request_path)?,"reply_sha256":file_hash(Path::new(&stdout_name))?}));
                if cursor.is_none() {
                    break;
                }
            }
            let cli_value = cli_pages.finish()?;
            for field in [
                "text",
                "bytes",
                "scope",
                "source_identity",
                "total",
                "owner_start",
                "owner_end",
            ] {
                if cli_value[field] != value[field] {
                    return Err(format!("CLI and MCP source {field} differs"));
                }
            }
            value["cli_first"] = cli_value["first"].clone();
            value["cli_last"] = cli_value["last"].clone();
        }
        value["cli_pages"] = json!(cli_receipts.len());
        write_json(&prefix.with_extension("aggregate.json"), &value)?;
        self.check(
            step.expect
                .as_ref()
                .ok_or("source pages expectation missing")?,
            Some(0),
            &[],
            &[],
            Some(&value),
        )?;
        for (name, binding) in &step.bind {
            self.bindings.insert(name.clone(), binding.value(&value)?);
        }
        Ok(
            json!({"pages":receipts.len(),"cli_pages":cli_receipts.len(),"bytes":value["bytes"],"isolation":isolation,"page_receipts":receipts,"cli_page_receipts":cli_receipts}),
        )
    }
    fn step(&mut self, step: &Step, prefix: &Path) -> Result<Value, String> {
        let timeout = Duration::from_secs(step.timeout_seconds);
        if !step.wait_for {
            return self.step_once(step, prefix, timeout);
        }
        let deadline = Instant::now() + timeout;
        let mut attempt = 0usize;
        loop {
            let mut name = prefix.as_os_str().to_os_string();
            name.push(format!("-attempt-{attempt}"));
            match self.step_once(
                step,
                Path::new(&name),
                deadline.saturating_duration_since(Instant::now()),
            ) {
                Ok(result) => return Ok(json!({"convergence_attempts":attempt+1,"result":result})),
                Err(error) if Instant::now() >= deadline => {
                    return Err(format!(
                        "query predicate never converged before its absolute deadline: {error}"
                    ));
                }
                Err(error) => {
                    fs::write(prefix.with_extension("last-readiness-error"), error)
                        .map_err(|e| e.to_string())?;
                }
            }
            std::thread::sleep(Duration::from_millis(30));
            attempt += 1;
        }
    }
    fn step_once(
        &mut self,
        step: &Step,
        prefix: &Path,
        timeout: Duration,
    ) -> Result<Value, String> {
        let until = Instant::now() + timeout;
        let time_left = || until.saturating_duration_since(Instant::now());
        if step.kind == "pages" {
            return if step.page_format.as_deref() == Some("source-range") {
                self.source_pages(step, prefix, timeout)
            } else {
                self.pages(step, prefix)
            };
        }
        match step.kind.as_str() {
            "mcp-start" => return self.mcp_start(step, prefix, timeout),
            "mcp-call" => return self.mcp_call(step, prefix, timeout),
            "mcp-stop" => return self.mcp_stop(step, prefix, timeout),
            "write" => {
                self.files(&step.files, &step.remove)?;
                return Ok(
                    json!({"changed":step.files.keys().collect::<Vec<_>>(),"removed":step.remove}),
                );
            }
            "restart" => {
                self.start()?;
                return Ok(json!({"generation":self.generation}));
            }
            "index" => {
                let args = vec![
                    "add".into(),
                    "${project}".into(),
                    "--wait".into(),
                    "--wait-timeout".into(),
                    step.timeout_seconds.to_string(),
                ];
                let output = self.cli(&args, "json", time_left(), prefix)?;
                let value: Value = serde_json::from_slice(&output.stdout)
                    .map_err(|e| format!("index returned non-JSON: {e}"))?;
                let detail = &value["index_operation"]["detail"];
                if output.code != Some(0)
                    || value["answer"] == "fault"
                    || value["index_operation"]["state"] != "known"
                    || detail["state"]["state"] != "published"
                {
                    return Err(format!(
                        "index must publish a terminal receipt, got {value}"
                    ));
                }
                let profiles = detail["source_capture"]["profiles"]
                    .as_array()
                    .ok_or("index receipt lacks native profiles")?;
                if profiles.is_empty()
                    || profiles.iter().any(|p| {
                        p["state"]["state"] != "published"
                            || p["state"]["detail"]["coverage"] != json!({"coverage":"complete"})
                    })
                {
                    return Err(format!(
                        "index native profile coverage incomplete: {profiles:?}"
                    ));
                }
                let root = detail["state"]["detail"]["view_root"]
                    .as_str()
                    .ok_or("published receipt lacks view_root")?;
                if root.len() != 64 || !root.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("published view_root malformed".into());
                }
                if let Some(expect) = &step.expect {
                    self.check(
                        expect,
                        output.code,
                        &output.stdout,
                        &output.stderr,
                        Some(&value),
                    )?;
                }
                write_json(&prefix.with_extension("json"), &value)?;
                return Ok(json!({"view_root":root,"profiles":profiles}));
            }
            _ => {}
        }
        let output = match step.kind.as_str() {
            "cli" => self.cli(&step.args, "json", time_left(), prefix)?,
            "query" => self.cli(&step.cli, "json", time_left(), prefix)?,
            "process" => {
                let mut command = self.command(&step.binary);
                for arg in &step.args {
                    command.arg(self.expand(arg)?);
                }
                let input = if step.protocol.as_deref() == Some("stylo") {
                    let source = step
                        .source
                        .as_ref()
                        .ok_or("Stylo request lacks source")?
                        .as_bytes();
                    let config = serde_json::to_vec(
                        step.config.as_ref().ok_or("Stylo request lacks config")?,
                    )
                    .map_err(|e| e.to_string())?;
                    let mut bytes = b"STYLOR01".to_vec();
                    bytes.extend_from_slice(
                        &u32::try_from(config.len())
                            .map_err(|_| "Stylo config too large")?
                            .to_be_bytes(),
                    );
                    bytes.extend_from_slice(
                        &u32::try_from(source.len())
                            .map_err(|_| "Stylo source too large")?
                            .to_be_bytes(),
                    );
                    bytes.extend_from_slice(&config);
                    bytes.extend_from_slice(source);
                    Some(bytes)
                } else if let Some(value) = &step.input {
                    let mut value = self.expand_json(value)?;
                    if let Some(source) = &step.source {
                        value
                            .as_object_mut()
                            .ok_or("source injection requires input object")?
                            .insert("source".into(), json!(source.as_bytes()));
                    }
                    Some(serde_json::to_vec(&value).map_err(|e| e.to_string())?)
                } else {
                    step.stdin
                        .as_ref()
                        .map(|s| self.expand(s).map(String::into_bytes))
                        .transpose()?
                };
                process::run(&mut command, input, time_left(), prefix, self.secret())?
            }
            _ => return Err("validated step kind became unknown".into()),
        };
        let decoded = if step.protocol.as_deref() == Some("stylo") && output.code == Some(0) {
            if output.stdout.len() < 12 || &output.stdout[..8] != b"STYLOS01" {
                return Err("Stylo response frame magic/truncation".into());
            }
            let size = u32::from_be_bytes(
                output.stdout[8..12]
                    .try_into()
                    .map_err(|_| "Stylo length")?,
            ) as usize;
            if size != output.stdout.len() - 12 {
                return Err("Stylo response length differs from complete frame".into());
            }
            &output.stdout[12..]
        } else {
            &output.stdout[..]
        };
        let value = if step.protocol.as_deref() == Some("jsonrpc-lines") {
            let mut replies = serde_json::Map::new();
            for line in decoded
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
            {
                let reply: Value =
                    serde_json::from_slice(line).map_err(|e| format!("JSON-RPC output: {e}"))?;
                let id = reply
                    .get("id")
                    .ok_or("JSON-RPC response lacks id")?
                    .to_string();
                if replies.insert(id, reply).is_some() {
                    return Err("JSON-RPC emitted duplicate response identity".into());
                }
            }
            Some(Value::Object(replies))
        } else {
            serde_json::from_slice::<Value>(decoded).ok()
        };
        if let (Some(source), Some(value)) = (&step.source, &value) {
            let field = if step.protocol.as_deref() == Some("stylo") {
                "source_digest"
            } else {
                "content_sha256"
            };
            let digest: [u8; 32] = if step.protocol.as_deref() == Some("stylo") {
                *blake3::hash(source.as_bytes()).as_bytes()
            } else {
                Sha256::digest(source.as_bytes()).into()
            };
            if value.get(field) != Some(&json!(digest)) {
                return Err(format!(
                    "native worker {field} is not bound to the exact submitted source bytes"
                ));
            }
        }
        let expect = step.expect.as_ref().ok_or("missing expectation")?;
        self.check(
            expect,
            output.code,
            &output.stdout,
            &output.stderr,
            value.as_ref(),
        )?;
        if let Some(value) = &value {
            write_json(&prefix.with_extension("json"), value)?;
        }
        if step.kind == "query" {
            let params = json!({"name":step.tool,"arguments":self.expand_json(&step.arguments)?});
            let requests = [
                json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"keel-integration","version":"1"}}}),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":params}),
            ];
            let input = requests
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let mut command = self.account_command("backend-mcp");
            command
                .arg("--endpoint")
                .arg(&self.endpoint)
                .arg("--project")
                .arg(&self.project);
            let mcp = process::run(
                &mut command,
                Some(input.into_bytes()),
                time_left(),
                &prefix.with_extension("mcp"),
                self.secret(),
            )?;
            if mcp.code != Some(0) {
                return Err(format!(
                    "MCP process exited {:?}: {}",
                    mcp.code,
                    String::from_utf8_lossy(&mcp.stderr)
                ));
            }
            let mut replies = BTreeMap::new();
            for line in mcp
                .stdout
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
            {
                let reply: Value = serde_json::from_slice(line)
                    .map_err(|e| format!("MCP emitted malformed JSON: {e}"))?;
                if let Some(id) = reply.get("id") {
                    if replies.insert(id.to_string(), reply).is_some() {
                        return Err("MCP emitted duplicate response id".into());
                    }
                }
            }
            if replies.get("0").and_then(|v| v.get("result")).is_none() {
                return Err("MCP initialization missing or refused".into());
            }
            let rpc = replies.get("1").ok_or("MCP omitted tool response")?;
            let result = rpc
                .get("result")
                .ok_or_else(|| format!("MCP JSON-RPC fault: {rpc}"))?;
            if result["isError"] == true && expect.exit == 0 {
                return Err(format!(
                    "MCP tool refused successful CLI operation: {result}"
                ));
            }
            if result.get("structuredContent") != value.as_ref() {
                write_json(
                    &prefix.with_extension("parity-diff.json"),
                    &json!({"cli":value,"mcp":result.get("structuredContent")}),
                )?;
                return Err(
                    "CLI JSON and MCP structuredContent differ; inspect parity-diff.json".into(),
                );
            }
            let markdown = self.cli(
                &step.cli,
                "markdown",
                time_left(),
                &prefix.with_extension("markdown"),
            )?;
            if markdown.code != Some(expect.exit) {
                return Err("CLI markdown exit differs from JSON".into());
            }
            let text = result["content"]
                .as_array()
                .ok_or("MCP omitted content")?
                .iter()
                .filter_map(|v| v["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if String::from_utf8_lossy(&markdown.stdout).trim_end_matches('\n')
                != text.trim_end_matches('\n')
            {
                return Err("CLI markdown and MCP text differ; inspect raw captures".into());
            }
            write_json(&prefix.with_extension("mcp.json"), rpc)?;
        }
        if !step.bind.is_empty() {
            let value = value.as_ref().ok_or("bindings require JSON")?;
            for (name, binding) in &step.bind {
                self.bindings.insert(name.clone(), binding.value(value)?);
            }
        }
        Ok(
            json!({"exit":output.code,"duration_ms":output.elapsed_ms,"stdout_sha256":hash(&output.stdout),"stderr_sha256":hash(&output.stderr),"isolation":output.isolation}),
        )
    }
}
impl Drop for World {
    fn drop(&mut self) {
        self.daemon.take();
        let _ = fs::remove_file(&self.endpoint);
    }
}

fn run() -> Result<bool, String> {
    let options = options()?;
    let raw = read(&options.manifest)?;
    let driver_path = std::env::current_exe().map_err(|e| format!("driver identity: {e}"))?;
    let driver_sha256 = file_hash(&driver_path)?;
    let manifest: Manifest = serde_json::from_slice(&raw).map_err(|e| format!("manifest: {e}"))?;
    manifest.validate()?;
    let all = manifest
        .cases
        .iter()
        .map(|c| c.id.clone())
        .collect::<BTreeSet<_>>();
    for id in &options.cases {
        if !all.contains(id) {
            return Err(format!("unknown --case {id}"));
        }
    }
    let mut wanted = options.cases.clone();
    if !wanted.is_empty() {
        loop {
            let before = wanted.len();
            for case in &manifest.cases {
                if wanted.contains(&case.id) {
                    wanted.extend(case.requires.iter().cloned());
                }
            }
            if before == wanted.len() {
                break;
            }
        }
    }
    let mut cases = manifest
        .cases
        .iter()
        .filter(|c| wanted.is_empty() || wanted.contains(&c.id))
        .collect::<Vec<_>>();
    let order = if let Some(path) = &options.order {
        let bytes = read(path)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if value["schema"] != 1 {
            return Err("order file must use schema 1".into());
        }
        let ids = value["cases"]
            .as_array()
            .ok_or("order file needs cases array")?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or("order case id must be string".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let selected = cases.iter().map(|c| c.id.clone()).collect::<BTreeSet<_>>();
        if ids.len() != selected.len()
            || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
            || ids.iter().any(|id| !selected.contains(id))
        {
            return Err(
                "order must be a complete permutation of selected cases; scores cannot skip tests"
                    .into(),
            );
        }
        cases.sort_by_key(|c| ids.iter().position(|id| id == &c.id).unwrap_or(usize::MAX));
        Some(json!({"sha256":hash(&bytes),"data":value}))
    } else {
        None
    };
    let mut ready_order = Vec::new();
    let mut placed = BTreeSet::new();
    while ready_order.len() < cases.len() {
        let next = cases
            .iter()
            .find(|case| {
                !placed.contains(&case.id) && case.requires.iter().all(|r| placed.contains(r))
            })
            .ok_or("selected inventory lacks a required foundation")?;
        placed.insert(next.id.clone());
        ready_order.push(*next);
    }
    cases = ready_order;
    let raw_manifest: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let authorities = authority_environment();
    let authority_hash = hash(&serde_json::to_vec(&authorities).map_err(|e| e.to_string())?);
    let inventory_cases = cases.iter().map(|case| {
        let definition=raw_manifest["cases"].as_array().and_then(|rows|rows.iter().find(|v|v["id"]==case.id)).ok_or("inventory case missing definition")?;
        let inputs=case.files.iter().map(|(path,bytes)|(path.clone(),hash(bytes.as_bytes()))).collect::<BTreeMap<_,_>>();
        Ok(json!({"id":case.id,"node":case.node,"language":case.language,"requires":case.requires,"world":if case.daemon==Some(false){"process"}else{"owner"},"definition_sha256":hash(&serde_json::to_vec(definition).map_err(|e|e.to_string())?),"inputs":inputs,"steps":case.steps.iter().map(|s|json!({"id":s.id,"kind":s.kind})).collect::<Vec<_>>()}))
    }).collect::<Result<Vec<Value>,String>>()?;
    if options.inventory {
        println!("{}",serde_json::to_string_pretty(&json!({"schema":1,"kind":"keel-contract-inventory","manifest_sha256":hash(&raw),"driver_sha256":driver_sha256,"authority_environment":authorities,"authority_environment_sha256":authority_hash,"cases":inventory_cases})).map_err(|e|e.to_string())?);
        return Ok(true);
    }
    if options.list {
        for case in cases {
            println!("{}\t{}\t{}", case.id, case.language, case.node);
        }
        return Ok(true);
    }
    let account_key = account_key()?;
    let account_key_source = account_key.as_ref().map(|k| k.basename.as_str());
    let bins = options
        .bins
        .canonicalize()
        .map_err(|e| format!("bin directory: {e}"))?;
    let mut binaries = BTreeSet::new();
    for case in &cases {
        if case.daemon != Some(false) {
            binaries.extend(["backend-locald".to_owned(), "backend-cli".to_owned()]);
        }
        for step in &case.steps {
            if step.kind == "query" || step.kind == "pages" || step.kind == "mcp-start" {
                binaries.insert("backend-mcp".into());
            }
            if step.kind == "process" {
                binaries.insert(step.binary.clone());
            }
        }
    }
    let mut binary_hashes = BTreeMap::new();
    for binary in binaries {
        binary_hashes.insert(binary.clone(), file_hash(&bins.join(&binary))?);
    }
    fs::create_dir(&options.evidence).map_err(|e| {
        format!(
            "evidence directory must be new {}: {e}",
            options.evidence.display()
        )
    })?;
    let evidence = options.evidence.canonicalize().map_err(|e| e.to_string())?;
    fs::write(evidence.join("manifest.json"), &raw).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let mut reports = Vec::new();
    let mut green = true;
    let mut outcomes = BTreeMap::new();
    for (serial, case) in cases.iter().enumerate() {
        let root = evidence.join(&case.id);
        fs::create_dir(&root).map_err(|e| e.to_string())?;
        let start = Instant::now();
        let mut steps = Vec::new();
        let mut failed = None;
        let mut world_isolation = Value::Null;
        let blocked = case
            .requires
            .iter()
            .filter(|r| outcomes.get(*r) != Some(&true))
            .cloned()
            .collect::<Vec<_>>();
        let world = if blocked.is_empty() {
            World::new(case, &bins, &root, serial, account_key.clone())
        } else {
            Err(format!(
                "required foundation failed or blocked: {}",
                blocked.join(", ")
            ))
        }
        .and_then(|mut world| {
            if case.daemon != Some(false) {
                world.start()?;
            }
            Ok(world)
        });
        match world {
            Err(error) => {
                if !blocked.is_empty() {
                    steps = case
                        .steps
                        .iter()
                        .map(|step| json!({"id":step.id,"status":"blocked","blocked_by":blocked}))
                        .collect();
                }
                failed = Some(error);
            }
            Ok(mut world) => {
                world_isolation = world
                    .daemon
                    .as_ref()
                    .map_or(Value::Null, |daemon| daemon.isolation().clone());
                for (n, step) in case.steps.iter().enumerate() {
                    if let Some(error) = &failed {
                        steps.push(json!({"id":step.id,"status":"blocked","blocked_by":error}));
                        continue;
                    }
                    let start = Instant::now();
                    let prefix = root.join(format!("{n:03}-{}", step.id));
                    match world.step(step,&prefix) {
                        Ok(detail)=>steps.push(json!({"id":step.id,"status":"pass","duration_ms":start.elapsed().as_millis(),"detail":detail})),
                        Err(error)=>{steps.push(json!({"id":step.id,"status":"fail","duration_ms":start.elapsed().as_millis(),"error":error}));failed=Some(step.id.clone());},
                    }
                }
                if !world.sessions.is_empty() && failed.is_none() {
                    failed = Some("case ended with live MCP sessions".into());
                }
                if let Err(error) = world.stop_sessions() {
                    failed = Some(format!("MCP session cleanup failed: {error}"));
                }
                if let Some(mut daemon) = world.daemon.take() {
                    if let Err(error) = daemon.stop() {
                        failed = Some(format!("world containment cleanup failed: {error}"));
                    }
                }
            }
        }
        let status = if !blocked.is_empty() {
            "blocked"
        } else if failed.is_some() {
            "fail"
        } else {
            "pass"
        };
        green &= failed.is_none();
        outcomes.insert(case.id.clone(), status == "pass");
        println!("{status}\t{}\t{}ms", case.id, start.elapsed().as_millis());
        reports.push(json!({"id":case.id,"node":case.node,"language":case.language,"status":status,"error":failed,"duration_ms":start.elapsed().as_millis(),"steps":steps,"world_isolation":world_isolation,"evidence_dir":root}));
        write_json(
            &evidence.join("report.json"),
            &json!({"schema":1,"manifest_sha256":hash(&raw),"driver_sha256":driver_sha256,"authority_environment":authorities,"authority_environment_sha256":authority_hash,"account_key":{"present":account_key.is_some(),"source_basename":account_key_source},"inventory":inventory_cases,"containment_policy":{"root":std::env::var_os("KEEL_CGROUP_ROOT"),"required":std::env::var_os("KEEL_REQUIRE_CGROUP").as_deref()==Some(std::ffi::OsStr::new("1"))},"binaries":binary_hashes,"order":order,"status":if green{"pass"}else{"fail"},"cases":reports,"duration_ms":started.elapsed().as_millis()}),
        )?;
    }
    if file_hash(&driver_path)? != driver_sha256 {
        write_json(
            &evidence.join("report.json"),
            &json!({"schema":1,"manifest_sha256":hash(&raw),"driver_sha256":driver_sha256,"status":"fail","driver_error":"driver executable changed during execution","cases":reports}),
        )?;
        return Err("driver executable changed during execution".into());
    }
    // Detect replacement of an admitted executable during a run. Evidence never
    // certifies a mixed artifact set, even if all behavior assertions passed.
    for (binary, before) in &binary_hashes {
        if file_hash(&bins.join(binary))? != *before {
            write_json(
                &evidence.join("report.json"),
                &json!({"schema":1,"manifest_sha256":hash(&raw),"driver_sha256":driver_sha256,"authority_environment":authorities,"authority_environment_sha256":authority_hash,"account_key":{"present":account_key.is_some(),"source_basename":account_key_source},"inventory":inventory_cases,"containment_policy":{"root":std::env::var_os("KEEL_CGROUP_ROOT"),"required":std::env::var_os("KEEL_REQUIRE_CGROUP").as_deref()==Some(std::ffi::OsStr::new("1"))},"binaries":binary_hashes,"order":order,"status":"fail","artifact_error":format!("artifact {binary} changed while cases were running"),"cases":reports,"duration_ms":started.elapsed().as_millis()}),
            )?;
            return Err(format!(
                "artifact {binary} changed while cases were running"
            ));
        }
    }
    Ok(green)
}
pub(crate) fn entry() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("keel: {error}");
            ExitCode::from(2)
        }
    }
}
