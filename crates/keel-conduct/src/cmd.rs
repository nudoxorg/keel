//! Nodes that run a command: nushell checks (`nu-check`), plain commands, and
//! artifact producers (`artifact`) with their consumers.
//!
//! The command's own script and every file it `use`s or `source`s are keyed
//! automatically, so an edit to a helper module reruns exactly the checks that
//! load it. Anything the script reads that is not code is declared in
//! `inputs`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use keel::store::ResultStore;
use keel::{
    CONTROL_DID_NOT_FAIL, Control, Detail, Digest, EnvContract, Evidence, FileSpec, FilesInput,
    GroupId, Inputs, KEY_SCHEMA, Kind, NetMode, Node, NodeId, PartId, Platform, Policy, Status,
    Upstream, files_key, key,
};
use serde::{Deserialize, Serialize};

use crate::config::{Config, EnvSpec, NodeConfig};
use crate::model::{CleanEnv, Cx, Outcome, Planned, Runner, evidence_or_skip, sanitize};
use crate::util::{Spawn, glob_escape, mix, rel_to, resolve_tools, run_captured, tail_text, which};

/// A planned command node's execution side.
pub struct CmdRun {
    argv: Vec<String>,
    display: String,
    cwd: PathBuf,
    env: CleanEnv,
    timeout: Option<Duration>,
    produces: Vec<String>,
    consumes: Vec<NodeId>,
    /// Present for a negative control; it cannot be built without a declaration.
    negative: Option<ExpectedFailure>,
}

/// The way a negative control is declared to fail. A control passes only when
/// the command ran and failed like this: "any non-zero exit" would also pass
/// a command that was not found (127), not executable (126) or killed, none
/// of which says anything about the behaviour the control exists to refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedFailure {
    codes: BTreeSet<i32>,
    output: Option<String>,
}

/// What a negative control's run means.
#[derive(Debug, PartialEq, Eq)]
enum ControlResult {
    /// It ran and failed in the declared way.
    Refused,
    /// Exit 0: the wrong configuration was accepted.
    DidNotFail,
    /// It never ran, or died without failing by its own logic.
    CouldNotRun(String),
    /// It ran and failed, but not as declared.
    FailedElsewise(String),
}

impl ExpectedFailure {
    /// Reads the declaration of control node `id`, refusing one that would
    /// accept any failure.
    fn declare(id: &NodeId, n: &NodeConfig) -> Result<Self> {
        if n.expect_exit.is_empty() && n.expect_output.is_none() {
            bail!(
                "node {id} is a negative control but declares no expected failure; add `expect_exit = [1]` (the exit codes it fails with) and/or `expect_output = \"text\"` (what it prints when it refuses), because \"any non-zero exit\" also passes a command that was not found or was killed"
            );
        }
        if let Some(c) = n
            .expect_exit
            .iter()
            .find(|c| matches!(**c, 0 | 126 | 127) || !(1..=255).contains(*c))
        {
            bail!(
                "node {id} declares `expect_exit` {c}, which is not a way to fail: 0 is success, 126 and 127 mean the shell could not run the command, and codes outside 1..=255 do not exist; declare the code the command itself exits with"
            );
        }
        if n.expect_output.as_deref() == Some("") {
            bail!(
                "node {id} declares an empty `expect_output`, which every output contains; name the text the refusal prints"
            );
        }
        Ok(ExpectedFailure {
            codes: n.expect_exit.iter().copied().collect(),
            output: n.expect_output.clone(),
        })
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.codes.is_empty() {
            parts.push(format!(
                "exit {}",
                self.codes
                    .iter()
                    .map(i32::to_string)
                    .collect::<Vec<_>>()
                    .join(" or ")
            ));
        }
        if let Some(o) = &self.output {
            parts.push(format!("output containing `{o}`"));
        }
        parts.join(" and ")
    }

    fn judge(&self, code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> ControlResult {
        match code {
            Some(0) => ControlResult::DidNotFail,
            None => ControlResult::CouldNotRun(
                "the process was killed by a signal, which is not a failure of its own logic"
                    .to_owned(),
            ),
            Some(c @ (126 | 127)) => ControlResult::CouldNotRun(format!(
                "exit {c} means the command was {}; fix the command, a failing run of the wrong configuration is what this control needs",
                if c == 127 {
                    "not found"
                } else {
                    "not executable"
                }
            )),
            Some(c) => {
                let mut wrong = Vec::new();
                if !self.codes.is_empty() && !self.codes.contains(&c) {
                    wrong.push(format!(
                        "exit {c}, not the declared {}",
                        self.describe_codes()
                    ));
                }
                if let Some(o) = &self.output
                    && !String::from_utf8_lossy(stdout).contains(o.as_str())
                    && !String::from_utf8_lossy(stderr).contains(o.as_str())
                {
                    wrong.push(format!("output without `{o}`: {}", tail_text(stderr, 300)));
                }
                if wrong.is_empty() {
                    ControlResult::Refused
                } else {
                    ControlResult::FailedElsewise(wrong.join("; "))
                }
            }
        }
    }

    fn describe_codes(&self) -> String {
        self.codes
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(" or ")
    }
}

/// The `reason` of a control that failed, but not the way it declared.
pub const CONTROL_FAILED_ELSEWISE: &str = "control-failed-differently";

/// The files `script` pulls in with `use`, `source` and friends, recursively,
/// as canonical absolute paths (the script itself included).
pub fn nu_dependencies(script: &Path, cwd: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut seen = BTreeSet::new();
    let mut queue = vec![script.canonicalize().with_context(|| {
        format!(
            "script {} does not exist; fix the node's `command` or `cwd`",
            script.display()
        )
    })?];
    while let Some(file) = queue.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let text = std::fs::read_to_string(&file).with_context(|| {
            format!(
                "cannot read {} to find the modules it uses; is it text?",
                file.display()
            )
        })?;
        let dir = file.parent().unwrap_or(Path::new("/"));
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some(target) = use_target(line) else {
                continue;
            };
            // Nushell resolves a relative module against the file that names
            // it first, then the working directory.
            let found = [dir.join(&target), cwd.join(&target)]
                .into_iter()
                .find(|c| c.exists());
            match found {
                Some(p) if p.is_dir() => queue.extend(nu_files_under(&p)?),
                Some(p) => queue.push(p.canonicalize()?),
                None if target.ends_with(".nu") => bail!(
                    "{} uses {target} but no such file exists next to it or under {}; fix the path, or the check cannot be keyed",
                    file.display(),
                    cwd.display()
                ),
                // `use std/assert`: a built-in module, content is the tool.
                None => {}
            }
        }
    }
    Ok(seen)
}

/// The path operand of a `use`/`source` line, if it is a literal.
fn use_target(line: &str) -> Option<String> {
    let rest = [
        "export use ",
        "overlay use ",
        "source-env ",
        "source ",
        "use ",
    ]
    .iter()
    .find_map(|p| line.strip_prefix(p))?;
    let tok = rest.split_whitespace().next()?;
    let tok = tok.trim_matches(|c| matches!(c, '"' | '\'' | '`'));
    (!tok.is_empty() && !tok.starts_with('$') && !tok.starts_with('(')).then(|| tok.to_owned())
}

fn nu_files_under(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("cannot list module directory {}", dir.display()))?
    {
        let p = entry?.path();
        if p.is_dir() {
            out.extend(nu_files_under(&p)?);
        } else if p.extension().is_some_and(|e| e == "nu") {
            out.push(p.canonicalize()?);
        }
    }
    Ok(out)
}

/// The id with its namespace.
pub fn namespaced(id: &str, default: &str) -> NodeId {
    match id.split_once(':') {
        Some((p, _)) if NodeId::PREFIXES.contains(&p) => NodeId::new(id),
        _ => NodeId::new(format!("{default}:{id}")),
    }
}

fn kind_of(n: &NodeConfig) -> Result<Kind> {
    Ok(match (n.kind.as_deref(), n.produces.is_empty()) {
        (Some("artifact"), _) | (None, false) => Kind::Artifact,
        (Some("command"), _) => Kind::Command,
        (Some("nu-check") | None, _) => Kind::NuCheck,
        (Some(other), _) => bail!(
            "node kind `{other}` is not one the conductor runs from a [[node]] command; use `nu-check`, `command` or `artifact` (Nix nodes use `drv`)"
        ),
    })
}

/// Plans every `[[node]]` that has a `command`.
pub fn plan(cfg: &Config, repo_root: &Path) -> Result<Vec<Planned>> {
    let repo = repo_root.canonicalize().with_context(|| {
        format!(
            "the repository root {} does not exist; fix --repo-root",
            repo_root.display()
        )
    })?;
    let mut pending: Vec<&NodeConfig> = cfg.nodes.iter().filter(|n| n.drv.is_none()).collect();
    let mut done: Vec<Planned> = Vec::new();
    // Consumers need their producers' keys, so plan producers first.
    while !pending.is_empty() {
        let before = pending.len();
        let mut rest = Vec::new();
        for n in pending {
            let ready = n.consumes.iter().all(|c| {
                let id = namespaced(c, "nu");
                done.iter().any(|p| p.node.id == id)
            });
            if ready {
                let planned = plan_one(n, &repo, &done)?;
                done.push(planned);
            } else {
                rest.push(n);
            }
        }
        if rest.len() == before {
            let names: Vec<_> = rest
                .iter()
                .map(|n| n.id.clone().unwrap_or_default())
                .collect();
            bail!(
                "nodes {} consume artifacts that no [[node]] produces (or consume each other in a cycle); each `consumes` entry must name a node with `produces`",
                names.join(", ")
            );
        }
        pending = rest;
    }
    Ok(done)
}

fn plan_one(n: &NodeConfig, repo: &Path, done: &[Planned]) -> Result<Planned> {
    let kind = kind_of(n)?;
    let id = namespaced(n.id.as_deref().expect("validated by Config::load"), "nu");
    if kind == Kind::Artifact && id.as_str().contains('/') {
        bail!(
            "artifact node `{id}` has a `/` in its id, but consumers receive it as the directory $KEEL_CONSUMED/<id>/; rename it"
        );
    }
    let cwd = repo.join(n.cwd.as_deref().unwrap_or("."));
    let cwd = cwd.canonicalize().with_context(|| {
        format!(
            "node {id}: cwd {} does not exist; fix `cwd` (relative to the repository root)",
            cwd.display()
        )
    })?;
    if !cwd.starts_with(repo) {
        bail!(
            "node {id}: cwd {} is outside the repository root {}",
            cwd.display(),
            repo.display()
        );
    }

    // Tools: the program itself is always a tool, plus what is declared.
    let mut tool_names = n.tools.clone();
    let program = &n.command[0];
    if !program.contains('/') && !tool_names.contains(program) {
        tool_names.push(program.clone());
    }
    let (tools, tools_digest) = resolve_tools(&tool_names, &[])?;
    let mut argv = n.command.clone();
    argv[0] = if program.contains('/') {
        cwd.join(program).to_string_lossy().into_owned()
    } else {
        tools
            .iter()
            .find(|t| t.name == *program)
            .map(|t| t.path.to_string_lossy().into_owned())
            .or_else(|| {
                which(program, &std::env::var("PATH").unwrap_or_default())
                    .map(|p| p.to_string_lossy().into_owned())
            })
            .ok_or_else(|| anyhow!("node {id}: program `{program}` not found on PATH"))?
    };

    // Files: declared globs, plus every script in the command and what it uses.
    let mut globs: Vec<String> = n.inputs.clone();
    for arg in &n.command[1..] {
        let candidate = cwd.join(arg);
        if arg.ends_with(".nu") && candidate.is_file() {
            for dep in nu_dependencies(&candidate, &cwd)? {
                let rel = rel_to(repo, &dep).ok_or_else(|| {
                    anyhow!("node {id}: {} is used by a script but lies outside the repository root {}; move it inside, or it cannot be keyed", dep.display(), repo.display())
                })?;
                globs.push(glob_escape(&rel));
            }
        }
    }
    let (files, _) = files_key(
        repo,
        &FileSpec {
            package_dir: None,
            globs,
            ..FileSpec::default()
        },
    )
    .with_context(|| format!("cannot hash the input files of node {id}"))?;

    let consumes: Vec<NodeId> = n.consumes.iter().map(|c| namespaced(c, "nu")).collect();
    let consumed: Vec<(NodeId, Digest)> = consumes
        .iter()
        .map(|c| {
            let p = done
                .iter()
                .find(|p| p.node.id == *c)
                .expect("producers are planned first");
            if p.node.kind != Kind::Artifact {
                bail!(
                    "node {id} consumes {c}, which is not an artifact node (it has no `produces`)"
                );
            }
            Ok((c.clone(), p.node.key))
        })
        .collect::<Result<_>>()?;
    // What the digest of the files cannot say: the command line, where it
    // runs, what it is expected to do, and which artifacts it reads. Without
    // these a control and its twin, or two nodes that differ only in
    // arguments, would share a key and so share each other's stored passes.
    let negative = match n.control.as_deref() {
        None => None,
        Some("negative") => Some(ExpectedFailure::declare(&id, n)?),
        Some(other) => {
            bail!("node {id}: control `{other}` is not known; the only control is `negative`")
        }
    };
    if negative.is_none() && (!n.expect_exit.is_empty() || n.expect_output.is_some()) {
        bail!(
            "node {id} declares `expect_exit` or `expect_output` but is not a negative control; they only say how a control fails, so drop them or add `control = \"negative\"`"
        );
    }
    let mut parts = vec![
        ("argv".to_owned(), n.command.join("\u{1f}")),
        (
            "expect".to_owned(),
            negative
                .as_ref()
                .map(ExpectedFailure::describe)
                .unwrap_or_default(),
        ),
        ("cwd".to_owned(), rel_to(repo, &cwd).unwrap_or_default()),
        ("kind".to_owned(), format!("{kind:?}")),
        ("control".to_owned(), n.control.clone().unwrap_or_default()),
    ];
    parts.extend(
        consumed
            .iter()
            .map(|(id, k)| (format!("consumes:{id}"), k.to_hex())),
    );
    let files = mix(files, &parts);

    let (allow, profile_env) = match &n.env {
        EnvSpec::List(l) => (l.clone(), BTreeMap::new()),
        EnvSpec::Table(t) => (Vec::new(), t.clone()),
        EnvSpec::None => (Vec::new(), BTreeMap::new()),
    };
    let contract = EnvContract { allow, profile_env };
    let ambient = std::env::vars().collect();
    let env_digest = keel::env_key(&contract, &ambient);

    let inputs = Inputs {
        files: Some(FilesInput::Hash(files)),
        env: Some(env_digest),
        tools: Some(tools_digest),
        consumes: consumes.clone(),
        ..Inputs::default()
    };
    let platform = Platform::new(
        crate::util::host_triple(),
        "keel-conduct",
        // The conductor does not isolate the network; the host units of §6.2 do.
        NetMode::Open,
    );

    let twin = n.twin.as_deref().map(|t| namespaced(t, "nu"));
    if negative.is_some() && twin.is_none() {
        bail!(
            "node {id} is a negative control but names no `twin`; say which node's behaviour it must contradict"
        );
    }
    let mut stands_on: Vec<Upstream> = n
        .stands_on
        .iter()
        .map(|s| s.parse::<Upstream>().map_err(|e| anyhow!("node {id}: {e}")))
        .collect::<Result<_>>()?;
    // Consumed artifacts and a control's twin must be terminal first.
    stands_on.extend(consumes.iter().map(|c| Upstream::Node(c.clone())));
    stands_on.extend(
        twin.iter()
            .filter(|_| negative.is_some())
            .map(|t| Upstream::Node(t.clone())),
    );
    stands_on.sort();
    stands_on.dedup();

    let group = match &n.group {
        Some(g) => g
            .parse::<GroupId>()
            .map_err(|e| anyhow!("node {id}: {e}"))?,
        None => GroupId::unit(id.as_str().split_once(':').map_or(id.as_str(), |(_, r)| r)),
    };
    let joins = n
        .joins
        .iter()
        .map(|j| j.parse::<PartId>().map_err(|e| anyhow!("node {id}: {e}")))
        .collect::<Result<_>>()?;
    let node = Node {
        id: id.clone(),
        kind,
        group,
        stands_on,
        joins,
        key: key(KEY_SCHEMA, &inputs, &platform)?,
        inputs,
        produces: n.produces.clone(),
        via: None,
        policy: Policy {
            blocks: n.blocks.unwrap_or(true),
            control: negative.as_ref().map(|_| Control::Negative),
            twin: twin.filter(|_| negative.is_some()),
            timeout: n.timeout_s,
            network: n.network.unwrap_or(false),
            sensitive: Vec::new(),
        },
    };
    Ok(Planned {
        runner: Runner::Cmd(CmdRun {
            display: n.command.join(" "),
            argv,
            cwd,
            env: CleanEnv {
                contract,
                tools: tools.into_iter().map(|t| (t.name, t.path)).collect(),
            },
            timeout: n.timeout_s.map(Duration::from_secs),
            produces: n.produces.clone(),
            consumes,
            negative,
        }),
        node,
    })
}

/// The manifest an artifact node stores next to its file blobs.
#[derive(Serialize, Deserialize)]
struct ArtifactManifest {
    schema: u32,
    node: NodeId,
    files: Vec<ArtifactFile>,
}

#[derive(Serialize, Deserialize)]
struct ArtifactFile {
    path: String,
    blob: Digest,
    executable: bool,
}

/// Most files and bytes one artifact node may produce.
const ARTIFACT_FILES: usize = 4096;

fn safe_relative(p: &str) -> bool {
    let path = Path::new(p);
    !p.is_empty()
        && path.is_relative()
        && path
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
}

fn walk_files(base: &Path, rel: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let meta = std::fs::symlink_metadata(base.join(rel))?;
    if meta.is_dir() {
        let mut names: Vec<_> =
            std::fs::read_dir(base.join(rel))?.collect::<Result<Vec<_>, _>>()?;
        names.sort_by_key(|e| e.file_name());
        for e in names {
            walk_files(base, &rel.join(e.file_name()), out)?;
        }
    } else {
        out.push(rel.to_owned());
    }
    Ok(())
}

/// Stores the produced files as blobs plus a manifest; returns the evidence.
fn collect_artifact(
    store: &dyn ResultStore,
    node: &NodeId,
    cwd: &Path,
    produces: &[String],
) -> Result<Vec<Evidence>> {
    let mut files = Vec::new();
    for p in produces {
        if !safe_relative(p) {
            bail!(
                "`produces` entry `{p}` of {node} must be a relative path inside the node's cwd, with no `..`"
            );
        }
        if std::fs::symlink_metadata(cwd.join(p)).is_err() {
            bail!(
                "{node} declares it produces `{p}` but {} does not exist after the command ran; the command must write it",
                cwd.join(p).display()
            );
        }
        walk_files(cwd, Path::new(p), &mut files)?;
    }
    if files.len() > ARTIFACT_FILES {
        bail!(
            "{node} produced {} files, over the limit of {ARTIFACT_FILES}; produce an archive instead",
            files.len()
        );
    }
    let mut manifest = ArtifactManifest {
        schema: 1,
        node: node.clone(),
        files: Vec::new(),
    };
    let mut evidence = Vec::new();
    for rel in files {
        let abs = cwd.join(&rel);
        let meta = std::fs::symlink_metadata(&abs)?;
        if !meta.is_file() {
            bail!(
                "{} is a symlink or special file; artifacts hold regular files only",
                abs.display()
            );
        }
        let bytes = std::fs::read(&abs)
            .with_context(|| format!("cannot read produced file {}", abs.display()))?;
        let blob = store
            .put_blob(&bytes)
            .with_context(|| format!("cannot store produced file {}", abs.display()))?;
        #[cfg(unix)]
        let executable = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o111 != 0
        };
        let rel = rel_to(Path::new(""), &rel).unwrap_or_default();
        evidence.push(Evidence {
            name: format!("artifact:{rel}"),
            reference: blob,
        });
        manifest.files.push(ArtifactFile {
            path: rel,
            blob,
            executable,
        });
    }
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    evidence.push(Evidence {
        name: "artifact".to_owned(),
        reference: store.put_blob(&bytes)?,
    });
    Ok(evidence)
}

fn manifest_of(store: &dyn ResultStore, evidence: &[Evidence]) -> Result<Option<ArtifactManifest>> {
    let Some(e) = evidence.iter().find(|e| e.name == "artifact") else {
        return Ok(None);
    };
    let Some(bytes) = store.get_blob(&e.reference)? else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_slice(&bytes).context(
        "the stored artifact manifest is not valid JSON",
    )?))
}

/// Whether a stored artifact can still be materialised: the manifest and
/// every file blob it names are in the store.
pub fn artifact_available(store: &dyn ResultStore, evidence: &[Evidence]) -> bool {
    let Ok(Some(m)) = manifest_of(store, evidence) else {
        return false;
    };
    m.files
        .iter()
        .all(|f| store.get_blob(&f.blob).is_ok_and(|b| b.is_some()))
}

/// Writes a producer's files under `dest`. The manifest came from the store,
/// so every path in it is checked again before it is joined to `dest`.
fn materialise(
    store: &dyn ResultStore,
    producer: &NodeId,
    evidence: &[Evidence],
    dest: &Path,
) -> Result<()> {
    let m = manifest_of(store, evidence)?.ok_or_else(|| {
        anyhow!("artifact {producer} has no manifest in the store; rerun the run so {producer} produces it again")
    })?;
    for f in m.files {
        if !safe_relative(&f.path) {
            bail!(
                "the manifest of {producer} names `{}`, which is not a relative path inside the artifact; the store entry is damaged, delete it",
                f.path
            );
        }
        let bytes = store.get_blob(&f.blob)?.ok_or_else(|| {
            anyhow!(
                "blob {} of {producer}/{} is missing from the store; rerun {producer}",
                f.blob,
                f.path
            )
        })?;
        let target = dest.join(&f.path);
        std::fs::create_dir_all(target.parent().unwrap_or(dest))?;
        std::fs::write(&target, bytes)?;
        #[cfg(unix)]
        if f.executable {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    Ok(())
}

impl CmdRun {
    /// Runs the command.
    pub fn run(&self, node: &Node, cx: &Cx<'_>) -> Outcome {
        let started = Instant::now();
        let fail = |msg: String| Outcome::error(msg, &self.display, started);
        let mut env = match self.env.build(cx.work, &node.id) {
            Ok(e) => e,
            Err(e) => return fail(format!("{e:#}")),
        };
        if !self.consumes.is_empty() {
            let root = cx.work.join(sanitize(node.id.as_str())).join("consumed");
            let _ = std::fs::remove_dir_all(&root);
            for producer in &self.consumes {
                let evidence = cx.consumed.get(producer).map(Vec::as_slice).unwrap_or(&[]);
                if let Err(e) =
                    materialise(cx.store, producer, evidence, &root.join(producer.as_str()))
                {
                    return fail(format!("{e:#}"));
                }
            }
            env.insert(
                "KEEL_CONSUMED".to_owned(),
                root.to_string_lossy().into_owned(),
            );
        }
        let got = match run_captured(&Spawn {
            argv: &self.argv,
            cwd: &self.cwd,
            env: &env,
            timeout: self.timeout,
        }) {
            Ok(g) => g,
            Err(e) => return fail(format!("{e:#}")),
        };
        let mut evidence = evidence_or_skip(cx.store, "stdout", &got.stdout);
        evidence.extend(evidence_or_skip(cx.store, "stderr", &got.stderr));
        let exited_zero = got.code == Some(0);
        let (status, reason, actual) = if got.timed_out {
            (
                Status::Timeout,
                None,
                Some(format!(
                    "killed after {:?}",
                    self.timeout.unwrap_or_default()
                )),
            )
        } else if let Some(expect) = &self.negative {
            // A wrong-configuration twin: failing in the declared way is the
            // expected result, and nothing else is.
            match expect.judge(got.code, &got.stdout, &got.stderr) {
                ControlResult::Refused => (Status::Pass, None, None),
                ControlResult::DidNotFail => (
                    Status::Fail,
                    Some(CONTROL_DID_NOT_FAIL.to_owned()),
                    Some("exit 0".to_owned()),
                ),
                ControlResult::CouldNotRun(why) => (
                    Status::Error,
                    None,
                    Some(format!("the control could not run: {why}")),
                ),
                ControlResult::FailedElsewise(why) => (
                    Status::Fail,
                    Some(CONTROL_FAILED_ELSEWISE.to_owned()),
                    Some(why),
                ),
            }
        } else if exited_zero {
            (Status::Pass, None, None)
        } else {
            let how = got
                .code
                .map_or("a signal".to_owned(), |c| format!("exit {c}"));
            (
                Status::Fail,
                None,
                Some(format!("{how}: {}", tail_text(&got.stderr, 1500))),
            )
        };
        let (mut status, mut actual) = (status, actual);
        if status == Status::Pass && node.kind == Kind::Artifact {
            match collect_artifact(cx.store, &node.id, &self.cwd, &self.produces) {
                Ok(e) => evidence.extend(e),
                Err(e) => {
                    status = Status::Fail;
                    actual = Some(format!("{e:#}"));
                }
            }
        }
        Outcome {
            status,
            reason,
            detail: actual.map(|a| Detail {
                ran: self.display.clone(),
                expected: Some(
                    self.negative
                        .as_ref()
                        .map_or_else(|| "exit 0".to_owned(), ExpectedFailure::describe),
                ),
                actual: Some(a),
            }),
            evidence,
            extra: Vec::new(),
            duration_ms: started.elapsed().as_millis() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_use_targets() {
        assert_eq!(
            use_target("use lib/helpers.nu *").as_deref(),
            Some("lib/helpers.nu")
        );
        assert_eq!(
            use_target("export use \"mod.nu\"").as_deref(),
            Some("mod.nu")
        );
        assert_eq!(use_target("source ./x.nu").as_deref(), Some("./x.nu"));
        assert_eq!(use_target("use $dyn"), None);
        assert_eq!(use_target("let used = 1"), None);
    }

    #[test]
    fn namespace_is_added_only_when_missing() {
        assert_eq!(namespaced("x", "nu").as_str(), "nu:x");
        assert_eq!(namespaced("nix:y", "nu").as_str(), "nix:y");
        assert_eq!(namespaced("other:z", "nu").as_str(), "nu:other:z");
    }

    #[test]
    fn a_control_passes_only_when_it_ran_and_failed_as_declared() {
        let e = ExpectedFailure {
            codes: [1, 2].into(),
            output: Some("refused".into()),
        };
        assert_eq!(
            e.judge(Some(2), b"", b"x refused y"),
            ControlResult::Refused
        );
        assert_eq!(e.judge(Some(0), b"refused", b""), ControlResult::DidNotFail);
        for code in [Some(126), Some(127), None] {
            assert!(
                matches!(
                    e.judge(code, b"refused", b"refused"),
                    ControlResult::CouldNotRun(_)
                ),
                "{code:?}"
            );
        }
        assert!(matches!(
            e.judge(Some(3), b"", b"refused"),
            ControlResult::FailedElsewise(_)
        ));
        assert!(matches!(
            e.judge(Some(1), b"", b"other"),
            ControlResult::FailedElsewise(_)
        ));
        // Output alone, exit code alone.
        let out = ExpectedFailure {
            codes: [].into(),
            output: Some("no".into()),
        };
        assert_eq!(out.judge(Some(99), b"no", b""), ControlResult::Refused);
        let code = ExpectedFailure {
            codes: [4].into(),
            output: None,
        };
        assert_eq!(code.judge(Some(4), b"", b""), ControlResult::Refused);
    }

    #[test]
    fn manifest_paths_must_stay_inside() {
        for bad in ["", "/etc/passwd", "../x", "a/../../x"] {
            assert!(!safe_relative(bad), "{bad}");
        }
        assert!(safe_relative("a/b.txt"));
    }
}
