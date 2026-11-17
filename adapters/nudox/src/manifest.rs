//! The evaluated Nix model is the only authoring surface for cases.
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub schema: u32,
    pub cases: Vec<Case>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Case {
    pub id: String,
    pub language: String,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    pub steps: Vec<Step>,
    #[serde(default)]
    pub daemon: Option<bool>,
    #[serde(default)]
    pub requires: Vec<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Step {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cli: Vec<String>,
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub session: String,
    #[serde(default)]
    pub call: Option<Value>,
    #[serde(default)]
    pub mcp_error: bool,
    #[serde(default)]
    pub arguments: Value,
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub bind: BTreeMap<String, Binding>,
    #[serde(default)]
    pub expect: Option<Expect>,
    #[serde(default)]
    pub binary: String,
    #[serde(default)]
    pub input: Option<Value>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub config: Option<Value>,
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "one")]
    pub minimum_pages: usize,
    #[serde(default = "max_pages")]
    pub maximum_pages: usize,
    #[serde(default, deserialize_with = "present_format")]
    pub page_format: Option<String>,
    #[serde(default)]
    pub wait_for: bool,
}
fn present_format<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
fn one() -> usize {
    1
}
fn max_pages() -> usize {
    64
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum Binding {
    Pointer(String),
    Transform { pointer: String, transform: String },
}
impl Binding {
    pub(crate) fn pointer(&self) -> &str {
        match self {
            Self::Pointer(p) | Self::Transform { pointer: p, .. } => p,
        }
    }
    pub(crate) fn value(&self, value: &Value) -> Result<Value, String> {
        let found = value
            .pointer(self.pointer())
            .cloned()
            .ok_or_else(|| format!("binding lacks {}", self.pointer()))?;
        match self {
            Self::Pointer(_) => Ok(found),
            Self::Transform { transform, .. } if transform == "hex-root" => {
                let value = found
                    .as_str()
                    .filter(|v| {
                        v.len() == 64
                            && v.bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    })
                    .ok_or("hex-root needs an exact64lowercasehex root")?;
                Ok(Value::String(value.to_owned()))
            }
            Self::Transform { transform, .. } if transform == "selected-symbol-key" => {
                if found["kind"] != "selected-symbol-id" {
                    return Err(
                        "selected-symbol-key needs the exact selected-symbol-id object".into(),
                    );
                }
                // Public projections encode the copied selected ID as canonical
                // hex in `value`; older projections used a 32-byte value array.
                // Both representations name the same bytes, without hashing.
                let value = found
                    .get("value")
                    .ok_or("selected symbol identity lacks value")?;
                let hex = if let Some(value) = value.as_str() {
                    if value.len() != 64
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                        || value.bytes().all(|b| b == b'0')
                    {
                        return Err(
                            "selected symbol value must be a nonzero canonical 64-hex identity"
                                .into(),
                        );
                    }
                    value.to_owned()
                } else {
                    let bytes = value
                        .as_array()
                        .filter(|b| b.len() == 32)
                        .ok_or("legacy selected symbol value must contain 32 bytes")?;
                    let mut hex = String::new();
                    for byte in bytes {
                        use std::fmt::Write;
                        let byte = byte
                            .as_u64()
                            .and_then(|v| u8::try_from(v).ok())
                            .ok_or("invalid selected symbol byte")?;
                        write!(&mut hex, "{byte:02x}").map_err(|e| e.to_string())?;
                    }
                    if hex.bytes().all(|b| b == b'0') {
                        return Err("selected symbol identity is zero".into());
                    }
                    hex
                };
                Ok(Value::String(format!("symbol:{hex}")))
            }
            Self::Transform { transform, .. } => {
                Err(format!("unknown identity binding transform {transform}"))
            }
        }
    }
}
fn timeout() -> u64 {
    180
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Expect {
    pub exit: i32,
    #[serde(default)]
    pub json: Vec<Assertion>,
    #[serde(default)]
    pub stdout_contains: Vec<String>,
    #[serde(default)]
    pub stderr_contains: Vec<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Assertion {
    pub pointer: String,
    #[serde(default)]
    pub select: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub equals: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    pub contains: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    pub not_contains: Option<Value>,
    pub set_equals: Option<Vec<Value>>,
    #[serde(default)]
    pub absent: bool,
}
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
pub(crate) fn relative(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.contains('\\')
        || std::path::Path::new(path)
            .components()
            .any(|p| !matches!(p, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "fixture path {path:?} must contain only relative normal components"
        ));
    }
    Ok(())
}
impl Manifest {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema != 1 || self.cases.is_empty() {
            return Err("manifest must have schema 1 and at least one case".into());
        }
        let mut ids = BTreeSet::new();
        for case in &self.cases {
            if !valid_id(&case.id) || !ids.insert(&case.id) {
                return Err(format!("invalid or duplicate case id {:?}", case.id));
            }
            if ![
                "rust",
                "python",
                "javascript",
                "typescript",
                "css",
                "sql",
                "protocol",
            ]
            .contains(&case.language.as_str())
            {
                return Err(format!(
                    "{}: unsupported or paused language {}",
                    case.id, case.language
                ));
            }
            if case.steps.is_empty() {
                return Err(format!("{} has no steps", case.id));
            }
            for path in case.files.keys() {
                relative(path)?;
            }
            let mut steps = BTreeSet::new();
            let mut sessions = BTreeSet::new();
            for step in &case.steps {
                match (step.kind.as_str(), step.page_format.as_deref()) {
                    (_, None) => {}
                    ("pages", Some("source-range"))
                        if step.tool == "backend.source"
                            && step.arguments["byte_range"] == true
                            && step.arguments.get("cursor").is_none()
                            && (step.cli.is_empty()
                                || (step.cli.first().is_some_and(|v| v == "source")
                                    && step.cli.iter().any(|v| v == "--byte-range")
                                    && !step.cli.iter().any(|v| {
                                        v == "--cursor" || v.starts_with("--cursor=")
                                    }))) => {}
                    _ => {
                        return Err(format!(
                            "{}: invalid page_format or source-range selector",
                            step.id
                        ));
                    }
                }
                if step.kind == "pages" && step.page_format.is_none() && !step.cli.is_empty() {
                    return Err(format!(
                        "{}: CLI pagination requires source-range format",
                        step.id
                    ));
                }
                let is_session =
                    matches!(step.kind.as_str(), "mcp-start" | "mcp-call" | "mcp-stop");
                if !is_session
                    && (!step.session.is_empty() || step.call.is_some() || step.mcp_error)
                {
                    return Err(format!(
                        "{}: MCP session fields are only valid for MCP session steps",
                        step.id
                    ));
                }
                if matches!(step.kind.as_str(), "mcp-start" | "mcp-stop")
                    && (!step.tool.is_empty()
                        || step.call.is_some()
                        || step.mcp_error
                        || (!step.arguments.is_null()
                            && !step
                                .arguments
                                .as_object()
                                .is_some_and(serde_json::Map::is_empty)))
                {
                    return Err(format!(
                        "{}: MCP start/stop cannot specify call fields",
                        step.id
                    ));
                }
                if step.wait_for && step.kind != "query" {
                    return Err(format!(
                        "{}: wait_for is an explicit query-convergence contract",
                        step.id
                    ));
                }
                if let Some(protocol) = &step.protocol {
                    if !["stylo", "json", "jsonrpc-lines"].contains(&protocol.as_str()) {
                        return Err(format!(
                            "{}: unsupported process protocol {protocol}",
                            step.id
                        ));
                    }
                }
                if case.daemon == Some(false)
                    && ["index", "restart", "query", "cli", "pages"].contains(&step.kind.as_str())
                {
                    return Err(format!(
                        "{}: owner operation requires a daemon world",
                        step.id
                    ));
                }
                if !valid_id(&step.id) || !steps.insert(&step.id) {
                    return Err(format!(
                        "{}: invalid or duplicate step {}",
                        case.id, step.id
                    ));
                }
                if step.timeout_seconds == 0 || step.timeout_seconds > 600 {
                    return Err(format!("{}: timeout must be 1..600 seconds", step.id));
                }
                for path in step.files.keys().chain(step.remove.iter()) {
                    relative(path)?;
                }
                match step.kind.as_str() {
                    "mcp-start" => {
                        if !valid_id(&step.session)
                            || !sessions.insert(step.session.clone())
                            || sessions.len() > 8
                        {
                            return Err(format!(
                                "{}: invalid, duplicate or excessive live session",
                                step.id
                            ));
                        }
                    }
                    "mcp-stop" => {
                        if !sessions.remove(&step.session) {
                            return Err(format!("{}: session is not live", step.id));
                        }
                    }
                    "write" => {
                        if step.files.is_empty() && step.remove.is_empty() {
                            return Err(format!("{}: write changes nothing", step.id));
                        }
                    }
                    "index" | "restart" => {}
                    "cli" | "query" | "process" | "pages" | "mcp-call" => {
                        let e = step.expect.as_ref().ok_or_else(|| {
                            format!(
                                "{}: executable steps require reviewed expectations",
                                step.id
                            )
                        })?;
                        if e.json.is_empty()
                            && e.stdout_contains.is_empty()
                            && e.stderr_contains.is_empty()
                        {
                            return Err(format!(
                                "{}: exit status alone is not a behavior oracle",
                                step.id
                            ));
                        }
                        if e.stdout_contains
                            .iter()
                            .chain(e.stderr_contains.iter())
                            .any(String::is_empty)
                        {
                            return Err(format!("{}: empty output substring is vacuous", step.id));
                        }
                        for a in &e.json {
                            if !a.pointer.is_empty() && !a.pointer.starts_with('/') {
                                return Err(format!("{}: assertion needs a JSON pointer", step.id));
                            }
                            let n = usize::from(a.equals.is_some())
                                + usize::from(a.contains.is_some())
                                + usize::from(a.not_contains.is_some())
                                + usize::from(a.set_equals.is_some())
                                + usize::from(a.absent);
                            if n != 1 {
                                return Err(format!(
                                    "{}: assertions require exactly one operator",
                                    step.id
                                ));
                            }
                        }
                        if step.kind == "mcp-call"
                            && (!sessions.contains(&step.session)
                                || (step.call.is_some() == !step.tool.is_empty())
                                || (step.call.is_some()
                                    && !step.arguments.is_null()
                                    && !step
                                        .arguments
                                        .as_object()
                                        .is_some_and(serde_json::Map::is_empty))
                                || e.exit != 0)
                        {
                            return Err(format!(
                                "{}: call needs a live session, one copied call or tool, and no additional copied-call arguments",
                                step.id
                            ));
                        }
                        if step.kind == "pages"
                            && (step.tool.is_empty()
                                || step.minimum_pages == 0
                                || step.minimum_pages > step.maximum_pages
                                || step.maximum_pages > 256)
                        {
                            return Err(format!(
                                "{}: paged checks need a tool and 1..256 bounded pages",
                                step.id
                            ));
                        }
                        if step.kind == "query" && (step.tool.is_empty() || step.cli.is_empty()) {
                            return Err(format!(
                                "{}: query needs both real CLI and MCP operations",
                                step.id
                            ));
                        }
                        if step.kind == "process" && !valid_id(&step.binary) {
                            return Err(format!(
                                "{}: process binary must be an artifact basename",
                                step.id
                            ));
                        }
                    }
                    other => return Err(format!("{}: unknown step kind {other}", step.id)),
                }
            }
            if !sessions.is_empty() {
                return Err(format!(
                    "{}: every MCP session requires an explicit stop",
                    case.id
                ));
            }
        }
        let known = self
            .cases
            .iter()
            .map(|c| c.id.as_str())
            .collect::<BTreeSet<_>>();
        let mut resolved = BTreeSet::new();
        for case in &self.cases {
            let requirements = case.requires.iter().collect::<BTreeSet<_>>();
            if requirements.len() != case.requires.len()
                || case
                    .requires
                    .iter()
                    .any(|r| r == &case.id || !known.contains(r.as_str()))
            {
                return Err(format!(
                    "{}: duplicate, self, or unknown required case",
                    case.id
                ));
            }
        }
        loop {
            let before = resolved.len();
            for case in &self.cases {
                if case.requires.iter().all(|r| resolved.contains(r.as_str())) {
                    resolved.insert(case.id.as_str());
                }
            }
            if resolved.len() == self.cases.len() {
                break;
            }
            if before == resolved.len() {
                return Err("case world/foundation dependencies contain a cycle".into());
            }
        }
        Ok(())
    }
}
