//! The node vocabulary of DESIGN.md §2 and the manifest field names of §8.1.
//!
//! Every type here is `deny_unknown_fields` on read: a manifest from a newer
//! producer fails loudly instead of being silently half-understood. The one
//! deliberate exception is [`Platform`](crate::key::Platform), an open map.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::digest::Digest;

/// Implements `Serialize`/`Deserialize` as the `Display`/`FromStr` text form.
macro_rules! string_serde {
    ($($ty:ty),* $(,)?) => {$(
        impl Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = String::deserialize(d)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    )*};
}
string_serde!(Digest);

/// Stable identity of one node across runs and machines.
///
/// The text starts with a namespace that says which runner owns it:
///
/// - `rust:` nextest binary id plus test path, `rust:backend-store::wal_replay::replays_torn_tail`
/// - `go:` module path, package and test name
/// - `nu:` repo, script path and test name
/// - `nix:` the attribute path, `nix:scenario:backend-mcp-serves`
///
/// A control twin appends `!<variant>` to its twin's id
/// (`nix:scenario:backend-mcp-serves!wrong-port`). Ids with another or no
/// namespace are accepted (a conductor may merge foreign reports) but have no
/// [`kind_prefix`](Self::kind_prefix).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(SmolStr);

impl NodeId {
    /// The namespaces runners use, in the order DESIGN.md §2.1 lists them.
    pub const PREFIXES: [&'static str; 4] = ["rust", "go", "nu", "nix"];

    /// Wraps an id without validating it; ids are opaque outside the prefix.
    pub fn new(id: impl Into<SmolStr>) -> Self {
        NodeId(id.into())
    }

    /// The full id text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The runner namespace (`rust`, `go`, `nu` or `nix`), if the id has one.
    pub fn kind_prefix(&self) -> Option<&str> {
        let (head, _) = self.0.split_once(':')?;
        Self::PREFIXES.contains(&head).then_some(head)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.0)
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        NodeId::new(s)
    }
}

/// What a [`GroupId`] groups.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum GroupKind {
    /// `unit(<package>)`: the `kind(lib)` tests of a package.
    Unit,
    /// `integration(<package>)`: the `kind(test)` tests of a package.
    Integration,
    /// `scenario(<name>)`: the nodes of one scenario run.
    Scenario,
}

impl GroupKind {
    const ALL: [(GroupKind, &'static str); 3] = [
        (GroupKind::Unit, "unit"),
        (GroupKind::Integration, "integration"),
        (GroupKind::Scenario, "scenario"),
    ];

    fn head(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(k, _)| *k == self)
            .map_or("", |(_, h)| h)
    }
}

/// A virtual node whose status is the conjunction of its members (§2.2).
///
/// Text form is exactly `unit(<pkg>)`, `integration(<pkg>)` or
/// `scenario(<name>)`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct GroupId {
    kind: GroupKind,
    name: SmolStr,
}

/// Why a string is not a [`GroupId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not a group id; write `unit(<package>)`, `integration(<package>)` or `scenario(<name>)` with a non-empty name that has no parentheses"
)]
pub struct GroupParseError(String);

impl GroupId {
    /// `unit(<package>)`.
    pub fn unit(package: impl Into<SmolStr>) -> Self {
        GroupId {
            kind: GroupKind::Unit,
            name: package.into(),
        }
    }

    /// `integration(<package>)`.
    pub fn integration(package: impl Into<SmolStr>) -> Self {
        GroupId {
            kind: GroupKind::Integration,
            name: package.into(),
        }
    }

    /// `scenario(<name>)`.
    pub fn scenario(name: impl Into<SmolStr>) -> Self {
        GroupId {
            kind: GroupKind::Scenario,
            name: name.into(),
        }
    }

    /// Which kind of group this is.
    pub fn kind(&self) -> GroupKind {
        self.kind
    }

    /// The package or scenario name inside the parentheses.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether `s` begins like a group id, so a malformed one is an error
    /// rather than being taken for a node id.
    fn looks_like(s: &str) -> bool {
        GroupKind::ALL
            .iter()
            .any(|(_, h)| s.strip_prefix(h).is_some_and(|r| r.starts_with('(')))
    }
}

impl FromStr for GroupId {
    type Err = GroupParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || GroupParseError(s.to_owned());
        let inner = s.strip_suffix(')').ok_or_else(bad)?;
        let (head, name) = inner.split_once('(').ok_or_else(bad)?;
        let kind = GroupKind::ALL
            .iter()
            .find(|(_, h)| *h == head)
            .map(|(k, _)| *k)
            .ok_or_else(bad)?;
        if name.is_empty() || name.contains(['(', ')']) {
            return Err(bad());
        }
        Ok(GroupId {
            kind,
            name: name.into(),
        })
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.kind.head(), self.name)
    }
}

/// What a test stands on: one node, or every member of a group.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Upstream {
    /// A single node.
    Node(NodeId),
    /// All members of a group.
    Group(GroupId),
}

impl FromStr for Upstream {
    type Err = GroupParseError;

    /// Text that starts like a group (`unit(`, `integration(`, `scenario(`)
    /// must be a well-formed group; anything else is a node id. A node id
    /// such as `rust:unit(x)` therefore stays a node id.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if GroupId::looks_like(s) {
            s.parse().map(Upstream::Group)
        } else {
            Ok(Upstream::Node(NodeId::new(s)))
        }
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Upstream::Node(n) => n.fmt(f),
            Upstream::Group(g) => g.fmt(f),
        }
    }
}

/// The namespace of a [`PartId`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum PartKind {
    /// A Rust crate.
    Crate,
    /// A deployed service.
    Service,
    /// A named edge between services.
    Edge,
    /// An HTTP route.
    Route,
}

impl PartKind {
    /// Every namespace, as written in ids.
    pub const NAMESPACES: [&'static str; 4] = ["crate", "service", "edge", "route"];

    fn namespace(self) -> &'static str {
        Self::NAMESPACES[self as usize]
    }
}

/// A namespaced part id: `crate:backend-store`, `service:nudox-auth`,
/// `edge:auth-to-zitadel-oidc`, `route:/v1/me` (§2.7).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct PartId {
    kind: PartKind,
    name: SmolStr,
}

/// Why a string is not a [`PartId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "part id `{0}` needs a namespace and a name; use one of `crate:`, `service:`, `edge:` or `route:` followed by the name, e.g. `crate:backend-store`"
)]
pub struct PartParseError(String);

impl PartId {
    /// Builds a part from a namespace and a non-empty name.
    pub fn new(kind: PartKind, name: impl Into<SmolStr>) -> Self {
        PartId {
            kind,
            name: name.into(),
        }
    }

    /// The namespace.
    pub fn kind(&self) -> PartKind {
        self.kind
    }

    /// The name after the namespace.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl FromStr for PartId {
    type Err = PartParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || PartParseError(s.to_owned());
        let (ns, name) = s.split_once(':').ok_or_else(bad)?;
        let idx = PartKind::NAMESPACES
            .iter()
            .position(|n| *n == ns)
            .ok_or_else(bad)?;
        if name.is_empty() {
            return Err(bad());
        }
        let kind = [
            PartKind::Crate,
            PartKind::Service,
            PartKind::Edge,
            PartKind::Route,
        ][idx];
        Ok(PartId {
            kind,
            name: name.into(),
        })
    }
}

impl fmt::Display for PartId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind.namespace(), self.name)
    }
}

string_serde!(GroupId, Upstream, PartId);

/// The runner family that executes a node.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A Rust test run by the nextest fork.
    RustTest,
    /// A Go test.
    GoTest,
    /// A Nushell check.
    NuCheck,
    /// A Nix check or scenario read from a realised report.
    NixCheck,
    /// A node that runs a command and produces files others consume.
    Artifact,
    /// An arbitrary command.
    Command,
}

/// Which analysis decided a node's `code` digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeKind {
    /// The Merkle hash over the reachable symbols (§3.2).
    Reach,
    /// The hash of the binary's loadable sections (§3.1).
    Executable,
}

impl CodeKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            CodeKind::Reach => "reach",
            CodeKind::Executable => "executable",
        }
    }
}

/// A wrong-configuration twin whose expected status is `fail` (§8.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Control {
    /// Passing here means the twin's pass proves nothing.
    Negative,
}

/// Platform facts a node declares it can observe (§3.7).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    /// The CPU feature mask enters the key.
    Cpu,
    /// The kernel release and libc version enter the key.
    Kernel,
}

fn yes() -> bool {
    true
}

fn is_yes(b: &bool) -> bool {
    *b
}

/// Per-node execution policy.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Whether a failure of this node blocks the nodes above it. Defaults to
    /// true when absent, as in the control-twin example of §8.1.
    #[serde(default = "yes", skip_serializing_if = "is_yes")]
    pub blocks: bool,
    /// `negative` for wrong-configuration twins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<Control>,
    /// For a control node, the node whose behaviour it must contradict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub twin: Option<NodeId>,
    /// Timeout in seconds; the wire name is `timeout_s`.
    #[serde(default, rename = "timeout_s", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Whether the test needs the network. Such nodes never cache (§4.4).
    #[serde(default)]
    pub network: bool,
    /// Platform facts that enter this node's key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive: Vec<Sensitivity>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            blocks: true,
            control: None,
            twin: None,
            timeout: None,
            network: false,
            sensitive: Vec::new(),
        }
    }
}

/// The `files` input: either the hash a runner computed, or globs a runner
/// could not hash and left for the conductor (§8.1, last paragraph). Globs
/// are a declaration: [`crate::key::key`] refuses them, so resolve them with
/// [`crate::files_key`] first.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilesInput {
    /// The §3.3 files key.
    Hash(Digest),
    /// Globs relative to the workspace root, to be hashed by the conductor.
    Globs(Vec<String>),
}

/// Everything that can reach a node's process (§3).
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    /// Digest of the code, absent when the runner could not compute it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Digest>,
    /// Which analysis produced `code`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_kind: Option<CodeKind>,
    /// Runtime files, hashed or still globs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<FilesInput>,
    /// Digest of the environment contract (§3.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Digest>,
    /// Digest of the declared tools (§3.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Digest>,
    /// Artifact nodes whose outputs this node reads (§3.6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumes: Vec<NodeId>,
    /// The Nix derivation a Nix node is read from; many nodes share one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drv: Option<String>,
}

/// One entry of a node manifest (§8.1).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// Stable identity.
    pub id: NodeId,
    /// The runner family.
    pub kind: Kind,
    /// The group this node is a member of.
    pub group: GroupId,
    /// Upstream nodes and groups; all must be terminal before this node runs.
    #[serde(default)]
    pub stands_on: Vec<Upstream>,
    /// Parts this node exercises, for interaction coverage.
    #[serde(default)]
    pub joins: Vec<PartId>,
    /// What can reach the node's process.
    #[serde(default)]
    pub inputs: Inputs,
    /// For artifact nodes, the files the command produces.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub produces: Vec<String>,
    /// The realised report output a Nix node is read from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// The input key (§3).
    pub key: Digest,
    /// Execution policy.
    #[serde(default)]
    pub policy: Policy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_prefix() {
        assert_eq!(NodeId::new("rust:a::b").kind_prefix(), Some("rust"));
        assert_eq!(NodeId::new("nix:scenario:x").kind_prefix(), Some("nix"));
        assert_eq!(NodeId::new("go:m/p::T").kind_prefix(), Some("go"));
        assert_eq!(NodeId::new("nu:r:s::t").kind_prefix(), Some("nu"));
        assert_eq!(NodeId::new("other:x").kind_prefix(), None);
        assert_eq!(NodeId::new("plain").kind_prefix(), None);
    }

    #[test]
    fn group_round_trip_and_rejections() {
        for text in [
            "unit(backend-store)",
            "integration(backend-store)",
            "scenario(backend-mcp)",
        ] {
            let g: GroupId = text.parse().unwrap();
            assert_eq!(g.to_string(), text);
        }
        assert_eq!(GroupId::unit("x").to_string(), "unit(x)");
        for bad in [
            "unit()",
            "unit(a",
            "unit a)",
            "group(a)",
            "unit(a(b))",
            "",
            "Unit(a)",
        ] {
            assert!(bad.parse::<GroupId>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn part_ids_need_a_known_namespace() {
        let p: PartId = "route:/v1/me".parse().unwrap();
        assert_eq!(p.kind(), PartKind::Route);
        assert_eq!(p.to_string(), "route:/v1/me");
        for ns in PartKind::NAMESPACES {
            assert!(format!("{ns}:x").parse::<PartId>().is_ok());
        }
        let err = "backend-store".parse::<PartId>().unwrap_err().to_string();
        for ns in PartKind::NAMESPACES {
            assert!(err.contains(ns), "{err}");
        }
        assert!("crate:".parse::<PartId>().is_err());
        assert!("cargo:x".parse::<PartId>().is_err());
    }

    #[test]
    fn upstream_distinguishes_groups_from_nodes() {
        assert_eq!(
            "unit(a)".parse::<Upstream>().unwrap(),
            Upstream::Group(GroupId::unit("a"))
        );
        assert_eq!(
            "rust:a::b".parse::<Upstream>().unwrap(),
            Upstream::Node("rust:a::b".into())
        );
        // A cross-repo spelling stays a node id rather than being guessed at.
        assert!(matches!(
            "rust:unit(a)".parse::<Upstream>().unwrap(),
            Upstream::Node(_)
        ));
        // But something that starts like a group and is malformed is an error.
        assert!("unit(".parse::<Upstream>().is_err());
    }

    #[test]
    fn unknown_fields_are_errors() {
        let json = r#"{"blocks":true,"surprise":1}"#;
        let err = serde_json::from_str::<Policy>(json)
            .unwrap_err()
            .to_string();
        assert!(err.contains("surprise"), "{err}");
        let inputs = r#"{"code":"blake3:00","bogus":1}"#;
        assert!(serde_json::from_str::<Inputs>(inputs).is_err());
    }

    #[test]
    fn files_input_is_hash_or_globs() {
        let h = format!("\"blake3:{}\"", "ab".repeat(32));
        assert!(matches!(
            serde_json::from_str::<FilesInput>(&h).unwrap(),
            FilesInput::Hash(_)
        ));
        let g = serde_json::from_str::<FilesInput>(r#"["data/**"]"#).unwrap();
        assert_eq!(g, FilesInput::Globs(vec!["data/**".into()]));
    }

    #[test]
    fn policy_defaults_match_the_control_twin_example() {
        let p: Policy = serde_json::from_str(r#"{"control":"negative","twin":"nix:a"}"#).unwrap();
        assert!(p.blocks);
        assert_eq!(p.control, Some(Control::Negative));
        assert_eq!(p.twin, Some(NodeId::new("nix:a")));
        let p: Policy = serde_json::from_str(r#"{"timeout_s":60,"network":false}"#).unwrap();
        assert_eq!(p.timeout, Some(60));
    }
}
