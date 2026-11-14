// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Builds the Keel plan: one node per test, with its edges and its key
//! (DESIGN.md §2 and §3).

use super::{
    config::{InputDecl, KeelConfig},
    keyer::{BinaryCodeKeys, CodeKeyer},
};
use crate::{
    config::core::EvaluatableProfile,
    errors::{CodeKeyError, KeelError},
    list::{RustTestSuite, TestInstance, TestList},
    platform::BuildPlatforms,
    rustc_cli::RustcCli,
    target_runner::TargetRunner,
};
use camino::{Utf8Path, Utf8PathBuf};
use guppy::{
    PackageId,
    graph::{DependencyDirection, PackageGraph, PackageMetadata},
};
use keel::{
    Digest, EnvContract, FileSpec, FilesInput, GroupId, Inputs, Kind, LocalStore, NetMode, Node,
    NodeId, PartId, PartKind, Plan, Platform, Policy, ReachInfo, ResultStore, StoredPass, SymbolId,
    Upstream,
};
use keel_decl::{Declaration, applies_to, try_nextest_test_name};
use nextest_filtering::EvalContext;
use nextest_metadata::RustTestBinaryKind;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    time::{Duration, Instant},
};
use tracing::{debug, warn};

/// One test of the plan.
#[derive(Debug)]
pub(crate) struct PlannedTest {
    pub(crate) node: Node,
    pub(crate) cached: Option<StoredPass>,
}

/// Everything needed to build a [`KeelPlan`].
#[derive(Debug)]
pub struct KeelPlanInputs<'a, 'g> {
    /// The listed tests.
    pub test_list: &'a TestList<'g>,

    /// The profile the tests run under.
    pub profile: &'a EvaluatableProfile<'a>,

    /// The workspace graph.
    pub graph: &'g PackageGraph,

    /// The workspace root, as seen by the tests.
    pub workspace_root: &'a Utf8Path,

    /// The platforms the tests were built for.
    pub build_platforms: &'a BuildPlatforms,

    /// The target runner.
    pub target_runner: &'a TargetRunner,
}

/// A planned run: the nodes, their hierarchy, and which of them are cached.
#[derive(Debug)]
pub struct KeelPlan {
    pub(crate) tests: Vec<PlannedTest>,
    pub(crate) index: HashMap<NodeId, usize>,
    pub(crate) plan: Plan,
    pub(crate) platform: Platform,
    pub(crate) reach: Option<ReachInfo>,
    pub(crate) key_duration: Duration,
    pub(crate) binaries_keyed: usize,
}

impl KeelPlan {
    /// Builds the plan for the selected tests of `inputs.test_list`.
    pub fn build<'g>(
        inputs: &KeelPlanInputs<'_, 'g>,
        config: &KeelConfig,
        store: &LocalStore,
        keyer: &dyn CodeKeyer,
    ) -> Result<Self, KeelError> {
        let start = Instant::now();
        let platform = platform_facts(inputs.build_platforms, inputs.target_runner)?;
        let ecx = inputs.profile.filterset_ecx();
        let mut builder = PlanBuilder::new(inputs, config, &ecx);

        let mut nodes = Vec::new();
        let mut reach = ReachBuilder::default();
        let mut binaries_keyed = 0;
        for suite in inputs.test_list.iter() {
            let selected: Vec<TestInstance<'_>> = suite
                .status
                .test_cases()
                .map(|case| TestInstance::new(case, suite))
                .filter(|instance| instance.test_info.filter_match.is_match())
                .collect();
            if selected.is_empty() {
                continue;
            }
            binaries_keyed += 1;
            builder.plan_suite(suite, &selected, keyer, &platform, &mut nodes, &mut reach)?;
        }

        let plan = Plan::new(&nodes).map_err(KeelError::Plan)?;
        let index: HashMap<NodeId, usize> = nodes
            .iter()
            .enumerate()
            .map(|(i, node)| (node.id.clone(), i))
            .collect();

        let mut tests = Vec::with_capacity(nodes.len());
        for node in nodes {
            let cached = if node.policy.network {
                None
            } else {
                lookup_pass(store, &node)
            };
            tests.push(PlannedTest { node, cached });
        }

        Ok(Self {
            tests,
            index,
            plan,
            platform,
            reach: reach.finish(),
            key_duration: start.elapsed(),
            binaries_keyed,
        })
    }

    /// Returns the number of planned tests.
    pub fn len(&self) -> usize {
        self.tests.len()
    }

    /// Returns true if no test is planned.
    pub fn is_empty(&self) -> bool {
        self.tests.is_empty()
    }

    /// Returns the number of tests with a stored pass for their current key.
    pub fn cached_count(&self) -> usize {
        self.tests.iter().filter(|t| t.cached.is_some()).count()
    }

    /// Returns the number of test binaries that were keyed.
    pub fn binaries_keyed(&self) -> usize {
        self.binaries_keyed
    }

    /// Returns how long keying took.
    pub fn key_duration(&self) -> Duration {
        self.key_duration
    }

    /// Returns the platform the keys were computed for.
    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    /// Writes one line per node: level, group, key prefix, `cached` or `run`,
    /// the number of nodes it stands on, and its ID.
    pub fn render(&self) -> String {
        let mut order: Vec<usize> = (0..self.tests.len()).collect();
        order.sort_by_key(|&i| {
            let node = &self.tests[i].node;
            (self.plan.level(&node.id).unwrap_or(0), node.id.clone())
        });
        let mut out = String::new();
        for i in order {
            let test = &self.tests[i];
            let node = &test.node;
            let level = self.plan.level(&node.id).unwrap_or(0);
            let upstream = self.plan.upstream(&node.id).map_or(0, |ups| ups.len());
            let hex = node.key.to_hex();
            let state = if test.cached.is_some() {
                "cached"
            } else {
                "run"
            };
            out.push_str(&format!(
                "{level:>3} {group} {prefix} {state} {upstream} {id}\n",
                group = node.group,
                prefix = &hex[..12.min(hex.len())],
                id = node.id,
            ));
        }
        out
    }
}

fn lookup_pass(store: &LocalStore, node: &Node) -> Option<StoredPass> {
    match store.get_pass(&node.key) {
        Ok(Some(pass)) if pass.id == node.id => Some(pass),
        Ok(_) => None,
        Err(error) => {
            warn!(
                "ignoring an unreadable Keel store entry for `{}`: {error}",
                node.id
            );
            None
        }
    }
}

#[derive(Default)]
struct ReachBuilder {
    info: ReachInfo,
    any: bool,
}

impl ReachBuilder {
    fn record(
        &mut self,
        id: &NodeId,
        reach: Option<&BTreeSet<u32>>,
        exercised: Option<&BTreeSet<u32>>,
    ) {
        let symbols = |set: &BTreeSet<u32>| set.iter().map(|&s| SymbolId(u64::from(s))).collect();
        if let Some(reach) = reach {
            self.info.reach.insert(id.clone(), symbols(reach));
            self.any = true;
        }
        if let Some(exercised) = exercised {
            self.info.exercised.insert(id.clone(), symbols(exercised));
            self.any = true;
        }
    }

    fn finish(self) -> Option<ReachInfo> {
        self.any.then_some(self.info)
    }
}

struct PlanBuilder<'a, 'g, 'e> {
    inputs: &'a KeelPlanInputs<'a, 'g>,
    config: &'a KeelConfig,
    ecx: &'e EvalContext<'e>,
    ambient: HashMap<String, String>,
    cargo_env: BTreeMap<String, String>,
    crate_names: HashMap<String, String>,
    dependency_groups: HashMap<PackageId, Vec<GroupId>>,
    files_keys: HashMap<(String, Vec<String>), Digest>,
    env_keys: HashMap<Vec<String>, Digest>,
    tool_digests: HashMap<String, Digest>,
}

impl<'a, 'g, 'e> PlanBuilder<'a, 'g, 'e> {
    fn new(
        inputs: &'a KeelPlanInputs<'a, 'g>,
        config: &'a KeelConfig,
        ecx: &'e EvalContext<'e>,
    ) -> Self {
        let crate_names = inputs
            .graph
            .workspace()
            .iter()
            .map(|package| (package.name().replace('-', "_"), package.name().to_owned()))
            .collect();
        Self {
            inputs,
            config,
            ecx,
            ambient: std::env::vars().collect(),
            cargo_env: inputs
                .test_list
                .cargo_env()
                .name_values()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            crate_names,
            dependency_groups: HashMap::new(),
            files_keys: HashMap::new(),
            env_keys: HashMap::new(),
            tool_digests: HashMap::new(),
        }
    }

    fn plan_suite(
        &mut self,
        suite: &RustTestSuite<'g>,
        selected: &[TestInstance<'_>],
        keyer: &dyn CodeKeyer,
        platform: &Platform,
        nodes: &mut Vec<Node>,
        reach: &mut ReachBuilder,
    ) -> Result<(), KeelError> {
        let names: Vec<&str> = selected.iter().map(|t| t.name.as_str()).collect();
        let code_keys = keyer
            .keys(&suite.binary_path, &suite.binary_name, &names)
            .map_err(|error| KeelError::CodeKey {
                binary_id: suite.binary_id.clone(),
                error,
            })?;
        let bin_digest = hash_bin_exes(suite).map_err(|error| KeelError::CodeKey {
            binary_id: suite.binary_id.clone(),
            error,
        })?;
        let declarations =
            keel_decl::read_declarations(suite.binary_path.as_std_path()).map_err(|error| {
                KeelError::Declarations {
                    binary_id: suite.binary_id.clone(),
                    error,
                }
            })?;
        let declared: Vec<(String, &Declaration)> = declarations
            .iter()
            .filter_map(|decl| {
                try_nextest_test_name(decl, &suite.binary_name).map(|name| (name, decl))
            })
            .collect();

        let group = group_for(suite);
        let derived = self.derived_edges(suite);
        for instance in selected {
            let id = NodeId::new(format!(
                "rust:{}::{}",
                suite.binary_id,
                instance.name.as_str()
            ));
            let applicable: Vec<&Declaration> = declared
                .iter()
                .filter(|(name, _)| applies_to(name, instance.name.as_str()))
                .map(|(_, decl)| *decl)
                .collect();
            let node = self.plan_test(
                suite,
                instance,
                id,
                &group,
                &derived,
                &applicable,
                &code_keys,
                &bin_digest,
                platform,
                reach,
            )?;
            nodes.push(node);
        }
        Ok(())
    }

    #[expect(clippy::too_many_arguments)]
    fn plan_test(
        &mut self,
        suite: &RustTestSuite<'_>,
        instance: &TestInstance<'_>,
        id: NodeId,
        group: &GroupId,
        derived: &[Upstream],
        declarations: &[&Declaration],
        code_keys: &BinaryCodeKeys,
        bin_digest: &Digest,
        platform: &Platform,
        reach: &mut ReachBuilder,
    ) -> Result<Node, KeelError> {
        let test_name = instance.name.as_str();
        let query = instance.to_test_query();
        let package_name = suite.package.name();

        let mut decl = self
            .config
            .packages
            .get(package_name)
            .cloned()
            .unwrap_or_default();
        for entry in &self.config.overrides {
            if entry.filter.matches_test(&query, self.ecx) {
                decl.merge(&entry.decl);
            }
        }

        let mut stands_on: Vec<Upstream> = derived.to_vec();
        let mut joins: BTreeSet<PartId> = BTreeSet::new();
        for entry in &self.config.hierarchy {
            if !entry.filter.matches_test(&query, self.ecx) {
                continue;
            }
            if entry.stands_on_only {
                stands_on.clear();
            }
            stands_on.extend(entry.stands_on.iter().cloned());
            joins.extend(entry.joins.iter().cloned());
        }
        for declaration in declarations {
            for text in &declaration.stands_on {
                let upstream =
                    text.parse::<Upstream>()
                        .map_err(|error| KeelError::DeclarationEntry {
                            test: id.to_string(),
                            entry: text.clone(),
                            reason: error.to_string(),
                        })?;
                stands_on.push(self.canonical_upstream(upstream));
            }
            for text in &declaration.joins {
                joins.insert(self.crate_part(text));
            }
        }
        stands_on.sort();
        stands_on.dedup();
        stands_on.retain(|upstream| !matches!(upstream, Upstream::Node(n) if *n == id));

        let (test_key, kind) = code_keys.key_for(test_name);
        if let Some(per_test) = code_keys.per_test.get(test_name) {
            joins.extend(per_test.crates.iter().map(|name| self.crate_part(name)));
            reach.record(&id, per_test.reach.as_ref(), per_test.exercised.as_ref());
        }
        let code = fold_code(&test_key, bin_digest, &id);

        let files = self.files_digest(suite, &decl)?;
        let env = self.env_digest(&decl);
        let tools = self.tools_digest(&id, &decl)?;

        let inputs = Inputs {
            code: Some(code),
            code_kind: Some(kind),
            files: Some(FilesInput::Hash(files)),
            env: Some(env),
            tools,
            consumes: Vec::new(),
            drv: None,
        };
        let key =
            keel::key(keel::KEY_SCHEMA, &inputs, platform).map_err(|error| KeelError::Key {
                test: id.to_string(),
                error,
            })?;

        Ok(Node {
            id,
            kind: Kind::RustTest,
            group: group.clone(),
            stands_on,
            joins: joins.into_iter().collect(),
            inputs,
            produces: Vec::new(),
            via: None,
            key,
            policy: Policy {
                blocks: decl.blocks.unwrap_or(true),
                network: decl.network.unwrap_or(false),
                ..Policy::default()
            },
        })
    }

    fn canonical_name(&self, name: &str) -> String {
        self.crate_names
            .get(&name.replace('-', "_"))
            .cloned()
            .unwrap_or_else(|| name.to_owned())
    }

    fn crate_part(&self, text: &str) -> PartId {
        match text.parse::<PartId>() {
            Ok(part) => part,
            Err(_) => PartId::new(PartKind::Crate, self.canonical_name(text)),
        }
    }

    fn canonical_upstream(&self, upstream: Upstream) -> Upstream {
        match upstream {
            Upstream::Group(group) => {
                let name = self.canonical_name(group.name());
                Upstream::Group(match group.kind() {
                    keel::GroupKind::Unit => GroupId::unit(name),
                    keel::GroupKind::Integration => GroupId::integration(name),
                    keel::GroupKind::Scenario => GroupId::scenario(name),
                })
            }
            node @ Upstream::Node(_) => node,
        }
    }

    fn derived_edges(&mut self, suite: &RustTestSuite<'g>) -> Vec<Upstream> {
        let package = suite.package;
        let mut groups = self.dependency_groups_of(&package).to_vec();
        if is_integration(&suite.kind) {
            groups.push(GroupId::unit(package.name()));
        }
        groups.into_iter().map(Upstream::Group).collect()
    }

    fn dependency_groups_of(&mut self, package: &PackageMetadata<'g>) -> &[GroupId] {
        self.dependency_groups
            .entry(package.id().clone())
            .or_insert_with(|| workspace_dependency_groups(self.inputs.graph, package))
    }

    fn files_digest(
        &mut self,
        suite: &RustTestSuite<'_>,
        decl: &InputDecl,
    ) -> Result<Digest, KeelError> {
        let package_dir = package_relative_dir(self.inputs.graph, &suite.package);
        let globs = decl
            .inputs
            .iter()
            .map(|glob| {
                resolve_glob(&package_dir, glob).ok_or_else(|| KeelError::ConfigEntry {
                    path: self.config.path().to_owned(),
                    section: format!("package.{}", suite.package.name()),
                    value: glob.clone(),
                    reason: "the glob points outside the workspace; keep `..` segments inside \
                             the workspace root"
                        .to_owned(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let cache_key = (suite.package.name().to_owned(), globs.clone());
        if let Some(digest) = self.files_keys.get(&cache_key) {
            return Ok(*digest);
        }
        let spec = FileSpec {
            package_dir: Some(package_dir),
            globs,
            exclude: Vec::new(),
        };
        let (digest, _paths) = keel::files_key(self.inputs.workspace_root.as_std_path(), &spec)
            .map_err(|error| KeelError::Files {
                package: suite.package.name().to_owned(),
                error,
            })?;
        self.files_keys.insert(cache_key, digest);
        Ok(digest)
    }

    fn env_digest(&mut self, decl: &InputDecl) -> Digest {
        if let Some(digest) = self.env_keys.get(&decl.env) {
            return *digest;
        }
        let contract = EnvContract {
            allow: decl.env.clone(),
            profile_env: self.cargo_env.clone(),
        };
        let digest = keel::env_key(&contract, &self.ambient);
        self.env_keys.insert(decl.env.clone(), digest);
        digest
    }

    fn tools_digest(&mut self, id: &NodeId, decl: &InputDecl) -> Result<Option<Digest>, KeelError> {
        if decl.tools.is_empty() {
            return Ok(None);
        }
        let mut names: Vec<&String> = decl.tools.iter().collect();
        names.sort();
        names.dedup();
        let mut buf = Vec::new();
        put(&mut buf, b"keel/nextest/tools/v1");
        for name in names {
            let digest = match self.tool_digests.get(name) {
                Some(digest) => *digest,
                None => {
                    let path = which(name).ok_or_else(|| KeelError::ToolNotFound {
                        test: id.to_string(),
                        tool: name.clone(),
                    })?;
                    let bytes = std::fs::read(&path).map_err(|error| KeelError::ToolRead {
                        tool: name.clone(),
                        path: path.clone(),
                        error,
                    })?;
                    let digest = Digest::of(&bytes);
                    self.tool_digests.insert(name.clone(), digest);
                    digest
                }
            };
            put(&mut buf, name.as_bytes());
            put(&mut buf, digest.to_string().as_bytes());
        }
        Ok(Some(Digest::of(&buf)))
    }
}

fn is_integration(kind: &RustTestBinaryKind) -> bool {
    !(*kind == RustTestBinaryKind::LIB
        || *kind == RustTestBinaryKind::BIN
        || *kind == RustTestBinaryKind::PROC_MACRO)
}

fn group_for(suite: &RustTestSuite<'_>) -> GroupId {
    if is_integration(&suite.kind) {
        GroupId::integration(suite.package.name())
    } else {
        GroupId::unit(suite.package.name())
    }
}

fn workspace_dependency_groups(
    graph: &PackageGraph,
    package: &PackageMetadata<'_>,
) -> Vec<GroupId> {
    let mut start: Vec<&PackageId> = vec![package.id()];
    for link in package.direct_links() {
        if link.dev().is_present() && link.to().in_workspace() {
            start.push(link.to().id());
        }
    }
    let Ok(query) = graph.query_forward(start) else {
        return Vec::new();
    };
    let set =
        query.resolve_with_fn(|_, link| link.normal().is_present() || link.build().is_present());
    let mut names: BTreeSet<&str> = set
        .packages(DependencyDirection::Forward)
        .filter(|dep| dep.in_workspace() && dep.id() != package.id())
        .map(|dep| dep.name())
        .collect();
    names.remove(package.name());
    names.into_iter().map(GroupId::unit).collect()
}

fn package_relative_dir(graph: &PackageGraph, package: &PackageMetadata<'_>) -> Utf8PathBuf {
    let manifest_dir = package
        .manifest_path()
        .parent()
        .unwrap_or(Utf8Path::new(""));
    manifest_dir
        .strip_prefix(graph.workspace().root())
        .map(Utf8Path::to_owned)
        .unwrap_or_else(|_| manifest_dir.to_owned())
}

/// Resolves a declared glob to a pattern relative to the workspace root.
///
/// Globs are relative to the package directory; a leading `/` makes them
/// relative to the workspace root. Returns `None` if the glob climbs out of
/// the workspace.
fn resolve_glob(package_dir: &Utf8Path, glob: &str) -> Option<String> {
    let (base, rest) = match glob.strip_prefix('/') {
        Some(rest) => (Utf8Path::new(""), rest),
        None => (package_dir, glob),
    };
    let mut parts: Vec<&str> = base
        .components()
        .map(|component| component.as_str())
        .collect();
    for segment in rest.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

fn hash_bin_exes(suite: &RustTestSuite<'_>) -> Result<Digest, CodeKeyError> {
    let mut buf = Vec::new();
    put(&mut buf, b"keel/nextest/bin-exes/v1");
    for (name, path) in &suite.non_test_binaries {
        let digest =
            keel::executable_key(path.as_std_path()).map_err(|error| CodeKeyError::Executable {
                path: path.clone(),
                error,
            })?;
        put(&mut buf, name.as_bytes());
        put(&mut buf, digest.to_string().as_bytes());
    }
    Ok(Digest::of(&buf))
}

/// Folds the binary's executables and the test's identity into the code
/// digest.
///
/// The key of a node does not otherwise contain the node, so two tests with
/// identical code would share a key and one test's pass would satisfy the
/// other.
fn fold_code(test_key: &Digest, bin_digest: &Digest, id: &NodeId) -> Digest {
    let mut buf = Vec::new();
    put(&mut buf, b"keel/nextest/code/v1");
    put(&mut buf, test_key.to_string().as_bytes());
    put(&mut buf, bin_digest.to_string().as_bytes());
    put(&mut buf, id.as_str().as_bytes());
    Digest::of(&buf)
}

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn which(name: &str) -> Option<PathBuf> {
    let is_executable = |path: &PathBuf| {
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        if !meta.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            true
        }
    };
    if name.contains(std::path::MAIN_SEPARATOR) {
        let path = PathBuf::from(name);
        return is_executable(&path).then_some(path);
    }
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(is_executable)
}

fn platform_facts(
    build_platforms: &BuildPlatforms,
    target_runner: &TargetRunner,
) -> Result<Platform, KeelError> {
    let output = RustcCli::version_verbose()
        .read()
        .ok_or_else(|| KeelError::Rustc {
            message:
                "the command failed or could not be run; check that `rustc` is on PATH, or set \
                  RUSTC"
                    .to_owned(),
        })?;
    let text = String::from_utf8_lossy(&output);
    let version = text
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .ok_or_else(|| KeelError::Rustc {
            message: "the output was empty".to_owned(),
        })?;
    let triple = match &build_platforms.target {
        Some(target) => target.triple.platform.triple_str().to_owned(),
        None => build_platforms.host.platform.triple_str().to_owned(),
    };
    let mut platform = Platform::new(triple, version, NetMode::Open);
    let runner = match &build_platforms.target {
        Some(_) => target_runner.target(),
        None => target_runner.host(),
    };
    platform.emulator = runner.map(|runner| {
        std::iter::once(runner.binary())
            .chain(runner.args())
            .collect::<Vec<_>>()
            .join(" ")
    });
    debug!("keel platform: {platform:?}");
    Ok(platform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_are_package_relative_unless_rooted() {
        let dir = Utf8Path::new("crates/store");
        assert_eq!(
            resolve_glob(dir, "../../.config/fixtures/**").as_deref(),
            Some(".config/fixtures/**")
        );
        assert_eq!(
            resolve_glob(dir, "data/*.json").as_deref(),
            Some("crates/store/data/*.json")
        );
        assert_eq!(
            resolve_glob(dir, "/shared/**").as_deref(),
            Some("shared/**")
        );
        assert_eq!(resolve_glob(dir, "../../../escape"), None);
    }

    #[test]
    fn folded_code_depends_on_the_test_identity() {
        let key = Digest::of(b"binary");
        let bins = Digest::of(b"bins");
        let a = fold_code(&key, &bins, &NodeId::new("rust:x::a"));
        let b = fold_code(&key, &bins, &NodeId::new("rust:x::b"));
        assert_ne!(a, b);
        assert_eq!(a, fold_code(&key, &bins, &NodeId::new("rust:x::a")));
    }

    #[test]
    fn which_finds_a_program_on_path() {
        assert!(which("sh").is_some() || cfg!(windows));
        assert!(which("keel-no-such-tool-xyz").is_none());
    }
}
