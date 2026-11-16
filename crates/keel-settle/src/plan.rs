//! The plan (design/ir.md 7.2), at the fields slice 1 needs: schema, repository, base, head,
//! units and its own digest.
//!
//! A plan is canonical JSON: fields in declaration order, no whitespace, units strictly
//! sorted by (binary, name) so there is one byte stream per plan. The digest is blake3 over
//! that stream with the digest field left out. A plan that does not verify cannot be loaded.

use crate::digest::Digest;
use crate::error::{InputError, REGENERATE_PLAN};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

pub const SCHEMA: u32 = 1;
const DOMAIN: &str = "keel/plan/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BinaryKind {
    Lib,
    Bin,
    Test,
    Example,
    Bench,
}

/// `(package, kind, target)` of design/ir.md 5.5. For a lib the index does not know the
/// target name cargo gave it, so `target` is the package name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binary {
    pub package: String,
    pub kind: BinaryKind,
    pub target: String,
}

impl Binary {
    /// `pkg` (the lib's unit tests), `pkg::name` (integration test `name`), or
    /// `pkg::bin/x`, `pkg::example/x`, `pkg::bench/x`: the shapes nextest prints and
    /// `keel-index` approximates.
    pub fn parse(s: &str) -> Result<Binary, String> {
        let bad = |why: &str| format!("{s:?} is not a test binary: {why}. Write `<package>` for the lib's tests or `<package>::<target>` for an integration test (`<package>::bin/<x>` for a bin).");
        let (package, rest) = match s.split_once("::") {
            None => (s, None),
            Some((p, r)) => (p, Some(r)),
        };
        if package.is_empty() || package.contains(char::is_whitespace) {
            return Err(bad("the package name is empty or has a space"));
        }
        let Some(rest) = rest else {
            return Ok(Binary { package: package.to_owned(), kind: BinaryKind::Lib, target: package.to_owned() });
        };
        if rest.is_empty() || rest.contains("::") || rest.contains(char::is_whitespace) {
            return Err(bad("the target is empty, has a space, or has another `::`"));
        }
        let (kind, target) = if let Some(t) = rest.strip_prefix("bin/") {
            (BinaryKind::Bin, t)
        } else if let Some(t) = rest.strip_prefix("example/") {
            (BinaryKind::Example, t)
        } else if let Some(t) = rest.strip_prefix("bench/") {
            (BinaryKind::Bench, t)
        } else if rest == "build-script" {
            return Err(bad("a build script has no tests"));
        } else {
            (BinaryKind::Test, rest)
        };
        if target.is_empty() {
            return Err(bad("the target is empty"));
        }
        Ok(Binary { package: package.to_owned(), kind, target: target.to_owned() })
    }

    /// A unit as a person reads it: `<binary>$<name>`, the shape `keel-index` prints.
    pub fn label(&self, name: &str) -> String {
        format!("{self}${name}")
    }
}

impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            BinaryKind::Lib => write!(f, "{}", self.package),
            BinaryKind::Test => write!(f, "{}::{}", self.package, self.target),
            BinaryKind::Bin => write!(f, "{}::bin/{}", self.package, self.target),
            BinaryKind::Example => write!(f, "{}::example/{}", self.package, self.target),
            BinaryKind::Bench => write!(f, "{}::bench/{}", self.package, self.target),
        }
    }
}

/// A commit id: 40 (sha1) or 64 (sha256) lowercase hex characters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GitOid(String);

impl GitOid {
    pub fn new(s: &str) -> Result<GitOid, String> {
        if matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            Ok(GitOid(s.to_owned()))
        } else {
            Err(format!("{s:?} is not a full commit id (40 or 64 lowercase hex characters); resolve a revision name with `git rev-parse` first"))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for GitOid {
    type Error = String;
    fn try_from(s: String) -> Result<GitOid, String> {
        GitOid::new(&s)
    }
}
impl From<GitOid> for String {
    fn from(o: GitOid) -> String {
        o.0
    }
}

/// Why a unit runs (design/doubt.md 4.6). There is no variant for likelihood or budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Selected {
    KeyChanged,
    NoRecord,
    Recheck,
    RerunOfFailure,
}

/// What the plan expects of a unit (design/doubt.md 4.6, which ir.md 12 says to quote). Slice
/// 1 writes only `ReuseIfKeyHolds`: there is no store, so no key is known and neither
/// `KeyChanged` nor `NoRecord` can be asserted. `settle` of this slice refuses `Reuse` and
/// `Deferred` (Z4 and Z9 are not implemented) rather than judging them as something else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Disposition {
    Run { why: Selected },
    ReuseIfKeyHolds,
    Reuse { record: Digest },
    Deferred,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum What {
    Test { binary: Binary, name: String },
}

impl What {
    pub fn binary(&self) -> &Binary {
        let What::Test { binary, .. } = self;
        binary
    }
    pub fn test_name(&self) -> &str {
        let What::Test { name, .. } = self;
        name
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unit {
    /// For people (design/ir.md I3); the join key is `what`.
    pub name: String,
    pub what: What,
    pub expect: Disposition,
}

impl Unit {
    pub fn test(binary: Binary, name: String, expect: Disposition) -> Unit {
        Unit { name: binary.label(&name), what: What::Test { binary, name }, expect }
    }
    fn key(&self) -> (&Binary, &str) {
        (self.what.binary(), self.what.test_name())
    }
}

#[derive(Serialize)]
struct Body<'a> {
    schema: u32,
    repository: &'a str,
    base: &'a GitOid,
    head: &'a GitOid,
    units: &'a [Unit],
}

#[derive(Serialize)]
struct Written<'a> {
    #[serde(flatten)]
    body: Body<'a>,
    digest: Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    schema: u32,
    repository: String,
    base: GitOid,
    head: GitOid,
    units: Vec<Unit>,
    digest: Digest,
}

/// A plan that has been checked: units non-empty, strictly sorted (so each exactly once),
/// and the digest equal to the content's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    repository: String,
    base: GitOid,
    head: GitOid,
    units: Vec<Unit>,
    digest: Digest,
}

impl Plan {
    /// Sorts the units and refuses an empty plan: a plan with nothing in it would settle as
    /// a pass with nothing run.
    pub fn new(repository: String, base: GitOid, head: GitOid, mut units: Vec<Unit>) -> Result<Plan, String> {
        units.sort_by(|a, b| a.key().cmp(&b.key()));
        Plan::checked(repository, base, head, units, None)
    }

    fn checked(repository: String, base: GitOid, head: GitOid, units: Vec<Unit>, claimed: Option<Digest>) -> Result<Plan, String> {
        if repository.is_empty() || repository.contains(char::is_control) {
            return Err("the repository name is empty or has a control character".to_owned());
        }
        if units.is_empty() {
            return Err("the plan has no units: a verdict over nothing would be a pass".to_owned());
        }
        for w in units.windows(2) {
            match w[0].key().cmp(&w[1].key()) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(format!("unit {} is listed twice; each unit appears exactly once (PL1)", w[0].name)),
                std::cmp::Ordering::Greater => return Err(format!("units are not sorted: {} comes before {}; the canonical form is sorted by (binary, name)", w[0].name, w[1].name)),
            }
        }
        for u in &units {
            let want = u.what.binary().label(u.what.test_name());
            if u.name != want {
                return Err(format!("unit named {:?} is the test {want:?}; the printed name must be derived from the test", u.name));
            }
        }
        let body = Body { schema: SCHEMA, repository: &repository, base: &base, head: &head, units: &units };
        let digest = Digest::of(DOMAIN, &serde_json::to_vec(&body).map_err(|e| e.to_string())?);
        if let Some(c) = claimed
            && c != digest
        {
            return Err(format!("the digest in the file is {c} but its content hashes to {digest}; the file was edited or cut after it was written"));
        }
        Ok(Plan { repository, base, head, units, digest })
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }
    pub fn base(&self) -> &GitOid {
        &self.base
    }
    pub fn head(&self) -> &GitOid {
        &self.head
    }
    pub fn units(&self) -> &[Unit] {
        &self.units
    }
    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// Distinct binaries, in order.
    pub fn binaries(&self) -> Vec<&Binary> {
        let mut out: Vec<&Binary> = Vec::new();
        for u in &self.units {
            if out.last() != Some(&u.what.binary()) {
                out.push(u.what.binary());
            }
        }
        out
    }

    pub fn tests_of<'a>(&'a self, binary: &'a Binary) -> impl Iterator<Item = &'a str> + 'a {
        self.units.iter().filter(move |u| u.what.binary() == binary).map(|u| u.what.test_name())
    }

    /// Canonical bytes, newline-terminated.
    pub fn to_bytes(&self) -> Vec<u8> {
        let body = Body { schema: SCHEMA, repository: &self.repository, base: &self.base, head: &self.head, units: &self.units };
        let mut v = serde_json::to_vec(&Written { body, digest: self.digest }).expect("a plan is plain data");
        v.push(b'\n');
        v
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Plan, String> {
        let raw: Raw = serde_json::from_slice(bytes).map_err(|e| format!("line {} column {}: {e}", e.line(), e.column()))?;
        if raw.schema != SCHEMA {
            return Err(format!("schema {} but this keel-settle reads schema {SCHEMA}; use the keel-tree that wrote it or one of the same schema", raw.schema));
        }
        Plan::checked(raw.repository, raw.base, raw.head, raw.units, Some(raw.digest))
    }

    pub fn read(path: &Path) -> Result<Plan, InputError> {
        let bytes = std::fs::read(path).map_err(|source| InputError::Read { path: path.to_owned(), source })?;
        Plan::from_bytes(&bytes).map_err(|what| InputError::Malformed { path: path.to_owned(), line: 1, what: format!("not a valid plan: {what}"), advice: REGENERATE_PLAN })
    }

    pub fn write(&self, path: &Path) -> Result<(), InputError> {
        // Written beside the target and renamed, so a reader never sees half a plan.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.to_bytes()).map_err(|source| InputError::Write { path: tmp.clone(), source })?;
        std::fs::rename(&tmp, path).map_err(|source| InputError::Write { path: path.to_owned(), source })
    }
}
