//! Signed attestations (AMBITION 8): evidence that commit X had node set N
//! green under policy P, checkable offline by a deploy job.
//!
//! The signature covers the canonical JSON of every field but itself, and
//! the attestation carries the digest of the canonical report, so changing a
//! node's status, a policy name, a revision or a single byte of the report
//! breaks a named check.

use std::fmt;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use keel::{Digest, Manifest, NodeId, Report, Upstream, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::util::rfc3339;

/// The attestation document's schema.
pub const ATTESTATION_SCHEMA: u32 = 1;

/// The policy a report was judged against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    /// `name` from the policy file.
    pub name: String,
    /// blake3 of the policy file's bytes.
    pub digest: Digest,
}

/// The signed document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    /// [`ATTESTATION_SCHEMA`].
    pub schema: u32,
    /// blake3 of the report's canonical JSON.
    pub report_digest: Digest,
    /// The certified revision.
    pub revision: String,
    /// The repository.
    pub repo: String,
    /// The policy.
    pub policy: PolicyRef,
    /// Nodes that were `pass` or `cached`.
    pub nodes_green: u64,
    /// The report's roots; empty for a passing run.
    pub roots: Vec<NodeId>,
    /// Derived from the report's nodes, never copied from its header.
    pub verdict: Verdict,
    /// RFC 3339 UTC.
    pub issued_at: String,
    /// The verifying key, base64 of its 32 bytes.
    pub public_key: String,
    /// Base64 of the 64-byte Ed25519 signature over [`signed_bytes`].
    pub signature: String,
}

/// The policy file: a name and the nodes or groups that must be green.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Shown in the attestation and checked by `verify --require-policy`.
    pub name: String,
    /// Node ids (`go:dev.example/m/api`) or groups (`unit(go:...)`).
    pub require: Vec<String>,
}

/// JSON with object keys sorted and no whitespace. Written out here rather
/// than trusting `serde_json`'s map order, which a feature flag anywhere in
/// the dependency graph can change.
pub fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let body: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), canonical(&m[k])))
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => other.to_string(),
    }
}

/// What the signature covers: the attestation without `signature`.
pub fn signed_bytes(att: &Value) -> Vec<u8> {
    let mut v = att.clone();
    if let Some(m) = v.as_object_mut() {
        m.remove("signature");
    }
    canonical(&v).into_bytes()
}

fn report_digest(report_value: &Value) -> Digest {
    Digest::of(canonical(report_value).as_bytes())
}

fn b64_32(text: &str, what: &str, path: &Path) -> Result<[u8; 32]> {
    STANDARD
        .decode(text.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| {
            anyhow!(
                "{what} in {} is not base64 of 32 bytes; generate one with `keel-conduct keygen`",
                path.display()
            )
        })
}

/// Reads a secret key file: base64 of the 32-byte seed.
pub fn read_secret_key(path: &Path) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "cannot read the secret key {}; pass --key <file>",
            path.display()
        )
    })?;
    Ok(SigningKey::from_bytes(&b64_32(
        &text,
        "the secret key",
        path,
    )?))
}

/// Reads a public key file: base64 of the 32-byte key.
pub fn read_public_key(path: &Path) -> Result<VerifyingKey> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "cannot read the public key {}; pass --public-key <file>",
            path.display()
        )
    })?;
    VerifyingKey::from_bytes(&b64_32(&text, "the public key", path)?).map_err(|e| {
        anyhow!(
            "the public key in {} is not a valid Ed25519 key ({e}); regenerate it",
            path.display()
        )
    })
}

/// Writes a fresh key pair; the secret file is owner-only.
pub fn keygen(secret: &Path, public: &Path) -> Result<()> {
    use std::io::Write;
    let seed: [u8; 32] = rand::random();
    let sk = SigningKey::from_bytes(&seed);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(secret).with_context(|| {
        format!(
            "cannot create {}; it must not exist yet (refusing to overwrite a key)",
            secret.display()
        )
    })?;
    writeln!(f, "{}", STANDARD.encode(seed))?;
    std::fs::write(
        public,
        format!("{}\n", STANDARD.encode(sk.verifying_key().to_bytes())),
    )
    .with_context(|| format!("cannot write {}", public.display()))?;
    Ok(())
}

fn load_report(path: &Path) -> Result<(Report, Value)> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "cannot read the report {}; pass --report <report.json>",
            path.display()
        )
    })?;
    let value: Value = serde_json::from_str(&text).with_context(|| {
        format!(
            "{} is not JSON; it must be a keel run report",
            path.display()
        )
    })?;
    let report: Report = serde_json::from_value(value.clone())
        .with_context(|| format!("{} is not a keel run report (DESIGN §8.2)", path.display()))?;
    Ok((report, value))
}

/// The report's verdict and roots as its nodes say, not as its header does.
fn rederive(report: &Report) -> Report {
    let mut r = report.clone();
    r.derive();
    r
}

/// Judges `report` against `policy`; returns one line per unmet requirement.
fn unmet(policy: &Policy, report: &Report, manifest: Option<&Manifest>) -> Result<Vec<String>> {
    let status_of = |id: &NodeId| report.nodes.iter().find(|r| r.id == *id).map(|r| r.status);
    let mut problems = Vec::new();
    let judge = |id: &NodeId, via: Option<&str>| -> Option<String> {
        let how = via.map(|g| format!(" (member of {g})")).unwrap_or_default();
        match status_of(id) {
            None => Some(format!(
                "{id}{how} is missing from the report; it was not run, so nothing is known about it"
            )),
            Some(s) if !s.gates_as_pass() => Some(format!(
                "{id}{how} is {}, not pass or cached",
                format!("{s:?}").to_lowercase()
            )),
            Some(_) => None,
        }
    };
    for entry in &policy.require {
        match entry
            .parse::<Upstream>()
            .map_err(|e| anyhow!("policy `{}`: {e}", policy.name))?
        {
            Upstream::Node(id) => problems.extend(judge(&id, None)),
            Upstream::Group(g) => {
                let m = manifest.ok_or_else(|| {
                    anyhow!("policy `{}` requires group {g}, and a report does not record groups; pass --manifest <manifest.json> written by `keel-conduct run --manifest-out`", policy.name)
                })?;
                if m.revision != report.revision || m.repo != report.repo {
                    bail!(
                        "the manifest is for {} at {} but the report is for {} at {}; use the manifest of the same run",
                        m.repo,
                        m.revision,
                        report.repo,
                        report.revision
                    );
                }
                let members: Vec<&NodeId> = m
                    .nodes
                    .iter()
                    .filter(|n| n.group == g)
                    .map(|n| &n.id)
                    .collect();
                if members.is_empty() {
                    problems.push(format!("group {g} has no members in the manifest; the policy names something that does not exist"));
                }
                for id in members {
                    problems.extend(judge(id, Some(&g.to_string())));
                }
            }
        }
    }
    Ok(problems)
}

/// Inputs of [`attest`].
pub struct AttestArgs<'a> {
    /// `report.json`.
    pub report: &'a Path,
    /// Secret key file.
    pub key: &'a Path,
    /// Policy file.
    pub policy: &'a Path,
    /// `run --manifest-out` file, needed when the policy names groups.
    pub manifest: Option<&'a Path>,
}

/// Builds and signs the attestation; refuses when the policy does not hold.
pub fn attest(args: &AttestArgs<'_>) -> Result<Attestation> {
    let (report, value) = load_report(args.report)?;
    let derived = rederive(&report);
    if derived.verdict != report.verdict
        || derived.roots != report.roots
        || derived.counts != report.counts
    {
        bail!(
            "the report {} states verdict {:?} with {} roots, but its own nodes give {:?} with {}; it was edited or produced by a broken runner, so it cannot be attested (rerun the conductor)",
            args.report.display(),
            report.verdict,
            report.roots.len(),
            derived.verdict,
            derived.roots.len()
        );
    }
    let policy_bytes = std::fs::read(args.policy).with_context(|| {
        format!(
            "cannot read the policy {}; pass --policy <policy.toml>",
            args.policy.display()
        )
    })?;
    let policy: Policy =
        toml::from_str(&String::from_utf8_lossy(&policy_bytes)).with_context(|| {
            format!(
                "{} is not a policy; it needs `name` and `require = [node ids or groups]`",
                args.policy.display()
            )
        })?;
    let manifest: Option<Manifest> = args
        .manifest
        .map(|p| {
            serde_json::from_slice(
                &std::fs::read(p)
                    .with_context(|| format!("cannot read the manifest {}", p.display()))?,
            )
            .with_context(|| format!("{} is not a keel manifest", p.display()))
        })
        .transpose()?;
    let problems = unmet(&policy, &report, manifest.as_ref())?;
    if !problems.is_empty() {
        bail!(
            "policy `{}` does not hold for {} at {}; refusing to sign:\n  - {}\nfix or rerun these nodes, or relax the policy on purpose",
            policy.name,
            report.repo,
            report.revision,
            problems.join("\n  - ")
        );
    }
    let key = read_secret_key(args.key)?;
    let mut att = Attestation {
        schema: ATTESTATION_SCHEMA,
        report_digest: report_digest(&value),
        revision: report.revision.clone(),
        repo: report.repo.clone(),
        policy: PolicyRef {
            name: policy.name,
            digest: Digest::of(&policy_bytes),
        },
        nodes_green: report
            .nodes
            .iter()
            .filter(|r| r.status.gates_as_pass())
            .count() as u64,
        roots: derived.roots,
        verdict: derived.verdict,
        issued_at: rfc3339(std::time::SystemTime::now()),
        public_key: STANDARD.encode(key.verifying_key().to_bytes()),
        signature: String::new(),
    };
    let as_value = serde_json::to_value(&att)?;
    att.signature = STANDARD.encode(key.sign(&signed_bytes(&as_value)).to_bytes());
    Ok(att)
}

/// Which check of [`verify`] failed, and why.
#[derive(Debug)]
pub struct VerifyFailure {
    /// `signature`, `report-digest`, `report`, `verdict`, `policy`, `revision`.
    pub check: &'static str,
    /// What is wrong and what to do.
    pub message: String,
}

impl fmt::Display for VerifyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "verify failed at check `{}`: {}",
            self.check, self.message
        )
    }
}

impl std::error::Error for VerifyFailure {}

fn fail<T>(check: &'static str, message: impl Into<String>) -> Result<T, VerifyFailure> {
    Err(VerifyFailure {
        check,
        message: message.into(),
    })
}

/// Inputs of [`verify`].
pub struct VerifyArgs<'a> {
    /// The attestation file.
    pub attestation: &'a Path,
    /// The report it attests.
    pub report: &'a Path,
    /// The trusted public key file.
    pub public_key: &'a Path,
    /// The policy name the deploy requires.
    pub require_policy: &'a str,
    /// The revision being deployed, if the caller knows it.
    pub revision: Option<&'a str>,
    /// The policy file, to check its digest.
    pub policy: Option<&'a Path>,
}

/// Checks an attestation offline. Everything is read from the three files.
pub fn verify(args: &VerifyArgs<'_>) -> Result<Attestation, VerifyFailure> {
    let setup = |e: anyhow::Error| VerifyFailure {
        check: "input",
        message: format!("{e:#}"),
    };
    let trusted = read_public_key(args.public_key).map_err(setup)?;
    let text = std::fs::read_to_string(args.attestation)
        .with_context(|| format!("cannot read the attestation {}", args.attestation.display()))
        .map_err(setup)?;
    let raw: Value = serde_json::from_str(&text).map_err(|e| VerifyFailure {
        check: "signature",
        message: format!(
            "{} is not JSON ({e}); the attestation is damaged",
            args.attestation.display()
        ),
    })?;
    let att: Attestation = serde_json::from_value(raw.clone()).map_err(|e| VerifyFailure {
        check: "signature",
        message: format!(
            "{} is not an attestation ({e}); regenerate it with `keel-conduct attest`",
            args.attestation.display()
        ),
    })?;
    if att.schema != ATTESTATION_SCHEMA {
        return fail(
            "signature",
            format!(
                "attestation schema {} is not {ATTESTATION_SCHEMA}; this verifier is too old or too new for it",
                att.schema
            ),
        );
    }

    // 1. The signature, under the key the deploy trusts, not the one the
    //    document names about itself.
    let sig = STANDARD
        .decode(&att.signature)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .map(|b| Signature::from_bytes(&b));
    let ok = sig.is_some_and(|s| trusted.verify(&signed_bytes(&raw), &s).is_ok());
    if !ok {
        let who = if att.public_key == STANDARD.encode(trusted.to_bytes()) {
            "the attestation names the trusted key, so its content was changed after signing"
        } else {
            "the attestation was signed by a different key than the trusted one"
        };
        return fail(
            "signature",
            format!(
                "the Ed25519 signature does not verify under {}: {who}; do not deploy on this attestation",
                args.public_key.display()
            ),
        );
    }

    // 2. The report is the one that was attested.
    let (report, report_value) = load_report(args.report).map_err(setup)?;
    let digest = report_digest(&report_value);
    if digest != att.report_digest {
        return fail(
            "report-digest",
            format!(
                "{} hashes to {digest} but the attestation covers {}; the report was changed after it was attested, or it is another run's report",
                args.report.display(),
                att.report_digest
            ),
        );
    }
    let derived = rederive(&report);
    let green = report
        .nodes
        .iter()
        .filter(|r| r.status.gates_as_pass())
        .count() as u64;
    if derived.verdict != att.verdict
        || derived.roots != att.roots
        || green != att.nodes_green
        || report.revision != att.revision
        || report.repo != att.repo
    {
        return fail(
            "report",
            "the attestation's verdict, roots, green count, repo or revision disagree with the report it covers; it was signed by a broken attester",
        );
    }

    // 3. The verdict.
    if att.verdict != Verdict::Pass {
        return fail(
            "verdict",
            format!(
                "the attested run did not pass ({} roots: {}); a deploy needs a green run",
                att.roots.len(),
                att.roots
                    .iter()
                    .map(NodeId::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }

    // 4. The policy.
    if att.policy.name != args.require_policy {
        return fail(
            "policy",
            format!(
                "the attestation is for policy `{}`, but this deploy requires `{}`",
                att.policy.name, args.require_policy
            ),
        );
    }
    if let Some(p) = args.policy {
        let bytes = std::fs::read(p).map_err(|e| VerifyFailure {
            check: "policy",
            message: format!("cannot read {}: {e}", p.display()),
        })?;
        if Digest::of(&bytes) != att.policy.digest {
            return fail(
                "policy",
                format!(
                    "{} is not the policy file that was attested (digest differs); the policy was changed since",
                    p.display()
                ),
            );
        }
    }

    // 5. The commit being deployed.
    if let Some(rev) = args.revision
        && rev != att.revision
    {
        return fail(
            "revision",
            format!(
                "the attestation certifies {} but the deploy is of {rev}",
                att.revision
            ),
        );
    }
    Ok(att)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_sorts_keys_at_every_depth() {
        let v: Value = serde_json::from_str(r#"{"b":[{"z":1,"a":2}],"a":"x y","c":null}"#).unwrap();
        assert_eq!(canonical(&v), r#"{"a":"x y","b":[{"a":2,"z":1}],"c":null}"#);
    }

    #[test]
    fn signature_field_is_not_signed() {
        let a: Value = serde_json::from_str(r#"{"k":1,"signature":"AAAA"}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"signature":"BBBB","k":1}"#).unwrap();
        assert_eq!(signed_bytes(&a), signed_bytes(&b));
    }
}
