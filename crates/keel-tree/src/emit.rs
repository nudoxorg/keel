//! `plan --emit`: the plan artefact of design/ir.md 7.2 and 11, slice 1.
//!
//! Every test the index has for one binary becomes a unit `(binary, name)` expecting
//! `ReuseIfKeyHolds`. It is written only from a resolution that has no errors (K6), a cargo
//! index that is not degraded (K4), and a checkout that is the head being planned: the index
//! reads the working tree, so a plan for any other tree would name tests the head may not have.

use crate::finding::Severity;
use crate::resolve::Resolution;
use crate::testset::TestTable;
use anyhow::{Context, Result, bail};
use keel_settle::{Binary, Disposition, GitOid, Plan, Unit};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

pub struct Request<'a> {
    pub binary: &'a str,
    pub repository: Option<&'a str>,
    pub base: &'a str,
    pub head: &'a str,
    /// Why the cargo index is absent (`Source::GitOnly`), if it is.
    pub no_cargo: Option<&'a str>,
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git").arg("-C").arg(root).args(args).output().with_context(|| format!("cannot run git in {}", root.display()))?;
    if !out.status.success() {
        bail!("`git {}` failed in {}: {}", args.join(" "), root.display(), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn oid(root: &Path, rev: &str, which: &str) -> Result<GitOid> {
    let spec = format!("{rev}^{{commit}}");
    let full = git(root, &["rev-parse", "--verify", "--end-of-options", &spec]).with_context(|| format!("--{which} {rev:?} is not a commit of {}; pass a revision that exists there", root.display()))?;
    GitOid::new(&full).map_err(anyhow::Error::msg)
}

pub fn build(res: &Resolution<'_>, table: &TestTable, root: &Path, req: &Request<'_>) -> Result<Plan> {
    let binary = Binary::parse(req.binary).map_err(anyhow::Error::msg)?;

    // K6: a plan is not written from a resolution with errors.
    let errors: Vec<_> = res.findings.iter().filter(|f| f.severity == Severity::Error).collect();
    if !errors.is_empty() {
        let shown: Vec<String> = errors.iter().take(5).map(|f| format!("  {} {}{}", f.code, f.node.as_deref().map(|n| format!("[{n}] ")).unwrap_or_default(), f.message)).collect();
        bail!(
            "the resolver found {} error(s), so no plan is written (a plan from a broken resolution would look complete). First {}:\n{}\nRun `keel-tree check` and fix them.",
            errors.len(),
            shown.len(),
            shown.join("\n")
        );
    }
    // K4: a degraded index lists only what git alone can see.
    if let Some(why) = req.no_cargo {
        bail!("the cargo index is not available ({why}), so the tests of a binary are not known. Make `cargo metadata` work in {} and rerun.", root.display());
    }
    if let Some(note) = &res.index.graph_note {
        bail!("the cargo index is degraded ({note}); no plan is written from it. Fix `cargo metadata` and rerun.");
    }
    if let Some(why) = res.tracked_error() {
        bail!("the tracked file list could not be read ({why}); no plan is written without it.");
    }
    let unreadable: Vec<_> = crate::source::unreadable(res.index);
    if !unreadable.is_empty() {
        let shown: Vec<String> = unreadable.iter().take(3).map(|(p, e)| format!("{p} ({e})")).collect();
        bail!("{} tracked Rust file(s) could not be read, so their tests may be missing: {}. Fix that and rerun.", unreadable.len(), shown.join(", "));
    }

    let head = oid(root, req.head, "head")?;
    let base = oid(root, req.base, "base")?;
    let checked_out = git(root, &["rev-parse", "HEAD"])?;
    if checked_out != head.as_str() {
        bail!(
            "the index reads the checkout, which is at {checked_out}, but --head is {}. Check out the head commit in {} (or point --root at a checkout of it) and rerun.",
            head.as_str(),
            root.display()
        );
    }
    if !git(root, &["status", "--porcelain", "--untracked-files=no"])?.is_empty() {
        bail!("{} has uncommitted changes to tracked files, so the index is not the head commit's. Commit or stash them and rerun.", root.display());
    }

    let mut names = BTreeSet::new();
    let mut known: BTreeSet<String> = BTreeSet::new();
    for id in &table.ids {
        let Some((b, name)) = id.split_once('$') else { continue };
        known.insert(b.to_owned());
        if Binary::parse(b).is_ok_and(|p| p == binary) {
            // Two index items with one name are two cfg branches of one test; a binary lists a name once.
            names.insert(name.to_owned());
        }
    }
    if names.is_empty() {
        let some: Vec<&str> = known.iter().take(8).map(String::as_str).collect();
        bail!("the index has no tests for binary {binary}. Binaries it knows include: {}. Pass one as --binary <package>[::<target>].", some.join(", "));
    }
    let repository = match req.repository {
        Some(r) => r.to_owned(),
        None => {
            let top = git(root, &["rev-parse", "--show-toplevel"])?;
            Path::new(&top).file_name().map(|n| n.to_string_lossy().into_owned()).context("the repository has no directory name; pass --repository")?
        }
    };
    let units = names.into_iter().map(|n| Unit::test(binary.clone(), n, Disposition::ReuseIfKeyHolds)).collect();
    Plan::new(repository, base, head, units).map_err(anyhow::Error::msg)
}
