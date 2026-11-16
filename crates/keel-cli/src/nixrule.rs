//! Stage 0 rules for Nix and Nickel sources: an edit is junk when what it
//! evaluates to did not change.
//!
//! Nix. A `.nix` file or `flake.lock` that changed is accepted only if every
//! installable the operator listed (`--nix-check`) has the same derivation path
//! at the base commit and at the merge result. A derivation path is a hash of
//! the derivation's whole closure of inputs, so equal paths mean equal builds.
//! The operator's list is a claim about what the edit can affect; the
//! `covers` check below refuses when a node that reads the changed file has a
//! derivation the list does not account for.
//!
//! Nickel. A `.ncl` file that changed is accepted only if regenerating the
//! lockfile (`--nickel-lock`, with `--nickel-cmd`) at the merge result gives
//! exactly the bytes committed at the base. Both rules evaluate trees checked
//! out into private directories (through a private git index), never the
//! caller's working tree.

use std::path::Path;
use std::process::Command;

use crate::git::Git;
use crate::util::TempDir;

/// `nix path-info --derivation <installable>` in `dir`, trimmed.
fn derivation(dir: &Path, installable: &str) -> Result<String, String> {
    let out = Command::new("nix")
        .args(["--extra-experimental-features", "nix-command flakes"])
        .args(["path-info", "--derivation", installable])
        .current_dir(dir)
        .output()
        .map_err(|e| format!("cannot run `nix`: {e}; put nix on PATH or drop --nix-check"))?;
    if !out.status.success() {
        return Err(format!(
            "`nix path-info --derivation {installable}` failed: {}; fix the installable or the evaluation error",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .map(|l| l.trim().to_owned())
        .filter(|l| l.ends_with(".drv"))
        .ok_or_else(|| {
            format!("`nix path-info --derivation {installable}` printed no derivation path")
        })
}

/// What evaluating the listed installables at both revisions found.
pub struct NixComparison {
    /// The base derivation of each installable, to check node coverage against.
    pub base_drvs: Vec<String>,
    /// `Err` names the first installable whose derivation moved.
    pub unchanged: Result<(), String>,
}

pub fn compare_nix(
    git: &Git,
    base: &str,
    merge_tree: &str,
    installables: &[String],
) -> Result<NixComparison, String> {
    let tmp = TempDir::new("nix").map_err(|e| format!("cannot create a temp dir: {e}"))?;
    let (bdir, mdir) = (tmp.path().join("base"), tmp.path().join("merge"));
    git.checkout_tree(base, &bdir).map_err(|e| e.to_string())?;
    git.checkout_tree(merge_tree, &mdir)
        .map_err(|e| e.to_string())?;
    let mut base_drvs = Vec::new();
    let mut unchanged = Ok(());
    for inst in installables {
        let (b, m) = (derivation(&bdir, inst)?, derivation(&mdir, inst)?);
        if b != m && unchanged.is_ok() {
            unchanged = Err(format!("`{inst}` evaluates to {m} where the base has {b}"));
        }
        base_drvs.push(b);
    }
    Ok(NixComparison {
        base_drvs,
        unchanged,
    })
}

/// Splits a command line on whitespace, honouring single and double quotes. No
/// expansion of any kind happens: the command is run directly, not through a shell.
pub fn split_command(s: &str) -> Result<Vec<String>, String> {
    let (mut out, mut cur, mut quote, mut any) = (Vec::new(), String::new(), None, false);
    for c in s.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                any = true;
            }
            (None, c) if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if quote.is_some() {
        return Err(format!("unbalanced quote in --nickel-cmd `{s}`"));
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    if out.is_empty() {
        return Err("--nickel-cmd is empty".into());
    }
    Ok(out)
}

/// Regenerates `lock` at `merge_tree` with `cmd` and compares it with the
/// committed lockfile at `base`.
pub fn nickel_unchanged(
    git: &Git,
    base: &str,
    merge_tree: &str,
    lock: &str,
    cmd: &str,
) -> Result<(), String> {
    let argv = split_command(cmd)?;
    let committed = git
        .blob_at(base, lock)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            format!("--nickel-lock `{lock}` does not exist at the base commit; fix the path")
        })?;
    let tmp = TempDir::new("nickel").map_err(|e| format!("cannot create a temp dir: {e}"))?;
    let dir = tmp.path().join("merge");
    git.checkout_tree(merge_tree, &dir)
        .map_err(|e| e.to_string())?;
    let out = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(&dir)
        .output()
        .map_err(|e| format!("cannot run `{}`: {e}; fix --nickel-cmd", argv[0]))?;
    if !out.status.success() {
        return Err(format!(
            "`{cmd}` failed ({}): {}; fix --nickel-cmd or the Nickel sources",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let regenerated = std::fs::read(dir.join(lock)).map_err(|e| {
        format!("`{cmd}` did not leave {lock} readable ({e}); --nickel-cmd must write the lockfile in place")
    })?;
    if regenerated == committed {
        Ok(())
    } else {
        Err(format!(
            "regenerating {lock} at the merge result differs from the committed base"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_like_a_shell_without_being_one() {
        assert_eq!(
            split_command("a b  'c d' \"e\"").unwrap(),
            ["a", "b", "c d", "e"]
        );
        assert_eq!(split_command("x ''").unwrap(), ["x", ""]);
        assert!(split_command("x 'y").is_err());
        assert!(split_command("   ").is_err());
        assert_eq!(
            split_command("echo $HOME; ls").unwrap(),
            ["echo", "$HOME;", "ls"]
        );
    }
}
