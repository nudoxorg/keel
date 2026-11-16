//! Stage 0 rule: a `Cargo.lock` that resolves to the same packages is junk.
//!
//! What cargo builds from a lockfile is its set of `[[package]]` entries and
//! the resolved dependency edges inside each. The header `version` (the file
//! format), the order of the packages and the order of a `dependencies` list
//! carry no meaning, so a format bump or a reordering alone changes nothing.
//! Anything else in the file (a `[metadata]` table, `[[patch.unused]]`, a
//! field this code does not know) is compared too, so an unfamiliar lockfile
//! can only make the rule refuse.

use std::collections::BTreeMap;

use toml::{Table, Value};

type Key = (String, String, String);

struct Parsed {
    packages: BTreeMap<Key, Table>,
    rest: Table,
}

fn parse(bytes: &[u8]) -> Result<Parsed, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not valid UTF-8".to_owned())?;
    let mut table: Table = text.parse().map_err(|e| format!("not valid TOML: {e}"))?;
    table.remove("version");
    let list = match table.remove("package") {
        Some(Value::Array(a)) => a,
        None => vec![],
        Some(_) => return Err("`package` is not an array of tables".into()),
    };
    let mut packages = BTreeMap::new();
    for p in list {
        let Value::Table(mut t) = p else {
            return Err("a `package` entry is not a table".into());
        };
        let field = |t: &Table, k: &str| t.get(k).and_then(Value::as_str).map(str::to_owned);
        let (Some(name), Some(version)) = (field(&t, "name"), field(&t, "version")) else {
            return Err("a `package` entry has no name or version".into());
        };
        let key = (
            name.clone(),
            version.clone(),
            field(&t, "source").unwrap_or_default(),
        );
        // Order of a dependency list is cargo's sort, not part of the resolution.
        if let Some(Value::Array(deps)) = t.get_mut("dependencies") {
            deps.sort_by_key(|d| d.as_str().unwrap_or_default().to_owned());
        }
        if packages.insert(key, t).is_some() {
            return Err(format!(
                "package {name} {version} appears twice with the same source"
            ));
        }
    }
    Ok(Parsed {
        packages,
        rest: table,
    })
}

/// `Ok(())` iff the two lockfiles resolve identically.
pub fn resolves_identically(old: &[u8], new: &[u8]) -> Result<(), String> {
    let (a, b) = (
        parse(old).map_err(|e| format!("the old lockfile is {e}"))?,
        parse(new).map_err(|e| format!("the new lockfile is {e}"))?,
    );
    for (key, pkg) in &b.packages {
        match a.packages.get(key) {
            None => {
                let siblings: Vec<_> = a
                    .packages
                    .keys()
                    .filter(|k| k.0 == key.0)
                    .map(|k| k.1.as_str())
                    .collect();
                return Err(if siblings.is_empty() {
                    format!("package {} {} is new", key.0, key.1)
                } else {
                    format!(
                        "package {} changed version ({} to {})",
                        key.0,
                        siblings.join(", "),
                        key.1
                    )
                });
            }
            Some(old_pkg) if old_pkg != pkg => {
                return Err(if old_pkg.get("checksum") != pkg.get("checksum") {
                    format!("package {} {} has a different checksum", key.0, key.1)
                } else {
                    format!(
                        "package {} {} resolves different dependencies or fields",
                        key.0, key.1
                    )
                });
            }
            Some(_) => {}
        }
    }
    if let Some(gone) = a.packages.keys().find(|k| !b.packages.contains_key(*k)) {
        return Err(format!("package {} {} was removed", gone.0, gone.1));
    }
    if a.rest != b.rest {
        return Err("a table other than `package` (metadata or patch) differs".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"
version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "serde",
 "zed 1.0.0",
]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "zed"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbb"
"#;

    fn check(new: &str) -> Result<(), String> {
        resolves_identically(LOCK.as_bytes(), new.as_bytes())
    }

    #[test]
    fn header_bump_and_reordering_are_junk() {
        assert_eq!(check(&LOCK.replace("version = 3", "version = 4")), Ok(()));
        // Packages in another order, dependency list reversed.
        let reordered = r#"
version = 3
[[package]]
name = "zed"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbb"
[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["zed 1.0.0", "serde"]
"#;
        assert_eq!(check(reordered), Ok(()));
        assert_eq!(check(&format!("# generated\n{LOCK}\n\n")), Ok(()));
    }

    #[test]
    fn a_version_bump_is_refused() {
        let err = check(&LOCK.replace("1.0.200", "1.0.201")).unwrap_err();
        assert!(
            err.contains("changed version") && err.contains("1.0.201"),
            "{err}"
        );
    }

    #[test]
    fn a_checksum_change_is_refused() {
        let err = check(&LOCK.replace("\"aaaa\"", "\"cccc\"")).unwrap_err();
        assert!(err.contains("checksum"), "{err}");
    }

    #[test]
    fn a_new_package_and_a_removed_one_are_refused() {
        let added = format!("{LOCK}\n[[package]]\nname = \"extra\"\nversion = \"0.0.1\"\n");
        assert!(check(&added).unwrap_err().contains("is new"));
        let removed = LOCK.replace("[[package]]\nname = \"zed\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"bbbb\"\n", "");
        assert!(check(&removed).unwrap_err().contains("removed"));
    }

    #[test]
    fn a_dependency_edge_change_is_refused() {
        let err = check(&LOCK.replace("\"zed 1.0.0\",\n", "")).unwrap_err();
        assert!(err.contains("dependencies"), "{err}");
    }

    #[test]
    fn a_source_change_is_refused_and_junk_input_is_not_trusted() {
        let git = LOCK.replace(
            "registry+https://github.com/rust-lang/crates.io-index",
            "git+https://example.com/x",
        );
        assert!(check(&git).is_err());
        assert!(check("not = [valid").unwrap_err().contains("TOML"));
        assert!(
            check(&format!("{LOCK}\n[metadata]\nx = \"y\"\n"))
                .unwrap_err()
                .contains("metadata")
        );
    }
}
