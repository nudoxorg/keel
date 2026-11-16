//! The environment contract of DESIGN.md §3.4.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::digest::Digest;
use crate::frame::Framer;

/// Names the framework sets itself; a contract cannot override or key them.
/// `PATH` comes from the declared tools (their hashes are in the key), `HOME`
/// and `TMPDIR` are per-test directories.
const RESERVED: [&str; 3] = ["PATH", "HOME", "TMPDIR"];

/// `NEXTEST` and `NEXTEST_*` are set by nextest for its test processes. They
/// vary per run (`NEXTEST_RUN_ID`), which is why they are passed through but
/// never keyed.
fn is_nextest(name: &str) -> bool {
    name == "NEXTEST" || name.starts_with("NEXTEST_")
}

/// What a test process may observe of the environment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvContract {
    /// Names of ambient variables the test may see (`env = [...]`).
    pub allow: Vec<String>,
    /// The profile's `[profile.*.env]` table; always set, and wins over an
    /// ambient value of the same name.
    pub profile_env: BTreeMap<String, String>,
}

fn is_reserved(name: &str) -> bool {
    RESERVED.contains(&name)
}

/// The allow-listed variables that are actually present and not reserved.
fn allowed_present<'a>(
    contract: &'a EnvContract,
    ambient: &'a HashMap<String, String>,
) -> BTreeMap<&'a str, &'a str> {
    contract
        .allow
        .iter()
        .filter(|n| !is_reserved(n))
        .filter_map(|n| ambient.get(n).map(|v| (n.as_str(), v.as_str())))
        .collect()
}

/// The profile entries that survive the reserved-name rule.
fn profile_effective(contract: &EnvContract) -> impl Iterator<Item = (&str, &str)> {
    contract
        .profile_env
        .iter()
        .filter(|(k, _)| !is_reserved(k))
        .map(|(k, v)| (k.as_str(), v.as_str()))
}

/// Digest of the allow-listed names and values present in `ambient`, plus the
/// profile env table.
///
/// An allowed variable that is unset contributes nothing: the process cannot
/// tell it from a variable that was never allowed, so neither should the key.
/// Reserved names (`PATH`, `HOME`, `TMPDIR`) are ignored because
/// [`clean_environment`] overrides them.
pub fn env_key(contract: &EnvContract, ambient: &HashMap<String, String>) -> Digest {
    let mut f = Framer::new("keel/env");
    let allowed = allowed_present(contract, ambient);
    f.field(1, &(allowed.len() as u64).to_le_bytes());
    for (k, v) in allowed {
        f.field(2, k.as_bytes()).field(3, v.as_bytes());
    }
    let profile: Vec<_> = profile_effective(contract).collect();
    f.field(4, &(profile.len() as u64).to_le_bytes());
    for (k, v) in profile {
        f.field(5, k.as_bytes()).field(6, v.as_bytes());
    }
    f.finish()
}

/// Exactly the environment a test process receives.
///
/// In increasing precedence: allow-listed ambient variables, `NEXTEST*`
/// variables, the profile table, then `PATH`, `HOME` and `TMPDIR` set from the
/// arguments. Everything else in `ambient` is dropped, so an undeclared
/// variable is absent rather than silently leaking in.
///
/// `CARGO_*` variables that nextest derives per binary (`CARGO_MANIFEST_DIR`,
/// `CARGO_BIN_EXE_*`) are not in `ambient` and not added here; the caller that
/// builds the command adds them, since they follow from the binary which is
/// already in `code`.
pub fn clean_environment(
    contract: &EnvContract,
    ambient: &HashMap<String, String>,
    tools_path: &str,
    home: &Path,
    tmpdir: &Path,
) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = allowed_present(contract, ambient)
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    env.extend(
        ambient
            .iter()
            .filter(|(k, _)| is_nextest(k))
            .map(|(k, v)| (k.clone(), v.clone())),
    );
    env.extend(profile_effective(contract).map(|(k, v)| (k.to_owned(), v.to_owned())));
    env.insert("PATH".into(), tools_path.to_owned());
    env.insert("HOME".into(), home.to_string_lossy().into_owned());
    env.insert("TMPDIR".into(), tmpdir.to_string_lossy().into_owned());
    env
}

/// The environment of a [`Runner`](crate::Runner): [`clean_environment`]'s,
/// closed all the way. `NEXTEST*` variables are not passed (they vary per run, so
/// they could be neither keyed nor allowed to differ), and the two variables
/// that fix locale and time zone are set to constants, so the process cannot
/// observe the machine's. Everything in the result is part of the runner's key.
pub(crate) fn closed_environment(
    contract: &EnvContract,
    ambient: &HashMap<String, String>,
    tools_path: &str,
    home: &Path,
    tmpdir: &Path,
) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = allowed_present(contract, ambient)
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    // A declared TZ or LANG is the model learning a real input; only the default is fixed.
    env.entry("TZ".into()).or_insert_with(|| "UTC".into());
    env.entry("LANG".into()).or_insert_with(|| "C.UTF-8".into());
    // The model's own table wins over the constants and over ambient values, as before.
    env.extend(profile_effective(contract).map(|(k, v)| (k.to_owned(), v.to_owned())));
    env.insert("PATH".into(), tools_path.to_owned());
    env.insert("HOME".into(), home.to_string_lossy().into_owned());
    env.insert("TMPDIR".into(), tmpdir.to_string_lossy().into_owned());
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ambient() -> HashMap<String, String> {
        [
            ("PATH", "/usr/bin"),
            ("HOME", "/home/me"),
            ("SECRET", "hunter2"),
            ("RUST_LOG", "debug"),
            ("NEXTEST", "1"),
            ("NEXTEST_RUN_ID", "abc"),
            ("MY_NEXTEST_THING", "no"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }

    fn contract() -> EnvContract {
        EnvContract {
            allow: vec!["RUST_LOG".into(), "UNSET_VAR".into()],
            profile_env: [("FIXED".to_owned(), "1".to_owned())].into(),
        }
    }

    #[test]
    fn test_process_sees_only_the_contract() {
        let env = clean_environment(
            &contract(),
            &ambient(),
            "/tools/bin",
            Path::new("/t/home"),
            Path::new("/t/tmp"),
        );
        let expected: BTreeMap<String, String> = [
            ("FIXED", "1"),
            ("HOME", "/t/home"),
            ("NEXTEST", "1"),
            ("NEXTEST_RUN_ID", "abc"),
            ("PATH", "/tools/bin"),
            ("RUST_LOG", "debug"),
            ("TMPDIR", "/t/tmp"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        assert_eq!(env, expected);
    }

    #[test]
    fn profile_wins_over_ambient_but_not_over_reserved() {
        let mut c = contract();
        c.profile_env.insert("RUST_LOG".into(), "trace".into());
        c.profile_env.insert("HOME".into(), "/evil".into());
        c.allow.push("HOME".into());
        let env = clean_environment(&c, &ambient(), "/p", Path::new("/h"), Path::new("/t"));
        assert_eq!(env["RUST_LOG"], "trace");
        assert_eq!(env["HOME"], "/h");
    }

    #[test]
    fn key_covers_allowed_values_and_profile_only() {
        let base = env_key(&contract(), &ambient());
        let mut a = ambient();
        a.insert("SECRET".into(), "changed".into());
        a.insert("NEXTEST_RUN_ID".into(), "another".into());
        a.insert("PATH".into(), "/elsewhere".into());
        assert_eq!(
            base,
            env_key(&contract(), &a),
            "undeclared, nextest and reserved vars are not keyed"
        );

        a.insert("RUST_LOG".into(), "info".into());
        assert_ne!(base, env_key(&contract(), &a));

        let mut c = contract();
        c.profile_env.insert("FIXED".into(), "2".into());
        assert_ne!(base, env_key(&c, &ambient()));
    }

    #[test]
    fn an_unset_allowed_variable_is_not_keyed_but_a_set_one_is() {
        let mut c = contract();
        let without = env_key(&c, &ambient());
        c.allow.push("ANOTHER_UNSET".into());
        assert_eq!(without, env_key(&c, &ambient()));
        let mut a = ambient();
        a.insert("ANOTHER_UNSET".into(), String::new());
        assert_ne!(without, env_key(&c, &a));
    }

    #[test]
    fn name_and_value_boundaries_cannot_shift() {
        let c = EnvContract {
            allow: vec!["AB".into(), "C".into()],
            ..EnvContract::default()
        };
        let c2 = EnvContract {
            allow: vec!["A".into(), "BC".into()],
            ..EnvContract::default()
        };
        let a1: HashMap<_, _> = [
            ("AB".to_owned(), "x".to_owned()),
            ("C".to_owned(), "y".to_owned()),
        ]
        .into();
        let a2: HashMap<_, _> = [
            ("A".to_owned(), "Bx".to_owned()),
            ("BC".to_owned(), "y".to_owned()),
        ]
        .into();
        assert_ne!(env_key(&c, &a1), env_key(&c2, &a2));
    }

    #[test]
    fn allow_list_order_and_duplicates_do_not_matter() {
        let a = EnvContract {
            allow: vec!["A".into(), "B".into(), "A".into()],
            ..EnvContract::default()
        };
        let b = EnvContract {
            allow: vec!["B".into(), "A".into()],
            ..EnvContract::default()
        };
        let amb: HashMap<_, _> = [
            ("A".to_owned(), "1".to_owned()),
            ("B".to_owned(), "2".to_owned()),
        ]
        .into();
        assert_eq!(env_key(&a, &amb), env_key(&b, &amb));
    }
}
