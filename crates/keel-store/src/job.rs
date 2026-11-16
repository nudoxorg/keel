//! What a job unit may be told, and how to read how it ended.
//!
//! The `keel-{fetch,build,test,audit}@<job>` units (and their `keel-canon-` twins) are fixed systemd templates whose
//! only variable inputs are the instance name and the env file the conductor
//! writes. Both are checked again inside the unit (`validate-job` in
//! `ExecStartPre`), so a bug in the conductor, or anything that can write
//! into the jobs directory, cannot smuggle a path, a flag or a shell word into
//! a job. The checks are by hand, no regex crate: the shapes are tiny.

use serde::{Deserialize, Serialize};

/// Why a name or an env file was refused. The message says what is allowed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct JobError(String);

fn refuse<T>(msg: impl Into<String>) -> Result<T, JobError> {
    Err(JobError(msg.into()))
}

/// `^[a-z0-9][a-z0-9._-]{0,63}$` and no `..`. Checked on `%i`, the escaped
/// instance string: `%I` would turn `-` into `/` and could name a path.
pub fn validate_name(name: &str) -> Result<(), JobError> {
    let ok = (1..=64).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
        && !name.contains("..");
    if ok {
        Ok(())
    } else {
        refuse(format!(
            "job name `{name}` is not allowed; a job name is 1 to 64 characters of lowercase letters, digits, `.`, `_` and `-`, starts with a letter or digit and has no `..`, for example `backend-pr-132-a1b2c3d`"
        ))
    }
}

/// The part of a unit instance name that stands for a repo: the repo name
/// lowercased with `/` turned into `-` (`Nudox/Backend` is `nudox-backend`).
/// The module computes the same with `lib.toLower` and `replaceStrings`.
pub fn repo_slug(repo: &str) -> String {
    repo.to_ascii_lowercase().replace('/', "-")
}

/// Which trust domain an instance belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstanceKind {
    /// `<slug>-pr-slot<N>`, run as keel-build.
    Pr,
    /// `<slug>-canon`, run as keel-canon.
    Canon,
}

/// Validates a unit instance name, which names a **slot**, not a job:
/// `<repo slug>-pr-slot<N>` (N below `slots`, no leading zeros) for
/// [`InstanceKind::Pr`] or `<repo slug>-canon` for [`InstanceKind::Canon`],
/// with the slug taken from the allow-list. Checked on `%i`, never `%I`.
pub fn validate_instance(
    name: &str,
    kind: InstanceKind,
    slugs: &[String],
    slots: u32,
) -> Result<(), JobError> {
    validate_name(name)?;
    let bad = |why: &str| {
        refuse(format!(
            "instance name `{name}` is not allowed: {why}; instances look like `<repo>-pr-slot<N>` (N below {slots}) for PR jobs or `<repo>-canon` for canonical jobs, with <repo> one of {slugs:?}"
        ))
    };
    let slug = match kind {
        InstanceKind::Canon => name.strip_suffix("-canon"),
        InstanceKind::Pr => match name.rsplit_once("-pr-slot") {
            Some((slug, n))
                if !n.is_empty()
                    && n.bytes().all(|b| b.is_ascii_digit())
                    && (n == "0" || !n.starts_with('0'))
                    && n.parse::<u32>().is_ok_and(|n| n < slots) =>
            {
                Some(slug)
            }
            _ => None,
        },
    };
    match slug {
        Some(s) if slugs.iter().any(|a| a == s) => Ok(()),
        Some(_) => bad("the repo part is not on the allow-list"),
        None => bad("it is not of the required shape"),
    }
}

const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";

/// An absolute store path: `/nix/store/<32 base-32 chars>-<name>[/component]*`,
/// no `.`/`..` components. The conductor picks it; nothing from the forge does.
pub fn validate_program(v: &str) -> Result<(), JobError> {
    let bad = || {
        refuse(format!(
            "KEEL_PROGRAM=`{v}` is not allowed; it must be a Nix store path chosen by the conductor, like /nix/store/<32 chars>-cargo-1.97.1/bin/cargo, with letters, digits and `._+-` only"
        ))
    };
    let Some(rest) = v.strip_prefix("/nix/store/") else {
        return bad();
    };
    let mut parts = rest.split('/');
    let first = parts.next().unwrap_or("");
    let hash_ok = first.len() > 33
        && first.is_char_boundary(32)
        && first[..32].chars().all(|c| NIX32.contains(c))
        && first.as_bytes()[32] == b'-';
    let comp = |c: &str| {
        !c.is_empty()
            && c != "."
            && c != ".."
            && c.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
    };
    if hash_ok && comp(&first[33..]) && parts.all(comp) {
        Ok(())
    } else {
        bad()
    }
}

/// 1 to 16 words separated by single spaces; each word is 1 to 128 characters
/// of `[A-Za-z0-9._/-]`, starts with a letter or digit (so it can never be a
/// flag) and has no `..`. These are the shapes of the job id, a repo name from
/// the conductor's allow-list, a 40-hex revision and a slot number.
pub fn validate_args(v: &str) -> Result<(), JobError> {
    let words: Vec<&str> = v.split(' ').collect();
    let ok = (1..=16).contains(&words.len())
        && words.iter().all(|w| {
            (1..=128).contains(&w.len())
                && w.starts_with(|c: char| c.is_ascii_alphanumeric())
                && w.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
                && !w.contains("..")
        });
    if ok {
        Ok(())
    } else {
        refuse(format!(
            "KEEL_ARGS=`{v}` is not allowed; it must be 1 to 16 words separated by single spaces, each of letters, digits and `._/-`, starting with a letter or digit (a job id, a repo from the allow-list, a 40-hex revision, a slot number); branch names, titles and commit messages never belong here"
        ))
    }
}

/// Checks an env file the conductor wrote: only `KEEL_PROGRAM` and
/// `KEEL_ARGS`, each exactly once, each with a value of its shape. Blank lines
/// and `#` comments are allowed; a value may sit in one pair of double quotes,
/// as systemd allows.
pub fn validate_env_file(text: &str) -> Result<(), JobError> {
    let (mut program, mut args) = (false, false);
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return refuse(format!(
                "env file line {}: `{line}` is not KEY=value; the file may hold only KEEL_PROGRAM and KEEL_ARGS",
                n + 1
            ));
        };
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        let seen = match key {
            "KEEL_PROGRAM" => &mut program,
            "KEEL_ARGS" => &mut args,
            _ => {
                return refuse(format!(
                    "env file line {}: key `{key}` is not allowed; the file may hold only KEEL_PROGRAM and KEEL_ARGS",
                    n + 1
                ));
            }
        };
        if std::mem::replace(seen, true) {
            return refuse(format!("env file line {}: `{key}` is set twice", n + 1));
        }
        if key == "KEEL_PROGRAM" {
            validate_program(value)?;
        } else {
            validate_args(value)?;
        }
    }
    if program && args {
        Ok(())
    } else {
        refuse(
            "env file must set both KEEL_PROGRAM and KEEL_ARGS; the conductor writes them before starting the job",
        )
    }
}

/// Whether `unit` is a job unit name this crate may ask systemd about:
/// `keel-[canon-]{fetch,build,test,audit}@<valid job name>.service`.
pub fn validate_unit(unit: &str) -> Result<(), JobError> {
    let rest = unit
        .strip_prefix("keel-")
        .map(|r| r.strip_prefix("canon-").unwrap_or(r));
    let parsed = rest.and_then(|r| r.split_once('@'));
    let phase_ok = |p: &str| matches!(p, "fetch" | "build" | "test" | "audit");
    match parsed.and_then(|(p, i)| Some((p, i.strip_suffix(".service")?))) {
        Some((p, name)) if phase_ok(p) && validate_name(name).is_ok() => Ok(()),
        _ => refuse(format!(
            "`{unit}` is not a job unit; expected keel-[canon-]{{fetch,build,test,audit}}@<job>.service with a valid job name"
        )),
    }
}

/// How a job unit ended, as systemd reports it. The job user cannot write any
/// of this: it comes from `systemctl show`, never from a file in the job's
/// output directory.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Outcome {
    /// `ActiveState`: `active`, `activating`, `inactive`, `failed`, ...
    pub active_state: String,
    /// `Result`: `success`, `exit-code`, `signal`, `timeout`, ...
    pub result: String,
    /// `ExecMainCode`: 1 exited, 2 killed, 3 dumped (siginfo `CLD_*`), 0 never ran.
    pub exec_main_code: i32,
    /// `ExecMainStatus`: the exit status, or the signal number when killed.
    pub exec_main_status: i32,
}

/// The properties asked of `systemctl show`. `ActiveState` is on top of the
/// three the outcome is judged by so a caller can tell "not finished yet".
pub const SHOW_PROPERTIES: &str = "ActiveState,Result,ExecMainCode,ExecMainStatus";

/// Parses `systemctl show --property=… <unit>` text (`Key=value` lines).
pub fn parse_show(text: &str) -> Result<Outcome, JobError> {
    let get = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
            .ok_or_else(|| {
                JobError(format!(
                    "`systemctl show` output has no {key}; run it with --property={SHOW_PROPERTIES}"
                ))
            })
    };
    let num = |key: &str| {
        get(key)?
            .trim()
            .parse::<i32>()
            .map_err(|e| JobError(format!("`systemctl show` gave a non-numeric {key}: {e}")))
    };
    Ok(Outcome {
        active_state: get("ActiveState")?.trim().to_owned(),
        result: get("Result")?.trim().to_owned(),
        exec_main_code: num("ExecMainCode")?,
        exec_main_status: num("ExecMainStatus")?,
    })
}

/// Asks systemd how `unit` (for example `keel-build@job-1.service`) ended.
/// Runs `systemctl show` without a shell; the unit name is validated first.
pub fn job_outcome(unit: &str) -> Result<Outcome, JobError> {
    validate_unit(unit)?;
    let out = std::process::Command::new("systemctl")
        .args(["show", &format!("--property={SHOW_PROPERTIES}"), "--", unit])
        .output()
        .map_err(|e| {
            JobError(format!(
                "cannot run systemctl: {e}; the conductor's unit needs systemd in its PATH"
            ))
        })?;
    if !out.status.success() {
        return refuse(format!(
            "`systemctl show {unit}` failed: {}; check the unit name and that systemd is reachable",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    parse_show(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROG: &str = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-cargo-1.97.1/bin/cargo";

    #[test]
    fn names_follow_the_documented_shape() {
        for ok in [
            "smoke",
            "backend-pr-132-a1b2c3d",
            "0",
            "a.b_c-d",
            &"a".repeat(64),
        ] {
            assert_eq!(validate_name(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "Smoke",
            "-x",
            ".x",
            "a..b",
            "a/b",
            "a b",
            "a\\x2db",
            &"a".repeat(65),
            "é",
        ] {
            let e = validate_name(bad).unwrap_err().to_string();
            assert!(e.contains("lowercase letters, digits"), "{bad}: {e}");
        }
    }

    #[test]
    fn instances_name_slots_of_allow_listed_repos() {
        let slugs = vec!["nudox-backend".to_owned(), "nudox-other".to_owned()];
        assert_eq!(repo_slug("Nudox/Backend"), "nudox-backend");
        let pr = |n: &str| validate_instance(n, InstanceKind::Pr, &slugs, 3);
        let canon = |n: &str| validate_instance(n, InstanceKind::Canon, &slugs, 3);
        for ok in ["nudox-backend-pr-slot0", "nudox-other-pr-slot2"] {
            assert_eq!(pr(ok), Ok(()), "{ok}");
        }
        for bad in [
            "nudox-backend-pr-slot3",
            "nudox-backend-pr-slot",
            "nudox-backend-pr-slot01",
            "nudox-backend-pr-slot-1",
            "evil-pr-slot0",
            "nudox-backend-canon",
            "nudox-backend-pr-slot0x",
            "-pr-slot0",
            "Nudox-Backend-pr-slot0",
        ] {
            assert!(pr(bad).is_err(), "{bad}");
        }
        assert_eq!(canon("nudox-backend-canon"), Ok(()));
        for bad in [
            "nudox-backend-pr-slot0",
            "evil-canon",
            "-canon",
            "nudox-backend-canon-x",
        ] {
            assert!(canon(bad).is_err(), "{bad}");
        }
        let e = pr("evil-pr-slot0").unwrap_err().to_string();
        assert!(
            e.contains("allow-list") && e.contains("nudox-backend"),
            "{e}"
        );
    }

    #[test]
    fn env_files_accept_only_the_two_keys_with_their_shapes() {
        let good = format!(
            "# written by the conductor\nKEEL_PROGRAM={PROG}\nKEEL_ARGS=\"run job-1 Nudox/Backend {} 2\"\n",
            "a".repeat(40)
        );
        assert_eq!(validate_env_file(&good), Ok(()));
        for (bad, why) in [
            ("KEEL_PROGRAM=/bin/sh\nKEEL_ARGS=run\n", "KEEL_PROGRAM"),
            (
                "KEEL_PROGRAM=/nix/store/short-x/bin/y\nKEEL_ARGS=run\n",
                "KEEL_PROGRAM",
            ),
            (
                &format!("KEEL_PROGRAM={PROG}/../x\nKEEL_ARGS=run\n"),
                "KEEL_PROGRAM",
            ),
            (
                &format!("KEEL_PROGRAM={PROG}\nKEEL_ARGS=--config x\n"),
                "KEEL_ARGS",
            ),
            (
                &format!("KEEL_PROGRAM={PROG}\nKEEL_ARGS=run;rm\n"),
                "KEEL_ARGS",
            ),
            (
                &format!("KEEL_PROGRAM={PROG}\nKEEL_ARGS=a  b\n"),
                "KEEL_ARGS",
            ),
            (
                &format!("KEEL_PROGRAM={PROG}\nKEEL_ARGS=../x\n"),
                "KEEL_ARGS",
            ),
            (
                &format!("KEEL_PROGRAM={PROG}\nKEEL_ARGS=run\nPATH=/x\n"),
                "PATH",
            ),
            (
                &format!("KEEL_PROGRAM={PROG}\nKEEL_ARGS=run\nKEEL_ARGS=x\n"),
                "twice",
            ),
            (&format!("KEEL_PROGRAM={PROG}\n"), "both"),
            ("garbage\n", "KEY=value"),
        ] {
            let e = validate_env_file(bad).unwrap_err().to_string();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
    }

    /// Recorded from `systemctl show --property=ActiveState,Result,ExecMainCode,ExecMainStatus`.
    const SHOW_OK: &str =
        "Result=success\nExecMainCode=1\nExecMainStatus=0\nActiveState=inactive\n";
    const SHOW_TIMEOUT: &str =
        "Result=timeout\nExecMainCode=2\nExecMainStatus=9\nActiveState=failed\n";
    const SHOW_RUNNING: &str =
        "Result=success\nExecMainCode=0\nExecMainStatus=0\nActiveState=activating\n";

    #[test]
    fn systemctl_show_text_becomes_an_outcome() {
        let ok = parse_show(SHOW_OK).unwrap();
        assert_eq!(
            (ok.result.as_str(), ok.exec_main_code, ok.exec_main_status),
            ("success", 1, 0)
        );
        assert_eq!(ok.active_state, "inactive");
        let t = parse_show(SHOW_TIMEOUT).unwrap();
        assert_eq!(
            (t.result.as_str(), t.exec_main_code, t.exec_main_status),
            ("timeout", 2, 9)
        );
        assert_eq!(parse_show(SHOW_RUNNING).unwrap().active_state, "activating");
        // Property order and extra lines do not matter.
        assert!(
            parse_show(
                "Foo=bar\nExecMainStatus=3\nResult=exit-code\nExecMainCode=1\nActiveState=failed\n"
            )
            .is_ok()
        );
        for bad in [
            "",
            "Result=success\n",
            "Result=success\nExecMainCode=x\nExecMainStatus=0\nActiveState=a\n",
        ] {
            let e = parse_show(bad).unwrap_err().to_string();
            assert!(e.contains("systemctl show"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn only_job_units_can_be_asked_about() {
        for ok in [
            "keel-build@job-1.service",
            "keel-fetch@a.service",
            "keel-canon-test@x.y.service",
            "keel-audit@0.service",
        ] {
            assert_eq!(validate_unit(ok), Ok(()), "{ok}");
        }
        for bad in [
            "keel-store.service",
            "sshd.service",
            "keel-build@.service",
            "keel-build@A.service",
            "keel-build@a b.service",
            "keel-canon-canon-build@a.service",
            "keel-build@a",
            "--all",
            "keel-conduct@a.service",
        ] {
            assert!(validate_unit(bad).is_err(), "{bad}");
        }
        assert!(job_outcome("--all").is_err());
    }
}
