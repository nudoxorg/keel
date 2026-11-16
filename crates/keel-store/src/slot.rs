//! Preparing a slot's work directory, run as root by the fetch unit.
//!
//! A slot's work directory lives under a root owned by the job user, so the
//! job user controls every entry in it, including the directory entry for
//! the slot itself. Root must never follow what it finds there: a symlink
//! planted as `/ci/keel/work/<slot>` pointing at `/etc` would otherwise turn
//! "remove the contents" or "chown the directory" into damage to the host.
//! Everything below therefore works on file descriptors: the work root and
//! the slot are opened with `O_NOFOLLOW | O_DIRECTORY`, ownership is set with
//! `fchown` on the descriptor, and removal is `unlinkat` relative to it.

use std::ffi::CString;
use std::path::{Path, PathBuf};

use rustix::fd::OwnedFd;
use rustix::fs::{
    AtFlags, Dir, FileType, Gid, Mode, OFlags, Uid, fchmod, fchown, mkdirat, open, openat, statat,
    unlinkat,
};
use rustix::io::Errno;

/// Deepest directory nesting `wipe` will descend before giving up. A tree
/// deeper than this was built to exhaust the stack, not by a compiler.
const MAX_DEPTH: usize = 256;

/// Why a slot could not be prepared. Each names the path and what to do.
#[derive(Debug, thiserror::Error)]
pub enum SlotError {
    /// A path that must be a real directory is not.
    #[error(
        "{path} is not a real directory ({reason}); a job may have replaced it with a link, remove it by hand and investigate the job"
    )]
    NotDir {
        /// The path.
        path: PathBuf,
        /// The OS error.
        reason: String,
    },
    /// Any other filesystem failure.
    #[error("cannot {op} {path}: {reason}")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The path.
        path: PathBuf,
        /// The OS error.
        reason: String,
    },
    /// The user is not in the passwd file.
    #[error("user `{0}` is not in the passwd file; the module creates it, check the --user flag")]
    NoUser(String),
}

/// A uid and gid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ids {
    /// User id.
    pub uid: u32,
    /// Primary group id.
    pub gid: u32,
}

/// Looks `user` up in the text of a passwd file.
pub fn lookup_ids(passwd: &str, user: &str) -> Option<Ids> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == user).then_some(())?;
        let (_pw, uid, gid) = (f.next()?, f.next()?, f.next()?);
        Some(Ids {
            uid: uid.parse().ok()?,
            gid: gid.parse().ok()?,
        })
    })
}

fn io(op: &'static str, path: &Path) -> impl FnOnce(Errno) -> SlotError {
    let path = path.to_path_buf();
    move |e| SlotError::Io {
        op,
        path,
        reason: e.to_string(),
    }
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Opens (creating) the directory `name` inside `parent`, never following a
/// symlink, and gives it to `ids` with mode 0750.
fn ensure_dir(
    parent: &OwnedFd,
    parent_path: &Path,
    name: &str,
    ids: Ids,
) -> Result<OwnedFd, SlotError> {
    let path = parent_path.join(name);
    let fd = match openat(parent, name, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => {
            mkdirat(parent, name, Mode::from_raw_mode(0o750)).map_err(io("create", &path))?;
            openat(parent, name, DIR_FLAGS, Mode::empty()).map_err(io("open", &path))?
        }
        Err(e) => {
            return Err(SlotError::NotDir {
                path,
                reason: e.to_string(),
            });
        }
    };
    fchown(
        &fd,
        Some(Uid::from_raw(ids.uid)),
        Some(Gid::from_raw(ids.gid)),
    )
    .map_err(io("chown", &path))?;
    fchmod(&fd, Mode::from_raw_mode(0o750)).map_err(io("chmod", &path))?;
    Ok(fd)
}

/// Removes everything inside `dir`, without following links or leaving it.
fn wipe(dir: &OwnedFd, path: &Path, depth: usize) -> Result<(), SlotError> {
    if depth > MAX_DEPTH {
        return Err(SlotError::Io {
            op: "wipe",
            path: path.into(),
            reason: format!("nested more than {MAX_DEPTH} directories deep; remove it by hand"),
        });
    }
    let mut names: Vec<CString> = Vec::new();
    for entry in Dir::read_from(dir).map_err(io("list", path))? {
        let name = entry.map_err(io("list", path))?.file_name().to_owned();
        if name.as_bytes() != b"." && name.as_bytes() != b".." {
            names.push(name);
        }
    }
    for name in names {
        let child = path.join(String::from_utf8_lossy(name.as_bytes()).as_ref());
        let st =
            statat(dir, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(io("stat", &child))?;
        if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
            let sub = openat(dir, name.as_c_str(), DIR_FLAGS, Mode::empty())
                .map_err(io("open", &child))?;
            wipe(&sub, &child, depth + 1)?;
            unlinkat(dir, name.as_c_str(), AtFlags::REMOVEDIR).map_err(io("remove", &child))?;
        } else {
            unlinkat(dir, name.as_c_str(), AtFlags::empty()).map_err(io("remove", &child))?;
        }
    }
    Ok(())
}

/// What `prepare` did.
#[derive(Debug, PartialEq, Eq)]
pub struct Prepared {
    /// Whether the slot's contents were removed.
    pub wiped: bool,
}

/// Makes `<work_root>/<instance>` ready for a job: owned by `ids`, mode 0750,
/// with an empty-or-existing `.home`. With `honour_wipe`, a marker
/// `<jobs_dir>/<instance>.wipe` (written by the conductor when the slot is
/// reassigned to another PR) empties the directory first and is removed.
/// `instance` must already be validated.
pub fn prepare(
    work_root: &Path,
    jobs_dir: &Path,
    instance: &str,
    ids: Ids,
    honour_wipe: bool,
) -> Result<Prepared, SlotError> {
    let root = open(work_root, DIR_FLAGS, Mode::empty()).map_err(|e| SlotError::NotDir {
        path: work_root.into(),
        reason: e.to_string(),
    })?;
    let slot_path = work_root.join(instance);
    let slot = ensure_dir(&root, work_root, instance, ids)?;

    let marker = jobs_dir.join(format!("{instance}.wipe"));
    let mut wiped = false;
    if honour_wipe && std::fs::symlink_metadata(&marker).is_ok() {
        wipe(&slot, &slot_path, 0)?;
        std::fs::remove_file(&marker).map_err(|e| SlotError::Io {
            op: "remove",
            path: marker.clone(),
            reason: e.to_string(),
        })?;
        wiped = true;
    }
    // HOME for the job; a wipe takes it away with everything else.
    ensure_dir(&slot, &slot_path, ".home", ids)?;
    Ok(Prepared { wiped })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(label: &str) -> Tmp {
            let p = std::env::temp_dir().join(format!("keel-slot-{label}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn me() -> Ids {
        let st = statat(rustix::fs::CWD, ".", AtFlags::empty()).unwrap();
        Ids {
            uid: st.st_uid,
            gid: st.st_gid,
        }
    }

    #[test]
    fn passwd_lines_give_ids() {
        let text =
            "root:x:0:0:root:/root:/bin/sh\nkeel-build:x:991:990::/ci/keel/work:/bin/nologin\n";
        assert_eq!(
            lookup_ids(text, "keel-build"),
            Some(Ids { uid: 991, gid: 990 })
        );
        assert_eq!(lookup_ids(text, "keel"), None);
    }

    #[test]
    fn a_first_use_creates_the_slot_and_home() {
        let t = Tmp::new("first");
        let (work, jobs) = (t.0.join("work"), t.0.join("jobs"));
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&jobs).unwrap();
        let r = prepare(&work, &jobs, "nudox-backend-pr-slot0", me(), true).unwrap();
        assert_eq!(r, Prepared { wiped: false });
        assert!(work.join("nudox-backend-pr-slot0/.home").is_dir());
    }

    #[test]
    fn the_marker_wipes_everything_including_links_without_following_them() {
        let t = Tmp::new("wipe");
        let (work, jobs, outside) = (t.0.join("work"), t.0.join("jobs"), t.0.join("outside"));
        for d in [&work, &jobs, &outside] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(outside.join("precious"), b"keep").unwrap();
        let slot = work.join("s-pr-slot0");
        fs::create_dir_all(slot.join("target/debug/deps")).unwrap();
        fs::write(slot.join("target/debug/deps/a.rlib"), b"x").unwrap();
        fs::write(slot.join("sentinel"), b"x").unwrap();
        symlink(&outside, slot.join("link-to-dir")).unwrap();
        symlink(outside.join("precious"), slot.join("link-to-file")).unwrap();

        // No marker: nothing is touched.
        assert_eq!(
            prepare(&work, &jobs, "s-pr-slot0", me(), true).unwrap(),
            Prepared { wiped: false }
        );
        assert!(slot.join("sentinel").exists());
        // A marker the unit is not asked to honour (build, test) is left alone.
        fs::write(jobs.join("s-pr-slot0.wipe"), b"").unwrap();
        assert_eq!(
            prepare(&work, &jobs, "s-pr-slot0", me(), false).unwrap(),
            Prepared { wiped: false }
        );
        assert!(slot.join("sentinel").exists() && jobs.join("s-pr-slot0.wipe").exists());

        assert_eq!(
            prepare(&work, &jobs, "s-pr-slot0", me(), true).unwrap(),
            Prepared { wiped: true }
        );
        assert!(!slot.join("sentinel").exists() && !slot.join("target").exists());
        assert!(
            !jobs.join("s-pr-slot0.wipe").exists(),
            "the marker is consumed"
        );
        assert!(slot.join(".home").is_dir(), "HOME is back");
        assert_eq!(
            fs::read(outside.join("precious")).unwrap(),
            b"keep",
            "links were not followed"
        );
    }

    #[test]
    fn a_slot_replaced_by_a_link_is_refused_and_the_target_untouched() {
        let t = Tmp::new("link");
        let (work, jobs, victim) = (t.0.join("work"), t.0.join("jobs"), t.0.join("victim"));
        for d in [&work, &jobs, &victim] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(victim.join("passwd"), b"root").unwrap();
        symlink(&victim, work.join("s-pr-slot0")).unwrap();
        fs::write(jobs.join("s-pr-slot0.wipe"), b"").unwrap();
        let e = prepare(&work, &jobs, "s-pr-slot0", me(), true).unwrap_err();
        assert!(matches!(e, SlotError::NotDir { .. }), "{e}");
        assert_eq!(fs::read(victim.join("passwd")).unwrap(), b"root");
        // So is a work root that is itself a link.
        symlink(&victim, t.0.join("work-link")).unwrap();
        assert!(matches!(
            prepare(&t.0.join("work-link"), &jobs, "x", me(), true),
            Err(SlotError::NotDir { .. })
        ));
    }
}
