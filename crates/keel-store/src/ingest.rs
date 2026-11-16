//! Reading a job's output directory, which is attacker-controlled.
//!
//! A PR's build or test can leave anything in `/ci/keel/out/<job>`: a symlink
//! to the writer token, a FIFO that blocks the reader forever, a sparse file
//! that claims 10 GiB, a name that climbs out with `..`. The conductor reads
//! that directory, so every one of those must end in an error and never in a
//! read. Files are opened relative to the directory's own descriptor with
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` on
//! Linux; elsewhere `O_NOFOLLOW` on the final component after a name check and
//! an `lstat`-equivalent `fstat` of what was actually opened. Either way only
//! regular files are accepted, and count and size are capped before a byte is
//! read.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{Dir, FileType, Mode, OFlags, fstat, open};

/// Limits on what one job may hand back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// Most files accepted.
    pub files: usize,
    /// Largest accepted file, bytes.
    pub file_bytes: u64,
    /// Largest accepted total, bytes.
    pub total_bytes: u64,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            files: 64,
            file_bytes: 16 << 20,
            total_bytes: 256 << 20,
        }
    }
}

/// Why an output directory was refused. Each message names the offender and
/// what to do; any of them means the job's results are not trusted.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// The directory itself could not be opened as a plain directory.
    #[error(
        "cannot open the output directory {path}: {reason}; it must be a real directory (not a symlink) readable by the conductor"
    )]
    Dir {
        /// The directory.
        path: PathBuf,
        /// The OS error.
        reason: String,
    },
    /// An entry's name is not a plain file name.
    #[error(
        "output entry `{name}` has a name that is not allowed (empty, `.`, `..`, or containing `/` or NUL); the job is untrusted"
    )]
    BadName {
        /// The name.
        name: String,
    },
    /// An entry is a symlink, FIFO, socket, device or directory.
    #[error(
        "output `{name}` is not a regular file ({what}); only regular files are accepted, treat the job as failed"
    )]
    NotRegular {
        /// The entry.
        name: String,
        /// What it is, or why it could not be opened safely.
        what: String,
    },
    /// More files than the cap.
    #[error(
        "the job left more than {max} output files; treat the job as failed or raise the cap deliberately"
    )]
    TooManyFiles {
        /// The cap.
        max: usize,
    },
    /// One file over the per-file cap.
    #[error(
        "output `{name}` is {size} bytes, over the per-file cap of {max}; treat the job as failed"
    )]
    FileTooLarge {
        /// The entry.
        name: String,
        /// Its size.
        size: u64,
        /// The cap.
        max: u64,
    },
    /// All files together over the total cap.
    #[error("the job's outputs total more than {max} bytes; treat the job as failed")]
    TotalTooLarge {
        /// The cap.
        max: u64,
    },
    /// Reading failed.
    #[error("cannot read output `{name}`: {reason}")]
    Read {
        /// The entry.
        name: String,
        /// The OS error.
        reason: String,
    },
}

/// A directory entry name that can only name a file directly inside the
/// directory.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

/// Opens `name` inside `dir` without following anything.
#[cfg(target_os = "linux")]
fn open_beneath(dir: &OwnedFd, name: &str) -> Result<OwnedFd, rustix::io::Errno> {
    use rustix::fs::{ResolveFlags, openat2};
    // O_NONBLOCK so opening a FIFO returns at once (and is then rejected by
    // type) instead of waiting for a writer that never comes.
    openat2(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
}

/// Non-Linux fallback: the name is already known to be a single component, so
/// `O_NOFOLLOW` covers the one component that matters.
#[cfg(not(target_os = "linux"))]
fn open_beneath(dir: &OwnedFd, name: &str) -> Result<OwnedFd, rustix::io::Errno> {
    rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
    )
}

/// Reads every file in `dir`, which the job controls, under `caps`.
///
/// Returns `(name, bytes)` in name order. The last component of `dir` must not
/// be a symlink; its parents are trusted (they are created by the host, not
/// by the job).
pub fn ingest_outputs(dir: &Path, caps: &Caps) -> Result<Vec<(String, Vec<u8>)>, IngestError> {
    let dir_err = |reason: String| IngestError::Dir {
        path: dir.into(),
        reason,
    };
    let dirfd = open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| dir_err(e.to_string()))?;

    let mut names = Vec::new();
    let listing = Dir::read_from(&dirfd).map_err(|e| dir_err(e.to_string()))?;
    for entry in listing {
        let entry = entry.map_err(|e| dir_err(e.to_string()))?;
        let raw = entry.file_name().to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        let name = String::from_utf8_lossy(raw).into_owned();
        if !plain_name(&name) || name.as_bytes() != raw {
            return Err(IngestError::BadName { name });
        }
        names.push(name);
        if names.len() > caps.files {
            return Err(IngestError::TooManyFiles { max: caps.files });
        }
    }
    names.sort();

    let mut out = Vec::with_capacity(names.len());
    let mut total = 0u64;
    for name in names {
        let fd = open_beneath(&dirfd, &name).map_err(|e| IngestError::NotRegular {
            name: name.clone(),
            what: format!("it could not be opened without following links: {e}"),
        })?;
        // What was actually opened, not what the listing said a moment ago.
        let st = fstat(fd.as_fd()).map_err(|e| IngestError::Read {
            name: name.clone(),
            reason: e.to_string(),
        })?;
        let kind = FileType::from_raw_mode(st.st_mode);
        if kind != FileType::RegularFile {
            return Err(IngestError::NotRegular {
                name,
                what: format!("{kind:?}"),
            });
        }
        let size = u64::try_from(st.st_size).unwrap_or(0);
        if size > caps.file_bytes {
            return Err(IngestError::FileTooLarge {
                name,
                size,
                max: caps.file_bytes,
            });
        }
        total = total.saturating_add(size);
        if total > caps.total_bytes {
            return Err(IngestError::TotalTooLarge {
                max: caps.total_bytes,
            });
        }
        // The file can still grow after fstat; stop one byte past the cap.
        let mut bytes = Vec::with_capacity(size as usize);
        File::from(fd)
            .take(caps.file_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| IngestError::Read {
                name: name.clone(),
                reason: e.to_string(),
            })?;
        if bytes.len() as u64 > caps.file_bytes {
            return Err(IngestError::FileTooLarge {
                name,
                size: bytes.len() as u64,
                max: caps.file_bytes,
            });
        }
        out.push((name, bytes));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(label: &str) -> Tmp {
            let p =
                std::env::temp_dir().join(format!("keel-ingest-{label}-{}", std::process::id()));
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

    #[test]
    fn caps_default_to_the_documented_limits() {
        let c = Caps::default();
        assert_eq!(
            (c.files, c.file_bytes, c.total_bytes),
            (64, 16 << 20, 256 << 20)
        );
    }

    #[test]
    fn names_must_be_plain() {
        for ok in ["stdout", "report.json", ".hidden", "a b"] {
            assert!(plain_name(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "../x", "a\0b"] {
            assert!(!plain_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn regular_files_are_read_in_name_order() {
        let t = Tmp::new("ok");
        fs::write(t.0.join("b"), b"two").unwrap();
        fs::write(t.0.join("a"), b"one").unwrap();
        let got = ingest_outputs(&t.0, &Caps::default()).unwrap();
        assert_eq!(
            got,
            vec![("a".into(), b"one".to_vec()), ("b".into(), b"two".to_vec())]
        );
        assert!(ingest_outputs(&t.0.join("missing"), &Caps::default()).is_err());
    }

    #[test]
    fn count_and_size_caps_hold() {
        let t = Tmp::new("caps");
        for i in 0..3 {
            fs::write(t.0.join(format!("f{i}")), b"12345").unwrap();
        }
        let few = Caps {
            files: 2,
            ..Caps::default()
        };
        assert!(matches!(
            ingest_outputs(&t.0, &few),
            Err(IngestError::TooManyFiles { max: 2 })
        ));
        let small = Caps {
            file_bytes: 4,
            ..Caps::default()
        };
        assert!(matches!(
            ingest_outputs(&t.0, &small),
            Err(IngestError::FileTooLarge { .. })
        ));
        let total = Caps {
            total_bytes: 12,
            ..Caps::default()
        };
        assert!(matches!(
            ingest_outputs(&t.0, &total),
            Err(IngestError::TotalTooLarge { .. })
        ));
    }

    /// Hostile entries. These behave the same through `openat2` and through
    /// the `O_NOFOLLOW` fallback, so they run wherever there are symlinks.
    #[cfg(unix)]
    #[test]
    fn symlinks_fifos_sparse_files_and_directories_are_refused() {
        use std::os::unix::fs::symlink;
        let case = |label: &str, make: &dyn Fn(&Path)| {
            let t = Tmp::new(label);
            make(&t.0);
            ingest_outputs(&t.0, &Caps::default()).unwrap_err()
        };

        let secret = Tmp::new("secret");
        fs::write(secret.0.join("token"), b"hunter2-hunter2-hunter2").unwrap();
        let target = secret.0.join("token");
        let e = case("link", &|d| symlink(&target, d.join("report")).unwrap());
        assert!(matches!(e, IngestError::NotRegular { .. }), "{e}");
        let e = case("dirlink", &|d| symlink(&secret.0, d.join("dir")).unwrap());
        assert!(matches!(e, IngestError::NotRegular { .. }), "{e}");
        let e = case("dangling", &|d| {
            symlink("/no/such/place", d.join("x")).unwrap()
        });
        assert!(matches!(e, IngestError::NotRegular { .. }), "{e}");

        let e = case("fifo", &|d| {
            // mkfifo(1) exists on every unix this runs on; rustix has no mknodat on macOS.
            let status = std::process::Command::new("mkfifo")
                .arg(d.join("pipe"))
                .status()
                .unwrap();
            assert!(status.success());
        });
        assert!(matches!(e, IngestError::NotRegular { .. }), "{e}");

        let e = case("sparse", &|d| {
            File::create(d.join("big"))
                .unwrap()
                .set_len(10 << 30)
                .unwrap();
        });
        assert!(
            matches!(e, IngestError::FileTooLarge { size, .. } if size == 10 << 30),
            "{e}"
        );

        let e = case("subdir", &|d| fs::create_dir(d.join("sub")).unwrap());
        assert!(matches!(e, IngestError::NotRegular { .. }), "{e}");

        // The directory itself may not be a symlink the job planted.
        let real = Tmp::new("real");
        let holder = Tmp::new("holder");
        symlink(&real.0, holder.0.join("out")).unwrap();
        let e = ingest_outputs(&holder.0.join("out"), &Caps::default()).unwrap_err();
        assert!(matches!(e, IngestError::Dir { .. }), "{e}");
    }

    /// `..` cannot appear in a listing, so the only way to name one is
    /// through a path the job controls; the openat2 resolve flags are what
    /// refuse it, which only Linux has.
    #[cfg(target_os = "linux")]
    #[test]
    fn openat2_refuses_dotdot_and_magic_links() {
        let t = Tmp::new("beneath");
        let dirfd = open(&t.0, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        assert!(open_beneath(&dirfd, "../etc").is_err());
        assert!(open_beneath(&dirfd, "/etc/passwd").is_err());
        assert!(open_beneath(&dirfd, "/proc/self/exe").is_err());
    }
}
