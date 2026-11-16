//! `check --watch`: which files a model is made of, and when one of them changed.
//!
//! Polling modification times is enough for a few files and needs no platform API, so no crate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// How often the files are looked at.
pub const POLL: Duration = Duration::from_millis(500);

/// Each file with its modification time and size; `None` for one that cannot be read.
pub type Snapshot = BTreeMap<PathBuf, Option<(SystemTime, u64)>>;

/// The .nix files a change to which can change the model: every one under the directory of the
/// entry point, and every one those name by a relative path (`import ../../nix/keel/lib.nix`),
/// followed from file to file. A path built by evaluation (`root + "/x.nix"`) is not seen.
pub fn files(model: &Path) -> Vec<PathBuf> {
    let dir = match model.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let mut found: BTreeSet<PathBuf> = BTreeSet::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let path = e.path();
            // Not followed through symlinks: a link back up the tree would never end.
            let Ok(kind) = e.file_type() else { continue };
            if kind.is_dir() && !e.file_name().to_string_lossy().starts_with('.') {
                todo.push(path);
            } else if path.extension().is_some_and(|x| x == "nix") {
                found.insert(canonical(&path));
            }
        }
    }
    found.insert(canonical(model));
    let mut queue: Vec<PathBuf> = found.iter().cloned().collect();
    while let Some(file) = queue.pop() {
        let Ok(text) = std::fs::read_to_string(&file) else { continue };
        let base = file.parent().unwrap_or(Path::new("."));
        for reference in relative_nix_paths(&text) {
            let target = base.join(reference);
            if target.is_file() && found.insert(canonical(&target)) {
                queue.push(canonical(&target));
            }
        }
    }
    found.into_iter().collect()
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Path literals in Nix text that start with `./` or `../` and end in `.nix`.
fn relative_nix_paths(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || "_./+-".contains(c)))
        .filter(|w| (w.starts_with("./") || w.starts_with("../")) && w.ends_with(".nix"))
        .collect()
}

pub fn snapshot(files: &[PathBuf]) -> Snapshot {
    files
        .iter()
        .map(|f| (f.clone(), std::fs::metadata(f).and_then(|m| m.modified().map(|t| (t, m.len()))).ok()))
        .collect()
}

/// Returns once the files differ from `seen`: one changed, appeared or went away. The set is
/// listed again each time, so a new import is watched from the run after it is written.
pub fn wait_for_change(model: &Path, seen: &Snapshot) -> Snapshot {
    loop {
        std::thread::sleep(POLL);
        let now = snapshot(&files(model));
        if &now != seen {
            return now;
        }
    }
}

/// The line between two runs: when the run ended and how long it took. UTC, because local time
/// is not in the standard library.
pub fn separator(model: &Path, watched: usize, took: Duration) -> String {
    let day = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs()) % 86_400;
    let dir = model.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    format!(
        "---- {:02}:{:02}:{:02} UTC  check took {:.1} s; watching {watched} .nix files (under {} and what they import); Ctrl-C ends it ----",
        day / 3600,
        day % 3600 / 60,
        day % 60,
        took.as_secs_f64(),
        dir.display()
    )
}
