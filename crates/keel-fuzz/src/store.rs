//! Content-addressed corpus: every input lives at `inputs/<blake3 hex>`, and an
//! append-only `manifest.jsonl` records, for each input, the edges it was the first
//! to cover.
//!
//! The file name is the integrity check. A reader that finds a name which does not
//! match the content has found a corrupt or hand-edited store and refuses it.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// 64 lowercase hex characters: the blake3 hash of the input bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InputId(String);

impl InputId {
    pub fn of(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).to_hex().to_string())
    }

    pub fn parse(text: &str) -> Result<Self> {
        if text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(text.to_string()))
        } else {
            bail!("'{text}' is not an input id: expected 64 lowercase hex characters (a blake3 hash)")
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first 12 characters, for human-readable output.
    pub fn short(&self) -> &str {
        &self.0[..12]
    }
}

impl std::fmt::Display for InputId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One manifest line. `new_edges` are edge ids (indices into the target's edge
/// space, see `sancov`), so they are only meaningful together with `target_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub id: InputId,
    pub len: usize,
    /// blake3 of the target binary the edge ids refer to.
    pub target_key: String,
    /// "explore", "import", "cmin", "tmin" or a caller-chosen label.
    pub origin: String,
    pub new_edges: Vec<u32>,
    pub edges_covered_after: u32,
    pub found_ms: u64,
    pub execs: u64,
    pub seed: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct CorpusStore {
    root: PathBuf,
}

impl CorpusStore {
    /// Opens the store at `root`, creating it if absent.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("inputs")).with_context(|| {
            format!(
                "creating the corpus store at {}: check that the parent exists and is writable",
                root.display()
            )
        })?;
        Ok(Self { root })
    }

    /// Opens an existing store without creating anything; used by read-only commands.
    pub fn open_existing(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        if !root.join("inputs").is_dir() {
            bail!(
                "{} is not a corpus store (no inputs/ directory): point --corpus at a directory made by `keel-fuzz explore`, or at a directory of raw input files with --raw-dir",
                root.display()
            );
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path_of(&self, id: &InputId) -> PathBuf {
        self.root.join("inputs").join(id.as_str())
    }

    /// Stores `bytes` and returns its id and whether it was new. The write goes
    /// through a temporary name and a rename, so an interrupted run leaves either
    /// the whole input or nothing.
    pub fn put(&self, bytes: &[u8]) -> Result<(InputId, bool)> {
        let id = InputId::of(bytes);
        let path = self.path_of(&id);
        if path.exists() {
            return Ok((id, false));
        }
        let tmp = self.root.join("inputs").join(format!(".tmp-{}-{}", std::process::id(), id.short()));
        fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &path)
            .with_context(|| format!("moving {} to {}", tmp.display(), path.display()))?;
        Ok((id, true))
    }

    pub fn get(&self, id: &InputId) -> Result<Vec<u8>> {
        let path = self.path_of(id);
        let bytes = fs::read(&path).with_context(|| format!("reading corpus input {}", path.display()))?;
        if InputId::of(&bytes) != *id {
            bail!(
                "corpus input {} does not hash to its own name; the store is corrupt or was edited by hand: delete the file and re-run exploration to regenerate it",
                path.display()
            );
        }
        Ok(bytes)
    }

    /// All ids, sorted.
    pub fn ids(&self) -> Result<Vec<InputId>> {
        let dir = self.root.join("inputs");
        let mut ids = Vec::new();
        for entry in fs::read_dir(&dir).with_context(|| format!("listing {}", dir.display()))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            ids.push(InputId::parse(&name).with_context(|| {
                format!("{} holds a file that is not a content-addressed input", dir.display())
            })?);
        }
        ids.sort();
        Ok(ids)
    }

    pub fn remove(&self, id: &InputId) -> Result<()> {
        let path = self.path_of(id);
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))
    }

    /// The content hash of the whole corpus: blake3 over the sorted raw ids. Two
    /// stores with the same inputs have the same key whatever order they were built in.
    pub fn corpus_key(&self) -> Result<String> {
        Ok(corpus_key_of(&self.ids()?))
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join("manifest.jsonl")
    }

    /// Appends one line with a single write so concurrent appenders and a killed
    /// process never leave a torn record in the middle of the file.
    pub fn append_manifest(&self, entry: &ManifestEntry) -> Result<()> {
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.manifest_path())
            .with_context(|| format!("opening {}", self.manifest_path().display()))?;
        file.write_all(&line)?;
        Ok(())
    }

    /// The manifest as a map; the first line for an id wins, because the first
    /// writer is the one that actually discovered the coverage. A torn last line
    /// (killed mid-write) is skipped.
    pub fn manifest(&self) -> Result<BTreeMap<InputId, ManifestEntry>> {
        let path = self.manifest_path();
        let mut entries = BTreeMap::new();
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<ManifestEntry>(line) {
                Ok(entry) => {
                    entries.entry(entry.id.clone()).or_insert(entry);
                }
                Err(_) if n + 1 == lines.len() => {} // torn tail
                Err(e) => bail!(
                    "{}:{} is not a manifest entry ({e}); delete the line or the file: the manifest is rebuilt by `keel-fuzz cmin`",
                    path.display(),
                    n + 1
                ),
            }
        }
        Ok(entries)
    }
}

pub fn corpus_key_of(ids: &[InputId]) -> String {
    let mut sorted: Vec<&InputId> = ids.iter().collect();
    sorted.sort();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"keel-fuzz-corpus-v1\0");
    for id in sorted {
        hasher.update(id.as_str().as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// Reads a corpus from either a content-addressed store (a directory with
/// `inputs/`) or a plain directory of files, so existing seed directories work.
/// Returns (display name, bytes) pairs in a stable order.
pub fn read_inputs(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    if path.is_file() {
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        return Ok(vec![(InputId::of(&bytes).to_string(), bytes)]);
    }
    if path.join("inputs").is_dir() {
        let store = CorpusStore::open_existing(path)?;
        return store.ids()?.into_iter().map(|id| Ok((id.to_string(), store.get(&id)?))).collect();
    }
    if !path.is_dir() {
        bail!("{} is neither a file nor a directory: pass an input file, a corpus store or a directory of inputs", path.display());
    }
    let mut files: Vec<PathBuf> = fs::read_dir(path)
        .with_context(|| format!("listing {}", path.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .map(|e| e.path())
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let bytes = fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
            Ok((InputId::of(&bytes).to_string(), bytes))
        })
        .collect()
}

/// Writes `bytes` to `path`, replacing it; for outputs that are not corpus members.
pub fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(bytes: &[u8], edges: Vec<u32>) -> ManifestEntry {
        ManifestEntry {
            id: InputId::of(bytes),
            len: bytes.len(),
            target_key: "t".into(),
            origin: "explore".into(),
            new_edges: edges,
            edges_covered_after: 1,
            found_ms: 5,
            execs: 10,
            seed: Some(7),
        }
    }

    #[test]
    fn put_is_idempotent_and_named_by_blake3() {
        let dir = tempfile::tempdir().unwrap();
        let store = CorpusStore::open(dir.path()).unwrap();
        let (id, new) = store.put(b"hello").unwrap();
        assert!(new);
        assert_eq!(id.as_str(), blake3::hash(b"hello").to_hex().as_str());
        let (again, new) = store.put(b"hello").unwrap();
        assert_eq!(again, id);
        assert!(!new);
        assert_eq!(store.get(&id).unwrap(), b"hello");
        assert_eq!(store.ids().unwrap(), vec![id]);
    }

    #[test]
    fn a_renamed_input_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = CorpusStore::open(dir.path()).unwrap();
        let (id, _) = store.put(b"hello").unwrap();
        fs::write(store.path_of(&id), b"tampered").unwrap();
        let err = store.get(&id).unwrap_err().to_string();
        assert!(err.contains("does not hash to its own name"), "{err}");
    }

    #[test]
    fn corpus_key_ignores_insertion_order_and_changes_with_content() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let (sa, sb) = (CorpusStore::open(a.path()).unwrap(), CorpusStore::open(b.path()).unwrap());
        for x in [&b"one"[..], b"two", b"three"] {
            sa.put(x).unwrap();
        }
        for x in [&b"three"[..], b"one", b"two"] {
            sb.put(x).unwrap();
        }
        assert_eq!(sa.corpus_key().unwrap(), sb.corpus_key().unwrap());
        sb.put(b"four").unwrap();
        assert_ne!(sa.corpus_key().unwrap(), sb.corpus_key().unwrap());
    }

    #[test]
    fn manifest_first_writer_wins_and_torn_tail_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let store = CorpusStore::open(dir.path()).unwrap();
        store.append_manifest(&entry(b"x", vec![1, 2])).unwrap();
        store.append_manifest(&entry(b"x", vec![9])).unwrap();
        store.append_manifest(&entry(b"y", vec![3])).unwrap();
        // A killed writer leaves half a line at the end.
        let mut f = OpenOptions::new().append(true).open(dir.path().join("manifest.jsonl")).unwrap();
        f.write_all(b"{\"id\":\"deadbeef").unwrap();
        let manifest = store.manifest().unwrap();
        assert_eq!(manifest.len(), 2);
        assert_eq!(manifest[&InputId::of(b"x")].new_edges, vec![1, 2]);
    }

    #[test]
    fn a_torn_line_in_the_middle_is_an_error_that_says_what_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let store = CorpusStore::open(dir.path()).unwrap();
        fs::write(dir.path().join("manifest.jsonl"), "garbage\n{}\n").unwrap();
        let err = store.manifest().unwrap_err().to_string();
        assert!(err.contains("manifest.jsonl:1"), "{err}");
    }

    #[test]
    fn ids_reject_non_hex_names() {
        assert!(InputId::parse("abc").is_err());
        assert!(InputId::parse(&"A".repeat(64)).is_err());
        assert!(InputId::parse(&"a".repeat(64)).is_ok());
    }
}
