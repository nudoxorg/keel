//! Opening link inputs: map, split into objects, and parse each distinct object once.

use crate::cache;
use crate::model::*;
use crate::record::LinkInputs;
use memmap2::Mmap;
use object::FileKind;
use object::read::archive::ArchiveFile;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// An object file or archive after loading: its objects, in order.
pub struct ParsedFile {
    pub is_archive: bool,
    pub members: Vec<Member>,
    /// Offset of each member's bytes in the file; `Atom::file_off` is relative to it.
    pub bases: Vec<u64>,
    /// The file's bytes, kept only where atom contents are read back (the test crate's own
    /// objects, whose descriptors and strings are read). Archives are unmapped once their
    /// objects are parsed or found in the cache.
    pub map: Option<Mmap>,
    /// File-level failure (unreadable archive); members may be empty.
    pub problem: Option<String>,
}

impl ParsedFile {
    /// The bytes of atom `a` of member `member`; `None` if the file was not kept mapped or
    /// the atom has no bytes (zero-fill).
    pub fn atom_bytes(&self, member: usize, a: &Atom) -> Option<&[u8]> {
        if a.file_off == u64::MAX {
            return Some(&[]);
        }
        let start = usize::try_from(self.bases.get(member)? + a.file_off).ok()?;
        self.map.as_ref()?.get(start..start.checked_add(a.size as usize)?)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnitKind {
    /// An object of the crate under test, preserved by the shim.
    TestObject,
    Archive,
}

/// One link input after loading.
pub struct Unit {
    pub path: PathBuf,
    pub kind: UnitKind,
    /// Crate the input belongs to: from the rlib's file name, or the test crate.
    pub crate_name: String,
    pub file: Arc<ParsedFile>,
    /// Place on the link line (argument index), if it can be established. Archives found
    /// by resolving `-l` names have none.
    pub order: Option<u32>,
}

pub struct Loaded {
    pub units: Vec<Unit>,
    /// First reason the inputs cannot be trusted, naming the file, member and symbol if known.
    pub problem: Option<String>,
    pub notes: Vec<String>,
    /// Inputs of the link that are not keyed by their content: dynamic libraries the
    /// linker read (or, without a dependency file, every `-l` name no static library
    /// was found for). Calls into them are hashed by name only.
    pub unkeyed: Vec<String>,
}

/// Path, kind, crate, the hash it was recorded with, place on the link line.
type Job = (PathBuf, UnitKind, String, Option<String>, Option<u32>);

/// Archives larger than this have their objects handled in parallel.
const BIG_ARCHIVE: u64 = 16 << 20;

#[derive(Default)]
pub struct Loader {
    /// Objects already parsed in this process, by content hash.
    parsed: Mutex<HashMap<Hash, Arc<OnceLock<Arc<MemberData>>>>>,
    cache: Option<PathBuf>,
    parses: AtomicUsize,
    hits: AtomicUsize,
    cache_notes: Mutex<Vec<String>>,
    /// Split Mach-O sections at symbols whether or not the object says it may be. Wrong for
    /// objects built without MH_SUBSECTIONS_VIA_SYMBOLS; exists so that a report made with
    /// the old rule can be compared with one made with the new (`compare` is the oracle).
    pub assume_subsections: bool,
}

impl Loader {
    pub fn new() -> Loader {
        Loader::default()
    }

    /// A loader that keeps parsed objects in `dir`, keyed by the blake3 of each object's bytes.
    pub fn with_cache(dir: PathBuf) -> anyhow::Result<Loader> {
        std::fs::create_dir_all(&dir).map_err(|e| {
            anyhow::anyhow!(
                "cannot create the cache directory {}: {e}; pass a writable --cache",
                dir.display()
            )
        })?;
        Ok(Loader {
            cache: Some(dir),
            ..Loader::default()
        })
    }

    /// Objects served from the on-disk cache so far.
    pub fn cache_hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }

    /// Distinct objects parsed so far (not served from the cache or from memory).
    pub fn parse_count(&self) -> usize {
        self.parses.load(Ordering::Relaxed)
    }

    /// The parsed form of one object's bytes: from this process, else from the cache, else
    /// parsed (and then cached).
    fn object(&self, bytes: &[u8], hash: Hash) -> Arc<MemberData> {
        let cell = self.parsed.lock().unwrap().entry(hash).or_default().clone();
        cell.get_or_init(|| {
            if let Some(dir) = &self.cache {
                let path = cache::entry_path(dir, self.assume_subsections, &hash);
                if let Some(d) = cache::open(&path).and_then(|m| cache::decode(&m)) {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Arc::new(d);
                }
            }
            self.parses.fetch_add(1, Ordering::Relaxed);
            let built = parse_object(bytes, self.assume_subsections);
            let data = built.finish();
            let Some(dir) = &self.cache else {
                return Arc::new(data);
            };
            if data.problem.is_some() {
                return Arc::new(data);
            }
            // Written, then read back through the mapping, so that the process holds one
            // copy of the object (the file's) however it got there.
            let path = cache::entry_path(dir, self.assume_subsections, &hash);
            match cache::write(&path, &cache::encode(&data)) {
                Ok(()) => {
                    if let Some(d) = cache::open(&path).and_then(|m| cache::decode(&m)) {
                        return Arc::new(d);
                    }
                    self.note_cache(format!("cannot read back {}; this run keeps the object in memory", path.display()));
                }
                Err(e) => self.note_cache(format!(
                    "cannot write {}: {e}; the cache is not growing (is the disk full or the directory read-only?)",
                    path.display()
                )),
            }
            Arc::new(data)
        })
        .clone()
    }

    fn note_cache(&self, why: String) {
        let mut n = self.cache_notes.lock().unwrap();
        if n.len() < 3 {
            n.push(why);
        }
    }

    pub fn open(
        &self,
        path: &Path,
        keep_map: bool,
        expect: Option<&str>,
        parallel_members: bool,
    ) -> Result<Arc<ParsedFile>, String> {
        let f = File::open(path).map_err(|e| {
            format!(
                "cannot open {}: {e}; the link input was deleted or moved after linking",
                path.display()
            )
        })?;
        // SAFETY: the mapping is read-only. cargo replaces rlibs by rename, not truncation,
        // so a concurrent rebuild leaves this mapping on the old inode.
        let map =
            unsafe { Mmap::map(&f) }.map_err(|e| format!("cannot map {}: {e}", path.display()))?;
        let data: &[u8] = &map;
        let whole = |bytes: &[u8]| -> Hash {
            let mut h = blake3::Hasher::new();
            if bytes.len() > 1 << 20 {
                h.update_rayon(bytes);
            } else {
                h.update(bytes);
            }
            *h.finalize().as_bytes()
        };
        let (is_archive, members, bases, problem);
        match FileKind::parse(data) {
            Ok(FileKind::Archive) => {
                let (m, b, p) = open_archive(self, data, parallel_members);
                (is_archive, members, bases, problem) = (true, m, b, p);
            }
            Ok(_) => {
                let h = whole(data);
                if let Some(want) = expect {
                    let got = hex(&h);
                    if got != want {
                        return Err(format!(
                            "{} changed after it was linked (recorded {want}, now {got}); relink the binary so keel-linker preserves the current objects",
                            path.display()
                        ));
                    }
                }
                let m = Member {
                    name: "<object>".into(),
                    data: self.object(data, h),
                };
                (is_archive, members, bases, problem) = (false, vec![m], vec![0], None);
            }
            Err(e) => {
                (is_archive, members, bases) = (false, vec![], vec![]);
                problem = Some(format!("not an object file or archive: {e}"));
            }
        }
        Ok(Arc::new(ParsedFile {
            is_archive,
            members,
            bases,
            map: keep_map.then_some(map),
            problem,
        }))
    }

    /// Load every input a record names. Failures do not return early: the caller
    /// gets the units that did load plus the first problem, and decides.
    pub fn load(&self, rec: &LinkInputs, test_crate: &str) -> Loaded {
        let mut jobs: Vec<Job> = Vec::new();
        let positions0 = arg_positions(rec);
        let preserved = rec.preserved_objects.len() == rec.objects.len();
        for (i, o) in rec.objects.iter().enumerate() {
            let p = if preserved {
                rec.preserved_objects[i].clone()
            } else {
                o.clone()
            };
            let want = rec
                .preserved_hashes
                .get(i)
                .filter(|_| preserved && !rec.preserved_hashes[i].is_empty())
                .cloned();
            let order = positions0.get(&rec.objects[i]).copied();
            jobs.push((p, UnitKind::TestObject, test_crate.to_string(), want, order));
        }
        let mut notes = Vec::new();
        let mut unkeyed = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut archives = rec.archives.clone();
        let positions = arg_positions(rec);
        // What the linker itself says it read, if it was asked.
        let read: Option<Vec<PathBuf>> = rec.dependency_file.as_ref().and_then(|p| {
            match read_dependency_file(p, &rec.dependency_flavour) {
                Ok(v) => Some(v),
                Err(why) => {
                    notes.push(format!("{why}; falling back to resolving -l names by search"));
                    None
                }
            }
        });
        match &read {
            Some(inputs) => {
                let known: std::collections::HashSet<&PathBuf> =
                    rec.archives.iter().chain(&rec.objects).collect();
                for p in inputs {
                    if known.contains(p) {
                        continue;
                    }
                    match p.extension().and_then(|e| e.to_str()) {
                        Some("a" | "rlib" | "o") => archives.push(p.clone()),
                        _ => {
                            // The linker lists a stub once per re-export that reads it.
                            let line = format!(
                                "{} (read by the linker as a dynamic library or stub; calls into it are hashed by name)",
                                p.display()
                            );
                            if !unkeyed.contains(&line) {
                                unkeyed.push(line);
                            }
                        }
                    }
                }
            }
            None => {
                for l in &rec.libs {
                    // `-lfoo` names `libfoo.a` in a `-L` directory if a static library exists;
                    // otherwise it is a dynamic library whose symbols are imports. The search
                    // misses libraries the compiler driver finds on its own (compiler-rt, a
                    // static libc), which then count as dynamic, so each one is listed.
                    match rec
                        .lib_dirs
                        .iter()
                        .map(|d| d.join(format!("lib{l}.a")))
                        .find(|p| p.exists())
                    {
                        Some(p) => archives.push(p),
                        None => {
                            notes.push(format!(
                                "-l{l}: no static library found, treated as dynamic imports"
                            ));
                            unkeyed.push(format!(
                                "-l{l} (no static library in the -L directories; the linker may have found one the record does not show; calls into it are hashed by name)"
                            ));
                        }
                    }
                }
            }
        }
        for a in archives {
            if seen.insert(a.clone()) {
                let name = crate_name_of(&a);
                let order = positions.get(&a).copied();
                jobs.push((a, UnitKind::Archive, name, None, order));
            }
        }
        let make = |parallel: bool, (path, kind, crate_name, want, order): Job| -> Result<Unit, String> {
            let file = self.open(&path, kind == UnitKind::TestObject, want.as_deref(), parallel)?;
            Ok(Unit {
                path,
                kind,
                crate_name,
                file,
                order,
            })
        };
        // Big archives one at a time, with their objects in parallel; the rest side by side.
        let big = |j: &Job| std::fs::metadata(&j.0).is_ok_and(|m| m.len() > BIG_ARCHIVE);
        let (bigs, smalls): (Vec<_>, Vec<_>) =
            jobs.into_iter().enumerate().partition(|(_, j)| big(j));
        let mut results: Vec<(usize, Result<Unit, String>)> = Vec::new();
        for (i, j) in bigs {
            results.push((i, make(true, j)));
        }
        results.extend(
            smalls
                .into_par_iter()
                .map(|(i, j)| (i, make(false, j)))
                .collect::<Vec<_>>(),
        );
        results.sort_by_key(|r| r.0);
        let results: Vec<Result<Unit, String>> = results.into_iter().map(|r| r.1).collect();
        let mut units = Vec::new();
        let mut problem = None;
        for r in results {
            match r {
                Ok(u) => {
                    if problem.is_none() {
                        problem = u
                            .file
                            .problem
                            .as_ref()
                            .map(|p| format!("{}: {p}", u.path.display()))
                            .or_else(|| {
                                u.file.members.iter().find_map(|m| {
                                    m.problem.as_ref().map(|p| {
                                        format!("{} member {}: {p}", u.path.display(), m.name)
                                    })
                                })
                            });
                    }
                    units.push(u);
                }
                Err(e) => problem = problem.or(Some(e)),
            }
        }
        notes.extend(self.cache_notes.lock().unwrap().iter().cloned());
        Loaded {
            units,
            problem,
            notes,
            unkeyed,
        }
    }
}

/// Index in the argument list of each file the record names, where it can be found
/// (a plain argument, or one of a `-Wl,` list).
fn arg_positions(rec: &LinkInputs) -> HashMap<PathBuf, u32> {
    let abs = |s: &str| -> PathBuf {
        let p = Path::new(s);
        if p.is_absolute() { p.to_path_buf() } else { rec.cwd.join(p) }
    };
    let mut out = HashMap::new();
    for (i, a) in rec.args.iter().enumerate() {
        let parts: Vec<&str> = match a.strip_prefix("-Wl,") {
            Some(rest) => rest.split(',').collect(),
            None => vec![a.as_str()],
        };
        for p in parts {
            if p.ends_with(".o") || p.ends_with(".a") || p.ends_with(".rlib") {
                out.entry(abs(p)).or_insert(i as u32);
            }
        }
    }
    out
}

/// The files a linker read, from the file it was asked to write.
///
/// ld64 `-dependency_info`: a version record (`0x00`, linker version, NUL), then records of
/// one opcode byte and a NUL-terminated string; `0x10` is an input file, `0x11` an input
/// that was looked for and not found, `0x40` the output. lld and mold `--dependency-file`:
/// a makefile rule `output: input input ...` with backslash-escaped spaces.
pub fn read_dependency_file(path: &Path, flavour: &str) -> Result<Vec<PathBuf>, String> {
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "cannot read the linker's dependency file {}: {e}; the link may have failed or the linker may not support the option",
            path.display()
        )
    })?;
    match flavour {
        "ld64" => {
            let mut out = Vec::new();
            let mut i = 0;
            while i < bytes.len() {
                let op = bytes[i];
                let end = bytes[i + 1..].iter().position(|&b| b == 0).map(|n| i + 1 + n).ok_or_else(|| {
                    format!("{} ends in the middle of a record; it is truncated", path.display())
                })?;
                if op == 0x10 {
                    out.push(PathBuf::from(String::from_utf8_lossy(&bytes[i + 1..end]).into_owned()));
                }
                i = end + 1;
            }
            Ok(out)
        }
        "make" => {
            let text = String::from_utf8_lossy(&bytes);
            let text = text.replace("\\\n", " ");
            let rule = text.split_once(':').map_or("", |x| x.1);
            let mut out = Vec::new();
            let mut cur = String::new();
            let mut chars = rule.chars().peekable();
            while let Some(c) = chars.next() {
                match c {
                    '\\' if chars.peek() == Some(&' ') => {
                        cur.push(' ');
                        chars.next();
                    }
                    c if c.is_whitespace() => {
                        if !cur.is_empty() {
                            out.push(PathBuf::from(std::mem::take(&mut cur)));
                        }
                    }
                    c => cur.push(c),
                }
            }
            if !cur.is_empty() {
                out.push(PathBuf::from(cur));
            }
            Ok(out)
        }
        other => Err(format!(
            "dependency file flavour `{other}` is not understood (ld64 and make are); record the link with a current keel-linker"
        )),
    }
}

pub fn hex(h: &[u8]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// `libc000-0123abcd.rlib` is crate `c000`.
pub fn crate_name_of(p: &Path) -> String {
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = stem.strip_prefix("lib").unwrap_or(&stem);
    stem.rsplit_once('-').map_or(stem, |(a, _)| a).to_string()
}

/// The objects of an archive, parsed or fetched in parallel.
fn open_archive(
    l: &Loader,
    data: &[u8],
    parallel_members: bool,
) -> (Vec<Member>, Vec<u64>, Option<String>) {
    let ar = match ArchiveFile::parse(data) {
        Ok(a) => a,
        Err(e) => return (vec![], vec![], Some(format!("unreadable archive: {e}"))),
    };
    let mut raw: Vec<(String, u64, &[u8])> = Vec::new();
    for mem in ar.members() {
        let mem = match mem {
            Ok(m) => m,
            Err(e) => return (vec![], vec![], Some(format!("unreadable archive member: {e}"))),
        };
        let name = String::from_utf8_lossy(mem.name()).into_owned();
        let (off, _) = mem.file_range();
        match mem.data(data) {
            Ok(b) => raw.push((name, off, b)),
            Err(e) => {
                return (vec![], vec![], Some(format!("archive member {name}: {e}")));
            }
        }
    }
    let one = |(name, off, bytes): (String, u64, &[u8])| -> Option<(Member, u64)> {
            let data = match FileKind::parse(bytes) {
                // lib.rmeta and other non-object payloads are metadata, not code.
                Ok(FileKind::Elf32 | FileKind::Elf64 | FileKind::MachO64 | FileKind::MachO32) => {
                    let mut h = blake3::Hasher::new();
                    if bytes.len() > 1 << 20 {
                        h.update_rayon(bytes);
                    } else {
                        h.update(bytes);
                    }
                    l.object(bytes, *h.finalize().as_bytes())
                }
                Ok(other) => Arc::new(problem_member(format!(
                    "{other:?} members are not supported; only ELF and Mach-O objects are understood"
                ))),
                Err(_) if is_bitcode(bytes) => Arc::new(problem_member(
                    "LLVM bitcode member (linker-plugin LTO); the real code is generated at link time and cannot be read".into(),
                )),
                Err(_) => return None,
            };
            Some((Member { name, data }, off))
    };
    // Members of one archive are done on one thread unless the archive is big: many
    // archives open at once, each fully mapped, is what makes a run's resident size large.
    let parsed: Vec<Option<(Member, u64)>> = if parallel_members {
        raw.into_par_iter().map(one).collect()
    } else {
        raw.into_iter().map(one).collect()
    };
    let (members, bases) = parsed.into_iter().flatten().unzip();
    (members, bases, None)
}

fn problem_member(why: String) -> MemberData {
    MemberData {
        problem: Some(why),
        ..Default::default()
    }
}

fn is_bitcode(b: &[u8]) -> bool {
    b.starts_with(b"BC\xC0\xDE") || b.starts_with(&[0xDE, 0xC0, 0x17, 0x0B])
}

fn parse_object(bytes: &[u8], assume_subsections: bool) -> MemberBuild {
    let mut m = MemberBuild::default();
    let r = match FileKind::parse(bytes) {
        Ok(FileKind::MachO64) => crate::macho::parse(bytes, &mut m, assume_subsections),
        Ok(FileKind::Elf64) => object::read::elf::ElfFile64::<object::Endianness>::parse(bytes)
            .map_err(|e| format!("unparsable ELF object: {e}"))
            .and_then(|f| crate::elf::parse(&f, &mut m)),
        Ok(FileKind::Elf32) => object::read::elf::ElfFile32::<object::Endianness>::parse(bytes)
            .map_err(|e| format!("unparsable ELF object: {e}"))
            .and_then(|f| crate::elf::parse(&f, &mut m)),
        Ok(other) => Err(format!("{other:?} objects are not supported")),
        Err(e) => Err(format!("not an object file: {e}")),
    };
    if let Err(e) = r {
        m.problem = Some(e);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ld64(records: &[(u8, &str)]) -> Vec<u8> {
        let mut v = vec![0x00];
        v.extend(b"ld 1.0\0");
        for (op, s) in records {
            v.push(*op);
            v.extend(s.as_bytes());
            v.push(0);
        }
        v
    }

    #[test]
    fn ld64_dependency_info_lists_the_inputs_it_read() {
        let d = std::env::temp_dir().join(format!("keel-deps-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("out.deps");
        std::fs::write(
            &f,
            ld64(&[
                (0x10, "/a/libfoo.a"),
                (0x10, "/usr/lib/libSystem.tbd"),
                (0x11, "/missing/libbar.a"),
                (0x40, "/out"),
            ]),
        )
        .unwrap();
        let got = read_dependency_file(&f, "ld64").unwrap();
        assert_eq!(got, [PathBuf::from("/a/libfoo.a"), PathBuf::from("/usr/lib/libSystem.tbd")]);
        // A file cut off in the middle of a record is refused, not read as far as it goes.
        let mut cut = ld64(&[(0x10, "/a/libfoo.a")]);
        cut.pop();
        std::fs::write(&f, cut).unwrap();
        assert!(read_dependency_file(&f, "ld64").unwrap_err().contains("truncated"));
        assert!(read_dependency_file(&f, "nonsense").unwrap_err().contains("not understood"));
        assert!(read_dependency_file(&d.join("absent"), "ld64").unwrap_err().contains("cannot read"));
    }

    #[test]
    fn make_dependency_files_unescape_spaces_and_join_lines() {
        let d = std::env::temp_dir().join(format!("keel-deps-make-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("out.d");
        std::fs::write(&f, "out: /a/libfoo.a /x\\ y/z.o \\\n /usr/lib/libc.so.6\n").unwrap();
        assert_eq!(
            read_dependency_file(&f, "make").unwrap(),
            [
                PathBuf::from("/a/libfoo.a"),
                PathBuf::from("/x y/z.o"),
                PathBuf::from("/usr/lib/libc.so.6")
            ]
        );
    }
}
