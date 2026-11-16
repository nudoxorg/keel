//! One parsed object on disk.
//!
//! Parsing 4,500 objects takes most of a cold run, and almost all of them are the same
//! from one build to the next, so a parsed object is kept in a file named by the blake3 of
//! the object's bytes. The file is laid out so that it can be used where it lies: the large
//! arrays are fixed-layout records at 8-byte-aligned offsets, which a `Slab::Mapped`
//! reads through a memory mapping, and the symbol names' text is never copied to the heap.
//!
//! ```text
//! magic(8) | n_atoms n_relocs n_defs n_aliases n_roots n_names text_len small_len flags (9 x u64)
//! small block (sections, crates, problem; varints and strings) | pad to 8
//! atoms | relocs | defs | aliases | roots (pad) | name ids | name ends (pad) | name text (pad)
//! blake3 of everything above (32)
//! ```
//!
//! A file whose size, magic or checksum is wrong is a miss, never an error: it is parsed
//! again and replaced. Which parser produced it is part of the directory name, so changing
//! how objects are read cannot serve results from the old way.

use crate::model::*;
use memmap2::Mmap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAGIC: &[u8; 8] = b"KEELMEM1";
const HEADER_WORDS: usize = 9;

/// Bump when what a parser produces changes. Part of the cache directory's name.
pub const FORMAT: &str = "m2";

/// Where an object with this content hash lives.
pub fn entry_path(dir: &Path, assume_subsections: bool, hash: &Hash) -> PathBuf {
    let hex = crate::load::hex(hash);
    dir.join(format!("{FORMAT}{}", if assume_subsections { "-sub" } else { "" }))
        .join(&hex[..2])
        .join(&hex[2..])
}

struct W(Vec<u8>);

impl W {
    fn u(&mut self, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.0.push(b);
                return;
            }
            self.0.push(b | 0x80);
        }
    }

    fn s(&mut self, s: &str) {
        self.u(s.len() as u64);
        self.0.extend_from_slice(s.as_bytes());
    }

    fn align(&mut self) {
        while !self.0.len().is_multiple_of(8) {
            self.0.push(0);
        }
    }

    fn pod<T: bytemuck::Pod>(&mut self, v: &[T]) {
        self.0.extend_from_slice(bytemuck::cast_slice(v));
        self.align();
    }
}

pub fn encode(d: &MemberData) -> Vec<u8> {
    let mut small = W(Vec::new());
    small.u(d.sections.len() as u64);
    for s in &d.sections {
        small.0.push(s.role.to_u8());
        small.0.push(s.class.to_u8());
        small.s(&s.key);
    }
    small.u(d.crates.len() as u64);
    for c in &d.crates {
        small.s(c);
    }
    match &d.problem {
        Some(p) => {
            small.u(1);
            small.s(p);
        }
        None => small.u(0),
    }
    let text = d.names.text_bytes();
    let mut w = W(Vec::with_capacity(128 + small.0.len() + text.len() + d.relocs.len() * 24));
    w.0.extend_from_slice(MAGIC);
    for v in [
        d.atoms.len(),
        d.relocs.len(),
        d.defs.len(),
        d.aliases.len(),
        d.roots.len(),
        d.names.len(),
        text.len(),
        small.0.len(),
        usize::from(d.whole_sections),
    ] {
        w.0.extend_from_slice(&(v as u64).to_le_bytes());
    }
    w.0.extend_from_slice(&small.0);
    w.align();
    w.pod(&d.atoms);
    w.pod(&d.relocs);
    w.pod(&d.defs);
    w.pod(&d.aliases);
    w.pod(&d.roots);
    w.pod(&d.names.ids);
    w.pod(&d.names.ends);
    w.0.extend_from_slice(text);
    w.align();
    let sum = blake3::hash(&w.0);
    w.0.extend_from_slice(sum.as_bytes());
    w.0
}

struct R<'a> {
    b: &'a [u8],
    at: usize,
}

impl R<'_> {
    fn u(&mut self) -> Option<u64> {
        let (mut v, mut shift) = (0u64, 0);
        loop {
            let b = *self.b.get(self.at)?;
            self.at += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    }

    fn s(&mut self) -> Option<&str> {
        let n = self.u()? as usize;
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        std::str::from_utf8(s).ok()
    }
}

fn pad8(n: usize) -> usize {
    n.next_multiple_of(8)
}

/// Check a file's checksum without keeping it in memory, then map it.
pub fn open(path: &Path) -> Option<Arc<Mmap>> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if len < (8 + 8 * HEADER_WORDS + 32) as u64 {
        return None;
    }
    let body = len - 32;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut left = body;
    use std::io::Read;
    while left > 0 {
        let want = buf.len().min(left as usize);
        let n = f.read(&mut buf[..want]).ok()?;
        if n == 0 {
            return None;
        }
        h.update(&buf[..n]);
        left -= n as u64;
    }
    let mut stored = [0u8; 32];
    f.read_exact(&mut stored).ok()?;
    if h.finalize().as_bytes() != &stored {
        return None;
    }
    // SAFETY: read-only mapping of a file this crate writes by rename and never modifies.
    let map = unsafe { Mmap::map(&f) }.ok()?;
    Some(Arc::new(map))
}

/// The object a verified cache file holds, used in place.
pub fn decode(map: &Arc<Mmap>) -> Option<MemberData> {
    let b: &[u8] = map;
    if b.get(..8)? != MAGIC {
        return None;
    }
    let word = |i: usize| -> Option<usize> {
        Some(u64::from_le_bytes(b.get(8 + 8 * i..16 + 8 * i)?.try_into().ok()?) as usize)
    };
    let (n_atoms, n_relocs, n_defs, n_aliases, n_roots, n_names, text_len, small_len, whole) = (
        word(0)?, word(1)?, word(2)?, word(3)?, word(4)?, word(5)?, word(6)?, word(7)?, word(8)?,
    );
    let mut at = 8 + 8 * HEADER_WORDS;
    let mut r = R { b, at };
    r.b = b.get(..at + small_len)?;
    let mut sections = Vec::new();
    for _ in 0..r.u()? {
        let role = Role::from_u8(*r.b.get(r.at)?)?;
        let class = SecClass::from_u8(*r.b.get(r.at + 1)?)?;
        r.at += 2;
        sections.push(SectionInfo { key: r.s()?.into(), role, class });
    }
    let mut crates = Vec::new();
    for _ in 0..r.u()? {
        crates.push(Box::<str>::from(r.s()?));
    }
    let problem = if r.u()? == 1 { Some(r.s()?.to_string()) } else { None };
    if r.at != at + small_len {
        return None;
    }
    at = pad8(at + small_len);
    let mut take = |count: usize, size: usize| -> usize {
        let o = at;
        at = pad8(at + count * size);
        o
    };
    let atoms_at = take(n_atoms, std::mem::size_of::<Atom>());
    let relocs_at = take(n_relocs, std::mem::size_of::<Reloc>());
    let defs_at = take(n_defs, std::mem::size_of::<Def>());
    let aliases_at = take(n_aliases, std::mem::size_of::<Alias>());
    let roots_at = take(n_roots, 4);
    let ids_at = take(n_names, 16);
    let ends_at = take(n_names, 4);
    let text_at = take(text_len, 1);
    if at + 32 != b.len() {
        return None;
    }
    let ends: Slab<u32> = Slab::mapped(map, ends_at, n_names)?;
    if ends.last().is_some_and(|&e| e as usize > text_len) {
        return None;
    }
    Some(MemberData {
        sections,
        atoms: Slab::mapped(map, atoms_at, n_atoms)?,
        relocs: Slab::mapped(map, relocs_at, n_relocs)?,
        names: Names {
            ids: Slab::mapped(map, ids_at, n_names)?,
            ends,
            text: Text::Mapped {
                map: map.clone(),
                off: text_at,
                len: text_len,
            },
        },
        crates,
        aliases: Slab::mapped(map, aliases_at, n_aliases)?,
        defs: Slab::mapped(map, defs_at, n_defs)?,
        roots: Slab::mapped(map, roots_at, n_roots)?,
        whole_sections: whole == 1,
        problem,
    })
}

/// Write an entry by rename, so a reader sees all of it or none.
pub fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}-{:?}", std::process::id(), std::thread::current().id()));
    let mut f = File::create(&tmp)?;
    f.write_all(bytes)?;
    f.flush()?;
    drop(f);
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}
