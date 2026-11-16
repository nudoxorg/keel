//! What a parsed object looks like once the object format is forgotten.
//!
//! Everything here is plain data. `macho.rs` and `elf.rs` fill in a `MemberBuild`, which
//! becomes an immutable `MemberData` that `link.rs` reads. A `MemberData` is addressed by
//! the blake3 of the object's bytes, so nothing in it may depend on the path it was found
//! at, or on the archive it was found in. Its big arrays are fixed-layout (`bytemuck::Pod`)
//! so that they can live in a cache file and be used straight from a memory mapping.

use bytemuck::{Pod, Zeroable};
use memmap2::Mmap;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::{Deref, Index};
use std::sync::Arc;

pub type Hash = [u8; 32];
pub const NONE: u32 = u32::MAX;

/// Flags derived from an atom's demangled symbol, so reach queries never
/// demangle: it is done once per object content, not once per test.
pub const F_CURRENT_EXE: u8 = 1;
pub const F_DLOPEN: u8 = 2;
pub const F_COMMAND: u8 = 4;

/// Kind code for "the address of the symbol, page offset part", however the compiler
/// reached it (see `macho::canonicalise`).
pub const ADDR_PAGEOFF: u32 = 0x1000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Code,
    /// `.rodata*`, `.data.rel.ro*`, Mach-O `__const`, `__DATA_CONST`: where test descriptors live.
    RoData,
    Data,
    Bss,
    Tls,
    /// Initialiser and finaliser pointer arrays.
    Init,
}

impl Role {
    pub fn to_u8(self) -> u8 {
        match self {
            Role::Code => 0,
            Role::RoData => 1,
            Role::Data => 2,
            Role::Bss => 3,
            Role::Tls => 4,
            Role::Init => 5,
        }
    }

    pub fn from_u8(b: u8) -> Option<Role> {
        Some(match b {
            0 => Role::Code,
            1 => Role::RoData,
            2 => Role::Data,
            3 => Role::Bss,
            4 => Role::Tls,
            5 => Role::Init,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SectionInfo {
    /// ELF: the section name. Mach-O: `segment,section`. Matches `__start_X` / `section$start$seg$sect`.
    pub key: Box<str>,
    pub role: Role,
    pub class: SecClass,
}

/// What the linker does with a section beyond placing it. Literal sections are split,
/// de-duplicated and reordered by the linker itself, so their pieces (one per string or per
/// fixed-size constant) are the atoms; no code can depend on which piece is next to which.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecClass {
    Plain,
    /// Mach-O S_CSTRING_LITERALS, ELF SHF_MERGE|SHF_STRINGS with one-byte characters.
    CString,
    /// Mach-O S_4BYTE/8BYTE/16BYTE_LITERALS, ELF SHF_MERGE with an entry size.
    Literal,
    /// Language-specific data areas (`__gcc_except_tab`, `.gcc_except_table`). Kept whole:
    /// the unwind entries that bound them are in sections this crate does not read.
    Lsda,
}

impl SecClass {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(b: u8) -> Option<SecClass> {
        Some(match b {
            0 => SecClass::Plain,
            1 => SecClass::CString,
            2 => SecClass::Literal,
            3 => SecClass::Lsda,
            _ => return None,
        })
    }
}

/// What an atom is, for reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AtomClass {
    Text = 0,
    Data = 1,
    Literal = 2,
    CString = 3,
    Lsda = 4,
    Other = 5,
}

impl AtomClass {
    pub fn of(role: Role, class: SecClass) -> AtomClass {
        match (class, role) {
            (SecClass::CString, _) => AtomClass::CString,
            (SecClass::Literal, _) => AtomClass::Literal,
            (SecClass::Lsda, _) => AtomClass::Lsda,
            (_, Role::Code) => AtomClass::Text,
            (_, Role::RoData | Role::Data | Role::Bss | Role::Tls | Role::Init) => AtomClass::Data,
        }
    }

    pub fn name(b: u8) -> &'static str {
        match b {
            0 => "text",
            1 => "data",
            2 => "literal",
            3 => "cstring",
            4 => "lsda",
            _ => "other",
        }
    }
}

/// A relocation target after the object format's addressing has been resolved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RTarget {
    /// Atom index within the same member.
    Atom(u32),
    /// Name index in the member's table; resolved across all inputs at link time.
    Undef(u32),
    /// A constant (absolute symbol); the value is folded into the addend.
    Abs,
}

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct Reloc {
    /// Offset within the atom.
    pub offset: u32,
    /// Format-specific type code, opaque to everything but hashing.
    pub kind: u32,
    /// Includes the offset into the target atom, so equal addends mean equal targets.
    pub addend: i64,
    /// The index half of `RTarget`.
    tv: u32,
    /// The variant half of `RTarget`: 0 atom, 1 undefined name, 2 absolute.
    tk: u8,
    /// Size of the patched field in bytes.
    pub size: u8,
    _pad: [u8; 2],
}

impl Reloc {
    pub fn new(offset: u32, kind: u32, size: u8, addend: i64, target: RTarget) -> Reloc {
        let (tk, tv) = match target {
            RTarget::Atom(a) => (0, a),
            RTarget::Undef(n) => (1, n),
            RTarget::Abs => (2, 0),
        };
        Reloc {
            offset,
            kind,
            addend,
            tv,
            tk,
            size,
            _pad: [0; 2],
        }
    }

    pub fn target(&self) -> RTarget {
        match self.tk {
            0 => RTarget::Atom(self.tv),
            1 => RTarget::Undef(self.tv),
            _ => RTarget::Abs,
        }
    }
}

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct Atom {
    pub section: u32,
    /// Name index of the symbol that starts this atom (global preferred).
    pub symbol: u32,
    /// Index into `MemberData::crates` of the first demangled path segment.
    pub crate_seg: u32,
    pub flags: u8,
    _pad: [u8; 3],
    pub offset: u64,
    pub size: u64,
    /// Offset of the atom's bytes in the object; `u64::MAX` for zero-fill.
    pub file_off: u64,
    /// Range into `MemberData::relocs`.
    pub relocs: [u32; 2],
    /// blake3 of size, bytes with relocation fields zeroed, and each
    /// relocation's offset, kind, size and addend (not its target). Computed
    /// once per object; the Merkle hash adds the targets. This is the atom's `local`.
    pub content: Hash,
    /// The two halves of `content`, separately, 16 bytes each: the atom's bytes with
    /// relocated fields zeroed (and its size), and its relocations' offset, kind, size and
    /// addend. They tell a change of code from a change of what the code points at by offset.
    pub bytes_hash: [u8; 16],
    pub reloc_hash: [u8; 16],
}

impl Atom {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        section: u32,
        offset: u64,
        size: u64,
        file_off: u64,
        relocs: (u32, u32),
        content: Hash,
        symbol: u32,
        crate_seg: u32,
        flags: u8,
        parts: ([u8; 16], [u8; 16]),
    ) -> Atom {
        Atom {
            section,
            symbol,
            crate_seg,
            flags,
            _pad: [0; 3],
            offset,
            size,
            file_off,
            relocs: [relocs.0, relocs.1],
            content,
            bytes_hash: parts.0,
            reloc_hash: parts.1,
        }
    }
}

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct Def {
    pub name: u32,
    pub atom: u32,
    /// Offset of the symbol within the atom (nonzero only for alternate entry points).
    pub off: u32,
    /// 1 for a weak definition.
    pub weak: u32,
}

/// A symbol name inside an atom other than the one that names it. Identical functions
/// that LLVM merged, and `.set`-style aliases, put several names on one range of
/// bytes; all of them stay, because the capability flags are the OR over every name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Alias {
    pub atom: u32,
    pub name: u32,
    /// Offset of the symbol within the atom: 0 for a second name at the atom's own
    /// address, non-zero for an alternate entry point inside it.
    pub off: u32,
}

/// An array that is either on the heap or a view into a memory-mapped cache file.
pub enum Slab<T> {
    Heap(Vec<T>),
    Mapped {
        map: Arc<Mmap>,
        off: usize,
        len: usize,
        _t: PhantomData<T>,
    },
}

impl<T: Pod> Slab<T> {
    /// A view of `len` elements at byte `off` of `map`; `None` if the bytes are not in the
    /// mapping or are not aligned for `T`.
    pub fn mapped(map: &Arc<Mmap>, off: usize, len: usize) -> Option<Slab<T>> {
        let end = off.checked_add(len.checked_mul(std::mem::size_of::<T>())?)?;
        bytemuck::try_cast_slice::<u8, T>(map.get(off..end)?).ok()?;
        Some(Slab::Mapped {
            map: map.clone(),
            off,
            len,
            _t: PhantomData,
        })
    }
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Slab::Heap(Vec::new())
    }
}

impl<T> From<Vec<T>> for Slab<T> {
    fn from(v: Vec<T>) -> Self {
        Slab::Heap(v)
    }
}

impl<T: Pod> Deref for Slab<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        match self {
            Slab::Heap(v) => v,
            Slab::Mapped { map, off, len, .. } => {
                // `mapped` checked the range and the alignment, and the mapping is read-only.
                bytemuck::cast_slice(&map[*off..*off + *len * std::mem::size_of::<T>()])
            }
        }
    }
}

impl<T: Pod + std::fmt::Debug> std::fmt::Debug for Slab<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Slab({} items)", self.len())
    }
}

/// The 128-bit identity of a symbol name: how names are matched across inputs. Collisions
/// among a few million names are not a practical concern at this width, so matched names
/// are not compared again by text.
pub fn name_id(s: &str) -> [u64; 2] {
    let h = blake3::hash(s.as_bytes());
    let b = h.as_bytes();
    [
        u64::from_le_bytes(b[..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..16].try_into().unwrap()),
    ]
}

/// The text of a member's symbol names: contiguous bytes with end offsets and a 128-bit
/// identity per name. In a cache file the text stays on disk until a name is read, and
/// most names (undefined references, atoms nothing reaches) never are.
#[derive(Default, Debug)]
pub struct Names {
    pub ids: Slab<[u64; 2]>,
    pub ends: Slab<u32>,
    pub text: Text,
}

#[derive(Debug)]
pub enum Text {
    Heap(Vec<u8>),
    Mapped {
        map: Arc<Mmap>,
        off: usize,
        len: usize,
    },
}

impl Default for Text {
    fn default() -> Self {
        Text::Heap(Vec::new())
    }
}

impl Text {
    fn bytes(&self) -> &[u8] {
        match self {
            Text::Heap(v) => v,
            Text::Mapped { map, off, len } => &map[*off..*off + *len],
        }
    }
}

impl Names {
    pub fn from_items(items: &[Box<str>]) -> Names {
        let mut text = Vec::with_capacity(items.iter().map(|s| s.len()).sum());
        let (mut ids, mut ends) = (Vec::with_capacity(items.len()), Vec::with_capacity(items.len()));
        for s in items {
            text.extend_from_slice(s.as_bytes());
            ids.push(name_id(s));
            ends.push(text.len() as u32);
        }
        Names {
            ids: ids.into(),
            ends: ends.into(),
            text: Text::Heap(text),
        }
    }

    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    pub fn get(&self, i: usize) -> &str {
        let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
        let end = self.ends[i] as usize;
        // Valid UTF-8 when written (names are interned lossily); a damaged cache entry is
        // caught by its checksum before it gets here, but never trust bytes to be text.
        std::str::from_utf8(&self.text.bytes()[start..end]).unwrap_or("<invalid utf-8>")
    }

    pub fn id(&self, i: usize) -> [u64; 2] {
        self.ids[i]
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        (0..self.len()).map(|i| self.get(i))
    }

    /// Total bytes of name text.
    pub fn text_len(&self) -> usize {
        self.text.bytes().len()
    }

    pub fn text_bytes(&self) -> &[u8] {
        self.text.bytes()
    }
}

impl Index<usize> for Names {
    type Output = str;
    fn index(&self, i: usize) -> &str {
        self.get(i)
    }
}

/// An object while a parser is filling it in.
#[derive(Default, Debug)]
pub struct MemberBuild {
    pub sections: Vec<SectionInfo>,
    pub atoms: Vec<Atom>,
    pub relocs: Vec<Reloc>,
    pub names: Vec<Box<str>>,
    pub crates: Vec<Box<str>>,
    pub aliases: Vec<Alias>,
    pub defs: Vec<Def>,
    pub roots: Vec<u32>,
    pub whole_sections: bool,
    pub problem: Option<String>,
}

impl MemberBuild {
    pub fn finish(self) -> MemberData {
        MemberData {
            sections: self.sections,
            atoms: self.atoms.into(),
            relocs: self.relocs.into(),
            names: Names::from_items(&self.names),
            crates: self.crates,
            aliases: self.aliases.into(),
            defs: self.defs.into(),
            roots: self.roots.into(),
            whole_sections: self.whole_sections,
            problem: self.problem,
        }
    }
}

/// A parsed object, by content. Immutable.
#[derive(Default, Debug)]
pub struct MemberData {
    pub sections: Vec<SectionInfo>,
    pub atoms: Slab<Atom>,
    pub relocs: Slab<Reloc>,
    pub names: Names,
    pub crates: Vec<Box<str>>,
    /// Sorted by atom, then by offset and symbol-table order: every symbol inside an
    /// atom except the one in `Atom::symbol`.
    pub aliases: Slab<Alias>,
    pub defs: Slab<Def>,
    /// Atoms in initialiser or TLS sections: harness roots.
    pub roots: Slab<u32>,
    /// A Mach-O object without MH_SUBSECTIONS_VIA_SYMBOLS: every section is one atom.
    pub whole_sections: bool,
    /// Why this member cannot be trusted, if so; the binary becomes unverifiable.
    pub problem: Option<String>,
}

/// An object as one link input holds it: its content, and the name this input gave it.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub data: Arc<MemberData>,
}

impl Deref for Member {
    type Target = MemberData;
    fn deref(&self) -> &MemberData {
        &self.data
    }
}

impl MemberData {
    /// Tell the system this object's pages are no longer needed: a cache-backed object's
    /// mapped pages stay in the process's resident set once touched, though they are clean
    /// and a read brings them back. Without this a run's resident size grows to the size of
    /// everything it ever read.
    pub fn release_pages(&self) {
        if let Text::Mapped { map, .. } = &self.names.text {
            // SAFETY: the mapping is a read-only view of a file; dropping its pages from
            // memory changes nothing a later read can see.
            let _ = unsafe { map.unchecked_advise(memmap2::UncheckedAdvice::DontNeed) };
        }
    }

    pub fn atom_relocs(&self, a: &Atom) -> &[Reloc] {
        &self.relocs[a.relocs[0] as usize..a.relocs[1] as usize]
    }

    /// The aliases of atom `ai`, a slice of the sorted alias table.
    pub fn aliases_of(&self, ai: u32) -> &[Alias] {
        let lo = self.aliases.partition_point(|x| x.atom < ai);
        let hi = lo + self.aliases[lo..].partition_point(|x| x.atom == ai);
        &self.aliases[lo..hi]
    }

    /// Every name defined inside atom `ai`: the naming symbol first, then the aliases.
    pub fn names_of(&self, ai: u32) -> impl Iterator<Item = u32> + '_ {
        let sym = self.atoms[ai as usize].symbol;
        (sym != NONE)
            .then_some(sym)
            .into_iter()
            .chain(self.aliases_of(ai).iter().map(|a| a.name))
    }
}

/// Interns strings into a vector and hands out indices.
#[derive(Default)]
pub struct Interner {
    map: HashMap<Box<str>, u32>,
    pub items: Vec<Box<str>>,
}

impl Interner {
    pub fn intern_lossy(&mut self, b: &[u8]) -> u32 {
        self.intern(&String::from_utf8_lossy(b))
    }

    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&i) = self.map.get(s) {
            return i;
        }
        let i = self.items.len() as u32;
        self.items.push(s.into());
        self.map.insert(s.into(), i);
        i
    }
}

/// `align` is the section's alignment in bytes where atoms are delimited by symbols in a shared
/// section (Mach-O), 0 where an atom is exactly its section (ELF).
///
/// A Mach-O atom runs to the next symbol, so it ends in whatever alignment padding the
/// next atom needed, and that depends on layout, not on the program (the same string
/// constant measured 53 bytes in one build and 48 in another). Trailing zero bytes are
/// therefore left out of the hashed bytes and the size enters rounded up to the section
/// alignment. Padding is shorter than the next atom's alignment, which divides the
/// section's, so the rounded size does not see it, while the content still sees every
/// non-zero byte. What this cannot see is a change in the number of genuine trailing
/// zero bytes that stays inside one alignment unit; code that uses such a constant also
/// embeds its length.
pub fn content_hash(size: u64, align: u64, zeroed: &[u8], relocs: &[Reloc]) -> Hash {
    content_parts(size, align, zeroed, relocs).0
}

/// `content_hash`, and its bytes and relocation halves hashed on their own (truncated).
pub fn content_parts(
    size: u64,
    align: u64,
    zeroed: &[u8],
    relocs: &[Reloc],
) -> (Hash, ([u8; 16], [u8; 16])) {
    let (len, bytes) = if align == 0 {
        (size, zeroed)
    } else {
        let end = zeroed.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        (size.div_ceil(align), &zeroed[..end])
    };
    let mut h = blake3::Hasher::new();
    h.update(b"keel-reach/atom-content/2");
    h.update(&len.to_le_bytes());
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    let mut b = blake3::Hasher::new();
    b.update(b"keel-reach/atom-bytes/1");
    b.update(&len.to_le_bytes());
    b.update(&(bytes.len() as u64).to_le_bytes());
    b.update(bytes);
    let mut rh = blake3::Hasher::new();
    rh.update(b"keel-reach/atom-relocs/1");
    for r in relocs {
        let fields = [
            &r.offset.to_le_bytes()[..],
            &r.kind.to_le_bytes(),
            &[r.size],
            &r.addend.to_le_bytes(),
        ];
        for f in fields {
            h.update(f);
            rh.update(f);
        }
    }
    let cut = |x: blake3::Hash| -> [u8; 16] { x.as_bytes()[..16].try_into().unwrap() };
    (*h.finalize().as_bytes(), (cut(b.finalize()), cut(rh.finalize())))
}

/// One section while a member is being built.
pub struct SecBuild {
    pub info: SectionInfo,
    pub size: u64,
    /// Section alignment in bytes for shared-section formats, 0 for exact atoms (see `content_hash`).
    pub align: u64,
    /// Offset of the section's bytes in the object, `None` for zero-fill.
    pub file_off: Option<u64>,
    /// Section bytes with relocation fields zeroed; empty for zero-fill.
    pub bytes: Vec<u8>,
    /// Atom start offsets, sorted and unique, beginning at 0.
    pub starts: Vec<u64>,
    /// Relocations with offsets relative to the section start.
    pub relocs: Vec<Reloc>,
    /// Symbols (offset in section, name index) used to name atoms.
    pub syms: Vec<(u64, u32, bool)>,
}

/// Capability flags carried by a text: the demangled path of a Rust symbol, or the
/// raw name of anything else.
fn flags_of_text(text: &str) -> u8 {
    let mut flags = 0;
    // `std::env::current_exe` is `#[inline]` and often vanishes into its caller, leaving only
    // the platform function, so match the leaf name.
    if text.contains("current_exe") {
        flags |= F_CURRENT_EXE;
    }
    if text.contains("dlopen") || text.contains("libloading") || text.contains("dlsym") {
        flags |= F_DLOPEN;
    }
    if text.contains("std::process::Command") {
        flags |= F_COMMAND;
    }
    flags
}

/// Demangled-path facts about a symbol. Mach-O prefixes C-level names with `_`,
/// which `rustc_demangle` strips itself.
pub fn symbol_facts(name: &str) -> Option<(String, u8)> {
    let d = rustc_demangle::try_demangle(name).ok()?;
    let text = format!("{d:#}");
    let flags = flags_of_text(&text);
    Some((text, flags))
}

/// Every flag needs one of these literally in the mangled name: both manglings spell
/// identifiers out (legacy escapes only punctuation, v0 length-prefixes), and the
/// demangled path is made of those identifiers. A name without any of them has no flags,
/// which spares demangling the other 99.9% of two and a half million names.
const NEEDLES: [&str; 5] = ["current_exe", "dlopen", "libloading", "dlsym", "Command"];

/// The flags of one symbol name, whatever language it came from. A name that is not
/// Rust-mangled (a C function from a bundled library, an assembler label) has no
/// demangled path to match, so its raw text is matched instead: that can only flag
/// more atoms than the demangled form would, never fewer.
pub fn name_flags(name: &str) -> u8 {
    if !NEEDLES.iter().any(|n| name.contains(n)) {
        return 0;
    }
    symbol_facts(name).map_or_else(|| flags_of_text(name), |(_, f)| f)
}

/// The demangled text of a symbol for display, or the raw name if it is not Rust-mangled.
pub fn display_name(name: &str) -> String {
    symbol_facts(name).map_or_else(|| name.to_string(), |x| x.0)
}

/// First path segment of a demangled name: `core` for `core::ptr::drop_in_place<..>`,
/// `c001` for `<c001::Foo as core::fmt::Debug>::fmt`.
pub fn crate_of(demangled: &str) -> &str {
    let s = demangled.trim_start_matches(['<', '&', '*', ' ']);
    let s = s.strip_prefix("mut ").unwrap_or(s);
    let end = s
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    &s[..end]
}

/// Assemble atoms, relocations, defs and symbol facts from per-section builds.
/// `defs` holds (name index, section, offset in section, weak) for every
/// externally visible definition.
pub fn assemble(m: &mut MemberBuild, secs: Vec<SecBuild>, defs: &[(u32, u32, u64, bool)]) {
    let mut crate_ix = Interner::default();
    let mut atom_base = Vec::with_capacity(secs.len());
    let mut secs = secs;
    for s in &mut secs {
        // Stable, so names at one offset keep the symbol table's order.
        s.syms.sort_by_key(|x| x.0);
        s.relocs.sort_by_key(|r| r.offset);
    }
    for (si, s) in secs.iter().enumerate() {
        atom_base.push(m.atoms.len() as u32);
        m.sections.push(s.info.clone());
        let relocs = &s.relocs;
        let mut ri = 0;
        for (k, &start) in s.starts.iter().enumerate() {
            let end = s.starts.get(k + 1).copied().unwrap_or(s.size);
            let first = m.relocs.len() as u32;
            while ri < relocs.len() && u64::from(relocs[ri].offset) < end {
                let mut r = relocs[ri];
                r.offset -= start as u32;
                m.relocs.push(r);
                ri += 1;
            }
            let rr = (first, m.relocs.len() as u32);
            let bytes = if s.file_off.is_some() {
                &s.bytes[start as usize..end as usize]
            } else {
                &[][..]
            };
            // Prefer a global symbol, then the lowest name index, so the choice
            // is a function of the object alone.
            let lo = s.syms.partition_point(|x| x.0 < start);
            let hi = lo + s.syms[lo..].partition_point(|x| x.0 < end);
            let inside = &s.syms[lo..hi];
            let at_start = &inside[..inside.partition_point(|x| x.0 == start)];
            let sym = at_start
                .iter()
                .min_by_key(|(_, n, g)| (!*g, *n))
                .map(|x| x.1);
            let mut crate_seg = NONE;
            // Only code is attributed to a crate by its name; data is attributed to the
            // crate of the input it came from.
            if s.info.role == Role::Code {
                for (_, n, _) in at_start {
                    if let Some((text, _)) = symbol_facts(&m.names[*n as usize])
                        && (crate_seg == NONE || Some(*n) == sym)
                    {
                        crate_seg = crate_ix.intern(crate_of(&text));
                    }
                }
            }
            // Capabilities are the OR over every name inside the atom, at its start or at
            // an alternate entry point, so which name is printed never changes the verdict.
            let ai = m.atoms.len() as u32;
            let mut flags = 0u8;
            for &(o, n, _) in inside {
                flags |= name_flags(&m.names[n as usize]);
                if Some(n) != sym {
                    m.aliases.push(Alias {
                        atom: ai,
                        name: n,
                        off: (o - start) as u32,
                    });
                }
            }
            let size = end - start;
            let (content, parts) =
                content_parts(size, s.align, bytes, &m.relocs[rr.0 as usize..rr.1 as usize]);
            m.atoms.push(Atom::new(
                si as u32,
                start,
                size,
                s.file_off.map_or(u64::MAX, |f| f + start),
                rr,
                content,
                sym.unwrap_or(NONE),
                crate_seg,
                flags,
                parts,
            ));
            if matches!(s.info.role, Role::Init | Role::Tls) {
                m.roots.push(m.atoms.len() as u32 - 1);
            }
        }
    }
    for &(name, sec, off, weak) in defs {
        let s = &secs[sec as usize];
        let k = s.starts.partition_point(|&x| x <= off).saturating_sub(1);
        let atom = atom_base[sec as usize] + k as u32;
        m.defs.push(Def {
            name,
            atom,
            off: (off - s.starts[k]) as u32,
            weak: u32::from(weak),
        });
    }
    m.crates = crate_ix.items;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_segment_of_demangled_names() {
        assert_eq!(crate_of("core::ptr::drop_in_place<c001::X>"), "core");
        assert_eq!(crate_of("<c001::Foo as core::fmt::Debug>::fmt"), "c001");
        assert_eq!(crate_of("<&mut W as core::fmt::Write>::write_str"), "W");
        assert_eq!(crate_of("main"), "main");
    }

    #[test]
    fn facts_flag_exec_and_loader_calls() {
        let (t, f) = symbol_facts("_ZN3std3env11current_exe17h0123456789abcdefE").unwrap();
        assert_eq!(t, "std::env::current_exe");
        assert_eq!(f & F_CURRENT_EXE, F_CURRENT_EXE);
        let (_, f) = symbol_facts("__ZN3std7process7Command3new17h0123456789abcdefE").unwrap();
        assert_eq!(f, F_COMMAND, "a leading Mach-O underscore is understood");
        assert!(symbol_facts("_malloc").is_none());
    }

    #[test]
    fn the_needle_prefilter_never_hides_a_flag() {
        // Legacy and v0 manglings of the flagged paths, and a plain C name.
        for n in [
            "_ZN3std3env11current_exe17h0123456789abcdefE",
            "_ZN10libloading2os4unix7Library3new17h0123456789abcdefE",
            "_ZN3std7process7Command3new17h0123456789abcdefE",
            "_RNvNtCs1234_3std3env11current_exe",
            "_RNvMNtCs1234_3std7processNtB2_7Command3new",
            "dlopen",
            "_dlsym",
        ] {
            let slow = symbol_facts(n).map_or_else(|| flags_of_text(n), |(_, f)| f);
            assert_eq!(name_flags(n), slow, "{n}");
        }
        assert_ne!(name_flags("_ZN3std3env11current_exe17h0123456789abcdefE"), 0);
        assert_eq!(name_flags("_ZN4core3ptr13drop_in_place17h0123456789abcdefE"), 0);
    }

    #[test]
    fn names_round_trip_with_stable_identities() {
        let n = Names::from_items(&["a".into(), "".into(), "_ZN1b1cE".into()]);
        assert_eq!((n.get(0), n.get(1), n.get(2)), ("a", "", "_ZN1b1cE"));
        assert_eq!(n.id(2), name_id("_ZN1b1cE"));
        assert_ne!(n.id(0), n.id(2));
        assert_eq!(&n[2], "_ZN1b1cE");
    }
}
