//! PC to function: from the runtime address of a basic block to the symbol that
//! contains it, and whether that symbol is Rust or native (C, C++, assembly).
//!
//! Symbol tables are read from the image file with `object`; no debug info is
//! needed, so a stripped-of-DWARF release build still resolves. A target stripped
//! of its symbol table does not, and its functions are reported as `<unknown>`.
//!
//! Language is decided per instrumented module, not per symbol: a Rust codegen
//! unit holds only Rust code, including `#[no_mangle]` functions whose names look
//! like C. A module is Rust when any function symbol inside it carries a Rust
//! mangling (legacy `_ZN..17h<hash>E` or v0 `_R`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use object::{Object, ObjectSymbol, SymbolKind};
use serde::{Deserialize, Serialize};

use crate::sancov::EdgeSpace;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    Rust,
    /// C, C++, Objective-C or assembly: everything that is not Rust.
    Native,
}

/// True for Rust's legacy and v0 manglings. `raw` may carry the extra leading
/// underscore Mach-O adds to every symbol.
pub fn is_rust_mangled(raw: &str) -> bool {
    let s = raw.strip_prefix('_').unwrap_or(raw);
    if let Some(rest) = s.strip_prefix("_ZN") {
        return has_legacy_hash(rest);
    }
    if let Some(rest) = s.strip_prefix("ZN") {
        return has_legacy_hash(rest);
    }
    // v0: _R followed by a path tag (C crate root, N nested, M/X/Y impls...).
    let v0 = raw.strip_prefix("__R").or_else(|| raw.strip_prefix("_R"));
    v0.is_some_and(|r| r.starts_with(['C', 'N', 'M', 'X', 'Y', 'I']))
}

fn has_legacy_hash(rest: &str) -> bool {
    // ...17h0123456789abcdefE
    let Some(body) = rest.strip_suffix('E') else { return false };
    let Some(tail) = body.get(body.len().saturating_sub(17)..) else { return false };
    tail.len() == 17 && tail.starts_with('h') && tail[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// A readable name: Rust symbols demangled without their hash, others as the
/// linker saw them minus Mach-O's extra underscore.
pub fn display_name(raw: &str) -> String {
    if is_rust_mangled(raw) {
        let candidate = if raw.starts_with("__") { &raw[1..] } else { raw };
        return format!("{:#}", rustc_demangle::demangle(candidate));
    }
    raw.strip_prefix('_').unwrap_or(raw).to_string()
}

/// Function symbols of one image, by image-relative address.
#[derive(Debug, Default)]
pub struct SymbolTable {
    funcs: Vec<(u64, String)>,
}

impl SymbolTable {
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let file = object::File::parse(&*data)
            .with_context(|| format!("parsing {} as an object file", path.display()))?;
        let base = file.relative_address_base();
        let mut funcs: Vec<(u64, String)> = file
            .symbols()
            .filter(|s| s.kind() == SymbolKind::Text && s.is_definition())
            .filter_map(|s| Some((s.address().checked_sub(base)?, s.name().ok()?.to_string())))
            .filter(|(_, n)| !n.is_empty())
            .collect();
        funcs.sort();
        funcs.dedup_by_key(|f| f.0);
        Ok(Self { funcs })
    }

    pub fn lookup(&self, rva: u64) -> Option<(u64, &str)> {
        let idx = self.funcs.partition_point(|f| f.0 <= rva);
        let (addr, name) = self.funcs.get(idx.checked_sub(1)?)?;
        Some((*addr, name))
    }

    pub fn len(&self) -> usize {
        self.funcs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.funcs.is_empty()
    }
}

/// A loaded image and its symbols.
#[derive(Debug)]
pub struct Image {
    pub path: PathBuf,
    pub base: usize,
    pub symbols: SymbolTable,
}

/// One function that has at least one edge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub symbol: String,
    pub lang: Lang,
    pub image: String,
    pub edges_total: u32,
}

/// Everything needed to turn a set of edge ids into functions and languages.
#[derive(Debug)]
pub struct Model {
    pub images: Vec<Image>,
    pub functions: Vec<Function>,
    /// Function index for each edge id.
    pub edge_function: Vec<u32>,
    pub edge_lang: Vec<Lang>,
    pub native_edges_total: usize,
    pub rust_edges_total: usize,
}

fn image_of(addr: usize) -> Option<(PathBuf, usize)> {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: dladdr only reads the address and fills `info`.
    if unsafe { libc::dladdr(addr as *const libc::c_void, &mut info) } == 0 || info.dli_fname.is_null() {
        return None;
    }
    // SAFETY: dli_fname is a NUL-terminated path owned by the dynamic loader.
    let name = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }.to_string_lossy().into_owned();
    Some((PathBuf::from(name), info.dli_fbase as usize))
}

impl Model {
    pub fn build(space: &EdgeSpace) -> Result<Self> {
        let mut images: Vec<Image> = Vec::new();
        let mut image_index: HashMap<usize, usize> = HashMap::new();
        let mut module_image: Vec<Option<usize>> = Vec::new();
        for m in &space.modules {
            let idx = match image_of(m.pc(0)) {
                Some((path, base)) => Some(*image_index.entry(base).or_insert_with(|| {
                    let symbols = SymbolTable::load(&path).unwrap_or_else(|e| {
                        eprintln!("keel-fuzz: no symbols for {}: {e:#}; its functions are reported as <unknown>", path.display());
                        SymbolTable::default()
                    });
                    images.push(Image { path, base, symbols });
                    images.len() - 1
                })),
                None => None,
            };
            module_image.push(idx);
        }

        let mut functions: Vec<Function> = Vec::new();
        let mut function_index: HashMap<(usize, u64), u32> = HashMap::new();
        let mut edge_function = vec![0u32; space.total];
        let mut edge_lang = vec![Lang::Native; space.total];
        let mut unknown: HashMap<usize, u32> = HashMap::new();

        for (mi, m) in space.modules.iter().enumerate() {
            let img = module_image[mi];
            // First pass: which function does each edge belong to, and is any of
            // them Rust-mangled (that decides the module's language).
            let mut resolved: Vec<(u32, String)> = Vec::with_capacity(m.len());
            let mut rust_module = false;
            for i in 0..m.len() {
                let found = img.and_then(|ii| {
                    let rva = (m.pc(i) - images[ii].base) as u64;
                    images[ii].symbols.lookup(rva).map(|(a, n)| (ii, a, n.to_string()))
                });
                match found {
                    Some((ii, addr, raw)) => {
                        rust_module |= is_rust_mangled(&raw);
                        let next = functions.len() as u32;
                        let id = *function_index.entry((ii, addr)).or_insert(next);
                        if id == next {
                            functions.push(Function {
                                name: display_name(&raw),
                                symbol: raw.clone(),
                                lang: Lang::Native,
                                image: images[ii].path.display().to_string(),
                                edges_total: 0,
                            });
                        }
                        resolved.push((id, raw));
                    }
                    None => {
                        let key = img.unwrap_or(usize::MAX);
                        let next = functions.len() as u32;
                        let id = *unknown.entry(key).or_insert(next);
                        if id == next {
                            functions.push(Function {
                                name: "<unknown>".into(),
                                symbol: String::new(),
                                lang: Lang::Native,
                                image: img.map(|ii| images[ii].path.display().to_string()).unwrap_or_default(),
                                edges_total: 0,
                            });
                        }
                        resolved.push((id, String::new()));
                    }
                }
            }
            let lang = if rust_module { Lang::Rust } else { Lang::Native };
            for (i, (id, _)) in resolved.into_iter().enumerate() {
                let e = m.first_edge + i;
                edge_function[e] = id;
                edge_lang[e] = lang;
                let f = &mut functions[id as usize];
                f.edges_total += 1;
                f.lang = lang;
            }
        }
        let rust_edges_total = edge_lang.iter().filter(|l| **l == Lang::Rust).count();
        Ok(Self {
            images,
            functions,
            native_edges_total: space.total - rust_edges_total,
            rust_edges_total,
            edge_function,
            edge_lang,
        })
    }

    /// Resolves a runtime PC (e.g. from a sanitizer stack trace) to a display name.
    pub fn name_of_pc(&self, pc: usize) -> Option<String> {
        let img = self.images.iter().filter(|i| pc >= i.base).max_by_key(|i| i.base)?;
        let (_, raw) = img.symbols.lookup((pc - img.base) as u64)?;
        Some(display_name(raw))
    }

    /// (edges covered, of which native) for a set of edge ids.
    pub fn count_split(&self, edges: &[u32]) -> (usize, usize) {
        let native = edges.iter().filter(|e| self.edge_lang[**e as usize] == Lang::Native).count();
        (edges.len(), native)
    }

    /// The functions touched by `edges`, with how many of their edges were hit.
    pub fn covered_functions(&self, edges: &[u32]) -> Vec<CoveredFunction> {
        let mut hits: HashMap<u32, u32> = HashMap::new();
        for e in edges {
            *hits.entry(self.edge_function[*e as usize]).or_default() += 1;
        }
        let mut out: Vec<CoveredFunction> = hits
            .into_iter()
            .map(|(id, edges_hit)| {
                let f = &self.functions[id as usize];
                CoveredFunction {
                    function: f.name.clone(),
                    lang: f.lang,
                    edges_hit,
                    edges_total: f.edges_total,
                    image: f.image.clone(),
                }
            })
            .collect();
        out.sort_by(|a, b| (a.lang as u8, &a.function).cmp(&(b.lang as u8, &b.function)));
        out
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoveredFunction {
    pub function: String,
    pub lang: Lang,
    pub edges_hit: u32,
    pub edges_total: u32,
    pub image: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_manglings_are_recognised_with_and_without_the_macho_underscore() {
        assert!(is_rust_mangled("__ZN14keel_fuzz_demo5parse17h0123456789abcdefE"));
        assert!(is_rust_mangled("_ZN14keel_fuzz_demo5parse17h0123456789abcdefE"));
        assert!(is_rust_mangled("__RNvCsh0fGCXkbek2_14keel_fuzz_demo5parse"));
        assert!(!is_rust_mangled("_keel_demo_decode_record"));
        assert!(!is_rust_mangled("_LLVMFuzzerTestOneInput"));
        // A C++ Itanium symbol has _ZN...E but no Rust hash.
        assert!(!is_rust_mangled("__ZN3foo3barEv"));
        assert!(!is_rust_mangled("__ZN3foo3barE"));
    }

    #[test]
    fn display_names_drop_hashes_and_underscores() {
        assert_eq!(display_name("_keel_demo_decode_record"), "keel_demo_decode_record");
        assert_eq!(
            display_name("__ZN14keel_fuzz_demo5parse17h0123456789abcdefE"),
            "keel_fuzz_demo::parse"
        );
    }

    #[test]
    fn lookup_finds_the_containing_function() {
        let t = SymbolTable { funcs: vec![(0x100, "a".into()), (0x200, "b".into())] };
        assert_eq!(t.lookup(0x100), Some((0x100, "a")));
        assert_eq!(t.lookup(0x1ff), Some((0x100, "a")));
        assert_eq!(t.lookup(0x200), Some((0x200, "b")));
        assert_eq!(t.lookup(0x50), None);
    }
}
