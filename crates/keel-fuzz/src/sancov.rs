//! The SanitizerCoverage runtime: where instrumented code (Rust and C alike)
//! registers its counters and PC tables.
//!
//! LLVM's module constructors call `__sanitizer_cov_8bit_counters_init(start, stop)`
//! and then `__sanitizer_cov_pcs_init(begin, end)` once per instrumented object,
//! Rust codegen unit or C translation unit. We record both and pair them in call
//! order, which gives every edge a PC, and with it a function and a language.
//! The compare callbacks (`__sanitizer_cov_trace_cmp*`) are not defined here: they
//! come from `libafl_targets`, which feeds cmplog (input-to-state) and value profile.
//!
//! The pairing relies on LLVM emitting the two calls from the same constructor,
//! which holds for the LLVM versions used by rustc 1.99 and Apple clang 17; `edge_space`
//! checks that every pair has the same number of counters as PC-table entries and
//! refuses to continue otherwise rather than mislabelling edges.

use std::sync::Mutex;

use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Region {
    start: usize,
    end: usize,
}

static COUNTERS: Mutex<Vec<Region>> = Mutex::new(Vec::new());
static PCS: Mutex<Vec<Region>> = Mutex::new(Vec::new());

fn register(list: &Mutex<Vec<Region>>, start: usize, end: usize) {
    if start >= end {
        return;
    }
    let mut list = list.lock().unwrap_or_else(|e| e.into_inner());
    let region = Region { start, end };
    // A module that is initialised twice (some linkers duplicate constructors) must
    // not appear twice, or its edges would be counted twice.
    if !list.contains(&region) {
        list.push(region);
    }
}

/// # Safety
/// Called by instrumented module constructors with the bounds of their counter section.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8) {
    register(&COUNTERS, start as usize, stop as usize);
}

/// # Safety
/// Called by instrumented module constructors with the bounds of their PC table.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_pcs_init(begin: *const usize, end: *const usize) {
    register(&PCS, begin as usize, end as usize);
}

/// One registered object: a contiguous run of counters and the PC table that
/// describes them.
#[derive(Clone, Copy, Debug)]
pub struct Module {
    counters: *mut u8,
    len: usize,
    pcs: *const [usize; 2],
    /// Edge id of this module's first counter in the whole edge space.
    pub first_edge: usize,
}

// SAFETY: the pointers refer to static sections of loaded images that live as long
// as the process (targets are never unloaded).
unsafe impl Send for Module {}
unsafe impl Sync for Module {}

impl Module {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// The runtime address of the basic block behind counter `i` of this module.
    pub fn pc(&self, i: usize) -> usize {
        debug_assert!(i < self.len);
        // SAFETY: bounds-checked against the table length verified in `edge_space`.
        unsafe { (*self.pcs.add(i))[0] }
    }
    /// PC-table flag bit 0: this block is a function entry.
    pub fn is_function_entry(&self, i: usize) -> bool {
        // SAFETY: as in `pc`.
        unsafe { (*self.pcs.add(i))[1] & 1 == 1 }
    }
    pub fn counters(&self) -> *mut u8 {
        self.counters
    }
    /// The counters as a slice. The target mutates them concurrently with any
    /// reader, which is the point of coverage; callers read after the target returns.
    ///
    /// # Safety
    /// No other `&mut` to the same counters may be live.
    pub unsafe fn counters_slice(&self) -> &'static mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.counters, self.len) }
    }
}

/// Every edge of every instrumented object loaded so far, numbered 0..total in
/// registration order.
#[derive(Debug)]
pub struct EdgeSpace {
    pub modules: Vec<Module>,
    pub total: usize,
}

/// Snapshots the registered modules. Call it after the target is loaded.
pub fn edge_space() -> Result<EdgeSpace> {
    let counters = COUNTERS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let pcs = PCS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if counters.is_empty() {
        bail!(
            "the target registered no coverage counters: it was built without -fsanitize-coverage=inline-8bit-counters (C) or the sancov flags (Rust); rebuild it with bench/fuzz/build-target.nu"
        );
    }
    if counters.len() != pcs.len() {
        bail!(
            "the target registered {} counter sections but {} PC tables; edges cannot be tied to code. Build every object with both inline-8bit-counters and pc-table (bench/fuzz/build-target.nu does)",
            counters.len(),
            pcs.len()
        );
    }
    let mut modules = Vec::with_capacity(counters.len());
    let mut first_edge = 0usize;
    for (c, p) in counters.iter().zip(pcs.iter()) {
        let len = c.end - c.start;
        let entries = (p.end - p.start) / (2 * size_of::<usize>());
        if entries != len {
            bail!(
                "a coverage module has {len} counters but a PC table of {entries} entries (counter section at {:#x}, PC table at {:#x}); the two registration calls did not come from the same object. Rebuild the target with bench/fuzz/build-target.nu",
                c.start,
                p.start
            );
        }
        modules.push(Module {
            counters: c.start as *mut u8,
            len,
            pcs: p.start as *const [usize; 2],
            first_edge,
        });
        first_edge += len;
    }
    Ok(EdgeSpace { modules, total: first_edge })
}

impl EdgeSpace {
    /// Zeroes every counter. Called before each execution whose coverage is wanted.
    pub fn reset(&self) {
        for m in &self.modules {
            // SAFETY: the section is writable process memory owned by the target image.
            unsafe { std::ptr::write_bytes(m.counters, 0, m.len) };
        }
    }

    /// Appends the ids of the edges hit since the last `reset`, ascending.
    pub fn hit_edges(&self, out: &mut Vec<u32>) {
        for m in &self.modules {
            // SAFETY: read after the target returned; counters are plain bytes.
            let slice = unsafe { std::slice::from_raw_parts(m.counters, m.len) };
            for (i, &c) in slice.iter().enumerate() {
                if c != 0 {
                    out.push((m.first_edge + i) as u32);
                }
            }
        }
    }

    /// Writes 1 into `dst[edge]` for every edge hit. Async-signal-safe: no
    /// allocation, no locks; used from the crash handler of an isolated run.
    ///
    /// # Safety
    /// `dst` must point to `self.total` writable bytes.
    pub unsafe fn snapshot_into(&self, dst: *mut u8) {
        for m in &self.modules {
            for i in 0..m.len {
                // SAFETY: i < m.len and first_edge + i < total.
                unsafe {
                    if *m.counters.add(i) != 0 {
                        *dst.add(m.first_edge + i) = 1;
                    }
                }
            }
        }
    }

    /// The PC of an edge, and whether it is a function entry.
    pub fn pc_of(&self, edge: usize) -> Option<(usize, bool)> {
        let m = self.module_of(edge)?;
        let i = edge - m.first_edge;
        Some((m.pc(i), m.is_function_entry(i)))
    }

    pub fn module_index_of(&self, edge: usize) -> Option<usize> {
        self.modules.iter().position(|m| edge >= m.first_edge && edge < m.first_edge + m.len)
    }

    fn module_of(&self, edge: usize) -> Option<&Module> {
        self.module_index_of(edge).map(|i| &self.modules[i])
    }
}
