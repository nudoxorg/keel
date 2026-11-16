//! `generate`: lay out the crate DAG, then write every crate in parallel.
//! The generator computes every expected value itself (combined(), filler
//! results, fixture first lines) and writes it as a literal, so a test failing
//! in a pristine workspace is a generator bug and a test failing after a
//! mutation is exactly the flip the mutation predicted.

use crate::model::{Asserts, CrateInfo, Synth, TestInfo};
use crate::rng::Rng;
use anyhow::{Context, Result, bail};
use clap::Args;
use rayon::prelude::*;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct GenerateArgs {
    /// Directory to create; must be absent or empty.
    #[arg(long)]
    pub out: PathBuf,
    /// Preset from BENCH.md section 2: S, M or L (default S). Explicit flags override it.
    #[arg(long)]
    pub shape: Option<String>,
    #[arg(long)]
    pub crates: Option<usize>,
    /// Number of levels; the longest dependency chain has exactly this many crates.
    #[arg(long)]
    pub depth: Option<usize>,
    /// Dependencies per non-root crate (at least 1, fewer when fewer exist below).
    #[arg(long)]
    pub fan_in: Option<usize>,
    #[arg(long)]
    pub tests_per_crate: Option<usize>,
    #[arg(long)]
    pub integration_bins_per_crate: Option<usize>,
    /// Target length of the non-test part of each lib.rs.
    #[arg(long)]
    pub lines_per_crate: Option<usize>,
    #[arg(long)]
    pub fixtures_per_crate: Option<usize>,
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    /// Give every level-0 crate the source-position-sensitive features of `LINE_FEATURES` and
    /// every direct dependent a `tests/line_oracle.rs` calling them. Off by default so the
    /// shapes of BENCH.md keep their quoted test counts.
    #[arg(long)]
    pub line_oracle: bool,
    /// `default`, or `backend`: the real backend's dev profile (`debug = 1`, incremental, and
    /// `opt-level = 2` for the level-0 crates, which stand in for its foundation crates).
    #[arg(long, default_value = "default")]
    pub profile: String,
}

struct Shape {
    crates: usize,
    depth: usize,
    fan_in: usize,
    tests: usize,
    bins: usize,
    lines: usize,
    fixtures: usize,
}

fn shape(name: &str) -> Result<Shape> {
    let (crates, depth, fan_in, tests, bins, lines, fixtures) =
        match name.to_ascii_uppercase().as_str() {
            "S" => (8, 3, 2, 400, 16, 60, 2),
            "M" => (48, 12, 3, 18_000, 360, 150, 4),
            "L" => (120, 16, 3, 50_000, 900, 150, 4),
            _ => bail!("unknown shape `{name}`; use S, M or L"),
        };
    Ok(Shape {
        crates,
        depth,
        fan_in,
        tests,
        bins,
        lines,
        fixtures,
    })
}

/// Split `total` over `n` crates; the first `total % n` crates take one extra.
/// Shapes quote totals (360 binaries over 48 crates is 7.5 each), so a flat
/// per-crate number cannot hit them.
fn spread(total: usize, n: usize) -> Vec<usize> {
    (0..n)
        .map(|i| total / n + usize::from(i < total % n))
        .collect()
}

struct Plan {
    name: String,
    level: usize,
    deps: Vec<usize>,
    probe: u32,
    combined: u64,
    seed: u64,
    tests: usize,
    bins: usize,
}

struct Filler {
    a: u32,
    r: u32,
    b: u32,
}

impl Filler {
    fn apply(&self, x: u32) -> u32 {
        x.wrapping_mul(self.a)
            .rotate_left(self.r)
            .wrapping_add(self.b)
    }
}

fn write(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)
            .with_context(|| format!("cannot create {}; check permissions", dir.display()))?;
    }
    fs::write(path, text).with_context(|| {
        format!(
            "cannot write {}; check disk space and permissions",
            path.display()
        )
    })
}

pub fn run(args: &GenerateArgs) -> Result<()> {
    let sh = shape(args.shape.as_deref().unwrap_or("S"))?;
    let n = args.crates.unwrap_or(sh.crates);
    let depth = args.depth.unwrap_or(sh.depth);
    let fan_in = args.fan_in.unwrap_or(sh.fan_in).max(1);
    let lines = args.lines_per_crate.unwrap_or(sh.lines);
    let fixtures = args.fixtures_per_crate.unwrap_or(sh.fixtures);
    if depth == 0 || n < depth {
        bail!(
            "--crates ({n}) must be at least --depth ({depth}) and depth at least 1, because every level needs a crate; raise --crates or lower --depth"
        );
    }
    if args.out.exists() && fs::read_dir(&args.out)?.next().is_some() {
        bail!(
            "{} is not empty; remove it or choose another --out",
            args.out.display()
        );
    }
    // Totals scale with the crate count when only --crates is overridden.
    let scale = |t: usize| t * n / sh.crates;
    let tests = args
        .tests_per_crate
        .map_or_else(|| spread(scale(sh.tests), n), |t| vec![t; n]);
    let bins = args
        .integration_bins_per_crate
        .map_or_else(|| spread(scale(sh.bins), n), |b| vec![b; n]);

    let mut rng = Rng::new(args.seed);
    // Levels: one crate per level guarantees a real chain, the rest land
    // anywhere. Sorting makes crate numbers topological (deps have lower numbers).
    let mut levels: Vec<usize> = (0..depth).collect();
    levels.extend((depth..n).map(|_| rng.below(depth)));
    levels.sort();

    let mut plans: Vec<Plan> = Vec::with_capacity(n);
    for i in 0..n {
        let level = levels[i];
        let mut deps = Vec::new();
        if level > 0 {
            let prev: Vec<usize> = (0..i).filter(|&j| levels[j] == level - 1).collect();
            deps.push(prev[rng.below(prev.len())]);
            let mut pool: Vec<usize> = (0..i)
                .filter(|j| levels[*j] < level && !deps.contains(j))
                .collect();
            while deps.len() < fan_in && !pool.is_empty() {
                deps.push(pool.swap_remove(rng.below(pool.len())));
            }
            deps.sort();
        }
        let probe = 1 + rng.below(999) as u32;
        let combined = deps.iter().fold(u64::from(probe), |acc, &d| {
            acc.wrapping_add(plans[d].combined)
        });
        plans.push(Plan {
            name: format!("c{i:03}"),
            level,
            deps,
            probe,
            combined,
            seed: rng.next(),
            tests: tests[i],
            bins: bins[i],
        });
    }

    let root = &args.out;
    let results: Vec<(CrateInfo, Vec<TestInfo>)> = plans
        .par_iter()
        .map(|p| gen_crate(root, p, &plans, fixtures, lines, args.line_oracle))
        .collect::<Result<_>>()?;
    let (crates, tests): (Vec<_>, Vec<_>) = results.into_iter().unzip();
    let tests: Vec<TestInfo> = tests.into_iter().flatten().collect();

    let profile = match args.profile.as_str() {
        "default" => "[profile.test]\nsplit-debuginfo = \"packed\"\n".to_string(),
        // Mirrors the backend's `[profile.dev]`; its optimised foundation crates are the roots here,
        // so inlining from optimised roots into unoptimised dependents is exercised.
        "backend" => {
            let mut s = "[profile.dev]\ndebug = 1\nincremental = true\n".to_string();
            for p in plans.iter().filter(|p| p.level == 0) {
                s.push_str(&format!("\n[profile.dev.package.{}]\nopt-level = 2\n", p.name));
            }
            s
        }
        other => bail!("unknown --profile `{other}`; use default or backend"),
    };
    write(
        &root.join("Cargo.toml"),
        &format!("[workspace]\nresolver = \"2\"\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\nserde_json = \"1\"\n\n{profile}"),
    )?;
    write(&root.join(".gitignore"), "target/\n")?;
    write(
        &root.join("README.md"),
        &format!(
            "# Synthetic workspace\n\nGenerated by `synth-workspace` ({n} crates, depth {depth}, seed {}).\nDo not edit by hand.\n",
            args.seed
        ),
    )?;
    let params = serde_json::json!({
        "shape": args.shape.as_deref().unwrap_or("S").to_ascii_uppercase(),
        "crates": n, "depth": depth, "fan_in": fan_in,
        "tests_per_crate": args.tests_per_crate, "integration_bins_per_crate": args.integration_bins_per_crate,
        "lines_per_crate": lines, "fixtures_per_crate": fixtures, "seed": args.seed,
        "line_oracle": args.line_oracle, "profile": args.profile,
    });
    let synth = Synth {
        version: 1,
        params,
        crates,
        tests,
    };
    write(&root.join("synth.json"), &serde_json::to_string(&synth)?)?;
    println!(
        "generated {} crates, {} tests in {}",
        n,
        synth.tests.len(),
        root.display()
    );
    Ok(())
}

fn gen_crate(
    root: &Path,
    p: &Plan,
    all: &[Plan],
    fixtures: usize,
    lines: usize,
    line_oracle: bool,
) -> Result<(CrateInfo, Vec<TestInfo>)> {
    let name = &p.name;
    let dir = root.join("crates").join(name);
    let mut rng = Rng::new(p.seed);
    let unit = p.tests / 2;
    let n_comb = unit.div_ceil(2);
    let n_fill = unit - n_comb;
    let n_int = if p.bins > 0 { p.tests - unit } else { 0 };
    let mut infos: Vec<TestInfo> = Vec::new();
    let mut info = |binary: &str, tname: &str, kind: &str, asserts, fixture| {
        infos.push(TestInfo {
            id: format!("{binary} {tname}"),
            binary: binary.into(),
            name: tname.into(),
            krate: name.clone(),
            kind: kind.into(),
            asserts,
            fixture,
            feature: None,
            root: None,
        });
    };

    // lib.rs, non-test part.
    let mut lib = String::new();
    writeln!(
        lib,
        "//! Synthetic crate {name} (level {}). Generated by synth-workspace.\n",
        p.level
    )?;
    writeln!(lib, "pub fn probe() -> u32 {{ {} }}\n", p.probe)?;
    writeln!(
        lib,
        "/// Sum of this crate's probe and every dependency's `combined()`. Cached because\n/// diamond-shaped graphs would otherwise make the recursion exponential."
    )?;
    writeln!(
        lib,
        "pub fn combined() -> u64 {{\n    static CACHE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();\n    *CACHE.get_or_init(|| {{\n        u64::from(probe())"
    )?;
    for &d in &p.deps {
        writeln!(
            lib,
            "            .wrapping_add({}::combined())",
            all[d].name
        )?;
    }
    writeln!(lib, "    }})\n}}\n")?;
    writeln!(
        lib,
        "/// The registry dependency every crate really uses.\npub fn json_tag() -> String {{\n    serde_json::json!({{ \"crate\": \"{name}\" }}).to_string()\n}}\n"
    )?;
    let mut fillers: Vec<Filler> = Vec::new();
    if n_fill > 0 {
        let mut count = lib.lines().count();
        while fillers.is_empty() || count < lines {
            let f = Filler {
                a: (rng.next() as u32) | 1,
                r: 1 + rng.below(31) as u32,
                b: rng.next() as u32,
            };
            writeln!(
                lib,
                "pub fn f{:03}(x: u32) -> u32 {{\n    x.wrapping_mul({}).rotate_left({}).wrapping_add({})\n}}\n",
                fillers.len(),
                f.a,
                f.r,
                f.b
            )?;
            fillers.push(f);
            count += 4;
        }
    }

    if line_oracle && p.level == 0 {
        lib.push_str(ROOT_FEATURES);
    }

    // Unit tests. Every filler is covered: test j % n_fill calls filler j % nf.
    lib.push_str("#[cfg(test)]\nmod tests {\n    use super::*;\n\n");
    let nf = fillers.len();
    let mut calls: Vec<Vec<(usize, u32)>> = vec![Vec::new(); n_fill];
    for j in 0..nf.max(n_fill) {
        calls[j % n_fill.max(1)].push((j % nf.max(1), rng.below(1000) as u32));
    }
    let mut first = true;
    for k in 0..unit {
        let comb = k < n_comb;
        let tname = if comb {
            format!("u_comb_{k:03}")
        } else {
            format!("u_fill_{:03}", k - n_comb)
        };
        writeln!(lib, "    #[test]\n    fn {tname}() {{")?;
        if std::mem::take(&mut first) {
            // The hook is where `mutate dep-add` plants its call; the json_tag
            // assertion keeps serde_json exercised by a test.
            writeln!(
                lib,
                "        // bench:hook\n        assert_eq!(json_tag(), r#\"{{\"crate\":\"{name}\"}}\"#);"
            )?;
        }
        if comb {
            writeln!(
                lib,
                "        assert_eq!(combined().wrapping_add({k}), {});",
                p.combined.wrapping_add(k as u64)
            )?;
            info(
                name,
                &format!("tests::{tname}"),
                "unit",
                Asserts::Combined,
                None,
            );
        } else {
            let (expr, val) = filler_expr(&fillers, &calls[k - n_comb], "");
            writeln!(lib, "        assert_eq!({expr}, {val});")?;
            info(
                name,
                &format!("tests::{tname}"),
                "unit",
                Asserts::Filler,
                None,
            );
        }
        lib.push_str("    }\n\n");
    }
    lib.push_str("}\n");
    write(&dir.join("src/lib.rs"), &lib)?;

    // Fixtures: deterministic content; the first line is what tests assert on.
    let mut first_lines = Vec::new();
    for i in 0..fixtures {
        let head = format!("fixture {name} f{i} {:08x}", rng.next() as u32);
        write(
            &dir.join(format!("fixtures/f{i}.txt")),
            &format!("{head}\n{:016x}\n{:016x}\n", rng.next(), rng.next()),
        )?;
        first_lines.push(head);
    }

    // Integration binaries: the first test of each is its fixture test.
    for b in 0..p.bins {
        let stem = format!("bin{b:02}");
        let count = n_int / p.bins + usize::from(b < n_int % p.bins);
        let mut src = format!("//! Integration binary {b} of {name}.\n\n");
        for k in 0..count {
            let tname = format!("t{k:03}");
            writeln!(src, "#[test]\nfn {tname}() {{")?;
            let binary = format!("{name}::{stem}");
            if k == 0 && fixtures > 0 {
                // Pair the include_str! and runtime-read binaries on the same fixture, so a
                // fixture mutation exercises both the dep-info path and the files-key path.
                let i = (b / 2) % fixtures;
                if b % 2 == 0 {
                    writeln!(src, "    let s = include_str!(\"../fixtures/f{i}.txt\");")?;
                } else {
                    writeln!(
                        src,
                        "    let s = std::fs::read_to_string(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/fixtures/f{i}.txt\"))\n        .expect(\"fixture file missing; regenerate the workspace\");"
                    )?;
                }
                writeln!(
                    src,
                    "    assert_eq!(s.lines().next().unwrap(), \"{}\");",
                    first_lines[i]
                )?;
                info(&binary, &tname, "integration", Asserts::Fixture, Some(i));
            } else if k % 2 == 0 && nf > 0 {
                let (expr, val) = filler_expr(
                    &fillers,
                    &[(rng.below(nf), rng.below(1000) as u32)],
                    &format!("{name}::"),
                );
                writeln!(src, "    assert_eq!({expr}, {val});")?;
                info(&binary, &tname, "integration", Asserts::Filler, None);
            } else {
                writeln!(
                    src,
                    "    assert_eq!({name}::combined().wrapping_add({k}), {});",
                    p.combined.wrapping_add(k as u64)
                )?;
                info(&binary, &tname, "integration", Asserts::Combined, None);
            }
            src.push_str("}\n\n");
        }
        write(&dir.join(format!("tests/{stem}.rs")), &src)?;
    }

    if line_oracle {
        let deps: Vec<&Plan> = p.deps.iter().map(|&d| &all[d]).collect();
        gen_line_oracle(&dir, name, &deps, &mut infos)?;
    }

    let mut manifest = format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\npublish = false\n\n[dependencies]\n"
    );
    for &d in &p.deps {
        writeln!(manifest, "{0} = {{ path = \"../{0}\" }}", all[d].name)?;
    }
    manifest.push_str("serde_json.workspace = true\n");
    write(&dir.join("Cargo.toml"), &manifest)?;
    write(
        &dir.join("README.md"),
        &format!(
            "# {name}\n\nSynthetic crate at level {}; depends on {} crate(s).\n",
            p.level,
            p.deps.len()
        ),
    )?;

    let ci = CrateInfo {
        name: name.clone(),
        level: p.level,
        deps: p.deps.iter().map(|&d| all[d].name.clone()).collect(),
        probe: p.probe,
        combined: p.combined,
        unit_tests: unit,
        integration_tests: n_int,
        integration_bins: p.bins,
        fixtures,
        fillers: nf,
    };
    Ok((ci, infos))
}

/// Source text and expected value of a sum of filler calls (as u64 so the
/// test-side addition cannot overflow).
fn filler_expr(fillers: &[Filler], calls: &[(usize, u32)], prefix: &str) -> (String, u64) {
    let mut val = 0u64;
    let parts: Vec<String> = calls
        .iter()
        .map(|&(f, x)| {
            val += u64::from(fillers[f].apply(x));
            format!("u64::from({prefix}f{f:03}({x}))")
        })
        .collect();
    (parts.join(" + "), val)
}

/// The source-position-sensitive features every level-0 crate carries under
/// `--line-oracle`, as (name, whether a shift of the root's lines must change the
/// key of a dependent test that calls it).
///
/// `track_caller` is the control: both levels forward the *caller's* location, so
/// the only position in play is the dependent's own call site, which does not move.
/// `macro_line` expands `line!()` at the use site for the same reason, but the helper
/// it calls asserts inside the root, which does move.
pub const LINE_FEATURES: &[(&str, bool)] = &[
    ("checked", true),
    ("inline_unwrap", true),
    ("track_caller", false),
    ("macro_line", true),
    ("const_line", true),
    ("static_location", true),
    ("overflow", true),
];

const ROOT_FEATURES: &str = r#"// Line-shift oracle: each item below embeds a source position in code or data that a
// dependent's tests execute.

/// Monomorphised in the dependent, so the `assert!` location lands in its object.
pub fn checked<T: Into<u64>>(x: T) -> u64 {
    let v: u64 = x.into();
    assert!(v < 1_000_000, "value out of range");
    v
}

/// Instantiated in the dependent because it is `#[inline]`.
#[inline]
pub fn first_of(v: &[u64]) -> u64 {
    *v.first().unwrap()
}

#[track_caller]
pub fn must(v: Option<u64>) -> u64 {
    must_inner(v)
}

#[track_caller]
fn must_inner(v: Option<u64>) -> u64 {
    v.expect("value required")
}

#[macro_export]
macro_rules! probe_line {
    () => {
        $crate::line_helper(line!())
    };
}

pub fn line_helper(l: u32) -> u32 {
    assert!(l != 0, "line numbers start at 1");
    l
}

pub const ROOT_LINE: u32 = line!();

pub const fn where_am_i() -> u32 {
    line!()
}

pub static CALLER: &std::panic::Location<'static> = std::panic::Location::caller();

#[track_caller]
pub fn here() -> &'static std::panic::Location<'static> {
    std::panic::Location::caller()
}

pub fn root_here() -> &'static std::panic::Location<'static> {
    here()
}

/// Overflow check inlined into the dependent.
#[inline]
pub fn add_u8(a: u8, b: u8) -> u8 {
    a + b
}

"#;

/// The body of one dependent test per feature. Every assertion is on a value that
/// does not depend on the root's line numbers, so the test passes before and after a
/// shift; `black_box` keeps constant folding from erasing the position under test.
fn line_test_body(feature: &str, root: &str) -> String {
    match feature {
        "checked" => format!("assert_eq!({root}::checked(black_box(7u8)), 7);"),
        "inline_unwrap" => format!("assert_eq!({root}::first_of(black_box(&[5u64, 6])), 5);"),
        "track_caller" => format!("assert_eq!({root}::must(black_box(Some(9))), 9);"),
        "macro_line" => format!("assert!({root}::probe_line!() > 0);"),
        "const_line" => format!(
            "assert!(black_box({root}::ROOT_LINE) > 0);\n    assert!(black_box({root}::where_am_i()) > 0);"
        ),
        "static_location" => format!(
            "assert!({root}::CALLER.line() > 0);\n    assert!({root}::root_here().line() > 0);"
        ),
        "overflow" => format!("assert_eq!({root}::add_u8(black_box(100), black_box(20)), 120);"),
        _ => unreachable!("every LINE_FEATURES entry has a body"),
    }
}

fn gen_line_oracle(
    dir: &Path,
    name: &str,
    deps: &[&Plan],
    infos: &mut Vec<TestInfo>,
) -> Result<()> {
    let roots: Vec<&&Plan> = deps.iter().filter(|d| d.level == 0).collect();
    if roots.is_empty() {
        return Ok(());
    }
    let mut src = String::from(
        "//! Calls each source-position-sensitive feature of the level-0 dependencies.\n\nuse std::hint::black_box;\n\n",
    );
    let binary = format!("{name}::line_oracle");
    for r in roots {
        for (feature, _) in LINE_FEATURES {
            let tname = format!("l_{}_{feature}", r.name);
            writeln!(src, "#[test]\nfn {tname}() {{\n    {}\n}}\n", line_test_body(feature, &r.name))?;
            infos.push(TestInfo {
                id: format!("{binary} {tname}"),
                binary: binary.clone(),
                name: tname,
                krate: name.into(),
                kind: "integration".into(),
                asserts: Asserts::Line,
                fixture: None,
                feature: Some((*feature).into()),
                root: Some(r.name.clone()),
            });
        }
    }
    write(&dir.join("tests/line_oracle.rs"), &src)
}
