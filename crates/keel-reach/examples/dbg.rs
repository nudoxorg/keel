use keel_reach::{LinkInputs, Loader};
use std::collections::BTreeMap;

type Atoms = Vec<(String, Vec<u8>, Vec<(u32, i64, u32)>)>;

fn collect(rec: &str) -> BTreeMap<String, Atoms> {
    let l = Loader::new();
    let rec = LinkInputs::from_record(std::path::Path::new(rec)).unwrap();
    let loaded = l.load(&rec, "c000");
    assert!(loaded.problem.is_none());
    let mut out: BTreeMap<String, Vec<_>> = BTreeMap::new();
    for u in &loaded.units {
        for m in &u.file.members {
            for a in m.atoms.iter() {
                if a.symbol == keel_reach::model::NONE { continue; }
                let raw = &m.names[a.symbol as usize];
                let Ok(d) = rustc_demangle::try_demangle(raw) else { continue };
                let name = format!("{d:#}");
                let relocs = m.atom_relocs(a).iter().map(|r| (r.offset, r.addend, r.kind)).collect();
                // Archives are no longer kept mapped, so the bytes are represented by their content hash.
                let b = a.content.to_vec();
                out.entry(name).or_default().push((u.path.display().to_string(), b, relocs));
            }
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (a, b) = (collect(&args[1]), collect(&args[2]));
    let mut n = 0;
    for (name, va) in &a {
        let Some(vb) = b.get(name) else { continue };
        if va.len() != 1 || vb.len() != 1 { continue; }
        let (x, y) = (&va[0], &vb[0]);
        if x.1 != y.1 || x.2 != y.2 {
            n += 1;
            if n > 12 { continue; }
            let diffs: Vec<_> = x.1.iter().zip(&y.1).enumerate().filter(|(_, (p, q))| p != q).map(|(i, _)| i).take(12).collect();
            println!("{name}\n   len {} vs {}; byte diffs at {diffs:?}; relocs equal {}", x.1.len(), y.1.len(), x.2 == y.2);
            if let (Some(&i), true) = (diffs.first(), x.1.len() == y.1.len()) {
                let lo = i.saturating_sub(8); let hi = (i + 24).min(x.1.len());
                println!("   A {:02x?}\n   B {:02x?}", &x.1[lo..hi], &y.1[lo..hi]);
            }
        }
    }
    println!("{n} same-named atoms differ in bytes or relocation shape");
}
