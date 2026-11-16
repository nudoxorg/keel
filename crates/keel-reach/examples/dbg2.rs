use keel_reach::{LinkInputs, Loader};
use std::collections::HashSet;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let l = Loader::new();
    let load = |p: &str| l.load(&LinkInputs::from_record(std::path::Path::new(p)).unwrap(), "c000");
    let (a, b) = (load(&args[1]), load(&args[2]));
    let hashes = |x: &keel_reach::load::Loaded| -> HashSet<[u8; 32]> { x.units.iter().flat_map(|u| u.file.members.iter().flat_map(|m| m.atoms.iter().map(|a| a.content))).collect() };
    let hb = hashes(&b);
    for u in &a.units {
        if !u.path.to_string_lossy().contains("serde_json") { continue }
        for m in &u.file.members {
            for at in m.atoms.iter() {
                if at.symbol == keel_reach::model::NONE { continue }
                let name = &m.names[at.symbol as usize];
                if name.starts_with("l_anon") && !hb.contains(&at.content) && at.size < 200 {
                    println!("{name} size {} reloc {}: content {}", at.size, at.relocs[1] - at.relocs[0], keel_reach::load::hex(&at.content[..8]));
                }
            }
        }
    }
}
