//! Diagnostic: for named tests, the descriptor's function and the atoms the path-spelled
//! names found, with every name each atom carries.
use keel_reach::entry::{guess_by_name, read_descriptors};
use keel_reach::link::Program;
use keel_reach::model::display_name;
use keel_reach::{LinkInputs, Loader};
use std::collections::HashSet;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (rec, krate, list) = (&a[1], &a[2], &a[3]);
    let tests: Vec<String> = std::fs::read_to_string(list).unwrap().lines().map(str::to_string).collect();
    let want: Vec<&String> = a[4..].iter().collect();
    let rec = LinkInputs::from_record(std::path::Path::new(rec)).unwrap();
    let l = Loader::new();
    let loaded = l.load(&rec, krate);
    let prog = Program::new(&loaded.units);
    let wanted: HashSet<&str> = tests.iter().map(String::as_str).collect();
    let table = read_descriptors(&prog, &wanted);
    let guess = guess_by_name(&prog, krate, &tests);
    println!("candidates {} shaped {} bound {} unbound {} ambiguous {}", table.candidates, table.shaped, table.bound.len(), table.unbound, table.ambiguous);
    let names = |g: u32| -> Vec<String> {
        let (mem, ai) = prog.locate(g);
        let m = prog.member(mem);
        m.names_of(ai).map(|n| display_name(&m.names[n as usize])).collect()
    };
    for t in want {
        println!("== {t}");
        for b in table.bound.get(t).into_iter().flatten() {
            println!("  descriptor fn {} -> {:?}", b.func, names(b.func));
            let (mem, ai) = prog.locate(b.func);
            let m = prog.member(mem);
            for r in m.atom_relocs(&m.atoms[ai as usize]) {
                if let Some(g) = prog.reloc_atom(mem, r) { println!("      calls {} -> {:?}", g, names(g)); } else { println!("      reloc {:?}", r.target()); }
            }
        }
        for g in guess.get(t).into_iter().flatten() {
            println!("  guessed {} -> {:?}", g, names(*g));
        }
    }
}
