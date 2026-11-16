//! Diagnostic: rewrite a report's compact form at several zstd levels and print sizes and times.
use std::time::Instant;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let t = Instant::now();
    let r = keel_reach::store::read(std::path::Path::new(&a[1])).unwrap();
    println!("read {} ms", t.elapsed().as_millis());
    for l in &a[2..] {
        let level: i32 = l.parse().unwrap();
        let out = std::path::PathBuf::from(format!("{}.z{level}.json", a[1]));
        let t = Instant::now();
        let (h, s) = keel_reach::store::write_compact_at(&r, &out, level).unwrap();
        println!("level {level}: header {h} side {s} bytes, {} ms", t.elapsed().as_millis());
    }
}
