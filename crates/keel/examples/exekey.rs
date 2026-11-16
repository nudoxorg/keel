//! Prints the executable key (DESIGN §3.1) and the whole-file blake3 of each
//! path given, so determinism can be checked by hand across builds and
//! targets before the CLI exists.
use std::path::PathBuf;

fn main() {
    for arg in std::env::args_os().skip(1) {
        let path = PathBuf::from(arg);
        let whole = blake3::hash(&std::fs::read(&path).expect("readable file"));
        match keel::executable::executable_key(&path) {
            Ok(key) => println!("{key}  file:{}  {}", &whole.to_hex()[..16], path.display()),
            Err(err) => println!("error: {err}  {}", path.display()),
        }
    }
}
