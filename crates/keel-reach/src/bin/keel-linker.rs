//! `-C linker=<this>`: record what rustc links, then link for real.
fn main() {
    std::process::exit(keel_reach::shim::run(std::env::args_os().skip(1).collect()));
}
