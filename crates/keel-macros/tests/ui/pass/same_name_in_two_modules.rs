// Statics are named from the fn and live in the fn's own module, so equal fn
// names in sibling modules do not collide and carry distinct module paths.
use keel_macros::stands_on;

mod a {
    use super::stands_on;
    #[stands_on("unit(a)")]
    pub fn t() {}
    pub fn record() -> Vec<u8> {
        __KEEL_DECL_t.to_vec()
    }
}

mod b {
    use super::stands_on;
    #[stands_on("unit(b)")]
    pub fn t() {}
    pub fn record() -> Vec<u8> {
        __KEEL_DECL_t.to_vec()
    }
}

fn main() {
    a::t();
    b::t();
    let da = keel_decl::decode_section(&a::record()).unwrap().remove(0);
    let db = keel_decl::decode_section(&b::record()).unwrap().remove(0);
    assert_ne!(da.module_path, db.module_path);
    assert!(da.module_path.ends_with("::a") && db.module_path.ends_with("::b"));
}
