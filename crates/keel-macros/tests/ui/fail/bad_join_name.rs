use keel_macros::joins;

#[joins("Backend::Store")]
fn not_a_crate_name() {}

#[joins(Backend)]
fn upper_case_ident() {}

fn main() {}
