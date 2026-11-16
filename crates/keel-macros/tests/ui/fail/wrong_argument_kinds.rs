use keel_macros::{joins, stands_on};

#[stands_on(unit)]
fn ident_for_stands_on() {}

#[joins(1)]
fn number() {}

#[stands_on()]
fn empty() {}

#[joins(a, a)]
fn repeated() {}

#[stands_on("unit(a)")]
struct NotAFn;

fn main() {}
