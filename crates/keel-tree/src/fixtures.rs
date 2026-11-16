//! Small in-memory repositories for the resolution tests.

use crate::model::Model;
use keel_index::{CodeIndex, Item, Package, SourceFile, Target};
use std::path::PathBuf;

pub struct Fixture {
    pub packages: Vec<(&'static str, &'static str, Vec<u32>, Vec<u32>)>,
    pub files: Vec<(&'static str, Option<u32>, Target)>,
    pub tests: Vec<(u32, &'static str, bool)>,
}

impl Fixture {
    pub fn index(&self) -> CodeIndex {
        CodeIndex {
            root: PathBuf::from("/nonexistent-keel-tree-fixture"),
            packages: self
                .packages
                .iter()
                .map(|(name, dir, deps, dev)| Package {
                    name: (*name).to_owned(),
                    dir: (*dir).to_owned(),
                    deps: deps.clone(),
                    dev_only_deps: dev.clone(),
                    member: true,
                })
                .collect(),
            files: self
                .files
                .iter()
                .map(|(path, package, target)| SourceFile {
                    path: (*path).to_owned(),
                    package: *package,
                    target: target.clone(),
                    content: [0; 32],
                    parse_error: None,
                })
                .collect(),
            graph_note: None,
            items: self
                .tests
                .iter()
                .map(|(file, path, ignored)| Item {
                    file: *file,
                    path: (*path).to_owned(),
                    start_line: 1,
                    end_line: 2,
                    tokens: [0; 32],
                    signature: [0; 32],
                    branches: 0,
                    is_test: true,
                    ignored: *ignored,
                    in_test_code: true,
                })
                .collect(),
        }
    }
}

/// Four packages: `core` <- `mid` <- `top`, and `tooling` which depends on
/// `core` only for its own tests. `stray` is outside every package.
pub fn standard() -> Fixture {
    Fixture {
        packages: vec![
            ("core", "crates/core", vec![], vec![]),
            ("mid", "crates/mid", vec![0], vec![]),
            ("top", "crates/top", vec![0, 1], vec![]),
            ("tooling", "crates/tooling", vec![0], vec![0]),
        ],
        files: vec![
            ("crates/core/src/lib.rs", Some(0), Target::Lib),
            ("crates/core/src/wal/mod.rs", Some(0), Target::Lib),
            ("crates/mid/src/lib.rs", Some(1), Target::Lib),
            ("crates/top/src/lib.rs", Some(2), Target::Lib),
            ("crates/top/tests/journey.rs", Some(2), Target::IntegrationTest("journey".into())),
            ("crates/tooling/src/lib.rs", Some(3), Target::Lib),
            ("stray/src/lib.rs", None, Target::Lib),
        ],
        tests: vec![
            (0, "tests::roundtrip", false),
            (1, "tests::replays", false),
            (2, "tests::wide", true),
            (4, "walks_everything", false),
            (5, "tests::tool", false),
        ],
    }
}

pub fn model(json: &str) -> Model {
    Model::from_json(json).expect("fixture model parses")
}
