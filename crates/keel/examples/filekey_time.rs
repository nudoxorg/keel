//! Times `files_key` over a real checkout: `filekey_time <root> <package> [glob ...] [-x exclude ...]`.
//! Prints the median of five runs (the first is a cold-cache run and is reported separately).

use std::time::Instant;

use keel::{FileSpec, files_key};

fn main() {
    let mut args = std::env::args().skip(1);
    let root = args.next().expect("root");
    let package = args.next().expect("package dir, or - for none");
    let mut spec = FileSpec {
        package_dir: (package != "-").then(|| package.into()),
        ..FileSpec::default()
    };
    let mut excluding = false;
    for a in args {
        if a == "-x" {
            excluding = true;
        } else if excluding {
            spec.exclude.push(a);
        } else {
            spec.globs.push(a);
        }
    }
    let mut times = Vec::new();
    let mut last = None;
    for _ in 0..6 {
        let t = Instant::now();
        last = Some(files_key(root.as_ref(), &spec).expect("files_key"));
        times.push(t.elapsed());
    }
    let (key, files) = last.unwrap();
    let first = times.remove(0);
    times.sort();
    println!(
        "files={} key={key} first={first:?} median={:?} min={:?}",
        files.len(),
        times[times.len() / 2],
        times[0]
    );
}
