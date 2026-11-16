//! Retention on a directory with dated records.

mod common;

use std::fs;
use std::time::{Duration, SystemTime};

use common::*;
use keel::store::{LocalStore, ResultStore};
use keel::{Digest, Evidence, Status};
use keel_store::gc::{self, GcError, Policy, parse_rfc3339};

const DAY: u64 = 86_400;

fn policy() -> Policy {
    Policy {
        keep_pass: Duration::from_secs(30 * DAY),
        keep_fail: Duration::from_secs(90 * DAY),
        blob_grace: Duration::from_secs(DAY),
        reserve_bytes: 0,
    }
}

fn ago(now: u64, days: u64) -> String {
    rfc3339(now - days * DAY)
}

fn age_file(path: &std::path::Path, days: u64) {
    let f = fs::File::options().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(days * DAY))
        .unwrap();
}

fn with_evidence(mut r: keel::StoredRecord, d: Digest) -> keel::StoredRecord {
    r.evidence = vec![Evidence {
        name: "stderr".into(),
        reference: d,
    }];
    r
}

#[test]
fn formatter_and_parser_agree() {
    for secs in [0, 86_399, 951_782_400, 1_794_643_923, 4_102_444_800] {
        assert_eq!(parse_rfc3339(&rfc3339(secs)), Some(secs));
    }
}

#[test]
fn old_records_and_unreferenced_blobs_go_and_the_rest_stays() {
    let dir = TempDir::new("gc");
    let store = LocalStore::open(dir.path()).unwrap();
    let now = gc::now();

    let kept_blob = store.put_blob(b"evidence of a recent pass").unwrap();
    let expired_blob = store.put_blob(b"evidence of an old pass").unwrap();
    let orphan_old = store.put_blob(b"nobody names me, and I am old").unwrap();
    let orphan_young = store
        .put_blob(b"nobody names me yet, but I am new")
        .unwrap();
    for d in [&expired_blob, &orphan_old] {
        age_file(&blob_path(dir.path(), d), 5);
    }
    age_file(&blob_path(dir.path(), &kept_blob), 5);

    // key 1: a 40-day-old pass (expires) and a 10-day-old pass (stays).
    store
        .put(&with_evidence(
            record(1, Status::Pass, "old-pass", &ago(now, 40)),
            expired_blob,
        ))
        .unwrap();
    store
        .put(&with_evidence(
            record(1, Status::Pass, "new-pass", &ago(now, 10)),
            kept_blob,
        ))
        .unwrap();
    // key 2: a 60-day-old failure stays (failures keep 90 days), a 100-day-old one goes.
    store
        .put(&record(2, Status::Fail, "fail-60", &ago(now, 60)))
        .unwrap();
    store
        .put(&record(2, Status::Flaky, "flaky-100", &ago(now, 100)))
        .unwrap();
    // key 3: every line is expired, so the file goes.
    store
        .put(&record(3, Status::Pass, "gone", &ago(now, 31)))
        .unwrap();

    let dry = gc::run(dir.path(), &policy(), now, true).unwrap();
    assert_eq!(
        (dry.records, dry.record_files, dry.blobs),
        (3, 1, 2),
        "{:#?}",
        dry.actions
    );
    assert!(
        results_path(dir.path(), &key(3)).exists(),
        "--dry-run changes nothing"
    );
    assert!(blob_path(dir.path(), &orphan_old).exists());
    assert!(!dir.path().join("results").join("not-created").exists());

    let out = gc::run(dir.path(), &policy(), now, false).unwrap();
    assert_eq!((out.records, out.record_files, out.blobs), (3, 1, 2));
    assert_eq!(
        out.bytes_freed,
        (b"evidence of an old pass".len() + b"nobody names me, and I am old".len()) as u64
    );

    assert_eq!(store.get_pass(&key(1)).unwrap().unwrap().run_id, "new-pass");
    let text = fs::read_to_string(results_path(dir.path(), &key(1))).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert_eq!(
        fs::read_to_string(results_path(dir.path(), &key(2)))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert!(!results_path(dir.path(), &key(3)).exists());
    assert!(store.get_blob(&kept_blob).unwrap().is_some());
    assert!(
        store.get_blob(&orphan_young).unwrap().is_some(),
        "inside the grace period"
    );
    assert!(store.get_blob(&expired_blob).unwrap().is_none());
    assert!(store.get_blob(&orphan_old).unwrap().is_none());

    // Idempotent.
    let again = gc::run(dir.path(), &policy(), now, false).unwrap();
    assert_eq!((again.records, again.blobs), (0, 0));
}

#[test]
fn unreadable_lines_are_kept_with_a_warning() {
    let dir = TempDir::new("gc-warn");
    let store = LocalStore::open(dir.path()).unwrap();
    let now = gc::now();
    store
        .put(&record(4, Status::Pass, "old", &ago(now, 40)))
        .unwrap();
    let path = results_path(dir.path(), &key(4));
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str("{this is not json}\n");
    fs::write(&path, text).unwrap();

    let out = gc::run(dir.path(), &policy(), now, false).unwrap();
    assert_eq!(out.records, 1);
    assert_eq!(fs::read_to_string(&path).unwrap(), "{this is not json}\n");
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("never deletes what it cannot read"))
    );
}

#[test]
fn index_entries_expire_and_release_their_blobs() {
    let dir = TempDir::new("gc-index");
    let store = LocalStore::open(dir.path()).unwrap();
    let now = gc::now();
    let stale = store.put_blob(b"old manifest").unwrap();
    let fresh = store.put_blob(b"new manifest").unwrap();
    for (name, d, age) in [("rev-old", stale, 120), ("rev-new", fresh, 1)] {
        let p = dir.path().join("index/manifest");
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join(name), d.to_string()).unwrap();
        age_file(&p.join(name), age);
        age_file(&blob_path(dir.path(), &d), age);
    }
    let out = gc::run(dir.path(), &policy(), now, false).unwrap();
    assert_eq!((out.index_entries, out.blobs), (1, 1));
    assert!(!dir.path().join("index/manifest/rev-old").exists());
    assert!(store.get_blob(&stale).unwrap().is_none());
    assert!(store.get_blob(&fresh).unwrap().is_some());
}

#[test]
fn it_refuses_to_run_when_the_filesystem_cannot_be_stat_ed_and_checks_the_reserve() {
    let dir = TempDir::new("gc-stat");
    let missing = dir.path().join("no-such-dir");
    let err = gc::run(&missing, &policy(), gc::now(), false).unwrap_err();
    assert!(matches!(err, GcError::Stat { .. }), "{err}");
    assert!(err.to_string().contains("refusing to prune"), "{err}");

    let out = gc::run(dir.path(), &policy(), gc::now(), true).unwrap();
    assert!(out.free_before > 0 && !out.below_reserve(&policy()));
    let huge = Policy {
        reserve_bytes: u64::MAX / 2,
        ..policy()
    };
    assert!(out.below_reserve(&huge));
}
