//! The service end to end: a real server on an ephemeral port, driven by the
//! real client and, where the client would hide the detail, by raw requests.

mod common;

use std::fs;

use common::*;
use keel::store::{LocalStore, ResultStore};
use keel::{Digest, Manifest, Status};
use keel_store::client::{Client, ClientError};
use keel_store::server::Limits;
use keel_store::wire::{BLOB_LIMIT, RECORD_LIMIT, valid_id};

const NOW: &str = "2026-11-14T08:12:03Z";

/// A raw request with no client logic: returns (status, body text).
fn raw(method: &str, url: &str, auth: Option<&str>, body: &[u8]) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let mut resp = match method {
        "GET" => {
            let mut req = agent.get(url);
            if let Some(a) = auth {
                req = req.header("Authorization", a);
            }
            req.call()
        }
        _ => {
            let mut req = agent.put(url);
            if let Some(a) = auth {
                req = req.header("Authorization", a);
            }
            req.send(body)
        }
    }
    .unwrap();
    (
        resp.status().as_u16(),
        resp.body_mut().read_to_string().unwrap(),
    )
}

fn manifest(revision: &str) -> Manifest {
    serde_json::from_value(serde_json::json!({
        "schema": 1, "producer": "test", "repo": "Nudox/Backend", "revision": revision,
        "platform": platform(), "nodes": []
    }))
    .unwrap()
}

fn report(run_id: &str) -> keel::Report {
    serde_json::from_value(serde_json::json!({
        "schema": 1, "run_id": run_id, "repo": "Nudox/Backend", "revision": "abc",
        "platform": platform(), "verdict": "pass", "started_at": NOW, "duration_ms": 1,
        "counts": {}, "roots": [], "nodes": []
    }))
    .unwrap()
}

#[test]
fn every_endpoint_round_trips_through_the_client() {
    let dir = TempDir::new("e2e");
    let token = token();
    let server = start(dir.path(), &token, Limits::default());
    let client = Client::new(&server.url(), Some(token));

    let h = client.health().unwrap();
    assert_eq!((h.schema, h.records, h.blobs), (1, 0, 0));
    assert_eq!(h.version, env!("CARGO_PKG_VERSION"));

    let blob = client.put_blob(b"stderr of a test").unwrap();
    assert_eq!(blob, Digest::of(b"stderr of a test"));
    assert_eq!(
        client.get_blob(&blob).unwrap().unwrap(),
        b"stderr of a test"
    );

    let mut rec = record(1, Status::Pass, "r1", NOW);
    rec.evidence = vec![keel::Evidence {
        name: "stderr".into(),
        reference: blob,
    }];
    client.put_record(&rec).unwrap();
    let pass = client.get_pass(&rec.key).unwrap().unwrap();
    assert_eq!((pass.run_id.as_str(), pass.evidence.len()), ("r1", 1));

    // A failure for another key is stored but never served as a pass.
    client
        .put_record(&record(2, Status::Fail, "r2", NOW))
        .unwrap();
    assert!(client.get_pass(&key(2)).unwrap().is_none());

    let m = manifest("7ab31d0");
    client.put_manifest(&m).unwrap();
    assert_eq!(client.get_manifest("7ab31d0").unwrap().unwrap(), m);
    let r = report("01JD");
    client.put_report(&r).unwrap();
    assert_eq!(client.get_report("01JD").unwrap().unwrap(), r);

    // Counts are cached for up to 30 s, so a second server sees the settled state.
    drop(server);
    let again = start(dir.path(), "another-token-another", Limits::default());
    let h = Client::new(&again.url(), None).health().unwrap();
    assert_eq!(h.records, 2, "one results file per key");
    assert_eq!(h.blobs, 3, "evidence blob, manifest, report");
    assert!(h.bytes > 0);
}

#[test]
fn the_client_is_a_result_store_like_the_local_one() {
    let dir = TempDir::new("trait");
    let token = token();
    let server = start(dir.path(), &token, Limits::default());
    let local = LocalStore::open(dir.path()).unwrap();
    let remote = Client::new(&server.url(), Some(token));
    for store in [&local as &dyn ResultStore, &remote as &dyn ResultStore] {
        let d = store.put_blob(b"same bytes").unwrap();
        assert_eq!(store.get_blob(&d).unwrap().unwrap(), b"same bytes");
        store.put(&record(7, Status::Pass, "any", NOW)).unwrap();
        assert_eq!(store.get_pass(&key(7)).unwrap().unwrap().run_id, "any");
    }
}

#[test]
fn remote_failures_through_the_trait_are_store_error_remote() {
    // A port that was free a moment ago and has no listener now.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let down = Client::new(&format!("http://127.0.0.1:{port}"), Some(token()));
    let store: &dyn ResultStore = &down;
    let err = store.get_pass(&key(1)).unwrap_err();
    assert!(
        matches!(&err, keel::StoreError::Remote { endpoint, .. } if endpoint.contains("/v1/pass/")),
        "{err}"
    );
    assert!(
        err.to_string()
            .contains("keel-store is running and reachable"),
        "{err}"
    );

    // A wrong token is Remote too, and the message does not echo it.
    let dir = TempDir::new("remote");
    let server = start(dir.path(), &token(), Limits::default());
    let wrong = Client::new(&server.url(), Some("not-the-token-at-all".into()));
    let err = (&wrong as &dyn ResultStore).put_blob(b"x").unwrap_err();
    assert!(matches!(err, keel::StoreError::Remote { .. }), "{err}");
    assert!(!err.to_string().contains("not-the-token-at-all"));
}

#[test]
fn a_directory_written_by_local_store_is_served_and_the_reverse() {
    let dir = TempDir::new("interop");
    let local = LocalStore::open(dir.path()).unwrap();
    let blob = local.put_blob(b"written locally").unwrap();
    local
        .put(&record(5, Status::Pass, "local-run", NOW))
        .unwrap();
    local
        .put(&record(5, Status::Pass, "local-run-2", NOW))
        .unwrap();

    let token = token();
    let server = start(dir.path(), &token, Limits::default());
    let client = Client::new(&server.url(), Some(token));
    assert_eq!(
        client.get_pass(&key(5)).unwrap().unwrap().run_id,
        "local-run-2"
    );
    assert_eq!(client.get_blob(&blob).unwrap().unwrap(), b"written locally");

    // And the other way: the service's writes are plain LocalStore files,
    // appended after the existing lines.
    client
        .put_record(&record(5, Status::Pass, "remote-run", NOW))
        .unwrap();
    let remote_blob = client.put_blob(b"written remotely").unwrap();
    assert_eq!(
        local.get_pass(&key(5)).unwrap().unwrap().run_id,
        "remote-run"
    );
    assert_eq!(
        local.get_blob(&remote_blob).unwrap().unwrap(),
        b"written remotely"
    );
    let lines = fs::read_to_string(results_path(dir.path(), &key(5))).unwrap();
    assert_eq!(lines.lines().count(), 3, "records are only ever appended");
}

#[test]
fn writes_without_the_token_are_401_and_reads_stay_open() {
    let dir = TempDir::new("auth");
    let token = token();
    let server = start(dir.path(), &token, Limits::default());
    let url = server.url();
    let body = serde_json::to_vec(&record(1, Status::Pass, "r", NOW)).unwrap();

    for (path, payload) in [
        ("/v1/record", body.as_slice()),
        ("/v1/blob", b"bytes".as_slice()),
        ("/v1/manifest/abc", b"{}".as_slice()),
        ("/v1/report/abc", b"{}".as_slice()),
    ] {
        for auth in [
            None,
            Some("Bearer wrong"),
            Some(token.as_str()),
            Some("Basic xyz"),
        ] {
            let (status, text) = raw("PUT", &format!("{url}{path}"), auth, payload);
            assert_eq!(status, 401, "{path} with {auth:?}");
            assert!(text.contains("Authorization: Bearer"), "{text}");
            assert!(!text.contains(&token), "the answer must not echo the token");
        }
    }
    // Nothing was written by the refused requests.
    assert!(
        fs::read_dir(dir.path().join("results"))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        fs::read_dir(dir.path().join("objects"))
            .unwrap()
            .next()
            .is_none()
    );

    // The client reports it as a token problem, and refuses to write with none.
    let wrong = Client::new(&url, Some("not-the-token".into()));
    let err = wrong.put_blob(b"x").unwrap_err();
    assert!(matches!(err, ClientError::Unauthorized { .. }), "{err}");
    assert!(
        err.to_string().contains("KEEL_STORE_TOKEN_FILE")
            && !err.to_string().contains("not-the-token")
    );
    let none = Client::new(&url, None);
    assert!(matches!(
        none.put_blob(b"x").unwrap_err(),
        ClientError::NoToken { .. }
    ));
    assert_eq!(raw("GET", &format!("{url}/v1/health"), None, b"").0, 200);
}

#[test]
fn unknown_things_are_404() {
    let dir = TempDir::new("404");
    let token = token();
    let server = start(dir.path(), &token, Limits::default());
    let client = Client::new(&server.url(), Some(token.clone()));
    assert!(client.get_pass(&key(9)).unwrap().is_none());
    assert!(client.get_pass(&Digest::Sha256([9; 32])).unwrap().is_none());
    assert!(
        client
            .get_blob(&Digest::of(b"never stored"))
            .unwrap()
            .is_none()
    );
    assert!(client.get_manifest("nope").unwrap().is_none());
    assert!(client.get_report("nope").unwrap().is_none());
    let (status, text) = raw(
        "GET",
        &format!("{}/v1/pass/not-a-digest", server.url()),
        Some(&format!("Bearer {}", read_token(&token))),
        b"",
    );
    assert_eq!(status, 400);
    assert!(text.contains("blake3:"), "{text}");
}

#[test]
fn oversized_bodies_are_413_and_name_the_limit() {
    let dir = TempDir::new("413");
    let token = token();
    let server = start(
        dir.path(),
        &token,
        Limits {
            blob: 1024,
            record: 2048,
        },
    );
    let client = Client::new(&server.url(), Some(token.clone()));

    let err = client.put_blob(&[7u8; 4096]).unwrap_err();
    assert!(matches!(err, ClientError::TooLarge { .. }), "{err}");
    assert!(
        err.to_string().contains("blob limit of 1024 bytes"),
        "{err}"
    );

    let (status, text) = raw(
        "PUT",
        &format!("{}/v1/record", server.url()),
        Some(&format!("Bearer {token}")),
        &[b' '; 4096],
    );
    assert_eq!(status, 413);
    assert!(text.contains("record limit of 2048 bytes"), "{text}");

    assert_eq!(
        client.put_blob(&[7u8; 1024]).unwrap(),
        Digest::of(&[7u8; 1024])
    );
    assert_eq!((BLOB_LIMIT, RECORD_LIMIT), (64 << 20, 16 << 20));
}

#[test]
fn a_corrupt_blob_on_disk_is_a_clear_5xx_not_served_bytes() {
    let dir = TempDir::new("corrupt");
    let token = token();
    let server = start(dir.path(), &token, Limits::default());
    let client = Client::new(&server.url(), Some(token.clone()));
    let d = client.put_blob(b"the original bytes").unwrap();
    fs::write(blob_path(dir.path(), &d), b"tampered").unwrap();

    let (status, text) = raw(
        "GET",
        &format!("{}/v1/blob/{d}", server.url()),
        Some(&format!("Bearer {}", read_token(&token))),
        b"",
    );
    assert_eq!(status, 500);
    assert!(
        text.contains("corrupt") && text.contains("hash to"),
        "{text}"
    );
    assert!(!text.contains("tampered"));
    let err = client.get_blob(&d).unwrap_err();
    assert!(matches!(err, ClientError::Corrupt { .. }), "{err}");

    // Through the trait the same failure stays `Corrupt`, so a runner can treat it as a miss.
    let as_store: &dyn ResultStore = &client;
    assert!(matches!(
        as_store.get_blob(&d),
        Err(keel::StoreError::Corrupt { .. })
    ));
}

#[test]
fn manifests_and_reports_must_match_their_url() {
    let dir = TempDir::new("docs");
    let token = token();
    let server = start(dir.path(), &token, Limits::default());
    let auth = format!("Bearer {token}");
    let body = serde_json::to_vec(&manifest("aaa")).unwrap();

    let (status, text) = raw(
        "PUT",
        &format!("{}/v1/manifest/bbb", server.url()),
        Some(&auth),
        &body,
    );
    assert_eq!(status, 400);
    assert!(
        text.contains("revision aaa") && text.contains("bbb"),
        "{text}"
    );
    let (status, _) = raw(
        "PUT",
        &format!("{}/v1/manifest/aaa", server.url()),
        Some(&auth),
        b"{\"nope\":1}",
    );
    assert_eq!(status, 400);
    let (status, _) = raw(
        "PUT",
        &format!("{}/v1/report/.hidden", server.url()),
        Some(&auth),
        b"{}",
    );
    assert_eq!(status, 400);
    let (status, stored) = raw(
        "PUT",
        &format!("{}/v1/manifest/aaa", server.url()),
        Some(&auth),
        &body,
    );
    assert_eq!(status, 200, "{stored}");
    let (status, served) = raw(
        "GET",
        &format!("{}/v1/manifest/aaa", server.url()),
        Some(&auth),
        b"",
    );
    assert_eq!(
        (status, served.as_bytes()),
        (200, body.as_slice()),
        "stored byte for byte"
    );

    assert!(valid_id("7ab31d0") && valid_id("01JD.x_y-z"));
    assert!(!valid_id("") && !valid_id("../x") && !valid_id("a/b") && !valid_id(".x"));
}

#[test]
fn reads_need_the_read_token_or_the_writer_token_but_health_is_open() {
    let dir = TempDir::new("readauth");
    let token = token();
    let read = read_token(&token);
    let server = start(dir.path(), &token, Limits::default());
    let url = server.url();
    let writer = Client::new(&url, Some(token.clone()));
    let blob = writer.put_blob(b"secret stdout").unwrap();
    writer
        .put_record(&record(3, Status::Pass, "r", NOW))
        .unwrap();
    writer.put_manifest(&manifest("rev1")).unwrap();
    writer.put_report(&report("run1")).unwrap();

    for path in [
        format!("/v1/blob/{blob}"),
        format!("/v1/pass/{}", key(3)),
        "/v1/manifest/rev1".to_string(),
        "/v1/report/run1".to_string(),
    ] {
        for bad in [
            None,
            Some("Bearer nope"),
            Some(read.as_str()),
            Some("Basic xyz"),
        ] {
            let (status, text) = raw("GET", &format!("{url}{path}"), bad, b"");
            assert_eq!(status, 401, "{path} with {bad:?}");
            assert!(
                text.contains("read token") && !text.contains(&read) && !text.contains(&token),
                "{text}"
            );
        }
        for good in [format!("Bearer {read}"), format!("Bearer {token}")] {
            assert_eq!(
                raw("GET", &format!("{url}{path}"), Some(&good), b"").0,
                200,
                "{path}"
            );
        }
    }
    assert_eq!(raw("GET", &format!("{url}/v1/health"), None, b"").0, 200);

    // The read token reads but cannot write.
    let (status, _) = raw(
        "PUT",
        &format!("{url}/v1/blob"),
        Some(&format!("Bearer {read}")),
        b"x",
    );
    assert_eq!(status, 401);
    // The client sends the read token on reads and the writer token on writes.
    let reader = Client::new(&url, None).with_read_token(read.clone());
    assert_eq!(reader.get_blob(&blob).unwrap().unwrap(), b"secret stdout");
    assert!(matches!(
        reader.put_blob(b"x").unwrap_err(),
        ClientError::NoToken { .. }
    ));
    let both = Client::new(&url, Some(token)).with_read_token(read);
    assert!(both.get_pass(&key(3)).unwrap().is_some());
    let unauth = Client::new(&url, None);
    assert!(matches!(
        unauth.get_blob(&blob).unwrap_err(),
        ClientError::Unauthorized { .. }
    ));
}
