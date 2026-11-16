//! The HTTP service: routing, authentication, limits and logging.
//!
//! All filesystem work is `keel::store::LocalStore` (blocking, flock-based)
//! run on tokio's blocking pool, so the on-disk layout stays the library's.
//! The service only ever adds: nothing here deletes a record or a blob
//! (`gc` is the one deletion path and it is not reachable over HTTP).

use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, HttpBody};
use axum::extract::{Path as UrlPath, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use keel::store::{LocalStore, ResultStore, StoreError, StoredRecord};
use keel::{Digest, Manifest, Report};
use serde::Serialize;

use crate::wire::valid_id;
use crate::wire::{BLOB_LIMIT, DigestBody, ErrorBody, Health, RECORD_LIMIT, SCHEMA};

/// Subdirectories of the store root that index manifests and reports by
/// revision / run id. `LocalStore` ignores them; `gc` expires them.
pub(crate) const INDEX_KINDS: [&str; 2] = ["manifest", "report"];

/// How long a health scan is reused. A full walk of a large store is not
/// something a monitoring probe should trigger every few seconds.
const HEALTH_TTL: Duration = Duration::from_secs(30);

/// Request body limits; overridable so tests need not send 64 MiB.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// `PUT /v1/blob`.
    pub blob: usize,
    /// `PUT /v1/record`, manifests and reports.
    pub record: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            blob: BLOB_LIMIT,
            record: RECORD_LIMIT,
        }
    }
}

/// What the service needs to run.
#[derive(Clone)]
pub struct Config {
    /// The store directory (created if missing).
    pub dir: PathBuf,
    /// The writer token. Kept only as a hash after startup.
    pub token: String,
    /// The read token: every GET except `/v1/health` needs it (the writer
    /// token also satisfies a read). `None` leaves reads open, which only
    /// tests and embedding want; the binary refuses to start without one.
    pub read_token: Option<String>,
    /// Body limits.
    pub limits: Limits,
}

struct App {
    store: LocalStore,
    // Compared as blake3 hashes: `blake3::Hash` equality is constant-time, so
    // a wrong token cannot be refined byte by byte from response timing.
    token: blake3::Hash,
    read_token: Option<blake3::Hash>,
    limits: Limits,
    health: Mutex<Option<(Instant, Health)>>,
}

type Shared = State<Arc<App>>;

/// A failure rendered as a JSON [`ErrorBody`].
struct ApiError {
    status: StatusCode,
    message: String,
    kind: Option<&'static str>,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        ApiError {
            status,
            message: message.into(),
            kind: None,
        }
    }
    fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        let (status, kind) = match &e {
            StoreError::Corrupt { .. } => (StatusCode::INTERNAL_SERVER_ERROR, Some("corrupt")),
            StoreError::Io { source, .. } if source.kind() == io::ErrorKind::StorageFull => {
                (StatusCode::INSUFFICIENT_STORAGE, Some("full"))
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, None),
        };
        ApiError {
            status,
            message: e.to_string(),
            kind,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut message = self.message;
        if self.status == StatusCode::INSUFFICIENT_STORAGE {
            message.push_str("; the store disk is full, run `keel-store gc` or free space");
        }
        json(
            self.status,
            &ErrorBody {
                error: message,
                kind: self.kind.map(str::to_owned),
            },
        )
    }
}

type ApiResult<T = Response> = Result<T, ApiError>;

fn json<T: Serialize>(status: StatusCode, body: &T) -> Response {
    // The wire types serialize infallibly; an empty body would be a bug
    // visible in the first test, not a runtime condition.
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response()
}

fn not_found(what: &str) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, format!("no {what} in the store"))
}

/// Runs blocking filesystem work off the async threads.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> ApiResult<T> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r.map_err(ApiError::from),
        Err(e) => Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("the store task panicked: {e}; this is a bug, report it with the service log"),
        )),
    }
}

/// Requires `Authorization: Bearer <writer token>`. The answer names the
/// header and never the token.
fn authorize(app: &App, headers: &HeaderMap) -> ApiResult<()> {
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match given {
        Some(t) if blake3::hash(t.as_bytes()) == app.token => Ok(()),
        _ => Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "writes need the header `Authorization: Bearer <writer token>`; it was missing or did not match the service's token",
        )),
    }
}

/// Requires the read token, or the writer token, on a GET. `/v1/health`
/// skips this so a probe needs no secret. Like [`authorize`] it never echoes
/// a token.
fn authorize_read(app: &App, headers: &HeaderMap) -> ApiResult<()> {
    let Some(read) = app.read_token else {
        return Ok(());
    };
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| blake3::hash(t.as_bytes()));
    match given {
        Some(h) if h == read || h == app.token => Ok(()),
        _ => Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "reads need the header `Authorization: Bearer <read token>` (the writer token also works); it was missing or did not match",
        )),
    }
}

/// Reads a request body of at most `limit` bytes, answering 413 with the
/// name of the limit otherwise. A declared length over the limit is refused
/// before reading anything.
async fn read_body(
    headers: &HeaderMap,
    body: Body,
    limit: usize,
    what: &str,
) -> ApiResult<Vec<u8>> {
    let too_big = || {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "the {what} body exceeds the {what} limit of {} bytes ({} MiB); split it or store it as smaller blobs",
                limit,
                limit / (1024 * 1024)
            ),
        )
    };
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > limit) {
        return Err(too_big());
    }
    match axum::body::to_bytes(body, limit).await {
        Ok(b) => Ok(b.to_vec()),
        Err(e) => {
            // axum collapses the length-limit error into its own type; the
            // text is the only stable way to tell it from a dropped socket.
            let mut cause: Option<&dyn std::error::Error> = Some(&e);
            while let Some(c) = cause {
                if c.to_string().contains("length limit") {
                    return Err(too_big());
                }
                cause = c.source();
            }
            Err(ApiError::bad(format!(
                "the {what} body could not be read ({e}); the client disconnected or sent a malformed body, retry the request"
            )))
        }
    }
}

fn parse_digest(s: &str) -> ApiResult<Digest> {
    Digest::from_str(s).map_err(|e| ApiError::bad(e.to_string()))
}

/// Blobs are named by blake3 only; a sha256 name (a Nix derivation hash)
/// can key a record but never names stored bytes.
fn parse_blob_digest(s: &str) -> ApiResult<Digest> {
    match parse_digest(s)? {
        d @ Digest::Blake3(_) => Ok(d),
        d => Err(ApiError::bad(format!(
            "{d} is not a blob name; blobs are named `blake3:<hex>`"
        ))),
    }
}

async fn health_h(State(app): Shared) -> ApiResult {
    let cached = app.health.lock().ok().and_then(|g| {
        g.as_ref()
            .filter(|(at, _)| at.elapsed() < HEALTH_TTL)
            .cloned()
    });
    let health = match cached {
        Some((_, h)) => h,
        None => {
            let root = app.store.root().to_path_buf();
            let h = blocking(move || Ok(scan(&root))).await?;
            if let Ok(mut g) = app.health.lock() {
                *g = Some((Instant::now(), h.clone()));
            }
            h
        }
    };
    Ok(json(StatusCode::OK, &health))
}

/// Counts result files, blob files and their bytes. Unreadable entries are
/// skipped: the numbers are for dashboards, not for correctness.
fn scan(root: &Path) -> Health {
    let mut h = Health {
        schema: SCHEMA,
        version: env!("CARGO_PKG_VERSION").into(),
        records: 0,
        blobs: 0,
        bytes: 0,
    };
    for (area, count) in [("results", true), ("objects", false)] {
        let (files, bytes) = count_files(&root.join(area));
        if count {
            h.records = files;
        } else {
            h.blobs = files;
        }
        h.bytes += bytes;
    }
    h
}

fn count_files(area: &Path) -> (u64, u64) {
    let (mut files, mut bytes) = (0, 0);
    for shard in read_dir_names(area) {
        let Ok(rd) = fs::read_dir(area.join(shard)) else {
            continue;
        };
        for entry in rd.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || name.contains("tmp-") {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                files += 1;
                bytes += meta.len();
            }
        }
    }
    (files, bytes)
}

fn read_dir_names(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

async fn get_pass_h(
    State(app): Shared,
    headers: HeaderMap,
    UrlPath(key): UrlPath<String>,
) -> ApiResult {
    authorize_read(&app, &headers)?;
    let key = parse_digest(&key)?;
    let store = app.store.clone();
    match blocking(move || store.get_pass(&key)).await? {
        Some(p) => Ok(json(StatusCode::OK, &p)),
        None => Err(not_found(&format!("stored pass for {key}"))),
    }
}

async fn get_blob_h(
    State(app): Shared,
    headers: HeaderMap,
    UrlPath(digest): UrlPath<String>,
) -> ApiResult {
    authorize_read(&app, &headers)?;
    let digest = parse_blob_digest(&digest)?;
    let store = app.store.clone();
    // `LocalStore::get_blob` rehashes the bytes and fails with `Corrupt`
    // before anything is served, which this maps to a 500 naming the file.
    match blocking(move || store.get_blob(&digest)).await? {
        Some(bytes) => Ok(octets(bytes)),
        None => Err(not_found(&format!("blob {digest}"))),
    }
}

fn octets(bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    )
        .into_response()
}

async fn put_record_h(State(app): Shared, headers: HeaderMap, body: Body) -> ApiResult {
    authorize(&app, &headers)?;
    let bytes = read_body(&headers, body, app.limits.record, "record").await?;
    let record: StoredRecord = serde_json::from_slice(&bytes).map_err(|e| {
        ApiError::bad(format!(
            "the body is not a result record ({e}); send the JSON of keel::store::StoredRecord"
        ))
    })?;
    let key = record.key;
    let store = app.store.clone();
    blocking(move || store.put(&record)).await?;
    Ok(json(StatusCode::OK, &serde_json::json!({ "key": key })))
}

async fn put_blob_h(State(app): Shared, headers: HeaderMap, body: Body) -> ApiResult {
    authorize(&app, &headers)?;
    let bytes = read_body(&headers, body, app.limits.blob, "blob").await?;
    let store = app.store.clone();
    let digest = blocking(move || store.put_blob(&bytes)).await?;
    Ok(json(StatusCode::OK, &DigestBody { digest }))
}

fn index_path(root: &Path, kind: &str, id: &str) -> PathBuf {
    root.join("index").join(kind).join(id)
}

fn check_id(kind: &str, id: &str) -> ApiResult<()> {
    if valid_id(id) {
        Ok(())
    } else {
        Err(ApiError::bad(format!(
            "`{id}` is not a usable {kind} id; use 1 to 128 of letters, digits, `.`, `_` and `-`, not starting with `.`"
        )))
    }
}

/// Stores a document as a blob and points `index/<kind>/<id>` at it.
/// Replacing an index entry is allowed (the same revision can be certified
/// again); the old blob stays until `gc`.
async fn put_indexed(app: &App, kind: &'static str, id: String, bytes: Vec<u8>) -> ApiResult {
    let store = app.store.clone();
    let digest = blocking(move || {
        let digest = store.put_blob(&bytes)?;
        let path = index_path(store.root(), kind, &id);
        write_index(&path, &digest)?;
        Ok(digest)
    })
    .await?;
    Ok(json(StatusCode::OK, &DigestBody { digest }))
}

fn write_index(path: &Path, digest: &Digest) -> Result<(), StoreError> {
    static N: AtomicU64 = AtomicU64::new(0);
    let io_err = |op, p: &Path| {
        let p = p.to_path_buf();
        move |source| StoreError::Io {
            op,
            path: p,
            source,
        }
    };
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir).map_err(io_err("create", dir))?;
    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(digest.to_string().as_bytes()))
        .map_err(io_err("write", &tmp))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_err("rename into place", path)(e)
    })
}

async fn get_indexed(app: &App, kind: &'static str, id: String) -> ApiResult {
    let store = app.store.clone();
    let found = blocking(move || {
        let path = index_path(store.root(), kind, &id);
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(StoreError::Io {
                    op: "read",
                    path,
                    source,
                });
            }
        };
        let digest = Digest::from_str(text.trim()).map_err(|e| StoreError::Corrupt {
            path: path.clone(),
            reason: e.to_string(),
        })?;
        store.get_blob(&digest).and_then(|b| match b {
            Some(b) => Ok(Some(b)),
            None => Err(StoreError::Corrupt {
                path,
                reason: format!("it points at {digest}, which is not in the store"),
            }),
        })
    })
    .await?;
    match found {
        Some(bytes) => Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response()),
        None => Err(not_found(&format!("stored {kind} for this id"))),
    }
}

async fn put_manifest_h(
    State(app): Shared,
    UrlPath(revision): UrlPath<String>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    authorize(&app, &headers)?;
    check_id("revision", &revision)?;
    let bytes = read_body(&headers, body, app.limits.record, "manifest").await?;
    // Validate with the strict protocol type, but store the caller's bytes
    // unchanged so a re-serialisation can never alter what was certified.
    let m: Manifest = serde_json::from_slice(&bytes).map_err(|e| {
        ApiError::bad(format!(
            "the body is not a node manifest (DESIGN §8.1): {e}"
        ))
    })?;
    if m.revision != revision {
        return Err(ApiError::bad(format!(
            "the manifest is for revision {} but the URL names {revision}; fix the URL",
            m.revision
        )));
    }
    put_indexed(&app, "manifest", revision, bytes).await
}

async fn get_manifest_h(
    State(app): Shared,
    headers: HeaderMap,
    UrlPath(revision): UrlPath<String>,
) -> ApiResult {
    authorize_read(&app, &headers)?;
    check_id("revision", &revision)?;
    get_indexed(&app, "manifest", revision).await
}

async fn put_report_h(
    State(app): Shared,
    UrlPath(run_id): UrlPath<String>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    authorize(&app, &headers)?;
    check_id("run", &run_id)?;
    let bytes = read_body(&headers, body, app.limits.record, "report").await?;
    let r: Report = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::bad(format!("the body is not a run report (DESIGN §8.2): {e}")))?;
    if r.run_id != run_id {
        return Err(ApiError::bad(format!(
            "the report is for run {} but the URL names {run_id}; fix the URL",
            r.run_id
        )));
    }
    put_indexed(&app, "report", run_id, bytes).await
}

async fn get_report_h(
    State(app): Shared,
    headers: HeaderMap,
    UrlPath(run_id): UrlPath<String>,
) -> ApiResult {
    authorize_read(&app, &headers)?;
    check_id("run", &run_id)?;
    get_indexed(&app, "report", run_id).await
}

/// One line per request on stderr: `method path status bytes ms`. Headers
/// are never logged, so the token cannot appear.
async fn log_requests(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let start = Instant::now();
    let resp = next.run(req).await;
    let bytes = resp.body().size_hint().exact().unwrap_or(0);
    eprintln!(
        "keel-store: method={method} path={path} status={} bytes={bytes} ms={}",
        resp.status().as_u16(),
        start.elapsed().as_millis()
    );
    resp
}

/// Builds the router for `config`, creating the store directory.
pub fn router(config: &Config) -> Result<Router, StoreError> {
    let app = Arc::new(App {
        store: LocalStore::open(&config.dir)?,
        token: blake3::hash(config.token.as_bytes()),
        read_token: config
            .read_token
            .as_ref()
            .map(|t| blake3::hash(t.as_bytes())),
        limits: config.limits,
        health: Mutex::new(None),
    });
    Ok(Router::new()
        .route("/v1/health", get(health_h))
        .route("/v1/pass/{key}", get(get_pass_h))
        .route("/v1/blob/{digest}", get(get_blob_h))
        .route("/v1/blob", put(put_blob_h))
        .route("/v1/record", put(put_record_h))
        .route(
            "/v1/manifest/{revision}",
            get(get_manifest_h).put(put_manifest_h),
        )
        .route("/v1/report/{run_id}", get(get_report_h).put(put_report_h))
        .layer(middleware::from_fn(log_requests))
        .with_state(app))
}

/// Serves the [`router`] on `listener` until `shutdown` resolves.
pub async fn serve(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// A server running on its own thread and runtime, stopped on drop. For
/// tests and for embedding; the binary uses [`serve`] directly.
pub struct Running {
    addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Running {
    /// Binds `listen` (port 0 picks a free one) and starts serving.
    pub fn spawn(config: Config, listen: SocketAddr) -> io::Result<Running> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => return drop(ready_tx.send(Err(e))),
            };
            rt.block_on(async {
                let listener = match tokio::net::TcpListener::bind(listen).await {
                    Ok(l) => l,
                    Err(e) => return drop(ready_tx.send(Err(e))),
                };
                let app = match router(&config) {
                    Ok(app) => app,
                    Err(e) => return drop(ready_tx.send(Err(io::Error::other(e)))),
                };
                let _ = ready_tx.send(listener.local_addr());
                let _ = serve(listener, app, async {
                    let _ = stop_rx.await;
                })
                .await;
            });
        });
        let addr = ready_rx
            .recv()
            .map_err(|_| io::Error::other("the server thread exited before binding"))??;
        Ok(Running {
            addr,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// The address actually bound.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://addr`, for building a client.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
