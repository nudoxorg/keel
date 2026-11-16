//! A blocking client for the service, implementing [`ResultStore`] so the
//! runner can hold a `Box<dyn ResultStore>` that is either a `LocalStore` or
//! this, chosen at startup.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use keel::store::{ResultStore, StoreError, StoredPass, StoredRecord};
use keel::{Digest, Manifest, Report};
use serde::de::DeserializeOwned;

use crate::wire::{BLOB_LIMIT, DigestBody, ErrorBody, Health, RECORD_LIMIT, valid_id};

/// Why a call failed. Every message names the endpoint and what to check.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// No TCP connection, a timeout, or a dropped socket.
    #[error(
        "cannot reach the result store for {endpoint}: {detail}; check that keel-store is running (`systemctl status keel-store`), that the URL and KEEL_STORE_PORT are right, and that the CI bridge route is up"
    )]
    Unreachable {
        /// `METHOD url`.
        endpoint: String,
        /// The transport error.
        detail: String,
    },
    /// The service answered 401.
    #[error(
        "the result store refused {endpoint}: the token is missing or wrong (writes need the writer token, reads the read token or the writer token); check the token files this process reads (KEEL_STORE_TOKEN_FILE, KEEL_STORE_READ_TOKEN_FILE) match the service's"
    )]
    Unauthorized {
        /// `METHOD url`.
        endpoint: String,
    },
    /// A write needs a token and this client has none.
    #[error(
        "{endpoint} needs the writer token but this client has none; build it with a token (Client::with_token_file)"
    )]
    NoToken {
        /// `METHOD url`.
        endpoint: String,
    },
    /// The body is over a size limit, here or on the service.
    #[error("the result store refused {endpoint}: {detail}")]
    TooLarge {
        /// `METHOD url`.
        endpoint: String,
        /// Which limit.
        detail: String,
    },
    /// The disk behind the store is full or below its reserve.
    #[error(
        "the result store could not write {endpoint}: {detail}; free space on the store disk (`keel-store gc --dry-run` shows what retention would remove) or lower the retention"
    )]
    Full {
        /// `METHOD url`.
        endpoint: String,
        /// The service's message.
        detail: String,
    },
    /// The service reported a damaged store file.
    #[error("the result store reports a corrupt entry for {endpoint}: {detail}")]
    Corrupt {
        /// `METHOD url`.
        endpoint: String,
        /// The service's message.
        detail: String,
    },
    /// Any other non-2xx answer.
    #[error(
        "the result store answered {status} to {endpoint}: {detail}; see the keel-store log on the CI host"
    )]
    Status {
        /// `METHOD url`.
        endpoint: String,
        /// HTTP status.
        status: u16,
        /// The service's message.
        detail: String,
    },
    /// A 2xx answer that is not what the endpoint promises.
    #[error(
        "the result store's answer to {endpoint} could not be understood: {detail}; the client and service may be different versions, check `GET /v1/health`"
    )]
    Decode {
        /// `METHOD url`.
        endpoint: String,
        /// What was wrong.
        detail: String,
    },
    /// A revision or run id that cannot be a path segment.
    #[error(
        "`{0}` is not a usable id; use 1 to 128 of letters, digits, `.`, `_` and `-`, not starting with `.`"
    )]
    BadId(String),
}

impl ClientError {
    fn from_status(endpoint: String, status: u16, body: &[u8]) -> ClientError {
        let parsed: Option<ErrorBody> = serde_json::from_slice(body).ok();
        let detail = parsed.as_ref().map_or_else(
            || String::from_utf8_lossy(body).into_owned(),
            |b| b.error.clone(),
        );
        let kind = parsed.and_then(|b| b.kind);
        match (status, kind.as_deref()) {
            (401, _) => ClientError::Unauthorized { endpoint },
            (413, _) => ClientError::TooLarge { endpoint, detail },
            (507, _) | (_, Some("full")) => ClientError::Full { endpoint, detail },
            (_, Some("corrupt")) => ClientError::Corrupt { endpoint, detail },
            _ => ClientError::Status {
                endpoint,
                status,
                detail,
            },
        }
    }
}

/// The store as seen from the runner.
#[derive(Clone)]
pub struct Client {
    agent: ureq::Agent,
    base: String,
    /// Sent with every write, and with reads when there is no read token.
    token: Option<String>,
    /// Sent with reads.
    read_token: Option<String>,
}

impl Client {
    /// A client for the service at `base` (`http://192.0.2.1:PORT`), with the
    /// writer token if it will write. Connect timeout 5 s; 60 s for the
    /// response and for each socket read, so a large blob that keeps flowing
    /// is not cut off.
    pub fn new(base: &str, token: Option<String>) -> Client {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .timeout_per_read(Some(Duration::from_secs(60)))
            // Statuses are mapped by us so the body's message is kept.
            .http_status_as_error(false)
            .build()
            .into();
        Client {
            agent,
            base: base.trim_end_matches('/').to_owned(),
            token,
            read_token: None,
        }
    }

    /// Sets the read token, sent with GETs. Without one, reads carry the
    /// writer token if there is one (the service accepts it for reads).
    #[must_use]
    pub fn with_read_token(mut self, read_token: impl Into<String>) -> Client {
        self.read_token = Some(read_token.into());
        self
    }

    /// Reads a token file the way the service does (trailing whitespace trimmed).
    pub fn read_token_file(path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
            .map(|t| t.trim().to_owned())
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "cannot read the token file {}: {e}; check the path and that this user may read it",
                        path.display()
                    ),
                )
            })
    }

    /// Like [`Client::new`], reading the token from a file (trailing
    /// whitespace trimmed), as the conductor does.
    pub fn with_token_file(base: &str, token_file: &Path) -> io::Result<Client> {
        let token = std::fs::read_to_string(token_file).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "cannot read the writer token file {}: {e}; check the path and that this user may read it",
                    token_file.display()
                ),
            )
        })?;
        Ok(Client::new(base, Some(token.trim().to_owned())))
    }

    /// One request with one retry on a connection-level failure. A retried
    /// record `PUT` can append the record twice if the first attempt reached
    /// the service; a duplicate line changes nothing `get_pass` returns.
    fn call(
        &self,
        method: &'static str,
        path: &str,
        body: Option<(&str, &[u8])>,
        write: bool,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        let url = format!("{}{path}", self.base);
        let endpoint = format!("{method} {url}");
        if write && self.token.is_none() {
            return Err(ClientError::NoToken { endpoint });
        }
        let mut last = None;
        for _attempt in 0..2 {
            let auth = self.token.as_ref().map(|t| format!("Bearer {t}"));
            let sent = match body {
                Some((ctype, bytes)) => {
                    let mut req = self.agent.put(&url).header("Content-Type", ctype);
                    if let Some(a) = &auth {
                        req = req.header("Authorization", a);
                    }
                    req.send(bytes)
                }
                None => {
                    let mut req = self.agent.get(&url);
                    // /v1/health is open; every other read needs a token.
                    if let Some(t) = self.read_token.as_ref().or(self.token.as_ref()) {
                        req = req.header("Authorization", format!("Bearer {t}"));
                    }
                    req.call()
                }
            };
            let mut resp = match sent {
                Ok(r) => r,
                Err(
                    e @ (ureq::Error::ConnectionFailed
                    | ureq::Error::Io(_)
                    | ureq::Error::Timeout(_)),
                ) => {
                    last = Some(e);
                    continue;
                }
                Err(e) => {
                    return Err(ClientError::Unreachable {
                        endpoint,
                        detail: e.to_string(),
                    });
                }
            };
            let status = resp.status().as_u16();
            let bytes = resp
                .body_mut()
                .with_config()
                .limit(BLOB_LIMIT as u64 + 1)
                .read_to_vec()
                .map_err(|e| ClientError::Unreachable {
                    endpoint: endpoint.clone(),
                    detail: e.to_string(),
                })?;
            return match status {
                200..=299 => Ok(Some(bytes)),
                404 => Ok(None),
                _ => Err(ClientError::from_status(endpoint, status, &bytes)),
            };
        }
        let detail = last.map_or_else(String::new, |e| e.to_string());
        Err(ClientError::Unreachable { endpoint, detail })
    }

    fn decode<T: DeserializeOwned>(
        method: &str,
        path: &str,
        bytes: &[u8],
    ) -> Result<T, ClientError> {
        serde_json::from_slice(bytes).map_err(|e| ClientError::Decode {
            endpoint: format!("{method} {path}"),
            detail: e.to_string(),
        })
    }

    fn limit_check(
        &self,
        method: &str,
        path: &str,
        len: usize,
        limit: usize,
        what: &str,
    ) -> Result<(), ClientError> {
        if len > limit {
            return Err(ClientError::TooLarge {
                endpoint: format!("{method} {}{path}", self.base),
                detail: format!(
                    "the {what} is {len} bytes, over the {what} limit of {} MiB; split it into smaller blobs",
                    limit / (1024 * 1024)
                ),
            });
        }
        Ok(())
    }

    /// `GET /v1/health`.
    pub fn health(&self) -> Result<Health, ClientError> {
        let b = self
            .call("GET", "/v1/health", None, false)?
            .unwrap_or_default();
        Self::decode("GET", "/v1/health", &b)
    }

    /// The newest stored pass for `key`.
    pub fn get_pass(&self, key: &Digest) -> Result<Option<StoredPass>, ClientError> {
        let path = format!("/v1/pass/{key}");
        match self.call("GET", &path, None, false)? {
            Some(b) => Ok(Some(Self::decode::<StoredPass>("GET", &path, &b)?)),
            None => Ok(None),
        }
    }

    /// Appends a record (needs the token).
    pub fn put_record(&self, record: &StoredRecord) -> Result<(), ClientError> {
        let body = serde_json::to_vec(record).map_err(|e| ClientError::Decode {
            endpoint: "PUT /v1/record".into(),
            detail: format!("cannot encode the record: {e}"),
        })?;
        self.limit_check("PUT", "/v1/record", body.len(), RECORD_LIMIT, "record")?;
        self.call("PUT", "/v1/record", Some(("application/json", &body)), true)?;
        Ok(())
    }

    /// Stores a blob and returns its digest (needs the token).
    pub fn put_blob(&self, bytes: &[u8]) -> Result<Digest, ClientError> {
        self.limit_check("PUT", "/v1/blob", bytes.len(), BLOB_LIMIT, "blob")?;
        let b = self
            .call(
                "PUT",
                "/v1/blob",
                Some(("application/octet-stream", bytes)),
                true,
            )?
            .unwrap_or_default();
        let d: DigestBody = Self::decode("PUT", "/v1/blob", &b)?;
        // The service says what it stored; check it is what we sent.
        if d.digest != Digest::of(bytes) {
            return Err(ClientError::Decode {
                endpoint: "PUT /v1/blob".into(),
                detail: format!(
                    "the service stored {} but the bytes hash to {}",
                    d.digest,
                    Digest::of(bytes)
                ),
            });
        }
        Ok(d.digest)
    }

    /// The bytes behind `d`, verified against the digest.
    pub fn get_blob(&self, d: &Digest) -> Result<Option<Vec<u8>>, ClientError> {
        let path = format!("/v1/blob/{d}");
        let Some(bytes) = self.call("GET", &path, None, false)? else {
            return Ok(None);
        };
        // Verify on this side too: the service checks its disk, this checks
        // the wire.
        if matches!(d, Digest::Blake3(_)) && Digest::of(&bytes) != *d {
            return Err(ClientError::Decode {
                endpoint: format!("GET {path}"),
                detail: format!("the bytes received hash to {}, not {d}", Digest::of(&bytes)),
            });
        }
        Ok(Some(bytes))
    }

    /// The Stage-0 manifest stored for `revision`.
    pub fn get_manifest(&self, revision: &str) -> Result<Option<Manifest>, ClientError> {
        self.get_doc("manifest", revision)
    }

    /// Stores `manifest` under its own revision (needs the token).
    pub fn put_manifest(&self, manifest: &Manifest) -> Result<Digest, ClientError> {
        self.put_doc("manifest", &manifest.revision, manifest)
    }

    /// The run report stored for `run_id`.
    pub fn get_report(&self, run_id: &str) -> Result<Option<Report>, ClientError> {
        self.get_doc("report", run_id)
    }

    /// Stores `report` under its own run id (needs the token).
    pub fn put_report(&self, report: &Report) -> Result<Digest, ClientError> {
        self.put_doc("report", &report.run_id, report)
    }

    fn get_doc<T: DeserializeOwned>(&self, kind: &str, id: &str) -> Result<Option<T>, ClientError> {
        if !valid_id(id) {
            return Err(ClientError::BadId(id.into()));
        }
        let path = format!("/v1/{kind}/{id}");
        match self.call("GET", &path, None, false)? {
            Some(b) => Ok(Some(Self::decode("GET", &path, &b)?)),
            None => Ok(None),
        }
    }

    fn put_doc<T: serde::Serialize>(
        &self,
        kind: &str,
        id: &str,
        doc: &T,
    ) -> Result<Digest, ClientError> {
        if !valid_id(id) {
            return Err(ClientError::BadId(id.into()));
        }
        let path = format!("/v1/{kind}/{id}");
        let body = serde_json::to_vec(doc).map_err(|e| ClientError::Decode {
            endpoint: format!("PUT {path}"),
            detail: format!("cannot encode the {kind}: {e}"),
        })?;
        self.limit_check("PUT", &path, body.len(), RECORD_LIMIT, kind)?;
        let b = self
            .call("PUT", &path, Some(("application/json", &body)), true)?
            .unwrap_or_default();
        Ok(Self::decode::<DigestBody>("PUT", &path, &b)?.digest)
    }
}

/// Every failure of a remote call becomes `StoreError::Remote`, which names
/// the endpoint and tells the operator what to check. The one exception is a
/// damaged entry the service reports: it stays `Corrupt`, so callers that
/// treat a corrupt local entry as a miss treat a corrupt remote one the same.
fn to_store_error(e: ClientError) -> StoreError {
    let (endpoint, reason) = match e {
        ClientError::Corrupt { endpoint, detail } => {
            return StoreError::Corrupt {
                path: PathBuf::from(endpoint),
                reason: detail,
            };
        }
        ClientError::Unreachable { endpoint, detail }
        | ClientError::TooLarge { endpoint, detail }
        | ClientError::Full { endpoint, detail }
        | ClientError::Decode { endpoint, detail } => (endpoint, detail),
        ClientError::Unauthorized { endpoint } => {
            (endpoint, "the token is missing or wrong".into())
        }
        ClientError::NoToken { endpoint } => (endpoint, "this client has no writer token".into()),
        ClientError::Status {
            endpoint,
            status,
            detail,
        } => (endpoint, format!("status {status}: {detail}")),
        ClientError::BadId(id) => ("(not sent)".into(), format!("`{id}` is not a usable id")),
    };
    StoreError::Remote { endpoint, reason }
}

impl ResultStore for Client {
    fn get_pass(&self, key: &Digest) -> keel::store::Result<Option<StoredPass>> {
        Client::get_pass(self, key).map_err(to_store_error)
    }

    fn put(&self, record: &StoredRecord) -> keel::store::Result<()> {
        self.put_record(record).map_err(to_store_error)
    }

    fn put_blob(&self, bytes: &[u8]) -> keel::store::Result<Digest> {
        Client::put_blob(self, bytes).map_err(to_store_error)
    }

    fn get_blob(&self, d: &Digest) -> keel::store::Result<Option<Vec<u8>>> {
        Client::get_blob(self, d).map_err(to_store_error)
    }
}
