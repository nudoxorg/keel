//! Opening the store named on the command line: an `http://` URL (the
//! `keel-store` service, tokens from the environment) or a directory.

use std::path::Path;

use anyhow::{Context, Result, bail};
use keel::store::{LocalStore, ResultStore, StoredPass, StoredRecord};
use keel::{Digest, Report};
use keel_store::client::Client;

/// Either kind of store, behind one [`ResultStore`].
pub enum Store {
    /// A directory.
    Local(LocalStore),
    /// The service; `writable` is whether a writer token was given.
    Remote {
        /// The client.
        client: Client,
        /// Whether writes can succeed.
        writable: bool,
    },
}

impl Store {
    /// `spec` is `http://host:port` or a directory (created if absent).
    ///
    /// The writer token file is `$KEEL_STORE_TOKEN_FILE`, the read token file
    /// `$KEEL_STORE_READ_TOKEN_FILE`; neither value is ever printed.
    pub fn open(spec: &str) -> Result<Store> {
        if spec.starts_with("https://") {
            bail!(
                "the store URL {spec} is https, but the keel client speaks plain http over the CI bridge; use http:// (no TLS stack is linked into the conductor)"
            );
        }
        if !spec.starts_with("http://") {
            return Ok(Store::Local(
                LocalStore::open(Path::new(spec)).with_context(|| {
                    format!("cannot open the store directory {spec}; pass --store <dir|url>")
                })?,
            ));
        }
        // An empty variable counts as unset: it is how a shell clears one.
        let set = |name| std::env::var_os(name).filter(|v| !v.is_empty());
        let writer = set("KEEL_STORE_TOKEN_FILE")
            .map(|p| Client::read_token_file(Path::new(&p)))
            .transpose()?;
        let mut client = Client::new(spec, writer.clone());
        if let Some(p) = set("KEEL_STORE_READ_TOKEN_FILE") {
            client = client.with_read_token(Client::read_token_file(Path::new(&p))?);
        }
        Ok(Store::Remote {
            client,
            writable: writer.is_some(),
        })
    }

    /// Uploads the run report to the service's report index. A directory
    /// store has no index; a read-only client cannot write one.
    pub fn publish_report(&self, report: &Report) -> Result<bool> {
        match self {
            Store::Remote {
                client,
                writable: true,
            } => {
                client.put_report(report)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

impl ResultStore for Store {
    fn get_pass(&self, key: &Digest) -> keel::store::Result<Option<StoredPass>> {
        match self {
            Store::Local(s) => s.get_pass(key),
            Store::Remote { client, .. } => ResultStore::get_pass(client, key),
        }
    }
    fn put(&self, record: &StoredRecord) -> keel::store::Result<()> {
        match self {
            Store::Local(s) => s.put(record),
            Store::Remote { client, .. } => ResultStore::put(client, record),
        }
    }
    fn put_blob(&self, bytes: &[u8]) -> keel::store::Result<Digest> {
        match self {
            Store::Local(s) => s.put_blob(bytes),
            Store::Remote { client, .. } => ResultStore::put_blob(client, bytes),
        }
    }
    fn get_blob(&self, d: &Digest) -> keel::store::Result<Option<Vec<u8>>> {
        match self {
            Store::Local(s) => s.get_blob(d),
            Store::Remote { client, .. } => ResultStore::get_blob(client, d),
        }
    }
}
