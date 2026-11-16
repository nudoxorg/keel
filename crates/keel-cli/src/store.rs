//! `--store <url|dir>`: either a keel-store service or a store directory.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use keel::store::{LocalStore, ResultStore, StoredPass};
use keel::{Digest, Manifest};
use keel_store::client::Client;

pub enum Store {
    Remote(Client),
    Local(LocalStore),
}

/// Tokens come from the files the service's own tooling uses, so the CLI needs
/// no flag for a secret: `KEEL_STORE_READ_TOKEN_FILE`, else `KEEL_STORE_TOKEN_FILE`.
fn token(var: &str) -> Result<Option<String>> {
    match std::env::var_os(var) {
        Some(p) => Ok(Some(Client::read_token_file(Path::new(&p))?)),
        None => Ok(None),
    }
}

impl Store {
    pub fn open(spec: &str) -> Result<Store> {
        if spec.starts_with("http://") {
            let (read, write) = (
                token("KEEL_STORE_READ_TOKEN_FILE")?,
                token("KEEL_STORE_TOKEN_FILE")?,
            );
            let c = match (read, write) {
                (Some(r), w) => Client::new(spec, w).with_read_token(r),
                (None, w) => Client::new(spec, w),
            };
            return Ok(Store::Remote(c));
        }
        if spec.starts_with("https://") {
            bail!(
                "--store {spec}: this build speaks plain http only (the store is on the CI bridge, DESIGN §6); use the http:// bridge address"
            );
        }
        let dir = PathBuf::from(spec);
        if !dir.join("objects").is_dir() {
            bail!(
                "--store {spec} is neither an http:// URL nor a store directory (no `objects/` inside); check the path"
            );
        }
        Ok(Store::Local(LocalStore::open(dir)?))
    }

    /// The Stage-0 manifest the store holds for `revision`, if any.
    pub fn manifest(&self, revision: &str) -> Result<Option<Manifest>> {
        match self {
            Store::Remote(c) => Ok(c.get_manifest(revision)?),
            Store::Local(s) => {
                // The service keeps `index/manifest/<revision>` holding a blob digest.
                let pointer = s.root().join("index").join("manifest").join(revision);
                let Ok(text) = std::fs::read_to_string(&pointer) else {
                    return Ok(None);
                };
                let digest = Digest::from_str(text.trim()).with_context(|| {
                    format!(
                        "{} does not hold a digest; delete it and rerun the canonical run",
                        pointer.display()
                    )
                })?;
                let Some(bytes) = s.get_blob(&digest)? else {
                    return Ok(None);
                };
                Ok(Some(serde_json::from_slice(&bytes)?))
            }
        }
    }

    pub fn blob(&self, d: &Digest) -> Result<Option<Vec<u8>>> {
        Ok(match self {
            Store::Remote(c) => c.get_blob(d)?,
            Store::Local(s) => s.get_blob(d)?,
        })
    }

    pub fn pass(&self, key: &Digest) -> Result<Option<StoredPass>> {
        Ok(match self {
            Store::Remote(c) => c.get_pass(key)?,
            Store::Local(s) => s.get_pass(key)?,
        })
    }
}
