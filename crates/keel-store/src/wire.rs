//! What crosses the wire: shared by the service and the client so the two
//! cannot drift apart.

use keel::Digest;
use serde::{Deserialize, Serialize};

/// The `schema` of every JSON body this service produces.
pub const SCHEMA: u32 = 1;
/// Largest accepted blob body (`PUT /v1/blob`), DESIGN §6 outputs.
pub const BLOB_LIMIT: usize = 64 * 1024 * 1024;
/// Largest accepted record, manifest or report body.
pub const RECORD_LIMIT: usize = 16 * 1024 * 1024;

/// `GET /v1/health`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Health {
    /// Always [`SCHEMA`].
    pub schema: u32,
    /// The service's crate version.
    pub version: String,
    /// Result files on disk, one per key (not lines: counting lines would
    /// mean reading every file). Approximate: cached for up to 30 s.
    pub records: u64,
    /// Blob files on disk. Approximate in the same way.
    pub blobs: u64,
    /// Bytes in those result and blob files. Approximate in the same way.
    pub bytes: u64,
}

/// `PUT /v1/blob`, `PUT /v1/manifest/..` and `PUT /v1/report/..` answer with
/// the blob the bytes were stored as.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DigestBody {
    /// `blake3:<hex>`.
    pub digest: Digest,
}

/// Every non-2xx answer.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    /// What failed and what to do. Never contains the token.
    pub error: String,
    /// `corrupt` for a damaged store file, `full` for a full disk, else
    /// absent; lets the client map the failure without parsing prose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// Whether `id` is safe to use as a file name for a revision or run id:
/// 1 to 128 of `[A-Za-z0-9._-]`, not starting with `.`, so it cannot climb
/// out of the index directory.
pub fn valid_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && !id.starts_with('.')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
