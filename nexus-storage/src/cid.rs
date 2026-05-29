//! Content Identifier — a SHA-256 hash used as a content address.
//!
//! We keep it simple: `Cid` = 32-byte SHA-256 digest.  No multihash
//! prefix or varint framing at this layer (we can layer that on later).

use serde::{Deserialize, Serialize};
use std::fmt;

/// A content identifier — 32-byte SHA-256 hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cid([u8; 32]);

impl Cid {
    /// The size of a CID (32 bytes for SHA-256).
    pub const SIZE: usize = 32;

    /// Create a CID from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute the CID of arbitrary bytes (SHA-256 hash).
    pub fn hash_of(data: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show first 8 hex chars for readability
        write!(f, "cid({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cid({})", hex::encode(&self.0[..8]))
    }
}

impl From<[u8; 32]> for Cid {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_hash() {
        let c1 = Cid::hash_of(b"hello");
        let c2 = Cid::hash_of(b"hello");
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_data_different_hash() {
        let c1 = Cid::hash_of(b"hello");
        let c2 = Cid::hash_of(b"world");
        assert_ne!(c1, c2);
    }

    #[test]
    fn size_is_32() {
        let cid = Cid::hash_of(b"test");
        assert_eq!(cid.as_bytes().len(), 32);
    }
}
