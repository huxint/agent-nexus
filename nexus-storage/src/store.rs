//! Block store — the persistence layer for Merkle nodes.
//!
//! A [`BlockStore`] is a key-value store keyed by [`Cid`].
//! The trait is `async` so it can be backed by disk, S3, IPFS, etc.

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::cid::Cid;
use crate::node::MerkleNode;

/// Errors that can occur during block store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("block not found: {0}")]
    NotFound(Cid),

    #[error("serialisation: {0}")]
    Serialisation(String),

    #[error("IO: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// A content-addressed block store.
///
/// Implementations must guarantee that `get(cid)` returns the exact bytes
/// that were passed to `put(node)` — i.e. the store is immutable (no
/// overwrites for the same CID; content-addressable by construction).
#[async_trait]
pub trait BlockStore: Send + Sync {
    /// Store a Merkle node and return its CID.
    async fn put(&self, node: MerkleNode) -> StoreResult<Cid>;

    /// Retrieve a Merkle node by CID.
    async fn get(&self, cid: &Cid) -> StoreResult<MerkleNode>;

    /// Check whether a block exists.
    async fn has(&self, cid: &Cid) -> StoreResult<bool>;
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/// A simple in-memory block store, useful for tests and single-node operation.
pub struct InMemoryBlockStore {
    blocks: Mutex<HashMap<Cid, MerkleNode>>,
}

impl InMemoryBlockStore {
    pub fn new() -> Self {
        Self {
            blocks: Mutex::new(HashMap::new()),
        }
    }

    /// Number of blocks currently stored.
    pub fn len(&self) -> usize {
        self.blocks.lock().unwrap().len()
    }

    /// True if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.blocks.lock().unwrap().is_empty()
    }
}

impl Default for InMemoryBlockStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlockStore for InMemoryBlockStore {
    async fn put(&self, node: MerkleNode) -> StoreResult<Cid> {
        let cid = node.cid();
        self.blocks.lock().unwrap().insert(cid, node);
        Ok(cid)
    }

    async fn get(&self, cid: &Cid) -> StoreResult<MerkleNode> {
        self.blocks
            .lock()
            .unwrap()
            .get(cid)
            .cloned()
            .ok_or(StoreError::NotFound(*cid))
    }

    async fn has(&self, cid: &Cid) -> StoreResult<bool> {
        Ok(self.blocks.lock().unwrap().contains_key(cid))
    }
}

// ---------------------------------------------------------------------------
// Disk-backed implementation
// ---------------------------------------------------------------------------

/// A disk-backed block store.
///
/// Each block is stored as a file at `<root>/<first_2_hex>/<cid_hex>.cbor`.
/// The two-char prefix sharding prevents too many files in one directory.
pub struct DiskBlockStore {
    root: PathBuf,
}

impl DiskBlockStore {
    /// Create or open a disk-backed block store at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Path to a block file: `<root>/<ab>/<abcdef....cbor>`.
    fn block_path(&self, cid: &Cid) -> PathBuf {
        let hex_str = hex::encode(cid.as_bytes());
        let prefix = &hex_str[..2];
        let rest = &hex_str[2..];
        self.root.join(prefix).join(format!("{rest}.cbor"))
    }
}

#[async_trait]
impl BlockStore for DiskBlockStore {
    async fn put(&self, node: MerkleNode) -> StoreResult<Cid> {
        let cid = node.cid();
        let path = self.block_path(&cid);

        // Skip only after verifying the existing block still matches its CID.
        if path.exists() && self.get(&cid).await.is_ok() {
            return Ok(cid);
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let cbor = node.to_cbor().map_err(StoreError::Serialisation)?;
        std::fs::write(&path, &cbor)?;
        Ok(cid)
    }

    async fn get(&self, cid: &Cid) -> StoreResult<MerkleNode> {
        let path = self.block_path(cid);
        if !path.exists() {
            return Err(StoreError::NotFound(*cid));
        }
        let cbor = std::fs::read(&path)?;
        let node = MerkleNode::from_cbor(&cbor).map_err(StoreError::Serialisation)?;
        let actual = node.cid();
        if actual != *cid {
            return Err(StoreError::Other(format!(
                "block content CID mismatch: expected {}, got {}",
                hex::encode(cid.as_bytes()),
                hex::encode(actual.as_bytes())
            )));
        }
        Ok(node)
    }

    async fn has(&self, cid: &Cid) -> StoreResult<bool> {
        match self.get(cid).await {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(StoreError::Serialisation(_) | StoreError::Other(_)) => Ok(false),
            Err(StoreError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Recursively store a tree and all its descendants into `store`.
///
/// Returns the root CID.  This is the primary entry point for persisting
/// a workspace file tree.
pub async fn store_tree(store: &impl BlockStore, root: MerkleNode) -> StoreResult<Cid> {
    match &root {
        MerkleNode::Tree { entries } => {
            // Depth-first: store children first, then the parent
            for entry in entries {
                let child = store.get(&entry.cid).await?;
                // Already stored — nothing to do; but in the future we may
                // need to recurse for inline nodes.
                let _ = child;
            }
        }
        MerkleNode::ChunkedBlob { chunks, .. } => {
            for chunk in chunks {
                let child = store.get(chunk).await?;
                let _ = child;
            }
        }
        MerkleNode::Blob { .. } => {
            // Leaf node — just store it.
        }
    }

    store.put(root).await
}

/// Recursively fetch a tree and all its descendants from `store`.
///
/// The callback `on_node` is invoked for every node encountered during
/// the traversal (depth-first).
pub async fn fetch_tree<F>(
    store: &impl BlockStore,
    root_cid: &Cid,
    on_node: &mut F,
) -> StoreResult<MerkleNode>
where
    F: FnMut(&Cid, &MerkleNode) + Send,
{
    let node = store.get(root_cid).await?;
    on_node(root_cid, &node);

    match &node {
        MerkleNode::Tree { entries } => {
            for entry in entries {
                // Box the future to allow recursion in async context
                Box::pin(fetch_tree(store, &entry.cid, on_node)).await?;
            }
        }
        MerkleNode::ChunkedBlob { chunks, .. } => {
            for chunk in chunks {
                // Box the future to allow recursion in async context
                Box::pin(fetch_tree(store, chunk, on_node)).await?;
            }
        }
        MerkleNode::Blob { .. } => {}
    }

    Ok(node)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{NodeKind, TreeEntry};

    #[tokio::test]
    async fn put_and_get() {
        let store = InMemoryBlockStore::new();
        let blob = MerkleNode::blob(b"hello nexus".to_vec());
        let cid = store.put(blob.clone()).await.unwrap();

        assert!(store.has(&cid).await.unwrap());

        let retrieved = store.get(&cid).await.unwrap();
        assert_eq!(retrieved, blob);
    }

    #[tokio::test]
    async fn not_found() {
        let store = InMemoryBlockStore::new();
        let cid = Cid::hash_of(b"nonexistent");
        let err = store.get(&cid).await.unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
    }

    #[tokio::test]
    async fn store_and_fetch_tree() {
        let store = InMemoryBlockStore::new();

        // Build: root/
        //         ├── hello.txt → blob("world")
        //         └── sub/
        //             └── data.bin → blob([1,2,3])
        let blob_hello = MerkleNode::blob(b"world".to_vec());
        let cid_hello = store.put(blob_hello).await.unwrap();

        let blob_data = MerkleNode::blob(vec![1, 2, 3]);
        let cid_data = store.put(blob_data).await.unwrap();

        let sub_tree = MerkleNode::tree(vec![TreeEntry {
            name: "data.bin".into(),
            cid: cid_data,
            kind: NodeKind::Blob,
        }]);
        let cid_sub = store.put(sub_tree).await.unwrap();

        let cid_chunk_a = store
            .put(MerkleNode::blob(b"large-".to_vec()))
            .await
            .unwrap();
        let cid_chunk_b = store.put(MerkleNode::blob(b"file".to_vec())).await.unwrap();
        let cid_chunked = store
            .put(MerkleNode::chunked_blob(
                vec![cid_chunk_a, cid_chunk_b],
                "large-file".len() as u64,
            ))
            .await
            .unwrap();

        let root_tree = MerkleNode::tree(vec![
            TreeEntry {
                name: "hello.txt".into(),
                cid: cid_hello,
                kind: NodeKind::Blob,
            },
            TreeEntry {
                name: "large.bin".into(),
                cid: cid_chunked,
                kind: NodeKind::Blob,
            },
            TreeEntry {
                name: "sub".into(),
                cid: cid_sub,
                kind: NodeKind::Tree,
            },
        ]);
        let cid_root = store.put(root_tree.clone()).await.unwrap();

        // Fetch entire tree
        let mut visited = Vec::new();
        fetch_tree(&store, &cid_root, &mut |cid, node| {
            visited.push((*cid, node.kind()));
        })
        .await
        .unwrap();

        // Should have visited 7 nodes: root, hello, chunked file,
        // two chunks, sub, and data.
        assert_eq!(visited.len(), 7);
    }

    #[tokio::test]
    async fn disk_store_rejects_and_repairs_wrong_content_at_cid_path() {
        let root = std::env::temp_dir().join(format!(
            "nexus-storage-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = DiskBlockStore::new(&root);
        let expected = MerkleNode::blob(b"expected".to_vec());
        let expected_cid = expected.cid();
        let wrong = MerkleNode::blob(b"wrong".to_vec());
        let wrong_cbor = wrong.to_cbor().unwrap();
        let path = store.block_path(&expected_cid);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, wrong_cbor).unwrap();

        let err = store.get(&expected_cid).await.unwrap_err();
        assert!(matches!(
            err,
            StoreError::Other(message) if message.contains("block content CID mismatch")
        ));
        assert!(!store.has(&expected_cid).await.unwrap());

        store.put(expected.clone()).await.unwrap();
        assert!(store.has(&expected_cid).await.unwrap());
        let repaired = store.get(&expected_cid).await.unwrap();
        assert_eq!(repaired, expected);

        let _ = std::fs::remove_dir_all(root);
    }
}
