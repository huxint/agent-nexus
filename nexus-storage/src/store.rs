//! Block store — the persistence layer for Merkle nodes.
//!
//! A [`BlockStore`] is a key-value store keyed by [`Cid`].
//! The trait is `async` so it can be backed by disk, S3, IPFS, etc.

use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
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

    #[error("block store quota exceeded: used {used_bytes} bytes, limit {max_bytes} bytes")]
    QuotaExceeded { used_bytes: u64, max_bytes: u64 },

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

/// Result of a disk block-store garbage-collection pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Number of block files scanned.
    pub scanned_blocks: usize,
    /// Number of blocks reachable from pinned roots.
    pub retained_blocks: usize,
    /// Number of unreachable block files deleted.
    pub deleted_blocks: usize,
    /// Bytes removed from unreachable block files.
    pub deleted_bytes: u64,
    /// Bytes left in the block store after GC.
    pub retained_bytes: u64,
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

    /// List all block CIDs currently present on disk.
    pub fn list_cids(&self) -> StoreResult<Vec<Cid>> {
        let mut cids = Vec::new();
        if !self.root.exists() {
            return Ok(cids);
        }

        for prefix in std::fs::read_dir(&self.root)? {
            let prefix = prefix?;
            let file_type = prefix.file_type()?;
            if !file_type.is_dir() {
                continue;
            }
            let prefix_name = prefix.file_name().to_string_lossy().into_owned();
            if prefix_name.len() != 2 {
                continue;
            }
            for entry in std::fs::read_dir(prefix.path())? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let Some(rest) = name.strip_suffix(".cbor") else {
                    continue;
                };
                if let Some(cid) = cid_from_hex(&format!("{prefix_name}{rest}")) {
                    cids.push(cid);
                }
            }
        }
        cids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        cids.dedup();
        Ok(cids)
    }

    /// Total size in bytes of block files currently present on disk.
    pub fn total_size_bytes(&self) -> StoreResult<u64> {
        let mut bytes = 0_u64;
        if !self.root.exists() {
            return Ok(bytes);
        }

        for prefix in std::fs::read_dir(&self.root)? {
            let prefix = prefix?;
            if !prefix.file_type()?.is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(prefix.path())? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    bytes += entry.metadata()?.len();
                }
            }
        }
        Ok(bytes)
    }

    /// Delete blocks not reachable from `pinned_roots`.
    ///
    /// Pinned roots are ordinary Merkle root CIDs: every tree child and
    /// chunked-blob chunk reachable from those roots is retained. Unreachable
    /// block files are removed. If a pinned root points at a corrupt block, the
    /// traversal error is returned and no sweep is performed.
    pub async fn gc_unreachable(&self, pinned_roots: &[Cid]) -> StoreResult<GcReport> {
        let all_cids = self.list_cids()?;
        let all_set = all_cids.iter().copied().collect::<HashSet<_>>();
        let mut reachable = HashSet::new();
        for root in pinned_roots {
            if all_set.contains(root) {
                self.collect_reachable(root, &mut reachable).await?;
            }
        }

        let mut report = GcReport {
            scanned_blocks: all_cids.len(),
            retained_blocks: reachable.len(),
            ..Default::default()
        };

        for cid in all_cids {
            if reachable.contains(&cid) {
                continue;
            }
            let path = self.block_path(&cid);
            let size = match std::fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
                Err(err) => return Err(StoreError::Io(err)),
            };
            match Self::remove_block_file(&path) {
                Ok(true) => {
                    report.deleted_blocks += 1;
                    report.deleted_bytes += size;
                }
                Ok(false) => {}
                Err(err) => return Err(err),
            }
        }
        self.remove_empty_shards()?;
        report.retained_bytes = self.total_size_bytes()?;
        Ok(report)
    }

    /// Run GC and fail if reachable pinned data still exceeds `max_bytes`.
    pub async fn gc_unreachable_with_quota(
        &self,
        pinned_roots: &[Cid],
        max_bytes: u64,
    ) -> StoreResult<GcReport> {
        let report = self.gc_unreachable(pinned_roots).await?;
        if report.retained_bytes > max_bytes {
            return Err(StoreError::QuotaExceeded {
                used_bytes: report.retained_bytes,
                max_bytes,
            });
        }
        Ok(report)
    }

    async fn collect_reachable(&self, cid: &Cid, reachable: &mut HashSet<Cid>) -> StoreResult<()> {
        if !reachable.insert(*cid) {
            return Ok(());
        }
        let node = self.get(cid).await?;
        match node {
            MerkleNode::Tree { entries } => {
                for entry in entries {
                    Box::pin(self.collect_reachable(&entry.cid, reachable)).await?;
                }
            }
            MerkleNode::ChunkedBlob { chunks, .. } => {
                for chunk in chunks {
                    Box::pin(self.collect_reachable(&chunk, reachable)).await?;
                }
            }
            MerkleNode::Blob { .. } => {}
        }
        Ok(())
    }

    fn remove_block_file(path: &std::path::Path) -> StoreResult<bool> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(StoreError::Io(err)),
        }
    }

    fn remove_empty_shards(&self) -> StoreResult<()> {
        if !self.root.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                match std::fs::remove_dir(entry.path()) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => return Err(StoreError::Io(err)),
                }
            }
        }
        Ok(())
    }
}

fn cid_from_hex(hex_str: &str) -> Option<Cid> {
    let bytes = hex::decode(hex_str).ok()?;
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Some(Cid::from_bytes(bytes))
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

    #[tokio::test]
    async fn disk_gc_removes_unreachable_blocks_and_keeps_pinned_dag() {
        let root = std::env::temp_dir().join(format!(
            "nexus-storage-gc-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = DiskBlockStore::new(&root);

        let reachable_blob = store
            .put(MerkleNode::blob(b"reachable".to_vec()))
            .await
            .unwrap();
        let chunk_a = store
            .put(MerkleNode::blob(b"chunk-a".to_vec()))
            .await
            .unwrap();
        let chunk_b = store
            .put(MerkleNode::blob(b"chunk-b".to_vec()))
            .await
            .unwrap();
        let chunked = store
            .put(MerkleNode::chunked_blob(vec![chunk_a, chunk_b], 14))
            .await
            .unwrap();
        let root_cid = store
            .put(MerkleNode::tree(vec![
                TreeEntry {
                    name: "reachable.txt".into(),
                    cid: reachable_blob,
                    kind: NodeKind::Blob,
                },
                TreeEntry {
                    name: "large.bin".into(),
                    cid: chunked,
                    kind: NodeKind::Blob,
                },
            ]))
            .await
            .unwrap();
        let orphan = store
            .put(MerkleNode::blob(b"orphan".to_vec()))
            .await
            .unwrap();

        let report = store.gc_unreachable(&[root_cid]).await.unwrap();

        assert_eq!(report.scanned_blocks, 6);
        assert_eq!(report.retained_blocks, 5);
        assert_eq!(report.deleted_blocks, 1);
        assert!(report.deleted_bytes > 0);
        assert!(report.retained_bytes > 0);
        assert!(store.has(&root_cid).await.unwrap());
        assert!(store.has(&reachable_blob).await.unwrap());
        assert!(store.has(&chunked).await.unwrap());
        assert!(store.has(&chunk_a).await.unwrap());
        assert!(store.has(&chunk_b).await.unwrap());
        assert!(!store.has(&orphan).await.unwrap());

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn disk_gc_enforces_quota_after_sweep() {
        let root = std::env::temp_dir().join(format!(
            "nexus-storage-quota-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = DiskBlockStore::new(&root);
        let blob = store
            .put(MerkleNode::blob(b"kept block".to_vec()))
            .await
            .unwrap();

        let err = store
            .gc_unreachable_with_quota(&[blob], 1)
            .await
            .unwrap_err();

        assert!(matches!(err, StoreError::QuotaExceeded { .. }));
        assert!(store.has(&blob).await.unwrap());

        let _ = std::fs::remove_dir_all(root);
    }
}
