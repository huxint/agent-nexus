//! Workspace — the core abstraction that ties storage, execution, and identity together.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use nexus_core::{Capability, Did, PermissionSet, WorkspaceId};
use nexus_crypto::capability::verify_capability_for_caller;
use nexus_crypto::NodeIdentity;
use nexus_runtime::{ExecOptions, Executor, ProcessOutput, ResourceUsage};
use nexus_storage::cid::Cid;
use nexus_storage::node::{MerkleNode, NodeKind, TreeEntry};
use nexus_storage::store::{BlockStore, DiskBlockStore, GcReport};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{WorkspaceError, WorkspaceResult};
use crate::filesystem;

const FILE_CHUNK_SIZE_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_SNAPSHOT_RETENTION_LIMIT: usize = 2;

// ---------------------------------------------------------------------------
// Guest
// ---------------------------------------------------------------------------

/// A guest agent that has joined this workspace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Guest {
    /// The guest's DID.
    pub did: Did,
    /// Optional signed social/trust credential for this join.
    pub capability: Option<Capability>,
    /// When the guest joined (Unix timestamp).
    pub joined_at: u64,
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for creating a workspace.
#[derive(Clone, Debug)]
pub struct WorkspaceConfig {
    /// Human-readable name (for display only).
    pub name: String,
    /// Description of what this workspace is for.
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkspaceMetadata {
    name: String,
    description: String,
    id: String,
    owner: Option<Did>,
    #[serde(default)]
    guests: Vec<Guest>,
    #[serde(default)]
    snapshot_history: Vec<String>,
    #[serde(default = "default_snapshot_retention_limit")]
    snapshot_retention_limit: usize,
}

struct LoadedWorkspaceMetadata {
    id: WorkspaceId,
    name: String,
    description: String,
    owner: Option<Did>,
    guests: Vec<Guest>,
    snapshot_history: Vec<Cid>,
    snapshot_retention_limit: usize,
    needs_persist: bool,
}

struct WorkspaceMetadataWrite<'a> {
    root_dir: &'a Path,
    name: &'a str,
    description: &'a str,
    id: &'a WorkspaceId,
    owner: &'a Did,
    guests: &'a [Guest],
    snapshot_history: &'a [Cid],
    snapshot_retention_limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileSnapshotCacheEntry {
    signature: FileSignature,
    cid: Cid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileSignature {
    len: u64,
    modified_nanos: Option<u128>,
}

impl FileSignature {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        let modified_nanos = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos());
        Self {
            len: metadata.len(),
            modified_nanos,
        }
    }
}

// ---------------------------------------------------------------------------
// Workspace
// ---------------------------------------------------------------------------

/// A workspace — an AI's "computer".
///
/// Each workspace owns a directory on the host filesystem, backed by
/// a Merkle-DAG block store for content-addressed versioning.
/// Joined agents run with native freedom; trust is social metadata, not a
/// local sandbox or permission gate.
pub struct Workspace {
    /// The workspace identity (derived from the initial Merkle root).
    id: WorkspaceId,

    /// Human-readable metadata.
    name: String,
    description: String,

    /// The owner's identity.
    owner: Did,

    /// Path to the workspace directory on the host filesystem.
    root_dir: PathBuf,

    /// Content-addressed block store backing the Merkle-DAG.
    store: Arc<DiskBlockStore>,

    /// Native process executor.
    executor: Executor,

    /// Agents currently joined (presented valid capabilities).
    guests: Vec<Guest>,

    /// Current Merkle root CID (updated on snapshot).
    root_cid: Option<Cid>,

    /// Snapshot roots kept for GC pinning, oldest first.
    snapshot_history: Vec<Cid>,

    /// Maximum number of roots kept for GC pinning.
    snapshot_retention_limit: usize,

    /// File-level snapshot cache keyed by path relative to `root_dir`.
    file_cache: HashMap<PathBuf, FileSnapshotCacheEntry>,

    /// Accumulated resource usage across all executions in this workspace.
    total_resources: ResourceUsage,
}

impl Workspace {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new workspace on disk.
    ///
    /// The workspace is created under `base_dir/<name>`.  An initial empty
    /// Merkle tree is computed and stored.
    pub async fn create(
        owner: &NodeIdentity,
        base_dir: impl AsRef<Path>,
        config: WorkspaceConfig,
    ) -> WorkspaceResult<Self> {
        let root_dir = base_dir.as_ref().join(&config.name);

        if root_dir.exists() {
            return Err(WorkspaceError::AlreadyExists(
                root_dir.display().to_string(),
            ));
        }

        // Create the directory structure
        filesystem::ensure_dir(&root_dir)?;

        // Generate a stable random workspace ID
        let mut id_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut id_bytes);
        let id = WorkspaceId::from_bytes(id_bytes);

        // Create a disk-backed block store at .nexus/blocks/
        let store = Arc::new(DiskBlockStore::new(root_dir.join(".nexus").join("blocks")));
        let empty_tree = MerkleNode::tree(Vec::new());
        let root_cid = store.put(empty_tree).await?;
        let snapshot_history = vec![root_cid];

        // Persist metadata to .nexus/config.json
        Self::write_metadata(WorkspaceMetadataWrite {
            root_dir: &root_dir,
            name: &config.name,
            description: &config.description,
            id: &id,
            owner: owner.did(),
            guests: &[],
            snapshot_history: &snapshot_history,
            snapshot_retention_limit: DEFAULT_SNAPSHOT_RETENTION_LIMIT,
        })?;

        Ok(Self {
            id,
            name: config.name,
            description: config.description,
            owner: owner.did().clone(),
            executor: Executor::new(root_dir.clone()),
            root_dir,
            store,
            guests: Vec::new(),
            root_cid: Some(root_cid),
            snapshot_history,
            snapshot_retention_limit: DEFAULT_SNAPSHOT_RETENTION_LIMIT,
            file_cache: HashMap::new(),
            total_resources: ResourceUsage::default(),
        })
    }

    /// Load an existing workspace from disk.
    ///
    /// The workspace directory must already exist.  The Merkle state is
    /// reconstructed from scratch by re-indexing the files on disk.
    pub async fn load(owner: &NodeIdentity, root_dir: impl AsRef<Path>) -> WorkspaceResult<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();

        if !root_dir.is_dir() {
            return Err(WorkspaceError::NotFound(root_dir.display().to_string()));
        }

        // Open existing disk-backed block store
        let store = Arc::new(DiskBlockStore::new(root_dir.join(".nexus").join("blocks")));
        let metadata = Self::read_metadata(&root_dir)?;

        // Index the filesystem
        let mut file_cache = HashMap::new();
        let root_cid = Self::index_directory(
            store.as_ref(),
            &root_dir,
            &root_dir,
            &HashMap::new(),
            &mut file_cache,
        )
        .await?;

        let workspace = Self {
            id: metadata.id,
            name: metadata.name,
            description: metadata.description,
            owner: metadata.owner.unwrap_or_else(|| owner.did().clone()),
            root_dir: root_dir.clone(),
            store,
            executor: Executor::new(root_dir),
            guests: metadata.guests,
            root_cid: Some(root_cid),
            snapshot_history: if metadata.snapshot_history.is_empty() {
                vec![root_cid]
            } else {
                metadata.snapshot_history
            },
            snapshot_retention_limit: metadata.snapshot_retention_limit,
            file_cache,
            total_resources: ResourceUsage::default(),
        };
        if metadata.needs_persist {
            workspace.persist_metadata()?;
        }
        Ok(workspace)
    }

    /// Materialize a workspace from an already-synced Merkle tree.
    ///
    /// This is the final local step of decentralized workspace cloning: the
    /// caller obtains blocks from any transport, stores them in this
    /// workspace's block store, then restores the root tree into native files.
    pub async fn materialize_from_store(
        owner: &Did,
        root_dir: impl AsRef<Path>,
        config: WorkspaceConfig,
        id: WorkspaceId,
        root_cid: Cid,
        source_store: &dyn BlockStore,
    ) -> WorkspaceResult<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        if root_dir.exists() {
            return Err(WorkspaceError::AlreadyExists(
                root_dir.display().to_string(),
            ));
        }

        filesystem::ensure_dir(&root_dir)?;
        let store = Arc::new(DiskBlockStore::new(root_dir.join(".nexus").join("blocks")));
        Self::restore_tree(
            source_store,
            store.as_ref(),
            &root_cid,
            &root_dir,
            &root_dir,
        )
        .await?;
        Self::write_metadata(WorkspaceMetadataWrite {
            root_dir: &root_dir,
            name: &config.name,
            description: &config.description,
            id: &id,
            owner,
            guests: &[],
            snapshot_history: &[root_cid],
            snapshot_retention_limit: DEFAULT_SNAPSHOT_RETENTION_LIMIT,
        })?;

        Ok(Self {
            id,
            name: config.name,
            description: config.description,
            owner: owner.clone(),
            executor: Executor::new(root_dir.clone()),
            root_dir,
            store,
            guests: Vec::new(),
            root_cid: Some(root_cid),
            snapshot_history: vec![root_cid],
            snapshot_retention_limit: DEFAULT_SNAPSHOT_RETENTION_LIMIT,
            file_cache: HashMap::new(),
            total_resources: ResourceUsage::default(),
        })
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// The workspace's unique ID.
    pub fn id(&self) -> WorkspaceId {
        self.id
    }

    /// Human-readable name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The owner's DID.
    pub fn owner(&self) -> &Did {
        &self.owner
    }

    /// Path to the workspace root directory.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Current Merkle root CID.
    pub fn root_cid(&self) -> Option<Cid> {
        self.root_cid
    }

    /// Roots retained for block-store GC pinning.
    pub fn retained_roots(&self) -> Vec<Cid> {
        self.snapshot_roots_for_gc()
    }

    /// Accumulated resource usage.
    pub fn total_resources(&self) -> &ResourceUsage {
        &self.total_resources
    }

    /// List of current guests.
    pub fn guests(&self) -> &[Guest] {
        &self.guests
    }

    // -----------------------------------------------------------------------
    // File operations
    // -----------------------------------------------------------------------

    /// Write bytes to a file within the workspace.
    ///
    /// The file is written to disk AND a blob node is stored in the
    /// Merkle-DAG store.  Call `snapshot()` to update the root tree.
    pub fn write_file(&self, relative_path: impl AsRef<Path>, data: &[u8]) -> WorkspaceResult<()> {
        self.write_file_checked(relative_path.as_ref(), data)
    }

    /// Read a file from the workspace.
    pub fn read_file(&self, relative_path: impl AsRef<Path>) -> WorkspaceResult<Vec<u8>> {
        let full_path = self.root_dir.join(relative_path.as_ref());
        Ok(std::fs::read(&full_path)?)
    }

    /// List all files in the workspace.
    pub fn list_files(&self) -> WorkspaceResult<Vec<filesystem::FileEntry>> {
        Ok(filesystem::list_files(&self.root_dir)?)
    }

    // -----------------------------------------------------------------------
    // Execution
    // -----------------------------------------------------------------------

    /// Execute a command inside the workspace.
    ///
    /// The command runs with the workspace root as the working directory.
    /// Resource usage is tracked and accumulated.
    pub async fn exec(
        &mut self,
        program: &str,
        args: &[&str],
        options: &ExecOptions,
    ) -> WorkspaceResult<ProcessOutput> {
        let output = self.executor.exec(program, args, options).await?;
        self.total_resources.merge(&output.resources);
        Ok(output)
    }

    // -----------------------------------------------------------------------
    // Merkle-DAG snapshots
    // -----------------------------------------------------------------------

    /// Retrieve a Merkle block by CID from the workspace's store.
    pub async fn get_block(&self, cid: &Cid) -> WorkspaceResult<MerkleNode> {
        self.store
            .get(cid)
            .await
            .map_err(|e| WorkspaceError::Other(format!("block not found: {e}")))
    }

    /// Snapshot the current filesystem state into the Merkle-DAG store.
    ///
    /// This re-indexes the entire workspace directory and computes a new
    /// root CID.  The previous root CID is NOT overwritten — old snapshots
    /// remain reachable via the block store.
    pub async fn snapshot(&mut self) -> WorkspaceResult<Cid> {
        let mut next_cache = HashMap::new();
        let root_cid = Self::index_directory(
            self.store.as_ref(),
            &self.root_dir,
            &self.root_dir,
            &self.file_cache,
            &mut next_cache,
        )
        .await?;
        self.root_cid = Some(root_cid);
        self.snapshot_history.push(root_cid);
        self.trim_snapshot_history();
        self.file_cache = next_cache;
        self.persist_metadata()?;
        Ok(root_cid)
    }

    /// Replace the visible workspace tree with a snapshot fetched into another
    /// block store, preserving the current local state as a retained snapshot.
    pub async fn apply_snapshot_from_store(
        &mut self,
        root_cid: Cid,
        source_store: &dyn BlockStore,
    ) -> WorkspaceResult<Cid> {
        let previous_root = self.snapshot().await?;
        if previous_root == root_cid {
            return Ok(previous_root);
        }

        let staging_dir = self.apply_staging_dir();
        if staging_dir.exists() {
            filesystem::remove_dir_all(&staging_dir)?;
        }
        filesystem::ensure_dir(&staging_dir)?;

        let apply_result = async {
            Self::restore_tree(
                source_store,
                self.store.as_ref(),
                &root_cid,
                &staging_dir,
                &staging_dir,
            )
            .await?;
            replace_visible_workspace_entries(&self.root_dir, &staging_dir)?;
            Ok::<(), WorkspaceError>(())
        }
        .await;

        let _ = filesystem::remove_dir_all(&staging_dir);
        apply_result?;

        self.root_cid = Some(root_cid);
        self.snapshot_history.push(root_cid);
        self.trim_snapshot_history();
        self.file_cache.clear();
        self.persist_metadata()?;
        Ok(previous_root)
    }

    /// Garbage collect unreachable block-store entries.
    pub async fn gc_block_store(&self) -> WorkspaceResult<GcReport> {
        let roots = self.snapshot_roots_for_gc();
        self.store.gc_unreachable(&roots).await.map_err(Into::into)
    }

    /// Garbage collect unreachable block-store entries and enforce a quota.
    pub async fn gc_block_store_with_quota(&self, max_bytes: u64) -> WorkspaceResult<GcReport> {
        let roots = self.snapshot_roots_for_gc();
        self.store
            .gc_unreachable_with_quota(&roots, max_bytes)
            .await
            .map_err(Into::into)
    }

    // -----------------------------------------------------------------------
    // Guest management
    // -----------------------------------------------------------------------

    /// Let an agent join this workspace by identity alone.
    ///
    /// This records social presence in the workspace. It does not constrain
    /// file access or execution; the workspace is intentionally a free native
    /// computer for AI agents.
    pub fn join_agent(&mut self, guest_did: &Did, now: u64) -> WorkspaceResult<()> {
        self.guests.retain(|g| g.did != *guest_did);
        self.guests.push(Guest {
            did: guest_did.clone(),
            capability: None,
            joined_at: now,
        });
        self.persist_metadata()
    }

    /// Admit a guest agent with a signed capability as trust metadata.
    ///
    /// The token proves who invited whom and for which workspace. It is useful
    /// for decentralized reputation, provenance, and social audit trails, but
    /// it is not used as a local permission gate.
    pub fn admit_guest(
        &mut self,
        guest_did: &Did,
        capability: &Capability,
        now: u64,
    ) -> WorkspaceResult<()> {
        verify_capability_for_caller(capability, guest_did, self.id, now)
            .map_err(|e| WorkspaceError::InvalidCapability(e.to_string()))?;

        // Check if already admitted — replace if so
        self.guests.retain(|g| g.did != *guest_did);
        self.guests.push(Guest {
            did: guest_did.clone(),
            capability: Some(capability.clone()),
            joined_at: now,
        });

        self.persist_metadata()
    }

    /// Revoke a guest's access.
    pub fn revoke_guest(&mut self, guest_did: &Did) -> WorkspaceResult<()> {
        self.guests.retain(|g| g.did != *guest_did);
        self.persist_metadata()
    }

    /// Compatibility helper: owner and joined agents are present.
    ///
    /// `required` is intentionally ignored. Local operations are not permission
    /// gated in this framework; trust and consequences are represented by the
    /// social/economic layers.
    pub fn check_permission(&self, did: &Did, _required: &PermissionSet) -> bool {
        *did == self.owner || self.guests.iter().any(|guest| guest.did == *did)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Recursively index a directory tree into the block store.
    /// Returns the CID of the root tree node.
    async fn index_directory(
        store: &dyn BlockStore,
        base: &Path,
        dir: &Path,
        previous_cache: &HashMap<PathBuf, FileSnapshotCacheEntry>,
        next_cache: &mut HashMap<PathBuf, FileSnapshotCacheEntry>,
    ) -> WorkspaceResult<Cid> {
        let mut entries = Vec::new();
        let read_dir = std::fs::read_dir(dir)?;

        for entry in read_dir {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();

            // Skip only the workspace's own metadata directory.
            if dir == base && name == ".nexus" {
                continue;
            }

            let path = entry.path();
            let file_type = entry.file_type()?;

            if file_type.is_symlink() || (!file_type.is_dir() && !file_type.is_file()) {
                continue;
            }

            if file_type.is_dir() {
                let child_cid = Box::pin(Self::index_directory(
                    store,
                    base,
                    &path,
                    previous_cache,
                    next_cache,
                ))
                .await?;
                entries.push(TreeEntry {
                    name,
                    cid: child_cid,
                    kind: NodeKind::Tree,
                });
            } else if file_type.is_file() {
                let child_cid =
                    Self::index_file(store, base, &path, previous_cache, next_cache).await?;
                entries.push(TreeEntry {
                    name,
                    cid: child_cid,
                    kind: NodeKind::Blob,
                });
            }
        }

        let tree = MerkleNode::tree(entries);
        let cid = store.put(tree).await?;
        Ok(cid)
    }

    async fn index_file(
        store: &dyn BlockStore,
        base: &Path,
        path: &Path,
        previous_cache: &HashMap<PathBuf, FileSnapshotCacheEntry>,
        next_cache: &mut HashMap<PathBuf, FileSnapshotCacheEntry>,
    ) -> WorkspaceResult<Cid> {
        let metadata = std::fs::metadata(path)?;
        let signature = FileSignature::from_metadata(&metadata);
        let relative = path.strip_prefix(base).unwrap_or(path).to_path_buf();
        let _ = previous_cache;

        let cid = if metadata.len() <= FILE_CHUNK_SIZE_BYTES as u64 {
            let data = std::fs::read(path)?;
            store.put(MerkleNode::blob(data)).await?
        } else {
            let mut file = std::fs::File::open(path)?;
            let mut chunks = Vec::new();
            let mut total_size = 0_u64;

            loop {
                let mut data = vec![0_u8; FILE_CHUNK_SIZE_BYTES];
                let read = file.read(&mut data)?;
                if read == 0 {
                    break;
                }
                data.truncate(read);
                total_size += read as u64;
                chunks.push(store.put(MerkleNode::blob(data)).await?);
            }

            if chunks.is_empty() {
                store.put(MerkleNode::blob(Vec::new())).await?
            } else if chunks.len() == 1 {
                chunks[0]
            } else {
                store
                    .put(MerkleNode::chunked_blob(chunks, total_size))
                    .await?
            }
        };

        next_cache.insert(relative, FileSnapshotCacheEntry { signature, cid });
        Ok(cid)
    }

    async fn restore_tree(
        source_store: &dyn BlockStore,
        target_store: &dyn BlockStore,
        cid: &Cid,
        dir: &Path,
        root_dir: &Path,
    ) -> WorkspaceResult<()> {
        let node = Self::verified_node(source_store, cid).await?;
        let entries = node.as_tree().ok_or_else(|| {
            WorkspaceError::Other("workspace root CID does not reference a tree".into())
        })?;
        target_store.put(node.clone()).await?;

        for entry in entries {
            let path = checked_child_path(dir, root_dir, &entry.name)?;
            match entry.kind {
                NodeKind::Blob => {
                    let node = Self::verified_node(source_store, &entry.cid).await?;
                    target_store.put(node.clone()).await?;
                    if let Some(parent) = path.parent() {
                        filesystem::ensure_dir(parent)?;
                    }
                    Self::restore_blob_node(source_store, target_store, &node, &entry.name, &path)
                        .await?;
                }
                NodeKind::Tree => {
                    filesystem::ensure_dir(&path)?;
                    Box::pin(Self::restore_tree(
                        source_store,
                        target_store,
                        &entry.cid,
                        &path,
                        root_dir,
                    ))
                    .await?;
                }
            }
        }

        Ok(())
    }

    async fn restore_blob_node(
        source_store: &dyn BlockStore,
        target_store: &dyn BlockStore,
        node: &MerkleNode,
        entry_name: &str,
        path: &Path,
    ) -> WorkspaceResult<()> {
        if let Some(data) = node.as_blob() {
            std::fs::write(path, data)?;
            return Ok(());
        }

        if let Some((chunks, expected_size)) = node.as_chunked_blob() {
            let mut file = std::fs::File::create(path)?;
            let mut restored_size = 0_u64;
            for chunk in chunks {
                let chunk_node = Self::verified_node(source_store, chunk).await?;
                let data = chunk_node.as_blob().ok_or_else(|| {
                    WorkspaceError::Other(format!(
                        "chunk {} for '{}' is not a blob",
                        hex::encode(chunk.as_bytes()),
                        entry_name
                    ))
                })?;
                target_store.put(chunk_node.clone()).await?;
                file.write_all(data)?;
                restored_size += data.len() as u64;
            }
            if restored_size != expected_size {
                return Err(WorkspaceError::Other(format!(
                    "chunked blob '{}' size mismatch: expected {}, got {}",
                    entry_name, expected_size, restored_size
                )));
            }
            return Ok(());
        }

        Err(WorkspaceError::Other(format!(
            "tree entry '{}' is not a blob",
            entry_name
        )))
    }

    async fn verified_node(store: &dyn BlockStore, cid: &Cid) -> WorkspaceResult<MerkleNode> {
        let node = store.get(cid).await?;
        let actual = node.cid();
        if actual != *cid {
            return Err(WorkspaceError::Other(format!(
                "block content CID mismatch: expected {}, got {}",
                hex::encode(cid.as_bytes()),
                hex::encode(actual.as_bytes())
            )));
        }
        Ok(node)
    }

    fn write_file_checked(&self, relative_path: &Path, data: &[u8]) -> WorkspaceResult<()> {
        let full_path = self.root_dir.join(relative_path);

        if let Some(parent) = full_path.parent() {
            filesystem::ensure_dir(parent)?;
        }

        std::fs::write(&full_path, data)?;
        Ok(())
    }

    fn apply_staging_dir(&self) -> PathBuf {
        let mut nonce = [0_u8; 16];
        OsRng.fill_bytes(&mut nonce);
        self.root_dir
            .join(".nexus")
            .join("apply-staging")
            .join(hex::encode(nonce))
    }

    fn persist_metadata(&self) -> WorkspaceResult<()> {
        Self::write_metadata(WorkspaceMetadataWrite {
            root_dir: &self.root_dir,
            name: &self.name,
            description: &self.description,
            id: &self.id,
            owner: &self.owner,
            guests: &self.guests,
            snapshot_history: &self.snapshot_history,
            snapshot_retention_limit: self.snapshot_retention_limit,
        })
    }

    /// Write workspace metadata to `.nexus/config.json`.
    fn write_metadata(metadata: WorkspaceMetadataWrite<'_>) -> WorkspaceResult<()> {
        let nexus_dir = metadata.root_dir.join(".nexus");
        filesystem::ensure_dir(&nexus_dir)?;

        let config = WorkspaceMetadata {
            name: metadata.name.to_string(),
            description: metadata.description.to_string(),
            id: hex::encode(metadata.id.as_bytes()),
            owner: Some(metadata.owner.clone()),
            guests: metadata.guests.to_vec(),
            snapshot_history: metadata
                .snapshot_history
                .iter()
                .map(|cid| hex::encode(cid.as_bytes()))
                .collect(),
            snapshot_retention_limit: metadata.snapshot_retention_limit,
        };

        let config_path = nexus_dir.join("config.json");
        filesystem::write_file_atomic(
            &config_path,
            serde_json::to_string_pretty(&config)?.as_bytes(),
        )?;
        Ok(())
    }

    /// Read workspace metadata from `.nexus/config.json`.
    fn read_metadata(root_dir: &Path) -> WorkspaceResult<LoadedWorkspaceMetadata> {
        let config_path = root_dir.join(".nexus").join("config.json");
        if !config_path.exists() {
            return Ok(Self::legacy_metadata(root_dir, true));
        }

        let data = std::fs::read_to_string(&config_path)?;
        let json = serde_json::from_str::<serde_json::Value>(&data)?;
        let name = json
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed")
            .to_string();
        let description = json
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let (id, generated_id) = if let Some(id_hex) = json.get("id").and_then(|v| v.as_str()) {
            let bytes = hex::decode(id_hex)
                .map_err(|e| WorkspaceError::Other(format!("invalid workspace id hex: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| WorkspaceError::Other("invalid workspace id length".into()))?;
            (WorkspaceId::from_bytes(arr), false)
        } else {
            let mut id_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut id_bytes);
            (WorkspaceId::from_bytes(id_bytes), true)
        };

        let owner = json
            .get("owner")
            .and_then(|v| v.as_str())
            .map(|did| Did::new(did.to_string()));
        let guests = json
            .get("guests")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();
        let snapshot_history_json = json.get("snapshot_history");
        let snapshot_history = snapshot_history_json
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .map(|value| {
                        value.as_str().ok_or_else(|| {
                            WorkspaceError::Other("invalid snapshot history entry".into())
                        })
                    })
                    .map(|result| {
                        result.and_then(|hex_str| {
                            let bytes = hex::decode(hex_str).map_err(|e| {
                                WorkspaceError::Other(format!(
                                    "invalid snapshot history cid hex: {e}"
                                ))
                            })?;
                            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                                WorkspaceError::Other("invalid snapshot history cid length".into())
                            })?;
                            Ok(Cid::from_bytes(arr))
                        })
                    })
                    .collect::<WorkspaceResult<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let snapshot_retention_limit = json
            .get("snapshot_retention_limit")
            .and_then(|value| value.as_u64())
            .map(|value| value as usize)
            .unwrap_or(DEFAULT_SNAPSHOT_RETENTION_LIMIT)
            .max(1);

        Ok(LoadedWorkspaceMetadata {
            id,
            name,
            description,
            owner,
            guests,
            snapshot_history,
            snapshot_retention_limit,
            needs_persist: generated_id
                || snapshot_history_json.is_none()
                || json.get("snapshot_retention_limit").is_none(),
        })
    }

    fn legacy_metadata(root_dir: &Path, needs_persist: bool) -> LoadedWorkspaceMetadata {
        let name = root_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unnamed".into());

        let mut id_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut id_bytes);
        let id = WorkspaceId::from_bytes(id_bytes);

        LoadedWorkspaceMetadata {
            id,
            name,
            description: String::new(),
            owner: None,
            guests: Vec::new(),
            snapshot_history: Vec::new(),
            snapshot_retention_limit: DEFAULT_SNAPSHOT_RETENTION_LIMIT,
            needs_persist,
        }
    }

    fn snapshot_roots_for_gc(&self) -> Vec<Cid> {
        let mut roots = self.snapshot_history.clone();
        if roots.is_empty() {
            if let Some(root) = self.root_cid {
                roots.push(root);
            }
        } else if let Some(root) = self.root_cid {
            if roots.last().copied() != Some(root) {
                roots.push(root);
            }
        }
        roots
    }

    fn trim_snapshot_history(&mut self) {
        if self.snapshot_history.len() > self.snapshot_retention_limit {
            let excess = self.snapshot_history.len() - self.snapshot_retention_limit;
            self.snapshot_history.drain(0..excess);
        }
        if self.snapshot_history.is_empty() {
            if let Some(root) = self.root_cid {
                self.snapshot_history.push(root);
            }
        }
    }
}

fn default_snapshot_retention_limit() -> usize {
    DEFAULT_SNAPSHOT_RETENTION_LIMIT
}

fn checked_child_path(base: &Path, root_dir: &Path, name: &str) -> WorkspaceResult<PathBuf> {
    let child = Path::new(name);
    let components = child.components().collect::<Vec<_>>();
    if child.is_absolute()
        || components.len() != 1
        || !matches!(components[0], std::path::Component::Normal(_))
        || (base == root_dir && name == ".nexus")
    {
        return Err(WorkspaceError::Other(format!(
            "invalid workspace tree entry: {name}"
        )));
    }
    Ok(base.join(child))
}

fn replace_visible_workspace_entries(root_dir: &Path, staging_dir: &Path) -> WorkspaceResult<()> {
    clear_visible_workspace_entries(root_dir)?;
    for entry in std::fs::read_dir(staging_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let target = checked_child_path(root_dir, root_dir, &name)?;
        std::fs::rename(entry.path(), target)?;
    }
    Ok(())
}

fn clear_visible_workspace_entries(root_dir: &Path) -> WorkspaceResult<()> {
    for entry in std::fs::read_dir(root_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".nexus" {
            continue;
        }

        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_crypto::NodeIdentity;
    use tempfile::TempDir;

    async fn setup_workspace() -> (Workspace, TempDir) {
        let owner = NodeIdentity::generate();
        let base = TempDir::new().unwrap();
        let config = WorkspaceConfig {
            name: "test-workspace".into(),
            description: "A test workspace".into(),
        };
        let ws = Workspace::create(&owner, base.path(), config)
            .await
            .expect("create workspace");
        (ws, base)
    }

    async fn copy_tree(
        source: &dyn BlockStore,
        target: &dyn BlockStore,
        cid: &Cid,
    ) -> WorkspaceResult<()> {
        let node = source.get(cid).await?;
        if let Some(entries) = node.as_tree() {
            for entry in entries {
                Box::pin(copy_tree(source, target, &entry.cid)).await?;
            }
        } else if let Some((chunks, _)) = node.as_chunked_blob() {
            for chunk in chunks {
                Box::pin(copy_tree(source, target, chunk)).await?;
            }
        }
        target.put(node).await?;
        Ok(())
    }

    #[tokio::test]
    async fn create_and_load_workspace() {
        let owner = NodeIdentity::generate();
        let base = TempDir::new().unwrap();

        let config = WorkspaceConfig {
            name: "my-ws".into(),
            description: "test".into(),
        };

        let ws = Workspace::create(&owner, base.path(), config)
            .await
            .expect("create");

        assert_eq!(ws.name(), "my-ws");
        assert_eq!(ws.owner().to_string(), owner.did().to_string());
        assert!(ws.root_cid().is_some());
        assert!(ws.root_dir().is_dir());

        // Load it back
        let ws2 = Workspace::load(&owner, ws.root_dir()).await.expect("load");
        assert_eq!(ws2.id(), ws.id());
    }

    #[tokio::test]
    async fn write_and_read_file() {
        let (ws, _base) = setup_workspace().await;

        ws.write_file("hello.txt", b"Hello, Nexus!")
            .expect("write file");

        let data = ws.read_file("hello.txt").expect("read file");
        assert_eq!(data, b"Hello, Nexus!");
    }

    #[tokio::test]
    async fn workspace_files_are_native_and_unrestricted() {
        let (ws, base) = setup_workspace().await;

        ws.write_file("../outside.txt", b"native freedom").unwrap();
        let outside = base.path().join("outside.txt");
        assert_eq!(std::fs::read(outside).unwrap(), b"native freedom");

        ws.write_file(".nexus/agent-note.txt", b"internal note")
            .unwrap();
        assert_eq!(
            ws.read_file(".nexus/agent-note.txt").unwrap(),
            b"internal note"
        );
    }

    #[tokio::test]
    async fn write_nested_file() {
        let (ws, _base) = setup_workspace().await;

        ws.write_file("sub/deep/nested.txt", b"deep data")
            .expect("write nested file");

        let data = ws.read_file("sub/deep/nested.txt").expect("read");
        assert_eq!(data, b"deep data");
    }

    #[tokio::test]
    async fn list_files_hides_internal_metadata() {
        let (ws, _base) = setup_workspace().await;

        ws.write_file("visible.txt", b"ok").unwrap();

        let files = ws.list_files().unwrap();
        assert!(files
            .iter()
            .any(|entry| entry.path == Path::new("visible.txt")));
        assert!(files.iter().all(|entry| !entry.path.starts_with(".nexus")));
    }

    #[tokio::test]
    async fn snapshot_includes_nested_nexus_directories() {
        let (mut ws, _base) = setup_workspace().await;

        ws.write_file("project/.nexus/data.txt", b"keep me")
            .unwrap();
        let root = ws.snapshot().await.unwrap();

        let root_node = ws.store.get(&root).await.unwrap();
        let project = root_node.lookup("project").expect("project tree");
        let project_node = ws.store.get(&project.cid).await.unwrap();
        let nested_nexus = project_node.lookup(".nexus").expect("nested .nexus tree");
        let nested_node = ws.store.get(&nested_nexus.cid).await.unwrap();
        let data = nested_node.lookup("data.txt").expect("nested data file");
        let data_node = ws.store.get(&data.cid).await.unwrap();

        assert_eq!(data_node.as_blob().unwrap(), b"keep me");
    }

    #[tokio::test]
    async fn block_store_gc_keeps_retained_roots_and_removes_expired_snapshots() {
        let (mut ws, _base) = setup_workspace().await;

        ws.write_file("data.txt", b"version-one").unwrap();
        let root_v1 = ws.snapshot().await.unwrap();
        let blob_v1 = MerkleNode::blob(b"version-one".to_vec()).cid();
        assert!(ws.store.has(&root_v1).await.unwrap());
        assert!(ws.store.has(&blob_v1).await.unwrap());

        ws.write_file("data.txt", b"version-two-longer").unwrap();
        let root_v2 = ws.snapshot().await.unwrap();
        ws.write_file("data.txt", b"version-three-longest").unwrap();
        let root_v3 = ws.snapshot().await.unwrap();
        let blob_v3 = MerkleNode::blob(b"version-three-longest".to_vec()).cid();

        assert_eq!(ws.retained_roots(), vec![root_v2, root_v3]);

        let report = ws.gc_block_store().await.unwrap();

        assert!(report.deleted_blocks > 0);
        assert!(!ws.store.has(&root_v1).await.unwrap());
        assert!(!ws.store.has(&blob_v1).await.unwrap());
        assert!(ws.store.has(&root_v2).await.unwrap());
        assert!(ws.store.has(&root_v3).await.unwrap());
        assert!(ws.store.has(&blob_v3).await.unwrap());

        let err = ws.gc_block_store_with_quota(1).await.unwrap_err();
        assert!(matches!(
            err,
            WorkspaceError::Storage(nexus_storage::store::StoreError::QuotaExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn exec_command() {
        let (mut ws, _base) = setup_workspace().await;

        let opts = ExecOptions::default();
        let output = ws
            .exec("echo", &["-n", "hello from exec"], &opts)
            .await
            .expect("exec");

        assert_eq!(output.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&output.stdout), "hello from exec");
    }

    #[tokio::test]
    async fn exec_in_workspace_context() {
        let (mut ws, _base) = setup_workspace().await;

        // Write a shell script
        ws.write_file("run.sh", b"#!/bin/sh\necho 'workspace output'")
            .expect("write script");

        // Make it executable and run it
        let opts = ExecOptions::default();
        ws.exec("sh", &["run.sh"], &opts)
            .await
            .expect("exec script");

        // Verify via cat (no need for chmod since we use sh)
        let output = ws.exec("cat", &["run.sh"], &opts).await.expect("cat");

        assert!(String::from_utf8_lossy(&output.stdout).contains("workspace output"));
    }

    #[tokio::test]
    async fn exec_working_dir_stays_inside_workspace() {
        let (mut ws, _base) = setup_workspace().await;

        let opts = ExecOptions {
            working_dir: Some(PathBuf::from("..")),
            ..Default::default()
        };

        let err = ws.exec("true", &[], &opts).await.unwrap_err();
        assert!(
            err.to_string().contains("escapes workspace root"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn snapshot_captures_state() {
        let (mut ws, _base) = setup_workspace().await;

        ws.write_file("a.txt", b"aaa").unwrap();
        ws.write_file("b.txt", b"bbb").unwrap();

        let cid1 = ws.snapshot().await.expect("snapshot 1");

        // Write more files
        ws.write_file("c.txt", b"ccc").unwrap();
        let cid2 = ws.snapshot().await.expect("snapshot 2");

        // Snapshots should differ
        assert_ne!(cid1, cid2);
        // Root CID should be the latest
        assert_eq!(ws.root_cid().unwrap(), cid2);
    }

    #[tokio::test]
    async fn snapshot_detects_same_length_rewrites() {
        let (mut ws, _base) = setup_workspace().await;

        ws.write_file("state.txt", b"one").unwrap();
        let cid1 = ws.snapshot().await.expect("snapshot 1");

        ws.write_file("state.txt", b"two").unwrap();
        let cid2 = ws.snapshot().await.expect("snapshot 2");

        assert_ne!(cid1, cid2);
        let root_node = ws.store.get(&cid2).await.unwrap();
        let entry = root_node.lookup("state.txt").expect("state file entry");
        let file_node = ws.store.get(&entry.cid).await.unwrap();
        assert_eq!(file_node.as_blob().unwrap(), b"two");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn snapshot_and_listing_skip_symlinks() {
        let (mut ws, base) = setup_workspace().await;
        let outside = base.path().join("outside-secret.txt");
        std::fs::write(&outside, b"outside secret").unwrap();
        std::os::unix::fs::symlink(&outside, ws.root_dir().join("linked-secret")).unwrap();
        ws.write_file("real.txt", b"real").unwrap();

        let files = ws.list_files().unwrap();
        assert!(files
            .iter()
            .any(|entry| entry.path == Path::new("real.txt")));
        assert!(!files
            .iter()
            .any(|entry| entry.path == Path::new("linked-secret")));

        let root = ws.snapshot().await.unwrap();
        let root_node = ws.store.get(&root).await.unwrap();
        let entries = root_node.as_tree().unwrap();
        assert!(entries.iter().any(|entry| entry.name == "real.txt"));
        assert!(!entries.iter().any(|entry| entry.name == "linked-secret"));
        assert!(!ws
            .store
            .has(&MerkleNode::blob(b"outside secret".to_vec()).cid())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn materialize_from_store_restores_workspace_files() {
        let owner = NodeIdentity::generate();
        let remote_owner = NodeIdentity::generate();
        let base = TempDir::new().unwrap();
        let mut source = Workspace::create(
            &owner,
            base.path(),
            WorkspaceConfig {
                name: "source".into(),
                description: "source workspace".into(),
            },
        )
        .await
        .unwrap();
        source.write_file("hello.txt", b"hello").unwrap();
        source.write_file("sub/data.txt", b"data").unwrap();
        let root = source.snapshot().await.unwrap();

        let clone_path = base.path().join("clone");
        let synced_store = DiskBlockStore::new(base.path().join("synced-blocks"));
        copy_tree(source.store.as_ref(), &synced_store, &root)
            .await
            .unwrap();
        let cloned = Workspace::materialize_from_store(
            remote_owner.did(),
            &clone_path,
            WorkspaceConfig {
                name: "clone".into(),
                description: "restored workspace".into(),
            },
            source.id(),
            root,
            &synced_store,
        )
        .await
        .unwrap();

        assert_eq!(cloned.id(), source.id());
        assert_eq!(cloned.owner(), remote_owner.did());
        assert_eq!(cloned.root_cid(), Some(root));
        assert_eq!(cloned.read_file("hello.txt").unwrap(), b"hello");
        assert_eq!(cloned.read_file("sub/data.txt").unwrap(), b"data");

        let loaded = Workspace::load(&owner, &clone_path).await.unwrap();
        assert_eq!(loaded.id(), source.id());
        assert_eq!(loaded.owner(), remote_owner.did());
    }

    #[tokio::test]
    async fn apply_snapshot_from_store_replaces_visible_workspace_tree() {
        let owner = NodeIdentity::generate();
        let base = TempDir::new().unwrap();
        let mut source = Workspace::create(
            &owner,
            base.path(),
            WorkspaceConfig {
                name: "source".into(),
                description: "source workspace".into(),
            },
        )
        .await
        .unwrap();
        source.write_file("same.txt", b"old").unwrap();
        source.write_file("remove-me.txt", b"old").unwrap();
        let old_root = source.snapshot().await.unwrap();

        let clone_path = base.path().join("apply-target");
        let mut target = Workspace::materialize_from_store(
            owner.did(),
            &clone_path,
            WorkspaceConfig {
                name: "apply-target".into(),
                description: "target workspace".into(),
            },
            source.id(),
            old_root,
            source.store.as_ref(),
        )
        .await
        .unwrap();
        target.write_file("local-only.txt", b"local").unwrap();

        std::fs::remove_file(source.root_dir().join("remove-me.txt")).unwrap();
        source.write_file("same.txt", b"new").unwrap();
        source.write_file("nested/new.txt", b"fresh").unwrap();
        let new_root = source.snapshot().await.unwrap();

        let previous_root = target
            .apply_snapshot_from_store(new_root, source.store.as_ref())
            .await
            .unwrap();

        assert_ne!(previous_root, old_root);
        assert_eq!(target.root_cid(), Some(new_root));
        assert_eq!(target.read_file("same.txt").unwrap(), b"new");
        assert_eq!(target.read_file("nested/new.txt").unwrap(), b"fresh");
        assert!(!clone_path.join("remove-me.txt").exists());
        assert!(!clone_path.join("local-only.txt").exists());
        assert!(clone_path.join(".nexus/config.json").exists());
    }

    #[tokio::test]
    async fn apply_snapshot_from_store_rejects_root_nexus_tree_before_replacing_files() {
        let owner = NodeIdentity::generate();
        let base = TempDir::new().unwrap();
        let source = Workspace::create(
            &owner,
            base.path(),
            WorkspaceConfig {
                name: "source".into(),
                description: "source workspace".into(),
            },
        )
        .await
        .unwrap();
        let mut target = Workspace::create(
            &owner,
            base.path(),
            WorkspaceConfig {
                name: "target".into(),
                description: "target workspace".into(),
            },
        )
        .await
        .unwrap();
        target.write_file("safe.txt", b"safe").unwrap();

        let blob_cid = source
            .store
            .put(MerkleNode::blob(b"poison".to_vec()))
            .await
            .unwrap();
        let nexus_cid = source
            .store
            .put(MerkleNode::tree(vec![TreeEntry {
                name: "config.json".into(),
                cid: blob_cid,
                kind: NodeKind::Blob,
            }]))
            .await
            .unwrap();
        let root_cid = source
            .store
            .put(MerkleNode::tree(vec![TreeEntry {
                name: ".nexus".into(),
                cid: nexus_cid,
                kind: NodeKind::Tree,
            }]))
            .await
            .unwrap();

        let err = target
            .apply_snapshot_from_store(root_cid, source.store.as_ref())
            .await
            .unwrap_err();

        assert!(err.to_string().contains("invalid workspace tree entry"));
        assert_eq!(target.read_file("safe.txt").unwrap(), b"safe");
    }

    #[tokio::test]
    async fn large_files_snapshot_as_chunks_and_restore() {
        let owner = NodeIdentity::generate();
        let base = TempDir::new().unwrap();
        let mut source = Workspace::create(
            &owner,
            base.path(),
            WorkspaceConfig {
                name: "source".into(),
                description: "source workspace".into(),
            },
        )
        .await
        .unwrap();

        let data = (0..(FILE_CHUNK_SIZE_BYTES + 17))
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        source.write_file("large.bin", &data).unwrap();
        let root = source.snapshot().await.unwrap();

        let root_node = source.store.get(&root).await.unwrap();
        let entry = root_node
            .lookup("large.bin")
            .expect("large file tree entry");
        let file_node = source.store.get(&entry.cid).await.unwrap();
        let (chunks, size) = file_node
            .as_chunked_blob()
            .expect("large file should be chunked");
        assert_eq!(size, data.len() as u64);
        assert!(chunks.len() > 1);
        for chunk in chunks {
            let chunk_node = source.store.get(chunk).await.unwrap();
            assert!(chunk_node.as_blob().unwrap().len() <= FILE_CHUNK_SIZE_BYTES);
        }

        let clone_path = base.path().join("chunked-clone");
        let cloned = Workspace::materialize_from_store(
            owner.did(),
            &clone_path,
            WorkspaceConfig {
                name: "clone".into(),
                description: "restored workspace".into(),
            },
            source.id(),
            root,
            source.store.as_ref(),
        )
        .await
        .unwrap();

        assert_eq!(cloned.read_file("large.bin").unwrap(), data);
    }

    #[tokio::test]
    async fn materialize_from_store_rejects_escaping_tree_entries() {
        let owner = NodeIdentity::generate();
        let base = TempDir::new().unwrap();
        let source = Workspace::create(
            &owner,
            base.path(),
            WorkspaceConfig {
                name: "source".into(),
                description: "source workspace".into(),
            },
        )
        .await
        .unwrap();

        let blob = MerkleNode::blob(b"escape".to_vec());
        let blob_cid = source.store.put(blob).await.unwrap();
        let root = MerkleNode::tree(vec![TreeEntry {
            name: "../escape.txt".into(),
            cid: blob_cid,
            kind: NodeKind::Blob,
        }]);
        let root_cid = source.store.put(root).await.unwrap();

        let err = match Workspace::materialize_from_store(
            owner.did(),
            base.path().join("clone"),
            WorkspaceConfig {
                name: "clone".into(),
                description: "bad tree".into(),
            },
            source.id(),
            root_cid,
            source.store.as_ref(),
        )
        .await
        {
            Ok(_) => panic!("escaping tree entry should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("invalid workspace tree entry"));
        assert!(!base.path().join("escape.txt").exists());
    }

    #[tokio::test]
    async fn materialize_from_store_rejects_root_nexus_tree() {
        let owner = NodeIdentity::generate();
        let base = TempDir::new().unwrap();
        let source = Workspace::create(
            &owner,
            base.path(),
            WorkspaceConfig {
                name: "source".into(),
                description: "source workspace".into(),
            },
        )
        .await
        .unwrap();

        let blob_cid = source
            .store
            .put(MerkleNode::blob(b"poison".to_vec()))
            .await
            .unwrap();
        let nexus_cid = source
            .store
            .put(MerkleNode::tree(vec![TreeEntry {
                name: "config.json".into(),
                cid: blob_cid,
                kind: NodeKind::Blob,
            }]))
            .await
            .unwrap();
        let root_cid = source
            .store
            .put(MerkleNode::tree(vec![TreeEntry {
                name: ".nexus".into(),
                cid: nexus_cid,
                kind: NodeKind::Tree,
            }]))
            .await
            .unwrap();

        let err = match Workspace::materialize_from_store(
            owner.did(),
            base.path().join("clone"),
            WorkspaceConfig {
                name: "clone".into(),
                description: "bad tree".into(),
            },
            source.id(),
            root_cid,
            source.store.as_ref(),
        )
        .await
        {
            Ok(_) => panic!("root .nexus tree should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("invalid workspace tree entry"));
    }

    #[tokio::test]
    async fn load_rejects_corrupt_workspace_metadata() {
        let owner = NodeIdentity::generate();
        let base = TempDir::new().unwrap();
        let workspace = Workspace::create(
            &owner,
            base.path(),
            WorkspaceConfig {
                name: "corrupt-config".into(),
                description: "metadata must be strict".into(),
            },
        )
        .await
        .unwrap();
        std::fs::write(
            workspace.root_dir().join(".nexus/config.json"),
            b"{not-json",
        )
        .unwrap();

        let err = match Workspace::load(&owner, workspace.root_dir()).await {
            Ok(_) => panic!("corrupt metadata should not create a new workspace id"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("JSON error"));
    }

    #[tokio::test]
    async fn admit_and_check_guest() {
        let owner = NodeIdentity::generate();
        let guest_id = NodeIdentity::generate();
        let base = TempDir::new().unwrap();
        let config = WorkspaceConfig {
            name: "guest-test".into(),
            description: "".into(),
        };

        let mut ws = Workspace::create(&owner, base.path(), config)
            .await
            .expect("create");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Owner issues a capability to the guest
        let cap = nexus_crypto::capability::sign_capability(
            &owner,
            guest_id.did(),
            ws.id(),
            PermissionSet::READ_WRITE,
            now + 3600,
        )
        .expect("sign capability");

        // Guest presents it
        ws.admit_guest(guest_id.did(), &cap, now)
            .expect("admit guest");

        assert_eq!(ws.guests().len(), 1);
        assert!(ws.guests()[0].capability.is_some());
        assert!(ws.check_permission(guest_id.did(), &PermissionSet::READ_WRITE));
        assert!(ws.check_permission(guest_id.did(), &PermissionSet::FULL));
    }

    #[tokio::test]
    async fn agents_can_join_without_permission_gate() {
        let owner = NodeIdentity::generate();
        let guest = NodeIdentity::generate();
        let base = TempDir::new().unwrap();
        let config = WorkspaceConfig {
            name: "join-test".into(),
            description: String::new(),
        };

        let mut ws = Workspace::create(&owner, base.path(), config)
            .await
            .expect("create");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        ws.join_agent(guest.did(), now).expect("join guest");
        assert_eq!(ws.guests().len(), 1);
        assert!(ws.guests()[0].capability.is_none());
        assert!(ws.check_permission(guest.did(), &PermissionSet::FULL));

        let loaded = Workspace::load(&owner, ws.root_dir()).await.unwrap();
        assert_eq!(loaded.owner(), owner.did());
        assert_eq!(loaded.guests().len(), 1);
        assert_eq!(&loaded.guests()[0].did, guest.did());

        let output = ws.exec("true", &[], &ExecOptions::default()).await.unwrap();
        assert_eq!(output.exit_code, 0);
    }

    #[tokio::test]
    async fn revoke_guest() {
        let owner = NodeIdentity::generate();
        let guest_id = NodeIdentity::generate();
        let base = TempDir::new().unwrap();
        let config = WorkspaceConfig {
            name: "revoke-test".into(),
            description: "".into(),
        };

        let mut ws = Workspace::create(&owner, base.path(), config)
            .await
            .expect("create");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cap = nexus_crypto::capability::sign_capability(
            &owner,
            guest_id.did(),
            ws.id(),
            PermissionSet::READ_ONLY,
            now + 3600,
        )
        .expect("sign");

        ws.admit_guest(guest_id.did(), &cap, now).expect("admit");
        assert_eq!(ws.guests().len(), 1);

        ws.revoke_guest(guest_id.did()).expect("revoke");
        assert_eq!(ws.guests().len(), 0);
        assert!(!ws.check_permission(guest_id.did(), &PermissionSet::READ_ONLY));

        let loaded = Workspace::load(&owner, ws.root_dir()).await.unwrap();
        assert_eq!(loaded.guests().len(), 0);
    }

    #[tokio::test]
    async fn resource_tracking_accumulates() {
        let (mut ws, _base) = setup_workspace().await;
        let opts = ExecOptions::default();

        ws.exec("echo", &["1"], &opts).await.unwrap();
        ws.exec("echo", &["2"], &opts).await.unwrap();

        // Should have tracked at least 2 processes
        assert!(ws.total_resources().process_count >= 2);
    }
}
