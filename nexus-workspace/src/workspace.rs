//! Workspace — the core abstraction that ties storage, execution, and identity together.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nexus_core::{Capability, Did, PermissionSet, WorkspaceId};
use nexus_crypto::capability::verify_capability_for_caller;
use nexus_crypto::NodeIdentity;
use nexus_runtime::{ExecOptions, Executor, ProcessOutput, ResourceUsage};
use nexus_storage::cid::Cid;
use nexus_storage::node::{MerkleNode, NodeKind, TreeEntry};
use nexus_storage::store::{BlockStore, DiskBlockStore};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{WorkspaceError, WorkspaceResult};
use crate::filesystem;

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
}

struct LoadedWorkspaceMetadata {
    id: WorkspaceId,
    name: String,
    description: String,
    owner: Option<Did>,
    guests: Vec<Guest>,
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
    store: Arc<dyn BlockStore>,

    /// Native process executor.
    executor: Executor,

    /// Agents currently joined (presented valid capabilities).
    guests: Vec<Guest>,

    /// Current Merkle root CID (updated on snapshot).
    root_cid: Option<Cid>,

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
        let store: Arc<dyn BlockStore> =
            Arc::new(DiskBlockStore::new(root_dir.join(".nexus").join("blocks")));
        let empty_tree = MerkleNode::tree(Vec::new());
        let root_cid = store.put(empty_tree).await?;

        // Persist metadata to .nexus/config.json
        Self::write_metadata(
            &root_dir,
            &config.name,
            &config.description,
            &id,
            owner.did(),
            &[],
        )?;

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
        let store: Arc<dyn BlockStore> =
            Arc::new(DiskBlockStore::new(root_dir.join(".nexus").join("blocks")));
        let metadata = Self::read_metadata(&root_dir)?;

        // Index the filesystem
        let root_cid = Self::index_directory(store.as_ref(), &root_dir).await?;

        Ok(Self {
            id: metadata.id,
            name: metadata.name,
            description: metadata.description,
            owner: metadata.owner.unwrap_or_else(|| owner.did().clone()),
            root_dir: root_dir.clone(),
            store,
            executor: Executor::new(root_dir),
            guests: metadata.guests,
            root_cid: Some(root_cid),
            total_resources: ResourceUsage::default(),
        })
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
        let store: Arc<dyn BlockStore> =
            Arc::new(DiskBlockStore::new(root_dir.join(".nexus").join("blocks")));
        Self::restore_tree(source_store, store.as_ref(), &root_cid, &root_dir).await?;
        Self::write_metadata(
            &root_dir,
            &config.name,
            &config.description,
            &id,
            owner,
            &[],
        )?;

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
        let root_cid = Self::index_directory(self.store.as_ref(), &self.root_dir).await?;
        self.root_cid = Some(root_cid);
        Ok(root_cid)
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
    async fn index_directory(store: &dyn BlockStore, dir: &Path) -> WorkspaceResult<Cid> {
        let mut entries = Vec::new();
        let read_dir = std::fs::read_dir(dir)?;

        for entry in read_dir {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();

            // Skip nexus metadata
            if name == ".nexus" {
                continue;
            }

            let path = entry.path();
            let metadata = entry.metadata()?;

            if metadata.is_dir() {
                let child_cid = Box::pin(Self::index_directory(store, &path)).await?;
                entries.push(TreeEntry {
                    name,
                    cid: child_cid,
                    kind: NodeKind::Tree,
                });
            } else {
                let data = std::fs::read(&path)?;
                let blob = MerkleNode::blob(data);
                let child_cid = store.put(blob).await?;
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

    async fn restore_tree(
        source_store: &dyn BlockStore,
        target_store: &dyn BlockStore,
        cid: &Cid,
        dir: &Path,
    ) -> WorkspaceResult<()> {
        let node = Self::verified_node(source_store, cid).await?;
        let entries = node.as_tree().ok_or_else(|| {
            WorkspaceError::Other("workspace root CID does not reference a tree".into())
        })?;
        target_store.put(node.clone()).await?;

        for entry in entries {
            let path = checked_child_path(dir, &entry.name)?;
            match entry.kind {
                NodeKind::Blob => {
                    let node = Self::verified_node(source_store, &entry.cid).await?;
                    let data = node.as_blob().ok_or_else(|| {
                        WorkspaceError::Other(format!("tree entry '{}' is not a blob", entry.name))
                    })?;
                    target_store.put(node.clone()).await?;
                    if let Some(parent) = path.parent() {
                        filesystem::ensure_dir(parent)?;
                    }
                    std::fs::write(path, data)?;
                }
                NodeKind::Tree => {
                    filesystem::ensure_dir(&path)?;
                    Box::pin(Self::restore_tree(
                        source_store,
                        target_store,
                        &entry.cid,
                        &path,
                    ))
                    .await?;
                }
            }
        }

        Ok(())
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

    fn persist_metadata(&self) -> WorkspaceResult<()> {
        Self::write_metadata(
            &self.root_dir,
            &self.name,
            &self.description,
            &self.id,
            &self.owner,
            &self.guests,
        )
    }

    /// Write workspace metadata to `.nexus/config.json`.
    fn write_metadata(
        root_dir: &Path,
        name: &str,
        description: &str,
        id: &WorkspaceId,
        owner: &Did,
        guests: &[Guest],
    ) -> WorkspaceResult<()> {
        let nexus_dir = root_dir.join(".nexus");
        filesystem::ensure_dir(&nexus_dir)?;

        let config = WorkspaceMetadata {
            name: name.to_string(),
            description: description.to_string(),
            id: hex::encode(id.as_bytes()),
            owner: Some(owner.clone()),
            guests: guests.to_vec(),
        };

        let config_path = nexus_dir.join("config.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;
        Ok(())
    }

    /// Read workspace metadata from `.nexus/config.json`.
    fn read_metadata(root_dir: &Path) -> WorkspaceResult<LoadedWorkspaceMetadata> {
        let config_path = root_dir.join(".nexus").join("config.json");
        if let Ok(data) = std::fs::read_to_string(&config_path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
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

                let id = if let Some(id_hex) = json.get("id").and_then(|v| v.as_str()) {
                    let bytes = hex::decode(id_hex).map_err(|e| {
                        WorkspaceError::Other(format!("invalid workspace id hex: {e}"))
                    })?;
                    let arr: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| WorkspaceError::Other("invalid workspace id length".into()))?;
                    WorkspaceId::from_bytes(arr)
                } else {
                    // Legacy: no ID in config, generate one
                    let mut id_bytes = [0u8; 32];
                    OsRng.fill_bytes(&mut id_bytes);
                    WorkspaceId::from_bytes(id_bytes)
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

                return Ok(LoadedWorkspaceMetadata {
                    id,
                    name,
                    description,
                    owner,
                    guests,
                });
            }
        }

        // Fallback: generate new ID, use directory name
        let name = root_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unnamed".into());

        let mut id_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut id_bytes);
        let id = WorkspaceId::from_bytes(id_bytes);

        Ok(LoadedWorkspaceMetadata {
            id,
            name,
            description: String::new(),
            owner: None,
            guests: Vec::new(),
        })
    }
}

fn checked_child_path(base: &Path, name: &str) -> WorkspaceResult<PathBuf> {
    let child = Path::new(name);
    let components = child.components().collect::<Vec<_>>();
    if child.is_absolute()
        || components.len() != 1
        || !matches!(components[0], std::path::Component::Normal(_))
    {
        return Err(WorkspaceError::Other(format!(
            "invalid workspace tree entry: {name}"
        )));
    }
    Ok(base.join(child))
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
    async fn exec_working_dir_is_unrestricted() {
        let (mut ws, _base) = setup_workspace().await;

        let opts = ExecOptions {
            working_dir: Some(PathBuf::from("..")),
            ..Default::default()
        };

        let output = ws.exec("true", &[], &opts).await.unwrap();
        assert_eq!(output.exit_code, 0);
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
