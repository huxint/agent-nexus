//! Nexus Core — fundamental types shared across all crates.
//!
//! This crate is free of heavy dependencies; it defines the vocabulary
//! every other crate speaks: identities, capabilities, errors, and the
//! resource primitives that the economic layer meters.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Unified error type for the Nexus stack.
#[derive(Debug, thiserror::Error)]
pub enum NexusError {
    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("runtime error: {0}")]
    Runtime(String),

    #[error("workspace not found: {0}")]
    WorkspaceNotFound(WorkspaceId),

    #[error("permission denied: {reason}")]
    PermissionDenied { reason: String },

    #[error("invalid capability: {0}")]
    InvalidCapability(String),

    #[error("resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type NexusResult<T> = Result<T, NexusError>;

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// A Decentralized Identifier — `did:key:<multibase-encoded-ed25519-pubkey>`.
///
/// The `Did` is derived deterministically from an Ed25519 public key.
/// It is the primary, self-sovereign identity primitive in the system.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(String);

impl Did {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Did({})", self.0)
    }
}

// ---------------------------------------------------------------------------
// Workspace
// ---------------------------------------------------------------------------

/// Unique identifier for a workspace — a content-addressed root.
///
/// A workspace is identified by the CID of its root Merkle node
/// at creation time.  This binds the identity of the workspace to
/// its initial state.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceId([u8; 32]);

impl WorkspaceId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for WorkspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WorkspaceId({})", hex::encode(&self.0[..8]))
    }
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// What an agent is allowed to do in a workspace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub admin: bool,
}

impl PermissionSet {
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        exec: false,
        admin: false,
    };
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        exec: false,
        admin: false,
    };
    pub const FULL: Self = Self {
        read: true,
        write: true,
        exec: true,
        admin: true,
    };

    pub fn can_read(&self) -> bool {
        self.read || self.admin
    }
    pub fn can_write(&self) -> bool {
        self.write || self.admin
    }
    pub fn can_exec(&self) -> bool {
        self.exec || self.admin
    }
    pub fn is_admin(&self) -> bool {
        self.admin
    }
}

/// A bearer capability — proof that `subject` is authorised by `issuer`.
///
/// Capabilities are signed statements.  Possession of a valid capability
/// (matching the caller's `Did`) grants access to the specified workspace
/// under the stated permissions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    pub issuer: Did,
    pub subject: Did,
    pub workspace: WorkspaceId,
    pub permissions: PermissionSet,
    /// Unix timestamp (seconds) after which this capability is invalid.
    pub expires_at: u64,
    /// Optional parent token proving that the issuer was allowed to delegate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Box<Capability>>,
    /// Remaining delegation depth after this token. `None` means no further
    /// delegation is allowed; `Some(0)` is the same for child tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_depth: Option<u8>,
    /// Ed25519 signature over the canonical serialisation of the fields above.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

/// Lightweight handle for an agent — just its identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(Did);

impl AgentId {
    pub fn new(did: Did) -> Self {
        Self(did)
    }

    pub fn did(&self) -> &Did {
        &self.0
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What an agent declares about itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentManifest {
    pub name: String,
    pub description: String,
    /// Capabilities this agent *provides* to others.
    pub provides: Vec<String>,
    /// Capabilities this agent *requires* from others.
    pub requires: Vec<String>,
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// Resource types that the economic layer meters and prices.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceKind {
    /// CPU time, in milliseconds.
    CpuTime,
    /// Memory usage, in megabytes.
    Memory,
    /// Storage usage, in megabyte-hours.
    Storage,
    /// Network egress, in megabytes.
    Bandwidth,
}

/// A quantified amount of a resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceAmount {
    pub kind: ResourceKind,
    pub quantity: f64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_set_read_only() {
        let p = PermissionSet::READ_ONLY;
        assert!(p.can_read());
        assert!(!p.can_write());
        assert!(!p.can_exec());
        assert!(!p.is_admin());
    }

    #[test]
    fn permission_set_full() {
        let p = PermissionSet::FULL;
        assert!(p.can_read());
        assert!(p.can_write());
        assert!(p.can_exec());
        assert!(p.is_admin());
    }

    #[test]
    fn workspace_id_roundtrip() {
        let bytes = [42u8; 32];
        let id = WorkspaceId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn did_display() {
        let did = Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert_eq!(
            did.to_string(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }
}
