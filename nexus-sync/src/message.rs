//! Sync protocol message types.

use serde::{Deserialize, Serialize};

use nexus_core::WorkspaceId;

/// Request sent by a node wanting to sync a workspace.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum SyncRequest {
    /// Ask for the current state of a workspace.
    StateRequest { workspace_id: WorkspaceId },

    /// Ask for a specific Merkle block by CID (hex-encoded SHA-256).
    BlockRequest {
        workspace_id: WorkspaceId,
        /// Hex-encoded CID.
        cid_hex: String,
    },

    /// Ask for signed social events known by the remote node.
    SocialEventsRequest {
        /// Event ids already known locally; the remote may omit these.
        known_event_ids: Vec<String>,
        /// Maximum number of events to return.
        limit: usize,
    },
}

/// Response to a sync request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum SyncResponse {
    /// Current workspace state.
    StateResponse {
        workspace_id: WorkspaceId,
        /// Hex-encoded root CID.
        root_cid_hex: String,
        /// Workspace name.
        name: String,
        /// Owner DID.
        owner_did: String,
    },

    /// A single Merkle block.
    BlockResponse {
        workspace_id: WorkspaceId,
        /// Hex-encoded CID of this block.
        cid_hex: String,
        /// CBOR-serialised MerkleNode bytes, base64-encoded.
        cbor_base64: String,
    },

    /// The requested block was not found.
    BlockNotFound {
        workspace_id: WorkspaceId,
        cid_hex: String,
    },

    /// Signed social events encoded as JSON bytes, one event per vector item.
    SocialEventsResponse { events_json: Vec<Vec<u8>> },

    /// The workspace is not available on this node.
    WorkspaceNotFound { workspace_id: WorkspaceId },

    /// Generic error.
    Error { message: String },
}
