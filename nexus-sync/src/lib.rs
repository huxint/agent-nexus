//! Nexus Sync — workspace state synchronisation over the P2P network.
//!
//! ## Protocol
//!
//! Two protocols run over libp2p:
//!
//! 1. **Gossipsub** — nodes announce workspaces and social events.
//! 2. **Request-Response** — point-to-point block transfer on `/nexus/sync/1.0.0`.
//!
//! ## Sync flow
//!
//! ```text
//! Node A (owner)                  Node B (cloner)
//!   │                                │
//!   │── gossip(WorkspaceAnnounce) ──→│  (B discovers workspace X)
//!   │                                │
//!   │←── StateRequest(workspace X) ──│  (B asks for root CID)
//!   │── StateResponse(root_cid) ────→│
//!   │                                │
//!   │←── BlockRequest(cid) ──────────│  (B asks for missing blocks)
//!   │── BlockResponse(node_cbor) ───→│
//!   │         ... repeat ...         │
//!   │                                │
//!   │                          B reconstructs workspace locally
//! ```

pub mod client;
pub mod codec;
pub mod message;

pub use client::SyncClient;
pub use codec::SyncCodec;
pub use message::{SyncRequest, SyncResponse};

/// Protocol name for workspace sync request-response.
pub const SYNC_PROTOCOL: &str = "/nexus/sync/1.0.0";

/// Gossipsub topic for workspace announcements.
pub const ANNOUNCE_TOPIC: &str = "nexus-workspace-announce";

/// Gossipsub topic for signed AI society events.
pub const SOCIAL_EVENT_TOPIC: &str = "nexus-social-events";
