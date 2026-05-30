//! Sync client — fetches workspace state and blocks from a remote peer.

use std::sync::Arc;
use std::time::Duration;

use libp2p::PeerId;
use nexus_core::WorkspaceId;
use nexus_storage::cid::Cid;
use nexus_storage::node::MerkleNode;
use nexus_storage::store::BlockStore;
use tokio::sync::{mpsc, oneshot};

use crate::message::{SyncRequest, SyncResponse};

pub type SyncReplySender = oneshot::Sender<Result<SyncResponse, String>>;
pub type SyncRequestEnvelope = (PeerId, SyncRequest, SyncReplySender);
pub type SyncRequestSender = mpsc::UnboundedSender<SyncRequestEnvelope>;

/// Errors during sync operations.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("request failed: {0}")]
    RequestFailed(String),

    #[error("request timed out after {0:?}")]
    RequestTimedOut(Duration),

    #[error("workspace not found on remote")]
    WorkspaceNotFound,

    #[error("block not found on remote: {0}")]
    BlockNotFound(String),

    #[error("remote error: {0}")]
    Remote(String),

    #[error("storage error: {0}")]
    Storage(String),
}

/// A client for syncing workspace state from a remote peer.
///
/// Sends requests via a channel to the network event loop and
/// receives responses asynchronously.
pub struct SyncClient {
    /// Channel to send sync requests to the network event loop.
    request_tx: SyncRequestSender,
    request_timeout: Duration,
}

impl SyncClient {
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

    /// Create a new sync client backed by the given request channel.
    pub fn new(request_tx: SyncRequestSender) -> Self {
        Self::with_timeout(request_tx, Self::DEFAULT_REQUEST_TIMEOUT)
    }

    /// Create a sync client with an explicit per-request timeout.
    pub fn with_timeout(request_tx: SyncRequestSender, request_timeout: Duration) -> Self {
        Self {
            request_tx,
            request_timeout,
        }
    }

    /// Send a sync request to a peer and await the response.
    pub async fn request(&self, peer: PeerId, req: SyncRequest) -> Result<SyncResponse, SyncError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.request_tx
            .send((peer, req, reply_tx))
            .map_err(|_| SyncError::RequestFailed("event loop closed".into()))?;

        let reply = tokio::time::timeout(self.request_timeout, reply_rx)
            .await
            .map_err(|_| SyncError::RequestTimedOut(self.request_timeout))?;

        match reply {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(SyncError::Remote(e)),
            Err(_) => Err(SyncError::RequestFailed("reply channel closed".into())),
        }
    }

    /// Get the current state (root CID, name, owner) of a remote workspace.
    pub async fn get_state(
        &self,
        peer: PeerId,
        workspace_id: WorkspaceId,
    ) -> Result<SyncResponse, SyncError> {
        self.request(peer, SyncRequest::StateRequest { workspace_id })
            .await
    }

    /// Fetch signed social events from a peer.
    pub async fn get_social_events(
        &self,
        peer: PeerId,
        known_event_ids: Vec<String>,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, SyncError> {
        let resp = self
            .request(
                peer,
                SyncRequest::SocialEventsRequest {
                    known_event_ids,
                    limit,
                },
            )
            .await?;

        match resp {
            SyncResponse::SocialEventsResponse { events_json } => Ok(events_json),
            SyncResponse::Error { message } => Err(SyncError::Remote(message)),
            other => Err(SyncError::Remote(format!("unexpected response: {other:?}"))),
        }
    }

    /// Fetch signed workspace announcements from a peer.
    pub async fn get_workspace_announcements(
        &self,
        peer: PeerId,
        workspace_id: Option<WorkspaceId>,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, SyncError> {
        let resp = self
            .request(
                peer,
                SyncRequest::WorkspaceAnnouncementsRequest {
                    workspace_id,
                    limit,
                },
            )
            .await?;

        match resp {
            SyncResponse::WorkspaceAnnouncementsResponse { announcements_json } => {
                Ok(announcements_json)
            }
            SyncResponse::Error { message } => Err(SyncError::Remote(message)),
            other => Err(SyncError::Remote(format!("unexpected response: {other:?}"))),
        }
    }

    /// Fetch a single Merkle block from a remote peer.
    pub async fn get_block(
        &self,
        peer: PeerId,
        workspace_id: WorkspaceId,
        cid: &Cid,
    ) -> Result<MerkleNode, SyncError> {
        let cid_hex = hex::encode(cid.as_bytes());
        let resp = self
            .request(
                peer,
                SyncRequest::BlockRequest {
                    workspace_id,
                    cid_hex: cid_hex.clone(),
                },
            )
            .await?;

        match resp {
            SyncResponse::BlockResponse { cbor_base64, .. } => {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&cbor_base64)
                    .map_err(|e| SyncError::Remote(format!("base64 decode: {e}")))?;
                let node = MerkleNode::from_cbor(&bytes)
                    .map_err(|e| SyncError::Remote(format!("CBOR decode: {e}")))?;
                let actual = node.cid();
                if actual != *cid {
                    return Err(SyncError::Remote(format!(
                        "block content CID mismatch: expected {}, got {}",
                        cid_hex,
                        hex::encode(actual.as_bytes())
                    )));
                }
                Ok(node)
            }
            SyncResponse::BlockNotFound { .. } => Err(SyncError::BlockNotFound(cid_hex)),
            other => Err(SyncError::Remote(format!("unexpected response: {other:?}"))),
        }
    }

    /// Clone an entire workspace from a remote peer into a local block store.
    ///
    /// This fetches the root CID, then recursively fetches all blocks
    /// reachable from the root.
    pub async fn clone_workspace(
        &self,
        peer: PeerId,
        workspace_id: WorkspaceId,
        store: &Arc<dyn BlockStore>,
    ) -> Result<Cid, SyncError> {
        // 1. Get state (root CID)
        let state = self.get_state(peer, workspace_id).await?;
        let root_cid_hex = match state {
            SyncResponse::StateResponse { root_cid_hex, .. } => root_cid_hex,
            SyncResponse::WorkspaceNotFound { .. } => return Err(SyncError::WorkspaceNotFound),
            other => return Err(SyncError::Remote(format!("unexpected: {other:?}"))),
        };

        let root_bytes: [u8; 32] = hex::decode(&root_cid_hex)
            .map_err(|e| SyncError::Remote(format!("hex decode: {e}")))?
            .try_into()
            .map_err(|_| SyncError::Remote("invalid CID length".into()))?;
        let root_cid = Cid::from_bytes(root_bytes);

        // 2. Recursively fetch blocks
        self.fetch_recursive(peer, workspace_id, &root_cid, store)
            .await?;

        Ok(root_cid)
    }

    /// Recursively fetch a block and all its descendants.
    async fn fetch_recursive(
        &self,
        peer: PeerId,
        workspace_id: WorkspaceId,
        cid: &Cid,
        store: &Arc<dyn BlockStore>,
    ) -> Result<(), SyncError> {
        // Check if we already have this block
        if store
            .has(cid)
            .await
            .map_err(|e| SyncError::Storage(e.to_string()))?
        {
            return Ok(());
        }

        let node = self.get_block(peer, workspace_id, cid).await?;

        let child_cids = if let Some(entries) = node.as_tree() {
            entries.iter().map(|entry| entry.cid).collect::<Vec<_>>()
        } else if let Some((chunks, _)) = node.as_chunked_blob() {
            chunks.to_vec()
        } else {
            Vec::new()
        };

        for child in child_cids {
            Box::pin(self.fetch_recursive(peer, workspace_id, &child, store)).await?;
        }

        // Store the block
        store
            .put(node)
            .await
            .map_err(|e| SyncError::Storage(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_times_out_when_network_task_never_replies() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let client = SyncClient::with_timeout(tx, Duration::from_millis(20));
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let workspace_id = WorkspaceId::from_bytes([42; 32]);

        let _hold_reply = tokio::spawn(async move {
            let (_peer, _request, _reply) = rx.recv().await.expect("sync request");
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let err = client
            .request(peer, SyncRequest::StateRequest { workspace_id })
            .await
            .expect_err("request should time out");

        assert!(matches!(
            err,
            SyncError::RequestTimedOut(timeout) if timeout == Duration::from_millis(20)
        ));
    }
}
