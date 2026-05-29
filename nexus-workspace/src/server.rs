//! Workspace Server — bridges workspace storage/execution with the P2P network.
//!
//! Handles incoming sync requests (block queries) from remote peers,
//! responding with data from local workspaces.

use std::collections::HashMap;
use std::sync::Arc;

use nexus_core::{Did, WorkspaceId};
use nexus_network::{Network, NetworkEvent};
use nexus_storage::Cid;
use nexus_sync::message::{SyncRequest, SyncResponse};

use crate::error::WorkspaceResult;
use crate::workspace::Workspace;

/// Manages a collection of workspaces and handles network events.
pub struct WorkspaceServer {
    network: Arc<Network>,
    workspaces: HashMap<WorkspaceId, Workspace>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceState {
    pub workspace_id: WorkspaceId,
    pub root: Cid,
    pub name: String,
    pub owner: Did,
}

impl WorkspaceServer {
    pub fn new(network: Arc<Network>) -> Self {
        Self {
            network,
            workspaces: HashMap::new(),
        }
    }

    pub fn register(&mut self, workspace: Workspace) {
        self.workspaces.insert(workspace.id(), workspace);
    }

    pub fn unregister(&mut self, id: &WorkspaceId) {
        self.workspaces.remove(id);
    }

    pub fn get(&self, id: &WorkspaceId) -> Option<&Workspace> {
        self.workspaces.get(id)
    }

    pub fn get_mut(&mut self, id: &WorkspaceId) -> Option<&mut Workspace> {
        self.workspaces.get_mut(id)
    }

    pub fn workspace_count(&self) -> usize {
        self.workspaces.len()
    }

    pub fn workspaces(&self) -> impl Iterator<Item = &Workspace> {
        self.workspaces.values()
    }

    pub fn workspaces_mut(&mut self) -> impl Iterator<Item = &mut Workspace> {
        self.workspaces.values_mut()
    }

    pub async fn refresh_workspace(
        &mut self,
        workspace_id: &WorkspaceId,
    ) -> WorkspaceResult<Option<WorkspaceState>> {
        let Some(workspace) = self.workspaces.get_mut(workspace_id) else {
            return Ok(None);
        };
        let root = workspace.snapshot().await?;
        Ok(Some(WorkspaceState {
            workspace_id: *workspace_id,
            root,
            name: workspace.name().to_string(),
            owner: workspace.owner().clone(),
        }))
    }

    /// Process a single network event.
    pub async fn handle_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::SyncRequest {
                request_id,
                request,
                ..
            } => {
                let response = self.handle_sync_request(&request).await;
                self.network.respond_to_sync(request_id, response);
            }
            NetworkEvent::WorkspaceAnnounce { source, data } => {
                tracing::debug!("Workspace announce from {:?}: {} bytes", source, data.len());
            }
            NetworkEvent::SocialEvent { source, data } => {
                tracing::debug!("Social event from {:?}: {} bytes", source, data.len());
            }
            _ => {}
        }
    }

    async fn handle_sync_request(&mut self, request: &SyncRequest) -> SyncResponse {
        match request {
            SyncRequest::StateRequest { workspace_id } => {
                match self.refresh_workspace(workspace_id).await {
                    Ok(Some(state)) => SyncResponse::StateResponse {
                        workspace_id: state.workspace_id,
                        root_cid_hex: hex::encode(state.root.as_bytes()),
                        name: state.name,
                        owner_did: state.owner.to_string(),
                    },
                    Ok(None) => SyncResponse::WorkspaceNotFound {
                        workspace_id: *workspace_id,
                    },
                    Err(err) => SyncResponse::Error {
                        message: format!("refresh workspace state: {err}"),
                    },
                }
            }
            SyncRequest::BlockRequest {
                workspace_id,
                cid_hex,
            } => {
                if let Some(ws) = self.workspaces.get(workspace_id) {
                    let cid_bytes = match hex::decode(cid_hex) {
                        Ok(b) => b,
                        Err(e) => {
                            return SyncResponse::Error {
                                message: format!("invalid CID hex: {e}"),
                            }
                        }
                    };
                    let cid_arr: [u8; 32] = match cid_bytes.try_into() {
                        Ok(a) => a,
                        Err(_) => {
                            return SyncResponse::Error {
                                message: "invalid CID length".into(),
                            }
                        }
                    };
                    let cid = nexus_storage::cid::Cid::from_bytes(cid_arr);

                    match ws.get_block(&cid).await {
                        Ok(node) => {
                            let cbor = match node.to_cbor() {
                                Ok(c) => c,
                                Err(e) => return SyncResponse::Error { message: e },
                            };
                            use base64::Engine;
                            SyncResponse::BlockResponse {
                                workspace_id: *workspace_id,
                                cid_hex: cid_hex.clone(),
                                cbor_base64: base64::engine::general_purpose::STANDARD
                                    .encode(&cbor),
                            }
                        }
                        Err(_) => SyncResponse::BlockNotFound {
                            workspace_id: *workspace_id,
                            cid_hex: cid_hex.clone(),
                        },
                    }
                } else {
                    SyncResponse::WorkspaceNotFound {
                        workspace_id: *workspace_id,
                    }
                }
            }
            SyncRequest::SocialEventsRequest { .. } => SyncResponse::Error {
                message: "social events are handled by nexus-node".into(),
            },
        }
    }
}
