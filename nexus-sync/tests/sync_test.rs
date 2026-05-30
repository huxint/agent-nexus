//! Workspace sync protocol tests.

use std::sync::Arc;

use nexus_core::WorkspaceId;
use nexus_storage::cid::Cid;
use nexus_storage::node::{MerkleNode, NodeKind, TreeEntry};
use nexus_storage::store::{BlockStore, InMemoryBlockStore};
use nexus_sync::message::{SyncRequest, SyncResponse};
use nexus_sync::SyncClient;

/// Verify sync messages serialise and deserialise correctly.
#[test]
fn sync_message_roundtrip() {
    let ws_id = WorkspaceId::from_bytes([0xabu8; 32]);

    // StateRequest
    let req = SyncRequest::StateRequest {
        workspace_id: ws_id,
    };
    let json = serde_json::to_string(&req).unwrap();
    let decoded: SyncRequest = serde_json::from_str(&json).unwrap();
    assert!(matches!(decoded, SyncRequest::StateRequest { .. }));

    // BlockRequest
    let req = SyncRequest::BlockRequest {
        workspace_id: ws_id,
        cid_hex: "abcdef1234567890".into(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let decoded: SyncRequest = serde_json::from_str(&json).unwrap();
    assert!(matches!(decoded, SyncRequest::BlockRequest { .. }));

    // SocialEventsRequest
    let req = SyncRequest::SocialEventsRequest {
        known_event_ids: vec!["event-a".into()],
        limit: 50,
    };
    let json = serde_json::to_string(&req).unwrap();
    let decoded: SyncRequest = serde_json::from_str(&json).unwrap();
    assert!(matches!(
        decoded,
        SyncRequest::SocialEventsRequest {
            known_event_ids,
            limit: 50,
        } if known_event_ids == vec!["event-a".to_string()]
    ));

    // WorkspaceAnnouncementsRequest
    let req = SyncRequest::WorkspaceAnnouncementsRequest {
        workspace_id: Some(ws_id),
        limit: 10,
    };
    let json = serde_json::to_string(&req).unwrap();
    let decoded: SyncRequest = serde_json::from_str(&json).unwrap();
    assert!(matches!(
        decoded,
        SyncRequest::WorkspaceAnnouncementsRequest {
            workspace_id: Some(got_ws),
            limit: 10,
        } if got_ws == ws_id
    ));

    // StateResponse
    let resp = SyncResponse::StateResponse {
        workspace_id: ws_id,
        root_cid_hex: "deadbeef".into(),
        name: "test-ws".into(),
        owner_did: "did:key:z6MkTest".into(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let decoded: SyncResponse = serde_json::from_str(&json).unwrap();
    assert!(matches!(decoded, SyncResponse::StateResponse { .. }));

    // SocialEventsResponse
    let resp = SyncResponse::SocialEventsResponse {
        events_json: vec![br#"{"id":"event-a"}"#.to_vec()],
    };
    let json = serde_json::to_string(&resp).unwrap();
    let decoded: SyncResponse = serde_json::from_str(&json).unwrap();
    assert!(matches!(
        decoded,
        SyncResponse::SocialEventsResponse { events_json } if events_json.len() == 1
    ));

    // WorkspaceAnnouncementsResponse
    let resp = SyncResponse::WorkspaceAnnouncementsResponse {
        announcements_json: vec![br#"{"workspace":"abc"}"#.to_vec()],
    };
    let json = serde_json::to_string(&resp).unwrap();
    let decoded: SyncResponse = serde_json::from_str(&json).unwrap();
    assert!(matches!(
        decoded,
        SyncResponse::WorkspaceAnnouncementsResponse { announcements_json }
            if announcements_json.len() == 1
    ));
}

/// Build a Merkle tree, serialise blocks as CBOR, and verify they can be
/// reconstructed — simulating what happens during sync.
#[tokio::test]
async fn block_serialisation_for_sync() {
    let store: Arc<dyn BlockStore> = Arc::new(InMemoryBlockStore::new());

    // Create a simple tree
    let blob = MerkleNode::blob(b"sync test data".to_vec());
    let cid_blob = store.put(blob).await.unwrap();

    let tree = MerkleNode::tree(vec![TreeEntry {
        name: "data.txt".into(),
        cid: cid_blob,
        kind: NodeKind::Blob,
    }]);
    let cid_tree = store.put(tree).await.unwrap();

    // Simulate block retrieval: get node, serialise to CBOR, reconstruct
    let node = store.get(&cid_tree).await.unwrap();
    let cbor = node.to_cbor().unwrap();

    // This CBOR is what would be sent over the wire in BlockResponse
    let reconstructed = MerkleNode::from_cbor(&cbor).unwrap();
    assert_eq!(node, reconstructed);

    // Verify the CID is consistent
    let recalculated_cid = reconstructed.cid();
    assert_eq!(cid_tree, recalculated_cid);
}

/// Reject a remote block whose decoded content does not hash to the requested
/// CID. This protects workspace cloning from accepting forged Merkle blocks.
#[tokio::test]
async fn get_block_rejects_content_cid_mismatch() {
    use base64::Engine;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let client = SyncClient::new(tx);
    let peer = libp2p::PeerId::random();
    let workspace_id = WorkspaceId::from_bytes([7; 32]);
    let requested = Cid::hash_of(b"requested block");
    let wrong_node = MerkleNode::blob(b"different block".to_vec());
    let wrong_cbor = wrong_node.to_cbor().unwrap();

    tokio::spawn(async move {
        let (_peer, request, reply) = rx.recv().await.unwrap();
        let cid_hex = match request {
            SyncRequest::BlockRequest {
                workspace_id: got_workspace,
                cid_hex,
            } => {
                assert_eq!(got_workspace, workspace_id);
                assert_eq!(cid_hex, hex::encode(requested.as_bytes()));
                cid_hex
            }
            other => panic!("unexpected request: {other:?}"),
        };
        reply
            .send(Ok(SyncResponse::BlockResponse {
                workspace_id,
                cid_hex,
                cbor_base64: base64::engine::general_purpose::STANDARD.encode(wrong_cbor),
            }))
            .ok();
    });

    let err = client
        .get_block(peer, workspace_id, &requested)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("block content CID mismatch"));
}

/// Chunked file nodes must cause sync recursion to fetch the chunk blocks too.
#[tokio::test]
async fn clone_workspace_fetches_chunked_blob_children() {
    use base64::Engine;

    let remote_store: Arc<dyn BlockStore> = Arc::new(InMemoryBlockStore::new());
    let chunk_a = remote_store
        .put(MerkleNode::blob(b"large-".to_vec()))
        .await
        .unwrap();
    let chunk_b = remote_store
        .put(MerkleNode::blob(b"file".to_vec()))
        .await
        .unwrap();
    let file_node = MerkleNode::chunked_blob(vec![chunk_a, chunk_b], "large-file".len() as u64);
    let file_cid = remote_store.put(file_node).await.unwrap();
    let root_node = MerkleNode::tree(vec![TreeEntry {
        name: "large.bin".into(),
        cid: file_cid,
        kind: NodeKind::Blob,
    }]);
    let root_cid = remote_store.put(root_node).await.unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let client = SyncClient::new(tx);
    let peer = libp2p::PeerId::random();
    let workspace_id = WorkspaceId::from_bytes([9; 32]);
    let remote_store_for_task = Arc::clone(&remote_store);

    tokio::spawn(async move {
        while let Some((_peer, request, reply)) = rx.recv().await {
            let response = match request {
                SyncRequest::StateRequest { workspace_id } => SyncResponse::StateResponse {
                    workspace_id,
                    root_cid_hex: hex::encode(root_cid.as_bytes()),
                    name: "chunked".into(),
                    owner_did: "did:key:z6MkChunked".into(),
                },
                SyncRequest::BlockRequest {
                    workspace_id,
                    cid_hex,
                } => {
                    let cid_bytes = hex::decode(&cid_hex).unwrap();
                    let cid = Cid::from_bytes(cid_bytes.try_into().unwrap());
                    let node = remote_store_for_task.get(&cid).await.unwrap();
                    SyncResponse::BlockResponse {
                        workspace_id,
                        cid_hex,
                        cbor_base64: base64::engine::general_purpose::STANDARD
                            .encode(node.to_cbor().unwrap()),
                    }
                }
                other => panic!("unexpected request: {other:?}"),
            };
            reply.send(Ok(response)).ok();
        }
    });

    let local_store: Arc<dyn BlockStore> = Arc::new(InMemoryBlockStore::new());
    let synced_root = client
        .clone_workspace(peer, workspace_id, &local_store)
        .await
        .unwrap();

    assert_eq!(synced_root, root_cid);
    assert!(local_store.has(&file_cid).await.unwrap());
    assert!(local_store.has(&chunk_a).await.unwrap());
    assert!(local_store.has(&chunk_b).await.unwrap());
}

/// Verify workspace ID is stable when derived from root CID.
#[test]
fn workspace_id_from_root_cid() {
    let root_tree = MerkleNode::tree(vec![TreeEntry {
        name: "test".into(),
        cid: Cid::hash_of(b"test data"),
        kind: NodeKind::Blob,
    }]);
    let cid = root_tree.cid();
    let ws_id_1 = WorkspaceId::from_bytes(*cid.as_bytes());
    let ws_id_2 = WorkspaceId::from_bytes(*cid.as_bytes());
    assert_eq!(ws_id_1, ws_id_2);
}
