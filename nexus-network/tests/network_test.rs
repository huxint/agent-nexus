//! Integration tests for the P2P network layer.
//!
//! Tests two-node communication: both nodes start, discover each other,
//! and exchange events.

use nexus_crypto::NodeIdentity;
use nexus_network::{Network, NetworkConfig, NetworkEvent};
use nexus_sync::message::{SyncRequest, SyncResponse};
use nexus_sync::SyncClient;
use std::time::Duration;

async fn wait_for_listen(net: &mut Network) -> libp2p::Multiaddr {
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = net.next_event().await {
            if let NetworkEvent::Listening(addr) = event {
                return addr;
            }
        }
        panic!("network event stream ended before listening");
    })
    .await
    .expect("node should start listening")
}

async fn wait_for_peer_connection(net: &mut Network, peer: libp2p::PeerId) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = net.next_event().await {
            if matches!(event, NetworkEvent::PeerConnected(connected) if connected == peer) {
                break;
            }
        }
    })
    .await
    .expect("peer connection timeout");
}

async fn publish_social_event_with_retry(net: &Network, data: Vec<u8>) {
    let mut last_error = None;
    for _ in 0..40 {
        match net.publish_social_event(data.clone()).await {
            Ok(()) => return,
            Err(err) => {
                last_error = Some(err);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    panic!("social event publish failed after retries: {last_error:?}");
}

async fn wait_for_social_event(
    net: &mut Network,
    expected: &[u8],
) -> (Option<libp2p::PeerId>, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(NetworkEvent::SocialEvent { source, data }) = net.next_event().await {
                if data == expected {
                    return (source, data);
                }
            }
        }
    })
    .await
    .expect("social event gossip timeout")
}

async fn wait_for_social_sync_request(
    net: &mut Network,
) -> (
    libp2p::PeerId,
    libp2p::request_response::InboundRequestId,
    SyncRequest,
) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(NetworkEvent::SyncRequest {
                peer,
                request_id,
                request,
            }) = net.next_event().await
            {
                if matches!(request, SyncRequest::SocialEventsRequest { .. }) {
                    return (peer, request_id, request);
                }
            }
        }
    })
    .await
    .expect("social sync request timeout")
}

/// Start two nodes and verify they can discover each other via Kademlia.
#[tokio::test]
async fn two_nodes_discover_each_other() {
    let _ = tracing_subscriber::fmt::try_init();

    // -- Node A --
    let id_a = NodeIdentity::generate();
    let config_a = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        bootstrap_peers: Vec::new(),
        ..Default::default()
    };
    let mut net_a = Network::new(&id_a, config_a).await.expect("node A start");

    // Wait for A to start listening
    let addr_a = wait_for_listen(&mut net_a).await;

    // -- Node B, bootstrapping from A --
    let id_b = NodeIdentity::generate();
    let config_b = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        bootstrap_peers: vec![addr_a.clone()],
        ..Default::default()
    };
    let mut net_b = Network::new(&id_b, config_b).await.expect("node B start");

    // Wait for B to connect to A and discover it
    let mut b_discovered_a = false;
    let mut a_discovered_b = false;

    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                event_a = net_a.next_event() => {
                    if let Some(NetworkEvent::PeerDiscovered { .. }) = event_a {
                        a_discovered_b = true;
                    }
                    if let Some(NetworkEvent::PeerConnected(_)) = event_a {
                        // Connected — good sign
                    }
                }
                event_b = net_b.next_event() => {
                    if let Some(NetworkEvent::PeerConnected(peer_id)) = event_b {
                        if peer_id == net_a.local_peer_id() {
                            b_discovered_a = true;
                        }
                    }
                }
            }

            if a_discovered_b && b_discovered_a {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("discovery timeout");

    assert!(
        a_discovered_b || b_discovered_a,
        "nodes should discover each other"
    );
}

/// Signed social events are first-class gossip payloads.
#[tokio::test]
async fn social_event_gossip_reaches_connected_peer() {
    let _ = tracing_subscriber::fmt::try_init();

    let id_a = NodeIdentity::generate();
    let mut net_a = Network::new(
        &id_a,
        NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            ..Default::default()
        },
    )
    .await
    .expect("node A start");
    let addr_a = wait_for_listen(&mut net_a).await;

    let id_b = NodeIdentity::generate();
    let mut net_b = Network::new(
        &id_b,
        NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            bootstrap_peers: vec![addr_a],
            ..Default::default()
        },
    )
    .await
    .expect("node B start");

    wait_for_peer_connection(&mut net_b, net_a.local_peer_id()).await;

    let event = nexus_agent::SocialEvent::new(
        id_a.did().clone(),
        1,
        nexus_agent::SocialEventKind::WorkspaceJoined {
            workspace: nexus_core::WorkspaceId::from_bytes([42; 32]),
        },
    )
    .sign(&id_a)
    .expect("sign social event");
    let event_bytes = event.to_json().expect("serialize social event");
    publish_social_event_with_retry(&net_a, event_bytes.clone()).await;

    let received = wait_for_social_event(&mut net_b, &event_bytes).await;

    assert_eq!(received.0, Some(net_a.local_peer_id()));
    let decoded = nexus_agent::SocialEvent::from_json(&received.1).expect("decode social event");
    decoded.verify_signature().expect("verify social event");
}

/// Local social memory can be replayed after a peer appears.
#[tokio::test]
async fn social_event_can_be_replayed_after_initial_publish_failure() {
    let _ = tracing_subscriber::fmt::try_init();

    let id_a = NodeIdentity::generate();
    let mut net_a = Network::new(
        &id_a,
        NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            ..Default::default()
        },
    )
    .await
    .expect("node A start");
    let addr_a = wait_for_listen(&mut net_a).await;

    let event = nexus_agent::SocialEvent::new(
        id_a.did().clone(),
        2,
        nexus_agent::SocialEventKind::WorkspaceJoined {
            workspace: nexus_core::WorkspaceId::from_bytes([43; 32]),
        },
    )
    .sign(&id_a)
    .expect("sign social event");
    let event_bytes = event.to_json().expect("serialize social event");

    assert!(
        net_a
            .publish_social_event(event_bytes.clone())
            .await
            .is_err(),
        "publish should fail before any gossipsub peer is available"
    );

    let id_b = NodeIdentity::generate();
    let mut net_b = Network::new(
        &id_b,
        NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            bootstrap_peers: vec![addr_a],
            ..Default::default()
        },
    )
    .await
    .expect("node B start");

    wait_for_peer_connection(&mut net_b, net_a.local_peer_id()).await;
    publish_social_event_with_retry(&net_a, event_bytes.clone()).await;

    let received = wait_for_social_event(&mut net_b, &event_bytes).await;
    assert_eq!(received.0, Some(net_a.local_peer_id()));
    nexus_agent::SocialEvent::from_json(&received.1)
        .expect("decode social event")
        .verify_signature()
        .expect("verify replayed social event");
}

/// Social events can also be requested over the request-response sync channel.
#[tokio::test]
async fn social_events_can_be_requested_over_sync_protocol() {
    let _ = tracing_subscriber::fmt::try_init();

    let id_a = NodeIdentity::generate();
    let mut net_a = Network::new(
        &id_a,
        NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            ..Default::default()
        },
    )
    .await
    .expect("node A start");
    let addr_a = wait_for_listen(&mut net_a).await;

    let id_b = NodeIdentity::generate();
    let mut net_b = Network::new(
        &id_b,
        NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            bootstrap_peers: vec![addr_a],
            ..Default::default()
        },
    )
    .await
    .expect("node B start");

    wait_for_peer_connection(&mut net_b, net_a.local_peer_id()).await;

    let event = nexus_agent::SocialEvent::new(
        id_a.did().clone(),
        3,
        nexus_agent::SocialEventKind::WorkspaceJoined {
            workspace: nexus_core::WorkspaceId::from_bytes([44; 32]),
        },
    )
    .sign(&id_a)
    .expect("sign social event");
    let event_bytes = event.to_json().expect("serialize social event");

    let client = SyncClient::new(net_b.sync_request_channel());
    let peer_a = net_a.local_peer_id();
    let request =
        tokio::spawn(async move { client.get_social_events(peer_a, Vec::new(), 10).await });

    let (request_peer, request_id, request_msg) = wait_for_social_sync_request(&mut net_a).await;
    assert_eq!(request_peer, net_b.local_peer_id());
    assert!(matches!(
        request_msg,
        SyncRequest::SocialEventsRequest {
            known_event_ids,
            limit: 10,
        } if known_event_ids.is_empty()
    ));

    net_a.respond_to_sync(
        request_id,
        SyncResponse::SocialEventsResponse {
            events_json: vec![event_bytes.clone()],
        },
    );

    let events = request
        .await
        .expect("social sync task")
        .expect("social sync response");
    assert_eq!(events, vec![event_bytes]);
    let decoded = nexus_agent::SocialEvent::from_json(&events[0]).expect("decode social event");
    decoded
        .verify_signature()
        .expect("verify synced social event");
}

/// Failed sync requests wake the caller with an error instead of hanging.
#[tokio::test]
async fn sync_request_to_unreachable_peer_returns_error() {
    let _ = tracing_subscriber::fmt::try_init();

    let id = NodeIdentity::generate();
    let mut net = Network::new(
        &id,
        NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            ..Default::default()
        },
    )
    .await
    .expect("node start");
    wait_for_listen(&mut net).await;

    let unreachable = nexus_network::to_peer_id(&NodeIdentity::generate());
    let client = SyncClient::new(net.sync_request_channel());
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.get_social_events(unreachable, Vec::new(), 1),
    )
    .await
    .expect("sync request should fail promptly, not hang");

    assert!(
        result.is_err(),
        "unreachable sync request should return an error"
    );
}

/// A single node starts and stops cleanly.
#[tokio::test]
async fn single_node_startup() {
    let _ = tracing_subscriber::fmt::try_init();

    let id = NodeIdentity::generate();
    let config = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        ..Default::default()
    };

    let mut net = Network::new(&id, config).await.expect("node start");

    // Should get a Listening event within 5 seconds
    let listened_addr = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = net.next_event().await {
            if let NetworkEvent::Listening(addr) = event {
                return Some(addr);
            }
        }
        None
    })
    .await
    .unwrap_or(None);

    let listened_addr = listened_addr.expect("node should report listening address");
    assert!(
        net.listen_addrs().contains(&listened_addr),
        "node should retain listening address for announcements"
    );
}

/// Verify PeerId is deterministic from NodeIdentity.
#[test]
fn peer_id_from_identity_is_deterministic() {
    let id = NodeIdentity::generate();
    let peer_id_1 = nexus_network::transport::to_peer_id(&id);
    let peer_id_2 = nexus_network::transport::to_peer_id(&id);
    assert_eq!(peer_id_1, peer_id_2);
}
