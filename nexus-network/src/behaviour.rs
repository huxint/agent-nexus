//! Composite [`NetworkBehaviour`] — Kademlia + Identify + Gossipsub + WorkspaceSync + NAT traversal.

use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, relay,
    request_response::{self, ProtocolSupport},
    PeerId, StreamProtocol,
};
use libp2p_swarm::behaviour::toggle::Toggle;
use libp2p_swarm::NetworkBehaviour as NetworkBehaviourDerive;
use std::num::NonZeroUsize;

use nexus_sync::client::SyncClient;
use nexus_sync::codec::SyncCodec;
use nexus_sync::message::{SyncRequest, SyncResponse};
use nexus_sync::{ANNOUNCE_TOPIC, SOCIAL_EVENT_TOPIC, SYNC_PROTOCOL};
use tracing::warn;

const GOSSIP_MAX_TRANSMIT_SIZE: usize = 1_048_576;

// ---------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------

/// Unified event emitted by our composite behaviour.
#[derive(Debug)]
pub enum BehaviourEvent {
    Autonat(autonat::Event),
    Dcutr(dcutr::Event),
    Relay(relay::client::Event),
    Kad(kad::Event),
    Mdns(mdns::Event),
    Identify(Box<identify::Event>),
    GossipsubMessage {
        source: Option<PeerId>,
        message_id: gossipsub::MessageId,
        /// Raw message data (JSON bytes — caller decodes).
        data: Vec<u8>,
    },
    SyncRequest {
        peer: PeerId,
        request_id: request_response::InboundRequestId,
        request: SyncRequest,
    },
    SyncResponse {
        peer: PeerId,
        request_id: request_response::OutboundRequestId,
        response: Result<SyncResponse, String>,
    },
}

/// The composite behaviour.
#[derive(NetworkBehaviourDerive)]
#[behaviour(to_swarm = "ToSwarm")]
pub struct CompositeBehaviour {
    pub autonat: autonat::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub relay: relay::client::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub gossipsub: gossipsub::Behaviour,
    pub sync: request_response::Behaviour<SyncCodec>,
    pub identify: identify::Behaviour,
}

/// Unified event we convert to in `ToSwarm`.
#[derive(Debug)]
pub enum ToSwarm {
    Autonat(autonat::Event),
    Dcutr(dcutr::Event),
    Relay(relay::client::Event),
    Kad(kad::Event),
    Mdns(mdns::Event),
    Gossipsub(gossipsub::Event),
    Sync(request_response::Event<SyncRequest, SyncResponse>),
    Identify(identify::Event),
}

impl From<autonat::Event> for ToSwarm {
    fn from(e: autonat::Event) -> Self {
        Self::Autonat(e)
    }
}
impl From<dcutr::Event> for ToSwarm {
    fn from(e: dcutr::Event) -> Self {
        Self::Dcutr(e)
    }
}
impl From<relay::client::Event> for ToSwarm {
    fn from(e: relay::client::Event) -> Self {
        Self::Relay(e)
    }
}
impl From<kad::Event> for ToSwarm {
    fn from(e: kad::Event) -> Self {
        Self::Kad(e)
    }
}
impl From<mdns::Event> for ToSwarm {
    fn from(e: mdns::Event) -> Self {
        Self::Mdns(e)
    }
}
impl From<gossipsub::Event> for ToSwarm {
    fn from(e: gossipsub::Event) -> Self {
        Self::Gossipsub(e)
    }
}
impl From<request_response::Event<SyncRequest, SyncResponse>> for ToSwarm {
    fn from(e: request_response::Event<SyncRequest, SyncResponse>) -> Self {
        Self::Sync(e)
    }
}
impl From<identify::Event> for ToSwarm {
    fn from(e: identify::Event) -> Self {
        Self::Identify(e)
    }
}

impl CompositeBehaviour {
    /// Create a new composite behaviour.
    pub fn new(
        local_peer_id: PeerId,
        public_key: libp2p::identity::PublicKey,
        gossipsub_keypair: libp2p::identity::Keypair,
        enable_mdns: bool,
        relay_behaviour: relay::client::Behaviour,
    ) -> Result<Self, String> {
        let autonat = autonat::Behaviour::new(local_peer_id, autonat::Config::default());
        let dcutr = dcutr::Behaviour::new(local_peer_id);
        let mut kademlia_config = kad::Config::new(
            StreamProtocol::try_from_owned("/ipfs/kad/1.0.0".to_string())
                .map_err(|err| format!("kad protocol: {err}"))?,
        );
        kademlia_config.disjoint_query_paths(true);
        kademlia_config.set_parallelism(NonZeroUsize::new(3).expect("non-zero"));
        let kademlia = kad::Behaviour::with_config(
            local_peer_id,
            kad::store::MemoryStore::new(local_peer_id),
            kademlia_config,
        );
        let mdns = if enable_mdns {
            match mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id) {
                Ok(behaviour) => Some(behaviour),
                Err(err) => {
                    warn!("mDNS discovery disabled: {err}");
                    None
                }
            }
        } else {
            None
        }
        .into();

        let gs_config = gossipsub::ConfigBuilder::default()
            .max_transmit_size(GOSSIP_MAX_TRANSMIT_SIZE)
            .heartbeat_interval(std::time::Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .validate_messages()
            .build()
            .map_err(|err| format!("gossipsub config: {err}"))?;
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(gossipsub_keypair),
            gs_config,
        )
        .map_err(|err| format!("gossipsub behaviour: {err}"))?;
        let (score_params, score_thresholds) = default_gossipsub_peer_score();
        gossipsub
            .with_peer_score(score_params, score_thresholds)
            .map_err(|err| format!("gossipsub peer score: {err}"))?;

        for topic in [ANNOUNCE_TOPIC, SOCIAL_EVENT_TOPIC] {
            gossipsub
                .subscribe(&gossipsub::IdentTopic::new(topic))
                .map_err(|err| format!("subscribe to gossipsub topic {topic}: {err}"))?;
        }

        let sync_protocol = StreamProtocol::try_from_owned(SYNC_PROTOCOL.to_string())
            .map_err(|err| format!("sync protocol: {err}"))?;
        let sync = request_response::Behaviour::new(
            [(sync_protocol, ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(SyncClient::DEFAULT_REQUEST_TIMEOUT),
        );

        let identify_config = identify::Config::new("/nexus/1.0.0".into(), public_key)
            .with_agent_version(format!("nexus/{}", env!("CARGO_PKG_VERSION")));
        let identify = identify::Behaviour::new(identify_config);

        Ok(Self {
            autonat,
            dcutr,
            relay: relay_behaviour,
            kademlia,
            mdns,
            gossipsub,
            sync,
            identify,
        })
    }
}

fn default_gossipsub_peer_score() -> (gossipsub::PeerScoreParams, gossipsub::PeerScoreThresholds) {
    let mut score_params = gossipsub::PeerScoreParams::default();
    score_params.topics.insert(
        gossipsub::IdentTopic::new(ANNOUNCE_TOPIC).hash(),
        gossip_topic_score_params(),
    );
    score_params.topics.insert(
        gossipsub::IdentTopic::new(SOCIAL_EVENT_TOPIC).hash(),
        gossip_topic_score_params(),
    );

    (score_params, gossipsub::PeerScoreThresholds::default())
}

fn gossip_topic_score_params() -> gossipsub::TopicScoreParams {
    gossipsub::TopicScoreParams {
        topic_weight: 1.0,
        invalid_message_deliveries_weight: -16.0,
        invalid_message_deliveries_decay: 0.3,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_crypto::NodeIdentity;

    use crate::transport;

    #[test]
    fn default_gossip_peer_score_covers_social_and_announcement_topics() {
        let (params, thresholds) = default_gossipsub_peer_score();

        params.validate().unwrap();
        thresholds.validate().unwrap();
        assert!(params
            .topics
            .contains_key(&gossipsub::IdentTopic::new(ANNOUNCE_TOPIC).hash()));
        assert!(params
            .topics
            .contains_key(&gossipsub::IdentTopic::new(SOCIAL_EVENT_TOPIC).hash()));
        assert!(params
            .topics
            .values()
            .all(|topic| topic.invalid_message_deliveries_weight < 0.0));
    }

    #[test]
    fn composite_behaviour_includes_nat_traversal_stack() {
        let node = NodeIdentity::generate();
        let keypair = transport::to_libp2p_keypair(&node);
        let local_peer_id = keypair.public().to_peer_id();
        let (_relay_transport, relay_behaviour) = relay::client::new(local_peer_id);

        let mut behaviour = CompositeBehaviour::new(
            local_peer_id,
            keypair.public(),
            keypair.clone(),
            false,
            relay_behaviour,
        )
        .expect("construct composite behaviour");

        behaviour.kademlia.set_mode(Some(kad::Mode::Client));
        let _ = &behaviour.autonat;
        let _ = &behaviour.dcutr;
        let _ = &behaviour.relay;
    }
}
