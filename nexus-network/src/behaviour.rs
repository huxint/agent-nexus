//! Composite [`NetworkBehaviour`] — Kademlia + Identify + Gossipsub + WorkspaceSync.

use libp2p::{
    gossipsub, identify, kad,
    request_response::{self, ProtocolSupport},
    PeerId, StreamProtocol,
};
use libp2p_swarm::NetworkBehaviour as NetworkBehaviourDerive;

use nexus_sync::client::SyncClient;
use nexus_sync::codec::SyncCodec;
use nexus_sync::message::{SyncRequest, SyncResponse};
use nexus_sync::{ANNOUNCE_TOPIC, SOCIAL_EVENT_TOPIC, SYNC_PROTOCOL};

// ---------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------

/// Unified event emitted by our composite behaviour.
#[derive(Debug)]
pub enum BehaviourEvent {
    Kad(kad::Event),
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
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub sync: request_response::Behaviour<SyncCodec>,
    pub identify: identify::Behaviour,
}

/// Unified event we convert to in `ToSwarm`.
#[derive(Debug)]
pub enum ToSwarm {
    Kad(kad::Event),
    Gossipsub(gossipsub::Event),
    Sync(request_response::Event<SyncRequest, SyncResponse>),
    Identify(identify::Event),
}

impl From<kad::Event> for ToSwarm {
    fn from(e: kad::Event) -> Self {
        Self::Kad(e)
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
    ) -> Result<Self, String> {
        let kademlia =
            kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));

        let gs_config = gossipsub::ConfigBuilder::default()
            .max_transmit_size(1_048_576)
            .heartbeat_interval(std::time::Duration::from_secs(10))
            .build()
            .map_err(|err| format!("gossipsub config: {err}"))?;
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(gossipsub_keypair),
            gs_config,
        )
        .map_err(|err| format!("gossipsub behaviour: {err}"))?;

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
            kademlia,
            gossipsub,
            sync,
            identify,
        })
    }
}
