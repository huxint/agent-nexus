//! Network — high-level wrapper around a libp2p [`Swarm`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    gossipsub, identify,
    kad::{self, QueryResult},
    request_response::{self, InboundRequestId, OutboundRequestId, ResponseChannel},
    swarm::SwarmEvent,
    Multiaddr, PeerId, SwarmBuilder, Transport,
};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{debug, info, warn};

use nexus_core::{NexusError, NexusResult};
use nexus_crypto::NodeIdentity;
use nexus_sync::client::{SyncReplySender, SyncRequestSender};
use nexus_sync::message::{SyncRequest, SyncResponse};
use nexus_sync::{ANNOUNCE_TOPIC, SOCIAL_EVENT_TOPIC};

use crate::behaviour::{CompositeBehaviour, ToSwarm};
use crate::transport;

// ---------------------------------------------------------------------------
// Config / Events
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub listen_addr: Multiaddr,
    pub bootstrap_peers: Vec<Multiaddr>,
    pub kademlia_mode: kad::Mode,
    pub bootstrap_interval: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),
            bootstrap_peers: Vec::new(),
            kademlia_mode: kad::Mode::Server,
            bootstrap_interval: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug)]
pub enum NetworkEvent {
    PeerDiscovered {
        peer_id: PeerId,
    },
    RoutingUpdated {
        peer_id: PeerId,
        is_new: bool,
    },
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    Listening(Multiaddr),
    WorkspaceAnnounce {
        source: Option<PeerId>,
        data: Vec<u8>,
    },
    SocialEvent {
        source: Option<PeerId>,
        data: Vec<u8>,
    },
    SyncRequest {
        peer: PeerId,
        request_id: InboundRequestId,
        request: SyncRequest,
    },
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

pub struct Network {
    local_peer_id: PeerId,
    cmd_tx: mpsc::UnboundedSender<NetworkCommand>,
    event_tx: broadcast::Sender<NetworkEvent>,
    sync_request_tx: SyncRequestSender,
    event_rx: broadcast::Receiver<NetworkEvent>,
    listen_addrs: Arc<Mutex<Vec<Multiaddr>>>,
}

impl Clone for Network {
    fn clone(&self) -> Self {
        Self {
            local_peer_id: self.local_peer_id,
            cmd_tx: self.cmd_tx.clone(),
            event_tx: self.event_tx.clone(),
            sync_request_tx: self.sync_request_tx.clone(),
            event_rx: self.event_tx.subscribe(),
            listen_addrs: Arc::clone(&self.listen_addrs),
        }
    }
}

enum NetworkCommand {
    Dial(Multiaddr),
    Publish {
        topic: GossipTopic,
        data: Vec<u8>,
        reply: oneshot::Sender<NexusResult<()>>,
    },
    SyncRespond {
        request_id: InboundRequestId,
        response: SyncResponse,
    },
}

#[derive(Clone, Copy, Debug)]
enum GossipTopic {
    WorkspaceAnnounce,
    SocialEvent,
}

impl GossipTopic {
    fn name(self) -> &'static str {
        match self {
            Self::WorkspaceAnnounce => ANNOUNCE_TOPIC,
            Self::SocialEvent => SOCIAL_EVENT_TOPIC,
        }
    }
}

impl Network {
    pub async fn new(node_identity: &NodeIdentity, config: NetworkConfig) -> NexusResult<Self> {
        let libp2p_keypair = transport::to_libp2p_keypair(node_identity);
        let local_peer_id = libp2p_keypair.public().to_peer_id();
        let gs_kp = libp2p_keypair.clone();

        let mut swarm = SwarmBuilder::with_existing_identity(libp2p_keypair.clone())
            .with_tokio()
            .with_other_transport(|keypair| {
                let qc = libp2p::quic::Config::new(keypair);
                libp2p::quic::tokio::Transport::new(qc)
                    .map(|(p, m), _| (p, libp2p::core::muxing::StreamMuxerBox::new(m)))
                    .boxed()
            })
            .expect("transport")
            .with_behaviour(|_key| {
                let mut b =
                    CompositeBehaviour::new(local_peer_id, libp2p_keypair.public(), gs_kp.clone());
                b.kademlia.set_mode(Some(config.kademlia_mode));
                b
            })
            .expect("behaviour")
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        swarm
            .listen_on(config.listen_addr.clone())
            .map_err(|e| nexus_core::NexusError::Network(format!("listen: {e}")))?;
        for addr in &config.bootstrap_peers {
            swarm
                .dial(addr.clone())
                .map_err(|e| nexus_core::NexusError::Network(format!("dial: {e}")))?;
        }

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = broadcast::channel(256);
        let (sync_request_tx, mut sync_request_rx) = mpsc::unbounded_channel();
        let listen_addrs = Arc::new(Mutex::new(Vec::new()));

        let mut pending_outbound: HashMap<OutboundRequestId, SyncReplySender> = HashMap::new();
        let mut pending_inbound: HashMap<InboundRequestId, ResponseChannel<SyncResponse>> =
            HashMap::new();

        let event_tx_clone = event_tx.clone();
        let listen_addrs_clone = Arc::clone(&listen_addrs);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(config.bootstrap_interval);
            loop {
                tokio::select! {
                    Some(cmd) = cmd_rx.recv() => match cmd {
                        NetworkCommand::Dial(a) => { let _ = swarm.dial(a); }
                        NetworkCommand::Publish { topic, data, reply } => {
                            let result = swarm
                                .behaviour_mut()
                                .gossipsub
                                .publish(gossipsub::IdentTopic::new(topic.name()), data)
                                .map(|_| ())
                                .map_err(|e| NexusError::Network(format!("publish {}: {e:?}", topic.name())));
                            if let Err(e) = &result { warn!("{e}"); }
                            let _ = reply.send(result);
                        }
                        NetworkCommand::SyncRespond { request_id, response } => {
                            if let Some(channel) = pending_inbound.remove(&request_id) {
                                if let Err(e) = swarm.behaviour_mut().sync.send_response(channel, response) {
                                    warn!("sync respond error: {e:?}");
                                }
                            }
                        }
                    },
                    Some((peer, request, reply_tx)) = sync_request_rx.recv() => {
                        let rid = swarm.behaviour_mut().sync.send_request(&peer, request);
                        pending_outbound.insert(rid, reply_tx);
                    }
                    Some(event) = swarm.next() => {
                        handle_swarm_event(event, &event_tx_clone, &listen_addrs_clone, &mut pending_outbound, &mut pending_inbound);
                    }
                    _ = tick.tick() => {
                        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() { warn!("kad: {e:?}"); }
                    }
                    else => break,
                }
            }
        });

        Ok(Self {
            local_peer_id,
            cmd_tx,
            event_tx,
            sync_request_tx,
            event_rx,
            listen_addrs,
        })
    }

    pub fn dial(&self, a: Multiaddr) {
        let _ = self.cmd_tx.send(NetworkCommand::Dial(a));
    }
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }
    pub fn listen_addrs(&self) -> Vec<Multiaddr> {
        self.listen_addrs
            .lock()
            .map(|addrs| addrs.clone())
            .unwrap_or_default()
    }
    pub async fn publish_announce(&self, d: Vec<u8>) -> NexusResult<()> {
        self.publish_gossip(GossipTopic::WorkspaceAnnounce, d).await
    }
    pub async fn publish_social_event(&self, d: Vec<u8>) -> NexusResult<()> {
        self.publish_gossip(GossipTopic::SocialEvent, d).await
    }
    pub fn sync_request_channel(&self) -> SyncRequestSender {
        self.sync_request_tx.clone()
    }
    pub async fn next_event(&mut self) -> Option<NetworkEvent> {
        match self.event_rx.recv().await {
            Ok(ev) => Some(ev),
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("event receiver lagged by {n} messages");
                self.event_rx = self.event_tx.subscribe();
                self.event_rx.recv().await.ok()
            }
            Err(_) => None,
        }
    }
    pub fn respond_to_sync(&self, request_id: InboundRequestId, response: SyncResponse) {
        let _ = self.cmd_tx.send(NetworkCommand::SyncRespond {
            request_id,
            response,
        });
    }

    async fn publish_gossip(&self, topic: GossipTopic, data: Vec<u8>) -> NexusResult<()> {
        let (reply, result) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCommand::Publish { topic, data, reply })
            .map_err(|_| NexusError::Network("network task stopped".into()))?;
        result
            .await
            .map_err(|_| NexusError::Network("network task dropped publish result".into()))?
    }
}

// ---------------------------------------------------------------------------
// Event handler
// ---------------------------------------------------------------------------

fn handle_swarm_event(
    event: SwarmEvent<ToSwarm>,
    event_tx: &broadcast::Sender<NetworkEvent>,
    listen_addrs: &Arc<Mutex<Vec<Multiaddr>>>,
    pending_out: &mut HashMap<OutboundRequestId, oneshot::Sender<Result<SyncResponse, String>>>,
    pending_in: &mut HashMap<InboundRequestId, ResponseChannel<SyncResponse>>,
) {
    match event {
        SwarmEvent::Behaviour(ToSwarm::Kad(kad::Event::RoutingUpdated {
            peer,
            is_new_peer,
            ..
        })) => {
            let _ = event_tx.send(NetworkEvent::RoutingUpdated {
                peer_id: peer,
                is_new: is_new_peer,
            });
        }
        SwarmEvent::Behaviour(ToSwarm::Kad(kad::Event::OutboundQueryProgressed {
            result: QueryResult::GetClosestPeers(Ok(kad::GetClosestPeersOk { peers, .. })),
            ..
        })) => {
            for info in peers {
                let _ = event_tx.send(NetworkEvent::PeerDiscovered {
                    peer_id: info.peer_id,
                });
            }
        }
        SwarmEvent::Behaviour(ToSwarm::Identify(identify::Event::Received { peer_id, .. })) => {
            let _ = event_tx.send(NetworkEvent::PeerDiscovered { peer_id });
        }
        SwarmEvent::Behaviour(ToSwarm::Gossipsub(gossipsub::Event::Message {
            message, ..
        })) => match message.topic.as_str() {
            ANNOUNCE_TOPIC => {
                let _ = event_tx.send(NetworkEvent::WorkspaceAnnounce {
                    source: message.source,
                    data: message.data,
                });
            }
            SOCIAL_EVENT_TOPIC => {
                let _ = event_tx.send(NetworkEvent::SocialEvent {
                    source: message.source,
                    data: message.data,
                });
            }
            _ => {}
        },
        SwarmEvent::Behaviour(ToSwarm::Sync(request_response::Event::Message {
            peer,
            message,
            ..
        })) => match message {
            request_response::Message::Request {
                request_id,
                request,
                channel,
                ..
            } => {
                pending_in.insert(request_id, channel);
                let _ = event_tx.send(NetworkEvent::SyncRequest {
                    peer,
                    request_id,
                    request,
                });
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(tx) = pending_out.remove(&request_id) {
                    let _ = tx.send(Ok(response));
                }
            }
        },
        SwarmEvent::Behaviour(ToSwarm::Sync(request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        })) => {
            warn!("sync outbound failure to {peer}: {error}");
            if let Some(tx) = pending_out.remove(&request_id) {
                let _ = tx.send(Err(error.to_string()));
            }
        }
        SwarmEvent::Behaviour(ToSwarm::Sync(request_response::Event::InboundFailure {
            peer,
            request_id,
            error,
            ..
        })) => {
            warn!("sync inbound failure from {peer}: {error}");
            pending_in.remove(&request_id);
        }
        SwarmEvent::Behaviour(ToSwarm::Sync(request_response::Event::ResponseSent {
            peer,
            request_id,
            ..
        })) => {
            debug!("sync response sent to {peer}: {request_id:?}");
        }
        SwarmEvent::NewListenAddr { address, .. } => {
            info!("Listening on {address}");
            if let Ok(mut addrs) = listen_addrs.lock() {
                if !addrs.contains(&address) {
                    addrs.push(address.clone());
                }
            }
            let _ = event_tx.send(NetworkEvent::Listening(address));
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            debug!("Connected to {peer_id}");
            let _ = event_tx.send(NetworkEvent::PeerConnected(peer_id));
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            debug!("Disconnected from {peer_id}");
            let _ = event_tx.send(NetworkEvent::PeerDisconnected(peer_id));
        }
        _ => {}
    }
}
