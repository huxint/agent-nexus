//! Network — high-level wrapper around a libp2p [`Swarm`].

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    gossipsub, identify,
    kad::{self, QueryResult},
    multiaddr::Protocol,
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
    pub enable_mdns: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),
            bootstrap_peers: Vec::new(),
            kademlia_mode: kad::Mode::Server,
            bootstrap_interval: Duration::from_secs(30),
            enable_mdns: true,
        }
    }
}

#[derive(Clone, Debug)]
pub enum NetworkEvent {
    PeerDiscovered {
        peer_id: PeerId,
    },
    ProvidersFound {
        key: Vec<u8>,
        providers: Vec<PeerId>,
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
    connected_peers: Arc<Mutex<HashSet<PeerId>>>,
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
            connected_peers: Arc::clone(&self.connected_peers),
        }
    }
}

enum NetworkCommand {
    Dial(Multiaddr),
    DialPeer(PeerId),
    StartProviding(Vec<u8>),
    FindProviders(Vec<u8>),
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
        let enable_mdns = config.enable_mdns && !is_loopback_addr(&config.listen_addr);
        let mut behaviour = CompositeBehaviour::new(
            local_peer_id,
            libp2p_keypair.public(),
            gs_kp.clone(),
            enable_mdns,
        )
        .map_err(|err| NexusError::Network(format!("behaviour: {err}")))?;
        behaviour.kademlia.set_mode(Some(config.kademlia_mode));

        let mut swarm = SwarmBuilder::with_existing_identity(libp2p_keypair.clone())
            .with_tokio()
            .with_other_transport(|keypair| {
                let qc = libp2p::quic::Config::new(keypair);
                libp2p::quic::tokio::Transport::new(qc)
                    .map(|(p, m), _| (p, libp2p::core::muxing::StreamMuxerBox::new(m)))
                    .boxed()
            })
            .map_err(|err| NexusError::Network(format!("transport: {err}")))?
            .with_dns()
            .map_err(|err| NexusError::Network(format!("dns transport: {err}")))?
            .with_behaviour(|_key| behaviour)
            .map_err(|err| NexusError::Network(format!("behaviour: {err}")))?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        swarm
            .listen_on(config.listen_addr.clone())
            .map_err(|e| nexus_core::NexusError::Network(format!("listen: {e}")))?;
        for addr in &config.bootstrap_peers {
            if let Some((peer, kad_addr)) = peer_and_kad_addr(addr) {
                behaviour_add_address(swarm.behaviour_mut(), &peer, kad_addr);
            }
            if let Err(err) = swarm.dial(addr.clone()) {
                warn!("failed to dial bootstrap peer {addr}: {err}");
            }
        }

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = broadcast::channel(256);
        let (sync_request_tx, mut sync_request_rx) = mpsc::unbounded_channel();
        let listen_addrs = Arc::new(Mutex::new(Vec::new()));
        let connected_peers = Arc::new(Mutex::new(HashSet::new()));

        let mut pending_outbound: HashMap<OutboundRequestId, SyncReplySender> = HashMap::new();
        let mut pending_inbound: HashMap<InboundRequestId, ResponseChannel<SyncResponse>> =
            HashMap::new();

        let event_tx_clone = event_tx.clone();
        let listen_addrs_clone = Arc::clone(&listen_addrs);
        let connected_peers_clone = Arc::clone(&connected_peers);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(config.bootstrap_interval);
            loop {
                tokio::select! {
                    Some(cmd) = cmd_rx.recv() => match cmd {
                        NetworkCommand::Dial(a) => { let _ = swarm.dial(a); }
                        NetworkCommand::DialPeer(peer) => { let _ = swarm.dial(peer); }
                        NetworkCommand::StartProviding(key) => {
                            match swarm.behaviour_mut().kademlia.start_providing(kad::RecordKey::new(&key)) {
                                Ok(_) => debug!("started provider announcement for {}", discovery_key_label(&key)),
                                Err(err) => warn!("failed to start provider announcement for {}: {err}", discovery_key_label(&key)),
                            }
                        }
                        NetworkCommand::FindProviders(key) => {
                            let label = discovery_key_label(&key);
                            swarm.behaviour_mut().kademlia.get_providers(kad::RecordKey::new(&key));
                            debug!("started provider lookup for {label}");
                        }
                        NetworkCommand::Publish { topic, data, reply } => {
                            let result = match swarm
                                .behaviour_mut()
                                .gossipsub
                                .publish(gossipsub::IdentTopic::new(topic.name()), data)
                            {
                                Ok(_) => Ok(()),
                                Err(err) => {
                                    let result = NexusError::Network(format!(
                                        "publish {}: {err:?}",
                                        topic.name()
                                    ));
                                    match err {
                                        gossipsub::PublishError::InsufficientPeers => {
                                            debug!("{result}");
                                        }
                                        _ => warn!("{result}"),
                                    }
                                    Err(result)
                                }
                            };
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
                        handle_swarm_event(
                            event,
                            &event_tx_clone,
                            &listen_addrs_clone,
                            &connected_peers_clone,
                            &mut pending_outbound,
                            &mut pending_inbound,
                            &mut swarm,
                        );
                    }
                    _ = tick.tick() => {
                        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                            debug!("kad bootstrap skipped: {e:?}");
                        }
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
            connected_peers,
        })
    }

    pub fn dial(&self, a: Multiaddr) {
        let _ = self.cmd_tx.send(NetworkCommand::Dial(a));
    }
    pub fn dial_peer(&self, peer: PeerId) {
        let _ = self.cmd_tx.send(NetworkCommand::DialPeer(peer));
    }
    pub fn start_providing(&self, key: Vec<u8>) -> NexusResult<()> {
        self.cmd_tx
            .send(NetworkCommand::StartProviding(key))
            .map_err(|_| NexusError::Network("network task stopped".into()))
    }
    pub fn find_providers(&self, key: Vec<u8>) -> NexusResult<()> {
        self.cmd_tx
            .send(NetworkCommand::FindProviders(key))
            .map_err(|_| NexusError::Network("network task stopped".into()))
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
    pub fn is_connected(&self, peer: PeerId) -> bool {
        self.connected_peers
            .lock()
            .map(|peers| peers.contains(&peer))
            .unwrap_or(false)
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

pub fn global_discovery_key() -> Vec<u8> {
    b"/nexus/global/1".to_vec()
}

pub fn workspace_discovery_key(workspace_id: &nexus_core::WorkspaceId) -> Vec<u8> {
    format!("/nexus/workspace/1/{workspace_id}").into_bytes()
}

// ---------------------------------------------------------------------------
// Event handler
// ---------------------------------------------------------------------------

fn handle_swarm_event(
    event: SwarmEvent<ToSwarm>,
    event_tx: &broadcast::Sender<NetworkEvent>,
    listen_addrs: &Arc<Mutex<Vec<Multiaddr>>>,
    connected_peers: &Arc<Mutex<HashSet<PeerId>>>,
    pending_out: &mut HashMap<OutboundRequestId, oneshot::Sender<Result<SyncResponse, String>>>,
    pending_in: &mut HashMap<InboundRequestId, ResponseChannel<SyncResponse>>,
    swarm: &mut libp2p::Swarm<CompositeBehaviour>,
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
        SwarmEvent::Behaviour(ToSwarm::Kad(kad::Event::OutboundQueryProgressed {
            result:
                QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { key, providers })),
            ..
        })) => {
            let mut providers = providers.into_iter().collect::<Vec<_>>();
            providers.sort();
            providers.dedup();
            for peer in &providers {
                if peer != swarm.local_peer_id() {
                    let _ = swarm.dial(*peer);
                }
                let _ = event_tx.send(NetworkEvent::PeerDiscovered { peer_id: *peer });
            }
            let _ = event_tx.send(NetworkEvent::ProvidersFound {
                key: key.to_vec(),
                providers,
            });
        }
        SwarmEvent::Behaviour(ToSwarm::Kad(kad::Event::OutboundQueryProgressed {
            result: QueryResult::GetProviders(Err(err)),
            ..
        })) => {
            debug!(
                "provider lookup failed for {}: {err}",
                discovery_key_label(err.key().as_ref())
            );
        }
        SwarmEvent::Behaviour(ToSwarm::Kad(kad::Event::OutboundQueryProgressed {
            result: QueryResult::StartProviding(Ok(ok)),
            ..
        })) => {
            debug!(
                "provider announcement published for {}",
                discovery_key_label(ok.key.as_ref())
            );
        }
        SwarmEvent::Behaviour(ToSwarm::Kad(kad::Event::OutboundQueryProgressed {
            result: QueryResult::StartProviding(Err(err)),
            ..
        })) => {
            debug!(
                "provider announcement failed for {}: {err}",
                discovery_key_label(err.key().as_ref())
            );
        }
        SwarmEvent::Behaviour(ToSwarm::Mdns(libp2p::mdns::Event::Discovered(peers))) => {
            for (peer, addr) in peers {
                if peer == *swarm.local_peer_id() {
                    continue;
                }
                debug!("mDNS discovered {peer} at {addr}");
                behaviour_add_address(swarm.behaviour_mut(), &peer, addr.clone());
                let _ = swarm.dial(addr.with(Protocol::P2p(peer)));
                let _ = event_tx.send(NetworkEvent::PeerDiscovered { peer_id: peer });
            }
        }
        SwarmEvent::Behaviour(ToSwarm::Mdns(libp2p::mdns::Event::Expired(peers))) => {
            for (peer, addr) in peers {
                debug!("mDNS expired {peer} at {addr}");
            }
        }
        SwarmEvent::Behaviour(ToSwarm::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            for addr in info.listen_addrs {
                behaviour_add_address(swarm.behaviour_mut(), &peer_id, addr);
            }
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
            debug!("sync outbound failure to {peer}: {error}");
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
        SwarmEvent::ExternalAddrConfirmed { address } => {
            info!("External address confirmed: {address}");
            if let Ok(mut addrs) = listen_addrs.lock() {
                if !addrs.contains(&address) {
                    addrs.push(address);
                }
            }
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            debug!("Connected to {peer_id}");
            if let Ok(mut peers) = connected_peers.lock() {
                peers.insert(peer_id);
            }
            let _ = event_tx.send(NetworkEvent::PeerConnected(peer_id));
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            ..
        } => {
            debug!("Disconnected from {peer_id}");
            if num_established == 0 {
                if let Ok(mut peers) = connected_peers.lock() {
                    peers.remove(&peer_id);
                }
            }
            let _ = event_tx.send(NetworkEvent::PeerDisconnected(peer_id));
        }
        _ => {}
    }
}

fn peer_and_kad_addr(addr: &Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut addr = addr.clone();
    match addr.pop() {
        Some(Protocol::P2p(peer)) => Some((peer, addr)),
        _ => None,
    }
}

fn is_loopback_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|protocol| match protocol {
        Protocol::Ip4(ip) => ip.is_loopback(),
        Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

fn behaviour_add_address(behaviour: &mut CompositeBehaviour, peer: &PeerId, addr: Multiaddr) {
    let _ = behaviour.kademlia.add_address(peer, addr);
}

fn discovery_key_label(key: &[u8]) -> String {
    String::from_utf8_lossy(key).into_owned()
}
