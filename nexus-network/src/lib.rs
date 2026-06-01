//! Nexus Network — P2P networking layer built on libp2p.
//!
//! ## Architecture
//!
//! ```text
//! Network
//!   └── Swarm<CompositeBehaviour>
//!         ├── Kademlia      (peer discovery via DHT)
//!         ├── mDNS          (zero-config LAN discovery)
//!         ├── Identify      (peer info exchange)
//!         ├── AutoNAT       (observed reachability)
//!         ├── DCUtR         (direct connection upgrade through relay)
//!         └── Relay client  (circuit relay fallback)
//! ```
//!
//! Transport: QUIC (TLS 1.3 encryption) plus relay circuit fallback for NATed peers.
//! Identity: Ed25519 keypair from `nexus_crypto::NodeIdentity`.

pub mod behaviour;
pub mod swarm;
pub mod transport;

pub use swarm::{
    global_discovery_key, workspace_discovery_key, Network, NetworkConfig, NetworkDiagnostics,
    NetworkEvent,
};
pub use transport::{to_libp2p_keypair, to_peer_id};
