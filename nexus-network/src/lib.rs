//! Nexus Network — P2P networking layer built on libp2p.
//!
//! ## Architecture
//!
//! ```text
//! Network
//!   └── Swarm<CompositeBehaviour>
//!         ├── Kademlia      (peer discovery via DHT)
//!         └── Identify      (peer info exchange)
//! ```
//!
//! Transport: QUIC (TLS 1.3 encryption).
//! Identity: Ed25519 keypair from `nexus_crypto::NodeIdentity`.

pub mod behaviour;
pub mod swarm;
pub mod transport;

pub use swarm::{Network, NetworkConfig, NetworkEvent};
pub use transport::{to_libp2p_keypair, to_peer_id};
