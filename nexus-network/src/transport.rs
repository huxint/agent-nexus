//! Transport construction — QUIC with TLS 1.3 encryption.

use libp2p::{core::transport, identity, quic, Transport};

use nexus_crypto::NodeIdentity;

/// Build a QUIC transport with the node's Ed25519 identity.
pub fn build_quic_transport(
    node_identity: &NodeIdentity,
) -> std::io::Result<transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)>> {
    let libp2p_keypair = to_libp2p_keypair(node_identity);

    let quic_config = quic::Config::new(&libp2p_keypair);
    let quic_transport = quic::tokio::Transport::new(quic_config);

    Ok(quic_transport
        .map(|(peer_id, muxer), _| (peer_id, libp2p::core::muxing::StreamMuxerBox::new(muxer)))
        .boxed())
}

/// Convert our Ed25519 `NodeIdentity` into a libp2p `Keypair`.
pub fn to_libp2p_keypair(node_identity: &NodeIdentity) -> identity::Keypair {
    // SigningKey::to_bytes() returns the 32-byte seed (SecretKey).
    // libp2p-identity's ed25519_from_bytes expects exactly the 32-byte seed.
    let secret_bytes = node_identity.signing_key().to_bytes();
    identity::Keypair::ed25519_from_bytes(secret_bytes).expect("valid Ed25519 keypair bytes")
}

/// Extract our PeerId from a NodeIdentity.
pub fn to_peer_id(node_identity: &NodeIdentity) -> libp2p::PeerId {
    let vk = node_identity.verifying_key();
    let public_key = identity::PublicKey::from(
        identity::ed25519::PublicKey::try_from_bytes(vk.as_bytes())
            .expect("valid ed25519 public key"),
    );
    public_key.to_peer_id()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_identity_to_libp2p_keypair() {
        let node = NodeIdentity::generate();
        let kp = to_libp2p_keypair(&node);
        let peer_id_1 = to_peer_id(&node);
        let peer_id_2 = kp.public().to_peer_id();
        assert_eq!(peer_id_1, peer_id_2);
    }

    #[test]
    fn build_transport_ok() {
        let node = NodeIdentity::generate();
        assert!(build_quic_transport(&node).is_ok());
    }
}
