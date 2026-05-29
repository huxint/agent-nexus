//! Node identity: Ed25519 keypair + DID derivation.
//!
//! Every node in the network generates a single long-lived Ed25519 keypair
//! on first launch.  The `Did` is derived from the public key, and the
//! signing key is used to author capability tokens and sign workspace
//! operations.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use nexus_core::Did;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::did::{derive_did, parse_did, DidError};

/// Errors during detached DID signature verification.
#[derive(Debug, thiserror::Error)]
pub enum IdentitySignatureError {
    #[error("invalid signer DID: {0}")]
    InvalidDid(#[from] DidError),

    #[error("invalid signer verifying key: {0}")]
    InvalidVerifyingKey(ed25519_dalek::SignatureError),

    #[error("invalid Ed25519 signature bytes")]
    InvalidSignatureBytes,

    #[error("signature verification failed")]
    VerificationFailed,
}

/// A node's cryptographic identity.
///
/// The signing key is held in memory and **never** serialised to disk
/// in plaintext by this crate.  Persistence is the caller's responsibility
/// (e.g. encrypt with a passphrase-derived key, use OS keychain, etc.).
pub struct NodeIdentity {
    signing_key: SigningKey,
    did: Did,
}

impl NodeIdentity {
    /// Generate a fresh identity from OS randomness.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        // SecretKey is a type alias for [u8; 32] in ed25519-dalek 2.x
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let did_str = derive_did(&verifying_key);
        let did = Did::new(did_str);

        Self { signing_key, did }
    }

    /// Build from an existing [`SigningKey`].
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let did_str = derive_did(&verifying_key);
        let did = Did::new(did_str);

        Self { signing_key, did }
    }

    /// The self-sovereign DID for this node.
    pub fn did(&self) -> &Did {
        &self.did
    }

    /// The Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// The Ed25519 signing (private) key — handle with care.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Serialise the signing key to a 32-byte seed for storage.
    pub fn to_seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Reconstruct identity from a 32-byte seed.
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self::from_signing_key(signing_key)
    }

    /// Save identity to a JSON file.
    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), std::io::Error> {
        let json = serde_json::json!({
            "did": self.did().to_string(),
            "seed_hex": hex::encode(self.to_seed_bytes()),
        });
        let data = serde_json::to_string_pretty(&json)?;
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, data)
    }

    /// Load identity from a JSON file.
    pub fn load_from_file(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let data = std::fs::read_to_string(path)?;
        let json: serde_json::Value = serde_json::from_str(&data)?;
        let seed_hex = json["seed_hex"].as_str().ok_or("missing seed_hex")?;
        let seed_bytes: [u8; 32] = hex::decode(seed_hex)?
            .try_into()
            .map_err(|_| "invalid seed length")?;
        Ok(Self::from_seed_bytes(&seed_bytes))
    }

    /// Sign an arbitrary message with this identity's key.
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message)
    }

    /// Verify a signature purportedly made by the given verifying key.
    pub fn verify(
        verifying_key: &VerifyingKey,
        message: &[u8],
        signature: &ed25519_dalek::Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        use ed25519_dalek::Verifier;
        verifying_key.verify(message, signature)
    }
}

/// Verify a detached Ed25519 signature against a `did:key` signer.
pub fn verify_did_signature(
    did: &Did,
    message: &[u8],
    signature: &[u8],
) -> Result<(), IdentitySignatureError> {
    let signature = Signature::from_slice(signature)
        .map_err(|_| IdentitySignatureError::InvalidSignatureBytes)?;
    let key_bytes = parse_did(did.as_str())?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(IdentitySignatureError::InvalidVerifyingKey)?;

    NodeIdentity::verify(&verifying_key, message, &signature)
        .map_err(|_| IdentitySignatureError::VerificationFailed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn generate_creates_valid_did() {
        let id = NodeIdentity::generate();
        let did = id.did().to_string();
        assert!(did.starts_with("did:key:z"), "got: {did}");
    }

    #[test]
    fn deterministic_did_from_signing_key() {
        let id1 = NodeIdentity::generate();
        let sk_bytes = id1.signing_key().to_bytes();

        // Reconstruct from the same key bytes
        let sk2 = SigningKey::from_bytes(&sk_bytes);
        let id2 = NodeIdentity::from_signing_key(sk2);

        assert_eq!(id1.did(), id2.did());
        assert_eq!(id1.verifying_key(), id2.verifying_key());
    }

    #[test]
    fn save_and_load_identity() {
        let id = NodeIdentity::generate();
        let tmp = std::env::temp_dir().join("nexus-test-identity.json");
        id.save_to_file(&tmp).expect("save");
        let loaded = NodeIdentity::load_from_file(&tmp).expect("load");
        assert_eq!(id.did(), loaded.did());
        assert_eq!(id.to_seed_bytes(), loaded.to_seed_bytes());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn sign_and_verify() {
        let id = NodeIdentity::generate();
        let msg = b"hello nexus";

        let sig = id.sign(msg);
        let vk = id.verifying_key();

        vk.verify(msg, &sig).expect("signature must verify");

        // Tampered message must fail
        let bad = vk.verify(b"hello nexsus", &sig);
        assert!(bad.is_err());
    }

    #[test]
    fn verify_did_signature_checks_message_and_signature() {
        let id = NodeIdentity::generate();
        let msg = b"detached claim";
        let signature = id.sign(msg).to_bytes();

        verify_did_signature(id.did(), msg, &signature).unwrap();
        assert!(verify_did_signature(id.did(), b"tampered claim", &signature).is_err());

        let mut tampered_signature = signature;
        tampered_signature[0] ^= 0xff;
        assert!(verify_did_signature(id.did(), msg, &tampered_signature).is_err());
    }
}
