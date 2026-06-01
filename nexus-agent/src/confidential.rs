//! Confidential social-event envelopes.

use nexus_core::Did;
use rand::RngCore;
use ring::{aead, hmac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::SocialEventKind;

const ENVELOPE_VERSION: u16 = 1;
const ENVELOPE_KEY_DOMAIN: &[u8] = b"nexus:confidential-social-envelope:key:v1";
const ENVELOPE_AAD_DOMAIN: &str = "nexus:confidential-social-envelope:aad:v1";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSocialEnvelope {
    pub version: u16,
    pub recipients: Vec<Did>,
    pub key_id: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfidentialEnvelopeError {
    #[error("confidential envelope has no recipients")]
    NoRecipients,

    #[error("shared secret must not be empty")]
    EmptySharedSecret,

    #[error("invalid nonce hex: {0}")]
    InvalidNonceHex(hex::FromHexError),

    #[error("invalid ciphertext hex: {0}")]
    InvalidCiphertextHex(hex::FromHexError),

    #[error("invalid nonce length: expected {expected} bytes, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    #[error("unsupported confidential envelope version {0}")]
    UnsupportedVersion(u16),

    #[error("recipient {0} is not listed in envelope recipients")]
    RecipientNotAllowed(Did),

    #[error("confidential envelope encryption failed")]
    EncryptionFailed,

    #[error("confidential envelope decryption failed")]
    DecryptionFailed,

    #[error("confidential envelope JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl EncryptedSocialEnvelope {
    pub fn encrypt(
        recipients: Vec<Did>,
        shared_secret: &[u8],
        payload: &SocialEventKind,
    ) -> Result<Self, ConfidentialEnvelopeError> {
        if recipients.is_empty() {
            return Err(ConfidentialEnvelopeError::NoRecipients);
        }
        if shared_secret.is_empty() {
            return Err(ConfidentialEnvelopeError::EmptySharedSecret);
        }

        let mut recipients = recipients;
        recipients.sort_by_key(|did| did.to_string());
        recipients.dedup();

        let key = envelope_key(shared_secret, &recipients);
        let key_id = envelope_key_id(&key, &recipients);
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut ciphertext = serde_json::to_vec(payload)?;
        aead_key(&key)
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                envelope_aad(&recipients, &key_id),
                &mut ciphertext,
            )
            .map_err(|_| ConfidentialEnvelopeError::EncryptionFailed)?;

        Ok(Self {
            version: ENVELOPE_VERSION,
            recipients,
            key_id,
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ciphertext),
        })
    }

    pub fn decrypt_for(
        &self,
        recipient: &Did,
        shared_secret: &[u8],
    ) -> Result<SocialEventKind, ConfidentialEnvelopeError> {
        self.validate_metadata()?;
        if shared_secret.is_empty() {
            return Err(ConfidentialEnvelopeError::EmptySharedSecret);
        }
        if !self.includes_recipient(recipient) {
            return Err(ConfidentialEnvelopeError::RecipientNotAllowed(
                recipient.clone(),
            ));
        }

        let key = envelope_key(shared_secret, &self.recipients);
        let key_id = envelope_key_id(&key, &self.recipients);
        if key_id != self.key_id {
            return Err(ConfidentialEnvelopeError::DecryptionFailed);
        }
        let nonce = nonce_from_hex(&self.nonce_hex)?;
        let mut ciphertext = hex::decode(&self.ciphertext_hex)
            .map_err(ConfidentialEnvelopeError::InvalidCiphertextHex)?;
        let plaintext = aead_key(&key)
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                envelope_aad(&self.recipients, &self.key_id),
                &mut ciphertext,
            )
            .map_err(|_| ConfidentialEnvelopeError::DecryptionFailed)?;
        Ok(serde_json::from_slice(plaintext)?)
    }

    pub fn validate_metadata(&self) -> Result<(), ConfidentialEnvelopeError> {
        if self.version != ENVELOPE_VERSION {
            return Err(ConfidentialEnvelopeError::UnsupportedVersion(self.version));
        }
        if self.recipients.is_empty() {
            return Err(ConfidentialEnvelopeError::NoRecipients);
        }
        let _ = nonce_from_hex(&self.nonce_hex)?;
        let _ = hex::decode(&self.ciphertext_hex)
            .map_err(ConfidentialEnvelopeError::InvalidCiphertextHex)?;
        Ok(())
    }

    pub fn includes_recipient(&self, recipient: &Did) -> bool {
        self.recipients
            .iter()
            .any(|candidate| candidate == recipient)
    }

    pub fn matches_shared_secret(
        &self,
        shared_secret: &[u8],
    ) -> Result<bool, ConfidentialEnvelopeError> {
        self.validate_metadata()?;
        if shared_secret.is_empty() {
            return Err(ConfidentialEnvelopeError::EmptySharedSecret);
        }
        let key = envelope_key(shared_secret, &self.recipients);
        Ok(envelope_key_id(&key, &self.recipients) == self.key_id)
    }
}

fn envelope_key(shared_secret: &[u8], recipients: &[Did]) -> [u8; KEY_LEN] {
    let mut context = Vec::new();
    for recipient in recipients {
        context.extend_from_slice(recipient.as_str().as_bytes());
        context.push(0);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, shared_secret);
    let tag = hmac::sign(&key, &[ENVELOPE_KEY_DOMAIN, &context].concat());
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

fn envelope_key_id(key: &[u8; KEY_LEN], recipients: &[Did]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus:confidential-social-envelope:key-id:v1");
    hasher.update(key);
    for recipient in recipients {
        hasher.update(recipient.as_str().as_bytes());
        hasher.update([0]);
    }
    hex::encode(&hasher.finalize()[..16])
}

fn envelope_aad(recipients: &[Did], key_id: &str) -> aead::Aad<Vec<u8>> {
    let mut aad = format!("{ENVELOPE_AAD_DOMAIN}:{key_id}:").into_bytes();
    for recipient in recipients {
        aad.extend_from_slice(recipient.as_str().as_bytes());
        aad.push(0);
    }
    aead::Aad::from(aad)
}

fn nonce_from_hex(hex_value: &str) -> Result<[u8; NONCE_LEN], ConfidentialEnvelopeError> {
    let bytes = hex::decode(hex_value).map_err(ConfidentialEnvelopeError::InvalidNonceHex)?;
    if bytes.len() != NONCE_LEN {
        return Err(ConfidentialEnvelopeError::InvalidNonceLength {
            expected: NONCE_LEN,
            actual: bytes.len(),
        });
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

fn aead_key(key: &[u8; KEY_LEN]) -> aead::LessSafeKey {
    let unbound =
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key).expect("valid envelope key length");
    aead::LessSafeKey::new(unbound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::society::RelationKind;

    fn did(name: &str) -> Did {
        Did::new(format!("did:key:{name}"))
    }

    #[test]
    fn encrypted_envelope_hides_and_recovers_social_payload() {
        let alice = did("alice");
        let bob = did("bob");
        let payload = SocialEventKind::RelationDeclared {
            peer: bob.clone(),
            relation: RelationKind::Collaborator,
            note: Some("private relation".into()),
        };

        let envelope =
            EncryptedSocialEnvelope::encrypt(vec![alice.clone(), bob.clone()], b"shared", &payload)
                .unwrap();

        assert!(!envelope.ciphertext_hex.contains("private relation"));
        match envelope.decrypt_for(&bob, b"shared").unwrap() {
            SocialEventKind::RelationDeclared {
                peer,
                relation,
                note,
            } => {
                assert_eq!(peer, bob);
                assert_eq!(relation, RelationKind::Collaborator);
                assert_eq!(note.as_deref(), Some("private relation"));
            }
            other => panic!("unexpected confidential payload: {other:?}"),
        }
        assert!(envelope.decrypt_for(&did("mallory"), b"shared").is_err());
        assert!(envelope.decrypt_for(&bob, b"wrong").is_err());
    }
}
