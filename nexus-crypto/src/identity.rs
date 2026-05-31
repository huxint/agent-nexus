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
use ring::{aead, pbkdf2};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::path::Path;

use crate::did::{derive_did, parse_did, DidError};

const IDENTITY_FILE_VERSION: u32 = 1;
const IDENTITY_KEY_SCHEME: &str = "nexus-identity-key-v1";
const IDENTITY_KDF: &str = "pbkdf2-sha256";
const IDENTITY_CIPHER: &str = "chacha20-poly1305";
const IDENTITY_KDF_ITERATIONS: u32 = 210_000;
const IDENTITY_SEED_LEN: usize = 32;
const IDENTITY_SALT_LEN: usize = 16;
const IDENTITY_NONCE_LEN: usize = 12;

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

/// Errors during encrypted identity persistence.
#[derive(Debug, thiserror::Error)]
pub enum IdentityStorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("identity JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("identity hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("NEXUS_PASSPHRASE is required to encrypt or decrypt node identity")]
    MissingPassphrase,

    #[error("identity passphrase cannot be empty")]
    EmptyPassphrase,

    #[error("identity file is missing encrypted key material")]
    MissingKeyMaterial,

    #[error("unsupported identity file version {0}")]
    UnsupportedVersion(u32),

    #[error("unsupported identity key scheme {0}")]
    UnsupportedKeyScheme(String),

    #[error("unsupported identity KDF {0}")]
    UnsupportedKdf(String),

    #[error("unsupported identity cipher {0}")]
    UnsupportedCipher(String),

    #[error("invalid {field} length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("identity KDF iterations must be greater than zero")]
    InvalidKdfIterations,

    #[error("identity encryption failed")]
    EncryptionFailed,

    #[error("identity decryption failed")]
    DecryptionFailed,

    #[error("stored DID {stored} does not match decrypted identity {actual}")]
    DidMismatch { stored: String, actual: String },
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredIdentityFile {
    #[serde(default)]
    version: u32,
    did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<EncryptedIdentityKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seed_hex: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedIdentityKey {
    scheme: String,
    kdf: String,
    iterations: u32,
    salt_hex: String,
    cipher: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

/// A node's cryptographic identity.
///
/// The signing key is held in memory and persisted only through the encrypted
/// identity file helpers below.
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

    /// Save identity to an encrypted JSON file using `NEXUS_PASSPHRASE`.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), IdentityStorageError> {
        let passphrase = identity_passphrase_from_env()?;
        self.save_to_file_with_passphrase(path, &passphrase)
    }

    /// Save identity to an encrypted JSON file.
    pub fn save_to_file_with_passphrase(
        &self,
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<(), IdentityStorageError> {
        let encrypted = encrypt_seed(self.to_seed_bytes(), self.did().as_str(), passphrase)?;
        let stored = StoredIdentityFile {
            version: IDENTITY_FILE_VERSION,
            did: self.did().to_string(),
            key: Some(encrypted),
            seed_hex: None,
        };
        write_identity_file(path.as_ref(), &stored)
    }

    /// Load identity from an encrypted JSON file using `NEXUS_PASSPHRASE`.
    ///
    /// Legacy plaintext `seed_hex` files are migrated in-place after the
    /// passphrase is supplied.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, IdentityStorageError> {
        let passphrase = identity_passphrase_from_env()?;
        Self::load_from_file_with_passphrase(path, &passphrase)
    }

    /// Load identity from an encrypted JSON file.
    ///
    /// Legacy plaintext `seed_hex` files are migrated in-place after the
    /// passphrase is supplied.
    pub fn load_from_file_with_passphrase(
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<Self, IdentityStorageError> {
        ensure_passphrase(passphrase)?;
        let path = path.as_ref();
        let data = std::fs::read_to_string(path)?;
        let stored: StoredIdentityFile = serde_json::from_str(&data)?;

        if let Some(encrypted) = stored.key.as_ref() {
            if stored.version != IDENTITY_FILE_VERSION {
                return Err(IdentityStorageError::UnsupportedVersion(stored.version));
            }
            let seed = decrypt_seed(encrypted, &stored.did, passphrase)?;
            let identity = Self::from_seed_bytes(&seed);
            identity.ensure_stored_did(&stored.did)?;
            return Ok(identity);
        }

        if let Some(seed_hex) = stored.seed_hex.as_deref() {
            let seed = decode_hex_array::<IDENTITY_SEED_LEN>("seed_hex", seed_hex)?;
            let identity = Self::from_seed_bytes(&seed);
            identity.ensure_stored_did(&stored.did)?;
            identity.save_to_file_with_passphrase(path, passphrase)?;
            return Ok(identity);
        }

        Err(IdentityStorageError::MissingKeyMaterial)
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

impl NodeIdentity {
    fn ensure_stored_did(&self, stored: &str) -> Result<(), IdentityStorageError> {
        let actual = self.did().to_string();
        if stored == actual {
            Ok(())
        } else {
            Err(IdentityStorageError::DidMismatch {
                stored: stored.to_string(),
                actual,
            })
        }
    }
}

fn identity_passphrase_from_env() -> Result<String, IdentityStorageError> {
    let passphrase =
        std::env::var("NEXUS_PASSPHRASE").map_err(|_| IdentityStorageError::MissingPassphrase)?;
    ensure_passphrase(&passphrase)?;
    Ok(passphrase)
}

fn ensure_passphrase(passphrase: &str) -> Result<(), IdentityStorageError> {
    if passphrase.is_empty() {
        Err(IdentityStorageError::EmptyPassphrase)
    } else {
        Ok(())
    }
}

fn encrypt_seed(
    seed: [u8; IDENTITY_SEED_LEN],
    did: &str,
    passphrase: &str,
) -> Result<EncryptedIdentityKey, IdentityStorageError> {
    ensure_passphrase(passphrase)?;
    let mut salt = [0u8; IDENTITY_SALT_LEN];
    let mut nonce = [0u8; IDENTITY_NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key_bytes = derive_identity_key(passphrase.as_bytes(), &salt, IDENTITY_KDF_ITERATIONS)?;
    let key = aead_key(&key_bytes)?;
    let mut ciphertext = seed.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        identity_aad(did),
        &mut ciphertext,
    )
    .map_err(|_| IdentityStorageError::EncryptionFailed)?;

    Ok(EncryptedIdentityKey {
        scheme: IDENTITY_KEY_SCHEME.into(),
        kdf: IDENTITY_KDF.into(),
        iterations: IDENTITY_KDF_ITERATIONS,
        salt_hex: hex::encode(salt),
        cipher: IDENTITY_CIPHER.into(),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

fn decrypt_seed(
    encrypted: &EncryptedIdentityKey,
    did: &str,
    passphrase: &str,
) -> Result<[u8; IDENTITY_SEED_LEN], IdentityStorageError> {
    ensure_passphrase(passphrase)?;
    if encrypted.scheme != IDENTITY_KEY_SCHEME {
        return Err(IdentityStorageError::UnsupportedKeyScheme(
            encrypted.scheme.clone(),
        ));
    }
    if encrypted.kdf != IDENTITY_KDF {
        return Err(IdentityStorageError::UnsupportedKdf(encrypted.kdf.clone()));
    }
    if encrypted.cipher != IDENTITY_CIPHER {
        return Err(IdentityStorageError::UnsupportedCipher(
            encrypted.cipher.clone(),
        ));
    }

    let salt = decode_hex_array::<IDENTITY_SALT_LEN>("salt_hex", &encrypted.salt_hex)?;
    let nonce = decode_hex_array::<IDENTITY_NONCE_LEN>("nonce_hex", &encrypted.nonce_hex)?;
    let key_bytes = derive_identity_key(passphrase.as_bytes(), &salt, encrypted.iterations)?;
    let key = aead_key(&key_bytes)?;
    let mut ciphertext = hex::decode(&encrypted.ciphertext_hex)?;
    let seed = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            identity_aad(did),
            &mut ciphertext,
        )
        .map_err(|_| IdentityStorageError::DecryptionFailed)?;

    if seed.len() != IDENTITY_SEED_LEN {
        return Err(IdentityStorageError::InvalidLength {
            field: "seed",
            expected: IDENTITY_SEED_LEN,
            actual: seed.len(),
        });
    }
    let mut seed_bytes = [0u8; IDENTITY_SEED_LEN];
    seed_bytes.copy_from_slice(seed);
    Ok(seed_bytes)
}

fn derive_identity_key(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; 32], IdentityStorageError> {
    let iterations =
        NonZeroU32::new(iterations).ok_or(IdentityStorageError::InvalidKdfIterations)?;
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        passphrase,
        &mut key,
    );
    Ok(key)
}

fn aead_key(key_bytes: &[u8; 32]) -> Result<aead::LessSafeKey, IdentityStorageError> {
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key_bytes)
        .map_err(|_| IdentityStorageError::EncryptionFailed)?;
    Ok(aead::LessSafeKey::new(unbound))
}

fn identity_aad(did: &str) -> aead::Aad<Vec<u8>> {
    aead::Aad::from(format!("{IDENTITY_KEY_SCHEME}:{did}").into_bytes())
}

fn decode_hex_array<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], IdentityStorageError> {
    let bytes = hex::decode(value)?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_| IdentityStorageError::InvalidLength {
            field,
            expected: N,
            actual,
        })
}

fn write_identity_file(
    path: &Path,
    stored: &StoredIdentityFile,
) -> Result<(), IdentityStorageError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(stored)?;
    std::fs::write(path, data)?;
    set_private_file_permissions(path)?;
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> Result<(), IdentityStorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
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
        id.save_to_file_with_passphrase(&tmp, "test-passphrase")
            .expect("save");
        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&tmp).unwrap()).unwrap();
        assert!(file.get("seed_hex").is_none());
        assert_eq!(file["key"]["kdf"], "pbkdf2-sha256");

        let loaded =
            NodeIdentity::load_from_file_with_passphrase(&tmp, "test-passphrase").expect("load");
        assert_eq!(id.did(), loaded.did());
        assert_eq!(id.to_seed_bytes(), loaded.to_seed_bytes());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn legacy_plaintext_identity_is_migrated_on_load() {
        let id = NodeIdentity::generate();
        let tmp = std::env::temp_dir().join("nexus-test-identity-legacy.json");
        let legacy = serde_json::json!({
            "did": id.did().to_string(),
            "seed_hex": hex::encode(id.to_seed_bytes()),
        });
        std::fs::write(&tmp, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();

        let loaded =
            NodeIdentity::load_from_file_with_passphrase(&tmp, "test-passphrase").expect("load");
        assert_eq!(id.did(), loaded.did());

        let migrated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&tmp).unwrap()).unwrap();
        assert!(migrated.get("seed_hex").is_none());
        assert!(migrated.get("key").is_some());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn wrong_identity_passphrase_is_rejected() {
        let id = NodeIdentity::generate();
        let tmp = std::env::temp_dir().join("nexus-test-identity-wrong-passphrase.json");
        id.save_to_file_with_passphrase(&tmp, "test-passphrase")
            .expect("save");

        let err = match NodeIdentity::load_from_file_with_passphrase(&tmp, "wrong-passphrase") {
            Ok(_) => panic!("wrong passphrase must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, IdentityStorageError::DecryptionFailed));
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
