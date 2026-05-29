//! DID derivation and parsing (`did:key` method).
//!
//! Format: `did:key:z<base58btc(multicodec || raw-pubkey)>`
//!
//! The multicodec prefix for Ed25519 public keys is the varint `0xed01`.

use ed25519_dalek::VerifyingKey;
// sha2 is available for future hash-based DIDs but unused for now

/// Errors during DID operations.
#[derive(Debug, thiserror::Error)]
pub enum DidError {
    #[error("invalid did prefix: expected 'did:key:', got '{0}'")]
    InvalidPrefix(String),

    #[error("unsupported multibase encoding: {0}")]
    UnsupportedEncoding(char),

    #[error("unsupported multicodec: expected ed25519-pub (0xed01)")]
    UnsupportedMulticodec,

    #[error("invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("base58 decode error: {0}")]
    Base58Decode(String),

    #[error("base58 encode error: {0}")]
    Base58Encode(String),
}

// ---------------------------------------------------------------------------
// Multicodec / multibase constants
// ---------------------------------------------------------------------------

/// Multicodec prefix for Ed25519 public key: varint encoding of 0xed01.
/// See <https://github.com/multiformats/multicodec/blob/master/table.csv>
const ED25519_PUB_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Multibase prefix for base58btc.
const BASE58BTC_PREFIX: char = 'z';

/// The DID method prefix.
const DID_KEY_PREFIX: &str = "did:key:";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Derive a `did:key` identifier from an Ed25519 verifying (public) key.
///
/// ```
/// use nexus_crypto::NodeIdentity;
/// use nexus_crypto::did::derive_did;
///
/// let identity = NodeIdentity::generate();
/// let vk = identity.verifying_key();
/// let did_str = derive_did(&vk);
/// assert!(did_str.starts_with("did:key:z"));
/// ```
pub fn derive_did(verifying_key: &VerifyingKey) -> String {
    let raw_pubkey = verifying_key.as_bytes(); // 32 bytes

    // Concatenate multicodec prefix + raw key bytes
    let mut buf = Vec::with_capacity(ED25519_PUB_MULTICODEC.len() + raw_pubkey.len());
    buf.extend_from_slice(&ED25519_PUB_MULTICODEC);
    buf.extend_from_slice(raw_pubkey);

    // Base58btc encode
    let encoded = bs58_encode(&buf);

    format!("{DID_KEY_PREFIX}{BASE58BTC_PREFIX}{encoded}")
}

/// Parse a `did:key` string back into raw Ed25519 public key bytes (32 bytes).
///
/// Returns an error if the DID is malformed, uses an unsupported encoding,
/// or encodes a non-Ed25519 key type.
pub fn parse_did(did: &str) -> Result<[u8; 32], DidError> {
    // Strip prefix
    let remainder = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or_else(|| DidError::InvalidPrefix(did.to_string()))?;

    // Check multibase prefix
    let first_char = remainder.chars().next().unwrap_or('\0');
    if first_char != BASE58BTC_PREFIX {
        return Err(DidError::UnsupportedEncoding(first_char));
    }

    let encoded = &remainder[1..];

    // Base58btc decode
    let decoded = bs58_decode(encoded).map_err(DidError::Base58Decode)?;

    // Check multicodec prefix
    if decoded.len() < ED25519_PUB_MULTICODEC.len() + 32 {
        return Err(DidError::InvalidKeyLength(
            decoded.len().saturating_sub(ED25519_PUB_MULTICODEC.len()),
        ));
    }
    if decoded[..2] != ED25519_PUB_MULTICODEC {
        return Err(DidError::UnsupportedMulticodec);
    }

    // Extract raw 32-byte key
    let raw: [u8; 32] = decoded[2..34]
        .try_into()
        .map_err(|_| DidError::InvalidKeyLength(decoded.len() - 2))?;

    Ok(raw)
}

// ---------------------------------------------------------------------------
// Base58btc (Bitcoin alphabet) — minimal impl
// ---------------------------------------------------------------------------

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn bs58_encode(data: &[u8]) -> String {
    // Count leading zeros
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert big-endian bytes to base58 digits
    let mut digits = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for d in &mut digits {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    // Add leading zeros back
    digits.extend(std::iter::repeat_n(0, leading_zeros));

    digits.reverse();

    digits
        .iter()
        .map(|&d| BASE58_ALPHABET[d as usize] as char)
        .collect()
}

fn bs58_decode(encoded: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for ch in encoded.chars() {
        let pos = BASE58_ALPHABET
            .iter()
            .position(|&c| c == ch as u8)
            .ok_or_else(|| format!("invalid base58 character: '{ch}'"))?;

        let mut carry = pos as u32;
        for b in &mut bytes {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    // Handle leading zeros (base58 '1' = 0)
    for ch in encoded.chars() {
        if ch == '1' {
            bytes.push(0);
        } else {
            break;
        }
    }

    bytes.reverse();
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;

    #[test]
    fn derive_and_parse_roundtrip() {
        let id = NodeIdentity::generate();
        let vk = id.verifying_key();
        let did_str = derive_did(&vk);

        assert!(did_str.starts_with("did:key:z"), "got: {did_str}");

        let parsed = parse_did(&did_str).expect("parse_did failed");
        assert_eq!(parsed, id.verifying_key().as_bytes().to_owned());
    }

    #[test]
    fn parse_invalid_prefix() {
        let err = parse_did("did:web:example.com").unwrap_err();
        assert!(matches!(err, DidError::InvalidPrefix(_)));
    }

    #[test]
    fn parse_wrong_encoding() {
        let err = parse_did("did:key:xdeadbeef").unwrap_err();
        assert!(matches!(err, DidError::UnsupportedEncoding('x')));
    }

    #[test]
    fn parse_garbage_data() {
        let err = parse_did("did:key:z1234").unwrap_err();
        assert!(
            matches!(err, DidError::Base58Decode(_)) | matches!(err, DidError::InvalidKeyLength(_))
        );
    }

    #[test]
    fn bs58_roundtrip() {
        let data = b"hello world";
        let encoded = bs58_encode(data);
        let decoded = bs58_decode(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }

    #[test]
    fn bs58_leading_zeros() {
        let data = [0u8, 0u8, 1u8];
        let encoded = bs58_encode(&data);
        assert!(encoded.starts_with("11"));
        let decoded = bs58_decode(&encoded).unwrap();
        assert_eq!(&data[..], &decoded[..]);
    }
}
