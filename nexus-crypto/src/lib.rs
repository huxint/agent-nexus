//! Nexus Crypto — Ed25519 identities, DIDs, and capability tokens.
//!
//! ## DID Format
//!
//! We use the `did:key` method (W3C draft):
//!   did:key:z<multibase-base58btc(multicodec-varint || raw-pubkey)>
//!
//! For Ed25519 the multicodec prefix is `0xed 0x01`.
//!
//! ## Capability Signing
//!
//! Capabilities are serialised to CBOR in a canonical field order,
//! then signed with Ed25519.  The signature is appended to the token
//! and verified by the workspace owner on every access.

pub mod capability;
pub mod did;
pub mod identity;

pub use capability::{
    delegate_capability, sign_capability, sign_capability_with_depth, verify_capability,
    SigningError,
};
pub use did::{derive_did, parse_did, DidError};
pub use identity::{verify_did_signature, IdentitySignatureError, NodeIdentity};
