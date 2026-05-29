//! Capability token signing and verification.
//!
//! A capability is a signed bearer token: the issuer grants the subject
//! specific permissions on a workspace for a bounded time window.
//!
//! ## Canonical serialisation (for signing)
//!
//! We serialise the *unsigned* fields to CBOR in a fixed order:
//!   [issuer, subject, workspace, permissions(read,write,exec,admin), expires_at]
//!
//! The signature covers this exact byte string.  Verification reconstructs
//! the same bytes and checks the Ed25519 signature.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nexus_core::{Capability, Did, NexusError, NexusResult, PermissionSet, WorkspaceId};

use crate::did::parse_did;
use crate::identity::NodeIdentity;

/// Errors specific to capability operations.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("canonical serialisation failed: {0}")]
    Serialisation(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("capability expired at {expires_at} (current time: {now})")]
    Expired { expires_at: u64, now: u64 },

    #[error("subject DID does not match: expected {expected}, got {actual}")]
    SubjectMismatch { expected: Did, actual: Did },

    #[error("workspace mismatch: expected {expected}, got {actual}")]
    WorkspaceMismatch {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },

    #[error("DID parse error: {0}")]
    DidParse(#[from] crate::did::DidError),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a signed capability token.
///
/// The issuer (caller) grants `subject` the given permissions on `workspace`
/// until `expires_at` (Unix timestamp in seconds).
pub fn sign_capability(
    issuer: &NodeIdentity,
    subject: &Did,
    workspace: WorkspaceId,
    permissions: PermissionSet,
    expires_at: u64,
) -> NexusResult<Capability> {
    let unsigned = CapabilityFields {
        issuer: issuer.did().clone(),
        subject: subject.clone(),
        workspace,
        permissions: permissions.clone(),
        expires_at,
    };

    let payload = canonical_encode(&unsigned)
        .map_err(|e| NexusError::Crypto(format!("canonical encode: {e}")))?;

    let sig = issuer.sign(&payload);

    Ok(Capability {
        issuer: unsigned.issuer,
        subject: unsigned.subject,
        workspace: unsigned.workspace,
        permissions: unsigned.permissions,
        expires_at: unsigned.expires_at,
        signature: sig.to_bytes().to_vec(),
    })
}

/// Verify a capability token.
///
/// Checks:
///   1. The signature is valid for the issuer's public key.
///   2. The token has not expired (`now` is the caller's current Unix time).
///
/// On success, returns `()`; on failure, returns a descriptive error.
pub fn verify_capability(cap: &Capability, now: u64) -> Result<(), SigningError> {
    // 1. Check expiry
    if cap.expires_at <= now {
        return Err(SigningError::Expired {
            expires_at: cap.expires_at,
            now,
        });
    }

    // 2. Reconstruct canonical payload
    let unsigned = CapabilityFields {
        issuer: cap.issuer.clone(),
        subject: cap.subject.clone(),
        workspace: cap.workspace,
        permissions: cap.permissions.clone(),
        expires_at: cap.expires_at,
    };

    let payload = canonical_encode(&unsigned).map_err(SigningError::Serialisation)?;

    // 3. Extract issuer's VerifyingKey from DID
    let raw_pk = parse_did(cap.issuer.as_str())?;
    let vk = VerifyingKey::from_bytes(&raw_pk).map_err(|_| SigningError::InvalidSignature)?;

    // 4. Parse signature
    let sig = Signature::from_slice(&cap.signature).map_err(|_| SigningError::InvalidSignature)?;

    // 5. Verify
    vk.verify(&payload, &sig)
        .map_err(|_| SigningError::InvalidSignature)
}

/// Verify a capability AND check that `caller` is the subject.
///
/// This is the typical check when an agent presents a capability to
/// access a workspace: the token must be valid AND the calling agent
/// must be who the token was issued to.
pub fn verify_capability_for_caller(
    cap: &Capability,
    caller: &Did,
    workspace: WorkspaceId,
    now: u64,
) -> Result<(), SigningError> {
    // Check subject
    if cap.subject != *caller {
        return Err(SigningError::SubjectMismatch {
            expected: cap.subject.clone(),
            actual: caller.clone(),
        });
    }

    // Check workspace
    if cap.workspace != workspace {
        return Err(SigningError::WorkspaceMismatch {
            expected: cap.workspace,
            actual: workspace,
        });
    }

    verify_capability(cap, now)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// The unsigned fields of a capability — what gets signed.
#[derive(serde::Serialize)]
struct CapabilityFields {
    issuer: Did,
    subject: Did,
    workspace: WorkspaceId,
    permissions: PermissionSet,
    expires_at: u64,
}

/// Encode `fields` to a deterministic CBOR byte string.
fn canonical_encode(fields: &CapabilityFields) -> Result<Vec<u8>, String> {
    // ciborium with default settings produces canonical CBOR
    let mut buf = Vec::new();
    ciborium::into_writer(fields, &mut buf).map_err(|e| format!("CBOR encode: {e}"))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ts_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn sign_and_verify_valid_capability() {
        let issuer = NodeIdentity::generate();
        let subject_id = NodeIdentity::generate();
        let subject = subject_id.did().clone();
        let ws = WorkspaceId::from_bytes([0xabu8; 32]);
        let perms = PermissionSet::READ_WRITE;
        let expires = ts_now() + 3600;

        let cap = sign_capability(&issuer, &subject, ws, perms.clone(), expires)
            .expect("signing must succeed");

        assert!(verify_capability(&cap, ts_now()).is_ok());
    }

    #[test]
    fn expired_capability_rejected() {
        let issuer = NodeIdentity::generate();
        let subject = NodeIdentity::generate().did().clone();
        let ws = WorkspaceId::from_bytes([0xbu8; 32]);
        let expires = ts_now() - 1; // already expired

        let cap = sign_capability(&issuer, &subject, ws, PermissionSet::READ_ONLY, expires)
            .expect("signing must succeed");

        let err = verify_capability(&cap, ts_now()).unwrap_err();
        assert!(matches!(err, SigningError::Expired { .. }));
    }

    #[test]
    fn tampered_signature_rejected() {
        let issuer = NodeIdentity::generate();
        let subject = NodeIdentity::generate().did().clone();
        let ws = WorkspaceId::from_bytes([0xcdu8; 32]);
        let expires = ts_now() + 3600;

        let mut cap = sign_capability(&issuer, &subject, ws, PermissionSet::READ_ONLY, expires)
            .expect("signing must succeed");

        // Flip a byte in the signature
        if let Some(b) = cap.signature.first_mut() {
            *b ^= 0xff;
        }

        let err = verify_capability(&cap, ts_now()).unwrap_err();
        assert!(matches!(err, SigningError::InvalidSignature));
    }

    #[test]
    fn caller_mismatch_rejected() {
        let issuer = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let charlie = NodeIdentity::generate();
        let ws = WorkspaceId::from_bytes([0xefu8; 32]);
        let expires = ts_now() + 3600;

        let cap = sign_capability(&issuer, bob.did(), ws, PermissionSet::READ_ONLY, expires)
            .expect("signing must succeed");

        // Charlie tries to use Bob's capability
        let err = verify_capability_for_caller(&cap, charlie.did(), ws, ts_now()).unwrap_err();
        assert!(matches!(err, SigningError::SubjectMismatch { .. }));
    }
}
