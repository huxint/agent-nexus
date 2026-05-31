//! Capability token signing and verification.
//!
//! A capability is a signed bearer token: the issuer grants the subject
//! specific permissions on a workspace for a bounded time window.
//!
//! ## Canonical serialisation (for signing)
//!
//! We serialise the *unsigned* fields to CBOR in a fixed order:
//!   [issuer, subject, workspace, permissions(read,write,exec,admin), expires_at, parent, delegation_depth]
//!
//! The signature covers this exact byte string.  Verification reconstructs
//! the same bytes and checks the Ed25519 signature.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nexus_core::{Capability, Did, NexusError, NexusResult, PermissionSet, WorkspaceId};

use crate::did::parse_did;
use crate::identity::NodeIdentity;
use crate::signing::domain_separated_cbor;

const CAPABILITY_SIGNING_DOMAIN_V2: &str = "nexus:capability:v2";

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

    #[error("delegated capability issuer {issuer} is not the parent subject {parent_subject}")]
    DelegationIssuerMismatch { issuer: Did, parent_subject: Did },

    #[error("delegated capability permissions exceed parent permissions")]
    DelegationPermissionsExceedParent,

    #[error(
        "delegated capability expiry {child_expires_at} exceeds parent expiry {parent_expires_at}"
    )]
    DelegationExpiryExceedsParent {
        child_expires_at: u64,
        parent_expires_at: u64,
    },

    #[error("parent capability does not allow further delegation")]
    DelegationDepthExceeded,

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
    sign_capability_with_depth(issuer, subject, workspace, permissions, expires_at, None)
        .map_err(|err| NexusError::Crypto(err.to_string()))
}

/// Create a signed capability token that may itself delegate further.
pub fn sign_capability_with_depth(
    issuer: &NodeIdentity,
    subject: &Did,
    workspace: WorkspaceId,
    permissions: PermissionSet,
    expires_at: u64,
    delegation_depth: Option<u8>,
) -> Result<Capability, SigningError> {
    let unsigned = CapabilityFields {
        issuer: issuer.did().clone(),
        subject: subject.clone(),
        workspace,
        permissions: permissions.clone(),
        expires_at,
        parent: None,
        delegation_depth,
    };

    let payload = signing_payload(&unsigned).map_err(SigningError::Serialisation)?;

    let sig = issuer.sign(&payload);

    Ok(Capability {
        issuer: unsigned.issuer,
        subject: unsigned.subject,
        workspace: unsigned.workspace,
        permissions: unsigned.permissions,
        expires_at: unsigned.expires_at,
        parent: None,
        delegation_depth,
        signature: sig.to_bytes().to_vec(),
    })
}

/// Create a delegated capability token from an existing valid parent token.
///
/// The parent subject becomes the delegated token issuer. The delegated token
/// must stay within the parent's workspace, permissions, expiry, and remaining
/// delegation depth.
pub fn delegate_capability(
    issuer: &NodeIdentity,
    parent: Capability,
    subject: &Did,
    permissions: PermissionSet,
    expires_at: u64,
    delegation_depth: Option<u8>,
    now: u64,
) -> Result<Capability, SigningError> {
    verify_capability(&parent, now)?;
    if parent.subject != *issuer.did() {
        return Err(SigningError::DelegationIssuerMismatch {
            issuer: issuer.did().clone(),
            parent_subject: parent.subject.clone(),
        });
    }
    ensure_delegation_within_parent(
        issuer.did(),
        parent.workspace,
        &permissions,
        expires_at,
        &parent,
    )?;
    let max_child_depth = parent
        .delegation_depth
        .ok_or(SigningError::DelegationDepthExceeded)?
        .checked_sub(1)
        .ok_or(SigningError::DelegationDepthExceeded)?;
    if delegation_depth.unwrap_or(0) > max_child_depth {
        return Err(SigningError::DelegationDepthExceeded);
    }

    let unsigned = CapabilityFields {
        issuer: issuer.did().clone(),
        subject: subject.clone(),
        workspace: parent.workspace,
        permissions: permissions.clone(),
        expires_at,
        parent: Some(parent.clone()),
        delegation_depth,
    };
    let payload = signing_payload(&unsigned).map_err(SigningError::Serialisation)?;
    let sig = issuer.sign(&payload);

    Ok(Capability {
        issuer: unsigned.issuer,
        subject: unsigned.subject,
        workspace: unsigned.workspace,
        permissions,
        expires_at,
        parent: Some(Box::new(parent)),
        delegation_depth,
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
        parent: cap.parent.as_deref().cloned(),
        delegation_depth: cap.delegation_depth,
    };

    let payload = signing_payload(&unsigned).map_err(SigningError::Serialisation)?;
    let legacy_current_payload =
        canonical_encode(&unsigned).map_err(SigningError::Serialisation)?;
    let legacy_payload = if cap.parent.is_none() && cap.delegation_depth.is_none() {
        let legacy_unsigned = LegacyCapabilityFields {
            issuer: cap.issuer.clone(),
            subject: cap.subject.clone(),
            workspace: cap.workspace,
            permissions: cap.permissions.clone(),
            expires_at: cap.expires_at,
        };
        Some(canonical_encode_legacy(&legacy_unsigned).map_err(SigningError::Serialisation)?)
    } else {
        None
    };

    // 3. Extract issuer's VerifyingKey from DID
    let raw_pk = parse_did(cap.issuer.as_str())?;
    let vk = VerifyingKey::from_bytes(&raw_pk).map_err(|_| SigningError::InvalidSignature)?;

    // 4. Parse signature
    let sig = Signature::from_slice(&cap.signature).map_err(|_| SigningError::InvalidSignature)?;

    // 5. Verify
    if vk.verify(&payload, &sig).is_err()
        && vk.verify(&legacy_current_payload, &sig).is_err()
        && legacy_payload
            .as_deref()
            .is_none_or(|legacy_payload| vk.verify(legacy_payload, &sig).is_err())
    {
        return Err(SigningError::InvalidSignature);
    }

    if let Some(parent) = cap.parent.as_deref() {
        verify_capability(parent, now)?;
        ensure_delegation_within_parent(
            &cap.issuer,
            cap.workspace,
            &cap.permissions,
            cap.expires_at,
            parent,
        )?;
        let max_child_depth = parent
            .delegation_depth
            .ok_or(SigningError::DelegationDepthExceeded)?
            .checked_sub(1)
            .ok_or(SigningError::DelegationDepthExceeded)?;
        if cap.delegation_depth.unwrap_or(0) > max_child_depth {
            return Err(SigningError::DelegationDepthExceeded);
        }
    }

    Ok(())
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
    parent: Option<Capability>,
    delegation_depth: Option<u8>,
}

/// The v1 unsigned fields, kept so persisted non-delegated tokens continue to verify.
#[derive(serde::Serialize)]
struct LegacyCapabilityFields {
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

fn signing_payload(fields: &CapabilityFields) -> Result<Vec<u8>, String> {
    domain_separated_cbor(CAPABILITY_SIGNING_DOMAIN_V2, fields)
}

fn canonical_encode_legacy(fields: &LegacyCapabilityFields) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(fields, &mut buf).map_err(|e| format!("CBOR encode: {e}"))?;
    Ok(buf)
}

fn ensure_delegation_within_parent(
    issuer: &Did,
    workspace: WorkspaceId,
    permissions: &PermissionSet,
    expires_at: u64,
    parent: &Capability,
) -> Result<(), SigningError> {
    if parent.subject != *issuer {
        return Err(SigningError::DelegationIssuerMismatch {
            issuer: issuer.clone(),
            parent_subject: parent.subject.clone(),
        });
    }
    if parent.workspace != workspace {
        return Err(SigningError::WorkspaceMismatch {
            expected: parent.workspace,
            actual: workspace,
        });
    }
    if expires_at > parent.expires_at {
        return Err(SigningError::DelegationExpiryExceedsParent {
            child_expires_at: expires_at,
            parent_expires_at: parent.expires_at,
        });
    }
    if !permissions_within_parent(permissions, &parent.permissions) {
        return Err(SigningError::DelegationPermissionsExceedParent);
    }
    Ok(())
}

fn permissions_within_parent(child: &PermissionSet, parent: &PermissionSet) -> bool {
    (!child.read || parent.can_read())
        && (!child.write || parent.can_write())
        && (!child.exec || parent.can_exec())
        && (!child.admin || parent.is_admin())
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
    fn new_capability_signature_uses_domain_separated_payload() {
        let issuer = NodeIdentity::generate();
        let subject = NodeIdentity::generate().did().clone();
        let ws = WorkspaceId::from_bytes([0xacu8; 32]);
        let expires = ts_now() + 3600;
        let cap = sign_capability(&issuer, &subject, ws, PermissionSet::READ_ONLY, expires)
            .expect("signing must succeed");
        let unsigned = CapabilityFields {
            issuer: cap.issuer.clone(),
            subject: cap.subject.clone(),
            workspace: cap.workspace,
            permissions: cap.permissions.clone(),
            expires_at: cap.expires_at,
            parent: None,
            delegation_depth: None,
        };
        let old_payload = canonical_encode(&unsigned).unwrap();
        let new_payload = signing_payload(&unsigned).unwrap();
        let signature = Signature::from_slice(&cap.signature).unwrap();
        let verifying_key = issuer.verifying_key();

        assert!(verifying_key.verify(&new_payload, &signature).is_ok());
        assert!(verifying_key.verify(&old_payload, &signature).is_err());
    }

    #[test]
    fn legacy_capability_signature_still_verifies() {
        let issuer = NodeIdentity::generate();
        let subject = NodeIdentity::generate().did().clone();
        let ws = WorkspaceId::from_bytes([0xadu8; 32]);
        let expires = ts_now() + 3600;
        let unsigned = CapabilityFields {
            issuer: issuer.did().clone(),
            subject: subject.clone(),
            workspace: ws,
            permissions: PermissionSet::READ_ONLY,
            expires_at: expires,
            parent: None,
            delegation_depth: None,
        };
        let legacy_payload = canonical_encode(&unsigned).unwrap();
        let signature = issuer.sign(&legacy_payload).to_bytes().to_vec();
        let cap = Capability {
            issuer: unsigned.issuer,
            subject,
            workspace: ws,
            permissions: PermissionSet::READ_ONLY,
            expires_at: expires,
            parent: None,
            delegation_depth: None,
            signature,
        };

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

    #[test]
    fn delegated_capability_chain_verifies_with_bounded_depth() {
        let owner = NodeIdentity::generate();
        let delegate = NodeIdentity::generate();
        let grantee = NodeIdentity::generate();
        let ws = WorkspaceId::from_bytes([0x11u8; 32]);
        let now = ts_now();
        let parent = sign_capability_with_depth(
            &owner,
            delegate.did(),
            ws,
            PermissionSet::READ_WRITE,
            now + 3600,
            Some(1),
        )
        .unwrap();

        let delegated = delegate_capability(
            &delegate,
            parent.clone(),
            grantee.did(),
            PermissionSet::READ_ONLY,
            now + 1800,
            None,
            now,
        )
        .expect("delegation must succeed");

        assert_eq!(delegated.issuer, *delegate.did());
        assert_eq!(delegated.subject, *grantee.did());
        assert!(delegated.parent.is_some());
        assert!(verify_capability(&delegated, now).is_ok());
        assert!(verify_capability_for_caller(&delegated, grantee.did(), ws, now).is_ok());
    }

    #[test]
    fn delegated_capability_cannot_exceed_parent_permissions_or_depth() {
        let owner = NodeIdentity::generate();
        let delegate = NodeIdentity::generate();
        let grantee = NodeIdentity::generate();
        let ws = WorkspaceId::from_bytes([0x12u8; 32]);
        let now = ts_now();
        let parent = sign_capability_with_depth(
            &owner,
            delegate.did(),
            ws,
            PermissionSet::READ_ONLY,
            now + 3600,
            Some(1),
        )
        .unwrap();

        let err = delegate_capability(
            &delegate,
            parent.clone(),
            grantee.did(),
            PermissionSet::READ_WRITE,
            now + 1800,
            None,
            now,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SigningError::DelegationPermissionsExceedParent
        ));

        let delegated = delegate_capability(
            &delegate,
            parent,
            grantee.did(),
            PermissionSet::READ_ONLY,
            now + 1800,
            None,
            now,
        )
        .unwrap();
        let err = delegate_capability(
            &grantee,
            delegated,
            owner.did(),
            PermissionSet::READ_ONLY,
            now + 1200,
            None,
            now,
        )
        .unwrap_err();
        assert!(matches!(err, SigningError::DelegationDepthExceeded));
    }
}
