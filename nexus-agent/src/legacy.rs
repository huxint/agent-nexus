//! Explicit migration helpers for pre-chain social event wire data.

use std::collections::HashSet;

use ed25519_dalek::{Signature, VerifyingKey};
use nexus_core::Did;
use nexus_crypto::{parse_did, NodeIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::event_log::SocialEventLog;
use crate::protocol::{SocialEvent, SocialEventKind, SocialProtocolError};
use crate::society::Society;
use crate::SocialMemory;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacySocialMemoryMigration {
    pub legacy_events: usize,
    pub migrated_events: usize,
    pub duplicate_events: usize,
    pub unsupported_events: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct LegacySocialEvent {
    id: String,
    author: Did,
    timestamp: u64,
    kind: SocialEventKind,
    signature: Option<Vec<u8>>,
}

impl LegacySocialEvent {
    fn signing_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        legacy_signing_payload_for(&self.author, self.timestamp, &self.kind)
    }

    fn content_id(&self) -> Result<String, serde_json::Error> {
        let payload = self.signing_payload()?;
        Ok(hex::encode(Sha256::digest(payload)))
    }

    fn validate(&self) -> Result<(), SocialProtocolError> {
        if self.content_id()? != self.id {
            return Err(SocialProtocolError::EventIdMismatch {
                actual: self.id.clone(),
                expected: self.content_id()?,
            });
        }

        let signature = self
            .signature
            .as_deref()
            .ok_or(SocialProtocolError::MissingSignature)?;
        let signature = Signature::from_slice(signature)
            .map_err(|_| SocialProtocolError::InvalidSignatureBytes)?;
        let key_bytes = parse_did(self.author.as_str())?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)?;
        let payload = self.signing_payload()?;
        NodeIdentity::verify(&verifying_key, &payload, &signature)
            .map_err(|_| SocialProtocolError::SignatureVerificationFailed)
    }
}

pub fn legacy_social_event_json(
    author: Did,
    timestamp: u64,
    kind: SocialEventKind,
    identity: &NodeIdentity,
) -> Result<Vec<u8>, SocialProtocolError> {
    let payload = legacy_signing_payload_for(&author, timestamp, &kind)?;
    let id = hex::encode(Sha256::digest(&payload));
    let event = serde_json::json!({
        "id": id,
        "author": author,
        "timestamp": timestamp,
        "kind": kind,
        "signature": identity.sign(&payload).to_bytes().to_vec(),
    });
    Ok(serde_json::to_vec(&event)?)
}

pub fn migrate_legacy_social_memory_json(
    data: &[u8],
) -> Result<(SocialMemory, LegacySocialMemoryMigration), SocialProtocolError> {
    let legacy_events = decode_legacy_social_events(data)?;
    migrate_legacy_social_events(legacy_events)
}

fn migrate_legacy_social_events(
    mut legacy_events: Vec<LegacySocialEvent>,
) -> Result<(SocialMemory, LegacySocialMemoryMigration), SocialProtocolError> {
    let mut report = LegacySocialMemoryMigration {
        legacy_events: legacy_events.len(),
        ..Default::default()
    };
    legacy_events.sort_by(|a, b| {
        a.author
            .to_string()
            .cmp(&b.author.to_string())
            .then_with(|| a.timestamp.cmp(&b.timestamp))
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut society = Society::new();
    let mut seen = HashSet::new();
    let mut authors = HashSet::new();
    for event in legacy_events {
        match event.validate() {
            Ok(()) => {}
            Err(_) => {
                report.unsupported_events += 1;
                continue;
            }
        }
        if !seen.insert(event.id.clone()) {
            report.duplicate_events += 1;
            continue;
        }
        let migrated_event = legacy_event_as_unverified_chain_event(&event);
        if migrated_event.validate_author_claims().is_err() {
            report.unsupported_events += 1;
            continue;
        }
        authors.insert(event.author.clone());
        society.apply_event(&migrated_event);
        report.migrated_events += 1;
    }

    let log = SocialEventLog::from_migrated_legacy_base(&society, authors, report.migrated_events)?;

    Ok((SocialMemory::from_log(log), report))
}

fn legacy_event_as_unverified_chain_event(event: &LegacySocialEvent) -> SocialEvent {
    SocialEvent {
        version: crate::protocol::SOCIAL_EVENT_PROTOCOL_VERSION,
        id: event.id.clone(),
        author: event.author.clone(),
        seq: 0,
        prev: None,
        timestamp: event.timestamp,
        kind: event.kind.clone(),
        signature: event.signature.clone(),
    }
}

fn decode_legacy_social_events(data: &[u8]) -> Result<Vec<LegacySocialEvent>, SocialProtocolError> {
    let value = serde_json::from_slice::<serde_json::Value>(data)
        .map_err(SocialProtocolError::EventDecode)?;
    let entries = legacy_event_entries(&value);
    let mut events = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.get("seq").is_some() || entry.get("prev").is_some() {
            continue;
        }
        if let Ok(event) = serde_json::from_value::<LegacySocialEvent>(entry.clone()) {
            events.push(event);
        }
    }
    Ok(events)
}

fn legacy_event_entries(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    if let Some(events) = value.as_array() {
        return events.iter().collect();
    }
    if let Some(events) = value.get("events").and_then(|events| events.as_array()) {
        return events.iter().collect();
    }
    if let Some(events) = value
        .get("log")
        .and_then(|log| log.get("events"))
        .and_then(|events| events.as_array())
    {
        return events.iter().collect();
    }
    vec![value]
}

fn legacy_signing_payload_for(
    author: &Did,
    timestamp: u64,
    kind: &SocialEventKind,
) -> Result<Vec<u8>, serde_json::Error> {
    #[derive(Serialize)]
    struct Payload<'a> {
        author: &'a Did,
        timestamp: u64,
        kind: &'a SocialEventKind,
    }

    serde_json::to_vec(&Payload {
        author,
        timestamp,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::WorkspaceId;

    use crate::society::RelationKind;

    #[test]
    fn migrates_pre_chain_events_into_compacted_base() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = legacy_social_event_json(
            alice.did().clone(),
            10,
            SocialEventKind::RelationDeclared {
                peer: bob.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("old wire".into()),
            },
            &alice,
        )
        .unwrap();
        let second = legacy_social_event_json(
            alice.did().clone(),
            11,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([7; 32]),
            },
            &alice,
        )
        .unwrap();
        let data = serde_json::to_vec(&serde_json::json!({
            "log": {
                "events": [
                    serde_json::from_slice::<serde_json::Value>(&first).unwrap(),
                    serde_json::from_slice::<serde_json::Value>(&second).unwrap(),
                ]
            }
        }))
        .unwrap();

        let (mut memory, report) = migrate_legacy_social_memory_json(&data).unwrap();

        assert_eq!(report.legacy_events, 2);
        assert_eq!(report.migrated_events, 2);
        assert_eq!(report.unsupported_events, 0);
        assert_eq!(memory.event_count(), 2);
        assert_eq!(memory.retained_event_count(), 0);
        assert_eq!(memory.compacted_event_count(), 2);
        assert_eq!(
            memory.society().edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Collaborator
        );

        let next = memory
            .sign_event(
                &alice,
                12,
                SocialEventKind::WorkspaceJoined {
                    workspace: WorkspaceId::from_bytes([8; 32]),
                },
            )
            .unwrap();
        assert_eq!(next.seq, 1);
        assert!(next.prev.is_some());
        assert!(memory.ingest_event(next).unwrap());
        assert_eq!(memory.event_count(), 3);
    }

    #[test]
    fn migration_skips_invalid_legacy_signatures() {
        let alice = NodeIdentity::generate();
        let mut event = serde_json::from_slice::<serde_json::Value>(
            &legacy_social_event_json(
                alice.did().clone(),
                10,
                SocialEventKind::WorkspaceJoined {
                    workspace: WorkspaceId::from_bytes([9; 32]),
                },
                &alice,
            )
            .unwrap(),
        )
        .unwrap();
        event["timestamp"] = serde_json::json!(11);
        let data = serde_json::to_vec(&serde_json::json!({ "events": [event] })).unwrap();

        let (memory, report) = migrate_legacy_social_memory_json(&data).unwrap();

        assert_eq!(report.legacy_events, 1);
        assert_eq!(report.migrated_events, 0);
        assert_eq!(report.unsupported_events, 1);
        assert_eq!(memory.event_count(), 0);
    }
}
