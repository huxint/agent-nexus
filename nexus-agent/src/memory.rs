//! Local social memory for an autonomous agent node.
//!
//! `SocialMemory` is the bridge between the wire protocol and the in-memory
//! society graph: it decodes signed gossip bytes, appends them to the verified
//! event log, and rebuilds the subjective society view.

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::confidential::ConfidentialEnvelopeError;
use crate::event_log::SocialEventLog;
use crate::protocol::{SocialEvent, SocialEventKind, SocialProtocolError};
use crate::society::Society;
use nexus_crypto::NodeIdentity;

/// Maximum accepted JSON size for one social event.
pub const MAX_SOCIAL_EVENT_JSON_BYTES: usize = 256 * 1024;

/// A node's verified social event log plus its replayed society view.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SocialMemory {
    log: SocialEventLog,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint: Option<SocialMemoryCheckpoint>,
    #[serde(skip)]
    society: Society,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SocialMemoryCheckpoint {
    version: u16,
    replayed_events: usize,
    replayed_equivocation_proofs: usize,
    log_digest: String,
    society_cbor_hex: String,
}

impl<'de> Deserialize<'de> for SocialMemory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StoredMemory {
            log: SocialEventLog,
            #[serde(default)]
            checkpoint: Option<SocialMemoryCheckpoint>,
        }

        let stored = StoredMemory::deserialize(deserializer)?;
        Ok(Self::from_log_with_checkpoint(
            stored.log,
            stored.checkpoint,
        ))
    }
}

impl SocialMemory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_log(log: SocialEventLog) -> Self {
        Self::from_log_with_checkpoint(log, None)
    }

    fn from_log_with_checkpoint(
        log: SocialEventLog,
        checkpoint: Option<SocialMemoryCheckpoint>,
    ) -> Self {
        if let Some(checkpoint) = checkpoint {
            if let Some(society) = society_from_valid_checkpoint(&log, &checkpoint) {
                return Self {
                    log,
                    checkpoint: Some(checkpoint),
                    society,
                };
            }
        }

        let society = log.to_society();
        let checkpoint = Some(checkpoint_for(&log, &society));
        Self {
            log,
            checkpoint,
            society,
        }
    }

    pub fn log(&self) -> &SocialEventLog {
        &self.log
    }

    pub fn events(&self) -> &[SocialEvent] {
        self.log.events()
    }

    pub fn pending_events(&self) -> &[SocialEvent] {
        self.log.pending_events()
    }

    pub fn sign_event(
        &self,
        identity: &NodeIdentity,
        timestamp: u64,
        kind: SocialEventKind,
    ) -> Result<SocialEvent, SocialProtocolError> {
        let (seq, prev) = self.log.next_position(identity.did());
        SocialEvent::new_chained(identity.did().clone(), seq, prev, timestamp, kind).sign(identity)
    }

    pub fn sign_event_sequence(
        &self,
        identity: &NodeIdentity,
        events: impl IntoIterator<Item = (u64, SocialEventKind)>,
    ) -> Result<Vec<SocialEvent>, SocialProtocolError> {
        let (mut seq, mut prev) = self.log.next_position(identity.did());
        let mut signed = Vec::new();
        for (timestamp, kind) in events {
            let event =
                SocialEvent::new_chained(identity.did().clone(), seq, prev, timestamp, kind)
                    .sign(identity)?;
            seq = seq.saturating_add(1);
            prev = Some(event.id.clone());
            signed.push(event);
        }
        Ok(signed)
    }

    pub fn society(&self) -> &Society {
        &self.society
    }

    pub fn private_society_for(
        &self,
        recipient: &nexus_core::Did,
        shared_secret: &[u8],
    ) -> Result<Society, ConfidentialEnvelopeError> {
        let mut society = self.society.clone();
        for event in self.events() {
            let SocialEventKind::ConfidentialEnvelope { envelope } = &event.kind else {
                continue;
            };
            if !envelope.includes_recipient(recipient) {
                continue;
            }
            if !envelope.matches_shared_secret(shared_secret)? {
                continue;
            }
            let kind = envelope.decrypt_for(recipient, shared_secret)?;
            let decrypted_event = SocialEvent::new_chained(
                event.author.clone(),
                event.seq,
                event.prev.clone(),
                event.timestamp,
                kind,
            );
            if decrypted_event.validate_author_claims().is_err() {
                continue;
            }
            society.apply_event(&decrypted_event);
        }
        Ok(society)
    }

    pub fn event_count(&self) -> usize {
        self.log.len()
    }

    pub fn retained_event_count(&self) -> usize {
        self.log.retained_len()
    }

    pub fn compacted_event_count(&self) -> usize {
        self.log.compacted_event_count()
    }

    pub fn agent_count(&self) -> usize {
        self.society.agent_count()
    }

    /// Append a verified social event and refresh the local society view.
    ///
    /// Returns `true` when this event was newly inserted and `false` when it
    /// was already known.
    pub fn ingest_event(&mut self, event: SocialEvent) -> Result<bool, SocialProtocolError> {
        let inserted = self.log.append(event)?;
        if inserted {
            self.society = self.log.to_society();
            self.checkpoint = Some(checkpoint_for(&self.log, &self.society));
        }
        Ok(inserted)
    }

    /// Append many verified events and rebuild the society view once.
    pub fn ingest_events(
        &mut self,
        events: impl IntoIterator<Item = SocialEvent>,
    ) -> Result<usize, SocialProtocolError> {
        let mut inserted = 0;
        for event in events {
            if self.log.append(event)? {
                inserted += 1;
            }
        }
        if inserted > 0 {
            self.society = self.log.to_society();
            self.checkpoint = Some(checkpoint_for(&self.log, &self.society));
        }
        Ok(inserted)
    }

    /// Decode and ingest many JSON events, returning one result per input while
    /// rebuilding the society view at most once.
    pub fn ingest_json_batch<'a>(
        &mut self,
        events_json: impl IntoIterator<Item = &'a [u8]>,
    ) -> Vec<Result<bool, SocialProtocolError>> {
        let mut inserted_any = false;
        let results = events_json
            .into_iter()
            .map(|data| {
                reject_oversized_event_json(data)?;
                let event =
                    SocialEvent::from_json(data).map_err(SocialProtocolError::EventDecode)?;
                let inserted = self.log.append(event)?;
                inserted_any |= inserted;
                Ok(inserted)
            })
            .collect::<Vec<_>>();
        if inserted_any {
            self.society = self.log.to_society();
            self.checkpoint = Some(checkpoint_for(&self.log, &self.society));
        }
        results
    }

    /// Decode a social event from JSON bytes and ingest it.
    pub fn ingest_json(&mut self, data: &[u8]) -> Result<bool, SocialProtocolError> {
        reject_oversized_event_json(data)?;
        let event = SocialEvent::from_json(data).map_err(SocialProtocolError::EventDecode)?;
        self.ingest_event(event)
    }

    pub fn compact_retaining_recent(
        &mut self,
        retain_events: usize,
    ) -> Result<bool, SocialProtocolError> {
        let compacted = self.log.compact_retaining_recent(retain_events)?;
        if compacted {
            self.society = self.log.to_society();
            self.checkpoint = Some(checkpoint_for(&self.log, &self.society));
        }
        Ok(compacted)
    }
}

fn reject_oversized_event_json(data: &[u8]) -> Result<(), SocialProtocolError> {
    if data.len() > MAX_SOCIAL_EVENT_JSON_BYTES {
        return Err(SocialProtocolError::EventTooLarge {
            actual: data.len(),
            max: MAX_SOCIAL_EVENT_JSON_BYTES,
        });
    }
    Ok(())
}

fn society_from_valid_checkpoint(
    log: &SocialEventLog,
    checkpoint: &SocialMemoryCheckpoint,
) -> Option<Society> {
    if checkpoint.version != 1 {
        return None;
    }
    let replayed_events = checkpoint.replayed_events;
    let replayed_proofs = checkpoint.replayed_equivocation_proofs;
    if replayed_events > log.events().len() || replayed_proofs > log.equivocation_proofs().len() {
        return None;
    }
    if log_digest(log, replayed_events, replayed_proofs) != checkpoint.log_digest {
        return None;
    }
    if !log.suffix_replay_is_ordered(replayed_events) {
        return None;
    }

    let society_bytes = hex::decode(&checkpoint.society_cbor_hex).ok()?;
    let mut society = ciborium::from_reader::<Society, _>(society_bytes.as_slice()).ok()?;
    log.replay_from(&mut society, replayed_events, replayed_proofs);
    Some(society)
}

fn checkpoint_for(log: &SocialEventLog, society: &Society) -> SocialMemoryCheckpoint {
    SocialMemoryCheckpoint {
        version: 1,
        replayed_events: log.events().len(),
        replayed_equivocation_proofs: log.equivocation_proofs().len(),
        log_digest: log_digest(log, log.events().len(), log.equivocation_proofs().len()),
        society_cbor_hex: society_cbor_hex(society),
    }
}

fn society_cbor_hex(society: &Society) -> String {
    let mut bytes = Vec::new();
    if ciborium::into_writer(society, &mut bytes).is_err() {
        return String::new();
    }
    hex::encode(bytes)
}

fn log_digest(log: &SocialEventLog, event_count: usize, proof_count: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus:social-memory-checkpoint:v1");
    hasher.update((event_count as u64).to_le_bytes());
    for event in log.events().iter().take(event_count) {
        hasher.update((event.id.len() as u64).to_le_bytes());
        hasher.update(event.id.as_bytes());
    }
    hasher.update((proof_count as u64).to_le_bytes());
    for proof in log.equivocation_proofs().iter().take(proof_count) {
        let key = proof.evidence_key();
        hasher.update((key.len() as u64).to_le_bytes());
        hasher.update(key.as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::WorkspaceId;
    use nexus_crypto::NodeIdentity;

    use crate::confidential::EncryptedSocialEnvelope;
    use crate::protocol::{SocialEventKind, SocialProtocolError};
    use crate::society::RelationKind;

    #[test]
    fn memory_ingests_signed_event_bytes_and_replays_society() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let event = SocialEvent::new(
            alice.did().clone(),
            1,
            SocialEventKind::RelationDeclared {
                peer: bob.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("gossiped relation".into()),
            },
        )
        .sign(&alice)
        .unwrap();
        let event_bytes = event.to_json().unwrap();

        let mut memory = SocialMemory::new();
        assert!(memory.ingest_json(&event_bytes).unwrap());
        assert!(!memory.ingest_json(&event_bytes).unwrap());
        assert_eq!(memory.event_count(), 1);
        assert_eq!(memory.agent_count(), 2);
        assert_eq!(
            memory.society().edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Collaborator
        );
    }

    #[test]
    fn encrypted_social_event_keeps_private_payload_out_of_public_society() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let private_kind = SocialEventKind::RelationDeclared {
            peer: bob.did().clone(),
            relation: RelationKind::Collaborator,
            note: Some("private relation".into()),
        };
        let envelope = EncryptedSocialEnvelope::encrypt(
            vec![alice.did().clone(), bob.did().clone()],
            b"shared secret",
            &private_kind,
        )
        .unwrap();
        let event = SocialEvent::new(
            alice.did().clone(),
            1,
            SocialEventKind::ConfidentialEnvelope { envelope },
        )
        .sign(&alice)
        .unwrap();

        let mut public_memory = SocialMemory::new();
        assert!(public_memory.ingest_event(event.clone()).unwrap());
        assert!(public_memory
            .society()
            .edge(alice.did(), bob.did())
            .is_none());
        assert!(public_memory.society().has_agent(alice.did()));
        assert!(public_memory.society().has_agent(bob.did()));

        let decrypted = match &event.kind {
            SocialEventKind::ConfidentialEnvelope { envelope } => {
                envelope.decrypt_for(bob.did(), b"shared secret").unwrap()
            }
            _ => unreachable!(),
        };
        let private_event = public_memory.sign_event(&alice, 2, decrypted).unwrap();
        let mut private_memory = public_memory.clone();
        assert!(private_memory.ingest_event(private_event).unwrap());
        assert_eq!(
            private_memory
                .society()
                .edge(alice.did(), bob.did())
                .unwrap()
                .kind,
            RelationKind::Collaborator
        );

        let private_society = public_memory
            .private_society_for(bob.did(), b"shared secret")
            .unwrap();
        assert_eq!(
            private_society.edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Collaborator
        );
        assert!(public_memory
            .private_society_for(bob.did(), b"wrong secret")
            .unwrap()
            .edge(alice.did(), bob.did())
            .is_none());
    }

    #[test]
    fn memory_rejects_unsigned_or_invalid_event_bytes() {
        let alice = NodeIdentity::generate();
        let event = SocialEvent::new(
            alice.did().clone(),
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([12; 32]),
            },
        );
        let event_bytes = event.to_json().unwrap();
        let mut memory = SocialMemory::new();

        let err = memory.ingest_json(&event_bytes).unwrap_err();
        assert!(matches!(err, SocialProtocolError::MissingSignature));

        let err = memory.ingest_json(b"not-json").unwrap_err();
        assert!(matches!(err, SocialProtocolError::EventDecode(_)));
    }

    #[test]
    fn memory_rejects_oversized_event_bytes_before_decode() {
        let mut memory = SocialMemory::new();
        let oversized = vec![b' '; MAX_SOCIAL_EVENT_JSON_BYTES + 1];

        let err = memory.ingest_json(&oversized).unwrap_err();
        assert!(matches!(
            err,
            SocialProtocolError::EventTooLarge {
                actual,
                max: MAX_SOCIAL_EVENT_JSON_BYTES
            } if actual == MAX_SOCIAL_EVENT_JSON_BYTES + 1
        ));
        assert_eq!(memory.event_count(), 0);

        let results = memory.ingest_json_batch([oversized.as_slice()]);
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results[0].as_ref().unwrap_err(),
            SocialProtocolError::EventTooLarge { .. }
        ));
        assert_eq!(memory.event_count(), 0);
    }

    #[test]
    fn deserialized_memory_rebuilds_society_from_log() {
        let alice = NodeIdentity::generate();
        let event = SocialEvent::new(
            alice.did().clone(),
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([13; 32]),
            },
        )
        .sign(&alice)
        .unwrap();
        let mut memory = SocialMemory::new();
        assert!(memory.ingest_event(event).unwrap());

        let json = serde_json::to_vec(&memory).unwrap();
        let decoded: SocialMemory = serde_json::from_slice(&json).unwrap();

        assert_eq!(decoded.event_count(), 1);
        assert!(decoded.society().has_agent(alice.did()));
        assert_eq!(decoded.events().len(), 1);
        assert!(serde_json::from_slice::<serde_json::Value>(&json)
            .unwrap()
            .get("checkpoint")
            .is_some());
    }

    #[test]
    fn deserialized_memory_uses_valid_checkpoint_for_log_tail() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = SocialEvent::new(
            alice.did().clone(),
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([15; 32]),
            },
        )
        .sign(&alice)
        .unwrap();
        let second = SocialEvent::new(
            bob.did().clone(),
            2,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([16; 32]),
            },
        )
        .sign(&bob)
        .unwrap();

        let mut checkpointed = SocialMemory::new();
        assert!(checkpointed.ingest_event(first).unwrap());
        let mut json = serde_json::from_slice::<serde_json::Value>(
            &serde_json::to_vec(&checkpointed).unwrap(),
        )
        .unwrap();
        json["log"]["events"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::to_value(second).unwrap());

        let decoded: SocialMemory = serde_json::from_value(json).unwrap();

        assert_eq!(decoded.event_count(), 2);
        assert!(decoded.society().has_agent(alice.did()));
        assert!(decoded.society().has_agent(bob.did()));
    }

    #[test]
    fn invalid_checkpoint_falls_back_to_full_replay() {
        let alice = NodeIdentity::generate();
        let event = SocialEvent::new(
            alice.did().clone(),
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([17; 32]),
            },
        )
        .sign(&alice)
        .unwrap();
        let mut memory = SocialMemory::new();
        assert!(memory.ingest_event(event).unwrap());
        let mut json =
            serde_json::from_slice::<serde_json::Value>(&serde_json::to_vec(&memory).unwrap())
                .unwrap();
        json["checkpoint"]["log_digest"] = serde_json::Value::String("tampered".into());

        let decoded: SocialMemory = serde_json::from_value(json).unwrap();

        assert_eq!(decoded.event_count(), 1);
        assert!(decoded.society().has_agent(alice.did()));
    }

    #[test]
    fn checkpoint_serializes_society_with_pair_key_indexes() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let relation = SocialEvent::new(
            alice.did().clone(),
            1,
            SocialEventKind::RelationDeclared {
                peer: bob.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("checkpoint edge".into()),
            },
        )
        .sign(&alice)
        .unwrap();
        let mut memory = SocialMemory::new();
        assert!(memory.ingest_event(relation).unwrap());

        let json = serde_json::to_vec(&memory).unwrap();
        let decoded: SocialMemory = serde_json::from_slice(&json).unwrap();

        assert_eq!(
            decoded.society().edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Collaborator
        );
        let checkpoint = serde_json::from_slice::<serde_json::Value>(&json).unwrap();
        let cbor_hex = checkpoint["checkpoint"]["society_cbor_hex"]
            .as_str()
            .unwrap();
        assert!(!cbor_hex.is_empty());
    }

    #[test]
    fn memory_batch_ingest_rebuilds_society_once_for_many_events() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let events = [
            SocialEvent::new(
                alice.did().clone(),
                1,
                SocialEventKind::WorkspaceJoined {
                    workspace: WorkspaceId::from_bytes([14; 32]),
                },
            )
            .sign(&alice)
            .unwrap(),
            SocialEvent::new(
                bob.did().clone(),
                2,
                SocialEventKind::RelationDeclared {
                    peer: alice.did().clone(),
                    relation: RelationKind::Collaborator,
                    note: None,
                },
            )
            .sign(&bob)
            .unwrap(),
        ];
        let mut memory = SocialMemory::new();

        assert_eq!(memory.ingest_events(events).unwrap(), 2);

        assert_eq!(memory.event_count(), 2);
        assert!(memory.society().has_agent(alice.did()));
        assert!(memory.society().has_agent(bob.did()));
    }

    #[test]
    fn memory_compaction_retains_log_tail_and_checkpointed_society() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let mut memory = SocialMemory::new();
        let events = memory
            .sign_event_sequence(
                &alice,
                [
                    (
                        1,
                        SocialEventKind::WorkspaceJoined {
                            workspace: WorkspaceId::from_bytes([41; 32]),
                        },
                    ),
                    (
                        2,
                        SocialEventKind::RelationDeclared {
                            peer: bob.did().clone(),
                            relation: RelationKind::Collaborator,
                            note: Some("compacted prefix".into()),
                        },
                    ),
                    (
                        3,
                        SocialEventKind::RelationDeclared {
                            peer: bob.did().clone(),
                            relation: RelationKind::Blocked,
                            note: Some("retained tail".into()),
                        },
                    ),
                ],
            )
            .unwrap();
        assert_eq!(memory.ingest_events(events).unwrap(), 3);

        assert!(memory.compact_retaining_recent(1).unwrap());
        assert_eq!(memory.event_count(), 3);
        assert_eq!(memory.retained_event_count(), 1);
        assert_eq!(memory.compacted_event_count(), 2);
        assert_eq!(
            memory.society().edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Blocked
        );

        let json = serde_json::to_vec(&memory).unwrap();
        let decoded: SocialMemory = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.event_count(), 3);
        assert_eq!(decoded.retained_event_count(), 1);
        assert_eq!(
            decoded.society().edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Blocked
        );
    }
}
