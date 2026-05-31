//! Append-only social event log.
//!
//! The log is the smallest local ledger an agent needs to participate in the
//! society protocol. It verifies event authorship, de-duplicates gossip, and
//! can replay accepted events into a [`Society`](crate::society::Society).

use std::collections::{HashMap, HashSet};

use nexus_core::Did;
use serde::{Deserialize, Deserializer, Serialize};

use crate::protocol::{EquivocationProof, SocialEvent, SocialProtocolError};
use crate::society::Society;

/// Append-only set of signed social events.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SocialEventLog {
    events: Vec<SocialEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending: Vec<SocialEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    equivocation_proofs: Vec<EquivocationProof>,
    #[serde(skip)]
    index: HashMap<String, usize>,
    #[serde(skip)]
    pending_index: HashSet<String>,
    #[serde(skip)]
    seq_index: HashMap<(Did, u64), usize>,
    #[serde(skip)]
    heads: HashMap<Did, (u64, String)>,
    #[serde(skip)]
    equivocation_index: HashSet<String>,
}

impl<'de> Deserialize<'de> for SocialEventLog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StoredLog {
            events: Vec<SocialEvent>,
            #[serde(default)]
            pending: Vec<SocialEvent>,
            #[serde(default)]
            equivocation_proofs: Vec<EquivocationProof>,
        }

        let stored = StoredLog::deserialize(deserializer)?;
        Self::from_parts(stored.events, stored.pending, stored.equivocation_proofs)
            .map_err(serde::de::Error::custom)
    }
}

impl SocialEventLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a log from events that were already serialized or stored.
    ///
    /// Every event is verified and duplicate ids must describe the same event.
    pub fn from_events(
        events: impl IntoIterator<Item = SocialEvent>,
    ) -> Result<Self, SocialProtocolError> {
        Self::from_parts(events, std::iter::empty(), std::iter::empty())
    }

    fn from_parts(
        events: impl IntoIterator<Item = SocialEvent>,
        pending: impl IntoIterator<Item = SocialEvent>,
        equivocation_proofs: impl IntoIterator<Item = EquivocationProof>,
    ) -> Result<Self, SocialProtocolError> {
        let mut log = Self::new();
        for event in events {
            log.append(event)?;
        }
        for event in pending {
            log.append(event)?;
        }
        for proof in equivocation_proofs {
            log.record_equivocation(proof)?;
        }
        Ok(log)
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn events(&self) -> &[SocialEvent] {
        &self.events
    }

    pub fn pending_events(&self) -> &[SocialEvent] {
        &self.pending
    }

    pub fn equivocation_proofs(&self) -> &[EquivocationProof] {
        &self.equivocation_proofs
    }

    pub fn contains(&self, event_id: &str) -> bool {
        self.index.contains_key(event_id) || self.pending_index.contains(event_id)
    }

    pub fn next_position(&self, author: &Did) -> (u64, Option<String>) {
        self.heads
            .get(author)
            .map(|(seq, id)| (seq.saturating_add(1), Some(id.clone())))
            .unwrap_or((0, None))
    }

    /// Append a signed event. Returns `true` when the event is newly inserted.
    pub fn append(&mut self, event: SocialEvent) -> Result<bool, SocialProtocolError> {
        event.validate()?;

        if let Some(existing) = self.index.get(&event.id) {
            let existing_payload = self.events[*existing].signing_payload()?;
            let incoming_payload = event.signing_payload()?;
            if existing_payload == incoming_payload
                && self.events[*existing].signature == event.signature
            {
                return Ok(false);
            }

            return Err(SocialProtocolError::DuplicateEventConflict { event_id: event.id });
        }
        if self.pending_index.contains(&event.id) {
            return Ok(false);
        }
        if let Some(existing) = self.seq_index.get(&(event.author.clone(), event.seq)) {
            let proof = EquivocationProof::new(self.events[*existing].clone(), event)?;
            return self.record_equivocation(proof);
        }
        if let Some(pending) = self
            .pending
            .iter()
            .find(|pending| pending.author == event.author && pending.seq == event.seq)
            .cloned()
        {
            let proof = EquivocationProof::new(pending, event)?;
            return self.record_equivocation(proof);
        }

        if self.can_accept(&event)? {
            let author = event.author.clone();
            self.accept_event(event)?;
            self.drain_pending_for(&author)?;
        } else {
            self.pending_index.insert(event.id.clone());
            self.pending.push(event);
        }
        Ok(true)
    }

    /// Merge another node's events using the same verification and de-dup rules.
    pub fn merge(
        &mut self,
        events: impl IntoIterator<Item = SocialEvent>,
    ) -> Result<usize, SocialProtocolError> {
        let mut inserted = 0;
        for event in events {
            if self.append(event)? {
                inserted += 1;
            }
        }
        Ok(inserted)
    }

    fn can_accept(&self, event: &SocialEvent) -> Result<bool, SocialProtocolError> {
        match self.heads.get(&event.author) {
            None => {
                if event.seq == 0 {
                    if event.prev.is_none() {
                        Ok(true)
                    } else {
                        Err(SocialProtocolError::InvalidChainGenesis {
                            author: event.author.clone(),
                        })
                    }
                } else {
                    Ok(false)
                }
            }
            Some((head_seq, head_id)) => {
                if event.seq == head_seq.saturating_add(1)
                    && event.prev.as_deref() == Some(head_id.as_str())
                {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn accept_event(&mut self, event: SocialEvent) -> Result<(), SocialProtocolError> {
        let index = self.events.len();
        self.index.insert(event.id.clone(), index);
        self.seq_index
            .insert((event.author.clone(), event.seq), index);
        self.heads
            .insert(event.author.clone(), (event.seq, event.id.clone()));
        self.record_pending_equivocations(&event)?;
        self.events.push(event);
        Ok(())
    }

    fn drain_pending_for(&mut self, author: &Did) -> Result<(), SocialProtocolError> {
        loop {
            let Some(position) = self.pending.iter().position(|event| {
                &event.author == author && self.can_accept(event).unwrap_or(false)
            }) else {
                break;
            };

            let event = self.pending.remove(position);
            self.pending_index.remove(&event.id);
            self.accept_event(event)?;
        }
        Ok(())
    }

    fn record_pending_equivocations(
        &mut self,
        accepted: &SocialEvent,
    ) -> Result<(), SocialProtocolError> {
        let mut position = 0;
        while position < self.pending.len() {
            let pending = &self.pending[position];
            if pending.author == accepted.author && pending.seq == accepted.seq {
                let pending = self.pending.remove(position);
                self.pending_index.remove(&pending.id);
                if pending.id != accepted.id {
                    self.record_equivocation(EquivocationProof::new(accepted.clone(), pending)?)?;
                }
            } else {
                position += 1;
            }
        }
        Ok(())
    }

    fn record_equivocation(
        &mut self,
        proof: EquivocationProof,
    ) -> Result<bool, SocialProtocolError> {
        proof.verify()?;
        let key = proof.evidence_key();
        if !self.equivocation_index.insert(key) {
            return Ok(false);
        }
        self.equivocation_proofs.push(proof);
        Ok(true)
    }

    /// Replay events in deterministic causal order into a society graph.
    pub fn replay_into(&self, society: &mut Society) {
        let mut events: Vec<&SocialEvent> = self.events.iter().collect();
        events.sort_by(|a, b| {
            a.author
                .to_string()
                .cmp(&b.author.to_string())
                .then_with(|| a.seq.cmp(&b.seq))
                .then_with(|| a.timestamp.cmp(&b.timestamp))
                .then_with(|| a.id.cmp(&b.id))
        });

        for event in events {
            society.apply_event(event);
        }
        for proof in &self.equivocation_proofs {
            society.record_equivocation_proof(proof.clone());
        }
    }

    /// Build a fresh society graph from this log.
    pub fn to_society(&self) -> Society {
        let mut society = Society::new();
        self.replay_into(&mut society);
        society
    }

    /// Rebuild the transient index after deserialization.
    pub fn rebuild_index(&mut self) -> Result<(), SocialProtocolError> {
        self.index.clear();
        self.pending_index.clear();
        self.seq_index.clear();
        self.heads.clear();
        self.equivocation_index.clear();

        let events = std::mem::take(&mut self.events);
        let pending = std::mem::take(&mut self.pending);
        let proofs = std::mem::take(&mut self.equivocation_proofs);
        *self = Self::from_parts(events, pending, proofs)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::WorkspaceId;
    use nexus_crypto::NodeIdentity;

    use crate::protocol::{SocialEventKind, SocialProtocolError};
    use crate::society::RelationKind;

    fn signed_relation(
        identity: &NodeIdentity,
        peer: &NodeIdentity,
        timestamp: u64,
    ) -> SocialEvent {
        SocialEvent::new(
            identity.did().clone(),
            timestamp,
            SocialEventKind::RelationDeclared {
                peer: peer.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("shared society log".into()),
            },
        )
        .sign(identity)
        .unwrap()
    }

    #[test]
    fn log_appends_signed_events_and_deduplicates_gossip() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let event = signed_relation(&alice, &bob, 1);

        let mut log = SocialEventLog::new();
        assert!(log.append(event.clone()).unwrap());
        assert!(!log.append(event.clone()).unwrap());
        assert_eq!(log.len(), 1);
        assert!(log.contains(&event.id));
    }

    #[test]
    fn log_rejects_unsigned_events() {
        let alice = NodeIdentity::generate();
        let event = SocialEvent::new(
            alice.did().clone(),
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([9; 32]),
            },
        );

        let err = SocialEventLog::new().append(event).unwrap_err();
        assert!(matches!(err, SocialProtocolError::MissingSignature));
    }

    #[test]
    fn log_rejects_duplicate_id_with_different_payload() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = signed_relation(&alice, &bob, 1);
        let mut second = signed_relation(&alice, &bob, 2);
        second.id = first.id.clone();

        let mut log = SocialEventLog::new();
        assert!(log.append(first.clone()).unwrap());
        let err = log.append(second).unwrap_err();
        assert!(matches!(err, SocialProtocolError::EventIdMismatch { .. }));
    }

    #[test]
    fn content_hash_id_changes_when_payload_changes() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = signed_relation(&alice, &bob, 1);
        let second = signed_relation(&alice, &bob, 2);

        assert_ne!(first.id, second.id);
        assert_eq!(first.id, first.content_id().unwrap());
        assert_eq!(second.id, second.content_id().unwrap());
    }

    #[test]
    fn out_of_order_author_chain_drains_when_predecessor_arrives() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = SocialEvent::new_chained(
            alice.did().clone(),
            0,
            None,
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([7; 32]),
            },
        )
        .sign(&alice)
        .unwrap();
        let second = SocialEvent::new_chained(
            alice.did().clone(),
            1,
            Some(first.id.clone()),
            2,
            SocialEventKind::RelationDeclared {
                peer: bob.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("arrived before predecessor".into()),
            },
        )
        .sign(&alice)
        .unwrap();

        let mut log = SocialEventLog::new();
        assert!(log.append(second.clone()).unwrap());
        assert_eq!(log.len(), 0);
        assert_eq!(log.pending_events().len(), 1);
        assert!(log.contains(&second.id));

        assert!(log.append(first).unwrap());
        assert_eq!(log.len(), 2);
        assert!(log.pending_events().is_empty());

        let society = log.to_society();
        assert_eq!(
            society.edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Collaborator
        );
    }

    #[test]
    fn same_author_sequence_conflict_records_equivocation_proof() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = signed_relation(&alice, &bob, 1);
        let fork = SocialEvent::new_chained(
            alice.did().clone(),
            0,
            None,
            2,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([8; 32]),
            },
        )
        .sign(&alice)
        .unwrap();

        let mut log = SocialEventLog::new();
        assert!(log.append(first.clone()).unwrap());
        assert!(log.append(fork.clone()).unwrap());

        assert_eq!(log.len(), 1);
        assert_eq!(log.equivocation_proofs().len(), 1);
        let proof = &log.equivocation_proofs()[0];
        proof.verify().unwrap();
        assert_eq!(proof.author, *alice.did());
        assert_eq!(proof.seq, 0);
        assert_ne!(proof.event_a.id, proof.event_b.id);

        let society = log.to_society();
        assert!(society.is_equivocating(alice.did()));
        assert_eq!(society.agent_equivocations(alice.did()).len(), 1);
    }

    #[test]
    fn tampering_with_signed_content_invalidates_id_and_signature() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let mut first = signed_relation(&alice, &bob, 1);
        first.timestamp = 99;
        assert!(matches!(
            first.verify_signature().unwrap_err(),
            SocialProtocolError::EventIdMismatch { .. }
        ));
    }

    #[test]
    fn replay_builds_society_from_deterministic_event_order() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let relation = signed_relation(&alice, &bob, 5);
        let joined = SocialEvent::new(
            bob.did().clone(),
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([11; 32]),
            },
        )
        .sign(&bob)
        .unwrap();

        let mut log = SocialEventLog::new();
        assert_eq!(log.merge([relation, joined]).unwrap(), 2);

        let mut society = Society::new();
        log.replay_into(&mut society);
        assert!(society.has_agent(alice.did()));
        assert!(society.has_agent(bob.did()));
        assert_eq!(
            society.edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Collaborator
        );
    }

    #[test]
    fn deserialized_log_rebuilds_index_and_verifies_events() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let event = signed_relation(&alice, &bob, 1);
        let mut log = SocialEventLog::new();
        assert!(log.append(event.clone()).unwrap());

        let json = serde_json::to_vec(&log).unwrap();
        let mut decoded: SocialEventLog = serde_json::from_slice(&json).unwrap();

        assert_eq!(decoded.len(), 1);
        assert!(!decoded.append(event).unwrap());
        assert_eq!(decoded.len(), 1);
    }
}
