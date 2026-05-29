//! Append-only social event log.
//!
//! The log is the smallest local ledger an agent needs to participate in the
//! society protocol. It verifies event authorship, de-duplicates gossip, and
//! can replay accepted events into a [`Society`](crate::society::Society).

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};

use crate::protocol::{SocialEvent, SocialProtocolError};
use crate::society::Society;

/// Append-only set of signed social events.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SocialEventLog {
    events: Vec<SocialEvent>,
    #[serde(skip)]
    index: HashMap<String, usize>,
}

impl<'de> Deserialize<'de> for SocialEventLog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StoredLog {
            events: Vec<SocialEvent>,
        }

        let stored = StoredLog::deserialize(deserializer)?;
        Self::from_events(stored.events).map_err(serde::de::Error::custom)
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
        let mut log = Self::new();
        for event in events {
            log.append(event)?;
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

    pub fn contains(&self, event_id: &str) -> bool {
        self.index.contains_key(event_id)
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

        self.index.insert(event.id.clone(), self.events.len());
        self.events.push(event);
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

    /// Replay events in deterministic causal order into a society graph.
    pub fn replay_into(&self, society: &mut Society) {
        let mut events: Vec<&SocialEvent> = self.events.iter().collect();
        events.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.id.cmp(&b.id))
                .then_with(|| a.author.to_string().cmp(&b.author.to_string()))
        });

        for event in events {
            society.apply_event(event);
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
        for (position, event) in self.events.iter().enumerate() {
            if let Some(existing) = self.index.insert(event.id.clone(), position) {
                let existing_payload = self.events[existing].signing_payload()?;
                let event_payload = event.signing_payload()?;
                if existing_payload != event_payload
                    || self.events[existing].signature != event.signature
                {
                    return Err(SocialProtocolError::DuplicateEventConflict {
                        event_id: event.id.clone(),
                    });
                }
            }
        }
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
        let mut first = signed_relation(&alice, &bob, 1);
        let mut second = signed_relation(&alice, &bob, 2);
        second.id = first.id.clone();
        second = second.sign(&alice).unwrap();

        let mut log = SocialEventLog::new();
        assert!(log.append(first.clone()).unwrap());
        let err = log.append(second).unwrap_err();
        assert!(matches!(
            err,
            SocialProtocolError::DuplicateEventConflict { .. }
        ));

        first.timestamp = 99;
        assert!(first.verify_signature().is_err());
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
