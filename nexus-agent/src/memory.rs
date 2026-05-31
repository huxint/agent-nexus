//! Local social memory for an autonomous agent node.
//!
//! `SocialMemory` is the bridge between the wire protocol and the in-memory
//! society graph: it decodes signed gossip bytes, appends them to the verified
//! event log, and rebuilds the subjective society view.

use serde::{Deserialize, Deserializer, Serialize};

use crate::event_log::SocialEventLog;
use crate::protocol::{SocialEvent, SocialEventKind, SocialProtocolError};
use crate::society::Society;
use nexus_crypto::NodeIdentity;

/// A node's verified social event log plus its replayed society view.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SocialMemory {
    log: SocialEventLog,
    #[serde(skip)]
    society: Society,
}

impl<'de> Deserialize<'de> for SocialMemory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StoredMemory {
            log: SocialEventLog,
        }

        let stored = StoredMemory::deserialize(deserializer)?;
        Ok(Self::from_log(stored.log))
    }
}

impl SocialMemory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_log(log: SocialEventLog) -> Self {
        let society = log.to_society();
        Self { log, society }
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

    pub fn event_count(&self) -> usize {
        self.log.len()
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
                let event =
                    SocialEvent::from_json(data).map_err(SocialProtocolError::EventDecode)?;
                let inserted = self.log.append(event)?;
                inserted_any |= inserted;
                Ok(inserted)
            })
            .collect::<Vec<_>>();
        if inserted_any {
            self.society = self.log.to_society();
        }
        results
    }

    /// Decode a social event from JSON bytes and ingest it.
    pub fn ingest_json(&mut self, data: &[u8]) -> Result<bool, SocialProtocolError> {
        let event = SocialEvent::from_json(data).map_err(SocialProtocolError::EventDecode)?;
        self.ingest_event(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::WorkspaceId;
    use nexus_crypto::NodeIdentity;

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
}
