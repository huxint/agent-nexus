//! Local social memory for an autonomous agent node.
//!
//! `SocialMemory` is the bridge between the wire protocol and the in-memory
//! society graph: it decodes signed gossip bytes, appends them to the verified
//! event log, and rebuilds the subjective society view.

use serde::{Deserialize, Deserializer, Serialize};

use crate::event_log::SocialEventLog;
use crate::protocol::{SocialEvent, SocialProtocolError};
use crate::society::Society;

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
}
