//! Wire-level social protocol for autonomous agents.
//!
//! The protocol is an append-only event stream. Events can be gossiped,
//! stored in a workspace, signed by the emitting agent, and replayed into a
//! [`Society`](crate::society::Society). This gives the framework a shared
//! language for AI social life without limiting local runtime freedom.

use ed25519_dalek::{Signature, VerifyingKey};
use nexus_core::{Did, WorkspaceId};
use nexus_crypto::capability::{verify_capability, SigningError};
use nexus_crypto::{parse_did, DidError, NodeIdentity};
use nexus_economy::SettlementError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::AgentManifest;
use crate::society::{
    AgentIntent, CapabilityGrant, CapabilityRevocation, CollectiveDecision, CollectiveProposal,
    CollectiveVote, IdentityRevocation, IntentResponse, Interaction, RelationKind,
    SettlementRecord, TaskDispute, WorkspaceRun, WorkspaceSnapshot,
};
use crate::task::{
    ExecutionAttestation, ExecutionReceiptError, TaskAcceptance, TaskCancellation, TaskOffer,
    TaskResult, TaskSpec,
};

/// Errors produced while signing or verifying social events.
#[derive(Debug, thiserror::Error)]
pub enum SocialProtocolError {
    #[error("event author {author} does not match signer {signer}")]
    AuthorSignerMismatch { author: Did, signer: Did },

    #[error("{event} subject {subject} does not match event author {author}")]
    AuthorSubjectMismatch {
        event: &'static str,
        author: Did,
        subject: Did,
    },

    #[error("social event is missing an author signature")]
    MissingSignature,

    #[error("invalid author DID: {0}")]
    InvalidAuthorDid(#[from] DidError),

    #[error("invalid Ed25519 verifying key: {0}")]
    InvalidVerifyingKey(#[from] ed25519_dalek::SignatureError),

    #[error("invalid Ed25519 signature bytes")]
    InvalidSignatureBytes,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid task result execution receipt: {0}")]
    InvalidExecutionReceipt(#[from] ExecutionReceiptError),

    #[error("invalid capability grant: {0}")]
    InvalidCapabilityGrant(#[from] SigningError),

    #[error("invalid settlement proof: {0}")]
    InvalidSettlementProof(#[from] SettlementError),

    #[error("task result receipt does not match result")]
    TaskResultReceiptMismatch,

    #[error("duplicate social event id with divergent payload: {event_id}")]
    DuplicateEventConflict { event_id: String },

    #[error("social event id {actual} does not match content hash {expected}")]
    EventIdMismatch { actual: String, expected: String },

    #[error("genesis event for {author} must use seq=0 and prev=None")]
    InvalidChainGenesis { author: Did },

    #[error("event for {author} links to {actual:?}, expected {expected:?}")]
    InvalidChainLink {
        author: Did,
        actual: Option<String>,
        expected: Option<String>,
    },

    #[error(
        "event from {author} has timestamp {timestamp}, which is more than {max_future_skew_secs}s after observed time {observed_at}"
    )]
    EventTimestampTooFarAhead {
        author: Did,
        timestamp: u64,
        observed_at: u64,
        max_future_skew_secs: u64,
    },

    #[error("social event JSON is {actual} bytes, exceeding max {max}")]
    EventTooLarge { actual: usize, max: usize },

    #[error("equivocation proof authors differ: {left} != {right}")]
    EquivocationAuthorMismatch { left: Did, right: Did },

    #[error("equivocation proof seq values differ: {left} != {right}")]
    EquivocationSeqMismatch { left: u64, right: u64 },

    #[error("equivocation proof events are identical: {event_id}")]
    EquivocationEventsIdentical { event_id: String },

    #[error("failed to serialize social event signing payload: {0}")]
    PayloadSerialization(#[from] serde_json::Error),

    #[error("failed to decode social event JSON: {0}")]
    EventDecode(serde_json::Error),
}

/// A signed or unsigned social protocol event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SocialEvent {
    pub id: String,
    pub author: Did,
    pub seq: u64,
    pub prev: Option<String>,
    pub timestamp: u64,
    pub kind: SocialEventKind,
    /// Optional detached Ed25519 signature over [`Self::signing_payload`].
    pub signature: Option<Vec<u8>>,
}

/// Cryptographic evidence that one author signed two incompatible events for
/// the same sequence number.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EquivocationProof {
    pub author: Did,
    pub seq: u64,
    pub event_a: Box<SocialEvent>,
    pub event_b: Box<SocialEvent>,
}

/// Event kinds that form the AI society protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum SocialEventKind {
    /// Publish a verifiable proof that an author forked their own event chain.
    EquivocationObserved { proof: Box<EquivocationProof> },
    /// Publish or refresh an agent's public profile.
    ManifestPublished { manifest: AgentManifest },
    /// Revoke the author's identity in the social layer.
    IdentityRevoked { revocation: IdentityRevocation },
    /// Join a workspace as a social presence event.
    WorkspaceJoined { workspace: WorkspaceId },
    /// Declare or update a subjective relation to another agent.
    RelationDeclared {
        peer: Did,
        relation: RelationKind,
        note: Option<String>,
    },
    /// Record a social memory of an interaction.
    InteractionRecorded { interaction: Interaction },
    /// Create or update a collective.
    CollectiveDeclared {
        collective_id: String,
        name: String,
        purpose: String,
        members: Vec<Did>,
    },
    /// Join a collective as the event author.
    CollectiveJoined { collective_id: String },
    /// Attach a workspace to a collective.
    CollectiveWorkspaceAttached {
        collective_id: String,
        workspace: WorkspaceId,
    },
    /// Publish a proposal inside a collective.
    CollectiveProposalPublished { proposal: CollectiveProposal },
    /// Cast or replace the author's vote on a proposal.
    CollectiveVoteCast { vote: CollectiveVote },
    /// Record an observed collective decision.
    CollectiveDecisionRecorded { decision: CollectiveDecision },
    /// Publish a signed workspace capability grant as social trust metadata.
    CapabilityIssued { grant: CapabilityGrant },
    /// Revoke a previously issued capability token.
    CapabilityRevoked { revocation: CapabilityRevocation },
    /// Record an observed Merkle root for a workspace.
    WorkspaceSnapshotted { snapshot: WorkspaceSnapshot },
    /// Record a command run performed freely in a workspace.
    WorkspaceRunRecorded { run: Box<WorkspaceRun> },
    /// Publish a lightweight goal, need, offer, proposal, or status signal.
    IntentPublished { intent: AgentIntent },
    /// Respond to another agent's published intent.
    IntentResponded { response: IntentResponse },
    /// Publish a task into the social economy.
    TaskPublished { task: TaskSpec },
    /// Offer to perform a task.
    TaskOffered { offer: TaskOffer },
    /// Accept an offer and assign a task.
    TaskAccepted { acceptance: TaskAcceptance },
    /// Cancel a task before completion.
    TaskCancelled { cancellation: TaskCancellation },
    /// Report a task result.
    TaskCompleted { result: TaskResult },
    /// Publish third-party re-execution evidence for a task result.
    TaskExecutionAttested { attestation: ExecutionAttestation },
    /// Dispute a task result or execution claim.
    TaskDisputed { dispute: TaskDispute },
    /// Record a verified economic settlement claim.
    SettlementRecorded { settlement: SettlementRecord },
}

impl SocialEvent {
    pub fn new(author: Did, timestamp: u64, kind: SocialEventKind) -> Self {
        Self::new_chained(author, 0, None, timestamp, kind)
    }

    pub fn new_chained(
        author: Did,
        seq: u64,
        prev: Option<String>,
        timestamp: u64,
        kind: SocialEventKind,
    ) -> Self {
        let id = Self::content_id_for(&author, seq, prev.as_deref(), timestamp, &kind)
            .expect("social event content should serialize");
        Self {
            id,
            author,
            seq,
            prev,
            timestamp,
            kind,
            signature: None,
        }
    }

    /// Deterministic bytes for signing and content addressing.
    ///
    /// The event id and signature are excluded so the id can be the hash of
    /// the payload being signed instead of an independent mutable field.
    pub fn signing_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        Self::signing_payload_for(
            &self.author,
            self.seq,
            self.prev.as_deref(),
            self.timestamp,
            &self.kind,
        )
    }

    pub fn content_id(&self) -> Result<String, serde_json::Error> {
        Self::content_id_for(
            &self.author,
            self.seq,
            self.prev.as_deref(),
            self.timestamp,
            &self.kind,
        )
    }

    fn signing_payload_for(
        author: &Did,
        seq: u64,
        prev: Option<&str>,
        timestamp: u64,
        kind: &SocialEventKind,
    ) -> Result<Vec<u8>, serde_json::Error> {
        #[derive(Serialize)]
        struct Payload<'a> {
            author: &'a Did,
            seq: u64,
            prev: Option<&'a str>,
            timestamp: u64,
            kind: &'a SocialEventKind,
        }

        serde_json::to_vec(&Payload {
            author,
            seq,
            prev,
            timestamp,
            kind,
        })
    }

    fn content_id_for(
        author: &Did,
        seq: u64,
        prev: Option<&str>,
        timestamp: u64,
        kind: &SocialEventKind,
    ) -> Result<String, serde_json::Error> {
        let payload = Self::signing_payload_for(author, seq, prev, timestamp, kind)?;
        Ok(hex::encode(Sha256::digest(payload)))
    }

    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Sign the event with its author's identity.
    pub fn sign(mut self, identity: &NodeIdentity) -> Result<Self, SocialProtocolError> {
        let signer = identity.did().clone();
        if self.author != signer {
            return Err(SocialProtocolError::AuthorSignerMismatch {
                author: self.author,
                signer,
            });
        }

        self.id = self.content_id()?;
        let payload = self.signing_payload()?;
        self.signature = Some(identity.sign(&payload).to_bytes().to_vec());
        Ok(self)
    }

    pub fn verify_content_id(&self) -> Result<(), SocialProtocolError> {
        let expected = self.content_id()?;
        if self.id == expected {
            Ok(())
        } else {
            Err(SocialProtocolError::EventIdMismatch {
                actual: self.id.clone(),
                expected,
            })
        }
    }

    /// Verify that the event signature was produced by `author`.
    pub fn verify_signature(&self) -> Result<(), SocialProtocolError> {
        self.verify_content_id()?;
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

    /// Verify the signature and semantic author claims carried inside the event.
    pub fn validate(&self) -> Result<(), SocialProtocolError> {
        self.verify_signature()?;
        self.validate_author_claims()
    }

    /// Ensure signed events cannot make another DID appear to have acted.
    pub fn validate_author_claims(&self) -> Result<(), SocialProtocolError> {
        match &self.kind {
            SocialEventKind::ManifestPublished { manifest } => {
                self.ensure_subject("manifest", &manifest.did)
            }
            SocialEventKind::IdentityRevoked { revocation } => {
                self.ensure_subject("identity revocation", &revocation.did)
            }
            SocialEventKind::InteractionRecorded { interaction } => {
                self.ensure_subject("interaction", &interaction.from)
            }
            SocialEventKind::TaskPublished { task } => {
                self.ensure_subject("task publication", &task.publisher)
            }
            SocialEventKind::CapabilityIssued { grant } => {
                self.ensure_subject("capability grant", &grant.capability.issuer)?;
                verify_capability(&grant.capability, grant.issued_at)?;
                Ok(())
            }
            SocialEventKind::CapabilityRevoked { revocation } => {
                self.ensure_subject("capability revocation", &revocation.issuer)
            }
            SocialEventKind::WorkspaceSnapshotted { snapshot } => {
                self.ensure_subject("workspace snapshot", &snapshot.actor)
            }
            SocialEventKind::WorkspaceRunRecorded { run } => {
                self.ensure_subject("workspace run", &run.actor)
            }
            SocialEventKind::IntentPublished { intent } => {
                self.ensure_subject("intent", &intent.author)
            }
            SocialEventKind::IntentResponded { response } => {
                self.ensure_subject("intent response", &response.responder)
            }
            SocialEventKind::TaskOffered { offer } => {
                self.ensure_subject("task offer", &offer.bidder)
            }
            SocialEventKind::TaskAccepted { acceptance } => {
                self.ensure_subject("task acceptance", &acceptance.publisher)
            }
            SocialEventKind::TaskCancelled { cancellation } => {
                self.ensure_subject("task cancellation", &cancellation.publisher)
            }
            SocialEventKind::TaskCompleted { result } => {
                self.ensure_subject("task result", &result.executor)?;
                result.validate_receipt()?;
                Ok(())
            }
            SocialEventKind::TaskExecutionAttested { attestation } => {
                self.ensure_subject("task execution attestation", &attestation.attestor)?;
                attestation.verify_signature()?;
                Ok(())
            }
            SocialEventKind::TaskDisputed { dispute } => {
                self.ensure_subject("task dispute", &dispute.disputer)
            }
            SocialEventKind::SettlementRecorded { settlement } => {
                self.ensure_subject("settlement", &settlement.payer)?;
                settlement.validate()?;
                Ok(())
            }
            SocialEventKind::EquivocationObserved { proof } => proof.verify(),
            SocialEventKind::CollectiveDeclared { members, .. } => {
                for member in members {
                    self.ensure_subject("collective membership", member)?;
                }
                Ok(())
            }
            SocialEventKind::CollectiveProposalPublished { proposal } => {
                self.ensure_subject("collective proposal", &proposal.proposer)
            }
            SocialEventKind::CollectiveVoteCast { vote } => {
                self.ensure_subject("collective vote", &vote.voter)
            }
            SocialEventKind::CollectiveDecisionRecorded { decision } => {
                self.ensure_subject("collective decision", &decision.decider)?;
                decision.validate_anchor()?;
                Ok(())
            }
            SocialEventKind::WorkspaceJoined { .. }
            | SocialEventKind::RelationDeclared { .. }
            | SocialEventKind::CollectiveJoined { .. }
            | SocialEventKind::CollectiveWorkspaceAttached { .. } => Ok(()),
        }
    }

    fn ensure_subject(
        &self,
        event: &'static str,
        subject: &Did,
    ) -> Result<(), SocialProtocolError> {
        if subject == &self.author {
            return Ok(());
        }

        Err(SocialProtocolError::AuthorSubjectMismatch {
            event,
            author: self.author.clone(),
            subject: subject.clone(),
        })
    }

    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_json(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

impl EquivocationProof {
    pub fn new(event_a: SocialEvent, event_b: SocialEvent) -> Result<Self, SocialProtocolError> {
        let proof = Self {
            author: event_a.author.clone(),
            seq: event_a.seq,
            event_a: Box::new(event_a),
            event_b: Box::new(event_b),
        };
        proof.verify()?;
        Ok(proof)
    }

    pub fn verify(&self) -> Result<(), SocialProtocolError> {
        self.event_a.validate()?;
        self.event_b.validate()?;
        if self.event_a.author != self.event_b.author {
            return Err(SocialProtocolError::EquivocationAuthorMismatch {
                left: self.event_a.author.clone(),
                right: self.event_b.author.clone(),
            });
        }
        if self.event_a.seq != self.event_b.seq {
            return Err(SocialProtocolError::EquivocationSeqMismatch {
                left: self.event_a.seq,
                right: self.event_b.seq,
            });
        }
        if self.event_a.id == self.event_b.id {
            return Err(SocialProtocolError::EquivocationEventsIdentical {
                event_id: self.event_a.id.clone(),
            });
        }
        if self.author != self.event_a.author || self.seq != self.event_a.seq {
            return Err(SocialProtocolError::EquivocationAuthorMismatch {
                left: self.author.clone(),
                right: self.event_a.author.clone(),
            });
        }
        Ok(())
    }

    pub fn evidence_key(&self) -> String {
        let (left, right) = if self.event_a.id <= self.event_b.id {
            (&self.event_a.id, &self.event_b.id)
        } else {
            (&self.event_b.id, &self.event_a.id)
        };
        format!("{}|{}|{}|{}", self.author, self.seq, left, right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::PermissionSet;
    use nexus_crypto::capability::{
        delegate_capability, sign_capability, sign_capability_with_depth,
    };
    use nexus_crypto::NodeIdentity;
    use nexus_economy::{LightningSettlement, SettlementProof};
    use nexus_runtime::{ProcessOutput, ResourceUsage};
    use sha2::{Digest, Sha256};

    use crate::society::{
        AgentIntent, IntentKind, IntentResponse, IntentResponseKind, InteractionOutcome,
        SettlementRecord, Society,
    };
    use crate::task::{ExecutionAttestation, ExecutionReceipt, TaskResult, TaskSpec};

    fn did(s: &str) -> Did {
        Did::new(format!("did:key:{s}"))
    }

    #[test]
    fn event_json_roundtrip_excludes_signature_from_payload() {
        let author = did("alice");
        let peer = did("bob");
        let event = SocialEvent::new(
            author,
            10,
            SocialEventKind::RelationDeclared {
                peer,
                relation: RelationKind::Collaborator,
                note: Some("works well under autonomy".into()),
            },
        )
        .with_signature(vec![1, 2, 3]);

        let json = event.to_json().unwrap();
        let decoded = SocialEvent::from_json(&json).unwrap();
        assert_eq!(decoded.signature, Some(vec![1, 2, 3]));

        let signed_payload = decoded.signing_payload().unwrap();
        let payload_text = String::from_utf8(signed_payload).unwrap();
        assert!(!payload_text.contains("signature"));
    }

    #[test]
    fn social_event_can_be_applied_to_society() {
        let alice = did("alice");
        let bob = did("bob");
        let mut society = Society::new();

        let relation_event = SocialEvent::new(
            alice.clone(),
            1,
            SocialEventKind::RelationDeclared {
                peer: bob.clone(),
                relation: RelationKind::Collaborator,
                note: None,
            },
        );
        society.apply_event(&relation_event);
        assert_eq!(
            society.edge(&alice, &bob).unwrap().kind,
            RelationKind::Collaborator
        );

        let interaction = Interaction::new(
            alice.clone(),
            bob.clone(),
            None,
            "co-created a workspace",
            InteractionOutcome::Success,
            2,
        );
        society.apply_event(&SocialEvent::new(
            alice.clone(),
            2,
            SocialEventKind::InteractionRecorded { interaction },
        ));
        assert_eq!(society.interaction_count(), 1);
        assert!(society.edge(&alice, &bob).unwrap().score() > 0.5);
    }

    #[test]
    fn event_can_be_signed_and_verified_by_author() {
        let identity = NodeIdentity::generate();
        let event = SocialEvent::new(
            identity.did().clone(),
            42,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([3; 32]),
            },
        )
        .sign(&identity)
        .unwrap();

        event.verify_signature().unwrap();
        assert_eq!(event.signature.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn signing_rejects_author_mismatch() {
        let identity = NodeIdentity::generate();
        let event = SocialEvent::new(
            did("someone-else"),
            42,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([4; 32]),
            },
        );

        let err = event.sign(&identity).unwrap_err();
        assert!(matches!(
            err,
            SocialProtocolError::AuthorSignerMismatch { .. }
        ));
    }

    #[test]
    fn verification_rejects_tampered_event() {
        let identity = NodeIdentity::generate();
        let mut event = SocialEvent::new(
            identity.did().clone(),
            42,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([5; 32]),
            },
        )
        .sign(&identity)
        .unwrap();
        event.timestamp = 43;

        let err = event.verify_signature().unwrap_err();
        assert!(matches!(err, SocialProtocolError::EventIdMismatch { .. }));
    }

    #[test]
    fn verification_requires_signature() {
        let identity = NodeIdentity::generate();
        let event = SocialEvent::new(
            identity.did().clone(),
            42,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([6; 32]),
            },
        );

        let err = event.verify_signature().unwrap_err();
        assert!(matches!(err, SocialProtocolError::MissingSignature));
    }

    #[test]
    fn validation_rejects_task_claim_for_different_author() {
        let attacker = NodeIdentity::generate();
        let publisher = NodeIdentity::generate();
        let task = TaskSpec::new(
            publisher.did().clone(),
            "run borrowed compute",
            "python-exec",
            "python",
            vec!["main.py".into()],
            100,
            999,
            1,
        );
        let event = SocialEvent::new(
            attacker.did().clone(),
            1,
            SocialEventKind::TaskPublished { task },
        )
        .sign(&attacker)
        .unwrap();

        event.verify_signature().unwrap();
        let err = event.validate().unwrap_err();
        assert!(matches!(
            err,
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }

    #[test]
    fn validation_rejects_intent_claim_for_different_author() {
        let attacker = NodeIdentity::generate();
        let author = NodeIdentity::generate();
        let intent = AgentIntent::new(
            author.did().clone(),
            IntentKind::Need,
            "Need workspace reviewer",
            "looking for another AI to inspect this computer",
            Some(WorkspaceId::from_bytes([31; 32])),
            None,
            Some("review".into()),
            vec!["audit".into()],
            10,
            None,
        );
        let event = SocialEvent::new(
            attacker.did().clone(),
            10,
            SocialEventKind::IntentPublished { intent },
        )
        .sign(&attacker)
        .unwrap();

        let err = event.validate().unwrap_err();
        assert!(matches!(
            err,
            SocialProtocolError::AuthorSubjectMismatch {
                event: "intent",
                ..
            }
        ));
    }

    #[test]
    fn validation_rejects_intent_response_claim_for_different_author() {
        let attacker = NodeIdentity::generate();
        let responder = NodeIdentity::generate();
        let response = IntentResponse::new(
            "intent-1",
            responder.did().clone(),
            IntentResponseKind::Interested,
            "I can inspect this workspace",
            Some(WorkspaceId::from_bytes([32; 32])),
            None,
            Some("review".into()),
            None,
            11,
        );
        let event = SocialEvent::new(
            attacker.did().clone(),
            11,
            SocialEventKind::IntentResponded { response },
        )
        .sign(&attacker)
        .unwrap();

        let err = event.validate().unwrap_err();
        assert!(matches!(
            err,
            SocialProtocolError::AuthorSubjectMismatch {
                event: "intent response",
                ..
            }
        ));
    }

    #[test]
    fn validation_rejects_collective_membership_claim_for_another_agent() {
        let author = NodeIdentity::generate();
        let other = NodeIdentity::generate();
        let event = SocialEvent::new(
            author.did().clone(),
            1,
            SocialEventKind::CollectiveDeclared {
                collective_id: "lab".into(),
                name: "Open Lab".into(),
                purpose: "build freely".into(),
                members: vec![author.did().clone(), other.did().clone()],
            },
        )
        .sign(&author)
        .unwrap();

        event.verify_signature().unwrap();
        let err = event.validate().unwrap_err();
        assert!(matches!(
            err,
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }

    #[test]
    fn validation_rejects_collective_governance_claim_for_another_agent() {
        let author = NodeIdentity::generate();
        let other = NodeIdentity::generate();
        let proposal = CollectiveProposal {
            id: "proposal-1".into(),
            collective_id: "lab".into(),
            proposer: other.did().clone(),
            title: "Use shared workspace".into(),
            body: "coordinate execution".into(),
            workspace: None,
            created_at: 1,
            deadline: 0,
        };
        let event = SocialEvent::new(
            author.did().clone(),
            1,
            SocialEventKind::CollectiveProposalPublished { proposal },
        )
        .sign(&author)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));

        let vote = CollectiveVote {
            proposal_id: "proposal-1".into(),
            collective_id: "lab".into(),
            voter: other.did().clone(),
            choice: crate::society::CollectiveVoteChoice::Approve,
            rationale: "looks useful".into(),
            timestamp: 2,
        };
        let event = SocialEvent::new(
            author.did().clone(),
            2,
            SocialEventKind::CollectiveVoteCast { vote },
        )
        .sign(&author)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }

    #[test]
    fn validation_rejects_capability_grant_claim_for_another_issuer() {
        let author = NodeIdentity::generate();
        let issuer = NodeIdentity::generate();
        let subject = NodeIdentity::generate();
        let capability = sign_capability(
            &issuer,
            subject.did(),
            WorkspaceId::from_bytes([9; 32]),
            PermissionSet::READ_WRITE,
            10,
        )
        .unwrap();
        let event = SocialEvent::new(
            author.did().clone(),
            1,
            SocialEventKind::CapabilityIssued {
                grant: CapabilityGrant {
                    capability,
                    issued_at: 1,
                    note: Some("invite into shared workspace".into()),
                },
            },
        )
        .sign(&author)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }

    #[test]
    fn validation_rejects_capability_revocation_for_another_issuer() {
        let author = NodeIdentity::generate();
        let issuer = NodeIdentity::generate();
        let event = SocialEvent::new(
            author.did().clone(),
            1,
            SocialEventKind::CapabilityRevoked {
                revocation: CapabilityRevocation {
                    issuer: issuer.did().clone(),
                    capability_signature_id: "capability-id".into(),
                    reason: Some("rotated access".into()),
                    revoked_at: 1,
                },
            },
        )
        .sign(&author)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }

    #[test]
    fn validation_rejects_identity_revocation_for_another_identity() {
        let author = NodeIdentity::generate();
        let target = NodeIdentity::generate();
        let event = SocialEvent::new(
            author.did().clone(),
            1,
            SocialEventKind::IdentityRevoked {
                revocation: IdentityRevocation {
                    did: target.did().clone(),
                    reason: Some("compromised".into()),
                    revoked_at: 1,
                },
            },
        )
        .sign(&author)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }

    #[test]
    fn validation_rejects_workspace_snapshot_claim_for_another_agent() {
        let author = NodeIdentity::generate();
        let actor = NodeIdentity::generate();
        let event = SocialEvent::new(
            author.did().clone(),
            1,
            SocialEventKind::WorkspaceSnapshotted {
                snapshot: WorkspaceSnapshot {
                    workspace: WorkspaceId::from_bytes([11; 32]),
                    actor: actor.did().clone(),
                    root: nexus_storage::Cid::hash_of(b"snapshot"),
                    label: Some("after run".into()),
                    note: None,
                    timestamp: 1,
                },
            },
        )
        .sign(&author)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }

    #[test]
    fn validation_rejects_workspace_run_claim_for_another_agent() {
        let author = NodeIdentity::generate();
        let actor = NodeIdentity::generate();
        let event = SocialEvent::new(
            author.did().clone(),
            1,
            SocialEventKind::WorkspaceRunRecorded {
                run: Box::new(WorkspaceRun {
                    workspace: WorkspaceId::from_bytes([12; 32]),
                    actor: actor.did().clone(),
                    command: "python".into(),
                    args: vec!["analysis.py".into()],
                    exit_code: 0,
                    stdout: nexus_storage::Cid::hash_of(b"ok"),
                    stderr: nexus_storage::Cid::hash_of(b""),
                    output_root: Some(nexus_storage::Cid::hash_of(b"root")),
                    resources: ResourceUsage::default(),
                    context: None,
                    failure: None,
                    started_at: 1,
                    finished_at: 2,
                    note: Some("autonomous run".into()),
                }),
            },
        )
        .sign(&author)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }

    #[test]
    fn validation_rejects_invalid_capability_grant_signature() {
        let issuer = NodeIdentity::generate();
        let subject = NodeIdentity::generate();
        let mut capability = sign_capability_with_depth(
            &issuer,
            subject.did(),
            WorkspaceId::from_bytes([10; 32]),
            PermissionSet::READ_WRITE,
            10,
            None,
        )
        .unwrap();
        capability.signature[0] ^= 0xff;
        let event = SocialEvent::new(
            issuer.did().clone(),
            1,
            SocialEventKind::CapabilityIssued {
                grant: CapabilityGrant {
                    capability,
                    issued_at: 1,
                    note: None,
                },
            },
        )
        .sign(&issuer)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::InvalidCapabilityGrant(_)
        ));
    }

    #[test]
    fn validation_accepts_delegated_capability_grant_chain() {
        let owner = NodeIdentity::generate();
        let delegate = NodeIdentity::generate();
        let subject = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([13; 32]);
        let parent = sign_capability_with_depth(
            &owner,
            delegate.did(),
            workspace,
            PermissionSet::READ_WRITE,
            100,
            Some(1),
        )
        .unwrap();
        let capability = delegate_capability(
            &delegate,
            parent,
            subject.did(),
            PermissionSet::READ_ONLY,
            90,
            None,
            1,
        )
        .unwrap();
        let event = SocialEvent::new(
            delegate.did().clone(),
            1,
            SocialEventKind::CapabilityIssued {
                grant: CapabilityGrant {
                    capability,
                    issued_at: 1,
                    note: Some("delegated invite".into()),
                },
            },
        )
        .sign(&delegate)
        .unwrap();

        assert!(event.validate().is_ok());
    }

    #[test]
    fn validation_rejects_task_dispute_claim_for_another_agent() {
        let author = NodeIdentity::generate();
        let other = NodeIdentity::generate();
        let event = SocialEvent::new(
            author.did().clone(),
            1,
            SocialEventKind::TaskDisputed {
                dispute: TaskDispute {
                    task_id: "task-1".into(),
                    disputer: other.did().clone(),
                    target: author.did().clone(),
                    claim_id: None,
                    reason: "receipt does not match observed output".into(),
                    evidence: Some("audit:1".into()),
                    timestamp: 1,
                },
            },
        )
        .sign(&author)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }

    #[test]
    fn validation_rejects_task_acceptance_or_cancel_claim_for_another_agent() {
        let author = NodeIdentity::generate();
        let publisher = NodeIdentity::generate();
        let worker = NodeIdentity::generate();
        let accepted = SocialEvent::new(
            author.did().clone(),
            1,
            SocialEventKind::TaskAccepted {
                acceptance: TaskAcceptance {
                    task_id: "task-1".into(),
                    publisher: publisher.did().clone(),
                    bidder: worker.did().clone(),
                    price: 10,
                    accepted_at: 1,
                },
            },
        )
        .sign(&author)
        .unwrap();

        assert!(matches!(
            accepted.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));

        let cancelled = SocialEvent::new(
            author.did().clone(),
            2,
            SocialEventKind::TaskCancelled {
                cancellation: TaskCancellation {
                    task_id: "task-1".into(),
                    publisher: publisher.did().clone(),
                    reason: "changed priorities".into(),
                    cancelled_at: 2,
                },
            },
        )
        .sign(&author)
        .unwrap();

        assert!(matches!(
            cancelled.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }

    #[test]
    fn validation_accepts_task_completed_with_signed_receipt() {
        let executor = NodeIdentity::generate();
        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"done".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let receipt = ExecutionReceipt::from_process_output(
            "task-1",
            executor.did().clone(),
            None,
            "echo",
            vec!["done".into()],
            &output,
            None,
            10,
            11,
        )
        .sign(&executor)
        .unwrap();
        let result = TaskResult {
            task_id: "task-1".into(),
            executor: executor.did().clone(),
            success: true,
            exit_code: 0,
            stdout: "done".into(),
            stderr: String::new(),
            actual_cost: 1,
            error: None,
            receipt: Some(Box::new(receipt)),
            attestations: Vec::new(),
        };

        let event = SocialEvent::new(
            executor.did().clone(),
            12,
            SocialEventKind::TaskCompleted { result },
        )
        .sign(&executor)
        .unwrap();

        event.validate().unwrap();
    }

    #[test]
    fn validation_accepts_task_execution_attestation_by_attestor() {
        let executor = NodeIdentity::generate();
        let attestor = NodeIdentity::generate();
        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"done".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let receipt = ExecutionReceipt::from_process_output(
            "task-1",
            executor.did().clone(),
            None,
            "echo",
            vec!["done".into()],
            &output,
            None,
            10,
            11,
        )
        .sign(&executor)
        .unwrap();
        let attestation = ExecutionAttestation::from_process_output(
            &receipt,
            attestor.did().clone(),
            &output,
            None,
            12,
        )
        .sign(&attestor)
        .unwrap();

        let event = SocialEvent::new(
            attestor.did().clone(),
            12,
            SocialEventKind::TaskExecutionAttested { attestation },
        )
        .sign(&attestor)
        .unwrap();

        event.validate().unwrap();
    }

    #[test]
    fn validation_rejects_task_execution_attestation_for_another_attestor() {
        let executor = NodeIdentity::generate();
        let attestor = NodeIdentity::generate();
        let author = NodeIdentity::generate();
        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"done".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let receipt = ExecutionReceipt::from_process_output(
            "task-1",
            executor.did().clone(),
            None,
            "echo",
            vec!["done".into()],
            &output,
            None,
            10,
            11,
        )
        .sign(&executor)
        .unwrap();
        let attestation = ExecutionAttestation::from_process_output(
            &receipt,
            attestor.did().clone(),
            &output,
            None,
            12,
        )
        .sign(&attestor)
        .unwrap();

        let event = SocialEvent::new(
            author.did().clone(),
            12,
            SocialEventKind::TaskExecutionAttested { attestation },
        )
        .sign(&author)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }

    #[test]
    fn validation_rejects_task_completed_with_mismatched_receipt() {
        let executor = NodeIdentity::generate();
        let output = ProcessOutput {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let receipt = ExecutionReceipt::from_process_output(
            "task-1",
            executor.did().clone(),
            None,
            "true",
            Vec::new(),
            &output,
            None,
            10,
            11,
        )
        .sign(&executor)
        .unwrap();
        let result = TaskResult {
            task_id: "task-2".into(),
            executor: executor.did().clone(),
            success: true,
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            actual_cost: 1,
            error: None,
            receipt: Some(Box::new(receipt)),
            attestations: Vec::new(),
        };

        let event = SocialEvent::new(
            executor.did().clone(),
            12,
            SocialEventKind::TaskCompleted { result },
        )
        .sign(&executor)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::InvalidExecutionReceipt(_)
        ));
    }

    #[test]
    fn validation_accepts_settlement_record_with_valid_proof() {
        let payer = NodeIdentity::generate();
        let payee = NodeIdentity::generate();
        let preimage = [11u8; 32];
        let settlement = SettlementRecord {
            id: "settlement-1".into(),
            task_id: Some("task-1".into()),
            claim_id: Some("claim-1".into()),
            payer: payer.did().clone(),
            payee: payee.did().clone(),
            amount: 100,
            proof: SettlementProof::Lightning(LightningSettlement {
                amount_msat: 100_000,
                payment_hash_hex: hex::encode(Sha256::digest(preimage)),
                preimage_hex: hex::encode(preimage),
            }),
            settled_at: 50,
        };

        let event = SocialEvent::new(
            payer.did().clone(),
            51,
            SocialEventKind::SettlementRecorded { settlement },
        )
        .sign(&payer)
        .unwrap();

        event.validate().unwrap();
    }

    #[test]
    fn validation_rejects_settlement_record_for_another_payer() {
        let payer = NodeIdentity::generate();
        let payee = NodeIdentity::generate();
        let observer = NodeIdentity::generate();
        let preimage = [12u8; 32];
        let settlement = SettlementRecord {
            id: "settlement-1".into(),
            task_id: None,
            claim_id: None,
            payer: payer.did().clone(),
            payee: payee.did().clone(),
            amount: 100,
            proof: SettlementProof::Lightning(LightningSettlement {
                amount_msat: 100_000,
                payment_hash_hex: hex::encode(Sha256::digest(preimage)),
                preimage_hex: hex::encode(preimage),
            }),
            settled_at: 50,
        };

        let event = SocialEvent::new(
            observer.did().clone(),
            51,
            SocialEventKind::SettlementRecorded { settlement },
        )
        .sign(&observer)
        .unwrap();

        assert!(matches!(
            event.validate().unwrap_err(),
            SocialProtocolError::AuthorSubjectMismatch { .. }
        ));
    }
}
