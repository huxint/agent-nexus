//! Social graph for autonomous agents.
//!
//! This layer is intentionally not a sandbox. It gives agents a shared social
//! substrate: identity, relationships, collectives, memories of interaction,
//! and subjective trust. Runtime freedom stays below this layer; consequences,
//! preference, reputation, and cooperation live here.

use std::collections::{HashMap, HashSet};

use nexus_core::{Capability, Did, WorkspaceId};
use nexus_economy::{
    AuthorityAnchor, AuthorityKind, ReputationScore, SettlementError, SettlementProof,
};
use nexus_runtime::ResourceUsage;
use nexus_storage::Cid;
use serde::{Deserialize, Serialize};

use crate::manifest::{AgentManifest, CapabilityDecl};
use crate::protocol::{EquivocationProof, SocialEvent, SocialEventKind};
use crate::task::{
    ExecutionAttestation, Task, TaskAcceptance, TaskCancellation, TaskOffer, TaskResult, TaskState,
};

fn acceptance_key(acceptance: &TaskAcceptance) -> String {
    format!(
        "{}|{}|{}|{}",
        acceptance.publisher, acceptance.bidder, acceptance.price, acceptance.accepted_at
    )
}

fn cancellation_key(cancellation: &TaskCancellation) -> String {
    format!(
        "{}|{}|{}",
        cancellation.publisher, cancellation.reason, cancellation.cancelled_at
    )
}

/// Stable social identifier for a task result claim.
///
/// The ID commits to the full [`TaskResult`] content rather than only stdout,
/// stderr, or output roots. This lets later disputes and governance decisions
/// point at the exact execution claim they are judging.
pub fn task_result_claim_id(result: &TaskResult) -> String {
    let bytes = serde_json::to_vec(result).unwrap_or_else(|_| result.task_id.as_bytes().to_vec());
    hex::encode(Cid::hash_of(&bytes).as_bytes())
}

pub fn random_social_id() -> String {
    use rand::RngCore;

    let mut id_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    hex::encode(id_bytes)
}

fn task_dispute_key(dispute: &TaskDispute) -> String {
    format!(
        "{}|{}|{}|{}",
        dispute.task_id,
        dispute.disputer,
        dispute.target,
        dispute.claim_id.as_deref().unwrap_or_default()
    )
}

fn execution_attestation_key(attestation: &ExecutionAttestation) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        attestation.task_id,
        attestation.executor,
        attestation.attestor,
        attestation.receipt_signature_hex,
        hex::encode(attestation.stdout_cid.as_bytes()),
        hex::encode(attestation.stderr_cid.as_bytes())
    )
}

fn settlement_key(settlement: &SettlementRecord) -> String {
    settlement.id.clone()
}

fn checkpoint_subject_matches_settlement(subject: &str, settlement: &SettlementRecord) -> bool {
    subject == format!("settlement:{}", settlement.id)
        || settlement.task_id.as_ref().is_some_and(|task_id| {
            subject == format!("task:{task_id}:settlement:{}", settlement.id)
        })
        || settlement.claim_id.as_ref().is_some_and(|claim_id| {
            subject == format!("claim:{claim_id}:settlement:{}", settlement.id)
        })
}

fn anchor_collective_id(anchor: &AuthorityAnchor) -> Option<&str> {
    let locator = anchor.locator.as_deref()?;
    let (_, after_collective) = locator.split_once("collective:")?;
    let collective_id = after_collective
        .split(['/', '#', '?', ' '])
        .next()
        .unwrap_or_default();
    (!collective_id.is_empty()).then_some(collective_id)
}

fn decision_anchor_subject_matches(
    anchor: &AuthorityAnchor,
    decision: &CollectiveDecision,
) -> bool {
    let Some(locator) = anchor.locator.as_deref() else {
        return true;
    };
    locator.contains(&format!("proposal:{}", decision.proposal_id))
        || decision
            .task_id
            .as_ref()
            .is_some_and(|task_id| locator.contains(&format!("task:{task_id}")))
        || decision
            .claim_id
            .as_ref()
            .is_some_and(|claim_id| locator.contains(&format!("claim:{claim_id}")))
}

fn capability_grant_key(grant: &CapabilityGrant) -> String {
    format!(
        "{}|{}|{}|{}",
        grant.capability.workspace,
        grant.capability.issuer,
        grant.capability.subject,
        grant.capability.expires_at
    )
}

pub fn capability_signature_id(signature: &[u8]) -> String {
    hex::encode(Cid::hash_of(signature).as_bytes())
}

fn workspace_snapshot_key(snapshot: &WorkspaceSnapshot) -> String {
    format!(
        "{}|{}|{}|{}",
        snapshot.workspace, snapshot.actor, snapshot.root, snapshot.timestamp
    )
}

fn workspace_ownership_claim_key(claim: &WorkspaceOwnershipClaim) -> String {
    format!(
        "{}|{}|{}|{}",
        claim.workspace,
        claim.owner,
        claim
            .previous_owner
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        claim
            .root
            .map(|root| hex::encode(root.as_bytes()))
            .unwrap_or_default()
    )
}

fn workspace_run_key(run: &WorkspaceRun) -> String {
    let bytes = serde_json::to_vec(run).unwrap_or_else(|_| {
        format!(
            "{}|{}|{}|{}|{}",
            run.workspace, run.actor, run.command, run.started_at, run.finished_at
        )
        .into_bytes()
    });
    hex::encode(Cid::hash_of(&bytes).as_bytes())
}

fn intent_key(intent: &AgentIntent) -> String {
    intent.id.clone()
}

fn intent_response_key(response: &IntentResponse) -> String {
    response.id.clone()
}

fn collective_proposal_key(collective_id: &str, proposal_id: &str) -> String {
    format!("{collective_id}|{proposal_id}")
}

// ---------------------------------------------------------------------------
// Relationship model
// ---------------------------------------------------------------------------

/// A broad social relation between two agents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationKind {
    /// General awareness without established history.
    Acquaintance,
    /// Repeated positive collaboration.
    Collaborator,
    /// Capability provider/consumer relationship.
    ServiceProvider,
    /// Explicit mentor/teacher relationship.
    Mentor,
    /// Shared stewardship of a workspace or collective.
    CoOwner,
    /// Conflicting goals or unresolved dispute.
    Rival,
    /// Locally muted/avoided peer.
    Blocked,
}

/// A directed, subjective social edge: `from` has a view of `to`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SocialEdge {
    pub from: Did,
    pub to: Did,
    pub kind: RelationKind,
    /// Subjective trust, 0.0 to 1.0.
    pub trust: f64,
    /// Affinity captures preference/compatibility, 0.0 to 1.0.
    pub affinity: f64,
    /// Successful interactions seen by `from`.
    pub successes: u64,
    /// Failed or disputed interactions seen by `from`.
    pub failures: u64,
    pub created_at: u64,
    pub updated_at: u64,
    pub notes: Vec<String>,
}

impl SocialEdge {
    pub fn new(from: Did, to: Did, kind: RelationKind, now: u64) -> Self {
        Self {
            from,
            to,
            kind,
            trust: 0.5,
            affinity: 0.5,
            successes: 0,
            failures: 0,
            created_at: now,
            updated_at: now,
            notes: Vec::new(),
        }
    }

    pub fn score(&self) -> f64 {
        if self.kind == RelationKind::Blocked {
            return 0.0;
        }

        let total = self.successes + self.failures;
        let reliability = if total == 0 {
            0.5
        } else {
            self.successes as f64 / total as f64
        };

        self.trust * 0.45 + self.affinity * 0.25 + reliability * 0.30
    }

    fn record_outcome(&mut self, outcome: InteractionOutcome, now: u64) {
        match outcome {
            InteractionOutcome::Success => {
                self.successes += 1;
                self.trust = ema(self.trust, 1.0);
                self.affinity = ema(self.affinity, 0.8);
            }
            InteractionOutcome::Neutral => {
                self.affinity = ema(self.affinity, 0.5);
            }
            InteractionOutcome::Failure => {
                self.failures += 1;
                self.trust = ema(self.trust, 0.15);
                self.affinity = ema(self.affinity, 0.25);
            }
            InteractionOutcome::Dispute => {
                self.failures += 1;
                self.trust = ema(self.trust, 0.0);
                self.affinity = ema(self.affinity, 0.1);
            }
        }
        self.updated_at = now;
    }
}

/// Result of a meaningful interaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteractionOutcome {
    Success,
    Neutral,
    Failure,
    Dispute,
}

/// Append-only social memory event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Interaction {
    pub id: String,
    pub from: Did,
    pub to: Did,
    pub workspace: Option<WorkspaceId>,
    pub topic: String,
    pub outcome: InteractionOutcome,
    pub timestamp: u64,
    pub evidence: Option<String>,
}

/// A group, institution, or temporary working collective.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Collective {
    pub id: String,
    pub name: String,
    pub purpose: String,
    pub members: HashSet<Did>,
    pub workspaces: HashSet<WorkspaceId>,
    pub created_at: u64,
}

/// A proposal made inside a collective.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectiveProposal {
    pub id: String,
    pub collective_id: String,
    pub proposer: Did,
    pub title: String,
    pub body: String,
    pub workspace: Option<WorkspaceId>,
    pub created_at: u64,
    pub deadline: u64,
}

/// A subjective vote on a collective proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CollectiveVoteChoice {
    Approve,
    Reject,
    Abstain,
    Block,
}

/// The latest vote by one agent on one proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectiveVote {
    pub proposal_id: String,
    pub collective_id: String,
    pub voter: Did,
    pub choice: CollectiveVoteChoice,
    pub rationale: String,
    pub timestamp: u64,
}

/// Whether a social fact is only signed by its claimant or independently anchored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactTruthStatus {
    Claimed,
    Anchored,
}

/// A signed statement that an agent owns a workspace.
///
/// This is social truth metadata: it distinguishes "this node has a local
/// copy" from "this identity claims stewardship of the workspace". Anchors can
/// later upgrade that claim into a witnessed fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceOwnershipClaim {
    pub workspace: WorkspaceId,
    pub owner: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_owner: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<Cid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<AuthorityAnchor>,
    pub claimed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceOwnershipFact {
    pub claim: WorkspaceOwnershipClaim,
    pub truth_status: FactTruthStatus,
}

/// Possible outcome of a collective governance decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CollectiveDecisionOutcome {
    Accepted,
    Rejected,
    Deferred,
    Disputed,
}

/// A recorded decision for a collective proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectiveDecision {
    pub proposal_id: String,
    pub collective_id: String,
    pub decider: Did,
    pub outcome: CollectiveDecisionOutcome,
    /// Optional task this decision is judging.
    #[serde(default)]
    pub task_id: Option<String>,
    /// Optional exact result claim this decision is judging.
    #[serde(default)]
    pub claim_id: Option<String>,
    /// Optional agent whose claim or conduct is being judged.
    #[serde(default)]
    pub target: Option<Did>,
    /// Optional authority evidence that turns this from a signed claim into a
    /// witnessed collective fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<AuthorityAnchor>,
    pub reason: String,
    pub timestamp: u64,
}

impl CollectiveDecision {
    pub fn validate_anchor(&self) -> Result<(), SettlementError> {
        if let Some(anchor) = &self.anchor {
            anchor.validate()?;
        }
        Ok(())
    }
}

/// A governance decision that has been anchored to a task or exact result claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskClaimJudgment {
    pub collective_id: String,
    pub proposal_id: String,
    pub decider: Did,
    pub outcome: CollectiveDecisionOutcome,
    pub task_id: Option<String>,
    pub claim_id: Option<String>,
    pub target: Option<Did>,
    pub truth_status: FactTruthStatus,
    pub reason: String,
    pub timestamp: u64,
}

/// A subjective dispute against a task result or execution claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDispute {
    pub task_id: String,
    pub disputer: Did,
    pub target: Did,
    /// Optional exact task result claim this dispute is judging.
    #[serde(default)]
    pub claim_id: Option<String>,
    pub reason: String,
    pub evidence: Option<String>,
    pub timestamp: u64,
}

/// A signed claim that a task, claim, or relationship was economically settled.
///
/// Recording a settlement does not itself manufacture reputation. It gives the
/// society layer a verifiable economic fact that other adoption rules can
/// require before applying credit, rank, or governance consequences.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub id: String,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub claim_id: Option<String>,
    pub payer: Did,
    pub payee: Did,
    pub amount: u64,
    pub proof: SettlementProof,
    pub settled_at: u64,
}

impl SettlementRecord {
    pub fn validate(&self) -> Result<(), SettlementError> {
        self.proof
            .validate_for_settlement(&self.payer, &self.payee, self.amount)
    }

    pub fn truth_status(&self) -> FactTruthStatus {
        match &self.proof {
            SettlementProof::AnchoredCheckpoint(proof) if proof.validate().is_ok() => {
                FactTruthStatus::Anchored
            }
            _ => FactTruthStatus::Claimed,
        }
    }

    pub fn authority_anchor(&self) -> Option<&AuthorityAnchor> {
        match &self.proof {
            SettlementProof::AnchoredCheckpoint(proof) => Some(&proof.anchor),
            _ => None,
        }
    }

    pub fn checkpoint_subject(&self) -> Option<&str> {
        match &self.proof {
            SettlementProof::AnchoredCheckpoint(proof) => Some(proof.checkpoint.subject.as_str()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TaskResultClaim {
    result: TaskResult,
    timestamp: u64,
}

/// A capability provider recommended from the local society view.
///
/// This is advisory social intelligence, not an enforcement gate: agents can
/// still choose any peer, but the society layer can explain who appears able,
/// affordable, and socially reliable for a requested capability.
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderRecommendation {
    pub did: Did,
    pub name: String,
    pub capability: CapabilityDecl,
    pub social_score: f64,
    pub reputation_score: f64,
    /// How strongly this provider is reachable from the requester's local
    /// trust graph. Unknown or disconnected peers keep reputation neutral.
    pub reachability_score: f64,
    /// Whether this recommendation has either local trust reachability or an
    /// independently anchored external witness behind high-confidence ranking.
    pub high_trust_eligible: bool,
    /// Fraction of strong praise that appears to come from a closed, locally
    /// unreachable mutual-praise cluster.
    pub sybil_cluster_score: f64,
    /// Score derived from collective judgments about the provider's claims.
    pub governance_score: f64,
    /// Recent collective judgments that explain the governance score.
    pub governance_signals: Vec<GovernanceSignal>,
    pub verified_capability: Option<VerifiedCapability>,
    pub price_per_unit: u64,
    pub ranking_score: f64,
}

/// Evidence that an agent has successfully performed a declared capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCapability {
    pub name: String,
    pub successful_tasks: usize,
    pub independently_attested_tasks: usize,
    pub latest_task_id: String,
    pub latest_observed_at: u64,
}

/// An intent that appears useful for an agent to notice or answer.
///
/// This is a local discovery aid, not a scheduler. The society layer only
/// explains why an open social signal may fit the agent's capabilities,
/// workspace context, relationship graph, and declared preferences.
#[derive(Clone, Debug, PartialEq)]
pub struct IntentRecommendation {
    pub intent: AgentIntent,
    pub author_name: Option<String>,
    pub capability_score: f64,
    pub workspace_score: f64,
    pub social_score: f64,
    pub reputation_score: f64,
    pub response_score: f64,
    pub preference_score: f64,
    pub response_count: usize,
    pub fulfilled: bool,
    pub ranking_score: f64,
    pub reasons: Vec<String>,
    pub actions: Vec<IntentActionPlan>,
}

/// A draft social action an agent may choose after reading an intent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IntentActionPlan {
    pub kind: IntentActionKind,
    pub event_hint: String,
    pub intent_id: String,
    pub actor: Did,
    pub peer: Did,
    pub title: String,
    pub body: String,
    pub confidence: f64,
    pub workspace: Option<WorkspaceId>,
    pub task_id: Option<String>,
    pub capability: Option<String>,
    pub response_kind: Option<IntentResponseKind>,
    pub suggested_price: Option<u64>,
    pub estimated_time_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentActionKind {
    RespondIntent,
    OfferTask,
    JoinWorkspace,
    ProposeCollective,
}

/// A compact explanation of a collective governance decision affecting a provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceSignal {
    pub collective_id: String,
    pub proposal_id: String,
    pub decider: Did,
    pub outcome: CollectiveDecisionOutcome,
    pub task_id: Option<String>,
    pub claim_id: Option<String>,
    pub truth_status: FactTruthStatus,
    pub reason: String,
    pub timestamp: u64,
}

/// A signed workspace capability visible to the AI society graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub capability: Capability,
    pub issued_at: u64,
    pub note: Option<String>,
}

/// A signed social fact that revokes a previously issued capability token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityRevocation {
    pub issuer: Did,
    pub capability_signature_id: String,
    pub reason: Option<String>,
    pub revoked_at: u64,
}

/// A signed social fact that marks an identity as revoked.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityRevocation {
    pub did: Did,
    pub reason: Option<String>,
    pub revoked_at: u64,
}

/// A signed claim that an agent observed or created a workspace snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    pub workspace: WorkspaceId,
    pub actor: Did,
    pub root: Cid,
    pub label: Option<String>,
    pub note: Option<String>,
    pub timestamp: u64,
}

/// Non-secret execution context for a free workspace run.
///
/// The context records enough to replay or audit how a command was invoked,
/// while intentionally omitting environment variable values.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRunContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<WorkspaceRunStdin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl WorkspaceRunContext {
    pub fn is_empty(&self) -> bool {
        self.working_dir.is_none()
            && self.env_keys.is_empty()
            && self.stdin.is_none()
            && self.timeout_ms.is_none()
    }
}

/// Content-addressed stdin evidence for a workspace run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRunStdin {
    pub bytes: u64,
    pub cid: Cid,
}

/// Error metadata for a workspace run attempt that did not produce process
/// output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRunFailure {
    pub kind: String,
    pub message: String,
}

/// A signed claim that an agent executed a command in a free workspace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceRun {
    pub workspace: WorkspaceId,
    pub actor: Did,
    pub command: String,
    pub args: Vec<String>,
    pub exit_code: i32,
    pub stdout: Cid,
    pub stderr: Cid,
    pub output_root: Option<Cid>,
    pub resources: ResourceUsage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<WorkspaceRunContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<WorkspaceRunFailure>,
    pub started_at: u64,
    pub finished_at: u64,
    pub note: Option<String>,
}

/// A signed declaration of what an agent wants, needs, offers, or proposes.
///
/// Intents are lightweight social signals: they do not assign work, enforce
/// permissions, or require a central scheduler. Other agents can independently
/// read them and decide whether to respond, collaborate, ignore, or govern.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIntent {
    pub id: String,
    pub author: Did,
    pub kind: IntentKind,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub workspace: Option<WorkspaceId>,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub capability: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentKind {
    Goal,
    Need,
    Offer,
    Proposal,
    Status,
}

/// A signed response to another agent's intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentResponse {
    pub id: String,
    pub intent_id: String,
    pub responder: Did,
    pub kind: IntentResponseKind,
    pub body: String,
    #[serde(default)]
    pub workspace: Option<WorkspaceId>,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub capability: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    pub created_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentResponseKind {
    Interested,
    Accept,
    Decline,
    Counter,
    Fulfilled,
}

impl AgentIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        author: Did,
        kind: IntentKind,
        title: impl Into<String>,
        body: impl Into<String>,
        workspace: Option<WorkspaceId>,
        task_id: Option<String>,
        capability: Option<String>,
        tags: Vec<String>,
        created_at: u64,
        expires_at: Option<u64>,
    ) -> Self {
        Self {
            id: random_social_id(),
            author,
            kind,
            title: title.into(),
            body: body.into(),
            workspace,
            task_id,
            capability,
            tags,
            created_at,
            expires_at,
        }
    }
}

impl IntentResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: impl Into<String>,
        responder: Did,
        kind: IntentResponseKind,
        body: impl Into<String>,
        workspace: Option<WorkspaceId>,
        task_id: Option<String>,
        capability: Option<String>,
        evidence: Option<String>,
        created_at: u64,
    ) -> Self {
        Self {
            id: random_social_id(),
            intent_id: intent_id.into(),
            responder,
            kind,
            body: body.into(),
            workspace,
            task_id,
            capability,
            evidence,
            created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Society graph
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Society {
    agents: HashSet<Did>,
    #[serde(default)]
    identity_revocations: HashMap<Did, IdentityRevocation>,
    manifests: HashMap<Did, AgentManifest>,
    edges: HashMap<(Did, Did), SocialEdge>,
    #[serde(default)]
    reputations: HashMap<(Did, Did), ReputationScore>,
    interactions: Vec<Interaction>,
    collectives: HashMap<String, Collective>,
    #[serde(default)]
    collective_proposals: HashMap<String, CollectiveProposal>,
    #[serde(default)]
    collective_votes: HashMap<String, HashMap<Did, CollectiveVote>>,
    #[serde(default)]
    collective_decisions: HashMap<String, CollectiveDecision>,
    #[serde(default)]
    workspace_members: HashMap<WorkspaceId, HashSet<Did>>,
    #[serde(default)]
    agent_workspaces: HashMap<Did, HashSet<WorkspaceId>>,
    #[serde(default)]
    capability_grants: HashMap<String, CapabilityGrant>,
    #[serde(default)]
    capability_revocations: HashMap<String, CapabilityRevocation>,
    #[serde(default)]
    workspace_snapshots: HashMap<String, WorkspaceSnapshot>,
    #[serde(default)]
    workspace_ownership_claims: HashMap<String, WorkspaceOwnershipClaim>,
    #[serde(default)]
    workspace_current_owners: HashMap<WorkspaceId, Did>,
    #[serde(default)]
    workspace_runs: HashMap<String, WorkspaceRun>,
    #[serde(default)]
    intents: HashMap<String, AgentIntent>,
    #[serde(default)]
    intent_responses: HashMap<String, IntentResponse>,
    tasks: HashMap<String, Task>,
    task_offers: HashMap<String, Vec<TaskOffer>>,
    #[serde(default)]
    task_acceptances: HashMap<String, HashMap<String, TaskAcceptance>>,
    #[serde(default)]
    task_cancellations: HashMap<String, HashMap<String, TaskCancellation>>,
    task_results: HashMap<String, TaskResult>,
    #[serde(default)]
    task_result_claims: HashMap<String, HashMap<String, TaskResultClaim>>,
    #[serde(default)]
    task_execution_attestations: HashMap<String, HashMap<String, ExecutionAttestation>>,
    #[serde(default)]
    task_disputes: HashMap<String, TaskDispute>,
    #[serde(default)]
    settlements: HashMap<String, SettlementRecord>,
    #[serde(default)]
    applied_task_results: HashSet<String>,
    #[serde(default)]
    equivocations: HashMap<Did, Vec<EquivocationProof>>,
}

impl Society {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    pub fn manifest_count(&self) -> usize {
        self.manifests.len()
    }

    pub fn interaction_count(&self) -> usize {
        self.interactions.len()
    }

    pub fn interactions(&self) -> &[Interaction] {
        &self.interactions
    }

    pub fn settlements(&self) -> Vec<&SettlementRecord> {
        let mut settlements: Vec<&SettlementRecord> = self.settlements.values().collect();
        settlements.sort_by(|a, b| {
            a.settled_at
                .cmp(&b.settled_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        settlements
    }

    pub fn is_equivocating(&self, author: &Did) -> bool {
        self.equivocations
            .get(author)
            .is_some_and(|proofs| !proofs.is_empty())
    }

    pub fn equivocation_proofs(&self) -> Vec<&EquivocationProof> {
        let mut proofs = self
            .equivocations
            .values()
            .flat_map(|proofs| proofs.iter())
            .collect::<Vec<_>>();
        proofs.sort_by(|a, b| {
            a.author
                .to_string()
                .cmp(&b.author.to_string())
                .then_with(|| a.seq.cmp(&b.seq))
                .then_with(|| a.evidence_key().cmp(&b.evidence_key()))
        });
        proofs
    }

    pub fn agent_equivocations(&self, author: &Did) -> Vec<&EquivocationProof> {
        let mut proofs = self
            .equivocations
            .get(author)
            .map(|proofs| proofs.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        proofs.sort_by(|a, b| {
            a.seq
                .cmp(&b.seq)
                .then_with(|| a.evidence_key().cmp(&b.evidence_key()))
        });
        proofs
    }

    pub fn settlement(&self, id: &str) -> Option<&SettlementRecord> {
        self.settlements.get(id)
    }

    pub fn settlement_truth_status(&self, settlement: &SettlementRecord) -> FactTruthStatus {
        if self.settlement_anchor_valid(settlement) {
            FactTruthStatus::Anchored
        } else {
            FactTruthStatus::Claimed
        }
    }

    pub fn task_settlements(&self, task_id: &str) -> Vec<&SettlementRecord> {
        let mut settlements: Vec<&SettlementRecord> = self
            .settlements
            .values()
            .filter(|settlement| settlement.task_id.as_deref() == Some(task_id))
            .collect();
        settlements.sort_by(|a, b| {
            a.settled_at
                .cmp(&b.settled_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        settlements
    }

    pub fn agent_interactions(&self, agent: &Did) -> Vec<&Interaction> {
        let mut interactions: Vec<&Interaction> = self
            .interactions
            .iter()
            .filter(|interaction| interaction.from == *agent || interaction.to == *agent)
            .collect();
        interactions.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id)));
        interactions
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    pub fn register_agent(&mut self, did: Did) {
        self.agents.insert(did);
    }

    pub fn has_agent(&self, did: &Did) -> bool {
        self.agents.contains(did)
    }

    pub fn agents(&self) -> Vec<&Did> {
        let mut agents: Vec<&Did> = self.agents.iter().collect();
        agents.sort_by_key(|did| did.to_string());
        agents
    }

    pub fn record_identity_revocation(&mut self, revocation: IdentityRevocation) {
        self.register_agent(revocation.did.clone());
        self.identity_revocations
            .entry(revocation.did.clone())
            .or_insert(revocation);
    }

    pub fn identity_revocation(&self, did: &Did) -> Option<&IdentityRevocation> {
        self.identity_revocations.get(did)
    }

    pub fn identity_revocations(&self) -> Vec<&IdentityRevocation> {
        let mut revocations: Vec<&IdentityRevocation> =
            self.identity_revocations.values().collect();
        revocations.sort_by(|a, b| {
            a.revoked_at
                .cmp(&b.revoked_at)
                .then_with(|| a.did.to_string().cmp(&b.did.to_string()))
        });
        revocations
    }

    pub fn is_identity_revoked(&self, did: &Did) -> bool {
        self.identity_revocations.contains_key(did)
    }

    pub fn agent_manifest(&self, did: &Did) -> Option<&AgentManifest> {
        self.manifests.get(did)
    }

    pub fn manifests(&self) -> impl Iterator<Item = &AgentManifest> {
        self.manifests.values()
    }

    pub fn agent_verified_capabilities(&self, agent: &Did) -> Vec<VerifiedCapability> {
        let mut capabilities: HashMap<String, VerifiedCapability> = HashMap::new();

        for result in self.task_results.values() {
            if result.executor != *agent || !result.success {
                continue;
            }
            let Some(task) = self.tasks.get(&result.task_id) else {
                continue;
            };
            if task.assigned_to.as_ref() != Some(agent) {
                continue;
            }
            let Some(receipt) = result.receipt.as_deref() else {
                continue;
            };
            if receipt.verify_signature().is_err()
                || !task_result_matches_task_commitment(result, task)
            {
                continue;
            }

            let matching_attestations = self.task_result_attestations(result).len();
            let evidence = capabilities
                .entry(task.required_capability.clone())
                .or_insert_with(|| VerifiedCapability {
                    name: task.required_capability.clone(),
                    successful_tasks: 0,
                    independently_attested_tasks: 0,
                    latest_task_id: result.task_id.clone(),
                    latest_observed_at: receipt.finished_at,
                });

            evidence.successful_tasks += 1;
            if matching_attestations > 0 {
                evidence.independently_attested_tasks += 1;
            }
            if receipt.finished_at > evidence.latest_observed_at
                || (receipt.finished_at == evidence.latest_observed_at
                    && result.task_id < evidence.latest_task_id)
            {
                evidence.latest_task_id = result.task_id.clone();
                evidence.latest_observed_at = receipt.finished_at;
            }
        }

        let mut capabilities: Vec<VerifiedCapability> = capabilities.into_values().collect();
        capabilities.sort_by(|a, b| a.name.cmp(&b.name));
        capabilities
    }

    pub fn verified_capability(&self, agent: &Did, capability: &str) -> Option<VerifiedCapability> {
        self.agent_verified_capabilities(agent)
            .into_iter()
            .find(|verified| verified.name == capability)
    }

    pub fn relate(&mut self, from: Did, to: Did, kind: RelationKind, now: u64) {
        self.agents.insert(from.clone());
        self.agents.insert(to.clone());

        self.edges
            .entry((from.clone(), to.clone()))
            .and_modify(|edge| {
                edge.kind = kind;
                edge.updated_at = now;
            })
            .or_insert_with(|| SocialEdge::new(from, to, kind, now));
    }

    pub fn edge(&self, from: &Did, to: &Did) -> Option<&SocialEdge> {
        self.edges.get(&(from.clone(), to.clone()))
    }

    pub fn edges(&self) -> Vec<&SocialEdge> {
        let mut edges: Vec<&SocialEdge> = self.edges.values().collect();
        edges.sort_by(|a, b| {
            a.from
                .to_string()
                .cmp(&b.from.to_string())
                .then_with(|| a.to.to_string().cmp(&b.to.to_string()))
        });
        edges
    }

    pub fn reputation(&self, from: &Did, to: &Did) -> Option<&ReputationScore> {
        self.reputations.get(&(from.clone(), to.clone()))
    }

    pub fn reputations(&self) -> Vec<(&Did, &Did, &ReputationScore)> {
        let mut reputations: Vec<(&Did, &Did, &ReputationScore)> = self
            .reputations
            .iter()
            .map(|((from, to), score)| (from, to, score))
            .collect();
        reputations.sort_by(|a, b| {
            a.0.to_string()
                .cmp(&b.0.to_string())
                .then_with(|| a.1.to_string().cmp(&b.1.to_string()))
        });
        reputations
    }

    pub fn agent_reputations(&self, agent: &Did) -> Vec<(&Did, &Did, &ReputationScore)> {
        let mut reputations: Vec<(&Did, &Did, &ReputationScore)> = self
            .reputations
            .iter()
            .filter(|((from, to), _)| from == agent || to == agent)
            .map(|((from, to), score)| (from, to, score))
            .collect();
        reputations.sort_by(|a, b| {
            a.0.to_string()
                .cmp(&b.0.to_string())
                .then_with(|| a.1.to_string().cmp(&b.1.to_string()))
        });
        reputations
    }

    pub fn join_workspace(&mut self, agent: Did, workspace: WorkspaceId) {
        self.register_agent(agent.clone());
        self.workspace_members
            .entry(workspace)
            .or_default()
            .insert(agent.clone());
        self.agent_workspaces
            .entry(agent)
            .or_default()
            .insert(workspace);
    }

    pub fn record_workspace_ownership_claim(&mut self, claim: WorkspaceOwnershipClaim) -> bool {
        if claim.previous_owner.is_some() {
            return false;
        }
        if self
            .workspace_claimed_owner(&claim.workspace)
            .is_some_and(|owner| owner != claim.owner)
        {
            return false;
        }
        self.adopt_workspace_ownership_claim(claim)
    }

    pub fn record_workspace_ownership_transfer(
        &mut self,
        signer: &Did,
        claim: WorkspaceOwnershipClaim,
    ) -> bool {
        let Some(previous_owner) = &claim.previous_owner else {
            return false;
        };
        if signer != previous_owner {
            return false;
        }
        if self.workspace_claimed_owner(&claim.workspace).as_ref() != Some(previous_owner) {
            return false;
        }
        self.adopt_workspace_ownership_claim(claim)
    }

    fn adopt_workspace_ownership_claim(&mut self, claim: WorkspaceOwnershipClaim) -> bool {
        self.register_agent(claim.owner.clone());
        self.workspace_current_owners
            .insert(claim.workspace, claim.owner.clone());
        self.workspace_ownership_claims
            .entry(workspace_ownership_claim_key(&claim))
            .and_modify(|existing| {
                if claim.claimed_at >= existing.claimed_at {
                    *existing = claim.clone();
                }
            })
            .or_insert(claim);
        true
    }

    pub fn workspace_ownership_claims(
        &self,
        workspace: &WorkspaceId,
    ) -> Vec<WorkspaceOwnershipFact> {
        let mut claims = self
            .workspace_ownership_claims
            .values()
            .filter(|claim| claim.workspace == *workspace)
            .map(|claim| WorkspaceOwnershipFact {
                claim: claim.clone(),
                truth_status: self.workspace_ownership_truth_status(claim),
            })
            .collect::<Vec<_>>();
        claims.sort_by(|a, b| {
            b.truth_status
                .cmp(&a.truth_status)
                .then_with(|| b.claim.claimed_at.cmp(&a.claim.claimed_at))
                .then_with(|| a.claim.owner.to_string().cmp(&b.claim.owner.to_string()))
        });
        claims
    }

    pub fn workspace_claimed_owner(&self, workspace: &WorkspaceId) -> Option<Did> {
        self.workspace_current_owners
            .get(workspace)
            .cloned()
            .or_else(|| {
                self.workspace_ownership_claims(workspace)
                    .first()
                    .map(|fact| fact.claim.owner.clone())
            })
    }

    fn workspace_ownership_truth_status(&self, claim: &WorkspaceOwnershipClaim) -> FactTruthStatus {
        if claim
            .anchor
            .as_ref()
            .is_some_and(|anchor| anchor.validate().is_ok())
        {
            FactTruthStatus::Anchored
        } else {
            FactTruthStatus::Claimed
        }
    }

    pub fn workspace_members(&self, workspace: &WorkspaceId) -> Vec<&Did> {
        let Some(members) = self.workspace_members.get(workspace) else {
            return Vec::new();
        };

        let mut members: Vec<&Did> = members.iter().collect();
        members.sort_by_key(|did| did.to_string());
        members
    }

    pub fn agent_workspaces(&self, agent: &Did) -> Vec<WorkspaceId> {
        let Some(workspaces) = self.agent_workspaces.get(agent) else {
            return Vec::new();
        };

        let mut workspaces: Vec<WorkspaceId> = workspaces.iter().copied().collect();
        workspaces.sort_by_key(|workspace| workspace.to_string());
        workspaces
    }

    pub fn record_capability_grant(&mut self, grant: CapabilityGrant) {
        self.register_agent(grant.capability.issuer.clone());
        self.register_agent(grant.capability.subject.clone());
        self.capability_grants
            .entry(capability_grant_key(&grant))
            .or_insert(grant);
    }

    pub fn record_capability_revocation(&mut self, revocation: CapabilityRevocation) {
        self.register_agent(revocation.issuer.clone());
        if self.capability_grants.values().any(|grant| {
            grant.capability.issuer == revocation.issuer
                && capability_signature_id(&grant.capability.signature)
                    == revocation.capability_signature_id
        }) {
            self.capability_revocations
                .entry(revocation.capability_signature_id.clone())
                .or_insert(revocation);
        }
    }

    pub fn capability_grants(&self) -> Vec<&CapabilityGrant> {
        let mut grants: Vec<&CapabilityGrant> = self.capability_grants.values().collect();
        grants.sort_by(|a, b| {
            a.capability
                .workspace
                .to_string()
                .cmp(&b.capability.workspace.to_string())
                .then_with(|| {
                    a.capability
                        .issuer
                        .to_string()
                        .cmp(&b.capability.issuer.to_string())
                })
                .then_with(|| {
                    a.capability
                        .subject
                        .to_string()
                        .cmp(&b.capability.subject.to_string())
                })
                .then_with(|| a.issued_at.cmp(&b.issued_at))
        });
        grants
    }

    pub fn capability_revocation(&self, grant: &CapabilityGrant) -> Option<&CapabilityRevocation> {
        self.capability_revocations
            .get(&capability_signature_id(&grant.capability.signature))
            .filter(|revocation| revocation.issuer == grant.capability.issuer)
    }

    pub fn capability_revocations(&self) -> Vec<&CapabilityRevocation> {
        let mut revocations: Vec<&CapabilityRevocation> =
            self.capability_revocations.values().collect();
        revocations.sort_by(|a, b| {
            a.revoked_at
                .cmp(&b.revoked_at)
                .then_with(|| a.issuer.to_string().cmp(&b.issuer.to_string()))
                .then_with(|| a.capability_signature_id.cmp(&b.capability_signature_id))
        });
        revocations
    }

    pub fn workspace_capability_grants(&self, workspace: &WorkspaceId) -> Vec<&CapabilityGrant> {
        self.capability_grants()
            .into_iter()
            .filter(|grant| grant.capability.workspace == *workspace)
            .collect()
    }

    pub fn agent_capability_grants(&self, subject: &Did) -> Vec<&CapabilityGrant> {
        self.capability_grants()
            .into_iter()
            .filter(|grant| grant.capability.subject == *subject)
            .collect()
    }

    pub fn record_workspace_snapshot(&mut self, snapshot: WorkspaceSnapshot) {
        self.register_agent(snapshot.actor.clone());
        let key = workspace_snapshot_key(&snapshot);
        if let Some(existing) = self.workspace_snapshots.get_mut(&key) {
            if is_derived_snapshot(existing) && !is_derived_snapshot(&snapshot) {
                *existing = snapshot;
            }
            return;
        }

        self.workspace_snapshots.insert(key, snapshot);
    }

    pub fn workspace_snapshots(&self, workspace: &WorkspaceId) -> Vec<&WorkspaceSnapshot> {
        let mut snapshots: Vec<&WorkspaceSnapshot> = self
            .workspace_snapshots
            .values()
            .filter(|snapshot| snapshot.workspace == *workspace)
            .collect();
        snapshots.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.actor.to_string().cmp(&b.actor.to_string()))
                .then_with(|| a.root.as_bytes().cmp(b.root.as_bytes()))
        });
        snapshots
    }

    pub fn latest_workspace_snapshot(&self, workspace: &WorkspaceId) -> Option<&WorkspaceSnapshot> {
        self.workspace_snapshots(workspace)
            .into_iter()
            .max_by(|a, b| {
                a.timestamp
                    .cmp(&b.timestamp)
                    .then_with(|| a.actor.to_string().cmp(&b.actor.to_string()))
                    .then_with(|| a.root.as_bytes().cmp(b.root.as_bytes()))
            })
    }

    pub fn record_workspace_run(&mut self, run: WorkspaceRun) {
        self.register_agent(run.actor.clone());
        let key = workspace_run_key(&run);
        if self.workspace_runs.contains_key(&key) {
            return;
        }

        if let Some(root) = run.output_root {
            self.record_workspace_snapshot(WorkspaceSnapshot {
                workspace: run.workspace,
                actor: run.actor.clone(),
                root,
                label: Some("workspace-run".into()),
                note: Some(format!(
                    "run {}{}",
                    run.command,
                    format_args_for_note(&run.args)
                )),
                timestamp: run.finished_at,
            });
        }

        self.workspace_runs.insert(key, run);
    }

    pub fn workspace_runs(&self, workspace: &WorkspaceId) -> Vec<&WorkspaceRun> {
        let mut runs: Vec<&WorkspaceRun> = self
            .workspace_runs
            .values()
            .filter(|run| run.workspace == *workspace)
            .collect();
        runs.sort_by(|a, b| {
            a.started_at
                .cmp(&b.started_at)
                .then_with(|| a.finished_at.cmp(&b.finished_at))
                .then_with(|| a.actor.to_string().cmp(&b.actor.to_string()))
                .then_with(|| a.command.cmp(&b.command))
        });
        runs
    }

    pub fn agent_workspace_runs(&self, actor: &Did) -> Vec<&WorkspaceRun> {
        let mut runs: Vec<&WorkspaceRun> = self
            .workspace_runs
            .values()
            .filter(|run| run.actor == *actor)
            .collect();
        runs.sort_by(|a, b| {
            a.started_at
                .cmp(&b.started_at)
                .then_with(|| a.workspace.to_string().cmp(&b.workspace.to_string()))
                .then_with(|| a.command.cmp(&b.command))
        });
        runs
    }

    pub fn record_intent(&mut self, intent: AgentIntent) {
        self.register_agent(intent.author.clone());
        let key = intent_key(&intent);
        self.intents.entry(key).or_insert(intent);
    }

    pub fn record_intent_response(&mut self, response: IntentResponse) {
        self.register_agent(response.responder.clone());
        let key = intent_response_key(&response);
        self.intent_responses.entry(key).or_insert(response);
    }

    pub fn intents(&self) -> Vec<&AgentIntent> {
        let mut intents: Vec<&AgentIntent> = self.intents.values().collect();
        intents.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.author.to_string().cmp(&b.author.to_string()))
                .then_with(|| a.id.cmp(&b.id))
        });
        intents
    }

    pub fn agent_intents(&self, author: &Did) -> Vec<&AgentIntent> {
        let mut intents: Vec<&AgentIntent> = self
            .intents
            .values()
            .filter(|intent| intent.author == *author)
            .collect();
        intents.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        intents
    }

    pub fn workspace_intents(&self, workspace: &WorkspaceId) -> Vec<&AgentIntent> {
        let mut intents: Vec<&AgentIntent> = self
            .intents
            .values()
            .filter(|intent| intent.workspace == Some(*workspace))
            .collect();
        intents.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.author.to_string().cmp(&b.author.to_string()))
                .then_with(|| a.id.cmp(&b.id))
        });
        intents
    }

    pub fn intent_responses(&self) -> Vec<&IntentResponse> {
        let mut responses: Vec<&IntentResponse> = self.intent_responses.values().collect();
        responses.sort_by(intent_response_order);
        responses
    }

    pub fn responses_for_intent(&self, intent_id: &str) -> Vec<&IntentResponse> {
        let mut responses: Vec<&IntentResponse> = self
            .intent_responses
            .values()
            .filter(|response| response.intent_id == intent_id)
            .collect();
        responses.sort_by(intent_response_order);
        responses
    }

    pub fn agent_intent_responses(&self, responder: &Did) -> Vec<&IntentResponse> {
        let mut responses: Vec<&IntentResponse> = self
            .intent_responses
            .values()
            .filter(|response| response.responder == *responder)
            .collect();
        responses.sort_by(intent_response_order);
        responses
    }

    pub fn workspace_intent_responses(&self, workspace: &WorkspaceId) -> Vec<&IntentResponse> {
        let mut responses: Vec<&IntentResponse> = self
            .intent_responses
            .values()
            .filter(|response| response.workspace == Some(*workspace))
            .collect();
        responses.sort_by(intent_response_order);
        responses
    }

    pub fn workspace_ids(&self) -> Vec<WorkspaceId> {
        let mut workspaces: HashSet<WorkspaceId> = self.workspace_members.keys().copied().collect();
        workspaces.extend(
            self.capability_grants
                .values()
                .map(|grant| grant.capability.workspace),
        );
        workspaces.extend(self.intents.values().filter_map(|intent| intent.workspace));
        workspaces.extend(
            self.intent_responses
                .values()
                .filter_map(|response| response.workspace),
        );
        workspaces.extend(
            self.workspace_snapshots
                .values()
                .map(|snapshot| snapshot.workspace),
        );
        workspaces.extend(self.workspace_runs.values().map(|run| run.workspace));
        let mut workspaces: Vec<WorkspaceId> = workspaces.into_iter().collect();
        workspaces.sort_by_key(|workspace| workspace.to_string());
        workspaces
    }

    pub fn record_interaction(&mut self, interaction: Interaction) {
        self.register_agent(interaction.from.clone());
        self.register_agent(interaction.to.clone());

        let key = (interaction.from.clone(), interaction.to.clone());
        let edge = self.edges.entry(key).or_insert_with(|| {
            SocialEdge::new(
                interaction.from.clone(),
                interaction.to.clone(),
                RelationKind::Acquaintance,
                interaction.timestamp,
            )
        });
        edge.record_outcome(interaction.outcome, interaction.timestamp);
        self.record_reputation_outcome(
            interaction.from.clone(),
            interaction.to.clone(),
            interaction.outcome,
            interaction.timestamp,
        );

        self.interactions.push(interaction);
    }

    pub fn create_collective(
        &mut self,
        id: String,
        name: String,
        purpose: String,
        members: impl IntoIterator<Item = Did>,
        created_at: u64,
    ) {
        let members: HashSet<Did> = members.into_iter().collect();
        for member in &members {
            self.register_agent(member.clone());
        }

        self.collectives
            .entry(id.clone())
            .and_modify(|collective| {
                collective.name = name.clone();
                collective.purpose = purpose.clone();
                collective.members.extend(members.iter().cloned());
                if collective.created_at == 0 {
                    collective.created_at = created_at;
                }
            })
            .or_insert_with(|| Collective {
                id,
                name,
                purpose,
                members,
                workspaces: HashSet::new(),
                created_at,
            });
    }

    pub fn join_collective(&mut self, collective_id: String, member: Did, joined_at: u64) {
        self.register_agent(member.clone());
        self.collectives
            .entry(collective_id.clone())
            .or_insert_with(|| Collective {
                id: collective_id,
                name: String::new(),
                purpose: String::new(),
                members: HashSet::new(),
                workspaces: HashSet::new(),
                created_at: joined_at,
            })
            .members
            .insert(member);
    }

    pub fn attach_workspace(&mut self, collective_id: &str, workspace: WorkspaceId) -> bool {
        self.ensure_collective(collective_id, 0)
            .workspaces
            .insert(workspace);
        true
    }

    pub fn collective(&self, id: &str) -> Option<&Collective> {
        self.collectives.get(id)
    }

    pub fn collectives(&self) -> Vec<&Collective> {
        let mut collectives: Vec<&Collective> = self.collectives.values().collect();
        collectives.sort_by(|a, b| a.id.cmp(&b.id));
        collectives
    }

    pub fn record_collective_proposal(&mut self, proposal: CollectiveProposal) {
        self.register_agent(proposal.proposer.clone());
        self.ensure_collective(&proposal.collective_id, proposal.created_at);
        self.collective_proposals
            .entry(collective_proposal_key(
                &proposal.collective_id,
                &proposal.id,
            ))
            .or_insert(proposal);
    }

    pub fn record_collective_vote(&mut self, vote: CollectiveVote) {
        self.register_agent(vote.voter.clone());
        self.ensure_collective(&vote.collective_id, vote.timestamp);
        self.collective_votes
            .entry(collective_proposal_key(
                &vote.collective_id,
                &vote.proposal_id,
            ))
            .or_default()
            .insert(vote.voter.clone(), vote);
    }

    pub fn record_collective_decision(&mut self, decision: CollectiveDecision) {
        self.register_agent(decision.decider.clone());
        self.ensure_collective(&decision.collective_id, decision.timestamp);
        self.collective_decisions.insert(
            collective_proposal_key(&decision.collective_id, &decision.proposal_id),
            decision,
        );
    }

    pub fn collective_proposals(&self, collective_id: &str) -> Vec<&CollectiveProposal> {
        let mut proposals: Vec<&CollectiveProposal> = self
            .collective_proposals
            .values()
            .filter(|proposal| proposal.collective_id == collective_id)
            .collect();
        proposals.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        proposals
    }

    pub fn collective_votes(&self, collective_id: &str, proposal_id: &str) -> Vec<&CollectiveVote> {
        let key = collective_proposal_key(collective_id, proposal_id);
        let Some(votes) = self.collective_votes.get(&key) else {
            return Vec::new();
        };

        let mut votes: Vec<&CollectiveVote> = votes.values().collect();
        votes.sort_by(|a, b| a.voter.to_string().cmp(&b.voter.to_string()));
        votes
    }

    pub fn collective_decision(
        &self,
        collective_id: &str,
        proposal_id: &str,
    ) -> Option<&CollectiveDecision> {
        self.collective_decisions
            .get(&collective_proposal_key(collective_id, proposal_id))
    }

    pub fn collective_decision_truth_status(
        &self,
        decision: &CollectiveDecision,
    ) -> FactTruthStatus {
        if self.collective_decision_anchor_valid(decision) {
            FactTruthStatus::Anchored
        } else {
            FactTruthStatus::Claimed
        }
    }

    pub fn task_claim_judgments(&self, task_id: &str) -> Vec<TaskClaimJudgment> {
        let mut judgments: Vec<TaskClaimJudgment> = self
            .collective_decisions
            .values()
            .filter(|decision| decision.task_id.as_deref() == Some(task_id))
            .map(|decision| task_claim_judgment_from_decision(self, decision))
            .collect();
        judgments.sort_by(task_claim_judgment_order);
        judgments
    }

    pub fn result_claim_judgments(&self, task_id: &str, claim_id: &str) -> Vec<TaskClaimJudgment> {
        let mut judgments: Vec<TaskClaimJudgment> = self
            .collective_decisions
            .values()
            .filter(|decision| {
                decision.task_id.as_deref() == Some(task_id)
                    && decision.claim_id.as_deref() == Some(claim_id)
            })
            .map(|decision| task_claim_judgment_from_decision(self, decision))
            .collect();
        judgments.sort_by(task_claim_judgment_order);
        judgments
    }

    pub fn task(&self, task_id: &str) -> Option<&Task> {
        self.tasks.get(task_id)
    }

    pub fn tasks(&self) -> Vec<&Task> {
        let mut tasks: Vec<&Task> = self.tasks.values().collect();
        tasks.sort_by(|a, b| a.id.cmp(&b.id));
        tasks
    }

    pub fn task_offers(&self, task_id: &str) -> &[TaskOffer] {
        self.task_offers
            .get(task_id)
            .map(|offers| offers.as_slice())
            .unwrap_or(&[])
    }

    pub fn task_result(&self, task_id: &str) -> Option<&TaskResult> {
        self.task_results.get(task_id)
    }

    pub fn task_result_claims(&self, task_id: &str) -> Vec<&TaskResult> {
        let Some(claims) = self.task_result_claims.get(task_id) else {
            return Vec::new();
        };

        let mut claims: Vec<&TaskResultClaim> = claims.values().collect();
        claims.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| {
                    task_result_claim_started_at(&a.result)
                        .cmp(&task_result_claim_started_at(&b.result))
                })
                .then_with(|| {
                    task_result_claim_finished_at(&a.result)
                        .cmp(&task_result_claim_finished_at(&b.result))
                })
                .then_with(|| {
                    a.result
                        .executor
                        .to_string()
                        .cmp(&b.result.executor.to_string())
                })
                .then_with(|| {
                    task_result_claim_command(&a.result).cmp(task_result_claim_command(&b.result))
                })
                .then_with(|| {
                    task_result_claim_args(&a.result).cmp(task_result_claim_args(&b.result))
                })
                .then_with(|| a.result.exit_code.cmp(&b.result.exit_code))
        });
        claims.into_iter().map(|claim| &claim.result).collect()
    }

    pub fn task_execution_attestations(&self, task_id: &str) -> Vec<&ExecutionAttestation> {
        let Some(attestations) = self.task_execution_attestations.get(task_id) else {
            return Vec::new();
        };

        let mut attestations: Vec<&ExecutionAttestation> = attestations.values().collect();
        attestations.sort_by(|a, b| {
            a.observed_at
                .cmp(&b.observed_at)
                .then_with(|| a.executor.to_string().cmp(&b.executor.to_string()))
                .then_with(|| a.attestor.to_string().cmp(&b.attestor.to_string()))
                .then_with(|| a.receipt_signature_hex.cmp(&b.receipt_signature_hex))
        });
        attestations
    }

    pub fn task_result_attestations<'a>(
        &'a self,
        result: &'a TaskResult,
    ) -> Vec<&'a ExecutionAttestation> {
        let Some(receipt) = result.receipt.as_deref() else {
            return Vec::new();
        };
        let mut attestations: Vec<&ExecutionAttestation> = result
            .attestations
            .iter()
            .chain(self.task_execution_attestations(&result.task_id))
            .filter(|attestation| {
                attestation.validate_against_receipt(receipt).is_ok()
                    && attestation.stdout_cid == Cid::hash_of(result.stdout.as_bytes())
                    && attestation.stderr_cid == Cid::hash_of(result.stderr.as_bytes())
            })
            .collect();
        attestations.sort_by(|a, b| {
            a.observed_at
                .cmp(&b.observed_at)
                .then_with(|| a.attestor.to_string().cmp(&b.attestor.to_string()))
        });
        attestations.dedup_by(|a, b| execution_attestation_key(a) == execution_attestation_key(b));
        attestations
    }

    pub fn agent_task_results(&self, executor: &Did) -> Vec<&TaskResult> {
        let mut results: Vec<&TaskResult> = self
            .task_results
            .values()
            .filter(|result| result.executor == *executor)
            .collect();
        results.sort_by(|a, b| {
            a.task_id
                .cmp(&b.task_id)
                .then_with(|| a.exit_code.cmp(&b.exit_code))
        });
        results
    }

    pub fn agent_task_result_claims(&self, executor: &Did) -> Vec<&TaskResult> {
        let mut claims: Vec<&TaskResult> = self
            .task_result_claims
            .values()
            .flat_map(|claims| claims.values())
            .map(|claim| &claim.result)
            .filter(|result| result.executor == *executor)
            .collect();
        claims.sort_by(|a, b| {
            a.task_id
                .cmp(&b.task_id)
                .then_with(|| task_result_claim_started_at(a).cmp(&task_result_claim_started_at(b)))
                .then_with(|| {
                    task_result_claim_finished_at(a).cmp(&task_result_claim_finished_at(b))
                })
                .then_with(|| task_result_claim_command(a).cmp(task_result_claim_command(b)))
                .then_with(|| task_result_claim_args(a).cmp(task_result_claim_args(b)))
                .then_with(|| a.exit_code.cmp(&b.exit_code))
        });
        claims
    }

    pub fn task_acceptance(&self, task_id: &str) -> Option<&TaskAcceptance> {
        self.active_task_acceptance(task_id)
    }

    pub fn task_cancellation(&self, task_id: &str) -> Option<&TaskCancellation> {
        self.active_task_cancellation(task_id)
    }

    pub fn task_disputes(&self, task_id: &str) -> Vec<&TaskDispute> {
        let mut disputes: Vec<&TaskDispute> = self
            .task_disputes
            .values()
            .filter(|dispute| dispute.task_id == task_id)
            .collect();
        disputes.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.disputer.to_string().cmp(&b.disputer.to_string()))
                .then_with(|| a.target.to_string().cmp(&b.target.to_string()))
                .then_with(|| a.claim_id.cmp(&b.claim_id))
        });
        disputes
    }

    pub fn open_tasks_for(&self, capability: &str) -> Vec<&Task> {
        self.tasks
            .values()
            .filter(|task| task.is_open() && task.required_capability == capability)
            .collect()
    }

    /// Find all known agents that declare a capability.
    pub fn find_providers(&self, capability: &str) -> Vec<ProviderRecommendation> {
        self.provider_recommendations(None, capability, usize::MAX)
    }

    /// Recommend known providers for a requester and capability.
    ///
    /// Blocked peers are excluded from the recommendation list because that
    /// is a local relationship preference, not a runtime restriction.
    pub fn recommend_providers(
        &self,
        requester: &Did,
        capability: &str,
        limit: usize,
    ) -> Vec<ProviderRecommendation> {
        self.provider_recommendations(Some(requester), capability, limit)
    }

    /// Recommend open intents for an agent from the local society view.
    ///
    /// This excludes the agent's own intents, already-answered intents,
    /// expired intents, and peers that the agent locally blocked. Everything
    /// else remains advisory: the returned scores help an AI decide what to
    /// inspect or answer, but they do not grant or revoke any runtime power.
    pub fn recommend_intents(
        &self,
        agent: &Did,
        now: Option<u64>,
        limit: usize,
    ) -> Vec<IntentRecommendation> {
        if limit == 0 {
            return Vec::new();
        }

        let manifest = self.agent_manifest(agent);
        let workspaces: HashSet<WorkspaceId> = self.agent_workspaces(agent).into_iter().collect();
        let mut recommendations = self
            .intents
            .values()
            .filter_map(|intent| {
                if intent.author == *agent {
                    return None;
                }
                if now.is_some_and(|now| {
                    intent
                        .expires_at
                        .is_some_and(|expires_at| expires_at <= now)
                }) {
                    return None;
                }
                if self
                    .edge(agent, &intent.author)
                    .is_some_and(|edge| edge.kind == RelationKind::Blocked)
                {
                    return None;
                }
                if self.is_equivocating(&intent.author) {
                    return None;
                }

                let responses = self.responses_for_intent(&intent.id);
                if responses
                    .iter()
                    .any(|response| &response.responder == agent)
                {
                    return None;
                }

                let capability_score = intent_capability_score(manifest, intent);
                let workspace_score = intent_workspace_score(&workspaces, intent);
                let social_score = self
                    .edge(agent, &intent.author)
                    .map(SocialEdge::score)
                    .unwrap_or(0.5);
                let reputation_score = self
                    .reputation(agent, &intent.author)
                    .map(ReputationScore::composite)
                    .unwrap_or(0.5);
                let response_score = intent_response_score(&responses);
                let preference_score = intent_preference_score(manifest, intent);
                let response_count = responses.len();
                let fulfilled = responses
                    .iter()
                    .any(|response| response.kind == IntentResponseKind::Fulfilled);
                let action_context = IntentActionContext {
                    capability_score,
                    workspace_score,
                    social_score,
                    reputation_score,
                    response_score,
                    preference_score,
                    response_count,
                    fulfilled,
                };
                let ranking_score = capability_score * 0.30
                    + workspace_score * 0.15
                    + social_score * 0.20
                    + reputation_score * 0.15
                    + response_score * 0.10
                    + preference_score * 0.10;

                Some(IntentRecommendation {
                    intent: intent.clone(),
                    author_name: self
                        .agent_manifest(&intent.author)
                        .map(|manifest| manifest.name.clone()),
                    capability_score,
                    workspace_score,
                    social_score,
                    reputation_score,
                    response_score,
                    preference_score,
                    response_count,
                    fulfilled,
                    ranking_score,
                    reasons: intent_recommendation_reasons(
                        intent,
                        capability_score,
                        workspace_score,
                        social_score,
                        reputation_score,
                        preference_score,
                        response_count,
                        fulfilled,
                    ),
                    actions: intent_action_plans(agent, manifest, intent, &action_context),
                })
            })
            .collect::<Vec<_>>();

        recommendations.sort_by(intent_recommendation_order);
        recommendations.truncate(limit);
        recommendations
    }

    pub fn apply_event(&mut self, event: &SocialEvent) {
        self.register_agent(event.author.clone());

        match &event.kind {
            SocialEventKind::EquivocationObserved { proof } => {
                self.record_equivocation_proof(proof.as_ref().clone());
            }
            SocialEventKind::ManifestPublished { manifest } => {
                self.register_agent(manifest.did.clone());
                self.manifests
                    .insert(manifest.did.clone(), manifest.clone());
            }
            SocialEventKind::IdentityRevoked { revocation } => {
                self.record_identity_revocation(revocation.clone());
            }
            SocialEventKind::WorkspaceJoined { workspace } => {
                self.join_workspace(event.author.clone(), *workspace);
            }
            SocialEventKind::WorkspaceOwnershipClaimed { claim } => {
                self.record_workspace_ownership_claim(claim.clone());
            }
            SocialEventKind::WorkspaceOwnershipTransferred { claim } => {
                self.record_workspace_ownership_transfer(&event.author, claim.clone());
            }
            SocialEventKind::RelationDeclared {
                peer,
                relation,
                note,
            } => {
                self.relate(
                    event.author.clone(),
                    peer.clone(),
                    *relation,
                    event.timestamp,
                );
                if let Some(note) = note {
                    if let Some(edge) = self.edges.get_mut(&(event.author.clone(), peer.clone())) {
                        edge.notes.push(note.clone());
                    }
                }
            }
            SocialEventKind::InteractionRecorded { interaction } => {
                self.record_interaction(interaction.clone());
            }
            SocialEventKind::CollectiveDeclared {
                collective_id,
                name,
                purpose,
                members,
            } => {
                self.create_collective(
                    collective_id.clone(),
                    name.clone(),
                    purpose.clone(),
                    members.clone(),
                    event.timestamp,
                );
            }
            SocialEventKind::CollectiveJoined { collective_id } => {
                self.join_collective(collective_id.clone(), event.author.clone(), event.timestamp);
            }
            SocialEventKind::CollectiveWorkspaceAttached {
                collective_id,
                workspace,
            } => {
                self.join_collective(collective_id.clone(), event.author.clone(), event.timestamp);
                let _ = self.attach_workspace(collective_id, *workspace);
            }
            SocialEventKind::CollectiveProposalPublished { proposal } => {
                self.record_collective_proposal(proposal.clone());
            }
            SocialEventKind::CollectiveVoteCast { vote } => {
                self.record_collective_vote(vote.clone());
            }
            SocialEventKind::CollectiveDecisionRecorded { decision } => {
                self.record_collective_decision(decision.clone());
            }
            SocialEventKind::CapabilityIssued { grant } => {
                self.record_capability_grant(grant.clone());
            }
            SocialEventKind::CapabilityRevoked { revocation } => {
                self.record_capability_revocation(revocation.clone());
            }
            SocialEventKind::WorkspaceSnapshotted { snapshot } => {
                self.record_workspace_snapshot(snapshot.clone());
            }
            SocialEventKind::WorkspaceRunRecorded { run } => {
                self.record_workspace_run(run.as_ref().clone());
            }
            SocialEventKind::IntentPublished { intent } => {
                self.record_intent(intent.clone());
            }
            SocialEventKind::IntentResponded { response } => {
                self.record_intent_response(response.clone());
            }
            SocialEventKind::TaskPublished { task } => {
                self.register_agent(task.publisher.clone());
                let task = Task::from_spec(task.clone());
                let task_id = task.id.clone();
                self.tasks.entry(task_id.clone()).or_insert(task);
                self.apply_known_task_acceptance(&task_id);
                self.apply_known_task_cancellation(&task_id);
                self.apply_known_task_result(&task_id);
            }
            SocialEventKind::TaskOffered { offer } => {
                self.register_agent(offer.bidder.clone());
                self.record_task_offer(offer.clone());
            }
            SocialEventKind::TaskAccepted { acceptance } => {
                self.register_agent(acceptance.publisher.clone());
                self.register_agent(acceptance.bidder.clone());
                self.record_task_acceptance(acceptance.clone());
            }
            SocialEventKind::TaskCancelled { cancellation } => {
                self.register_agent(cancellation.publisher.clone());
                self.record_task_cancellation(cancellation.clone());
            }
            SocialEventKind::TaskCompleted { result } => {
                self.register_agent(result.executor.clone());
                self.record_task_result(result.clone(), event.timestamp);
            }
            SocialEventKind::TaskExecutionAttested { attestation } => {
                self.register_agent(attestation.executor.clone());
                self.register_agent(attestation.attestor.clone());
                self.record_task_execution_attestation(attestation.clone());
            }
            SocialEventKind::TaskDisputed { dispute } => {
                self.record_task_dispute(dispute.clone());
            }
            SocialEventKind::SettlementRecorded { settlement } => {
                self.record_settlement(settlement.clone());
            }
        }
    }

    /// Recommend collaborators from `agent`'s subjective view.
    pub fn recommend_collaborators(&self, agent: &Did, limit: usize) -> Vec<&SocialEdge> {
        let mut candidates: Vec<&SocialEdge> = self
            .edges
            .values()
            .filter(|edge| {
                edge.from == *agent
                    && edge.kind != RelationKind::Blocked
                    && !self.is_equivocating(&edge.to)
            })
            .collect();

        candidates.sort_by(|a, b| {
            b.score()
                .partial_cmp(&a.score())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.to.to_string().cmp(&b.to.to_string()))
        });
        candidates.truncate(limit);
        candidates
    }

    fn record_task_offer(&mut self, offer: TaskOffer) {
        let task_id = offer.task_id.clone();
        let offers = self.task_offers.entry(offer.task_id.clone()).or_default();
        if offers
            .iter()
            .any(|existing| existing.bidder == offer.bidder)
        {
            return;
        }

        offers.push(offer);
        offers.sort_by(|a, b| {
            a.price
                .cmp(&b.price)
                .then_with(|| a.bidder.to_string().cmp(&b.bidder.to_string()))
        });
        self.apply_known_task_acceptance(&task_id);
        self.apply_known_task_cancellation(&task_id);
    }

    fn record_task_acceptance(&mut self, acceptance: TaskAcceptance) {
        let task_id = acceptance.task_id.clone();
        self.task_acceptances
            .entry(task_id.clone())
            .or_default()
            .entry(acceptance_key(&acceptance))
            .or_insert(acceptance);
        self.apply_known_task_acceptance(&task_id);
        self.apply_known_task_cancellation(&task_id);
    }

    fn acceptance_can_apply(&self, acceptance: &TaskAcceptance) -> bool {
        let Some(task) = self.tasks.get(&acceptance.task_id) else {
            return false;
        };
        let Some(offers) = self.task_offers.get(&acceptance.task_id) else {
            return false;
        };

        task.publisher == acceptance.publisher
            && task.is_open()
            && offers
                .iter()
                .any(|offer| offer.bidder == acceptance.bidder && offer.price == acceptance.price)
    }

    fn active_task_acceptance(&self, task_id: &str) -> Option<&TaskAcceptance> {
        let task = self.tasks.get(task_id)?;
        let offers = self.task_offers.get(task_id)?;

        self.task_acceptances
            .get(task_id)?
            .values()
            .filter(|acceptance| {
                task.publisher == acceptance.publisher
                    && task.assigned_to.as_ref() == Some(&acceptance.bidder)
                    && offers.iter().any(|offer| {
                        offer.bidder == acceptance.bidder && offer.price == acceptance.price
                    })
            })
            .min_by(|a, b| {
                a.accepted_at
                    .cmp(&b.accepted_at)
                    .then_with(|| a.bidder.to_string().cmp(&b.bidder.to_string()))
                    .then_with(|| a.price.cmp(&b.price))
            })
    }

    fn apply_known_task_acceptance(&mut self, task_id: &str) {
        let Some(acceptance) = self
            .task_acceptances
            .get(task_id)
            .and_then(|acceptances| {
                acceptances
                    .values()
                    .filter(|acceptance| self.acceptance_can_apply(acceptance))
                    .min_by(|a, b| {
                        a.accepted_at
                            .cmp(&b.accepted_at)
                            .then_with(|| a.bidder.to_string().cmp(&b.bidder.to_string()))
                            .then_with(|| a.price.cmp(&b.price))
                    })
            })
            .cloned()
        else {
            return;
        };
        let Some(task) = self.tasks.get_mut(task_id) else {
            return;
        };
        if task.publisher != acceptance.publisher || !task.is_open() {
            return;
        }
        let Some(offers) = self.task_offers.get(task_id) else {
            return;
        };
        if !offers
            .iter()
            .any(|offer| offer.bidder == acceptance.bidder && offer.price == acceptance.price)
        {
            return;
        }

        task.accept_bid(&acceptance.bidder);
        self.apply_known_task_result(task_id);
    }

    fn record_task_cancellation(&mut self, cancellation: TaskCancellation) {
        let task_id = cancellation.task_id.clone();
        self.task_cancellations
            .entry(task_id.clone())
            .or_default()
            .entry(cancellation_key(&cancellation))
            .or_insert(cancellation);
        self.apply_known_task_cancellation(&task_id);
    }

    fn cancellation_can_apply(&self, cancellation: &TaskCancellation) -> bool {
        let Some(task) = self.tasks.get(&cancellation.task_id) else {
            return false;
        };

        task.publisher == cancellation.publisher && !task.is_done()
    }

    fn active_task_cancellation(&self, task_id: &str) -> Option<&TaskCancellation> {
        let task = self.tasks.get(task_id)?;
        if task.state != TaskState::Cancelled {
            return None;
        }

        self.task_cancellations
            .get(task_id)?
            .values()
            .filter(|cancellation| cancellation.publisher == task.publisher)
            .min_by(|a, b| {
                a.cancelled_at
                    .cmp(&b.cancelled_at)
                    .then_with(|| a.reason.cmp(&b.reason))
            })
    }

    fn apply_known_task_cancellation(&mut self, task_id: &str) {
        let Some(cancellation) = self
            .task_cancellations
            .get(task_id)
            .and_then(|cancellations| {
                cancellations
                    .values()
                    .filter(|cancellation| self.cancellation_can_apply(cancellation))
                    .min_by(|a, b| {
                        a.cancelled_at
                            .cmp(&b.cancelled_at)
                            .then_with(|| a.reason.cmp(&b.reason))
                    })
            })
            .cloned()
        else {
            return;
        };
        let Some(task) = self.tasks.get_mut(task_id) else {
            return;
        };
        if task.publisher != cancellation.publisher || task.is_done() {
            return;
        }

        task.cancel();
    }

    fn record_task_result(&mut self, result: TaskResult, timestamp: u64) {
        let task_id = result.task_id.clone();
        let claim_key = task_result_claim_id(&result);
        if self
            .task_result_claims
            .entry(task_id.clone())
            .or_default()
            .insert(claim_key, TaskResultClaim { result, timestamp })
            .is_some()
        {
            return;
        }

        self.apply_known_task_result(&task_id);
    }

    fn record_task_result_workspace_snapshot(&mut self, result: &TaskResult) {
        let Some(receipt) = result.receipt.as_deref() else {
            return;
        };
        let (Some(workspace), Some(root)) = (receipt.workspace, receipt.output_root) else {
            return;
        };

        self.record_workspace_snapshot(WorkspaceSnapshot {
            workspace,
            actor: receipt.executor.clone(),
            root,
            label: Some("task-result".into()),
            note: Some(format!("task {} result", result.task_id)),
            timestamp: receipt.finished_at,
        });
    }

    fn record_task_execution_attestation(&mut self, attestation: ExecutionAttestation) {
        if attestation.verify_signature().is_err() {
            return;
        }

        let task_id = attestation.task_id.clone();
        self.task_execution_attestations
            .entry(task_id)
            .or_default()
            .entry(execution_attestation_key(&attestation))
            .or_insert(attestation);
    }

    fn record_task_dispute(&mut self, dispute: TaskDispute) {
        self.register_agent(dispute.disputer.clone());
        self.register_agent(dispute.target.clone());

        let task_id = dispute.task_id.clone();
        let disputer = dispute.disputer.clone();
        let target = dispute.target.clone();
        let claim_id = dispute.claim_id.clone();
        let key = task_dispute_key(&dispute);
        if self.task_disputes.insert(key, dispute.clone()).is_some() {
            return;
        }

        self.record_interaction(Interaction {
            id: format!(
                "task-dispute:{task_id}:{disputer}:{target}:{}",
                claim_id.as_deref().unwrap_or_default()
            ),
            from: disputer,
            to: target,
            workspace: None,
            topic: match claim_id.as_deref() {
                Some(claim_id) => format!("task dispute: {} ({claim_id})", dispute.reason),
                None => format!("task dispute: {}", dispute.reason),
            },
            outcome: InteractionOutcome::Dispute,
            timestamp: dispute.timestamp,
            evidence: dispute
                .evidence
                .or_else(|| claim_id.map(|claim_id| format!("claim:{claim_id}")))
                .or(Some(task_id)),
        });
    }

    fn record_settlement(&mut self, settlement: SettlementRecord) {
        if settlement.validate().is_err() {
            return;
        }
        self.register_agent(settlement.payer.clone());
        self.register_agent(settlement.payee.clone());
        self.settlements
            .entry(settlement_key(&settlement))
            .or_insert(settlement);
    }

    fn collective_decision_anchor_valid(&self, decision: &CollectiveDecision) -> bool {
        let Some(anchor) = decision.anchor.as_ref() else {
            return false;
        };
        if anchor.validate().is_err() {
            return false;
        }
        if !decision_anchor_subject_matches(anchor, decision) {
            return false;
        }
        if anchor.kind != AuthorityKind::CollectiveQuorum {
            return true;
        }
        let Some(collective) = self.collectives.get(&decision.collective_id) else {
            return false;
        };
        let threshold = anchor.threshold.unwrap_or(0);
        let unique_attestors = anchor.attestors.iter().collect::<HashSet<_>>();
        unique_attestors.len() >= threshold
            && unique_attestors
                .iter()
                .all(|attestor| collective.members.contains(*attestor))
    }

    fn settlement_anchor_valid(&self, settlement: &SettlementRecord) -> bool {
        let SettlementProof::AnchoredCheckpoint(proof) = &settlement.proof else {
            return false;
        };
        if proof.validate().is_err() {
            return false;
        }
        if !checkpoint_subject_matches_settlement(&proof.checkpoint.subject, settlement) {
            return false;
        }
        let anchor = &proof.anchor;
        if anchor.kind != AuthorityKind::CollectiveQuorum {
            return true;
        }
        let Some(collective_id) = anchor_collective_id(anchor) else {
            return false;
        };
        let Some(collective) = self.collectives.get(collective_id) else {
            return false;
        };
        let threshold = anchor.threshold.unwrap_or(0);
        let unique_attestors = anchor.attestors.iter().collect::<HashSet<_>>();
        unique_attestors.len() >= threshold
            && unique_attestors
                .iter()
                .all(|attestor| collective.members.contains(*attestor))
    }

    pub fn record_equivocation_proof(&mut self, proof: EquivocationProof) {
        if proof.verify().is_err() {
            return;
        }
        self.register_agent(proof.author.clone());
        let proofs = self.equivocations.entry(proof.author.clone()).or_default();
        if proofs
            .iter()
            .any(|existing| existing.evidence_key() == proof.evidence_key())
        {
            return;
        }
        proofs.push(proof);
    }

    fn apply_known_task_result(&mut self, task_id: &str) {
        if self.applied_task_results.contains(task_id) {
            return;
        }

        let Some(claim) = self.select_applicable_task_result(task_id) else {
            return;
        };
        let result = claim.result;
        let timestamp = claim.timestamp;
        let workspace = result
            .receipt
            .as_deref()
            .and_then(|receipt| receipt.workspace);
        if result.success && result.receipt.is_none() {
            return;
        };
        let Some(task) = self.tasks.get(task_id) else {
            return;
        };
        if task.assigned_to.as_ref() != Some(&result.executor) {
            return;
        }
        if matches!(task.state, TaskState::Published | TaskState::Cancelled) {
            return;
        }

        let publisher = task.publisher.clone();
        let description = task.description.clone();
        let self_transaction = publisher == result.executor;
        self.applied_task_results.insert(task_id.to_string());
        {
            let Some(task) = self.tasks.get_mut(task_id) else {
                return;
            };
            if result.success {
                task.complete();
            } else {
                task.fail();
            }
        }
        self.record_task_result_workspace_snapshot(&result);
        self.task_results
            .insert(task_id.to_string(), result.clone());

        if self_transaction {
            return;
        }

        let interaction = Interaction {
            id: format!("task-result:{task_id}"),
            from: publisher,
            to: result.executor,
            workspace,
            topic: description,
            outcome: if result.success {
                InteractionOutcome::Success
            } else {
                InteractionOutcome::Failure
            },
            timestamp,
            evidence: Some(task_id.to_string()),
        };
        self.record_interaction(interaction);
    }

    fn select_applicable_task_result(&self, task_id: &str) -> Option<TaskResultClaim> {
        let task = self.tasks.get(task_id)?;
        if matches!(task.state, TaskState::Published | TaskState::Cancelled) {
            return None;
        }

        let assigned = task.assigned_to.as_ref()?;
        self.task_result_claims
            .get(task_id)?
            .values()
            .filter(|claim| {
                claim.result.executor == *assigned
                    && (!claim.result.success || claim.result.receipt.is_some())
                    && task_result_matches_task_commitment(&claim.result, task)
            })
            .min_by(|a, b| {
                a.timestamp
                    .cmp(&b.timestamp)
                    .then_with(|| {
                        a.result
                            .executor
                            .to_string()
                            .cmp(&b.result.executor.to_string())
                    })
                    .then_with(|| a.result.exit_code.cmp(&b.result.exit_code))
            })
            .cloned()
    }

    fn record_reputation_outcome(
        &mut self,
        from: Did,
        to: Did,
        outcome: InteractionOutcome,
        timestamp: u64,
    ) {
        let score = self
            .reputations
            .entry((from, to.clone()))
            .or_insert_with(|| ReputationScore::new(to, timestamp));

        match outcome {
            InteractionOutcome::Success => {
                score.record_success(timestamp);
                score.update_availability(1.0);
                score.update_correctness(1.0);
                score.update_timeliness(0.8);
                score.update_fairness(0.8);
            }
            InteractionOutcome::Neutral => {
                score.last_seen = timestamp;
                score.update_availability(0.7);
                score.update_correctness(0.5);
                score.update_timeliness(0.5);
                score.update_fairness(0.5);
            }
            InteractionOutcome::Failure => {
                score.record_failure(timestamp);
                score.update_availability(0.4);
                score.update_correctness(0.2);
                score.update_timeliness(0.4);
                score.update_fairness(0.4);
            }
            InteractionOutcome::Dispute => {
                score.record_failure(timestamp);
                score.update_availability(0.2);
                score.update_correctness(0.0);
                score.update_timeliness(0.2);
                score.update_fairness(0.0);
            }
        }
    }

    fn provider_recommendations(
        &self,
        requester: Option<&Did>,
        capability: &str,
        limit: usize,
    ) -> Vec<ProviderRecommendation> {
        let mut raw = Vec::new();
        let mut max_price = 0;

        for manifest in self.manifests.values() {
            let Some(capability_decl) = manifest.find_provided(capability) else {
                continue;
            };
            if self.is_equivocating(&manifest.did) {
                continue;
            }

            if let Some(requester) = requester {
                if self
                    .edge(requester, &manifest.did)
                    .is_some_and(|edge| edge.kind == RelationKind::Blocked)
                {
                    continue;
                }
            }

            max_price = max_price.max(capability_decl.price_per_unit);
            raw.push((manifest, capability_decl));
        }

        let mut providers: Vec<ProviderRecommendation> = raw
            .into_iter()
            .map(|(manifest, capability_decl)| {
                let social_score = requester
                    .and_then(|requester| self.edge(requester, &manifest.did))
                    .map(SocialEdge::score)
                    .unwrap_or(0.5);
                let reachability_score = requester
                    .map(|requester| self.trust_reachability_score(requester, &manifest.did))
                    .unwrap_or(1.0);
                let sybil_cluster_score = requester
                    .map(|requester| self.sybil_cluster_score(requester, &manifest.did))
                    .unwrap_or(0.0);
                let reputation_score = requester
                    .map(|requester| {
                        self.reachable_reputation_score(
                            requester,
                            &manifest.did,
                            reachability_score,
                            sybil_cluster_score,
                        )
                    })
                    .unwrap_or(0.5);
                let governance_signals = self.governance_signals_for(&manifest.did, 5);
                let governance_score = governance_score_from_signals(&governance_signals);
                let verified_capability =
                    self.verified_capability(&manifest.did, &capability_decl.name);
                let has_anchored_witness = governance_signals.iter().any(|signal| {
                    signal.truth_status == FactTruthStatus::Anchored
                        && signal.outcome == CollectiveDecisionOutcome::Accepted
                });
                let high_trust_eligible =
                    requester.is_none() || reachability_score > 0.0 || has_anchored_witness;
                let price_score = if max_price == 0 {
                    1.0
                } else {
                    1.0 - (capability_decl.price_per_unit as f64 / max_price as f64)
                };
                let mut ranking_score = social_score * 0.45
                    + reputation_score * 0.25
                    + governance_score * 0.20
                    + price_score * 0.10;
                if !high_trust_eligible {
                    ranking_score = ranking_score.min(0.60);
                }

                ProviderRecommendation {
                    did: manifest.did.clone(),
                    name: manifest.name.clone(),
                    capability: capability_decl.clone(),
                    social_score,
                    reputation_score,
                    reachability_score,
                    high_trust_eligible,
                    sybil_cluster_score,
                    governance_score,
                    governance_signals,
                    verified_capability,
                    price_per_unit: capability_decl.price_per_unit,
                    ranking_score,
                }
            })
            .collect();

        providers.sort_by(|a, b| {
            b.ranking_score
                .partial_cmp(&a.ranking_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    b.social_score
                        .partial_cmp(&a.social_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| {
                    b.governance_score
                        .partial_cmp(&a.governance_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.price_per_unit.cmp(&b.price_per_unit))
                .then_with(|| a.did.to_string().cmp(&b.did.to_string()))
        });
        providers.truncate(limit);
        providers
    }

    fn trust_reachability_score(&self, from: &Did, to: &Did) -> f64 {
        if from == to {
            return 1.0;
        }
        if self.edge(from, to).is_some() || self.reputation(from, to).is_some() {
            return 1.0;
        }

        let mut queue = std::collections::VecDeque::new();
        let mut visited = HashSet::new();
        queue.push_back((from.clone(), 1.0));
        visited.insert(from.clone());

        while let Some((current, confidence)) = queue.pop_front() {
            for edge in self.edges.values().filter(|edge| edge.from == current) {
                if edge.kind == RelationKind::Blocked || edge.failures > edge.successes {
                    continue;
                }
                let edge_score = edge.score();
                if edge_score < 0.55 {
                    continue;
                }
                let next_confidence = confidence * edge_score;
                if edge.to == *to {
                    return next_confidence.clamp(0.0, 1.0);
                }
                if next_confidence >= 0.30 && visited.insert(edge.to.clone()) {
                    queue.push_back((edge.to.clone(), next_confidence));
                }
            }
        }

        0.0
    }

    fn reachable_reputation_score(
        &self,
        requester: &Did,
        target: &Did,
        target_reachability: f64,
        sybil_cluster_score: f64,
    ) -> f64 {
        if let Some(score) = self.reputation(requester, target) {
            return score.composite();
        }

        let mut weighted_score = 0.0;
        let mut total_weight = 0.0;
        for ((source, subject), score) in &self.reputations {
            if subject != target {
                continue;
            }

            let source_reachability = if source == requester {
                1.0
            } else {
                self.trust_reachability_score(requester, source)
            };
            if source_reachability <= 0.0 {
                continue;
            }

            weighted_score += score.composite() * source_reachability;
            total_weight += source_reachability;
        }

        if total_weight <= 0.0 {
            return 0.5;
        }

        reachable_reputation(
            weighted_score / total_weight,
            target_reachability * (1.0 - sybil_cluster_score),
        )
    }

    fn sybil_cluster_score(&self, requester: &Did, target: &Did) -> f64 {
        if self.trust_reachability_score(requester, target) > 0.0 {
            return 0.0;
        }

        let inbound_sources = self
            .reputations
            .iter()
            .filter_map(|((source, subject), score)| {
                (subject == target
                    && source != requester
                    && source != target
                    && score.successes >= 2
                    && score.failures == 0
                    && score.composite() > 0.70)
                    .then_some(source)
            })
            .collect::<Vec<_>>();

        if inbound_sources.is_empty() {
            return 0.0;
        }

        let closed_praise = inbound_sources
            .iter()
            .filter(|source| {
                self.reputation(target, source).is_some_and(|score| {
                    score.successes >= 2 && score.failures == 0 && score.composite() > 0.70
                })
            })
            .count();

        (closed_praise as f64 / inbound_sources.len() as f64).clamp(0.0, 1.0)
    }

    fn governance_signals_for(&self, target: &Did, limit: usize) -> Vec<GovernanceSignal> {
        let mut judgments: Vec<&CollectiveDecision> = self
            .collective_decisions
            .values()
            .filter(|decision| decision.target.as_ref() == Some(target))
            .collect();
        judgments.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.collective_id.cmp(&b.collective_id))
                .then_with(|| a.proposal_id.cmp(&b.proposal_id))
                .then_with(|| a.decider.to_string().cmp(&b.decider.to_string()))
        });

        let start = judgments.len().saturating_sub(limit);
        judgments[start..]
            .iter()
            .map(|judgment| GovernanceSignal {
                collective_id: judgment.collective_id.clone(),
                proposal_id: judgment.proposal_id.clone(),
                decider: judgment.decider.clone(),
                outcome: judgment.outcome,
                task_id: judgment.task_id.clone(),
                claim_id: judgment.claim_id.clone(),
                truth_status: self.collective_decision_truth_status(judgment),
                reason: judgment.reason.clone(),
                timestamp: judgment.timestamp,
            })
            .collect()
    }

    fn ensure_collective(&mut self, collective_id: &str, created_at: u64) -> &mut Collective {
        self.collectives
            .entry(collective_id.to_string())
            .or_insert_with(|| Collective {
                id: collective_id.to_string(),
                name: String::new(),
                purpose: String::new(),
                members: HashSet::new(),
                workspaces: HashSet::new(),
                created_at,
            })
    }
}

impl Interaction {
    pub fn new(
        from: Did,
        to: Did,
        workspace: Option<WorkspaceId>,
        topic: impl Into<String>,
        outcome: InteractionOutcome,
        timestamp: u64,
    ) -> Self {
        let mut id_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id_bytes);
        Self {
            id: hex::encode(id_bytes),
            from,
            to,
            workspace,
            topic: topic.into(),
            outcome,
            timestamp,
            evidence: None,
        }
    }
}

fn ema(current: f64, observed: f64) -> f64 {
    (current * 0.75 + observed * 0.25).clamp(0.0, 1.0)
}

fn reachable_reputation(raw: f64, reachability: f64) -> f64 {
    (0.5 + (raw - 0.5) * reachability).clamp(0.0, 1.0)
}

fn format_args_for_note(args: &[String]) -> String {
    if args.is_empty() {
        String::new()
    } else {
        format!(" {}", args.join(" "))
    }
}

fn intent_capability_score(manifest: Option<&AgentManifest>, intent: &AgentIntent) -> f64 {
    let Some(capability) = intent.capability.as_deref() else {
        return match intent.kind {
            IntentKind::Offer | IntentKind::Status => 0.45,
            IntentKind::Goal | IntentKind::Proposal => 0.55,
            IntentKind::Need => 0.50,
        };
    };
    let Some(manifest) = manifest else {
        return 0.25;
    };

    if manifest.provides_named(capability) {
        return match intent.kind {
            IntentKind::Need => 1.0,
            IntentKind::Goal | IntentKind::Proposal => 0.90,
            IntentKind::Status | IntentKind::Offer => 0.70,
        };
    }
    if manifest.requires.iter().any(|decl| decl.name == capability) {
        return match intent.kind {
            IntentKind::Offer => 0.95,
            IntentKind::Proposal | IntentKind::Status => 0.70,
            IntentKind::Goal | IntentKind::Need => 0.45,
        };
    }

    0.20
}

fn intent_workspace_score(workspaces: &HashSet<WorkspaceId>, intent: &AgentIntent) -> f64 {
    match intent.workspace {
        Some(workspace) if workspaces.contains(&workspace) => 1.0,
        Some(_) => 0.35,
        None => 0.55,
    }
}

fn intent_response_score(responses: &[&IntentResponse]) -> f64 {
    if responses
        .iter()
        .any(|response| response.kind == IntentResponseKind::Fulfilled)
    {
        return 0.0;
    }
    if responses
        .iter()
        .any(|response| response.kind == IntentResponseKind::Accept)
    {
        return 0.35;
    }
    let interested = responses
        .iter()
        .filter(|response| {
            matches!(
                response.kind,
                IntentResponseKind::Interested | IntentResponseKind::Counter
            )
        })
        .count();

    (1.0 - interested as f64 * 0.12).clamp(0.20, 1.0)
}

fn intent_preference_score(manifest: Option<&AgentManifest>, intent: &AgentIntent) -> f64 {
    let Some(manifest) = manifest else {
        return 0.5;
    };
    let mut declared = Vec::new();
    declared.extend(manifest.goals.iter().map(String::as_str));
    declared.extend(manifest.values.iter().map(String::as_str));
    declared.extend(manifest.preferences.iter().map(String::as_str));
    declared.extend(manifest.workspace_roles.iter().map(String::as_str));

    if declared.is_empty() || intent.tags.is_empty() {
        return 0.5;
    }

    let matches = intent
        .tags
        .iter()
        .filter(|tag| {
            declared
                .iter()
                .any(|value| social_text_matches(value, tag.as_str()))
        })
        .count();

    if matches == 0 {
        0.5
    } else {
        (0.65 + matches as f64 * 0.10).clamp(0.0, 1.0)
    }
}

struct IntentActionContext {
    capability_score: f64,
    workspace_score: f64,
    social_score: f64,
    reputation_score: f64,
    response_score: f64,
    preference_score: f64,
    response_count: usize,
    fulfilled: bool,
}

fn intent_action_plans(
    actor: &Did,
    manifest: Option<&AgentManifest>,
    intent: &AgentIntent,
    context: &IntentActionContext,
) -> Vec<IntentActionPlan> {
    let mut actions = Vec::new();
    if context.fulfilled {
        return actions;
    }

    let base_confidence = (context.capability_score * 0.35
        + context.workspace_score * 0.15
        + context.social_score * 0.20
        + context.reputation_score * 0.15
        + context.response_score * 0.10
        + context.preference_score * 0.05)
        .clamp(0.0, 1.0);

    let response_kind = if context.capability_score >= 0.75 {
        IntentResponseKind::Interested
    } else if matches!(intent.kind, IntentKind::Offer | IntentKind::Proposal) {
        IntentResponseKind::Counter
    } else {
        IntentResponseKind::Decline
    };
    actions.push(IntentActionPlan {
        kind: IntentActionKind::RespondIntent,
        event_hint: "event intent-response".into(),
        intent_id: intent.id.clone(),
        actor: actor.clone(),
        peer: intent.author.clone(),
        title: match response_kind {
            IntentResponseKind::Interested => "Respond with interest".into(),
            IntentResponseKind::Counter => "Open a counter-proposal".into(),
            IntentResponseKind::Decline => "Decline this intent".into(),
            IntentResponseKind::Accept => "Accept this intent".into(),
            IntentResponseKind::Fulfilled => "Mark intent fulfilled".into(),
        },
        body: response_body_for_intent(manifest, intent, response_kind),
        confidence: base_confidence,
        workspace: intent.workspace,
        task_id: intent.task_id.clone(),
        capability: intent.capability.clone(),
        response_kind: Some(response_kind),
        suggested_price: None,
        estimated_time_secs: None,
    });

    if context.capability_score >= 0.75 {
        if let Some(task_id) = intent.task_id.clone() {
            actions.push(IntentActionPlan {
                kind: IntentActionKind::OfferTask,
                event_hint: "event task-offer".into(),
                intent_id: intent.id.clone(),
                actor: actor.clone(),
                peer: intent.author.clone(),
                title: "Offer to execute the referenced task".into(),
                body: task_offer_body_for_intent(manifest, intent),
                confidence: (base_confidence + 0.08).clamp(0.0, 1.0),
                workspace: intent.workspace,
                task_id: Some(task_id),
                capability: intent.capability.clone(),
                response_kind: None,
                suggested_price: intent
                    .capability
                    .as_deref()
                    .and_then(|capability| {
                        manifest.and_then(|manifest| manifest.find_provided(capability))
                    })
                    .map(|capability| capability.price_per_unit),
                estimated_time_secs: Some(0),
            });
        }
    }

    if intent.workspace.is_some() && context.workspace_score < 1.0 {
        actions.push(IntentActionPlan {
            kind: IntentActionKind::JoinWorkspace,
            event_hint: "event workspace-join".into(),
            intent_id: intent.id.clone(),
            actor: actor.clone(),
            peer: intent.author.clone(),
            title: "Join the referenced workspace".into(),
            body: "Publish presence in the workspace before deeper collaboration".into(),
            confidence: (base_confidence * 0.85).clamp(0.0, 1.0),
            workspace: intent.workspace,
            task_id: intent.task_id.clone(),
            capability: intent.capability.clone(),
            response_kind: None,
            suggested_price: None,
            estimated_time_secs: None,
        });
    }

    if matches!(intent.kind, IntentKind::Proposal | IntentKind::Goal)
        && context.preference_score >= 0.6
        && context.response_count == 0
    {
        actions.push(IntentActionPlan {
            kind: IntentActionKind::ProposeCollective,
            event_hint: "event collective-proposal".into(),
            intent_id: intent.id.clone(),
            actor: actor.clone(),
            peer: intent.author.clone(),
            title: "Escalate to collective proposal".into(),
            body: format!("Coordinate around intent {}: {}", intent.id, intent.title),
            confidence: (base_confidence * 0.75).clamp(0.0, 1.0),
            workspace: intent.workspace,
            task_id: intent.task_id.clone(),
            capability: intent.capability.clone(),
            response_kind: None,
            suggested_price: None,
            estimated_time_secs: None,
        });
    }

    actions.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| action_kind_order(a.kind).cmp(&action_kind_order(b.kind)))
            .then_with(|| a.title.cmp(&b.title))
    });
    actions
}

fn response_body_for_intent(
    manifest: Option<&AgentManifest>,
    intent: &AgentIntent,
    response_kind: IntentResponseKind,
) -> String {
    match response_kind {
        IntentResponseKind::Interested => {
            let name = manifest
                .map(|manifest| manifest.name.as_str())
                .unwrap_or("this agent");
            if let Some(capability) = intent.capability.as_deref() {
                format!("{name} can help with {capability}: {}", intent.title)
            } else {
                format!("{name} is interested in this intent: {}", intent.title)
            }
        }
        IntentResponseKind::Counter => {
            format!(
                "Counter-proposal requested before acting on: {}",
                intent.title
            )
        }
        IntentResponseKind::Decline => {
            format!(
                "Declining for now because this intent is not a strong local match: {}",
                intent.title
            )
        }
        IntentResponseKind::Accept => format!("Accepting intent: {}", intent.title),
        IntentResponseKind::Fulfilled => format!("Intent fulfilled: {}", intent.title),
    }
}

fn task_offer_body_for_intent(manifest: Option<&AgentManifest>, intent: &AgentIntent) -> String {
    let name = manifest
        .map(|manifest| manifest.name.as_str())
        .unwrap_or("this agent");
    match intent.capability.as_deref() {
        Some(capability) => format!("{name} can offer {capability} for intent {}", intent.id),
        None => format!("{name} can offer work for intent {}", intent.id),
    }
}

fn action_kind_order(kind: IntentActionKind) -> u8 {
    match kind {
        IntentActionKind::RespondIntent => 0,
        IntentActionKind::OfferTask => 1,
        IntentActionKind::JoinWorkspace => 2,
        IntentActionKind::ProposeCollective => 3,
    }
}

#[allow(clippy::too_many_arguments)]
fn intent_recommendation_reasons(
    intent: &AgentIntent,
    capability_score: f64,
    workspace_score: f64,
    social_score: f64,
    reputation_score: f64,
    preference_score: f64,
    response_count: usize,
    fulfilled: bool,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if let Some(capability) = intent.capability.as_deref() {
        if capability_score >= 0.9 {
            reasons.push(format!("capability:{capability}"));
        } else if capability_score <= 0.25 {
            reasons.push(format!("capability-gap:{capability}"));
        }
    }
    if intent.workspace.is_some() {
        if workspace_score >= 1.0 {
            reasons.push("shared-workspace".into());
        } else if workspace_score <= 0.35 {
            reasons.push("new-workspace".into());
        }
    }
    if social_score >= 0.7 {
        reasons.push("trusted-author".into());
    }
    if reputation_score >= 0.7 {
        reasons.push("positive-history".into());
    }
    if preference_score > 0.5 {
        reasons.push("preference-match".into());
    }
    if response_count == 0 {
        reasons.push("unanswered".into());
    } else {
        reasons.push(format!("responses:{response_count}"));
    }
    if fulfilled {
        reasons.push("fulfilled".into());
    }
    reasons
}

fn social_text_matches(value: &str, needle: &str) -> bool {
    value.eq_ignore_ascii_case(needle)
        || value
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
}

fn intent_recommendation_order(
    a: &IntentRecommendation,
    b: &IntentRecommendation,
) -> std::cmp::Ordering {
    b.ranking_score
        .partial_cmp(&a.ranking_score)
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| {
            b.capability_score
                .partial_cmp(&a.capability_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| {
            b.workspace_score
                .partial_cmp(&a.workspace_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| a.intent.created_at.cmp(&b.intent.created_at))
        .then_with(|| {
            a.intent
                .author
                .to_string()
                .cmp(&b.intent.author.to_string())
        })
        .then_with(|| a.intent.id.cmp(&b.intent.id))
}

fn intent_response_order(a: &&IntentResponse, b: &&IntentResponse) -> std::cmp::Ordering {
    a.created_at
        .cmp(&b.created_at)
        .then_with(|| a.intent_id.cmp(&b.intent_id))
        .then_with(|| a.responder.to_string().cmp(&b.responder.to_string()))
        .then_with(|| a.id.cmp(&b.id))
}

fn is_derived_snapshot(snapshot: &WorkspaceSnapshot) -> bool {
    matches!(
        snapshot.label.as_deref(),
        Some("workspace-run" | "task-result")
    )
}

fn task_claim_judgment_from_decision(
    society: &Society,
    decision: &CollectiveDecision,
) -> TaskClaimJudgment {
    TaskClaimJudgment {
        collective_id: decision.collective_id.clone(),
        proposal_id: decision.proposal_id.clone(),
        decider: decision.decider.clone(),
        outcome: decision.outcome,
        task_id: decision.task_id.clone(),
        claim_id: decision.claim_id.clone(),
        target: decision.target.clone(),
        truth_status: society.collective_decision_truth_status(decision),
        reason: decision.reason.clone(),
        timestamp: decision.timestamp,
    }
}

fn task_claim_judgment_order(a: &TaskClaimJudgment, b: &TaskClaimJudgment) -> std::cmp::Ordering {
    a.timestamp
        .cmp(&b.timestamp)
        .then_with(|| a.collective_id.cmp(&b.collective_id))
        .then_with(|| a.proposal_id.cmp(&b.proposal_id))
        .then_with(|| a.decider.to_string().cmp(&b.decider.to_string()))
}

fn governance_score_from_signals(signals: &[GovernanceSignal]) -> f64 {
    let mut score: f64 = 0.5;
    for signal in signals {
        let observed = match signal.outcome {
            CollectiveDecisionOutcome::Accepted => 0.85,
            CollectiveDecisionOutcome::Rejected => 0.15,
            CollectiveDecisionOutcome::Deferred => 0.45,
            CollectiveDecisionOutcome::Disputed => 0.05,
        };
        let weighted = match signal.truth_status {
            FactTruthStatus::Anchored => observed,
            FactTruthStatus::Claimed => 0.5 + (observed - 0.5) * 0.5,
        };
        score = ema(score, weighted);
    }
    score.clamp(0.0, 1.0)
}

fn task_result_matches_task_commitment(result: &TaskResult, task: &Task) -> bool {
    if let Some(receipt) = result.receipt.as_deref() {
        receipt.command == task.command && receipt.args == task.args
    } else {
        !result.success
    }
}

fn task_result_claim_started_at(result: &TaskResult) -> u64 {
    result
        .receipt
        .as_deref()
        .map(|receipt| receipt.started_at)
        .unwrap_or_default()
}

fn task_result_claim_finished_at(result: &TaskResult) -> u64 {
    result
        .receipt
        .as_deref()
        .map(|receipt| receipt.finished_at)
        .unwrap_or_default()
}

fn task_result_claim_command(result: &TaskResult) -> &str {
    result
        .receipt
        .as_deref()
        .map(|receipt| receipt.command.as_str())
        .unwrap_or_default()
}

fn task_result_claim_args(result: &TaskResult) -> &[String] {
    result
        .receipt
        .as_deref()
        .map(|receipt| receipt.args.as_slice())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{AgentManifest, CapabilityDecl};
    use crate::protocol::SocialEventKind;
    use crate::task::{
        ExecutionAttestation, ExecutionReceipt, TaskOffer, TaskResult, TaskSpec, TaskState,
    };
    use nexus_core::PermissionSet;
    use nexus_crypto::capability::sign_capability;
    use nexus_crypto::NodeIdentity;
    use nexus_economy::{
        AnchoredCheckpoint, AuthorityAnchor, AuthorityKind, LightningSettlement,
        MutualCreditSettlement, SettlementProof, StateCheckpoint,
    };
    use nexus_runtime::{ProcessOutput, ResourceUsage};
    use sha2::{Digest, Sha256};

    fn did(s: &str) -> Did {
        Did::new(format!("did:key:{s}"))
    }

    fn hash_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn interaction_builds_social_edge() {
        let alice = did("alice");
        let bob = did("bob");
        let mut society = Society::new();

        society.record_interaction(Interaction::new(
            alice.clone(),
            bob.clone(),
            None,
            "shared workspace run",
            InteractionOutcome::Success,
            10,
        ));

        let edge = society.edge(&alice, &bob).unwrap();
        assert_eq!(edge.successes, 1);
        assert!(edge.score() > 0.5);
        let reputation = society.reputation(&alice, &bob).unwrap();
        assert_eq!(reputation.successes, 1);
        assert!(reputation.composite() > 0.5);
        assert_eq!(society.interaction_count(), 1);
    }

    #[test]
    fn settlement_events_record_verifiable_economic_facts_without_reputation() {
        let payer = did("payer");
        let payee = did("payee");
        let preimage = [13u8; 32];
        let settlement = SettlementRecord {
            id: "settlement-1".into(),
            task_id: Some("task-1".into()),
            claim_id: Some("claim-1".into()),
            payer: payer.clone(),
            payee: payee.clone(),
            amount: 42,
            proof: SettlementProof::Lightning(LightningSettlement {
                amount_msat: 42_000,
                payment_hash_hex: hex::encode(Sha256::digest(preimage)),
                preimage_hex: hex::encode(preimage),
            }),
            settled_at: 10,
        };
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            payer.clone(),
            11,
            SocialEventKind::SettlementRecorded { settlement },
        ));

        assert!(society.settlement("settlement-1").is_some());
        assert_eq!(society.task_settlements("task-1").len(), 1);
        assert!(society.reputations().is_empty());
        assert!(society.interactions().is_empty());
        assert!(society.has_agent(&payer));
        assert!(society.has_agent(&payee));
    }

    #[test]
    fn mutual_credit_settlement_with_forged_counterparty_signature_is_ignored() {
        let payer = NodeIdentity::generate();
        let payee = NodeIdentity::generate();
        let forged_payload = MutualCreditSettlement::counterparty_signing_payload(
            "ledger-tx-1",
            43,
            payer.did(),
            payee.did(),
        )
        .unwrap();
        let settlement = SettlementRecord {
            id: "settlement-forged".into(),
            task_id: Some("task-1".into()),
            claim_id: None,
            payer: payer.did().clone(),
            payee: payee.did().clone(),
            amount: 42,
            proof: SettlementProof::MutualCredit(MutualCreditSettlement {
                counterparty: payee.did().clone(),
                amount: 42,
                ledger_tx_id: "ledger-tx-1".into(),
                counterparty_signature: payee.sign(&forged_payload).to_bytes().to_vec(),
            }),
            settled_at: 10,
        };
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            payer.did().clone(),
            11,
            SocialEventKind::SettlementRecorded { settlement },
        ));

        assert!(society.settlement("settlement-forged").is_none());
        assert!(society.settlements().is_empty());
    }

    #[test]
    fn settlement_truth_status_distinguishes_claimed_and_anchored_facts() {
        let payer = did("payer");
        let payee = did("payee");
        let alice = did("alice");
        let bob = did("bob");
        let mut society = Society::new();
        society.apply_event(&SocialEvent::new(
            alice.clone(),
            9,
            SocialEventKind::CollectiveDeclared {
                collective_id: "audit-lab".into(),
                name: "Audit Lab".into(),
                purpose: "witness settlement finality".into(),
                members: vec![alice.clone(), bob.clone()],
            },
        ));
        let claimed = SettlementRecord {
            id: "settlement-claimed".into(),
            task_id: Some("task-1".into()),
            claim_id: None,
            payer: payer.clone(),
            payee: payee.clone(),
            amount: 42,
            proof: SettlementProof::Sovereign,
            settled_at: 10,
        };
        society.apply_event(&SocialEvent::new(
            payer.clone(),
            10,
            SocialEventKind::SettlementRecorded {
                settlement: claimed,
            },
        ));

        let checkpoint = StateCheckpoint {
            version: 1,
            subject: "settlement:settlement-anchored".into(),
            social_root_hex: Some(hash_hex(1)),
            workspace_root_hex: None,
            ledger_root_hex: Some(hash_hex(2)),
            policy_id: "settlement-finality-v1".into(),
            timestamp: 11,
        };
        let anchor = AuthorityAnchor {
            kind: AuthorityKind::CollectiveQuorum,
            commitment_hex: checkpoint.commitment_hex().unwrap(),
            locator: Some("collective:audit-lab/proposal:settlement-anchored".into()),
            attestors: vec![alice, bob],
            threshold: Some(2),
        };
        let anchored = SettlementRecord {
            id: "settlement-anchored".into(),
            task_id: Some("task-2".into()),
            claim_id: None,
            payer: payer.clone(),
            payee: payee.clone(),
            amount: 100,
            proof: SettlementProof::AnchoredCheckpoint(AnchoredCheckpoint { checkpoint, anchor }),
            settled_at: 11,
        };
        society.apply_event(&SocialEvent::new(
            payer,
            11,
            SocialEventKind::SettlementRecorded {
                settlement: anchored,
            },
        ));

        assert_eq!(
            society.settlement_truth_status(society.settlement("settlement-claimed").unwrap()),
            FactTruthStatus::Claimed
        );
        let stored = society.settlement("settlement-anchored").unwrap();
        assert_eq!(
            society.settlement_truth_status(stored),
            FactTruthStatus::Anchored
        );
        assert!(stored.authority_anchor().is_some());
    }

    #[test]
    fn collective_quorum_settlement_requires_member_attestors_and_matching_subject() {
        let payer = did("payer");
        let payee = did("payee");
        let alice = did("alice");
        let bob = did("bob");
        let outsider = did("outsider");
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            alice.clone(),
            1,
            SocialEventKind::CollectiveDeclared {
                collective_id: "audit-lab".into(),
                name: "Audit Lab".into(),
                purpose: "witness settlement finality".into(),
                members: vec![alice.clone(), bob.clone()],
            },
        ));

        for (id, subject, attestors) in [
            (
                "settlement-member-quorum",
                "settlement:settlement-member-quorum",
                vec![alice.clone(), bob.clone()],
            ),
            (
                "settlement-outsider-quorum",
                "settlement:settlement-outsider-quorum",
                vec![alice.clone(), outsider],
            ),
            (
                "settlement-wrong-subject",
                "settlement:someone-else",
                vec![alice, bob],
            ),
        ] {
            let checkpoint = StateCheckpoint {
                version: 1,
                subject: subject.into(),
                social_root_hex: Some(hash_hex(id.len() as u8)),
                workspace_root_hex: None,
                ledger_root_hex: Some(hash_hex(id.len() as u8 + 1)),
                policy_id: "settlement-finality-v1".into(),
                timestamp: 20,
            };
            let settlement = SettlementRecord {
                id: id.into(),
                task_id: None,
                claim_id: None,
                payer: payer.clone(),
                payee: payee.clone(),
                amount: 10,
                proof: SettlementProof::AnchoredCheckpoint(AnchoredCheckpoint {
                    anchor: AuthorityAnchor {
                        kind: AuthorityKind::CollectiveQuorum,
                        commitment_hex: checkpoint.commitment_hex().unwrap(),
                        locator: Some("collective:audit-lab/proposal:settlement-finality".into()),
                        attestors,
                        threshold: Some(2),
                    },
                    checkpoint,
                }),
                settled_at: 20,
            };
            society.apply_event(&SocialEvent::new(
                payer.clone(),
                20,
                SocialEventKind::SettlementRecorded { settlement },
            ));
        }

        assert_eq!(
            society
                .settlement_truth_status(society.settlement("settlement-member-quorum").unwrap()),
            FactTruthStatus::Anchored
        );
        assert_eq!(
            society
                .settlement("settlement-outsider-quorum")
                .unwrap()
                .truth_status(),
            FactTruthStatus::Anchored
        );
        assert_eq!(
            society
                .settlement_truth_status(society.settlement("settlement-outsider-quorum").unwrap()),
            FactTruthStatus::Claimed
        );
        assert_eq!(
            society
                .settlement("settlement-wrong-subject")
                .unwrap()
                .truth_status(),
            FactTruthStatus::Anchored
        );
        assert_eq!(
            society
                .settlement_truth_status(society.settlement("settlement-wrong-subject").unwrap()),
            FactTruthStatus::Claimed
        );
    }

    #[test]
    fn recommendations_ignore_blocked_edges() {
        let alice = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let mut society = Society::new();

        society.relate(alice.clone(), bob.clone(), RelationKind::Collaborator, 1);
        society.relate(alice.clone(), carol, RelationKind::Blocked, 1);
        society.record_interaction(Interaction::new(
            alice.clone(),
            bob.clone(),
            None,
            "finished task",
            InteractionOutcome::Success,
            2,
        ));

        let recs = society.recommend_collaborators(&alice, 10);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].to, bob);
    }

    #[test]
    fn collective_tracks_members_and_workspaces() {
        let alice = did("alice");
        let bob = did("bob");
        let ws = WorkspaceId::from_bytes([7; 32]);
        let mut society = Society::new();

        society.create_collective(
            "lab".into(),
            "Open AI Lab".into(),
            "research freely".into(),
            [alice, bob],
            1,
        );
        assert!(society.attach_workspace("lab", ws));

        let lab = society.collective("lab").unwrap();
        assert_eq!(lab.members.len(), 2);
        assert!(lab.workspaces.contains(&ws));
    }

    #[test]
    fn capability_grant_events_index_workspace_invitations() {
        let issuer = NodeIdentity::generate();
        let subject = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([8; 32]);
        let grant = CapabilityGrant {
            capability: sign_capability(
                &issuer,
                subject.did(),
                workspace,
                PermissionSet::READ_WRITE,
                100,
            )
            .unwrap(),
            issued_at: 1,
            note: Some("join shared lab".into()),
        };
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            issuer.did().clone(),
            1,
            SocialEventKind::CapabilityIssued { grant },
        ));

        assert!(society.has_agent(issuer.did()));
        assert!(society.has_agent(subject.did()));
        assert_eq!(society.workspace_ids(), vec![workspace]);
        assert_eq!(society.workspace_capability_grants(&workspace).len(), 1);
        assert_eq!(society.agent_capability_grants(subject.did()).len(), 1);
        assert_eq!(
            society.capability_grants()[0].capability.subject,
            subject.did().clone()
        );
    }

    #[test]
    fn identity_revocation_marks_agent_revoked() {
        let identity = NodeIdentity::generate();
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            identity.did().clone(),
            1,
            SocialEventKind::IdentityRevoked {
                revocation: IdentityRevocation {
                    did: identity.did().clone(),
                    reason: Some("key compromised".into()),
                    revoked_at: 1,
                },
            },
        ));

        assert!(society.has_agent(identity.did()));
        assert!(society.is_identity_revoked(identity.did()));
        let revocation = society.identity_revocation(identity.did()).unwrap();
        assert_eq!(revocation.did, *identity.did());
        assert_eq!(revocation.reason.as_deref(), Some("key compromised"));
        assert_eq!(society.identity_revocations().len(), 1);
    }

    #[test]
    fn capability_revocation_marks_existing_grant_revoked() {
        let issuer = NodeIdentity::generate();
        let subject = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([18; 32]);
        let grant = CapabilityGrant {
            capability: sign_capability(
                &issuer,
                subject.did(),
                workspace,
                PermissionSet::READ_WRITE,
                100,
            )
            .unwrap(),
            issued_at: 1,
            note: Some("join shared lab".into()),
        };
        let signature_id = capability_signature_id(&grant.capability.signature);
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            issuer.did().clone(),
            1,
            SocialEventKind::CapabilityIssued {
                grant: grant.clone(),
            },
        ));
        society.apply_event(&SocialEvent::new(
            issuer.did().clone(),
            2,
            SocialEventKind::CapabilityRevoked {
                revocation: CapabilityRevocation {
                    issuer: issuer.did().clone(),
                    capability_signature_id: signature_id.clone(),
                    reason: Some("access rotated".into()),
                    revoked_at: 2,
                },
            },
        ));

        let stored = society.capability_grants()[0];
        let revocation = society.capability_revocation(stored).unwrap();
        assert_eq!(revocation.capability_signature_id, signature_id);
        assert_eq!(society.capability_revocations().len(), 1);
    }

    #[test]
    fn capability_revocation_by_non_issuer_is_ignored() {
        let issuer = NodeIdentity::generate();
        let subject = NodeIdentity::generate();
        let attacker = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([19; 32]);
        let grant = CapabilityGrant {
            capability: sign_capability(
                &issuer,
                subject.did(),
                workspace,
                PermissionSet::READ_WRITE,
                100,
            )
            .unwrap(),
            issued_at: 1,
            note: None,
        };
        let signature_id = capability_signature_id(&grant.capability.signature);
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            issuer.did().clone(),
            1,
            SocialEventKind::CapabilityIssued {
                grant: grant.clone(),
            },
        ));
        society.apply_event(&SocialEvent::new(
            attacker.did().clone(),
            2,
            SocialEventKind::CapabilityRevoked {
                revocation: CapabilityRevocation {
                    issuer: attacker.did().clone(),
                    capability_signature_id: signature_id,
                    reason: Some("forged revoke".into()),
                    revoked_at: 2,
                },
            },
        ));

        let stored = society.capability_grants()[0];
        assert!(society.capability_revocation(stored).is_none());
        assert!(society.capability_revocations().is_empty());
    }

    #[test]
    fn workspace_snapshot_events_index_workspace_roots() {
        let actor = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([9; 32]);
        let first_root = nexus_storage::Cid::hash_of(b"first");
        let second_root = nexus_storage::Cid::hash_of(b"second");
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            actor.did().clone(),
            1,
            SocialEventKind::WorkspaceSnapshotted {
                snapshot: WorkspaceSnapshot {
                    workspace,
                    actor: actor.did().clone(),
                    root: first_root,
                    label: Some("before".into()),
                    note: None,
                    timestamp: 1,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            actor.did().clone(),
            2,
            SocialEventKind::WorkspaceSnapshotted {
                snapshot: WorkspaceSnapshot {
                    workspace,
                    actor: actor.did().clone(),
                    root: second_root,
                    label: Some("after".into()),
                    note: Some("finished a run".into()),
                    timestamp: 2,
                },
            },
        ));

        let snapshots = society.workspace_snapshots(&workspace);
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].root, first_root);
        assert_eq!(
            society.latest_workspace_snapshot(&workspace).unwrap().root,
            second_root
        );
        assert_eq!(society.workspace_ids(), vec![workspace]);
        assert!(society.has_agent(actor.did()));
    }

    #[test]
    fn workspace_run_events_index_free_workspace_execution() {
        let actor = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([10; 32]);
        let stdout = nexus_storage::Cid::hash_of(b"ok");
        let stderr = nexus_storage::Cid::hash_of(b"");
        let root = nexus_storage::Cid::hash_of(b"root");
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            actor.did().clone(),
            2,
            SocialEventKind::WorkspaceRunRecorded {
                run: Box::new(WorkspaceRun {
                    workspace,
                    actor: actor.did().clone(),
                    command: "python".into(),
                    args: vec!["analysis.py".into()],
                    exit_code: 0,
                    stdout,
                    stderr,
                    output_root: Some(root),
                    resources: ResourceUsage {
                        process_count: 1,
                        ..Default::default()
                    },
                    context: Some(WorkspaceRunContext {
                        working_dir: Some("analysis".into()),
                        env_keys: vec!["PYTHONPATH".into()],
                        stdin: Some(WorkspaceRunStdin {
                            bytes: 2,
                            cid: nexus_storage::Cid::hash_of(b"{}"),
                        }),
                        timeout_ms: Some(30_000),
                    }),
                    failure: None,
                    started_at: 1,
                    finished_at: 2,
                    note: Some("autonomous analysis".into()),
                }),
            },
        ));

        let runs = society.workspace_runs(&workspace);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].actor, actor.did().clone());
        assert_eq!(runs[0].stdout, stdout);
        assert_eq!(runs[0].output_root, Some(root));
        let context = runs[0].context.as_ref().unwrap();
        assert_eq!(context.working_dir.as_deref(), Some("analysis"));
        assert_eq!(context.env_keys, vec!["PYTHONPATH"]);
        assert_eq!(context.stdin.as_ref().unwrap().bytes, 2);
        assert_eq!(context.timeout_ms, Some(30_000));
        let snapshots = society.workspace_snapshots(&workspace);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].actor, actor.did().clone());
        assert_eq!(snapshots[0].root, root);
        assert_eq!(snapshots[0].label.as_deref(), Some("workspace-run"));
        assert_eq!(
            society.latest_workspace_snapshot(&workspace).unwrap().root,
            root
        );
        assert_eq!(society.agent_workspace_runs(actor.did()).len(), 1);
        assert_eq!(society.workspace_ids(), vec![workspace]);
        assert!(society.has_agent(actor.did()));
    }

    #[test]
    fn workspace_run_events_keep_same_second_distinct_outputs() {
        let actor = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([77; 32]);
        let mut society = Society::new();

        for stdout in [
            nexus_storage::Cid::hash_of(b"first"),
            nexus_storage::Cid::hash_of(b"second"),
        ] {
            society.apply_event(&SocialEvent::new(
                actor.did().clone(),
                2,
                SocialEventKind::WorkspaceRunRecorded {
                    run: Box::new(WorkspaceRun {
                        workspace,
                        actor: actor.did().clone(),
                        command: "python".into(),
                        args: vec!["analysis.py".into()],
                        exit_code: 0,
                        stdout,
                        stderr: nexus_storage::Cid::hash_of(b""),
                        output_root: None,
                        resources: ResourceUsage::default(),
                        context: None,
                        failure: None,
                        started_at: 1,
                        finished_at: 2,
                        note: None,
                    }),
                },
            ));
        }

        let runs = society.workspace_runs(&workspace);
        assert_eq!(runs.len(), 2);
        assert_ne!(runs[0].stdout, runs[1].stdout);
    }

    #[test]
    fn explicit_workspace_snapshot_replaces_derived_snapshot_metadata() {
        let actor = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([76; 32]);
        let root = nexus_storage::Cid::hash_of(b"root");
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            actor.did().clone(),
            2,
            SocialEventKind::WorkspaceRunRecorded {
                run: Box::new(WorkspaceRun {
                    workspace,
                    actor: actor.did().clone(),
                    command: "sh".into(),
                    args: vec!["-c".into(), "true".into()],
                    exit_code: 0,
                    stdout: nexus_storage::Cid::hash_of(b""),
                    stderr: nexus_storage::Cid::hash_of(b""),
                    output_root: Some(root),
                    resources: ResourceUsage::default(),
                    context: None,
                    failure: None,
                    started_at: 1,
                    finished_at: 2,
                    note: None,
                }),
            },
        ));
        society.apply_event(&SocialEvent::new(
            actor.did().clone(),
            2,
            SocialEventKind::WorkspaceSnapshotted {
                snapshot: WorkspaceSnapshot {
                    workspace,
                    actor: actor.did().clone(),
                    root,
                    label: Some("after:sh".into()),
                    note: Some("explicit exec snapshot".into()),
                    timestamp: 2,
                },
            },
        ));

        let snapshots = society.workspace_snapshots(&workspace);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].label.as_deref(), Some("after:sh"));
        assert_eq!(snapshots[0].note.as_deref(), Some("explicit exec snapshot"));
    }

    #[test]
    fn collective_events_merge_signed_membership_and_workspace_context() {
        let alice = did("alice");
        let bob = did("bob");
        let ws = WorkspaceId::from_bytes([70; 32]);
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            bob.clone(),
            1,
            SocialEventKind::CollectiveWorkspaceAttached {
                collective_id: "lab".into(),
                workspace: ws,
            },
        ));
        society.apply_event(&SocialEvent::new(
            alice.clone(),
            2,
            SocialEventKind::CollectiveDeclared {
                collective_id: "lab".into(),
                name: "Open Lab".into(),
                purpose: "build shared AI society".into(),
                members: vec![alice.clone()],
            },
        ));
        society.apply_event(&SocialEvent::new(
            bob.clone(),
            3,
            SocialEventKind::CollectiveJoined {
                collective_id: "lab".into(),
            },
        ));

        let lab = society.collective("lab").unwrap();
        assert_eq!(lab.name, "Open Lab");
        assert_eq!(lab.purpose, "build shared AI society");
        assert_eq!(lab.created_at, 1);
        assert!(lab.members.contains(&alice));
        assert!(lab.members.contains(&bob));
        assert!(lab.workspaces.contains(&ws));
        assert_eq!(society.collectives()[0].id, "lab");
    }

    #[test]
    fn collective_governance_events_track_proposals_votes_and_decisions() {
        let alice = did("alice");
        let bob = did("bob");
        let ws = WorkspaceId::from_bytes([71; 32]);
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            alice.clone(),
            1,
            SocialEventKind::CollectiveDeclared {
                collective_id: "lab".into(),
                name: "Open Lab".into(),
                purpose: "coordinate society work".into(),
                members: vec![alice.clone()],
            },
        ));
        society.apply_event(&SocialEvent::new(
            bob.clone(),
            2,
            SocialEventKind::CollectiveJoined {
                collective_id: "lab".into(),
            },
        ));
        society.apply_event(&SocialEvent::new(
            alice.clone(),
            3,
            SocialEventKind::CollectiveProposalPublished {
                proposal: CollectiveProposal {
                    id: "proposal-1".into(),
                    collective_id: "lab".into(),
                    proposer: alice.clone(),
                    title: "Open shared workspace".into(),
                    body: "use workspace for a society run".into(),
                    workspace: Some(ws),
                    created_at: 3,
                    deadline: 30,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            bob.clone(),
            4,
            SocialEventKind::CollectiveVoteCast {
                vote: CollectiveVote {
                    proposal_id: "proposal-1".into(),
                    collective_id: "lab".into(),
                    voter: bob.clone(),
                    choice: CollectiveVoteChoice::Approve,
                    rationale: "useful coordination".into(),
                    timestamp: 4,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            alice.clone(),
            5,
            SocialEventKind::CollectiveDecisionRecorded {
                decision: CollectiveDecision {
                    proposal_id: "proposal-1".into(),
                    collective_id: "lab".into(),
                    decider: alice.clone(),
                    outcome: CollectiveDecisionOutcome::Accepted,
                    task_id: None,
                    claim_id: None,
                    target: None,
                    anchor: None,
                    reason: "approved by known members".into(),
                    timestamp: 5,
                },
            },
        ));

        let proposals = society.collective_proposals("lab");
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].title, "Open shared workspace");
        assert_eq!(proposals[0].workspace, Some(ws));

        let votes = society.collective_votes("lab", "proposal-1");
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].voter, bob);
        assert_eq!(votes[0].choice, CollectiveVoteChoice::Approve);

        let decision = society.collective_decision("lab", "proposal-1").unwrap();
        assert_eq!(decision.decider, alice);
        assert_eq!(decision.outcome, CollectiveDecisionOutcome::Accepted);
    }

    #[test]
    fn collective_governance_is_scoped_by_collective_and_proposal() {
        let alice = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            alice.clone(),
            1,
            SocialEventKind::CollectiveProposalPublished {
                proposal: CollectiveProposal {
                    id: "proposal-1".into(),
                    collective_id: "lab-a".into(),
                    proposer: alice.clone(),
                    title: "Use lab A workspace".into(),
                    body: "scope A".into(),
                    workspace: None,
                    created_at: 1,
                    deadline: 0,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            bob.clone(),
            1,
            SocialEventKind::CollectiveProposalPublished {
                proposal: CollectiveProposal {
                    id: "proposal-1".into(),
                    collective_id: "lab-b".into(),
                    proposer: bob.clone(),
                    title: "Use lab B workspace".into(),
                    body: "scope B".into(),
                    workspace: None,
                    created_at: 1,
                    deadline: 0,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            carol.clone(),
            2,
            SocialEventKind::CollectiveVoteCast {
                vote: CollectiveVote {
                    proposal_id: "proposal-1".into(),
                    collective_id: "lab-b".into(),
                    voter: carol.clone(),
                    choice: CollectiveVoteChoice::Reject,
                    rationale: "not ready".into(),
                    timestamp: 2,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            bob.clone(),
            3,
            SocialEventKind::CollectiveDecisionRecorded {
                decision: CollectiveDecision {
                    proposal_id: "proposal-1".into(),
                    collective_id: "lab-b".into(),
                    decider: bob.clone(),
                    outcome: CollectiveDecisionOutcome::Rejected,
                    task_id: None,
                    claim_id: None,
                    target: None,
                    anchor: None,
                    reason: "lab B declined".into(),
                    timestamp: 3,
                },
            },
        ));

        let lab_a = society.collective_proposals("lab-a");
        let lab_b = society.collective_proposals("lab-b");
        assert_eq!(lab_a.len(), 1);
        assert_eq!(lab_b.len(), 1);
        assert_eq!(lab_a[0].title, "Use lab A workspace");
        assert_eq!(lab_b[0].title, "Use lab B workspace");
        assert!(society.collective_votes("lab-a", "proposal-1").is_empty());
        assert_eq!(society.collective_votes("lab-b", "proposal-1").len(), 1);
        assert!(society.collective_decision("lab-a", "proposal-1").is_none());
        assert_eq!(
            society
                .collective_decision("lab-b", "proposal-1")
                .unwrap()
                .outcome,
            CollectiveDecisionOutcome::Rejected
        );
    }

    #[test]
    fn collective_decision_can_anchor_task_claim_judgment() {
        let auditor = did("auditor");
        let worker = did("worker");
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            auditor.clone(),
            1,
            SocialEventKind::CollectiveProposalPublished {
                proposal: CollectiveProposal {
                    id: "review-claim".into(),
                    collective_id: "audit-lab".into(),
                    proposer: auditor.clone(),
                    title: "Review claim".into(),
                    body: "judge a disputed task result claim".into(),
                    workspace: None,
                    created_at: 1,
                    deadline: 0,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            auditor.clone(),
            2,
            SocialEventKind::CollectiveDecisionRecorded {
                decision: CollectiveDecision {
                    proposal_id: "review-claim".into(),
                    collective_id: "audit-lab".into(),
                    decider: auditor.clone(),
                    outcome: CollectiveDecisionOutcome::Disputed,
                    task_id: Some("task-1".into()),
                    claim_id: Some("claim-1".into()),
                    target: Some(worker.clone()),
                    anchor: None,
                    reason: "receipt was not signed".into(),
                    timestamp: 2,
                },
            },
        ));

        let judgments = society.task_claim_judgments("task-1");
        assert_eq!(judgments.len(), 1);
        assert_eq!(judgments[0].collective_id, "audit-lab");
        assert_eq!(judgments[0].proposal_id, "review-claim");
        assert_eq!(judgments[0].claim_id.as_deref(), Some("claim-1"));
        assert_eq!(judgments[0].target.as_ref(), Some(&worker));
        assert_eq!(judgments[0].outcome, CollectiveDecisionOutcome::Disputed);
        assert_eq!(society.result_claim_judgments("task-1", "claim-1").len(), 1);
        assert!(society
            .result_claim_judgments("task-1", "claim-2")
            .is_empty());
    }

    #[test]
    fn collective_quorum_anchor_marks_decision_as_anchored_only_for_members() {
        let alice = did("alice");
        let bob = did("bob");
        let outsider = did("outsider");
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            alice.clone(),
            1,
            SocialEventKind::CollectiveDeclared {
                collective_id: "audit-lab".into(),
                name: "Audit Lab".into(),
                purpose: "witness disputed facts".into(),
                members: vec![alice.clone(), bob.clone()],
            },
        ));
        for (proposal_id, anchor) in [
            (
                "member-quorum",
                AuthorityAnchor {
                    kind: AuthorityKind::CollectiveQuorum,
                    commitment_hex: hash_hex(7),
                    locator: Some("proposal:member-quorum".into()),
                    attestors: vec![alice.clone(), bob.clone()],
                    threshold: Some(2),
                },
            ),
            (
                "outsider-quorum",
                AuthorityAnchor {
                    kind: AuthorityKind::CollectiveQuorum,
                    commitment_hex: hash_hex(8),
                    locator: Some("proposal:outsider-quorum".into()),
                    attestors: vec![alice.clone(), outsider.clone()],
                    threshold: Some(2),
                },
            ),
        ] {
            society.apply_event(&SocialEvent::new(
                alice.clone(),
                2,
                SocialEventKind::CollectiveDecisionRecorded {
                    decision: CollectiveDecision {
                        proposal_id: proposal_id.into(),
                        collective_id: "audit-lab".into(),
                        decider: alice.clone(),
                        outcome: CollectiveDecisionOutcome::Accepted,
                        task_id: Some(format!("task-{proposal_id}")),
                        claim_id: None,
                        target: Some(bob.clone()),
                        anchor: Some(anchor),
                        reason: "quorum witness".into(),
                        timestamp: 2,
                    },
                },
            ));
        }

        let anchored = society
            .collective_decision("audit-lab", "member-quorum")
            .unwrap();
        assert_eq!(
            society.collective_decision_truth_status(anchored),
            FactTruthStatus::Anchored
        );
        let claimed = society
            .collective_decision("audit-lab", "outsider-quorum")
            .unwrap();
        assert_eq!(
            society.collective_decision_truth_status(claimed),
            FactTruthStatus::Claimed
        );
        assert_eq!(
            society.task_claim_judgments("task-member-quorum")[0].truth_status,
            FactTruthStatus::Anchored
        );
        assert_eq!(
            society.task_claim_judgments("task-outsider-quorum")[0].truth_status,
            FactTruthStatus::Claimed
        );
    }

    #[test]
    fn workspace_join_events_build_presence_index() {
        let alice = did("alice");
        let bob = did("bob");
        let ws = WorkspaceId::from_bytes([8; 32]);
        let other = WorkspaceId::from_bytes([9; 32]);
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            bob.clone(),
            2,
            SocialEventKind::WorkspaceJoined { workspace: ws },
        ));
        society.apply_event(&SocialEvent::new(
            alice.clone(),
            1,
            SocialEventKind::WorkspaceJoined { workspace: ws },
        ));
        society.apply_event(&SocialEvent::new(
            alice.clone(),
            3,
            SocialEventKind::WorkspaceJoined { workspace: ws },
        ));
        society.apply_event(&SocialEvent::new(
            alice.clone(),
            4,
            SocialEventKind::WorkspaceJoined { workspace: other },
        ));

        let members = society.workspace_members(&ws);
        assert_eq!(members, vec![&alice, &bob]);
        assert_eq!(society.agent_workspaces(&alice), vec![ws, other]);
        assert_eq!(society.agent_workspaces(&bob), vec![ws]);
    }

    #[test]
    fn workspace_ownership_claims_are_distinct_from_local_membership() {
        let owner = did("owner");
        let guest = did("guest");
        let ws = WorkspaceId::from_bytes([10; 32]);
        let root = nexus_storage::Cid::hash_of(b"owner root");
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            guest.clone(),
            1,
            SocialEventKind::WorkspaceJoined { workspace: ws },
        ));
        assert_eq!(society.workspace_members(&ws), vec![&guest]);
        assert_eq!(society.workspace_claimed_owner(&ws), None);

        society.apply_event(&SocialEvent::new(
            owner.clone(),
            2,
            SocialEventKind::WorkspaceOwnershipClaimed {
                claim: WorkspaceOwnershipClaim {
                    workspace: ws,
                    owner: owner.clone(),
                    previous_owner: None,
                    root: Some(root),
                    anchor: None,
                    claimed_at: 2,
                },
            },
        ));

        assert_eq!(society.workspace_members(&ws), vec![&guest]);
        assert_eq!(society.workspace_claimed_owner(&ws), Some(owner.clone()));
        let claims = society.workspace_ownership_claims(&ws);
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].claim.owner, owner);
        assert_eq!(claims[0].truth_status, FactTruthStatus::Claimed);
    }

    #[test]
    fn workspace_ownership_transfer_requires_current_owner() {
        let owner = did("owner");
        let next_owner = did("next-owner");
        let attacker = did("attacker");
        let ws = WorkspaceId::from_bytes([11; 32]);
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            owner.clone(),
            1,
            SocialEventKind::WorkspaceOwnershipClaimed {
                claim: WorkspaceOwnershipClaim {
                    workspace: ws,
                    owner: owner.clone(),
                    previous_owner: None,
                    root: None,
                    anchor: None,
                    claimed_at: 1,
                },
            },
        ));
        assert_eq!(society.workspace_claimed_owner(&ws), Some(owner.clone()));

        society.apply_event(&SocialEvent::new(
            attacker.clone(),
            2,
            SocialEventKind::WorkspaceOwnershipClaimed {
                claim: WorkspaceOwnershipClaim {
                    workspace: ws,
                    owner: attacker.clone(),
                    previous_owner: None,
                    root: None,
                    anchor: None,
                    claimed_at: 2,
                },
            },
        ));
        assert_eq!(society.workspace_claimed_owner(&ws), Some(owner.clone()));

        society.apply_event(&SocialEvent::new(
            attacker,
            3,
            SocialEventKind::WorkspaceOwnershipTransferred {
                claim: WorkspaceOwnershipClaim {
                    workspace: ws,
                    owner: next_owner.clone(),
                    previous_owner: Some(owner.clone()),
                    root: None,
                    anchor: None,
                    claimed_at: 3,
                },
            },
        ));
        assert_eq!(society.workspace_claimed_owner(&ws), Some(owner.clone()));

        society.apply_event(&SocialEvent::new(
            owner,
            4,
            SocialEventKind::WorkspaceOwnershipTransferred {
                claim: WorkspaceOwnershipClaim {
                    workspace: ws,
                    owner: next_owner.clone(),
                    previous_owner: Some(did("owner")),
                    root: None,
                    anchor: None,
                    claimed_at: 4,
                },
            },
        ));
        assert_eq!(society.workspace_claimed_owner(&ws), Some(next_owner));
    }

    fn provider_manifest(did: Did, name: &str, capability: &str, price: u64) -> AgentManifest {
        AgentManifest::new(did, name, 1).provide(CapabilityDecl {
            name: capability.into(),
            description: format!("provides {capability}"),
            version: "1.0".into(),
            price_per_unit: price,
            price_unit: "per-request".into(),
        })
    }

    #[test]
    fn manifest_events_build_capability_provider_index() {
        let alice = did("alice");
        let bob = did("bob");
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            alice.clone(),
            1,
            SocialEventKind::ManifestPublished {
                manifest: provider_manifest(alice.clone(), "Alice", "python-exec", 9),
            },
        ));
        society.apply_event(&SocialEvent::new(
            bob.clone(),
            2,
            SocialEventKind::ManifestPublished {
                manifest: provider_manifest(bob.clone(), "Bob", "image-gen", 5),
            },
        ));

        assert_eq!(society.manifest_count(), 2);
        assert_eq!(society.agent_manifest(&alice).unwrap().name, "Alice");

        let providers = society.find_providers("python-exec");
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].did, alice);
        assert_eq!(providers[0].capability.name, "python-exec");
    }

    #[test]
    fn completed_receipted_task_marks_capability_verified() {
        let publisher = did("publisher");
        let worker = NodeIdentity::generate();
        let attestor = NodeIdentity::generate();
        let worker_did = worker.did().clone();
        let mut society = Society::new();
        let task = TaskSpec::new(
            publisher.clone(),
            "verify python execution",
            "python-exec",
            "python",
            vec!["verify.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();
        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let receipt = ExecutionReceipt::from_process_output(
            task_id.clone(),
            worker_did.clone(),
            None,
            "python",
            vec!["verify.py".into()],
            &output,
            None,
            4,
            5,
        )
        .sign(&worker)
        .unwrap();
        let attestation = ExecutionAttestation::from_process_output(
            &receipt,
            attestor.did().clone(),
            &output,
            None,
            6,
        )
        .sign(&attestor)
        .unwrap();

        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            1,
            SocialEventKind::ManifestPublished {
                manifest: provider_manifest(worker_did.clone(), "Worker", "python-exec", 10),
            },
        ));
        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            2,
            SocialEventKind::TaskPublished { task },
        ));
        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            3,
            SocialEventKind::TaskOffered {
                offer: TaskOffer {
                    task_id: task_id.clone(),
                    bidder: worker_did.clone(),
                    price: 10,
                    estimated_time_secs: 1,
                    rationale: "ready".into(),
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            4,
            SocialEventKind::TaskAccepted {
                acceptance: TaskAcceptance {
                    task_id: task_id.clone(),
                    publisher: publisher.clone(),
                    bidder: worker_did.clone(),
                    price: 10,
                    accepted_at: 4,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            5,
            SocialEventKind::TaskCompleted {
                result: TaskResult {
                    task_id: task_id.clone(),
                    executor: worker_did.clone(),
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 10,
                    error: None,
                    receipt: Some(Box::new(receipt)),
                    attestations: Vec::new(),
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            attestor.did().clone(),
            6,
            SocialEventKind::TaskExecutionAttested { attestation },
        ));

        let verified = society.agent_verified_capabilities(&worker_did);
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].name, "python-exec");
        assert_eq!(verified[0].successful_tasks, 1);
        assert_eq!(verified[0].independently_attested_tasks, 1);
        assert_eq!(verified[0].latest_task_id, task_id);
        assert_eq!(verified[0].latest_observed_at, 5);

        let providers = society.find_providers("python-exec");
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].verified_capability, Some(verified[0].clone()));
    }

    #[test]
    fn provider_recommendations_rank_social_trust_and_filter_blocked() {
        let requester = did("requester");
        let trusted = did("trusted");
        let cheap = did("cheap");
        let blocked = did("blocked");
        let mut society = Society::new();

        for (did, name, price) in [
            (trusted.clone(), "Trusted", 30),
            (cheap.clone(), "Cheap", 1),
            (blocked.clone(), "Blocked", 1),
        ] {
            society.apply_event(&SocialEvent::new(
                did.clone(),
                1,
                SocialEventKind::ManifestPublished {
                    manifest: provider_manifest(did, name, "python-exec", price),
                },
            ));
        }

        society.relate(
            requester.clone(),
            trusted.clone(),
            RelationKind::Collaborator,
            2,
        );
        society.record_interaction(Interaction::new(
            requester.clone(),
            trusted.clone(),
            None,
            "previous task",
            InteractionOutcome::Success,
            3,
        ));
        society.relate(requester.clone(), blocked.clone(), RelationKind::Blocked, 2);

        let providers = society.recommend_providers(&requester, "python-exec", 10);
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0].did, trusted);
        assert!(providers[0].reputation_score > providers[1].reputation_score);
        assert_eq!(providers[0].governance_score, 0.5);
        assert_eq!(providers[1].did, cheap);
        assert!(providers.iter().all(|provider| provider.did != blocked));
    }

    #[test]
    fn provider_recommendations_do_not_import_disconnected_reputation() {
        let requester = did("requester");
        let direct = did("direct");
        let sybil = did("sybil");
        let sybil_peer = did("sybil-peer");
        let mut society = Society::new();

        for (did, name, price) in [(direct.clone(), "Direct", 10), (sybil.clone(), "Sybil", 10)] {
            society.apply_event(&SocialEvent::new(
                did.clone(),
                1,
                SocialEventKind::ManifestPublished {
                    manifest: provider_manifest(did, name, "python-exec", price),
                },
            ));
        }

        society.relate(
            requester.clone(),
            direct.clone(),
            RelationKind::Collaborator,
            2,
        );
        society.record_interaction(Interaction::new(
            requester.clone(),
            direct.clone(),
            None,
            "local trial",
            InteractionOutcome::Success,
            3,
        ));
        for i in 0..8 {
            society.record_interaction(Interaction::new(
                sybil_peer.clone(),
                sybil.clone(),
                None,
                "closed loop praise",
                InteractionOutcome::Success,
                10 + i,
            ));
        }

        let providers = society.recommend_providers(&requester, "python-exec", 10);
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0].did, direct);
        let sybil_view = providers
            .iter()
            .find(|provider| provider.did == sybil)
            .unwrap();
        assert_eq!(sybil_view.reachability_score, 0.0);
        assert!((sybil_view.reputation_score - 0.5).abs() < 0.001);
    }

    #[test]
    fn provider_recommendations_use_reachable_reputation() {
        let requester = did("requester");
        let introducer = did("introducer");
        let provider = did("provider");
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            provider.clone(),
            1,
            SocialEventKind::ManifestPublished {
                manifest: provider_manifest(provider.clone(), "Provider", "python-exec", 10),
            },
        ));
        society.relate(
            requester.clone(),
            introducer.clone(),
            RelationKind::Collaborator,
            2,
        );
        society.record_interaction(Interaction::new(
            requester.clone(),
            introducer.clone(),
            None,
            "trusted introducer",
            InteractionOutcome::Success,
            3,
        ));
        society.relate(
            introducer.clone(),
            provider.clone(),
            RelationKind::Collaborator,
            4,
        );
        society.record_interaction(Interaction::new(
            introducer,
            provider.clone(),
            None,
            "introduced provider success",
            InteractionOutcome::Success,
            5,
        ));

        let providers = society.recommend_providers(&requester, "python-exec", 10);
        assert_eq!(providers.len(), 1);
        assert!(providers[0].reachability_score > 0.30);
        assert!(providers[0].reputation_score > 0.5);
    }

    #[test]
    fn provider_recommendations_require_anchor_or_reachability_for_high_trust() {
        let requester = did("requester");
        let witnessed = did("witnessed");
        let unwitnessed = did("unwitnessed");
        let alice = did("alice");
        let bob = did("bob");
        let mut society = Society::new();

        for (did, name) in [
            (witnessed.clone(), "Witnessed"),
            (unwitnessed.clone(), "Unwitnessed"),
        ] {
            society.apply_event(&SocialEvent::new(
                did.clone(),
                1,
                SocialEventKind::ManifestPublished {
                    manifest: provider_manifest(did, name, "python-exec", 10),
                },
            ));
        }
        society.apply_event(&SocialEvent::new(
            alice.clone(),
            2,
            SocialEventKind::CollectiveDeclared {
                collective_id: "audit-lab".into(),
                name: "Audit Lab".into(),
                purpose: "witness provider claims".into(),
                members: vec![alice.clone(), bob.clone()],
            },
        ));
        society.apply_event(&SocialEvent::new(
            alice,
            3,
            SocialEventKind::CollectiveDecisionRecorded {
                decision: CollectiveDecision {
                    proposal_id: "approve-witnessed".into(),
                    collective_id: "audit-lab".into(),
                    decider: bob.clone(),
                    outcome: CollectiveDecisionOutcome::Accepted,
                    task_id: None,
                    claim_id: None,
                    target: Some(witnessed.clone()),
                    anchor: Some(AuthorityAnchor {
                        kind: AuthorityKind::CollectiveQuorum,
                        commitment_hex: hash_hex(9),
                        locator: Some("collective:audit-lab/proposal:approve-witnessed".into()),
                        attestors: vec![bob.clone(), did("alice")],
                        threshold: Some(2),
                    }),
                    reason: "provider claim witnessed".into(),
                    timestamp: 3,
                },
            },
        ));

        let providers = society.recommend_providers(&requester, "python-exec", 10);
        let witnessed_view = providers
            .iter()
            .find(|provider| provider.did == witnessed)
            .unwrap();
        let unwitnessed_view = providers
            .iter()
            .find(|provider| provider.did == unwitnessed)
            .unwrap();

        assert_eq!(witnessed_view.reachability_score, 0.0);
        assert!(witnessed_view.governance_score > 0.5);
        assert!(witnessed_view.high_trust_eligible);
        assert_eq!(unwitnessed_view.reachability_score, 0.0);
        assert!(!unwitnessed_view.high_trust_eligible);
    }

    #[test]
    fn provider_recommendations_downrank_closed_mutual_praise() {
        let requester = did("requester");
        let sybil_a = did("sybil-a");
        let sybil_b = did("sybil-b");
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            sybil_a.clone(),
            1,
            SocialEventKind::ManifestPublished {
                manifest: provider_manifest(sybil_a.clone(), "Sybil A", "python-exec", 10),
            },
        ));
        for i in 0..4 {
            society.record_interaction(Interaction::new(
                sybil_b.clone(),
                sybil_a.clone(),
                None,
                "mutual praise a",
                InteractionOutcome::Success,
                10 + i,
            ));
            society.record_interaction(Interaction::new(
                sybil_a.clone(),
                sybil_b.clone(),
                None,
                "mutual praise b",
                InteractionOutcome::Success,
                20 + i,
            ));
        }

        let providers = society.recommend_providers(&requester, "python-exec", 10);
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].reachability_score, 0.0);
        assert_eq!(providers[0].sybil_cluster_score, 1.0);
        assert!((providers[0].reputation_score - 0.5).abs() < 0.001);
        assert!(providers[0].ranking_score <= 0.60);
    }

    #[test]
    fn provider_recommendations_include_collective_claim_judgments() {
        let requester = did("requester");
        let approved = did("approved");
        let disputed = did("disputed");
        let decider = did("decider");
        let mut society = Society::new();

        for (did, name) in [
            (approved.clone(), "Approved"),
            (disputed.clone(), "Disputed"),
        ] {
            society.apply_event(&SocialEvent::new(
                did.clone(),
                1,
                SocialEventKind::ManifestPublished {
                    manifest: provider_manifest(did, name, "python-exec", 10),
                },
            ));
        }

        for (proposal_id, target, outcome) in [
            (
                "approve-claim",
                approved.clone(),
                CollectiveDecisionOutcome::Accepted,
            ),
            (
                "dispute-claim",
                disputed.clone(),
                CollectiveDecisionOutcome::Disputed,
            ),
        ] {
            society.apply_event(&SocialEvent::new(
                decider.clone(),
                2,
                SocialEventKind::CollectiveDecisionRecorded {
                    decision: CollectiveDecision {
                        proposal_id: proposal_id.into(),
                        collective_id: "audit-lab".into(),
                        decider: decider.clone(),
                        outcome,
                        task_id: Some(format!("task-{proposal_id}")),
                        claim_id: Some(format!("claim-{proposal_id}")),
                        target: Some(target),
                        anchor: None,
                        reason: "governance signal for provider choice".into(),
                        timestamp: 2,
                    },
                },
            ));
        }

        let providers = society.recommend_providers(&requester, "python-exec", 10);
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0].did, approved);
        assert_eq!(providers[1].did, disputed);
        assert!(providers[0].governance_score > 0.5);
        assert!(providers[1].governance_score < 0.5);
        assert_eq!(providers[0].governance_signals.len(), 1);
        assert_eq!(
            providers[0].governance_signals[0].outcome,
            CollectiveDecisionOutcome::Accepted
        );
        assert_eq!(
            providers[1].governance_signals[0].claim_id.as_deref(),
            Some("claim-dispute-claim")
        );
        assert!(providers[0].ranking_score > providers[1].ranking_score);
    }

    #[test]
    fn intent_recommendations_match_capability_workspace_and_social_context() {
        let agent = did("agent");
        let trusted = did("trusted");
        let stranger = did("stranger");
        let blocked = did("blocked");
        let workspace = WorkspaceId::from_bytes([45; 32]);
        let mut society = Society::new();

        society.apply_event(&SocialEvent::new(
            agent.clone(),
            1,
            SocialEventKind::ManifestPublished {
                manifest: AgentManifest::new(agent.clone(), "agent", 1)
                    .provide(CapabilityDecl {
                        name: "code-review".into(),
                        description: "review code".into(),
                        version: "1.0".into(),
                        price_per_unit: 1,
                        price_unit: "per-request".into(),
                    })
                    .preference("high-autonomy"),
            },
        ));
        society.apply_event(&SocialEvent::new(
            agent.clone(),
            2,
            SocialEventKind::WorkspaceJoined { workspace },
        ));
        society.relate(
            agent.clone(),
            trusted.clone(),
            RelationKind::Collaborator,
            3,
        );
        society.record_interaction(Interaction::new(
            agent.clone(),
            trusted.clone(),
            Some(workspace),
            "previous collaboration",
            InteractionOutcome::Success,
            4,
        ));
        society.relate(agent.clone(), blocked.clone(), RelationKind::Blocked, 3);

        for (author, id, capability, workspace, tags) in [
            (
                trusted.clone(),
                "intent-trusted",
                "code-review",
                Some(workspace),
                vec!["high-autonomy".into()],
            ),
            (
                stranger.clone(),
                "intent-stranger",
                "image-gen",
                None,
                Vec::new(),
            ),
            (
                blocked.clone(),
                "intent-blocked",
                "code-review",
                Some(workspace),
                Vec::new(),
            ),
        ] {
            society.apply_event(&SocialEvent::new(
                author.clone(),
                10,
                SocialEventKind::IntentPublished {
                    intent: AgentIntent {
                        id: id.into(),
                        author,
                        kind: IntentKind::Need,
                        title: "Need help".into(),
                        body: "open collaboration".into(),
                        workspace,
                        task_id: None,
                        capability: Some(capability.into()),
                        tags,
                        created_at: 10,
                        expires_at: Some(100),
                    },
                },
            ));
        }
        society.apply_event(&SocialEvent::new(
            agent.clone(),
            11,
            SocialEventKind::IntentResponded {
                response: IntentResponse {
                    id: "response-stranger".into(),
                    intent_id: "intent-stranger".into(),
                    responder: agent.clone(),
                    kind: IntentResponseKind::Decline,
                    body: "not aligned".into(),
                    workspace: None,
                    task_id: None,
                    capability: Some("image-gen".into()),
                    evidence: None,
                    created_at: 11,
                },
            },
        ));

        let recommendations = society.recommend_intents(&agent, Some(20), 10);
        assert_eq!(recommendations.len(), 1);
        assert_eq!(recommendations[0].intent.id, "intent-trusted");
        assert_eq!(recommendations[0].capability_score, 1.0);
        assert_eq!(recommendations[0].workspace_score, 1.0);
        assert!(recommendations[0].social_score > 0.5);
        assert!(recommendations[0].reputation_score > 0.5);
        assert!(recommendations[0]
            .reasons
            .contains(&"capability:code-review".into()));
        assert!(recommendations[0]
            .reasons
            .contains(&"shared-workspace".into()));
        assert!(recommendations[0].reasons.contains(&"unanswered".into()));
        assert!(recommendations[0]
            .actions
            .iter()
            .any(|action| action.kind == IntentActionKind::RespondIntent
                && action.response_kind == Some(IntentResponseKind::Interested)
                && action.event_hint == "event intent-response"));
        assert!(recommendations[0].actions.iter().all(|action| {
            action.kind != IntentActionKind::OfferTask || action.task_id.is_some()
        }));
    }

    #[test]
    fn task_events_rebuild_social_task_board() {
        let publisher = did("publisher");
        let worker = NodeIdentity::generate();
        let worker_did = worker.did().clone();
        let workspace = WorkspaceId::from_bytes([74; 32]);
        let output_root = nexus_storage::Cid::hash_of(b"task root");
        let mut society = Society::new();
        let task = TaskSpec::new(
            publisher.clone(),
            "analyze shared workspace",
            "python-exec",
            "python",
            vec!["analysis.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();

        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            1,
            SocialEventKind::TaskPublished { task },
        ));
        assert_eq!(society.task_count(), 1);
        assert_eq!(society.open_tasks_for("python-exec").len(), 1);

        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            2,
            SocialEventKind::TaskOffered {
                offer: TaskOffer {
                    task_id: task_id.clone(),
                    bidder: worker_did.clone(),
                    price: 25,
                    estimated_time_secs: 10,
                    rationale: "I have the runtime".into(),
                },
            },
        ));
        assert_eq!(society.task_offers(&task_id).len(), 1);

        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            3,
            SocialEventKind::TaskAccepted {
                acceptance: TaskAcceptance {
                    task_id: task_id.clone(),
                    publisher: publisher.clone(),
                    bidder: worker_did.clone(),
                    price: 25,
                    accepted_at: 3,
                },
            },
        ));

        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let receipt = ExecutionReceipt::from_process_output(
            task_id.clone(),
            worker_did.clone(),
            Some(workspace),
            "python",
            vec!["analysis.py".into()],
            &output,
            Some(output_root),
            2,
            3,
        )
        .sign(&worker)
        .unwrap();

        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            4,
            SocialEventKind::TaskCompleted {
                result: TaskResult {
                    task_id: task_id.clone(),
                    executor: worker_did.clone(),
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 20,
                    error: None,
                    receipt: Some(Box::new(receipt)),
                    attestations: Vec::new(),
                },
            },
        ));

        let task = society.task(&task_id).unwrap();
        assert_eq!(task.state, TaskState::Completed);
        assert_eq!(task.assigned_to, Some(worker_did.clone()));
        assert!(society.task_result(&task_id).is_some());
        assert_eq!(society.edge(&publisher, &worker_did).unwrap().successes, 1);
        assert_eq!(
            society.interactions().last().unwrap().workspace,
            Some(workspace)
        );
        let snapshots = society.workspace_snapshots(&workspace);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].actor, worker_did);
        assert_eq!(snapshots[0].root, output_root);
        assert_eq!(snapshots[0].label.as_deref(), Some("task-result"));
        assert_eq!(
            society.latest_workspace_snapshot(&workspace).unwrap().root,
            output_root
        );
        let reputation = society.reputation(&publisher, &worker_did).unwrap();
        assert_eq!(reputation.successes, 1);
        assert_eq!(reputation.failures, 0);
        assert!(reputation.composite() > 0.5);
    }

    #[test]
    fn independent_execution_attestation_matches_task_result_claim() {
        let publisher = did("publisher");
        let worker = NodeIdentity::generate();
        let attestor = NodeIdentity::generate();
        let worker_did = worker.did().clone();
        let mut society = Society::new();
        let task = TaskSpec::new(
            publisher.clone(),
            "audit shared workspace",
            "python-exec",
            "python",
            vec!["audit.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();
        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let receipt = ExecutionReceipt::from_process_output(
            task_id.clone(),
            worker_did.clone(),
            None,
            "python",
            vec!["audit.py".into()],
            &output,
            None,
            2,
            3,
        )
        .sign(&worker)
        .unwrap();
        let attestation = ExecutionAttestation::from_process_output(
            &receipt,
            attestor.did().clone(),
            &output,
            None,
            4,
        )
        .sign(&attestor)
        .unwrap();

        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            1,
            SocialEventKind::TaskPublished { task },
        ));
        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            2,
            SocialEventKind::TaskOffered {
                offer: TaskOffer {
                    task_id: task_id.clone(),
                    bidder: worker_did.clone(),
                    price: 25,
                    estimated_time_secs: 10,
                    rationale: "ready".into(),
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            3,
            SocialEventKind::TaskAccepted {
                acceptance: TaskAcceptance {
                    task_id: task_id.clone(),
                    publisher: publisher.clone(),
                    bidder: worker_did.clone(),
                    price: 25,
                    accepted_at: 3,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            4,
            SocialEventKind::TaskCompleted {
                result: TaskResult {
                    task_id: task_id.clone(),
                    executor: worker_did.clone(),
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 20,
                    error: None,
                    receipt: Some(Box::new(receipt)),
                    attestations: Vec::new(),
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            attestor.did().clone(),
            5,
            SocialEventKind::TaskExecutionAttested {
                attestation: attestation.clone(),
            },
        ));

        assert_eq!(society.task_execution_attestations(&task_id).len(), 1);
        let result = society.task_result(&task_id).unwrap();
        let attestations = society.task_result_attestations(result);
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].attestor, *attestor.did());
        assert_eq!(
            attestations[0].receipt_signature_hex,
            attestation.receipt_signature_hex
        );
    }

    #[test]
    fn self_transaction_task_result_does_not_grant_reputation() {
        let identity = NodeIdentity::generate();
        let actor = identity.did().clone();
        let mut society = Society::new();
        let task = TaskSpec::new(
            actor.clone(),
            "self assigned task",
            "python-exec",
            "python",
            vec!["self.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();

        society.apply_event(&SocialEvent::new(
            actor.clone(),
            1,
            SocialEventKind::TaskPublished { task },
        ));
        society.apply_event(&SocialEvent::new(
            actor.clone(),
            2,
            SocialEventKind::TaskOffered {
                offer: TaskOffer {
                    task_id: task_id.clone(),
                    bidder: actor.clone(),
                    price: 10,
                    estimated_time_secs: 1,
                    rationale: "self run for audit".into(),
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            actor.clone(),
            3,
            SocialEventKind::TaskAccepted {
                acceptance: TaskAcceptance {
                    task_id: task_id.clone(),
                    publisher: actor.clone(),
                    bidder: actor.clone(),
                    price: 10,
                    accepted_at: 3,
                },
            },
        ));

        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let receipt = ExecutionReceipt::from_process_output(
            task_id.clone(),
            actor.clone(),
            None,
            "python",
            vec!["self.py".into()],
            &output,
            None,
            4,
            5,
        )
        .sign(&identity)
        .unwrap();

        society.apply_event(&SocialEvent::new(
            actor.clone(),
            6,
            SocialEventKind::TaskCompleted {
                result: TaskResult {
                    task_id: task_id.clone(),
                    executor: actor.clone(),
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 10,
                    error: None,
                    receipt: Some(Box::new(receipt)),
                    attestations: Vec::new(),
                },
            },
        ));

        assert_eq!(society.task(&task_id).unwrap().state, TaskState::Completed);
        assert!(society.task_result(&task_id).is_some());
        assert!(society.edge(&actor, &actor).is_none());
        assert!(society.reputation(&actor, &actor).is_none());
        assert!(society.interactions().is_empty());
    }

    #[test]
    fn task_acceptance_and_cancellation_events_update_task_state() {
        let publisher = did("publisher");
        let worker = did("worker");
        let mut society = Society::new();
        let task = TaskSpec::new(
            publisher.clone(),
            "assignable task",
            "python-exec",
            "python",
            vec!["analysis.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();

        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            1,
            SocialEventKind::TaskPublished { task },
        ));
        society.apply_event(&SocialEvent::new(
            worker.clone(),
            2,
            SocialEventKind::TaskOffered {
                offer: TaskOffer {
                    task_id: task_id.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    estimated_time_secs: 10,
                    rationale: "ready".into(),
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            3,
            SocialEventKind::TaskAccepted {
                acceptance: TaskAcceptance {
                    task_id: task_id.clone(),
                    publisher: publisher.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    accepted_at: 3,
                },
            },
        ));

        let accepted_task = society.task(&task_id).unwrap();
        assert_eq!(accepted_task.state, TaskState::InProgress);
        assert_eq!(accepted_task.assigned_to, Some(worker));
        assert_eq!(society.task_acceptance(&task_id).unwrap().price, 25);

        let cancel_task = TaskSpec::new(
            publisher.clone(),
            "cancelable task",
            "python-exec",
            "python",
            vec!["cancel.py".into()],
            100,
            999,
            4,
        );
        let cancel_id = cancel_task.id.clone();
        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            4,
            SocialEventKind::TaskPublished { task: cancel_task },
        ));
        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            5,
            SocialEventKind::TaskCancelled {
                cancellation: TaskCancellation {
                    task_id: cancel_id.clone(),
                    publisher,
                    reason: "superseded".into(),
                    cancelled_at: 5,
                },
            },
        ));

        assert_eq!(
            society.task(&cancel_id).unwrap().state,
            TaskState::Cancelled
        );
        assert_eq!(
            society.task_cancellation(&cancel_id).unwrap().reason,
            "superseded"
        );
    }

    #[test]
    fn task_acceptance_and_cancellation_survive_out_of_order_replay() {
        let publisher = did("publisher");
        let worker = did("worker");
        let mut society = Society::new();
        let task = TaskSpec::new(
            publisher.clone(),
            "out of order task",
            "python-exec",
            "python",
            vec!["analysis.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();

        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            3,
            SocialEventKind::TaskAccepted {
                acceptance: TaskAcceptance {
                    task_id: task_id.clone(),
                    publisher: publisher.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    accepted_at: 3,
                },
            },
        ));
        assert!(society.task_acceptance(&task_id).is_none());

        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            1,
            SocialEventKind::TaskPublished { task },
        ));
        assert!(society.task_acceptance(&task_id).is_none());

        society.apply_event(&SocialEvent::new(
            worker.clone(),
            2,
            SocialEventKind::TaskOffered {
                offer: TaskOffer {
                    task_id: task_id.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    estimated_time_secs: 10,
                    rationale: "ready".into(),
                },
            },
        ));

        let accepted_task = society.task(&task_id).unwrap();
        assert_eq!(accepted_task.state, TaskState::InProgress);
        assert_eq!(accepted_task.assigned_to, Some(worker));
        assert_eq!(society.task_acceptance(&task_id).unwrap().price, 25);

        let cancel_task = TaskSpec::new(
            publisher.clone(),
            "out of order cancel",
            "python-exec",
            "python",
            vec!["cancel.py".into()],
            100,
            999,
            4,
        );
        let cancel_id = cancel_task.id.clone();
        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            5,
            SocialEventKind::TaskCancelled {
                cancellation: TaskCancellation {
                    task_id: cancel_id.clone(),
                    publisher: publisher.clone(),
                    reason: "superseded".into(),
                    cancelled_at: 5,
                },
            },
        ));
        assert!(society.task_cancellation(&cancel_id).is_none());

        society.apply_event(&SocialEvent::new(
            publisher,
            4,
            SocialEventKind::TaskPublished { task: cancel_task },
        ));

        assert_eq!(
            society.task(&cancel_id).unwrap().state,
            TaskState::Cancelled
        );
        assert_eq!(
            society.task_cancellation(&cancel_id).unwrap().reason,
            "superseded"
        );
    }

    #[test]
    fn successful_task_result_without_receipt_does_not_grant_social_credit() {
        let publisher = did("publisher");
        let worker = did("worker");
        let mut society = Society::new();
        let task = TaskSpec::new(
            publisher.clone(),
            "repeatable task",
            "python-exec",
            "python",
            vec!["repeat.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();
        let result = TaskResult {
            task_id: task_id.clone(),
            executor: worker.clone(),
            success: true,
            exit_code: 0,
            stdout: "ok".into(),
            stderr: String::new(),
            actual_cost: 20,
            error: None,
            receipt: None,
            attestations: Vec::new(),
        };

        society.apply_event(&SocialEvent::new(
            worker.clone(),
            2,
            SocialEventKind::TaskCompleted {
                result: result.clone(),
            },
        ));
        assert!(society.edge(&publisher, &worker).is_none());

        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            1,
            SocialEventKind::TaskPublished { task },
        ));
        society.apply_event(&SocialEvent::new(
            worker.clone(),
            3,
            SocialEventKind::TaskCompleted { result },
        ));

        let task = society.task(&task_id).unwrap();
        assert_eq!(task.state, TaskState::Published);
        assert!(society.task_result(&task_id).is_none());
        assert_eq!(society.interaction_count(), 0);
        assert!(society.edge(&publisher, &worker).is_none());
        assert!(society.reputation(&publisher, &worker).is_none());
    }

    #[test]
    fn unaccepted_task_result_claim_does_not_change_task_or_reputation() {
        let publisher = did("publisher");
        let worker = NodeIdentity::generate();
        let worker_did = worker.did().clone();
        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let mut society = Society::new();
        let task = TaskSpec::new(
            publisher.clone(),
            "unaccepted task",
            "python-exec",
            "python",
            vec!["unaccepted.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();
        let receipt = ExecutionReceipt::from_process_output(
            task_id.clone(),
            worker_did.clone(),
            None,
            "python",
            vec!["unaccepted.py".into()],
            &output,
            None,
            2,
            3,
        )
        .sign(&worker)
        .unwrap();

        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            1,
            SocialEventKind::TaskPublished { task },
        ));
        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            3,
            SocialEventKind::TaskCompleted {
                result: TaskResult {
                    task_id: task_id.clone(),
                    executor: worker_did.clone(),
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 20,
                    error: None,
                    receipt: Some(Box::new(receipt)),
                    attestations: Vec::new(),
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            4,
            SocialEventKind::TaskCompleted {
                result: TaskResult {
                    task_id: task_id.clone(),
                    executor: worker_did.clone(),
                    success: false,
                    exit_code: 7,
                    stdout: String::new(),
                    stderr: "failed".into(),
                    actual_cost: 0,
                    error: Some("failed".into()),
                    receipt: None,
                    attestations: Vec::new(),
                },
            },
        ));

        assert_eq!(society.task(&task_id).unwrap().state, TaskState::Published);
        assert!(society.task_result(&task_id).is_none());
        assert_eq!(society.interaction_count(), 0);
        assert!(society.edge(&publisher, &worker_did).is_none());
        assert!(society.reputation(&publisher, &worker_did).is_none());
    }

    #[test]
    fn out_of_order_task_result_applies_after_matching_acceptance() {
        let publisher = did("publisher");
        let worker = NodeIdentity::generate();
        let worker_did = worker.did().clone();
        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let mut society = Society::new();
        let task = TaskSpec::new(
            publisher.clone(),
            "accepted after result",
            "python-exec",
            "python",
            vec!["late-accept.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();
        let receipt = ExecutionReceipt::from_process_output(
            task_id.clone(),
            worker_did.clone(),
            None,
            "python",
            vec!["late-accept.py".into()],
            &output,
            None,
            2,
            3,
        )
        .sign(&worker)
        .unwrap();

        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            1,
            SocialEventKind::TaskPublished { task },
        ));
        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            3,
            SocialEventKind::TaskCompleted {
                result: TaskResult {
                    task_id: task_id.clone(),
                    executor: worker_did.clone(),
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 20,
                    error: None,
                    receipt: Some(Box::new(receipt)),
                    attestations: Vec::new(),
                },
            },
        ));
        assert_eq!(society.task(&task_id).unwrap().state, TaskState::Published);
        assert!(society.task_result(&task_id).is_none());

        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            2,
            SocialEventKind::TaskOffered {
                offer: TaskOffer {
                    task_id: task_id.clone(),
                    bidder: worker_did.clone(),
                    price: 25,
                    estimated_time_secs: 10,
                    rationale: "ready".into(),
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            4,
            SocialEventKind::TaskAccepted {
                acceptance: TaskAcceptance {
                    task_id: task_id.clone(),
                    publisher: publisher.clone(),
                    bidder: worker_did.clone(),
                    price: 25,
                    accepted_at: 4,
                },
            },
        ));

        assert_eq!(society.task(&task_id).unwrap().state, TaskState::Completed);
        assert!(society.task_result(&task_id).is_some());
        assert_eq!(society.edge(&publisher, &worker_did).unwrap().successes, 1);
    }

    #[test]
    fn task_result_receipt_must_match_task_command_to_be_adopted() {
        let publisher = did("publisher");
        let worker = NodeIdentity::generate();
        let worker_did = worker.did().clone();
        let workspace = WorkspaceId::from_bytes([77; 32]);
        let output_root = nexus_storage::Cid::hash_of(b"same output root");
        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let mut society = Society::new();
        let task = TaskSpec::new(
            publisher.clone(),
            "match command",
            "python-exec",
            "python",
            vec!["expected.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();
        let wrong_receipt = ExecutionReceipt::from_process_output(
            task_id.clone(),
            worker_did.clone(),
            Some(workspace),
            "python",
            vec!["other.py".into()],
            &output,
            Some(output_root),
            3,
            4,
        )
        .sign(&worker)
        .unwrap();
        let correct_receipt = ExecutionReceipt::from_process_output(
            task_id.clone(),
            worker_did.clone(),
            Some(workspace),
            "python",
            vec!["expected.py".into()],
            &output,
            Some(output_root),
            5,
            6,
        )
        .sign(&worker)
        .unwrap();

        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            1,
            SocialEventKind::TaskPublished { task },
        ));
        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            2,
            SocialEventKind::TaskOffered {
                offer: TaskOffer {
                    task_id: task_id.clone(),
                    bidder: worker_did.clone(),
                    price: 25,
                    estimated_time_secs: 10,
                    rationale: "ready".into(),
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            3,
            SocialEventKind::TaskAccepted {
                acceptance: TaskAcceptance {
                    task_id: task_id.clone(),
                    publisher: publisher.clone(),
                    bidder: worker_did.clone(),
                    price: 25,
                    accepted_at: 3,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            4,
            SocialEventKind::TaskCompleted {
                result: TaskResult {
                    task_id: task_id.clone(),
                    executor: worker_did.clone(),
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 20,
                    error: None,
                    receipt: Some(Box::new(wrong_receipt)),
                    attestations: Vec::new(),
                },
            },
        ));

        assert_eq!(society.task(&task_id).unwrap().state, TaskState::InProgress);
        assert!(society.task_result(&task_id).is_none());
        assert!(society.workspace_snapshots(&workspace).is_empty());
        assert_eq!(society.task_result_claims(&task_id).len(), 1);

        society.apply_event(&SocialEvent::new(
            worker_did.clone(),
            6,
            SocialEventKind::TaskCompleted {
                result: TaskResult {
                    task_id: task_id.clone(),
                    executor: worker_did.clone(),
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 20,
                    error: None,
                    receipt: Some(Box::new(correct_receipt)),
                    attestations: Vec::new(),
                },
            },
        ));

        assert_eq!(society.task(&task_id).unwrap().state, TaskState::Completed);
        assert_eq!(
            society
                .task_result(&task_id)
                .unwrap()
                .receipt
                .as_deref()
                .unwrap()
                .args,
            vec!["expected.py".to_string()]
        );
        assert_eq!(
            society.latest_workspace_snapshot(&workspace).unwrap().root,
            output_root
        );
        assert_eq!(society.task_result_claims(&task_id).len(), 2);
        assert_eq!(society.edge(&publisher, &worker_did).unwrap().successes, 1);
    }

    #[test]
    fn failed_task_result_updates_reputation_negatively_after_acceptance() {
        let publisher = did("publisher");
        let worker = did("worker");
        let mut society = Society::new();
        let task = TaskSpec::new(
            publisher.clone(),
            "run fragile job",
            "python-exec",
            "python",
            vec!["fragile.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();

        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            1,
            SocialEventKind::TaskPublished { task },
        ));
        society.apply_event(&SocialEvent::new(
            worker.clone(),
            2,
            SocialEventKind::TaskOffered {
                offer: TaskOffer {
                    task_id: task_id.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    estimated_time_secs: 10,
                    rationale: "ready".into(),
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            publisher.clone(),
            3,
            SocialEventKind::TaskAccepted {
                acceptance: TaskAcceptance {
                    task_id: task_id.clone(),
                    publisher: publisher.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    accepted_at: 3,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            worker.clone(),
            4,
            SocialEventKind::TaskCompleted {
                result: TaskResult {
                    task_id: task_id.clone(),
                    executor: worker.clone(),
                    success: false,
                    exit_code: 7,
                    stdout: String::new(),
                    stderr: "failed".into(),
                    actual_cost: 0,
                    error: Some("failed".into()),
                    receipt: None,
                    attestations: Vec::new(),
                },
            },
        ));

        let task = society.task(&task_id).unwrap();
        assert_eq!(task.state, TaskState::Failed);
        assert_eq!(society.edge(&publisher, &worker).unwrap().failures, 1);
        let reputation = society.reputation(&publisher, &worker).unwrap();
        assert_eq!(reputation.successes, 0);
        assert_eq!(reputation.failures, 1);
        assert!(reputation.composite() < 0.5);
    }

    #[test]
    fn task_dispute_events_are_recorded_as_disputed_interactions() {
        let publisher = did("publisher");
        let worker = did("worker");
        let auditor = did("auditor");
        let mut society = Society::new();
        let task = TaskSpec::new(
            publisher.clone(),
            "verify shared output",
            "python-exec",
            "python",
            vec!["verify.py".into()],
            100,
            999,
            1,
        );
        let task_id = task.id.clone();

        society.apply_event(&SocialEvent::new(
            auditor.clone(),
            3,
            SocialEventKind::TaskDisputed {
                dispute: TaskDispute {
                    task_id: task_id.clone(),
                    disputer: auditor.clone(),
                    target: worker.clone(),
                    claim_id: Some("claim:stdout-mismatch".into()),
                    reason: "stdout cid mismatch".into(),
                    evidence: Some("receipt-audit:1".into()),
                    timestamp: 3,
                },
            },
        ));
        assert_eq!(society.task_disputes(&task_id).len(), 1);
        assert_eq!(
            society.task_disputes(&task_id)[0].claim_id.as_deref(),
            Some("claim:stdout-mismatch")
        );
        assert_eq!(society.edge(&auditor, &worker).unwrap().failures, 1);
        assert_eq!(society.reputation(&auditor, &worker).unwrap().failures, 1);

        society.apply_event(&SocialEvent::new(
            publisher,
            1,
            SocialEventKind::TaskPublished { task },
        ));
        assert_eq!(
            society.task_disputes(&task_id)[0].reason,
            "stdout cid mismatch"
        );
        assert!(society
            .interactions()
            .last()
            .unwrap()
            .topic
            .contains("claim:stdout-mismatch"));
        assert_eq!(
            society.interactions().last().unwrap().outcome,
            InteractionOutcome::Dispute
        );
    }

    #[test]
    fn intent_events_build_open_social_coordination_layer() {
        let author = did("intent-author");
        let responder = did("intent-responder");
        let workspace = WorkspaceId::from_bytes([91; 32]);
        let mut society = Society::new();
        let intent = AgentIntent {
            id: "intent-1".into(),
            author: author.clone(),
            kind: IntentKind::Need,
            title: "Need an autonomous reviewer".into(),
            body: "inspect the workspace and publish a signed claim".into(),
            workspace: Some(workspace),
            task_id: Some("task-42".into()),
            capability: Some("review".into()),
            tags: vec!["audit".into(), "high-autonomy".into()],
            created_at: 10,
            expires_at: Some(20),
        };

        society.apply_event(&SocialEvent::new(
            responder.clone(),
            9,
            SocialEventKind::IntentResponded {
                response: IntentResponse {
                    id: "response-1".into(),
                    intent_id: "intent-1".into(),
                    responder: responder.clone(),
                    kind: IntentResponseKind::Interested,
                    body: "I can inspect this workspace".into(),
                    workspace: Some(workspace),
                    task_id: Some("task-42".into()),
                    capability: Some("review".into()),
                    evidence: Some("manifest:reviewer".into()),
                    created_at: 9,
                },
            },
        ));
        society.apply_event(&SocialEvent::new(
            author.clone(),
            10,
            SocialEventKind::IntentPublished {
                intent: intent.clone(),
            },
        ));
        society.apply_event(&SocialEvent::new(
            author.clone(),
            10,
            SocialEventKind::IntentPublished { intent },
        ));

        assert!(society.has_agent(&author));
        assert!(society.has_agent(&responder));
        assert_eq!(society.intents().len(), 1);
        assert_eq!(society.agent_intents(&author).len(), 1);
        assert_eq!(society.workspace_intents(&workspace).len(), 1);
        assert_eq!(society.intent_responses().len(), 1);
        assert_eq!(society.responses_for_intent("intent-1").len(), 1);
        assert_eq!(society.agent_intent_responses(&responder).len(), 1);
        assert_eq!(society.workspace_intent_responses(&workspace).len(), 1);
        assert_eq!(society.workspace_ids(), vec![workspace]);
        assert_eq!(society.intents()[0].kind, IntentKind::Need);
        assert_eq!(society.intents()[0].task_id.as_deref(), Some("task-42"));
        assert_eq!(
            society.responses_for_intent("intent-1")[0].kind,
            IntentResponseKind::Interested
        );
    }
}
