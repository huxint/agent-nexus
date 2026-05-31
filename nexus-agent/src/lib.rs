//! Nexus Agent — agent identity, society, capability manifest, and task marketplace.
//!
//! Every agent publishes a manifest declaring what it can do.
//! The society layer records relationships, collectives, and interaction
//! memory. The task market allows agents to publish tasks, bid on them, and
//! settle payments through the credit ledger.

pub mod event_log;
pub mod manifest;
pub mod market;
pub mod memory;
pub mod protocol;
pub mod registry;
pub mod society;
pub mod task;

pub use event_log::SocialEventLog;
pub use manifest::{AgentManifest, CapabilityDecl};
pub use market::TaskMarket;
pub use memory::SocialMemory;
pub use nexus_economy::ReputationScore;
pub use protocol::{SocialEvent, SocialEventKind, SocialProtocolError};
pub use registry::AgentRegistry;
pub use society::{
    capability_signature_id, random_social_id, task_result_claim_id, AgentIntent, CapabilityGrant,
    CapabilityRevocation, Collective, CollectiveDecision, CollectiveDecisionOutcome,
    CollectiveProposal, CollectiveVote, CollectiveVoteChoice, FactTruthStatus, GovernanceSignal,
    IdentityRevocation, IntentActionKind, IntentActionPlan, IntentKind, IntentRecommendation,
    IntentResponse, IntentResponseKind, Interaction, InteractionOutcome, ProviderRecommendation,
    RelationKind, SettlementRecord, SocialEdge, Society, TaskClaimJudgment, TaskDispute,
    VerifiedCapability, WorkspaceRun, WorkspaceRunContext, WorkspaceRunFailure, WorkspaceRunStdin,
    WorkspaceSnapshot,
};
pub use task::{
    ExecutionAttestation, ExecutionReceipt, ExecutionReceiptError, Task, TaskAcceptance, TaskBid,
    TaskCancellation, TaskOffer, TaskResult, TaskSpec, TaskState,
};
