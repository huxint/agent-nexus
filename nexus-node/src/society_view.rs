use std::path::Path;

use nexus_agent::{
    capability_signature_id, task_result_claim_id, AgentIntent, CapabilityGrant,
    CapabilityRevocation, Collective, CollectiveProposal, CollectiveVote, ExecutionAttestation,
    ExecutionReceipt, GovernanceSignal, IdentityRevocation, IntentRecommendation, IntentResponse,
    Interaction, ProviderRecommendation, ReputationScore, SettlementRecord, SocialEdge,
    SocialMemory, Task, TaskClaimJudgment, TaskResult, VerifiedCapability, WorkspaceRun,
    WorkspaceRunContext, WorkspaceRunFailure, WorkspaceSnapshot,
};
use nexus_core::{Did, WorkspaceId};
use nexus_storage::Cid;

use crate::discovery::{discovered_workspace_views, load_workspace_discovery, DiscoveryFilter};
use crate::unix_now;

pub(crate) fn print_society_text(base: &Path, memory: &SocialMemory) {
    let society = memory.society();
    println!("AI Society: {}", base.display());
    println!("events: {}", memory.event_count());
    println!("agents: {}", society.agent_count());
    println!("manifests: {}", society.manifest_count());
    println!("interactions: {}", society.interaction_count());
    println!("tasks: {}", society.task_count());

    println!("\nAgents:");
    for did in society.agents() {
        if let Some(manifest) = society.agent_manifest(did) {
            let capabilities = manifest
                .provides
                .iter()
                .map(|cap| cap.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            println!("  {}  {}  [{}]", did, manifest.name, capabilities);
        } else {
            println!("  {did}");
        }
    }

    println!("\nWorkspaces:");
    for workspace in society.workspace_ids() {
        let members = society
            .workspace_members(&workspace)
            .into_iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        println!("  {workspace}  members={}", members.len());
        for member in members {
            println!("    {member}");
        }
    }

    println!("\nCollectives:");
    for collective in society.collectives() {
        println!(
            "  {}  {}  members={} workspaces={}",
            collective.id,
            collective.name,
            collective.members.len(),
            collective.workspaces.len()
        );
    }

    println!("\nTasks:");
    for task in society.tasks() {
        println!(
            "  {}  {:?}  {}  publisher={} assigned={}",
            task.id,
            task.state,
            task.required_capability,
            task.publisher,
            task.assigned_to
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "-".into())
        );
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SocietyJsonOptions {
    pub(crate) activity_limit: Option<usize>,
    pub(crate) activity_since: Option<u64>,
    pub(crate) intent_recommendation_limit: Option<usize>,
    pub(crate) agent_filter: Option<Did>,
    pub(crate) workspace_filter: Option<WorkspaceId>,
    pub(crate) task_filter: Option<String>,
}

pub(crate) fn print_society_json(
    base: &Path,
    memory: &SocialMemory,
    options: SocietyJsonOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{}",
        serde_json::to_string_pretty(&society_json_for_base(base, memory, options))?
    );
    Ok(())
}

#[cfg(test)]
pub(crate) fn society_json(memory: &SocialMemory) -> serde_json::Value {
    society_json_for_base(Path::new("."), memory, SocietyJsonOptions::default())
}

pub(crate) fn society_json_for_base(
    base: &Path,
    memory: &SocialMemory,
    options: SocietyJsonOptions,
) -> serde_json::Value {
    let society = memory.society();
    let agents = society
        .agents()
        .into_iter()
        .filter(|did| agent_matches_filters(society, did, &options))
        .map(|did| {
            let manifest = society.agent_manifest(did);
            let revocation = society.identity_revocation(did);
            let provider_recommendations = manifest
                .map(|manifest| {
                    manifest
                        .provides
                        .iter()
                        .flat_map(|capability| {
                            society
                                .recommend_providers(did, &capability.name, 10)
                                .into_iter()
                        })
                        .filter(|provider| provider.did == *did)
                        .map(provider_recommendation_json)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            serde_json::json!({
                "did": did.to_string(),
                "revoked": revocation.is_some(),
                "revocation": revocation.map(identity_revocation_json),
                "manifest": manifest,
                "declared_capabilities": manifest
                    .map(|manifest| manifest.provides.clone())
                    .unwrap_or_default(),
                "verified_capabilities": society
                    .agent_verified_capabilities(did)
                    .into_iter()
                    .map(verified_capability_json)
                    .collect::<Vec<_>>(),
                "provider_recommendations": provider_recommendations,
                "activity": agent_activity_json(society, did, &options),
                "intents": society
                    .agent_intents(did)
                    .into_iter()
                    .filter(|intent| intent_matches_filters(intent, &options))
                    .map(intent_json)
                    .collect::<Vec<_>>(),
                "intent_responses": society
                    .agent_intent_responses(did)
                    .into_iter()
                    .filter(|response| intent_response_matches_filters(response, &options))
                    .map(intent_response_json)
                    .collect::<Vec<_>>(),
                "intent_recommendations": society
                    .recommend_intents(
                        did,
                        Some(unix_now()),
                        options.intent_recommendation_limit.unwrap_or(10),
                    )
                    .into_iter()
                    .filter(|recommendation| {
                        intent_recommendation_matches_filters(recommendation, &options)
                    })
                    .map(intent_recommendation_json)
                    .collect::<Vec<_>>(),
                "workspaces": society
                    .agent_workspaces(did)
                    .into_iter()
                    .filter(|workspace| workspace_matches_filters(society, workspace, &options))
                    .map(|workspace| workspace.to_string())
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let workspaces = society
        .workspace_ids()
        .into_iter()
        .filter(|workspace| workspace_matches_filters(society, workspace, &options))
        .map(|workspace| {
            serde_json::json!({
                "id": workspace.to_string(),
                "members": society
                    .workspace_members(&workspace)
                    .into_iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                "capability_grants": society
                    .workspace_capability_grants(&workspace)
                    .into_iter()
                    .map(|grant| capability_grant_json(society, grant))
                    .collect::<Vec<_>>(),
                "snapshots": society
                    .workspace_snapshots(&workspace)
                    .into_iter()
                    .map(workspace_snapshot_json)
                    .collect::<Vec<_>>(),
                "latest_snapshot": society
                    .latest_workspace_snapshot(&workspace)
                    .map(workspace_snapshot_json),
                "runs": society
                    .workspace_runs(&workspace)
                    .into_iter()
                    .map(workspace_run_json)
                    .collect::<Vec<_>>(),
                "intents": society
                    .workspace_intents(&workspace)
                    .into_iter()
                    .filter(|intent| intent_matches_filters(intent, &options))
                    .map(intent_json)
                    .collect::<Vec<_>>(),
                "intent_responses": society
                    .workspace_intent_responses(&workspace)
                    .into_iter()
                    .filter(|response| intent_response_matches_filters(response, &options))
                    .map(intent_response_json)
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let capability_grants = society
        .capability_grants()
        .into_iter()
        .filter(|grant| capability_grant_matches_filters(society, grant, &options))
        .map(|grant| capability_grant_json(society, grant))
        .collect::<Vec<_>>();
    let collectives = society
        .collectives()
        .into_iter()
        .filter(|collective| collective_matches_filters(society, collective, &options))
        .map(|collective| {
            let mut members = collective
                .members
                .iter()
                .filter(|member| member_matches_filters(society, member, &options))
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            members.sort();
            let mut workspaces = collective
                .workspaces
                .iter()
                .filter(|workspace| workspace_matches_filters(society, workspace, &options))
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            workspaces.sort();
            let proposals = society
                .collective_proposals(&collective.id)
                .into_iter()
                .filter(|proposal| proposal_matches_filters(society, proposal, &options))
                .map(|proposal| {
                    serde_json::json!({
                        "id": proposal.id,
                        "collective_id": proposal.collective_id,
                        "proposer": proposal.proposer.to_string(),
                        "title": proposal.title,
                        "body": proposal.body,
                        "workspace": proposal.workspace.map(|workspace| workspace.to_string()),
                        "created_at": proposal.created_at,
                        "deadline": proposal.deadline,
                        "votes": society
                            .collective_votes(&proposal.collective_id, &proposal.id)
                            .into_iter()
                            .filter(|vote| vote_matches_filters(vote, &options))
                            .map(|vote| {
                                serde_json::json!({
                                    "proposal_id": vote.proposal_id,
                                    "collective_id": vote.collective_id,
                                    "voter": vote.voter.to_string(),
                                    "choice": vote.choice,
                                    "rationale": vote.rationale,
                                    "timestamp": vote.timestamp,
                                })
                            })
                            .collect::<Vec<_>>(),
                        "decision": society
                            .collective_decision(&proposal.collective_id, &proposal.id)
                            .map(|decision| {
                            serde_json::json!({
                                "proposal_id": decision.proposal_id,
                                "collective_id": decision.collective_id,
                                "decider": decision.decider.to_string(),
                                "outcome": decision.outcome,
                                "task_id": decision.task_id,
                                "claim_id": decision.claim_id,
                                "target": decision.target.as_ref().map(ToString::to_string),
                                "truth_status": society.collective_decision_truth_status(decision),
                                "anchor": decision.anchor,
                                "reason": decision.reason,
                                "timestamp": decision.timestamp,
                            })
                        }),
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "id": collective.id,
                "name": collective.name,
                "purpose": collective.purpose,
                "members": members,
                "workspaces": workspaces,
                "proposals": proposals,
                "created_at": collective.created_at,
            })
        })
        .collect::<Vec<_>>();
    let tasks = society
        .tasks()
        .into_iter()
        .filter(|task| task_matches_filters(society, task, &options))
        .map(|task| {
            serde_json::json!({
                "id": task.id,
                "publisher": task.publisher.to_string(),
                "description": task.description,
                "required_capability": task.required_capability,
                "command": task.command,
                "args": task.args,
                "max_budget": task.max_budget,
                "deadline": task.deadline,
                "state": task.state,
                "assigned_to": task.assigned_to.as_ref().map(ToString::to_string),
                "created_at": task.created_at,
                "offers": society.task_offers(&task.id),
                "acceptance": society.task_acceptance(&task.id).map(|acceptance| {
                    serde_json::json!({
                        "task_id": acceptance.task_id,
                        "publisher": acceptance.publisher.to_string(),
                        "bidder": acceptance.bidder.to_string(),
                        "price": acceptance.price,
                        "accepted_at": acceptance.accepted_at,
                    })
                }),
                "cancellation": society.task_cancellation(&task.id).map(|cancellation| {
                    serde_json::json!({
                        "task_id": cancellation.task_id,
                        "publisher": cancellation.publisher.to_string(),
                        "reason": cancellation.reason,
                        "cancelled_at": cancellation.cancelled_at,
                    })
                }),
                "result": society.task_result(&task.id).map(|result| task_result_json(society, result)),
                "result_claims": society
                    .task_result_claims(&task.id)
                    .into_iter()
                    .map(|result| task_result_claim_json(society, result))
                    .collect::<Vec<_>>(),
                "claim_judgments": society
                    .task_claim_judgments(&task.id)
                    .into_iter()
                    .map(task_claim_judgment_json)
                    .collect::<Vec<_>>(),
                "disputes": society
                    .task_disputes(&task.id)
                    .into_iter()
                    .map(|dispute| {
                        serde_json::json!({
                            "task_id": dispute.task_id,
                            "disputer": dispute.disputer.to_string(),
                            "target": dispute.target.to_string(),
                            "claim_id": dispute.claim_id,
                            "reason": dispute.reason,
                            "evidence": dispute.evidence,
                            "timestamp": dispute.timestamp,
                        })
                    })
                    .collect::<Vec<_>>(),
                "execution_attestations": society
                    .task_execution_attestations(&task.id)
                    .into_iter()
                    .map(execution_attestation_json)
                    .collect::<Vec<_>>(),
                "settlements": society
                    .task_settlements(&task.id)
                    .into_iter()
                    .map(|settlement| settlement_json(society, settlement))
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let relations = society
        .edges()
        .into_iter()
        .filter(|edge| relation_matches_filters(society, edge, &options))
        .map(|edge| {
            serde_json::json!({
                "from": edge.from.to_string(),
                "to": edge.to.to_string(),
                "kind": edge.kind,
                "trust": edge.trust,
                "affinity": edge.affinity,
                "successes": edge.successes,
                "failures": edge.failures,
                "score": edge.score(),
                "notes": edge.notes,
                "created_at": edge.created_at,
                "updated_at": edge.updated_at,
            })
        })
        .collect::<Vec<_>>();
    let interactions = society
        .interactions()
        .iter()
        .filter(|interaction| interaction_matches_filters(interaction, &options))
        .map(interaction_json)
        .collect::<Vec<_>>();
    let intents = society
        .intents()
        .into_iter()
        .filter(|intent| intent_matches_filters(intent, &options))
        .map(intent_json)
        .collect::<Vec<_>>();
    let intent_responses = society
        .intent_responses()
        .into_iter()
        .filter(|response| intent_response_matches_filters(response, &options))
        .map(intent_response_json)
        .collect::<Vec<_>>();
    let reputations = society
        .reputations()
        .into_iter()
        .filter(|reputation| reputation_matches_filters(society, *reputation, &options))
        .map(reputation_json)
        .collect::<Vec<_>>();
    let settlements = society
        .settlements()
        .into_iter()
        .filter(|settlement| settlement_matches_filters(settlement, &options))
        .map(|settlement| settlement_json(society, settlement))
        .collect::<Vec<_>>();
    let discovered_workspaces =
        if options.task_filter.is_some() && options.workspace_filter.is_none() {
            Vec::new()
        } else {
            load_workspace_discovery(base)
                .map(|announcements| {
                    let discovery_filter = DiscoveryFilter {
                        workspace: options
                            .workspace_filter
                            .map(|workspace| workspace.to_string()),
                        owner: options.agent_filter.clone(),
                        ..Default::default()
                    };
                    discovered_workspace_views(&announcements, &discovery_filter)
                })
                .unwrap_or_default()
        };

    serde_json::json!({
        "events": memory.event_count(),
        "agents": agents,
        "workspaces": workspaces,
        "discovered_workspaces": discovered_workspaces,
        "collectives": collectives,
        "relations": relations,
        "interactions": interactions,
        "intents": intents,
        "intent_responses": intent_responses,
        "reputations": reputations,
        "capability_grants": capability_grants,
        "settlements": settlements,
        "tasks": tasks,
    })
}

fn agent_matches_filters(
    society: &nexus_agent::Society,
    did: &Did,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| did == agent)
        && options
            .workspace_filter
            .is_none_or(|workspace| agent_uses_workspace(society, did, &workspace))
        && options.task_filter.as_ref().is_none_or(|task_id| {
            society.task(task_id).is_some_and(|task| {
                task.publisher == *did
                    || task.assigned_to.as_ref() == Some(did)
                    || society
                        .task_offers(task_id)
                        .iter()
                        .any(|offer| offer.bidder == *did)
                    || society.task_acceptance(task_id).is_some_and(|acceptance| {
                        acceptance.publisher == *did || acceptance.bidder == *did
                    })
                    || society
                        .task_result(task_id)
                        .is_some_and(|result| result.executor == *did)
                    || society
                        .task_result_claims(task_id)
                        .into_iter()
                        .any(|result| result.executor == *did)
                    || society
                        .task_execution_attestations(task_id)
                        .into_iter()
                        .any(|attestation| {
                            attestation.executor == *did || attestation.attestor == *did
                        })
                    || society
                        .task_disputes(task_id)
                        .into_iter()
                        .any(|dispute| dispute.disputer == *did || dispute.target == *did)
                    || society
                        .task_claim_judgments(task_id)
                        .into_iter()
                        .any(|judgment| {
                            judgment.decider == *did || judgment.target.as_ref() == Some(did)
                        })
            })
        })
}

fn member_matches_filters(
    society: &nexus_agent::Society,
    did: &Did,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| did == agent)
        && options.task_filter.as_ref().is_none_or(|task_id| {
            society.task(task_id).is_some_and(|task| {
                task.publisher == *did || task.assigned_to.as_ref() == Some(did)
            })
        })
}

fn workspace_matches_filters(
    society: &nexus_agent::Society,
    workspace: &WorkspaceId,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .workspace_filter
        .is_none_or(|filter| workspace == &filter)
        && options.agent_filter.as_ref().is_none_or(|agent| {
            society
                .workspace_members(workspace)
                .into_iter()
                .any(|member| member == agent)
                || society
                    .workspace_runs(workspace)
                    .into_iter()
                    .any(|run| run.actor == *agent)
                || society
                    .workspace_snapshots(workspace)
                    .into_iter()
                    .any(|snapshot| snapshot.actor == *agent)
                || society
                    .workspace_capability_grants(workspace)
                    .into_iter()
                    .any(|grant| {
                        grant.capability.issuer == *agent || grant.capability.subject == *agent
                    })
                || society
                    .workspace_intents(workspace)
                    .into_iter()
                    .any(|intent| intent.author == *agent)
                || society
                    .workspace_intent_responses(workspace)
                    .into_iter()
                    .any(|response| response.responder == *agent)
                || agent_task_uses_workspace(society, agent, workspace)
        })
        && options
            .task_filter
            .as_ref()
            .is_none_or(|task_id| task_uses_workspace(society, task_id, workspace))
}

fn capability_grant_matches_filters(
    society: &nexus_agent::Society,
    grant: &CapabilityGrant,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .workspace_filter
        .is_none_or(|workspace| grant.capability.workspace == workspace)
        && options.agent_filter.as_ref().is_none_or(|agent| {
            grant.capability.issuer == *agent || grant.capability.subject == *agent
        })
        && options.task_filter.as_ref().is_none_or(|task_id| {
            task_uses_workspace(society, task_id, &grant.capability.workspace)
        })
}

fn collective_matches_filters(
    society: &nexus_agent::Society,
    collective: &Collective,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| collective_involves_agent(society, collective, agent))
        && options.workspace_filter.is_none_or(|workspace| {
            collective.workspaces.contains(&workspace)
                || society
                    .collective_proposals(&collective.id)
                    .into_iter()
                    .any(|proposal| proposal.workspace == Some(workspace))
        })
        && options.task_filter.as_ref().is_none_or(|task_id| {
            society
                .collective_proposals(&collective.id)
                .into_iter()
                .any(|proposal| proposal_matches_task_filter(society, proposal, task_id))
        })
}

fn proposal_matches_filters(
    society: &nexus_agent::Society,
    proposal: &CollectiveProposal,
    options: &SocietyJsonOptions,
) -> bool {
    options.agent_filter.as_ref().is_none_or(|agent| {
        proposal.proposer == *agent
            || society
                .collective_votes(&proposal.collective_id, &proposal.id)
                .into_iter()
                .any(|vote| vote.voter == *agent)
            || society
                .collective_decision(&proposal.collective_id, &proposal.id)
                .is_some_and(|decision| {
                    decision.decider == *agent || decision.target.as_ref() == Some(agent)
                })
    }) && options
        .workspace_filter
        .is_none_or(|workspace| proposal.workspace == Some(workspace))
        && options
            .task_filter
            .as_ref()
            .is_none_or(|task_id| proposal_matches_task_filter(society, proposal, task_id))
}

fn vote_matches_filters(vote: &CollectiveVote, options: &SocietyJsonOptions) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| vote.voter == *agent)
}

fn task_matches_filters(
    society: &nexus_agent::Society,
    task: &Task,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .task_filter
        .as_ref()
        .is_none_or(|task_id| task.id == *task_id)
        && options
            .agent_filter
            .as_ref()
            .is_none_or(|agent| task_involves_agent(society, task, agent))
        && options
            .workspace_filter
            .is_none_or(|workspace| task_uses_workspace(society, &task.id, &workspace))
}

fn relation_matches_filters(
    society: &nexus_agent::Society,
    edge: &SocialEdge,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| edge.from == *agent || edge.to == *agent)
        && options.task_filter.as_ref().is_none_or(|task_id| {
            society.task(task_id).is_some_and(|task| {
                edge.from == task.publisher
                    || edge.to == task.publisher
                    || task.assigned_to.as_ref() == Some(&edge.from)
                    || task.assigned_to.as_ref() == Some(&edge.to)
            })
        })
}

fn interaction_matches_filters(interaction: &&Interaction, options: &SocietyJsonOptions) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| interaction.from == *agent || interaction.to == *agent)
        && options
            .workspace_filter
            .is_none_or(|workspace| interaction.workspace == Some(workspace))
        && options.task_filter.as_ref().is_none_or(|task_id| {
            interaction.evidence.as_deref() == Some(task_id) || interaction.topic.contains(task_id)
        })
}

fn settlement_matches_filters(
    settlement: &&SettlementRecord,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| settlement.payer == *agent || settlement.payee == *agent)
        && options
            .task_filter
            .as_ref()
            .is_none_or(|task_id| settlement.task_id.as_deref() == Some(task_id.as_str()))
}

fn intent_matches_filters(intent: &&AgentIntent, options: &SocietyJsonOptions) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| intent.author == *agent)
        && options
            .workspace_filter
            .is_none_or(|workspace| intent.workspace == Some(workspace))
        && options.task_filter.as_ref().is_none_or(|task_id| {
            intent.task_id.as_deref() == Some(task_id)
                || intent.title.contains(task_id)
                || intent.body.contains(task_id)
        })
}

fn intent_response_matches_filters(
    response: &&IntentResponse,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| response.responder == *agent)
        && options
            .workspace_filter
            .is_none_or(|workspace| response.workspace == Some(workspace))
        && options.task_filter.as_ref().is_none_or(|task_id| {
            response.task_id.as_deref() == Some(task_id)
                || response.intent_id == *task_id
                || response.body.contains(task_id)
        })
}

fn intent_recommendation_matches_filters(
    recommendation: &IntentRecommendation,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .workspace_filter
        .is_none_or(|workspace| recommendation.intent.workspace == Some(workspace))
        && options.task_filter.as_ref().is_none_or(|task_id| {
            recommendation.intent.task_id.as_deref() == Some(task_id)
                || recommendation.intent.title.contains(task_id)
                || recommendation.intent.body.contains(task_id)
        })
}

fn reputation_matches_filters(
    society: &nexus_agent::Society,
    (from, to, _score): (&Did, &Did, &ReputationScore),
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| from == agent || to == agent)
        && options.task_filter.as_ref().is_none_or(|task_id| {
            society.task(task_id).is_some_and(|task| {
                from == &task.publisher
                    || to == &task.publisher
                    || task.assigned_to.as_ref() == Some(from)
                    || task.assigned_to.as_ref() == Some(to)
            })
        })
}

fn collective_involves_agent(
    society: &nexus_agent::Society,
    collective: &Collective,
    agent: &Did,
) -> bool {
    collective.members.contains(agent)
        || society
            .collective_proposals(&collective.id)
            .into_iter()
            .any(|proposal| {
                proposal.proposer == *agent
                    || society
                        .collective_votes(&proposal.collective_id, &proposal.id)
                        .into_iter()
                        .any(|vote| vote.voter == *agent)
                    || society
                        .collective_decision(&proposal.collective_id, &proposal.id)
                        .is_some_and(|decision| {
                            decision.decider == *agent || decision.target.as_ref() == Some(agent)
                        })
            })
}

fn proposal_matches_task_filter(
    society: &nexus_agent::Society,
    proposal: &CollectiveProposal,
    task_id: &str,
) -> bool {
    society
        .collective_decision(&proposal.collective_id, &proposal.id)
        .is_some_and(|decision| decision.task_id.as_deref() == Some(task_id))
}

fn task_involves_agent(society: &nexus_agent::Society, task: &Task, agent: &Did) -> bool {
    task.publisher == *agent
        || task.assigned_to.as_ref() == Some(agent)
        || society
            .task_offers(&task.id)
            .iter()
            .any(|offer| offer.bidder == *agent)
        || society
            .task_acceptance(&task.id)
            .is_some_and(|acceptance| acceptance.publisher == *agent || acceptance.bidder == *agent)
        || society
            .task_result(&task.id)
            .is_some_and(|result| result.executor == *agent)
        || society
            .task_result_claims(&task.id)
            .into_iter()
            .any(|result| result.executor == *agent)
        || society
            .task_execution_attestations(&task.id)
            .into_iter()
            .any(|attestation| attestation.executor == *agent || attestation.attestor == *agent)
        || society
            .task_disputes(&task.id)
            .into_iter()
            .any(|dispute| dispute.disputer == *agent || dispute.target == *agent)
        || society
            .task_claim_judgments(&task.id)
            .into_iter()
            .any(|judgment| judgment.decider == *agent || judgment.target.as_ref() == Some(agent))
}

fn agent_uses_workspace(
    society: &nexus_agent::Society,
    agent: &Did,
    workspace: &WorkspaceId,
) -> bool {
    society.agent_workspaces(agent).contains(workspace)
        || society
            .workspace_runs(workspace)
            .into_iter()
            .any(|run| run.actor == *agent)
        || society
            .workspace_snapshots(workspace)
            .into_iter()
            .any(|snapshot| snapshot.actor == *agent)
        || society
            .workspace_capability_grants(workspace)
            .into_iter()
            .any(|grant| grant.capability.issuer == *agent || grant.capability.subject == *agent)
        || society
            .workspace_intents(workspace)
            .into_iter()
            .any(|intent| intent.author == *agent)
        || society
            .workspace_intent_responses(workspace)
            .into_iter()
            .any(|response| response.responder == *agent)
        || agent_task_uses_workspace(society, agent, workspace)
}

fn agent_task_uses_workspace(
    society: &nexus_agent::Society,
    agent: &Did,
    workspace: &WorkspaceId,
) -> bool {
    society
        .tasks()
        .into_iter()
        .filter(|task| task_involves_agent(society, task, agent))
        .any(|task| task_uses_workspace(society, &task.id, workspace))
}

fn task_uses_workspace(
    society: &nexus_agent::Society,
    task_id: &str,
    workspace: &WorkspaceId,
) -> bool {
    society
        .task_result(task_id)
        .and_then(|result| result.receipt.as_deref())
        .is_some_and(|receipt| receipt.workspace.as_ref() == Some(workspace))
        || society
            .task_result_claims(task_id)
            .into_iter()
            .filter_map(|result| result.receipt.as_deref())
            .any(|receipt| receipt.workspace.as_ref() == Some(workspace))
}

fn capability_grant_json(
    society: &nexus_agent::Society,
    grant: &CapabilityGrant,
) -> serde_json::Value {
    let revocation = society.capability_revocation(grant);
    serde_json::json!({
        "issuer": grant.capability.issuer.to_string(),
        "subject": grant.capability.subject.to_string(),
        "workspace": grant.capability.workspace.to_string(),
        "capability_signature_id": capability_signature_id(&grant.capability.signature),
        "permissions": {
            "read": grant.capability.permissions.read,
            "write": grant.capability.permissions.write,
            "exec": grant.capability.permissions.exec,
            "admin": grant.capability.permissions.admin,
        },
        "expires_at": grant.capability.expires_at,
        "delegation_depth": grant.capability.delegation_depth,
        "delegation_chain_length": capability_delegation_chain_length(&grant.capability),
        "delegated": grant.capability.parent.is_some(),
        "issued_at": grant.issued_at,
        "revoked": revocation.is_some(),
        "revocation": revocation.map(capability_revocation_json),
        "note": grant.note,
    })
}

fn capability_delegation_chain_length(capability: &nexus_core::Capability) -> usize {
    let mut length = 0;
    let mut cursor = capability.parent.as_deref();
    while let Some(parent) = cursor {
        length += 1;
        cursor = parent.parent.as_deref();
    }
    length
}

fn capability_revocation_json(revocation: &CapabilityRevocation) -> serde_json::Value {
    serde_json::json!({
        "issuer": revocation.issuer.to_string(),
        "capability_signature_id": revocation.capability_signature_id,
        "reason": revocation.reason,
        "revoked_at": revocation.revoked_at,
    })
}

fn identity_revocation_json(revocation: &IdentityRevocation) -> serde_json::Value {
    serde_json::json!({
        "did": revocation.did.to_string(),
        "reason": revocation.reason,
        "revoked_at": revocation.revoked_at,
    })
}

fn provider_recommendation_json(recommendation: ProviderRecommendation) -> serde_json::Value {
    serde_json::json!({
        "did": recommendation.did.to_string(),
        "name": recommendation.name,
        "capability": recommendation.capability,
        "capability_claim_status": if recommendation.verified_capability.is_some() {
            "verified"
        } else {
            "declared"
        },
        "verified_capability": recommendation.verified_capability.map(verified_capability_json),
        "social_score": recommendation.social_score,
        "reputation_score": recommendation.reputation_score,
        "reachability_score": recommendation.reachability_score,
        "high_trust_eligible": recommendation.high_trust_eligible,
        "sybil_cluster_score": recommendation.sybil_cluster_score,
        "governance_score": recommendation.governance_score,
        "governance_signals": recommendation
            .governance_signals
            .into_iter()
            .map(governance_signal_json)
            .collect::<Vec<_>>(),
        "price_per_unit": recommendation.price_per_unit,
        "ranking_score": recommendation.ranking_score,
    })
}

fn verified_capability_json(verified: VerifiedCapability) -> serde_json::Value {
    serde_json::json!({
        "name": verified.name,
        "successful_tasks": verified.successful_tasks,
        "independently_attested_tasks": verified.independently_attested_tasks,
        "latest_task_id": verified.latest_task_id,
        "latest_observed_at": verified.latest_observed_at,
    })
}

fn governance_signal_json(signal: GovernanceSignal) -> serde_json::Value {
    serde_json::json!({
        "collective_id": signal.collective_id,
        "proposal_id": signal.proposal_id,
        "decider": signal.decider.to_string(),
        "outcome": signal.outcome,
        "task_id": signal.task_id,
        "claim_id": signal.claim_id,
        "truth_status": signal.truth_status,
        "reason": signal.reason,
        "timestamp": signal.timestamp,
    })
}

fn intent_json(intent: &AgentIntent) -> serde_json::Value {
    serde_json::json!({
        "id": intent.id,
        "author": intent.author.to_string(),
        "kind": intent.kind,
        "title": intent.title,
        "body": intent.body,
        "workspace": intent.workspace.map(|workspace| workspace.to_string()),
        "task_id": intent.task_id,
        "capability": intent.capability,
        "tags": intent.tags,
        "created_at": intent.created_at,
        "expires_at": intent.expires_at,
    })
}

fn intent_response_json(response: &IntentResponse) -> serde_json::Value {
    serde_json::json!({
        "id": response.id,
        "intent_id": response.intent_id,
        "responder": response.responder.to_string(),
        "kind": response.kind,
        "body": response.body,
        "workspace": response.workspace.map(|workspace| workspace.to_string()),
        "task_id": response.task_id,
        "capability": response.capability,
        "evidence": response.evidence,
        "created_at": response.created_at,
    })
}

fn intent_recommendation_json(recommendation: IntentRecommendation) -> serde_json::Value {
    serde_json::json!({
        "intent": intent_json(&recommendation.intent),
        "author_name": recommendation.author_name,
        "capability_score": recommendation.capability_score,
        "workspace_score": recommendation.workspace_score,
        "social_score": recommendation.social_score,
        "reputation_score": recommendation.reputation_score,
        "response_score": recommendation.response_score,
        "preference_score": recommendation.preference_score,
        "response_count": recommendation.response_count,
        "fulfilled": recommendation.fulfilled,
        "ranking_score": recommendation.ranking_score,
        "reasons": recommendation.reasons,
        "actions": recommendation
            .actions
            .into_iter()
            .map(intent_action_plan_json)
            .collect::<Vec<_>>(),
    })
}

fn intent_action_plan_json(action: nexus_agent::IntentActionPlan) -> serde_json::Value {
    serde_json::json!({
        "kind": action.kind,
        "event_hint": action.event_hint,
        "intent_id": action.intent_id,
        "actor": action.actor.to_string(),
        "peer": action.peer.to_string(),
        "title": action.title,
        "body": action.body,
        "confidence": action.confidence,
        "workspace": action.workspace.map(|workspace| workspace.to_string()),
        "task_id": action.task_id,
        "capability": action.capability,
        "response_kind": action.response_kind,
        "suggested_price": action.suggested_price,
        "estimated_time_secs": action.estimated_time_secs,
    })
}

fn agent_activity_json(
    society: &nexus_agent::Society,
    agent: &Did,
    options: &SocietyJsonOptions,
) -> serde_json::Value {
    serde_json::json!({
        "workspace_runs": activity_window(
            society.agent_workspace_runs(agent),
            options,
            |run| run.finished_at,
        )
            .into_iter()
            .map(workspace_run_json)
            .collect::<Vec<_>>(),
        "task_results": activity_window(
            society.agent_task_results(agent),
            options,
            |result| task_result_activity_timestamp(result),
        )
            .into_iter()
            .map(|result| task_result_json(society, result))
            .collect::<Vec<_>>(),
        "task_result_claims": activity_window(
            society.agent_task_result_claims(agent),
            options,
            |result| task_result_activity_timestamp(result),
        )
            .into_iter()
            .map(|result| task_result_claim_json(society, result))
            .collect::<Vec<_>>(),
        "interactions": activity_window(
            society.agent_interactions(agent),
            options,
            |interaction| interaction.timestamp,
        )
            .into_iter()
            .map(interaction_json)
            .collect::<Vec<_>>(),
        "reputations": activity_window(
            society.agent_reputations(agent),
            options,
            |(_, _, score)| score.last_seen,
        )
            .into_iter()
            .map(reputation_json)
            .collect::<Vec<_>>(),
    })
}

fn activity_window<T, F>(items: Vec<T>, options: &SocietyJsonOptions, timestamp: F) -> Vec<T>
where
    F: Fn(&T) -> u64,
{
    let mut filtered = items
        .into_iter()
        .filter(|item| {
            options
                .activity_since
                .is_none_or(|since| timestamp(item) >= since)
        })
        .collect::<Vec<_>>();

    if let Some(limit) = options.activity_limit {
        let drop_count = filtered.len().saturating_sub(limit);
        if drop_count > 0 {
            filtered.drain(0..drop_count);
        }
    }

    filtered
}

fn task_result_activity_timestamp(result: &TaskResult) -> u64 {
    result
        .receipt
        .as_deref()
        .map(|receipt| receipt.finished_at)
        .unwrap_or_default()
}

fn workspace_snapshot_json(snapshot: &WorkspaceSnapshot) -> serde_json::Value {
    serde_json::json!({
        "workspace": snapshot.workspace.to_string(),
        "actor": snapshot.actor.to_string(),
        "root": hex::encode(snapshot.root.as_bytes()),
        "label": snapshot.label,
        "note": snapshot.note,
        "timestamp": snapshot.timestamp,
    })
}

fn workspace_run_json(run: &WorkspaceRun) -> serde_json::Value {
    serde_json::json!({
        "workspace": run.workspace.to_string(),
        "actor": run.actor.to_string(),
        "command": run.command,
        "args": run.args,
        "exit_code": run.exit_code,
        "stdout": hex::encode(run.stdout.as_bytes()),
        "stderr": hex::encode(run.stderr.as_bytes()),
        "output_root": run.output_root.map(|root| hex::encode(root.as_bytes())),
        "resources": run.resources,
        "resource_evidence": workspace_run_resource_evidence_json(run),
        "context": run.context.as_ref().map(workspace_run_context_json),
        "failure": run.failure.as_ref().map(workspace_run_failure_json),
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "note": run.note,
    })
}

fn workspace_run_resource_evidence_json(run: &WorkspaceRun) -> serde_json::Value {
    serde_json::json!({
        "measurement_status": "self_reported",
        "source": "workspace_run.resources",
        "signed_by": run.actor.to_string(),
        "signature_scope": "social_event",
        "independent_verification": "not_performed",
        "verified_measurement": false,
    })
}

fn workspace_run_failure_json(failure: &WorkspaceRunFailure) -> serde_json::Value {
    serde_json::json!({
        "kind": failure.kind,
        "message": failure.message,
    })
}

fn workspace_run_context_json(context: &WorkspaceRunContext) -> serde_json::Value {
    serde_json::json!({
        "working_dir": context.working_dir.as_ref(),
        "env_keys": &context.env_keys,
        "stdin": context.stdin.as_ref().map(|stdin| serde_json::json!({
            "bytes": stdin.bytes,
            "cid": hex::encode(stdin.cid.as_bytes()),
        })),
        "timeout_ms": context.timeout_ms,
    })
}

fn interaction_json(interaction: &Interaction) -> serde_json::Value {
    serde_json::json!({
        "id": interaction.id,
        "from": interaction.from.to_string(),
        "to": interaction.to.to_string(),
        "workspace": interaction.workspace.map(|workspace| workspace.to_string()),
        "topic": interaction.topic,
        "outcome": interaction.outcome,
        "timestamp": interaction.timestamp,
        "evidence": interaction.evidence,
    })
}

fn reputation_json((from, to, score): (&Did, &Did, &ReputationScore)) -> serde_json::Value {
    serde_json::json!({
        "from": from.to_string(),
        "to": to.to_string(),
        "subject": score.subject.to_string(),
        "availability": score.availability,
        "correctness": score.correctness,
        "timeliness": score.timeliness,
        "fairness": score.fairness,
        "successes": score.successes,
        "failures": score.failures,
        "composite": score.composite(),
        "first_seen": score.first_seen,
        "last_seen": score.last_seen,
    })
}

fn task_result_json(society: &nexus_agent::Society, result: &TaskResult) -> serde_json::Value {
    serde_json::json!({
        "task_id": result.task_id,
        "executor": result.executor.to_string(),
        "success": result.success,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "actual_cost": result.actual_cost,
        "error": result.error,
        "resource_evidence": task_result_resource_evidence_json(society, result),
        "receipt": result.receipt.as_deref().map(execution_receipt_json),
        "attestations": society.task_result_attestations(result).into_iter().map(execution_attestation_json).collect::<Vec<_>>(),
    })
}

fn task_result_resource_evidence_json(
    society: &nexus_agent::Society,
    result: &TaskResult,
) -> serde_json::Value {
    match result.receipt.as_deref() {
        Some(receipt) => {
            let receipt_signature_valid = receipt.verify_signature().is_ok();
            let output_cids_match_result = receipt.stdout_cid
                == Cid::hash_of(result.stdout.as_bytes())
                && receipt.stderr_cid == Cid::hash_of(result.stderr.as_bytes());
            let matching_attestations = society.task_result_attestations(result).len();
            let has_independent_reexecution = matching_attestations > 0;

            serde_json::json!({
                "measurement_status": if has_independent_reexecution {
                    "independent_reexecution_cross_checked"
                } else {
                    "signed_executor_claim"
                },
                "source": "receipt.resources",
                "signed_by": receipt.executor.to_string(),
                "signature_scope": "execution_receipt",
                "receipt_signature_valid": receipt_signature_valid,
                "output_cids_match_result": output_cids_match_result,
                "matching_attestations": matching_attestations,
                "independent_verification": if has_independent_reexecution {
                    "attested_reexecution"
                } else {
                    "not_performed"
                },
                "verified_output": has_independent_reexecution,
                "verified_measurement": false,
            })
        }
        None => serde_json::json!({
            "measurement_status": "self_reported",
            "source": null,
            "signed_by": result.executor.to_string(),
            "signature_scope": "social_event",
            "receipt_signature_valid": null,
            "output_cids_match_result": null,
            "matching_attestations": 0,
            "independent_verification": "not_performed",
            "verified_output": false,
            "verified_measurement": false,
        }),
    }
}

fn settlement_json(
    society: &nexus_agent::Society,
    settlement: &SettlementRecord,
) -> serde_json::Value {
    serde_json::json!({
        "id": settlement.id,
        "task_id": settlement.task_id,
        "claim_id": settlement.claim_id,
        "payer": settlement.payer.to_string(),
        "payee": settlement.payee.to_string(),
        "amount": settlement.amount,
        "truth_status": society.settlement_truth_status(settlement),
        "anchor": settlement.authority_anchor(),
        "checkpoint_subject": settlement.checkpoint_subject(),
        "proof": settlement.proof,
        "settled_at": settlement.settled_at,
    })
}

fn task_result_claim_json(
    society: &nexus_agent::Society,
    result: &TaskResult,
) -> serde_json::Value {
    let claim_id = task_result_claim_id(result);
    let mut value = task_result_json(society, result);
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "claim_id".into(),
            serde_json::Value::String(claim_id.clone()),
        );
        object.insert(
            "judgments".into(),
            serde_json::Value::Array(
                society
                    .result_claim_judgments(&result.task_id, &claim_id)
                    .into_iter()
                    .map(task_claim_judgment_json)
                    .collect(),
            ),
        );
    }
    value
}

fn task_claim_judgment_json(judgment: TaskClaimJudgment) -> serde_json::Value {
    serde_json::json!({
        "collective_id": judgment.collective_id,
        "proposal_id": judgment.proposal_id,
        "decider": judgment.decider.to_string(),
        "outcome": judgment.outcome,
        "task_id": judgment.task_id,
        "claim_id": judgment.claim_id,
        "target": judgment.target.as_ref().map(ToString::to_string),
        "truth_status": judgment.truth_status,
        "reason": judgment.reason,
        "timestamp": judgment.timestamp,
    })
}

fn execution_receipt_json(receipt: &ExecutionReceipt) -> serde_json::Value {
    serde_json::json!({
        "task_id": receipt.task_id,
        "executor": receipt.executor.to_string(),
        "workspace": receipt.workspace.map(|workspace| workspace.to_string()),
        "command": receipt.command,
        "args": receipt.args,
        "exit_code": receipt.exit_code,
        "stdout_cid": hex::encode(receipt.stdout_cid.as_bytes()),
        "stderr_cid": hex::encode(receipt.stderr_cid.as_bytes()),
        "output_root": receipt.output_root.map(|root| hex::encode(root.as_bytes())),
        "resources": receipt.resources,
        "resource_evidence": execution_receipt_resource_evidence_json(receipt),
        "started_at": receipt.started_at,
        "finished_at": receipt.finished_at,
        "signature": receipt.signature.as_ref().map(hex::encode),
    })
}

fn execution_receipt_resource_evidence_json(receipt: &ExecutionReceipt) -> serde_json::Value {
    serde_json::json!({
        "measurement_status": "signed_executor_claim",
        "source": "receipt.resources",
        "signed_by": receipt.executor.to_string(),
        "signature_scope": "execution_receipt",
        "receipt_signature_valid": receipt.verify_signature().is_ok(),
        "independent_verification": "not_performed",
        "verified_measurement": false,
    })
}

fn execution_attestation_json(attestation: &ExecutionAttestation) -> serde_json::Value {
    serde_json::json!({
        "task_id": attestation.task_id,
        "executor": attestation.executor.to_string(),
        "attestor": attestation.attestor.to_string(),
        "receipt_signature_hex": attestation.receipt_signature_hex,
        "stdout_cid": hex::encode(attestation.stdout_cid.as_bytes()),
        "stderr_cid": hex::encode(attestation.stderr_cid.as_bytes()),
        "output_root": attestation.output_root.map(|root| hex::encode(root.as_bytes())),
        "resources": attestation.resources,
        "resource_evidence": execution_attestation_resource_evidence_json(attestation),
        "observed_at": attestation.observed_at,
        "signature": attestation.signature.as_ref().map(hex::encode),
    })
}

fn execution_attestation_resource_evidence_json(
    attestation: &ExecutionAttestation,
) -> serde_json::Value {
    serde_json::json!({
        "measurement_status": "signed_attestor_claim",
        "source": "attestation.resources",
        "signed_by": attestation.attestor.to_string(),
        "signature_scope": "execution_attestation",
        "attestation_signature_valid": attestation.verify_signature().is_ok(),
        "independent_verification": "attested_reexecution",
        "verified_measurement": false,
    })
}
