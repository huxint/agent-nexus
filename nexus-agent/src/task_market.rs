use std::collections::{HashMap, HashSet};

use nexus_core::Did;
use nexus_storage::Cid;
use serde::{Deserialize, Serialize};

use crate::society::{
    task_result_claim_id, Interaction, InteractionOutcome, TaskDispute, VerifiedCapability,
    WorkspaceSnapshot,
};
use crate::task::{
    ExecutionAttestation, Task, TaskAcceptance, TaskCancellation, TaskOffer, TaskResult, TaskSpec,
    TaskState,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct TaskMarketProjection {
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
    applied_task_results: HashSet<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum TaskMarketEffect {
    WorkspaceSnapshot(WorkspaceSnapshot),
    Interaction(Interaction),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TaskResultClaim {
    result: TaskResult,
    timestamp: u64,
}

impl TaskMarketProjection {
    pub(crate) fn task_count(&self) -> usize {
        self.tasks.len()
    }

    pub(crate) fn task(&self, task_id: &str) -> Option<&Task> {
        self.tasks.get(task_id)
    }

    pub(crate) fn tasks(&self) -> Vec<&Task> {
        let mut tasks: Vec<&Task> = self.tasks.values().collect();
        tasks.sort_by(|a, b| a.id.cmp(&b.id));
        tasks
    }

    pub(crate) fn task_offers(&self, task_id: &str) -> &[TaskOffer] {
        self.task_offers
            .get(task_id)
            .map(|offers| offers.as_slice())
            .unwrap_or(&[])
    }

    pub(crate) fn task_result(&self, task_id: &str) -> Option<&TaskResult> {
        self.task_results.get(task_id)
    }

    pub(crate) fn task_result_claims(&self, task_id: &str) -> Vec<&TaskResult> {
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

    pub(crate) fn task_execution_attestations(&self, task_id: &str) -> Vec<&ExecutionAttestation> {
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

    pub(crate) fn task_result_attestations<'a>(
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

    pub(crate) fn agent_task_results(&self, executor: &Did) -> Vec<&TaskResult> {
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

    pub(crate) fn agent_task_result_claims(&self, executor: &Did) -> Vec<&TaskResult> {
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

    pub(crate) fn task_acceptance(&self, task_id: &str) -> Option<&TaskAcceptance> {
        self.active_task_acceptance(task_id)
    }

    pub(crate) fn task_cancellation(&self, task_id: &str) -> Option<&TaskCancellation> {
        self.active_task_cancellation(task_id)
    }

    pub(crate) fn task_disputes(&self, task_id: &str) -> Vec<&TaskDispute> {
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

    pub(crate) fn open_tasks_for(&self, capability: &str) -> Vec<&Task> {
        self.tasks
            .values()
            .filter(|task| task.is_open() && task.required_capability == capability)
            .collect()
    }

    pub(crate) fn agent_verified_capabilities(&self, agent: &Did) -> Vec<VerifiedCapability> {
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

    pub(crate) fn publish_task(&mut self, task: TaskSpec) -> Vec<TaskMarketEffect> {
        let task = Task::from_spec(task);
        let task_id = task.id.clone();
        self.tasks.entry(task_id.clone()).or_insert(task);
        let mut effects = self.apply_known_task_acceptance(&task_id);
        effects.extend(self.apply_known_task_cancellation(&task_id));
        effects.extend(self.apply_known_task_result(&task_id));
        effects
    }

    pub(crate) fn record_offer(&mut self, offer: TaskOffer) -> Vec<TaskMarketEffect> {
        let task_id = offer.task_id.clone();
        let offers = self.task_offers.entry(offer.task_id.clone()).or_default();
        if offers
            .iter()
            .any(|existing| existing.bidder == offer.bidder)
        {
            return Vec::new();
        }

        offers.push(offer);
        offers.sort_by(|a, b| {
            a.price
                .cmp(&b.price)
                .then_with(|| a.bidder.to_string().cmp(&b.bidder.to_string()))
        });
        let mut effects = self.apply_known_task_acceptance(&task_id);
        effects.extend(self.apply_known_task_cancellation(&task_id));
        effects
    }

    pub(crate) fn record_acceptance(
        &mut self,
        acceptance: TaskAcceptance,
    ) -> Vec<TaskMarketEffect> {
        let task_id = acceptance.task_id.clone();
        self.task_acceptances
            .entry(task_id.clone())
            .or_default()
            .entry(acceptance_key(&acceptance))
            .or_insert(acceptance);
        let mut effects = self.apply_known_task_acceptance(&task_id);
        effects.extend(self.apply_known_task_cancellation(&task_id));
        effects
    }

    pub(crate) fn record_cancellation(
        &mut self,
        cancellation: TaskCancellation,
    ) -> Vec<TaskMarketEffect> {
        let task_id = cancellation.task_id.clone();
        self.task_cancellations
            .entry(task_id.clone())
            .or_default()
            .entry(cancellation_key(&cancellation))
            .or_insert(cancellation);
        self.apply_known_task_cancellation(&task_id)
    }

    pub(crate) fn record_result(
        &mut self,
        result: TaskResult,
        timestamp: u64,
    ) -> Vec<TaskMarketEffect> {
        let task_id = result.task_id.clone();
        let claim_key = task_result_claim_id(&result);
        if self
            .task_result_claims
            .entry(task_id.clone())
            .or_default()
            .insert(claim_key, TaskResultClaim { result, timestamp })
            .is_some()
        {
            return Vec::new();
        }

        self.apply_known_task_result(&task_id)
    }

    pub(crate) fn record_execution_attestation(&mut self, attestation: ExecutionAttestation) {
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

    pub(crate) fn record_dispute(&mut self, dispute: TaskDispute) -> Option<TaskMarketEffect> {
        let task_id = dispute.task_id.clone();
        let disputer = dispute.disputer.clone();
        let target = dispute.target.clone();
        let claim_id = dispute.claim_id.clone();
        let key = task_dispute_key(&dispute);
        if self.task_disputes.insert(key, dispute.clone()).is_some() {
            return None;
        }

        Some(TaskMarketEffect::Interaction(Interaction {
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
        }))
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

    fn apply_known_task_acceptance(&mut self, task_id: &str) -> Vec<TaskMarketEffect> {
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
            return Vec::new();
        };
        let Some(task) = self.tasks.get_mut(task_id) else {
            return Vec::new();
        };
        if task.publisher != acceptance.publisher || !task.is_open() {
            return Vec::new();
        }
        let Some(offers) = self.task_offers.get(task_id) else {
            return Vec::new();
        };
        if !offers
            .iter()
            .any(|offer| offer.bidder == acceptance.bidder && offer.price == acceptance.price)
        {
            return Vec::new();
        }

        task.accept_bid(&acceptance.bidder);
        self.apply_known_task_result(task_id)
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

    fn apply_known_task_cancellation(&mut self, task_id: &str) -> Vec<TaskMarketEffect> {
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
            return Vec::new();
        };
        let Some(task) = self.tasks.get_mut(task_id) else {
            return Vec::new();
        };
        if task.publisher != cancellation.publisher || task.is_done() {
            return Vec::new();
        }

        task.cancel();
        Vec::new()
    }

    fn apply_known_task_result(&mut self, task_id: &str) -> Vec<TaskMarketEffect> {
        if self.applied_task_results.contains(task_id) {
            return Vec::new();
        }

        let Some(claim) = self.select_applicable_task_result(task_id) else {
            return Vec::new();
        };
        let result = claim.result;
        let timestamp = claim.timestamp;
        let workspace = result
            .receipt
            .as_deref()
            .and_then(|receipt| receipt.workspace);
        if result.success && result.receipt.is_none() {
            return Vec::new();
        };
        let Some(task) = self.tasks.get(task_id) else {
            return Vec::new();
        };
        if task.assigned_to.as_ref() != Some(&result.executor) {
            return Vec::new();
        }
        if matches!(task.state, TaskState::Published | TaskState::Cancelled) {
            return Vec::new();
        }

        let publisher = task.publisher.clone();
        let description = task.description.clone();
        let self_transaction = publisher == result.executor;
        self.applied_task_results.insert(task_id.to_string());
        {
            let Some(task) = self.tasks.get_mut(task_id) else {
                return Vec::new();
            };
            if result.success {
                task.complete();
            } else {
                task.fail();
            }
        }

        let mut effects = Vec::new();
        if let Some(snapshot) = task_result_workspace_snapshot(&result) {
            effects.push(TaskMarketEffect::WorkspaceSnapshot(snapshot));
        }
        self.task_results
            .insert(task_id.to_string(), result.clone());

        if !self_transaction {
            effects.push(TaskMarketEffect::Interaction(Interaction {
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
            }));
        }

        effects
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
}

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

fn task_result_workspace_snapshot(result: &TaskResult) -> Option<WorkspaceSnapshot> {
    let receipt = result.receipt.as_deref()?;
    let (Some(workspace), Some(root)) = (receipt.workspace, receipt.output_root) else {
        return None;
    };

    Some(WorkspaceSnapshot {
        workspace,
        actor: receipt.executor.clone(),
        root,
        label: Some("task-result".into()),
        note: Some(format!("task {} result", result.task_id)),
        timestamp: receipt.finished_at,
    })
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
    use nexus_core::Did;
    use nexus_crypto::NodeIdentity;
    use nexus_runtime::{ProcessOutput, ResourceUsage};

    fn did(s: &str) -> Did {
        Did::new(format!("did:key:{s}"))
    }

    fn task_spec(publisher: Did) -> TaskSpec {
        TaskSpec {
            id: "task-market-test".into(),
            publisher,
            description: "projection task".into(),
            required_capability: "shell".into(),
            command: "sh".into(),
            args: vec!["-c".into(), "true".into()],
            max_budget: 10,
            deadline: 100,
            created_at: 1,
        }
    }

    #[test]
    fn delayed_offer_applies_known_acceptance() {
        let publisher = did("publisher");
        let worker = did("worker");
        let spec = task_spec(publisher.clone());
        let task_id = spec.id.clone();
        let mut market = TaskMarketProjection::default();

        assert!(market
            .record_acceptance(TaskAcceptance {
                task_id: task_id.clone(),
                publisher: publisher.clone(),
                bidder: worker.clone(),
                price: 7,
                accepted_at: 3,
            })
            .is_empty());
        assert!(market.publish_task(spec).is_empty());

        let effects = market.record_offer(TaskOffer {
            task_id: task_id.clone(),
            bidder: worker.clone(),
            price: 7,
            estimated_time_secs: 1,
            rationale: "ready".into(),
        });

        assert!(effects.is_empty());
        let task = market.task(&task_id).unwrap();
        assert_eq!(task.state, TaskState::InProgress);
        assert_eq!(task.assigned_to.as_ref(), Some(&worker));
        assert_eq!(market.task_acceptance(&task_id).unwrap().price, 7);
    }

    #[test]
    fn accepted_receipted_result_emits_interaction_effect() {
        let publisher = did("publisher");
        let worker = NodeIdentity::generate();
        let worker_did = worker.did().clone();
        let spec = task_spec(publisher.clone());
        let task_id = spec.id.clone();
        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };
        let receipt = crate::task::ExecutionReceipt::from_process_output(
            task_id.clone(),
            worker_did.clone(),
            None,
            "sh",
            vec!["-c".into(), "true".into()],
            &output,
            None,
            4,
            5,
        )
        .sign(&worker)
        .unwrap();
        let mut market = TaskMarketProjection::default();

        market.publish_task(spec);
        market.record_offer(TaskOffer {
            task_id: task_id.clone(),
            bidder: worker_did.clone(),
            price: 7,
            estimated_time_secs: 1,
            rationale: "ready".into(),
        });
        market.record_acceptance(TaskAcceptance {
            task_id: task_id.clone(),
            publisher: publisher.clone(),
            bidder: worker_did.clone(),
            price: 7,
            accepted_at: 3,
        });

        let effects = market.record_result(
            TaskResult {
                task_id: task_id.clone(),
                executor: worker_did.clone(),
                success: true,
                exit_code: 0,
                stdout: "ok".into(),
                stderr: String::new(),
                actual_cost: 7,
                error: None,
                receipt: Some(Box::new(receipt)),
                attestations: Vec::new(),
            },
            6,
        );

        assert_eq!(market.task(&task_id).unwrap().state, TaskState::Completed);
        assert!(market.task_result(&task_id).is_some());
        assert_eq!(effects.len(), 1);
        match &effects[0] {
            TaskMarketEffect::Interaction(interaction) => {
                assert_eq!(interaction.from, publisher);
                assert_eq!(interaction.to, worker_did);
                assert_eq!(interaction.outcome, InteractionOutcome::Success);
                assert_eq!(interaction.evidence.as_deref(), Some(task_id.as_str()));
            }
            TaskMarketEffect::WorkspaceSnapshot(_) => {
                panic!("result without output root should not emit a workspace snapshot")
            }
        }
    }
}
