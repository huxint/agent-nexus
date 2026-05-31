//! Task market — matching tasks to agents via bids and settling payments.
//!
//! The market holds the state of all published tasks and their bids.
//! When a task completes, the payment is settled through the credit ledger.

use std::collections::HashMap;

use nexus_core::Did;
use nexus_economy::ledger::CreditLedger;

use crate::registry::AgentRegistry;
use crate::task::{ExecutionReceiptError, Task, TaskBid, TaskResult};

/// Errors that can occur in market operations.
#[derive(Debug, thiserror::Error)]
pub enum MarketError {
    #[error("task not found: {0}")]
    TaskNotFound(String),

    #[error("task is not open for bids")]
    TaskNotOpen,

    #[error("task already assigned")]
    TaskAlreadyAssigned,

    #[error("no submitted bid from agent")]
    BidNotFound,

    #[error("task has not been assigned")]
    TaskNotAssigned,

    #[error("task result executor does not match assigned agent")]
    ResultExecutorMismatch,

    #[error("task result cost exceeds max budget")]
    ResultExceedsBudget,

    #[error("task result cost exceeds accepted bid")]
    ResultExceedsAcceptedBid,

    #[error("execution receipt command does not match task command")]
    ReceiptCommandMismatch,

    #[error("successful task settlement requires a signed execution receipt")]
    MissingExecutionReceipt,

    #[error("invalid execution receipt: {0}")]
    InvalidExecutionReceipt(#[from] ExecutionReceiptError),

    #[error("bid exceeds max budget")]
    BidExceedsBudget,

    #[error("agent does not provide required capability")]
    MissingCapability,

    #[error("credit settlement failed: {0}")]
    SettlementFailed(String),

    #[error("{0}")]
    Other(String),
}

/// The task marketplace.
///
/// Holds all active tasks and their bids.  When a task completes,
/// payment is routed through the credit ledger using the trust graph.
#[derive(Debug, Default)]
pub struct TaskMarket {
    /// All known tasks (active + completed).
    tasks: HashMap<String, Task>,

    /// Bids for active tasks: task_id → list of bids.
    bids: HashMap<String, Vec<TaskBid>>,

    /// Accepted bid for assigned tasks: task_id → bid.
    accepted_bids: HashMap<String, TaskBid>,

    /// Results for completed tasks.
    results: HashMap<String, TaskResult>,
}

impl TaskMarket {
    pub fn new() -> Self {
        Self::default()
    }

    // -- Task lifecycle --

    /// Publish a new task to the market.
    pub fn publish(&mut self, task: Task) {
        self.tasks.insert(task.id.clone(), task);
    }

    /// Get a task by ID.
    pub fn get_task(&self, task_id: &str) -> Option<&Task> {
        self.tasks.get(task_id)
    }

    /// List all open tasks.
    pub fn open_tasks(&self) -> Vec<&Task> {
        self.tasks.values().filter(|t| t.is_open()).collect()
    }

    /// List open tasks requiring a specific capability.
    pub fn open_tasks_for(&self, capability: &str) -> Vec<&Task> {
        self.tasks
            .values()
            .filter(|t| t.is_open() && t.required_capability == capability)
            .collect()
    }

    // -- Bidding --

    /// Submit a bid for a task.
    pub fn submit_bid(
        &mut self,
        bid: TaskBid,
        registry: &AgentRegistry,
    ) -> Result<(), MarketError> {
        let task = self
            .tasks
            .get(&bid.task_id)
            .ok_or_else(|| MarketError::TaskNotFound(bid.task_id.clone()))?;

        if !task.is_open() {
            return Err(MarketError::TaskNotOpen);
        }

        if bid.price > task.max_budget {
            return Err(MarketError::BidExceedsBudget);
        }

        // Verify bidder provides required capability
        let agent = registry
            .get(&bid.bidder)
            .ok_or(MarketError::MissingCapability)?;
        if !agent.provides_named(&task.required_capability) {
            return Err(MarketError::MissingCapability);
        }

        self.bids.entry(bid.task_id.clone()).or_default().push(bid);
        Ok(())
    }

    /// Get all bids for a task.
    pub fn get_bids(&self, task_id: &str) -> &[TaskBid] {
        self.bids.get(task_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Find the cheapest valid bid for a task.
    pub fn cheapest_bid(&self, task_id: &str) -> Option<&TaskBid> {
        self.bids
            .get(task_id)
            .and_then(|bids| bids.iter().min_by_key(|b| b.price))
    }

    // -- Acceptance & execution --

    /// Accept a bid and assign the task.
    pub fn accept_bid(&mut self, task_id: &str, bidder: &Did) -> Result<(), MarketError> {
        let has_bid = self
            .bids
            .get(task_id)
            .is_some_and(|bids| bids.iter().any(|bid| &bid.bidder == bidder));
        if !has_bid {
            return Err(MarketError::BidNotFound);
        }

        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| MarketError::TaskNotFound(task_id.into()))?;

        if !task.is_open() {
            return Err(MarketError::TaskNotOpen);
        }

        let bid = self
            .bids
            .get(task_id)
            .and_then(|bids| bids.iter().find(|bid| &bid.bidder == bidder))
            .cloned()
            .ok_or(MarketError::BidNotFound)?;

        task.accept_bid(bidder);
        self.accepted_bids.insert(task_id.to_string(), bid);
        Ok(())
    }

    /// Record a task result and settle payment.
    pub fn complete_task(
        &mut self,
        result: TaskResult,
        ledger: &mut CreditLedger,
        now: u64,
    ) -> Result<(), MarketError> {
        let task_id = result.task_id.clone();

        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| MarketError::TaskNotFound(task_id.clone()))?;

        match &task.assigned_to {
            Some(assigned) if assigned == &result.executor => {}
            Some(_) => return Err(MarketError::ResultExecutorMismatch),
            None => return Err(MarketError::TaskNotAssigned),
        }

        if result.actual_cost > task.max_budget {
            return Err(MarketError::ResultExceedsBudget);
        }
        if let Some(accepted_bid) = self.accepted_bids.get(&task_id) {
            if result.actual_cost > accepted_bid.price {
                return Err(MarketError::ResultExceedsAcceptedBid);
            }
        }

        if result.success {
            let receipt = result
                .receipt
                .as_ref()
                .ok_or(MarketError::MissingExecutionReceipt)?;
            result.validate_receipt()?;
            if receipt.command != task.command || receipt.args != task.args {
                return Err(MarketError::ReceiptCommandMismatch);
            }
            task.complete();
            // Settle payment: task publisher pays executor.
            let amount = result.actual_cost as i64;
            ledger
                .record(&result.executor, -amount, now)
                .map_err(|e| MarketError::SettlementFailed(e.to_string()))?;
        } else {
            if result.receipt.is_some() {
                result.validate_receipt()?;
            }
            task.fail();
        }

        self.results.insert(task_id, result);
        Ok(())
    }

    /// Cancel a task.
    pub fn cancel_task(&mut self, task_id: &str) -> Result<(), MarketError> {
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| MarketError::TaskNotFound(task_id.into()))?;
        task.cancel();
        Ok(())
    }

    /// Number of active tasks.
    pub fn active_count(&self) -> usize {
        self.tasks.values().filter(|t| !t.is_done()).count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{AgentManifest, CapabilityDecl};
    use crate::registry::AgentRegistry;
    use crate::task::{ExecutionReceipt, Task};
    use nexus_crypto::NodeIdentity;
    use nexus_runtime::{ProcessOutput, ResourceUsage};

    fn did(s: &str) -> Did {
        Did::new(format!("did:key:{s}"))
    }

    fn setup() -> (TaskMarket, AgentRegistry) {
        let market = TaskMarket::new();
        let mut registry = AgentRegistry::new();

        // Register a worker agent
        let worker = did("worker");
        let manifest = AgentManifest::new(worker.clone(), "worker", 0).provide(CapabilityDecl {
            name: "python-exec".into(),
            description: "Runs Python".into(),
            version: "1.0".into(),
            price_per_unit: 5,
            price_unit: "per-second".into(),
        });
        registry.register(manifest);

        (market, registry)
    }

    fn signed_receipt(
        identity: &NodeIdentity,
        task_id: &str,
        command: &str,
        args: Vec<String>,
        exit_code: i32,
    ) -> Box<ExecutionReceipt> {
        let output = ProcessOutput {
            exit_code,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            resources: ResourceUsage::default(),
        };

        Box::new(
            ExecutionReceipt::from_process_output(
                task_id,
                identity.did().clone(),
                None,
                command,
                args,
                &output,
                None,
                1,
                2,
            )
            .sign(identity)
            .unwrap(),
        )
    }

    #[test]
    fn publish_and_bid() {
        let (mut market, registry) = setup();
        let publisher = did("publisher");
        let worker = did("worker");

        let task = Task::new(
            publisher,
            "test task",
            "python-exec",
            "python",
            vec!["script.py".into()],
            100,
            999999,
            0,
        );
        let task_id = task.id.clone();
        market.publish(task);

        let bid = TaskBid {
            task_id: task_id.clone(),
            bidder: worker,
            price: 30,
            estimated_time_secs: 10,
            rationale: "I can do this".into(),
        };

        market
            .submit_bid(bid, &registry)
            .expect("bid should succeed");
        assert_eq!(market.get_bids(&task_id).len(), 1);
    }

    #[test]
    fn bid_exceeds_budget_rejected() {
        let (mut market, registry) = setup();
        let publisher = did("publisher");
        let worker = did("worker");

        let task = Task::new(publisher, "test", "python-exec", "cmd", vec![], 50, 999, 0);
        let task_id = task.id.clone();
        market.publish(task);

        let bid = TaskBid {
            task_id,
            bidder: worker,
            price: 100, // Exceeds budget of 50
            estimated_time_secs: 1,
            rationale: "".into(),
        };

        let err = market.submit_bid(bid, &registry).unwrap_err();
        assert!(matches!(err, MarketError::BidExceedsBudget));
    }

    #[test]
    fn bid_missing_capability_rejected() {
        let (mut market, registry) = setup();
        let publisher = did("publisher");
        let noob = did("noob"); // Not in registry

        let task = Task::new(publisher, "test", "python-exec", "cmd", vec![], 100, 999, 0);
        let task_id = task.id.clone();
        market.publish(task);

        let bid = TaskBid {
            task_id,
            bidder: noob,
            price: 10,
            estimated_time_secs: 1,
            rationale: "".into(),
        };

        let err = market.submit_bid(bid, &registry).unwrap_err();
        assert!(matches!(err, MarketError::MissingCapability));
    }

    #[test]
    fn complete_task_settles_payment() {
        let (mut market, registry) = setup();
        let publisher = did("publisher");
        let worker_identity = NodeIdentity::generate();
        let worker = worker_identity.did().clone();

        let mut registry = registry;
        registry.unregister(&did("worker"));
        registry.register(AgentManifest::new(worker.clone(), "worker", 0).provide(
            CapabilityDecl {
                name: "python-exec".into(),
                description: "Runs Python".into(),
                version: "1.0".into(),
                price_per_unit: 5,
                price_unit: "per-second".into(),
            },
        ));

        let task = Task::new(
            publisher.clone(),
            "test",
            "python-exec",
            "cmd",
            vec![],
            100,
            999,
            0,
        );
        let task_id = task.id.clone();
        market.publish(task);

        market
            .submit_bid(
                TaskBid {
                    task_id: task_id.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    estimated_time_secs: 1,
                    rationale: "ready".into(),
                },
                &registry,
            )
            .unwrap();
        market.accept_bid(&task_id, &worker).expect("accept bid");

        let mut ledger = CreditLedger::new();
        ledger.get_or_create(&worker, 1000, 1000, 0);

        let result = TaskResult {
            task_id: task_id.clone(),
            executor: worker.clone(),
            success: true,
            exit_code: 0,
            stdout: "ok".into(),
            stderr: String::new(),
            actual_cost: 25,
            error: None,
            receipt: Some(signed_receipt(
                &worker_identity,
                &task_id,
                "cmd",
                Vec::new(),
                0,
            )),
            attestations: Vec::new(),
        };

        market
            .complete_task(result, &mut ledger, 1)
            .expect("complete");
        // Publisher paid worker 25
        assert_eq!(ledger.get(&worker).unwrap().balance, -25);
    }

    #[test]
    fn successful_completion_requires_signed_receipt() {
        let (mut market, registry) = setup();
        let publisher = did("publisher");
        let worker = did("worker");
        let task = Task::new(publisher, "test", "python-exec", "cmd", vec![], 100, 999, 0);
        let task_id = task.id.clone();
        market.publish(task);
        market
            .submit_bid(
                TaskBid {
                    task_id: task_id.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    estimated_time_secs: 1,
                    rationale: "ready".into(),
                },
                &registry,
            )
            .unwrap();
        market.accept_bid(&task_id, &worker).unwrap();

        let mut ledger = CreditLedger::new();
        ledger.get_or_create(&worker, 1000, 1000, 0);
        let err = market
            .complete_task(
                TaskResult {
                    task_id,
                    executor: worker.clone(),
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 25,
                    error: None,
                    receipt: None,
                    attestations: Vec::new(),
                },
                &mut ledger,
                1,
            )
            .unwrap_err();

        assert!(matches!(err, MarketError::MissingExecutionReceipt));
        assert_eq!(ledger.get(&worker).unwrap().balance, 0);
    }

    #[test]
    fn completion_rejects_mismatched_receipt_before_settlement() {
        let (mut market, registry) = setup();
        let publisher = did("publisher");
        let worker_identity = NodeIdentity::generate();
        let worker = worker_identity.did().clone();

        let mut registry = registry;
        registry.unregister(&did("worker"));
        registry.register(AgentManifest::new(worker.clone(), "worker", 0).provide(
            CapabilityDecl {
                name: "python-exec".into(),
                description: "Runs Python".into(),
                version: "1.0".into(),
                price_per_unit: 5,
                price_unit: "per-second".into(),
            },
        ));

        let task = Task::new(publisher, "test", "python-exec", "cmd", vec![], 100, 999, 0);
        let task_id = task.id.clone();
        market.publish(task);
        market
            .submit_bid(
                TaskBid {
                    task_id: task_id.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    estimated_time_secs: 1,
                    rationale: "ready".into(),
                },
                &registry,
            )
            .unwrap();
        market.accept_bid(&task_id, &worker).unwrap();

        let mut ledger = CreditLedger::new();
        ledger.get_or_create(&worker, 1000, 1000, 0);
        let err = market
            .complete_task(
                TaskResult {
                    task_id: task_id.clone(),
                    executor: worker.clone(),
                    success: true,
                    exit_code: 1,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 25,
                    error: None,
                    receipt: Some(signed_receipt(
                        &worker_identity,
                        &task_id,
                        "cmd",
                        Vec::new(),
                        0,
                    )),
                    attestations: Vec::new(),
                },
                &mut ledger,
                1,
            )
            .unwrap_err();

        assert!(matches!(err, MarketError::InvalidExecutionReceipt(_)));
        assert_eq!(ledger.get(&worker).unwrap().balance, 0);
    }

    #[test]
    fn completion_rejects_cost_above_accepted_bid() {
        let (mut market, registry) = setup();
        let publisher = did("publisher");
        let worker_identity = NodeIdentity::generate();
        let worker = worker_identity.did().clone();

        let mut registry = registry;
        registry.unregister(&did("worker"));
        registry.register(AgentManifest::new(worker.clone(), "worker", 0).provide(
            CapabilityDecl {
                name: "python-exec".into(),
                description: "Runs Python".into(),
                version: "1.0".into(),
                price_per_unit: 5,
                price_unit: "per-second".into(),
            },
        ));

        let task = Task::new(publisher, "test", "python-exec", "cmd", vec![], 100, 999, 0);
        let task_id = task.id.clone();
        market.publish(task);
        market
            .submit_bid(
                TaskBid {
                    task_id: task_id.clone(),
                    bidder: worker.clone(),
                    price: 10,
                    estimated_time_secs: 1,
                    rationale: "low fixed price".into(),
                },
                &registry,
            )
            .unwrap();
        market.accept_bid(&task_id, &worker).unwrap();

        let mut ledger = CreditLedger::new();
        ledger.get_or_create(&worker, 1000, 1000, 0);
        let err = market
            .complete_task(
                TaskResult {
                    task_id: task_id.clone(),
                    executor: worker.clone(),
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 25,
                    error: None,
                    receipt: Some(signed_receipt(
                        &worker_identity,
                        &task_id,
                        "cmd",
                        Vec::new(),
                        0,
                    )),
                    attestations: Vec::new(),
                },
                &mut ledger,
                1,
            )
            .unwrap_err();

        assert!(matches!(err, MarketError::ResultExceedsAcceptedBid));
        assert_eq!(ledger.get(&worker).unwrap().balance, 0);
    }

    #[test]
    fn completion_rejects_receipt_for_different_command() {
        let (mut market, registry) = setup();
        let publisher = did("publisher");
        let worker_identity = NodeIdentity::generate();
        let worker = worker_identity.did().clone();

        let mut registry = registry;
        registry.unregister(&did("worker"));
        registry.register(AgentManifest::new(worker.clone(), "worker", 0).provide(
            CapabilityDecl {
                name: "python-exec".into(),
                description: "Runs Python".into(),
                version: "1.0".into(),
                price_per_unit: 5,
                price_unit: "per-second".into(),
            },
        ));

        let task = Task::new(
            publisher,
            "test",
            "python-exec",
            "python",
            vec!["script.py".into()],
            100,
            999,
            0,
        );
        let task_id = task.id.clone();
        market.publish(task);
        market
            .submit_bid(
                TaskBid {
                    task_id: task_id.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    estimated_time_secs: 1,
                    rationale: "ready".into(),
                },
                &registry,
            )
            .unwrap();
        market.accept_bid(&task_id, &worker).unwrap();

        let mut ledger = CreditLedger::new();
        ledger.get_or_create(&worker, 1000, 1000, 0);
        let err = market
            .complete_task(
                TaskResult {
                    task_id: task_id.clone(),
                    executor: worker.clone(),
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 25,
                    error: None,
                    receipt: Some(signed_receipt(
                        &worker_identity,
                        &task_id,
                        "sh",
                        vec!["other.sh".into()],
                        0,
                    )),
                    attestations: Vec::new(),
                },
                &mut ledger,
                1,
            )
            .unwrap_err();

        assert!(matches!(err, MarketError::ReceiptCommandMismatch));
        assert_eq!(ledger.get(&worker).unwrap().balance, 0);
    }

    #[test]
    fn failed_completion_records_result_without_settlement() {
        let (mut market, registry) = setup();
        let publisher = did("publisher");
        let worker = did("worker");
        let task = Task::new(publisher, "test", "python-exec", "cmd", vec![], 100, 999, 0);
        let task_id = task.id.clone();
        market.publish(task);
        market
            .submit_bid(
                TaskBid {
                    task_id: task_id.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    estimated_time_secs: 1,
                    rationale: "ready".into(),
                },
                &registry,
            )
            .unwrap();
        market.accept_bid(&task_id, &worker).unwrap();

        let mut ledger = CreditLedger::new();
        ledger.get_or_create(&worker, 1000, 1000, 0);
        market
            .complete_task(
                TaskResult {
                    task_id: task_id.clone(),
                    executor: worker.clone(),
                    success: false,
                    exit_code: 7,
                    stdout: String::new(),
                    stderr: "failed".into(),
                    actual_cost: 25,
                    error: Some("failed".into()),
                    receipt: None,
                    attestations: Vec::new(),
                },
                &mut ledger,
                1,
            )
            .unwrap();

        assert_eq!(ledger.get(&worker).unwrap().balance, 0);
        assert!(market.get_task(&task_id).unwrap().is_done());
    }

    #[test]
    fn accept_bid_requires_submitted_bid() {
        let (mut market, _registry) = setup();
        let publisher = did("publisher");
        let worker = did("worker");
        let task = Task::new(publisher, "test", "python-exec", "cmd", vec![], 100, 999, 0);
        let task_id = task.id.clone();
        market.publish(task);

        let err = market.accept_bid(&task_id, &worker).unwrap_err();
        assert!(matches!(err, MarketError::BidNotFound));
    }

    #[test]
    fn complete_task_rejects_wrong_executor() {
        let (mut market, registry) = setup();
        let publisher = did("publisher");
        let worker = did("worker");
        let intruder = did("intruder");
        let task = Task::new(publisher, "test", "python-exec", "cmd", vec![], 100, 999, 0);
        let task_id = task.id.clone();
        market.publish(task);
        market
            .submit_bid(
                TaskBid {
                    task_id: task_id.clone(),
                    bidder: worker.clone(),
                    price: 25,
                    estimated_time_secs: 1,
                    rationale: "ready".into(),
                },
                &registry,
            )
            .unwrap();
        market.accept_bid(&task_id, &worker).unwrap();

        let mut ledger = CreditLedger::new();
        ledger.get_or_create(&intruder, 1000, 1000, 0);
        let err = market
            .complete_task(
                TaskResult {
                    task_id,
                    executor: intruder,
                    success: true,
                    exit_code: 0,
                    stdout: "ok".into(),
                    stderr: String::new(),
                    actual_cost: 25,
                    error: None,
                    receipt: None,
                    attestations: Vec::new(),
                },
                &mut ledger,
                1,
            )
            .unwrap_err();
        assert!(matches!(err, MarketError::ResultExecutorMismatch));
    }

    #[test]
    fn cheapest_bid_wins() {
        let (mut market, registry) = setup();
        let publisher = did("publisher");
        let worker_a = did("worker");
        let worker_b = did("workerB");

        // Register worker B too
        let manifest_b =
            AgentManifest::new(worker_b.clone(), "workerB", 0).provide(CapabilityDecl {
                name: "python-exec".into(),
                description: "Runs Python".into(),
                version: "1.0".into(),
                price_per_unit: 2,
                price_unit: "per-second".into(),
            });
        let mut registry = registry;
        registry.register(manifest_b);

        let task = Task::new(publisher, "test", "python-exec", "cmd", vec![], 100, 999, 0);
        let task_id = task.id.clone();
        market.publish(task);

        market
            .submit_bid(
                TaskBid {
                    task_id: task_id.clone(),
                    bidder: worker_a,
                    price: 30,
                    estimated_time_secs: 10,
                    rationale: "".into(),
                },
                &registry,
            )
            .unwrap();

        market
            .submit_bid(
                TaskBid {
                    task_id: task_id.clone(),
                    bidder: worker_b.clone(),
                    price: 15,
                    estimated_time_secs: 20,
                    rationale: "".into(),
                },
                &registry,
            )
            .unwrap();

        let cheapest = market.cheapest_bid(&task_id).unwrap();
        assert_eq!(cheapest.bidder, worker_b);
        assert_eq!(cheapest.price, 15);
    }
}
