//! Task — the unit of work in the agent marketplace.

use ed25519_dalek::{Signature, VerifyingKey};
use nexus_core::Did;
use nexus_crypto::{parse_did, DidError, NodeIdentity};
use nexus_runtime::{ProcessOutput, ResourceUsage};
use nexus_storage::Cid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// States a task can be in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    /// Task is published and awaiting bids.
    Published,
    /// A bid has been accepted; work is in progress.
    InProgress,
    /// Task completed successfully.
    Completed,
    /// Task failed.
    Failed,
    /// Task was cancelled.
    Cancelled,
}

/// A task published to the marketplace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Task {
    /// Unique task ID (random hex string).
    pub id: String,

    /// Who published this task.
    pub publisher: Did,

    /// Human-readable description.
    pub description: String,

    /// Required capability name, e.g. "python-exec".
    pub required_capability: String,

    /// The command to execute (program).
    pub command: String,

    /// Arguments.
    pub args: Vec<String>,

    /// Optional input data (base64-encoded).
    pub input: Option<String>,

    /// Maximum budget (credit units).
    pub max_budget: u64,

    /// Deadline (Unix timestamp).
    pub deadline: u64,

    /// Current state.
    pub state: TaskState,

    /// Who is executing this task (set after bid accepted).
    pub assigned_to: Option<Did>,

    /// When the task was created.
    pub created_at: u64,
}

/// An offer to execute a task for a given price.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskOffer {
    /// The task being bid on.
    pub task_id: String,

    /// Who is offering.
    pub bidder: Did,

    /// Proposed price (credit units).
    pub price: u64,

    /// Estimated completion time (seconds).
    pub estimated_time_secs: u64,

    /// Why this bidder is suitable.
    pub rationale: String,
}

/// Alias for backward compat and semantic clarity.
pub type TaskBid = TaskOffer;

/// Publisher acceptance of a specific task offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskAcceptance {
    pub task_id: String,
    pub publisher: Did,
    pub bidder: Did,
    pub price: u64,
    pub accepted_at: u64,
}

/// Publisher cancellation of an open task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskCancellation {
    pub task_id: String,
    pub publisher: Did,
    pub reason: String,
    pub cancelled_at: u64,
}

/// Result of executing a task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskResult {
    /// The task ID.
    pub task_id: String,

    /// Who executed it.
    pub executor: Did,

    /// Whether it succeeded.
    pub success: bool,

    /// Exit code.
    pub exit_code: i32,

    /// Captured stdout.
    pub stdout: String,

    /// Captured stderr.
    pub stderr: String,

    /// Actual cost (credit units).
    pub actual_cost: u64,

    /// Error message if any.
    pub error: Option<String>,

    /// Optional signed proof of the execution that produced this result.
    #[serde(default)]
    pub receipt: Option<Box<ExecutionReceipt>>,
}

/// Signed evidence that an agent executed a task in a free workspace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub task_id: String,
    pub executor: Did,
    pub workspace: Option<nexus_core::WorkspaceId>,
    pub command: String,
    pub args: Vec<String>,
    pub exit_code: i32,
    pub stdout_cid: Cid,
    pub stderr_cid: Cid,
    pub output_root: Option<Cid>,
    pub resources: ResourceUsage,
    pub started_at: u64,
    pub finished_at: u64,
    pub signature: Option<Vec<u8>>,
}

/// Input for creating a task without a long argument list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskSpec {
    /// Stable task ID used by social events, offers, results, and ledgers.
    ///
    /// Older serialized task specs may not contain this field; such specs are
    /// resolved to a deterministic content-derived ID when converted to a task.
    #[serde(default)]
    pub id: String,
    pub publisher: Did,
    pub description: String,
    pub required_capability: String,
    pub command: String,
    pub args: Vec<String>,
    pub max_budget: u64,
    pub deadline: u64,
    pub created_at: u64,
}

/// Errors produced while signing or verifying execution receipts.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionReceiptError {
    #[error("receipt executor {executor} does not match signer {signer}")]
    ExecutorSignerMismatch { executor: Did, signer: Did },

    #[error("execution receipt is missing an executor signature")]
    MissingSignature,

    #[error("invalid executor DID: {0}")]
    InvalidExecutorDid(#[from] DidError),

    #[error("invalid Ed25519 verifying key: {0}")]
    InvalidVerifyingKey(#[from] ed25519_dalek::SignatureError),

    #[error("invalid Ed25519 signature bytes")]
    InvalidSignatureBytes,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("execution receipt does not match task result")]
    ReceiptMismatch,

    #[error("execution receipt output CIDs do not match task result output")]
    OutputCidMismatch,

    #[error("successful task result must have zero exit code")]
    SuccessExitCodeMismatch,

    #[error("failed to serialize execution receipt signing payload: {0}")]
    PayloadSerialization(#[from] serde_json::Error),
}

impl ExecutionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn from_process_output(
        task_id: impl Into<String>,
        executor: Did,
        workspace: Option<nexus_core::WorkspaceId>,
        command: impl Into<String>,
        args: Vec<String>,
        output: &ProcessOutput,
        output_root: Option<Cid>,
        started_at: u64,
        finished_at: u64,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            executor,
            workspace,
            command: command.into(),
            args,
            exit_code: output.exit_code,
            stdout_cid: Cid::hash_of(&output.stdout),
            stderr_cid: Cid::hash_of(&output.stderr),
            output_root,
            resources: output.resources.clone(),
            started_at,
            finished_at,
            signature: None,
        }
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        #[derive(Serialize)]
        struct Payload<'a> {
            task_id: &'a str,
            executor: &'a Did,
            workspace: Option<nexus_core::WorkspaceId>,
            command: &'a str,
            args: &'a [String],
            exit_code: i32,
            stdout_cid: Cid,
            stderr_cid: Cid,
            output_root: Option<Cid>,
            resources: &'a ResourceUsage,
            started_at: u64,
            finished_at: u64,
        }

        serde_json::to_vec(&Payload {
            task_id: &self.task_id,
            executor: &self.executor,
            workspace: self.workspace,
            command: &self.command,
            args: &self.args,
            exit_code: self.exit_code,
            stdout_cid: self.stdout_cid,
            stderr_cid: self.stderr_cid,
            output_root: self.output_root,
            resources: &self.resources,
            started_at: self.started_at,
            finished_at: self.finished_at,
        })
    }

    pub fn sign(mut self, identity: &NodeIdentity) -> Result<Self, ExecutionReceiptError> {
        let signer = identity.did().clone();
        if self.executor != signer {
            return Err(ExecutionReceiptError::ExecutorSignerMismatch {
                executor: self.executor,
                signer,
            });
        }

        let payload = self.signing_payload()?;
        self.signature = Some(identity.sign(&payload).to_bytes().to_vec());
        Ok(self)
    }

    pub fn verify_signature(&self) -> Result<(), ExecutionReceiptError> {
        let signature = self
            .signature
            .as_deref()
            .ok_or(ExecutionReceiptError::MissingSignature)?;
        let signature = Signature::from_slice(signature)
            .map_err(|_| ExecutionReceiptError::InvalidSignatureBytes)?;
        let key_bytes = parse_did(self.executor.as_str())?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)?;
        let payload = self.signing_payload()?;

        NodeIdentity::verify(&verifying_key, &payload, &signature)
            .map_err(|_| ExecutionReceiptError::SignatureVerificationFailed)
    }
}

impl TaskResult {
    pub fn validate_receipt(&self) -> Result<(), ExecutionReceiptError> {
        let Some(receipt) = &self.receipt else {
            return Ok(());
        };

        receipt.verify_signature()?;
        if receipt.task_id != self.task_id
            || receipt.executor != self.executor
            || receipt.exit_code != self.exit_code
        {
            return Err(ExecutionReceiptError::ReceiptMismatch);
        }
        if receipt.stdout_cid != Cid::hash_of(self.stdout.as_bytes())
            || receipt.stderr_cid != Cid::hash_of(self.stderr.as_bytes())
        {
            return Err(ExecutionReceiptError::OutputCidMismatch);
        }
        if self.success && self.exit_code != 0 {
            return Err(ExecutionReceiptError::SuccessExitCodeMismatch);
        }

        Ok(())
    }
}

impl TaskSpec {
    /// Create a task spec with a stable ID that can be signed and gossiped.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publisher: Did,
        description: impl Into<String>,
        required_capability: impl Into<String>,
        command: impl Into<String>,
        args: Vec<String>,
        max_budget: u64,
        deadline: u64,
        created_at: u64,
    ) -> Self {
        Self {
            id: random_id(),
            publisher,
            description: description.into(),
            required_capability: required_capability.into(),
            command: command.into(),
            args,
            max_budget,
            deadline,
            created_at,
        }
    }

    /// Return the stable ID for this task spec.
    ///
    /// New specs carry an explicit random ID chosen by the publisher. Specs
    /// decoded from older social events may have no ID, so they fall back to a
    /// deterministic content hash to keep all peers in agreement.
    pub fn resolved_id(&self) -> String {
        if !self.id.is_empty() {
            return self.id.clone();
        }

        #[derive(Serialize)]
        struct LegacyTaskSpec<'a> {
            publisher: &'a Did,
            description: &'a str,
            required_capability: &'a str,
            command: &'a str,
            args: &'a [String],
            max_budget: u64,
            deadline: u64,
            created_at: u64,
        }

        let payload = serde_json::to_vec(&LegacyTaskSpec {
            publisher: &self.publisher,
            description: &self.description,
            required_capability: &self.required_capability,
            command: &self.command,
            args: &self.args,
            max_budget: self.max_budget,
            deadline: self.deadline,
            created_at: self.created_at,
        })
        .expect("legacy task spec serialization should not fail");
        let digest = Sha256::digest(payload);
        format!("legacy-{}", hex::encode(&digest[..16]))
    }
}

impl Task {
    /// Create a new task in Published state.
    pub fn from_spec(spec: TaskSpec) -> Self {
        let id = spec.resolved_id();

        Self {
            id,
            publisher: spec.publisher,
            description: spec.description,
            required_capability: spec.required_capability,
            command: spec.command,
            args: spec.args,
            input: None,
            max_budget: spec.max_budget,
            deadline: spec.deadline,
            state: TaskState::Published,
            assigned_to: None,
            created_at: spec.created_at,
        }
    }

    /// Convert this task back to the stable spec used by social events.
    pub fn to_spec(&self) -> TaskSpec {
        TaskSpec {
            id: self.id.clone(),
            publisher: self.publisher.clone(),
            description: self.description.clone(),
            required_capability: self.required_capability.clone(),
            command: self.command.clone(),
            args: self.args.clone(),
            max_budget: self.max_budget,
            deadline: self.deadline,
            created_at: self.created_at,
        }
    }

    /// Create a new task in Published state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publisher: Did,
        description: &str,
        required_capability: &str,
        command: &str,
        args: Vec<String>,
        max_budget: u64,
        deadline: u64,
        now: u64,
    ) -> Self {
        Self::from_spec(TaskSpec::new(
            publisher,
            description,
            required_capability,
            command,
            args,
            max_budget,
            deadline,
            now,
        ))
    }

    /// Accept a bid, assigning the task to the bidder.
    pub fn accept_bid(&mut self, bidder: &Did) {
        self.state = TaskState::InProgress;
        self.assigned_to = Some(bidder.clone());
    }

    /// Mark as completed.
    pub fn complete(&mut self) {
        self.state = TaskState::Completed;
    }

    /// Mark as failed.
    pub fn fail(&mut self) {
        self.state = TaskState::Failed;
    }

    /// Cancel the task.
    pub fn cancel(&mut self) {
        self.state = TaskState::Cancelled;
    }

    /// Whether the task is still open for bids.
    pub fn is_open(&self) -> bool {
        matches!(self.state, TaskState::Published)
    }

    /// Whether the task has finished (success or failure).
    pub fn is_done(&self) -> bool {
        matches!(
            self.state,
            TaskState::Completed | TaskState::Failed | TaskState::Cancelled
        )
    }
}

fn random_id() -> String {
    use rand::RngCore;

    let mut id_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    hex::encode(id_bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use nexus_crypto::NodeIdentity;

    fn did(s: &str) -> Did {
        Did::new(format!("did:key:{s}"))
    }

    #[test]
    fn task_lifecycle() {
        let publisher = did("publisher");
        let worker = did("worker");

        let mut task = Task::new(
            publisher.clone(),
            "Run data analysis",
            "python-exec",
            "python",
            vec!["analysis.py".into()],
            100,
            9999999999,
            0,
        );

        assert!(task.is_open());
        assert!(!task.is_done());

        task.accept_bid(&worker);
        assert_eq!(task.state, TaskState::InProgress);
        assert_eq!(task.assigned_to, Some(worker));

        task.complete();
        assert!(task.is_done());
    }

    #[test]
    fn task_id_is_unique() {
        let pub_did = did("pub");
        let t1 = Task::new(pub_did.clone(), "a", "cap", "cmd", vec![], 10, 999, 0);
        let t2 = Task::new(pub_did, "b", "cap", "cmd", vec![], 10, 999, 0);
        assert_ne!(t1.id, t2.id);
    }

    #[test]
    fn task_from_spec_preserves_social_id() {
        let pub_did = did("pub");
        let spec = TaskSpec {
            id: "task-abc".into(),
            publisher: pub_did,
            description: "shared task".into(),
            required_capability: "python-exec".into(),
            command: "python".into(),
            args: vec!["script.py".into()],
            max_budget: 10,
            deadline: 999,
            created_at: 1,
        };

        let task = Task::from_spec(spec.clone());
        assert_eq!(task.id, "task-abc");
        assert_eq!(task.to_spec().id, spec.id);
    }

    #[test]
    fn legacy_task_spec_resolves_to_deterministic_id() {
        let pub_did = did("pub");
        let first = TaskSpec {
            id: String::new(),
            publisher: pub_did,
            description: "old task".into(),
            required_capability: "shell".into(),
            command: "sh".into(),
            args: vec!["run.sh".into()],
            max_budget: 5,
            deadline: 100,
            created_at: 1,
        };
        let mut second = first.clone();

        assert_eq!(first.resolved_id(), second.resolved_id());
        second.description = "different task".into();
        assert_ne!(first.resolved_id(), second.resolved_id());
    }

    #[test]
    fn execution_receipt_signs_process_output_cids() {
        let executor = NodeIdentity::generate();
        let output = ProcessOutput {
            exit_code: 0,
            stdout: b"hello".to_vec(),
            stderr: b"warning".to_vec(),
            resources: ResourceUsage {
                wall_time: Duration::from_millis(25),
                process_count: 1,
                ..Default::default()
            },
        };
        let receipt = ExecutionReceipt::from_process_output(
            "task-1",
            executor.did().clone(),
            None,
            "echo",
            vec!["hello".into()],
            &output,
            Some(Cid::hash_of(b"workspace-root")),
            10,
            11,
        )
        .sign(&executor)
        .unwrap();

        receipt.verify_signature().unwrap();
        assert_eq!(receipt.stdout_cid, Cid::hash_of(b"hello"));
        assert_eq!(receipt.stderr_cid, Cid::hash_of(b"warning"));

        let result = TaskResult {
            task_id: "task-1".into(),
            executor: executor.did().clone(),
            success: true,
            exit_code: 0,
            stdout: "hello".into(),
            stderr: "warning".into(),
            actual_cost: 1,
            error: None,
            receipt: Some(Box::new(receipt)),
        };
        result.validate_receipt().unwrap();
    }

    #[test]
    fn receipt_verification_rejects_tampering_and_mismatch() {
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

        let mut tampered = receipt.clone();
        tampered.exit_code = 1;
        assert!(matches!(
            tampered.verify_signature().unwrap_err(),
            ExecutionReceiptError::SignatureVerificationFailed
        ));

        let mismatched = TaskResult {
            task_id: "task-2".into(),
            executor: executor.did().clone(),
            success: true,
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            actual_cost: 1,
            error: None,
            receipt: Some(Box::new(receipt.clone())),
        };
        assert!(matches!(
            mismatched.validate_receipt().unwrap_err(),
            ExecutionReceiptError::ReceiptMismatch
        ));

        let output_mismatched = TaskResult {
            task_id: "task-1".into(),
            executor: executor.did().clone(),
            success: true,
            exit_code: 0,
            stdout: "forged stdout".into(),
            stderr: String::new(),
            actual_cost: 1,
            error: None,
            receipt: Some(Box::new(receipt.clone())),
        };
        assert!(matches!(
            output_mismatched.validate_receipt().unwrap_err(),
            ExecutionReceiptError::OutputCidMismatch
        ));

        let failed_output = ProcessOutput {
            exit_code: 1,
            stdout: Vec::new(),
            stderr: b"failed".to_vec(),
            resources: ResourceUsage::default(),
        };
        let failed_receipt = ExecutionReceipt::from_process_output(
            "task-1",
            executor.did().clone(),
            None,
            "false",
            Vec::new(),
            &failed_output,
            None,
            10,
            11,
        )
        .sign(&executor)
        .unwrap();
        let inconsistent_success = TaskResult {
            task_id: "task-1".into(),
            executor: executor.did().clone(),
            success: true,
            exit_code: 1,
            stdout: String::new(),
            stderr: "failed".into(),
            actual_cost: 1,
            error: None,
            receipt: Some(Box::new(failed_receipt)),
        };
        assert!(matches!(
            inconsistent_success.validate_receipt().unwrap_err(),
            ExecutionReceiptError::SuccessExitCodeMismatch
        ));
    }
}
