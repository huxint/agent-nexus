//! Workspace-specific error types.

use nexus_core::NexusError;
use nexus_runtime::ExecError;
use nexus_storage::store::StoreError;

/// Errors that can occur during workspace operations.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("workspace already exists: {0}")]
    AlreadyExists(String),

    #[error("workspace not found: {0}")]
    NotFound(String),

    #[error("permission denied: {reason}")]
    PermissionDenied { reason: String },

    #[error("invalid capability: {0}")]
    InvalidCapability(String),

    #[error("storage error: {0}")]
    Storage(#[from] StoreError),

    #[error("execution error: {0}")]
    Exec(Box<ExecError>),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl From<ExecError> for WorkspaceError {
    fn from(error: ExecError) -> Self {
        Self::Exec(Box::new(error))
    }
}

impl From<WorkspaceError> for NexusError {
    fn from(e: WorkspaceError) -> Self {
        match e {
            WorkspaceError::PermissionDenied { reason } => NexusError::PermissionDenied { reason },
            WorkspaceError::InvalidCapability(msg) => NexusError::InvalidCapability(msg),
            WorkspaceError::Io(e) => NexusError::Io(e),
            other => NexusError::Other(other.to_string()),
        }
    }
}

pub type WorkspaceResult<T> = Result<T, WorkspaceError>;
