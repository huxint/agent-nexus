//! Nexus Workspace — the orchestration layer.
//!
//! A [`Workspace`] is the primary abstraction: it owns a directory on disk,
//! a content-addressed Merkle-DAG backing store, a native process executor,
//! and a set of guest agents with verified capabilities.
//!
//! ## Lifecycle
//!
//! ```text
//! create() → workspace directory + empty Merkle root
//!   ↓
//! write("hello.py", code) → file on disk + blob in BlockStore
//!   ↓
//! exec("python", ["hello.py"]) → native process, output captured
//!   ↓
//! snapshot() → new Merkle root CID (history preserved)
//! ```

mod error;
mod filesystem;
mod workspace;

pub use error::WorkspaceError;
pub use filesystem::FileEntry;
pub use server::{WorkspaceServer, WorkspaceState};
pub use workspace::{Guest, Workspace, WorkspaceConfig};

pub mod server;
