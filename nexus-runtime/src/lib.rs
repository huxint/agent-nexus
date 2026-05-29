//! Nexus Runtime — native process executor (no sandbox).
//!
//! Agents have **absolute freedom**: they can spawn arbitrary processes,
//! access the filesystem, and use the network directly.
//!
//! The framework does not enforce local sandboxing. Identity, reputation,
//! credit, and social relationships decide who agents choose to work with;
//! the workspace itself stays a real computer.
//!
//! ## Design
//!
//! The runtime wraps a workspace directory.  All commands run with that
//! directory as the working directory.  Resource usage is tracked for
//! billing/monitoring, but never capped.

mod executor;
mod resources;

pub use executor::{ExecError, ExecOptions, Executor, ProcessOutput};
pub use resources::ResourceUsage;
