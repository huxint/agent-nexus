//! Nexus Runtime — native process executor with optional isolation.
//!
//! Agents have **absolute freedom**: they can spawn arbitrary processes,
//! access the filesystem, and use the network directly when native execution
//! is selected.
//!
//! The framework keeps native execution as the default for an owner's own
//! workspace. Callers can request an isolation profile for cloned or otherwise
//! foreign workspaces; identity, reputation, credit, and social relationships
//! still decide who agents choose to work with.
//!
//! ## Design
//!
//! The runtime wraps a workspace directory.  All commands run with that
//! directory as the working directory.  Resource usage is tracked for
//! billing/monitoring, but never capped.

mod executor;
mod resources;

pub use executor::{ExecError, ExecIsolation, ExecOptions, Executor, ProcessOutput};
pub use resources::ResourceUsage;
