//! Resource usage tracking.
//!
//! Every process execution is metered for billing purposes.
//! These metrics are recorded but **never enforced** — agents
//! are trusted to consume what they need.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Accumulated resource consumption for one or more process executions.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Total wall-clock time spent executing.
    pub wall_time: Duration,

    /// Total user-mode CPU time (approximate, from OS).
    pub cpu_user: Duration,

    /// Total kernel-mode CPU time (approximate, from OS).
    pub cpu_kernel: Duration,

    /// Peak resident set size (bytes), if available.
    pub peak_memory: Option<u64>,

    /// Total bytes read from filesystem.
    pub fs_read_bytes: u64,

    /// Total bytes written to filesystem.
    pub fs_write_bytes: u64,

    /// Number of processes spawned.
    pub process_count: u64,
}

impl ResourceUsage {
    /// Merge another usage into this one (accumulate).
    pub fn merge(&mut self, other: &ResourceUsage) {
        self.wall_time += other.wall_time;
        self.cpu_user += other.cpu_user;
        self.cpu_kernel += other.cpu_kernel;
        self.peak_memory = match (self.peak_memory, other.peak_memory) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        self.fs_read_bytes += other.fs_read_bytes;
        self.fs_write_bytes += other.fs_write_bytes;
        self.process_count += other.process_count;
    }
}
