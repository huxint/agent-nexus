//! Resource pricing — how agents value their compute, storage, and bandwidth.
//!
//! Each agent sets their own prices.  The market discovers equilibrium
//! through offers and negotiations.  This module provides the data model
//! and estimation utilities.

use serde::{Deserialize, Serialize};
use std::time::Duration;

fn default_wall_time_per_second() -> f64 {
    0.1
}

fn default_cpu_per_second() -> f64 {
    0.1
}

fn default_memory_per_mb() -> f64 {
    0.001
}

fn default_storage_per_mb_hour() -> f64 {
    0.001
}

fn default_process_fee() -> f64 {
    0.01
}

fn bytes_to_mb(bytes: u64) -> f64 {
    bytes as f64 / 1_048_576.0
}

fn duration_secs(duration: Duration) -> f64 {
    duration.as_secs_f64().max(0.0)
}

/// Prices for different resource types, set by each agent independently.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourcePricing {
    /// Price per wall-clock execution second (in credit units).
    ///
    /// This is the only time dimension currently measured by the native
    /// executor, so it is the default variable component for short-term
    /// estimates.
    #[serde(default = "default_wall_time_per_second")]
    pub wall_time_per_second: f64,

    /// Price per measured user+kernel CPU second.
    #[serde(default = "default_cpu_per_second")]
    pub cpu_per_second: f64,

    /// Price per peak resident memory MB observed during execution.
    #[serde(default = "default_memory_per_mb")]
    pub memory_per_mb: f64,

    /// Price per MB-hour of filesystem data read or written by execution.
    #[serde(default = "default_storage_per_mb_hour")]
    pub storage_per_mb_hour: f64,

    /// Experimental price per MB of network egress (not charged until
    /// bandwidth usage is measured and verified).
    #[serde(default)]
    pub bandwidth_per_mb: f64,

    /// Base fee per task execution (in credit units).
    pub base_fee: u64,

    /// Small fee per spawned process.
    #[serde(default = "default_process_fee")]
    pub process_fee: f64,
}

impl Default for ResourcePricing {
    fn default() -> Self {
        Self {
            wall_time_per_second: default_wall_time_per_second(),
            cpu_per_second: default_cpu_per_second(),
            memory_per_mb: default_memory_per_mb(),
            storage_per_mb_hour: default_storage_per_mb_hour(),
            bandwidth_per_mb: 0.0,
            base_fee: 1,
            process_fee: default_process_fee(),
        }
    }
}

/// Measured resource usage used for pricing.
#[derive(Clone, Copy, Debug, Default)]
pub struct MeasuredUsage {
    pub wall_time: Duration,
    pub cpu_user: Duration,
    pub cpu_kernel: Duration,
    pub peak_memory_bytes: Option<u64>,
    pub fs_read_bytes: u64,
    pub fs_write_bytes: u64,
    pub process_count: u64,
    pub bandwidth_bytes: u64,
}

/// Estimated cost of a task.
#[derive(Clone, Debug)]
pub struct CostEstimate {
    /// Wall-clock time cost component.
    pub wall_time_cost: f64,
    /// CPU time cost component.
    pub cpu_cost: f64,
    /// Peak memory cost component.
    pub memory_cost: f64,
    /// Storage IO cost component.
    pub storage_cost: f64,
    /// Bandwidth cost component.
    pub bandwidth_cost: f64,
    /// Process count cost component.
    pub process_cost: f64,
    /// Base fee.
    pub base_fee: u64,
    /// Total cost (sum of above, rounded up).
    pub total: u64,
}

impl ResourcePricing {
    /// Estimate the cost of executing a task.
    ///
    /// `wall_time_seconds` — estimated wall-clock time.
    /// `storage_mb_hours` — estimated filesystem residency or IO footprint.
    /// `bandwidth_mb` — estimated network transfer.
    pub fn estimate(
        &self,
        wall_time_seconds: f64,
        storage_mb_hours: f64,
        bandwidth_mb: f64,
    ) -> CostEstimate {
        let has_variable_usage =
            wall_time_seconds > 0.0 || storage_mb_hours > 0.0 || bandwidth_mb > 0.0;
        let usage = MeasuredUsage {
            wall_time: Duration::from_secs_f64(wall_time_seconds.max(0.0)),
            fs_read_bytes: (storage_mb_hours.max(0.0) * 1_048_576.0).ceil() as u64,
            bandwidth_bytes: (bandwidth_mb.max(0.0) * 1_048_576.0).ceil() as u64,
            process_count: u64::from(has_variable_usage),
            ..Default::default()
        };
        self.estimate_usage(&usage)
    }

    pub fn estimate_usage(&self, usage: &MeasuredUsage) -> CostEstimate {
        let wall_time_cost = self.wall_time_per_second * duration_secs(usage.wall_time);
        let cpu_seconds = duration_secs(usage.cpu_user) + duration_secs(usage.cpu_kernel);
        let cpu_cost = self.cpu_per_second * cpu_seconds;
        let memory_cost = usage
            .peak_memory_bytes
            .map(|bytes| self.memory_per_mb * bytes_to_mb(bytes))
            .unwrap_or_default();
        let storage_mb = bytes_to_mb(usage.fs_read_bytes.saturating_add(usage.fs_write_bytes));
        let storage_cost = self.storage_per_mb_hour * storage_mb;
        let bandwidth_cost = self.bandwidth_per_mb * bytes_to_mb(usage.bandwidth_bytes);
        let process_cost = self.process_fee * usage.process_count as f64;
        let variable_total =
            wall_time_cost + cpu_cost + memory_cost + storage_cost + bandwidth_cost + process_cost;
        let total = variable_total.ceil() as u64 + self.base_fee;

        CostEstimate {
            wall_time_cost,
            cpu_cost,
            memory_cost,
            storage_cost,
            bandwidth_cost,
            process_cost,
            base_fee: self.base_fee,
            total,
        }
    }

    /// Quick estimate for a short command (1 wall-clock second, one process).
    pub fn estimate_short_command(&self) -> CostEstimate {
        self.estimate_usage(&MeasuredUsage {
            wall_time: Duration::from_secs(1),
            process_count: 1,
            ..Default::default()
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pricing_estimates_positive() {
        let pricing = ResourcePricing::default();
        let est = pricing.estimate(10.0, 100.0, 5.0);
        assert!(est.total > 0);
        assert!(est.wall_time_cost > 0.0);
        assert_eq!(est.cpu_cost, 0.0);
        assert_eq!(est.memory_cost, 0.0);
        assert!(est.storage_cost > 0.0);
        assert_eq!(est.bandwidth_cost, 0.0);
        assert!(est.process_cost > 0.0);
    }

    #[test]
    fn estimate_short_command() {
        let pricing = ResourcePricing::default();
        let est = pricing.estimate_short_command();
        assert_eq!(est.base_fee, 1);
        assert!(est.total >= 1);
    }

    #[test]
    fn zero_usage_minimal_cost() {
        let pricing = ResourcePricing::default();
        let est = pricing.estimate(0.0, 0.0, 0.0);
        assert_eq!(est.total, pricing.base_fee);
    }

    #[test]
    fn measured_usage_drives_measured_resource_price() {
        let pricing = ResourcePricing {
            wall_time_per_second: 0.0,
            cpu_per_second: 2.0,
            memory_per_mb: 1.0,
            storage_per_mb_hour: 0.5,
            bandwidth_per_mb: 3.0,
            base_fee: 2,
            process_fee: 0.25,
        };

        let est = pricing.estimate_usage(&MeasuredUsage {
            cpu_user: Duration::from_secs(1),
            cpu_kernel: Duration::from_secs(1),
            peak_memory_bytes: Some(2 * 1_048_576),
            fs_read_bytes: 3 * 1_048_576,
            fs_write_bytes: 1_048_576,
            bandwidth_bytes: 2 * 1_048_576,
            process_count: 2,
            ..Default::default()
        });

        assert_eq!(est.cpu_cost, 4.0);
        assert_eq!(est.memory_cost, 2.0);
        assert_eq!(est.storage_cost, 2.0);
        assert_eq!(est.bandwidth_cost, 6.0);
        assert_eq!(est.process_cost, 0.5);
        assert_eq!(est.total, 17);
    }
}
