//! Resource pricing — how agents value their compute, storage, and bandwidth.
//!
//! Each agent sets their own prices.  The market discovers equilibrium
//! through offers and negotiations.  This module provides the data model
//! and estimation utilities.

use serde::{Deserialize, Serialize};

fn default_wall_time_per_second() -> f64 {
    0.1
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

    /// Experimental price per CPU-second (not charged until CPU usage is
    /// measured and verified by the runtime).
    #[serde(default)]
    pub cpu_per_second: f64,

    /// Experimental price per MB-hour of storage (not charged until storage
    /// residency is measured and verified).
    #[serde(default)]
    pub storage_per_mb_hour: f64,

    /// Experimental price per MB of network egress (not charged until
    /// bandwidth usage is measured and verified).
    #[serde(default)]
    pub bandwidth_per_mb: f64,

    /// Base fee per task execution (in credit units).
    pub base_fee: u64,
}

impl Default for ResourcePricing {
    fn default() -> Self {
        Self {
            wall_time_per_second: default_wall_time_per_second(),
            cpu_per_second: 0.0,
            storage_per_mb_hour: 0.0,
            bandwidth_per_mb: 0.0,
            base_fee: 1,
        }
    }
}

/// Estimated cost of a task.
#[derive(Clone, Debug)]
pub struct CostEstimate {
    /// Wall-clock time cost component.
    pub wall_time_cost: f64,
    /// Experimental CPU cost component, currently not charged by estimates.
    pub cpu_cost: f64,
    /// Experimental storage cost component, currently not charged by estimates.
    pub storage_cost: f64,
    /// Experimental bandwidth cost component, currently not charged by estimates.
    pub bandwidth_cost: f64,
    /// Base fee.
    pub base_fee: u64,
    /// Total cost (sum of above, rounded up).
    pub total: u64,
}

impl ResourcePricing {
    /// Estimate the cost of executing a task.
    ///
    /// `wall_time_seconds` — estimated wall-clock time.
    /// `_storage_mb_hours` and `_bandwidth_mb` are accepted for API
    /// compatibility but are not charged until the runtime records those
    /// dimensions with verifiable measurements.
    pub fn estimate(
        &self,
        wall_time_seconds: f64,
        _storage_mb_hours: f64,
        _bandwidth_mb: f64,
    ) -> CostEstimate {
        let wall_time_cost = self.wall_time_per_second * wall_time_seconds.max(0.0);
        let cpu_cost = 0.0;
        let storage_cost = 0.0;
        let bandwidth_cost = 0.0;

        let total = wall_time_cost.ceil() as u64 + self.base_fee;

        CostEstimate {
            wall_time_cost,
            cpu_cost,
            storage_cost,
            bandwidth_cost,
            base_fee: self.base_fee,
            total,
        }
    }

    /// Quick estimate for a short command (1 CPU-second, 1 MB storage, 0.1 MB egress).
    pub fn estimate_short_command(&self) -> CostEstimate {
        self.estimate(1.0, 1.0, 0.1)
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
        assert_eq!(est.storage_cost, 0.0);
        assert_eq!(est.bandwidth_cost, 0.0);
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
    fn unmeasured_dimensions_do_not_drive_price() {
        let pricing = ResourcePricing {
            wall_time_per_second: 0.0,
            cpu_per_second: 99.0,
            storage_per_mb_hour: 99.0,
            bandwidth_per_mb: 99.0,
            base_fee: 2,
        };

        let est = pricing.estimate(0.0, 10_000.0, 10_000.0);
        assert_eq!(est.total, 2);
        assert_eq!(est.cpu_cost, 0.0);
        assert_eq!(est.storage_cost, 0.0);
        assert_eq!(est.bandwidth_cost, 0.0);
    }
}
