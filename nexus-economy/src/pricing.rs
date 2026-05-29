//! Resource pricing — how agents value their compute, storage, and bandwidth.
//!
//! Each agent sets their own prices.  The market discovers equilibrium
//! through offers and negotiations.  This module provides the data model
//! and estimation utilities.

use serde::{Deserialize, Serialize};

/// Prices for different resource types, set by each agent independently.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourcePricing {
    /// Price per CPU-second (in credit units).
    pub cpu_per_second: f64,

    /// Price per MB-hour of storage (in credit units).
    pub storage_per_mb_hour: f64,

    /// Price per MB of network egress (in credit units).
    pub bandwidth_per_mb: f64,

    /// Base fee per task execution (in credit units).
    pub base_fee: u64,
}

impl Default for ResourcePricing {
    fn default() -> Self {
        Self {
            cpu_per_second: 0.1,
            storage_per_mb_hour: 0.001,
            bandwidth_per_mb: 0.01,
            base_fee: 1,
        }
    }
}

/// Estimated cost of a task.
#[derive(Clone, Debug)]
pub struct CostEstimate {
    /// CPU cost component.
    pub cpu_cost: f64,
    /// Storage cost component.
    pub storage_cost: f64,
    /// Bandwidth cost component.
    pub bandwidth_cost: f64,
    /// Base fee.
    pub base_fee: u64,
    /// Total cost (sum of above, rounded up).
    pub total: u64,
}

impl ResourcePricing {
    /// Estimate the cost of executing a task.
    ///
    /// `cpu_seconds` — estimated CPU time.
    /// `storage_mb_hours` — estimated storage usage.
    /// `bandwidth_mb` — estimated egress.
    pub fn estimate(
        &self,
        cpu_seconds: f64,
        storage_mb_hours: f64,
        bandwidth_mb: f64,
    ) -> CostEstimate {
        let cpu_cost = self.cpu_per_second * cpu_seconds;
        let storage_cost = self.storage_per_mb_hour * storage_mb_hours;
        let bandwidth_cost = self.bandwidth_per_mb * bandwidth_mb;

        let total = (cpu_cost + storage_cost + bandwidth_cost).ceil() as u64 + self.base_fee;

        CostEstimate {
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
        assert!(est.cpu_cost > 0.0);
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
}
