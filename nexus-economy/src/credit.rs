//! Bilateral credit — a single credit line between two agents.
//!
//! Each agent maintains a balance with each counterparty.
//! Positive balance = counterparty owes me.
//! Negative balance = I owe counterparty.

use nexus_core::Did;
use serde::{Deserialize, Serialize};

/// A bilateral credit relationship between two agents.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BilateralCredit {
    /// The counterparty.
    pub counterparty: Did,

    /// Current balance.  Positive = counterparty owes me.
    /// Negative = I owe counterparty.  Zero = settled.
    pub balance: i64,

    /// Maximum credit I extend to this counterparty (positive balance limit).
    /// i.e., I allow them to owe me up to this amount.
    pub credit_limit: u64,

    /// Maximum debt I'm willing to take on from this counterparty (negative balance limit).
    /// i.e., I allow myself to owe them up to this amount.
    pub debt_limit: u64,

    /// Unix timestamp when this relationship was established.
    pub established_at: u64,

    /// Unix timestamp of the last transaction.
    pub last_activity: u64,

    /// Total volume of transactions (absolute value, both directions).
    pub total_volume: u64,
}

impl BilateralCredit {
    /// Create a new bilateral credit line.
    pub fn new(counterparty: Did, credit_limit: u64, debt_limit: u64, now: u64) -> Self {
        Self {
            counterparty,
            balance: 0,
            credit_limit,
            debt_limit,
            established_at: now,
            last_activity: now,
            total_volume: 0,
        }
    }

    /// My net position: positive means they owe me.
    pub fn my_position(&self) -> i64 {
        self.balance
    }

    /// Can I extend `amount` more credit to them?
    pub fn can_extend(&self, amount: u64) -> bool {
        (self.balance as i128 + amount as i128) <= self.credit_limit as i128
    }

    /// Can I take on `amount` more debt from them?
    pub fn can_borrow(&self, amount: u64) -> bool {
        (self.balance as i128 - amount as i128) >= -(self.debt_limit as i128)
    }

    /// Record a transaction: they pay me `amount` (positive) or I pay them (negative).
    /// Returns the new balance.
    pub fn record(&mut self, amount: i64, now: u64) -> i64 {
        self.balance += amount;
        self.last_activity = now;
        self.total_volume += amount.unsigned_abs();
        self.balance
    }

    /// How much available credit remains that I can extend to them.
    pub fn available_credit(&self) -> u64 {
        let remaining = self.credit_limit as i64 - self.balance;
        if remaining < 0 {
            0
        } else {
            remaining as u64
        }
    }

    /// How much more I can borrow from them.
    pub fn available_debt(&self) -> u64 {
        let remaining = self.debt_limit as i64 + self.balance;
        if remaining < 0 {
            0
        } else {
            remaining as u64
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn did(s: &str) -> Did {
        Did::new(format!("did:key:{s}"))
    }

    #[test]
    fn new_credit_line_zero_balance() {
        let alice = did("alice");
        let bc = BilateralCredit::new(alice.clone(), 100, 50, 0);
        assert_eq!(bc.balance, 0);
        assert!(bc.can_extend(100));
        assert!(bc.can_borrow(50));
    }

    #[test]
    fn record_positive_they_pay_me() {
        let alice = did("alice");
        let mut bc = BilateralCredit::new(alice, 100, 50, 0);
        bc.record(30, 1); // They pay me 30
        assert_eq!(bc.balance, 30);
        assert!(bc.can_extend(70)); // 30 + 70 = 100 (at limit)
        assert!(!bc.can_extend(71));
    }

    #[test]
    fn record_negative_i_pay_them() {
        let alice = did("alice");
        let mut bc = BilateralCredit::new(alice, 100, 50, 0);
        bc.record(-40, 1); // I pay them 40
        assert_eq!(bc.balance, -40);
        assert!(bc.can_borrow(10)); // -40 + (-10) = -50 (at debt limit)
        assert!(!bc.can_borrow(11));
    }

    #[test]
    fn total_volume_accumulates() {
        let alice = did("alice");
        let mut bc = BilateralCredit::new(alice, 1000, 1000, 0);
        bc.record(100, 1);
        bc.record(-50, 2);
        bc.record(200, 3);
        assert_eq!(bc.total_volume, 350);
        assert_eq!(bc.balance, 250);
    }

    #[test]
    fn capacity_constraints() {
        let alice = did("alice");
        let bc = BilateralCredit::new(alice, 100, 100, 0);
        assert!(bc.can_extend(100));
        assert!(!bc.can_extend(101));
        assert!(bc.can_borrow(100));
        assert!(!bc.can_borrow(101));
    }
}
