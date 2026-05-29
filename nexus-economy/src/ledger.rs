//! Credit ledger — manages all bilateral credit lines for one agent.

use std::collections::HashMap;

use nexus_core::Did;

use crate::credit::BilateralCredit;

/// A collection of bilateral credit lines managed by one agent.
///
/// All balances are from the perspective of the local agent.
#[derive(Clone, Debug, Default)]
pub struct CreditLedger {
    /// Credit lines keyed by counterparty DID.
    lines: HashMap<Did, BilateralCredit>,
}

impl CreditLedger {
    pub fn new() -> Self {
        Self {
            lines: HashMap::new(),
        }
    }

    /// Get or create a credit line with a counterparty.
    pub fn get_or_create(
        &mut self,
        counterparty: &Did,
        credit_limit: u64,
        debt_limit: u64,
        now: u64,
    ) -> &mut BilateralCredit {
        self.lines.entry(counterparty.clone()).or_insert_with(|| {
            BilateralCredit::new(counterparty.clone(), credit_limit, debt_limit, now)
        })
    }

    /// Get an existing credit line.
    pub fn get(&self, counterparty: &Did) -> Option<&BilateralCredit> {
        self.lines.get(counterparty)
    }

    /// Get a mutable reference.
    pub fn get_mut(&mut self, counterparty: &Did) -> Option<&mut BilateralCredit> {
        self.lines.get_mut(counterparty)
    }

    /// Record a transaction with a counterparty.
    /// Positive amount = they pay me.  Negative = I pay them.
    pub fn record(
        &mut self,
        counterparty: &Did,
        amount: i64,
        now: u64,
    ) -> Result<i64, &'static str> {
        let line = self
            .lines
            .get_mut(counterparty)
            .ok_or("no credit line with this counterparty")?;

        if amount > 0 && !line.can_extend(amount as u64) {
            return Err("exceeds credit limit");
        }
        if amount < 0 && !line.can_borrow(amount.unsigned_abs()) {
            return Err("exceeds debt limit");
        }

        Ok(line.record(amount, now))
    }

    /// Set a credit line's limits.
    pub fn set_limits(&mut self, counterparty: &Did, credit_limit: u64, debt_limit: u64) {
        if let Some(line) = self.lines.get_mut(counterparty) {
            line.credit_limit = credit_limit;
            line.debt_limit = debt_limit;
        }
    }

    /// Iterate over all credit lines.
    pub fn iter(&self) -> impl Iterator<Item = &BilateralCredit> {
        self.lines.values()
    }

    /// Number of credit lines.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Net position across all credit lines.
    /// Positive = overall others owe me.
    pub fn net_position(&self) -> i64 {
        self.lines.values().map(|l| l.balance).sum()
    }

    /// Get edges for the trust graph: (counterparty, available capacity from me to them).
    pub fn outbound_edges(&self) -> Vec<(Did, u64)> {
        self.lines
            .iter()
            .map(|(did, line)| (did.clone(), line.available_credit()))
            .filter(|(_, cap)| *cap > 0)
            .collect()
    }

    /// Get edges for the trust graph: (counterparty, available capacity from them to me).
    pub fn inbound_edges(&self) -> Vec<(Did, u64)> {
        self.lines
            .iter()
            .map(|(did, line)| (did.clone(), line.available_debt()))
            .filter(|(_, cap)| *cap > 0)
            .collect()
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
    fn get_or_create_same_line() {
        let mut ledger = CreditLedger::new();
        let alice = did("alice");
        ledger.get_or_create(&alice, 100, 50, 0);
        ledger.get_or_create(&alice, 200, 100, 1);
        let line = ledger.get(&alice).unwrap();
        // Second call should return existing, not overwrite
        assert_eq!(line.credit_limit, 100);
    }

    #[test]
    fn record_within_limits() {
        let mut ledger = CreditLedger::new();
        let bob = did("bob");
        ledger.get_or_create(&bob, 100, 50, 0);
        assert!(ledger.record(&bob, 30, 1).is_ok());
        assert_eq!(ledger.get(&bob).unwrap().balance, 30);
    }

    #[test]
    fn record_exceeds_credit_limit() {
        let mut ledger = CreditLedger::new();
        let bob = did("bob");
        ledger.get_or_create(&bob, 10, 50, 0);
        assert!(ledger.record(&bob, 30, 1).is_err()); // 30 > 10 credit limit
    }

    #[test]
    fn net_position() {
        let mut ledger = CreditLedger::new();
        let alice = did("alice");
        let bob = did("bob");
        ledger.get_or_create(&alice, 1000, 1000, 0);
        ledger.get_or_create(&bob, 1000, 1000, 0);
        ledger.record(&alice, 100, 1).unwrap(); // They owe me 100
        ledger.record(&bob, -50, 1).unwrap(); // I owe them 50
        assert_eq!(ledger.net_position(), 50);
    }
}
