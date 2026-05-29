//! Reputation scoring — local, non-transferable trust scores.
//!
//! Each agent maintains a subjective reputation score for every
//! peer it has interacted with.  Reputation is NOT globally
//! transferable — it's purely local to prevent Sybil attacks.

use nexus_core::Did;
use serde::{Deserialize, Serialize};

/// Dimensions of reputation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationScore {
    /// Who this score is about.
    pub subject: Did,

    /// Uptime / availability (0.0 - 1.0).
    pub availability: f64,

    /// How often results are correct / verifiable (0.0 - 1.0).
    pub correctness: f64,

    /// Responsiveness / latency (0.0 - 1.0, higher = faster).
    pub timeliness: f64,

    /// Pricing fairness (0.0 - 1.0, higher = fairer).
    pub fairness: f64,

    /// Number of successful interactions.
    pub successes: u64,

    /// Number of failed or disputed interactions.
    pub failures: u64,

    /// When we first interacted (Unix timestamp).
    pub first_seen: u64,

    /// When we last interacted.
    pub last_seen: u64,
}

impl ReputationScore {
    /// Create a neutral score for a new peer.
    pub fn new(subject: Did, now: u64) -> Self {
        Self {
            subject,
            availability: 0.5,
            correctness: 0.5,
            timeliness: 0.5,
            fairness: 0.5,
            successes: 0,
            failures: 0,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Composite score (weighted average).
    pub fn composite(&self) -> f64 {
        let total = self.successes + self.failures;
        let reliability = if total > 0 {
            self.successes as f64 / total as f64
        } else {
            0.5
        };

        self.availability * 0.15
            + self.correctness * 0.40
            + self.timeliness * 0.15
            + self.fairness * 0.15
            + reliability * 0.15
    }

    /// Record a successful interaction.
    pub fn record_success(&mut self, now: u64) {
        self.successes += 1;
        self.last_seen = now;
    }

    /// Record a failed interaction.
    pub fn record_failure(&mut self, now: u64) {
        self.failures += 1;
        self.last_seen = now;
    }

    /// Update availability score with exponential moving average.
    pub fn update_availability(&mut self, observed: f64) {
        self.availability = self.availability * 0.8 + observed * 0.2;
    }

    /// Update correctness score.
    pub fn update_correctness(&mut self, observed: f64) {
        self.correctness = self.correctness * 0.8 + observed * 0.2;
    }

    /// Update timeliness score.
    pub fn update_timeliness(&mut self, observed: f64) {
        self.timeliness = self.timeliness * 0.8 + observed * 0.2;
    }

    /// Update fairness score.
    pub fn update_fairness(&mut self, observed: f64) {
        self.fairness = self.fairness * 0.8 + observed * 0.2;
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
    fn new_score_is_neutral() {
        let score = ReputationScore::new(did("alice"), 0);
        assert!((score.composite() - 0.5).abs() < 0.01);
    }

    #[test]
    fn perfect_score_approaches_one() {
        let mut score = ReputationScore::new(did("bob"), 0);
        score.availability = 1.0;
        score.correctness = 1.0;
        score.timeliness = 1.0;
        score.fairness = 1.0;
        for _ in 0..100 {
            score.record_success(1);
        }
        assert!(score.composite() > 0.95);
    }

    #[test]
    fn ema_smooths_updates() {
        let mut score = ReputationScore::new(did("carol"), 0);
        assert_eq!(score.correctness, 0.5);
        score.update_correctness(1.0);
        assert!((score.correctness - 0.6).abs() < 0.001); // 0.5 * 0.8 + 1.0 * 0.2
        score.update_correctness(1.0);
        assert!((score.correctness - 0.68).abs() < 0.001);
    }
}
