//! Nexus Economy — bilateral credit, trust graph, and resource pricing.
//!
//! Every agent maintains a local ledger of bilateral credit lines
//! with its peers.  Payments are routed through the trust graph
//! using max-flow pathfinding (Edmonds-Karp / Ford-Fulkerson).
//!
//! There is no global token or blockchain — value is tracked
//! locally and settled through chains of trust.

pub mod credit;
pub mod ledger;
pub mod pricing;
pub mod reputation;
pub mod settlement;
pub mod trust;

pub use credit::BilateralCredit;
pub use ledger::CreditLedger;
pub use pricing::{CostEstimate, ResourcePricing};
pub use reputation::ReputationScore;
pub use settlement::{
    AnchoredCheckpoint, AuthorityAnchor, AuthorityKind, ExternalPaymentSettlement,
    LightningSettlement, MutualCreditSettlement, SettlementError, SettlementProof, StateCheckpoint,
    TeeAttestation,
};
pub use trust::{find_payment_paths, PaymentPath, TrustGraph};
