//! Settlement and authority anchors for economic facts.
//!
//! The system's signed event log and deterministic adoption rules are the
//! primary authority. External chains, Lightning, TEE reports, and future
//! zero-knowledge proofs are optional evidence sources, not prerequisites.

use nexus_core::Did;
use nexus_crypto::verify_did_signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const HASH_HEX_LEN: usize = 64;
const MUTUAL_CREDIT_SIGNATURE_DOMAIN: &str = "nexus:mutual-credit-settlement:v1";
const TEE_ATTESTATION_DOMAIN: &str = "nexus:tee-attestation:v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityKind {
    SovereignSociety,
    LocalSignature,
    CollectiveQuorum,
    Bitcoin,
    Lightning,
    ExternalChain,
    TeeAttestation,
    ZeroKnowledgeProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateCheckpoint {
    pub version: u32,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub social_root_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_root_hex: Option<String>,
    pub policy_id: String,
    pub timestamp: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityAnchor {
    pub kind: AuthorityKind,
    pub commitment_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    #[serde(default)]
    pub attestors: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutualCreditSettlement {
    pub counterparty: Did,
    pub amount: u64,
    pub ledger_tx_id: String,
    pub counterparty_signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalPaymentSettlement {
    pub authority: AuthorityKind,
    pub asset: String,
    pub amount: u64,
    pub payment_id: String,
    pub recipient: String,
    pub confirmations: u32,
    pub min_confirmations: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightningSettlement {
    pub amount_msat: u64,
    pub payment_hash_hex: String,
    pub preimage_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeAttestation {
    pub measurement_hex: String,
    pub report_data_hex: String,
    pub quote_locator: String,
    pub verifier: Did,
    pub verified_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchoredCheckpoint {
    pub checkpoint: StateCheckpoint,
    pub anchor: AuthorityAnchor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "proof")]
pub enum SettlementProof {
    Sovereign,
    MutualCredit(MutualCreditSettlement),
    ExternalPayment(ExternalPaymentSettlement),
    Lightning(LightningSettlement),
    TeeAttestation(TeeAttestation),
    AnchoredCheckpoint(AnchoredCheckpoint),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SettlementError {
    #[error("{field} is required")]
    MissingField { field: &'static str },

    #[error("{field} must be greater than zero")]
    ZeroAmount { field: &'static str },

    #[error("{field} must be 32-byte hex")]
    InvalidHashHex { field: &'static str },

    #[error("payment has {confirmations} confirmations, requires {required}")]
    InsufficientConfirmations { confirmations: u32, required: u32 },

    #[error("lightning preimage does not match payment hash")]
    LightningPreimageMismatch,

    #[error("TEE attestation commitment mismatch")]
    TeeAttestationCommitmentMismatch,

    #[error("anchor commitment does not match checkpoint")]
    AnchorCommitmentMismatch,

    #[error("collective quorum has {attestors} attestors, requires {threshold}")]
    InsufficientQuorum { attestors: usize, threshold: usize },

    #[error("mutual-credit proof amount {proof_amount} does not match settlement amount {settlement_amount}")]
    MutualCreditAmountMismatch {
        proof_amount: u64,
        settlement_amount: u64,
    },

    #[error("mutual-credit counterparty {counterparty} does not match settlement payee {payee}")]
    MutualCreditCounterpartyMismatch { counterparty: Did, payee: Did },

    #[error("mutual-credit counterparty signature verification failed")]
    InvalidCounterpartySignature,

    #[error("failed to encode settlement payload: {0}")]
    Serialization(String),
}

impl StateCheckpoint {
    pub fn validate(&self) -> Result<(), SettlementError> {
        require_non_empty("subject", &self.subject)?;
        require_non_empty("policy_id", &self.policy_id)?;
        validate_optional_hash("social_root_hex", self.social_root_hex.as_deref())?;
        validate_optional_hash("workspace_root_hex", self.workspace_root_hex.as_deref())?;
        validate_optional_hash("ledger_root_hex", self.ledger_root_hex.as_deref())?;
        Ok(())
    }

    pub fn commitment_hex(&self) -> Result<String, SettlementError> {
        self.validate()?;
        let payload = serde_json::to_vec(self)
            .map_err(|err| SettlementError::Serialization(err.to_string()))?;
        Ok(hex::encode(Sha256::digest(payload)))
    }
}

impl AuthorityAnchor {
    pub fn validate(&self) -> Result<(), SettlementError> {
        validate_hash_hex("commitment_hex", &self.commitment_hex)?;
        match self.kind {
            AuthorityKind::CollectiveQuorum => {
                let threshold = self.threshold.unwrap_or(0);
                if threshold == 0 {
                    return Err(SettlementError::MissingField { field: "threshold" });
                }
                if self.attestors.len() < threshold {
                    return Err(SettlementError::InsufficientQuorum {
                        attestors: self.attestors.len(),
                        threshold,
                    });
                }
            }
            AuthorityKind::Bitcoin | AuthorityKind::ExternalChain => {
                require_non_empty("locator", self.locator.as_deref().unwrap_or_default())?;
            }
            AuthorityKind::TeeAttestation => {
                require_non_empty("locator", self.locator.as_deref().unwrap_or_default())?;
                let threshold = self.threshold.unwrap_or(0);
                if threshold == 0 {
                    return Err(SettlementError::MissingField { field: "threshold" });
                }
                if self.attestors.len() < threshold {
                    return Err(SettlementError::InsufficientQuorum {
                        attestors: self.attestors.len(),
                        threshold,
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl SettlementProof {
    pub fn validate(&self) -> Result<(), SettlementError> {
        match self {
            Self::Sovereign => Ok(()),
            Self::MutualCredit(proof) => proof.validate(),
            Self::ExternalPayment(proof) => proof.validate(),
            Self::Lightning(proof) => proof.validate(),
            Self::TeeAttestation(proof) => proof.validate(),
            Self::AnchoredCheckpoint(proof) => proof.validate(),
        }
    }

    pub fn validate_for_settlement(
        &self,
        payer: &Did,
        payee: &Did,
        amount: u64,
    ) -> Result<(), SettlementError> {
        self.validate()?;
        if let Self::MutualCredit(proof) = self {
            proof.verify_counterparty_signature(payer, payee, amount)?;
        }
        Ok(())
    }
}

impl MutualCreditSettlement {
    pub fn validate(&self) -> Result<(), SettlementError> {
        require_positive("amount", self.amount)?;
        require_non_empty("ledger_tx_id", &self.ledger_tx_id)?;
        if self.counterparty_signature.is_empty() {
            return Err(SettlementError::MissingField {
                field: "counterparty_signature",
            });
        }
        Ok(())
    }

    pub fn counterparty_signing_payload(
        ledger_tx_id: &str,
        amount: u64,
        payer: &Did,
        payee: &Did,
    ) -> Result<Vec<u8>, SettlementError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            domain: &'static str,
            ledger_tx_id: &'a str,
            amount: u64,
            payer: &'a Did,
            payee: &'a Did,
        }

        serde_json::to_vec(&Payload {
            domain: MUTUAL_CREDIT_SIGNATURE_DOMAIN,
            ledger_tx_id,
            amount,
            payer,
            payee,
        })
        .map_err(|err| SettlementError::Serialization(err.to_string()))
    }

    pub fn verify_counterparty_signature(
        &self,
        payer: &Did,
        payee: &Did,
        settlement_amount: u64,
    ) -> Result<(), SettlementError> {
        self.validate()?;
        if self.amount != settlement_amount {
            return Err(SettlementError::MutualCreditAmountMismatch {
                proof_amount: self.amount,
                settlement_amount,
            });
        }
        if &self.counterparty != payee {
            return Err(SettlementError::MutualCreditCounterpartyMismatch {
                counterparty: self.counterparty.clone(),
                payee: payee.clone(),
            });
        }

        let payload =
            Self::counterparty_signing_payload(&self.ledger_tx_id, self.amount, payer, payee)?;
        verify_did_signature(payee, &payload, &self.counterparty_signature)
            .map_err(|_| SettlementError::InvalidCounterpartySignature)
    }
}

impl ExternalPaymentSettlement {
    pub fn validate(&self) -> Result<(), SettlementError> {
        require_positive("amount", self.amount)?;
        require_non_empty("asset", &self.asset)?;
        require_non_empty("payment_id", &self.payment_id)?;
        require_non_empty("recipient", &self.recipient)?;
        if self.confirmations < self.min_confirmations {
            return Err(SettlementError::InsufficientConfirmations {
                confirmations: self.confirmations,
                required: self.min_confirmations,
            });
        }
        if matches!(self.authority, AuthorityKind::Bitcoin) {
            validate_hash_hex("payment_id", &self.payment_id)?;
        }
        Ok(())
    }
}

impl LightningSettlement {
    pub fn validate(&self) -> Result<(), SettlementError> {
        require_positive("amount_msat", self.amount_msat)?;
        validate_hash_hex("payment_hash_hex", &self.payment_hash_hex)?;
        validate_hash_hex("preimage_hex", &self.preimage_hex)?;
        let preimage = decode_hash_hex("preimage_hex", &self.preimage_hex)?;
        let expected = hex::encode(Sha256::digest(preimage));
        if expected != self.payment_hash_hex.to_ascii_lowercase() {
            return Err(SettlementError::LightningPreimageMismatch);
        }
        Ok(())
    }
}

impl TeeAttestation {
    pub fn validate(&self) -> Result<(), SettlementError> {
        validate_hash_hex("measurement_hex", &self.measurement_hex)?;
        validate_hash_hex("report_data_hex", &self.report_data_hex)?;
        require_non_empty("quote_locator", &self.quote_locator)?;
        Ok(())
    }

    pub fn commitment_hex(&self) -> Result<String, SettlementError> {
        self.validate()?;
        #[derive(Serialize)]
        struct Payload<'a> {
            domain: &'static str,
            measurement_hex: &'a str,
            report_data_hex: &'a str,
            quote_locator: &'a str,
            verifier: &'a Did,
            verified_at: u64,
        }

        let payload = serde_json::to_vec(&Payload {
            domain: TEE_ATTESTATION_DOMAIN,
            measurement_hex: &self.measurement_hex.to_ascii_lowercase(),
            report_data_hex: &self.report_data_hex.to_ascii_lowercase(),
            quote_locator: &self.quote_locator,
            verifier: &self.verifier,
            verified_at: self.verified_at,
        })
        .map_err(|err| SettlementError::Serialization(err.to_string()))?;
        Ok(hex::encode(Sha256::digest(payload)))
    }

    pub fn authority_anchor(&self) -> Result<AuthorityAnchor, SettlementError> {
        Ok(AuthorityAnchor {
            kind: AuthorityKind::TeeAttestation,
            commitment_hex: self.commitment_hex()?,
            locator: Some(self.quote_locator.clone()),
            attestors: vec![self.verifier.clone()],
            threshold: Some(1),
        })
    }

    pub fn verify_anchor(&self, anchor: &AuthorityAnchor) -> Result<(), SettlementError> {
        self.validate()?;
        anchor.validate()?;
        if anchor.kind != AuthorityKind::TeeAttestation {
            return Err(SettlementError::MissingField {
                field: "tee_attestation_anchor",
            });
        }
        if anchor.commitment_hex.to_ascii_lowercase() != self.commitment_hex()? {
            return Err(SettlementError::TeeAttestationCommitmentMismatch);
        }
        if anchor.locator.as_deref() != Some(self.quote_locator.as_str()) {
            return Err(SettlementError::TeeAttestationCommitmentMismatch);
        }
        if !anchor.attestors.contains(&self.verifier) {
            return Err(SettlementError::TeeAttestationCommitmentMismatch);
        }
        Ok(())
    }
}

impl AnchoredCheckpoint {
    pub fn validate(&self) -> Result<(), SettlementError> {
        self.checkpoint.validate()?;
        self.anchor.validate()?;
        if self.checkpoint.commitment_hex()? != self.anchor.commitment_hex.to_ascii_lowercase() {
            return Err(SettlementError::AnchorCommitmentMismatch);
        }
        Ok(())
    }
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), SettlementError> {
    if value.trim().is_empty() {
        Err(SettlementError::MissingField { field })
    } else {
        Ok(())
    }
}

fn require_positive(field: &'static str, value: u64) -> Result<(), SettlementError> {
    if value == 0 {
        Err(SettlementError::ZeroAmount { field })
    } else {
        Ok(())
    }
}

fn validate_optional_hash(field: &'static str, value: Option<&str>) -> Result<(), SettlementError> {
    if let Some(value) = value {
        validate_hash_hex(field, value)?;
    }
    Ok(())
}

fn validate_hash_hex(field: &'static str, value: &str) -> Result<(), SettlementError> {
    let bytes = decode_hash_hex(field, value)?;
    if bytes.len() == 32 {
        Ok(())
    } else {
        Err(SettlementError::InvalidHashHex { field })
    }
}

fn decode_hash_hex(field: &'static str, value: &str) -> Result<Vec<u8>, SettlementError> {
    if value.len() != HASH_HEX_LEN {
        return Err(SettlementError::InvalidHashHex { field });
    }
    hex::decode(value).map_err(|_| SettlementError::InvalidHashHex { field })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_crypto::NodeIdentity;

    fn hash_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn lightning_settlement_validates_preimage_hash() {
        let preimage = [7u8; 32];
        let proof = LightningSettlement {
            amount_msat: 1_000,
            payment_hash_hex: hex::encode(Sha256::digest(preimage)),
            preimage_hex: hex::encode(preimage),
        };

        proof.validate().unwrap();

        let mut tampered = proof;
        tampered.preimage_hex = hash_hex(8);
        assert_eq!(
            tampered.validate().unwrap_err(),
            SettlementError::LightningPreimageMismatch
        );
    }

    #[test]
    fn anchored_checkpoint_requires_matching_commitment() {
        let checkpoint = StateCheckpoint {
            version: 1,
            subject: "society:local".into(),
            social_root_hex: Some(hash_hex(1)),
            workspace_root_hex: Some(hash_hex(2)),
            ledger_root_hex: Some(hash_hex(3)),
            policy_id: "adopted-facts-v1".into(),
            timestamp: 42,
        };
        let anchor = AuthorityAnchor {
            kind: AuthorityKind::Bitcoin,
            commitment_hex: checkpoint.commitment_hex().unwrap(),
            locator: Some(hash_hex(9)),
            attestors: Vec::new(),
            threshold: None,
        };

        AnchoredCheckpoint {
            checkpoint: checkpoint.clone(),
            anchor,
        }
        .validate()
        .unwrap();

        let wrong_anchor = AuthorityAnchor {
            kind: AuthorityKind::Bitcoin,
            commitment_hex: hash_hex(8),
            locator: Some(hash_hex(9)),
            attestors: Vec::new(),
            threshold: None,
        };
        assert_eq!(
            AnchoredCheckpoint {
                checkpoint,
                anchor: wrong_anchor,
            }
            .validate()
            .unwrap_err(),
            SettlementError::AnchorCommitmentMismatch
        );
    }

    #[test]
    fn collective_anchor_requires_quorum() {
        let anchor = AuthorityAnchor {
            kind: AuthorityKind::CollectiveQuorum,
            commitment_hex: hash_hex(4),
            locator: None,
            attestors: vec![Did::new("did:key:a")],
            threshold: Some(2),
        };

        assert_eq!(
            anchor.validate().unwrap_err(),
            SettlementError::InsufficientQuorum {
                attestors: 1,
                threshold: 2,
            }
        );
    }

    #[test]
    fn tee_attestation_commits_to_quote_payload() {
        let attestation = TeeAttestation {
            measurement_hex: hash_hex(10),
            report_data_hex: hash_hex(11),
            quote_locator: "tee://quote/123".into(),
            verifier: Did::new("did:key:verifier"),
            verified_at: 42,
        };
        let anchor = attestation.authority_anchor().unwrap();

        assert_eq!(anchor.kind, AuthorityKind::TeeAttestation);
        attestation.verify_anchor(&anchor).unwrap();

        let mut wrong = anchor;
        wrong.commitment_hex = hash_hex(12);
        assert_eq!(
            attestation.verify_anchor(&wrong).unwrap_err(),
            SettlementError::TeeAttestationCommitmentMismatch
        );
    }

    #[test]
    fn sovereign_settlement_is_valid_by_signed_event_authority() {
        SettlementProof::Sovereign.validate().unwrap();
    }

    #[test]
    fn bitcoin_payment_requires_confirmed_txid() {
        let proof = ExternalPaymentSettlement {
            authority: AuthorityKind::Bitcoin,
            asset: "BTC".into(),
            amount: 25_000,
            payment_id: hash_hex(6),
            recipient: "bc1qexample".into(),
            confirmations: 2,
            min_confirmations: 3,
        };

        assert_eq!(
            proof.validate().unwrap_err(),
            SettlementError::InsufficientConfirmations {
                confirmations: 2,
                required: 3,
            }
        );
    }

    #[test]
    fn mutual_credit_requires_valid_payee_signature() {
        let payer = NodeIdentity::generate();
        let payee = NodeIdentity::generate();
        let payload = MutualCreditSettlement::counterparty_signing_payload(
            "ledger-tx-1",
            42,
            payer.did(),
            payee.did(),
        )
        .unwrap();
        let proof = MutualCreditSettlement {
            counterparty: payee.did().clone(),
            amount: 42,
            ledger_tx_id: "ledger-tx-1".into(),
            counterparty_signature: payee.sign(&payload).to_bytes().to_vec(),
        };

        SettlementProof::MutualCredit(proof.clone())
            .validate_for_settlement(payer.did(), payee.did(), 42)
            .unwrap();

        let forged_payload = MutualCreditSettlement::counterparty_signing_payload(
            "ledger-tx-1",
            43,
            payer.did(),
            payee.did(),
        )
        .unwrap();
        let forged = MutualCreditSettlement {
            counterparty: payee.did().clone(),
            amount: 42,
            ledger_tx_id: "ledger-tx-1".into(),
            counterparty_signature: payee.sign(&forged_payload).to_bytes().to_vec(),
        };

        assert_eq!(
            SettlementProof::MutualCredit(forged)
                .validate_for_settlement(payer.did(), payee.did(), 42)
                .unwrap_err(),
            SettlementError::InvalidCounterpartySignature
        );

        assert_eq!(
            SettlementProof::MutualCredit(proof)
                .validate_for_settlement(payer.did(), payee.did(), 41)
                .unwrap_err(),
            SettlementError::MutualCreditAmountMismatch {
                proof_amount: 42,
                settlement_amount: 41,
            }
        );
    }
}
