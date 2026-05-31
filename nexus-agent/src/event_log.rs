//! Append-only social event log.
//!
//! The log is the smallest local ledger an agent needs to participate in the
//! society protocol. It verifies event authorship, de-duplicates gossip, and
//! can replay accepted events into a [`Society`](crate::society::Society).

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use nexus_core::Did;
use serde::{Deserialize, Deserializer, Serialize};

use crate::protocol::{EquivocationProof, SocialEvent, SocialEventKind, SocialProtocolError};
use crate::society::{IdentityRecoveryApproval, IdentityRecoveryPolicy, IdentityRotation, Society};

const SOCIAL_EVENT_LOG_COMPACTED_BASE_VERSION: u16 = 1;

/// Accepted clock skew for signed social events.
///
/// Social timestamps are author-provided metadata, not ordering authority, but
/// rejecting implausible future claims prevents an author from pre-dating later
/// local observations by years and then having that timestamp displayed as
/// current fact.
pub const MAX_FUTURE_TIMESTAMP_SKEW_SECS: u64 = 5 * 60;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn identity_recovery_approval_key(approval: &IdentityRecoveryApproval) -> String {
    format!(
        "{}|{}|{}",
        approval.identity, approval.recovered, approval.guardian
    )
}

/// Append-only set of signed social events.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SocialEventLog {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compacted_base: Option<CompactedEventLogBase>,
    events: Vec<SocialEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    observed_at: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending: Vec<SocialEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending_observed_at: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    equivocation_proofs: Vec<EquivocationProof>,
    #[serde(skip)]
    index: HashMap<String, usize>,
    #[serde(skip)]
    pending_index: HashSet<String>,
    #[serde(skip)]
    seq_index: HashMap<(Did, u64), usize>,
    #[serde(skip)]
    heads: HashMap<Did, (u64, String)>,
    #[serde(skip)]
    rotations: HashMap<Did, Did>,
    #[serde(skip)]
    recovery_policies: HashMap<Did, IdentityRecoveryPolicy>,
    #[serde(skip)]
    recovery_approvals: HashMap<String, IdentityRecoveryApproval>,
    #[serde(skip)]
    equivocation_index: HashSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactedEventLogBase {
    version: u16,
    event_count: usize,
    equivocation_proof_count: usize,
    last_observed_at: Option<u64>,
    society_cbor_hex: String,
    heads: Vec<CompactedAuthorHead>,
    rotations: Vec<CompactedIdentityRotation>,
    recovery_policies: Vec<IdentityRecoveryPolicy>,
    recovery_approvals: Vec<IdentityRecoveryApproval>,
    equivocation_proof_keys: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompactedAuthorHead {
    author: Did,
    seq: u64,
    id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompactedIdentityRotation {
    previous: Did,
    next: Did,
}

impl CompactedEventLogBase {
    fn from_log_state(
        log: &SocialEventLog,
        society: &Society,
        event_count: usize,
        equivocation_proof_count: usize,
    ) -> Self {
        let mut heads = log
            .heads
            .iter()
            .map(|(author, (seq, id))| CompactedAuthorHead {
                author: author.clone(),
                seq: *seq,
                id: id.clone(),
            })
            .collect::<Vec<_>>();
        heads.sort_by(|a, b| a.author.to_string().cmp(&b.author.to_string()));

        let mut rotations = log
            .rotations
            .iter()
            .map(|(previous, next)| CompactedIdentityRotation {
                previous: previous.clone(),
                next: next.clone(),
            })
            .collect::<Vec<_>>();
        rotations.sort_by(|a, b| a.previous.to_string().cmp(&b.previous.to_string()));

        let mut recovery_policies = log.recovery_policies.values().cloned().collect::<Vec<_>>();
        recovery_policies.sort_by(|a, b| a.identity.to_string().cmp(&b.identity.to_string()));

        let mut recovery_approvals = log.recovery_approvals.values().cloned().collect::<Vec<_>>();
        recovery_approvals.sort_by_key(identity_recovery_approval_key);

        let mut equivocation_proof_keys =
            log.equivocation_index.iter().cloned().collect::<Vec<_>>();
        equivocation_proof_keys.sort();

        Self {
            version: SOCIAL_EVENT_LOG_COMPACTED_BASE_VERSION,
            event_count,
            equivocation_proof_count,
            last_observed_at: log.observed_at.iter().copied().max(),
            society_cbor_hex: society_cbor_hex(society),
            heads,
            rotations,
            recovery_policies,
            recovery_approvals,
            equivocation_proof_keys,
        }
    }

    fn normalize(&mut self) -> Result<(), SocialProtocolError> {
        if self.version != SOCIAL_EVENT_LOG_COMPACTED_BASE_VERSION {
            return Err(SocialProtocolError::InvalidCompactedLog {
                reason: format!("unsupported compacted base version {}", self.version),
            });
        }
        if self.society_cbor_hex.is_empty() || self.society().is_none() {
            return Err(SocialProtocolError::InvalidCompactedLog {
                reason: "compacted base society snapshot is invalid".into(),
            });
        }

        self.heads
            .sort_by(|a, b| a.author.to_string().cmp(&b.author.to_string()));
        self.heads.dedup_by(|a, b| a.author == b.author);
        self.rotations
            .sort_by(|a, b| a.previous.to_string().cmp(&b.previous.to_string()));
        self.rotations.dedup_by(|a, b| a.previous == b.previous);
        self.recovery_policies
            .sort_by(|a, b| a.identity.to_string().cmp(&b.identity.to_string()));
        self.recovery_policies
            .dedup_by(|a, b| a.identity == b.identity);
        self.recovery_approvals
            .sort_by_key(identity_recovery_approval_key);
        self.recovery_approvals.dedup_by(|a, b| {
            identity_recovery_approval_key(a) == identity_recovery_approval_key(b)
        });
        self.equivocation_proof_keys.sort();
        self.equivocation_proof_keys.dedup();
        Ok(())
    }

    fn society(&self) -> Option<Society> {
        let bytes = hex::decode(&self.society_cbor_hex).ok()?;
        ciborium::from_reader::<Society, _>(bytes.as_slice()).ok()
    }
}

impl<'de> Deserialize<'de> for SocialEventLog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StoredLog {
            #[serde(default)]
            compacted_base: Option<CompactedEventLogBase>,
            events: Vec<SocialEvent>,
            #[serde(default)]
            observed_at: Vec<u64>,
            #[serde(default)]
            pending: Vec<SocialEvent>,
            #[serde(default)]
            pending_observed_at: Vec<u64>,
            #[serde(default)]
            equivocation_proofs: Vec<EquivocationProof>,
        }

        let stored = StoredLog::deserialize(deserializer)?;
        Self::from_parts(
            stored.compacted_base,
            stored
                .events
                .into_iter()
                .zip(fill_observed_times(stored.observed_at)),
            stored
                .pending
                .into_iter()
                .zip(fill_observed_times(stored.pending_observed_at)),
            stored.equivocation_proofs,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl SocialEventLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a log from events that were already serialized or stored.
    ///
    /// Every event is verified and duplicate ids must describe the same event.
    pub fn from_events(
        events: impl IntoIterator<Item = SocialEvent>,
    ) -> Result<Self, SocialProtocolError> {
        let now = unix_now();
        Self::from_parts(
            None,
            events.into_iter().map(|event| (event, now)),
            std::iter::empty(),
            std::iter::empty(),
        )
    }

    fn from_parts(
        compacted_base: Option<CompactedEventLogBase>,
        events: impl IntoIterator<Item = (SocialEvent, u64)>,
        pending: impl IntoIterator<Item = (SocialEvent, u64)>,
        equivocation_proofs: impl IntoIterator<Item = EquivocationProof>,
    ) -> Result<Self, SocialProtocolError> {
        let mut log = Self::new();
        log.install_compacted_base(compacted_base)?;
        for (event, observed_at) in events {
            log.append_observed(event, observed_at)?;
        }
        for (event, observed_at) in pending {
            log.append_observed(event, observed_at)?;
        }
        for proof in equivocation_proofs {
            log.record_equivocation(proof)?;
        }
        Ok(log)
    }

    pub fn len(&self) -> usize {
        self.compacted_event_count() + self.events.len()
    }

    pub fn retained_len(&self) -> usize {
        self.events.len()
    }

    pub fn compacted_event_count(&self) -> usize {
        self.compacted_base
            .as_ref()
            .map(|base| base.event_count)
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn events(&self) -> &[SocialEvent] {
        &self.events
    }

    pub fn observed_times(&self) -> &[u64] {
        &self.observed_at
    }

    pub fn pending_events(&self) -> &[SocialEvent] {
        &self.pending
    }

    pub fn equivocation_proofs(&self) -> &[EquivocationProof] {
        &self.equivocation_proofs
    }

    pub fn compacted_base(&self) -> Option<&CompactedEventLogBase> {
        self.compacted_base.as_ref()
    }

    pub fn compact_retaining_recent(
        &mut self,
        retain_events: usize,
    ) -> Result<bool, SocialProtocolError> {
        if self.events.len() <= retain_events {
            return Ok(false);
        }
        if !self.pending.is_empty() {
            return Err(SocialProtocolError::InvalidCompactedLog {
                reason: "cannot compact while author-chain gaps are pending".into(),
            });
        }

        let retained_start = self.events.len().saturating_sub(retain_events);
        let prefix_events = self.events[..retained_start].to_vec();
        let prefix_observed_at = self.observed_at[..retained_start].to_vec();
        let retained_events = self.events[retained_start..].to_vec();
        let retained_observed_at = self.observed_at[retained_start..].to_vec();
        let base_event_count = self.compacted_event_count().saturating_add(retained_start);
        let base_proof_count = self
            .compacted_base
            .as_ref()
            .map(|base| base.equivocation_proof_count)
            .unwrap_or(0)
            .saturating_add(self.equivocation_proofs.len());
        let mut base_log = Self::new();
        base_log.install_compacted_base(self.compacted_base.clone())?;
        for (event, observed_at) in prefix_events.into_iter().zip(prefix_observed_at) {
            base_log.append_observed(event, observed_at)?;
        }
        for proof in self.equivocation_proofs.clone() {
            base_log.record_equivocation(proof)?;
        }
        let society = base_log.to_society();
        let compacted_base = CompactedEventLogBase::from_log_state(
            &base_log,
            &society,
            base_event_count,
            base_proof_count,
        );

        self.compacted_base = Some(compacted_base);
        self.events = retained_events;
        self.observed_at = retained_observed_at;
        self.equivocation_proofs.clear();
        self.rebuild_index()?;
        Ok(true)
    }

    pub fn contains(&self, event_id: &str) -> bool {
        self.index.contains_key(event_id) || self.pending_index.contains(event_id)
    }

    pub fn next_position(&self, author: &Did) -> (u64, Option<String>) {
        self.heads
            .get(author)
            .map(|(seq, id)| (seq.saturating_add(1), Some(id.clone())))
            .unwrap_or((0, None))
    }

    /// Append a signed event. Returns `true` when the event is newly inserted.
    pub fn append(&mut self, event: SocialEvent) -> Result<bool, SocialProtocolError> {
        self.append_observed(event, unix_now())
    }

    /// Append a signed event with the local observation timestamp.
    ///
    /// This is primarily useful for deterministic tests and persistence
    /// rebuilds. Normal callers should use [`Self::append`].
    pub fn append_observed(
        &mut self,
        event: SocialEvent,
        observed_at: u64,
    ) -> Result<bool, SocialProtocolError> {
        event.validate()?;
        self.validate_observed_timestamp(&event, observed_at)?;

        if let Some(existing) = self.index.get(&event.id) {
            let existing_payload = self.events[*existing].signing_payload()?;
            let incoming_payload = event.signing_payload()?;
            if existing_payload == incoming_payload
                && self.events[*existing].signature == event.signature
            {
                return Ok(false);
            }

            return Err(SocialProtocolError::DuplicateEventConflict { event_id: event.id });
        }
        if self.pending_index.contains(&event.id) {
            return Ok(false);
        }
        if let Some(existing) = self.seq_index.get(&(event.author.clone(), event.seq)) {
            let proof = EquivocationProof::new(self.events[*existing].clone(), event)?;
            return self.record_equivocation(proof);
        }
        if let Some(pending) = self
            .pending
            .iter()
            .find(|pending| pending.author == event.author && pending.seq == event.seq)
            .cloned()
        {
            let proof = EquivocationProof::new(pending, event)?;
            return self.record_equivocation(proof);
        }

        self.validate_identity_rotation_authority(&event)?;

        if self.can_accept(&event)? {
            let author = event.author.clone();
            self.accept_event(event, observed_at)?;
            self.drain_pending_for(&author)?;
        } else {
            self.pending_index.insert(event.id.clone());
            self.pending_observed_at.push(observed_at);
            self.pending.push(event);
        }
        Ok(true)
    }

    /// Merge another node's events using the same verification and de-dup rules.
    pub fn merge(
        &mut self,
        events: impl IntoIterator<Item = SocialEvent>,
    ) -> Result<usize, SocialProtocolError> {
        let mut inserted = 0;
        for event in events {
            if self.append(event)? {
                inserted += 1;
            }
        }
        Ok(inserted)
    }

    fn can_accept(&self, event: &SocialEvent) -> Result<bool, SocialProtocolError> {
        match self.heads.get(&event.author) {
            None => {
                if event.seq == 0 {
                    if event.prev.is_none() {
                        Ok(true)
                    } else {
                        Err(SocialProtocolError::InvalidChainGenesis {
                            author: event.author.clone(),
                        })
                    }
                } else {
                    Ok(false)
                }
            }
            Some((head_seq, head_id)) => {
                if event.seq == head_seq.saturating_add(1)
                    && event.prev.as_deref() == Some(head_id.as_str())
                {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn validate_observed_timestamp(
        &self,
        event: &SocialEvent,
        observed_at: u64,
    ) -> Result<(), SocialProtocolError> {
        let latest_allowed = observed_at.saturating_add(MAX_FUTURE_TIMESTAMP_SKEW_SECS);
        if event.timestamp <= latest_allowed {
            Ok(())
        } else {
            Err(SocialProtocolError::EventTimestampTooFarAhead {
                author: event.author.clone(),
                timestamp: event.timestamp,
                observed_at,
                max_future_skew_secs: MAX_FUTURE_TIMESTAMP_SKEW_SECS,
            })
        }
    }

    fn accept_event(
        &mut self,
        event: SocialEvent,
        observed_at: u64,
    ) -> Result<(), SocialProtocolError> {
        let index = self.events.len();
        self.index.insert(event.id.clone(), index);
        self.seq_index
            .insert((event.author.clone(), event.seq), index);
        self.heads
            .insert(event.author.clone(), (event.seq, event.id.clone()));
        self.record_identity_rotation(&event);
        self.record_identity_recovery_policy(&event);
        self.record_identity_recovery_approval(&event);
        self.record_pending_equivocations(&event)?;
        self.observed_at.push(observed_at);
        self.events.push(event);
        Ok(())
    }

    fn drain_pending_for(&mut self, author: &Did) -> Result<(), SocialProtocolError> {
        loop {
            let Some(position) = self.pending.iter().position(|event| {
                &event.author == author && self.can_accept(event).unwrap_or(false)
            }) else {
                break;
            };

            let event = self.pending.remove(position);
            let observed_at = self.pending_observed_at.remove(position);
            self.pending_index.remove(&event.id);
            self.validate_identity_rotation_authority(&event)?;
            self.accept_event(event, observed_at)?;
        }
        Ok(())
    }

    fn record_pending_equivocations(
        &mut self,
        accepted: &SocialEvent,
    ) -> Result<(), SocialProtocolError> {
        let mut position = 0;
        while position < self.pending.len() {
            let pending = &self.pending[position];
            if pending.author == accepted.author && pending.seq == accepted.seq {
                let pending = self.pending.remove(position);
                self.pending_observed_at.remove(position);
                self.pending_index.remove(&pending.id);
                if pending.id != accepted.id {
                    self.record_equivocation(EquivocationProof::new(accepted.clone(), pending)?)?;
                }
            } else {
                position += 1;
            }
        }
        Ok(())
    }

    fn record_equivocation(
        &mut self,
        proof: EquivocationProof,
    ) -> Result<bool, SocialProtocolError> {
        proof.verify()?;
        let key = proof.evidence_key();
        if !self.equivocation_index.insert(key) {
            return Ok(false);
        }
        self.equivocation_proofs.push(proof);
        Ok(true)
    }

    fn install_compacted_base(
        &mut self,
        compacted_base: Option<CompactedEventLogBase>,
    ) -> Result<(), SocialProtocolError> {
        let Some(mut base) = compacted_base else {
            return Ok(());
        };
        base.normalize()?;
        for head in &base.heads {
            self.heads
                .insert(head.author.clone(), (head.seq, head.id.clone()));
        }
        for rotation in &base.rotations {
            self.rotations
                .insert(rotation.previous.clone(), rotation.next.clone());
        }
        for policy in &base.recovery_policies {
            self.recovery_policies
                .insert(policy.identity.clone(), policy.clone());
        }
        for approval in &base.recovery_approvals {
            self.recovery_approvals
                .insert(identity_recovery_approval_key(approval), approval.clone());
        }
        for key in &base.equivocation_proof_keys {
            self.equivocation_index.insert(key.clone());
        }
        self.compacted_base = Some(base);
        Ok(())
    }

    /// Replay events in deterministic causal order into a society graph.
    ///
    /// Each author chain is ordered by `seq`/`prev`; author-provided
    /// timestamps are fact metadata and never decide replay order. Cross-author
    /// ties use the content hash id and DID so independently merged logs
    /// converge without trusting one author's clock.
    pub fn replay_into(&self, society: &mut Society) {
        if let Some(base) = &self.compacted_base {
            if let Some(base_society) = base.society() {
                *society = base_society;
            }
        }
        self.replay_from(society, 0, 0);
    }

    /// Replay a suffix of accepted events and equivocation proofs.
    ///
    /// Callers must only use a suffix when all newly appended events sort
    /// after the checkpointed replay prefix; otherwise use [`Self::replay_into`]
    /// for a full deterministic replay.
    pub fn replay_from(&self, society: &mut Society, event_start: usize, proof_start: usize) {
        let mut events: Vec<&SocialEvent> = self.events.iter().skip(event_start).collect();
        events.sort_by(|a, b| event_replay_key(a).cmp(&event_replay_key(b)));

        for event in events {
            society.apply_event(event);
        }
        for proof in self.equivocation_proofs.iter().skip(proof_start) {
            society.record_equivocation_proof(proof.clone());
        }
    }

    pub fn suffix_replay_is_ordered(&self, event_start: usize) -> bool {
        if event_start == 0 || event_start >= self.events.len() {
            return true;
        }
        let max_prefix_key = self.events[..event_start]
            .iter()
            .map(event_replay_key)
            .max()
            .expect("non-empty prefix");
        self.events[event_start..]
            .iter()
            .map(event_replay_key)
            .all(|key| key >= max_prefix_key)
    }

    /// Build a fresh society graph from this log.
    pub fn to_society(&self) -> Society {
        let mut society = Society::new();
        self.replay_into(&mut society);
        society
    }

    /// Rebuild the transient index after deserialization.
    pub fn rebuild_index(&mut self) -> Result<(), SocialProtocolError> {
        let compacted_base = self.compacted_base.take();
        self.index.clear();
        self.pending_index.clear();
        self.seq_index.clear();
        self.heads.clear();
        self.rotations.clear();
        self.recovery_policies.clear();
        self.recovery_approvals.clear();
        self.equivocation_index.clear();

        let events = std::mem::take(&mut self.events)
            .into_iter()
            .zip(fill_observed_times(std::mem::take(&mut self.observed_at)));
        let pending = std::mem::take(&mut self.pending)
            .into_iter()
            .zip(fill_observed_times(std::mem::take(
                &mut self.pending_observed_at,
            )));
        let proofs = std::mem::take(&mut self.equivocation_proofs);
        *self = Self::from_parts(compacted_base, events, pending, proofs)?;
        Ok(())
    }

    fn validate_identity_rotation_authority(
        &self,
        event: &SocialEvent,
    ) -> Result<(), SocialProtocolError> {
        if let Some(successor) = self.rotations.get(&event.author) {
            return Err(SocialProtocolError::IdentityRotated {
                author: event.author.clone(),
                successor: successor.clone(),
            });
        }
        Ok(())
    }

    fn record_identity_rotation(&mut self, event: &SocialEvent) {
        if let SocialEventKind::IdentityRotated { rotation } = &event.kind {
            self.rotations
                .insert(rotation.previous.clone(), rotation.next.clone());
        }
    }

    fn record_identity_recovery_policy(&mut self, event: &SocialEvent) {
        if let SocialEventKind::IdentityRecoveryPolicy { policy } = &event.kind {
            let mut policy = policy.clone();
            policy.guardians.sort_by_key(|did| did.to_string());
            policy.guardians.dedup();
            if policy.guardians.is_empty()
                || policy.threshold == 0
                || policy.threshold > policy.guardians.len()
            {
                return;
            }
            self.recovery_policies
                .entry(policy.identity.clone())
                .and_modify(|existing| {
                    if policy.updated_at >= existing.updated_at {
                        *existing = policy.clone();
                    }
                })
                .or_insert(policy);
            if let Some(rotation) = self.identity_recovery_rotation(&event.author) {
                self.rotations
                    .insert(rotation.previous.clone(), rotation.next.clone());
            }
        }
    }

    fn record_identity_recovery_approval(&mut self, event: &SocialEvent) {
        if let SocialEventKind::IdentityRecoveryApproved { approval } = &event.kind {
            if approval.identity == approval.recovered {
                return;
            }
            let key = identity_recovery_approval_key(approval);
            self.recovery_approvals
                .entry(key)
                .and_modify(|existing| {
                    if approval.approved_at >= existing.approved_at {
                        *existing = approval.clone();
                    }
                })
                .or_insert(approval.clone());
            if let Some(rotation) = self.identity_recovery_rotation(&approval.identity) {
                self.rotations
                    .insert(rotation.previous.clone(), rotation.next.clone());
            }
        }
    }

    fn identity_recovery_policy(&self, did: &Did) -> Option<&IdentityRecoveryPolicy> {
        self.recovery_policies.get(did)
    }

    fn identity_recovery_approvals(&self, did: &Did) -> Vec<&IdentityRecoveryApproval> {
        self.recovery_approvals
            .values()
            .filter(|approval| approval.identity == *did)
            .collect()
    }

    fn identity_recovery_rotation(&self, did: &Did) -> Option<IdentityRotation> {
        let policy = self.identity_recovery_policy(did)?;
        let mut by_recovered: HashMap<Did, Vec<&IdentityRecoveryApproval>> = HashMap::new();
        for approval in self.identity_recovery_approvals(did) {
            if !policy.guardians.contains(&approval.guardian) {
                continue;
            }
            by_recovered
                .entry(approval.recovered.clone())
                .or_default()
                .push(approval);
        }

        by_recovered
            .into_iter()
            .filter(|(_recovered, approvals)| approvals.len() >= policy.threshold)
            .filter_map(|(recovered, approvals)| {
                let approved_at = approvals
                    .iter()
                    .map(|approval| approval.approved_at)
                    .max()?;
                let reason = approvals
                    .iter()
                    .filter_map(|approval| approval.reason.clone())
                    .next();
                Some(IdentityRotation {
                    previous: did.clone(),
                    next: recovered,
                    reason,
                    rotated_at: approved_at,
                })
            })
            .min_by(|a, b| {
                a.rotated_at
                    .cmp(&b.rotated_at)
                    .then_with(|| a.next.to_string().cmp(&b.next.to_string()))
            })
    }
}

fn fill_observed_times(observed_at: Vec<u64>) -> impl Iterator<Item = u64> {
    let fallback = unix_now();
    observed_at.into_iter().chain(std::iter::repeat(fallback))
}

fn event_replay_key(event: &SocialEvent) -> (u64, &str, String) {
    (event.seq, event.id.as_str(), event.author.to_string())
}

fn society_cbor_hex(society: &Society) -> String {
    let mut bytes = Vec::new();
    if ciborium::into_writer(society, &mut bytes).is_err() {
        return String::new();
    }
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::WorkspaceId;
    use nexus_crypto::NodeIdentity;

    use crate::protocol::{SocialEventKind, SocialProtocolError};
    use crate::society::{
        IdentityRecoveryApproval, IdentityRecoveryPolicy, IdentityRotation, RelationKind,
    };

    fn signed_relation(
        identity: &NodeIdentity,
        peer: &NodeIdentity,
        timestamp: u64,
    ) -> SocialEvent {
        SocialEvent::new(
            identity.did().clone(),
            timestamp,
            SocialEventKind::RelationDeclared {
                peer: peer.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("shared society log".into()),
            },
        )
        .sign(identity)
        .unwrap()
    }

    #[test]
    fn log_appends_signed_events_and_deduplicates_gossip() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let event = signed_relation(&alice, &bob, 1);

        let mut log = SocialEventLog::new();
        assert!(log.append(event.clone()).unwrap());
        assert!(!log.append(event.clone()).unwrap());
        assert_eq!(log.len(), 1);
        assert!(log.contains(&event.id));
    }

    #[test]
    fn log_rejects_unsigned_events() {
        let alice = NodeIdentity::generate();
        let event = SocialEvent::new(
            alice.did().clone(),
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([9; 32]),
            },
        );

        let err = SocialEventLog::new().append(event).unwrap_err();
        assert!(matches!(err, SocialProtocolError::MissingSignature));
    }

    #[test]
    fn log_rejects_duplicate_id_with_different_payload() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = signed_relation(&alice, &bob, 1);
        let mut second = signed_relation(&alice, &bob, 2);
        second.id = first.id.clone();

        let mut log = SocialEventLog::new();
        assert!(log.append(first.clone()).unwrap());
        let err = log.append(second).unwrap_err();
        assert!(matches!(err, SocialProtocolError::EventIdMismatch { .. }));
    }

    #[test]
    fn content_hash_id_changes_when_payload_changes() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = signed_relation(&alice, &bob, 1);
        let second = signed_relation(&alice, &bob, 2);

        assert_ne!(first.id, second.id);
        assert_eq!(first.id, first.content_id().unwrap());
        assert_eq!(second.id, second.content_id().unwrap());
    }

    #[test]
    fn out_of_order_author_chain_drains_when_predecessor_arrives() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = SocialEvent::new_chained(
            alice.did().clone(),
            0,
            None,
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([7; 32]),
            },
        )
        .sign(&alice)
        .unwrap();
        let second = SocialEvent::new_chained(
            alice.did().clone(),
            1,
            Some(first.id.clone()),
            2,
            SocialEventKind::RelationDeclared {
                peer: bob.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("arrived before predecessor".into()),
            },
        )
        .sign(&alice)
        .unwrap();

        let mut log = SocialEventLog::new();
        assert!(log.append(second.clone()).unwrap());
        assert_eq!(log.len(), 0);
        assert_eq!(log.pending_events().len(), 1);
        assert!(log.contains(&second.id));

        assert!(log.append(first).unwrap());
        assert_eq!(log.len(), 2);
        assert!(log.pending_events().is_empty());

        let society = log.to_society();
        assert_eq!(
            society.edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Collaborator
        );
    }

    #[test]
    fn identity_rotation_requires_successor_for_future_events() {
        let previous = NodeIdentity::generate();
        let next = NodeIdentity::generate();
        let peer = NodeIdentity::generate();
        let rotation = SocialEvent::new_chained(
            previous.did().clone(),
            0,
            None,
            1,
            SocialEventKind::IdentityRotated {
                rotation: IdentityRotation {
                    previous: previous.did().clone(),
                    next: next.did().clone(),
                    reason: Some("routine rotation".into()),
                    rotated_at: 1,
                },
            },
        )
        .sign(&previous)
        .unwrap();
        let old_key_event = SocialEvent::new_chained(
            previous.did().clone(),
            1,
            Some(rotation.id.clone()),
            2,
            SocialEventKind::RelationDeclared {
                peer: peer.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("old key should no longer act".into()),
            },
        )
        .sign(&previous)
        .unwrap();
        let successor_event = SocialEvent::new(
            next.did().clone(),
            2,
            SocialEventKind::RelationDeclared {
                peer: peer.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("successor key now acts".into()),
            },
        )
        .sign(&next)
        .unwrap();

        let mut log = SocialEventLog::new();
        assert!(log.append(rotation.clone()).unwrap());
        assert_eq!(
            log.to_society().active_identity(previous.did()),
            next.did().clone()
        );
        let err = log.append(old_key_event).unwrap_err();
        assert!(matches!(
            err,
            SocialProtocolError::IdentityRotated { author, successor }
                if author == *previous.did() && successor == *next.did()
        ));
        assert!(log.append(successor_event).unwrap());
        assert!(!log.append(rotation).unwrap());
    }

    #[test]
    fn identity_recovery_threshold_requires_successor_for_future_events() {
        let identity = NodeIdentity::generate();
        let guardian_a = NodeIdentity::generate();
        let guardian_b = NodeIdentity::generate();
        let recovered = NodeIdentity::generate();
        let peer = NodeIdentity::generate();

        let policy = SocialEvent::new(
            identity.did().clone(),
            1,
            SocialEventKind::IdentityRecoveryPolicy {
                policy: IdentityRecoveryPolicy {
                    identity: identity.did().clone(),
                    guardians: vec![guardian_a.did().clone(), guardian_b.did().clone()],
                    threshold: 2,
                    updated_at: 1,
                },
            },
        )
        .sign(&identity)
        .unwrap();
        let approval_a = SocialEvent::new(
            guardian_a.did().clone(),
            2,
            SocialEventKind::IdentityRecoveryApproved {
                approval: IdentityRecoveryApproval {
                    identity: identity.did().clone(),
                    guardian: guardian_a.did().clone(),
                    recovered: recovered.did().clone(),
                    reason: Some("lost old key".into()),
                    approved_at: 2,
                },
            },
        )
        .sign(&guardian_a)
        .unwrap();
        let approval_b = SocialEvent::new(
            guardian_b.did().clone(),
            3,
            SocialEventKind::IdentityRecoveryApproved {
                approval: IdentityRecoveryApproval {
                    identity: identity.did().clone(),
                    guardian: guardian_b.did().clone(),
                    recovered: recovered.did().clone(),
                    reason: Some("second guardian".into()),
                    approved_at: 3,
                },
            },
        )
        .sign(&guardian_b)
        .unwrap();

        let mut log = SocialEventLog::new();
        assert!(log.append(policy.clone()).unwrap());
        assert!(log.append(approval_a).unwrap());
        assert_eq!(
            log.to_society().active_identity(identity.did()),
            *identity.did()
        );
        assert!(log.append(approval_b).unwrap());
        assert_eq!(
            log.to_society().active_identity(identity.did()),
            recovered.did().clone()
        );

        let old_key_event = SocialEvent::new_chained(
            identity.did().clone(),
            1,
            Some(policy.id.clone()),
            4,
            SocialEventKind::RelationDeclared {
                peer: peer.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("old key should no longer act".into()),
            },
        )
        .sign(&identity)
        .unwrap();
        assert!(matches!(
            log.append(old_key_event).unwrap_err(),
            SocialProtocolError::IdentityRotated { author, successor }
                if author == *identity.did() && successor == *recovered.did()
        ));

        let recovered_event = SocialEvent::new(
            recovered.did().clone(),
            4,
            SocialEventKind::RelationDeclared {
                peer: peer.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("recovered key now acts".into()),
            },
        )
        .sign(&recovered)
        .unwrap();
        assert!(log.append(recovered_event).unwrap());
    }

    #[test]
    fn log_rejects_events_too_far_ahead_of_observation_time() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let observed_at = 1_700_000_000;
        let event = signed_relation(
            &alice,
            &bob,
            observed_at + MAX_FUTURE_TIMESTAMP_SKEW_SECS + 1,
        );

        let err = SocialEventLog::new()
            .append_observed(event, observed_at)
            .unwrap_err();
        assert!(matches!(
            err,
            SocialProtocolError::EventTimestampTooFarAhead { .. }
        ));
    }

    #[test]
    fn event_observation_time_survives_pending_drain_and_rebuild() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = SocialEvent::new_chained(
            alice.did().clone(),
            0,
            None,
            100,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([17; 32]),
            },
        )
        .sign(&alice)
        .unwrap();
        let second = SocialEvent::new_chained(
            alice.did().clone(),
            1,
            Some(first.id.clone()),
            90,
            SocialEventKind::RelationDeclared {
                peer: bob.did().clone(),
                relation: RelationKind::Collaborator,
                note: None,
            },
        )
        .sign(&alice)
        .unwrap();

        let mut log = SocialEventLog::new();
        assert!(log.append_observed(second, 200).unwrap());
        assert!(log.append_observed(first, 150).unwrap());

        assert_eq!(log.observed_times(), &[150, 200]);

        let json = serde_json::to_vec(&log).unwrap();
        let decoded: SocialEventLog = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.observed_times(), &[150, 200]);
    }

    #[test]
    fn replay_uses_author_sequence_not_self_reported_timestamp() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = SocialEvent::new_chained(
            alice.did().clone(),
            0,
            None,
            1_000,
            SocialEventKind::RelationDeclared {
                peer: bob.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("first in Alice's chain".into()),
            },
        )
        .sign(&alice)
        .unwrap();
        let second = SocialEvent::new_chained(
            alice.did().clone(),
            1,
            Some(first.id.clone()),
            10,
            SocialEventKind::RelationDeclared {
                peer: bob.did().clone(),
                relation: RelationKind::Blocked,
                note: Some("second in Alice's chain despite older timestamp".into()),
            },
        )
        .sign(&alice)
        .unwrap();

        let mut log = SocialEventLog::new();
        assert!(log.append_observed(second, 1_100).unwrap());
        assert!(log.append_observed(first, 1_100).unwrap());

        let society = log.to_society();
        let edge = society.edge(alice.did(), bob.did()).unwrap();
        assert_eq!(edge.kind, RelationKind::Blocked);
        assert_eq!(edge.updated_at, 10);
    }

    #[test]
    fn same_author_sequence_conflict_records_equivocation_proof() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = signed_relation(&alice, &bob, 1);
        let fork = SocialEvent::new_chained(
            alice.did().clone(),
            0,
            None,
            2,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([8; 32]),
            },
        )
        .sign(&alice)
        .unwrap();

        let mut log = SocialEventLog::new();
        assert!(log.append(first.clone()).unwrap());
        assert!(log.append(fork.clone()).unwrap());

        assert_eq!(log.len(), 1);
        assert_eq!(log.equivocation_proofs().len(), 1);
        let proof = &log.equivocation_proofs()[0];
        proof.verify().unwrap();
        assert_eq!(proof.author, *alice.did());
        assert_eq!(proof.seq, 0);
        assert_ne!(proof.event_a.id, proof.event_b.id);

        let society = log.to_society();
        assert!(society.is_equivocating(alice.did()));
        assert_eq!(society.agent_equivocations(alice.did()).len(), 1);
    }

    #[test]
    fn tampering_with_signed_content_invalidates_id_and_signature() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let mut first = signed_relation(&alice, &bob, 1);
        first.timestamp = 99;
        assert!(matches!(
            first.verify_signature().unwrap_err(),
            SocialProtocolError::EventIdMismatch { .. }
        ));
    }

    #[test]
    fn replay_builds_society_from_deterministic_event_order() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let relation = signed_relation(&alice, &bob, 5);
        let joined = SocialEvent::new(
            bob.did().clone(),
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([11; 32]),
            },
        )
        .sign(&bob)
        .unwrap();

        let mut log = SocialEventLog::new();
        assert_eq!(log.merge([relation, joined]).unwrap(), 2);

        let mut society = Society::new();
        log.replay_into(&mut society);
        assert!(society.has_agent(alice.did()));
        assert!(society.has_agent(bob.did()));
        assert_eq!(
            society.edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Collaborator
        );
    }

    #[test]
    fn deserialized_log_rebuilds_index_and_verifies_events() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let event = signed_relation(&alice, &bob, 1);
        let mut log = SocialEventLog::new();
        assert!(log.append(event.clone()).unwrap());

        let json = serde_json::to_vec(&log).unwrap();
        let mut decoded: SocialEventLog = serde_json::from_slice(&json).unwrap();

        assert_eq!(decoded.len(), 1);
        assert!(!decoded.append(event).unwrap());
        assert_eq!(decoded.len(), 1);
    }

    #[test]
    fn compacted_log_replays_base_state_and_allows_chain_continuation() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let first = SocialEvent::new_chained(
            alice.did().clone(),
            0,
            None,
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([31; 32]),
            },
        )
        .sign(&alice)
        .unwrap();
        let second = SocialEvent::new_chained(
            alice.did().clone(),
            1,
            Some(first.id.clone()),
            2,
            SocialEventKind::RelationDeclared {
                peer: bob.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("before compaction".into()),
            },
        )
        .sign(&alice)
        .unwrap();
        let third = SocialEvent::new_chained(
            alice.did().clone(),
            2,
            Some(second.id.clone()),
            3,
            SocialEventKind::RelationDeclared {
                peer: bob.did().clone(),
                relation: RelationKind::Blocked,
                note: Some("retained tail".into()),
            },
        )
        .sign(&alice)
        .unwrap();
        let mut log = SocialEventLog::new();
        assert_eq!(log.merge([first, second, third]).unwrap(), 3);

        assert!(log.compact_retaining_recent(1).unwrap());
        assert_eq!(log.len(), 3);
        assert_eq!(log.retained_len(), 1);
        assert_eq!(log.compacted_event_count(), 2);
        assert!(log.compacted_base().is_some());
        assert_eq!(
            log.to_society().edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Blocked
        );
        assert_eq!(log.next_position(alice.did()).0, 3);

        let next = SocialEvent::new_chained(
            alice.did().clone(),
            3,
            log.next_position(alice.did()).1,
            4,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([32; 32]),
            },
        )
        .sign(&alice)
        .unwrap();
        assert!(log.append(next).unwrap());
        assert_eq!(log.len(), 4);
    }
}
