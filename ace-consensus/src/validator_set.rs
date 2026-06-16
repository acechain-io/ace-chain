//! Validator set management with stake weights.
//!
//! The validator set is used by the leader schedule for slot assignment
//! and by the vote collector for quorum checks.

use ace_model::account::AccountId;
use ace_runtime::crypto::TaggedPubkey;
use ace_runtime::types::capability::{CommitteeDomain, ValidatorCapabilities};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A validator in the consensus set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// Identity commitment of the validator.
    pub id_com: AccountId,
    /// Stake weight (determines leader election probability and vote weight).
    pub stake: u64,
    /// Index in the validator set (for deterministic ordering).
    pub index: u32,
    /// Signing public key for vote/FC signature verification (PQC-ready).
    pub signing_pubkey: TaggedPubkey,
    /// Static execution capabilities used by the minimal committee flow.
    #[serde(default)]
    pub capabilities: ValidatorCapabilities,
}

/// Minimum stake required for a validator to be admitted to the set.
///
/// Validators with a stake below this threshold are silently filtered out
/// during construction and rejected from `add_validator`.
pub const MIN_VALIDATOR_STAKE: u64 = 1;

/// The set of active validators for an epoch.
///
/// Used by [`LeaderSchedule`](super::leader_schedule::LeaderSchedule)
/// for slot assignment and by [`VoteCollector`](super::vote::VoteCollector)
/// for quorum calculation.
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    total_stake: u64,
    /// In-memory generation counter, bumped on every effective-set rotation.
    /// Used by VoteCollector::reconcile_validator_set to short-circuit
    /// re-verification when the set is unchanged. Not persisted: after a
    /// process restart, generation resets to 0 and the next reconcile pays
    /// a one-shot full re-verification cost.
    generation: u64,
}

impl ValidatorSet {
    /// Create a validator set. Computes total_stake from the validators.
    ///
    /// Validators with a stake below [`MIN_VALIDATOR_STAKE`] are silently
    /// filtered out. Validators are sorted by `id_com` so that leader schedule
    /// and iteration order are deterministic across nodes.
    pub fn new(validators: Vec<Validator>) -> Self {
        let mut validators: Vec<Validator> = validators
            .into_iter()
            .filter(|v| v.stake >= MIN_VALIDATOR_STAKE)
            .collect();
        validators.sort_by(|a, b| a.id_com.cmp(&b.id_com));
        let total_stake = validators.iter().map(|v| v.stake).sum();
        Self {
            validators,
            total_stake,
            generation: 0,
        }
    }

    /// Total stake across all validators.
    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// In-memory generation counter (bumped on each effective-set rotation).
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Explicitly set the generation counter.
    pub(crate) fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Whether the validator set is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Get a validator by index.
    pub fn get_by_index(&self, index: u32) -> Option<&Validator> {
        self.validators.iter().find(|v| v.index == index)
    }

    /// Get a validator by identity commitment.
    pub fn get_by_id(&self, id: &AccountId) -> Option<&Validator> {
        self.validators.iter().find(|v| v.id_com == *id)
    }

    /// Get all validators as a slice.
    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }

    /// Return validators that support the requested committee domain.
    pub fn validators_for_domain(&self, domain: CommitteeDomain) -> Vec<Validator> {
        self.validators
            .iter()
            .filter(|validator| match domain {
                CommitteeDomain::BtcPayments => validator.capabilities.btc_payments,
                CommitteeDomain::SolanaLight => validator.capabilities.solana_light,
            })
            .cloned()
            .collect()
    }

    /// Build a filtered validator set from a list of allowed validator ids.
    pub fn filtered(&self, allowed: &BTreeSet<AccountId>) -> Self {
        let validators = self
            .validators
            .iter()
            .filter(|validator| allowed.contains(&validator.id_com))
            .cloned()
            .collect();
        Self::new(validators)
    }

    /// Add a new validator. Updates total stake.
    ///
    /// Rejects the validator if:
    /// - stake is below [`MIN_VALIDATOR_STAKE`],
    /// - the `id_com` already exists in the set, or
    /// - the `index` already exists in the set.
    pub fn add_validator(&mut self, v: Validator) -> Result<(), String> {
        if v.stake < MIN_VALIDATOR_STAKE {
            return Err(format!(
                "validator {} has insufficient stake {}",
                v.id_com, v.stake
            ));
        }
        if self
            .validators
            .iter()
            .any(|existing| existing.id_com == v.id_com)
        {
            return Err(format!("duplicate validator id_com {}", v.id_com));
        }
        if self
            .validators
            .iter()
            .any(|existing| existing.index == v.index)
        {
            return Err(format!(
                "duplicate validator index {} for {}",
                v.index, v.id_com
            ));
        }
        self.total_stake += v.stake;
        self.validators.push(v);
        self.validators.sort_by(|a, b| a.id_com.cmp(&b.id_com));
        Ok(())
    }

    /// Remove a validator by identity. Returns the removed validator if found.
    pub fn remove_validator(&mut self, id: &AccountId) -> Option<Validator> {
        if let Some(pos) = self.validators.iter().position(|v| v.id_com == *id) {
            let removed = self.validators.remove(pos);
            self.total_stake = self.total_stake.saturating_sub(removed.stake);
            Some(removed)
        } else {
            None
        }
    }

    /// Update the stake of an existing validator.
    ///
    /// If `new_stake` is below [`MIN_VALIDATOR_STAKE`], the validator is
    /// removed from the set instead of being kept with zero stake.
    pub fn update_stake(&mut self, id: &AccountId, new_stake: u64) {
        if new_stake < MIN_VALIDATOR_STAKE {
            if self.remove_validator(id).is_some() {
                tracing::warn!(
                    id = ?id,
                    "validator stake below minimum, removed from set"
                );
            }
            return;
        }
        if let Some(v) = self.validators.iter_mut().find(|v| v.id_com == *id) {
            self.total_stake = self.total_stake.saturating_sub(v.stake);
            v.stake = new_stake;
            self.total_stake += new_stake;
        }
    }
}
