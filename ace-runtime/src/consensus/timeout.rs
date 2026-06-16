//! Two-Phase Proof Timeout Protocol (Definition 5 in the paper).
//!
//! ## Two phases
//! 1. **Builder window** (K = 2–3 slots, 800–1200 ms):
//!    The designated builder must submit a valid finality certificate.
//!    Failure to do so triggers slashing.
//!
//! 2. **Backup window** (K' = 2–3 additional slots):
//!    Any validator with witness availability can generate the proof.
//!    Failure triggers rollback and transaction requeue.
//!
//! ## Witness Availability (Definition 6)
//! A block B satisfies witness availability when ≥ ⅔ of validators
//! have received the encrypted witness bundles via off-chain gossip.

use std::collections::HashMap;

use crate::config::{
    K_BACKUP_SLOTS, K_BUILDER_SLOTS, QUORUM_DENOMINATOR, QUORUM_NUMERATOR, SLOT_DURATION_MS,
};

/// Timeout phase in the two-phase protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutPhase {
    /// Still within the builder window (slots 1..K).
    BuilderWindow,
    /// Builder window expired; now in backup window (slots K+1..K+K').
    BackupWindow,
    /// Both windows expired; block should be rolled back.
    Expired,
    /// A finality certificate was received; timeout cancelled.
    Resolved,
}

/// Two-phase timeout protocol for a single block.
///
/// Tracks the elapsed slots since block publication and determines
/// the current timeout phase.
pub struct TimeoutProtocol {
    /// Slot at which the block was published.
    block_slot: u64,
    /// Whether a finality certificate has been received.
    resolved: bool,
}

impl TimeoutProtocol {
    /// Create a new timeout protocol for a block at the given slot.
    pub fn new(block_slot: u64) -> Self {
        Self {
            block_slot,
            resolved: false,
        }
    }

    /// Mark the timeout as resolved (FC received).
    pub fn resolve(&mut self) {
        self.resolved = true;
    }

    /// Check the current phase given the current slot.
    pub fn phase(&self, current_slot: u64) -> TimeoutPhase {
        if self.resolved {
            return TimeoutPhase::Resolved;
        }

        let elapsed = current_slot.saturating_sub(self.block_slot);

        if elapsed <= K_BUILDER_SLOTS {
            TimeoutPhase::BuilderWindow
        } else if elapsed <= K_BUILDER_SLOTS + K_BACKUP_SLOTS {
            TimeoutPhase::BackupWindow
        } else {
            TimeoutPhase::Expired
        }
    }

    /// Compute the deadline slot for the builder window.
    pub fn builder_deadline(&self) -> u64 {
        self.block_slot + K_BUILDER_SLOTS
    }

    /// Compute the deadline slot for the backup window.
    pub fn backup_deadline(&self) -> u64 {
        self.block_slot + K_BUILDER_SLOTS + K_BACKUP_SLOTS
    }

    /// Compute the builder deadline in milliseconds from block publication.
    pub fn builder_deadline_ms(&self) -> u64 {
        K_BUILDER_SLOTS * SLOT_DURATION_MS
    }

    /// Compute the total deadline (builder + backup) in milliseconds.
    pub fn total_deadline_ms(&self) -> u64 {
        (K_BUILDER_SLOTS + K_BACKUP_SLOTS) * SLOT_DURATION_MS
    }

    /// Whether the builder window has expired.
    pub fn is_builder_expired(&self, current_slot: u64) -> bool {
        !self.resolved && current_slot > self.block_slot + K_BUILDER_SLOTS
    }

    /// Whether both windows have expired (full timeout).
    pub fn is_fully_expired(&self, current_slot: u64) -> bool {
        !self.resolved && current_slot > self.block_slot + K_BUILDER_SLOTS + K_BACKUP_SLOTS
    }
}

/// Witness availability check (Definition 6 in the paper).
///
/// A block B satisfies witness availability when ≥ ⅔ of stake-weighted
/// validators have received the encrypted witness bundles via off-chain
/// gossip protocol.
///
/// ## Security properties
/// - **Deduplication**: Uses a `HashSet<u64>` so the same validator
///   cannot be counted twice.
/// - **Membership check**: When constructed with [`new_with_validator_set`],
///   only IDs present in the validator set are accepted. IDs not in the
///   set are silently rejected by [`record_receipt`].
pub struct WitnessAvailability {
    /// Map of validator IDs to their stake weight that have reported receipt.
    received: HashMap<u64, u64>,
    /// Total stake across all validators.
    pub total_validators: u64,
    /// Optional map of valid validator IDs to their stake for membership checking.
    /// When `Some`, only IDs in this map are accepted by `record_receipt`.
    valid_validators: Option<HashMap<u64, u64>>,
}

impl WitnessAvailability {
    /// Create a new witness availability tracker without membership checking.
    ///
    /// All validator IDs will be accepted with weight 1 (equal-weight mode).
    /// Use [`new_with_validator_set`] for production stake-weighted mode.
    pub fn new(total_validators: u64) -> Self {
        Self {
            received: HashMap::new(),
            total_validators,
            valid_validators: None,
        }
    }

    /// Create a new witness availability tracker with validator set membership checking.
    ///
    /// Only validator IDs present in `valid_set` will be accepted by
    /// [`record_receipt`]. `total_validators` is the total stake.
    /// Each validator's stake is used for quorum calculation.
    pub fn new_with_validator_set(total_validators: u64, valid_set: HashMap<u64, u64>) -> Self {
        Self {
            received: HashMap::new(),
            total_validators,
            valid_validators: Some(valid_set),
        }
    }

    /// Record that a validator has received the witness bundle.
    ///
    /// Returns `true` if this is a new, valid receipt.
    /// Returns `false` if:
    /// - The validator already reported (dedup), or
    /// - The validator ID is not in the validator set (membership check).
    pub fn record_receipt(&mut self, validator_id: u64) -> bool {
        if self.received.contains_key(&validator_id) {
            return false;
        }
        let stake = if let Some(ref valid_set) = self.valid_validators {
            match valid_set.get(&validator_id) {
                Some(&s) => s,
                None => return false,
            }
        } else {
            1 // equal-weight fallback
        };
        self.received.insert(validator_id, stake);
        true
    }

    /// Number of unique validators that have reported receipt.
    pub fn received_count(&self) -> u64 {
        self.received.len() as u64
    }

    /// Total stake of validators that have reported receipt.
    pub fn received_stake(&self) -> u64 {
        self.received.values().sum()
    }

    /// Check whether ⅔ quorum of stake-weighted validators have received witness data.
    /// Uses u128 arithmetic to prevent overflow with large stake values.
    pub fn is_available(&self) -> bool {
        let received_stake: u64 = self.received.values().sum();
        (received_stake as u128) * (QUORUM_DENOMINATOR as u128)
            >= (QUORUM_NUMERATOR as u128) * (self.total_validators as u128)
    }

    /// Fraction of stake that has received the witness.
    pub fn availability_fraction(&self) -> f64 {
        if self.total_validators == 0 {
            return 0.0;
        }
        let received_stake: u64 = self.received.values().sum();
        received_stake as f64 / self.total_validators as f64
    }
}
