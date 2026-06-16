//! Deterministic leader election per slot.
//!
//! Uses `SHA-256(seed || slot_bytes)` to select the leader, weighted
//! by stake. Consistent with ace-runtime's SHA-256 usage throughout.

use sha2::{Digest, Sha256};

use ace_model::account::AccountId;

use crate::validator_set::ValidatorSet;

/// Deterministic leader schedule based on epoch seed.
///
/// The same `(seed, slot)` pair always selects the same leader,
/// ensuring consensus on who should produce each block.
pub struct LeaderSchedule {
    /// Epoch randomness seed.
    seed: [u8; 32],
}

impl LeaderSchedule {
    /// Create a new leader schedule with the given seed.
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// Determine the leader for a given slot.
    ///
    /// Algorithm:
    /// 1. hash = SHA-256(seed || slot_bytes)
    /// 2. value = hash[0..8] as u64
    /// 3. target = value % total_stake
    /// 4. Walk validator list, accumulating stake, until target is covered
    pub fn leader_for_slot(&self, slot: u64, validators: &ValidatorSet) -> AccountId {
        if validators.is_empty() || validators.total_stake() == 0 {
            return AccountId::ZERO;
        }

        let mut hasher = Sha256::new();
        hasher.update(self.seed);
        hasher.update(slot.to_le_bytes());
        let result = hasher.finalize();

        let total_stake = validators.total_stake();

        // Rejection sampling: eliminate modular bias
        let threshold = u64::MAX - (u64::MAX % total_stake);
        let mut value = u64::from_le_bytes(
            result[0..8]
                .try_into()
                .expect("SHA-256 output is at least 8 bytes"),
        );
        let mut counter: u32 = 0;
        while value >= threshold {
            counter += 1;
            let mut rehasher = Sha256::new();
            rehasher.update(self.seed);
            rehasher.update(slot.to_le_bytes());
            rehasher.update(counter.to_le_bytes());
            let rehash = rehasher.finalize();
            value = u64::from_le_bytes(
                rehash[0..8]
                    .try_into()
                    .expect("SHA-256 output is at least 8 bytes"),
            );
        }
        let target = value % total_stake;
        let mut accumulated = 0u64;

        for v in validators.validators() {
            accumulated += v.stake;
            if accumulated > target {
                return v.id_com;
            }
        }

        // Fallback when target equals total_stake (should not happen with correct total_stake)
        validators
            .validators()
            .last()
            .expect("validator set is non-empty")
            .id_com
    }

    /// Determine the proposer for a given height and round (Tendermint).
    ///
    /// Algorithm: SHA-256(seed || height_bytes || round_bytes) with rejection sampling.
    /// Different rounds at the same height select different proposers.
    pub fn proposer_for_height_round(
        &self,
        height: u64,
        round: u32,
        validators: &ValidatorSet,
    ) -> AccountId {
        if validators.is_empty() || validators.total_stake() == 0 {
            return AccountId::ZERO;
        }

        let mut hasher = Sha256::new();
        hasher.update(self.seed);
        hasher.update(height.to_le_bytes());
        hasher.update(round.to_le_bytes());
        let result = hasher.finalize();

        let total_stake = validators.total_stake();

        // Rejection sampling for unbiased selection
        let threshold = u64::MAX - (u64::MAX % total_stake);
        let mut value = u64::from_le_bytes(
            result[0..8]
                .try_into()
                .expect("SHA-256 output is at least 8 bytes"),
        );
        let mut counter: u32 = 0;
        while value >= threshold {
            counter += 1;
            let mut rehasher = Sha256::new();
            rehasher.update(self.seed);
            rehasher.update(height.to_le_bytes());
            rehasher.update(round.to_le_bytes());
            rehasher.update(counter.to_le_bytes());
            let rehash = rehasher.finalize();
            value = u64::from_le_bytes(
                rehash[0..8]
                    .try_into()
                    .expect("SHA-256 output is at least 8 bytes"),
            );
        }
        let target = value % total_stake;
        let mut accumulated = 0u64;

        for v in validators.validators() {
            accumulated += v.stake;
            if accumulated > target {
                return v.id_com;
            }
        }

        validators
            .validators()
            .last()
            .expect("validator set is non-empty")
            .id_com
    }

    /// Rotate the epoch seed for leader selection.
    ///
    /// Should be called at epoch boundaries using the hash of the
    /// last finalized block to prevent long-range leader prediction.
    pub fn rotate_seed(&mut self, new_seed: [u8; 32]) {
        self.seed = new_seed;
    }

    /// Get the seed.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}
