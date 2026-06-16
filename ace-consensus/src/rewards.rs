//! Reward distribution engine for ACE Chain.

use ace_model::account::AccountId;
use serde::{Deserialize, Serialize};

/// Blocks per epoch (~1 day at 400ms slots).
pub const BLOCKS_PER_EPOCH: u64 = 216_000;

/// Initial daily reward pool in base units (100,000 ACE * 10^9 decimals).
pub const INITIAL_DAILY_REWARD: u64 = 100_000 * 1_000_000_000;

/// Target active validator count used for issuance warm-up.
pub const WARMUP_TARGET_VALIDATORS: u64 = 1_000;

/// Target base issuance per validator per day during warm-up (100 ACE/day).
pub const TARGET_DAILY_REWARD_PER_VALIDATOR: u64 = INITIAL_DAILY_REWARD / WARMUP_TARGET_VALIDATORS;

/// Transaction fee per tx in base units (9 decimals).
///
/// **Code-path energy estimate (critical path only, single-thread CPU):**
///
/// - **Native ACE (0x01 transfer):** `verify_credential` = SHA-256(payload) ~0.5 μs + Ed25519
///   verify_strict(72B) ~50 μs; `state.get`×2 + BTreeMap get_mut/insert ~2 μs ⇒ **~53 μs**.
/// - **Raw EVM (0x12):** RLP decode ~2 μs + Keccak256(signing_hash) ~2 μs + secp256k1 ecrecover
///   ~150 μs + SHA256(idcom) ~1 μs ⇒ **~155 μs**; then `AddressIndex::build_from_state` is
///   O(accounts): 1k accounts ~2 ms, 100k ~200 ms; revm simple CALL ~50–200 μs.
/// - **State:** BTreeMap get/insert O(log n); Merkle root is per-block, not per-tx.
///
/// Take **native path ~55 μs** as baseline. CPU power for one active core ~5–15 W; 55 μs × 10 W
/// = **0.55 mJ ≈ 1.5e-10 kWh/tx**. At $0.20/kWh ⇒ **~3e-11 USD/tx** (pure CPU, one core).
/// With whole-node amortization (memory, I/O, network, proof pipeline), 2–3 orders of magnitude
/// higher is plausible ⇒ **~1e-8–1e-7 USD/tx**. Fee in ACE then set by policy (e.g. 100× cost).
pub const TX_FEE: u64 = 20_000; // 0.00002 ACE

/// Halving interval in epochs (~4 years = 1461 days).
pub const HALVING_INTERVAL_EPOCHS: u64 = 1461;

/// Maximum supply in base units (1 billion ACE * 10^9 decimals).
pub const MAX_SUPPLY: u64 = 1_000_000_000 * 1_000_000_000;

/// Reward bucket weights in basis points.
pub const BASE_REWARD_BPS: u64 = 7_500;
pub const PERFORMANCE_REWARD_BPS: u64 = 1_700;
pub const AGE_REWARD_BPS: u64 = 800;
pub const BPS_DENOMINATOR: u64 = 10_000;

/// Performance bucket clamps in basis points (0.85x..1.15x).
pub const PERF_WEIGHT_FLOOR_BPS: u16 = 8_500;
pub const PERF_WEIGHT_CEIL_BPS: u16 = 11_500;

/// EMA update coefficients in basis points.
pub const PERF_EMA_PREV_BPS: u64 = 9_000;
pub const PERF_EMA_CUR_BPS: u64 = 1_000;

/// Node age cap used by the age bonus.
pub const AGE_CAP_MONTHS: u64 = 60;

/// Per-validator reward inputs supplied by governance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RewardProfile {
    pub validator: AccountId,
    /// Smoothed performance weight in basis points.
    pub perf_weight_bps: u16,
    /// Age weight in basis points (0..10000).
    pub age_weight_bps: u16,
}

/// Tracks epoch boundaries and accumulated fees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochTracker {
    current_epoch: u64,
    accumulated_fees: u64,
    total_minted: u64,
    blocks_in_epoch: u64,
    /// Transaction count accumulated in the current epoch (for admission controller).
    #[serde(default)]
    epoch_tx_count: u64,
    /// Transaction count of the most recently completed epoch.
    #[serde(default)]
    last_epoch_tx_count: u64,
}

impl EpochTracker {
    pub fn new() -> Self {
        Self {
            current_epoch: 0,
            accumulated_fees: 0,
            total_minted: 0,
            blocks_in_epoch: 0,
            epoch_tx_count: 0,
            last_epoch_tx_count: 0,
        }
    }

    pub fn with_state(epoch: u64, total_minted: u64) -> Self {
        Self {
            current_epoch: epoch,
            accumulated_fees: 0,
            total_minted,
            blocks_in_epoch: 0,
            epoch_tx_count: 0,
            last_epoch_tx_count: 0,
        }
    }

    pub fn with_checkpoint(
        epoch: u64,
        total_minted: u64,
        accumulated_fees: u64,
        blocks_in_epoch: u64,
    ) -> Self {
        Self {
            current_epoch: epoch,
            accumulated_fees,
            total_minted,
            blocks_in_epoch,
            epoch_tx_count: 0,
            last_epoch_tx_count: 0,
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn total_minted(&self) -> u64 {
        self.total_minted
    }

    pub fn on_block(&mut self, tx_count: u64) -> Option<u64> {
        self.accumulated_fees = self
            .accumulated_fees
            .saturating_add(tx_count.saturating_mul(TX_FEE));
        self.epoch_tx_count = self.epoch_tx_count.saturating_add(tx_count);
        self.blocks_in_epoch += 1;

        if self.blocks_in_epoch >= BLOCKS_PER_EPOCH {
            let completed_epoch = self.current_epoch;
            self.last_epoch_tx_count = self.epoch_tx_count;
            self.current_epoch += 1;
            self.blocks_in_epoch = 0;
            self.epoch_tx_count = 0;
            Some(completed_epoch)
        } else {
            None
        }
    }

    /// Transaction count of the most recently completed epoch.
    ///
    /// Valid immediately after `on_block()` returns `Some(epoch)`.
    /// Used by the admission controller to measure network load.
    pub fn last_epoch_tx_count(&self) -> u64 {
        self.last_epoch_tx_count
    }

    /// Transaction count accumulated so far in the current (in-progress) epoch.
    pub fn epoch_tx_count(&self) -> u64 {
        self.epoch_tx_count
    }

    pub fn take_fees(&mut self) -> u64 {
        let fees = self.accumulated_fees;
        self.accumulated_fees = 0;
        fees
    }

    pub fn accumulated_fees(&self) -> u64 {
        self.accumulated_fees
    }

    pub fn record_mint(&mut self, amount: u64) {
        self.total_minted = self.total_minted.saturating_add(amount);
    }
}

impl Default for EpochTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes rewards for validators at epoch boundaries.
pub struct RewardEngine;

impl RewardEngine {
    /// Calculate the block reward pool for a given epoch with early-network warm-up.
    pub fn epoch_reward_pool(epoch: u64, total_minted: u64, active_validator_count: u64) -> u64 {
        if active_validator_count == 0 {
            return 0;
        }

        let halvings = epoch / HALVING_INTERVAL_EPOCHS;
        if halvings >= 20 {
            return 0;
        }

        let warmup_validators = active_validator_count.min(WARMUP_TARGET_VALIDATORS);
        let warmup_pool = warmup_validators.saturating_mul(TARGET_DAILY_REWARD_PER_VALIDATOR);
        let pool = warmup_pool >> halvings;

        let remaining = MAX_SUPPLY.saturating_sub(total_minted);
        pool.min(remaining)
    }

    /// Distribute rewards across base/performance/age buckets.
    pub fn distribute(
        epoch: u64,
        total_minted: u64,
        accumulated_fees: u64,
        profiles: &[RewardProfile],
    ) -> Vec<(AccountId, u64)> {
        if profiles.is_empty() {
            return vec![];
        }

        let block_reward = Self::epoch_reward_pool(epoch, total_minted, profiles.len() as u64);
        let total_reward = block_reward.saturating_add(accumulated_fees);
        if total_reward == 0 {
            return vec![];
        }

        let base_pool = total_reward.saturating_mul(BASE_REWARD_BPS) / BPS_DENOMINATOR;
        let perf_pool = total_reward.saturating_mul(PERFORMANCE_REWARD_BPS) / BPS_DENOMINATOR;
        // AGE_REWARD_BPS = 800; residual form absorbs integer-division dust.
        let age_pool = total_reward
            .saturating_sub(base_pool)
            .saturating_sub(perf_pool);

        let mut rewards = vec![0u64; profiles.len()];
        // Use the epoch number as rotation offset so remainder dust rotates
        // across validators each epoch rather than always going to index 0.
        let rotation = epoch as usize;
        distribute_equal(base_pool, &mut rewards, rotation);
        distribute_weighted(
            perf_pool,
            profiles
                .iter()
                .map(|profile| {
                    profile
                        .perf_weight_bps
                        .clamp(PERF_WEIGHT_FLOOR_BPS, PERF_WEIGHT_CEIL_BPS)
                        as u64
                })
                .collect::<Vec<_>>()
                .as_slice(),
            &mut rewards,
            rotation,
        );
        distribute_weighted(
            age_pool,
            profiles
                .iter()
                .map(|profile| profile.age_weight_bps as u64)
                .collect::<Vec<_>>()
                .as_slice(),
            &mut rewards,
            rotation,
        );

        profiles
            .iter()
            .zip(rewards)
            .filter_map(|(profile, amount)| (amount > 0).then_some((profile.validator, amount)))
            .collect()
    }
}

fn distribute_equal(amount: u64, outputs: &mut [u64], rotation_offset: usize) {
    if outputs.is_empty() || amount == 0 {
        return;
    }
    let count = outputs.len();
    let per = amount / count as u64;
    let remainder = (amount % count as u64) as usize;
    for i in 0..count {
        // Rotate which validators receive the remainder units so that rounding
        // dust does not always accrue to the same (lowest-index) validators.
        let gets_extra = ((i + count - rotation_offset % count) % count) < remainder;
        outputs[i] = outputs[i].saturating_add(per + u64::from(gets_extra));
    }
}

fn distribute_weighted(amount: u64, weights: &[u64], outputs: &mut [u64], rotation_offset: usize) {
    if outputs.is_empty() || amount == 0 {
        return;
    }
    let total_weight: u64 = weights.iter().copied().fold(0u64, u64::saturating_add);
    if total_weight == 0 {
        distribute_equal(amount, outputs, rotation_offset);
        return;
    }

    let mut distributed = 0u64;
    for (index, output) in outputs.iter_mut().enumerate() {
        let share = ((amount as u128).saturating_mul(weights[index] as u128)
            / (total_weight as u128)) as u64;
        *output = output.saturating_add(share);
        distributed = distributed.saturating_add(share);
    }

    // Distribute remainder units with rotation so that rounding dust does not
    // always accrue to the same (lowest-index) validators.
    let count = outputs.len();
    let remainder = amount.saturating_sub(distributed) as usize;
    for j in 0..remainder.min(count) {
        let idx = (rotation_offset + j) % count;
        outputs[idx] = outputs[idx].saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles() -> Vec<RewardProfile> {
        vec![
            RewardProfile {
                validator: AccountId([1u8; 32]),
                perf_weight_bps: 10_000,
                age_weight_bps: 1_000,
            },
            RewardProfile {
                validator: AccountId([2u8; 32]),
                perf_weight_bps: 11_500,
                age_weight_bps: 8_000,
            },
        ]
    }

    #[test]
    fn test_epoch_reward_pool_respects_warmup() {
        let pool = RewardEngine::epoch_reward_pool(0, 0, 100);
        assert_eq!(pool, 100 * TARGET_DAILY_REWARD_PER_VALIDATOR);
    }

    #[test]
    fn test_epoch_reward_pool_caps_at_target() {
        let pool = RewardEngine::epoch_reward_pool(0, 0, 10_000);
        assert_eq!(pool, INITIAL_DAILY_REWARD);
    }

    #[test]
    fn test_epoch_reward_pool_first_halving() {
        let pool =
            RewardEngine::epoch_reward_pool(HALVING_INTERVAL_EPOCHS, 0, WARMUP_TARGET_VALIDATORS);
        assert_eq!(pool, INITIAL_DAILY_REWARD / 2);
    }

    #[test]
    fn test_epoch_reward_pool_max_supply_cap() {
        let nearly_all = MAX_SUPPLY - 1000;
        let pool = RewardEngine::epoch_reward_pool(0, nearly_all, WARMUP_TARGET_VALIDATORS);
        assert_eq!(pool, 1000);
    }

    #[test]
    fn test_distribute_respects_total_reward() {
        let profiles = profiles();
        let rewards = RewardEngine::distribute(0, 0, 5, &profiles);
        let total: u64 = rewards.iter().map(|(_, amount)| *amount).sum();
        assert_eq!(
            total,
            RewardEngine::epoch_reward_pool(0, 0, profiles.len() as u64) + 5
        );
    }

    #[test]
    fn test_distribute_age_and_perf_bias_are_small() {
        let profiles = profiles();
        let rewards = RewardEngine::distribute(0, 0, 0, &profiles);
        assert_eq!(rewards.len(), 2);
        assert!(rewards[1].1 > rewards[0].1);
        let delta = rewards[1].1 - rewards[0].1;
        assert!(delta < INITIAL_DAILY_REWARD / 4);
    }

    #[test]
    fn test_distribute_empty_validators() {
        let rewards = RewardEngine::distribute(0, 0, 0, &[]);
        assert!(rewards.is_empty());
    }

    #[test]
    fn test_weighted_distribution_falls_back_to_equal() {
        let mut outputs = vec![0u64; 3];
        distribute_weighted(5, &[0, 0, 0], &mut outputs, 0);
        assert_eq!(outputs, vec![2, 2, 1]);
    }

    #[test]
    fn test_distribute_equal_rotation() {
        // With rotation_offset=0, remainder goes to indices 0,1
        let mut a = vec![0u64; 3];
        distribute_equal(5, &mut a, 0);
        assert_eq!(a, vec![2, 2, 1]);

        // With rotation_offset=1, remainder rotates: indices 1,2 get extra
        let mut b = vec![0u64; 3];
        distribute_equal(5, &mut b, 1);
        assert_eq!(b, vec![1, 2, 2]);

        // With rotation_offset=2, remainder rotates: indices 2,0 get extra
        let mut c = vec![0u64; 3];
        distribute_equal(5, &mut c, 2);
        assert_eq!(c, vec![2, 1, 2]);

        // Total is always preserved regardless of rotation
        assert_eq!(a.iter().sum::<u64>(), 5);
        assert_eq!(b.iter().sum::<u64>(), 5);
        assert_eq!(c.iter().sum::<u64>(), 5);
    }
}
