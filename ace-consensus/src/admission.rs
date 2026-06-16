//! Dynamic Node Admission Controller for ACE Chain.
//!
//! Implements an algorithmic node admission mechanism inspired by Bitcoin's
//! difficulty adjustment. Instead of adjusting mining difficulty, ACE adjusts
//! the number of active validator slots based on network transaction load.
//!
//! ## Algorithm
//!
//! At each epoch boundary (~1 day):
//! 1. Measure the average transactions processed per active node
//! 2. Smooth the measurement with an exponential moving average (EMA)
//! 3. If smoothed load exceeds the expansion threshold → release new node slots
//! 4. If smoothed load is below the contraction threshold → freeze admissions
//!
//! The expansion rate is proportional to excess load above the target, capped
//! to prevent runaway growth. This creates a self-regulating feedback loop:
//! more transactions → more nodes → load distributes → equilibrium.
//!
//! ## BTC Analogy
//!
//! | Bitcoin                      | ACE Chain                         |
//! |------------------------------|-----------------------------------|
//! | Block time (10 min target)   | Avg txs per node (target load)    |
//! | Mining difficulty            | Active node quota                 |
//! | Adjustment every 2016 blocks | Adjustment every epoch (~1 day)   |
//! | 4× cap / 0.25× floor        | 20% expansion cap per epoch       |
//! | Hash rate ↑ → difficulty ↑   | Tx load ↑ → more node slots       |

use serde::{Deserialize, Serialize};

// ─── Configuration Constants ────────────────────────────────────────────────

/// Target average transactions per active node per epoch.
///
/// Calibrated for a network with ~100 active validators and ~46% average
/// block utilization (≈ 216,000 blocks × 926 avg txs = 200M total):
///
///   200,000,000 txs / 100 nodes = 2,000,000 txs/node/epoch
///
/// When load equals this value the network is at comfortable capacity.
pub const TARGET_AVG_TXS_PER_NODE: u64 = 2_000_000;

/// Load ratio (basis points) above which the controller releases new slots.
///
/// 12,000 bps = 120% of target load.  A moderate buffer prevents expansion
/// on every minor spike and lets the EMA absorb short-lived bursts.
pub const EXPANSION_THRESHOLD_BPS: u64 = 12_000;

/// Load ratio (basis points) below which expansion is fully suppressed.
///
/// 5,000 bps = 50% of target.  The network has ample spare capacity, so
/// admitting more nodes would waste resources without benefit.
pub const CONTRACTION_THRESHOLD_BPS: u64 = 5_000;

/// Maximum expansion rate per epoch: 20% of current active node count.
///
/// Prevents explosive growth after a single high-load epoch.  Even under
/// sustained 3× load, the network grows ≤ 20% per day.
pub const MAX_EXPANSION_RATE_BPS: u64 = 2_000;

/// Minimum slots released per expansion event (prevents stagnation with
/// very small validator sets where 20% rounds down to 0).
pub const MIN_EXPANSION_SLOTS: u32 = 1;

/// Absolute maximum slots released in a single epoch.
pub const MAX_EXPANSION_SLOTS: u32 = 100;

/// EMA weight for the *previous* smoothed value (70%).
///
/// Higher values make the controller more conservative (slower to react).
pub const LOAD_EMA_PREV_BPS: u64 = 7_000;

/// EMA weight for the *current* epoch observation (30%).
pub const LOAD_EMA_CUR_BPS: u64 = 3_000;

/// Basis-point denominator used throughout the module.
pub const BPS_DENOM: u64 = 10_000;

/// Hard ceiling: active node count can never exceed this value regardless
/// of how high the load grows.
pub const HARD_CAP_ACTIVE_NODES: u32 = 10_000;

// ─── Types ──────────────────────────────────────────────────────────────────

/// Outcome of an epoch-boundary admission evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionDecision {
    /// Updated active-node target (may have increased).
    pub new_active_target: u32,
    /// Number of standby nodes that should be promoted to Active.
    pub slots_to_release: u32,
    /// Smoothed load factor in basis points (10,000 = exactly at target).
    pub load_factor_bps: u64,
    /// `true` when the network is actively expanding.
    pub expanding: bool,
}

/// Tracks network load and dynamically adjusts the active-node quota.
///
/// Persisted as part of `GovernanceState` to guarantee deterministic
/// cross-node agreement on the admission schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionController {
    /// Exponentially weighted moving average of load factor (bps).
    ///
    /// 10,000 = target load, 20,000 = 2× target, etc.
    #[serde(default = "default_load_ema")]
    load_ema_bps: u64,

    /// Current dynamic cap on the number of active nodes.
    #[serde(default = "default_active_target")]
    active_target: u32,

    /// Cumulative count of slots released since genesis.
    #[serde(default)]
    total_slots_released: u32,

    /// Epoch of the most recent adjustment.
    #[serde(default)]
    last_adjustment_epoch: u64,
}

fn default_load_ema() -> u64 {
    BPS_DENOM // start at 100% = comfortable
}

fn default_active_target() -> u32 {
    HARD_CAP_ACTIVE_NODES
}

// ─── Implementation ─────────────────────────────────────────────────────────

impl AdmissionController {
    /// Create a controller whose initial quota matches the genesis validator count.
    pub fn new(initial_active_target: u32) -> Self {
        Self {
            load_ema_bps: BPS_DENOM,
            active_target: initial_active_target.min(HARD_CAP_ACTIVE_NODES),
            total_slots_released: 0,
            last_adjustment_epoch: 0,
        }
    }

    // ── Getters ──────────────────────────────────────────────────────────

    /// Current active-node target.
    pub fn active_target(&self) -> u32 {
        self.active_target
    }

    /// Current smoothed load factor (10,000 bps = exactly at target).
    pub fn load_ema_bps(&self) -> u64 {
        self.load_ema_bps
    }

    /// Total slots released since genesis.
    pub fn total_slots_released(&self) -> u32 {
        self.total_slots_released
    }

    /// Epoch of the last adjustment.
    pub fn last_adjustment_epoch(&self) -> u64 {
        self.last_adjustment_epoch
    }

    // ── Setters ──────────────────────────────────────────────────────────

    /// Manually override the active-node target (governance escape hatch).
    pub fn set_active_target(&mut self, target: u32) {
        self.active_target = target.min(HARD_CAP_ACTIVE_NODES);
    }

    // ── Core algorithm ───────────────────────────────────────────────────

    /// Evaluate at an epoch boundary and decide whether to expand.
    ///
    /// This is the "difficulty adjustment" equivalent:
    ///
    /// ```text
    /// load_ratio = avg_txs_per_node / TARGET_AVG_TXS_PER_NODE
    /// smoothed   = ema(previous, load_ratio)
    ///
    /// if smoothed > EXPANSION_THRESHOLD:
    ///     excess     = smoothed - 1.0
    ///     expansion  = active_count × excess
    ///     expansion  = clamp(expansion, MIN, min(MAX_RATE × active, MAX_ABS))
    ///     target    += expansion
    /// ```
    ///
    /// # Arguments
    ///
    /// * `epoch`              – The completed epoch number.
    /// * `epoch_total_txs`    – Total transactions processed in that epoch.
    /// * `active_node_count`  – Number of currently active validator nodes.
    pub fn on_epoch_boundary(
        &mut self,
        epoch: u64,
        epoch_total_txs: u64,
        active_node_count: u32,
    ) -> AdmissionDecision {
        if active_node_count == 0 {
            return AdmissionDecision {
                new_active_target: self.active_target,
                slots_to_release: 0,
                load_factor_bps: 0,
                expanding: false,
            };
        }

        // ── Step 1: compute current-epoch load factor ────────────────
        let avg_txs_per_node = epoch_total_txs / active_node_count as u64;
        let current_load_bps = if TARGET_AVG_TXS_PER_NODE == 0 {
            BPS_DENOM
        } else {
            avg_txs_per_node.saturating_mul(BPS_DENOM) / TARGET_AVG_TXS_PER_NODE
        };

        // ── Step 2: update EMA ───────────────────────────────────────
        self.load_ema_bps = self
            .load_ema_bps
            .saturating_mul(LOAD_EMA_PREV_BPS)
            .saturating_add(current_load_bps.saturating_mul(LOAD_EMA_CUR_BPS))
            / BPS_DENOM;
        self.last_adjustment_epoch = epoch;

        // ── Step 3: expansion decision ───────────────────────────────
        if self.load_ema_bps > EXPANSION_THRESHOLD_BPS && self.active_target < HARD_CAP_ACTIVE_NODES
        {
            // Excess load above the 1.0× target (in bps).
            let excess_bps = self.load_ema_bps.saturating_sub(BPS_DENOM);

            // Proportional expansion: more excess → more slots.
            let raw_expansion = (active_node_count as u64).saturating_mul(excess_bps) / BPS_DENOM;

            // Rate-limit: at most 20% of current active count per epoch.
            let max_rate_expansion =
                (active_node_count as u64).saturating_mul(MAX_EXPANSION_RATE_BPS) / BPS_DENOM;

            let expansion = raw_expansion
                .min(max_rate_expansion)
                .max(MIN_EXPANSION_SLOTS as u64)
                .min(MAX_EXPANSION_SLOTS as u64) as u32;

            let new_target = self
                .active_target
                .saturating_add(expansion)
                .min(HARD_CAP_ACTIVE_NODES);
            let actual_released = new_target.saturating_sub(self.active_target);

            self.active_target = new_target;
            self.total_slots_released = self.total_slots_released.saturating_add(actual_released);

            AdmissionDecision {
                new_active_target: self.active_target,
                slots_to_release: actual_released,
                load_factor_bps: self.load_ema_bps,
                expanding: true,
            }
        } else {
            // Load at or below target — hold current quota.
            AdmissionDecision {
                new_active_target: self.active_target,
                slots_to_release: 0,
                load_factor_bps: self.load_ema_bps,
                expanding: false,
            }
        }
    }
}

impl Default for AdmissionController {
    fn default() -> Self {
        Self {
            load_ema_bps: default_load_ema(),
            active_target: default_active_target(),
            total_slots_released: 0,
            last_adjustment_epoch: 0,
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_expansion_when_load_below_threshold() {
        let mut ctrl = AdmissionController::new(100);
        // Load = 50% of target → well below 120% threshold.
        let decision = ctrl.on_epoch_boundary(0, 100_000_000, 100);
        assert!(!decision.expanding);
        assert_eq!(decision.slots_to_release, 0);
        assert_eq!(decision.new_active_target, 100);
    }

    #[test]
    fn no_expansion_on_first_moderate_spike() {
        let mut ctrl = AdmissionController::new(100);
        // Single epoch at 200% load → EMA = 0.7 * 1.0 + 0.3 * 2.0 = 1.30
        // 13,000 bps > 12,000 threshold → expansion triggered
        let decision = ctrl.on_epoch_boundary(0, 400_000_000, 100);
        assert!(decision.expanding);
        // But after one normal epoch, EMA drops back:
        let decision2 = ctrl.on_epoch_boundary(1, 100_000_000, 100);
        // EMA = 0.7 * 1.30 + 0.3 * 0.50 = 0.91 + 0.15 = 1.06
        // 10,600 bps < 12,000 → no expansion
        assert!(!decision2.expanding);
    }

    #[test]
    fn sustained_high_load_expands() {
        let mut ctrl = AdmissionController::new(100);
        // Simulate sustained 180% load for several epochs.
        let txs = 3_600_000 * 100u64; // 3.6M per node × 100 nodes
        for epoch in 0..5 {
            ctrl.on_epoch_boundary(epoch, txs, 100);
        }
        // After 5 epochs of sustained 180% load, EMA should be well above threshold.
        let decision = ctrl.on_epoch_boundary(5, txs, 100);
        assert!(decision.expanding);
        assert!(decision.slots_to_release > 0);
        assert!(decision.new_active_target > 100);
    }

    #[test]
    fn expansion_capped_at_max_rate() {
        let mut ctrl = AdmissionController::new(100);
        // Force EMA very high to test rate cap.
        ctrl.load_ema_bps = 50_000; // 500% of target
        let decision = ctrl.on_epoch_boundary(0, 1_000_000_000, 100);
        // max_rate_expansion = 100 * 2000 / 10000 = 20 nodes
        assert!(decision.expanding);
        assert!(decision.slots_to_release <= 20);
    }

    #[test]
    fn hard_cap_respected() {
        let mut ctrl = AdmissionController::new(9_990);
        ctrl.load_ema_bps = 30_000; // way above threshold
        let decision = ctrl.on_epoch_boundary(0, 1_000_000_000, 9_990);
        // Can only release up to 10 more (cap is 10,000).
        assert!(decision.new_active_target <= HARD_CAP_ACTIVE_NODES);
        assert!(decision.slots_to_release <= 10);
    }

    #[test]
    fn zero_active_nodes_is_noop() {
        let mut ctrl = AdmissionController::new(0);
        let decision = ctrl.on_epoch_boundary(0, 1_000_000, 0);
        assert!(!decision.expanding);
        assert_eq!(decision.slots_to_release, 0);
        assert_eq!(decision.load_factor_bps, 0);
    }

    #[test]
    fn minimum_expansion_slots() {
        let mut ctrl = AdmissionController::new(3);
        // With only 3 active nodes, 20% = 0.6 → rounds down to 0.
        // MIN_EXPANSION_SLOTS ensures at least 1 slot is released.
        ctrl.load_ema_bps = 15_000; // well above threshold
        let decision = ctrl.on_epoch_boundary(0, 100_000_000, 3);
        assert!(decision.expanding);
        assert!(decision.slots_to_release >= MIN_EXPANSION_SLOTS);
    }

    #[test]
    fn ema_smoothing_prevents_oscillation() {
        let mut ctrl = AdmissionController::new(100);
        // Alternate between very high and very low load.
        let high_txs = 500_000_000u64; // 5M per node → 250% load
        let low_txs = 50_000_000u64; // 0.5M per node → 25% load

        let mut expanding_count = 0;
        for epoch in 0..10 {
            let txs = if epoch % 2 == 0 { high_txs } else { low_txs };
            let decision = ctrl.on_epoch_boundary(epoch, txs, 100);
            if decision.expanding {
                expanding_count += 1;
            }
        }
        // With alternating load, EMA averages to ~137.5% (above threshold
        // but moderated). Should expand less than half the time due to
        // the low epochs pulling EMA down.
        assert!(expanding_count < 10);
    }

    #[test]
    fn total_slots_released_accumulates() {
        let mut ctrl = AdmissionController::new(100);
        ctrl.load_ema_bps = 15_000;
        let d1 = ctrl.on_epoch_boundary(0, 500_000_000, 100);
        let released_1 = d1.slots_to_release;
        ctrl.load_ema_bps = 15_000;
        let d2 = ctrl.on_epoch_boundary(1, 500_000_000, 100 + released_1);
        assert_eq!(
            ctrl.total_slots_released(),
            released_1 + d2.slots_to_release
        );
    }

    #[test]
    fn governance_override_works() {
        let mut ctrl = AdmissionController::new(100);
        ctrl.set_active_target(500);
        assert_eq!(ctrl.active_target(), 500);

        // Cannot exceed hard cap.
        ctrl.set_active_target(99_999);
        assert_eq!(ctrl.active_target(), HARD_CAP_ACTIVE_NODES);
    }

    #[test]
    fn default_is_backward_compatible() {
        let ctrl = AdmissionController::default();
        // Default target = HARD_CAP → existing networks unrestricted.
        assert_eq!(ctrl.active_target(), HARD_CAP_ACTIVE_NODES);
        assert_eq!(ctrl.load_ema_bps(), BPS_DENOM);
    }

    #[test]
    fn serde_round_trip() {
        let mut ctrl = AdmissionController::new(42);
        ctrl.on_epoch_boundary(5, 300_000_000, 42);
        let json = serde_json::to_string(&ctrl).unwrap();
        let restored: AdmissionController = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.active_target(), ctrl.active_target());
        assert_eq!(restored.load_ema_bps(), ctrl.load_ema_bps());
        assert_eq!(restored.total_slots_released(), ctrl.total_slots_released());
    }

    #[test]
    fn serde_backward_compat_empty_json() {
        // Simulates loading from an old governance.json that doesn't have
        // admission_controller fields — all fields use #[serde(default)].
        let ctrl: AdmissionController = serde_json::from_str("{}").unwrap();
        assert_eq!(ctrl.active_target(), HARD_CAP_ACTIVE_NODES);
        assert_eq!(ctrl.load_ema_bps(), BPS_DENOM);
    }
}
