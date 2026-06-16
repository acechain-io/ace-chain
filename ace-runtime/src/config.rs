//! Protocol constants for ACE Runtime.
//!
//! All values correspond to the runtime's consensus and proving parameters.

/// Slot duration in milliseconds (wall-clock mapping in `SlotClock`: `elapsed / SLOT_DURATION_MS`).
/// Devnet uses a conservative 500 ms engineering target; non-devnet builds
/// keep the paper target of 400 ms.
/// Keep `ace-portal` `VITE_ACE_SLOT_DURATION_MS` in sync when this changes.
/// Orphan block pool handles gossipsub delays without needing longer slots.
#[cfg(feature = "devnet")]
pub const SLOT_DURATION_MS: u64 = 500;
#[cfg(not(feature = "devnet"))]
pub const SLOT_DURATION_MS: u64 = 400;

/// Builder window: number of slots the designated builder has to submit a
/// valid finality certificate before being slashed. (K in the paper)
pub const K_BUILDER_SLOTS: u64 = 3;

/// Backup window: number of additional slots after builder timeout for a
/// backup prover to submit a proof. (K' in the paper)
pub const K_BACKUP_SLOTS: u64 = 3;

/// Maximum proof-bundle entries accepted by the STARK verifier.
///
/// This limits individual proof bundles, NOT the number of transactions per
/// block.
pub const MAX_PROOF_BUNDLE_ENTRIES: usize = 1_536;

/// Maximum transactions per block.
///
/// Derived from first-principles throughput modelling on 32-core server
/// hardware (Aptos-class c5a.16xlarge):
///
///   Pure native transfers (in-memory, rayon parallel):
///     ~136,000 tx/slot → 340,000 TPS
///   Mixed workload (60% native + 20% SVM + 20% EVM):
///     ~50,000–120,000 tx/slot
///   Persistent storage (RocksDB + NVMe):
///     ~30,000–75,000 tx/slot
///
/// 80,000 is the cap — not the target.  Actual throughput is determined by
/// execution speed and I/O.  This value avoids being an artificial bottleneck
/// while staying within the network propagation budget of a 10–25 Gbps NIC
/// (80,000 × ~300 B/tx ≈ 24 MB/block at 2.5 blocks/s ≈ 60 MB/s).
pub const MAX_TXS_PER_BLOCK: usize = 80_000;

/// Initial transaction budget for the first proposal. The adaptive proposal
/// builder adjusts this budget each round based on measured execution time,
/// targeting `PROPOSAL_BUILD_TARGET_MS`.
///
/// Keep this low so that when traffic suddenly arrives after an idle period,
/// the first heavy block is small enough for all validators to have already
/// prefetched full credentials before a compact proposal arrives.  The budget
/// grows from observed build timing when the network path is healthy.
pub const PROPOSAL_TX_INITIAL_BUDGET: usize = 256;

/// Maximum wall-clock time (ms) allowed for compact-proposal transaction
/// reconstruction (all TxFetch attempts combined).  Set to 2/3 of
/// PROPOSE_TIMEOUT_MS, leaving the remaining third for block validation and
/// vote exchange.  The node enforces this as an absolute deadline; any retry
/// that would start after the deadline is abandoned immediately.
///
/// Both the node (reconstruction deadline) and the P2P service (channel
/// TTL cleanup) use this constant; keep them in sync.
#[cfg(feature = "devnet")]
pub const TX_FETCH_RECONSTRUCT_BUDGET_MS: u64 = PROPOSE_TIMEOUT_MS * 2 / 3; // ~3 333 ms
#[cfg(not(feature = "devnet"))]
pub const TX_FETCH_RECONSTRUCT_BUDGET_MS: u64 = PROPOSE_TIMEOUT_MS * 2 / 3; // 2 000 ms

/// Maximum number of TxFetch retry attempts for compact-proposal reconstruction.
///
/// This is an upper bound on retries; the node-side absolute deadline
/// (TX_FETCH_RECONSTRUCT_BUDGET_MS) will stop further attempts before this
/// count is reached if the budget is exhausted.  Changing this value requires
/// reviewing TX_FETCH_PER_ATTEMPT_TIMEOUT_MS to confirm the budget is still
/// respected in practice.
pub const COMPACT_TX_FETCH_MAX_RETRIES: u8 = 3;

/// Per-attempt libp2p network timeout for a single TxFetch request.
///
/// Strategy: devnet keeps the original 5 000 ms (proven stable); non-devnet
/// uses TX_FETCH_RECONSTRUCT_BUDGET_MS (2 000 ms) so a single attempt cannot
/// outlast the total budget.
///
/// Note: on devnet, 3 × 5 000 ms = 15 000 ms > TX_FETCH_RECONSTRUCT_BUDGET_MS
/// (~3 333 ms).  This is intentional — the per-attempt value is not required
/// to satisfy max_retries × per_attempt ≤ budget.  The node-side absolute
/// deadline (TX_FETCH_RECONSTRUCT_BUDGET_MS) enforces the hard bound across
/// all attempts and will abandon reconstruction before the retry count is
/// exhausted if the budget runs out first.
#[cfg(feature = "devnet")]
pub const TX_FETCH_PER_ATTEMPT_TIMEOUT_MS: u64 = 5_000;
#[cfg(not(feature = "devnet"))]
pub const TX_FETCH_PER_ATTEMPT_TIMEOUT_MS: u64 = TX_FETCH_RECONSTRUCT_BUDGET_MS; // 2 000 ms

/// Number of consecutive zero-tx proposals before the budget is reset to
/// `PROPOSAL_TX_INITIAL_BUDGET` on the next non-empty block.
///
/// After a long idle period the proposer's budget may sit at MAX.  For PQC
/// workloads, large first blocks can force validators to fetch full credentials
/// during compact-proposal reconstruction.  Resetting the budget after an idle
/// streak keeps the first loaded block conservatively sized; AR-ACE prefetch
/// then has time to converge before the budget grows.
pub const IDLE_RESET_EMPTY_THRESHOLD: u32 = 10;

/// Normal operating floor for the adaptive proposal budget after a compact
/// proposal miss.  Moderate misses (hit_rate 70–85%) reduce budget but not
/// below this value; only a streak of severe misses (≥ SEVERE_MISS_STREAK_THRESHOLD)
/// is allowed to drop further to PROPOSAL_TX_EMERGENCY_FLOOR.
pub const PROPOSAL_TX_NORMAL_FLOOR: usize = 320;

/// Emergency floor for the adaptive proposal budget.  Only reached after
/// SEVERE_MISS_STREAK_THRESHOLD consecutive severe compact-proposal misses.
/// Semantically equivalent to the former INITIAL_BUDGET role in miss paths;
/// PROPOSAL_TX_INITIAL_BUDGET is retained for cold-start / build_ms / round>0
/// paths unchanged.
pub const PROPOSAL_TX_EMERGENCY_FLOOR: usize = 256;

/// Number of consecutive severe compact-proposal misses (hit_rate < 70% while
/// EWMA also < 85%) required before the budget is dropped to EMERGENCY_FLOOR.
pub const SEVERE_MISS_STREAK_THRESHOLD: u32 = 3;

/// Number of consecutive healthy compact-proposal blocks required before the
/// budget is allowed to increment by BUDGET_RECOVERY_STEP toward MAX_BUDGET.
/// "Healthy" requires: hit_rate_ewma >= 95%, round == 0, mempool not congested.
pub const HEALTHY_STREAK_THRESHOLD: u32 = 12;

/// Blocks to freeze the budget after any downward adjustment.  During this
/// window the EWMA and streak counters continue updating; only the budget
/// write is suppressed to prevent multiple rapid adjustments on the same miss
/// cluster.
pub const BUDGET_COOLDOWN_BLOCKS: u32 = 8;

/// EWMA smoothing factor for compact-proposal hit rate.  α = 0.2 weights the
/// last ~4–5 blocks while keeping the estimate stable against single-block
/// spikes.
pub const HIT_RATE_EWMA_ALPHA: f64 = 0.2;

/// Budget increment per healthy recovery step.
pub const BUDGET_RECOVERY_STEP: usize = 32;

/// Hard upper bound for the adaptive proposal budget. Even if execution is
/// fast, the budget never exceeds this. Validators must ALSO execute the
/// entire block at commit time, so this must leave room for:
///   propose_execute + network + vote_exchange + commit_execute < round_timeout
///
/// Measured on devnet (3 nodes, 500ms BLOCK_INTERVAL):
///   build_ms ≈ 60ms/256tx → 0.235ms/tx → natural stable point = 250/0.235 ≈ 1061 tx.
///   At 1000 tx: build_ms ≈ 236ms, block cycle ≈ 736ms → ~1359 TPS ceiling.
///
/// Capped at 400 for 3-node devnet: at larger budgets the compact proposal
/// hit rate drops below 90%, triggering graduated miss feedback that halves
/// the budget in two consecutive rounds.  The sudden drop from 500+ to 256
/// causes the runner to overshoot mempool pending by ~1000 in 5 seconds,
/// pushing follower hit rates to 43% and triggering round=1 cascades.
/// 400 tx/block keeps hit rate reliably >90% and avoids this instability.
pub const PROPOSAL_TX_MAX_BUDGET: usize = 400;

/// Target wall-clock time (ms) for `execute_block_preview`.
/// Must fit comfortably inside a sub-slot budget so compact propagation,
/// validation, vote exchange, and commit-time execution do not spill into a
/// Tendermint timeout cascade.
pub const PROPOSAL_BUILD_TARGET_MS: u64 = 250;

/// Maximum binary block size admitted by the runtime.
///
/// Sized for up to 80,000 transactions at ~300 bytes each (≈ 24 MB) plus
/// header overhead, with headroom for outlier payloads.
pub const MAX_BLOCK_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

/// Maximum serialized P2P message size.
///
/// Must accommodate a full block (up to 32 MiB) plus the accompanying
/// finality certificate in block-sync responses.
pub const MAX_P2P_MESSAGE_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// BFT quorum numerator (2/3 supermajority).
pub const QUORUM_NUMERATOR: u64 = 2;

/// BFT quorum denominator.
pub const QUORUM_DENOMINATOR: u64 = 3;

/// Maximum builder timeout in milliseconds: K * SLOT_DURATION_MS.
pub const BUILDER_TIMEOUT_MS: u64 = K_BUILDER_SLOTS * SLOT_DURATION_MS;

/// Maximum total timeout (builder + backup) in milliseconds.
pub const TOTAL_TIMEOUT_MS: u64 = (K_BUILDER_SLOTS + K_BACKUP_SLOTS) * SLOT_DURATION_MS;

/// Tendermint propose timeout in milliseconds.
/// Devnet keeps a multi-slot safety margin but fails compact-proposal
/// reconstruction fast enough that a miss does not create a 10s+ TPS hole.
/// Mainnet: 3s (allows global propagation).
/// Set to 8000ms on devnet: under 500 TPS load the proposer occasionally
/// needs >5s to build and broadcast, causing spurious round=0 timeouts that
/// flood the mempool and disrupt nonce state. 8s provides headroom without
/// meaningfully slowing round-miss recovery.
#[cfg(feature = "devnet")]
pub const PROPOSE_TIMEOUT_MS: u64 = 8000;
#[cfg(not(feature = "devnet"))]
pub const PROPOSE_TIMEOUT_MS: u64 = 3000;

/// Tendermint prevote timeout in milliseconds.
/// Devnet keeps several 500 ms slots of slack without turning each round miss
/// into a long empty window.
#[cfg(feature = "devnet")]
pub const PREVOTE_TIMEOUT_MS: u64 = 2500;
#[cfg(not(feature = "devnet"))]
pub const PREVOTE_TIMEOUT_MS: u64 = 1000;

/// Tendermint precommit timeout in milliseconds.
/// Devnet mirrors prevote timeout.
#[cfg(feature = "devnet")]
pub const PRECOMMIT_TIMEOUT_MS: u64 = 2500;
#[cfg(not(feature = "devnet"))]
pub const PRECOMMIT_TIMEOUT_MS: u64 = 1000;

/// Per-round timeout increase in milliseconds (Tendermint).
pub const TIMEOUT_DELTA_MS: u64 = 200;

/// Minimum block interval in milliseconds (Tendermint).
/// After committing a block, the node waits at least this long before
/// starting the next height. This paces block production independently
/// of the round timeout parameters.
#[cfg(feature = "devnet")]
pub const BLOCK_INTERVAL_MS: u64 = 500;
#[cfg(not(feature = "devnet"))]
pub const BLOCK_INTERVAL_MS: u64 = 1000;

/// Commit-wait timeout in milliseconds (Tendermint).
/// After reaching ⅔ precommits, the node waits this long to collect
/// additional precommits before advancing to the next height.
/// This improves commit certificate completeness for the next proposer.
/// Devnet: 50ms — with faster heartbeat (100ms) and plaintext gossip,
/// late precommits arrive quickly; 200ms was excessive and added a
/// fixed per-block tax that hurt multi-node throughput.
#[cfg(feature = "devnet")]
pub const COMMIT_WAIT_MS: u64 = 20;
#[cfg(not(feature = "devnet"))]
pub const COMMIT_WAIT_MS: u64 = 200;

/// GPU parallelism factor for proof generation.
///
/// 1,024 reflects data-centre GPUs (A100 / H100 class).  The previous value
/// of 128 corresponded to consumer RTX 4090 hardware.
pub const GPU_THREAD_PARALLELISM: usize = 1_024;

/// Mock proof size in bytes (used by MockProver for deterministic test proofs).
pub const MOCK_PROOF_BYTES: usize = 256;

/// Checks whether a quorum is reached given votes and total stake.
///
/// Returns `false` for zero total stake (empty validator set).
#[inline]
pub fn has_quorum(votes: u64, total_stake: u64) -> bool {
    if total_stake == 0 {
        return false;
    }
    // votes / total_stake >= QUORUM_NUMERATOR / QUORUM_DENOMINATOR
    // Rewritten to avoid floating-point: votes * DENOM >= NUM * total_stake
    // Use u128 to prevent overflow with large stake values.
    (votes as u128) * (QUORUM_DENOMINATOR as u128)
        >= (QUORUM_NUMERATOR as u128) * (total_stake as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_exact_two_thirds() {
        assert!(has_quorum(2, 3));
        assert!(has_quorum(4, 6));
        assert!(has_quorum(67, 100));
    }

    #[test]
    fn test_quorum_below_threshold() {
        assert!(!has_quorum(1, 3));
        assert!(!has_quorum(66, 100));
    }

    #[test]
    fn test_quorum_above_threshold() {
        assert!(has_quorum(3, 3));
        assert!(has_quorum(100, 100));
    }

    #[test]
    fn test_timeout_constants() {
        assert_eq!(BUILDER_TIMEOUT_MS, K_BUILDER_SLOTS * SLOT_DURATION_MS);
        assert_eq!(
            TOTAL_TIMEOUT_MS,
            (K_BUILDER_SLOTS + K_BACKUP_SLOTS) * SLOT_DURATION_MS
        );
        assert_eq!(MAX_PROOF_BUNDLE_ENTRIES, 1_536);
        assert_eq!(MAX_TXS_PER_BLOCK, 80_000);
        assert_eq!(MAX_BLOCK_BYTES, 32 * 1024 * 1024);
        assert_eq!(MAX_P2P_MESSAGE_BYTES, 64 * 1024 * 1024);
    }

    #[test]
    fn test_quorum_zero_stake() {
        // Empty validator set must never reach quorum
        assert!(!has_quorum(0, 0));
        assert!(!has_quorum(1, 0));
    }

    #[test]
    fn test_quorum_no_overflow() {
        // Values near u64::MAX that would overflow with plain u64 multiplication
        assert!(has_quorum(u64::MAX, u64::MAX)); // 100% ≥ ⅔
        assert!(!has_quorum(0, u64::MAX)); // 0% < ⅔
                                           // Boundary with large values
        let total = u64::MAX / 3;
        assert!(has_quorum(total, total)); // 100% ≥ ⅔
        assert!(!has_quorum(1, u64::MAX)); // ε% < ⅔
    }
}
