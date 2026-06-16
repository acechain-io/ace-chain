//! Phase 1b: Parallel Execution (Algorithm 1, lines 10–13 in the paper).
//!
//! Executes validated transactions using a Sealevel-enhanced parallel model.
//! Non-conflicting transactions run in parallel; conflicting ones serialize.
//!
//! ## Simplification
//!
//! This reference implementation performs simplified execution:
//! - Validates transaction format
//! - Produces a state delta (hash of payload as a proxy for state changes)
//!
//! A full implementation would include the Sealevel dependency graph,
//! account state management, and program invocation.

use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::types::transaction::Transaction;

/// A state delta produced by executing a single transaction.
///
/// In a full implementation, this would contain read/write sets and
/// account state changes. Here it's a simplified representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDelta {
    /// Hash identifying the transaction that produced this delta.
    pub tx_hash: [u8; 32],
    /// Simplified state change representation.
    pub delta_hash: [u8; 32],
    /// Whether execution succeeded.
    pub success: bool,
}

/// Execute a batch of validated transactions in parallel.
///
/// This is Phase 1b of the Attest–Execute–Prove pipeline.
///
/// # Arguments
/// - `txs`: Transactions that passed attestation check (Phase 1a).
///
/// # Returns
/// A vector of [`StateDelta`]s, one per transaction.
pub fn execute_transactions(txs: &[Transaction]) -> Vec<StateDelta> {
    txs.par_iter().map(execute_single).collect()
}

/// Execute a single transaction (simplified).
///
/// In a real implementation, this would:
/// 1. Load account state
/// 2. Invoke the program/contract
/// 3. Validate state transitions
/// 4. Produce a state delta
///
/// Here we compute a deterministic delta from the payload.
fn execute_single(tx: &Transaction) -> StateDelta {
    // Use the canonical credential-independent tx hash, not obj_hash (which is
    // only the payload hash and not the transaction identifier).
    let tx_hash = tx.tx_hash();

    // Simplified execution: hash only the payload for a deterministic delta.
    // Credential bytes are intentionally excluded: gossip-relayed txs may have
    // their ML-DSA-44 credential stripped (AR-ACE relay path), so including
    // them would produce different delta_hashes across nodes and break the
    // state root computation.
    let mut hasher = Sha256::new();
    hasher.update(b"STATE_DELTA_V1");
    hasher.update(&tx.payload);
    let result = hasher.finalize();
    let mut delta_hash = [0u8; 32];
    delta_hash.copy_from_slice(&result);

    StateDelta {
        tx_hash,
        delta_hash,
        success: true,
    }
}

/// Compute the aggregate state root from a set of state deltas.
///
/// This is a simplified Merkle root over all delta hashes.
pub fn compute_state_root(deltas: &[StateDelta]) -> [u8; 32] {
    if deltas.is_empty() {
        return [0u8; 32];
    }

    let mut hashes: Vec<[u8; 32]> = deltas.iter().map(|d| d.delta_hash).collect();

    while hashes.len() > 1 {
        let mut next = Vec::with_capacity(hashes.len().div_ceil(2));
        for pair in hashes.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            if pair.len() > 1 {
                hasher.update(pair[1]);
            } else {
                hasher.update(pair[0]);
            }
            let result = hasher.finalize();
            let mut h = [0u8; 32];
            h.copy_from_slice(&result);
            next.push(h);
        }
        hashes = next;
    }

    hashes[0]
}
