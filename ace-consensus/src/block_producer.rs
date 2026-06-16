//! Block production orchestration.
//!
//! Uses ace-runtime's `BlockBuilder` for constructing blocks and
//! ace-n-vm's `NVm` for multi-VM state transitions. The block
//! producer is called by the consensus engine when this node is
//! the leader for the current slot.

use tracing::warn;

use ace_model::account::AccountId;
use ace_model::sharded_state::ShardedState;
use ace_n_vm::NVm;
use ace_runtime::types::block::{Block, BlockBuilder, BlockBuilderError};
use ace_runtime::types::transaction::Transaction;

use crate::error::ConsensusError;
use crate::poh::PohChain;

/// Produces blocks from validated transactions.
///
/// Interface between consensus and execution:
/// - Consensus decides *when* and *who* produces a block
/// - BlockProducer decides *how* to build it (execute + assemble)
pub struct BlockProducer;

impl BlockProducer {
    /// Produce a block for the given slot.
    ///
    /// 1. Execute transactions via n-VM with parallel batch scheduling (modifies `state`)
    /// 2. Compute state root from modified state tree
    /// 3. Build block using ace-runtime's `BlockBuilder`
    ///
    /// Transactions with disjoint write sets run in parallel within batches;
    /// batches run sequentially for determinism.
    /// Returns the produced block and execution receipts (for tx index / getTransactionReceipt).
    pub fn produce_block(
        slot: u64,
        parent_hash: [u8; 32],
        leader_idcom: AccountId,
        poh: &mut PohChain,
        state: &mut ShardedState,
        n_vm: &NVm,
        txs: Vec<Transaction>,
    ) -> Result<(Block, Vec<ace_n_vm::VmReceipt>), ConsensusError> {
        let mut preflight_builder = BlockBuilder::new(slot, parent_hash, [0u8; 32], leader_idcom.0);
        let mut selected_txs = Vec::with_capacity(txs.len());
        for tx in txs {
            match preflight_builder.add_transaction(tx.clone()) {
                Ok(()) => selected_txs.push(tx),
                Err(BlockBuilderError::BlockFull) => break,
                Err(BlockBuilderError::BlockTooLarge { .. }) => {
                    warn!(
                        tx_hash = hex::encode(tx.tx_hash()),
                        "Skipping transaction that does not fit within current block byte budget"
                    );
                }
            }
        }

        // Execute transactions via n-VM with parallel batch scheduling
        let receipts = n_vm.execute_block_sharded(state, &selected_txs, slot);

        // Log shard execution summary
        let success_count = receipts.iter().filter(|r| r.success).count();
        let fail_count = receipts.len() - success_count;
        tracing::debug!(
            slot,
            tx_count = receipts.len(),
            success_count,
            fail_count,
            shard_count = state.shard_count(),
            total_accounts = state.total_account_count(),
            "Block produced with sharded execution"
        );

        // Warn about mock-executed transactions (EVM/SVM stubs)
        let mock_count = receipts.iter().filter(|r| r.simulated).count();
        if mock_count > 0 {
            warn!(
                slot,
                mock_count,
                total = receipts.len(),
                "Block contains mock-executed transactions (EVM/SVM stubs)"
            );
        }

        // Compute new state root
        let state_root = state.compute_root();

        // Record block in PoH chain
        poh.record(&slot.to_le_bytes());
        let poh_hash = poh.current_hash();

        // Build block using ace-runtime's BlockBuilder
        let mut builder = BlockBuilder::new(slot, parent_hash, poh_hash, leader_idcom.0);
        for tx in &selected_txs {
            builder
                .add_transaction(tx.clone())
                .map_err(|e| ConsensusError::BlockBuilderError(e.to_string()))?;
        }

        // Timestamp is for display / tooling only; it does not drive consensus.
        // Using system time here; do not use this field for timeouts or slashing without review.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_millis() as u64;

        let block = builder.build(state_root, timestamp);
        Ok((block, receipts))
    }
}
