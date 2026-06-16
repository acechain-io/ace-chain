//! Block and finality certificate storage.
//!
//! Provides a trait for block persistence and an in-memory implementation
//! for the MVP. The consensus layer writes blocks; the RPC layer reads them.

use std::collections::{HashMap, VecDeque};

use ace_runtime::types::block::Block;
use ace_runtime::types::finality::{FinalityCertificate, FinalityState};
use ace_runtime::types::transaction::Transaction;

/// Trait for block and finality certificate storage.
///
/// The consensus engine calls `put_block` / `put_finality_cert` / `set_finality_state`
/// on block production. The RPC layer calls the getters to serve queries.
///
/// Returns owned values to support both in-memory and disk-backed implementations.
pub trait BlockStore: Send + Sync {
    fn get_block_by_slot(&self, slot: u64) -> Option<Block>;
    fn get_block_by_hash(&self, hash: &[u8; 32]) -> Option<Block>;
    fn put_block(&mut self, block: Block);
    fn delete_block_by_slot(&mut self, slot: u64) -> Option<Block>;
    fn latest_slot(&self) -> u64;
    fn get_finality_cert(&self, slot: u64) -> Option<FinalityCertificate>;
    fn put_finality_cert(&mut self, cert: FinalityCertificate);
    fn get_finality_state(&self, slot: u64) -> Option<FinalityState>;
    fn set_finality_state(&mut self, slot: u64, state: FinalityState);

    /// Linear scan of `1..=latest_slot()` (devnet-friendly). Prefer a tx index at scale.
    fn find_transaction_by_hash(&self, tx_hash: &[u8; 32]) -> Option<Transaction> {
        let latest = self.latest_slot();
        for slot in 1..=latest {
            if let Some(block) = self.get_block_by_slot(slot) {
                for tx in &block.transactions {
                    if tx.tx_hash() == *tx_hash {
                        return Some(tx.clone());
                    }
                }
            }
        }
        None
    }
}

/// Default maximum number of blocks to retain in memory.
const DEFAULT_MAX_BLOCKS: usize = 10_000;

/// In-memory block store for the MVP.
///
/// Bounded: when the store exceeds `max_blocks`, the oldest blocks (by insertion
/// order) are evicted along with their finality certificates and states.
pub struct InMemoryBlockStore {
    blocks_by_slot: HashMap<u64, Block>,
    blocks_by_hash: HashMap<[u8; 32], u64>,
    finality_certs: HashMap<u64, FinalityCertificate>,
    finality_states: HashMap<u64, FinalityState>,
    latest_slot: u64,
    insertion_order: VecDeque<u64>,
    max_blocks: usize,
}

impl InMemoryBlockStore {
    pub fn new() -> Self {
        Self {
            blocks_by_slot: HashMap::new(),
            blocks_by_hash: HashMap::new(),
            finality_certs: HashMap::new(),
            finality_states: HashMap::new(),
            latest_slot: 0,
            insertion_order: VecDeque::new(),
            max_blocks: DEFAULT_MAX_BLOCKS,
        }
    }

    /// Create a new store with a custom capacity limit.
    pub fn with_max_blocks(max_blocks: usize) -> Self {
        Self {
            max_blocks,
            ..Self::new()
        }
    }
}

impl Default for InMemoryBlockStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockStore for InMemoryBlockStore {
    fn get_block_by_slot(&self, slot: u64) -> Option<Block> {
        self.blocks_by_slot.get(&slot).cloned()
    }

    fn get_block_by_hash(&self, hash: &[u8; 32]) -> Option<Block> {
        self.blocks_by_hash
            .get(hash)
            .and_then(|slot| self.blocks_by_slot.get(slot))
            .cloned()
    }

    fn put_block(&mut self, block: Block) {
        let slot = block.header.slot;
        let hash = block.hash();
        if slot > self.latest_slot {
            self.latest_slot = slot;
        }
        // Remove stale hash index if overwriting a slot
        let is_overwrite = if let Some(old_block) = self.blocks_by_slot.get(&slot) {
            let old_hash = old_block.hash();
            if old_hash != hash {
                self.blocks_by_hash.remove(&old_hash);
            }
            true
        } else {
            false
        };
        self.blocks_by_hash.insert(hash, slot);
        self.blocks_by_slot.insert(slot, block);

        // Track insertion order (only for genuinely new slots, not overwrites)
        if !is_overwrite {
            self.insertion_order.push_back(slot);
        }

        // Evict oldest blocks if over capacity
        while self.blocks_by_slot.len() > self.max_blocks {
            if let Some(old_slot) = self.insertion_order.pop_front() {
                if let Some(old_block) = self.blocks_by_slot.remove(&old_slot) {
                    self.blocks_by_hash.remove(&old_block.hash());
                }
                self.finality_certs.remove(&old_slot);
                self.finality_states.remove(&old_slot);
            } else {
                break;
            }
        }
    }

    fn delete_block_by_slot(&mut self, slot: u64) -> Option<Block> {
        let removed = self.blocks_by_slot.remove(&slot)?;
        let removed_hash = removed.hash();
        self.blocks_by_hash.remove(&removed_hash);
        self.finality_certs.remove(&slot);
        self.finality_states.remove(&slot);
        self.insertion_order.retain(|&s| s != slot);

        if self.latest_slot == slot {
            self.latest_slot = self.blocks_by_slot.keys().copied().max().unwrap_or(0);
        }

        Some(removed)
    }

    fn latest_slot(&self) -> u64 {
        self.latest_slot
    }

    fn get_finality_cert(&self, slot: u64) -> Option<FinalityCertificate> {
        self.finality_certs.get(&slot).cloned()
    }

    fn put_finality_cert(&mut self, cert: FinalityCertificate) {
        self.finality_certs.insert(cert.slot, cert);
    }

    fn get_finality_state(&self, slot: u64) -> Option<FinalityState> {
        self.finality_states.get(&slot).copied()
    }

    fn set_finality_state(&mut self, slot: u64, state: FinalityState) {
        self.finality_states.insert(slot, state);
    }
}
