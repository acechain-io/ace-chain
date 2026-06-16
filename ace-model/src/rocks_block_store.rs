//! RocksDB-backed block and finality certificate storage.
//!
//! Uses column families to separate blocks, finality certificates, finality states,
//! and metadata. All keys are 8-byte big-endian slot numbers (for natural sort order)
//! except the hash→slot index which uses 32-byte block hashes.

use std::path::Path;
use std::sync::Arc;

use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};

use ace_runtime::types::block::Block;
use ace_runtime::types::finality::{FinalityCertificate, FinalityState};

use crate::block_store::BlockStore;

/// Column family names.
const CF_BLOCKS: &str = "blocks";
const CF_HASH_INDEX: &str = "hash_index";
const CF_FINALITY_CERTS: &str = "finality_certs";
const CF_FINALITY_STATES: &str = "finality_states";
const CF_META: &str = "meta";

const META_LATEST_SLOT: &[u8] = b"latest_slot";

/// RocksDB-backed block store for production use.
pub struct RocksDbBlockStore {
    db: Arc<DB>,
}

impl RocksDbBlockStore {
    /// Open or create a RocksDB block store at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(256);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_HASH_INDEX, Options::default()),
            ColumnFamilyDescriptor::new(CF_FINALITY_CERTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_FINALITY_STATES, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Self { db: Arc::new(db) })
    }

    fn slot_key(slot: u64) -> [u8; 8] {
        slot.to_be_bytes()
    }
}

impl BlockStore for RocksDbBlockStore {
    fn get_block_by_slot(&self, slot: u64) -> Option<Block> {
        let cf = self.db.cf_handle(CF_BLOCKS)?;
        let data = self.db.get_cf(&cf, Self::slot_key(slot)).ok()??;
        match bincode::deserialize(&data) {
            Ok(block) => Some(block),
            Err(e) => {
                tracing::error!(
                    "get_block_by_slot: failed to deserialize block at slot {slot}: {e}"
                );
                None
            }
        }
    }

    fn get_block_by_hash(&self, hash: &[u8; 32]) -> Option<Block> {
        let cf_idx = self.db.cf_handle(CF_HASH_INDEX)?;
        let slot_bytes = self.db.get_cf(&cf_idx, hash).ok()??;
        if slot_bytes.len() != 8 {
            return None;
        }
        let slot = u64::from_be_bytes(slot_bytes.try_into().ok()?);
        self.get_block_by_slot(slot)
    }

    fn put_block(&mut self, block: Block) {
        let slot = block.header.slot;
        let hash = block.hash();
        let key = Self::slot_key(slot);

        let cf_blocks = match self.db.cf_handle(CF_BLOCKS) {
            Some(cf) => cf,
            None => {
                tracing::error!("put_block: missing column family '{CF_BLOCKS}'");
                return;
            }
        };
        let cf_idx = match self.db.cf_handle(CF_HASH_INDEX) {
            Some(cf) => cf,
            None => {
                tracing::error!("put_block: missing column family '{CF_HASH_INDEX}'");
                return;
            }
        };
        let cf_meta = match self.db.cf_handle(CF_META) {
            Some(cf) => cf,
            None => {
                tracing::error!("put_block: missing column family '{CF_META}'");
                return;
            }
        };

        // Remove old hash index if overwriting a slot
        if let Ok(Some(old_data)) = self.db.get_cf(&cf_blocks, key) {
            if let Ok(old_block) = bincode::deserialize::<Block>(&old_data) {
                let old_hash = old_block.hash();
                if old_hash != hash {
                    let _ = self.db.delete_cf(&cf_idx, old_hash);
                }
            }
        }

        let encoded = match bincode::serialize(&block) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("put_block: failed to serialize block at slot {slot}: {e}");
                return;
            }
        };

        // Use WriteBatch for atomic writes
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf_blocks, key, &encoded);
        batch.put_cf(&cf_idx, hash, slot.to_be_bytes());

        // Update latest slot
        let current_latest = self.latest_slot();
        if slot > current_latest {
            batch.put_cf(&cf_meta, META_LATEST_SLOT, slot.to_be_bytes());
        }

        if let Err(e) = self.db.write(batch) {
            tracing::error!("put_block: WriteBatch failed for slot {slot}: {e}");
        }
    }

    fn delete_block_by_slot(&mut self, slot: u64) -> Option<Block> {
        let cf_blocks = self.db.cf_handle(CF_BLOCKS)?;
        let cf_idx = self.db.cf_handle(CF_HASH_INDEX)?;
        let cf_certs = self.db.cf_handle(CF_FINALITY_CERTS)?;
        let cf_states = self.db.cf_handle(CF_FINALITY_STATES)?;
        let cf_meta = self.db.cf_handle(CF_META)?;

        let key = Self::slot_key(slot);
        let data = self.db.get_cf(&cf_blocks, key).ok()??;
        let block: Block = bincode::deserialize(&data).ok()?;
        let hash = block.hash();

        let mut batch = WriteBatch::default();
        batch.delete_cf(&cf_blocks, key);
        batch.delete_cf(&cf_idx, hash);
        batch.delete_cf(&cf_certs, key);
        batch.delete_cf(&cf_states, key);

        // Update latest slot if we deleted the tip
        if self.latest_slot() == slot {
            // Scan backwards to find new latest
            let mut new_latest = 0u64;
            let iter = self.db.iterator_cf(&cf_blocks, rocksdb::IteratorMode::End);
            for item in iter {
                if let Ok((k, _)) = item {
                    if k.len() == 8 {
                        let candidate = u64::from_be_bytes(k[..8].try_into().unwrap_or([0; 8]));
                        if candidate != slot {
                            new_latest = candidate;
                            break;
                        }
                    }
                }
            }
            batch.put_cf(&cf_meta, META_LATEST_SLOT, new_latest.to_be_bytes());
        }

        if let Err(e) = self.db.write(batch) {
            tracing::error!("delete_block_by_slot: WriteBatch failed for slot {slot}: {e}");
        }

        Some(block)
    }

    fn latest_slot(&self) -> u64 {
        let cf_meta = match self.db.cf_handle(CF_META) {
            Some(cf) => cf,
            None => return 0,
        };
        match self.db.get_cf(&cf_meta, META_LATEST_SLOT) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
            }
            _ => 0,
        }
    }

    fn get_finality_cert(&self, slot: u64) -> Option<FinalityCertificate> {
        let cf = self.db.cf_handle(CF_FINALITY_CERTS)?;
        let data = self.db.get_cf(&cf, Self::slot_key(slot)).ok()??;
        match bincode::deserialize(&data) {
            Ok(cert) => Some(cert),
            Err(e) => {
                tracing::error!(
                    "get_finality_cert: failed to deserialize cert at slot {slot}: {e}"
                );
                None
            }
        }
    }

    fn put_finality_cert(&mut self, cert: FinalityCertificate) {
        let cf = match self.db.cf_handle(CF_FINALITY_CERTS) {
            Some(cf) => cf,
            None => {
                tracing::error!("put_finality_cert: missing column family '{CF_FINALITY_CERTS}'");
                return;
            }
        };
        let encoded = match bincode::serialize(&cert) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    "put_finality_cert: failed to serialize cert at slot {}: {e}",
                    cert.slot
                );
                return;
            }
        };
        if let Err(e) = self.db.put_cf(&cf, Self::slot_key(cert.slot), &encoded) {
            tracing::error!(
                "put_finality_cert: RocksDB write failed for slot {}: {e}",
                cert.slot
            );
        }
    }

    fn get_finality_state(&self, slot: u64) -> Option<FinalityState> {
        let cf = self.db.cf_handle(CF_FINALITY_STATES)?;
        let data = self.db.get_cf(&cf, Self::slot_key(slot)).ok()??;
        match bincode::deserialize(&data) {
            Ok(state) => Some(state),
            Err(e) => {
                tracing::error!(
                    "get_finality_state: failed to deserialize state at slot {slot}: {e}"
                );
                None
            }
        }
    }

    fn set_finality_state(&mut self, slot: u64, state: FinalityState) {
        let cf = match self.db.cf_handle(CF_FINALITY_STATES) {
            Some(cf) => cf,
            None => {
                tracing::error!("set_finality_state: missing column family '{CF_FINALITY_STATES}'");
                return;
            }
        };
        let encoded = match bincode::serialize(&state) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    "set_finality_state: failed to serialize state at slot {slot}: {e}"
                );
                return;
            }
        };
        if let Err(e) = self.db.put_cf(&cf, Self::slot_key(slot), &encoded) {
            tracing::error!("set_finality_state: RocksDB write failed for slot {slot}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_runtime::types::block::{Block, BlockHeader};
    use ace_runtime::types::finality::FinalityState;
    use tempfile::TempDir;

    fn make_test_block(slot: u64) -> Block {
        Block {
            header: BlockHeader {
                slot,
                parent_hash: [0u8; 32],
                state_root: [1u8; 32],
                tx_merkle_root: [2u8; 32],
                attest_merkle_root: [2u8; 32],
                poh_hash: [4u8; 32],
                leader_idcom: [3u8; 32],
                timestamp: 1000 + slot * 400,
                tx_count: 0,
                round: 0,
            },
            transactions: vec![],
        }
    }

    #[test]
    fn test_put_and_get_block() {
        let tmp = TempDir::new().unwrap();
        let mut store = RocksDbBlockStore::open(tmp.path().join("blocks")).unwrap();

        let block = make_test_block(1);
        let hash = block.hash();

        store.put_block(block.clone());

        let retrieved = store.get_block_by_slot(1).unwrap();
        assert_eq!(retrieved.header.slot, 1);

        let by_hash = store.get_block_by_hash(&hash).unwrap();
        assert_eq!(by_hash.header.slot, 1);

        assert_eq!(store.latest_slot(), 1);
    }

    #[test]
    fn test_delete_block() {
        let tmp = TempDir::new().unwrap();
        let mut store = RocksDbBlockStore::open(tmp.path().join("blocks")).unwrap();

        store.put_block(make_test_block(1));
        store.put_block(make_test_block(2));
        assert_eq!(store.latest_slot(), 2);

        let deleted = store.delete_block_by_slot(2);
        assert!(deleted.is_some());
        assert_eq!(store.latest_slot(), 1);
        assert!(store.get_block_by_slot(2).is_none());
    }

    #[test]
    fn test_finality_state() {
        let tmp = TempDir::new().unwrap();
        let mut store = RocksDbBlockStore::open(tmp.path().join("blocks")).unwrap();

        store.set_finality_state(5, FinalityState::Soft);
        assert_eq!(store.get_finality_state(5), Some(FinalityState::Soft));

        store.set_finality_state(5, FinalityState::Hard);
        assert_eq!(store.get_finality_state(5), Some(FinalityState::Hard));
    }

    #[test]
    fn test_persistence_across_reopen() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("blocks");

        {
            let mut store = RocksDbBlockStore::open(&path).unwrap();
            store.put_block(make_test_block(10));
            store.set_finality_state(10, FinalityState::Hard);
        }

        // Reopen and verify data persisted
        let store = RocksDbBlockStore::open(&path).unwrap();
        assert_eq!(store.latest_slot(), 10);
        assert!(store.get_block_by_slot(10).is_some());
        assert_eq!(store.get_finality_state(10), Some(FinalityState::Hard));
    }

    #[test]
    fn test_empty_store() {
        let tmp = TempDir::new().unwrap();
        let store = RocksDbBlockStore::open(tmp.path().join("blocks")).unwrap();

        assert_eq!(store.latest_slot(), 0);
        assert!(store.get_block_by_slot(0).is_none());
        assert!(store.get_finality_state(0).is_none());
    }
}
