//! RocksDB-backed state persistence.
//!
//! Stores account data in RocksDB with 32-byte identity commitment keys.
//! Designed to work alongside the in-memory `StateTree` — the tree is the
//! working copy during block execution, and this module persists state
//! at epoch boundaries or on graceful shutdown.

use std::path::Path;
use std::sync::Arc;

use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};

use crate::account::{Account, AccountId, AccountStub};
use crate::error::ModelError;
use crate::sharded_state::{ShardId, ShardedState};
use crate::state_db::StateDB;
use crate::state_tree::StateTree;

/// Column family names.
const CF_ACCOUNTS: &str = "accounts";
const CF_STORAGE: &str = "contract_storage";
const CF_META: &str = "state_meta";
const CF_STUBS: &str = "account_stubs";
const CF_HFI_RECIPIENTS: &str = "hfi_recipients";
const CF_ZK_REPLAY: &str = "zk_replay_registry";

const META_STATE_ROOT: &[u8] = b"state_root";
const META_GENESIS_HASH: &[u8] = b"genesis_hash";
const META_GENESIS_TIME_MS: &[u8] = b"genesis_time_ms";
const META_GENESIS_CONFIG_HASH: &[u8] = b"genesis_config_hash";
const META_SHARD_IDS: &[u8] = b"shard_ids";

use ace_runtime::crypto::sig_algo::TaggedPubkey;

/// Persisted account row. Mirrors [`Account`] for bincode serialization.
///
/// Uses [`TaggedPubkey`] for the auth key, which encodes algorithm + bytes.
/// Legacy databases with a bare `[u8; 32]` auth_pubkey are handled by the
/// fallback deserialization path in [`deserialize_account`].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedAccount {
    id_com: AccountId,
    balance: u64,
    nonce: u64,
    code_hash: Option<[u8; 32]>,
    code: Option<Vec<u8>>,
    storage_root: [u8; 32],
    #[serde(default)]
    xid: Option<[u8; 32]>,
    #[serde(default)]
    xaddress: Option<[u8; 32]>,
    #[serde(default)]
    evm_address: Option<[u8; 20]>,
    #[serde(default)]
    tron_address: Option<[u8; 20]>,
    #[serde(default)]
    solana_address: Option<[u8; 32]>,
    #[serde(default)]
    btc_address: Option<Vec<u8>>,
    auth_pubkey: TaggedPubkey,
    #[serde(default)]
    auth_keys: Vec<TaggedPubkey>,
    #[serde(default)]
    last_touched_slot: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyPersistedAccount {
    id_com: AccountId,
    balance: u64,
    nonce: u64,
    code_hash: Option<[u8; 32]>,
    code: Option<Vec<u8>>,
    storage_root: [u8; 32],
    auth_pubkey: TaggedPubkey,
    #[serde(default)]
    last_touched_slot: u64,
}

impl From<&Account> for PersistedAccount {
    fn from(account: &Account) -> Self {
        Self {
            id_com: account.id_com,
            balance: account.balance,
            nonce: account.nonce,
            code_hash: account.code_hash,
            code: account.code.clone(),
            storage_root: account.storage_root,
            xid: account.xid,
            xaddress: account.xaddress,
            evm_address: account.evm_address,
            tron_address: account.tron_address,
            solana_address: account.solana_address,
            btc_address: account.btc_address.clone(),
            auth_pubkey: account.auth_pubkey.clone(),
            auth_keys: account.auth_keys.clone(),
            last_touched_slot: account.last_touched_slot,
        }
    }
}

impl From<PersistedAccount> for Account {
    fn from(account: PersistedAccount) -> Self {
        Account {
            id_com: account.id_com,
            balance: account.balance,
            nonce: account.nonce,
            code_hash: account.code_hash,
            code: account.code,
            storage_root: account.storage_root,
            xid: account.xid,
            xaddress: account.xaddress,
            evm_address: account.evm_address,
            tron_address: account.tron_address,
            solana_address: account.solana_address,
            btc_address: account.btc_address,
            auth_pubkey: account.auth_pubkey,
            auth_keys: account.auth_keys,
            last_touched_slot: account.last_touched_slot,
        }
    }
}

fn serialize_account(account: &Account) -> Result<Vec<u8>, ModelError> {
    bincode::serialize(&PersistedAccount::from(account))
        .map_err(|e| ModelError::StorageError(format!("serialize account: {e}")))
}

fn deserialize_account(data: &[u8]) -> Result<Account, ModelError> {
    match bincode::deserialize::<PersistedAccount>(data) {
        Ok(account) => Ok(account.into()),
        Err(new_err) => match bincode::deserialize::<LegacyPersistedAccount>(data) {
            Ok(account) => Ok(Account {
                id_com: account.id_com,
                balance: account.balance,
                nonce: account.nonce,
                code_hash: account.code_hash,
                code: account.code,
                storage_root: account.storage_root,
                xid: None,
                xaddress: None,
                evm_address: None,
                tron_address: None,
                solana_address: None,
                btc_address: None,
                auth_pubkey: account.auth_pubkey,
                auth_keys: Vec::new(),
                last_touched_slot: account.last_touched_slot,
            }),
            Err(old_err) => Err(ModelError::StorageError(format!(
                "deserialize account: {new_err}; legacy fallback: {old_err}"
            ))),
        },
    }
}

/// RocksDB-backed state database for production use.
pub struct RocksDbStateDB {
    db: Arc<DB>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainIdentityMetadata {
    pub genesis_hash: [u8; 32],
    pub genesis_time_ms: u64,
    pub genesis_config_hash: Option<[u8; 32]>,
}

impl RocksDbStateDB {
    /// Open or create a RocksDB state database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(256);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_ACCOUNTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_STORAGE, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
            ColumnFamilyDescriptor::new(CF_STUBS, Options::default()),
            ColumnFamilyDescriptor::new(CF_HFI_RECIPIENTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_ZK_REPLAY, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Persist the full in-memory StateTree to RocksDB.
    ///
    /// Called at epoch boundaries or on graceful shutdown.
    pub fn persist_tree(&mut self, tree: &StateTree) -> Result<(), ModelError> {
        self.persist_tree_inner(tree, self.chain_identity_metadata())
    }

    /// Persist the full in-memory StateTree and chain metadata to RocksDB.
    pub fn persist_tree_with_metadata(
        &mut self,
        tree: &StateTree,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
    ) -> Result<(), ModelError> {
        self.persist_tree_with_identity(tree, genesis_hash, genesis_time_ms, None)
    }

    /// Persist the full in-memory StateTree and chain identity metadata to RocksDB.
    pub fn persist_tree_with_identity(
        &mut self,
        tree: &StateTree,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
        genesis_config_hash: Option<[u8; 32]>,
    ) -> Result<(), ModelError> {
        self.persist_tree_inner(
            tree,
            Some(ChainIdentityMetadata {
                genesis_hash,
                genesis_time_ms,
                genesis_config_hash,
            }),
        )
    }

    fn persist_tree_inner(
        &mut self,
        tree: &StateTree,
        chain_identity: Option<ChainIdentityMetadata>,
    ) -> Result<(), ModelError> {
        let cf_accounts = self
            .db
            .cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| ModelError::StorageError("cf_accounts not found".into()))?;
        let cf_storage = self
            .db
            .cf_handle(CF_STORAGE)
            .ok_or_else(|| ModelError::StorageError("cf_storage not found".into()))?;
        let cf_meta = self
            .db
            .cf_handle(CF_META)
            .ok_or_else(|| ModelError::StorageError("cf_meta not found".into()))?;
        let cf_stubs = self
            .db
            .cf_handle(CF_STUBS)
            .ok_or_else(|| ModelError::StorageError("cf_stubs not found".into()))?;
        let cf_hfi_recipients = self
            .db
            .cf_handle(CF_HFI_RECIPIENTS)
            .ok_or_else(|| ModelError::StorageError("cf_hfi_recipients not found".into()))?;
        let cf_zk_replay = self
            .db
            .cf_handle(CF_ZK_REPLAY)
            .ok_or_else(|| ModelError::StorageError("cf_zk_replay not found".into()))?;
        let mut batch = WriteBatch::default();
        let range_start = Vec::new();
        let range_end = vec![0xFF; 80];

        // Delete existing rows with range tombstones instead of issuing one
        // delete per key; this keeps full-state rewrites from burning CPU.
        batch.delete_range_cf(&cf_accounts, &range_start, &range_end);
        batch.delete_range_cf(&cf_storage, &range_start, &range_end);
        batch.delete_range_cf(&cf_stubs, &range_start, &range_end);
        batch.delete_range_cf(&cf_hfi_recipients, &range_start, &range_end);
        batch.delete_range_cf(&cf_zk_replay, &range_start, &range_end);

        for (id, account) in tree.iter() {
            let encoded = serialize_account(account)?;
            batch.put_cf(&cf_accounts, id.0, &encoded);

            // Persist contract storage
            if let Some(storage) = tree.get_account_storage(id) {
                for (slot, value) in storage {
                    // Key = account_id(32) || slot(32) = 64 bytes
                    let mut key = Vec::with_capacity(64);
                    key.extend_from_slice(&id.0);
                    key.extend_from_slice(slot);
                    batch.put_cf(&cf_storage, &key, value);
                }
            }
        }

        // Persist expired account stubs
        for (id, stub) in tree.iter_stubs() {
            let encoded = bincode::serialize(stub)
                .map_err(|e| ModelError::StorageError(format!("serialize stub: {e}")))?;
            batch.put_cf(&cf_stubs, id.0, &encoded);
        }

        // Persist HFI recipient registry (consensus state, contributes to state root).
        // Key = id_hash (32 bytes); value = opaque encoded recipient bytes.
        // The secondary idcom index is rebuilt from the value bytes on load.
        for (id_hash, encoded) in tree.iter_hfi_recipients() {
            batch.put_cf(&cf_hfi_recipients, id_hash, encoded);
        }

        // Persist ZK-ACE replay registry. Key = rp_com; value = idcom.
        for (rp_com, idcom) in tree.iter_zk_replay_registry() {
            batch.put_cf(&cf_zk_replay, rp_com, idcom);
        }

        // Store state root
        let root = tree.compute_root();
        batch.put_cf(&cf_meta, META_STATE_ROOT, root);

        if let Some(identity) = chain_identity {
            batch.put_cf(&cf_meta, META_GENESIS_HASH, identity.genesis_hash);
            batch.put_cf(
                &cf_meta,
                META_GENESIS_TIME_MS,
                identity.genesis_time_ms.to_le_bytes(),
            );
            if let Some(genesis_config_hash) = identity.genesis_config_hash {
                batch.put_cf(&cf_meta, META_GENESIS_CONFIG_HASH, genesis_config_hash);
            }
        }

        self.db
            .write(batch)
            .map_err(|e| ModelError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Load the full state from RocksDB into a StateTree.
    ///
    /// Called on node startup to recover state.
    pub fn load_tree(&self) -> Result<StateTree, ModelError> {
        let cf_accounts = self
            .db
            .cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| ModelError::StorageError("cf_accounts not found".into()))?;
        let cf_storage = self
            .db
            .cf_handle(CF_STORAGE)
            .ok_or_else(|| ModelError::StorageError("cf_storage not found".into()))?;

        let mut tree = StateTree::new();

        // Load all accounts
        let iter = self
            .db
            .iterator_cf(&cf_accounts, rocksdb::IteratorMode::Start);
        for item in iter {
            let (_, value) = item.map_err(|e| ModelError::StorageError(e.to_string()))?;
            let account = deserialize_account(&value)?;
            tree.insert(account);
        }

        // Load all contract storage
        let iter = self
            .db
            .iterator_cf(&cf_storage, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| ModelError::StorageError(e.to_string()))?;
            if key.len() == 64 && value.len() == 32 {
                let mut account_id = [0u8; 32];
                account_id.copy_from_slice(&key[..32]);
                let mut slot = [0u8; 32];
                slot.copy_from_slice(&key[32..]);
                let mut val = [0u8; 32];
                val.copy_from_slice(&value);
                tree.set_storage(&AccountId(account_id), slot, val);
            }
        }

        // Load expired account stubs
        if let Some(cf_stubs) = self.db.cf_handle(CF_STUBS) {
            let iter = self.db.iterator_cf(&cf_stubs, rocksdb::IteratorMode::Start);
            for item in iter {
                let (_, value) = item.map_err(|e| ModelError::StorageError(e.to_string()))?;
                let stub: AccountStub = bincode::deserialize(&value)
                    .map_err(|e| ModelError::StorageError(format!("deserialize stub: {e}")))?;
                tree.insert_stub(stub);
            }
        }

        // Load HFI recipient registry and rebuild the secondary idcom index.
        // The identity_commitment occupies bytes [64..96] of the encoded value
        // (see encode_recipient_record layout in ace-hfi-pay).
        if let Some(cf_hfi) = self.db.cf_handle(CF_HFI_RECIPIENTS) {
            let iter = self.db.iterator_cf(&cf_hfi, rocksdb::IteratorMode::Start);
            for item in iter {
                let (key, value) = item.map_err(|e| ModelError::StorageError(e.to_string()))?;
                if key.len() == 32 && value.len() >= 96 {
                    let mut id_hash = [0u8; 32];
                    id_hash.copy_from_slice(&key);
                    let mut idcom = [0u8; 32];
                    idcom.copy_from_slice(&value[64..96]);
                    tree.hfi_recipient_put(id_hash, idcom, value.to_vec());
                }
            }
        }

        if let Some(cf_zk_replay) = self.db.cf_handle(CF_ZK_REPLAY) {
            let iter = self
                .db
                .iterator_cf(&cf_zk_replay, rocksdb::IteratorMode::Start);
            for item in iter {
                let (key, value) = item.map_err(|e| ModelError::StorageError(e.to_string()))?;
                if key.len() == 32 && value.len() == 32 {
                    let mut rp_com = [0u8; 32];
                    rp_com.copy_from_slice(&key);
                    let mut idcom = [0u8; 32];
                    idcom.copy_from_slice(&value);
                    tree.zk_replay_consume(rp_com, idcom);
                }
            }
        }

        Ok(tree)
    }

    /// Get the persisted state root.
    pub fn persisted_state_root(&self) -> Option<[u8; 32]> {
        let cf_meta = self.db.cf_handle(CF_META)?;
        let data = self.db.get_cf(&cf_meta, META_STATE_ROOT).ok()??;
        if data.len() == 32 {
            let mut root = [0u8; 32];
            root.copy_from_slice(&data);
            Some(root)
        } else {
            None
        }
    }

    /// Get persisted chain metadata (genesis hash + genesis time).
    pub fn chain_metadata(&self) -> Option<([u8; 32], u64)> {
        let identity = self.chain_identity_metadata()?;
        Some((identity.genesis_hash, identity.genesis_time_ms))
    }

    /// Get persisted chain identity metadata.
    pub fn chain_identity_metadata(&self) -> Option<ChainIdentityMetadata> {
        let cf_meta = self.db.cf_handle(CF_META)?;
        let genesis_hash = self.db.get_cf(&cf_meta, META_GENESIS_HASH).ok()??;
        let genesis_time_ms = self.db.get_cf(&cf_meta, META_GENESIS_TIME_MS).ok()??;
        if genesis_hash.len() != 32 || genesis_time_ms.len() != 8 {
            return None;
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&genesis_hash);
        let genesis_config_hash = self
            .db
            .get_cf(&cf_meta, META_GENESIS_CONFIG_HASH)
            .ok()
            .flatten()
            .and_then(|bytes| {
                if bytes.len() != 32 {
                    return None;
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                Some(hash)
            });

        Some(ChainIdentityMetadata {
            genesis_hash: hash,
            genesis_time_ms: u64::from_le_bytes(genesis_time_ms[..8].try_into().ok()?),
            genesis_config_hash,
        })
    }

    /// Update just the chain identity metadata without rewriting the state rows.
    pub fn persist_chain_identity_metadata(
        &mut self,
        metadata: ChainIdentityMetadata,
    ) -> Result<(), ModelError> {
        let cf_meta = self
            .db
            .cf_handle(CF_META)
            .ok_or_else(|| ModelError::StorageError("cf_meta not found".into()))?;
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf_meta, META_GENESIS_HASH, metadata.genesis_hash);
        batch.put_cf(
            &cf_meta,
            META_GENESIS_TIME_MS,
            metadata.genesis_time_ms.to_le_bytes(),
        );
        if let Some(genesis_config_hash) = metadata.genesis_config_hash {
            batch.put_cf(&cf_meta, META_GENESIS_CONFIG_HASH, genesis_config_hash);
        }
        self.db
            .write(batch)
            .map_err(|e| ModelError::StorageError(e.to_string()))
    }

    /// Persist all shards of a ShardedState.
    ///
    /// Each shard's accounts are stored with a shard-prefixed key:
    /// shard_id(8 bytes BE) || account_id(32 bytes) = 40 bytes
    /// to distinguish accounts across shards. The default shard (id=0)
    /// uses the original 32-byte keys for backward compatibility.
    pub fn persist_sharded_state(
        &mut self,
        state: &ShardedState,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
    ) -> Result<(), ModelError> {
        let existing_config_hash = self
            .chain_identity_metadata()
            .and_then(|metadata| metadata.genesis_config_hash);
        self.persist_sharded_state_with_identity(
            state,
            genesis_hash,
            genesis_time_ms,
            existing_config_hash,
        )
    }

    /// Persist all shards of a ShardedState plus chain identity metadata.
    pub fn persist_sharded_state_with_identity(
        &mut self,
        state: &ShardedState,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
        genesis_config_hash: Option<[u8; 32]>,
    ) -> Result<(), ModelError> {
        let cf_accounts = self
            .db
            .cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| ModelError::StorageError("cf_accounts not found".into()))?;
        let cf_storage = self
            .db
            .cf_handle(CF_STORAGE)
            .ok_or_else(|| ModelError::StorageError("cf_storage not found".into()))?;
        let cf_meta = self
            .db
            .cf_handle(CF_META)
            .ok_or_else(|| ModelError::StorageError("cf_meta not found".into()))?;
        let cf_stubs = self
            .db
            .cf_handle(CF_STUBS)
            .ok_or_else(|| ModelError::StorageError("cf_stubs not found".into()))?;
        let mut batch = WriteBatch::default();
        let range_start = Vec::new();
        let range_end = vec![0xFF; 80];

        // Delete existing rows with range tombstones instead of per-key
        // deletes; the write path still rewrites the state, but avoids an
        // O(existing_rows) pre-pass for every persist.
        batch.delete_range_cf(&cf_accounts, &range_start, &range_end);
        batch.delete_range_cf(&cf_storage, &range_start, &range_end);
        batch.delete_range_cf(&cf_stubs, &range_start, &range_end);

        // Persist each shard
        let mut shard_ids: Vec<u64> = Vec::new();
        for (&shard_id, tree) in state.iter_shards() {
            shard_ids.push(shard_id.0);
            let is_default = shard_id.0 == 0;

            for (id, account) in tree.iter() {
                let encoded = serialize_account(account)?;
                if is_default {
                    // Default shard: 32-byte key (backward compatible)
                    batch.put_cf(&cf_accounts, id.0, &encoded);
                } else {
                    // Non-default shard: shard_id(8 BE) || account_id(32) = 40 bytes
                    let mut key = Vec::with_capacity(40);
                    key.extend_from_slice(&shard_id.0.to_be_bytes());
                    key.extend_from_slice(&id.0);
                    batch.put_cf(&cf_accounts, &key, &encoded);
                }

                // Persist contract storage
                if let Some(storage) = tree.get_account_storage(id) {
                    for (slot, value) in storage {
                        if is_default {
                            // Default shard: account_id(32) || slot(32) = 64 bytes
                            let mut key = Vec::with_capacity(64);
                            key.extend_from_slice(&id.0);
                            key.extend_from_slice(slot);
                            batch.put_cf(&cf_storage, &key, value);
                        } else {
                            // Non-default: shard_id(8 BE) || account_id(32) || slot(32) = 72 bytes
                            let mut key = Vec::with_capacity(72);
                            key.extend_from_slice(&shard_id.0.to_be_bytes());
                            key.extend_from_slice(&id.0);
                            key.extend_from_slice(slot);
                            batch.put_cf(&cf_storage, &key, value);
                        }
                    }
                }
            }

            // Persist expired account stubs
            for (id, stub) in tree.iter_stubs() {
                let encoded = bincode::serialize(stub)
                    .map_err(|e| ModelError::StorageError(format!("serialize stub: {e}")))?;
                if is_default {
                    batch.put_cf(&cf_stubs, id.0, &encoded);
                } else {
                    let mut key = Vec::with_capacity(40);
                    key.extend_from_slice(&shard_id.0.to_be_bytes());
                    key.extend_from_slice(&id.0);
                    batch.put_cf(&cf_stubs, &key, &encoded);
                }
            }
        }

        // Store shard metadata
        let shard_ids_encoded = bincode::serialize(&shard_ids)
            .map_err(|e| ModelError::StorageError(format!("serialize shard_ids: {e}")))?;
        batch.put_cf(&cf_meta, META_SHARD_IDS, &shard_ids_encoded);

        // Store state root
        let root = state.compute_root();
        batch.put_cf(&cf_meta, META_STATE_ROOT, root);

        // Store chain metadata
        batch.put_cf(&cf_meta, META_GENESIS_HASH, genesis_hash);
        batch.put_cf(
            &cf_meta,
            META_GENESIS_TIME_MS,
            genesis_time_ms.to_le_bytes(),
        );
        if let Some(genesis_config_hash) = genesis_config_hash {
            batch.put_cf(&cf_meta, META_GENESIS_CONFIG_HASH, genesis_config_hash);
        }

        self.db
            .write(batch)
            .map_err(|e| ModelError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Load all shards into a ShardedState.
    ///
    /// If shard metadata exists, loads all shards. Otherwise falls back
    /// to loading a single-shard state (backward compatible with old DBs).
    pub fn load_sharded_state(&self) -> Result<ShardedState, ModelError> {
        let cf_meta = self
            .db
            .cf_handle(CF_META)
            .ok_or_else(|| ModelError::StorageError("cf_meta not found".into()))?;

        // Check for shard metadata
        let shard_ids_data = self
            .db
            .get_cf(&cf_meta, META_SHARD_IDS)
            .map_err(|e| ModelError::StorageError(e.to_string()))?;

        match shard_ids_data {
            Some(data) => {
                let shard_ids: Vec<u64> = bincode::deserialize(&data)
                    .map_err(|e| ModelError::StorageError(format!("deserialize shard_ids: {e}")))?;
                self.load_multi_shard(&shard_ids)
            }
            None => {
                // Backward compatible: load as single shard
                let tree = self.load_tree()?;
                Ok(ShardedState::from_state_tree(tree))
            }
        }
    }

    fn load_multi_shard(&self, shard_ids: &[u64]) -> Result<ShardedState, ModelError> {
        let cf_accounts = self
            .db
            .cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| ModelError::StorageError("cf_accounts not found".into()))?;
        let cf_storage = self
            .db
            .cf_handle(CF_STORAGE)
            .ok_or_else(|| ModelError::StorageError("cf_storage not found".into()))?;

        let mut state = ShardedState::new();

        // Ensure all shards exist
        for &sid in shard_ids {
            if sid != 0 {
                state.shard_mut(ShardId(sid));
            }
        }

        // Load all accounts
        let iter = self
            .db
            .iterator_cf(&cf_accounts, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| ModelError::StorageError(e.to_string()))?;
            let account = deserialize_account(&value)?;
            if key.len() == 32 {
                // Default shard (backward compatible 32-byte key)
                state.shard_mut(ShardId(0)).insert(account);
            } else if key.len() == 40 {
                // Non-default shard: shard_id(8 BE) || account_id(32)
                let shard_id = ShardId(u64::from_be_bytes(key[..8].try_into().unwrap()));
                state.insert_into_shard(shard_id, account);
            }
        }

        // Load all contract storage
        let iter = self
            .db
            .iterator_cf(&cf_storage, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| ModelError::StorageError(e.to_string()))?;
            if key.len() == 64 && value.len() == 32 {
                // Default shard: account_id(32) || slot(32)
                let mut account_id = [0u8; 32];
                account_id.copy_from_slice(&key[..32]);
                let mut slot = [0u8; 32];
                slot.copy_from_slice(&key[32..]);
                let mut val = [0u8; 32];
                val.copy_from_slice(&value);
                state
                    .shard_mut(ShardId(0))
                    .set_storage(&AccountId(account_id), slot, val);
            } else if key.len() == 72 && value.len() == 32 {
                // Non-default shard: shard_id(8 BE) || account_id(32) || slot(32)
                let shard_id = u64::from_be_bytes(key[..8].try_into().unwrap());
                let mut account_id = [0u8; 32];
                account_id.copy_from_slice(&key[8..40]);
                let mut slot = [0u8; 32];
                slot.copy_from_slice(&key[40..72]);
                let mut val = [0u8; 32];
                val.copy_from_slice(&value);
                state
                    .shard_mut(ShardId(shard_id))
                    .set_storage(&AccountId(account_id), slot, val);
            }
        }

        // Load expired account stubs
        if let Some(cf_stubs) = self.db.cf_handle(CF_STUBS) {
            let iter = self.db.iterator_cf(&cf_stubs, rocksdb::IteratorMode::Start);
            for item in iter {
                let (key, value) = item.map_err(|e| ModelError::StorageError(e.to_string()))?;
                let stub: AccountStub = bincode::deserialize(&value)
                    .map_err(|e| ModelError::StorageError(format!("deserialize stub: {e}")))?;
                if key.len() == 32 {
                    state.shard_mut(ShardId(0)).insert_stub(stub);
                } else if key.len() == 40 {
                    let shard_id = u64::from_be_bytes(key[..8].try_into().unwrap());
                    state.shard_mut(ShardId(shard_id)).insert_stub(stub);
                }
            }
        }

        Ok(state)
    }
}

impl StateDB for RocksDbStateDB {
    fn get_account(&self, id: &AccountId) -> Result<Option<Account>, ModelError> {
        let cf = self
            .db
            .cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| ModelError::StorageError("cf_accounts not found".into()))?;
        match self.db.get_cf(&cf, id.0) {
            Ok(Some(data)) => {
                let account = deserialize_account(&data)?;
                Ok(Some(account))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ModelError::StorageError(e.to_string())),
        }
    }

    fn put_account(&mut self, account: &Account) -> Result<(), ModelError> {
        let cf = self
            .db
            .cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| ModelError::StorageError("cf_accounts not found".into()))?;
        let encoded = serialize_account(account)?;
        self.db
            .put_cf(&cf, account.id_com.0, &encoded)
            .map_err(|e| ModelError::StorageError(e.to_string()))
    }

    fn delete_account(&mut self, id: &AccountId) -> Result<(), ModelError> {
        let cf = self
            .db
            .cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| ModelError::StorageError("cf_accounts not found".into()))?;
        self.db
            .delete_cf(&cf, id.0)
            .map_err(|e| ModelError::StorageError(e.to_string()))
    }

    fn has_account(&self, id: &AccountId) -> Result<bool, ModelError> {
        let cf = self
            .db
            .cf_handle(CF_ACCOUNTS)
            .ok_or_else(|| ModelError::StorageError("cf_accounts not found".into()))?;
        match self.db.get_cf(&cf, id.0) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(ModelError::StorageError(e.to_string())),
        }
    }

    fn state_root(&self) -> Result<[u8; 32], ModelError> {
        self.persisted_state_root()
            .ok_or(ModelError::InvalidStateRoot)
    }

    fn get_stub(&self, id: &AccountId) -> Result<Option<AccountStub>, ModelError> {
        let cf = self
            .db
            .cf_handle(CF_STUBS)
            .ok_or_else(|| ModelError::StorageError("cf_stubs not found".into()))?;
        match self.db.get_cf(&cf, id.0) {
            Ok(Some(data)) => {
                let stub: AccountStub = bincode::deserialize(&data)
                    .map_err(|e| ModelError::StorageError(format!("deserialize stub: {e}")))?;
                Ok(Some(stub))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ModelError::StorageError(e.to_string())),
        }
    }

    fn has_stub(&self, id: &AccountId) -> Result<bool, ModelError> {
        let cf = self
            .db
            .cf_handle(CF_STUBS)
            .ok_or_else(|| ModelError::StorageError("cf_stubs not found".into()))?;
        match self.db.get_cf(&cf, id.0) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(ModelError::StorageError(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{Account, AccountId};
    use tempfile::TempDir;

    fn test_account(id_byte: u8, balance: u64) -> Account {
        Account::with_balance(AccountId([id_byte; 32]), balance)
    }

    #[test]
    fn test_put_and_get_account() {
        let tmp = TempDir::new().unwrap();
        let mut db = RocksDbStateDB::open(tmp.path().join("state")).unwrap();

        let acct = test_account(0xAA, 1000);
        db.put_account(&acct).unwrap();

        let retrieved = db.get_account(&acct.id_com).unwrap().unwrap();
        assert_eq!(retrieved.balance, 1000);
        assert!(db.has_account(&acct.id_com).unwrap());
    }

    #[test]
    fn test_delete_account() {
        let tmp = TempDir::new().unwrap();
        let mut db = RocksDbStateDB::open(tmp.path().join("state")).unwrap();

        let acct = test_account(0xBB, 500);
        db.put_account(&acct).unwrap();
        db.delete_account(&acct.id_com).unwrap();

        assert!(!db.has_account(&acct.id_com).unwrap());
        assert!(db.get_account(&acct.id_com).unwrap().is_none());
    }

    #[test]
    fn test_persist_and_load_tree() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state");

        let mut tree = StateTree::new();
        tree.insert(test_account(0x01, 100));
        tree.insert(test_account(0x02, 200));
        tree.set_storage(&AccountId([0x01; 32]), [0x10; 32], [0xFF; 32]);

        let expected_root = tree.compute_root();

        {
            let mut db = RocksDbStateDB::open(&path).unwrap();
            db.persist_tree(&tree).unwrap();
        }

        // Reopen and load
        let db = RocksDbStateDB::open(&path).unwrap();
        let loaded_tree = db.load_tree().unwrap();

        assert_eq!(loaded_tree.account_count(), 2);
        assert_eq!(
            loaded_tree.get(&AccountId([0x01; 32])).unwrap().balance,
            100
        );
        assert_eq!(
            loaded_tree.get(&AccountId([0x02; 32])).unwrap().balance,
            200
        );
        assert_eq!(
            loaded_tree.get_storage(&AccountId([0x01; 32]), &[0x10; 32]),
            [0xFF; 32]
        );
        assert_eq!(loaded_tree.compute_root(), expected_root);
        assert_eq!(db.persisted_state_root(), Some(expected_root));
    }

    #[test]
    fn test_persist_and_load_zk_replay_registry() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state");

        let mut tree = StateTree::new();
        tree.insert(test_account(0x01, 100));
        assert!(tree.zk_replay_consume([0xA1; 32], [0x01; 32]));
        let expected_root = tree.compute_root();

        {
            let mut db = RocksDbStateDB::open(&path).unwrap();
            db.persist_tree(&tree).unwrap();
        }

        let db = RocksDbStateDB::open(&path).unwrap();
        let loaded_tree = db.load_tree().unwrap();

        assert!(loaded_tree.zk_replay_contains(&[0xA1; 32]));
        assert_eq!(loaded_tree.zk_replay_count(), 1);
        assert_eq!(loaded_tree.compute_root(), expected_root);
        assert_eq!(db.persisted_state_root(), Some(expected_root));
    }

    #[test]
    fn test_persist_tree_replaces_removed_rows() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state");
        let owner = AccountId([0x01; 32]);
        let stale = AccountId([0x02; 32]);

        {
            let mut db = RocksDbStateDB::open(&path).unwrap();
            let mut tree = StateTree::new();
            tree.insert(Account::with_balance(owner, 100));
            tree.insert(Account::with_balance(stale, 50));
            tree.set_storage(&owner, [0x10; 32], [0xAB; 32]);
            db.persist_tree_with_metadata(&tree, [0x11; 32], 1234)
                .unwrap();
        }

        {
            let mut db = RocksDbStateDB::open(&path).unwrap();
            let mut tree = StateTree::new();
            tree.insert(Account::with_balance(owner, 999));
            db.persist_tree(&tree).unwrap();
        }

        let db = RocksDbStateDB::open(&path).unwrap();
        let loaded = db.load_tree().unwrap();
        assert_eq!(loaded.account_count(), 1);
        assert!(loaded.get(&stale).is_none());
        assert_eq!(loaded.get(&owner).unwrap().balance, 999);
        assert_eq!(loaded.get_storage(&owner, &[0x10; 32]), [0u8; 32]);
    }

    #[test]
    fn test_chain_metadata_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state");
        let mut tree = StateTree::new();
        tree.insert(test_account(0xAA, 42));

        {
            let mut db = RocksDbStateDB::open(&path).unwrap();
            db.persist_tree_with_metadata(&tree, [0x55; 32], 987_654)
                .unwrap();
        }

        let db = RocksDbStateDB::open(&path).unwrap();
        assert_eq!(db.chain_metadata(), Some(([0x55; 32], 987_654)));
    }

    #[test]
    fn test_chain_identity_metadata_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state");
        let mut tree = StateTree::new();
        tree.insert(test_account(0xAA, 42));

        {
            let mut db = RocksDbStateDB::open(&path).unwrap();
            db.persist_tree_with_identity(&tree, [0x55; 32], 987_654, Some([0x77; 32]))
                .unwrap();
        }

        let db = RocksDbStateDB::open(&path).unwrap();
        assert_eq!(
            db.chain_identity_metadata(),
            Some(ChainIdentityMetadata {
                genesis_hash: [0x55; 32],
                genesis_time_ms: 987_654,
                genesis_config_hash: Some([0x77; 32]),
            })
        );
    }

    #[test]
    fn test_persist_and_load_tree_preserves_contract_code() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state");
        let contract = AccountId([0xCC; 32]);

        let mut tree = StateTree::new();
        tree.insert(Account::with_balance(contract, 0));
        tree.set_code(&contract, vec![0x60, 0x2A, 0x60, 0x00, 0x52]);

        {
            let mut db = RocksDbStateDB::open(&path).unwrap();
            db.persist_tree(&tree).unwrap();
        }

        let db = RocksDbStateDB::open(&path).unwrap();
        let loaded_tree = db.load_tree().unwrap();
        assert_eq!(
            loaded_tree.get_code(&contract),
            Some(&[0x60, 0x2A, 0x60, 0x00, 0x52][..])
        );
    }

    #[test]
    fn test_empty_state() {
        let tmp = TempDir::new().unwrap();
        let db = RocksDbStateDB::open(tmp.path().join("state")).unwrap();

        assert!(!db.has_account(&AccountId([0x01; 32])).unwrap());
        assert!(db.persisted_state_root().is_none());
    }
}
