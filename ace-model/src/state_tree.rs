//! Binary Merkle state tree over accounts.
//!
//! Uses SHA-256 consistent with ace-runtime's Merkle root computation
//! (see `compute_tx_merkle_root` in `ace-runtime/src/types/block.rs`).
//! Odd nodes are hashed with themselves following the same convention.
//!
//! Supports two-tier storage:
//! - **Hot tier**: full `Account` objects in a sorted `BTreeMap`.
//! - **Stub tier**: expired accounts compressed to 32-byte hash stubs.
//!
//! Both tiers participate in Merkle root computation.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

use crate::account::{Account, AccountId, AccountStub, ResurrectionProof};

fn account_evm_address(account: &Account) -> [u8; 20] {
    account
        .evm_address
        .unwrap_or_else(|| derive_evm_address(&account.id_com))
}

fn account_tron_address(account: &Account) -> [u8; 20] {
    account
        .tron_address
        .unwrap_or_else(|| derive_tron_address(&account.id_com))
}

/// Derive a 20-byte EVM address from an ACE AccountId.
///
/// `SHA-256("evm:" || id_com)[12..32]`
///
/// Lives in ace-model so the StateTree can maintain an incremental
/// EVM address index without circular dependencies on ace-n-vm.
pub fn derive_evm_address(id_com: &AccountId) -> [u8; 20] {
    let mut hasher = Sha256::new();
    hasher.update(b"evm:");
    hasher.update(id_com.as_bytes());
    let result = hasher.finalize();

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&result[12..32]);
    addr
}

/// Derive a 20-byte TRON address from an ACE AccountId.
///
/// `SHA-256("tron:" || id_com)[12..32]`
///
/// Uses a distinct domain separator from EVM so the same AccountId
/// maps to different addresses in EVM and TRON contexts.
pub fn derive_tron_address(id_com: &AccountId) -> [u8; 20] {
    let mut hasher = Sha256::new();
    hasher.update(b"tron:");
    hasher.update(id_com.as_bytes());
    let result = hasher.finalize();

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&result[12..32]);
    addr
}

use std::sync::Arc;

/// In-memory state tree backed by reference-counted BTreeMaps.
///
/// Uses Arc to enable O(1) clones during parallel execution batches.
/// Write operations use make_mut() to perform Copy-on-Write (COW).
#[derive(Debug, Clone)]
pub struct StateTree {
    accounts: Arc<BTreeMap<AccountId, Account>>,
    /// Expired accounts compressed to hash stubs.
    stubs: Arc<BTreeMap<AccountId, AccountStub>>,
    /// Contract storage: account → (slot → value).
    contract_storage: Arc<BTreeMap<AccountId, BTreeMap<[u8; 32], [u8; 32]>>>,
    /// XID index: ACE-GF wallet fingerprint → ACE AccountId.
    xid_index: Arc<HashMap<[u8; 32], AccountId>>,
    /// Incremental EVM address index.
    evm_index: Arc<HashMap<[u8; 20], AccountId>>,
    /// Incremental TRON address index.
    tron_index: Arc<HashMap<[u8; 20], AccountId>>,
    /// Solana Ed25519 pubkey index.
    solana_index: Arc<HashMap<[u8; 32], AccountId>>,
    /// Bitcoin script pubkey index.
    btc_index: Arc<HashMap<Vec<u8>, AccountId>>,
    /// PQC xaddress fingerprint index.
    xaddress_index: Arc<HashMap<[u8; 32], AccountId>>,
    /// On-chain HFI Pay intent store — part of consensus state.
    ///
    /// Keyed by `intent_id` (32 bytes). Values are opaque borsh-encoded
    /// `OnChainIntent` bytes, owned by `ace_hfi_pay::onchain`. We store
    /// bytes instead of the typed struct so `ace-model` does not need
    /// to depend on `ace-hfi-pay`. Each intent contributes an extra Merkle leaf
    /// after all account leaves: `SHA-256(b"hfi:intent:v1:" || intent_id || value_bytes)`.
    hfi_intents: Arc<BTreeMap<[u8; 32], Vec<u8>>>,
    /// On-chain HFI Pay recipient registry — part of consensus state.
    ///
    /// Keyed by `id_hash` (32 bytes, salted SHA-256 of the normalized
    /// identifier). Values are opaque borsh-encoded `RegisteredRecipient`
    /// bytes owned by `ace_hfi_pay::registry`. Each entry contributes an extra
    /// Merkle leaf appended after intent leaves:
    /// `SHA-256(b"hfi:recipient:v1:" || id_hash || value_bytes)`.
    hfi_recipients: Arc<BTreeMap<[u8; 32], Vec<u8>>>,
    /// Secondary index `identity_commitment → id_hash` for the recipient
    /// registry, so on-chain handlers (e.g. HfiPayCreate) can resolve a
    /// registered recipient from the `identity_commitment` already present in
    /// the intent payload without learning the raw identifier.
    hfi_idcom_index: Arc<BTreeMap<[u8; 32], [u8; 32]>>,
    /// ZK-ACE replay registry. Keyed by `rp_com`; value is the submitting idcom.
    zk_replay_registry: Arc<BTreeMap<[u8; 32], [u8; 32]>>,
}

impl StateTree {
    /// Create an empty state tree.
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(BTreeMap::new()),
            stubs: Arc::new(BTreeMap::new()),
            contract_storage: Arc::new(BTreeMap::new()),
            xid_index: Arc::new(HashMap::new()),
            evm_index: Arc::new(HashMap::new()),
            tron_index: Arc::new(HashMap::new()),
            solana_index: Arc::new(HashMap::new()),
            btc_index: Arc::new(HashMap::new()),
            xaddress_index: Arc::new(HashMap::new()),
            hfi_intents: Arc::new(BTreeMap::new()),
            hfi_recipients: Arc::new(BTreeMap::new()),
            hfi_idcom_index: Arc::new(BTreeMap::new()),
            zk_replay_registry: Arc::new(BTreeMap::new()),
        }
    }

    // ── ZK-ACE replay registry (on-chain consensus state) ──

    /// Return true iff the replay-prevention commitment has already been consumed.
    pub fn zk_replay_contains(&self, rp_com: &[u8; 32]) -> bool {
        self.zk_replay_registry.contains_key(rp_com)
    }

    /// Consume a replay-prevention commitment.
    ///
    /// Returns `false` when the commitment already exists.
    pub fn zk_replay_consume(&mut self, rp_com: [u8; 32], idcom: [u8; 32]) -> bool {
        let registry = Arc::make_mut(&mut self.zk_replay_registry);
        if registry.contains_key(&rp_com) {
            return false;
        }
        registry.insert(rp_com, idcom);
        true
    }

    /// Iterate over consumed ZK-ACE replay commitments in deterministic order.
    pub fn iter_zk_replay_registry(&self) -> impl Iterator<Item = (&[u8; 32], &[u8; 32])> {
        self.zk_replay_registry.iter()
    }

    /// Number of consumed ZK-ACE replay commitments.
    pub fn zk_replay_count(&self) -> usize {
        self.zk_replay_registry.len()
    }

    // ── HFI Pay recipient registry (on-chain consensus state) ──

    /// Get the raw encoded recipient bytes by id_hash, if present.
    pub fn hfi_recipient(&self, id_hash: &[u8; 32]) -> Option<&[u8]> {
        self.hfi_recipients.get(id_hash).map(|v| v.as_slice())
    }

    /// Resolve a recipient by `identity_commitment` via the secondary index.
    /// Returns `(id_hash, encoded_recipient_bytes)` if registered.
    pub fn hfi_recipient_by_idcom(&self, idcom: &[u8; 32]) -> Option<(&[u8; 32], &[u8])> {
        let id_hash = self.hfi_idcom_index.get(idcom)?;
        let bytes = self.hfi_recipients.get(id_hash)?;
        Some((id_hash, bytes.as_slice()))
    }

    /// Insert or overwrite a recipient registry entry. Maintains the idcom
    /// index automatically: the new `identity_commitment` is mapped to
    /// `id_hash`, and any prior idcom mapping for `id_hash` is removed.
    pub fn hfi_recipient_put(
        &mut self,
        id_hash: [u8; 32],
        identity_commitment: [u8; 32],
        bytes: Vec<u8>,
    ) {
        // Remove any stale idcom → id_hash entry that previously pointed here.
        let prev_idcom = self.hfi_recipients.get(&id_hash).and_then(|prev_bytes| {
            // Recipient encoding starts with 32B xid, 32B account_id, 32B idcom...
            if prev_bytes.len() >= 96 {
                let mut prev = [0u8; 32];
                prev.copy_from_slice(&prev_bytes[64..96]);
                Some(prev)
            } else {
                None
            }
        });
        if let Some(prev) = prev_idcom {
            if prev != identity_commitment {
                Arc::make_mut(&mut self.hfi_idcom_index).remove(&prev);
            }
        }
        Arc::make_mut(&mut self.hfi_recipients).insert(id_hash, bytes);
        Arc::make_mut(&mut self.hfi_idcom_index).insert(identity_commitment, id_hash);
    }

    /// Iterate over all recipient entries in deterministic id_hash order.
    pub fn hfi_recipients_iter(&self) -> impl Iterator<Item = (&[u8; 32], &[u8])> {
        self.hfi_recipients.iter().map(|(k, v)| (k, v.as_slice()))
    }

    /// Number of recipients in the registry.
    pub fn hfi_recipient_count(&self) -> usize {
        self.hfi_recipients.len()
    }

    // ── HFI Pay intent store (on-chain consensus state) ──

    /// Get the raw encoded intent bytes, if present.
    pub fn hfi_intent(&self, intent_id: &[u8; 32]) -> Option<&[u8]> {
        self.hfi_intents.get(intent_id).map(|v| v.as_slice())
    }

    /// Insert or overwrite an intent's encoded bytes.
    pub fn hfi_intent_put(&mut self, intent_id: [u8; 32], bytes: Vec<u8>) {
        Arc::make_mut(&mut self.hfi_intents).insert(intent_id, bytes);
    }

    /// Remove an intent. Returns the previous bytes if any.
    pub fn hfi_intent_remove(&mut self, intent_id: &[u8; 32]) -> Option<Vec<u8>> {
        Arc::make_mut(&mut self.hfi_intents).remove(intent_id)
    }

    /// Iterate over all intents in deterministic id order.
    pub fn hfi_intents_iter(&self) -> impl Iterator<Item = (&[u8; 32], &[u8])> {
        self.hfi_intents.iter().map(|(k, v)| (k, v.as_slice()))
    }

    /// Number of intents in the store.
    pub fn hfi_intent_count(&self) -> usize {
        self.hfi_intents.len()
    }

    /// Get an immutable reference to an account.
    pub fn get(&self, id: &AccountId) -> Option<&Account> {
        self.accounts.get(id)
    }

    /// Get a mutable reference to an account.
    pub fn get_mut(&mut self, id: &AccountId) -> Option<&mut Account> {
        Arc::make_mut(&mut self.accounts).get_mut(id)
    }

    /// Insert or update an account.
    ///
    /// Also maintains the EVM address index incrementally.
    pub fn insert(&mut self, account: Account) {
        // Clear any expired stub for this id to prevent dual-existence
        // (e.g. when a raw-chain tx auto-creates a previously expired account).
        Arc::make_mut(&mut self.stubs).remove(&account.id_com);

        // Collect old index keys before mutating, to batch COW clones.
        // Reading through Arc does NOT trigger COW; only make_mut does.
        let old_keys = self.accounts.get(&account.id_com).map(|existing| {
            (
                account_evm_address(existing),
                account_tron_address(existing),
                existing.xid,
                existing.solana_address,
                existing.btc_address.clone(),
                existing.xaddress,
            )
        });

        // Compute new index keys from the incoming account.
        let new_evm = account_evm_address(&account);
        let new_tron = account_tron_address(&account);
        let id_com = account.id_com;

        // Single COW clone per index: remove old + insert new in one pass.
        let evm_idx = Arc::make_mut(&mut self.evm_index);
        if let Some((ref old_evm, _, _, _, _, _)) = old_keys {
            evm_idx.remove(old_evm);
        }
        if !evm_idx.contains_key(&new_evm) || evm_idx[&new_evm] == id_com {
            evm_idx.insert(new_evm, id_com);
        }

        let tron_idx = Arc::make_mut(&mut self.tron_index);
        if let Some((_, ref old_tron, _, _, _, _)) = old_keys {
            tron_idx.remove(old_tron);
        }
        if !tron_idx.contains_key(&new_tron) || tron_idx[&new_tron] == id_com {
            tron_idx.insert(new_tron, id_com);
        }

        let xid_idx = Arc::make_mut(&mut self.xid_index);
        if let Some((_, _, Some(ref old_xid), _, _, _)) = old_keys {
            xid_idx.remove(old_xid);
        }
        if let Some(xid) = &account.xid {
            if !xid_idx.contains_key(xid) || xid_idx[xid] == id_com {
                xid_idx.insert(*xid, id_com);
            }
        }

        let sol_idx = Arc::make_mut(&mut self.solana_index);
        if let Some((_, _, _, Some(ref old_sol), _, _)) = old_keys {
            sol_idx.remove(old_sol);
        }
        if let Some(sol) = &account.solana_address {
            if !sol_idx.contains_key(sol) || sol_idx[sol] == id_com {
                sol_idx.insert(*sol, id_com);
            }
        }

        let btc_idx = Arc::make_mut(&mut self.btc_index);
        if let Some((_, _, _, _, Some(ref old_btc), _)) = old_keys {
            btc_idx.remove(old_btc);
        }
        if let Some(btc) = &account.btc_address {
            if !btc_idx.contains_key(btc) || btc_idx[btc] == id_com {
                btc_idx.insert(btc.clone(), id_com);
            }
        }

        let xa_idx = Arc::make_mut(&mut self.xaddress_index);
        if let Some((_, _, _, _, _, Some(ref old_xa))) = old_keys {
            xa_idx.remove(old_xa);
        }
        if let Some(xa) = &account.xaddress {
            if !xa_idx.contains_key(xa) || xa_idx[xa] == id_com {
                xa_idx.insert(*xa, id_com);
            }
        }

        Arc::make_mut(&mut self.accounts).insert(id_com, account);
    }

    /// Remove an account by id. Returns the removed account if it existed.
    ///
    /// Also removes the corresponding EVM address index entry.
    pub fn remove(&mut self, id: &AccountId) -> Option<Account> {
        let account = Arc::make_mut(&mut self.accounts).remove(id)?;
        let evm_addr = account_evm_address(&account);
        Arc::make_mut(&mut self.evm_index).remove(&evm_addr);
        let tron_addr = account_tron_address(&account);
        Arc::make_mut(&mut self.tron_index).remove(&tron_addr);
        if let Some(xid) = &account.xid {
            Arc::make_mut(&mut self.xid_index).remove(xid);
        }
        if let Some(sol) = &account.solana_address {
            Arc::make_mut(&mut self.solana_index).remove(sol);
        }
        if let Some(btc) = &account.btc_address {
            Arc::make_mut(&mut self.btc_index).remove(btc);
        }
        if let Some(xa) = &account.xaddress {
            Arc::make_mut(&mut self.xaddress_index).remove(xa);
        }
        Arc::make_mut(&mut self.contract_storage).remove(id);
        Some(account)
    }

    /// Check whether an account exists in the hot tier.
    pub fn contains(&self, id: &AccountId) -> bool {
        self.accounts.contains_key(id)
    }

    /// Number of accounts in the hot tier.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Iterate over all hot accounts (sorted by AccountId).
    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &Account)> {
        self.accounts.iter()
    }

    // ── EVM address index ──

    /// Resolve an EVM 20-byte address to the corresponding ACE AccountId.
    ///
    /// O(1) via the incremental index maintained by `insert()` / `remove()`.
    pub fn resolve_evm(&self, evm_addr: &[u8; 20]) -> Option<&AccountId> {
        self.evm_index.get(evm_addr)
    }

    /// Resolve an EVM address to an account id, falling back to legacy raw-chain
    /// account ids that may predate explicit address aliases.
    pub fn resolve_evm_account_id(&self, evm_addr: &[u8; 20]) -> Option<AccountId> {
        self.resolve_evm(evm_addr).copied().or_else(|| {
            let legacy = AccountId::from_bytes(ace_runtime::crypto::legacy_idcom_evm(evm_addr));
            self.accounts.contains_key(&legacy).then_some(legacy)
        })
    }

    /// Resolve a TRON 20-byte address to the corresponding ACE AccountId.
    ///
    /// O(1) via the incremental index maintained by `insert()` / `remove()`.
    pub fn resolve_tron(&self, tron_addr: &[u8; 20]) -> Option<&AccountId> {
        self.tron_index.get(tron_addr)
    }

    /// Resolve a TRON address to an account id, falling back to legacy raw-chain
    /// account ids that may predate explicit address aliases.
    pub fn resolve_tron_account_id(&self, tron_addr: &[u8; 20]) -> Option<AccountId> {
        self.resolve_tron(tron_addr).copied().or_else(|| {
            let legacy = AccountId::from_bytes(ace_runtime::crypto::legacy_idcom_tron(tron_addr));
            self.accounts.contains_key(&legacy).then_some(legacy)
        })
    }

    /// Return the canonical EVM address for an account, if it exists.
    pub fn evm_address(&self, id: &AccountId) -> Option<[u8; 20]> {
        self.accounts.get(id).map(account_evm_address)
    }

    /// Return the canonical TRON address for an account, if it exists.
    pub fn tron_address(&self, id: &AccountId) -> Option<[u8; 20]> {
        self.accounts.get(id).map(account_tron_address)
    }

    // ── XID index ──

    /// Resolve an ACE-GF XID to the corresponding ACE AccountId.
    pub fn resolve_xid(&self, xid: &[u8; 32]) -> Option<&AccountId> {
        self.xid_index.get(xid)
    }

    /// Resolve an XID to an account id, falling back to the deterministic
    /// `idcom_xid` derivation for accounts that may not have the xid field set.
    pub fn resolve_xid_account_id(&self, xid: &[u8; 32]) -> Option<AccountId> {
        self.resolve_xid(xid).copied().or_else(|| {
            let derived = AccountId::from_bytes(ace_runtime::crypto::idcom_xid(xid));
            self.accounts.contains_key(&derived).then_some(derived)
        })
    }

    // ── Solana index ──

    /// Resolve a Solana Ed25519 public key to the corresponding ACE AccountId.
    pub fn resolve_solana(&self, pubkey: &[u8; 32]) -> Option<&AccountId> {
        self.solana_index.get(pubkey)
    }

    /// Resolve a Solana pubkey to an account id, falling back to legacy derivation.
    pub fn resolve_solana_account_id(&self, pubkey: &[u8; 32]) -> Option<AccountId> {
        self.resolve_solana(pubkey).copied().or_else(|| {
            let legacy = AccountId::from_bytes(ace_runtime::crypto::legacy_idcom_solana(pubkey));
            self.accounts.contains_key(&legacy).then_some(legacy)
        })
    }

    // ── Bitcoin index ──

    /// Resolve a Bitcoin script pubkey to the corresponding ACE AccountId.
    pub fn resolve_btc(&self, script: &[u8]) -> Option<&AccountId> {
        self.btc_index.get(script)
    }

    /// Resolve a Bitcoin script to an account id, falling back to legacy derivation.
    pub fn resolve_btc_account_id(&self, script: &[u8]) -> Option<AccountId> {
        self.resolve_btc(script).copied().or_else(|| {
            let legacy =
                AccountId::from_bytes(ace_runtime::crypto::legacy_idcom_btc_script(script));
            self.accounts.contains_key(&legacy).then_some(legacy)
        })
    }

    // ── xaddress (PQC) index ──

    /// Resolve a PQC xaddress fingerprint to the corresponding ACE AccountId.
    pub fn resolve_xaddress(&self, xaddress: &[u8; 32]) -> Option<&AccountId> {
        self.xaddress_index.get(xaddress)
    }

    /// Resolve an xaddress fingerprint to an account id.
    pub fn resolve_xaddress_account_id(&self, xaddress: &[u8; 32]) -> Option<AccountId> {
        self.resolve_xaddress(xaddress).copied()
    }

    // ── Contract storage ──

    /// Get a storage value for an account. Returns zero-bytes if unset.
    pub fn get_storage(&self, account: &AccountId, slot: &[u8; 32]) -> [u8; 32] {
        self.contract_storage
            .get(account)
            .and_then(|m| m.get(slot))
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// Set a storage value for an account.
    pub fn set_storage(&mut self, account: &AccountId, slot: [u8; 32], value: [u8; 32]) {
        Arc::make_mut(&mut self.contract_storage)
            .entry(*account)
            .or_default()
            .insert(slot, value);
    }

    /// Get the full storage map for an account (if any).
    pub fn get_account_storage(
        &self,
        account: &AccountId,
    ) -> Option<&BTreeMap<[u8; 32], [u8; 32]>> {
        self.contract_storage.get(account)
    }

    /// Store bytecode for an account and update its code_hash.
    /// Returns the code_hash.
    pub fn set_code(&mut self, account: &AccountId, code: Vec<u8>) -> Option<[u8; 32]> {
        let acct = Arc::make_mut(&mut self.accounts).get_mut(account)?;
        let mut hasher = Sha256::new();
        hasher.update(&code);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        acct.code_hash = Some(hash);
        acct.code = Some(code);
        Some(hash)
    }

    /// Get bytecode for an account.
    pub fn get_code(&self, account: &AccountId) -> Option<&[u8]> {
        self.accounts.get(account).and_then(|a| a.code.as_deref())
    }

    // ── Stub tier (state expiry) ──

    /// Check if an account has been expired to a stub.
    pub fn is_stubbed(&self, id: &AccountId) -> bool {
        self.stubs.contains_key(id)
    }

    /// Get the stub for an expired account.
    pub fn get_stub(&self, id: &AccountId) -> Option<&AccountStub> {
        self.stubs.get(id)
    }

    /// Insert a stub directly (used by `load_tree` during DB restore).
    pub fn insert_stub(&mut self, stub: AccountStub) {
        Arc::make_mut(&mut self.stubs).insert(stub.id_com, stub);
    }

    /// Iterate over all stubs (sorted by AccountId).
    pub fn iter_stubs(&self) -> impl Iterator<Item = (&AccountId, &AccountStub)> {
        self.stubs.iter()
    }

    /// Iterate over all HFI recipient registry entries (id_hash → encoded bytes).
    pub fn iter_hfi_recipients(&self) -> impl Iterator<Item = (&[u8; 32], &Vec<u8>)> {
        self.hfi_recipients.iter()
    }

    /// Number of expired account stubs.
    pub fn stub_count(&self) -> usize {
        self.stubs.len()
    }

    /// Expire an account: move from hot tier to stub tier.
    ///
    /// The full account data and storage are hashed into a 32-byte stub.
    /// Returns the stub if successful, `None` if account not found.
    pub fn expire_account(&mut self, id: &AccountId, current_slot: u64) -> Option<AccountStub> {
        let account = Arc::make_mut(&mut self.accounts).remove(id)?;
        let storage = Arc::make_mut(&mut self.contract_storage).remove(id);
        let stub = AccountStub {
            id_com: *id,
            hash: account.compute_stub_hash(storage.as_ref()),
            expired_at_slot: current_slot,
        };
        let evm_addr = account_evm_address(&account);
        Arc::make_mut(&mut self.evm_index).remove(&evm_addr);
        let tron_addr = account_tron_address(&account);
        Arc::make_mut(&mut self.tron_index).remove(&tron_addr);
        if let Some(xid) = &account.xid {
            Arc::make_mut(&mut self.xid_index).remove(xid);
        }
        if let Some(sol) = &account.solana_address {
            Arc::make_mut(&mut self.solana_index).remove(sol);
        }
        if let Some(btc) = &account.btc_address {
            Arc::make_mut(&mut self.btc_index).remove(btc);
        }
        if let Some(xa) = &account.xaddress {
            Arc::make_mut(&mut self.xaddress_index).remove(xa);
        }
        // Insert into stub tier
        Arc::make_mut(&mut self.stubs).insert(*id, stub);
        Some(stub)
    }

    /// Resurrect an expired account using a resurrection proof.
    ///
    /// Verifies that the proof hashes to the stored stub, then restores
    /// the account and its storage to the hot tier.
    pub fn resurrect_account(
        &mut self,
        proof: &ResurrectionProof,
        new_slot: u64,
    ) -> Result<(), &'static str> {
        let stub = self
            .stubs
            .get(&proof.account.id_com)
            .ok_or("account is not expired")?;
        if !proof.verify(stub) {
            return Err("resurrection proof does not match stub hash");
        }
        // Remove stub
        Arc::make_mut(&mut self.stubs).remove(&proof.account.id_com);
        // Restore account with updated last_touched_slot
        let mut restored = proof.account.clone();
        restored.last_touched_slot = new_slot;
        self.insert(restored);
        // Restore storage
        for (slot, value) in &proof.storage {
            self.set_storage(&proof.account.id_com, *slot, *value);
        }
        Ok(())
    }

    /// Sweep expired accounts. Returns the number of accounts expired.
    ///
    /// An account is eligible for expiry when:
    /// 1. `last_touched_slot + expiry_period < current_slot`
    /// 2. `balance == 0`
    /// 3. `code_hash.is_none()` (v1: don't expire contract accounts)
    pub fn sweep_expired(&mut self, current_slot: u64, expiry_period: u64) -> usize {
        let cutoff = current_slot.saturating_sub(expiry_period);
        let to_expire: Vec<AccountId> = self
            .accounts
            .iter()
            .filter(|(_, acct)| {
                acct.last_touched_slot < cutoff && acct.balance == 0 && acct.code_hash.is_none()
            })
            .map(|(id, _)| *id)
            .collect();
        let count = to_expire.len();
        for id in to_expire {
            self.expire_account(&id, current_slot);
        }
        count
    }

    // ── Merkle root ──

    /// Compute the SHA-256 binary Merkle root over all account hashes.
    ///
    /// Includes both hot accounts and expired stubs in a single sorted
    /// tree keyed by `AccountId`. Stubs contribute their pre-computed
    /// hash directly as a leaf.
    ///
    /// Empty tree returns `SHA-256(b"ACE-EMPTY-STATE-V1")`.
    /// Uses the same odd-node duplication convention as ace-runtime.
    pub fn compute_root(&self) -> [u8; 32] {
        if self.accounts.is_empty()
            && self.stubs.is_empty()
            && self.hfi_intents.is_empty()
            && self.hfi_recipients.is_empty()
            && self.zk_replay_registry.is_empty()
        {
            let hash = Sha256::digest(b"ACE-EMPTY-STATE-V1");
            let mut out = [0u8; 32];
            out.copy_from_slice(&hash);
            return out;
        }

        // Account + stub leaves: same `BTreeMap<&AccountId, _>` ordering as pre–HFI-Pay trees
        // so `state_root` is unchanged when `hfi_intents` is empty.
        let mut leaves: BTreeMap<&AccountId, [u8; 32]> = BTreeMap::new();

        for (id, stub) in self.stubs.iter() {
            leaves.insert(id, stub.hash);
        }

        for (id, acct) in self.accounts.iter() {
            let mut hasher = Sha256::new();
            hasher.update(acct.to_hash_bytes());
            if let Some(storage) = self.contract_storage.get(id) {
                for (slot, value) in storage {
                    hasher.update(slot);
                    hasher.update(value);
                }
            }
            let result = hasher.finalize();
            let mut h = [0u8; 32];
            h.copy_from_slice(&result);
            leaves.insert(id, h);
        }

        let mut hashes: Vec<[u8; 32]> = leaves.values().copied().collect();

        // HFI intents append after account leaves (deterministic `intent_id` order via BTreeMap).
        for (intent_id, value) in self.hfi_intents.iter() {
            let mut hasher = Sha256::new();
            hasher.update(b"hfi:intent:v1:");
            hasher.update(intent_id);
            hasher.update(value);
            let result = hasher.finalize();
            let mut h = [0u8; 32];
            h.copy_from_slice(&result);
            hashes.push(h);
        }

        // HFI recipient registry: deterministic `id_hash` order via BTreeMap.
        // Appended after intent leaves so `state_root` is unchanged when the
        // registry is empty (preserves backward compatibility for chains that
        // never use auto-claim).
        for (id_hash, value) in self.hfi_recipients.iter() {
            let mut hasher = Sha256::new();
            hasher.update(b"hfi:recipient:v1:");
            hasher.update(id_hash);
            hasher.update(value);
            let result = hasher.finalize();
            let mut h = [0u8; 32];
            h.copy_from_slice(&result);
            hashes.push(h);
        }

        // ZK-ACE replay registry: deterministic `rp_com` order via BTreeMap.
        for (rp_com, idcom) in self.zk_replay_registry.iter() {
            let mut hasher = Sha256::new();
            hasher.update(b"zkace:replay:v1:");
            hasher.update(rp_com);
            hasher.update(idcom);
            let result = hasher.finalize();
            let mut h = [0u8; 32];
            h.copy_from_slice(&result);
            hashes.push(h);
        }

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

    // ── Snapshots ──

    /// Take a snapshot of the current state for rollback support.
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            accounts: self.accounts.clone(),
            stubs: self.stubs.clone(),
            contract_storage: self.contract_storage.clone(),
            xid_index: self.xid_index.clone(),
            evm_index: self.evm_index.clone(),
            tron_index: self.tron_index.clone(),
            solana_index: self.solana_index.clone(),
            btc_index: self.btc_index.clone(),
            xaddress_index: self.xaddress_index.clone(),
            hfi_intents: self.hfi_intents.clone(),
            hfi_recipients: self.hfi_recipients.clone(),
            hfi_idcom_index: self.hfi_idcom_index.clone(),
            zk_replay_registry: self.zk_replay_registry.clone(),
        }
    }

    /// Rollback to a previously taken snapshot.
    pub fn rollback(&mut self, snapshot: StateSnapshot) {
        self.accounts = snapshot.accounts;
        self.stubs = snapshot.stubs;
        self.contract_storage = snapshot.contract_storage;
        self.xid_index = snapshot.xid_index;
        self.evm_index = snapshot.evm_index;
        self.tron_index = snapshot.tron_index;
        self.solana_index = snapshot.solana_index;
        self.btc_index = snapshot.btc_index;
        self.xaddress_index = snapshot.xaddress_index;
        self.hfi_intents = snapshot.hfi_intents;
        self.hfi_recipients = snapshot.hfi_recipients;
        self.hfi_idcom_index = snapshot.hfi_idcom_index;
        self.zk_replay_registry = snapshot.zk_replay_registry;
    }
}

impl Default for StateTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable snapshot of a `StateTree` for rollback support.
///
/// Used by the consensus layer when `FinalityAction::RequeueTxs`
/// triggers a state revert.
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    accounts: Arc<BTreeMap<AccountId, Account>>,
    stubs: Arc<BTreeMap<AccountId, AccountStub>>,
    contract_storage: Arc<BTreeMap<AccountId, BTreeMap<[u8; 32], [u8; 32]>>>,
    xid_index: Arc<HashMap<[u8; 32], AccountId>>,
    evm_index: Arc<HashMap<[u8; 20], AccountId>>,
    tron_index: Arc<HashMap<[u8; 20], AccountId>>,
    solana_index: Arc<HashMap<[u8; 32], AccountId>>,
    btc_index: Arc<HashMap<Vec<u8>, AccountId>>,
    xaddress_index: Arc<HashMap<[u8; 32], AccountId>>,
    hfi_intents: Arc<BTreeMap<[u8; 32], Vec<u8>>>,
    hfi_recipients: Arc<BTreeMap<[u8; 32], Vec<u8>>>,
    hfi_idcom_index: Arc<BTreeMap<[u8; 32], [u8; 32]>>,
    zk_replay_registry: Arc<BTreeMap<[u8; 32], [u8; 32]>>,
}

impl StateSnapshot {
    /// Number of accounts in the snapshot.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }
}
