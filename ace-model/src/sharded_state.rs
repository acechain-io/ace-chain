//! Sharded state: wraps multiple `StateTree` instances keyed by `ShardId`.
//!
//! Each shard maintains an independent state tree. Transactions are routed
//! to the appropriate shard based on their `context_tag` (via HKDF context
//! isolation). Different shards have cryptographically disjoint state,
//! enabling zero-coordination parallel execution.
//!
//! A special "default shard" (shard 0) handles transactions with all-zero
//! context tags for backward compatibility.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::account::{Account, AccountId, AccountStub, ResurrectionProof};
use crate::state_tree::{StateSnapshot, StateTree};

/// Shard identifier (mirrors `ace_n_vm::context::ShardId` to avoid
/// a dependency from ace-model on ace-n-vm).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShardId(pub u64);

impl From<u64> for ShardId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

/// Snapshot of the entire sharded state for rollback support.
#[derive(Debug, Clone)]
pub struct ShardedStateSnapshot {
    snapshots: BTreeMap<ShardId, StateSnapshot>,
    shard_index: std::collections::HashMap<AccountId, ShardId>,
}

/// Multi-shard state container.
///
/// Wraps a `BTreeMap<ShardId, StateTree>` and provides deterministic,
/// ShardId-ordered access across shards. The default shard (id 0) is
/// always present.
#[derive(Debug, Clone)]
pub struct ShardedState {
    shards: BTreeMap<ShardId, StateTree>,
    /// Index for non-deterministic account placement (legacy/manual).
    shard_index: std::collections::HashMap<AccountId, ShardId>,
}

/// Number of virtual shards for stable routing.
const NUM_VIRTUAL_SHARDS: u64 = 1024;

impl ShardedState {
    /// Create a new sharded state with a single default shard.
    pub fn new() -> Self {
        let mut shards = BTreeMap::new();
        shards.insert(ShardId(0), StateTree::new());
        Self {
            shards,
            shard_index: std::collections::HashMap::new(),
        }
    }

    /// Determine the deterministic ShardId for an AccountId.
    ///
    /// Uses virtual shards (fixed at 1024) to ensure routing remains stable
    /// even if physical shards are added or removed.
    pub fn target_shard(&self, id: &AccountId) -> ShardId {
        if let Some(&shard) = self.shard_index.get(id) {
            return shard;
        }
        Self::deterministic_shard(id)
    }

    /// Compute the deterministic ShardId for an AccountId, ignoring the manual index.
    pub fn deterministic_shard(id: &AccountId) -> ShardId {
        let prefix = u16::from_be_bytes([id.0[0], id.0[1]]) as u64;
        ShardId(prefix % NUM_VIRTUAL_SHARDS)
    }

    /// Create from an existing `StateTree` (placed in the default shard).
    ///
    /// This is the primary migration path: existing code using a single
    /// `StateTree` can wrap it in a `ShardedState` with zero overhead.
    pub fn from_state_tree(state: StateTree) -> Self {
        // Do NOT populate shard_index here.  Accounts in the migrated tree
        // live in the default shard (0), and target_shard() will fall back
        // to deterministic routing (prefix-based).  The get/get_mut/contains
        // methods already fall back to shard 0 when the target shard misses,
        // so unindexed accounts are still reachable.  When an account is
        // next written via insert(), it will be placed into its deterministic
        // shard and indexed properly.
        let mut shards = BTreeMap::new();
        shards.insert(ShardId(0), state);
        Self {
            shards,
            shard_index: std::collections::HashMap::new(),
        }
    }

    /// Extract the default shard's `StateTree` (for backward compatibility).
    pub fn into_default_state_tree(mut self) -> StateTree {
        self.shards.remove(&ShardId(0)).unwrap_or_default()
    }

    /// Get a reference to the default shard's `StateTree`.
    pub fn default_shard(&self) -> &StateTree {
        self.shards.get(&ShardId(0)).expect("default shard missing")
    }

    /// Get a mutable reference to the default shard's `StateTree`.
    pub fn default_shard_mut(&mut self) -> &mut StateTree {
        self.shards
            .get_mut(&ShardId(0))
            .expect("default shard missing")
    }

    /// Get or create a shard's `StateTree`.
    pub fn shard_mut(&mut self, id: ShardId) -> &mut StateTree {
        self.shards.entry(id).or_default()
    }

    /// Get a shard's `StateTree` mutably, only if it already exists.
    /// Unlike `shard_mut`, this does NOT create new shards.
    pub fn get_shard_mut(&mut self, id: ShardId) -> Option<&mut StateTree> {
        self.shards.get_mut(&id)
    }

    /// Get a shard's `StateTree` if it exists.
    pub fn shard(&self, id: ShardId) -> Option<&StateTree> {
        self.shards.get(&id)
    }

    /// Number of active shards.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Iterate over all shards.
    pub fn iter_shards(&self) -> impl Iterator<Item = (&ShardId, &StateTree)> {
        self.shards.iter()
    }

    /// Iterate over all shards mutably.
    pub fn iter_shards_mut(&mut self) -> impl Iterator<Item = (&ShardId, &mut StateTree)> {
        self.shards.iter_mut()
    }

    /// Look up an account with O(1) targeting.
    ///
    /// Checks the target shard first; if not found there, falls back to the
    /// default shard (id 0).  This handles accounts created via direct
    /// `StateTree::insert` on the default shard (e.g., transfer auto-create)
    /// that haven't been indexed into `shard_index` yet.
    pub fn get(&self, id: &AccountId) -> Option<&Account> {
        let shard_id = self.target_shard(id);
        if let Some(acct) = self.shards.get(&shard_id).and_then(|s| s.get(id)) {
            return Some(acct);
        }
        // Fallback: check default shard for unindexed accounts.
        if shard_id.0 != 0 {
            if let Some(acct) = self.shards.get(&ShardId(0)).and_then(|s| s.get(id)) {
                return Some(acct);
            }
        }
        None
    }

    /// Look up an account mutably with O(1) targeting.
    pub fn get_mut(&mut self, id: &AccountId) -> Option<&mut Account> {
        let shard_id = self.target_shard(id);
        if self.shards.get(&shard_id).and_then(|s| s.get(id)).is_some() {
            return self.shards.get_mut(&shard_id).and_then(|s| s.get_mut(id));
        }
        // Fallback: check default shard.
        if shard_id.0 != 0
            && self
                .shards
                .get(&ShardId(0))
                .and_then(|s| s.get(id))
                .is_some()
        {
            return self.shards.get_mut(&ShardId(0)).and_then(|s| s.get_mut(id));
        }
        None
    }

    /// Check if an account exists with O(1) targeting.
    pub fn contains(&self, id: &AccountId) -> bool {
        let shard_id = self.target_shard(id);
        if self.shards.get(&shard_id).is_some_and(|s| s.contains(id)) {
            return true;
        }
        // Fallback: check default shard for unindexed accounts.
        shard_id.0 != 0 && self.shards.get(&ShardId(0)).is_some_and(|s| s.contains(id))
    }

    /// Total number of accounts across all shards.
    pub fn total_account_count(&self) -> usize {
        self.shards.values().map(|s| s.account_count()).sum()
    }

    // ── Delegation methods (StateTree-compatible interface) ──

    /// Insert or update an account using O(1) shard targeting.
    ///
    /// The account is placed in its deterministic shard. If it previously
    /// existed in a different shard (e.g. before sharding or manual move),
    /// it is migrated to the new location.
    pub fn insert(&mut self, account: Account) {
        let id = account.id_com;
        let shard_id = self.target_shard(&id);

        // Ensure no duplicates: check indexed location first, then default shard.
        if let Some(&old_shard) = self.shard_index.get(&id) {
            if old_shard != shard_id {
                if let Some(state) = self.shards.get_mut(&old_shard) {
                    state.remove(&id);
                }
            }
        } else if shard_id.0 != 0 {
            // Account may exist unindexed in the default shard (e.g., created
            // by transfer auto-create via StateTree::insert on shard 0).
            // Remove stale copy to prevent duplicates.
            if let Some(default) = self.shards.get_mut(&ShardId(0)) {
                default.remove(&id);
            }
        }

        self.shards.entry(shard_id).or_default().insert(account);
        self.shard_index.insert(id, shard_id);
    }

    /// Insert an account into a specific shard and update the manual index.
    pub fn insert_into_shard(&mut self, shard: ShardId, account: Account) {
        let id = account.id_com;
        // Maintain invariant: each AccountId exists in at most one shard.
        if let Some(&old_shard) = self.shard_index.get(&id) {
            if old_shard != shard {
                if let Some(state) = self.shards.get_mut(&old_shard) {
                    state.remove(&id);
                }
            }
        }
        self.shard_mut(shard).insert(account);
        self.shard_index.insert(id, shard);
    }

    /// Remove an account from whichever shard contains it.
    pub fn remove(&mut self, id: &AccountId) -> Option<Account> {
        for state in self.shards.values_mut() {
            if state.contains(id) {
                let account = state.remove(id);
                if account.is_some() {
                    self.shard_index.remove(id);
                }
                return account;
            }
        }
        None
    }

    /// Number of accounts (alias for total_account_count).
    pub fn account_count(&self) -> usize {
        self.total_account_count()
    }

    /// Iterate over all hot accounts across all shards.
    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &Account)> {
        self.shards.values().flat_map(|s| s.iter())
    }

    // ── Cross-chain address resolution ──

    /// Resolve an EVM address across all shards.
    pub fn resolve_evm(&self, evm_addr: &[u8; 20]) -> Option<AccountId> {
        for state in self.shards.values() {
            if let Some(id) = state.resolve_evm(evm_addr) {
                return Some(*id);
            }
        }
        None
    }

    /// Resolve an EVM address across all shards.
    pub fn resolve_evm_account_id(&self, evm_addr: &[u8; 20]) -> Option<AccountId> {
        for state in self.shards.values() {
            if let Some(id) = state.resolve_evm_account_id(evm_addr) {
                return Some(id);
            }
        }
        None
    }

    /// Resolve a TRON address across all shards.
    pub fn resolve_tron_account_id(&self, tron_addr: &[u8; 20]) -> Option<AccountId> {
        for state in self.shards.values() {
            if let Some(id) = state.resolve_tron_account_id(tron_addr) {
                return Some(id);
            }
        }
        None
    }

    /// Resolve a Solana pubkey across all shards.
    pub fn resolve_solana_account_id(&self, pubkey: &[u8; 32]) -> Option<AccountId> {
        for state in self.shards.values() {
            if let Some(id) = state.resolve_solana_account_id(pubkey) {
                return Some(id);
            }
        }
        None
    }

    /// Resolve a Bitcoin script across all shards.
    pub fn resolve_btc_account_id(&self, script: &[u8]) -> Option<AccountId> {
        for state in self.shards.values() {
            if let Some(id) = state.resolve_btc_account_id(script) {
                return Some(id);
            }
        }
        None
    }

    /// Resolve an XID across all shards.
    pub fn resolve_xid_account_id(&self, xid: &[u8; 32]) -> Option<AccountId> {
        for state in self.shards.values() {
            if let Some(id) = state.resolve_xid_account_id(xid) {
                return Some(id);
            }
        }
        None
    }

    /// Resolve a PQC xaddress fingerprint across all shards.
    pub fn resolve_xaddress_account_id(&self, xaddress: &[u8; 32]) -> Option<AccountId> {
        for state in self.shards.values() {
            if let Some(id) = state.resolve_xaddress_account_id(xaddress) {
                return Some(id);
            }
        }
        None
    }

    /// Return the EVM address for an account across all shards.
    pub fn evm_address(&self, id: &AccountId) -> Option<[u8; 20]> {
        for state in self.shards.values() {
            if let Some(addr) = state.evm_address(id) {
                return Some(addr);
            }
        }
        None
    }

    /// Return the TRON address for an account across all shards.
    pub fn tron_address(&self, id: &AccountId) -> Option<[u8; 20]> {
        for state in self.shards.values() {
            if let Some(addr) = state.tron_address(id) {
                return Some(addr);
            }
        }
        None
    }

    // ── Contract storage ──

    /// Get a storage value across all shards.
    pub fn get_storage(&self, account: &AccountId, slot: &[u8; 32]) -> [u8; 32] {
        for state in self.shards.values() {
            if state.contains(account) {
                return state.get_storage(account, slot);
            }
        }
        [0u8; 32]
    }

    /// Set a storage value (in the shard containing the account, or default).
    pub fn set_storage(&mut self, account: &AccountId, slot: [u8; 32], value: [u8; 32]) {
        for state in self.shards.values_mut() {
            if state.contains(account) {
                state.set_storage(account, slot, value);
                return;
            }
        }
        self.default_shard_mut().set_storage(account, slot, value);
    }

    /// Get account storage map across all shards.
    pub fn get_account_storage(
        &self,
        account: &AccountId,
    ) -> Option<&std::collections::BTreeMap<[u8; 32], [u8; 32]>> {
        for state in self.shards.values() {
            if let Some(storage) = state.get_account_storage(account) {
                return Some(storage);
            }
        }
        None
    }

    /// Store bytecode for an account.
    pub fn set_code(&mut self, account: &AccountId, code: Vec<u8>) -> Option<[u8; 32]> {
        for state in self.shards.values_mut() {
            if state.contains(account) {
                return state.set_code(account, code);
            }
        }
        None
    }

    /// Get bytecode for an account across all shards.
    pub fn get_code(&self, account: &AccountId) -> Option<&[u8]> {
        for state in self.shards.values() {
            if let Some(code) = state.get_code(account) {
                return Some(code);
            }
        }
        None
    }

    // ── Stub tier (state expiry) ──

    /// Check if an account is stubbed in any shard.
    pub fn is_stubbed(&self, id: &AccountId) -> bool {
        self.shards.values().any(|s| s.is_stubbed(id))
    }

    /// Get stub across all shards.
    pub fn get_stub(&self, id: &AccountId) -> Option<&AccountStub> {
        for state in self.shards.values() {
            if let Some(stub) = state.get_stub(id) {
                return Some(stub);
            }
        }
        None
    }

    /// Insert a stub into the default shard.
    pub fn insert_stub(&mut self, stub: AccountStub) {
        self.default_shard_mut().insert_stub(stub);
    }

    /// Iterate over all stubs across all shards.
    pub fn iter_stubs(&self) -> impl Iterator<Item = (&AccountId, &AccountStub)> {
        self.shards.values().flat_map(|s| s.iter_stubs())
    }

    /// Total stub count across all shards.
    pub fn stub_count(&self) -> usize {
        self.shards.values().map(|s| s.stub_count()).sum()
    }

    /// Expire an account in whichever shard contains it.
    pub fn expire_account(&mut self, id: &AccountId, current_slot: u64) -> Option<AccountStub> {
        for state in self.shards.values_mut() {
            if state.contains(id) {
                let stub = state.expire_account(id, current_slot);
                if stub.is_some() {
                    self.shard_index.remove(id);
                }
                return stub;
            }
        }
        None
    }

    /// Resurrect an expired account.
    pub fn resurrect_account(
        &mut self,
        proof: &ResurrectionProof,
        new_slot: u64,
    ) -> Result<(), &'static str> {
        let id = proof.account.id_com;
        for (&shard_id, state) in self.shards.iter_mut() {
            if state.is_stubbed(&id) {
                let result = state.resurrect_account(proof, new_slot);
                if result.is_ok() {
                    self.shard_index.insert(id, shard_id);
                }
                return result;
            }
        }
        Err("account is not expired in any shard")
    }

    /// Sweep expired accounts across all shards.
    pub fn sweep_expired(&mut self, current_slot: u64, expiry_period: u64) -> usize {
        self.shards
            .values_mut()
            .map(|s| s.sweep_expired(current_slot, expiry_period))
            .sum()
    }

    /// Compute the aggregated state root across all shards.
    ///
    /// `global_root = SHA-256(shard_0_root || shard_1_root || ... || shard_N_root)`
    ///
    /// Shard roots are sorted by `ShardId` for determinism.
    /// If only one shard exists, returns that shard's root directly
    /// (backward compatible with pre-sharding state roots).
    pub fn compute_root(&self) -> [u8; 32] {
        if self.shards.len() == 1 {
            // Single shard: return its root directly for backward compatibility.
            return self
                .shards
                .values()
                .next()
                .expect("at least one shard")
                .compute_root();
        }

        // Collect shard roots sorted by ShardId.
        let mut shard_roots: Vec<(u64, [u8; 32])> = self
            .shards
            .iter()
            .map(|(id, state)| (id.0, state.compute_root()))
            .collect();
        shard_roots.sort_by_key(|(id, _)| *id);

        // Aggregate into a single root.
        let mut hasher = Sha256::new();
        hasher.update(b"ACE-SHARDED-STATE-V1");
        for (shard_id, root) in &shard_roots {
            hasher.update(shard_id.to_le_bytes());
            hasher.update(root);
        }
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Take a snapshot of all shards for rollback.
    pub fn snapshot(&self) -> ShardedStateSnapshot {
        ShardedStateSnapshot {
            snapshots: self
                .shards
                .iter()
                .map(|(&id, state)| (id, state.snapshot()))
                .collect(),
            shard_index: self.shard_index.clone(),
        }
    }

    /// Rollback all shards to a previous snapshot.
    pub fn rollback(&mut self, snapshot: ShardedStateSnapshot) {
        // Remove shards that weren't in the snapshot.
        self.shards
            .retain(|id, _| snapshot.snapshots.contains_key(id));
        // Restore each shard.
        for (id, snap) in snapshot.snapshots {
            if let Some(state) = self.shards.get_mut(&id) {
                state.rollback(snap);
            } else {
                let mut state = StateTree::new();
                state.rollback(snap);
                self.shards.insert(id, state);
            }
        }
        self.shard_index = snapshot.shard_index;
    }
}

impl Default for ShardedState {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardedStateSnapshot {
    /// Number of accounts in the snapshot across all shards.
    pub fn account_count(&self) -> usize {
        self.snapshots.values().map(|s| s.account_count()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;

    #[test]
    fn default_shard_exists() {
        let state = ShardedState::new();
        assert_eq!(state.shard_count(), 1);
        assert!(state.shard(ShardId(0)).is_some());
    }

    #[test]
    fn from_state_tree_preserves_accounts() {
        let mut tree = StateTree::new();
        let id = AccountId([1u8; 32]);
        tree.insert(Account::new(id));

        let sharded = ShardedState::from_state_tree(tree);
        assert!(sharded.contains(&id));
        assert_eq!(sharded.total_account_count(), 1);
    }

    #[test]
    fn multi_shard_isolation() {
        let mut state = ShardedState::new();
        let id_a = AccountId([0xAA; 32]);
        let id_b = AccountId([0xBB; 32]);

        state.insert_into_shard(ShardId(0), Account::new(id_a));
        state.insert_into_shard(ShardId(1), Account::new(id_b));

        assert_eq!(state.shard_count(), 2);
        assert!(state.shard(ShardId(0)).unwrap().contains(&id_a));
        assert!(!state.shard(ShardId(0)).unwrap().contains(&id_b));
        assert!(state.shard(ShardId(1)).unwrap().contains(&id_b));
        assert!(!state.shard(ShardId(1)).unwrap().contains(&id_a));
    }

    #[test]
    fn single_shard_root_backward_compatible() {
        let mut tree = StateTree::new();
        let id = AccountId([1u8; 32]);
        tree.insert(Account::new(id));
        let expected_root = tree.compute_root();

        let sharded = ShardedState::from_state_tree(tree);
        assert_eq!(sharded.compute_root(), expected_root);
    }

    #[test]
    fn multi_shard_root_differs_from_single() {
        let mut state = ShardedState::new();
        let id_a = AccountId([0xAA; 32]);
        let id_b = AccountId([0xBB; 32]);
        state.insert(Account::new(id_a));

        let single_root = state.compute_root();

        state.insert_into_shard(ShardId(1), Account::new(id_b));
        let multi_root = state.compute_root();

        assert_ne!(single_root, multi_root);
    }

    #[test]
    fn snapshot_and_rollback() {
        let mut state = ShardedState::new();
        let id = AccountId([1u8; 32]);
        state.insert(Account::with_balance(id, 100));

        let snap = state.snapshot();

        // Modify state
        state.get_mut(&id).unwrap().balance = 0;
        assert_eq!(state.get(&id).unwrap().balance, 0);

        // Rollback
        state.rollback(snap);
        assert_eq!(state.get(&id).unwrap().balance, 100);
    }

    #[test]
    fn cross_shard_lookup() {
        let mut state = ShardedState::new();
        let id = AccountId([0x42; 32]);
        state.insert_into_shard(ShardId(5), Account::new(id));

        // Should find via global lookup
        assert!(state.get(&id).is_some());
        assert!(state.contains(&id));
        assert_eq!(state.total_account_count(), 1);
    }

    #[test]
    fn insert_into_shard_removes_from_old_shard() {
        let mut state = ShardedState::new();
        let id = AccountId([0xCC; 32]);

        // Insert into shard 1
        state.insert_into_shard(ShardId(1), Account::with_balance(id, 50));
        assert!(state.shard(ShardId(1)).unwrap().contains(&id));
        assert_eq!(state.total_account_count(), 1);

        // Move to shard 2 — should be removed from shard 1
        state.insert_into_shard(ShardId(2), Account::with_balance(id, 100));
        assert!(!state.shard(ShardId(1)).unwrap().contains(&id));
        assert!(state.shard(ShardId(2)).unwrap().contains(&id));
        assert_eq!(state.total_account_count(), 1);
        assert_eq!(state.get(&id).unwrap().balance, 100);
    }

    #[test]
    fn deterministic_iteration_order() {
        let mut state = ShardedState::new();
        // Insert shards in non-sequential order
        state.shard_mut(ShardId(5));
        state.shard_mut(ShardId(2));
        state.shard_mut(ShardId(9));

        let ids: Vec<u64> = state.iter_shards().map(|(id, _)| id.0).collect();
        assert_eq!(ids, vec![0, 2, 5, 9]);
    }
}
