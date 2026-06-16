//! UTXO state management for BVM.
//!
//! Maps Bitcoin's UTXO model onto ACE's account-based StateTree by storing
//! UTXO sets in account storage slots. Each account's UTXOs are tracked as
//! storage entries keyed by `outpoint_hash` (SHA-256 of txid || vout).
//!
//! ## Storage layout
//!
//! For a given ACE `AccountId`:
//! - Storage slot `SHA-256("utxo:" || txid || vout)` → header:
//!   `[value:8 LE][live:1][script_len:4 LE][reserved:19]`
//! - Storage slot `SHA-256("utxo_script:" || txid || vout || chunk_idx)` →
//!   `script_pubkey` chunk (32 bytes per chunk)
//! - Storage slot `SHA-256("utxo_count")` → number of live UTXOs
//!
//! This allows the parallel scheduler to determine write sets accurately:
//! a BVM transaction's write set is { sender_account, recipient_account }.

use ace_engine::receipt::StateChange;
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use sha2::{Digest, Sha256};

/// A Bitcoin-style unspent transaction output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    /// Transaction hash that created this output.
    pub txid: [u8; 32],
    /// Output index within the transaction.
    pub vout: u32,
    /// Value in satoshis.
    pub value: u64,
    /// Locking script (scriptPubKey).
    pub script_pubkey: Vec<u8>,
}

impl Utxo {
    /// Compute the outpoint hash: SHA-256(txid || vout_le).
    pub fn outpoint_hash(&self) -> [u8; 32] {
        compute_outpoint_hash(&self.txid, self.vout)
    }

    /// Serialize to bytes: txid(32) || vout(4 LE) || value(8 LE) || script_len(4 LE) || script.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(48 + self.script_pubkey.len());
        buf.extend_from_slice(&self.txid);
        buf.extend_from_slice(&self.vout.to_le_bytes());
        buf.extend_from_slice(&self.value.to_le_bytes());
        buf.extend_from_slice(&(self.script_pubkey.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.script_pubkey);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 48 {
            return None;
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[..32]);
        let vout = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let value = u64::from_le_bytes(data[36..44].try_into().ok()?);
        let script_len = u32::from_le_bytes(data[44..48].try_into().ok()?) as usize;
        if data.len() < 48 + script_len {
            return None;
        }
        let script_pubkey = data[48..48 + script_len].to_vec();
        Some(Self {
            txid,
            vout,
            value,
            script_pubkey,
        })
    }
}

/// Compute outpoint hash from txid and vout.
pub fn compute_outpoint_hash(txid: &[u8; 32], vout: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"utxo:");
    hasher.update(txid);
    hasher.update(vout.to_le_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Storage slot key for a `script_pubkey` chunk.
fn utxo_script_slot(txid: &[u8; 32], vout: u32, chunk_idx: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"utxo_script:");
    hasher.update(txid);
    hasher.update(vout.to_le_bytes());
    hasher.update(chunk_idx.to_le_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Storage slot key for UTXO count.
fn utxo_count_slot() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"utxo_count");
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// UTXO state manager — reads and writes UTXOs via ACE StateTree storage.
pub struct UtxoState;

impl UtxoState {
    /// Load a full UTXO, including its `script_pubkey`, from account storage.
    pub fn get_utxo(
        state: &StateTree,
        owner: &AccountId,
        txid: &[u8; 32],
        vout: u32,
    ) -> Option<Utxo> {
        let header_slot = compute_outpoint_hash(txid, vout);
        let header = state.get_storage(owner, &header_slot);
        if header[8] != 0x01 {
            return None;
        }

        let value = u64::from_le_bytes(header[..8].try_into().unwrap());
        let script_len = u32::from_le_bytes(header[9..13].try_into().unwrap()) as usize;
        let mut script_pubkey = Vec::with_capacity(script_len);

        for chunk_idx in 0..script_len.div_ceil(32) {
            let slot = utxo_script_slot(txid, vout, chunk_idx as u32);
            let chunk = state.get_storage(owner, &slot);
            let remaining = script_len - script_pubkey.len();
            let take = remaining.min(32);
            script_pubkey.extend_from_slice(&chunk[..take]);
        }

        Some(Utxo {
            txid: *txid,
            vout,
            value,
            script_pubkey,
        })
    }

    /// Add a UTXO to an account's UTXO set.
    pub fn add_utxo(
        state: &mut StateTree,
        owner: &AccountId,
        utxo: &Utxo,
    ) -> Result<Vec<StateChange>, String> {
        let mut changes = Vec::new();

        // Ensure the account exists
        if state.get(owner).is_none() {
            state.insert(Account::new(*owner));
            changes.push(StateChange::AccountCreated { account: *owner });
        }

        // Header slot stores value + live flag + script length.
        let header_slot = utxo.outpoint_hash();
        let mut header_value = [0u8; 32];
        header_value[..8].copy_from_slice(&utxo.value.to_le_bytes());
        header_value[8] = 0x01;
        header_value[9..13].copy_from_slice(&(utxo.script_pubkey.len() as u32).to_le_bytes());

        let old_header = state.get_storage(owner, &header_slot);
        state.set_storage(owner, header_slot, header_value);
        changes.push(StateChange::StorageChange {
            account: *owner,
            slot: header_slot,
            old_value: old_header,
            new_value: header_value,
        });

        // Store the locking script in fixed-width 32-byte chunks.
        for (chunk_idx, chunk) in utxo.script_pubkey.chunks(32).enumerate() {
            let slot = utxo_script_slot(&utxo.txid, utxo.vout, chunk_idx as u32);
            let old_value = state.get_storage(owner, &slot);
            let mut chunk_value = [0u8; 32];
            chunk_value[..chunk.len()].copy_from_slice(chunk);
            state.set_storage(owner, slot, chunk_value);
            changes.push(StateChange::StorageChange {
                account: *owner,
                slot,
                old_value,
                new_value: chunk_value,
            });
        }

        // Increment UTXO count
        let count_slot = utxo_count_slot();
        let old_count_val = state.get_storage(owner, &count_slot);
        let old_count = u64::from_le_bytes(old_count_val[..8].try_into().unwrap());
        let new_count = old_count + 1;
        let mut new_count_val = [0u8; 32];
        new_count_val[..8].copy_from_slice(&new_count.to_le_bytes());
        state.set_storage(owner, count_slot, new_count_val);
        changes.push(StateChange::StorageChange {
            account: *owner,
            slot: count_slot,
            old_value: old_count_val,
            new_value: new_count_val,
        });

        // Also credit the account balance
        if let Some(acct) = state.get_mut(owner) {
            let old_balance = acct.balance;
            acct.balance = acct
                .balance
                .checked_add(utxo.value)
                .ok_or_else(|| format!("balance overflow: {} + {}", acct.balance, utxo.value))?;
            changes.push(StateChange::BalanceChange {
                account: *owner,
                old: old_balance,
                new: acct.balance,
            });
        }

        Ok(changes)
    }

    /// Spend (remove) a UTXO from an account's UTXO set.
    ///
    /// Returns the UTXO value if found, or None if the UTXO doesn't exist.
    pub fn spend_utxo(
        state: &mut StateTree,
        owner: &AccountId,
        txid: &[u8; 32],
        vout: u32,
    ) -> Option<(Utxo, Vec<StateChange>)> {
        let utxo = Self::get_utxo(state, owner, txid, vout)?;
        let slot = compute_outpoint_hash(txid, vout);
        let stored = state.get_storage(owner, &slot);
        let mut changes = Vec::new();
        let zeroed = [0u8; 32];

        // Zero out the storage slot (mark as spent)
        state.set_storage(owner, slot, zeroed);
        changes.push(StateChange::StorageChange {
            account: *owner,
            slot,
            old_value: stored,
            new_value: zeroed,
        });

        // Zero out all script chunks belonging to the UTXO.
        for chunk_idx in 0..utxo.script_pubkey.len().div_ceil(32) {
            let chunk_slot = utxo_script_slot(txid, vout, chunk_idx as u32);
            let chunk_exists = state
                .get_account_storage(owner)
                .is_some_and(|storage| storage.contains_key(&chunk_slot));
            if !chunk_exists {
                continue;
            }
            let old_value = state.get_storage(owner, &chunk_slot);
            state.set_storage(owner, chunk_slot, zeroed);
            changes.push(StateChange::StorageChange {
                account: *owner,
                slot: chunk_slot,
                old_value,
                new_value: zeroed,
            });
        }

        // Decrement UTXO count
        let count_slot = utxo_count_slot();
        let old_count_val = state.get_storage(owner, &count_slot);
        let old_count = u64::from_le_bytes(old_count_val[..8].try_into().unwrap());
        let new_count = old_count.saturating_sub(1);
        let mut new_count_val = [0u8; 32];
        new_count_val[..8].copy_from_slice(&new_count.to_le_bytes());
        state.set_storage(owner, count_slot, new_count_val);
        changes.push(StateChange::StorageChange {
            account: *owner,
            slot: count_slot,
            old_value: old_count_val,
            new_value: new_count_val,
        });

        // Debit the account balance
        if let Some(acct) = state.get_mut(owner) {
            let old_balance = acct.balance;
            acct.balance = acct.balance.saturating_sub(utxo.value);
            changes.push(StateChange::BalanceChange {
                account: *owner,
                old: old_balance,
                new: acct.balance,
            });
        }

        Some((utxo, changes))
    }

    /// Check if a UTXO exists and is unspent.
    pub fn is_unspent(state: &StateTree, owner: &AccountId, txid: &[u8; 32], vout: u32) -> bool {
        let slot = compute_outpoint_hash(txid, vout);
        let stored = state.get_storage(owner, &slot);
        stored[8] == 0x01
    }

    /// Get the total UTXO count for an account.
    pub fn utxo_count(state: &StateTree, owner: &AccountId) -> u64 {
        let count_slot = utxo_count_slot();
        let val = state.get_storage(owner, &count_slot);
        u64::from_le_bytes(val[..8].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_utxo() -> Utxo {
        Utxo {
            txid: [0xAA; 32],
            vout: 0,
            value: 100_000,
            script_pubkey: vec![0x76, 0xa9], // OP_DUP OP_HASH160 (truncated)
        }
    }

    #[test]
    fn test_utxo_serialization() {
        let utxo = test_utxo();
        let bytes = utxo.to_bytes();
        let decoded = Utxo::from_bytes(&bytes).unwrap();
        assert_eq!(utxo, decoded);
    }

    #[test]
    fn test_add_and_spend_utxo() {
        let mut state = StateTree::new();
        let owner = AccountId::from_bytes([0x01; 32]);

        let utxo = test_utxo();
        let changes = UtxoState::add_utxo(&mut state, &owner, &utxo).unwrap();
        assert!(!changes.is_empty());
        assert!(UtxoState::is_unspent(&state, &owner, &utxo.txid, utxo.vout));
        assert_eq!(UtxoState::utxo_count(&state, &owner), 1);
        assert_eq!(state.get(&owner).unwrap().balance, 100_000);
        assert_eq!(
            UtxoState::get_utxo(&state, &owner, &utxo.txid, utxo.vout),
            Some(utxo.clone())
        );

        // Spend it
        let (spent_utxo, spend_changes) =
            UtxoState::spend_utxo(&mut state, &owner, &utxo.txid, utxo.vout).unwrap();
        assert_eq!(spent_utxo, utxo);
        assert!(!spend_changes.is_empty());
        assert!(!UtxoState::is_unspent(
            &state, &owner, &utxo.txid, utxo.vout
        ));
        assert_eq!(UtxoState::utxo_count(&state, &owner), 0);
        assert_eq!(state.get(&owner).unwrap().balance, 0);
    }

    #[test]
    fn test_double_spend_fails() {
        let mut state = StateTree::new();
        let owner = AccountId::from_bytes([0x01; 32]);

        let utxo = test_utxo();
        UtxoState::add_utxo(&mut state, &owner, &utxo).unwrap();
        UtxoState::spend_utxo(&mut state, &owner, &utxo.txid, utxo.vout).unwrap();

        // Second spend should fail
        assert!(UtxoState::spend_utxo(&mut state, &owner, &utxo.txid, utxo.vout).is_none());
    }
}
