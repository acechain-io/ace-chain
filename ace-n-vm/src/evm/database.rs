//! revm Database adapter over ACE StateTree.
//!
//! Maps EVM 20-byte addresses to ACE 32-byte AccountIds via the
//! incremental EVM index maintained inside StateTree, and serves
//! account info / storage from the StateTree.

use std::convert::Infallible;

use ace_model::state_tree::StateTree;
use revm::primitives::{AccountInfo, Address, Bytecode, B256, KECCAK_EMPTY, U256};
use revm::Database;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressNamespace {
    Evm,
    Tron,
}

/// Read-only adapter presenting an ACE StateTree as a revm Database.
///
/// Does not modify state — use `Evm::transact()` (not `transact_commit`)
/// and apply the resulting diff to StateTree manually.
///
/// Address resolution uses the O(1) incremental EVM index inside StateTree
/// (no separate AddressIndex build step required).
pub struct AceStateDb<'a> {
    state: &'a StateTree,
    namespace: AddressNamespace,
}

impl<'a> AceStateDb<'a> {
    pub fn new(state: &'a StateTree) -> Self {
        Self::with_namespace(state, AddressNamespace::Evm)
    }

    pub fn with_namespace(state: &'a StateTree, namespace: AddressNamespace) -> Self {
        Self { state, namespace }
    }

    fn resolve_account_id(&self, address: &[u8; 20]) -> Option<ace_model::account::AccountId> {
        match self.namespace {
            AddressNamespace::Evm => self.state.resolve_evm_account_id(address),
            AddressNamespace::Tron => self.state.resolve_tron_account_id(address),
        }
    }
}

impl<'a> Database for AceStateDb<'a> {
    type Error = Infallible;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let evm_bytes: [u8; 20] = address.0 .0;
        let Some(ace_id) = self.resolve_account_id(&evm_bytes) else {
            return Ok(None);
        };
        let Some(acct) = self.state.get(&ace_id) else {
            return Ok(None);
        };

        let code_hash = acct.code_hash.map(B256::from).unwrap_or(KECCAK_EMPTY);

        let code = acct
            .code
            .as_ref()
            .map(|c| Bytecode::new_raw(c.clone().into()));

        Ok(Some(AccountInfo {
            balance: U256::from(acct.balance),
            nonce: acct.nonce,
            code_hash,
            code,
        }))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        // We always provide code in AccountInfo::code, so this is a fallback.
        Ok(Bytecode::new())
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let evm_bytes: [u8; 20] = address.0 .0;
        let Some(ace_id) = self.resolve_account_id(&evm_bytes) else {
            return Ok(U256::ZERO);
        };

        let slot: [u8; 32] = index.to_be_bytes();
        let value = self.state.get_storage(&ace_id, &slot);
        Ok(U256::from_be_bytes(value))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        // Deterministic non-zero block hash derived from block number.
        // Prevents EVM contracts from observing an all-zero BLOCKHASH,
        // which could be exploited as a distinguisher or entropy source.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ACE-BLOCK-HASH-V1");
        hasher.update(number.to_le_bytes());
        let hash = hasher.finalize();
        Ok(B256::from_slice(&hash))
    }
}
