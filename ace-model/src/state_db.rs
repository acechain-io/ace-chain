//! Persistence abstraction for state storage.
//!
//! Follows the same trait-based abstraction pattern as ace-runtime's
//! `ProofSystem` trait — define an interface, provide a mock/in-memory
//! implementation behind a feature flag, and allow production backends.

use crate::account::{Account, AccountId, AccountStub};
use crate::error::ModelError;
use crate::state_tree::StateTree;

/// Abstraction over state persistence backends.
///
/// Implementations must be `Send + Sync` to support concurrent access
/// from the RPC server (reader) and consensus engine (writer).
pub trait StateDB: Send + Sync {
    /// Retrieve an account by its identity commitment.
    fn get_account(&self, id: &AccountId) -> Result<Option<Account>, ModelError>;

    /// Store or update an account.
    fn put_account(&mut self, account: &Account) -> Result<(), ModelError>;

    /// Delete an account.
    fn delete_account(&mut self, id: &AccountId) -> Result<(), ModelError>;

    /// Check whether an account exists.
    fn has_account(&self, id: &AccountId) -> Result<bool, ModelError>;

    /// Compute the current state root.
    fn state_root(&self) -> Result<[u8; 32], ModelError>;

    /// Retrieve an expired account stub.
    fn get_stub(&self, id: &AccountId) -> Result<Option<AccountStub>, ModelError>;

    /// Check whether an account has been expired to a stub.
    fn has_stub(&self, id: &AccountId) -> Result<bool, ModelError>;
}

/// In-memory state database backed by a `StateTree`.
///
/// Suitable for testing and single-node MVP. A production deployment
/// would use RocksDB or similar persistent backend.
pub struct InMemoryStateDB {
    tree: StateTree,
}

impl InMemoryStateDB {
    /// Create a new empty in-memory state database.
    pub fn new() -> Self {
        Self {
            tree: StateTree::new(),
        }
    }

    /// Create from an existing state tree.
    pub fn from_tree(tree: StateTree) -> Self {
        Self { tree }
    }

    /// Get a reference to the underlying state tree.
    pub fn tree(&self) -> &StateTree {
        &self.tree
    }

    /// Get a mutable reference to the underlying state tree.
    pub fn tree_mut(&mut self) -> &mut StateTree {
        &mut self.tree
    }
}

impl Default for InMemoryStateDB {
    fn default() -> Self {
        Self::new()
    }
}

impl StateDB for InMemoryStateDB {
    fn get_account(&self, id: &AccountId) -> Result<Option<Account>, ModelError> {
        Ok(self.tree.get(id).cloned())
    }

    fn put_account(&mut self, account: &Account) -> Result<(), ModelError> {
        self.tree.insert(account.clone());
        Ok(())
    }

    fn delete_account(&mut self, id: &AccountId) -> Result<(), ModelError> {
        self.tree.remove(id);
        Ok(())
    }

    fn has_account(&self, id: &AccountId) -> Result<bool, ModelError> {
        Ok(self.tree.contains(id))
    }

    fn state_root(&self) -> Result<[u8; 32], ModelError> {
        Ok(self.tree.compute_root())
    }

    fn get_stub(&self, id: &AccountId) -> Result<Option<AccountStub>, ModelError> {
        Ok(self.tree.get_stub(id).copied())
    }

    fn has_stub(&self, id: &AccountId) -> Result<bool, ModelError> {
        Ok(self.tree.is_stubbed(id))
    }
}
