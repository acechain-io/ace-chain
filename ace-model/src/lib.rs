//! # ace-model — State Storage Layer for ACE Chain
//!
//! Provides the account model, Merkle state tree, and storage abstractions
//! used by the execution engine and consensus layer.
//!
//! ## Module Structure
//!
//! - [`account`]: `AccountId` and `Account` types (identity commitment–based)
//! - [`state_tree`]: Binary Merkle tree with SHA-256 (consistent with ace-runtime)
//! - [`state_db`]: Persistence abstraction trait + in-memory implementation
//! - [`block_store`]: Block and finality certificate storage
//! - [`error`]: Error types for the model layer

pub mod account;
pub mod affiliate;
pub mod block_store;
pub mod error;
pub mod node_registry;
pub mod serde_account_id;
pub mod sharded_state;
pub mod state_db;
pub mod state_tree;

#[cfg(feature = "persistence")]
pub mod rocks_app_store;
#[cfg(feature = "persistence")]
pub mod rocks_block_store;
#[cfg(feature = "persistence")]
pub mod rocks_state_db;

pub use account::{Account, AccountId, AccountStub, ResurrectionProof};
pub use block_store::{BlockStore, InMemoryBlockStore};
pub use error::ModelError;
pub use sharded_state::{ShardedState, ShardedStateSnapshot};
pub use state_db::{InMemoryStateDB, StateDB};
pub use state_tree::{derive_evm_address, derive_tron_address, StateSnapshot, StateTree};

#[cfg(feature = "persistence")]
pub use rocks_app_store::RocksDbAppStore;
#[cfg(feature = "persistence")]
pub use rocks_block_store::RocksDbBlockStore;
#[cfg(feature = "persistence")]
pub use rocks_state_db::RocksDbStateDB;
