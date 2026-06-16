//! # ace-engine — Transaction Execution Engine for ACE Chain
//!
//! Replaces ace-runtime's simplified `execute_transactions` (which produces
//! synthetic `StateDelta` hashes) with real account state transitions.
//!
//! ## Module Structure
//!
//! - [`executor`]: Block-level and transaction-level execution
//! - [`transfer`]: Native balance transfer logic
//! - [`receipt`]: Execution receipt types
//! - [`error`]: Engine error types

pub mod admission;
pub mod error;
pub mod executor;
pub mod receipt;
pub mod transfer;
pub mod vm;

pub use admission::{derive_devnet_signing_seed, devnet_signing_pubkey};
pub use error::EngineError;
pub use executor::{
    execute_block, execute_transaction, validate_approve_validator_sender, ExecutionPolicy,
    TransactionOp, OP_HFI_PAY_CLAIM,
};
pub use receipt::{ExecutionReceipt, StateChange};
pub use vm::{ExecutionHook, VmEngine, VmExecutionError, VmId, VmLog, VmReceipt};
