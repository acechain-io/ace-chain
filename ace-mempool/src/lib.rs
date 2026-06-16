//! # ace-mempool — Transaction Pool for ACE Chain
//!
//! Manages pending transactions with attestation-based validation.
//! Integrates with ace-runtime's `verify_payload_binding` for Phase 1a
//! checks before admitting transactions.
//!
//! ## Module Structure
//!
//! - [`pool`]: Concurrent mempool with deduplication and size limits
//! - [`validator`]: Transaction validation before admission
//! - [`zk_authorization`]: ZK-ACE proof and replay admission policy
//! - [`error`]: Mempool error types

pub mod error;
pub mod pool;
pub mod validator;
pub mod zk_authorization;

pub use error::MempoolError;
pub use pool::{InsertOutcome, Mempool, MempoolConfig};
pub use validator::TransactionValidator;
