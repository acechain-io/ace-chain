//! # ace-rpc — JSON-RPC API for ACE Chain
//!
//! Provides a jsonrpsee-based JSON-RPC server with methods for
//! querying state, submitting transactions, and checking finality.
//!
//! ## Module Structure
//!
//! - [`server`]: RPC server startup and lifecycle
//! - [`methods`]: RPC method implementations
//! - [`types`]: RPC request/response types (hex-encoded)
//! - [`error`]: RPC error types

pub mod error;
pub mod eth_rpc;
pub mod hfi_pay_rpc;
pub mod methods;
pub mod raw_tx;
pub mod server;
pub mod types;

pub use error::RpcError;
pub use server::RpcServer;
