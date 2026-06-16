//! ACE Chain Move VM - Smart Contract Engine
//!
//! This module provides the Move smart contract execution environment for ACE Chain.
//! ACE Native remains the system transaction path; Move is an additional VM for
//! programmable contracts alongside EVM, SVM, BVM, and TVM compatibility layers.
//!
//! ## Opcode Space
//! Move transactions use opcode range `0x50-0x5F`.
//!
//! ## Transaction Format
//! ```text
//! [opcode:1][nonce:8 LE][module_addr:32][module_name:32][func_name_len:2][func_name:var][args_count:2][args:var]
//! ```
//!
//! ## Example
//! ```text
//! // Deploy a module
//! 0x50 <nonce> <address> <name> 0x000E "publish_module" 0x0001 <bytecode>
//!
//! // Call a function
//! 0x50 <nonce> <address> <name> 0x0008 "transfer" 0x0002 <recipient> <amount>
//! ```
//!
//! ## Usage
//!
//! Move VM is automatically registered when creating the n-VM:
//!
//! ```rust,ignore
//! use ace_n_vm::NVm;
//!
//! // Move is the default native engine
//! let nvm = NVm::with_defaults();
//! ```

pub mod bytecode;
pub mod engine;
pub mod error;
pub mod state;
pub mod types;

pub use engine::MoveVmEngine;
pub use error::{MoveError, MoveResult};
pub use types::{ExecutionResult, ModuleId, MoveEvent, MoveValue, StructId};
