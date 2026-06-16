//! ACE Chain n-VM dispatcher: unified transaction routing.
//!
//! Routes transactions to one of six execution environments based on
//! opcode prefix byte:
//!
//! - `0x01–0x0F` → ACE Native Runtime
//! - `0x10–0x1F` → EVM (Shanghai, via revm, for Ethereum compatibility)
//! - `0x20–0x2F` → SVM (Solana-compatible built-in programs: SystemProgram, SPL Token, PDAs)
//! - `0x30–0x3F` → BVM (Bitcoin Script)
//! - `0x40–0x4F` → TVM (Tron-compatible, via revm)
//! - `0x50–0x5F` → Move VM (native smart contract environment)
//!
//! Move VM is an additional smart contract execution engine alongside EVM,
//! SVM, BVM, and TVM compatibility layers. ACE Native remains the primary
//! system transaction path.
//!
//! See Blueprint §VII for the full VM architecture.

pub mod bvm;
pub mod context;
pub mod cross_vm;
pub mod dispatcher;
pub mod error;
pub mod evm;
pub mod native;
pub mod raw_btc;
pub mod raw_evm;
pub mod raw_solana;
pub mod raw_tron;
pub mod scheduler;
pub mod svm;
pub mod token_runtime;
pub mod tvm;
pub mod vm;

pub use dispatcher::NVm;
pub use error::NVmError;
pub use vm::{HfiPayHook, VmEngine, VmId, VmReceipt};
