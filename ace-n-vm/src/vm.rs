//! Re-export of VM abstractions from ace-engine.
//!
//! The n-VM dispatcher uses the trait definitions from ace-engine,
//! allowing any crate to implement VmEngine without circular dependencies.

pub use ace_engine::{ExecutionHook, VmEngine, VmExecutionError, VmId, VmLog, VmReceipt};

/// HFI Pay hook — for backward compatibility.
/// Re-export ExecutionHook as HfiPayHook for existing code.
pub use ace_engine::ExecutionHook as HfiPayHook;
