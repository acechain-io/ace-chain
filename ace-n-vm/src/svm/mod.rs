//! Test-only stub engine. See `engine.rs` for the production implementation.
//!
//! Mock (test-only) SVM engine (Solana-compatible built-in programs).
//!
//! Opcodes 0x20–0x2F:
//! - 0x20: SVM invoke (program call)
//! - 0x21: SVM transfer (SOL-like value transfer)

pub mod engine;
pub mod programs;
pub mod syscall;

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ace_runtime::types::transaction::Transaction;

use crate::error::NVmError;
use crate::vm::{VmEngine, VmExecutionError, VmId, VmReceipt};

/// SVM opcode constants.
pub const OP_SVM_INVOKE: u8 = 0x20;
pub const OP_SVM_TRANSFER: u8 = 0x21;

/// Mock (test-only) SVM execution engine.
///
/// In production this wraps Solana-compatible built-in programs
/// (SystemProgram, SPL Token, PDAs). For tests, produces deterministic receipts.
pub struct MockSvmEngine;

impl VmEngine for MockSvmEngine {
    fn vm_id(&self) -> VmId {
        VmId::Svm
    }

    fn name(&self) -> &str {
        "Mock SVM (BPF)"
    }

    fn execute(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
    ) -> Result<VmReceipt, VmExecutionError> {
        self.execute_impl(state, tx).map_err(Into::into)
    }
}

impl MockSvmEngine {
    fn execute_impl(
        &self,
        _state: &mut StateTree,
        tx: &Transaction,
    ) -> Result<VmReceipt, NVmError> {
        if tx.payload.is_empty() {
            return Err(NVmError::EmptyPayload);
        }
        let sender = AccountId::from_bytes(tx.attestation.idcom);
        let opcode = tx.payload[0];

        let op_name = match opcode {
            OP_SVM_INVOKE => "svm_invoke",
            OP_SVM_TRANSFER => "svm_transfer",
            other => {
                return Err(NVmError::SvmError(format!(
                    "unsupported SVM opcode: 0x{other:02x}"
                )));
            }
        };

        tracing::debug!(opcode = op_name, sender = %hex::encode(sender.0), "Mock (test-only) SVM executing");

        Ok(VmReceipt {
            vm_id: VmId::Svm,
            tx_hash: tx.tx_hash(),
            success: true,
            sender,
            state_changes: vec![],
            error: None,
            simulated: true,
            gas_used: None,
            contract_address: None,
            return_data: None,
            logs: vec![],
        })
    }
}
