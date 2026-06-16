//! Test-only stub engine. See `engine.rs` for the production implementation.
//!
//! TVM engine — Tron-compatible execution via revm.
//!
//! Opcodes 0x40–0x4F:
//! - 0x40: TVM call (smart contract invocation)
//! - 0x41: TVM create (contract deployment)
//! - 0x42: TVM transfer (simple value transfer)

pub mod engine;

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ace_runtime::types::transaction::Transaction;

use crate::error::NVmError;
use crate::vm::{VmEngine, VmExecutionError, VmId, VmReceipt};

/// TVM opcode constants.
pub const OP_TVM_CALL: u8 = 0x40;
pub const OP_TVM_CREATE: u8 = 0x41;
pub const OP_TVM_TRANSFER: u8 = 0x42;

/// Mock (test-only) TVM execution engine.
///
/// Produces deterministic success receipts without executing bytecode.
pub struct MockTvmEngine;

impl VmEngine for MockTvmEngine {
    fn vm_id(&self) -> VmId {
        VmId::Tvm
    }

    fn name(&self) -> &str {
        "Mock TVM (Tron-compatible)"
    }

    fn execute(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
    ) -> Result<VmReceipt, VmExecutionError> {
        self.execute_impl(state, tx).map_err(Into::into)
    }
}

impl MockTvmEngine {
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
            OP_TVM_CALL => "tvm_call",
            OP_TVM_CREATE => "tvm_create",
            OP_TVM_TRANSFER => "tvm_transfer",
            other => {
                return Err(NVmError::TvmError(format!(
                    "unsupported TVM opcode: 0x{other:02x}"
                )));
            }
        };

        tracing::debug!(opcode = op_name, sender = %hex::encode(sender.0), "Mock (test-only) TVM executing");

        Ok(VmReceipt {
            vm_id: VmId::Tvm,
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
