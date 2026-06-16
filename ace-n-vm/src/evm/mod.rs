//! Test-only stub engine. See `engine.rs` for the production implementation.
//!
//! Mock (test-only) EVM engine (Shanghai).
//!
//! Opcodes 0x10–0x1F:
//! - 0x10: EVM call
//! - 0x11: EVM create (contract deployment)
//! - 0x12: EVM transfer (simple value transfer)

pub mod database;
pub mod engine;
pub mod precompile;

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ace_runtime::types::transaction::Transaction;

use crate::error::NVmError;
use crate::vm::{VmEngine, VmExecutionError, VmId, VmReceipt};

/// EVM opcode constants.
pub const OP_EVM_CALL: u8 = 0x10;
pub const OP_EVM_CREATE: u8 = 0x11;
pub const OP_EVM_TRANSFER: u8 = 0x12;

/// Mock (test-only) EVM execution engine.
///
/// In production this would wrap a full EVM interpreter (e.g. revm).
/// For the MVP, it produces deterministic success receipts.
pub struct MockEvmEngine;

impl VmEngine for MockEvmEngine {
    fn vm_id(&self) -> VmId {
        VmId::Evm
    }

    fn name(&self) -> &str {
        "Mock EVM (Shanghai)"
    }

    fn execute(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
    ) -> Result<VmReceipt, VmExecutionError> {
        self.execute_impl(state, tx).map_err(Into::into)
    }
}

impl MockEvmEngine {
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
            OP_EVM_CALL => "evm_call",
            OP_EVM_CREATE => "evm_create",
            OP_EVM_TRANSFER => "evm_transfer",
            other => {
                return Err(NVmError::EvmError(format!(
                    "unsupported EVM opcode: 0x{other:02x}"
                )));
            }
        };

        tracing::debug!(opcode = op_name, sender = %hex::encode(sender.0), "Mock (test-only) EVM executing");

        Ok(VmReceipt {
            vm_id: VmId::Evm,
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
