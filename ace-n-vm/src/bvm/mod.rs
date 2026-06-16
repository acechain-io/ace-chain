//! Test-only stub engine. See `engine.rs` for the production implementation.
//!
//! BVM — Bitcoin Script execution engine.
//!
//! Opcodes 0x30–0x3F:
//! - 0x30: BVM transfer (P2PKH-style value transfer)
//! - 0x31: BVM script execute (raw Bitcoin Script evaluation)
//! - 0x32: BVM UTXO spend (spend specific UTXOs with script satisfaction)

pub mod engine;
pub mod script;
pub mod utxo;

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ace_runtime::types::transaction::Transaction;

use crate::error::NVmError;
use crate::vm::{VmEngine, VmExecutionError, VmId, VmReceipt};

/// BVM opcode constants.
pub const OP_BVM_TRANSFER: u8 = 0x30;
pub const OP_BVM_SCRIPT_EXEC: u8 = 0x31;
pub const OP_BVM_UTXO_SPEND: u8 = 0x32;

/// Mock (test-only) BVM execution engine.
///
/// Produces deterministic success receipts for testing.
/// Use [`engine::BvmEngine`] for real Bitcoin Script execution.
pub struct MockBvmEngine;

impl VmEngine for MockBvmEngine {
    fn vm_id(&self) -> VmId {
        VmId::Bvm
    }

    fn name(&self) -> &str {
        "Mock BVM (Bitcoin Script)"
    }

    fn execute(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
    ) -> Result<VmReceipt, VmExecutionError> {
        self.execute_impl(state, tx).map_err(Into::into)
    }
}

impl MockBvmEngine {
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
            OP_BVM_TRANSFER => "bvm_transfer",
            OP_BVM_SCRIPT_EXEC => "bvm_script_exec",
            OP_BVM_UTXO_SPEND => "bvm_utxo_spend",
            other => {
                return Err(NVmError::BvmError(format!(
                    "unsupported BVM opcode: 0x{other:02x}"
                )));
            }
        };

        tracing::debug!(opcode = op_name, sender = %hex::encode(sender.0), "Mock (test-only) BVM executing");

        Ok(VmReceipt {
            vm_id: VmId::Bvm,
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
