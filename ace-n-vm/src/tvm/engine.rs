//! TvmEngine — real TVM execution via revm (EVM-compatible).
//!
//! TVM (Tron Virtual Machine) is EVM-bytecode-compatible, so execution
//! delegates to RevmEngine with opcode translation:
//!   0x40 (TVM call)     → 0x10 (EVM call)
//!   0x41 (TVM create)   → 0x11 (EVM create)
//!   0x42 (TVM transfer) → 0x12 (EVM transfer)
//!
//! The receipt is patched to carry VmId::Tvm.

use ace_model::state_tree::StateTree;
use ace_runtime::types::transaction::Transaction;

use crate::error::NVmError;
use crate::evm::engine::RevmEngine;
use crate::vm::{VmEngine, VmExecutionError, VmId, VmReceipt};

/// Real TVM execution engine.
///
/// Delegates to RevmEngine (revm) since TVM executes EVM-compatible bytecode.
/// Address namespace selection is handled automatically by RevmEngine based on
/// `tx.raw_chain.kind == RawChainKind::Tron`.
pub struct TvmEngine;

impl VmEngine for TvmEngine {
    fn vm_id(&self) -> VmId {
        VmId::Tvm
    }

    fn name(&self) -> &str {
        "TVM (Tron-compatible, revm)"
    }

    fn execute(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
    ) -> Result<VmReceipt, VmExecutionError> {
        self.execute_impl(state, tx).map_err(Into::into)
    }
}

impl TvmEngine {
    fn execute_impl(&self, state: &mut StateTree, tx: &Transaction) -> Result<VmReceipt, NVmError> {
        if tx.payload.is_empty() {
            return Err(NVmError::EmptyPayload);
        }
        let opcode = tx.payload[0];

        // Remap TVM opcodes to EVM opcodes for execution
        let evm_opcode = match opcode {
            0x40 => 0x10, // call
            0x41 => 0x11, // create
            0x42 => 0x12, // transfer
            other => {
                return Err(NVmError::TvmError(format!(
                    "unsupported TVM opcode: 0x{other:02x}"
                )));
            }
        };

        let mut modified_tx = tx.clone();
        modified_tx.payload[0] = evm_opcode;

        let mut receipt = RevmEngine
            .execute(state, &modified_tx)
            .map_err(|e| NVmError::TvmError(format!("{e}")))?;

        receipt.vm_id = VmId::Tvm;
        Ok(receipt)
    }
}
