//! ACE Native engine — delegates to `ace_engine::executor`.

use ace_engine::executor::{execute_transaction, ExecutionPolicy};
use ace_model::state_tree::StateTree;
use ace_runtime::types::transaction::Transaction;

use crate::error::NVmError;
use crate::vm::{VmEngine, VmExecutionError, VmId, VmReceipt};

/// Wraps `ace_engine::executor` as a VmEngine.
pub struct AceNativeEngine {
    policy: ExecutionPolicy,
}

impl Default for AceNativeEngine {
    fn default() -> Self {
        Self {
            policy: ExecutionPolicy::default(),
        }
    }
}

impl AceNativeEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_founder_id_com(&mut self, founder: Option<ace_model::account::AccountId>) {
        self.policy.founder_id_com = founder;
    }
}

impl VmEngine for AceNativeEngine {
    fn vm_id(&self) -> VmId {
        VmId::AceNative
    }

    fn name(&self) -> &str {
        "ACE Native"
    }

    fn execute(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
    ) -> Result<VmReceipt, VmExecutionError> {
        match execute_transaction(state, tx, &self.policy) {
            Ok(receipt) => Ok(VmReceipt {
                vm_id: VmId::AceNative,
                tx_hash: receipt.tx_hash,
                success: receipt.success,
                sender: receipt.sender,
                state_changes: receipt.state_changes,
                error: receipt.error,
                simulated: false,
                gas_used: None,
                contract_address: None,
                return_data: None,
                logs: vec![],
            }),
            Err(e) => Err(NVmError::NativeError(e.to_string()).into()),
        }
    }
}
