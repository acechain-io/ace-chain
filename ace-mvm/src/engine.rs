use tracing::{debug, warn};

use ace_engine::{VmEngine, VmExecutionError, VmId, VmReceipt};
use ace_engine::receipt::StateChange;
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::types::transaction::Transaction;

use crate::bytecode::{BytecodeVerifier, PayloadParser};
use crate::error::MoveError;
use crate::state::{load_module, module_id, publish_module};
use crate::types::{ModuleAbi, MoveModule, MoveValue};

/// Move VM execution engine for ACE Chain
pub struct MoveVmEngine {
}

impl MoveVmEngine {
    pub fn new() -> Self {
        Self {}
    }

    /// Verify and parse Move transaction.
    /// Opcode range: 0x50-0x5F.
    fn parse_tx(tx: &Transaction) -> Result<crate::types::MoveTxPayload, MoveError> {
        if tx.payload.is_empty() {
            return Err(MoveError::InvalidFormat("Empty payload".into()));
        }

        let opcode = tx.payload[0];
        if !matches!(opcode, 0x50..=0x5F) {
            return Err(MoveError::InvalidFormat(format!(
                "Invalid Move opcode: 0x{:02x} (expected 0x50-0x5F)",
                opcode
            )));
        }

        PayloadParser::parse(&tx.payload)
    }

    /// Execute a supported Move entry function.
    fn execute_function(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
        sender: &AccountId,
        payload: &crate::types::MoveTxPayload,
    ) -> Result<VmReceipt, MoveError> {
        debug!(
            module = %payload.module_name,
            function = %payload.function_name,
            "Executing Move function"
        );
        Self::validate_nonce(state, sender, payload.nonce)?;

        let mut state_changes = match payload.function_name.as_str() {
            "publish_module" => self.execute_publish_module(state, sender, payload)?,
            "transfer" => self.execute_transfer(state, sender, payload)?,
            other => {
                let id = module_id(payload.module_address, &payload.module_name);
                if load_module(state, &id)?.is_none() {
                    return Err(MoveError::ResourceNotFound(format!(
                        "module {}::{} is not published",
                        hex::encode(payload.module_address),
                        payload.module_name
                    )));
                }
                return Err(MoveError::ExecutionFailed(format!(
                    "Move function '{other}' is not implemented by the native Move executor"
                )));
            }
        };

        state_changes.push(Self::consume_nonce(state, sender, payload.nonce)?);

        let tx_hash = tx.tx_hash();
        // Informational receipt gas. Node-level fee charging still uses the
        // chain-wide fixed TX_FEE until Move-specific fee accounting lands.
        let gas_used = 21000 + (tx.payload.len() as u64 * 100);

        Ok(VmReceipt {
            vm_id: VmId::Move,
            tx_hash,
            success: true,
            sender: *sender,
            state_changes,
            error: None,
            simulated: false,
            gas_used: Some(gas_used),
            contract_address: None,
            return_data: Some(vec![]),
            logs: vec![],
        })
    }

    /// Execute a Move transfer operation
    fn execute_transfer(
        &self,
        state: &mut StateTree,
        sender: &AccountId,
        payload: &crate::types::MoveTxPayload,
    ) -> Result<Vec<StateChange>, MoveError> {
        // Extract recipient and amount from payload
        if payload.args.len() < 2 {
            return Err(MoveError::ExecutionFailed(
                "transfer requires 2 arguments".into(),
            ));
        }

        let recipient = payload.args[0]
            .as_address()
            .ok_or_else(|| MoveError::ExecutionFailed("recipient must be an address".into()))?;

        let amount = payload.args[1]
            .as_u64()
            .ok_or_else(|| MoveError::ExecutionFailed("amount must be u64".into()))?;
        if amount == 0 {
            return Err(MoveError::ExecutionFailed("transfer amount must be non-zero".into()));
        }

        let recipient = AccountId::from_bytes(*recipient);
        if !state.contains(sender) {
            return Err(MoveError::ResourceNotFound(format!("sender account not found: {sender}")));
        }
        if recipient == *sender {
            return Ok(Vec::new());
        }

        let old_sender_balance = state
            .get(sender)
            .ok_or_else(|| MoveError::ResourceNotFound(format!("sender account not found: {sender}")))?
            .balance;
        if old_sender_balance < amount {
            return Err(MoveError::ExecutionFailed(format!(
                "insufficient balance: have {old_sender_balance}, need {amount}"
            )));
        }
        let old_recipient_balance = state.get(&recipient).map(|account| account.balance).unwrap_or(0);
        let new_recipient_balance = old_recipient_balance
            .checked_add(amount)
            .ok_or_else(|| MoveError::ExecutionFailed("recipient balance overflow".into()))?;

        let mut changes = Vec::new();
        if !state.contains(&recipient) {
            state.insert(Account::new(recipient));
            changes.push(StateChange::AccountCreated { account: recipient });
        }

        let sender_account = state
            .get_mut(sender)
            .ok_or_else(|| MoveError::ResourceNotFound(format!("sender account not found: {sender}")))?;
        sender_account.balance = old_sender_balance - amount;
        let new_sender_balance = sender_account.balance;

        let recipient_account = state
            .get_mut(&recipient)
            .ok_or_else(|| MoveError::ResourceNotFound(format!("recipient account not found: {recipient}")))?;
        recipient_account.balance = new_recipient_balance;

        changes.push(StateChange::BalanceChange {
            account: *sender,
            old: old_sender_balance,
            new: new_sender_balance,
        });
        changes.push(StateChange::BalanceChange {
            account: recipient,
            old: old_recipient_balance,
            new: new_recipient_balance,
        });
        Ok(changes)
    }

    /// Execute a module publishing operation
    fn execute_publish_module(
        &self,
        state: &mut StateTree,
        sender: &AccountId,
        payload: &crate::types::MoveTxPayload,
    ) -> Result<Vec<StateChange>, MoveError> {
        if payload.module_address != sender.0 {
            return Err(MoveError::AccessDenied(
                "module address must match transaction sender".into(),
            ));
        }
        let bytecode = match payload.args.first() {
            Some(MoveValue::Bytes(bytes)) => bytes,
            _ => {
                return Err(MoveError::ExecutionFailed(
                    "publish_module requires one bytes argument".into(),
                ));
            }
        };
        BytecodeVerifier::verify_module(bytecode)?;

        let id = module_id(payload.module_address, &payload.module_name);
        if load_module(state, &id)?.is_some() {
            return Err(MoveError::ModuleAlreadyExists(format!(
                "{}::{}",
                hex::encode(payload.module_address),
                payload.module_name
            )));
        }
        let module = MoveModule {
            id,
            bytecode: bytecode.clone(),
            abi: ModuleAbi::default(),
        };
        publish_module(state, &module)
    }

    fn validate_nonce(
        state: &StateTree,
        sender: &AccountId,
        expected_nonce: u64,
    ) -> Result<(), MoveError> {
        let account = state
            .get(sender)
            .ok_or_else(|| MoveError::ResourceNotFound(format!("sender account not found: {sender}")))?;
        if account.nonce != expected_nonce {
            return Err(MoveError::ExecutionFailed(format!(
                "invalid nonce: expected {}, got {}",
                account.nonce, expected_nonce
            )));
        }
        Ok(())
    }

    fn consume_nonce(
        state: &mut StateTree,
        sender: &AccountId,
        expected_nonce: u64,
    ) -> Result<StateChange, MoveError> {
        let account = state
            .get_mut(sender)
            .ok_or_else(|| MoveError::ResourceNotFound(format!("sender account not found: {sender}")))?;
        if account.nonce != expected_nonce {
            return Err(MoveError::ExecutionFailed(format!(
                "invalid nonce: expected {}, got {}",
                account.nonce, expected_nonce
            )));
        }
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or_else(|| MoveError::ExecutionFailed("nonce overflow".into()))?;
        Ok(StateChange::NonceIncrement {
            account: *sender,
            new_nonce: account.nonce,
        })
    }
}

impl Default for MoveVmEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl VmEngine for MoveVmEngine {
    fn vm_id(&self) -> VmId {
        VmId::Move
    }

    fn name(&self) -> &str {
        "move-vm (native)"
    }

    fn execute(&self, state: &mut StateTree, tx: &Transaction) -> Result<VmReceipt, VmExecutionError> {
        let sender = AccountId::from_bytes(tx.attestation.idcom);

        // Parse and validate Move transaction format
        let payload = match Self::parse_tx(tx) {
            Ok(p) => p,
            Err(e) => {
                warn!("Move transaction parse failed: {}", e);
                return Ok(VmReceipt {
                    vm_id: VmId::Move,
                    tx_hash: tx.tx_hash(),
                    success: false,
                    sender,
                    state_changes: vec![],
                    error: Some(e.to_string()),
                    simulated: false,
                    gas_used: Some(0),
                    contract_address: None,
                    return_data: None,
                    logs: vec![],
                });
            }
        };

        // Check nonce first. If nonce is invalid, the entire transaction is invalid.
        if let Err(e) = Self::validate_nonce(state, &sender, payload.nonce) {
            return Ok(VmReceipt {
                vm_id: VmId::Move,
                tx_hash: tx.tx_hash(),
                success: false,
                sender,
                state_changes: vec![],
                error: Some(e.to_string()),
                simulated: false,
                gas_used: Some(0),
                contract_address: None,
                return_data: None,
                logs: vec![],
            });
        }

        // Execute the function
        let snapshot = state.snapshot();
        match self.execute_function(state, tx, &sender, &payload) {
            Ok(receipt) => Ok(receipt),
            Err(e) => {
                state.rollback(snapshot);
                warn!("Move execution failed: {}", e);
                
                // Even on logic failure, we MUST consume the nonce if it was valid.
                let mut state_changes = Vec::new();
                match Self::consume_nonce(state, &sender, payload.nonce) {
                    Ok(change) => state_changes.push(change),
                    Err(nonce_err) => warn!("Failed to consume nonce after logic failure: {}", nonce_err),
                }

                Ok(VmReceipt {
                    vm_id: VmId::Move,
                    tx_hash: tx.tx_hash(),
                    success: false,
                    sender,
                    state_changes,
                    error: Some(e.to_string()),
                    simulated: false,
                    gas_used: Some(21000), // Base fee for failure
                    contract_address: None,
                    return_data: None,
                    logs: vec![],
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_move_vm_engine_creation() {
        let engine = MoveVmEngine::new();
        assert_eq!(engine.vm_id(), VmId::Move);
        assert_eq!(engine.name(), "move-vm (native)");
    }
}
