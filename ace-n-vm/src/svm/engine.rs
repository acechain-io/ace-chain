//! SvmEngine — lightweight SVM with built-in programs.
//!
//! Payload formats:
//! - 0x20 invoke:   `[program_id:32][num_accounts:1][accounts:N*32][data...]`
//! - 0x21 transfer: `[nonce:8 LE][to:32][amount:8 LE]`
//!                  Raw Solana ingress may still use the legacy
//!                  `[to:32][amount:8 LE]` form because replay protection is
//!                  enforced by the signed Solana signature marker.

use ace_engine::receipt::StateChange;
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::types::transaction::RawChainKind;
use ace_runtime::types::transaction::Transaction;

use crate::error::NVmError;
use crate::raw_solana::{extract_first_solana_signature, solana_signature_replay_slot};
use crate::svm::programs::ProgramRegistry;
use crate::vm::{VmEngine, VmExecutionError, VmId, VmReceipt};

/// Simplified SVM engine with built-in programs (SystemProgram, TokenProgram).
///
/// All state is stored in ACE StateTree, so snapshot/rollback works natively.
pub struct SvmEngine {
    registry: ProgramRegistry,
}

impl Default for SvmEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SvmEngine {
    pub fn new() -> Self {
        Self {
            registry: ProgramRegistry::with_defaults(),
        }
    }
}

impl VmEngine for SvmEngine {
    fn vm_id(&self) -> VmId {
        VmId::Svm
    }

    fn name(&self) -> &str {
        "Simple SVM"
    }

    fn execute(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
    ) -> Result<VmReceipt, VmExecutionError> {
        self.execute_impl(state, tx).map_err(Into::into)
    }
}

impl SvmEngine {
    fn execute_impl(&self, state: &mut StateTree, tx: &Transaction) -> Result<VmReceipt, NVmError> {
        if tx.payload.is_empty() {
            return Err(NVmError::EmptyPayload);
        }
        let sender = AccountId::from_bytes(tx.attestation.idcom);
        let opcode = tx.payload[0];
        let solana_replay_marker = tx
            .raw_chain
            .as_ref()
            .filter(|raw_chain| raw_chain.kind == RawChainKind::Solana)
            .map(|raw_chain| {
                let signature = extract_first_solana_signature(&raw_chain.raw_bytes)
                    .map_err(|e| NVmError::SvmError(e.to_string()))?;
                Ok::<([u8; 32], [u8; 32]), NVmError>((solana_signature_replay_slot(&signature), {
                    let mut marker = [0u8; 32];
                    marker[0] = 1;
                    marker[1..9]
                        .copy_from_slice(&(tx.attestation.domain.slot as u64).to_le_bytes());
                    marker
                }))
            })
            .transpose()?;

        if let Some((replay_slot, _marker)) = &solana_replay_marker {
            if state.get_storage(&sender, replay_slot) != [0u8; 32] {
                return Err(NVmError::SvmError(
                    "solana transaction signature has already been used".into(),
                ));
            }
        }

        let mut state_changes = match opcode {
            // Invoke: dispatch to a built-in program
            0x20 => {
                if tx.payload.len() < 34 {
                    return Err(NVmError::SvmError("invoke payload too short".into()));
                }
                let mut program_id = [0u8; 32];
                program_id.copy_from_slice(&tx.payload[1..33]);
                let num_accounts = tx.payload[33] as usize;

                let accounts_end = 34 + num_accounts * 32;
                if tx.payload.len() < accounts_end {
                    return Err(NVmError::SvmError("invoke: not enough account data".into()));
                }

                let mut accounts = Vec::with_capacity(num_accounts);
                for i in 0..num_accounts {
                    let start = 34 + i * 32;
                    let mut acct = [0u8; 32];
                    acct.copy_from_slice(&tx.payload[start..start + 32]);
                    accounts.push(acct);
                }

                let instruction_data = &tx.payload[accounts_end..];

                let program = self.registry.get(&program_id).ok_or_else(|| {
                    NVmError::SvmError(format!("unknown program: 0x{}", hex::encode(program_id)))
                })?;

                program
                    .execute(state, &sender, &accounts, instruction_data)
                    .map_err(NVmError::SvmError)?
            }
            // Transfer shorthand (same as ACE native transfer format)
            0x21 => {
                let allow_legacy = matches!(
                    tx.raw_chain.as_ref().map(|raw_chain| raw_chain.kind),
                    Some(RawChainKind::Solana)
                );
                let (expected_nonce, recipient, amount) =
                    parse_transfer_payload(&tx.payload, allow_legacy)?;
                let mut state_changes = Vec::new();

                if !state.contains(&recipient) {
                    state.insert(Account::new(recipient));
                    state_changes.push(StateChange::AccountCreated { account: recipient });
                }

                // Look up sender's current nonce for replay-protection
                let sender_nonce = state
                    .get(&sender)
                    .ok_or_else(|| NVmError::SvmError("sender account not found".into()))?
                    .nonce;

                let mut transfer_changes = ace_engine::transfer::transfer(
                    state,
                    &sender,
                    &recipient,
                    amount,
                    Some(expected_nonce.unwrap_or(sender_nonce)),
                )
                .map_err(|e| NVmError::SvmError(e.to_string()))?;
                state_changes.append(&mut transfer_changes);
                state_changes
            }
            other => {
                return Err(NVmError::SvmError(format!(
                    "unsupported SVM opcode: 0x{other:02x}"
                )));
            }
        };

        if let Some((replay_slot, marker)) = solana_replay_marker {
            let old_value = [0u8; 32];
            state.set_storage(&sender, replay_slot, marker);
            state_changes.push(StateChange::StorageChange {
                account: sender,
                slot: replay_slot,
                old_value,
                new_value: marker,
            });
        }

        Ok(VmReceipt {
            vm_id: VmId::Svm,
            tx_hash: tx.tx_hash(),
            success: true,
            sender,
            state_changes,
            error: None,
            simulated: false,
            gas_used: None,
            contract_address: None,
            return_data: None,
            logs: vec![],
        })
    }
}

fn parse_transfer_payload(
    payload: &[u8],
    allow_legacy: bool,
) -> Result<(Option<u64>, AccountId, u64), NVmError> {
    if payload.len() >= 49 {
        let nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
        let mut to = [0u8; 32];
        to.copy_from_slice(&payload[9..41]);
        let amount = u64::from_le_bytes(payload[41..49].try_into().unwrap());
        return Ok((Some(nonce), AccountId::from_bytes(to), amount));
    }

    if allow_legacy && payload.len() >= 41 {
        let mut to = [0u8; 32];
        to.copy_from_slice(&payload[1..33]);
        let amount = u64::from_le_bytes(payload[33..41].try_into().unwrap());
        return Ok((None, AccountId::from_bytes(to), amount));
    }

    Err(NVmError::SvmError(
        "transfer payload too short or missing nonce".into(),
    ))
}
