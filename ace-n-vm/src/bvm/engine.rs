//! BvmEngine — Bitcoin Script execution engine.
//!
//! Payload formats:
//! - 0x30 transfer:    `[nonce:8 LE][to:32][value:8 LE]`
//! - 0x31 script_exec: `[nonce:8 LE][script_len:4 LE][script...][num_inputs:1][inputs...]`
//!                     Each input: `[txid:32][vout:4 LE]`
//! - 0x32 utxo_spend:  `[num_inputs:1][inputs...][num_outputs:1][outputs...]`
//!                     Each input:  `[txid:32][vout:4 LE][script_sig_len:4 LE][script_sig...]`
//!                     Each output: `[to:32][value:8 LE][script_pubkey_len:4 LE][script_pubkey...]`

use ace_engine::receipt::StateChange;
use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ace_runtime::types::transaction::Transaction;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::error::NVmError;
use crate::raw_btc::verify_raw_btc_against_state;
use crate::vm::{VmEngine, VmExecutionError, VmId, VmReceipt};

use super::script::ScriptInterpreter;
use super::utxo::{Utxo, UtxoState};
use super::{OP_BVM_SCRIPT_EXEC, OP_BVM_TRANSFER, OP_BVM_UTXO_SPEND};

/// Minimum UTXO output value to prevent dust pollution.
/// Matches Bitcoin's default relay minimum (546 satoshis).
const DUST_LIMIT: u64 = 546;

/// Real BVM execution engine with Bitcoin Script evaluation and UTXO tracking.
pub struct BvmEngine;

impl VmEngine for BvmEngine {
    fn vm_id(&self) -> VmId {
        VmId::Bvm
    }

    fn name(&self) -> &str {
        "BVM (Bitcoin Script)"
    }

    fn execute(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
    ) -> Result<VmReceipt, VmExecutionError> {
        self.execute_impl(state, tx).map_err(Into::into)
    }
}

impl BvmEngine {
    fn execute_impl(&self, state: &mut StateTree, tx: &Transaction) -> Result<VmReceipt, NVmError> {
        if tx.payload.is_empty() {
            return Err(NVmError::EmptyPayload);
        }
        let sender = AccountId::from_bytes(tx.attestation.idcom);
        let opcode = tx.payload[0];
        let tx_hash = tx.tx_hash();

        let (state_changes, return_data) = match opcode {
            OP_BVM_TRANSFER => execute_transfer(state, &sender, &tx_hash, &tx.payload)?,
            OP_BVM_SCRIPT_EXEC => execute_script(state, &sender, tx, &tx_hash)?,
            OP_BVM_UTXO_SPEND => execute_utxo_spend(state, &sender, tx, &tx_hash)?,
            other => {
                return Err(NVmError::BvmError(format!(
                    "unsupported BVM opcode: 0x{other:02x}"
                )));
            }
        };

        Ok(VmReceipt {
            vm_id: VmId::Bvm,
            tx_hash,
            success: true,
            sender,
            state_changes,
            error: None,
            simulated: false,
            gas_used: None,
            contract_address: None,
            return_data,
            logs: vec![],
        })
    }
}

/// 0x30: Simple BTC-like transfer — debit sender, credit recipient.
///
/// Creates UTXOs on the recipient side for UTXO-model consistency.
fn execute_transfer(
    state: &mut StateTree,
    sender: &AccountId,
    tx_hash: &[u8; 32],
    payload: &[u8],
) -> Result<(Vec<StateChange>, Option<Vec<u8>>), NVmError> {
    // Payload: [0x30][nonce:8 LE][to:32][value:8 LE]
    if payload.len() < 49 {
        return Err(NVmError::BvmError("transfer payload too short".into()));
    }

    let expected_nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
    let mut to_bytes = [0u8; 32];
    to_bytes.copy_from_slice(&payload[9..41]);
    let to = AccountId::from_bytes(to_bytes);
    let value = u64::from_le_bytes(payload[41..49].try_into().unwrap());

    if value == 0 {
        return Err(NVmError::BvmError("transfer value must be non-zero".into()));
    }

    let mut changes = Vec::new();
    let sender_nonce_before;

    // Debit sender
    {
        let sender_acct = state
            .get_mut(sender)
            .ok_or_else(|| NVmError::BvmError("sender account not found".into()))?;
        if sender_acct.nonce != expected_nonce {
            return Err(NVmError::BvmError(format!(
                "invalid nonce: expected {}, got {}",
                sender_acct.nonce, expected_nonce
            )));
        }
        if sender_acct.balance < value {
            return Err(NVmError::BvmError(format!(
                "insufficient balance: have {}, need {}",
                sender_acct.balance, value
            )));
        }
        let old_balance = sender_acct.balance;
        sender_nonce_before = sender_acct.nonce;
        sender_acct.balance = sender_acct.balance.checked_sub(value).ok_or_else(|| {
            NVmError::BvmError(format!(
                "balance underflow: have {}, need {}",
                sender_acct.balance, value
            ))
        })?;
        changes.push(StateChange::BalanceChange {
            account: *sender,
            old: old_balance,
            new: sender_acct.balance,
        });
        sender_acct.nonce = sender_acct
            .nonce
            .checked_add(1)
            .ok_or_else(|| NVmError::BvmError("nonce overflow".into()))?;
        changes.push(StateChange::NonceIncrement {
            account: *sender,
            new_nonce: sender_acct.nonce,
        });
    }

    // Derive a unique output txid from the transaction hash plus the sender's
    // pre-state nonce so even byte-identical replays cannot collide.
    let output_txid = derive_output_txid(tx_hash, sender_nonce_before);
    let utxo = Utxo {
        txid: output_txid,
        vout: 0,
        value,
        script_pubkey: build_p2pkh_script(&to_bytes),
    };
    changes.extend(UtxoState::add_utxo(state, &to, &utxo).map_err(NVmError::BvmError)?);

    Ok((changes, Some(output_txid.to_vec())))
}

/// 0x31: Execute a raw Bitcoin Script against sender's context.
///
/// The script is evaluated with the sender's sig_hash and pubkey pre-loaded.
/// Useful for testing script evaluation and P2SH-style contracts.
fn execute_script(
    state: &mut StateTree,
    sender: &AccountId,
    tx: &Transaction,
    tx_hash: &[u8; 32],
) -> Result<(Vec<StateChange>, Option<Vec<u8>>), NVmError> {
    let payload = &tx.payload;
    // Payload: [0x31][nonce:8 LE][script_len:4 LE][script...]
    if payload.len() < 13 {
        return Err(NVmError::BvmError("script_exec payload too short".into()));
    }

    let expected_nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
    let sender_nonce = state
        .get(sender)
        .map(|acct| acct.nonce)
        .ok_or_else(|| NVmError::BvmError("sender account not found".into()))?;
    if sender_nonce != expected_nonce {
        return Err(NVmError::BvmError(format!(
            "invalid nonce: expected {sender_nonce}, got {expected_nonce}"
        )));
    }

    let script_len = u32::from_le_bytes(payload[9..13].try_into().unwrap()) as usize;
    if payload.len() < 13 + script_len {
        return Err(NVmError::BvmError(
            "script data extends beyond payload".into(),
        ));
    }
    let script = &payload[13..13 + script_len];

    let mut interp = ScriptInterpreter::new();
    interp.sig_hash = *tx_hash;

    let result = interp
        .eval(script)
        .map_err(|e| NVmError::BvmError(format!("script execution failed: {e}")))?;

    if !result {
        return Err(NVmError::BvmError("script evaluated to false".into()));
    }

    // Increment sender nonce on successful script execution
    let mut changes = Vec::new();
    if let Some(acct) = state.get_mut(sender) {
        acct.nonce = acct
            .nonce
            .checked_add(1)
            .ok_or_else(|| NVmError::BvmError("nonce overflow".into()))?;
        changes.push(StateChange::NonceIncrement {
            account: *sender,
            new_nonce: acct.nonce,
        });
    }

    // Return the top of stack as return data
    let return_data = interp.stack().last().cloned();
    Ok((changes, return_data))
}

/// 0x32: Full UTXO spend — consume inputs, validate scripts, create outputs.
///
/// This is the closest analog to a real Bitcoin transaction:
/// 1. For each input: find the UTXO, evaluate scriptSig + scriptPubKey
/// 2. Sum input values, verify >= sum of output values
/// 3. Create new UTXOs for each output
fn execute_utxo_spend(
    state: &mut StateTree,
    sender: &AccountId,
    tx: &Transaction,
    tx_hash: &[u8; 32],
) -> Result<(Vec<StateChange>, Option<Vec<u8>>), NVmError> {
    let snapshot = state.snapshot();
    match execute_utxo_spend_inner(state, sender, tx, tx_hash) {
        Ok(result) => Ok(result),
        Err(err) => {
            state.rollback(snapshot);
            Err(err)
        }
    }
}

fn execute_utxo_spend_inner(
    state: &mut StateTree,
    sender: &AccountId,
    tx: &Transaction,
    tx_hash: &[u8; 32],
) -> Result<(Vec<StateChange>, Option<Vec<u8>>), NVmError> {
    let payload = &tx.payload;
    let mut cursor = 1; // skip opcode byte
    let sender_nonce_before = state
        .get(sender)
        .map(|acct| acct.nonce)
        .ok_or_else(|| NVmError::BvmError("sender account not found".into()))?;
    let raw_btc = tx
        .raw_chain
        .as_ref()
        .filter(|raw| matches!(raw.kind, ace_runtime::types::transaction::RawChainKind::Btc))
        .map(|raw| verify_raw_btc_against_state(state, &raw.raw_bytes))
        .transpose()?;
    if let Some(ref verified) = raw_btc {
        if tx.attestation.idcom != verified.sender_idcom {
            return Err(NVmError::InvalidCredential(tx.attestation.idcom));
        }
        if payload.as_slice() != verified.payload.as_slice() {
            return Err(NVmError::RawChainVerify(
                "btc raw payload does not match canonical reconstruction".into(),
            ));
        }
    }
    let output_txid = raw_btc
        .as_ref()
        .map(|verified| verified.txid)
        .unwrap_or_else(|| derive_output_txid(tx_hash, sender_nonce_before));

    // Parse inputs
    if cursor >= payload.len() {
        return Err(NVmError::BvmError("utxo_spend: missing num_inputs".into()));
    }
    let num_inputs = payload[cursor] as usize;
    cursor += 1;

    if num_inputs == 0 {
        return Err(NVmError::BvmError(
            "utxo_spend: must have at least one input".into(),
        ));
    }

    let mut total_input_value: u64 = 0;
    let mut all_changes = Vec::new();

    for input_idx in 0..num_inputs {
        // Each input: [txid:32][vout:4 LE][script_sig_len:4 LE][script_sig...]
        if cursor + 40 > payload.len() {
            return Err(NVmError::BvmError(
                "utxo_spend: input data too short".into(),
            ));
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&payload[cursor..cursor + 32]);
        cursor += 32;

        let vout = u32::from_le_bytes(payload[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;

        let script_sig_len =
            u32::from_le_bytes(payload[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;

        if cursor + script_sig_len > payload.len() {
            return Err(NVmError::BvmError(
                "utxo_spend: script_sig extends beyond payload".into(),
            ));
        }
        let script_sig = &payload[cursor..cursor + script_sig_len];
        cursor += script_sig_len;

        // Find and spend the UTXO
        let spend_owner = raw_btc
            .as_ref()
            .and_then(|verified| verified.input_owners.get(input_idx))
            .copied()
            .unwrap_or(*sender);
        let (spent_utxo, spend_changes) = UtxoState::spend_utxo(state, &spend_owner, &txid, vout)
            .ok_or_else(|| {
            NVmError::BvmError(format!(
                "UTXO not found or already spent: {}:{}",
                hex::encode(txid),
                vout
            ))
        })?;

        if raw_btc.is_none() {
            // Evaluate scriptSig (push data onto stack, then eval scriptPubKey would follow)
            // For simplified BVM: we trust the attestation credential check and validate
            // that the script_sig satisfies a P2PKH pattern against the sender's idcom.
            let mut interp = ScriptInterpreter::new();
            interp.sig_hash = *tx_hash;

            // Execute scriptSig to push data onto stack
            interp
                .eval(script_sig)
                .map_err(|e| NVmError::BvmError(format!("scriptSig evaluation failed: {e}")))?;

            let valid = interp
                .eval(&spent_utxo.script_pubkey)
                .map_err(|e| NVmError::BvmError(format!("scriptPubKey evaluation failed: {e}")))?;

            if !valid {
                return Err(NVmError::BvmError(
                    "script verification failed for input".into(),
                ));
            }
        }

        total_input_value = total_input_value
            .checked_add(spent_utxo.value)
            .ok_or_else(|| NVmError::BvmError("input value overflow".into()))?;

        all_changes.extend(spend_changes);
    }

    // Parse outputs
    if cursor >= payload.len() {
        return Err(NVmError::BvmError("utxo_spend: missing num_outputs".into()));
    }
    let num_outputs = payload[cursor] as usize;
    cursor += 1;

    let mut total_output_value: u64 = 0;

    for vout_idx in 0..num_outputs {
        // Each output: [to:32][value:8 LE][script_pubkey_len:4 LE][script_pubkey...]
        if cursor + 44 > payload.len() {
            return Err(NVmError::BvmError(
                "utxo_spend: output data too short".into(),
            ));
        }

        let mut to_bytes = [0u8; 32];
        to_bytes.copy_from_slice(&payload[cursor..cursor + 32]);
        cursor += 32;

        let out_value = u64::from_le_bytes(payload[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;

        // Enforce dust limit: reject uneconomically small outputs
        if out_value > 0 && out_value < DUST_LIMIT {
            return Err(NVmError::BvmError(format!(
                "output {vout_idx} value {out_value} below dust limit {DUST_LIMIT}"
            )));
        }

        let script_pubkey_len =
            u32::from_le_bytes(payload[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;

        if cursor + script_pubkey_len > payload.len() {
            return Err(NVmError::BvmError(
                "utxo_spend: script_pubkey extends beyond payload".into(),
            ));
        }
        let script_pubkey = payload[cursor..cursor + script_pubkey_len].to_vec();
        cursor += script_pubkey_len;

        total_output_value = total_output_value
            .checked_add(out_value)
            .ok_or_else(|| NVmError::BvmError("output value overflow".into()))?;

        // Create output UTXO
        let to = AccountId::from_bytes(to_bytes);
        let utxo = Utxo {
            txid: output_txid,
            vout: vout_idx as u32,
            value: out_value,
            script_pubkey,
        };
        let add_changes = UtxoState::add_utxo(state, &to, &utxo).map_err(NVmError::BvmError)?;
        all_changes.extend(add_changes);
    }

    // Verify: total inputs >= total outputs (difference is implicit fee)
    if total_input_value < total_output_value {
        return Err(NVmError::BvmError(format!(
            "insufficient input value: inputs={total_input_value}, outputs={total_output_value}"
        )));
    }

    let fee = total_input_value
        .checked_sub(total_output_value)
        .ok_or_else(|| {
            NVmError::BvmError(format!(
                "fee underflow: inputs={total_input_value}, outputs={total_output_value}"
            ))
        })?;
    if fee > 0 {
        all_changes.push(StateChange::Fee { amount: fee });
    }

    // Increment sender nonce
    if let Some(acct) = state.get_mut(sender) {
        acct.nonce = acct
            .nonce
            .checked_add(1)
            .ok_or_else(|| NVmError::BvmError("nonce overflow".into()))?;
        all_changes.push(StateChange::NonceIncrement {
            account: *sender,
            new_nonce: acct.nonce,
        });
    }

    Ok((all_changes, Some(output_txid.to_vec())))
}

/// Build a P2PKH-style scriptPubKey for an ACE identity.
///
/// OP_DUP OP_HASH160 <20-byte hash of pubkey> OP_EQUALVERIFY OP_CHECKSIG
fn build_p2pkh_script(pubkey_bytes: &[u8; 32]) -> Vec<u8> {
    let pubkey_hash = hash160(pubkey_bytes);
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(20); // Push 20 bytes
    script.extend_from_slice(&pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

fn derive_output_txid(tx_hash: &[u8; 32], sender_nonce_before: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bvm_output:");
    hasher.update(tx_hash);
    hasher.update(sender_nonce_before.to_le_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Real RIPEMD160(SHA256(data)) — Bitcoin-compatible HASH160.
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = sha256(data);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha);
    let result = ripemd.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
