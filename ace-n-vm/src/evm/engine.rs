//! RevmEngine — real EVM execution via embedded revm.
//!
//! Payload formats:
//! - 0x10 call:     `[to:20][value:8 LE][gas_limit:8 LE][calldata...]`
//! - 0x11 create:   `[value:8 LE][gas_limit:8 LE][init_code...]`
//! - 0x12 transfer: `[to:20][value:8 LE]`

use ace_engine::receipt::StateChange;
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::{legacy_idcom_evm, legacy_idcom_tron};
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use revm::primitives::{
    Address, Bytes, Env, ExecutionResult, Output, Precompile, PrecompileErrors, PrecompileOutput,
    PrecompileResult, SpecId, StatefulPrecompile, TxKind, U256,
};
use revm::{ContextPrecompile, Evm};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tiny_keccak::{Hasher, Keccak};

use crate::cross_vm::AddressResolver;
use crate::error::NVmError;
use crate::evm::database::{AceStateDb, AddressNamespace};
use crate::evm::precompile::all_precompiles;
use crate::raw_evm::decode_raw_evm_nonce;
use crate::token_runtime;
use crate::vm::{VmEngine, VmExecutionError, VmId, VmLog, VmReceipt};

const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

/// Gas cost: 100 base + 3 per input byte.
const ACE_PRECOMPILE_BASE_GAS: u64 = 100;
const ACE_PRECOMPILE_PER_BYTE_GAS: u64 = 3;

/// Wrapper that adapts an [`AcePrecompile`] to revm's [`StatefulPrecompile`].
struct AcePrecompileAdapter {
    inner: Box<dyn crate::evm::precompile::AcePrecompile>,
}

impl StatefulPrecompile for AcePrecompileAdapter {
    fn call(&self, bytes: &Bytes, gas_limit: u64, _env: &Env) -> PrecompileResult {
        let gas_cost = ACE_PRECOMPILE_BASE_GAS + ACE_PRECOMPILE_PER_BYTE_GAS * bytes.len() as u64;
        if gas_cost > gas_limit {
            return Err(PrecompileErrors::Error(
                revm::primitives::PrecompileError::OutOfGas,
            ));
        }
        match self.inner.execute(bytes) {
            Ok(output) => Ok(PrecompileOutput::new(gas_cost, Bytes::from(output))),
            Err(msg) => Err(PrecompileErrors::Fatal { msg }),
        }
    }
}

/// Real EVM execution engine backed by revm (Shanghai).
pub struct RevmEngine;

impl VmEngine for RevmEngine {
    fn vm_id(&self) -> VmId {
        VmId::Evm
    }

    fn name(&self) -> &str {
        "revm (Shanghai)"
    }

    fn execute(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
    ) -> Result<VmReceipt, VmExecutionError> {
        self.execute_impl(state, tx).map_err(Into::into)
    }
}

impl RevmEngine {
    fn execute_impl(&self, state: &mut StateTree, tx: &Transaction) -> Result<VmReceipt, NVmError> {
        if tx.payload.is_empty() {
            return Err(NVmError::EmptyPayload);
        }
        let sender_id = AccountId::from_bytes(tx.attestation.idcom);
        let opcode = tx.payload[0];
        let address_namespace = tx_address_namespace(tx);
        let sender_evm = sender_vm_address(state, &sender_id, address_namespace);
        let raw_evm_nonce = tx
            .raw_chain
            .as_ref()
            .filter(|raw_chain| raw_chain.kind == RawChainKind::Evm)
            .map(|raw_chain| decode_raw_evm_nonce(&raw_chain.raw_bytes))
            .transpose()?;

        // Parse payload into EVM transaction parameters
        let (tx_kind, value, gas_limit, data) = match opcode {
            0x10 => parse_call(&tx.payload)?,
            0x11 => parse_create(&tx.payload)?,
            0x12 => parse_transfer(&tx.payload)?,
            other => {
                return Err(NVmError::EvmError(format!(
                    "unsupported EVM opcode: 0x{other:02x}"
                )));
            }
        };

        if let Some(receipt) = maybe_execute_runtime_erc20_tx(
            state,
            tx,
            &sender_id,
            sender_evm,
            address_namespace,
            &tx_kind,
            value,
            gas_limit,
            &data,
        )? {
            return Ok(receipt);
        }

        // Execute EVM in a scoped block so the immutable borrow is released
        // before we apply state changes.
        let result_and_state = {
            let db = AceStateDb::with_namespace(&*state, address_namespace);
            let ace_precompiles: Vec<(Address, ContextPrecompile<_>)> = all_precompiles()
                .into_iter()
                .map(|p| {
                    let mut addr_bytes = [0u8; 20];
                    let raw = p.address();
                    addr_bytes[18] = (raw >> 8) as u8;
                    addr_bytes[19] = raw as u8;
                    let adapter = AcePrecompileAdapter { inner: p };
                    (
                        Address::from(addr_bytes),
                        ContextPrecompile::Ordinary(Precompile::new_stateful(adapter)),
                    )
                })
                .collect();
            let mut evm = Evm::builder()
                .with_db(db)
                .with_spec_id(SpecId::SHANGHAI)
                .modify_tx_env(|tx_env| {
                    tx_env.caller = Address::from(sender_evm);
                    tx_env.transact_to = tx_kind;
                    tx_env.value = U256::from(value);
                    tx_env.gas_limit = gas_limit;
                    tx_env.gas_price = U256::ZERO;
                    tx_env.data = data;
                    tx_env.nonce = raw_evm_nonce;
                })
                .modify_block_env(|blk| {
                    blk.gas_limit = U256::from(DEFAULT_GAS_LIMIT);
                    blk.basefee = U256::ZERO;
                })
                .append_handler_register_box(Box::new(move |handler| {
                    let prev = handler.pre_execution.load_precompiles();
                    let custom = ace_precompiles.clone();
                    handler.pre_execution.load_precompiles = Arc::new(move || {
                        let mut precompiles = prev.clone();
                        precompiles.extend(custom.clone());
                        precompiles
                    });
                }))
                .build();

            evm.transact()
                .map_err(|e| NVmError::EvmError(format!("{e:?}")))?
        };

        // Extract execution result
        let (success, gas_used, contract_address, return_data, logs, error) =
            match &result_and_state.result {
                ExecutionResult::Success {
                    gas_used,
                    logs,
                    output,
                    ..
                } => {
                    let (ret, contract_address) = match output {
                        Output::Call(data) => (data.to_vec(), None),
                        Output::Create(data, address) => {
                            (data.to_vec(), address.as_ref().map(|address| address.0 .0))
                        }
                    };
                    let vm_logs: Vec<VmLog> = logs
                        .iter()
                        .map(|log| VmLog {
                            address: log.address.0 .0,
                            topics: log.topics().iter().map(|t| t.0).collect(),
                            data: log.data.data.to_vec(),
                        })
                        .collect();
                    (true, *gas_used, contract_address, Some(ret), vm_logs, None)
                }
                ExecutionResult::Revert { gas_used, output } => (
                    false,
                    *gas_used,
                    None,
                    Some(output.to_vec()),
                    vec![],
                    Some(format!("revert: 0x{}", hex::encode(output))),
                ),
                ExecutionResult::Halt { reason, gas_used } => (
                    false,
                    *gas_used,
                    None,
                    None,
                    vec![],
                    Some(format!("halt: {reason:?}")),
                ),
            };

        let state_changes = if success {
            apply_revm_state_diff(
                state,
                &result_and_state.state,
                address_namespace,
                contract_address,
            )?
        } else {
            // On failure, only apply nonce increments (sender pays for gas)
            let mut nonce_changes = Vec::new();
            for (evm_addr, evm_account) in &result_and_state.state {
                let evm_bytes: [u8; 20] = evm_addr.0 .0;
                let ace_id = runtime_owner_account_id(state, address_namespace, &evm_bytes);
                if let Some(acct) = state.get_mut(&ace_id) {
                    if acct.nonce != evm_account.info.nonce {
                        acct.nonce = evm_account.info.nonce;
                        nonce_changes.push(StateChange::NonceIncrement {
                            account: ace_id,
                            new_nonce: evm_account.info.nonce,
                        });
                    }
                }
            }
            nonce_changes
        };

        Ok(VmReceipt {
            vm_id: VmId::Evm,
            tx_hash: tx.tx_hash(),
            success,
            sender: sender_id,
            state_changes,
            error,
            simulated: false,
            gas_used: Some(gas_used),
            contract_address,
            return_data,
            logs,
        })
    }
}

const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const ERC20_APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const ERC20_TRANSFER_FROM_SELECTOR: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const ERC20_BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
const ERC20_ALLOWANCE_SELECTOR: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];
const ERC20_TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];
const ERC20_DECIMALS_SELECTOR: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];

fn maybe_execute_runtime_erc20_tx(
    state: &mut StateTree,
    tx: &Transaction,
    sender_id: &AccountId,
    sender_evm: [u8; 20],
    address_namespace: AddressNamespace,
    tx_kind: &TxKind,
    value: u64,
    gas_limit: u64,
    data: &Bytes,
) -> Result<Option<VmReceipt>, NVmError> {
    let TxKind::Call(target) = tx_kind else {
        return Ok(None);
    };
    let target_bytes = target.0 .0;
    let Some(mint) = token_runtime::mint_for_runtime_erc20_address(state, &target_bytes) else {
        return Ok(None);
    };
    if value != 0 {
        return Ok(Some(runtime_erc20_failure_receipt(
            state,
            tx,
            *sender_id,
            "runtime ERC-20 calls do not accept native value".into(),
            gas_limit.min(25_000),
        )));
    }

    let selector = data.get(0..4).unwrap_or(&[]);
    let sender_owner = runtime_owner_account_id(state, address_namespace, &sender_evm);
    let mut state_changes = Vec::new();
    let mut logs = Vec::new();
    let result: Result<Vec<u8>, String> = match selector {
        s if s == ERC20_TRANSFER_SELECTOR => (|| {
            let recipient =
                abi_decode_address(data.get(4..36).unwrap_or(&[])).map_err(|e| e.to_string())?;
            let amount =
                abi_decode_u64(data.get(36..68).unwrap_or(&[])).map_err(|e| e.to_string())?;
            let recipient_owner = runtime_owner_account_id(state, address_namespace, &recipient);
            let mut changes = token_runtime::transfer_between_owners(
                state,
                &mint,
                &sender_owner,
                &recipient_owner,
                amount,
            )
            .map_err(|e| format!("erc20 transfer failed: {e}"))?;
            state_changes.append(&mut changes);
            logs.push(erc20_transfer_log(
                &target_bytes,
                &sender_evm,
                &recipient,
                amount,
            ));
            Ok(abi_encode_bool(true))
        })(),
        s if s == ERC20_APPROVE_SELECTOR => (|| {
            let spender =
                abi_decode_address(data.get(4..36).unwrap_or(&[])).map_err(|e| e.to_string())?;
            let amount =
                abi_decode_u64(data.get(36..68).unwrap_or(&[])).map_err(|e| e.to_string())?;
            let spender_owner = runtime_owner_account_id(state, address_namespace, &spender);
            let mut changes =
                token_runtime::set_allowance(state, &mint, &sender_owner, &spender_owner, amount)
                    .map_err(|e| format!("erc20 approve failed: {e}"))?;
            state_changes.append(&mut changes);
            logs.push(erc20_approval_log(
                &target_bytes,
                &sender_evm,
                &spender,
                amount,
            ));
            Ok(abi_encode_bool(true))
        })(),
        s if s == ERC20_TRANSFER_FROM_SELECTOR => (|| {
            let owner =
                abi_decode_address(data.get(4..36).unwrap_or(&[])).map_err(|e| e.to_string())?;
            let recipient =
                abi_decode_address(data.get(36..68).unwrap_or(&[])).map_err(|e| e.to_string())?;
            let amount =
                abi_decode_u64(data.get(68..100).unwrap_or(&[])).map_err(|e| e.to_string())?;
            let owner_account = runtime_owner_account_id(state, address_namespace, &owner);
            let recipient_account = runtime_owner_account_id(state, address_namespace, &recipient);
            let mut changes = token_runtime::transfer_from(
                state,
                &mint,
                &sender_owner,
                &owner_account,
                &recipient_account,
                amount,
            )
            .map_err(|e| format!("erc20 transferFrom failed: {e}"))?;
            state_changes.append(&mut changes);
            logs.push(erc20_transfer_log(
                &target_bytes,
                &owner,
                &recipient,
                amount,
            ));
            Ok(abi_encode_bool(true))
        })(),
        s if s == ERC20_BALANCE_OF_SELECTOR => (|| {
            let owner =
                abi_decode_address(data.get(4..36).unwrap_or(&[])).map_err(|e| e.to_string())?;
            let owner_account = runtime_owner_account_id(state, address_namespace, &owner);
            Ok(abi_encode_u64(token_runtime::balance_of(
                state,
                &mint,
                &owner_account,
            )))
        })(),
        s if s == ERC20_ALLOWANCE_SELECTOR => (|| {
            let owner =
                abi_decode_address(data.get(4..36).unwrap_or(&[])).map_err(|e| e.to_string())?;
            let spender =
                abi_decode_address(data.get(36..68).unwrap_or(&[])).map_err(|e| e.to_string())?;
            let owner_account = runtime_owner_account_id(state, address_namespace, &owner);
            let spender_account = runtime_owner_account_id(state, address_namespace, &spender);
            Ok(abi_encode_u64(token_runtime::allowance_of(
                state,
                &mint,
                &owner_account,
                &spender_account,
            )))
        })(),
        s if s == ERC20_TOTAL_SUPPLY_SELECTOR => (|| {
            let meta = token_runtime::get_mint_meta(state, &mint)
                .ok_or_else(|| "runtime ERC-20 mint does not exist".to_string())?;
            Ok(abi_encode_u64(meta.supply))
        })(),
        s if s == ERC20_DECIMALS_SELECTOR => (|| {
            let meta = token_runtime::get_mint_meta(state, &mint)
                .ok_or_else(|| "runtime ERC-20 mint does not exist".to_string())?;
            Ok(abi_encode_u8(meta.decimals))
        })(),
        _ => {
            return Ok(Some(runtime_erc20_failure_receipt(
                state,
                tx,
                *sender_id,
                "unsupported runtime ERC-20 selector".into(),
                gas_limit.min(25_000),
            )))
        }
    };

    let nonce_change = consume_runtime_erc20_nonce(state, sender_id)?;
    if let Some(change) = nonce_change.clone() {
        state_changes.push(change);
    }
    let return_data = match result {
        Ok(data) => data,
        Err(error) => {
            return Ok(Some(VmReceipt {
                vm_id: VmId::Evm,
                tx_hash: tx.tx_hash(),
                success: false,
                sender: *sender_id,
                state_changes: nonce_change.into_iter().collect(),
                error: Some(error),
                simulated: false,
                gas_used: Some(runtime_erc20_gas_used(selector, gas_limit)),
                contract_address: None,
                return_data: Some(vec![]),
                logs: vec![],
            }))
        }
    };

    Ok(Some(VmReceipt {
        vm_id: VmId::Evm,
        tx_hash: tx.tx_hash(),
        success: true,
        sender: *sender_id,
        state_changes,
        error: None,
        simulated: false,
        gas_used: Some(runtime_erc20_gas_used(selector, gas_limit)),
        contract_address: None,
        return_data: Some(return_data),
        logs,
    }))
}

fn runtime_erc20_failure_receipt(
    state: &mut StateTree,
    tx: &Transaction,
    sender_id: AccountId,
    error: String,
    gas_used: u64,
) -> VmReceipt {
    // Nonce overflow here means the account has executed u64::MAX transactions;
    // treat as no nonce change rather than panicking in the failure path.
    let state_changes = consume_runtime_erc20_nonce(state, &sender_id)
        .unwrap_or(None)
        .into_iter()
        .collect();
    VmReceipt {
        vm_id: VmId::Evm,
        tx_hash: tx.tx_hash(),
        success: false,
        sender: sender_id,
        state_changes,
        error: Some(error),
        simulated: false,
        gas_used: Some(gas_used),
        contract_address: None,
        return_data: Some(vec![]),
        logs: vec![],
    }
}

fn consume_runtime_erc20_nonce(
    state: &mut StateTree,
    sender_id: &AccountId,
) -> Result<Option<StateChange>, NVmError> {
    let sender_account = match state.get_mut(sender_id) {
        Some(a) => a,
        None => return Ok(None),
    };
    sender_account.nonce = sender_account
        .nonce
        .checked_add(1)
        .ok_or(NVmError::NonceOverflow)?;
    Ok(Some(StateChange::NonceIncrement {
        account: *sender_id,
        new_nonce: sender_account.nonce,
    }))
}

fn runtime_erc20_gas_used(selector: &[u8], gas_limit: u64) -> u64 {
    let estimate = match selector {
        s if s == ERC20_TRANSFER_SELECTOR => 50_000,
        s if s == ERC20_APPROVE_SELECTOR => 45_000,
        s if s == ERC20_TRANSFER_FROM_SELECTOR => 60_000,
        s if s == ERC20_BALANCE_OF_SELECTOR
            || s == ERC20_ALLOWANCE_SELECTOR
            || s == ERC20_TOTAL_SUPPLY_SELECTOR
            || s == ERC20_DECIMALS_SELECTOR =>
        {
            12_000
        }
        _ => 25_000,
    };
    estimate.min(gas_limit)
}

fn abi_decode_address(word: &[u8]) -> Result<[u8; 20], NVmError> {
    if word.len() != 32 {
        return Err(NVmError::EvmError("invalid ABI address word".into()));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&word[12..32]);
    Ok(out)
}

fn abi_decode_u64(word: &[u8]) -> Result<u64, NVmError> {
    if word.len() != 32 {
        return Err(NVmError::EvmError("invalid ABI uint256 word".into()));
    }
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(NVmError::EvmError(
            "runtime token amount exceeds u64 range".into(),
        ));
    }
    Ok(u64::from_be_bytes(word[24..32].try_into().unwrap()))
}

fn abi_encode_bool(value: bool) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[31] = u8::from(value);
    out
}

fn abi_encode_u64(value: u64) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[24..32].copy_from_slice(&value.to_be_bytes());
    out
}

fn abi_encode_u8(value: u8) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[31] = value;
    out
}

fn erc20_transfer_log(contract: &[u8; 20], from: &[u8; 20], to: &[u8; 20], amount: u64) -> VmLog {
    VmLog {
        address: *contract,
        topics: vec![
            keccak_topic(b"Transfer(address,address,uint256)"),
            address_topic(from),
            address_topic(to),
        ],
        data: abi_encode_u64(amount),
    }
}

fn erc20_approval_log(
    contract: &[u8; 20],
    owner: &[u8; 20],
    spender: &[u8; 20],
    amount: u64,
) -> VmLog {
    VmLog {
        address: *contract,
        topics: vec![
            keccak_topic(b"Approval(address,address,uint256)"),
            address_topic(owner),
            address_topic(spender),
        ],
        data: abi_encode_u64(amount),
    }
}

fn keccak_topic(signature: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signature);
    hasher.finalize(&mut out);
    out
}

fn address_topic(address: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(address);
    out
}

/// Derive a deterministic ACE AccountId for a contract created inside the EVM.
fn derive_contract_account_id(namespace: AddressNamespace, evm_address: &[u8; 20]) -> AccountId {
    let mut hasher = Sha256::new();
    hasher.update(match namespace {
        AddressNamespace::Evm => b"contract:evm:".as_slice(),
        AddressNamespace::Tron => b"contract:tron:".as_slice(),
    });
    hasher.update(evm_address);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    AccountId::from_bytes(id)
}

fn tx_address_namespace(tx: &Transaction) -> AddressNamespace {
    match tx.raw_chain.as_ref().map(|raw_chain| raw_chain.kind) {
        Some(RawChainKind::Tron) => AddressNamespace::Tron,
        _ => AddressNamespace::Evm,
    }
}

fn sender_vm_address(
    state: &StateTree,
    sender_id: &AccountId,
    namespace: AddressNamespace,
) -> [u8; 20] {
    match namespace {
        AddressNamespace::Evm => state
            .evm_address(sender_id)
            .unwrap_or_else(|| AddressResolver::to_evm_address(sender_id)),
        AddressNamespace::Tron => state
            .tron_address(sender_id)
            .unwrap_or_else(|| AddressResolver::to_tron_address(sender_id)),
    }
}

fn resolve_account_id(
    state: &StateTree,
    namespace: AddressNamespace,
    address: &[u8; 20],
) -> Option<AccountId> {
    match namespace {
        AddressNamespace::Evm => state.resolve_evm_account_id(address),
        AddressNamespace::Tron => state.resolve_tron_account_id(address),
    }
}

fn runtime_owner_account_id(
    state: &StateTree,
    namespace: AddressNamespace,
    address: &[u8; 20],
) -> AccountId {
    resolve_account_id(state, namespace, address)
        .unwrap_or_else(|| legacy_runtime_owner_account_id(namespace, address))
}

fn legacy_runtime_owner_account_id(namespace: AddressNamespace, address: &[u8; 20]) -> AccountId {
    match namespace {
        AddressNamespace::Evm => AccountId::from_bytes(legacy_idcom_evm(address)),
        AddressNamespace::Tron => AccountId::from_bytes(legacy_idcom_tron(address)),
    }
}

fn bind_namespace_address(account: &mut Account, namespace: AddressNamespace, address: [u8; 20]) {
    match namespace {
        AddressNamespace::Evm => account.evm_address = Some(address),
        AddressNamespace::Tron => account.tron_address = Some(address),
    }
}

fn apply_revm_state_diff(
    state: &mut StateTree,
    diff: &revm::primitives::EvmState,
    namespace: AddressNamespace,
    created_contract_address: Option<[u8; 20]>,
) -> Result<Vec<StateChange>, NVmError> {
    let snapshot = state.snapshot();
    let mut state_changes = Vec::new();

    for (evm_addr, evm_account) in diff {
        let evm_bytes: [u8; 20] = evm_addr.0 .0;
        let has_code = !evm_account.info.is_empty_code_hash();
        let is_contract = created_contract_address == Some(evm_bytes) || has_code;
        let ace_id = resolve_account_id(state, namespace, &evm_bytes).unwrap_or_else(|| {
            if is_contract {
                derive_contract_account_id(namespace, &evm_bytes)
            } else {
                legacy_runtime_owner_account_id(namespace, &evm_bytes)
            }
        });
        let existed = state.contains(&ace_id);
        let mut account = state
            .get(&ace_id)
            .cloned()
            .unwrap_or_else(|| Account::new(ace_id));
        bind_namespace_address(&mut account, namespace, evm_bytes);

        let new_balance: u64 = evm_account.info.balance.try_into().map_err(|_| {
            state.rollback(snapshot.clone());
            NVmError::EvmError("EVM account balance exceeds u64::MAX".into())
        })?;
        if account.balance != new_balance {
            let old = account.balance;
            account.balance = new_balance;
            state_changes.push(StateChange::BalanceChange {
                account: ace_id,
                old,
                new: new_balance,
            });
        }

        if account.nonce != evm_account.info.nonce {
            account.nonce = evm_account.info.nonce;
            state_changes.push(StateChange::NonceIncrement {
                account: ace_id,
                new_nonce: evm_account.info.nonce,
            });
        }

        state.insert(account);
        if !existed {
            state_changes.push(StateChange::AccountCreated { account: ace_id });
        }

        if has_code {
            if let Some(ref code) = evm_account.info.code {
                let code_bytes = code.bytes().to_vec();
                let needs_code_update = !code_bytes.is_empty()
                    && state
                        .get(&ace_id)
                        .and_then(|acct| acct.code.as_ref())
                        .map(|existing| existing.as_slice() != code_bytes.as_slice())
                        .unwrap_or(true);
                if needs_code_update {
                    if let Some(code_hash) = state.set_code(&ace_id, code_bytes) {
                        state_changes.push(StateChange::CodeDeployed {
                            account: ace_id,
                            code_hash,
                        });
                    }
                }
            }
        }

        for (slot, storage_val) in &evm_account.storage {
            if storage_val.present_value != storage_val.original_value {
                let slot_bytes: [u8; 32] = slot.to_be_bytes();
                let old_value: [u8; 32] = storage_val.original_value.to_be_bytes();
                let new_value: [u8; 32] = storage_val.present_value.to_be_bytes();
                state.set_storage(&ace_id, slot_bytes, new_value);
                state_changes.push(StateChange::StorageChange {
                    account: ace_id,
                    slot: slot_bytes,
                    old_value,
                    new_value,
                });
            }
        }
    }

    Ok(state_changes)
}

// ── Payload parsers ──

fn parse_call(payload: &[u8]) -> Result<(TxKind, u64, u64, Bytes), NVmError> {
    // 0x10: [to:20][value:8 LE][gas_limit:8 LE][calldata...]
    if payload.len() < 37 {
        return Err(NVmError::EvmError("call payload too short".into()));
    }
    let mut to = [0u8; 20];
    to.copy_from_slice(&payload[1..21]);
    let value = u64::from_le_bytes(payload[21..29].try_into().unwrap());
    let gas_limit = u64::from_le_bytes(payload[29..37].try_into().unwrap());
    let gas_limit = if gas_limit == 0 {
        DEFAULT_GAS_LIMIT
    } else {
        gas_limit
    };
    let calldata = Bytes::copy_from_slice(&payload[37..]);
    Ok((TxKind::Call(Address::from(to)), value, gas_limit, calldata))
}

fn parse_create(payload: &[u8]) -> Result<(TxKind, u64, u64, Bytes), NVmError> {
    // 0x11: [value:8 LE][gas_limit:8 LE][init_code...]
    if payload.len() < 17 {
        return Err(NVmError::EvmError("create payload too short".into()));
    }
    let value = u64::from_le_bytes(payload[1..9].try_into().unwrap());
    let gas_limit = u64::from_le_bytes(payload[9..17].try_into().unwrap());
    let gas_limit = if gas_limit == 0 {
        DEFAULT_GAS_LIMIT
    } else {
        gas_limit
    };
    let init_code = Bytes::copy_from_slice(&payload[17..]);
    Ok((TxKind::Create, value, gas_limit, init_code))
}

fn parse_transfer(payload: &[u8]) -> Result<(TxKind, u64, u64, Bytes), NVmError> {
    // 0x12: [to:20][value:8 LE]
    if payload.len() < 29 {
        return Err(NVmError::EvmError("transfer payload too short".into()));
    }
    let mut to = [0u8; 20];
    to.copy_from_slice(&payload[1..21]);
    let value = u64::from_le_bytes(payload[21..29].try_into().unwrap());
    Ok((TxKind::Call(Address::from(to)), value, 21_000, Bytes::new()))
}

#[cfg(test)]
mod tests {
    use super::{maybe_execute_runtime_erc20_tx, AddressNamespace, ERC20_TRANSFER_SELECTOR};
    use crate::token_runtime;
    use ace_model::account::{Account, AccountId};
    use ace_model::state_tree::StateTree;
    use ace_runtime::crypto::TaggedSignature;
    use ace_runtime::types::attestation::{Attestation, Domain};
    use ace_runtime::types::transaction::Transaction;
    use revm::primitives::{Address, Bytes, TxKind};

    fn dummy_tx(sender: AccountId) -> Transaction {
        Transaction::new(
            vec![],
            Attestation {
                obj_hash: [0u8; 32],
                idcom: sender.0,
                domain: Domain::new(1, 0),
                context_tag: [0u8; 16],
                credential: TaggedSignature::ed25519([0u8; 64]),
            },
        )
    }

    fn abi_encode_transfer(to: [u8; 20], amount: u64) -> Bytes {
        let mut calldata = Vec::with_capacity(68);
        calldata.extend_from_slice(&ERC20_TRANSFER_SELECTOR);
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(&to);
        calldata.extend_from_slice(&[0u8; 24]);
        calldata.extend_from_slice(&amount.to_be_bytes());
        Bytes::from(calldata)
    }

    #[test]
    fn runtime_erc20_transfer_uses_alias_bound_accounts() {
        let sender = AccountId::from_bytes([0x11; 32]);
        let recipient = AccountId::from_bytes([0x22; 32]);
        let sender_evm = [0x33; 20];
        let recipient_evm = [0x44; 20];
        let shadow_recipient =
            AccountId::from_bytes(ace_runtime::crypto::legacy_idcom_evm(&recipient_evm));
        assert_ne!(shadow_recipient, recipient);

        let mut state = StateTree::new();
        state.insert(Account::with_evm_address(sender, sender_evm));
        state.insert(Account::with_evm_address(recipient, recipient_evm));

        let mint = [0x55; 32];
        token_runtime::create_mint(&mut state, &mint, 6, sender.as_bytes()).expect("mint");
        token_runtime::mint_to_owner(&mut state, &mint, sender.as_bytes(), 100, &sender)
            .expect("mint to sender");

        let contract = token_runtime::runtime_erc20_address_for_mint(&mint);
        let receipt = maybe_execute_runtime_erc20_tx(
            &mut state,
            &dummy_tx(sender),
            &sender,
            sender_evm,
            AddressNamespace::Evm,
            &TxKind::Call(Address::from(contract)),
            0,
            100_000,
            &abi_encode_transfer(recipient_evm, 25),
        )
        .expect("runtime erc20 execution")
        .expect("runtime path receipt");

        assert!(receipt.success);
        assert_eq!(token_runtime::balance_of(&state, &mint, &sender), 75);
        assert_eq!(token_runtime::balance_of(&state, &mint, &recipient), 25);
        assert_eq!(
            token_runtime::balance_of(&state, &mint, &shadow_recipient),
            0
        );
    }
}
