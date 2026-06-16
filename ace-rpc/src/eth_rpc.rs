//! Ethereum JSON-RPC compatibility layer.
//!
//! Implements the standard `eth_*`, `net_*`, and `web3_*` methods so that
//! browser wallets (MetaMask, Rabby, etc.) can connect to ACE Chain
//! as if it were an EVM-compatible network.
//!
//! Gas pricing is always zero (ACE handles fees separately via ZK proofs).
//! Slot numbers map to block numbers. Attestation idcoms are truncated to
//! 20-byte Ethereum addresses where needed.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use ace_runtime::crypto::TaggedSignature;

use jsonrpsee::core::{async_trait, RpcResult, SubscriptionResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{PendingSubscriptionSink, SubscriptionMessage};
use parking_lot::RwLock;
use revm::primitives::{
    Address, Bytes, ExecutionResult, Output, SpecId, SuccessReason, TxKind, U256,
};
use revm::Evm;
use tokio::sync::broadcast;

use crate::error::RpcError;
use crate::methods::{
    check_tx_decoded_len, check_tx_hex_len, reject_unsupported_evm_tx_type, RpcState,
};
use crate::raw_tx::{
    decode_evm_auto, detect_format, evm_payload_call, evm_payload_create, evm_tx_hash,
    validate_chain, EvmDecoded, RawTxFormat,
};
use crate::types::{EthBlock, EthLog, EthTransactionReceipt};
use ace_model::block_store::BlockStore;
use ace_model::state_tree::StateTree;
use ace_n_vm::evm::database::AceStateDb;
use ace_n_vm::token_runtime;
use ace_runtime::crypto::legacy_idcom_evm;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use sha2::Digest;
use tiny_keccak::{Hasher, Keccak};

/// Ethereum-compatible JSON-RPC API trait.
///
/// These methods allow standard Ethereum wallets (MetaMask, Rabby) to interact
/// with ACE Chain using the familiar eth_* namespace.
#[rpc(server)]
pub trait EthRpc {
    /// Returns the chain ID (EIP-695).
    #[method(name = "eth_chainId")]
    fn eth_chain_id(&self) -> RpcResult<String>;

    /// Returns the current block number (slot).
    #[method(name = "eth_blockNumber")]
    fn eth_block_number(&self) -> RpcResult<String>;

    /// Returns the balance of an account by Ethereum address (20-byte hex).
    ///
    /// Looks up the account by legacy EVM idcom mapping. The `block` parameter
    /// is accepted but ignored (always returns latest state).
    #[method(name = "eth_getBalance")]
    fn eth_get_balance(&self, address: String, block: Option<String>) -> RpcResult<String>;

    /// Returns the transaction count (nonce) for an address.
    #[method(name = "eth_getTransactionCount")]
    fn eth_get_transaction_count(
        &self,
        address: String,
        block: Option<String>,
    ) -> RpcResult<String>;

    /// Submit a signed raw transaction (hex-encoded).
    ///
    /// Supports legacy EIP-155, EIP-2930 (Type 1), EIP-1559 (Type 2),
    /// EIP-4844 blob transactions (Type 3), and EIP-7702 (Type 4).
    /// Returns the transaction hash.
    #[method(name = "eth_sendRawTransaction")]
    fn eth_send_raw_transaction(&self, raw_hex: String) -> RpcResult<String>;

    /// Execute a call without creating a transaction (read-only).
    #[method(name = "eth_call")]
    fn eth_call(&self, call_object: serde_json::Value, block: Option<String>) -> RpcResult<String>;

    /// Estimate gas for a transaction using a read-only EVM execution.
    #[method(name = "eth_estimateGas")]
    fn eth_estimate_gas(
        &self,
        call_object: serde_json::Value,
        block: Option<String>,
    ) -> RpcResult<String>;

    /// Returns the current gas price (always 0 on ACE — fees handled by ZK proofs).
    #[method(name = "eth_gasPrice")]
    fn eth_gas_price(&self) -> RpcResult<String>;

    /// Returns fee history (EIP-1559). Always returns zero fees on ACE.
    #[method(name = "eth_feeHistory")]
    fn eth_fee_history(
        &self,
        block_count: String,
        newest_block: String,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<serde_json::Value>;

    /// Returns a block by number.
    #[method(name = "eth_getBlockByNumber")]
    fn eth_get_block_by_number(
        &self,
        block: String,
        full_transactions: bool,
    ) -> RpcResult<Option<EthBlock>>;

    /// Returns a block by hash.
    #[method(name = "eth_getBlockByHash")]
    fn eth_get_block_by_hash(
        &self,
        hash: String,
        full_transactions: bool,
    ) -> RpcResult<Option<EthBlock>>;

    #[method(name = "eth_getBlockTransactionCountByNumber")]
    fn eth_get_block_transaction_count_by_number(&self, block: String)
        -> RpcResult<Option<String>>;

    #[method(name = "eth_getBlockTransactionCountByHash")]
    fn eth_get_block_transaction_count_by_hash(&self, hash: String) -> RpcResult<Option<String>>;

    /// Returns a transaction receipt by hash.
    #[method(name = "eth_getTransactionReceipt")]
    fn eth_get_transaction_receipt(
        &self,
        tx_hash: String,
    ) -> RpcResult<Option<EthTransactionReceipt>>;

    /// Returns a transaction by hash.
    #[method(name = "eth_getTransactionByHash")]
    fn eth_get_transaction_by_hash(&self, tx_hash: String) -> RpcResult<Option<serde_json::Value>>;

    #[method(name = "eth_getTransactionByBlockNumberAndIndex")]
    fn eth_get_transaction_by_block_number_and_index(
        &self,
        block: String,
        index: String,
    ) -> RpcResult<Option<serde_json::Value>>;

    #[method(name = "eth_getTransactionByBlockHashAndIndex")]
    fn eth_get_transaction_by_block_hash_and_index(
        &self,
        hash: String,
        index: String,
    ) -> RpcResult<Option<serde_json::Value>>;

    #[method(name = "eth_getBlockReceipts")]
    fn eth_get_block_receipts(&self, block: String) -> RpcResult<Vec<EthTransactionReceipt>>;

    /// Returns code at a given address.
    #[method(name = "eth_getCode")]
    fn eth_get_code(&self, address: String, block: Option<String>) -> RpcResult<String>;

    /// Returns storage at a given position.
    #[method(name = "eth_getStorageAt")]
    fn eth_get_storage_at(
        &self,
        address: String,
        position: String,
        block: Option<String>,
    ) -> RpcResult<String>;

    /// Returns the network version (same as chain_id for EIP-155 networks).
    #[method(name = "net_version")]
    fn net_version(&self) -> RpcResult<String>;

    /// Returns true if the node is listening for connections.
    #[method(name = "net_listening")]
    fn net_listening(&self) -> RpcResult<bool>;

    #[method(name = "eth_syncing")]
    fn eth_syncing(&self) -> RpcResult<serde_json::Value>;

    /// Returns the client version string.
    #[method(name = "web3_clientVersion")]
    fn web3_client_version(&self) -> RpcResult<String>;

    /// Returns the number of connected peers.
    #[method(name = "net_peerCount")]
    fn net_peer_count(&self) -> RpcResult<String>;

    /// Returns the list of supported accounts (empty for a non-custodial node).
    #[method(name = "eth_accounts")]
    fn eth_accounts(&self) -> RpcResult<Vec<String>>;

    /// Returns the max priority fee per gas (always 0 on ACE).
    #[method(name = "eth_maxPriorityFeePerGas")]
    fn eth_max_priority_fee_per_gas(&self) -> RpcResult<String>;

    /// Returns logs matching a filter from the persisted receipt index.
    #[method(name = "eth_getLogs")]
    fn eth_get_logs(&self, filter: serde_json::Value) -> RpcResult<Vec<EthLog>>;

    #[method(name = "eth_newFilter")]
    fn eth_new_filter(&self, filter: serde_json::Value) -> RpcResult<String>;

    #[method(name = "eth_newBlockFilter")]
    fn eth_new_block_filter(&self) -> RpcResult<String>;

    #[method(name = "eth_newPendingTransactionFilter")]
    fn eth_new_pending_transaction_filter(&self) -> RpcResult<String>;

    #[method(name = "eth_getFilterChanges")]
    fn eth_get_filter_changes(&self, filter_id: String) -> RpcResult<serde_json::Value>;

    #[method(name = "eth_getFilterLogs")]
    fn eth_get_filter_logs(&self, filter_id: String) -> RpcResult<Vec<EthLog>>;

    #[method(name = "eth_uninstallFilter")]
    fn eth_uninstall_filter(&self, filter_id: String) -> RpcResult<bool>;

    #[subscription(
        name = "eth_subscribe" => "eth_subscription",
        unsubscribe = "eth_unsubscribe",
        item = serde_json::Value
    )]
    async fn eth_subscribe(
        &self,
        kind: String,
        params: Option<serde_json::Value>,
    ) -> SubscriptionResult;

    #[method(name = "debug_traceTransaction")]
    fn debug_trace_transaction(
        &self,
        tx_hash: String,
        options: Option<serde_json::Value>,
    ) -> RpcResult<serde_json::Value>;

    #[method(name = "trace_transaction")]
    fn trace_transaction(&self, tx_hash: String) -> RpcResult<Vec<serde_json::Value>>;
}

/// Implementation of the Ethereum-compatible RPC API.
pub struct EthRpcImpl<B: BlockStore> {
    pub shared: Arc<RpcState<B>>,
}

#[async_trait]
impl<B: BlockStore + Send + Sync + 'static> EthRpcServer for EthRpcImpl<B> {
    fn eth_chain_id(&self) -> RpcResult<String> {
        Ok(format!("0x{:x}", self.shared.chain_id))
    }

    fn eth_block_number(&self) -> RpcResult<String> {
        let slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        Ok(format!("0x{:x}", slot))
    }

    fn eth_get_balance(&self, address: String, _block: Option<String>) -> RpcResult<String> {
        let addr = parse_eth_address(&address)?;
        let state = self.shared.state.read();
        match resolve_eth_account_id(&state, &addr).and_then(|ace_id| state.get(&ace_id)) {
            Some(account) => Ok(format!("0x{:x}", account.balance)),
            None => Ok("0x0".into()),
        }
    }

    fn eth_get_transaction_count(
        &self,
        address: String,
        _block: Option<String>,
    ) -> RpcResult<String> {
        let addr = parse_eth_address(&address)?;
        let state = self.shared.state.read();
        match resolve_eth_account_id(&state, &addr).and_then(|ace_id| state.get(&ace_id)) {
            Some(account) => Ok(format!("0x{:x}", account.nonce)),
            None => Ok("0x0".into()),
        }
    }

    fn eth_send_raw_transaction(&self, raw_hex: String) -> RpcResult<String> {
        let hex_str = raw_hex.strip_prefix("0x").unwrap_or(&raw_hex);
        check_tx_hex_len(hex_str)?;
        let raw_bytes = hex::decode(hex_str).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
        check_tx_decoded_len(raw_bytes.len())?;

        let format = detect_format(&raw_bytes);
        if format != RawTxFormat::Evm {
            return Err(RpcError::InvalidParameter(
                "eth_sendRawTransaction only accepts EVM transactions".into(),
            )
            .into());
        }

        let decoded = decode_evm_auto(&raw_bytes)?;
        reject_unsupported_evm_tx_type(decoded.tx_type)?;
        validate_chain(format, self.shared.chain_id, Some(&decoded.parsed))?;

        let current_slot = u32::try_from(
            self.shared
                .current_slot
                .load(std::sync::atomic::Ordering::Relaxed),
        )
        .unwrap_or(u32::MAX);

        let payload = if decoded.is_create {
            evm_payload_create(decoded.value, decoded.gas_limit, &decoded.data)
        } else {
            evm_payload_call(&decoded.to, decoded.value, decoded.gas_limit, &decoded.data)
        };

        let obj_hash = {
            let mut h = [0u8; 32];
            let digest = sha2::Sha256::digest(&payload);
            h.copy_from_slice(&digest);
            h
        };
        let idcom = legacy_idcom_evm(&decoded.parsed.signer);
        let domain = Domain::new(self.shared.chain_id, current_slot);
        let attestation = Attestation {
            obj_hash,
            idcom,
            domain,
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        };
        let tx =
            Transaction::with_raw_chain(payload, attestation, RawChainKind::Evm, raw_bytes.clone());

        let response_hash = eth_display_tx_hash(&tx);
        self.shared.submit_transaction_to_mempool(tx)?;
        Ok(response_hash)
    }

    fn eth_call(
        &self,
        call_object: serde_json::Value,
        _block: Option<String>,
    ) -> RpcResult<String> {
        let call = parse_eth_call_object(&call_object)?;
        let state = self.shared.state.read();
        let result = execute_eth_call(&state, call)?;

        match result {
            ExecutionResult::Success { output, .. } => {
                let bytes = match output {
                    Output::Call(data) => data.to_vec(),
                    Output::Create(data, _) => data.to_vec(),
                };
                Ok(format!("0x{}", hex::encode(bytes)))
            }
            ExecutionResult::Revert { output, .. } => Err(RpcError::InvalidParameter(format!(
                "eth_call reverted: 0x{}",
                hex::encode(output)
            ))
            .into()),
            ExecutionResult::Halt { reason, .. } => {
                Err(RpcError::InvalidParameter(format!("eth_call halted: {reason:?}")).into())
            }
        }
    }

    fn eth_estimate_gas(
        &self,
        call_object: serde_json::Value,
        _block: Option<String>,
    ) -> RpcResult<String> {
        let call = parse_eth_call_object(&call_object)?;
        let state = self.shared.state.read();
        let result = execute_eth_call(&state, call)?;

        match result {
            ExecutionResult::Success { gas_used, .. } => Ok(format!("0x{:x}", gas_used)),
            ExecutionResult::Revert { output, .. } => Err(RpcError::InvalidParameter(format!(
                "eth_estimateGas reverted: 0x{}",
                hex::encode(output)
            ))
            .into()),
            ExecutionResult::Halt { reason, .. } => Err(RpcError::InvalidParameter(format!(
                "eth_estimateGas halted: {reason:?}"
            ))
            .into()),
        }
    }

    fn eth_gas_price(&self) -> RpcResult<String> {
        // Gas price is always 0 on ACE (fees handled via ZK proofs, not gas auction)
        Ok("0x0".into())
    }

    fn eth_fee_history(
        &self,
        _block_count: String,
        _newest_block: String,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<serde_json::Value> {
        let slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        let oldest_block = format!("0x{:x}", slot);
        let n = 1usize; // Return at least 1 entry

        let base_fee_per_gas = vec!["0x0".to_string(); n + 1];
        let gas_used_ratio = vec![0.0f64; n];

        let reward = reward_percentiles.map(|percs| {
            (0..n)
                .map(|_| percs.iter().map(|_| "0x0".to_string()).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        });

        let mut result = serde_json::json!({
            "oldestBlock": oldest_block,
            "baseFeePerGas": base_fee_per_gas,
            "gasUsedRatio": gas_used_ratio,
        });
        if let Some(r) = reward {
            result["reward"] = serde_json::json!(r);
        }
        Ok(result)
    }

    fn eth_get_block_by_number(
        &self,
        block: String,
        full_transactions: bool,
    ) -> RpcResult<Option<EthBlock>> {
        let slot = resolve_block_number(&block, &self.shared)?;
        let receipts = self
            .shared
            .tx_receipt_store
            .read()
            .get_receipts_for_slot(slot);
        let store = self.shared.block_store.read();
        Ok(store
            .get_block_by_slot(slot)
            .map(|b| build_eth_block(&b, &receipts, full_transactions)))
    }

    fn eth_get_block_by_hash(
        &self,
        hash: String,
        full_transactions: bool,
    ) -> RpcResult<Option<EthBlock>> {
        let hash_hex = hash.strip_prefix("0x").unwrap_or(&hash);
        let hash_bytes = hex::decode(hash_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
        if hash_bytes.len() != 32 {
            return Err(RpcError::InvalidParameter("hash must be 32 bytes".into()).into());
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash_bytes);

        let store = self.shared.block_store.read();
        Ok(store.get_block_by_hash(&h).map(|b| {
            let receipts = self
                .shared
                .tx_receipt_store
                .read()
                .get_receipts_for_slot(b.header.slot);
            build_eth_block(&b, &receipts, full_transactions)
        }))
    }

    fn eth_get_block_transaction_count_by_number(
        &self,
        block: String,
    ) -> RpcResult<Option<String>> {
        let slot = resolve_block_number(&block, &self.shared)?;
        let store = self.shared.block_store.read();
        Ok(store
            .get_block_by_slot(slot)
            .map(|block| format!("0x{:x}", block.transactions.len())))
    }

    fn eth_get_block_transaction_count_by_hash(&self, hash: String) -> RpcResult<Option<String>> {
        let block_hash = parse_block_hash(&hash)?;
        let store = self.shared.block_store.read();
        Ok(store
            .get_block_by_hash(&block_hash)
            .map(|block| format!("0x{:x}", block.transactions.len())))
    }

    fn eth_get_transaction_receipt(
        &self,
        tx_hash: String,
    ) -> RpcResult<Option<EthTransactionReceipt>> {
        let hash_hex = tx_hash.strip_prefix("0x").unwrap_or(&tx_hash);
        let hash_bytes = hex::decode(hash_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
        if hash_bytes.len() != 32 {
            return Err(RpcError::InvalidParameter("tx hash must be 32 bytes".into()).into());
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash_bytes);

        let store = self.shared.tx_receipt_store.read();
        let (slot, index) = match store.get_location(&h) {
            Some(loc) => loc,
            None => return Ok(None),
        };
        let receipt = match store.get_receipt(slot, index) {
            Some(r) => r,
            None => return Ok(None),
        };
        drop(store);

        let block_store = self.shared.block_store.read();
        let block = match block_store.get_block_by_slot(slot) {
            Some(block) => block,
            None => return Ok(None),
        };
        let tx = match block.transactions.get(index as usize) {
            Some(tx) => tx,
            None => return Ok(None),
        };
        let cumulative_gas_used = self
            .shared
            .tx_receipt_store
            .read()
            .get_receipts_for_slot(slot)
            .into_iter()
            .take_while(|candidate| candidate.transaction_index <= receipt.transaction_index)
            .map(|candidate| candidate.gas_used.unwrap_or(0))
            .sum();

        Ok(Some(build_eth_receipt(
            &receipt,
            tx,
            slot,
            cumulative_gas_used,
        )))
    }

    fn eth_get_transaction_by_hash(&self, tx_hash: String) -> RpcResult<Option<serde_json::Value>> {
        let hash_hex = tx_hash.strip_prefix("0x").unwrap_or(&tx_hash);
        let hash_bytes = hex::decode(hash_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
        if hash_bytes.len() != 32 {
            return Err(RpcError::InvalidParameter("tx hash must be 32 bytes".into()).into());
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash_bytes);

        let store = self.shared.tx_receipt_store.read();
        let (slot, index) = match store.get_location(&h) {
            Some(loc) => loc,
            None => return Ok(None),
        };
        drop(store);

        let block_store = self.shared.block_store.read();
        let block = match block_store.get_block_by_slot(slot) {
            Some(b) => b,
            None => return Ok(None),
        };
        let tx = match block.transactions.get(index as usize) {
            Some(t) => t,
            None => return Ok(None),
        };

        Ok(Some(build_eth_transaction_value(
            tx,
            Some(block.hash()),
            Some(slot),
            Some(index),
        )))
    }

    fn eth_get_transaction_by_block_number_and_index(
        &self,
        block: String,
        index: String,
    ) -> RpcResult<Option<serde_json::Value>> {
        let slot = resolve_block_number(&block, &self.shared)?;
        let index = parse_hex_u64(&index)? as usize;
        let store = self.shared.block_store.read();
        let Some(block) = store.get_block_by_slot(slot) else {
            return Ok(None);
        };
        let Some(tx) = block.transactions.get(index) else {
            return Ok(None);
        };
        Ok(Some(build_eth_transaction_value(
            tx,
            Some(block.hash()),
            Some(slot),
            Some(index as u32),
        )))
    }

    fn eth_get_transaction_by_block_hash_and_index(
        &self,
        hash: String,
        index: String,
    ) -> RpcResult<Option<serde_json::Value>> {
        let block_hash = parse_block_hash(&hash)?;
        let index = parse_hex_u64(&index)? as usize;
        let store = self.shared.block_store.read();
        let Some(block) = store.get_block_by_hash(&block_hash) else {
            return Ok(None);
        };
        let Some(tx) = block.transactions.get(index) else {
            return Ok(None);
        };
        Ok(Some(build_eth_transaction_value(
            tx,
            Some(block.hash()),
            Some(block.header.slot),
            Some(index as u32),
        )))
    }

    fn eth_get_block_receipts(&self, block: String) -> RpcResult<Vec<EthTransactionReceipt>> {
        let slot = resolve_block_number(&block, &self.shared)?;
        Ok(build_eth_receipts_for_slot(&self.shared, slot)?)
    }

    fn eth_get_code(&self, address: String, _block: Option<String>) -> RpcResult<String> {
        let addr = parse_eth_address(&address)?;
        let state = self.shared.state.read();
        if runtime_erc20_ledger_state(&state, &addr).is_some() {
            return Ok(format!("0x{}", hex::encode(runtime_erc20_stub_code())));
        }
        match resolve_eth_account_id(&state, &addr).and_then(|ace_id| state.get(&ace_id)) {
            Some(account) => {
                if let Some(ref code) = account.code {
                    Ok(format!("0x{}", hex::encode(code)))
                } else {
                    Ok("0x".into())
                }
            }
            None => Ok("0x".into()),
        }
    }

    fn eth_get_storage_at(
        &self,
        address: String,
        position: String,
        _block: Option<String>,
    ) -> RpcResult<String> {
        let addr = parse_eth_address(&address)?;

        let pos_hex = position.strip_prefix("0x").unwrap_or(&position);
        let pos_bytes = hex::decode(pos_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
        let mut slot = [0u8; 32];
        if pos_bytes.len() <= 32 {
            slot[32 - pos_bytes.len()..].copy_from_slice(&pos_bytes);
        } else {
            return Err(RpcError::InvalidParameter(format!(
                "storage position exceeds 32 bytes: got {}",
                pos_bytes.len()
            ))
            .into());
        }

        let state = self.shared.state.read();
        let value = resolve_eth_account_id(&state, &addr)
            .map(|ace_id| state.get_storage(&ace_id, &slot))
            .unwrap_or([0u8; 32]);
        Ok(format!("0x{}", hex::encode(value)))
    }

    fn net_version(&self) -> RpcResult<String> {
        Ok(self.shared.chain_id.to_string())
    }

    fn net_listening(&self) -> RpcResult<bool> {
        Ok(true)
    }

    fn eth_syncing(&self) -> RpcResult<serde_json::Value> {
        Ok(serde_json::Value::Bool(false))
    }

    fn web3_client_version(&self) -> RpcResult<String> {
        Ok("ACE-Chain/0.1.0/rust".into())
    }

    fn net_peer_count(&self) -> RpcResult<String> {
        Ok("0x0".into())
    }

    fn eth_accounts(&self) -> RpcResult<Vec<String>> {
        Ok(vec![])
    }

    fn eth_max_priority_fee_per_gas(&self) -> RpcResult<String> {
        Ok("0x0".into())
    }

    fn eth_get_logs(&self, _filter: serde_json::Value) -> RpcResult<Vec<EthLog>> {
        const MAX_LOG_RESULTS: usize = 10_000;
        const MAX_LOG_BLOCK_RANGE: u64 = 1000;
        let current_slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        let filter = parse_eth_log_filter(&_filter, current_slot)?;
        let (from_slot, to_slot) = if let Some(block_hash) = &filter.block_hash {
            let block_store = self.shared.block_store.read();
            let slot = block_store
                .get_block_by_hash(&parse_bytes32(block_hash)?)
                .map(|block| block.header.slot);
            (slot, slot)
        } else {
            (filter.from_block, filter.to_block)
        };
        if let (Some(from), Some(to)) = (from_slot, to_slot) {
            if to.saturating_sub(from) > MAX_LOG_BLOCK_RANGE {
                return Err(RpcError::InvalidParameter(format!(
                    "block range too large, max {} slots",
                    MAX_LOG_BLOCK_RANGE
                ))
                .into());
            }
        }
        let logs = self.shared.tx_receipt_store.read().collect_matching_logs(
            from_slot,
            to_slot,
            MAX_LOG_RESULTS,
            |log| log_matches_filter(log, &filter),
        );
        Ok(logs)
    }

    fn eth_new_filter(&self, filter: serde_json::Value) -> RpcResult<String> {
        let current_slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        let filter = parse_eth_log_filter(&filter, current_slot)?;
        Ok(self.shared.eth_events.install_log_filter(filter)?)
    }

    fn eth_new_block_filter(&self) -> RpcResult<String> {
        Ok(self.shared.eth_events.install_block_filter()?)
    }

    fn eth_new_pending_transaction_filter(&self) -> RpcResult<String> {
        Ok(self.shared.eth_events.install_pending_tx_filter()?)
    }

    fn eth_get_filter_changes(&self, filter_id: String) -> RpcResult<serde_json::Value> {
        Ok(self.shared.eth_events.get_filter_changes(&filter_id)?)
    }

    fn eth_get_filter_logs(&self, filter_id: String) -> RpcResult<Vec<EthLog>> {
        Ok(self.shared.eth_events.get_filter_logs(&filter_id)?)
    }

    fn eth_uninstall_filter(&self, filter_id: String) -> RpcResult<bool> {
        Ok(self.shared.eth_events.uninstall_filter(&filter_id))
    }

    async fn eth_subscribe(
        &self,
        pending: PendingSubscriptionSink,
        kind: String,
        params: Option<serde_json::Value>,
    ) -> SubscriptionResult {
        validate_subscription_kind(&kind)?;
        let log_filter = if kind == "logs" {
            let current_slot = self
                .shared
                .current_slot
                .load(std::sync::atomic::Ordering::Relaxed);
            Some(parse_eth_log_filter(
                params.as_ref().unwrap_or(&serde_json::Value::Null),
                current_slot,
            )?)
        } else {
            None
        };

        let sink = pending.accept().await?;
        let mut rx = self.shared.eth_events.subscribe();

        tokio::spawn(async move {
            let sink = sink;
            loop {
                let item = match rx.recv().await {
                    Ok(EthEvent::NewHead(head)) if kind == "newHeads" => Some(head),
                    Ok(EthEvent::PendingTx(tx_hash)) if kind == "newPendingTransactions" => {
                        Some(serde_json::Value::String(tx_hash))
                    }
                    Ok(EthEvent::Log(log)) if kind == "logs" => log_filter
                        .as_ref()
                        .filter(|filter| log_matches_filter(&log, filter))
                        .map(|_| serde_json::to_value(log).unwrap_or(serde_json::Value::Null)),
                    Ok(_) => None,
                    Err(_) => break,
                };

                let Some(item) = item else {
                    continue;
                };
                let Ok(message) = SubscriptionMessage::from_json(&item) else {
                    continue;
                };
                if sink.send(message).await.is_err() {
                    break;
                }
            }
        });

        Ok(())
    }

    fn debug_trace_transaction(
        &self,
        tx_hash: String,
        _options: Option<serde_json::Value>,
    ) -> RpcResult<serde_json::Value> {
        let (receipt, tx, slot, _block_hash) = lookup_evm_transaction(&self.shared, &tx_hash)?;
        let decoded = decoded_evm_tx(&tx).ok_or_else(|| {
            RpcError::InvalidParameter("transaction is not an EVM transaction".into())
        })?;

        Ok(serde_json::json!({
            "gas": format!("0x{:x}", receipt.gas_used.unwrap_or(0)),
            "failed": !receipt.status,
            "returnValue": "",
            "structLogs": [],
            "from": format!("0x{}", hex::encode(decoded.parsed.signer)),
            "to": (!decoded.is_create).then(|| format!("0x{}", hex::encode(decoded.to))),
            "type": format!("0x{:x}", decoded.tx_type),
            "blockNumber": format!("0x{:x}", slot),
            "stateChanges": receipt.state_changes,
            "logs": receipt.evm_logs,
        }))
    }

    fn trace_transaction(&self, tx_hash: String) -> RpcResult<Vec<serde_json::Value>> {
        let (receipt, tx, slot, block_hash) = lookup_evm_transaction(&self.shared, &tx_hash)?;
        let decoded = decoded_evm_tx(&tx).ok_or_else(|| {
            RpcError::InvalidParameter("transaction is not an EVM transaction".into())
        })?;

        Ok(vec![serde_json::json!({
            "type": "call",
            "action": {
                "from": format!("0x{}", hex::encode(decoded.parsed.signer)),
                "to": (!decoded.is_create).then(|| format!("0x{}", hex::encode(decoded.to))),
                "gas": format!("0x{:x}", decoded.gas_limit),
                "value": format!("0x{:x}", decoded.value),
                "input": format!("0x{}", hex::encode(decoded.data)),
                "callType": if decoded.is_create { serde_json::Value::Null } else { serde_json::Value::String("call".into()) },
            },
            "result": {
                "gasUsed": format!("0x{:x}", receipt.gas_used.unwrap_or(0)),
                "address": receipt.contract_address.as_ref().map(|addr| format!("0x{}", addr)),
                "output": "0x",
            },
            "error": receipt.error,
            "traceAddress": Vec::<u32>::new(),
            "subtraces": 0,
            "transactionHash": format!("0x{}", tx_hash.strip_prefix("0x").unwrap_or(&tx_hash)),
            "transactionPosition": format!("0x{:x}", receipt.transaction_index),
            "blockHash": format!("0x{}", hex::encode(block_hash)),
            "blockNumber": format!("0x{:x}", slot),
        })])
    }
}

// ── Helpers ──

struct ParsedEthCall {
    from: [u8; 20],
    tx_kind: TxKind,
    value: U256,
    gas: Option<u64>,
    data: Bytes,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct EthLogFilter {
    block_hash: Option<String>,
    from_block: Option<u64>,
    to_block: Option<u64>,
    addresses: Option<Vec<String>>,
    topics: Vec<Option<Vec<String>>>,
}

#[derive(Debug, Clone)]
pub(crate) enum EthEvent {
    NewHead(serde_json::Value),
    PendingTx(String),
    Log(EthLog),
}

#[derive(Debug, Clone)]
enum InstalledFilter {
    Blocks {
        cursor: u64,
    },
    PendingTx {
        cursor: u64,
    },
    Logs {
        cursor: u64,
        created_at: u64,
        filter: EthLogFilter,
    },
}

#[derive(Default)]
struct FilterState {
    next_id: u64,
    block_hashes: VecDeque<String>,
    block_hashes_base: u64,
    pending_txs: VecDeque<String>,
    pending_txs_base: u64,
    logs: VecDeque<EthLog>,
    logs_base: u64,
    filters: std::collections::HashMap<u64, InstalledFilter>,
}

pub struct EthEventHub {
    sender: broadcast::Sender<EthEvent>,
    state: RwLock<FilterState>,
    max_events: usize,
    max_filters: usize,
}

impl EthEventHub {
    pub fn new(max_events: usize) -> Self {
        Self::with_limits(max_events, 1024)
    }

    pub fn with_limits(max_events: usize, max_filters: usize) -> Self {
        let (sender, _) = broadcast::channel(512);
        Self {
            sender,
            state: RwLock::new(FilterState::default()),
            max_events,
            max_filters: max_filters.max(1),
        }
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<EthEvent> {
        self.sender.subscribe()
    }

    fn allocate_filter_id(&self, state: &mut FilterState) -> Result<u64, RpcError> {
        if state.filters.len() >= self.max_filters {
            return Err(RpcError::InvalidParameter(format!(
                "too many installed filters (max {})",
                self.max_filters
            )));
        }
        state.next_id += 1;
        Ok(state.next_id)
    }

    pub fn install_block_filter(&self) -> Result<String, RpcError> {
        let mut state = self.state.write();
        let filter_id = self.allocate_filter_id(&mut state)?;
        let cursor = state.block_hashes_base + state.block_hashes.len() as u64;
        state
            .filters
            .insert(filter_id, InstalledFilter::Blocks { cursor });
        Ok(format!("0x{:x}", filter_id))
    }

    pub fn install_pending_tx_filter(&self) -> Result<String, RpcError> {
        let mut state = self.state.write();
        let filter_id = self.allocate_filter_id(&mut state)?;
        let cursor = state.pending_txs_base + state.pending_txs.len() as u64;
        state
            .filters
            .insert(filter_id, InstalledFilter::PendingTx { cursor });
        Ok(format!("0x{:x}", filter_id))
    }

    pub(crate) fn install_log_filter(&self, filter: EthLogFilter) -> Result<String, RpcError> {
        let mut state = self.state.write();
        let filter_id = self.allocate_filter_id(&mut state)?;
        let cursor = state.logs_base + state.logs.len() as u64;
        let created_at = state.logs_base;
        state.filters.insert(
            filter_id,
            InstalledFilter::Logs {
                cursor,
                created_at,
                filter,
            },
        );
        Ok(format!("0x{:x}", filter_id))
    }

    pub fn uninstall_filter(&self, filter_id: &str) -> bool {
        parse_filter_id(filter_id)
            .ok()
            .and_then(|filter_id| self.state.write().filters.remove(&filter_id))
            .is_some()
    }

    pub fn get_filter_changes(&self, filter_id: &str) -> Result<serde_json::Value, RpcError> {
        let filter_id = parse_filter_id(filter_id)?;
        let mut state = self.state.write();
        let Some(snapshot) = state.filters.get(&filter_id).cloned() else {
            return Err(RpcError::InvalidParameter("unknown filter id".into()));
        };
        let result = match &snapshot {
            InstalledFilter::Blocks { cursor } => {
                let start = cursor.saturating_sub(state.block_hashes_base) as usize;
                let values = state
                    .block_hashes
                    .iter()
                    .skip(start.min(state.block_hashes.len()))
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect::<Vec<_>>();
                serde_json::Value::Array(values)
            }
            InstalledFilter::PendingTx { cursor } => {
                let start = cursor.saturating_sub(state.pending_txs_base) as usize;
                let values = state
                    .pending_txs
                    .iter()
                    .skip(start.min(state.pending_txs.len()))
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect::<Vec<_>>();
                serde_json::Value::Array(values)
            }
            InstalledFilter::Logs { cursor, filter, .. } => {
                let start = cursor.saturating_sub(state.logs_base) as usize;
                let values = state
                    .logs
                    .iter()
                    .skip(start.min(state.logs.len()))
                    .filter(|log| log_matches_filter(log, filter))
                    .cloned()
                    .map(serde_json::to_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| RpcError::ServerError(format!("failed to encode log: {e}")))?;
                serde_json::Value::Array(values)
            }
        };
        let next_block_cursor = state.block_hashes_base + state.block_hashes.len() as u64;
        let next_pending_cursor = state.pending_txs_base + state.pending_txs.len() as u64;
        let next_logs_cursor = state.logs_base + state.logs.len() as u64;
        if let Some(filter) = state.filters.get_mut(&filter_id) {
            match filter {
                InstalledFilter::Blocks { cursor } => {
                    *cursor = next_block_cursor;
                }
                InstalledFilter::PendingTx { cursor } => {
                    *cursor = next_pending_cursor;
                }
                InstalledFilter::Logs { cursor, .. } => {
                    *cursor = next_logs_cursor;
                }
            }
        }
        Ok(result)
    }

    pub fn get_filter_logs(&self, filter_id: &str) -> Result<Vec<EthLog>, RpcError> {
        let filter_id = parse_filter_id(filter_id)?;
        let state = self.state.read();
        let Some(filter) = state.filters.get(&filter_id) else {
            return Err(RpcError::InvalidParameter("unknown filter id".into()));
        };
        match filter {
            InstalledFilter::Logs {
                created_at, filter, ..
            } => {
                let start = created_at.saturating_sub(state.logs_base) as usize;
                let mut removed = HashSet::new();
                for log in state.logs.iter().skip(start.min(state.logs.len())) {
                    if log.removed && log_matches_filter(log, filter) {
                        removed.insert(log_identity(log));
                    }
                }
                Ok(state
                    .logs
                    .iter()
                    .skip(start.min(state.logs.len()))
                    .filter(|log| log_matches_filter(log, filter))
                    .filter(|log| !log.removed)
                    .filter(|log| !removed.contains(&log_identity(log)))
                    .cloned()
                    .collect())
            }
            _ => Err(RpcError::InvalidParameter(
                "filter id is not a log filter".into(),
            )),
        }
    }

    pub fn publish_new_head(&self, head: serde_json::Value) {
        let hash = head
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        if let Some(hash) = hash {
            let mut state = self.state.write();
            state.block_hashes.push_back(hash);
            while state.block_hashes.len() > self.max_events {
                state.block_hashes.pop_front();
                state.block_hashes_base += 1;
            }
        }
        let _ = self.sender.send(EthEvent::NewHead(head));
    }

    pub fn publish_pending_tx(&self, tx_hash: String) {
        {
            let mut state = self.state.write();
            state.pending_txs.push_back(tx_hash.clone());
            while state.pending_txs.len() > self.max_events {
                state.pending_txs.pop_front();
                state.pending_txs_base += 1;
            }
        }
        let _ = self.sender.send(EthEvent::PendingTx(tx_hash));
    }

    pub fn publish_logs<I>(&self, logs: I)
    where
        I: IntoIterator<Item = EthLog>,
    {
        let mut state = self.state.write();
        for log in logs {
            state.logs.push_back(log.clone());
            while state.logs.len() > self.max_events {
                state.logs.pop_front();
                state.logs_base += 1;
            }
            let _ = self.sender.send(EthEvent::Log(log));
        }
    }

    pub fn publish_removed_logs<I>(&self, logs: I)
    where
        I: IntoIterator<Item = EthLog>,
    {
        self.publish_logs(logs.into_iter().map(|mut log| {
            log.removed = true;
            log
        }));
    }
}

fn parse_filter_id(filter_id: &str) -> Result<u64, RpcError> {
    let filter_id = filter_id.strip_prefix("0x").unwrap_or(filter_id);
    u64::from_str_radix(filter_id, 16)
        .map_err(|e| RpcError::InvalidParameter(format!("invalid filter id: {e}")))
}

fn validate_subscription_kind(kind: &str) -> Result<(), RpcError> {
    match kind {
        "newHeads" | "newPendingTransactions" | "logs" => Ok(()),
        _ => Err(RpcError::InvalidParameter(format!(
            "unsupported subscription kind: {kind}"
        ))),
    }
}

fn log_identity(log: &EthLog) -> String {
    format!(
        "{}:{}:{}",
        log.block_hash, log.transaction_hash, log.log_index
    )
}

fn parse_eth_call_object(call_object: &serde_json::Value) -> Result<ParsedEthCall, RpcError> {
    let from = call_object
        .get("from")
        .and_then(serde_json::Value::as_str)
        .map(parse_eth_address)
        .transpose()?
        .unwrap_or([0u8; 20]);
    let to = call_object
        .get("to")
        .and_then(serde_json::Value::as_str)
        .map(parse_eth_address)
        .transpose()?;
    let value = call_object
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(parse_hex_u256)
        .transpose()?
        .unwrap_or(U256::ZERO);
    let gas = call_object
        .get("gas")
        .and_then(serde_json::Value::as_str)
        .map(parse_hex_u64)
        .transpose()?;
    let data = call_object
        .get("data")
        .and_then(serde_json::Value::as_str)
        .map(parse_hex_bytes)
        .transpose()?
        .unwrap_or_default();

    Ok(ParsedEthCall {
        from,
        tx_kind: match to {
            Some(addr) => TxKind::Call(Address::from(addr)),
            None => TxKind::Create,
        },
        value,
        gas,
        data: Bytes::from(data),
    })
}

fn execute_eth_call(
    state: &ace_model::sharded_state::ShardedState,
    call: ParsedEthCall,
) -> Result<ExecutionResult, RpcError> {
    if let Some(result) = maybe_execute_runtime_erc20_call(state, &call)? {
        return Ok(result);
    }

    let db = AceStateDb::new(state.default_shard());

    let mut evm = Evm::builder()
        .with_db(db)
        .with_spec_id(SpecId::SHANGHAI)
        .modify_tx_env(|tx_env| {
            tx_env.caller = Address::from(call.from);
            tx_env.transact_to = call.tx_kind;
            tx_env.value = call.value;
            tx_env.gas_limit = call.gas.unwrap_or(30_000_000);
            tx_env.gas_price = U256::ZERO;
            tx_env.data = call.data;
            tx_env.nonce = None;
        })
        .modify_block_env(|blk| {
            blk.gas_limit = U256::from(30_000_000u64);
            blk.basefee = U256::ZERO;
        })
        .build();

    evm.transact()
        .map(|result| result.result)
        .map_err(|e| RpcError::InvalidParameter(format!("EVM execution failed: {e:?}")))
}

const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const ERC20_APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const ERC20_TRANSFER_FROM_SELECTOR: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const ERC20_BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
const ERC20_ALLOWANCE_SELECTOR: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];
const ERC20_TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];
const ERC20_DECIMALS_SELECTOR: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];

fn maybe_execute_runtime_erc20_call(
    state: &ace_model::sharded_state::ShardedState,
    call: &ParsedEthCall,
) -> Result<Option<ExecutionResult>, RpcError> {
    let TxKind::Call(target) = call.tx_kind else {
        return Ok(None);
    };
    let target_bytes = target.0 .0;
    let Some((ledger_state, mint)) = runtime_erc20_ledger_state(state, &target_bytes) else {
        return Ok(None);
    };
    if call.value != U256::ZERO {
        return Ok(Some(ExecutionResult::Revert {
            gas_used: 25_000,
            output: b"runtime ERC-20 calls do not accept native value"
                .to_vec()
                .into(),
        }));
    }
    let selector = call.data.get(0..4).unwrap_or(&[]);
    let from_owner = resolve_eth_owner_account_id(state, &call.from);
    let output = match selector {
        s if s == ERC20_TRANSFER_SELECTOR => {
            let recipient = abi_decode_address(call.data.get(4..36).unwrap_or(&[]))?;
            let amount = abi_decode_u64(call.data.get(36..68).unwrap_or(&[]))?;
            let recipient_owner = resolve_eth_owner_account_id(state, &recipient);
            if token_runtime::balance_of(ledger_state, &mint, &from_owner) < amount {
                return Ok(Some(ExecutionResult::Revert {
                    gas_used: 50_000,
                    output: b"insufficient token balance".to_vec().into(),
                }));
            }
            let _ = recipient_owner;
            abi_encode_bool(true)
        }
        s if s == ERC20_APPROVE_SELECTOR => {
            let _spender = abi_decode_address(call.data.get(4..36).unwrap_or(&[]))?;
            let _amount = abi_decode_u64(call.data.get(36..68).unwrap_or(&[]))?;
            abi_encode_bool(true)
        }
        s if s == ERC20_TRANSFER_FROM_SELECTOR => {
            let owner = abi_decode_address(call.data.get(4..36).unwrap_or(&[]))?;
            let recipient = abi_decode_address(call.data.get(36..68).unwrap_or(&[]))?;
            let amount = abi_decode_u64(call.data.get(68..100).unwrap_or(&[]))?;
            let owner_account = resolve_eth_owner_account_id(state, &owner);
            let spender_account = resolve_eth_owner_account_id(state, &call.from);
            let _recipient_account = resolve_eth_owner_account_id(state, &recipient);
            if token_runtime::allowance_of(ledger_state, &mint, &owner_account, &spender_account)
                < amount
            {
                return Ok(Some(ExecutionResult::Revert {
                    gas_used: 60_000,
                    output: b"allowance too low".to_vec().into(),
                }));
            }
            if token_runtime::balance_of(ledger_state, &mint, &owner_account) < amount {
                return Ok(Some(ExecutionResult::Revert {
                    gas_used: 60_000,
                    output: b"insufficient token balance".to_vec().into(),
                }));
            }
            abi_encode_bool(true)
        }
        s if s == ERC20_BALANCE_OF_SELECTOR => {
            let owner = abi_decode_address(call.data.get(4..36).unwrap_or(&[]))?;
            let owner_account = resolve_eth_owner_account_id(state, &owner);
            abi_encode_u64(token_runtime::balance_of(
                ledger_state,
                &mint,
                &owner_account,
            ))
        }
        s if s == ERC20_ALLOWANCE_SELECTOR => {
            let owner = abi_decode_address(call.data.get(4..36).unwrap_or(&[]))?;
            let spender = abi_decode_address(call.data.get(36..68).unwrap_or(&[]))?;
            let owner_account = resolve_eth_owner_account_id(state, &owner);
            let spender_account = resolve_eth_owner_account_id(state, &spender);
            abi_encode_u64(token_runtime::allowance_of(
                ledger_state,
                &mint,
                &owner_account,
                &spender_account,
            ))
        }
        s if s == ERC20_TOTAL_SUPPLY_SELECTOR => {
            let meta = token_runtime::get_mint_meta(ledger_state, &mint).ok_or_else(|| {
                RpcError::InvalidParameter("runtime ERC-20 mint does not exist".into())
            })?;
            abi_encode_u64(meta.supply)
        }
        s if s == ERC20_DECIMALS_SELECTOR => {
            let meta = token_runtime::get_mint_meta(ledger_state, &mint).ok_or_else(|| {
                RpcError::InvalidParameter("runtime ERC-20 mint does not exist".into())
            })?;
            abi_encode_u8(meta.decimals)
        }
        _ => {
            return Ok(Some(ExecutionResult::Revert {
                gas_used: 25_000,
                output: b"unsupported runtime ERC-20 selector".to_vec().into(),
            }))
        }
    };

    Ok(Some(ExecutionResult::Success {
        reason: SuccessReason::Return,
        gas_used: runtime_erc20_estimate_gas(selector, call.gas.unwrap_or(30_000_000)),
        gas_refunded: 0,
        logs: vec![],
        output: Output::Call(Bytes::from(output)),
    }))
}

fn runtime_erc20_stub_code() -> &'static [u8] {
    b"\x60\x00\x60\x00\xf3"
}

fn runtime_erc20_estimate_gas(selector: &[u8], gas_limit: u64) -> u64 {
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

fn abi_decode_address(word: &[u8]) -> Result<[u8; 20], RpcError> {
    if word.len() != 32 {
        return Err(RpcError::InvalidParameter(
            "invalid ABI address word".into(),
        ));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&word[12..32]);
    Ok(out)
}

fn abi_decode_u64(word: &[u8]) -> Result<u64, RpcError> {
    if word.len() != 32 {
        return Err(RpcError::InvalidParameter(
            "invalid ABI uint256 word".into(),
        ));
    }
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(RpcError::InvalidParameter(
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

fn eth_display_tx_hash(tx: &Transaction) -> String {
    if let Some(raw_chain) = &tx.raw_chain {
        if raw_chain.kind == RawChainKind::Evm {
            return format!("0x{}", hex::encode(evm_tx_hash(&raw_chain.raw_bytes)));
        }
    }
    format!("0x{}", hex::encode(tx.tx_hash()))
}

fn decoded_evm_tx(tx: &Transaction) -> Option<EvmDecoded> {
    tx.raw_chain.as_ref().and_then(|raw_chain| {
        (raw_chain.kind == RawChainKind::Evm)
            .then(|| decode_evm_auto(&raw_chain.raw_bytes).ok())
            .flatten()
    })
}

pub fn maybe_publish_pending_evm_tx(events: &EthEventHub, tx: &Transaction) {
    if decoded_evm_tx(tx).is_some() {
        events.publish_pending_tx(eth_display_tx_hash(tx));
    }
}

pub fn publish_eth_block_events(
    events: &EthEventHub,
    block: &ace_runtime::types::block::Block,
    receipts: &[crate::types::RpcTransactionReceipt],
) {
    events.publish_new_head(build_eth_head_value(block, receipts));
    events.publish_logs(
        receipts
            .iter()
            .flat_map(|receipt| receipt.evm_logs.iter().cloned()),
    );
}

fn build_eth_transaction_value(
    tx: &Transaction,
    block_hash: Option<[u8; 32]>,
    block_number: Option<u64>,
    index: Option<u32>,
) -> serde_json::Value {
    if let Some(decoded) = decoded_evm_tx(tx) {
        let hash = eth_display_tx_hash(tx);
        let from = format!("0x{}", hex::encode(decoded.parsed.signer));
        let to = (!decoded.is_create).then(|| format!("0x{}", hex::encode(decoded.to)));
        let mut value = serde_json::Map::new();
        value.insert("hash".into(), serde_json::Value::String(hash));
        value.insert(
            "nonce".into(),
            serde_json::Value::String(format!("0x{:x}", decoded.nonce)),
        );
        value.insert(
            "blockHash".into(),
            block_hash
                .map(|hash| serde_json::Value::String(format!("0x{}", hex::encode(hash))))
                .unwrap_or(serde_json::Value::Null),
        );
        value.insert(
            "blockNumber".into(),
            block_number
                .map(|slot| serde_json::Value::String(format!("0x{:x}", slot)))
                .unwrap_or(serde_json::Value::Null),
        );
        value.insert(
            "transactionIndex".into(),
            index
                .map(|idx| serde_json::Value::String(format!("0x{:x}", idx)))
                .unwrap_or(serde_json::Value::Null),
        );
        value.insert("from".into(), serde_json::Value::String(from));
        value.insert(
            "to".into(),
            to.map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null),
        );
        value.insert(
            "value".into(),
            serde_json::Value::String(format!("0x{:x}", decoded.value)),
        );
        value.insert(
            "gas".into(),
            serde_json::Value::String(format!("0x{:x}", decoded.gas_limit)),
        );
        value.insert(
            "gasPrice".into(),
            serde_json::Value::String(format!("0x{:x}", decoded.gas_price)),
        );
        value.insert(
            "input".into(),
            serde_json::Value::String(format!("0x{}", hex::encode(decoded.data))),
        );
        value.insert(
            "type".into(),
            serde_json::Value::String(format!("0x{:x}", decoded.tx_type)),
        );
        value.insert(
            "chainId".into(),
            serde_json::Value::String(format!("0x{:x}", decoded.parsed.chain_id)),
        );
        value.insert(
            "v".into(),
            serde_json::Value::String(format!("0x{:x}", decoded.signature_v)),
        );
        value.insert(
            "r".into(),
            serde_json::Value::String(format!("0x{}", hex::encode(decoded.signature_r))),
        );
        value.insert(
            "s".into(),
            serde_json::Value::String(format!("0x{}", hex::encode(decoded.signature_s))),
        );
        if let Some(max_fee_per_gas) = decoded.max_fee_per_gas {
            value.insert(
                "maxFeePerGas".into(),
                serde_json::Value::String(format!("0x{:x}", max_fee_per_gas)),
            );
        }
        if let Some(max_priority_fee_per_gas) = decoded.max_priority_fee_per_gas {
            value.insert(
                "maxPriorityFeePerGas".into(),
                serde_json::Value::String(format!("0x{:x}", max_priority_fee_per_gas)),
            );
        }
        if let Some(access_list) = decoded.access_list {
            value.insert("accessList".into(), access_list);
        }
        if let Some(max_fee_per_blob_gas) = decoded.max_fee_per_blob_gas {
            value.insert(
                "maxFeePerBlobGas".into(),
                serde_json::Value::String(format!("0x{:x}", max_fee_per_blob_gas)),
            );
        }
        if let Some(blob_versioned_hashes) = decoded.blob_versioned_hashes {
            value.insert(
                "blobVersionedHashes".into(),
                serde_json::Value::Array(
                    blob_versioned_hashes
                        .into_iter()
                        .map(|hash| serde_json::Value::String(format!("0x{}", hex::encode(hash))))
                        .collect(),
                ),
            );
        }
        if let Some(authorization_list) = decoded.authorization_list {
            value.insert("authorizationList".into(), authorization_list);
        }
        return serde_json::Value::Object(value);
    }

    let sender_hex = hex::encode(tx.attestation.idcom);
    serde_json::json!({
        "hash": format!("0x{}", hex::encode(tx.tx_hash())),
        "nonce": "0x0",
        "blockHash": block_hash.map(|hash| format!("0x{}", hex::encode(hash))),
        "blockNumber": block_number.map(|slot| format!("0x{:x}", slot)),
        "transactionIndex": index.map(|idx| format!("0x{:x}", idx)),
        "from": format!("0x{}", &sender_hex[..40]),
        "to": serde_json::Value::Null,
        "value": "0x0",
        "gas": "0x1e8480",
        "gasPrice": "0x0",
        "input": format!("0x{}", hex::encode(&tx.payload)),
        "type": "0x0",
        "v": "0x0",
        "r": "0x0",
        "s": "0x0",
    })
}

fn build_eth_head_value(
    block: &ace_runtime::types::block::Block,
    receipts: &[crate::types::RpcTransactionReceipt],
) -> serde_json::Value {
    serde_json::json!({
        "number": format!("0x{:x}", block.header.slot),
        "hash": format!("0x{}", hex::encode(block.hash())),
        "parentHash": format!("0x{}", hex::encode(block.header.parent_hash)),
        "nonce": "0x0000000000000000",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "logsBloom": format!("0x{}", hex::encode(compute_logs_bloom(receipts))),
        "transactionsRoot": format!("0x{}", hex::encode(block.header.tx_merkle_root)),
        "stateRoot": format!("0x{}", hex::encode(block.header.state_root)),
        "receiptsRoot": format!("0x{}", hex::encode(compute_receipts_root(receipts))),
        "miner": format!("0x{}", &hex::encode(block.header.leader_idcom)[..40]),
        "difficulty": "0x0",
        "extraData": "0x",
        "gasLimit": "0x1c9c380",
        "gasUsed": format!(
            "0x{:x}",
            receipts.iter().map(|receipt| receipt.gas_used.unwrap_or(0)).sum::<u64>()
        ),
        "timestamp": format!("0x{:x}", block.header.timestamp / 1000),
        "baseFeePerGas": "0x0",
    })
}

fn build_eth_block(
    block: &ace_runtime::types::block::Block,
    receipts: &[crate::types::RpcTransactionReceipt],
    full_txs: bool,
) -> EthBlock {
    let transactions = if full_txs {
        block
            .transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                build_eth_transaction_value(
                    tx,
                    Some(block.hash()),
                    Some(block.header.slot),
                    Some(i as u32),
                )
            })
            .collect()
    } else {
        block
            .transactions
            .iter()
            .map(|tx| serde_json::Value::String(eth_display_tx_hash(tx)))
            .collect()
    };

    EthBlock {
        number: format!("0x{:x}", block.header.slot),
        hash: format!("0x{}", hex::encode(block.hash())),
        parent_hash: format!("0x{}", hex::encode(block.header.parent_hash)),
        nonce: "0x0000000000000000".into(),
        sha3_uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".into(),
        logs_bloom: format!("0x{}", hex::encode(compute_logs_bloom(receipts))),
        transactions_root: format!("0x{}", hex::encode(block.header.tx_merkle_root)),
        state_root: format!("0x{}", hex::encode(block.header.state_root)),
        receipts_root: format!("0x{}", hex::encode(compute_receipts_root(receipts))),
        miner: format!("0x{}", &hex::encode(block.header.leader_idcom)[..40]),
        difficulty: "0x0".into(),
        total_difficulty: "0x0".into(),
        extra_data: "0x".into(),
        size: format!("0x{:x}", 256 + block.transactions.len() * 244),
        gas_limit: "0x1c9c380".into(),
        gas_used: format!(
            "0x{:x}",
            receipts
                .iter()
                .map(|receipt| receipt.gas_used.unwrap_or(0))
                .sum::<u64>()
        ),
        timestamp: format!("0x{:x}", block.header.timestamp / 1000),
        transactions,
        uncles: vec![],
        base_fee_per_gas: "0x0".into(),
    }
}

fn build_eth_receipt(
    receipt: &crate::types::RpcTransactionReceipt,
    tx: &Transaction,
    slot: u64,
    cumulative_gas_used: u64,
) -> EthTransactionReceipt {
    let decoded = decoded_evm_tx(tx);
    let from = decoded
        .as_ref()
        .map(|decoded| format!("0x{}", hex::encode(decoded.parsed.signer)))
        .unwrap_or_else(|| format!("0x{}", &receipt.from[..40.min(receipt.from.len())]));
    let to = decoded
        .as_ref()
        .and_then(|decoded| (!decoded.is_create).then(|| format!("0x{}", hex::encode(decoded.to))));
    let tx_hash = receipt
        .external_transaction_hash
        .as_ref()
        .unwrap_or(&receipt.transaction_hash);

    EthTransactionReceipt {
        transaction_hash: format!("0x{}", tx_hash),
        transaction_index: format!("0x{:x}", receipt.transaction_index),
        block_hash: format!("0x{}", receipt.block_hash),
        block_number: format!("0x{:x}", slot),
        from,
        to,
        cumulative_gas_used: format!("0x{:x}", cumulative_gas_used),
        gas_used: format!("0x{:x}", receipt.gas_used.unwrap_or(21000)),
        contract_address: receipt
            .contract_address
            .as_ref()
            .map(|address| format!("0x{}", address)),
        logs: receipt.evm_logs.clone(),
        logs_bloom: format!(
            "0x{}",
            hex::encode(compute_logs_bloom(std::slice::from_ref(receipt)))
        ),
        status: if receipt.status { "0x1" } else { "0x0" }.into(),
        effective_gas_price: "0x0".into(),
        tx_type: decoded
            .as_ref()
            .map(|decoded| format!("0x{:x}", decoded.tx_type))
            .unwrap_or_else(|| "0x0".into()),
    }
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

fn bloom_insert_value(bloom: &mut [u8; 256], value: &[u8]) {
    let hash = keccak256(value);
    for chunk in hash[..6].chunks_exact(2) {
        let bit = (((chunk[0] as usize) << 8) | chunk[1] as usize) & 2047;
        let byte_index = 255usize.saturating_sub(bit / 8);
        bloom[byte_index] |= 1u8 << (bit % 8);
    }
}

fn compute_logs_bloom(receipts: &[crate::types::RpcTransactionReceipt]) -> [u8; 256] {
    let mut bloom = [0u8; 256];
    for receipt in receipts {
        for log in &receipt.evm_logs {
            if let Ok(address) = hex::decode(log.address.trim_start_matches("0x")) {
                bloom_insert_value(&mut bloom, &address);
            }
            for topic in &log.topics {
                if let Ok(topic_bytes) = hex::decode(topic.trim_start_matches("0x")) {
                    bloom_insert_value(&mut bloom, &topic_bytes);
                }
            }
        }
    }
    bloom
}

fn compute_receipts_root(receipts: &[crate::types::RpcTransactionReceipt]) -> [u8; 32] {
    if receipts.is_empty() {
        return [0u8; 32];
    }

    let mut hashes: Vec<[u8; 32]> = receipts
        .iter()
        .map(|receipt| {
            let encoded = bincode::serialize(receipt).unwrap_or_default();
            let digest = sha2::Sha256::digest(encoded);
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            out
        })
        .collect();

    while hashes.len() > 1 {
        let mut next = Vec::with_capacity(hashes.len().div_ceil(2));
        for pair in hashes.chunks(2) {
            if pair.len() == 2 {
                let mut hasher = sha2::Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                let mut out = [0u8; 32];
                out.copy_from_slice(&hasher.finalize());
                next.push(out);
            } else {
                next.push(pair[0]);
            }
        }
        hashes = next;
    }

    hashes[0]
}

fn parse_eth_log_filter(
    filter: &serde_json::Value,
    current_slot: u64,
) -> Result<EthLogFilter, RpcError> {
    let block_hash = filter
        .get("blockHash")
        .and_then(serde_json::Value::as_str)
        .map(normalize_0x_hex);
    let from_block = filter
        .get("fromBlock")
        .and_then(serde_json::Value::as_str)
        .map(|value| parse_block_tag_or_number(value, current_slot))
        .transpose()?;
    let to_block = filter
        .get("toBlock")
        .and_then(serde_json::Value::as_str)
        .map(|value| parse_block_tag_or_number(value, current_slot))
        .transpose()?;
    let addresses = filter
        .get("address")
        .map(parse_address_filter)
        .transpose()?;
    let topics = filter
        .get("topics")
        .and_then(serde_json::Value::as_array)
        .map(|topics| {
            topics
                .iter()
                .map(parse_topic_filter_entry)
                .collect::<Result<Vec<_>, RpcError>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(EthLogFilter {
        block_hash,
        from_block,
        to_block,
        addresses,
        topics,
    })
}

fn parse_address_filter(value: &serde_json::Value) -> Result<Vec<String>, RpcError> {
    match value {
        serde_json::Value::String(single) => Ok(vec![normalize_0x_hex(single)]),
        serde_json::Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(normalize_0x_hex).ok_or_else(|| {
                    RpcError::InvalidParameter("address filter must be hex string".into())
                })
            })
            .collect(),
        _ => Err(RpcError::InvalidParameter(
            "address filter must be a hex string or array".into(),
        )),
    }
}

fn parse_topic_filter_entry(value: &serde_json::Value) -> Result<Option<Vec<String>>, RpcError> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(single) => Ok(Some(vec![normalize_0x_hex(single)])),
        serde_json::Value::Array(values) => Ok(Some(
            values
                .iter()
                .map(|value| {
                    value.as_str().map(normalize_0x_hex).ok_or_else(|| {
                        RpcError::InvalidParameter("topic filter must be hex string".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => Err(RpcError::InvalidParameter(
            "topic filter must be null, string, or array".into(),
        )),
    }
}

fn log_matches_filter(log: &EthLog, filter: &EthLogFilter) -> bool {
    if let Some(block_hash) = &filter.block_hash {
        if normalize_0x_hex(&log.block_hash) != *block_hash {
            return false;
        }
    }

    let block_number = parse_hex_u64(&log.block_number).unwrap_or_default();
    if let Some(from_block) = filter.from_block {
        if block_number < from_block {
            return false;
        }
    }
    if let Some(to_block) = filter.to_block {
        if block_number > to_block {
            return false;
        }
    }

    if let Some(addresses) = &filter.addresses {
        if !addresses.contains(&normalize_0x_hex(&log.address)) {
            return false;
        }
    }

    for (idx, topic_filter) in filter.topics.iter().enumerate() {
        let Some(expected_topics) = topic_filter else {
            continue;
        };
        let Some(actual_topic) = log.topics.get(idx) else {
            return false;
        };
        if !expected_topics.contains(&normalize_0x_hex(actual_topic)) {
            return false;
        }
    }

    true
}

fn normalize_0x_hex(value: &str) -> String {
    format!(
        "0x{}",
        value
            .strip_prefix("0x")
            .unwrap_or(value)
            .to_ascii_lowercase()
    )
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, RpcError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(value).map_err(|e| RpcError::InvalidHex(e.to_string()))
}

fn parse_bytes32(value: &str) -> Result<[u8; 32], RpcError> {
    let bytes = parse_hex_bytes(value)?;
    if bytes.len() != 32 {
        return Err(RpcError::InvalidParameter(
            "expected 32-byte hex value".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_u64(value: &str) -> Result<u64, RpcError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(value, 16)
        .map_err(|e| RpcError::InvalidParameter(format!("invalid hex quantity: {e}")))
}

fn parse_hex_u256(value: &str) -> Result<U256, RpcError> {
    let bytes = parse_hex_bytes(value)?;
    if bytes.len() > 32 {
        return Err(RpcError::InvalidParameter(
            "hex quantity exceeds 32 bytes".into(),
        ));
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(U256::from_be_bytes(padded))
}

fn parse_block_tag_or_number(value: &str, current_slot: u64) -> Result<u64, RpcError> {
    match value {
        "earliest" => Ok(0),
        "latest" | "pending" | "safe" | "finalized" => Ok(current_slot),
        other => parse_hex_u64(other),
    }
}

/// Parse a 20-byte Ethereum address from hex string (with or without 0x prefix).
fn parse_eth_address(hex_str: &str) -> Result<[u8; 20], RpcError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
    if bytes.len() != 20 {
        return Err(RpcError::InvalidParameter(format!(
            "address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

/// Resolve a block number parameter ("latest", "earliest", "pending", or hex number).
fn resolve_block_number<B: BlockStore>(block: &str, shared: &RpcState<B>) -> Result<u64, RpcError> {
    match block {
        "latest" | "pending" | "safe" | "finalized" => Ok(shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed)),
        "earliest" => Ok(0),
        other => {
            let stripped = other.strip_prefix("0x").unwrap_or(other);
            u64::from_str_radix(stripped, 16)
                .map_err(|e| RpcError::InvalidParameter(format!("invalid block number: {e}")))
        }
    }
}

fn parse_block_hash(hash: &str) -> Result<[u8; 32], RpcError> {
    let hash_hex = hash.strip_prefix("0x").unwrap_or(hash);
    let hash_bytes = hex::decode(hash_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
    if hash_bytes.len() != 32 {
        return Err(RpcError::InvalidParameter("hash must be 32 bytes".into()));
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&hash_bytes);
    Ok(block_hash)
}

fn build_eth_receipts_for_slot<B: BlockStore + Send + Sync + 'static>(
    shared: &Arc<RpcState<B>>,
    slot: u64,
) -> Result<Vec<EthTransactionReceipt>, RpcError> {
    let block_store = shared.block_store.read();
    let block = block_store
        .get_block_by_slot(slot)
        .ok_or_else(|| RpcError::InvalidParameter("block not found".into()))?;

    let receipts = shared.tx_receipt_store.read().get_receipts_for_slot(slot);
    if receipts.is_empty() {
        return Ok(Vec::new());
    }

    let mut cumulative_gas_used = 0u64;
    let mut out = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        let index = receipt.transaction_index as usize;
        let Some(tx) = block.transactions.get(index) else {
            return Err(RpcError::ServerError(format!(
                "transaction index {index} missing from block {}",
                block.header.slot
            )));
        };
        cumulative_gas_used = cumulative_gas_used.saturating_add(receipt.gas_used.unwrap_or(0));
        out.push(build_eth_receipt(&receipt, tx, slot, cumulative_gas_used));
    }
    Ok(out)
}

fn resolve_eth_account_id(
    state: &ace_model::sharded_state::ShardedState,
    address: &[u8; 20],
) -> Option<ace_model::account::AccountId> {
    state.resolve_evm_account_id(address)
}

fn resolve_eth_owner_account_id(
    state: &ace_model::sharded_state::ShardedState,
    address: &[u8; 20],
) -> ace_model::account::AccountId {
    resolve_eth_account_id(state, address)
        .unwrap_or_else(|| ace_model::account::AccountId::from_bytes(legacy_idcom_evm(address)))
}

fn runtime_erc20_ledger_state<'a>(
    state: &'a ace_model::sharded_state::ShardedState,
    address: &[u8; 20],
) -> Option<(&'a StateTree, [u8; 32])> {
    state.iter_shards().find_map(|(_, shard)| {
        token_runtime::mint_for_runtime_erc20_address(shard, address).map(|mint| (shard, mint))
    })
}

fn lookup_evm_transaction<B: BlockStore + Send + Sync + 'static>(
    shared: &Arc<RpcState<B>>,
    tx_hash: &str,
) -> Result<
    (
        crate::types::RpcTransactionReceipt,
        Transaction,
        u64,
        [u8; 32],
    ),
    RpcError,
> {
    let hash_hex = tx_hash.strip_prefix("0x").unwrap_or(tx_hash);
    let hash_bytes = hex::decode(hash_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
    if hash_bytes.len() != 32 {
        return Err(RpcError::InvalidParameter(
            "tx hash must be 32 bytes".into(),
        ));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&hash_bytes);

    let store = shared.tx_receipt_store.read();
    let (slot, index) = store
        .get_location(&h)
        .ok_or_else(|| RpcError::InvalidParameter("transaction not found".into()))?;
    let receipt = store
        .get_receipt(slot, index)
        .ok_or_else(|| RpcError::InvalidParameter("transaction receipt not found".into()))?;
    drop(store);

    let block_store = shared.block_store.read();
    let block = block_store
        .get_block_by_slot(slot)
        .ok_or_else(|| RpcError::InvalidParameter("block not found".into()))?;
    let tx = block
        .transactions
        .get(index as usize)
        .cloned()
        .ok_or_else(|| RpcError::InvalidParameter("transaction missing from block".into()))?;
    Ok((receipt, tx, slot, block.hash()))
}

#[cfg(test)]
mod tests {
    use super::{
        build_eth_receipt, execute_eth_call, parse_eth_address, runtime_erc20_stub_code,
        validate_subscription_kind, EthEventHub, EthLogFilter, ParsedEthCall,
    };
    use crate::types::RpcTransactionReceipt;
    use ace_model::account::{Account, AccountId};
    use ace_model::sharded_state::ShardedState;
    use ace_n_vm::cross_vm::AddressResolver;
    use ace_n_vm::token_runtime;
    use ace_runtime::crypto::TaggedSignature;
    use ace_runtime::types::attestation::{Attestation, Domain};
    use ace_runtime::types::transaction::Transaction;
    use revm::primitives::{Address, Bytes, ExecutionResult, TxKind, U256};

    #[test]
    fn eth_receipt_preserves_contract_address() {
        let tx = Transaction::new(
            vec![0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Attestation {
                obj_hash: [0u8; 32],
                idcom: [1u8; 32],
                domain: Domain::new(1337, 7),
                context_tag: [0u8; 16],
                credential: TaggedSignature::ed25519([0u8; 64]),
            },
        );
        let receipt = RpcTransactionReceipt {
            transaction_hash: hex::encode([2u8; 32]),
            external_transaction_hash: None,
            block_slot: 7,
            block_hash: hex::encode([3u8; 32]),
            transaction_index: 0,
            from: hex::encode([4u8; 32]),
            status: true,
            error: None,
            state_changes: vec![],
            gas_used: Some(53_000),
            contract_address: Some(hex::encode([5u8; 20])),
            evm_logs: vec![],
        };

        let eth_receipt = build_eth_receipt(&receipt, &tx, 7, 53_000);

        assert_eq!(
            eth_receipt.contract_address,
            Some(format!("0x{}", hex::encode([5u8; 20])))
        );
    }

    #[test]
    fn runtime_erc20_eth_call_balance_of_reads_token_ledger() {
        let mut state = ShardedState::new();
        let owner = AccountId::from_bytes([7u8; 32]);
        state.insert(Account::new(owner));
        let mint = [8u8; 32];
        // Use owner as the mint authority for test
        token_runtime::create_mint(state.default_shard_mut(), &mint, 6, owner.as_bytes())
            .expect("mint");
        let owner_evm = AddressResolver::to_evm_address(&owner);
        // Credit the canonical AccountId (same as `resolve_evm_account_id` for this EVM address
        // when a native account is registered with `to_evm_address`), not `legacy_idcom_evm` only.
        token_runtime::mint_to_owner(
            state.default_shard_mut(),
            &mint,
            owner.as_bytes(),
            123_456,
            &owner,
        )
        .expect("mint tokens");

        let contract = token_runtime::runtime_erc20_address_for_mint(&mint);
        let mut calldata = vec![0x70, 0xa0, 0x82, 0x31];
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(&owner_evm);

        let result = execute_eth_call(
            &state,
            ParsedEthCall {
                from: [0u8; 20],
                tx_kind: TxKind::Call(Address::from(contract)),
                value: U256::ZERO,
                gas: Some(100_000),
                data: Bytes::from(calldata),
            },
        )
        .expect("eth_call");

        match result {
            ExecutionResult::Success { output, .. } => match output {
                revm::primitives::Output::Call(data) => {
                    let bytes = data.to_vec();
                    assert_eq!(&bytes[24..32], &123_456u64.to_be_bytes());
                }
                other => panic!("unexpected output: {other:?}"),
            },
            other => panic!("unexpected result: {other:?}"),
        }

        let _ = parse_eth_address(&format!("0x{}", hex::encode(contract))).expect("address");
        assert!(!runtime_erc20_stub_code().is_empty());
    }

    #[test]
    fn runtime_erc20_eth_call_balance_of_uses_alias_and_nondefault_shard_ledger() {
        let mut state = ShardedState::new();
        let owner = AccountId::from_bytes([9u8; 32]);
        let owner_evm = [0xabu8; 20];
        let shard = ace_model::sharded_state::ShardId(7);

        state.insert_into_shard(shard, Account::with_evm_address(owner, owner_evm));

        let mint = [0xacu8; 32];
        token_runtime::create_mint(state.shard_mut(shard), &mint, 6, owner.as_bytes())
            .expect("mint");
        token_runtime::mint_to_owner(
            state.shard_mut(shard),
            &mint,
            owner.as_bytes(),
            654_321,
            &owner,
        )
        .expect("mint tokens");

        let contract = token_runtime::runtime_erc20_address_for_mint(&mint);
        let mut calldata = vec![0x70, 0xa0, 0x82, 0x31];
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(&owner_evm);

        let result = execute_eth_call(
            &state,
            ParsedEthCall {
                from: [0u8; 20],
                tx_kind: TxKind::Call(Address::from(contract)),
                value: U256::ZERO,
                gas: Some(100_000),
                data: Bytes::from(calldata),
            },
        )
        .expect("eth_call");

        match result {
            ExecutionResult::Success { output, .. } => match output {
                revm::primitives::Output::Call(data) => {
                    let bytes = data.to_vec();
                    assert_eq!(&bytes[24..32], &654_321u64.to_be_bytes());
                }
                other => panic!("unexpected output: {other:?}"),
            },
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn event_hub_log_filter_tracks_changes_and_history() {
        let hub = EthEventHub::new(16);
        let filter_id = hub
            .install_log_filter(EthLogFilter {
                addresses: Some(vec!["0x1111111111111111111111111111111111111111".into()]),
                ..EthLogFilter::default()
            })
            .unwrap();
        let log = crate::types::EthLog {
            address: "0x1111111111111111111111111111111111111111".into(),
            topics: vec![
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ],
            data: "0x".into(),
            block_number: "0x2".into(),
            transaction_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
            transaction_index: "0x0".into(),
            block_hash: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            log_index: "0x0".into(),
            removed: false,
        };

        hub.publish_logs([log.clone()]);

        let changes = hub.get_filter_changes(&filter_id).unwrap();
        let history = hub.get_filter_logs(&filter_id).unwrap();

        assert_eq!(changes.as_array().map(Vec::len), Some(1));
        assert_eq!(history, vec![log]);
    }

    #[test]
    fn event_hub_block_and_pending_filters_are_incremental() {
        let hub = EthEventHub::new(16);
        let block_filter = hub.install_block_filter().unwrap();
        let pending_filter = hub.install_pending_tx_filter().unwrap();

        hub.publish_new_head(serde_json::json!({
            "hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }));
        hub.publish_pending_tx(
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        );

        let block_changes = hub.get_filter_changes(&block_filter).unwrap();
        let pending_changes = hub.get_filter_changes(&pending_filter).unwrap();

        assert_eq!(block_changes.as_array().map(Vec::len), Some(1));
        assert_eq!(pending_changes.as_array().map(Vec::len), Some(1));

        let second_block_changes = hub.get_filter_changes(&block_filter).unwrap();
        let second_pending_changes = hub.get_filter_changes(&pending_filter).unwrap();
        assert_eq!(second_block_changes.as_array().map(Vec::len), Some(0));
        assert_eq!(second_pending_changes.as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn event_hub_log_history_excludes_reorged_logs() {
        let hub = EthEventHub::new(16);
        let filter_id = hub
            .install_log_filter(EthLogFilter {
                addresses: Some(vec!["0x1111111111111111111111111111111111111111".into()]),
                ..EthLogFilter::default()
            })
            .unwrap();
        let log = crate::types::EthLog {
            address: "0x1111111111111111111111111111111111111111".into(),
            topics: vec![
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ],
            data: "0x".into(),
            block_number: "0x2".into(),
            transaction_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
            transaction_index: "0x0".into(),
            block_hash: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            log_index: "0x0".into(),
            removed: false,
        };

        hub.publish_logs([log.clone()]);
        hub.publish_removed_logs([log.clone()]);

        let changes = hub.get_filter_changes(&filter_id).unwrap();
        let history = hub.get_filter_logs(&filter_id).unwrap();

        assert_eq!(changes.as_array().map(Vec::len), Some(2));
        assert_eq!(history, Vec::<crate::types::EthLog>::new());
    }

    #[test]
    fn event_hub_rejects_filter_install_when_limit_reached() {
        let hub = EthEventHub::with_limits(16, 1);
        let _first = hub.install_block_filter().unwrap();
        let err = hub.install_pending_tx_filter().unwrap_err();
        assert!(err.to_string().contains("too many installed filters"));
    }

    #[test]
    fn unsupported_subscription_kind_is_rejected() {
        let err = validate_subscription_kind("syncing").unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported subscription kind: syncing"));
    }
}
