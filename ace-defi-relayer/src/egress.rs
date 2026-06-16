//! Egress execution: ACE Chain → External chains
//!
//! This module monitors ACE Chain for withdrawal records and executes
//! transfers on external chains.

use crate::error::{RelayerError, Result};
use crate::signing::sign_withdrawal_completion;
use crate::storage::{CheckpointStore, EgressCheckpoint};
use crate::types::{ChainConfig, WithdrawalExecutionResult, WithdrawalRecord};
use ace_defi::{ExternalAsset, ExternalChain};
use k256::ecdsa::SigningKey as EvmSigningKey;
use rlp::RlpStream;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tiny_keccak::{Hasher, Keccak};
use tracing::{debug, error, info};

/// Monitors ACE Chain for withdrawal records
pub struct WithdrawalMonitor {
    pub ace_rpc_url: String,
    pub last_checked_slot: u64,
    pub processed_withdrawals: HashMap<u64, bool>,
    pub external_tx_hashes: HashMap<u64, String>,
}

impl WithdrawalMonitor {
    pub fn new(ace_rpc_url: String) -> Self {
        Self {
            ace_rpc_url,
            last_checked_slot: 0,
            processed_withdrawals: HashMap::new(),
            external_tx_hashes: HashMap::new(),
        }
    }

    /// Query ACE Chain for pending withdrawals
    pub async fn fetch_pending_withdrawals(&mut self) -> Result<Vec<WithdrawalRecord>> {
        info!(
            "Querying ACE for pending withdrawals since slot {}",
            self.last_checked_slot
        );

        if std::env::var("ACE_DEFI_RELAYER_ALLOW_MOCK_ACE_WITHDRAWALS").as_deref() == Ok("1") {
            return Ok(vec![]);
        }

        let mut withdrawals = Vec::new();
        let mut start_index = 0u64;
        loop {
            let response = reqwest::Client::new()
                .post(&self.ace_rpc_url)
                .json(&json!({
                    "jsonrpc": "2.0",
                    "id": 1u64,
                    "method": "ace_getPendingWithdrawalsPage",
                    "params": [start_index, 1000u64],
                }))
                .send()
                .await
                .map_err(|e| RelayerError::AceError(e.to_string()))?;
            let value: Value = response
                .json()
                .await
                .map_err(|e| RelayerError::AceError(e.to_string()))?;
            if let Some(error) = value.get("error") {
                return Err(RelayerError::AceError(format!(
                    "ace_getPendingWithdrawalsPage failed: {error}"
                )));
            }
            let page: ace_defi::PendingWithdrawalsPage = serde_json::from_value(
                value
                    .get("result")
                    .cloned()
                    .ok_or_else(|| RelayerError::AceError("missing withdrawal result".into()))?,
            )?;
            withdrawals.extend(page.withdrawals);
            if page.next_index >= page.total_indexed {
                break;
            }
            start_index = page.next_index;
        }
        if let Some(max_slot) = withdrawals.iter().map(|w| w.requested_at).max() {
            self.last_checked_slot = self.last_checked_slot.max(max_slot.saturating_add(1));
        }
        Ok(withdrawals)
    }

    /// Mark a withdrawal as processed
    pub fn mark_processed(&mut self, withdrawal_id: u64) {
        self.processed_withdrawals.insert(withdrawal_id, true);
        debug!("Marked withdrawal {} as processed", withdrawal_id);
    }

    /// Check if withdrawal was already processed
    pub fn is_processed(&self, withdrawal_id: u64) -> bool {
        self.processed_withdrawals.contains_key(&withdrawal_id)
    }

    pub fn external_tx_hash(&self, withdrawal_id: u64) -> Option<&str> {
        self.external_tx_hashes
            .get(&withdrawal_id)
            .map(String::as_str)
    }

    pub fn record_external_tx(&mut self, withdrawal_id: u64, tx_hash: String) {
        self.external_tx_hashes.insert(withdrawal_id, tx_hash);
    }

    pub fn restore_checkpoint(&mut self, checkpoint: EgressCheckpoint) {
        self.last_checked_slot = checkpoint.last_checked_slot;
        self.processed_withdrawals = checkpoint
            .processed_withdrawals
            .into_iter()
            .map(|withdrawal_id| (withdrawal_id, true))
            .collect();
        self.external_tx_hashes = checkpoint.external_tx_hashes;
    }

    pub fn checkpoint(&self) -> EgressCheckpoint {
        EgressCheckpoint {
            last_checked_slot: self.last_checked_slot,
            processed_withdrawals: self.processed_withdrawals.keys().copied().collect(),
            external_tx_hashes: self.external_tx_hashes.clone(),
        }
    }
}

/// Executes withdrawals on external chains
pub struct WithdrawalExecutor {
    pub chain_executors: HashMap<String, ChainExecutor>,
}

impl WithdrawalExecutor {
    pub fn new(chains: &HashMap<String, ChainConfig>) -> Self {
        let mut executors = HashMap::new();

        for (name, config) in chains {
            executors.insert(
                name.clone(),
                ChainExecutor::new(name, &config.rpc_url, config.bridge_contract.clone()),
            );
        }

        Self {
            chain_executors: executors,
        }
    }

    /// Execute a withdrawal on the destination chain
    pub async fn execute_withdrawal<'a>(
        &self,
        withdrawal: &WithdrawalRecord,
        mut on_prepared: impl FnMut(String) -> Result<()> + Send + 'a,
    ) -> Result<WithdrawalExecutionResult> {
        info!(
            "Executing withdrawal {} to {} chain",
            withdrawal.withdrawal_id,
            withdrawal.asset.chain().name()
        );

        // Get the appropriate executor for this chain
        let destination_chain = withdrawal.asset.chain().name();
        let executor = self.chain_executors.get(destination_chain).ok_or_else(|| {
            RelayerError::WithdrawalError(format!("No executor for chain {}", destination_chain))
        })?;

        // Execute the transfer
        executor.execute(withdrawal, &mut on_prepared).await
    }
}

impl Default for WithdrawalExecutor {
    fn default() -> Self {
        Self::new(&HashMap::new())
    }
}

/// Chain-specific withdrawal executor
pub struct ChainExecutor {
    pub chain_name: String,
    pub rpc_url: String,
    pub bridge_contract: Option<String>,
}

impl ChainExecutor {
    pub fn new(chain_name: &str, rpc_url: &str, bridge_contract: Option<String>) -> Self {
        Self {
            chain_name: chain_name.to_string(),
            rpc_url: rpc_url.to_string(),
            bridge_contract,
        }
    }

    /// Execute transfer on this chain
    pub async fn execute<'a>(
        &self,
        withdrawal: &WithdrawalRecord,
        on_prepared: &mut (dyn FnMut(String) -> Result<()> + Send + 'a),
    ) -> Result<WithdrawalExecutionResult> {
        if std::env::var("ACE_DEFI_RELAYER_ALLOW_MOCK_EGRESS").as_deref() == Ok("1") {
            let mut hasher = Sha256::new();
            hasher.update(format!("{:?}", withdrawal).as_bytes());
            let tx_hash = format!("0x{}", hex::encode(hasher.finalize()));
            on_prepared(tx_hash.clone())?;
            return Ok(WithdrawalExecutionResult {
                withdrawal_id: withdrawal.withdrawal_id,
                destination_chain: withdrawal.asset.chain().name().to_string(),
                tx_hash,
                gateway_address: vec![],
                success: true,
                error: None,
                timestamp: chrono::Utc::now().timestamp() as u64,
            });
        }

        let destination_chain = withdrawal.asset.chain();
        if destination_chain.name() != self.chain_name {
            return Err(RelayerError::WithdrawalError(format!(
                "withdrawal is for {}, executor is {}",
                destination_chain.name(),
                self.chain_name
            )));
        }

        if destination_chain != ExternalChain::Ethereum && destination_chain != ExternalChain::Bsc {
            return Err(RelayerError::WithdrawalError(format!(
                "real {} egress is not implemented yet",
                destination_chain.name()
            )));
        }

        let egress_private_key = std::env::var(format!(
            "ACE_DEFI_EGRESS_PRIVATE_KEY_{}",
            self.chain_name.to_ascii_uppercase()
        ))
        .or_else(|_| std::env::var("ACE_DEFI_EGRESS_PRIVATE_KEY"))
        .map_err(|_| {
            RelayerError::ConfigError(format!(
                "missing ACE_DEFI_EGRESS_PRIVATE_KEY_{} or ACE_DEFI_EGRESS_PRIVATE_KEY",
                self.chain_name.to_ascii_uppercase()
            ))
        })?;
        let signing_key = evm_signing_key_from_hex(&egress_private_key)?;
        let from = evm_address_from_signing_key(&signing_key);
        let to = normalize_external_dest(&withdrawal.external_dest)?;
        let chain_id = self
            .json_rpc("eth_chainId", json!([]))
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or_else(|| RelayerError::WithdrawalError("invalid eth_chainId".into()))?;

        let mut completion_gateway_address = Vec::new();
        let mut expected_gateway_release: Option<([u8; 20], [u8; 20], [u8; 20], u64)> = None;
        let (tx_to, value, data) = match &withdrawal.asset {
            ExternalAsset::Native(ExternalChain::Ethereum)
            | ExternalAsset::Native(ExternalChain::Bsc) => {
                (parse_evm_address(&to)?, withdrawal.amount, Vec::new())
            }
            ExternalAsset::Erc20(token) | ExternalAsset::Bep20(token) => {
                if let Some(gateway) = &self.bridge_contract {
                    let gateway_address = parse_evm_address(gateway)?;
                    completion_gateway_address = gateway_address.to_vec();
                    let signatures = gateway_release_signatures(
                        &release_signing_keys(&self.chain_name)?,
                        chain_id,
                        gateway_address,
                        withdrawal.withdrawal_id,
                        token,
                        &to,
                        withdrawal.amount,
                    )?;
                    let calldata = omni_gateway_release_calldata(
                        withdrawal.withdrawal_id,
                        token,
                        &to,
                        withdrawal.amount,
                        &signatures,
                    )?;
                    let recipient_address = parse_evm_address(&to)?;
                    expected_gateway_release = Some((
                        gateway_address,
                        *token,
                        recipient_address,
                        withdrawal.amount,
                    ));
                    (gateway_address, 0, calldata)
                } else {
                    let calldata =
                        parse_hex_bytes(&erc20_transfer_calldata(&to, withdrawal.amount)?)?;
                    (*token, 0, calldata)
                }
            }
            other => {
                return Err(RelayerError::WithdrawalError(format!(
                    "real egress is not implemented for asset {other:?}"
                )));
            }
        };

        let tx_hash = self
            .send_signed_evm_transfer(&signing_key, from, tx_to, value, data, on_prepared)
            .await?;

        let receipt = self.wait_for_receipt_confirmation(&tx_hash).await?;
        if let Some((gateway, token, recipient, amount)) = expected_gateway_release {
            validate_gateway_release_receipt(
                &receipt,
                gateway,
                withdrawal.withdrawal_id,
                token,
                recipient,
                amount,
            )?;
        }

        info!(
            "Withdrawal {} executed on {} with tx {}",
            withdrawal.withdrawal_id, self.chain_name, tx_hash
        );

        Ok(WithdrawalExecutionResult {
            withdrawal_id: withdrawal.withdrawal_id,
            destination_chain: self.chain_name.clone(),
            tx_hash,
            gateway_address: completion_gateway_address,
            success: true,
            error: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    async fn json_rpc(&self, method: &str, params: Value) -> Result<Value> {
        let response = reqwest::Client::new()
            .post(&self.rpc_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1u64,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .map_err(|e| RelayerError::WithdrawalError(e.to_string()))?;
        let value: Value = response
            .json()
            .await
            .map_err(|e| RelayerError::WithdrawalError(e.to_string()))?;
        if let Some(error) = value.get("error") {
            return Err(RelayerError::WithdrawalError(format!(
                "{method} failed: {error}"
            )));
        }
        value.get("result").cloned().ok_or_else(|| {
            RelayerError::WithdrawalError(format!("{method} response missing result"))
        })
    }

    async fn send_signed_evm_transfer<'a>(
        &self,
        signing_key: &EvmSigningKey,
        from: [u8; 20],
        to: [u8; 20],
        value: u64,
        data: Vec<u8>,
        on_prepared: &mut (dyn FnMut(String) -> Result<()> + Send),
    ) -> Result<String> {
        let from_hex = format!("0x{}", hex::encode(from));
        let to_hex = format!("0x{}", hex::encode(to));
        let chain_id = self
            .json_rpc("eth_chainId", json!([]))
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or_else(|| RelayerError::WithdrawalError("invalid eth_chainId".into()))?;
        let nonce = self
            .json_rpc("eth_getTransactionCount", json!([from_hex, "pending"]))
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or_else(|| {
                RelayerError::WithdrawalError("invalid eth_getTransactionCount".into())
            })?;
        let gas_price = self
            .json_rpc("eth_gasPrice", json!([]))
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or_else(|| RelayerError::WithdrawalError("invalid eth_gasPrice".into()))?;
        let tx_for_estimate = json!({
            "from": format!("0x{}", hex::encode(from)),
            "to": to_hex,
            "value": u64_to_quantity(value),
            "data": format!("0x{}", hex::encode(&data)),
        });
        let gas_limit = match self
            .json_rpc("eth_estimateGas", json!([tx_for_estimate]))
            .await
        {
            Ok(value) => value.as_str().and_then(parse_quantity).unwrap_or_else(|| {
                if data.is_empty() {
                    21_000
                } else {
                    100_000
                }
            }),
            Err(error) => {
                tracing::warn!("eth_estimateGas failed, using fallback gas limit: {error}");
                if data.is_empty() {
                    21_000
                } else {
                    100_000
                }
            }
        };
        let (raw_tx, tx_hash) = sign_legacy_eip155_transaction(
            signing_key,
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            &data,
        )?;

        on_prepared(tx_hash.clone())?;

        let sent_hash = self
            .json_rpc("eth_sendRawTransaction", json!([raw_tx]))
            .await?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| {
                RelayerError::WithdrawalError("eth_sendRawTransaction returned non-string".into())
            })?;

        Ok(sent_hash)
    }

    async fn wait_for_receipt_confirmation(&self, tx_hash: &str) -> Result<Value> {
        let confirmations = std::env::var("ACE_DEFI_EGRESS_CONFIRMATIONS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1)
            .max(1);
        let timeout_secs = std::env::var("ACE_DEFI_EGRESS_RECEIPT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300);
        let started = std::time::Instant::now();

        loop {
            if started.elapsed().as_secs() > timeout_secs {
                return Err(RelayerError::WithdrawalError(format!(
                    "timed out waiting for receipt confirmation for {tx_hash}"
                )));
            }

            let receipt = self
                .json_rpc("eth_getTransactionReceipt", json!([tx_hash]))
                .await?;
            if !receipt.is_null() {
                let status = receipt
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("0x0");
                if status != "0x1" {
                    return Err(RelayerError::WithdrawalError(format!(
                        "external tx {tx_hash} failed with status {status}"
                    )));
                }
                let receipt_block = receipt
                    .get("blockNumber")
                    .and_then(Value::as_str)
                    .and_then(parse_quantity)
                    .ok_or_else(|| {
                        RelayerError::WithdrawalError(
                            "receipt missing confirmed blockNumber".into(),
                        )
                    })?;
                let current_block = self
                    .json_rpc("eth_blockNumber", json!([]))
                    .await?
                    .as_str()
                    .and_then(parse_quantity)
                    .ok_or_else(|| {
                        RelayerError::WithdrawalError(
                            "eth_blockNumber returned invalid value".into(),
                        )
                    })?;
                if current_block.saturating_add(1) >= receipt_block.saturating_add(confirmations) {
                    return Ok(receipt);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    }
}

fn validate_gateway_release_receipt(
    receipt: &Value,
    gateway: [u8; 20],
    withdrawal_id: u64,
    token: [u8; 20],
    recipient: [u8; 20],
    amount: u64,
) -> Result<()> {
    let logs = receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| RelayerError::WithdrawalError("receipt missing logs".into()))?;
    let topic0 = event_topic("Release(bytes32,address,address,uint256)");
    let withdrawal_topic = withdrawal_id_topic(withdrawal_id);
    let token_topic = address_topic(token);
    let recipient_topic = address_topic(recipient);
    let gateway_hex = format!("0x{}", hex::encode(gateway));
    let amount_word = format!("0x{:064x}", amount);

    let matched = logs.iter().any(|log| {
        let address_matches = log
            .get("address")
            .and_then(Value::as_str)
            .map(|address| address.eq_ignore_ascii_case(&gateway_hex))
            .unwrap_or(false);
        let topics = log.get("topics").and_then(Value::as_array);
        let data_matches = log
            .get("data")
            .and_then(Value::as_str)
            .map(|data| data.eq_ignore_ascii_case(&amount_word))
            .unwrap_or(false);
        address_matches
            && data_matches
            && topics
                .map(|topics| {
                    topics.get(0).and_then(Value::as_str) == Some(topic0.as_str())
                        && topics.get(1).and_then(Value::as_str) == Some(withdrawal_topic.as_str())
                        && topics.get(2).and_then(Value::as_str) == Some(token_topic.as_str())
                        && topics.get(3).and_then(Value::as_str) == Some(recipient_topic.as_str())
                })
                .unwrap_or(false)
    });
    if !matched {
        return Err(RelayerError::WithdrawalError(format!(
            "external tx receipt does not contain matching gateway Release event for withdrawal {withdrawal_id}"
        )));
    }
    Ok(())
}

fn event_topic(signature: &str) -> String {
    let mut hash = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signature.as_bytes());
    hasher.finalize(&mut hash);
    format!("0x{}", hex::encode(hash))
}

fn withdrawal_id_topic(withdrawal_id: u64) -> String {
    format!("0x{:064x}", withdrawal_id)
}

fn address_topic(address: [u8; 20]) -> String {
    format!("0x{}{}", "00".repeat(12), hex::encode(address))
}

/// Main egress monitoring loop
pub async fn monitor_egress(
    ace_rpc_url: String,
    chains: HashMap<String, ChainConfig>,
    relayer_private_key: String,
    poll_interval_secs: u64,
) -> Result<()> {
    let mut monitor = WithdrawalMonitor::new(ace_rpc_url);
    let checkpoint_path = std::env::var("ACE_DEFI_RELAYER_CHECKPOINT_FILE")
        .unwrap_or_else(|_| "ace-defi-relayer-checkpoints.json".to_string());
    let mut checkpoint_store = CheckpointStore::load(checkpoint_path)?;
    monitor.restore_checkpoint(checkpoint_store.egress());
    let executor = WithdrawalExecutor::new(&chains);

    info!("Started egress monitoring for ACE Chain");

    loop {
        match monitor.fetch_pending_withdrawals().await {
            Ok(withdrawals) => {
                for withdrawal in withdrawals {
                    if !monitor.is_processed(withdrawal.withdrawal_id) {
                        let (tx_hash, gateway_address) = match monitor.external_tx_hash(withdrawal.withdrawal_id) {
                            Some(existing) => (existing.to_string(), Vec::new()),
                            None => match executor
                                .execute_withdrawal(&withdrawal, |tx_hash| {
                                    monitor.record_external_tx(withdrawal.withdrawal_id, tx_hash);
                                    checkpoint_store.set_egress(monitor.checkpoint())
                                })
                                .await
                            {
                                Ok(result) if result.success => (result.tx_hash, result.gateway_address),
                                Ok(result) => {
                                    error!(
                                        "Withdrawal {} failed: {}",
                                        withdrawal.withdrawal_id,
                                        result.error.unwrap_or_default()
                                    );
                                    continue;
                                }
                                Err(e) => {
                                    error!("Error executing withdrawal: {}", e);
                                    continue;
                                }
                            },
                        };

                        match submit_withdrawal_completion(
                            &monitor.ace_rpc_url,
                            &withdrawal,
                            &tx_hash,
                            gateway_address,
                            &relayer_private_key,
                        )
                        .await
                        {
                            Ok(ace_tx_hash) => {
                                monitor.mark_processed(withdrawal.withdrawal_id);
                                checkpoint_store.set_egress(monitor.checkpoint())?;
                                info!(
                                    "Withdrawal {} completed on ACE with tx {}",
                                    withdrawal.withdrawal_id, ace_tx_hash
                                );
                            }
                            Err(e) => {
                                error!(
                                    "Withdrawal {} external tx {} confirmed, but ACE completion failed: {}",
                                    withdrawal.withdrawal_id, tx_hash, e
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Error querying ACE: {}", e);
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval_secs)).await;
    }
}

async fn submit_withdrawal_completion(
    ace_rpc_url: &str,
    withdrawal: &WithdrawalRecord,
    external_tx_hash: &str,
    gateway_address: Vec<u8>,
    relayer_private_key: &str,
) -> Result<String> {
    let completion = sign_withdrawal_completion(
        withdrawal,
        external_tx_hash,
        gateway_address,
        relayer_private_key,
    )?;
    let response = reqwest::Client::new()
        .post(ace_rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": "ace_markWithdrawalCompleted",
            "params": [completion],
        }))
        .send()
        .await
        .map_err(|e| RelayerError::AceError(e.to_string()))?;
    let value: Value = response
        .json()
        .await
        .map_err(|e| RelayerError::AceError(e.to_string()))?;
    if let Some(error) = value.get("error") {
        return Err(RelayerError::AceError(format!(
            "ace_markWithdrawalCompleted failed: {error}"
        )));
    }
    value
        .get("result")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| RelayerError::AceError("missing completion tx hash".into()))
}

fn normalize_external_dest(value: &[u8]) -> Result<String> {
    if value.len() != 20 {
        return Err(RelayerError::WithdrawalError(format!(
            "address must be 20 bytes, got {}",
            value.len()
        )));
    }
    Ok(format!("0x{}", hex::encode(value)))
}

fn u64_to_quantity(value: u64) -> String {
    format!("0x{value:x}")
}

fn parse_quantity(value: &str) -> Option<u64> {
    u64::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16).ok()
}

fn evm_signing_key_from_hex(private_key_hex: &str) -> Result<EvmSigningKey> {
    let bytes = parse_hex_bytes(private_key_hex)?;
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        RelayerError::ConfigError(format!(
            "EVM egress private key must be 32 bytes, got {}",
            bytes.len()
        ))
    })?;
    EvmSigningKey::from_bytes((&key_bytes).into())
        .map_err(|e| RelayerError::ConfigError(format!("invalid EVM egress private key: {e}")))
}

fn evm_address_from_signing_key(signing_key: &EvmSigningKey) -> [u8; 20] {
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let mut hasher = Keccak::v256();
    let mut hash = [0u8; 32];
    hasher.update(&encoded.as_bytes()[1..]);
    hasher.finalize(&mut hash);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

fn sign_legacy_eip155_transaction(
    signing_key: &EvmSigningKey,
    chain_id: u64,
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: [u8; 20],
    value: u64,
    data: &[u8],
) -> Result<(String, String)> {
    let mut unsigned = RlpStream::new_list(9);
    unsigned.append(&nonce);
    unsigned.append(&gas_price);
    unsigned.append(&gas_limit);
    unsigned.append(&to.as_slice());
    unsigned.append(&value);
    unsigned.append(&data);
    unsigned.append(&chain_id);
    unsigned.append(&0u8);
    unsigned.append(&0u8);

    let mut hasher = Keccak::v256();
    let mut sighash = [0u8; 32];
    hasher.update(&unsigned.out());
    hasher.finalize(&mut sighash);

    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&sighash)
        .map_err(|e| RelayerError::WithdrawalError(format!("EVM tx signing failed: {e}")))?;
    let sig_bytes = signature.to_bytes();
    let r = trim_leading_zeroes(&sig_bytes[..32]);
    let s = trim_leading_zeroes(&sig_bytes[32..]);
    let v = chain_id
        .checked_mul(2)
        .and_then(|v| v.checked_add(35))
        .and_then(|v| v.checked_add(recovery_id.to_byte() as u64))
        .ok_or(RelayerError::WithdrawalError(
            "EIP-155 recovery id overflow".into(),
        ))?;

    let mut signed = RlpStream::new_list(9);
    signed.append(&nonce);
    signed.append(&gas_price);
    signed.append(&gas_limit);
    signed.append(&to.as_slice());
    signed.append(&value);
    signed.append(&data);
    signed.append(&v);
    signed.append(&r);
    signed.append(&s);

    let signed_bytes = signed.out();
    let mut tx_hasher = Keccak::v256();
    let mut tx_hash_bytes = [0u8; 32];
    tx_hasher.update(&signed_bytes);
    tx_hasher.finalize(&mut tx_hash_bytes);

    Ok((
        format!("0x{}", hex::encode(signed_bytes)),
        format!("0x{}", hex::encode(tx_hash_bytes)),
    ))
}

fn trim_leading_zeroes(bytes: &[u8]) -> Vec<u8> {
    let first_non_zero = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[first_non_zero..].to_vec()
}

fn parse_evm_address(value: &str) -> Result<[u8; 20]> {
    let bytes = parse_hex_bytes(value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RelayerError::WithdrawalError(format!("EVM address must be 20 bytes, got {}", bytes.len()))
    })
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|e| RelayerError::WithdrawalError(format!("invalid hex value: {e}")))
}

fn erc20_transfer_calldata(to: &str, amount: u64) -> Result<String> {
    let mut data = Vec::with_capacity(4 + 32 + 32);
    data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    let address = hex::decode(to.strip_prefix("0x").unwrap_or(to))
        .map_err(|e| RelayerError::WithdrawalError(format!("invalid transfer recipient: {e}")))?;
    if address.len() != 20 {
        return Err(RelayerError::WithdrawalError(
            "transfer recipient must be 20 bytes".into(),
        ));
    }
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&address);
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&amount.to_be_bytes());
    Ok(format!("0x{}", hex::encode(data)))
}

fn omni_gateway_release_calldata(
    withdrawal_id: u64,
    token: &[u8; 20],
    recipient: &str,
    amount: u64,
    signatures: &[[u8; 65]],
) -> Result<Vec<u8>> {
    let mut selector_hash = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(b"releaseWithSignatures(bytes32,address,address,uint256,bytes[])");
    hasher.finalize(&mut selector_hash);

    let recipient = parse_evm_address(recipient)?;
    let mut data = Vec::with_capacity(4 + 32 * (6 + signatures.len() * 4));
    data.extend_from_slice(&selector_hash[0..4]);

    let mut withdrawal_id_word = [0u8; 32];
    withdrawal_id_word[24..32].copy_from_slice(&withdrawal_id.to_be_bytes());
    data.extend_from_slice(&withdrawal_id_word);

    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(token);

    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&recipient);

    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&amount.to_be_bytes());

    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&(32u64 * 5).to_be_bytes());

    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&(signatures.len() as u64).to_be_bytes());
    for idx in 0..signatures.len() {
        let offset = 32u64
            .checked_mul(signatures.len() as u64 + 1)
            .and_then(|v| v.checked_add((idx as u64) * 128))
            .ok_or_else(|| RelayerError::WithdrawalError("signature ABI offset overflow".into()))?;
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&offset.to_be_bytes());
    }
    for signature in signatures {
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&(signature.len() as u64).to_be_bytes());
        data.extend_from_slice(signature);
        data.extend_from_slice(&[0u8; 31]);
    }
    Ok(data)
}

fn release_signing_keys(chain_name: &str) -> Result<Vec<EvmSigningKey>> {
    let raw = std::env::var(format!(
        "ACE_DEFI_EGRESS_RELEASE_PRIVATE_KEYS_{}",
        chain_name.to_ascii_uppercase()
    ))
    .or_else(|_| std::env::var("ACE_DEFI_EGRESS_RELEASE_PRIVATE_KEYS"))
    .or_else(|_| std::env::var("ACE_DEFI_EGRESS_PRIVATE_KEY"))
    .map_err(|_| {
        RelayerError::ConfigError(format!(
            "missing ACE_DEFI_EGRESS_RELEASE_PRIVATE_KEYS_{} or ACE_DEFI_EGRESS_RELEASE_PRIVATE_KEYS",
            chain_name.to_ascii_uppercase()
        ))
    })?;
    let keys = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(evm_signing_key_from_hex)
        .collect::<Result<Vec<_>>>()?;
    if keys.is_empty() {
        return Err(RelayerError::ConfigError(
            "at least one release signing key is required".into(),
        ));
    }
    Ok(keys)
}

fn gateway_release_signatures(
    signing_keys: &[EvmSigningKey],
    chain_id: u64,
    gateway: [u8; 20],
    withdrawal_id: u64,
    token: &[u8; 20],
    recipient: &str,
    amount: u64,
) -> Result<Vec<[u8; 65]>> {
    let mut signatures = Vec::with_capacity(signing_keys.len());
    for signing_key in signing_keys {
        signatures.push((
            evm_address_from_signing_key(signing_key),
            gateway_release_signature(
                signing_key,
                chain_id,
                gateway,
                withdrawal_id,
                token,
                recipient,
                amount,
            )?,
        ));
    }
    signatures.sort_by_key(|(address, _)| *address);
    Ok(signatures.into_iter().map(|(_, signature)| signature).collect())
}

fn gateway_release_signature(
    signing_key: &EvmSigningKey,
    chain_id: u64,
    gateway: [u8; 20],
    withdrawal_id: u64,
    token: &[u8; 20],
    recipient: &str,
    amount: u64,
) -> Result<[u8; 65]> {
    let recipient = parse_evm_address(recipient)?;
    let mut typehash = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(b"OMNILIQUID_EVM_RELEASE_V1");
    hasher.finalize(&mut typehash);

    let mut encoded = Vec::with_capacity(32 * 7);
    encoded.extend_from_slice(&typehash);
    encoded.extend_from_slice(&[0u8; 24]);
    encoded.extend_from_slice(&chain_id.to_be_bytes());
    encoded.extend_from_slice(&[0u8; 12]);
    encoded.extend_from_slice(&gateway);
    let mut withdrawal_id_word = [0u8; 32];
    withdrawal_id_word[24..32].copy_from_slice(&withdrawal_id.to_be_bytes());
    encoded.extend_from_slice(&withdrawal_id_word);
    encoded.extend_from_slice(&[0u8; 12]);
    encoded.extend_from_slice(token);
    encoded.extend_from_slice(&[0u8; 12]);
    encoded.extend_from_slice(&recipient);
    encoded.extend_from_slice(&[0u8; 24]);
    encoded.extend_from_slice(&amount.to_be_bytes());

    let mut message_hash = [0u8; 32];
    let mut message_hasher = Keccak::v256();
    message_hasher.update(&encoded);
    message_hasher.finalize(&mut message_hash);

    let mut digest = [0u8; 32];
    let mut digest_hasher = Keccak::v256();
    digest_hasher.update(b"\x19Ethereum Signed Message:\n32");
    digest_hasher.update(&message_hash);
    digest_hasher.finalize(&mut digest);

    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).map_err(|e| {
        RelayerError::WithdrawalError(format!("Gateway release signing failed: {e}"))
    })?;
    let sig_bytes = signature.to_bytes();
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig_bytes);
    out[64] = recovery_id.to_byte() + 27;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_model::account::AccountId;

    #[test]
    fn test_withdrawal_monitor_creation() {
        let monitor = WithdrawalMonitor::new("http://localhost:18545".to_string());
        assert_eq!(monitor.last_checked_slot, 0);
    }

    #[test]
    fn test_withdrawal_idempotency() {
        let mut monitor = WithdrawalMonitor::new("http://localhost:18545".to_string());

        let withdrawal_id = 123u64;
        assert!(!monitor.is_processed(withdrawal_id));
        monitor.mark_processed(withdrawal_id);
        assert!(monitor.is_processed(withdrawal_id));
    }

    #[test]
    fn test_chain_executor_creation() {
        let executor = ChainExecutor::new("ethereum", "http://localhost:8545", None);
        assert_eq!(executor.chain_name, "ethereum");
    }

    #[test]
    fn test_withdrawal_executor_has_all_chains() {
        let mut chains = HashMap::new();
        for chain in ["ethereum", "bsc", "tron", "solana"] {
            chains.insert(
                chain.to_string(),
                ChainConfig {
                    name: chain.to_string(),
                    rpc_url: "http://localhost:8545".to_string(),
                    finality_blocks: 1,
                    block_time_secs: 1,
                    bridge_contract: None,
                },
            );
        }
        let executor = WithdrawalExecutor::new(&chains);
        assert!(executor.chain_executors.contains_key("ethereum"));
        assert!(executor.chain_executors.contains_key("bsc"));
        assert!(executor.chain_executors.contains_key("tron"));
        assert!(executor.chain_executors.contains_key("solana"));
    }

    #[tokio::test]
    async fn test_chain_executor_fails_closed_without_mock_flag() {
        std::env::remove_var("ACE_DEFI_RELAYER_ALLOW_MOCK_EGRESS");
        let executor = ChainExecutor::new("ethereum", "http://localhost:8545", None);
        let withdrawal = WithdrawalRecord {
            withdrawal_id: 1,
            intent_id: [0x11; 32],
            asset: ExternalAsset::Native(ExternalChain::Ethereum),
            amount: 100,
            sender: AccountId::from_bytes([0x22; 32]),
            external_dest: vec![0x01; 20],
            requested_at: 1,
            completed: false,
        };

        let result = executor.execute(&withdrawal, &mut |_| Ok(())).await;
        assert!(result.is_err());
    }

    #[test]
    fn erc20_transfer_calldata_is_abi_encoded() {
        let to = "0x00000000000000000000000000000000000000aa";
        let calldata = erc20_transfer_calldata(to, 500).unwrap();

        assert_eq!(calldata.len(), 2 + (4 + 32 + 32) * 2);
        assert!(calldata.starts_with("0xa9059cbb"));
        assert!(
            calldata.contains("00000000000000000000000000000000000000000000000000000000000000aa")
        );
        assert!(
            calldata.ends_with("00000000000000000000000000000000000000000000000000000000000001f4")
        );
    }

    #[test]
    fn omni_gateway_release_calldata_is_abi_encoded() {
        let token = [0x11u8; 20];
        let recipient = "0x00000000000000000000000000000000000000aa";
        let signature = [0x99u8; 65];
        let calldata =
            omni_gateway_release_calldata(7, &token, recipient, 500, &[signature]).unwrap();

        assert_eq!(calldata.len(), 4 + 32 * 11);
        assert_eq!(hex::encode(&calldata[4 + 24..4 + 32]), "0000000000000007");
        assert_eq!(
            hex::encode(&calldata[4 + 32 + 12..4 + 64]),
            hex::encode(token)
        );
        assert_eq!(
            hex::encode(&calldata[4 + 64 + 12..4 + 96]),
            "00000000000000000000000000000000000000aa"
        );
        assert_eq!(
            hex::encode(&calldata[4 + 96..4 + 128]),
            "00000000000000000000000000000000000000000000000000000000000001f4"
        );
        assert_eq!(
            hex::encode(&calldata[4 + 128..4 + 160]),
            "00000000000000000000000000000000000000000000000000000000000000a0"
        );
        assert_eq!(
            hex::encode(&calldata[4 + 160..4 + 192]),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            hex::encode(&calldata[4 + 192..4 + 224]),
            "0000000000000000000000000000000000000000000000000000000000000040"
        );
        assert_eq!(
            hex::encode(&calldata[4 + 224..4 + 256]),
            "0000000000000000000000000000000000000000000000000000000000000041"
        );
        assert_eq!(&calldata[4 + 256..4 + 321], &signature);
    }

    #[test]
    fn gateway_release_receipt_must_match_expected_event() {
        let gateway = [0xAAu8; 20];
        let token = [0x11u8; 20];
        let recipient = [0x22u8; 20];
        let amount = 500u64;
        let withdrawal_id = 7u64;
        let receipt = json!({
            "logs": [{
                "address": format!("0x{}", hex::encode(gateway)),
                "topics": [
                    event_topic("Release(bytes32,address,address,uint256)"),
                    withdrawal_id_topic(withdrawal_id),
                    address_topic(token),
                    address_topic(recipient)
                ],
                "data": format!("0x{:064x}", amount)
            }]
        });

        assert!(validate_gateway_release_receipt(
            &receipt,
            gateway,
            withdrawal_id,
            token,
            recipient,
            amount
        )
        .is_ok());
        assert!(validate_gateway_release_receipt(
            &receipt,
            gateway,
            withdrawal_id,
            token,
            recipient,
            amount + 1
        )
        .is_err());
    }
}
