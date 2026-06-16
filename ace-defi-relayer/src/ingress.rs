//! Ingress monitoring: External chains → ACE Chain
//!
//! This module monitors external chains for deposit events and submits
//! signed attestations to ACE Chain for minting wrapped tokens.

use crate::error::Result;
use crate::signing::sign_ace_deposit;
use crate::storage::{ChainCheckpoint, CheckpointStore};
use crate::types::DepositEvent;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, error, info};

const DEPOSIT_EVENT_TOPIC: &str =
    "0x5f6a399085038de872c0b08617dbc6d54bb35693a302ec9209c89607de5bc2d5";

/// Monitors a single external chain for deposit events
pub struct ChainMonitor {
    pub chain_name: String,
    pub rpc_url: String,
    pub finality_blocks: u64,
    pub block_time_secs: u64,
    pub last_scanned_block: u64,
    pub processed_deposits: HashMap<String, bool>,
}

pub struct DepositScan {
    pub deposits: Vec<DepositEvent>,
    pub finalized_block: u64,
}

impl ChainMonitor {
    pub fn new(
        chain_name: String,
        rpc_url: String,
        finality_blocks: u64,
        block_time_secs: u64,
    ) -> Self {
        Self {
            chain_name,
            rpc_url,
            finality_blocks,
            block_time_secs,
            last_scanned_block: 0,
            processed_deposits: HashMap::new(),
        }
    }

    /// Scan for new deposits since last checkpoint
    pub async fn scan_for_deposits(&self, bridge_contract: &str) -> Result<DepositScan> {
        info!(
            "Scanning {} from block {} for deposits",
            self.chain_name, self.last_scanned_block
        );

        // Get current block number
        let current_block = self.get_current_block().await?;
        debug!("Current block on {}: {}", self.chain_name, current_block);

        // Calculate finalized block (current - finality_blocks)
        let finalized_block = if current_block > self.finality_blocks {
            current_block - self.finality_blocks
        } else {
            0
        };

        info!(
            "Finalized block on {}: {}",
            self.chain_name, finalized_block
        );

        // Only process blocks that have reached finality
        if self.last_scanned_block >= finalized_block {
            debug!("No new finalized blocks to scan on {}", self.chain_name);
            return Ok(DepositScan {
                deposits: vec![],
                finalized_block,
            });
        }

        let from_block = self.last_scanned_block.saturating_add(1);
        let deposits = self
            .fetch_deposit_events(bridge_contract, from_block, finalized_block)
            .await?;

        Ok(DepositScan {
            deposits,
            finalized_block,
        })
    }

    /// Fetch EVM-compatible deposit events via `eth_getLogs`.
    async fn fetch_deposit_events(
        &self,
        bridge_contract: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<DepositEvent>> {
        let params = json!([{
            "address": bridge_contract,
            "fromBlock": hex_quantity(from_block),
            "toBlock": hex_quantity(to_block),
            "topics": [DEPOSIT_EVENT_TOPIC],
        }]);
        let logs = self
            .json_rpc("eth_getLogs", params)
            .await?
            .as_array()
            .cloned()
            .ok_or_else(|| {
                crate::error::RelayerError::RpcError("eth_getLogs returned non-array".into())
            })?;

        logs.into_iter()
            .map(|log| self.decode_deposit_log(log))
            .collect()
    }

    /// Get current block number from RPC
    async fn get_current_block(&self) -> Result<u64> {
        if std::env::var("ACE_DEFI_RELAYER_ALLOW_MOCK_RPC").as_deref() == Ok("1") {
            return match self.chain_name.as_str() {
                "ethereum" => Ok(19_000_000),
                "bsc" => Ok(35_000_000),
                _ => Ok(0),
            };
        }

        let value = self.json_rpc("eth_blockNumber", json!([])).await?;
        let block_hex = value.as_str().ok_or_else(|| {
            crate::error::RelayerError::RpcError("eth_blockNumber returned non-string".into())
        })?;
        parse_hex_u64(block_hex, "block number")
    }

    /// Mark a deposit as processed (idempotency)
    pub fn mark_processed(&mut self, deposit_id: &str) {
        self.processed_deposits.insert(deposit_id.to_string(), true);
        debug!(
            "Marked deposit {} as processed on {}",
            deposit_id, self.chain_name
        );
    }

    /// Check if deposit was already processed
    pub fn is_processed(&self, deposit_id: &str) -> bool {
        self.processed_deposits.contains_key(deposit_id)
    }

    pub fn advance_checkpoint(&mut self, finalized_block: u64) {
        self.last_scanned_block = self.last_scanned_block.max(finalized_block);
    }

    pub fn restore_checkpoint(&mut self, checkpoint: ChainCheckpoint) {
        self.last_scanned_block = checkpoint.last_scanned_block;
        self.processed_deposits = checkpoint
            .processed_deposits
            .into_iter()
            .map(|deposit_id| (deposit_id, true))
            .collect();
    }

    pub fn checkpoint(&self) -> ChainCheckpoint {
        ChainCheckpoint {
            last_scanned_block: self.last_scanned_block,
            processed_deposits: self.processed_deposits.keys().cloned().collect(),
        }
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
            .map_err(|e| crate::error::RelayerError::RpcError(e.to_string()))?;

        let value: Value = response
            .json()
            .await
            .map_err(|e| crate::error::RelayerError::RpcError(e.to_string()))?;
        if let Some(error) = value.get("error") {
            return Err(crate::error::RelayerError::RpcError(format!(
                "{method} failed: {error}"
            )));
        }
        value.get("result").cloned().ok_or_else(|| {
            crate::error::RelayerError::RpcError(format!("{method} response missing result"))
        })
    }

    fn decode_deposit_log(&self, log: Value) -> Result<DepositEvent> {
        let topics = log
            .get("topics")
            .and_then(Value::as_array)
            .ok_or_else(|| crate::error::RelayerError::RpcError("log missing topics".into()))?;
        if topics.len() < 4 {
            return Err(crate::error::RelayerError::RpcError(
                "Deposit log has fewer than 4 topics".into(),
            ));
        }

        let deposit_id = topics[1]
            .as_str()
            .ok_or_else(|| crate::error::RelayerError::RpcError("missing depositId topic".into()))?
            .to_string();
        let intent_id = topics[2]
            .as_str()
            .ok_or_else(|| crate::error::RelayerError::RpcError("missing intentId topic".into()))?
            .to_string();

        let data = log
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::error::RelayerError::RpcError("log missing data".into()))?;
        let words = decode_words(data, 4)?;
        let token = format!("0x{}", hex::encode(&words[0][12..32]));
        let amount = word_to_u128(&words[1], "amount")?;
        let recipient = format!("0x{}", hex::encode(words[2]));
        let timestamp = word_to_u128(&words[3], "timestamp")?;

        let block_number = log
            .get("blockNumber")
            .and_then(Value::as_str)
            .map(|s| parse_hex_u64(s, "log blockNumber"))
            .transpose()?
            .unwrap_or_default();
        let tx_hash = log
            .get("transactionHash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        Ok(DepositEvent {
            deposit_id,
            intent_id,
            source_chain: self.chain_name.clone(),
            token,
            amount,
            recipient,
            block_number,
            tx_hash,
            timestamp: u64::try_from(timestamp).map_err(|_| {
                crate::error::RelayerError::RpcError("timestamp exceeds u64".into())
            })?,
        })
    }
}

fn hex_quantity(value: u64) -> String {
    format!("0x{value:x}")
}

fn parse_hex_u64(value: &str, field: &str) -> Result<u64> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    u64::from_str_radix(trimmed, 16).map_err(|e| {
        crate::error::RelayerError::RpcError(format!("invalid {field} hex quantity: {e}"))
    })
}

fn decode_words(data: &str, expected_words: usize) -> Result<Vec<[u8; 32]>> {
    let bytes = hex::decode(data.strip_prefix("0x").unwrap_or(data))
        .map_err(|e| crate::error::RelayerError::RpcError(format!("invalid log data: {e}")))?;
    if bytes.len() < expected_words * 32 {
        return Err(crate::error::RelayerError::RpcError(format!(
            "log data too short: got {} bytes, need {}",
            bytes.len(),
            expected_words * 32
        )));
    }
    Ok(bytes
        .chunks_exact(32)
        .take(expected_words)
        .map(|chunk| {
            let mut word = [0u8; 32];
            word.copy_from_slice(chunk);
            word
        })
        .collect())
}

fn word_to_u128(word: &[u8; 32], field: &str) -> Result<u128> {
    if word[..16].iter().any(|b| *b != 0) {
        return Err(crate::error::RelayerError::RpcError(format!(
            "{field} exceeds u128"
        )));
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&word[16..32]);
    Ok(u128::from_be_bytes(buf))
}

/// Submitter for signed deposits to ACE Chain
pub struct DepositSubmitter {
    pub ace_rpc_url: String,
    pub relayer_private_key: String,
    pub relayer_id: String,
    pub max_deposit_per_tx: u128,
}

impl DepositSubmitter {
    pub fn new(
        ace_rpc_url: String,
        relayer_private_key: String,
        relayer_id: String,
        max_deposit_per_tx: u128,
    ) -> Self {
        Self {
            ace_rpc_url,
            relayer_private_key,
            relayer_id,
            max_deposit_per_tx,
        }
    }

    /// Sign and submit a deposit to ACE Chain
    pub async fn submit_deposit(&self, deposit: &DepositEvent) -> Result<String> {
        info!("Submitting deposit {} to ACE Chain", deposit.deposit_id);
        if deposit.amount > self.max_deposit_per_tx {
            return Err(crate::error::RelayerError::DepositError(format!(
                "deposit {} exceeds max_deposit_per_tx {}",
                deposit.amount, self.max_deposit_per_tx
            )));
        }

        // Sign using the exact ACE-side canonical deposit record format.
        let signed = sign_ace_deposit(deposit, &self.relayer_private_key)?;
        debug!(
            deposit_id = hex::encode(signed.deposit.deposit_id),
            relayer = hex::encode(signed.relayer_pubkey),
            "Signed ACE deposit record"
        );

        // Submit to ACE Chain via RPC
        let tx_hash = self.send_to_ace(&signed).await?;

        info!(
            "Deposit {} submitted to ACE with tx {}",
            deposit.deposit_id, tx_hash
        );
        Ok(tx_hash)
    }

    /// Send signed deposit to ACE Chain.
    async fn send_to_ace(&self, signed: &ace_defi::types::SignedDepositRecord) -> Result<String> {
        if std::env::var("ACE_DEFI_RELAYER_ALLOW_MOCK_RPC").as_deref() == Ok("1") {
            let mut hasher = Sha256::new();
            hasher.update(b"ace-defi-relayer:mock-submit:v1");
            hasher.update(signed.deposit.deposit_id);
            hasher.update(signed.relayer_pubkey);
            hasher.update(signed.relayer_signature);
            return Ok(format!("0x{}", hex::encode(hasher.finalize())));
        }

        let response = reqwest::Client::new()
            .post(&self.ace_rpc_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1u64,
                "method": "ace_submitDeposit",
                "params": [signed],
            }))
            .send()
            .await
            .map_err(|e| crate::error::RelayerError::AceError(e.to_string()))?;
        let value: Value = response
            .json()
            .await
            .map_err(|e| crate::error::RelayerError::AceError(e.to_string()))?;
        if let Some(error) = value.get("error") {
            return Err(crate::error::RelayerError::AceError(format!(
                "ace_submitDeposit failed: {error}"
            )));
        }
        value
            .get("result")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                crate::error::RelayerError::AceError(
                    "ace_submitDeposit response missing string result".into(),
                )
            })
    }
}

/// Main ingress monitoring loop
pub async fn monitor_ingress(
    chain_name: String,
    rpc_url: String,
    bridge_contract: String,
    finality_blocks: u64,
    block_time_secs: u64,
    ace_rpc_url: String,
    relayer_private_key: String,
    relayer_id: String,
    max_deposit_per_tx: u128,
    poll_interval_secs: u64,
) -> Result<()> {
    let mut monitor = ChainMonitor::new(
        chain_name.clone(),
        rpc_url,
        finality_blocks,
        block_time_secs,
    );
    let checkpoint_path = std::env::var("ACE_DEFI_RELAYER_CHECKPOINT_FILE")
        .unwrap_or_else(|_| "ace-defi-relayer-checkpoints.json".to_string());
    let mut checkpoint_store = CheckpointStore::load(checkpoint_path)?;
    monitor.restore_checkpoint(checkpoint_store.chain(&chain_name));
    let submitter = DepositSubmitter::new(
        ace_rpc_url,
        relayer_private_key,
        relayer_id,
        max_deposit_per_tx,
    );

    info!("Started ingress monitoring for {}", chain_name);

    loop {
        match monitor.scan_for_deposits(&bridge_contract).await {
            Ok(scan) => {
                let mut all_submitted = true;
                for deposit in scan.deposits {
                    if !monitor.is_processed(&deposit.deposit_id) {
                        match submitter.submit_deposit(&deposit).await {
                            Ok(_) => {
                                monitor.mark_processed(&deposit.deposit_id);
                                checkpoint_store.set_chain(&chain_name, monitor.checkpoint())?;
                            }
                            Err(e) => {
                                all_submitted = false;
                                error!("Failed to submit deposit: {}", e);
                                // Continue to next deposit; will retry next iteration
                            }
                        }
                    }
                }
                if all_submitted {
                    monitor.advance_checkpoint(scan.finalized_block);
                }
                checkpoint_store.set_chain(&chain_name, monitor.checkpoint())?;
            }
            Err(e) => {
                error!("Error scanning {}: {}", chain_name, e);
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval_secs)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_monitor_creation() {
        let monitor = ChainMonitor::new(
            "ethereum".to_string(),
            "https://eth.example.com".to_string(),
            12,
            12,
        );

        assert_eq!(monitor.chain_name, "ethereum");
        assert_eq!(monitor.finality_blocks, 12);
    }

    #[test]
    fn test_deposit_processing_idempotency() {
        let mut monitor = ChainMonitor::new(
            "ethereum".to_string(),
            "https://eth.example.com".to_string(),
            12,
            12,
        );

        let deposit_id = "test-deposit-123";

        assert!(!monitor.is_processed(deposit_id));
        monitor.mark_processed(deposit_id);
        assert!(monitor.is_processed(deposit_id));
    }

    #[test]
    fn checkpoint_advances_only_when_explicitly_committed() {
        let mut monitor = ChainMonitor::new(
            "ethereum".to_string(),
            "https://eth.example.com".to_string(),
            12,
            12,
        );

        assert_eq!(monitor.checkpoint().last_scanned_block, 0);
        monitor.advance_checkpoint(100);
        assert_eq!(monitor.checkpoint().last_scanned_block, 100);
        monitor.advance_checkpoint(50);
        assert_eq!(monitor.checkpoint().last_scanned_block, 100);
    }
}
