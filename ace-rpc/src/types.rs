//! RPC request/response types with hex-encoded fields.

use serde::{Deserialize, Serialize};

/// Account information returned by RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAccount {
    /// Identity commitment as hex string.
    pub id_com: String,
    /// Account balance.
    pub balance: u64,
    /// Transaction nonce (confirmed on-chain).
    pub nonce: u64,
    /// Next nonce to use, accounting for pending mempool transactions.
    pub pending_nonce: u64,
    /// Whether the account has a registered auth public key.
    pub has_auth_pubkey: bool,
    /// Registered auth key algorithms (e.g., ["ed25519", "ml-dsa-44"]).
    pub auth_algorithms: Vec<String>,
    /// Optional code hash as hex string.
    pub code_hash: Option<String>,
    /// Storage root as hex string.
    pub storage_root: String,
    /// XID (ACE-GF wallet fingerprint) as hex string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xid: Option<String>,
    /// PQC xaddress fingerprint as hex string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xaddress: Option<String>,
    /// EVM address as hex string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm_address: Option<String>,
    /// TRON address as hex string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tron_address: Option<String>,
    /// Solana Ed25519 pubkey as hex string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solana_address: Option<String>,
    /// Bitcoin script pubkey as hex string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub btc_address: Option<String>,
}

/// Block information returned by RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBlock {
    /// Slot number.
    pub slot: u64,
    /// Parent block hash as hex string.
    pub parent_hash: String,
    /// State root as hex string.
    pub state_root: String,
    /// Transaction Merkle root as hex string.
    pub tx_merkle_root: String,
    /// Attestation Merkle root as hex string.
    pub attest_merkle_root: String,
    /// PoH hash as hex string.
    pub poh_hash: String,
    /// Leader identity commitment as hex string.
    pub leader_idcom: String,
    /// Block timestamp.
    pub timestamp: u64,
    /// Number of transactions.
    pub tx_count: u32,
    /// Block hash as hex string.
    pub hash: String,
}

/// Finality status returned by RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcFinalityStatus {
    /// Slot number.
    pub slot: u64,
    /// Finality state: "pending", "soft", "hard", "backup_wait", "rolled_back".
    pub state: String,
}

/// Transaction information returned by RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTransaction {
    /// Index within the block.
    pub index: u32,
    /// Canonical transaction hash (SHA-256 of the serialized transaction) as hex string.
    pub tx_hash: String,
    /// Sender identity commitment as hex string.
    pub sender_idcom: String,
    /// Payload size in bytes.
    pub payload_size: usize,
    /// Domain chain_id.
    pub chain_id: u32,
    /// Domain slot.
    pub domain_slot: u32,
    /// Total wire size in bytes.
    pub wire_size: usize,
    /// First byte of payload (opcode).
    pub opcode: Option<u8>,
    /// VM type: "Native", "EVM", "SVM", or "Unknown".
    pub vm_type: String,
    /// Human-readable operation name.
    pub op_name: String,
    /// Signature algorithm: "Ed25519", "Secp256k1", "ML-DSA-44", or "HMAC-SHA256".
    pub sig_algorithm: String,
    /// Signature size in bytes.
    pub sig_size: usize,
    /// Credential (algorithm-tagged signature) as hex string.
    pub credential_hex: String,
}

/// A single TPS sample: timestamp (ms) + transactions-per-second.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTpsSample {
    /// Unix timestamp in milliseconds.
    pub time: u64,
    /// Transactions per second at this sample point.
    pub tps: f64,
}

/// Network status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcNetworkStatus {
    /// Current slot number.
    pub current_slot: u64,
    /// Latest block slot in store.
    pub latest_block_slot: u64,
    /// State root as hex string.
    pub state_root: String,
    /// Total blocks stored.
    pub block_count: u64,
    /// Currently connected P2P peers.
    pub peer_count: u64,
    /// Wall-clock slot step in ms (`ace_runtime::config::SLOT_DURATION_MS`); for clients computing
    /// time ↔ slot (e.g. HFI `expiry_slots`).
    pub slot_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcPeerInfo {
    pub peer_id: String,
    pub remote_addr: String,
    pub direction: String,
    pub connected_secs: u64,
    pub messages_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcValidatorOnboarding {
    pub enabled: bool,
    pub admission_policy: String,
    pub requires_founder_approval: bool,
    pub founder_idcom: Option<String>,
    pub current_validator_count: usize,
    pub activation: String,
    pub safety_model: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcValidatorCandidateCheck {
    pub candidate_idcom: String,
    pub admission_policy: String,
    pub eligible: bool,
    pub expected_signing_pubkey: Option<String>,
    pub supplied_signing_pubkey: Option<String>,
    pub errors: Vec<String>,
    pub next_step: String,
    pub safety_model: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcNodeContribution {
    pub roles: Vec<String>,
    pub public_rpc: bool,
    pub tx_relay: bool,
    pub block_relay: bool,
    pub archive: bool,
    pub light_client_provider: bool,
    pub indexer_backend: bool,
    pub consensus_participant: bool,
    pub safety_model: Vec<String>,
}

/// Mempool status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcMempoolInfo {
    /// Total transactions tracked (ready + future).
    pub pending_count: usize,
    /// Transactions ready for block inclusion.
    pub ready_count: usize,
}

/// Shard information returned by RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcShardInfo {
    /// Number of active shards.
    pub shard_count: usize,
    /// Total accounts across all shards.
    pub total_accounts: usize,
    /// Global state root (hex).
    pub state_root: String,
    /// Per-shard details, ordered by shard ID.
    pub shards: Vec<RpcShardDetail>,
}

/// Per-shard detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcShardDetail {
    /// Shard identifier.
    pub shard_id: u64,
    /// Number of accounts in this shard.
    pub account_count: usize,
    /// Shard-local state root (hex).
    pub state_root: String,
}

/// Native token metadata (symbol and decimals) for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeTokenInfo {
    pub symbol: String,
    pub decimals: u8,
}

/// Transaction receipt for RPC (industry-standard getTransactionReceipt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcTransactionReceipt {
    /// Transaction hash (hex).
    pub transaction_hash: String,
    /// Optional external transaction hash (hex), e.g. canonical Ethereum tx hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_transaction_hash: Option<String>,
    /// Block slot.
    pub block_slot: u64,
    /// Block hash (hex).
    pub block_hash: String,
    /// Index in block.
    pub transaction_index: u32,
    /// Sender identity commitment (hex).
    pub from: String,
    /// Success flag.
    pub status: bool,
    /// Error message if failed.
    pub error: Option<String>,
    /// State changes applied (for inspection).
    pub state_changes: Vec<RpcStateChange>,
    /// Gas used (EVM only).
    pub gas_used: Option<u64>,
    /// Contract address created by this transaction, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<String>,
    /// EVM logs with block/transaction metadata populated when available.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evm_logs: Vec<EthLog>,
}

/// Single state change in a receipt (JSON-friendly).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RpcStateChange {
    BalanceChange {
        account: String,
        old: u64,
        new: u64,
    },
    NonceIncrement {
        account: String,
        new_nonce: u64,
    },
    AccountCreated {
        account: String,
    },
    StorageChange {
        account: String,
        slot: String,
        old_value: String,
        new_value: String,
    },
    CodeDeployed {
        account: String,
        code_hash: String,
    },
    Fee {
        amount: u64,
    },
    AddressBound {
        account: String,
        address_type: u8,
    },
    AuthKeyUpdated {
        account: String,
        algorithm: u8,
    },
    IntentChange {
        intent_id: String,
        old_status: u8,
        new_status: u8,
        /// SHA-256(intent_id || ACE_CLAIM_SALT), present only on Claimed transitions.
        #[serde(skip_serializing_if = "Option::is_none")]
        claim_tag: Option<String>,
    },
    ZkReplayConsumed {
        rp_com: String,
        account: String,
    },
}

/// Transaction + location for getTransactionByHash response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTransactionByHash {
    /// Slot of the block containing this tx.
    pub block_slot: u64,
    /// Block hash (hex).
    pub block_hash: String,
    /// Index in block.
    pub transaction_index: u32,
    /// Transaction hash (hex).
    pub transaction_hash: String,
    /// Full transaction summary (same shape as in getBlockTransactions).
    pub transaction: RpcTransaction,
}

// ── Ethereum JSON-RPC compatible types ──

/// Ethereum-compatible transaction receipt (returned by eth_getTransactionReceipt).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTransactionReceipt {
    /// Transaction hash (0x-prefixed hex).
    pub transaction_hash: String,
    /// Index within the block (hex).
    pub transaction_index: String,
    /// Block hash (0x-prefixed hex).
    pub block_hash: String,
    /// Block number (hex). Maps to ACE slot.
    pub block_number: String,
    /// Sender address (0x-prefixed hex, 20 bytes).
    pub from: String,
    /// Recipient address (0x-prefixed hex, 20 bytes). Null for contract creation.
    pub to: Option<String>,
    /// Cumulative gas used in block up to this tx (hex).
    pub cumulative_gas_used: String,
    /// Gas used by this tx (hex).
    pub gas_used: String,
    /// Contract address if this was a contract creation (0x-prefixed hex).
    pub contract_address: Option<String>,
    /// Event logs.
    pub logs: Vec<EthLog>,
    /// Bloom filter (256 bytes, all zeros for now).
    pub logs_bloom: String,
    /// Status: "0x1" for success, "0x0" for failure.
    pub status: String,
    /// Effective gas price (hex, always 0 on ACE).
    pub effective_gas_price: String,
    /// Transaction type: "0x0" legacy, "0x2" EIP-1559.
    #[serde(rename = "type")]
    pub tx_type: String,
}

/// Ethereum-compatible log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: String,
    pub transaction_hash: String,
    pub transaction_index: String,
    pub block_hash: String,
    pub log_index: String,
    pub removed: bool,
}

/// Ethereum-compatible block (returned by eth_getBlockByNumber / eth_getBlockByHash).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthBlock {
    pub number: String,
    pub hash: String,
    pub parent_hash: String,
    pub nonce: String,
    pub sha3_uncles: String,
    pub logs_bloom: String,
    pub transactions_root: String,
    pub state_root: String,
    pub receipts_root: String,
    pub miner: String,
    pub difficulty: String,
    pub total_difficulty: String,
    pub extra_data: String,
    pub size: String,
    pub gas_limit: String,
    pub gas_used: String,
    pub timestamp: String,
    /// Transaction hashes (when full_transactions=false) or full tx objects.
    pub transactions: Vec<serde_json::Value>,
    pub uncles: Vec<String>,
    pub base_fee_per_gas: String,
}

/// Ethereum-compatible transaction object (returned by eth_getTransactionByHash).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTransaction {
    pub hash: String,
    pub nonce: String,
    pub block_hash: Option<String>,
    pub block_number: Option<String>,
    pub transaction_index: Option<String>,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub gas: String,
    pub gas_price: String,
    pub input: String,
    pub v: String,
    pub r: String,
    pub s: String,
    #[serde(rename = "type")]
    pub tx_type: String,
}

impl EthBlock {
    /// Build an Ethereum-compatible block from an ACE Block.
    pub fn from_ace_block(block: &ace_runtime::types::block::Block, full_txs: bool) -> Self {
        let transactions = if full_txs {
            block
                .transactions
                .iter()
                .enumerate()
                .map(|(i, tx)| {
                    let sender_idcom = hex::encode(tx.attestation.idcom);
                    serde_json::json!({
                        "hash": format!("0x{}", hex::encode(tx.tx_hash())),
                        "nonce": "0x0",
                        "blockHash": format!("0x{}", hex::encode(block.hash())),
                        "blockNumber": format!("0x{:x}", block.header.slot),
                        "transactionIndex": format!("0x{:x}", i),
                        "from": format!("0x{}", &sender_idcom[..40]),
                        "to": null,
                        "value": "0x0",
                        "gas": "0x1e8480",
                        "gasPrice": "0x0",
                        "input": format!("0x{}", hex::encode(&tx.payload)),
                        "type": "0x0"
                    })
                })
                .collect()
        } else {
            block
                .transactions
                .iter()
                .map(|tx| serde_json::Value::String(format!("0x{}", hex::encode(tx.tx_hash()))))
                .collect()
        };

        Self {
            number: format!("0x{:x}", block.header.slot),
            hash: format!("0x{}", hex::encode(block.hash())),
            parent_hash: format!("0x{}", hex::encode(block.header.parent_hash)),
            nonce: "0x0000000000000000".into(),
            sha3_uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                .into(),
            logs_bloom: format!("0x{}", "00".repeat(256)),
            transactions_root: format!("0x{}", hex::encode(block.header.tx_merkle_root)),
            state_root: format!("0x{}", hex::encode(block.header.state_root)),
            receipts_root: format!("0x{}", hex::encode([0u8; 32])),
            miner: format!("0x{}", &hex::encode(block.header.leader_idcom)[..40]),
            difficulty: "0x0".into(),
            total_difficulty: "0x0".into(),
            extra_data: "0x".into(),
            size: format!("0x{:x}", 256 + block.transactions.len() * 244),
            gas_limit: "0x1c9c380".into(), // 30M
            gas_used: "0x0".into(),
            timestamp: format!("0x{:x}", block.header.timestamp / 1000),
            transactions,
            uncles: vec![],
            base_fee_per_gas: "0x0".into(),
        }
    }
}

impl RpcBlock {
    /// Convert from an ace-runtime Block.
    pub fn from_block(block: &ace_runtime::types::block::Block) -> Self {
        Self {
            slot: block.header.slot,
            parent_hash: hex::encode(block.header.parent_hash),
            state_root: hex::encode(block.header.state_root),
            tx_merkle_root: hex::encode(block.header.tx_merkle_root),
            attest_merkle_root: hex::encode(block.header.attest_merkle_root),
            poh_hash: hex::encode(block.header.poh_hash),
            leader_idcom: hex::encode(block.header.leader_idcom),
            timestamp: block.header.timestamp,
            tx_count: block.header.tx_count,
            hash: hex::encode(block.hash()),
        }
    }
}

impl RpcTransaction {
    /// Convert from an ace-runtime Transaction with its index.
    pub fn from_tx(tx: &ace_runtime::types::transaction::Transaction, index: u32) -> Self {
        let opcode = tx.payload.first().copied();
        let (vm_type, op_name) = match opcode {
            Some(0x01) => ("Native", "Transfer"),
            Some(0x02) => ("Native", "CreateAccount"),
            Some(0x03) => ("Native", "SetAuthPubkey"),
            Some(0x04) => ("Native", "AddAuthKey"),
            Some(0x05) => ("Native", "RegisterAddresses"),
            Some(0x10) => ("EVM", "Call"),
            Some(0x11) => ("EVM", "Create"),
            Some(0x12) => ("EVM", "Transfer"),
            Some(0x20) => ("SVM", "Invoke"),
            Some(0x21) => ("SVM", "Transfer"),
            _ => ("Unknown", "Unknown"),
        };
        let sig_algorithm = match tx.attestation.credential.algorithm {
            ace_runtime::crypto::sig_algo::SignatureAlgorithm::Ed25519 => "Ed25519",
            ace_runtime::crypto::sig_algo::SignatureAlgorithm::Secp256k1 => "Secp256k1",
            ace_runtime::crypto::sig_algo::SignatureAlgorithm::MlDsa44 => "ML-DSA-44",
            ace_runtime::crypto::sig_algo::SignatureAlgorithm::HmacSha256 => "HMAC-SHA256",
        };
        Self {
            index,
            tx_hash: hex::encode(tx.tx_hash()),
            sender_idcom: hex::encode(tx.attestation.idcom),
            payload_size: tx.payload.len(),
            chain_id: tx.attestation.domain.chain_id,
            domain_slot: tx.attestation.domain.slot,
            wire_size: tx.wire_size(),
            opcode,
            vm_type: vm_type.to_string(),
            op_name: op_name.to_string(),
            sig_algorithm: sig_algorithm.to_string(),
            sig_size: tx.attestation.credential.bytes.len(),
            credential_hex: hex::encode(&tx.attestation.credential.to_wire_bytes()),
        }
    }
}
