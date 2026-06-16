//! Common types for ACE DeFi Relayer

use serde::{Deserialize, Serialize};

pub use ace_defi::WithdrawalRecord;

/// Represents a deposit event from an external chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositEvent {
    /// Unique identifier for this deposit (hash of tx + event)
    pub deposit_id: String,
    /// User-authorized ACE ConvertIntent identifier.
    pub intent_id: String,
    /// Source blockchain (ethereum, bsc, solana, etc.)
    pub source_chain: String,
    /// Token address on source chain
    pub token: String,
    /// Amount in smallest unit (wei, satosh, etc.)
    pub amount: u128,
    /// ACE Chain recipient address
    pub recipient: String,
    /// Source chain block number
    pub block_number: u64,
    /// Transaction hash on source chain
    pub tx_hash: String,
    /// Timestamp when event was emitted
    pub timestamp: u64,
}

/// Relayer attestation for a deposit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositAttestation {
    pub deposit_id: String,
    pub intent_id: String,
    pub source_chain: String,
    pub token: String,
    pub amount: u128,
    pub recipient: String,
    pub block_number: u64,
    pub tx_hash: String,
    pub timestamp: u64,
    /// Relayer's Ed25519 signature over the attestation data
    pub signature: String,
    /// Relayer's public key
    pub relayer_id: String,
}

/// Signed deposit with relayer attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDeposit {
    pub attestation: DepositAttestation,
    pub nonce: u64,
}

/// Chain-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub name: String,
    pub rpc_url: String,
    /// Number of blocks to wait for finality
    pub finality_blocks: u64,
    /// Average block time in seconds
    pub block_time_secs: u64,
    /// Bridge contract address on this chain
    pub bridge_contract: Option<String>,
}

/// Monitoring checkpoint for each chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringCheckpoint {
    pub chain: String,
    pub last_scanned_block: u64,
    pub last_processed_deposit_id: Option<String>,
    pub last_update: u64,
}

/// Withdrawal execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalExecutionResult {
    pub withdrawal_id: u64,
    pub destination_chain: String,
    pub tx_hash: String,
    #[serde(default)]
    pub gateway_address: Vec<u8>,
    pub success: bool,
    pub error: Option<String>,
    pub timestamp: u64,
}
