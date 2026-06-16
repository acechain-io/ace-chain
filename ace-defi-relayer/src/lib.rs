//! ACE DeFi Relayer - Cross-chain deposit and withdrawal orchestration
//!
//! This service monitors supported external chains for deposit events and
//! executes ACE-authorized withdrawals on supported external chains.
//!
//! # Architecture
//!
//! ## Ingress (External → ACE)
//! - Monitor Ethereum/BSC bridge contracts via `eth_getLogs`
//! - Wait for configured confirmation depth before accepting events
//! - Sign the canonical ACE `SignedDepositRecord`
//! - Submit the signed record to ACE Chain RPC
//!
//! ## Egress (ACE → External)
//! - Monitor ACE Chain RPC for pending withdrawal records
//! - Execute native or ERC20-compatible transfers on Ethereum/BSC
//! - Record local checkpoints so retries survive process restarts

pub mod config;
pub mod egress;
pub mod error;
pub mod ingress;
pub mod oracle;
pub mod signing;
pub mod storage;
pub mod types;

pub use config::RelayerConfig;
pub use error::{RelayerError, Result};
pub use types::*;

#[derive(Clone)]
pub struct RelayerService {
    pub config: RelayerConfig,
    pub private_key: Vec<u8>,
    pub relayer_id: String,
}

impl std::fmt::Debug for RelayerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayerService")
            .field("config", &self.config)
            .field("private_key", &"<redacted>")
            .field("relayer_id", &self.relayer_id)
            .finish()
    }
}

impl RelayerService {
    pub fn new(config: RelayerConfig, private_key: Vec<u8>) -> Self {
        Self {
            relayer_id: format!("relayer-{}", chrono::Utc::now().timestamp()),
            config,
            private_key,
        }
    }
}
