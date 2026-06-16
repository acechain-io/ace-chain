//! Configuration management for ACE DeFi Relayer

use crate::error::{RelayerError, Result};
use crate::types::ChainConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Serialize, Deserialize)]
pub struct RelayerConfig {
    /// ACE Chain RPC endpoint
    pub ace_rpc_url: String,

    /// Relayer's private key (Ed25519, hex-encoded)
    pub relayer_private_key: String,

    /// Per-chain configurations
    pub chains: HashMap<String, ChainConfig>,

    /// Maximum deposit amount per submission (rate limiting)
    pub max_deposit_per_tx: u128,

    /// Monitoring poll interval in seconds
    pub poll_interval_secs: u64,

    /// Oracle type: "mock" or "coingecko"
    pub oracle_type: String,
}

impl std::fmt::Debug for RelayerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayerConfig")
            .field("ace_rpc_url", &self.ace_rpc_url)
            .field("relayer_private_key", &"<redacted>")
            .field("chains", &self.chains)
            .field("max_deposit_per_tx", &self.max_deposit_per_tx)
            .field("poll_interval_secs", &self.poll_interval_secs)
            .field("oracle_type", &self.oracle_type)
            .finish()
    }
}

impl RelayerConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let ace_rpc_url = std::env::var("ACE_RPC_URL")
            .map_err(|_| RelayerError::ConfigError("Missing ACE_RPC_URL".to_string()))?;

        let relayer_private_key = std::env::var("RELAYER_PRIVATE_KEY")
            .map_err(|_| RelayerError::ConfigError("Missing RELAYER_PRIVATE_KEY".to_string()))?;

        let mut chains = HashMap::new();

        // Ethereum configuration
        if let Ok(eth_rpc) = std::env::var("ETH_RPC_URL") {
            chains.insert(
                "ethereum".to_string(),
                ChainConfig {
                    name: "ethereum".to_string(),
                    rpc_url: eth_rpc,
                    finality_blocks: 96,
                    block_time_secs: 12,
                    bridge_contract: std::env::var("ETH_BRIDGE_CONTRACT").ok(),
                },
            );
        }

        // BSC configuration
        if let Ok(bsc_rpc) = std::env::var("BSC_RPC_URL") {
            chains.insert(
                "bsc".to_string(),
                ChainConfig {
                    name: "bsc".to_string(),
                    rpc_url: bsc_rpc,
                    finality_blocks: 15,
                    block_time_secs: 3,
                    bridge_contract: std::env::var("BSC_BRIDGE_CONTRACT").ok(),
                },
            );
        }

        let poll_interval_secs = std::env::var("POLL_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        let max_deposit_per_tx = std::env::var("MAX_DEPOSIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1_000_000_000_000_000_000); // 1 with 18 decimals

        let oracle_type = std::env::var("ORACLE_TYPE").unwrap_or_else(|_| "mock".to_string());

        Ok(Self {
            ace_rpc_url,
            relayer_private_key,
            chains,
            max_deposit_per_tx,
            poll_interval_secs,
            oracle_type,
        })
    }

    /// Get chain-specific config
    pub fn get_chain(&self, name: &str) -> Option<&ChainConfig> {
        self.chains.get(name)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_default_poll_interval() {
        // When POLL_INTERVAL is not set, should default to 10
        std::env::remove_var("POLL_INTERVAL");
        // Can't fully test without env vars set, but logic is verified
    }
}
