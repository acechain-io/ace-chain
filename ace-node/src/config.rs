//! Node configuration.

use serde::{Deserialize, Serialize};

use crate::genesis::GenesisConfig;

pub const DEFAULT_CHAIN_ID: u32 = 122_766;

/// Weak subjectivity checkpoint for new node sync safety.
///
/// When a new node joins the network it must trust some recent finalized state
/// to avoid being tricked into following a long-range fork.  Setting a checkpoint
/// causes the node to verify that the block at the given slot matches the
/// expected hash before accepting the chain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WeakSubjectivityCheckpoint {
    /// Block hash at the checkpoint slot (hex-encoded).
    pub block_hash: Option<String>,
    /// Slot number of the checkpoint.
    pub slot: u64,
    /// State root hash at the checkpoint (hex-encoded).
    pub state_root: Option<String>,
}

impl WeakSubjectivityCheckpoint {
    /// Returns `true` when a checkpoint has been configured (non-default).
    pub fn is_active(&self) -> bool {
        self.block_hash.is_some() || self.state_root.is_some()
    }

    /// Validate a block against this checkpoint.
    ///
    /// Returns `Ok(())` if the block at the checkpoint slot matches the
    /// configured hashes, or if we have not yet reached the checkpoint slot.
    /// Returns `Err` when the block at the checkpoint slot does not match.
    pub fn verify(
        &self,
        slot: u64,
        block_hash_hex: &str,
        state_root_hex: &str,
    ) -> Result<(), String> {
        if !self.is_active() || slot != self.slot {
            return Ok(());
        }
        if let Some(ref expected) = self.block_hash {
            if expected != block_hash_hex {
                return Err(format!(
                    "weak subjectivity checkpoint failed at slot {}: expected block_hash {}, got {}",
                    self.slot, expected, block_hash_hex,
                ));
            }
        }
        if let Some(ref expected) = self.state_root {
            if expected != state_root_hex {
                return Err(format!(
                    "weak subjectivity checkpoint failed at slot {}: expected state_root {}, got {}",
                    self.slot, expected, state_root_hex,
                ));
            }
        }
        Ok(())
    }
}

/// Node configuration loaded from file or defaults.
///
/// Best practice: use a config file (e.g. `ace-node.json`) and optionally
/// a separate `genesis.json`. If `genesis_path` is set, it overrides inline `genesis`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Chain identifier.
    pub chain_id: u32,
    /// RPC server port.
    pub rpc_port: u16,
    /// RPC server bind address. Defaults to "127.0.0.1" (loopback-only).
    /// Set to "0.0.0.0" when a reverse proxy on another host needs to reach this node.
    #[serde(default = "default_rpc_bind_addr")]
    pub rpc_bind_addr: String,
    /// P2P listen port.
    pub p2p_port: u16,
    /// Prometheus metrics HTTP port. 0 disables the metrics endpoint.
    #[serde(default)]
    pub metrics_port: u16,
    /// Bootstrap peer addresses.
    pub bootnodes: Vec<String>,
    /// Additional bootstrap peer addresses for fixed devnet topologies.
    ///
    /// These may omit `/p2p/<peer-id>` and are intended for controlled LAN
    /// benchmarks where deterministic peering matters more than authenticated
    /// bootstrap.
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    /// Portal registry endpoint for public full-node registration.
    #[serde(default)]
    pub public_node_registry_url: Option<String>,
    /// Optional explicit public P2P multiaddr. If omitted, the registry may infer
    /// the public IP from the registration request and use `p2p_port`.
    #[serde(default)]
    pub public_node_multiaddr: Option<String>,
    /// Public node role reported to the off-chain registry.
    #[serde(default = "default_public_node_role")]
    pub public_node_role: String,
    /// Non-consensus public contribution roles advertised by this node.
    ///
    /// Supported values are descriptive service roles, not consensus privileges:
    /// `rpc`, `relay`, `archive`, `light`, `indexer`.
    #[serde(default)]
    pub public_node_roles: Vec<String>,
    /// Validator/full-node RPC URLs used to pull public peers at startup/runtime.
    #[serde(default)]
    pub peer_discovery_rpc_urls: Vec<String>,
    /// How often to refresh public peers from RPC discovery endpoints.
    #[serde(default = "default_peer_discovery_interval_secs")]
    pub peer_discovery_interval_secs: u64,
    /// Maximum public peer addresses dialed per discovery round.
    #[serde(default = "default_peer_discovery_max_dial_per_round")]
    pub peer_discovery_max_dial_per_round: usize,
    /// Whether this node produces blocks.
    pub validator: bool,
    /// Validator identity (hex id_com). If None, uses first genesis account.
    #[serde(default)]
    pub validator_key: Option<String>,
    /// Ed25519 signing seed for consensus votes (32-byte hex).
    ///
    /// Required when the validator's genesis `signing_pubkey` is not the
    /// default devnet key derived from `validator_key`.
    #[serde(default)]
    pub validator_signing_seed: Option<String>,
    /// Proof mode: `production` (STARK), `dev-mock`, or `dev-stark`.
    #[serde(default = "default_proof_mode")]
    pub proof_mode: String,
    /// Path to genesis JSON file. If set and file exists, overrides inline `genesis`.
    #[serde(default)]
    pub genesis_path: Option<String>,
    /// Inline genesis config. Used when `genesis_path` is not set.
    #[serde(default)]
    pub genesis: Option<GenesisConfig>,
    /// Data directory for persistent storage.
    /// If None, uses in-memory storage.
    #[serde(default)]
    pub data_dir: Option<String>,
    /// Local prover companion binary used to request finality certificates.
    #[serde(default)]
    pub prover_companion_bin: Option<String>,
    /// Additional arguments passed to the local prover companion.
    #[serde(default)]
    pub prover_companion_args: Vec<String>,
    /// Timeout for prover companion requests in milliseconds.
    #[serde(default = "default_prover_companion_timeout_ms")]
    pub prover_companion_timeout_ms: u64,
    /// Optional JSON file containing private witnesses keyed by tx obj_hash hex.
    ///
    /// Used by validators in cryptographic proof modes to prove native ACE txs
    /// without embedding witnesses in the transaction wire format.
    #[serde(default)]
    pub prover_witness_file: Option<String>,
    /// Weak subjectivity checkpoint for sync safety.
    ///
    /// When set, the node verifies that the block at the checkpoint slot
    /// matches the configured hash before accepting the chain during sync.
    #[serde(default)]
    pub weak_subjectivity_checkpoint: Option<WeakSubjectivityCheckpoint>,
    /// Slot at which MEV-ACE fair-ordering becomes a block validity rule.
    ///
    /// All validators/full nodes on the same network must use the same value.
    /// Use a future slot when upgrading an existing chain; use 0 for fresh chains.
    #[serde(default = "default_mev_ace_activation_slot")]
    pub mev_ace_activation_slot: u64,
    /// Slot at which full MEV-ACE proposal material becomes mandatory.
    ///
    /// This is intentionally separate from `mev_ace_activation_slot`: the
    /// former enforces the full commit/open/VDF/proposal-material predicate,
    /// while the latter only enforces deterministic fair ordering.
    #[serde(default = "default_mev_ace_full_activation_slot")]
    pub mev_ace_full_activation_slot: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID,
            rpc_port: 8545,
            rpc_bind_addr: default_rpc_bind_addr(),
            p2p_port: 30333,
            metrics_port: 0,
            bootnodes: Vec::new(),
            bootstrap_peers: Vec::new(),
            public_node_registry_url: None,
            public_node_multiaddr: None,
            public_node_role: default_public_node_role(),
            public_node_roles: Vec::new(),
            peer_discovery_rpc_urls: Vec::new(),
            peer_discovery_interval_secs: default_peer_discovery_interval_secs(),
            peer_discovery_max_dial_per_round: default_peer_discovery_max_dial_per_round(),
            validator: true,
            validator_key: None,
            validator_signing_seed: None,
            proof_mode: default_proof_mode(),
            genesis_path: None,
            genesis: None,
            data_dir: None,
            prover_companion_bin: None,
            prover_companion_args: Vec::new(),
            prover_companion_timeout_ms: default_prover_companion_timeout_ms(),
            prover_witness_file: None,
            weak_subjectivity_checkpoint: None,
            mev_ace_activation_slot: default_mev_ace_activation_slot(),
            mev_ace_full_activation_slot: default_mev_ace_full_activation_slot(),
        }
    }
}

fn default_rpc_bind_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_public_node_role() -> String {
    "fullnode".to_string()
}

fn default_peer_discovery_interval_secs() -> u64 {
    60
}

fn default_peer_discovery_max_dial_per_round() -> usize {
    16
}

fn default_proof_mode() -> String {
    "production".to_string()
}

fn default_prover_companion_timeout_ms() -> u64 {
    5_000
}

fn default_mev_ace_activation_slot() -> u64 {
    u64::MAX
}

fn default_mev_ace_full_activation_slot() -> u64 {
    u64::MAX
}

/// Resolve effective genesis config: from file if genesis_path set, else inline, else default.
///
/// When `genesis_path` is explicitly configured, it must exist. Failing open
/// to inline/default genesis would silently put the node on the wrong chain.
pub fn resolve_genesis(config: &NodeConfig) -> anyhow::Result<GenesisConfig> {
    use crate::genesis::MIN_PROTOCOL_VERSION;

    let genesis = if let Some(ref path) = config.genesis_path {
        if !std::path::Path::new(path).exists() {
            anyhow::bail!("configured genesis_path '{}' does not exist", path);
        }
        let data = std::fs::read_to_string(path)?;
        serde_json::from_str::<GenesisConfig>(&data)
            .map_err(|e| anyhow::anyhow!("invalid genesis file: {}", e))?
    } else if let Some(ref g) = config.genesis {
        if !g.accounts.is_empty() {
            g.clone()
        } else {
            let mut g = GenesisConfig::default();
            g.chain_id = config.chain_id;
            g
        }
    } else {
        let mut g = GenesisConfig::default();
        g.chain_id = config.chain_id;
        g
    };

    if genesis.protocol_version < MIN_PROTOCOL_VERSION {
        anyhow::bail!(
            "genesis protocol_version {} is below the minimum required version {} — \
             this genesis file was created for an older binary. \
             Update the genesis file or use a compatible binary.",
            genesis.protocol_version,
            MIN_PROTOCOL_VERSION
        );
    }

    Ok(genesis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_genesis_errors_when_explicit_path_is_missing() {
        let config = NodeConfig {
            genesis_path: Some("/definitely/missing/genesis.json".into()),
            genesis: Some(GenesisConfig::default()),
            ..NodeConfig::default()
        };

        let err = resolve_genesis(&config).expect_err("missing explicit genesis_path must fail");
        assert!(err.to_string().contains("does not exist"));
    }
}
