//! Network configuration.

/// P2P network configuration.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Chain identifier — used to scope gossipsub topics so that nodes
    /// on the same LAN but different chains don't interfere.
    pub chain_id: u32,
    /// Address to listen on (e.g., "/ip4/0.0.0.0/tcp/30333").
    pub listen_addr: String,
    /// Bootstrap node addresses.
    pub bootnodes: Vec<String>,
    /// Additional bootstrap peer addresses that may omit peer IDs.
    pub bootstrap_peers: Vec<String>,
    /// Human-readable node name.
    pub node_name: String,
    /// Maximum number of connected peers.
    pub max_peers: usize,
    /// Enable mDNS peer discovery. Should be false for production.
    pub enable_mdns: bool,
    /// Directory for persisting P2P state (keypair, etc.).
    pub data_dir: Option<std::path::PathBuf>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            chain_id: 0,
            listen_addr: "/ip4/0.0.0.0/tcp/30333".to_string(),
            bootnodes: Vec::new(),
            bootstrap_peers: Vec::new(),
            node_name: "ace-node".to_string(),
            max_peers: 50,
            enable_mdns: false,
            data_dir: None,
        }
    }
}

/// Validate that bootnode multiaddrs include peer IDs for authenticated connections.
///
/// Bootnode addresses must use the format `/ip4/1.2.3.4/tcp/9000/p2p/12D3KooW...`
/// so libp2p verifies the remote peer's identity during the handshake.
pub fn validate_bootnodes(bootnodes: &[String]) -> Result<(), String> {
    for addr_str in bootnodes {
        let addr: libp2p::Multiaddr = addr_str
            .parse()
            .map_err(|e| format!("invalid bootnode addr '{addr_str}': {e}"))?;
        let has_peer_id = addr
            .iter()
            .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(_)));
        if !has_peer_id {
            return Err(format!(
                "bootnode address '{addr_str}' must include /p2p/<peer-id> for authenticated bootstrap"
            ));
        }
    }
    Ok(())
}

/// Base gossipsub topic names for ACE Chain.
///
/// The actual topic strings include the chain_id to isolate networks:
/// e.g., `ace/<chain_id>/txs/1`.  Use [`topic_name`] to generate the full
/// topic string at runtime.
pub const TOPIC_TRANSACTIONS: &str = "txs";
pub const TOPIC_COMMITTEE: &str = "committee";
pub const TOPIC_BLOCKS: &str = "blocks";
pub const TOPIC_FINALITY: &str = "finality";
pub const TOPIC_SYNC: &str = "sync";
pub const TOPIC_TAKEOVER: &str = "takeover";
pub const TOPIC_IDENTITY: &str = "identity";
pub const TOPIC_PROPOSALS: &str = "proposals";
pub const TOPIC_PREVOTES: &str = "prevotes";
pub const TOPIC_PRECOMMITS: &str = "precommits";
pub const TOPIC_MEV_ACE: &str = "mev-ace";

/// Generate a chain_id-scoped topic name: `ace/{chain_id}/{base}/{version}`.
///
/// Different chain_ids produce different gossipsub topics, preventing
/// nodes on the same LAN from receiving messages from unrelated networks.
pub fn topic_name(chain_id: u32, base: &str) -> String {
    // Bump version to /2 for transactions due to wire layout change in NewTransaction.
    // Other topics stay on /1 for now, but we use a unified versioning helper.
    let version = if base == TOPIC_TRANSACTIONS { 2 } else { 1 };
    format!("ace/{chain_id}/{base}/{version}")
}
