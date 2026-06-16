//! Command-line interface definition.

use clap::Parser;

/// ACE Chain Node
#[derive(Parser, Debug)]
#[command(name = "ace-node", about = "ACE Chain single-node devnet")]
pub struct Cli {
    /// Path to the node configuration file (JSON).
    #[arg(long, default_value = "ace-node.json")]
    pub config: String,

    /// JSON-RPC server port (overrides config file if set).
    #[arg(long)]
    pub rpc_port: Option<u16>,

    /// P2P listen port (overrides config file if set).
    #[arg(long)]
    pub p2p_port: Option<u16>,

    /// Additional bootstrap peer address. Repeat to pass multiple values.
    #[arg(long = "bootstrap-peer")]
    pub bootstrap_peers: Vec<String>,

    /// Prometheus metrics HTTP port (overrides config file if set).
    #[arg(long)]
    pub metrics_port: Option<u16>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Run as a block-producing validator.
    #[arg(long)]
    pub validator: bool,

    /// Validator identity commitment (hex). Overrides config file.
    #[arg(long)]
    pub validator_key: Option<String>,

    /// Ed25519 signing seed for consensus votes (32-byte hex).
    #[arg(long, env = "ACE_VALIDATOR_SIGNING_SEED")]
    pub validator_signing_seed: Option<String>,

    /// Proof mode: `production` (STARK) or `dev-mock`.
    #[arg(long)]
    pub proof_mode: Option<String>,

    /// Path to genesis JSON file (overrides config file genesis_path/genesis).
    #[arg(long)]
    pub genesis_path: Option<String>,

    /// Data directory for persistent storage (blocks, state, identity).
    /// If not set, uses in-memory storage (non-persistent).
    #[arg(long)]
    pub data_dir: Option<String>,

    /// Local prover companion binary used to generate finality certificates.
    #[arg(long)]
    pub prover_companion_bin: Option<String>,

    /// Additional argument passed to the prover companion. Repeat to pass multiple values.
    #[arg(long = "prover-companion-arg")]
    pub prover_companion_args: Vec<String>,

    /// Timeout for a prover companion request in milliseconds.
    #[arg(long)]
    pub prover_companion_timeout_ms: Option<u64>,

    /// JSON file containing private witnesses keyed by tx obj_hash hex.
    #[arg(long, env = "ACE_PROVER_WITNESS_FILE")]
    pub prover_witness_file: Option<String>,

    /// Restore node identity from a BIP-39 mnemonic phrase (env var only).
    #[arg(env = "ACE_RESTORE_MNEMONIC", hide = true)]
    pub restore_mnemonic: Option<String>,

    /// Read the node mnemonic from a local file.
    #[arg(long)]
    pub restore_mnemonic_file: Option<String>,

    /// Read the node mnemonic from stdin.
    #[arg(long, default_value_t = false)]
    pub restore_mnemonic_stdin: bool,

    /// Read the node passphrase from a local file.
    #[arg(long)]
    pub identity_passphrase_file: Option<String>,

    /// Read the node passphrase from a named environment variable.
    #[arg(long)]
    pub identity_passphrase_env: Option<String>,

    /// Read the node passphrase from stdin.
    #[arg(long, default_value_t = false)]
    pub identity_passphrase_stdin: bool,
}
