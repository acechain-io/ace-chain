//! Genesis state initialization.

use sha2::{Digest, Sha256};

use ace_model::account::{Account, AccountId};
use ace_model::block_store::InMemoryBlockStore;
use ace_model::sharded_state::ShardedState;
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::TaggedPubkey;
use ace_runtime::types::capability::ValidatorCapabilities;
use serde::{Deserialize, Serialize};

use crate::config::DEFAULT_CHAIN_ID;

/// Native token metadata (symbol and decimals) for display and tooling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeTokenMeta {
    /// Token symbol, e.g. "ACE".
    pub symbol: String,
    /// Number of decimals for human-readable amounts (e.g. 9 => 1 token = 10^9 base units).
    pub decimals: u8,
}

impl Default for NativeTokenMeta {
    fn default() -> Self {
        Self {
            symbol: "ACE".to_string(),
            decimals: 9,
        }
    }
}

/// Minimum protocol version this binary requires in the genesis file.
///
/// Bumped to 2 for the AR-ACE tx_hash redesign (credential-independent hashing).
/// Old genesis files that omit `protocol_version` deserialize to 0 and are
/// rejected at startup, preventing mixed-version networks from forming silently.
///
/// Version history:
///   1 — original tx_hash (SHA-256 of full wire bytes including credential)
///   2 — AR-ACE tx_hash (credential-independent; raw_chain bytes included)
pub const MIN_PROTOCOL_VERSION: u32 = 2;

/// Genesis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Protocol version.  Must be >= MIN_PROTOCOL_VERSION for this binary to
    /// start.  Old genesis files that omit this field deserialize as 0 and are
    /// rejected, preventing accidental mixed-version network formation.
    #[serde(default)]
    pub protocol_version: u32,
    /// Initial accounts with balances.
    pub accounts: Vec<GenesisAccount>,
    /// Validator set definition. If empty, all accounts are treated as
    /// validators with stake=100 (backward compatible single-node default).
    #[serde(default)]
    pub validators: Vec<GenesisValidator>,
    /// Genesis timestamp in milliseconds since Unix epoch.
    /// If 0, uses current system time.
    pub genesis_time_ms: u64,
    /// Chain identifier.
    pub chain_id: u32,
    /// Native token metadata for RPC/explorer display. If absent, defaults to ACE/9.
    #[serde(default)]
    pub native_token: Option<NativeTokenMeta>,
    /// Genesis affiliate assignments used for operator fee settlement.
    #[serde(default)]
    pub affiliates: Vec<GenesisAffiliate>,
    /// Founder account identity commitment (hex). Only this account may submit
    /// OP_APPROVE_VALIDATOR transactions. If empty, validator admission is disabled.
    #[serde(default)]
    pub founder_id_com: String,
    /// Validator admission public-key policy.
    ///
    /// `devnet-derived` requires `signing_pubkey` to match the deterministic
    /// devnet ML-DSA-44 key derived from `candidate_id_com`.
    /// `founder-provided` accepts the founder-supplied signing key after normal
    /// duplicate and shape checks.
    #[serde(default = "default_validator_admission_policy")]
    pub validator_admission_policy: String,
    /// ACE DeFi relayer Ed25519 public keys approved at genesis.
    ///
    /// These keys may submit Phase A bridge deposit attestations. Production
    /// deployments should keep this explicit and rotate via a future
    /// governance-controlled relayer set transaction.
    #[serde(default)]
    pub ace_defi_approved_relayers: Vec<String>,
}

/// An account in genesis state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAccount {
    /// Identity commitment as hex string.
    pub id_com: String,
    /// Initial balance.
    pub balance: u64,
    /// Explicit Ed25519 verification key (32-byte hex).
    ///
    /// Production deployments should set this explicitly instead of relying on
    /// the backward-compatible devnet derivation.
    #[serde(default, alias = "auth_key")]
    pub auth_pubkey: Option<String>,
}

/// A validator in the genesis validator set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Identity commitment as hex string.
    pub id_com: String,
    /// Stake weight for leader election and vote weighting.
    pub stake: u64,
    /// Ed25519 signing public key (hex, 32 bytes). If empty, derived from id_com in dev mode.
    #[serde(default)]
    pub signing_pubkey: String,
    /// Static capability flags used by the minimal execution-committee path.
    #[serde(default)]
    pub capabilities: ValidatorCapabilities,
}

/// An affiliate assigned to an operator at genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAffiliate {
    /// Affiliate identity commitment as hex string.
    pub id_com: String,
    /// Operator identity commitment as hex string.
    pub operator_id_com: String,
    /// Registration timestamp in Unix ms. If 0, uses genesis_time_ms.
    #[serde(default)]
    pub registered_at_ms: u64,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        // Default: single validator with 1B native units (1 ACE if decimals=9)
        let default_id = "01".repeat(32);
        Self {
            protocol_version: MIN_PROTOCOL_VERSION,
            accounts: vec![GenesisAccount {
                id_com: default_id.clone(),
                balance: 1_000_000_000,
                auth_pubkey: None,
            }],
            validators: vec![GenesisValidator {
                id_com: default_id,
                stake: 100,
                signing_pubkey: String::new(),
                capabilities: ValidatorCapabilities::default(),
            }],
            genesis_time_ms: 0,
            chain_id: DEFAULT_CHAIN_ID,
            native_token: Some(NativeTokenMeta::default()),
            affiliates: vec![],
            founder_id_com: String::new(),
            validator_admission_policy: default_validator_admission_policy(),
            ace_defi_approved_relayers: vec![],
        }
    }
}

pub fn default_validator_admission_policy() -> String {
    "devnet-derived".to_string()
}

/// Parse optional founder identity from genesis config.
pub fn parse_founder_id_com(config: &GenesisConfig) -> anyhow::Result<Option<AccountId>> {
    if config.founder_id_com.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(config.founder_id_com.trim()).map_err(|e| {
        anyhow::anyhow!(
            "invalid founder_id_com hex '{}': {}",
            config.founder_id_com,
            e
        )
    })?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "founder_id_com must be 32 bytes, got {} for '{}'",
            bytes.len(),
            config.founder_id_com
        );
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(Some(AccountId(id)))
}

/// Initialize genesis state from configuration.
///
/// Returns the sharded state, block store, genesis hash, and resolved genesis time.
pub fn initialize_genesis(
    config: &GenesisConfig,
) -> anyhow::Result<(ShardedState, InMemoryBlockStore, [u8; 32], u64)> {
    if config.accounts.is_empty() {
        anyhow::bail!("genesis config must have at least one account");
    }

    let mut state = StateTree::new();

    for ga in &config.accounts {
        let bytes = hex::decode(&ga.id_com)
            .map_err(|e| anyhow::anyhow!("invalid genesis id_com hex '{}': {}", ga.id_com, e))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "genesis id_com must be 32 bytes, got {} for '{}'",
                bytes.len(),
                ga.id_com
            );
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        let account_id = AccountId(id);

        let auth_pubkey = match &ga.auth_pubkey {
            Some(raw) => parse_auth_pubkey(raw, &ga.id_com)?,
            None => {
                #[cfg(not(feature = "devnet"))]
                anyhow::bail!(
                    "genesis account '{}' requires an explicit auth_pubkey in non-devnet builds",
                    ga.id_com
                );
                #[cfg(feature = "devnet")]
                {
                    tracing::warn!(
                        "DEVNET: deriving auth_pubkey for '{}' from id_com — NOT SAFE FOR PRODUCTION",
                        ga.id_com
                    );
                    derive_devnet_auth_pubkey(&id)
                }
            }
        };
        let account = Account::with_auth(account_id, ga.balance, auth_pubkey);
        state.insert(account);
    }

    for relayer in &config.ace_defi_approved_relayers {
        let bytes = hex::decode(relayer.trim()).map_err(|e| {
            anyhow::anyhow!(
                "invalid ace_defi_approved_relayers pubkey '{}': {}",
                relayer,
                e
            )
        })?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "ace_defi_approved_relayers pubkey must be 32 bytes, got {} for '{}'",
                bytes.len(),
                relayer
            );
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&bytes);
        ace_defi::approve_relayer_in_state(&mut state, pubkey);
    }

    let genesis_hash = state.compute_root();
    let state = ShardedState::from_state_tree(state);
    let block_store = InMemoryBlockStore::new();

    let genesis_time_ms = if config.genesis_time_ms == 0 {
        #[cfg(feature = "devnet")]
        {
            tracing::warn!(
                "genesis_time_ms is 0; using current system time. Set explicitly for production deployments."
            );
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time before Unix epoch")
                .as_millis() as u64
        }
        #[cfg(not(feature = "devnet"))]
        {
            anyhow::bail!(
                "genesis_time_ms must be set explicitly in non-devnet builds for deterministic chain identity"
            );
        }
    } else {
        config.genesis_time_ms
    };

    Ok((state, block_store, genesis_hash, genesis_time_ms))
}

/// Derive a deterministic devnet attestation signing seed from an id_com.
///
/// seed = SHA-256("ACE-DEVNET-AUTH-SIGN" || id_com).
///
/// **NOT for production** — in production, private attestation keys stay
/// inside the wallet session and remain local to the signer.
pub fn derive_devnet_auth_signing_seed(id_com: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-DEVNET-AUTH-SIGN");
    hasher.update(id_com);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hasher.finalize());
    seed
}

/// Derive the corresponding devnet attestation public key from an id_com.
/// Uses ML-DSA-44 by default for post-quantum security.
pub fn derive_devnet_auth_pubkey(id_com: &[u8; 32]) -> TaggedPubkey {
    let seed = derive_devnet_auth_signing_seed(id_com);
    ace_runtime::crypto::attestation::auth_public_key_from_ml_dsa_44_seed(&seed)
}

/// Hash the resolved genesis configuration so persisted state can detect
/// incompatible restarts before entering the sync loop.
pub fn genesis_config_hash(config: &GenesisConfig) -> anyhow::Result<[u8; 32]> {
    let encoded = serde_json::to_vec(config)
        .map_err(|e| anyhow::anyhow!("failed to serialize genesis config: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-GENESIS-CONFIG");
    hasher.update(&encoded);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    Ok(hash)
}

fn parse_auth_pubkey(raw: &str, id_com: &str) -> anyhow::Result<TaggedPubkey> {
    let bytes = hex::decode(raw)
        .map_err(|e| anyhow::anyhow!("invalid genesis auth_pubkey hex for '{}': {}", id_com, e))?;
    match bytes.len() {
        32 => {
            let mut auth_pubkey = [0u8; 32];
            auth_pubkey.copy_from_slice(&bytes);
            if auth_pubkey == [0u8; 32] {
                anyhow::bail!("genesis auth_pubkey for '{}' must be non-zero", id_com);
            }
            Ok(TaggedPubkey::ed25519(auth_pubkey))
        }
        1312 => {
            if bytes.iter().all(|&b| b == 0) {
                anyhow::bail!("genesis auth_pubkey for '{}' must be non-zero", id_com);
            }
            Ok(TaggedPubkey::ml_dsa_44(bytes))
        }
        other => {
            anyhow::bail!(
                "genesis auth_pubkey has unsupported length {} for '{}' (expected 32 for Ed25519 or 1312 for ML-DSA-44)",
                other,
                id_com
            );
        }
    }
}

/// Derive a deterministic devnet relayer signing seed from the genesis hash.
pub fn derive_devnet_relayer_seed(genesis_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-DEVNET-RELAYER");
    hasher.update(genesis_hash);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hasher.finalize());
    seed
}

/// Derive a deterministic devnet ed25519 signing keypair seed from an id_com.
///
/// seed = SHA-256("ACE-DEVNET-SIGN" || id_com).
/// The seed is used to derive a deterministic ed25519 keypair.
pub fn derive_devnet_signing_seed(id_com: &[u8; 32]) -> [u8; 32] {
    ace_engine::admission::derive_devnet_signing_seed(id_com)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_registers_ace_defi_approved_relayers() {
        let relayer_pubkey = [0xB7; 32];
        let mut config = GenesisConfig::default();
        config.accounts[0].auth_pubkey = Some("11".repeat(32));
        config.genesis_time_ms = 1_000;
        config.ace_defi_approved_relayers = vec![hex::encode(relayer_pubkey)];

        let (state, _, _, _) = initialize_genesis(&config).unwrap();
        assert!(ace_defi::is_relayer_approved_in_state(
            state.default_shard(),
            &relayer_pubkey
        ));
    }

    #[test]
    fn genesis_rejects_malformed_ace_defi_relayer_pubkey() {
        let mut config = GenesisConfig::default();
        config.accounts[0].auth_pubkey = Some("11".repeat(32));
        config.genesis_time_ms = 1_000;
        config.ace_defi_approved_relayers = vec!["abcd".to_string()];

        match initialize_genesis(&config) {
            Ok(_) => panic!("short relayer key must fail"),
            Err(err) => assert!(err.to_string().contains("ace_defi_approved_relayers")),
        }
    }
}
