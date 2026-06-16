//! Node orchestration — wires together all subsystems.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use ace_engine::receipt::StateChange as EngineStateChange;
use ace_rpc::eth_rpc::{maybe_publish_pending_evm_tx, publish_eth_block_events, EthEventHub};
use ace_rpc::methods::TxReceiptStore;
use ace_rpc::raw_tx::evm_tx_hash;
use ace_rpc::types::{EthLog, RpcStateChange, RpcTransactionReceipt};
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};
use tracing::{info, warn};

use ace_consensus::engine::ConsensusEngine;
use ace_consensus::leader_schedule::LeaderSchedule;
use ace_consensus::mev_ace::{
    ace_alg_to_mev_alg, fair_order_transactions, is_fair_ordered, omission_proof_to_core,
    proposal_material_to_signed, verify_proposal_material_for_transactions, AceDevVdf,
    AceMevHasher, AceMevSignatureRegistry, MevAceValidatorSetSnapshot,
};
use ace_consensus::poh::PohChain;
use ace_consensus::slot_clock::SlotClock;
use ace_consensus::validator_set::{Validator, ValidatorSet};
use ace_mempool::pool::{Mempool, MempoolConfig, ParkedTxReason};
use ace_model::account::{Account, AccountId};
use ace_model::block_store::BlockStore;
use ace_model::rocks_state_db::ChainIdentityMetadata;
use ace_p2p::config::NetworkConfig;
use ace_p2p::messages::{
    BlockSyncRecord, BlockSyncRequest, BlockSyncResponse, CompactNetworkProposal,
    MevAceNetworkMessage, NetworkMessage, NetworkPrecommit, NetworkPrevote, NetworkProposal,
    TxFetchFailure, TxFetchRequest,
};
use ace_p2p::service::{NetworkService, SyncRequestCommand};
use ace_p2p::state_sync::{FAST_SYNC_BATCH_LIMIT, STATE_SYNC_THRESHOLD};
use ace_p2p::TakeoverManager;
use ace_rpc::methods::RpcState;
use ace_rpc::server::RpcServer;
use ace_runtime::consensus::finality::FinalityAction;
use ace_runtime::crypto::attestation::verify_credential;
use ace_runtime::crypto::proof::ProofVerifier;
use ace_runtime::crypto::sig_algo::{self, LocalSigningKey, SignatureAlgorithm, TaggedSignature};
use ace_runtime::crypto::TaggedPubkey;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::block::{
    decode_mev_ace_omission_evidence_payload, encode_mev_ace_omission_evidence_payload,
    is_mev_ace_omission_evidence_payload, mev_ace_omission_evidence_tx_idcom, Block, BlockBuilder,
    BlockHeader, MevAceCertifiedCommitment, MevAceCertifiedOpening, MevAceCommitReceipt,
    MevAceCommitment, MevAceOmissionProof, MevAceOpenReceipt, MevAceOpening,
    MevAceProposalMaterial,
};
use ace_runtime::types::capability::ValidatorCapabilities;
use ace_runtime::types::finality::{FinalityCertificate, FinalityState};
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use mev_ace_core::messages::{
    CommitReceipt as CoreCommitReceipt, Commitment as CoreCommitment,
    OpenReceipt as CoreOpenReceipt, Opening as CoreOpening,
};
use mev_ace_core::omission::verify_omission_proof;
use mev_ace_core::state::{
    CertifiedCommitment as CoreCertifiedCommitment, CertifiedOpening as CoreCertifiedOpening,
    SlotState,
};
use mev_ace_core::traits::SlotPhase;
use mev_ace_core::traits::{BondedIdentityStore, IdentityRecord};
use mev_ace_core::types::{
    commit_signing_input, open_signing_input, Hash32, Idcom, Nonce, Signature, Slot,
    VerificationKey,
};
use zeroize::Zeroizing;

const BLOCK_SYNC_RESPONSE_TARGET_BYTES: usize = 16 * 1024 * 1024;

#[cfg(feature = "devnet")]
use ace_runtime::crypto::proof::MockProver;
#[cfg(feature = "stark")]
use ace_runtime::crypto::proof::StarkVerifierOnly;

use crate::capability::{sign_local_approval, verify_certificate, ApprovalCollector};
use crate::cli::Cli;
use crate::companion_protocol::{ProverCompanionRequest, ProverCompanionResponse};
use crate::config::{resolve_genesis, NodeConfig, WeakSubjectivityCheckpoint};
use crate::genesis::{
    derive_devnet_signing_seed, genesis_config_hash, initialize_genesis, GenesisConfig,
};
use crate::governance::{RuntimeGovernance, TREASURY_ACCOUNT};
use crate::proof_material::{material_target_path, ProofMode, DEFAULT_PROVER_WITNESS_FILE};
use crate::resource_monitor::ResourceMonitor;

/// The ACE Chain node.
pub struct Node {
    config: NodeConfig,
    genesis: GenesisConfig,
    local_identity: Option<Arc<ace_identity::LoadedIdentity>>,
}

const LOCAL_IDENTITY_FILE: &str = "identity.json";
const BLOCK_SYNC_BATCH_LIMIT: u16 = 128;
const SYNC_REQUEST_RETRY_INTERVAL_SLOTS: u64 = 2;

const TX_RECEIPT_SNAPSHOT_FILE: &str = "tx_receipts.bin";
const LEGACY_DUMMY_WITNESS_ALG_ID: u64 = u64::MAX;
const DEFAULT_TX_RECEIPT_RETENTION: usize = 20_000;
const DEFAULT_ETH_EVENT_RETENTION: usize = 4_096;
const MAX_BUFFERED_FUTURE_ROUNDS: u32 = 64;
const CREDENTIAL_PREFETCH_MAX_PENDING: usize = 4_096;
const CREDENTIAL_PREFETCH_MAX_ATTEMPTS: u8 = 4;
const CREDENTIAL_PREFETCH_BATCH_PER_PEER: usize = 64;
const CREDENTIAL_PREFETCH_BASE_RETRY_MS: u64 = 100;
const CREDENTIAL_PREFETCH_DEADLINE_MS: u64 = 1_500;
use ace_runtime::config::COMPACT_TX_FETCH_MAX_RETRIES;

/// Maximum number of heights a network-observed slot can be ahead of
/// our consensus engine height before being ignored.  Prevents both
/// foreign-network messages (discovered via mDNS) and corrupted values
/// from poisoning `highest_observed_block_slot` and triggering a
/// spurious fast-sync stall.
///
/// We compare against the consensus height (block number) rather than
/// `slot_clock.current_slot()` (wall-clock time / 400ms) because the
/// wall-clock slot advances much faster than block production, making
/// the old check ineffective (e.g. at 19 min: clock_slot ≈ 2850 but
/// chain height ≈ 1189).
///
/// Trade-off: a small window (e.g. 10) is robust to a single poisoned
/// observation but prevents a node that joins late (or restarts after a
/// long downtime) from ever seeing how far behind it is — every gossiped
/// proposal is dropped as "implausible," so `highest_observed_block_slot`
/// stays at zero, `should_defer_leader_production` returns false, and the
/// node tries to propose at its stale local height forever instead of
/// triggering fast-sync.  This was the deep root cause of the cross-host
/// "node-2 stranded at genesis" stall.  Poisoning is bounded in practice
/// because `highest_observed_block_slot` is capped to the local height
/// every time a block commits (see the `min(new_height)` callsite), so a
/// burst of fake observations only delays proposing for one sync cycle —
/// it cannot cause a permanent stall.  We pick 1_000_000 (≈ 110 hours of
/// 400 ms slots) as a comfortable upper bound for any realistic catch-up.
///
/// Known DoS surface: a single malicious peer can send a Prevote/Precommit
/// with slot = local_height + 1_000_000, pushing highest_observed_block_slot
/// high enough that the node defers leader production for one sync cycle after
/// every commit.  This is a single-cycle stall (bounded by the next commit's
/// `min(new_height)` clamp) and does not cause chain halt, but it can reduce
/// effective TPS under sustained attack.  Mitigating requires authenticating
/// slot claims, which is tracked separately.
const SLOT_PLAUSIBILITY_WINDOW: u64 = 1_000_000;

/// Persist state to RocksDB every N hard-finalized slots for crash recovery.
const PERIODIC_PERSIST_INTERVAL: u64 = 100;

/// Tracks the last slot at which periodic persistence was performed.
static LAST_PERSISTED_SLOT: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct PersistenceHandles {
    #[cfg(feature = "persistence")]
    state_db: Option<Arc<RwLock<ace_model::RocksDbStateDB>>>,
    #[cfg(feature = "persistence")]
    pending_snapshot: Option<Arc<Mutex<Option<ace_model::sharded_state::ShardedState>>>>,
    #[cfg(feature = "persistence")]
    persist_task_running: Option<Arc<AtomicBool>>,
}

impl PersistenceHandles {
    fn disabled() -> Self {
        Self::default()
    }

    #[cfg(feature = "persistence")]
    fn enabled(state_db: ace_model::RocksDbStateDB) -> Self {
        Self {
            state_db: Some(Arc::new(RwLock::new(state_db))),
            pending_snapshot: Some(Arc::new(Mutex::new(None))),
            persist_task_running: Some(Arc::new(AtomicBool::new(false))),
        }
    }

    fn persist_tree(
        &self,
        state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
    ) -> anyhow::Result<()> {
        #[cfg(feature = "persistence")]
        if let Some(state_db) = &self.state_db {
            let state_guard = state.read();
            state_db
                .write()
                .persist_sharded_state(&state_guard, genesis_hash, genesis_time_ms)
                .map_err(|e| anyhow::anyhow!("failed to persist state: {e}"))?;
        }

        let _ = (state, genesis_hash, genesis_time_ms);
        Ok(())
    }

    /// Non-blocking persistence: clone state snapshot under a brief read lock,
    /// then write to RocksDB in a background task.  The consensus loop is only
    /// blocked for the clone (~µs) instead of the full DB write (~ms).
    fn persist_tree_async(
        &self,
        state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
    ) {
        #[cfg(feature = "persistence")]
        if let (Some(state_db), Some(pending_snapshot), Some(persist_task_running)) = (
            &self.state_db,
            &self.pending_snapshot,
            &self.persist_task_running,
        ) {
            *pending_snapshot.lock() = Some(state.read().clone());

            if persist_task_running
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let db = Arc::clone(state_db);
                let pending_snapshot = Arc::clone(pending_snapshot);
                let persist_task_running = Arc::clone(persist_task_running);
                tokio::spawn(async move {
                    loop {
                        let Some(snapshot) = pending_snapshot.lock().take() else {
                            persist_task_running.store(false, Ordering::Release);
                            if pending_snapshot.lock().is_some()
                                && persist_task_running
                                    .compare_exchange(
                                        false,
                                        true,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok()
                            {
                                continue;
                            }
                            break;
                        };

                        let db2 = Arc::clone(&db);
                        match tokio::task::spawn_blocking(move || {
                            db2.write().persist_sharded_state(
                                &snapshot,
                                genesis_hash,
                                genesis_time_ms,
                            )
                        })
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => tracing::warn!(%e, "Background state persistence failed"),
                            Err(e) => tracing::error!(%e, "State persistence task panicked"),
                        }
                    }
                });
            }
        }
        let _ = (state, genesis_hash, genesis_time_ms);
    }
}

fn local_identity_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join(LOCAL_IDENTITY_FILE)
}

fn persist_local_identity_profile(
    path: &Path,
    profile: &ace_identity::IdentityPublicProfile,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(profile)?;
    std::fs::write(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn load_local_identity_profile(
    path: &Path,
) -> anyhow::Result<Option<ace_identity::IdentityPublicProfile>> {
    if !path.exists() {
        return Ok(None);
    }

    let data = std::fs::read(path)?;
    let profile = serde_json::from_slice(&data)?;
    Ok(Some(profile))
}

fn trim_secret_input(mut value: String) -> String {
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    value
}

fn read_secret_file(path: &str, label: &str) -> anyhow::Result<Zeroizing<String>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read {label} file '{}': {e}", path))?;
    let trimmed = trim_secret_input(contents);
    if trimmed.is_empty() {
        anyhow::bail!("{label} file '{}' is empty", path);
    }
    Ok(Zeroizing::new(trimmed))
}

fn read_secret_stdin(label: &str, hide_input: bool) -> anyhow::Result<Zeroizing<String>> {
    let secret = if io::stdin().is_terminal() {
        if hide_input {
            rpassword::prompt_password(format!("Enter {label}: "))?
        } else {
            let mut line = String::new();
            eprint!("Enter {label}: ");
            io::stdin().read_line(&mut line)?;
            line
        }
    } else {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        buffer
    };

    let trimmed = trim_secret_input(secret);
    if trimmed.is_empty() {
        anyhow::bail!("{label} read from stdin is empty");
    }

    Ok(Zeroizing::new(trimmed))
}

fn resolve_restore_mnemonic(cli: &Cli) -> anyhow::Result<Option<Zeroizing<String>>> {
    let mut sources = 0usize;
    if cli.restore_mnemonic.is_some() {
        sources += 1;
    }
    if cli.restore_mnemonic_file.is_some() {
        sources += 1;
    }
    if cli.restore_mnemonic_stdin {
        sources += 1;
    }
    if sources > 1 {
        anyhow::bail!(
            "use only one mnemonic source: --restore-mnemonic, --restore-mnemonic-file, or --restore-mnemonic-stdin"
        );
    }

    if let Some(mnemonic) = &cli.restore_mnemonic {
        std::env::remove_var("ACE_RESTORE_MNEMONIC");
        let trimmed = mnemonic.trim().to_string();
        if trimmed.is_empty() {
            anyhow::bail!("--restore-mnemonic cannot be empty");
        }
        return Ok(Some(Zeroizing::new(trimmed)));
    }
    if let Some(path) = &cli.restore_mnemonic_file {
        return read_secret_file(path, "mnemonic").map(Some);
    }
    if cli.restore_mnemonic_stdin {
        return read_secret_stdin("mnemonic", false).map(Some);
    }

    Ok(None)
}

fn resolve_identity_passphrase(cli: &Cli) -> anyhow::Result<Option<Zeroizing<String>>> {
    let env_name = cli
        .identity_passphrase_env
        .clone()
        .unwrap_or_else(|| "ACE_IDENTITY_PASSPHRASE".to_string());
    let env_value = std::env::var(&env_name)
        .ok()
        .map(trim_secret_input)
        .filter(|value| !value.is_empty());

    let mut sources = 0usize;
    if env_value.is_some() {
        sources += 1;
    }
    if cli.identity_passphrase_file.is_some() {
        sources += 1;
    }
    if cli.identity_passphrase_stdin {
        sources += 1;
    }
    if sources > 1 {
        anyhow::bail!(
            "use only one passphrase source: environment variable, --identity-passphrase-file, or --identity-passphrase-stdin"
        );
    }

    if let Some(passphrase) = env_value {
        std::env::remove_var(&env_name);
        return Ok(Some(Zeroizing::new(passphrase)));
    }
    if let Some(path) = &cli.identity_passphrase_file {
        return read_secret_file(path, "passphrase").map(Some);
    }
    if cli.identity_passphrase_stdin {
        return read_secret_stdin("passphrase", true).map(Some);
    }

    Ok(None)
}

fn resolve_loaded_identity(
    cli: &Cli,
    data_dir: Option<&str>,
    chain_id: u32,
) -> anyhow::Result<(
    Option<Arc<ace_identity::LoadedIdentity>>,
    Option<ace_identity::IdentityPublicProfile>,
)> {
    let mnemonic = resolve_restore_mnemonic(cli)?;
    let passphrase = resolve_identity_passphrase(cli)?;

    if mnemonic.is_none() && passphrase.is_some() {
        anyhow::bail!("a passphrase was provided, but no mnemonic source was configured");
    }

    if let Some(mnemonic) = mnemonic {
        let Some(passphrase) = passphrase else {
            anyhow::bail!(
                "loading a node identity requires a passphrase via ACE_IDENTITY_PASSPHRASE, --identity-passphrase-file, or --identity-passphrase-stdin"
            );
        };

        let loaded = Arc::new(
            ace_identity::LoadedIdentity::open(&mnemonic, &passphrase, None, chain_id, b"")
                .map_err(|e| anyhow::anyhow!("failed to load ACE-GF identity: {e}"))?,
        );
        let profile = loaded.public_profile().clone();
        if let Some(dir) = data_dir {
            persist_local_identity_profile(&local_identity_path(dir), &profile)?;
        }
        return Ok((Some(loaded), Some(profile)));
    }

    if let Some(dir) = data_dir {
        let profile = load_local_identity_profile(&local_identity_path(dir))?;
        return Ok((None, profile));
    }

    Ok((None, None))
}

fn apply_local_identity_to_config(
    config: &mut NodeConfig,
    profile: &ace_identity::IdentityPublicProfile,
) -> anyhow::Result<()> {
    let restored_id = hex::encode(profile.chain.idcom);
    if let Some(existing) = &config.validator_key {
        if *existing != restored_id {
            anyhow::bail!(
                "restored identity {} does not match configured validator_key {}",
                restored_id,
                existing
            );
        }
    } else {
        config.validator_key = Some(restored_id);
    }

    Ok(())
}

fn validate_production_genesis(genesis: &GenesisConfig) -> anyhow::Result<()> {
    if genesis.chain_id == 0 {
        anyhow::bail!(
            "proof_mode=production requires a non-zero genesis chain_id (use a distinct chain_id for mainnet/testnet)"
        );
    }
    if is_reserved_public_chain_id(genesis.chain_id) {
        anyhow::bail!(
            "proof_mode=production refuses genesis chain_id {} because it collides with a public network; choose an ACE-specific chain_id",
            genesis.chain_id
        );
    }
    if genesis.validators.is_empty() {
        anyhow::bail!(
            "proof_mode=production requires an explicit genesis validator set with signing_pubkey values"
        );
    }

    for account in &genesis.accounts {
        let Some(auth_pubkey) = &account.auth_pubkey else {
            anyhow::bail!(
                "proof_mode=production requires explicit auth_pubkey for genesis account {}",
                account.id_com
            );
        };

        let auth_bytes = hex::decode(auth_pubkey).map_err(|e| {
            anyhow::anyhow!(
                "invalid production auth_pubkey hex for genesis account {}: {}",
                account.id_com,
                e
            )
        })?;
        let valid_len = auth_bytes.len() == 32 || auth_bytes.len() == 1312;
        if !valid_len || auth_bytes.iter().all(|b| *b == 0) {
            anyhow::bail!(
                "production auth_pubkey for genesis account {} must be a non-zero Ed25519 (32B) or ML-DSA-44 (1312B) hex value",
                account.id_com
            );
        }
    }

    let mut seen_validator_ids = std::collections::BTreeSet::new();
    let mut seen_signing_pubkeys = std::collections::BTreeSet::new();
    for validator in &genesis.validators {
        if !seen_validator_ids.insert(validator.id_com.clone()) {
            anyhow::bail!(
                "duplicate validator id_com in production genesis: {}",
                validator.id_com
            );
        }
        if validator.signing_pubkey.trim().is_empty() {
            anyhow::bail!(
                "proof_mode=production requires explicit signing_pubkey for validator {}",
                validator.id_com
            );
        }
        let pubkey_bytes = hex::decode(&validator.signing_pubkey).map_err(|e| {
            anyhow::anyhow!(
                "invalid validator signing_pubkey hex for {}: {}",
                validator.id_com,
                e
            )
        })?;
        if pubkey_bytes.len() != 32 || pubkey_bytes.iter().all(|b| *b == 0) {
            anyhow::bail!(
                "validator signing_pubkey for {} must be a non-zero 32-byte hex value",
                validator.id_com
            );
        }
        if !seen_signing_pubkeys.insert(validator.signing_pubkey.clone()) {
            anyhow::bail!(
                "duplicate validator signing_pubkey in production genesis: {}",
                validator.signing_pubkey
            );
        }
    }
    Ok(())
}

/// Chain IDs reserved by major public networks.
///
/// Using one of these as our chain_id would cause EVM-compatible wallets
/// to confuse ACE transactions with mainnet/testnet transactions,
/// potentially leading to replay attacks or user confusion.
///
/// This list is checked at startup when using production proof modes
/// to prevent accidental deployment with a conflicting chain_id.
const RESERVED_PUBLIC_CHAIN_IDS: &[u32] = &[
    1,        // Ethereum Mainnet
    5,        // Goerli (deprecated but still recognized)
    10,       // Optimism
    56,       // BSC
    100,      // Gnosis (xDai)
    137,      // Polygon
    250,      // Fantom
    324,      // zkSync Era
    420,      // Optimism Goerli
    42161,    // Arbitrum One
    43114,    // Avalanche C-Chain
    59144,    // Linea
    8453,     // Base
    11155111, // Sepolia
    534352,   // Scroll
];

fn is_reserved_public_chain_id(chain_id: u32) -> bool {
    RESERVED_PUBLIC_CHAIN_IDS.contains(&chain_id)
}

fn validate_runtime_chain_id(chain_id: u32, proof_mode: ProofMode) -> anyhow::Result<()> {
    if chain_id == 0 {
        anyhow::bail!("node chain_id must be non-zero");
    }
    if proof_mode.requires_production_genesis() && is_reserved_public_chain_id(chain_id) {
        anyhow::bail!(
            "proof_mode={} refuses node chain_id {} because it collides with a public network; choose an ACE-specific chain_id",
            proof_mode.as_str(),
            chain_id
        );
    }
    Ok(())
}

fn validate_chain_id_consistency(
    config_chain_id: u32,
    genesis: &GenesisConfig,
) -> anyhow::Result<()> {
    if genesis.chain_id != 0 && genesis.chain_id != config_chain_id {
        anyhow::bail!(
            "config chain_id {} does not match genesis chain_id {}",
            config_chain_id,
            genesis.chain_id
        );
    }
    Ok(())
}

fn validate_multinode_genesis_time(
    config: &NodeConfig,
    genesis: &GenesisConfig,
) -> anyhow::Result<()> {
    let multi_node = genesis.validators.len() > 1
        || !config.bootnodes.is_empty()
        || !config.bootstrap_peers.is_empty();
    if multi_node && genesis.genesis_time_ms == 0 {
        anyhow::bail!(
            "multi-node devnet requires an explicit shared genesis_time_ms; do not use 0 because each node will otherwise anchor slot 0 to its own local startup time"
        );
    }
    Ok(())
}

fn ensure_mock_precompile_compatible(proof_mode: ProofMode) -> anyhow::Result<()> {
    #[cfg(feature = "mock-precompile-n-vm")]
    {
        if proof_mode != ProofMode::DevMock {
            anyhow::bail!(
                "ace-node built with mock-precompile-n-vm can only run with proof_mode=dev-mock; rebuild without mock-precompile-n-vm for cryptographic or production modes"
            );
        }
    }

    let _ = proof_mode;
    Ok(())
}

fn ensure_mev_ace_full_vdf_compatible(
    proof_mode: ProofMode,
    full_activation_slot: u64,
) -> anyhow::Result<()> {
    if proof_mode == ProofMode::Production && full_activation_slot != u64::MAX {
        anyhow::bail!(
            "mev_ace_full_activation_slot requires a production VDF in proof_mode=production; \
             current binary only wires AceDevVdf for devnet/testnet"
        );
    }
    Ok(())
}

fn parse_config_proof_mode(raw: &str) -> anyhow::Result<ProofMode> {
    ProofMode::parse(raw).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid proof_mode '{}', expected 'production', 'dev-mock', or 'dev-stark'",
            raw
        )
    })
}

fn canonical_tip_hash<B: BlockStore>(block_store: &B, genesis_hash: [u8; 32]) -> [u8; 32] {
    let latest = block_store.latest_slot();
    for slot in (0..=latest).rev() {
        if let Some(block) = block_store.get_block_by_slot(slot) {
            return block.hash();
        }
    }

    genesis_hash
}

async fn wait_for_startup_peers(
    peer_count: &Arc<AtomicU64>,
    required_peers: usize,
    nag_interval: std::time::Duration,
    shutdown_rx: &mut mpsc::Receiver<()>,
) -> anyhow::Result<()> {
    if required_peers == 0 {
        return Ok(());
    }

    // We wait indefinitely until the local libp2p mesh has at least
    // `required_peers` connections.  This used to give up after a fixed
    // timeout and "continue anyway" with a partial mesh, which on a 3-node
    // devnet led to:
    //   - node-3 connected to node-1 and node-2 (sees 2 peers, proceeds)
    //   - node-1 connected only to node-3 (times out at connected=1, proceeds)
    //   - node-2 connected only to node-3 (times out at connected=1, proceeds)
    //   - the 3 enter consensus with mismatched local round counters and
    //     immediately fork at height=1; node-3 misses the height=1 commit,
    //     and even with the Bug-3 sync fix it cannot recover because the
    //     missing peer-to-peer connection never re-establishes itself.
    // Waiting indefinitely is the right behaviour: we'd rather block at
    // startup until the mesh is healthy than enter consensus with a
    // structurally broken peer set.  A noisy WARN every `nag_interval`
    // tells operators something is wrong without exiting.
    let started_at = tokio::time::Instant::now();
    let mut next_nag = started_at + nag_interval;
    loop {
        let connected = peer_count.load(Ordering::Relaxed) as usize;
        if connected >= required_peers {
            info!(
                connected,
                required_peers,
                waited_ms = started_at.elapsed().as_millis(),
                "P2P startup peer target reached"
            );
            return Ok(());
        }

        tokio::select! {
            _ = shutdown_rx.recv() => {
                anyhow::bail!("shutdown while waiting for startup peers");
            }
            _ = tokio::time::sleep_until(next_nag) => {
                warn!(
                    connected,
                    required_peers,
                    waited_ms = started_at.elapsed().as_millis(),
                    "Still waiting for startup peers (will keep trying — refusing to enter consensus with a partial P2P mesh)"
                );
                next_nag = tokio::time::Instant::now() + nag_interval;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
        }
    }
}

fn canonical_tip_slot<B: BlockStore>(block_store: &B) -> Option<u64> {
    let latest = block_store.latest_slot();
    (0..=latest)
        .rev()
        .find(|&slot| block_store.get_block_by_slot(slot).is_some())
}

fn slot_has_progress<B: BlockStore>(block_store: &B, slot: u64) -> bool {
    block_store.get_block_by_slot(slot).is_some()
        || block_store
            .get_finality_state(slot)
            .is_some_and(|state| state.is_confirmed())
}

fn latest_progress_slot_up_to<B: BlockStore>(block_store: &B, upper_bound: u64) -> Option<u64> {
    (0..=upper_bound)
        .rev()
        .find(|&slot| slot_has_progress(block_store, slot))
}

fn slot_is_resolved_for_production<B: BlockStore>(
    block_store: &B,
    _engine: &ConsensusEngine,
    slot: u64,
) -> bool {
    // A slot is resolved if it has a real block or if finality has been confirmed.
    // Skipped slots (no block, no finality) are also considered resolved —
    // the next leader simply builds on the most recent real block.
    block_store.get_block_by_slot(slot).is_some()
        || block_store
            .get_finality_state(slot)
            .is_some_and(|state| state.is_confirmed())
}

fn latest_resolved_slot_up_to<B: BlockStore>(
    block_store: &B,
    engine: &ConsensusEngine,
    upper_bound: u64,
) -> Option<u64> {
    (0..=upper_bound)
        .rev()
        .find(|&slot| slot_is_resolved_for_production(block_store, engine, slot))
}

fn should_defer_leader_production<B: BlockStore>(
    highest_observed_block_slot: u64,
    block_store: &B,
    current_consensus_height: u64,
) -> bool {
    // If our consensus engine is already working on (or past) the highest
    // slot observed from the network, every validator is at the same point
    // — deferring production would deadlock the chain because no node
    // would ever propose.  This fixes a liveness bug where
    // highest_observed_block_slot gets set from Prevote/Precommit messages
    // whose height field reflects the in-progress consensus round, not a
    // committed block.
    if highest_observed_block_slot <= current_consensus_height {
        return false;
    }

    let tip_slot = latest_progress_slot_up_to(
        block_store,
        highest_observed_block_slot.max(block_store.latest_slot()),
    )
    .unwrap_or(0);
    // Allow a small buffer of 3 slots to account for normal network propagation delay.
    // If we are more than 3 slots behind the highest block we've seen on the network,
    // we should defer our own production and focus on syncing.
    const SYNC_LAG_THRESHOLD: u64 = 3;
    highest_observed_block_slot > tip_slot.saturating_add(SYNC_LAG_THRESHOLD)
}

fn observed_block_slot_from_network_message(msg: &NetworkMessage) -> Option<u64> {
    match msg {
        NetworkMessage::Proposal(proposal) => Some(proposal.height),
        NetworkMessage::CompactProposal(cp) => Some(cp.height),
        NetworkMessage::Prevote(prevote) => Some(prevote.height),
        NetworkMessage::Precommit(precommit) => Some(precommit.height),
        NetworkMessage::CommitCertificate(cert) => Some(cert.height),
        NetworkMessage::FinalityCert(cert) => Some(cert.slot),
        NetworkMessage::NewBlock(block) => Some(block.header.slot),
        NetworkMessage::BlockSyncResponse(response) => Some(response.latest_slot),
        _ => None,
    }
}

fn maybe_request_validator_block_sync<B: BlockStore>(
    highest_observed_block_slot: u64,
    engine: &ConsensusEngine,
    block_store: &Arc<RwLock<B>>,
    net_outbound_tx: &mpsc::Sender<NetworkMessage>,
) -> bool {
    let store = block_store.read();
    let latest_resolved = latest_resolved_slot_up_to(
        &*store,
        engine,
        highest_observed_block_slot.max(store.latest_slot()),
    )
    .unwrap_or(0);
    if highest_observed_block_slot <= latest_resolved.saturating_add(2) {
        return false;
    }

    let start_slot = latest_resolved.saturating_add(1);
    let gap = highest_observed_block_slot.saturating_sub(latest_resolved);
    let batch_limit = if gap > STATE_SYNC_THRESHOLD as u64 {
        tracing::info!(
            current = latest_resolved,
            network = highest_observed_block_slot,
            gap,
            "Validator entering fast-sync mode"
        );
        FAST_SYNC_BATCH_LIMIT
    } else {
        BLOCK_SYNC_BATCH_LIMIT
    };
    send_block_sync_request(net_outbound_tx, start_slot, batch_limit);
    true
}

fn maybe_advance_engine_to_synced_block(engine: &mut ConsensusEngine, block_slot: u64) -> bool {
    let next_height = block_slot.saturating_add(1);
    if engine.current_height() >= next_height {
        return false;
    }

    engine.advance_height(next_height);
    engine
        .round_timer
        .start_step(0, ace_consensus::RoundStep::Propose);
    true
}

fn validator_sets_match(a: &ValidatorSet, b: &ValidatorSet) -> bool {
    a.validators()
        .iter()
        .map(|validator| (validator.id_com, validator.stake, validator.index))
        .eq(b
            .validators()
            .iter()
            .map(|validator| (validator.id_com, validator.stake, validator.index)))
}

fn compare_voted_hash_preference(
    engine: &ConsensusEngine,
    slot: u64,
    local_hash: [u8; 32],
    incoming_hash: [u8; 32],
) -> std::cmp::Ordering {
    if let Some(quorum_hash) = engine.quorum_block_hash(slot) {
        if incoming_hash == quorum_hash && local_hash != quorum_hash {
            return std::cmp::Ordering::Greater;
        }
        if local_hash == quorum_hash && incoming_hash != quorum_hash {
            return std::cmp::Ordering::Less;
        }
    }

    let local_stake = engine.voted_stake_for(slot, &local_hash);
    let incoming_stake = engine.voted_stake_for(slot, &incoming_hash);
    incoming_stake
        .cmp(&local_stake)
        .then_with(|| local_hash.cmp(&incoming_hash))
}

#[cfg(feature = "persistence")]
fn fallback_genesis_time_ms<B: BlockStore>(genesis: &GenesisConfig, block_store: &B) -> u64 {
    let latest = block_store.latest_slot();
    for slot in (0..=latest).rev() {
        if let Some(block) = block_store.get_block_by_slot(slot) {
            return block
                .header
                .timestamp
                .saturating_sub(slot * ace_runtime::config::SLOT_DURATION_MS);
        }
    }

    if genesis.genesis_time_ms != 0 {
        genesis.genesis_time_ms
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_millis() as u64
    }
}

#[cfg(feature = "persistence")]
fn ensure_persistent_chain_compatibility(
    data_dir: &str,
    persisted_identity: ChainIdentityMetadata,
    current_genesis: &GenesisConfig,
) -> anyhow::Result<[u8; 32]> {
    let current_genesis_config_hash = genesis_config_hash(current_genesis)?;
    if let Some(found_hash) = persisted_identity.genesis_config_hash {
        if found_hash != current_genesis_config_hash {
            anyhow::bail!(
                "persistent chain state in '{}' was created with a different genesis config; clean the data_dir or restore the matching genesis file",
                data_dir
            );
        }
        return Ok(current_genesis_config_hash);
    }

    let (_, _, expected_genesis_hash, expected_genesis_time_ms) =
        initialize_genesis(current_genesis).map_err(|e| {
            anyhow::anyhow!("failed to derive current genesis compatibility data: {e}")
        })?;
    if persisted_identity.genesis_hash != expected_genesis_hash {
        anyhow::bail!(
            "persistent chain state in '{}' was created from a different genesis state; clean the data_dir or restore the matching genesis file",
            data_dir
        );
    }
    if current_genesis.genesis_time_ms != 0
        && persisted_identity.genesis_time_ms != expected_genesis_time_ms
    {
        anyhow::bail!(
            "persistent chain state in '{}' uses genesis_time_ms={} but the current config expects {}; clean the data_dir or restore the matching genesis file",
            data_dir,
            persisted_identity.genesis_time_ms,
            expected_genesis_time_ms
        );
    }
    Ok(current_genesis_config_hash)
}

impl Node {
    /// Create a node from CLI arguments.
    pub fn from_cli(cli: Cli) -> anyhow::Result<Self> {
        // Try to load config file; fall back to defaults if it doesn't exist.
        let mut config = if std::path::Path::new(&cli.config).exists() {
            let data = std::fs::read_to_string(&cli.config)?;
            serde_json::from_str::<NodeConfig>(&data)?
        } else {
            NodeConfig::default()
        };

        // CLI flags override file values only when explicitly set
        if let Some(port) = cli.rpc_port {
            config.rpc_port = port;
        }
        if let Some(port) = cli.p2p_port {
            config.p2p_port = port;
        }
        if let Some(port) = cli.metrics_port {
            config.metrics_port = port;
        }
        if cli.validator {
            config.validator = true;
        }
        if let Some(ref key) = cli.validator_key {
            config.validator_key = Some(key.clone());
        }
        if let Some(ref seed) = cli.validator_signing_seed {
            config.validator_signing_seed = Some(seed.clone());
        }
        if let Some(ref mode) = cli.proof_mode {
            config.proof_mode = mode.clone();
        }
        if let Some(ref path) = cli.genesis_path {
            config.genesis_path = Some(path.clone());
        }
        if !cli.bootstrap_peers.is_empty() {
            config.bootstrap_peers = cli.bootstrap_peers.clone();
        }
        if let Some(ref dir) = cli.data_dir {
            config.data_dir = Some(dir.clone());
        }
        if let Some(ref bin) = cli.prover_companion_bin {
            config.prover_companion_bin = Some(bin.clone());
        }
        if !cli.prover_companion_args.is_empty() {
            config.prover_companion_args = cli.prover_companion_args.clone();
        }
        if let Some(timeout_ms) = cli.prover_companion_timeout_ms {
            config.prover_companion_timeout_ms = timeout_ms;
        }
        if let Some(ref path) = cli.prover_witness_file {
            config.prover_witness_file = Some(path.clone());
        }
        let (local_identity, local_identity_profile) =
            resolve_loaded_identity(&cli, config.data_dir.as_deref(), config.chain_id)?;
        if let Some(profile) = &local_identity_profile {
            apply_local_identity_to_config(&mut config, &profile)?;
        }

        let proof_mode = parse_config_proof_mode(&config.proof_mode)?;
        let genesis = resolve_genesis(&config)?;
        validate_runtime_chain_id(config.chain_id, proof_mode)?;
        validate_chain_id_consistency(config.chain_id, &genesis)?;
        validate_multinode_genesis_time(&config, &genesis)?;
        if proof_mode.requires_production_genesis() {
            validate_production_genesis(&genesis)?;
        }
        ensure_mock_precompile_compatible(proof_mode)?;
        ensure_mev_ace_full_vdf_compatible(proof_mode, config.mev_ace_full_activation_slot)?;

        Ok(Self {
            config,
            genesis,
            local_identity,
        })
    }

    fn active_proof_mode(&self) -> ProofMode {
        parse_config_proof_mode(&self.config.proof_mode)
            .expect("proof mode validated during node construction")
    }

    fn skips_native_witness_gating(&self) -> bool {
        self.active_proof_mode().is_mock() || self.defers_provable_txs_without_companion()
    }

    fn defers_provable_txs_without_companion(&self) -> bool {
        self.active_proof_mode() == ProofMode::DevStark && !self.prover_companion_enabled()
    }

    fn build_proof_system(&self) -> anyhow::Result<(Box<dyn ProofVerifier>, bool)> {
        match self.active_proof_mode() {
            ProofMode::Production => {
                // STARK verification is transparent — no keys to load.
                #[cfg(feature = "stark")]
                {
                    Ok((Box::new(StarkVerifierOnly), false))
                }
                #[cfg(not(feature = "stark"))]
                {
                    anyhow::bail!(
                        "proof_mode=production requires building ace-node with --features stark"
                    );
                }
            }
            ProofMode::DevMock => {
                #[cfg(feature = "devnet")]
                {
                    Ok((Box::new(MockProver::from_env()), true))
                }
                #[cfg(not(feature = "devnet"))]
                {
                    anyhow::bail!(
                        "proof_mode=dev-mock requires building ace-node with --features devnet"
                    );
                }
            }
            ProofMode::DevStark => {
                // Real STARK verification on devnet — uses StarkVerifierOnly
                // but auto-emits proper STARK-format finality certificates
                // (empty proof bundles for blocks without ZK transactions).
                #[cfg(all(feature = "devnet", feature = "stark"))]
                {
                    Ok((Box::new(StarkVerifierOnly), true))
                }
                #[cfg(not(all(feature = "devnet", feature = "stark")))]
                {
                    anyhow::bail!(
                        "proof_mode=dev-stark requires building ace-node with --features devnet,stark"
                    );
                }
            }
        }
    }

    fn prover_companion_enabled(&self) -> bool {
        self.config
            .prover_companion_bin
            .as_ref()
            .map(|bin| !bin.trim().is_empty())
            .unwrap_or(false)
    }

    fn configured_prover_witness_path(&self) -> Option<PathBuf> {
        self.config
            .prover_witness_file
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| {
                material_target_path(
                    "ACE_PROVER_WITNESS_FILE",
                    self.config.data_dir.as_deref(),
                    DEFAULT_PROVER_WITNESS_FILE,
                )
            })
    }

    fn load_configured_witness_map(
        &self,
    ) -> anyhow::Result<
        Option<BTreeMap<String, crate::companion_protocol::SerializablePrivateWitness>>,
    > {
        let Some(path) = self.configured_prover_witness_path() else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|e| {
            anyhow::anyhow!("failed to read witness file {}: {}", path.display(), e)
        })?;
        let decoded = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid witness file {}: {}", path.display(), e))?;
        Ok(Some(decoded))
    }

    fn companion_request_witnesses(
        &self,
        block: &ace_runtime::types::block::Block,
    ) -> anyhow::Result<Option<Vec<crate::companion_protocol::SerializablePrivateWitness>>> {
        let requires_native_witnesses = block.transactions.iter().any(|tx| tx.raw_chain.is_none());
        if !requires_native_witnesses {
            return Ok(None);
        }

        let witness_map = self.load_configured_witness_map()?.ok_or_else(|| {
            let hint = self
                .configured_prover_witness_path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| DEFAULT_PROVER_WITNESS_FILE.to_string());
            anyhow::anyhow!(
                "native transactions require local witnesses; populate {} or set --prover-witness-file",
                hint
            )
        })?;

        let mut witnesses = Vec::with_capacity(block.transactions.len());
        for tx in &block.transactions {
            witnesses.push(witness_for_tx(tx, Some(&witness_map)).ok_or_else(|| {
                anyhow::anyhow!(
                    "missing witness for native tx {}",
                    hex::encode(tx.attestation.obj_hash)
                )
            })?);
        }
        Ok(Some(witnesses))
    }

    /// Requests a finality certificate from the local prover companion process.
    ///
    /// Trust boundary: the prover companion MUST run on the same trusted host as the node;
    /// its binary and inputs are under the operator's control. Do not expose this path to untrusted peers.
    async fn request_finality_certificate(
        &self,
        block: &ace_runtime::types::block::Block,
        genesis_hash: [u8; 32],
    ) -> anyhow::Result<FinalityCertificate> {
        let bin = self
            .config
            .prover_companion_bin
            .as_ref()
            .filter(|bin| !bin.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("no prover companion configured"))?
            .clone();
        let request = ProverCompanionRequest {
            chain_id: self.config.chain_id,
            genesis_hash,
            block: block.clone(),
            witnesses: self.companion_request_witnesses(block)?,
        };
        let request_bytes = serde_json::to_vec(&request)?;

        let mut child = Command::new(&bin)
            .args(&self.config.prover_companion_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn prover companion '{}': {e}", bin))?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to open prover companion stdin"))?;
        let timeout_ms = self.config.prover_companion_timeout_ms;
        let output = timeout(std::time::Duration::from_millis(timeout_ms), async move {
            stdin.write_all(&request_bytes).await?;
            stdin.shutdown().await?;
            drop(stdin);
            child.wait_with_output().await
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "prover companion timed out after {} ms while proving slot {}",
                timeout_ms,
                block.header.slot
            )
        })??;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "prover companion exited with status {}: {}",
                output.status,
                stderr.trim()
            );
        }

        let response: ProverCompanionResponse = serde_json::from_slice(&output.stdout)
            .map_err(|e| anyhow::anyhow!("invalid prover companion response: {e}"))?;
        Ok(response.certificate)
    }

    async fn maybe_emit_finality_cert<B: BlockStore>(
        &self,
        slot: u64,
        engine: &mut ConsensusEngine,
        state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        block_store: &Arc<RwLock<B>>,
        tx_receipt_store: &Arc<RwLock<TxReceiptStore>>,
        eth_events: &Arc<EthEventHub>,
        mempool: &Arc<Mempool>,
        net_outbound_tx: &mpsc::Sender<NetworkMessage>,
        verifier: &dyn ProofVerifier,
        allow_mock_fc: bool,
        governance: &mut RuntimeGovernance,
        persistence: &PersistenceHandles,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
    ) {
        let should_emit = {
            let Some(fsm) = engine.finality_state(slot) else {
                return;
            };
            if fsm.state() != FinalityState::Soft {
                return;
            }
            let store = block_store.read();
            store.get_finality_cert(slot).is_none()
        };
        if !should_emit {
            return;
        }

        let maybe_block = block_store.read().get_block_by_slot(slot);
        let Some(block) = maybe_block else {
            return;
        };

        let proof_mode = self.active_proof_mode();
        if allow_mock_fc {
            match build_auto_dev_finality_certificate(&block, verifier, proof_mode) {
                AutoDevFinalityCertificate::Ready(cert) => {
                    let _ = net_outbound_tx.try_send(NetworkMessage::FinalityCert(cert.clone()));
                    let action = engine.on_finality_cert(cert.clone(), Some(&block), verifier);
                    {
                        let mut store = block_store.write();
                        store.put_finality_cert(cert);
                    }
                    handle_finality_action(
                        slot,
                        action,
                        engine,
                        state,
                        block_store,
                        tx_receipt_store,
                        eth_events,
                        mempool,
                        governance,
                        persistence,
                        genesis_time_ms,
                    );
                    return;
                }
                AutoDevFinalityCertificate::RequiresProverCompanion => {
                    if !self.prover_companion_enabled() {
                        warn!(
                            slot,
                            proof_mode = proof_mode.as_str(),
                            "Auto finality can only certify blocks without provable txs; configure a prover companion to finalize native-transaction blocks"
                        );
                        return;
                    }
                }
                AutoDevFinalityCertificate::Unavailable(reason) => {
                    warn!(
                        slot,
                        proof_mode = proof_mode.as_str(),
                        reason,
                        "Skipping automatic finality certificate emission"
                    );
                    return;
                }
            }
        }

        match self
            .request_finality_certificate(&block, genesis_hash)
            .await
        {
            Ok(cert) => {
                let block_hash = block.hash();
                if cert.slot != slot || cert.block_hash != block_hash {
                    warn!(slot, "Prover returned certificate for the wrong block");
                    return;
                }
                if !verifier.verify_finality_certificate_for_block(&cert, &block) {
                    warn!(slot, "Prover returned an invalid finality certificate");
                    return;
                }

                let _ = net_outbound_tx.try_send(NetworkMessage::FinalityCert(cert.clone()));
                let action = engine.on_finality_cert(cert.clone(), Some(&block), verifier);
                {
                    let mut store = block_store.write();
                    store.put_finality_cert(cert);
                }
                handle_finality_action(
                    slot,
                    action,
                    engine,
                    state,
                    block_store,
                    tx_receipt_store,
                    eth_events,
                    mempool,
                    governance,
                    persistence,
                    genesis_time_ms,
                );
            }
            Err(e) => {
                warn!(slot, %e, "Failed to obtain finality certificate");
            }
        }
    }

    /// Run the node (blocking).
    pub async fn run(self) -> anyhow::Result<()> {
        #[cfg(feature = "persistence")]
        if let Some(ref data_dir) = self.config.data_dir {
            let data_path = std::path::Path::new(data_dir);
            std::fs::create_dir_all(data_path)?;

            // Try to recover state from RocksDB
            let mut state_db = ace_model::RocksDbStateDB::open(data_path.join("state"))
                .map_err(|e| anyhow::anyhow!("failed to open state DB: {e}"))?;
            let block_store = ace_model::RocksDbBlockStore::open(data_path.join("blocks"))
                .map_err(|e| anyhow::anyhow!("failed to open block store: {e}"))?;

            // Check if we have persisted state; if so, recover it
            let (state, genesis_hash, genesis_time_ms) = if state_db
                .persisted_state_root()
                .is_some()
            {
                info!("Recovering state from RocksDB at {}", data_dir);
                let persisted_identity = state_db
                    .chain_identity_metadata()
                    .or_else(|| {
                        state_db
                            .chain_metadata()
                            .map(|(genesis_hash, genesis_time_ms)| ChainIdentityMetadata {
                                genesis_hash,
                                genesis_time_ms,
                                genesis_config_hash: None,
                            })
                    })
                    .unwrap_or_else(|| {
                        let (_, _, genesis_hash, _) = initialize_genesis(&self.genesis)
                            .expect("genesis config should be valid");
                        ChainIdentityMetadata {
                            genesis_hash,
                            genesis_time_ms: fallback_genesis_time_ms(&self.genesis, &block_store),
                            genesis_config_hash: None,
                        }
                    });
                let current_genesis_config_hash = ensure_persistent_chain_compatibility(
                    data_dir,
                    persisted_identity,
                    &self.genesis,
                )?;
                let sharded = state_db
                    .load_sharded_state()
                    .map_err(|e| anyhow::anyhow!("failed to load state: {e}"))?;
                if persisted_identity.genesis_config_hash.is_none() {
                    state_db
                        .persist_chain_identity_metadata(ChainIdentityMetadata {
                            genesis_hash: persisted_identity.genesis_hash,
                            genesis_time_ms: persisted_identity.genesis_time_ms,
                            genesis_config_hash: Some(current_genesis_config_hash),
                        })
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "failed to upgrade persistent chain metadata in '{}': {e}",
                                data_dir
                            )
                        })?;
                }
                let persisted_state_root = sharded.compute_root();
                info!(
                    state_root = hex::encode(persisted_state_root),
                    accounts = sharded.total_account_count(),
                    shards = sharded.shard_count(),
                    "State recovered from disk"
                );

                // If the block store is ahead of the persisted state, log the
                // gap but don't truncate — all validators likely have the same
                // stale state after a non-graceful shutdown, so they will agree
                // on state roots and continue from the block store tip.
                let block_tip = canonical_tip_slot(&block_store).unwrap_or(0);
                if block_tip > 0 {
                    if let Some(tip_block) = block_store.get_block_by_slot(block_tip) {
                        if tip_block.header.state_root != persisted_state_root {
                            warn!(
                                block_tip,
                                block_state_root = hex::encode(tip_block.header.state_root),
                                persisted_state_root = hex::encode(persisted_state_root),
                                "Persisted state root does not match block store tip — resuming from persisted state"
                            );
                        }
                    }
                }

                (
                    sharded,
                    persisted_identity.genesis_hash,
                    persisted_identity.genesis_time_ms,
                )
            } else {
                // Fresh start — initialize from genesis
                let (state, _, genesis_hash, genesis_time_ms) = initialize_genesis(&self.genesis)?;
                let current_genesis_config_hash = genesis_config_hash(&self.genesis)?;
                state_db
                    .persist_sharded_state_with_identity(
                        &state,
                        genesis_hash,
                        genesis_time_ms,
                        Some(current_genesis_config_hash),
                    )
                    .map_err(|e| anyhow::anyhow!("failed to persist genesis state: {e}"))?;
                info!(
                    genesis_hash = hex::encode(genesis_hash),
                    genesis_time_ms, "Genesis initialized (persistent mode)"
                );
                (state, genesis_hash, genesis_time_ms)
            };

            return self
                .run_with_store(
                    state,
                    block_store,
                    genesis_hash,
                    genesis_time_ms,
                    PersistenceHandles::enabled(state_db),
                )
                .await;
        }

        // Fallback: in-memory storage
        let (state, block_store, genesis_hash, genesis_time_ms) =
            initialize_genesis(&self.genesis)?;

        info!(
            genesis_hash = hex::encode(genesis_hash),
            genesis_time_ms, "Genesis initialized (in-memory mode)"
        );

        self.run_with_store(
            state,
            block_store,
            genesis_hash,
            genesis_time_ms,
            PersistenceHandles::disabled(),
        )
        .await
    }

    async fn run_with_store<B: BlockStore + 'static>(
        &self,
        state: ace_model::sharded_state::ShardedState,
        block_store: B,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
        persistence: PersistenceHandles,
    ) -> anyhow::Result<()> {
        let state = Arc::new(RwLock::new(state));
        let block_store = Arc::new(RwLock::new(block_store));
        let current_slot = Arc::new(AtomicU64::new(
            SlotClock::new(genesis_time_ms).current_slot(),
        ));
        let peer_count = Arc::new(AtomicU64::new(0));
        let founder_id_com = crate::genesis::parse_founder_id_com(&self.genesis)?;
        let mempool = Arc::new(Mempool::with_slot_and_state(
            MempoolConfig {
                chain_id: self.config.chain_id,
                founder_id_com,
                ..MempoolConfig::default()
            },
            Arc::clone(&current_slot),
            Arc::clone(&state),
        ));

        // Set up P2P networking
        let peer_snapshot = Arc::new(std::sync::RwLock::new(Vec::new()));
        let net_config = NetworkConfig {
            chain_id: self.config.chain_id,
            listen_addr: format!("/ip4/0.0.0.0/tcp/{}", self.config.p2p_port),
            bootnodes: self.config.bootnodes.clone(),
            bootstrap_peers: self.config.bootstrap_peers.clone(),
            node_name: "ace-validator".to_string(),
            max_peers: 50,
            // Static devnets already have explicit bootnodes; keeping mDNS off
            // there avoids mid-run peer churn and duplicate connections.
            enable_mdns: cfg!(feature = "devnet")
                && self.config.bootnodes.is_empty()
                && self.config.bootstrap_peers.is_empty(),
            data_dir: self.config.data_dir.as_ref().map(std::path::PathBuf::from),
        };
        let (
            net_service,
            consensus_rx,
            net_inbound_rx,
            net_outbound_tx,
            consensus_outbound_tx,
            sync_cmd_tx,
            tx_fetch_cmd_tx,
            tx_fetch_inbound_rx,
            tx_fetch_response_tx,
        ) = NetworkService::new(
            net_config,
            self.local_identity.clone(),
            Arc::clone(&peer_count),
            Arc::clone(&peer_snapshot),
        );

        let tx_receipt_store = Arc::new(RwLock::new(
            if let Some(data_dir) = self.config.data_dir.as_deref() {
                let snapshot_path = Path::new(data_dir).join(TX_RECEIPT_SNAPSHOT_FILE);
                TxReceiptStore::open_persistent(snapshot_path, DEFAULT_TX_RECEIPT_RETENTION)?
            } else {
                TxReceiptStore::with_max_receipts(DEFAULT_TX_RECEIPT_RETENTION)
            },
        ));
        let eth_events = Arc::new(EthEventHub::new(DEFAULT_ETH_EVENT_RETENTION));
        let native_token =
            self.genesis
                .native_token
                .as_ref()
                .map(|n| ace_rpc::types::NativeTokenInfo {
                    symbol: n.symbol.clone(),
                    decimals: n.decimals,
                });

        // Initialize wrapped native bridge assets. This must remain idempotent
        // so persistent nodes can restart against an already-populated state DB.
        {
            let mut bridge = ace_defi::BridgeState::new();
            let mut state_guard = state.write();
            bridge
                .initialize(state_guard.default_shard_mut())
                .map_err(|e| anyhow::anyhow!("bridge initialization failed: {e}"))?;
        }

        // Start Prometheus metrics exporter
        if self.config.metrics_port > 0 {
            crate::metrics::init(self.config.metrics_port);
        }

        // Start RPC server
        let latest_block_slot = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let state_root_hex = Arc::new(parking_lot::RwLock::new(hex::encode(
            state.read().compute_root(),
        )));
        let tps_samples = Arc::new(parking_lot::RwLock::new(std::collections::VecDeque::new()));
        let mempool_notify = Arc::new(tokio::sync::Notify::new());
        let (local_mev_ace_tx, local_mev_ace_rx) = mpsc::channel::<MevAceNetworkMessage>(10_000);
        let founder_id_com =
            crate::genesis::parse_founder_id_com(&self.genesis)?.map(|id| hex::encode(id.0));
        let public_node_roles = effective_public_node_roles(&self.config);
        let rpc_state = Arc::new(RpcState {
            state: Arc::clone(&state),
            block_store: Arc::clone(&block_store),
            mempool: Arc::clone(&mempool),
            mempool_notify: Some(Arc::clone(&mempool_notify)),
            current_slot: Arc::clone(&current_slot),
            peer_count: Arc::clone(&peer_count),
            peer_snapshot: Arc::clone(&peer_snapshot),
            latest_block_slot: Arc::clone(&latest_block_slot),
            state_root_hex: Arc::clone(&state_root_hex),
            chain_id: self.config.chain_id,
            native_token,
            tx_receipt_store: Arc::clone(&tx_receipt_store),
            eth_events: Arc::clone(&eth_events),
            outbound_tx: Some(net_outbound_tx.clone()),
            local_mev_ace_tx: self.config.validator.then_some(local_mev_ace_tx.clone()),
            otp_store: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
            tps_samples: Arc::clone(&tps_samples),
            validator_admission_policy: self.genesis.validator_admission_policy.clone(),
            founder_id_com,
            validator_count: self.genesis.validators.len(),
            validator: self.config.validator,
            public_rpc: is_public_rpc_bind_addr(&self.config.rpc_bind_addr)
                || public_node_roles.iter().any(|role| role == "rpc"),
            public_node_roles,
        });
        let hfi_pay_state = Arc::new(match self.config.data_dir.as_ref() {
            Some(dir) => {
                let dir_path = std::path::PathBuf::from(dir);

                // Try RocksDB-backed persistence first, fall back to JSON.
                #[cfg(feature = "persistence")]
                {
                    let app_store_path = dir_path.join("app_store");
                    match ace_model::rocks_app_store::RocksDbAppStore::open(&app_store_path) {
                        Ok(app_store) => {
                            let app_store = Arc::new(RwLock::new(app_store));
                            info!(path = %app_store_path.display(), "HFI Pay: RocksDB persistent mode");
                            ace_rpc::hfi_pay_rpc::HfiPayState::with_rocks_db(
                                app_store,
                                Some(dir_path.clone()),
                            )
                        }
                        Err(e) => {
                            warn!(%e, "failed to open RocksDB app store, falling back to JSON persistence");
                            let hfi_dir = dir_path.join("hfi-pay");
                            info!(path = %hfi_dir.display(), "HFI Pay: JSON persistent mode (fallback)");
                            ace_rpc::hfi_pay_rpc::HfiPayState::with_persistence(hfi_dir)
                        }
                    }
                }
                #[cfg(not(feature = "persistence"))]
                {
                    let hfi_dir = dir_path.join("hfi-pay");
                    info!(path = %hfi_dir.display(), "HFI Pay: JSON persistent mode");
                    ace_rpc::hfi_pay_rpc::HfiPayState::with_persistence(hfi_dir)
                }
            }
            None => {
                info!("HFI Pay: in-memory mode (no data_dir)");
                ace_rpc::hfi_pay_rpc::HfiPayState::new()
            }
        });
        {
            let lookup: Arc<dyn ace_hfi_pay::onchain::CommittedTxLookup> =
                Arc::new(HfiBlockTxLookup {
                    inner: Arc::clone(&block_store),
                });
            hfi_pay_state.attach_committed_tx_lookup(lookup);
        }
        let _rpc_handle = RpcServer::start(
            &self.config.rpc_bind_addr,
            self.config.rpc_port,
            rpc_state,
            hfi_pay_state.clone(),
        )
        .await?;

        // Spawn P2P task
        tokio::spawn(async move {
            if let Err(e) = net_service.run().await {
                warn!(%e, "P2P service error");
            }
        });

        if !self.config.validator {
            spawn_public_node_background_tasks(self.config.clone(), net_outbound_tx.clone());
        }

        let slot_clock = SlotClock::new(genesis_time_ms);
        let mut governance = RuntimeGovernance::load_or_new(
            &self.genesis,
            genesis_time_ms,
            self.config.data_dir.as_deref(),
        )?;

        let state_for_persist = Arc::clone(&state);
        let result = if self.config.validator {
            self.run_validator(
                slot_clock,
                genesis_hash,
                genesis_time_ms,
                self.local_identity.as_deref(),
                state,
                block_store,
                mempool,
                current_slot,
                peer_count,
                tx_receipt_store,
                Arc::clone(&eth_events),
                net_outbound_tx,
                consensus_outbound_tx,
                net_inbound_rx,
                local_mev_ace_rx,
                consensus_rx,
                &mut governance,
                &persistence,
                latest_block_slot,
                state_root_hex,
                tps_samples,
                Arc::clone(&mempool_notify),
                sync_cmd_tx,
                tx_fetch_cmd_tx,
                tx_fetch_inbound_rx,
                tx_fetch_response_tx,
                Arc::clone(&hfi_pay_state),
            )
            .await
        } else {
            self.run_non_validator(
                slot_clock,
                genesis_hash,
                genesis_time_ms,
                self.local_identity.as_deref(),
                state,
                block_store,
                mempool,
                current_slot,
                tx_receipt_store,
                Arc::clone(&eth_events),
                net_outbound_tx,
                consensus_outbound_tx,
                net_inbound_rx,
                &mut governance,
                &persistence,
                Arc::clone(&hfi_pay_state),
            )
            .await
        };

        if let Err(e) = persistence.persist_tree(&state_for_persist, genesis_hash, genesis_time_ms)
        {
            warn!(%e, "Failed to persist final state snapshot");
        }
        if let Err(e) = governance.persist() {
            warn!(%e, "Failed to persist final governance snapshot");
        }

        result
    }

    async fn run_validator<B: BlockStore + 'static>(
        &self,
        slot_clock: SlotClock,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
        local_identity: Option<&ace_identity::LoadedIdentity>,
        state: Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        block_store: Arc<RwLock<B>>,
        mempool: Arc<Mempool>,
        current_slot: Arc<AtomicU64>,
        peer_count: Arc<AtomicU64>,
        tx_receipt_store: Arc<RwLock<TxReceiptStore>>,
        eth_events: Arc<EthEventHub>,
        net_outbound_tx: mpsc::Sender<NetworkMessage>,
        consensus_outbound_tx: mpsc::Sender<NetworkMessage>,
        mut net_inbound_rx: mpsc::Receiver<NetworkMessage>,
        mut local_mev_ace_rx: mpsc::Receiver<MevAceNetworkMessage>,
        mut consensus_rx: mpsc::Receiver<NetworkMessage>,
        governance: &mut RuntimeGovernance,
        persistence: &PersistenceHandles,
        latest_block_slot: Arc<AtomicU64>,
        state_root_hex: Arc<parking_lot::RwLock<String>>,
        tps_samples: Arc<
            parking_lot::RwLock<std::collections::VecDeque<ace_rpc::types::RpcTpsSample>>,
        >,
        mempool_notify: Arc<tokio::sync::Notify>,
        _sync_cmd_tx: mpsc::Sender<SyncRequestCommand>,
        tx_fetch_cmd_tx: mpsc::Sender<ace_p2p::TxFetchCommand>,
        mut tx_fetch_inbound_rx: mpsc::Receiver<ace_p2p::TxFetchInboundRequest>,
        tx_fetch_response_tx: mpsc::Sender<ace_p2p::TxFetchResponseCommand>,
        hfi_pay_state: Arc<ace_rpc::hfi_pay_rpc::HfiPayState>,
    ) -> anyhow::Result<()> {
        let validator_set = build_validator_set(&self.genesis)?;
        let local_id =
            resolve_local_identity(&self.config.validator_key, &self.genesis, &validator_set)?;
        governance.ensure_validator_active(&local_id)?;
        let proof_mode = parse_config_proof_mode(&self.config.proof_mode)?;
        let mut resource_monitor = ResourceMonitor::with_defaults();
        let violations = resource_monitor.check_violations();
        if proof_mode.requires_production_genesis() {
            governance.enforce_local_resources(&local_id, &mut resource_monitor)?;
        } else if !violations.is_empty() {
            warn!(
                local_id = %hex::encode(local_id.0),
                proof_mode = proof_mode.as_str(),
                violations = %violations
                    .iter()
                    .map(|violation| violation.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                "Skipping production resource-limit enforcement in development proof mode"
            );
        }
        let local_signing_key = resolve_local_signing_key(
            &self.config.validator_signing_seed,
            &local_id,
            &validator_set,
            proof_mode.requires_production_genesis(),
        )?;
        let local_auth_pubkey =
            resolve_local_auth_pubkey(state.read().default_shard(), &local_id, local_identity)?;
        let mut takeover_manager = TakeoverManager::new(local_id.0, local_auth_pubkey);

        info!(
            local_id = hex::encode(local_id.0),
            validators = validator_set.len(),
            total_stake = validator_set.total_stake(),
            "Validator identity resolved"
        );

        let leader_schedule = LeaderSchedule::new(genesis_hash);
        let poh = PohChain::new(genesis_hash);

        let n_vm = n_vm_with_hfi_pay_hook(&hfi_pay_state, governance.founder_id_com);
        info!(
            "n-VM initialized with real ACE Native + revm EVM + Simple SVM + BVM + TVM (HFI Pay on-chain hook)"
        );

        let mut engine = ConsensusEngine::new(
            local_id,
            leader_schedule,
            validator_set,
            poh,
            n_vm,
            genesis_hash,
        );
        engine
            .rebuild_full_validator_set(&governance.approved_validators())
            .map_err(|e| anyhow::anyhow!("failed to rebuild full validator set at startup: {e}"))?;
        let tip_slot = canonical_tip_slot(&*block_store.read()).unwrap_or(0);
        sync_effective_validator_set(
            &mut engine,
            governance,
            slot_time_ms(genesis_time_ms, tip_slot),
        );
        engine.last_block_hash = canonical_tip_hash(&*block_store.read(), genesis_hash);

        let (verifier, allow_mock_fc) = self.build_proof_system()?;

        if allow_mock_fc {
            match proof_mode {
                ProofMode::DevMock => {
                    warn!(
                        "Using MockProver for finality verification — NOT cryptographically secure. Dev mode only."
                    );
                }
                ProofMode::DevStark => {
                    if self.prover_companion_enabled() {
                        info!(
                            proof_mode = proof_mode.as_str(),
                            "Using STARK verifier with auto-emitted FCs for raw-only blocks and prover companion support for native blocks"
                        );
                    } else {
                        info!(
                            proof_mode = proof_mode.as_str(),
                            "Using STARK verifier with auto-emitted FCs; native txs included without ZK proofs (devnet)"
                        );
                    }
                }
                ProofMode::Production => unreachable!("production does not auto-emit dev FCs"),
            }
        } else {
            info!(proof_mode = %self.config.proof_mode, "Using cryptographic proof verifier");
            if self.prover_companion_enabled() {
                info!(
                    companion = self
                        .config
                        .prover_companion_bin
                        .as_deref()
                        .unwrap_or_default(),
                    timeout_ms = self.config.prover_companion_timeout_ms,
                    "Local prover companion enabled for finality certificate generation"
                );
            } else {
                anyhow::bail!(
                    "validator mode with proof_mode={} requires --prover-companion-bin (or config prover_companion_bin) so the node can obtain finality certificates without holding proving secrets",
                    self.config.proof_mode
                );
            }
        }

        let node_tag = local_id.0[0];
        info!("Starting consensus slot loop");

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let shutdown_tx_clone = shutdown_tx.clone();
        // Notify used to wake the proposer immediately when a tx submission
        // makes the ready set transition from empty to non-empty.
        // Earliest wall-clock time we may start the next proposal (block pacing).
        let mut earliest_propose_time = tokio::time::Instant::now();
        // Proposal tx budget. Starts conservative and adjusts based on
        // measured execution time.
        let mut proposal_tx_budget: usize = ace_runtime::config::PROPOSAL_TX_INITIAL_BUDGET;
        // Compact-proposal budget control state.
        // hit_rate_ewma: EWMA of compact hit rate (α=0.2); starts at 1.0 (perfect).
        // severe_miss_streak: consecutive blocks where current<70% AND ewma<85%.
        // budget_cooldown: blocks remaining where budget writes are suppressed.
        // healthy_streak: consecutive healthy blocks toward budget recovery.
        let mut hit_rate_ewma: f64 = 1.0_f64;
        let mut severe_miss_streak: u32 = 0_u32;
        let mut budget_cooldown: u32 = 0_u32;
        let mut healthy_streak: u32 = 0_u32;
        // Number of consecutive zero-tx proposals produced by *this node*.
        // In a 3-node devnet with round-robin schedule this node leads every
        // 3rd slot, so IDLE_RESET_EMPTY_THRESHOLD=10 corresponds to ≈ 12 s of
        // chain-wide idle (10 × 3 × 400 ms).  On the first non-empty block
        // after that streak the budget is reset to INITIAL before current_budget
        // is computed, ensuring the block is small enough for TxFetch to
        // complete within the propose timeout.
        let mut consecutive_empty_proposals: u32 = 0;
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm =
                    signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received SIGINT, shutting down");
                    }
                    _ = sigterm.recv() => {
                        info!("Received SIGTERM, shutting down");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to listen for ctrl+c");
                info!("Received ctrl+c, shutting down");
            }
            let _ = shutdown_tx_clone.send(()).await;
        });

        let mut recent_sync_requests = std::collections::HashMap::<u64, u64>::new();
        let mut prepared_block_cache =
            std::collections::HashMap::<[u8; 32], PreparedBlockExecution>::new();
        let (proposal_validation_tx, mut proposal_validation_rx) =
            mpsc::unbounded_channel::<ConsensusLoopEvent>();
        let mut pending_proposal_validations =
            std::collections::HashMap::<[u8; 32], (u64, u32)>::new();
        let mut pending_local_proposal_build = None::<(u64, u32)>;
        let mut pending_commit = None::<PendingCommitApplication>;
        let mut mev_ace_runtime = MevAceNodeRuntime::default();
        // Signed precommits for the current height, used to build CommitCertificate.
        let mut signed_precommits_for_cert = Vec::<ace_p2p::messages::NetworkPrecommit>::new();
        let mut approval_collector = ApprovalCollector::default();
        // Buffer proposals that arrive for a future round within the same
        // height.  Without this, a proposer that advances to round N+1 before
        // other validators will broadcast a proposal that gets silently dropped
        // (the receivers are still in round N).  When they advance, the
        // proposal is gone and they prevote nil → permanent stall.
        let mut future_round_proposals = std::collections::HashMap::<u32, NetworkProposal>::new();
        // Buffer a proposal that arrives for the NEXT height while the node is
        // still processing/committing the current block.  Without this, a
        // lagging validator misses the proposal, waits for propose timeout
        // (5+ seconds), prevotes nil, and falls further behind — creating a
        // cascade where it never catches up.
        let mut next_height_proposal: Option<NetworkProposal> = None;

        // Compact block proposal support: proposer stores full blocks keyed
        // by block_hash so it can serve TxFetchRequests from other nodes.
        let mut compact_block_cache =
            std::collections::HashMap::<[u8; 32], ace_runtime::types::block::Block>::new();
        // Receiver side: pending compact proposal reconstructions waiting for
        // TxFetchResponse from the proposer.
        let mut pending_compact_reconstructions =
            std::collections::HashMap::<[u8; 32], PendingCompactReconstruction>::new();

        // Pending PQC credential prefetch requests: tx_hash → (credential_hash, source_peer).
        // When a stripped PQC gossip tx arrives with a CredentialCommitment, we queue a
        // TxFetch to the source peer so the full credential is in the mempool before
        // a compact proposal arrives (moves full-credential acquisition off the consensus
        // critical path).
        let mut pending_credential_prefetch: std::collections::HashMap<
            [u8; 32], // tx_hash
            PendingCredentialPrefetch,
        > = std::collections::HashMap::new();

        // Initialize Tendermint: determine starting height from chain tip
        let starting_height = canonical_tip_slot(&*block_store.read()).unwrap_or(0) + 1;
        let mut highest_observed_block_slot = starting_height.saturating_sub(1);
        let mut next_sync_retry_at = tokio::time::Instant::now();
        engine.advance_height(starting_height);
        current_slot.store(starting_height, Ordering::Relaxed);
        let mut consensus_wal = if let Some(ref dir) = self.config.data_dir {
            let wal_path = std::path::Path::new(dir).join("consensus.wal");
            match ace_consensus::wal::ConsensusWal::open(&wal_path) {
                Ok(mut wal) => {
                    let recovery = wal.recover();
                    // Only restore the lock if the WAL height matches the
                    // starting height AND the locked block actually exists in
                    // the store.  On a full restart every node loses its
                    // in-memory vote state, so a stale lock can never be
                    // unlocked (no node can supply the ⅔ prevote proof needed
                    // to override the Tendermint locking rule).  Clearing the
                    // lock is safe because no committed block exists at this
                    // height — all nodes restart at round 0 with a clean slate.
                    let lock_valid = if let (Some(lr), Some(lh)) =
                        (recovery.locked_round, recovery.locked_hash)
                    {
                        let height_matches = recovery.height == starting_height;
                        let block_exists = block_store.read().get_block_by_hash(&lh).is_some();
                        if height_matches && block_exists {
                            engine.tendermint.restore_lock(lr, lh);
                            tracing::info!(
                                wal_height = recovery.height,
                                locked_round = lr,
                                locked_hash = hex::encode(&lh[..8]),
                                "Restored consensus lock from WAL"
                            );
                            true
                        } else {
                            tracing::info!(
                                wal_height = recovery.height,
                                starting_height,
                                locked_round = lr,
                                locked_hash = hex::encode(&lh[..8]),
                                "Discarding stale WAL lock — block not committed at this height"
                            );
                            false
                        }
                    } else {
                        false
                    };
                    if !lock_valid {
                        let _ = wal.truncate();
                    }
                    wal
                }
                Err(e) => {
                    tracing::warn!(%e, "Failed to open consensus WAL, running without");
                    ace_consensus::wal::ConsensusWal::noop()
                }
            }
        } else {
            ace_consensus::wal::ConsensusWal::noop()
        };

        info!(
            height = starting_height,
            "Starting Tendermint consensus loop"
        );

        // Wait for genesis time before entering consensus
        let until_genesis_ms = slot_clock.time_until_genesis_ms();
        if until_genesis_ms > 0 {
            info!(until_genesis_ms, genesis_time_ms, "Waiting for genesis");
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(until_genesis_ms)) => {}
                _ = shutdown_rx.recv() => {
                    info!("Shutting down before genesis");
                    return Ok(());
                }
            }
        }

        let startup_peer_target = if !self.config.bootstrap_peers.is_empty() {
            self.config.bootstrap_peers.len()
        } else if !self.config.bootnodes.is_empty() {
            self.config
                .bootnodes
                .len()
                .min(engine.validator_set.len().saturating_sub(1))
        } else {
            0
        };

        // For any restart (genesis or non-clean) we need to wait until enough
        // peers are connected before entering consensus, so that votes and
        // proposals actually reach their destinations.  For mDNS-only networks
        // (startup_peer_target == 0) we derive the target from the validator
        // set size and fall back to a timeout if peers are slow to appear.
        let effective_peer_target = if startup_peer_target > 0 {
            startup_peer_target
        } else {
            engine.validator_set.len().saturating_sub(1)
        };

        if starting_height <= 1 && effective_peer_target > 0 {
            info!(
                required_peers = effective_peer_target,
                "Waiting for startup peers before entering genesis consensus"
            );
            if wait_for_startup_peers(
                &peer_count,
                effective_peer_target,
                std::time::Duration::from_secs(30),
                &mut shutdown_rx,
            )
            .await
            .is_err()
            {
                return Ok(());
            }
        } else if starting_height > 1 {
            // Non-clean restart: wait for peers to connect before resuming
            // consensus.  Using a real peer-count check (with a generous
            // timeout fallback) avoids the race condition where a fixed sleep
            // expires before mDNS discovery completes, causing votes to be
            // sent into the void and the chain to stall for many rounds.
            let restart_peer_target = effective_peer_target.max(1);
            info!(
                required_peers = restart_peer_target,
                height = starting_height,
                "Waiting for P2P peers before resuming consensus"
            );
            if wait_for_startup_peers(
                &peer_count,
                restart_peer_target,
                std::time::Duration::from_secs(20),
                &mut shutdown_rx,
            )
            .await
            .is_err()
            {
                return Ok(());
            }
        }

        // On non-genesis restart, probe peers for their latest height immediately
        // so that highest_observed_block_slot is seeded before the first consensus
        // tick fires.  Without this probe a restarted node at height N would not
        // know the network has advanced further and would skip fast-sync until
        // gossip happened to arrive first.
        if starting_height > 1 {
            send_block_sync_request(&net_outbound_tx, starting_height, FAST_SYNC_BATCH_LIMIT);
        }

        // If we are the proposer for the first round, kick off the proposal
        if engine.is_proposer(engine.current_height(), 0) {
            info!(
                height = engine.current_height(),
                round = 0,
                "We are the initial proposer"
            );
        }
        engine
            .round_timer
            .start_step(0, ace_consensus::RoundStep::Propose);

        loop {
            // Actively sweep pending compact-proposal reconstructions whose
            // absolute deadline has passed.  This stops waiting on reconstruction
            // unconditionally — independent of the TxFetch retry/failure path —
            // and relies on the round timer to advance (nil-prevote on timeout)
            // rather than waiting for the next libp2p failure event to trigger
            // the deadline check.
            let now_instant = tokio::time::Instant::now();
            pending_compact_reconstructions.retain(|block_hash, pending| {
                if now_instant >= pending.reconstruct_deadline {
                    tracing::warn!(
                        height = pending.compact_proposal.height,
                        round  = pending.compact_proposal.round,
                        hash   = hex::encode(&block_hash[..8]),
                        attempts = pending.attempts,
                        budget_ms = ace_runtime::config::TX_FETCH_RECONSTRUCT_BUDGET_MS,
                        "Abandoning compact proposal: reconstruction deadline reached (active sweep)"
                    );
                    false
                } else {
                    true
                }
            });

            let height = engine.current_height();
            let round = engine.current_round();
            let step = engine.current_step();
            current_slot.store(height, Ordering::Relaxed);

            // Replay a buffered future-round proposal if we just advanced to
            // its round.  The proposal was already verified (proposer +
            // signature) when it was buffered, so we only need to kick off
            // the async block-execution validation.
            if let Some(proposal) = future_round_proposals.remove(&round) {
                let block_hash = proposal.block.hash();
                if !prepared_block_cache.contains_key(&block_hash)
                    && !pending_proposal_validations.contains_key(&block_hash)
                    && !engine.proposals.contains_key(&block_hash)
                {
                    tracing::info!(
                        height,
                        round,
                        hash = hex::encode(&block_hash[..8]),
                        "Replaying buffered future-round proposal"
                    );
                    pending_proposal_validations
                        .insert(block_hash, (proposal.height, proposal.round));
                    let parent_stored_root = block_store
                        .read()
                        .get_block_by_hash(&proposal.block.header.parent_hash)
                        .map(|b| b.header.state_root);
                    Self::spawn_proposal_validation_task(
                        proposal,
                        Arc::clone(&state),
                        Arc::clone(&block_store),
                        engine.validator_set.clone(),
                        engine.last_block_hash,
                        governance.clone_for_preview(),
                        genesis_time_ms,
                        parent_stored_root,
                        Arc::clone(&hfi_pay_state),
                        self.config.mev_ace_activation_slot,
                        self.config.mev_ace_full_activation_slot,
                        proposal_validation_tx.clone(),
                    );
                }
            }

            let should_defer_production = should_defer_leader_production(
                highest_observed_block_slot,
                &*block_store.read(),
                height,
            );
            if should_defer_production {
                if !validator_sets_match(&engine.validator_set, &engine.full_validator_set) {
                    tracing::info!(
                        height,
                        observed = highest_observed_block_slot,
                        "Restoring full validator set while validator catches up"
                    );
                    engine.set_effective_validator_set(engine.full_validator_set.clone());
                }
            } else {
                sync_effective_validator_set(
                    &mut engine,
                    governance,
                    slot_time_ms(genesis_time_ms, height.saturating_sub(1)),
                );
            }
            if should_defer_production && tokio::time::Instant::now() >= next_sync_retry_at {
                if maybe_request_validator_block_sync(
                    highest_observed_block_slot,
                    &engine,
                    &block_store,
                    &net_outbound_tx,
                ) {
                    next_sync_retry_at =
                        tokio::time::Instant::now() + std::time::Duration::from_secs(1);
                }
            }

            // Dispatch pending credential prefetch requests. For each stripped PQC tx
            // in the queue, ask the source peer for the full-credential tx from its
            // mempool, moving full-credential acquisition off the compact-proposal
            // critical path.
            if !pending_credential_prefetch.is_empty() {
                let now = tokio::time::Instant::now();

                // Group by peer and dispatch one TxFetch per unique peer.
                let mut per_peer: std::collections::HashMap<
                    String,
                    Vec<([u8; 32], ace_p2p::messages::CredentialCommitment)>,
                > = std::collections::HashMap::new();
                pending_credential_prefetch.retain(|tx_hash, pending| {
                    // Drop if already upgraded (full tx present in mempool).
                    // We do NOT drop just because the stripped tx is missing from mempool,
                    // as it might have been drained but we still want the full credential
                    // for future validation or if it's re-broadcast.
                    if let Some(tx) = mempool.get(tx_hash) {
                        if !tx.is_credential_stripped() {
                            return false;
                        }
                    }

                    if now >= pending.deadline
                        || pending.attempts >= CREDENTIAL_PREFETCH_MAX_ATTEMPTS
                    {
                        tracing::debug!(
                            tx_hash = hex::encode(tx_hash),
                            attempts = pending.attempts,
                            expired = now >= pending.deadline,
                            "credential prefetch: dropping pending request"
                        );
                        return false;
                    }
                    if now >= pending.next_retry_at {
                        let batch = per_peer.entry(pending.peer_id.clone()).or_default();
                        if batch.len() < CREDENTIAL_PREFETCH_BATCH_PER_PEER {
                            batch.push((*tx_hash, pending.commitment.clone()));
                        }
                    }
                    true
                });

                for (peer_id, entries) in per_peer {
                    if entries.is_empty() {
                        continue;
                    }
                    let tx_hashes: Vec<[u8; 32]> = entries.iter().map(|(h, _)| *h).collect();
                    let credential_commitments: Vec<ace_p2p::messages::CredentialCommitment> =
                        entries.iter().map(|(_, c)| c.clone()).collect();
                    match tx_fetch_cmd_tx.try_send(ace_p2p::TxFetchCommand {
                        peer_id,
                        request: ace_p2p::messages::TxFetchRequest::Mempool {
                            tx_hashes: tx_hashes.clone(),
                            credential_commitments,
                        },
                    }) {
                        Ok(()) => {
                            for tx_hash in tx_hashes {
                                if let Some(pending) = pending_credential_prefetch.get_mut(&tx_hash)
                                {
                                    pending.attempts = pending.attempts.saturating_add(1);
                                    let retry_ms = CREDENTIAL_PREFETCH_BASE_RETRY_MS
                                        .saturating_mul(1u64 << pending.attempts.min(4));
                                    pending.next_retry_at =
                                        now + std::time::Duration::from_millis(retry_ms);
                                }
                            }
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            for tx_hash in tx_hashes {
                                if let Some(pending) = pending_credential_prefetch.get_mut(&tx_hash)
                                {
                                    pending.next_retry_at = now
                                        + std::time::Duration::from_millis(
                                            CREDENTIAL_PREFETCH_BASE_RETRY_MS,
                                        );
                                }
                            }
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            pending_credential_prefetch.clear();
                        }
                    }
                }
            }

            // If we are the proposer and in Propose step, build and broadcast proposal.
            // Empty blocks are valid — they keep the chain advancing and prevent
            // consensus stalls between transaction batches.
            let interval_ready = tokio::time::Instant::now() >= earliest_propose_time;
            if step == ace_consensus::RoundStep::Propose
                && engine.is_proposer(height, round)
                && !engine.tendermint.has_proposal()
                && interval_ready
                && !should_defer_production
                && pending_local_proposal_build != Some((height, round))
            {
                if round > 0 {
                    proposal_tx_budget = (proposal_tx_budget / 2)
                        .max(ace_runtime::config::PROPOSAL_TX_INITIAL_BUDGET);
                }
                // After a long idle streak the budget may sit at MAX.
                // Reset it to INITIAL *before* computing current_budget so
                // that the very first non-empty block after idle is small.
                // The adaptive loop in LocalProposalBuilt ramps it back up
                // based on actual build timing — no permanent throughput loss.
                if consecutive_empty_proposals >= ace_runtime::config::IDLE_RESET_EMPTY_THRESHOLD {
                    tracing::info!(
                        consecutive_empty = consecutive_empty_proposals,
                        old_budget = proposal_tx_budget,
                        new_budget = ace_runtime::config::PROPOSAL_TX_INITIAL_BUDGET,
                        "Resetting proposal budget after idle period"
                    );
                    proposal_tx_budget = ace_runtime::config::PROPOSAL_TX_INITIAL_BUDGET;
                }
                // After repeated round timeouts, force an empty block to
                // guarantee chain liveness.  The mempool will continue
                // draining once the chain advances past the stall.
                let force_empty = round >= 3;
                let current_budget = if force_empty { 0 } else { proposal_tx_budget };

                if force_empty {
                    // Build empty proposal synchronously — bypasses the
                    // blocking thread pool entirely so it cannot be starved
                    // by in-flight builds from earlier rounds.
                    //
                    // IMPORTANT: use the *same* pipeline as
                    // `build_tendermint_proposal_with_context` / proposal validation
                    // (`prepare_block_execution` + `preview_prepared_state_root`).
                    // The previous hand-rolled path (sweep + clone_for_preview governance
                    // only) could diverge from what followers replay, causing
                    // perpetual state_root rejections and liveness failure even
                    // for `tx_count=0` blocks.
                    if round == 3 {
                        tracing::warn!(
                            height,
                            round,
                            "Forcing empty proposal to recover chain liveness"
                        );
                    }
                    pending_local_proposal_build = Some((height, round));
                    let parent_stored_root = block_store
                        .read()
                        .get_block_by_hash(&engine.last_block_hash)
                        .map(|b| b.header.state_root);
                    let empty_vm =
                        n_vm_with_hfi_pay_hook(&hfi_pay_state, governance.founder_id_com);
                    let empty_result = build_tendermint_proposal_with_context(
                        engine.last_block_hash,
                        local_id,
                        engine.poh.clone(),
                        &engine.validator_set,
                        &empty_vm,
                        height,
                        round,
                        genesis_time_ms,
                        &state,
                        &block_store,
                        vec![],
                        governance,
                        parent_stored_root,
                        self.config.mev_ace_activation_slot,
                        self.config.mev_ace_full_activation_slot,
                        None,
                    );
                    let event = ConsensusLoopEvent::LocalProposalBuilt {
                        height,
                        round,
                        budget: 0,
                        build_ms: 0,
                        requeue_txs: Vec::new(),
                        prepared: empty_result.map_err(|e: anyhow::Error| e.to_string()),
                    };
                    self.handle_consensus_loop_event(
                        event,
                        &mut engine,
                        &local_id,
                        &local_signing_key,
                        &state,
                        &block_store,
                        &tx_receipt_store,
                        &eth_events,
                        &mempool,
                        &net_outbound_tx,
                        &consensus_outbound_tx,
                        verifier.as_ref(),
                        allow_mock_fc,
                        governance,
                        persistence,
                        genesis_hash,
                        genesis_time_ms,
                        &latest_block_slot,
                        &state_root_hex,
                        &tps_samples,
                        &mut consensus_wal,
                        &mut prepared_block_cache,
                        &mut pending_proposal_validations,
                        &mut pending_local_proposal_build,
                        &mut pending_commit,
                        &proposal_validation_tx,
                        &mut proposal_tx_budget,
                        &mut consecutive_empty_proposals,
                        &node_tag,
                        &mut compact_block_cache,
                        &mut signed_precommits_for_cert,
                        Arc::clone(&hfi_pay_state),
                        &mut hit_rate_ewma,
                        &mut budget_cooldown,
                        &mut healthy_streak,
                    )
                    .await;
                } else {
                    let (txs, mev_ace_material) = if mev_ace_full_material_is_active(
                        height,
                        self.config.mev_ace_full_activation_slot,
                    ) {
                        match mev_ace_runtime.build_material_and_transactions(
                            height,
                            engine.last_block_hash,
                            &engine.validator_set,
                            &local_id,
                            &local_signing_key,
                        ) {
                            Ok((material, txs)) => (txs, Some(material)),
                            Err(error) => {
                                warn!(height, round, %error, "Failed to build MEV-ACE material; proposing empty MEV-ACE block");
                                let empty_material = MevAceNodeRuntime::build_empty_material(
                                    height,
                                    engine.last_block_hash,
                                    &engine.validator_set,
                                    &local_id,
                                    &local_signing_key,
                                )
                                .ok();
                                (Vec::new(), empty_material)
                            }
                        }
                    } else {
                        (
                            self.select_transactions_for_block(
                                &state,
                                &mempool,
                                &mut approval_collector,
                                &engine,
                                &local_id,
                                &local_signing_key,
                                allow_mock_fc,
                                current_budget,
                            ),
                            None,
                        )
                    };
                    pending_local_proposal_build = Some((height, round));
                    let parent_stored_root = block_store
                        .read()
                        .get_block_by_hash(&engine.last_block_hash)
                        .map(|b| b.header.state_root);
                    Self::spawn_local_proposal_build_task(
                        height,
                        round,
                        current_budget,
                        txs,
                        local_id,
                        engine.last_block_hash,
                        engine.poh.clone(),
                        engine.validator_set.clone(),
                        governance.clone_for_preview(),
                        genesis_time_ms,
                        Arc::clone(&state),
                        Arc::clone(&block_store),
                        parent_stored_root,
                        Arc::clone(&hfi_pay_state),
                        self.config.mev_ace_activation_slot,
                        self.config.mev_ace_full_activation_slot,
                        mev_ace_material,
                        proposal_validation_tx.clone(),
                    );
                }
            }

            // ── Batch-drain non-consensus inbound messages ─────────────
            // Process up to MAX_INBOUND_DRAIN per iteration.
            // IMPORTANT: We check consensus_rx.try_recv() inside the loop to
            // ensure consensus messages can "interrupt" the drain if they
            // arrive during a heavy transaction flood.
            const MAX_INBOUND_DRAIN: usize = 64;
            for _ in 0..MAX_INBOUND_DRAIN {
                if let Ok(event) = proposal_validation_rx.try_recv() {
                    self.handle_consensus_loop_event(
                        event,
                        &mut engine,
                        &local_id,
                        &local_signing_key,
                        &state,
                        &block_store,
                        &tx_receipt_store,
                        &eth_events,
                        &mempool,
                        &net_outbound_tx,
                        &consensus_outbound_tx,
                        verifier.as_ref(),
                        allow_mock_fc,
                        governance,
                        persistence,
                        genesis_hash,
                        genesis_time_ms,
                        &latest_block_slot,
                        &state_root_hex,
                        &tps_samples,
                        &mut consensus_wal,
                        &mut prepared_block_cache,
                        &mut pending_proposal_validations,
                        &mut pending_local_proposal_build,
                        &mut pending_commit,
                        &proposal_validation_tx,
                        &mut proposal_tx_budget,
                        &mut consecutive_empty_proposals,
                        &node_tag,
                        &mut compact_block_cache,
                        &mut signed_precommits_for_cert,
                        Arc::clone(&hfi_pay_state),
                        &mut hit_rate_ewma,
                        &mut budget_cooldown,
                        &mut healthy_streak,
                    )
                    .await;
                }

                // If a consensus message is waiting, stop draining and handle it immediately.
                if let Ok(msg) = consensus_rx.try_recv() {
                    if let Some(observed_slot) = observed_block_slot_from_network_message(&msg) {
                        // Ignore slots unreasonably far ahead of our consensus
                        // height.  Use engine height (block number) instead of
                        // wall-clock slot to avoid the mismatch that allowed
                        // phantom fast-sync stalls.
                        let max_plausible = height.saturating_add(SLOT_PLAUSIBILITY_WINDOW);
                        if observed_slot <= max_plausible {
                            highest_observed_block_slot =
                                highest_observed_block_slot.max(observed_slot);
                        }
                    }
                    self.handle_consensus_message(
                        msg,
                        &mut engine,
                        &local_id,
                        &local_signing_key,
                        &state,
                        &block_store,
                        &tx_receipt_store,
                        &eth_events,
                        &mempool,
                        &net_outbound_tx,
                        &consensus_outbound_tx,
                        verifier.as_ref(),
                        allow_mock_fc,
                        governance,
                        persistence,
                        genesis_hash,
                        genesis_time_ms,
                        &latest_block_slot,
                        &state_root_hex,
                        &tps_samples,
                        &mut consensus_wal,
                        &node_tag,
                        &mut prepared_block_cache,
                        &proposal_validation_tx,
                        &mut pending_proposal_validations,
                        &mut pending_commit,
                        &mut future_round_proposals,
                        &mut next_height_proposal,
                        &mut pending_compact_reconstructions,
                        &tx_fetch_cmd_tx,
                        &mut signed_precommits_for_cert,
                        Arc::clone(&hfi_pay_state),
                        &mut pending_credential_prefetch,
                        &mempool_notify,
                        &mut proposal_tx_budget,
                        &mut hit_rate_ewma,
                        &mut severe_miss_streak,
                        &mut budget_cooldown,
                        &mut healthy_streak,
                    )
                    .await;
                    // We don't break here; we continue the drain, but we've
                    // prioritized the consensus message that just arrived.
                }

                let msg = match net_inbound_rx.try_recv() {
                    Ok(m) => m,
                    Err(_) => break,
                };
                if let Some(observed_slot) = observed_block_slot_from_network_message(&msg) {
                    let max_plausible = height.saturating_add(SLOT_PLAUSIBILITY_WINDOW);
                    if observed_slot <= max_plausible {
                        highest_observed_block_slot =
                            highest_observed_block_slot.max(observed_slot);
                    }
                }
                match msg {
                    NetworkMessage::NewTransaction {
                        tx,
                        credential_commitment,
                        source_peer_id,
                    } => {
                        let tx_hash = tx.tx_hash();
                        // Relay admission re-validates full-credential txs locally.
                        // Stripped PQC txs are parked as credential-fetch targets
                        // and are not locally proposable until upgraded.
                        match mempool.insert_relay(tx.clone()) {
                            Ok(outcome) => {
                                crate::metrics::record_mempool_accepted();
                                if outcome.became_ready {
                                    mempool_notify.notify_one();
                                }
                                maybe_publish_pending_evm_tx(&eth_events, &tx);
                                // NOTE: sign_local_approval offloaded from main loop to prevent
                                // consensus starvation. Approvals will be handled via gossip
                                // received from other nodes or a separate worker task.
                            }
                            Err(e) => {
                                crate::metrics::record_mempool_rejected(e.short_reason());
                                tracing::debug!(err = %e, "Mempool rejected tx");
                            }
                        }
                        // PQC stripped tx with commitment → queue credential prefetch.
                        // Only prefetch if the stripped transaction is actually
                        // resident in the local mempool. This prevents rejected
                        // txs (pool full, nonce gap, stale nonce, etc.) from
                        // amplifying into request-response traffic.
                        if let Some(commitment) = credential_commitment {
                            let mempool_has_stripped = mempool
                                .get(&tx_hash)
                                .map_or(false, |existing| existing.is_credential_stripped());
                            if mempool_has_stripped
                                && !pending_credential_prefetch.contains_key(&tx_hash)
                            {
                                if pending_credential_prefetch.len()
                                    >= CREDENTIAL_PREFETCH_MAX_PENDING
                                {
                                    tracing::debug!(
                                        pending = pending_credential_prefetch.len(),
                                        "credential prefetch: dropping request because queue is full"
                                    );
                                } else if let Some(peer_id) = source_peer_id {
                                    let now = tokio::time::Instant::now();
                                    pending_credential_prefetch.insert(
                                        tx_hash,
                                        PendingCredentialPrefetch {
                                            commitment,
                                            peer_id,
                                            attempts: 0,
                                            next_retry_at: now,
                                            deadline: now
                                                + std::time::Duration::from_millis(
                                                    CREDENTIAL_PREFETCH_DEADLINE_MS,
                                                ),
                                        },
                                    );
                                }
                            }
                        }
                    }
                    // NOTE: no separate NewTransactionPqc variant; handled above via credential_commitment field.
                    NetworkMessage::MevAce(mev_msg) => {
                        if let MevAceNetworkMessage::OmissionProof(proof) = &mev_msg {
                            let proof_result = {
                                let state_guard = state.read();
                                validate_mev_ace_omission_proof_from_store(
                                    proof,
                                    &block_store,
                                    &state_guard,
                                    &engine.validator_set,
                                )
                            };
                            match proof_result.and_then(|_| {
                                build_mev_ace_omission_evidence_tx(
                                    proof,
                                    self.config.chain_id,
                                    height,
                                )
                            }) {
                                Ok(tx) => match mempool.insert_relay(tx.clone()) {
                                    Ok(outcome) => {
                                        if outcome.became_ready {
                                            mempool_notify.notify_one();
                                        }
                                        let _ = net_outbound_tx.try_send(
                                            NetworkMessage::NewTransaction {
                                                tx,
                                                credential_commitment: None,
                                                source_peer_id: None,
                                            },
                                        );
                                    }
                                    Err(error) => {
                                        tracing::debug!(
                                            %error,
                                            "MEV-ACE omission evidence rejected by mempool"
                                        );
                                    }
                                },
                                Err(error) => {
                                    tracing::debug!(
                                        %error,
                                        "Ignoring invalid MEV-ACE omission proof"
                                    );
                                }
                            }
                            continue;
                        }
                        let state_guard = state.read();
                        if let Some(response) = mev_ace_runtime.handle_message(
                            mev_msg,
                            &state_guard,
                            &engine.validator_set,
                            &local_id,
                            &local_signing_key,
                            engine.last_block_hash,
                            height,
                        ) {
                            let _ = net_outbound_tx.try_send(response);
                        }
                    }
                    NetworkMessage::FinalityCert(cert) => {
                        let slot = cert.slot;
                        if !engine
                            .finality_state(slot)
                            .is_some_and(|fsm| !fsm.state().is_terminal())
                        {
                            continue;
                        }
                        let Some(known_block) = block_store
                            .read()
                            .get_block_by_slot(slot)
                            .filter(|block| block.hash() == cert.block_hash)
                        else {
                            continue;
                        };
                        let action = engine.on_finality_cert(
                            cert.clone(),
                            Some(&known_block),
                            verifier.as_ref(),
                        );
                        if engine
                            .finality_state(slot)
                            .is_some_and(|fsm| fsm.state() == FinalityState::Hard)
                        {
                            block_store.write().put_finality_cert(cert);
                        }
                        handle_finality_action(
                            slot,
                            action,
                            &mut engine,
                            &state,
                            &block_store,
                            &tx_receipt_store,
                            &eth_events,
                            &mempool,
                            governance,
                            persistence,
                            genesis_time_ms,
                        );
                    }
                    NetworkMessage::NewBlock(block) => {
                        tracing::debug!(
                            slot = block.header.slot,
                            "Received NewBlock (legacy) — ignoring in Tendermint mode"
                        );
                    }
                    NetworkMessage::BlockSyncRequest(request) => {
                        if let Some(response) =
                            build_block_sync_response(&*block_store.read(), &request)
                        {
                            let _ = net_outbound_tx
                                .try_send(NetworkMessage::BlockSyncResponse(response));
                        }
                    }
                    NetworkMessage::BlockSyncResponse(response) => {
                        let height_before_sync = engine.current_height();
                        for record in response.records {
                            ingest_block_record(
                                record,
                                height,
                                &mut engine,
                                &state,
                                &block_store,
                                &tx_receipt_store,
                                &eth_events,
                                &mempool,
                                governance,
                                persistence,
                                genesis_time_ms,
                                &net_outbound_tx,
                                verifier.as_ref(),
                                true,
                                &self.config.weak_subjectivity_checkpoint,
                                &mut recent_sync_requests,
                                self.config.mev_ace_activation_slot,
                                self.config.mev_ace_full_activation_slot,
                            );
                        }
                        if engine.current_height() > height_before_sync {
                            let new_height = engine.current_height();
                            tracing::info!(
                                old_height = height_before_sync,
                                new_height,
                                "Validator advanced after block sync"
                            );
                            pending_proposal_validations.clear();
                            pending_local_proposal_build = None;
                            pending_commit = None;
                            signed_precommits_for_cert.clear();
                            prepared_block_cache.clear();
                            future_round_proposals.clear();
                            current_slot.store(new_height, Ordering::Relaxed);
                            // Allow proposing immediately after sync — the
                            // block interval pacing should not penalise a node
                            // that just caught up.
                            earliest_propose_time = tokio::time::Instant::now();

                            // After sync catches up, replay any buffered
                            // next-height proposal so the lagging validator can
                            // participate immediately instead of waiting a full
                            // propose timeout (~5 s).
                            if let Some(prop) = next_height_proposal.take() {
                                if prop.height == new_height && prop.round == 0 {
                                    let bh = prop.block.hash();
                                    if !prepared_block_cache.contains_key(&bh)
                                        && !pending_proposal_validations.contains_key(&bh)
                                        && !engine.proposals.contains_key(&bh)
                                    {
                                        tracing::info!(
                                            height = new_height,
                                            hash = hex::encode(&bh[..8]),
                                            "Replaying buffered proposal after block sync"
                                        );
                                        pending_proposal_validations
                                            .insert(bh, (prop.height, prop.round));
                                        let parent_stored_root = block_store
                                            .read()
                                            .get_block_by_hash(&prop.block.header.parent_hash)
                                            .map(|b| b.header.state_root);
                                        Self::spawn_proposal_validation_task(
                                            prop,
                                            Arc::clone(&state),
                                            Arc::clone(&block_store),
                                            engine.validator_set.clone(),
                                            engine.last_block_hash,
                                            governance.clone_for_preview(),
                                            genesis_time_ms,
                                            parent_stored_root,
                                            Arc::clone(&hfi_pay_state),
                                            self.config.mev_ace_activation_slot,
                                            self.config.mev_ace_full_activation_slot,
                                            proposal_validation_tx.clone(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    NetworkMessage::CommitteeApproval(message) => {
                        if mempool.contains(&message.tx_hash) {
                            let tx_hash = message.tx_hash;
                            if approval_collector.add_verified(message, &engine.validator_set) {
                                mempool.promote_parked_committee(&tx_hash);
                                mempool_notify.notify_one();
                            }
                        }
                    }
                    NetworkMessage::IdentityTakeover(takeover_msg) => {
                        if takeover_manager.on_takeover_msg(&takeover_msg) {
                            warn!(
                                idcom = hex::encode(takeover_msg.idcom),
                                nonce = takeover_msg.nonce,
                                "Validated takeover message; shutting down"
                            );
                            return Ok(());
                        }
                    }
                    NetworkMessage::StateSyncRequest(_)
                    | NetworkMessage::StateSyncResponse(_)
                    | NetworkMessage::DialPeer { .. } => {}
                    // Consensus messages should be routed to consensus_rx by P2P.
                    // If they arrive here, handle them immediately.
                    NetworkMessage::Proposal(_)
                    | NetworkMessage::CompactProposal(_)
                    | NetworkMessage::TxFetchResponse(_)
                    | NetworkMessage::TxFetchFailure(_)
                    | NetworkMessage::Prevote(_)
                    | NetworkMessage::Precommit(_)
                    | NetworkMessage::CommitCertificate(_) => {
                        self.handle_consensus_message(
                            msg,
                            &mut engine,
                            &local_id,
                            &local_signing_key,
                            &state,
                            &block_store,
                            &tx_receipt_store,
                            &eth_events,
                            &mempool,
                            &net_outbound_tx,
                            &consensus_outbound_tx,
                            verifier.as_ref(),
                            allow_mock_fc,
                            governance,
                            persistence,
                            genesis_hash,
                            genesis_time_ms,
                            &latest_block_slot,
                            &state_root_hex,
                            &tps_samples,
                            &mut consensus_wal,
                            &node_tag,
                            &mut prepared_block_cache,
                            &proposal_validation_tx,
                            &mut pending_proposal_validations,
                            &mut pending_commit,
                            &mut future_round_proposals,
                            &mut next_height_proposal,
                            &mut pending_compact_reconstructions,
                            &tx_fetch_cmd_tx,
                            &mut signed_precommits_for_cert,
                            Arc::clone(&hfi_pay_state),
                            &mut pending_credential_prefetch,
                            &mempool_notify,
                            &mut proposal_tx_budget,
                            &mut hit_rate_ewma,
                            &mut severe_miss_streak,
                            &mut budget_cooldown,
                            &mut healthy_streak,
                        )
                        .await;
                    }
                }
            }

            // Compute the absolute deadline for the current round step ONCE,
            // before entering the select. This ensures batch-drain processing
            // time does not erode the timeout budget.
            let round_deadline = if let Some(std_deadline) = engine.round_timer.step_deadline() {
                let now_std = std::time::Instant::now();
                if std_deadline > now_std {
                    tokio::time::Instant::now() + (std_deadline - now_std)
                } else {
                    tokio::time::Instant::now() // already expired
                }
            } else {
                tokio::time::Instant::now() // already expired
            };

            // Event-driven select: consensus messages and timeouts.
            // Non-consensus messages were already batch-drained above.
            tokio::select! {
                validation_event = proposal_validation_rx.recv() => {
                    let Some(event) = validation_event else { continue; };
                    self.handle_consensus_loop_event(
                        event,
                        &mut engine,
                        &local_id,
                        &local_signing_key,
                        &state,
                        &block_store,
                        &tx_receipt_store,
                        &eth_events,
                        &mempool,
                        &net_outbound_tx,
                        &consensus_outbound_tx,
                        verifier.as_ref(),
                        allow_mock_fc,
                        governance,
                        persistence,
                        genesis_hash,
                        genesis_time_ms,
                        &latest_block_slot,
                        &state_root_hex,
                        &tps_samples,
                        &mut consensus_wal,
                        &mut prepared_block_cache,
                        &mut pending_proposal_validations,
                        &mut pending_local_proposal_build,
                        &mut pending_commit,
                        &proposal_validation_tx,
                        &mut proposal_tx_budget,
                        &mut consecutive_empty_proposals,
                        &node_tag,
                        &mut compact_block_cache,
                        &mut signed_precommits_for_cert,
                        Arc::clone(&hfi_pay_state),
                        &mut hit_rate_ewma,
                        &mut budget_cooldown,
                        &mut healthy_streak,
                    ).await;
                }

                // Consensus messages (Proposal, Prevote, Precommit)
                cmsg = consensus_rx.recv() => {
                    let Some(msg) = cmsg else { continue; };
                    if let Some(observed_slot) = observed_block_slot_from_network_message(&msg) {
                        let max_plausible = height.saturating_add(SLOT_PLAUSIBILITY_WINDOW);
                        if observed_slot <= max_plausible {
                            highest_observed_block_slot = highest_observed_block_slot.max(observed_slot);
                        }
                    }
                    self.handle_consensus_message(
                        msg,
                        &mut engine,
                        &local_id,
                        &local_signing_key,
                        &state,
                        &block_store,
                        &tx_receipt_store,
                        &eth_events,
                        &mempool,
                        &net_outbound_tx,
                        &consensus_outbound_tx,
                        verifier.as_ref(),
                        allow_mock_fc,
                        governance,
                        persistence,
                        genesis_hash,
                        genesis_time_ms,
                        &latest_block_slot,
                        &state_root_hex,
                        &tps_samples,
                        &mut consensus_wal,
                        &node_tag,
                        &mut prepared_block_cache,
                        &proposal_validation_tx,
                        &mut pending_proposal_validations,
                        &mut pending_commit,
                        &mut future_round_proposals,
                        &mut next_height_proposal,
                        &mut pending_compact_reconstructions,
                        &tx_fetch_cmd_tx,
                        &mut signed_precommits_for_cert,
                        Arc::clone(&hfi_pay_state),
                        &mut pending_credential_prefetch,
                        &mempool_notify,
                        &mut proposal_tx_budget,
                        &mut hit_rate_ewma,
                        &mut severe_miss_streak,
                        &mut budget_cooldown,
                        &mut healthy_streak,
                    ).await;
                }

                // Handle tx-fetch requests from peers (proposer side: serve missing txs).
                Some(req) = tx_fetch_inbound_rx.recv() => {
                    match req.request {
                        ace_p2p::messages::TxFetchRequest::Mempool { tx_hashes, credential_commitments } => {
                            // Credential prefetch: serve full-credential txs from local mempool.
                            let mut transactions_wire: Vec<Vec<u8>> = Vec::new();
                            if tx_hashes.len() == credential_commitments.len() {
                                for (tx_hash, commitment) in tx_hashes.iter().zip(&credential_commitments) {
                                    let Some(tx) = mempool.get(tx_hash) else {
                                        continue;
                                    };
                                    if tx.is_credential_stripped() {
                                        continue;
                                    }
                                    if !credential_matches_commitment(&tx, commitment) {
                                        continue;
                                    }
                                    transactions_wire.push(tx.to_bytes());
                                }
                            } else {
                                tracing::warn!(
                                    requested = tx_hashes.len(),
                                    commitments = credential_commitments.len(),
                                    "Rejecting credential prefetch request with mismatched lengths"
                                );
                            }
                            tracing::debug!(
                                requested = tx_hashes.len(),
                                served = transactions_wire.len(),
                                "Serving credential prefetch from mempool"
                            );
                            let _ = tx_fetch_response_tx.try_send(ace_p2p::TxFetchResponseCommand {
                                channel_id: req.channel_id,
                                response: ace_p2p::TxFetchResponse::Mempool { transactions_wire },
                            });
                        }
                        ace_p2p::messages::TxFetchRequest::CompactBlock { block_hash, tx_hashes } => {
                            if let Some(block) = compact_block_cache.get(&block_hash) {
                                let mut txs_by_hash: std::collections::HashMap<[u8; 32], &Transaction> = std::collections::HashMap::new();
                                for tx in &block.transactions {
                                    txs_by_hash.insert(tx.tx_hash(), tx);
                                }
                                let transactions_wire: Vec<Vec<u8>> = tx_hashes
                                    .iter()
                                    .filter_map(|h| txs_by_hash.get(h).map(|t| t.to_bytes()))
                                    .collect();
                                tracing::debug!(
                                    requested = tx_hashes.len(),
                                    served = transactions_wire.len(),
                                    "Serving tx-fetch request"
                                );
                                let _ = tx_fetch_response_tx.try_send(ace_p2p::TxFetchResponseCommand {
                                    channel_id: req.channel_id,
                                    response: ace_p2p::TxFetchResponse::CompactBlock { block_hash, transactions_wire },
                                });
                            } else {
                                tracing::debug!("Ignoring tx-fetch request: block not in compact cache");
                            }
                        }
                    }
                }

                Some(mev_msg) = local_mev_ace_rx.recv() => {
                    let state_guard = state.read();
                    if let Some(response) = mev_ace_runtime.handle_message(
                        mev_msg,
                        &state_guard,
                        &engine.validator_set,
                        &local_id,
                        &local_signing_key,
                        engine.last_block_hash,
                        height,
                    ) {
                        let _ = net_outbound_tx.try_send(response);
                    }
                    continue;
                }

                // Mempool received a tx — re-check proposal condition.
                // Only relevant during Propose step; other steps ignore this.
                _ = mempool_notify.notified(), if step == ace_consensus::RoundStep::Propose => {
                    continue;
                }

                // Block interval elapsed — re-check proposal
                _ = tokio::time::sleep_until(earliest_propose_time), if !interval_ready => {
                    continue;
                }

                // Round timeout fired
                _ = tokio::time::sleep_until(round_deadline) => {
                    let tm_step = engine.current_step();
                    if tm_step == ace_consensus::RoundStep::CommitWait {
                        tracing::debug!(
                            height,
                            round,
                            step = ?tm_step,
                            "Tendermint commit-wait elapsed"
                        );
                    } else {
                        tracing::warn!(
                            height,
                            round,
                            step = ?tm_step,
                            pending_build = ?pending_local_proposal_build,
                            "Tendermint round timeout"
                        );
                    }
                    let action = engine.on_timeout();
                    self.execute_tendermint_action(
                        action,
                        &mut engine,
                        &local_id,
                        &local_signing_key,
                        &state,
                        &block_store,
                        &tx_receipt_store,
                        &eth_events,
                        &mempool,
                        &net_outbound_tx,
                        &consensus_outbound_tx,
                        verifier.as_ref(),
                        allow_mock_fc,
                        governance,
                        persistence,
                        genesis_hash,
                        genesis_time_ms,
                        &latest_block_slot,
                        &state_root_hex,
                        &tps_samples,
                        &mut consensus_wal,
                        &mut prepared_block_cache,
                        &mut pending_commit,
                        &proposal_validation_tx,
                        &mut signed_precommits_for_cert,
                        Arc::clone(&hfi_pay_state),
                    )
                    .await;
                    // After CommitWait → Committed transition, refresh the round
                    // timer for the Committed step.  RoundStep::Committed has an
                    // effectively infinite timeout (u64::MAX/2 ms), which keeps
                    // the select waiting on channel events instead of spinning on
                    // an already-expired CommitWait deadline.
                    if engine.current_step() == ace_consensus::RoundStep::Committed {
                        engine.round_timer.start_step(
                            engine.current_round(),
                            ace_consensus::RoundStep::Committed,
                        );
                    }
                }

                _ = shutdown_rx.recv() => {
                    info!("Shutting down Tendermint consensus loop");
                    tx_receipt_store.write().force_persist_snapshot();
                    break;
                }
            }

            // If CommitWait finished, advance to the next height.
            if engine.current_step() == ace_consensus::RoundStep::Committed
                && engine.tendermint.committed_hash().is_some()
                && pending_commit.is_none()
            {
                let new_height = engine.current_height() + 1;
                let _ = consensus_wal
                    .write(&ace_consensus::wal::WalEntry::HeightAdvance { new_height });
                let _ = consensus_wal.truncate();
                engine.advance_height(new_height);
                // On commit, clamp highest_observed_block_slot to prevent
                // a stale/poisoned value from causing permanent fast-sync
                // stalls.  The committed height is the ground truth.
                highest_observed_block_slot = highest_observed_block_slot.min(new_height);
                pending_proposal_validations.clear();
                future_round_proposals.clear();
                pending_local_proposal_build = None;
                pending_commit = None;
                signed_precommits_for_cert.clear();
                // Clean up compact block caches from previous heights
                compact_block_cache
                    .retain(|_, block| block.header.slot >= new_height.saturating_sub(1));
                pending_compact_reconstructions.clear();
                engine
                    .round_timer
                    .start_step(0, ace_consensus::RoundStep::Propose);
                earliest_propose_time = tokio::time::Instant::now()
                    + std::time::Duration::from_millis(ace_runtime::config::BLOCK_INTERVAL_MS);

                // Replay a buffered next-height proposal if one arrived while
                // we were still committing the previous block.  This avoids a
                // full propose timeout (5+ seconds) for lagging validators.
                if let Some(prop) = next_height_proposal.take() {
                    if prop.height == new_height && prop.round == 0 {
                        let bh = prop.block.hash();
                        if !prepared_block_cache.contains_key(&bh)
                            && !pending_proposal_validations.contains_key(&bh)
                            && !engine.proposals.contains_key(&bh)
                        {
                            tracing::info!(
                                height = new_height,
                                hash = hex::encode(&bh[..8]),
                                "Replaying buffered next-height proposal"
                            );
                            pending_proposal_validations.insert(bh, (prop.height, prop.round));
                            let parent_stored_root = block_store
                                .read()
                                .get_block_by_hash(&prop.block.header.parent_hash)
                                .map(|b| b.header.state_root);
                            Self::spawn_proposal_validation_task(
                                prop,
                                Arc::clone(&state),
                                Arc::clone(&block_store),
                                engine.validator_set.clone(),
                                engine.last_block_hash,
                                governance.clone_for_preview(),
                                genesis_time_ms,
                                parent_stored_root,
                                Arc::clone(&hfi_pay_state),
                                self.config.mev_ace_activation_slot,
                                self.config.mev_ace_full_activation_slot,
                                proposal_validation_tx.clone(),
                            );
                        }
                    }
                }
                // Periodically evict stuck future txs (nonce gaps from
                // overload-rejected submissions).  drain_batch now evicts
                // stripped-tx lane blockage immediately, so this sweep mainly
                // handles Class 2 (orphaned future txs with no ready leader).
                if new_height % 10 == 0 {
                    mempool.evict_stale_future_txs();
                }
                tracing::debug!(
                    new_height,
                    proposer = engine.is_proposer(new_height, 0),
                    "Advanced to new Tendermint height"
                );
            } else if engine.current_step() == ace_consensus::RoundStep::Committed
                && pending_commit.is_some()
            {
                // Step is Committed but we cannot advance because the commit
                // application hasn't finished (or never started).  Try to kick
                // it off — the prepared block may have arrived since the last
                // attempt.
                Self::maybe_start_pending_commit_application(
                    &engine,
                    &state,
                    &block_store,
                    governance,
                    genesis_time_ms,
                    &mut prepared_block_cache,
                    &mut pending_commit,
                    &proposal_validation_tx,
                );
            }

            // Check for Tendermint equivocators and slash them.
            #[cfg(not(feature = "devnet"))]
            {
                let equivocators = engine.tendermint_equivocators();
                for (equivocator, (hash_a, hash_b)) in &equivocators {
                    tracing::warn!(
                        height,
                        voter = hex::encode(&equivocator.0[..4]),
                        hash_a = hex::encode(&hash_a[..8]),
                        hash_b = hex::encode(&hash_b[..8]),
                        "Tendermint equivocation detected — slashing validator"
                    );
                    match governance.slash_equivocator(equivocator, &mut state.write()) {
                        Ok(Some(amount)) => {
                            if amount > 0 {
                                info!(
                                    height,
                                    equivocator = hex::encode(&equivocator.0[..4]),
                                    amount,
                                    "Slashed Tendermint equivocator"
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!(height, equivocator = hex::encode(&equivocator.0[..4]), %e, "Failed to slash Tendermint equivocator");
                        }
                    }
                }
                if !equivocators.is_empty() {
                    sync_effective_validator_set(&mut engine, governance, current_time_ms());
                    if let Err(e) =
                        persistence.persist_tree(&state, engine.genesis_hash, genesis_time_ms)
                    {
                        warn!(height, %e, "Failed to persist state after slashing Tendermint equivocators");
                    }
                    if let Err(e) = governance.persist() {
                        warn!(height, %e, "Failed to persist governance after slashing Tendermint equivocators");
                    }
                }
            }

            // Check post-commit FC timeouts.
            let timeout_actions = engine.check_timeouts(height, verifier.as_ref());
            for (slot, action) in timeout_actions {
                handle_finality_action(
                    slot,
                    action,
                    &mut engine,
                    &state,
                    &block_store,
                    &tx_receipt_store,
                    &eth_events,
                    &mempool,
                    governance,
                    persistence,
                    genesis_time_ms,
                );
            }

            // Periodic cleanup
            if height % 10 == 0 {
                engine.cleanup_finalized(height, 50);
                recent_sync_requests.retain(|_, last| height <= last.saturating_add(8));
            }
        }

        Ok(())
    }

    /// Select transactions from the mempool for block production.
    ///
    /// Drain a batch from the mempool,
    /// filter by witness availability and committee certification, respect block
    /// size/count limits, and requeue deferred txs.
    fn select_transactions_for_block(
        &self,
        state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        mempool: &Arc<Mempool>,
        approval_collector: &mut ApprovalCollector,
        engine: &ConsensusEngine,
        local_id: &AccountId,
        local_signing_key: &LocalSigningKey,
        _allow_mock_fc: bool,
        tx_budget: usize,
    ) -> Vec<Transaction> {
        let select_start = std::time::Instant::now();
        let pending_before = mempool.pending_count();
        let ready_before = mempool.ready_count();
        approval_collector.prune_to_known(|tx_hash| mempool.contains(tx_hash));
        let prune_ms = select_start.elapsed().as_millis();

        let mut deferred_txs = Vec::new();
        let mut missing_witness_txs = Vec::new();
        let mut missing_committee_txs = Vec::new();
        let mut current_block_bytes = BlockHeader::APPROX_WIRE_SIZE;

        let skip_native_witness_gating = self.skips_native_witness_gating();
        let witness_map = if !skip_native_witness_gating {
            match self.load_configured_witness_map() {
                Ok(map) => map,
                Err(error) => {
                    warn!(%error, "Failed to load local witness file; native txs will be deferred");
                    None
                }
            }
        } else {
            None
        };
        let promoted_witness = mempool.promote_parked_witnesses(|tx| {
            skip_native_witness_gating
                || tx.raw_chain.is_some()
                || witness_for_tx(tx, witness_map.as_ref()).is_some()
        });
        if promoted_witness > 0 {
            tracing::debug!(
                promoted_witness,
                "Reactivated witness-parked transactions for proposal selection"
            );
        }

        let selection_window = tx_budget.saturating_mul(2);
        let drained_txs = mempool.drain_batch(selection_window);
        let drained_count = drained_txs.len();
        let drain_ms = select_start.elapsed().as_millis() - prune_ms;
        let mut txs = Vec::with_capacity(drained_txs.len());
        let state_guard = state.read();
        let committee_state = state_guard.default_shard();

        for mut tx in drained_txs {
            // In dev-stark without a prover companion, native txs are included
            // without ZK proofs; the auto-emitted FC covers them via
            // statement_root binding only (devnet feature guard).

            // Defer native txs without a local witness (needed for ZK proofs)
            if !skip_native_witness_gating
                && tx.raw_chain.is_none()
                && witness_for_tx(&tx, witness_map.as_ref()).is_none()
            {
                missing_witness_txs.push(tx);
                continue;
            }

            // Sign approval if we haven't yet
            if let Some(approval) = sign_local_approval(
                &tx,
                committee_state,
                local_id,
                local_signing_key,
                &engine.validator_set,
            ) {
                approval_collector.add_verified(approval, &engine.validator_set);
            }

            // Committee-domain txs need a certificate
            if tx
                .raw_chain
                .as_ref()
                .and_then(|raw_chain| raw_chain.kind.committee_domain())
                .is_some()
            {
                match approval_collector.build_certificate(
                    &tx,
                    committee_state,
                    &engine.validator_set,
                ) {
                    Ok(Some(certificate)) => {
                        tx.attach_committee_certificate(certificate);
                        let tx_wire_size = tx.wire_size();
                        if tx_wire_size + BlockHeader::APPROX_WIRE_SIZE
                            > ace_runtime::config::MAX_BLOCK_BYTES
                        {
                            approval_collector.discard(&tx.tx_hash());
                            continue;
                        }
                        if txs.len() >= tx_budget
                            || current_block_bytes + tx_wire_size
                                > ace_runtime::config::MAX_BLOCK_BYTES
                        {
                            deferred_txs.push(tx);
                            continue;
                        }
                        current_block_bytes += tx_wire_size;
                        approval_collector.discard(&tx.tx_hash());
                        txs.push(tx);
                    }
                    Ok(None) => {
                        missing_committee_txs.push(tx);
                    }
                    Err(error) => {
                        warn!(
                            tx_hash = hex::encode(tx.tx_hash()),
                            %error,
                            "Dropping raw committee tx from this block attempt"
                        );
                        missing_committee_txs.push(tx);
                    }
                }
            } else {
                let tx_wire_size = tx.wire_size();
                if tx_wire_size + BlockHeader::APPROX_WIRE_SIZE
                    > ace_runtime::config::MAX_BLOCK_BYTES
                {
                    // Oversized tx — drop permanently
                    continue;
                }
                if txs.len() >= tx_budget
                    || current_block_bytes + tx_wire_size > ace_runtime::config::MAX_BLOCK_BYTES
                {
                    deferred_txs.push(tx);
                    continue;
                }
                current_block_bytes += tx_wire_size;
                txs.push(tx);
            }
        }

        if !deferred_txs.is_empty() {
            mempool.requeue(deferred_txs);
        }
        if !missing_witness_txs.is_empty() {
            mempool.requeue_parked(missing_witness_txs, ParkedTxReason::MissingWitness);
        }
        if !missing_committee_txs.is_empty() {
            mempool.requeue_parked(
                missing_committee_txs,
                ParkedTxReason::MissingCommitteeCertificate,
            );
        }

        let total_ms = select_start.elapsed().as_millis();
        if total_ms > 100 || ready_before > 1000 {
            let mempool_states = mempool.state_counts();
            tracing::warn!(
                total_ms,
                prune_ms,
                drain_ms,
                pending_before,
                ready_before,
                drained_count,
                selected = txs.len(),
                parked_missing_witness = mempool_states.parked_missing_witness,
                parked_missing_committee = mempool_states.parked_missing_committee_certificate,
                tx_budget,
                "select_transactions_for_block slow"
            );
        }

        txs
    }

    fn requeue_transactions(mempool: &Arc<Mempool>, txs: Vec<Transaction>) {
        mempool.requeue(txs);
    }

    fn spawn_local_proposal_build_task<B: BlockStore + Send + Sync + 'static>(
        height: u64,
        round: u32,
        budget: usize,
        txs: Vec<Transaction>,
        proposer_id: AccountId,
        parent_hash: [u8; 32],
        poh: PohChain,
        validator_set: ValidatorSet,
        governance: RuntimeGovernance,
        genesis_time_ms: u64,
        state: Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        block_store: Arc<RwLock<B>>,
        canonical_parent_state_root: Option<[u8; 32]>,
        hfi_pay_state: Arc<ace_rpc::hfi_pay_rpc::HfiPayState>,
        mev_ace_activation_slot: u64,
        mev_ace_full_activation_slot: u64,
        mev_ace_material: Option<MevAceProposalMaterial>,
        result_tx: mpsc::UnboundedSender<ConsensusLoopEvent>,
    ) {
        Self::spawn_local_proposal_build_task_with_builder(
            height,
            round,
            budget,
            txs,
            result_tx,
            move |txs| {
                let mut preview_governance = governance;
                let founder_id_com = preview_governance.founder_id_com;
                let preview_vm = n_vm_with_hfi_pay_hook(&hfi_pay_state, founder_id_com);
                build_tendermint_proposal_with_context(
                    parent_hash,
                    proposer_id,
                    poh,
                    &validator_set,
                    &preview_vm,
                    height,
                    round,
                    genesis_time_ms,
                    &state,
                    &block_store,
                    txs,
                    &mut preview_governance,
                    canonical_parent_state_root,
                    mev_ace_activation_slot,
                    mev_ace_full_activation_slot,
                    mev_ace_material,
                )
                .map_err(|error| error.to_string())
            },
        );
    }

    fn spawn_local_proposal_build_task_with_builder<F>(
        height: u64,
        round: u32,
        budget: usize,
        txs: Vec<Transaction>,
        result_tx: mpsc::UnboundedSender<ConsensusLoopEvent>,
        build_fn: F,
    ) where
        F: FnOnce(Vec<Transaction>) -> Result<PreparedProposal, String> + Send + 'static,
    {
        let txs_requeue_on_join_failure = txs.clone();
        tokio::spawn(async move {
            let build_start = std::time::Instant::now();
            let blocking_future = tokio::task::spawn_blocking(move || {
                let requeue_txs = txs.clone();
                let prepared = build_fn(txs);
                (requeue_txs, prepared)
            });

            // Hard timeout: if the build takes longer than PROPOSE_TIMEOUT,
            // abort so the consensus loop can advance to the next round
            // (and eventually force an empty proposal at round >= 3).
            let deadline =
                std::time::Duration::from_millis(ace_runtime::config::PROPOSE_TIMEOUT_MS);
            let join_result = match tokio::time::timeout(deadline, blocking_future).await {
                Ok(result) => result,
                Err(_elapsed) => {
                    let build_ms = build_start.elapsed().as_millis() as u64;
                    warn!(
                        height,
                        round, build_ms, "Proposal build timed out — will retry next round"
                    );
                    let _ = result_tx.send(ConsensusLoopEvent::LocalProposalBuilt {
                        height,
                        round,
                        budget,
                        build_ms,
                        requeue_txs: txs_requeue_on_join_failure,
                        prepared: Err("proposal build timed out".into()),
                    });
                    return;
                }
            };

            let build_ms = build_start.elapsed().as_millis() as u64;
            match join_result {
                Ok((requeue_txs, prepared)) => {
                    if result_tx
                        .send(ConsensusLoopEvent::LocalProposalBuilt {
                            height,
                            round,
                            budget,
                            build_ms,
                            requeue_txs,
                            prepared,
                        })
                        .is_err()
                    {
                        tracing::debug!("Dropping proposal build result: consensus loop exited");
                    }
                }
                Err(error) => {
                    warn!(height, round, %error, "Async proposal build task failed (spawn_blocking panicked)");
                    let _ = result_tx.send(ConsensusLoopEvent::LocalProposalBuilt {
                        height,
                        round,
                        budget,
                        build_ms,
                        requeue_txs: txs_requeue_on_join_failure,
                        prepared: Err(format!("spawn_blocking task failed: {error}")),
                    });
                }
            }
        });
    }

    fn spawn_proposal_validation_task<B: BlockStore + Send + Sync + 'static>(
        proposal: NetworkProposal,
        state: Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        block_store: Arc<RwLock<B>>,
        validator_set: ValidatorSet,
        parent_hash: [u8; 32],
        governance: RuntimeGovernance,
        genesis_time_ms: u64,
        canonical_parent_state_root: Option<[u8; 32]>,
        hfi_pay_state: Arc<ace_rpc::hfi_pay_rpc::HfiPayState>,
        mev_ace_activation_slot: u64,
        mev_ace_full_activation_slot: u64,
        result_tx: mpsc::UnboundedSender<ConsensusLoopEvent>,
    ) {
        tokio::spawn(async move {
            let join_result = tokio::task::spawn_blocking(move || {
                let mut preview_governance = governance;
                let founder_id_com = preview_governance.founder_id_com;
                let preview_vm = n_vm_with_hfi_pay_hook(&hfi_pay_state, founder_id_com);
                let t0 = std::time::Instant::now();
                let tx_count = proposal.block.transactions.len();
                let prepared = validate_tendermint_proposal_with_context(
                    &proposal.block,
                    proposal.height,
                    proposal.round,
                    parent_hash,
                    &validator_set,
                    &preview_vm,
                    &state,
                    &block_store,
                    &mut preview_governance,
                    genesis_time_ms,
                    canonical_parent_state_root,
                    mev_ace_activation_slot,
                    mev_ace_full_activation_slot,
                );
                let validate_ms = t0.elapsed().as_millis() as u64;
                tracing::info!(
                    height = proposal.height,
                    round = proposal.round,
                    tx_count,
                    validate_ms,
                    valid = prepared.is_some(),
                    "Proposal validation completed"
                );
                (proposal, prepared)
            })
            .await;

            match join_result {
                Ok((proposal, prepared)) => {
                    if result_tx
                        .send(ConsensusLoopEvent::ProposalValidated { proposal, prepared })
                        .is_err()
                    {
                        tracing::debug!(
                            "Dropping validated proposal result: consensus loop exited"
                        );
                    }
                }
                Err(error) => {
                    warn!(%error, "Async proposal validation task failed");
                }
            }
        });
    }

    fn spawn_commit_preparation_task<B: BlockStore + Send + Sync + 'static>(
        block: ace_runtime::types::block::Block,
        height: u64,
        round: u32,
        state: Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        block_store: Arc<RwLock<B>>,
        validator_set: ValidatorSet,
        parent_hash: [u8; 32],
        governance: RuntimeGovernance,
        genesis_time_ms: u64,
        canonical_parent_state_root: Option<[u8; 32]>,
        hfi_pay_state: Arc<ace_rpc::hfi_pay_rpc::HfiPayState>,
        mev_ace_activation_slot: u64,
        mev_ace_full_activation_slot: u64,
        result_tx: mpsc::UnboundedSender<ConsensusLoopEvent>,
    ) {
        tokio::spawn(async move {
            let join_result = tokio::task::spawn_blocking(move || {
                let mut preview_governance = governance;
                let founder_id_com = preview_governance.founder_id_com;
                let preview_vm = n_vm_with_hfi_pay_hook(&hfi_pay_state, founder_id_com);
                let prepared = validate_tendermint_proposal_with_context(
                    &block,
                    height,
                    round,
                    parent_hash,
                    &validator_set,
                    &preview_vm,
                    &state,
                    &block_store,
                    &mut preview_governance,
                    genesis_time_ms,
                    canonical_parent_state_root,
                    mev_ace_activation_slot,
                    mev_ace_full_activation_slot,
                );
                (block, prepared)
            })
            .await;

            match join_result {
                Ok((block, prepared)) => {
                    if result_tx
                        .send(ConsensusLoopEvent::CommitBlockPrepared {
                            height,
                            round,
                            block,
                            prepared,
                        })
                        .is_err()
                    {
                        tracing::debug!(
                            "Dropping commit preparation result: consensus loop exited"
                        );
                    }
                }
                Err(error) => {
                    warn!(height, round, %error, "Async commit preparation task failed");
                }
            }
        });
    }

    fn spawn_commit_finalize_task(
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        block: ace_runtime::types::block::Block,
        prepared: PreparedBlockExecution,
        snapshot: ace_model::sharded_state::ShardedStateSnapshot,
        validator_set: ValidatorSet,
        governance: RuntimeGovernance,
        genesis_time_ms: u64,
        result_tx: mpsc::UnboundedSender<ConsensusLoopEvent>,
    ) {
        tokio::spawn(async move {
            let join_result = tokio::task::spawn_blocking(move || {
                if prepared.height != block.header.slot {
                    return Err(format!(
                        "prepared height {} does not match committed block {}",
                        prepared.height, block.header.slot
                    ));
                }
                if prepared.receipts.len() != block.transactions.len() {
                    return Err(format!(
                        "prepared receipt count {} does not match tx count {}",
                        prepared.receipts.len(),
                        block.transactions.len()
                    ));
                }

                let mut committed_governance = governance;
                let pre_gov_state_root = prepared.post_tx_state.compute_root();
                let mut post_commit_state = prepared.post_tx_state;
                let block_time_ms = slot_time_ms(genesis_time_ms, block.header.slot);
                committed_governance
                    .apply_completed_block(
                        &mut post_commit_state,
                        &validator_set,
                        prepared.charged_tx_count,
                        block_time_ms,
                    )
                    .map_err(|error| error.to_string())?;
                let computed_root = post_commit_state.compute_root();
                if computed_root != block.header.state_root {
                    tracing::error!(
                        slot = block.header.slot,
                        block_hash = hex::encode(block.hash()),
                        pre_gov_state_root = hex::encode(pre_gov_state_root),
                        expected_state_root = hex::encode(block.header.state_root),
                        computed_state_root = hex::encode(computed_root),
                        charged_tx_count = prepared.charged_tx_count,
                        tx_count = block.transactions.len(),
                        "state_root mismatch after cached execution (commit path; proposer state likely diverged)"
                    );
                    return Err("state_root mismatch after cached execution".to_string());
                }

                // Process on-chain validator admissions (same logic as sync path).
                let mut post_admission_full_validator_set = validator_set.clone();
                let admission_failures = process_block_validator_admissions(
                    &block.transactions,
                    &mut committed_governance,
                    &mut post_admission_full_validator_set,
                    block_time_ms,
                    block.header.slot,
                    "commit path",
                );

                let block_hash_hex = hex::encode(block.hash());
                let mut rpc_receipts = vm_receipts_to_rpc(
                    &block.transactions,
                    &prepared.receipts,
                    block.header.slot,
                    &block_hash_hex,
                );
                mark_admission_failures(&mut rpc_receipts, admission_failures);

                Ok(FinalizedCommit {
                    block,
                    snapshot,
                    post_commit_state,
                    governance: committed_governance,
                    rpc_receipts,
                })
            })
            .await;

            match join_result {
                Ok(result) => {
                    if result_tx
                        .send(ConsensusLoopEvent::CommitFinalized {
                            height,
                            round,
                            block_hash,
                            result,
                        })
                        .is_err()
                    {
                        tracing::debug!("Dropping commit finalize result: consensus loop exited");
                    }
                }
                Err(error) => {
                    warn!(height, round, %error, "Async commit finalize task failed");
                }
            }
        });
    }

    fn maybe_start_pending_commit_application<B: BlockStore + 'static>(
        engine: &ConsensusEngine,
        state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        block_store: &Arc<RwLock<B>>,
        governance: &RuntimeGovernance,
        genesis_time_ms: u64,
        prepared_block_cache: &mut std::collections::HashMap<[u8; 32], PreparedBlockExecution>,
        pending_commit: &mut Option<PendingCommitApplication>,
        result_tx: &mpsc::UnboundedSender<ConsensusLoopEvent>,
    ) {
        let Some(pending) = pending_commit.as_mut() else {
            return;
        };
        if pending.apply_started {
            return;
        }
        let Some(prepared) = prepared_block_cache.remove(&pending.block_hash) else {
            return;
        };
        let committed_block = engine
            .proposals
            .get(&pending.block_hash)
            .cloned()
            .or_else(|| block_store.read().get_block_by_hash(&pending.block_hash));
        let Some(committed_block) = committed_block else {
            prepared_block_cache.insert(pending.block_hash, prepared);
            warn!(
                height = pending.height,
                hash = hex::encode(&pending.block_hash[..8]),
                "Pending commit has no available proposal block yet"
            );
            return;
        };

        pending.apply_started = true;
        let snapshot = state.read().snapshot();
        Self::spawn_commit_finalize_task(
            pending.height,
            pending.round,
            pending.block_hash,
            committed_block,
            prepared,
            snapshot,
            engine.full_validator_set.clone(),
            governance.clone_for_preview(),
            genesis_time_ms,
            result_tx.clone(),
        );
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_consensus_loop_event<B: BlockStore + 'static>(
        &self,
        event: ConsensusLoopEvent,
        engine: &mut ConsensusEngine,
        local_id: &AccountId,
        local_signing_key: &LocalSigningKey,
        state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        block_store: &Arc<RwLock<B>>,
        tx_receipt_store: &Arc<RwLock<TxReceiptStore>>,
        eth_events: &Arc<EthEventHub>,
        mempool: &Arc<Mempool>,
        net_outbound_tx: &mpsc::Sender<NetworkMessage>,
        consensus_outbound_tx: &mpsc::Sender<NetworkMessage>,
        verifier: &dyn ProofVerifier,
        allow_mock_fc: bool,
        governance: &mut RuntimeGovernance,
        persistence: &PersistenceHandles,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
        latest_block_slot: &Arc<AtomicU64>,
        state_root_hex: &Arc<RwLock<String>>,
        tps_samples: &Arc<
            parking_lot::RwLock<std::collections::VecDeque<ace_rpc::types::RpcTpsSample>>,
        >,
        consensus_wal: &mut ace_consensus::wal::ConsensusWal,
        prepared_block_cache: &mut std::collections::HashMap<[u8; 32], PreparedBlockExecution>,
        pending_proposal_validations: &mut std::collections::HashMap<[u8; 32], (u64, u32)>,
        pending_local_proposal_build: &mut Option<(u64, u32)>,
        pending_commit: &mut Option<PendingCommitApplication>,
        proposal_validation_tx: &mpsc::UnboundedSender<ConsensusLoopEvent>,
        proposal_tx_budget: &mut usize,
        consecutive_empty_proposals: &mut u32,
        node_tag: &u8,
        compact_block_cache: &mut std::collections::HashMap<
            [u8; 32],
            ace_runtime::types::block::Block,
        >,
        signed_precommits_for_cert: &mut Vec<ace_p2p::messages::NetworkPrecommit>,
        hfi_pay_state: Arc<ace_rpc::hfi_pay_rpc::HfiPayState>,
        hit_rate_ewma: &mut f64,
        budget_cooldown: &mut u32,
        healthy_streak: &mut u32,
    ) {
        match event {
            ConsensusLoopEvent::ProposalValidated { proposal, prepared } => {
                let block_hash = proposal.block.hash();
                pending_proposal_validations.remove(&block_hash);

                if proposal.height != engine.current_height() {
                    tracing::debug!(
                        current_height = engine.current_height(),
                        proposal_height = proposal.height,
                        proposal_round = proposal.round,
                        hash = hex::encode(&block_hash[..8]),
                        "[{node_tag}] Dropping validated proposal for stale height"
                    );
                    return;
                }

                let Some(prepared) = prepared else {
                    tracing::debug!(
                        height = proposal.height,
                        round = proposal.round,
                        hash = hex::encode(&block_hash[..8]),
                        "[{node_tag}] Async proposal validation rejected block"
                    );
                    return;
                };

                prepared_block_cache.insert(block_hash, prepared);
                if let Err(e) = consensus_wal.write(&ace_consensus::wal::WalEntry::Proposal {
                    height: proposal.height,
                    round: proposal.round,
                    block_hash,
                }) {
                    tracing::error!("FATAL: consensus WAL write failed: {:?}", e);
                    panic!("consensus WAL write failed — cannot guarantee safety");
                }
                let action = engine.on_proposal(
                    proposal.height,
                    proposal.round,
                    block_hash,
                    proposal.block,
                    proposal.valid_round,
                );
                self.execute_tendermint_action(
                    action,
                    engine,
                    local_id,
                    local_signing_key,
                    state,
                    block_store,
                    tx_receipt_store,
                    eth_events,
                    mempool,
                    net_outbound_tx,
                    consensus_outbound_tx,
                    verifier,
                    allow_mock_fc,
                    governance,
                    persistence,
                    genesis_hash,
                    genesis_time_ms,
                    latest_block_slot,
                    state_root_hex,
                    tps_samples,
                    consensus_wal,
                    prepared_block_cache,
                    pending_commit,
                    proposal_validation_tx,
                    signed_precommits_for_cert,
                    Arc::clone(&hfi_pay_state),
                )
                .await;
                Self::maybe_start_pending_commit_application(
                    engine,
                    state,
                    block_store,
                    governance,
                    genesis_time_ms,
                    prepared_block_cache,
                    pending_commit,
                    proposal_validation_tx,
                );
            }
            ConsensusLoopEvent::LocalProposalBuilt {
                height,
                round,
                budget,
                build_ms,
                requeue_txs,
                prepared,
            } => {
                if *pending_local_proposal_build == Some((height, round)) {
                    *pending_local_proposal_build = None;
                }
                if build_ms > 0 {
                    let tx_count = prepared
                        .as_ref()
                        .map(|prepared| prepared.block.transactions.len())
                        .unwrap_or(budget);
                    if tx_count > 0 {
                        // First non-empty block after idle: counter was already
                        // used to reset proposal_tx_budget before this build
                        // started (see the idle-reset block in the propose path).
                        *consecutive_empty_proposals = 0;

                        let target_ms = ace_runtime::config::PROPOSAL_BUILD_TARGET_MS;
                        let new_budget = if build_ms > target_ms {
                            // Over budget: scale down proportionally
                            (tx_count as u64)
                                .saturating_mul(target_ms)
                                .checked_div(build_ms)
                                .unwrap_or(budget as u64) as usize
                        } else {
                            // Under budget: allow up to 50% growth based on
                            // ACTUAL tx count, not the budget.  This prevents
                            // the budget from ballooning during low-traffic
                            // periods (e.g. 8 prepare txs building in 5ms
                            // would erroneously inflate budget to 2000).
                            // 3/2 (vs old 5/4) reaches MAX_BUDGET in ~5 blocks
                            // instead of ~7 after a reset, without overshoot risk.
                            let max_growth = tx_count * 3 / 2;
                            let ideal = (tx_count as u64)
                                .saturating_mul(target_ms)
                                .checked_div(build_ms)
                                .unwrap_or(budget as u64)
                                as usize;
                            ideal.min(max_growth)
                        };
                        *proposal_tx_budget = new_budget
                            .max(ace_runtime::config::PROPOSAL_TX_INITIAL_BUDGET)
                            .min(ace_runtime::config::PROPOSAL_TX_MAX_BUDGET);
                    } else {
                        // Empty block: track idle streak.
                        *consecutive_empty_proposals =
                            consecutive_empty_proposals.saturating_add(1);
                    }
                }
                {
                    let tx_count = prepared
                        .as_ref()
                        .map(|p| p.block.transactions.len())
                        .unwrap_or(0);
                    crate::metrics::record_proposal_build(build_ms, budget, tx_count);
                }
                tracing::info!(
                    height,
                    round,
                    budget,
                    new_budget = *proposal_tx_budget,
                    build_ms,
                    "Proposal build timing"
                );

                let is_current_round = height == engine.current_height()
                    && round == engine.current_round()
                    && engine.current_step() == ace_consensus::RoundStep::Propose
                    && engine.is_proposer(height, round)
                    && !engine.tendermint.has_proposal();

                match prepared {
                    Ok(prepared_proposal) => {
                        if !is_current_round {
                            tracing::warn!(
                                height,
                                round,
                                build_ms,
                                current_height = engine.current_height(),
                                current_round = engine.current_round(),
                                current_step = ?engine.current_step(),
                                tx_count = prepared_proposal.block.transactions.len(),
                                "Discarding stale local proposal (round advanced during build)"
                            );
                            if prepared_proposal.block.mev_ace.is_none() {
                                Self::requeue_transactions(
                                    mempool,
                                    prepared_proposal.block.transactions,
                                );
                            }
                            return;
                        }

                        let block = prepared_proposal.block;
                        let block_hash = block.hash();
                        prepared_block_cache.insert(block_hash, prepared_proposal.execution);
                        tracing::debug!(
                            height,
                            round,
                            tx_count = block.transactions.len(),
                            hash = hex::encode(&block_hash[..8]),
                            "[{node_tag}] Produced proposal"
                        );

                        let proposal_sign_msg = proposal_sign_message(
                            height,
                            round,
                            &block_hash,
                            local_id,
                            self.config.chain_id,
                        );
                        let proposal_sig = local_signing_key.sign(&proposal_sign_msg);
                        let action =
                            engine.on_proposal(height, round, block_hash, block.clone(), None);

                        // Send compact proposal (tx hashes only) instead of full block.
                        // Store full block so we can serve TxFetch requests from receivers.
                        let tx_hashes: Vec<[u8; 32]> =
                            block.transactions.iter().map(|tx| tx.tx_hash()).collect();
                        let tx_wire_hashes: Vec<[u8; 32]> =
                            block.transactions.iter().map(|tx| tx.wire_hash()).collect();
                        compact_block_cache.insert(block_hash, block.clone());
                        if let Err(error) = consensus_outbound_tx
                            .send(NetworkMessage::CompactProposal(CompactNetworkProposal {
                                height,
                                round,
                                header: block.header.clone(),
                                tx_hashes,
                                tx_wire_hashes,
                                mev_ace: block.mev_ace.clone(),
                                valid_round: None,
                                proposer: local_id.0,
                                signature: proposal_sig,
                                chain_id: self.config.chain_id,
                                proposer_peer_id: None,
                            }))
                            .await
                        {
                            warn!(
                                height,
                                round,
                                %error,
                                "Failed to enqueue compact proposal for broadcast"
                            );
                        }

                        self.execute_tendermint_action(
                            action,
                            engine,
                            local_id,
                            local_signing_key,
                            state,
                            block_store,
                            tx_receipt_store,
                            eth_events,
                            mempool,
                            net_outbound_tx,
                            consensus_outbound_tx,
                            verifier,
                            allow_mock_fc,
                            governance,
                            persistence,
                            genesis_hash,
                            genesis_time_ms,
                            latest_block_slot,
                            state_root_hex,
                            tps_samples,
                            consensus_wal,
                            prepared_block_cache,
                            pending_commit,
                            proposal_validation_tx,
                            signed_precommits_for_cert,
                            Arc::clone(&hfi_pay_state),
                        )
                        .await;
                    }
                    Err(error) => {
                        Self::requeue_transactions(mempool, requeue_txs);
                        warn!(height, round, %error, "Block production (proposal) failed");
                    }
                }
            }
            ConsensusLoopEvent::CommitBlockPrepared {
                height,
                round,
                block,
                prepared,
            } => {
                let block_hash = block.hash();
                engine.proposals.entry(block_hash).or_insert(block);
                if let Some(prepared) = prepared {
                    prepared_block_cache.insert(block_hash, prepared);
                    Self::maybe_start_pending_commit_application(
                        engine,
                        state,
                        block_store,
                        governance,
                        genesis_time_ms,
                        prepared_block_cache,
                        pending_commit,
                        proposal_validation_tx,
                    );
                } else {
                    warn!(
                        height,
                        round,
                        hash = hex::encode(&block_hash[..8]),
                        "Failed to prepare committed block asynchronously"
                    );
                }
            }
            ConsensusLoopEvent::CommitFinalized {
                height,
                round,
                block_hash,
                result,
            } => {
                let Some(active_pending_commit) = pending_commit.take() else {
                    tracing::debug!(
                        height,
                        round,
                        hash = hex::encode(&block_hash[..8]),
                        "[{node_tag}] Dropping finalized commit without pending state"
                    );
                    return;
                };
                if active_pending_commit.block_hash != block_hash {
                    *pending_commit = Some(active_pending_commit);
                    tracing::debug!(
                        height,
                        round,
                        hash = hex::encode(&block_hash[..8]),
                        "[{node_tag}] Dropping finalized commit for stale block hash"
                    );
                    return;
                }

                let finalized = match result {
                    Ok(finalized) => finalized,
                    Err(error) => {
                        warn!(
                            height,
                            round,
                            hash = hex::encode(&block_hash[..8]),
                            %error,
                            "Failed to finalize committed Tendermint block"
                        );
                        return;
                    }
                };

                let FinalizedCommit {
                    block,
                    snapshot,
                    post_commit_state,
                    governance: committed_governance,
                    rpc_receipts,
                } = finalized;
                let block_hash = block.hash();
                {
                    let mut state_guard = state.write();
                    *state_guard = post_commit_state;
                }
                governance.replace_from_preview(committed_governance);
                if let Err(error) =
                    engine.rebuild_full_validator_set(&governance.approved_validators())
                {
                    tracing::error!(
                        %error,
                        height,
                        "failed to rebuild validator set after commit"
                    );
                    return;
                }
                sync_effective_validator_set(
                    engine,
                    governance,
                    slot_time_ms(genesis_time_ms, block.header.slot),
                );
                engine.store_snapshot(block.header.slot, snapshot);
                engine.last_block_hash = block_hash;

                for tx in &block.transactions {
                    let tx_hash = tx.tx_hash();
                    let _ = mempool.remove(&tx_hash);
                }

                // Prometheus metrics
                {
                    let tx_total = block.header.tx_count;
                    let tx_success = rpc_receipts.iter().filter(|r| r.status).count() as u32;
                    crate::metrics::record_block_committed(tx_total, tx_success, height);
                    crate::metrics::record_consensus_round(round);
                    // Per-algorithm success counters for TPS chart algo split.
                    // block.transactions[i] and rpc_receipts[i] are in the same order.
                    let ed_ok = block
                        .transactions
                        .iter()
                        .zip(rpc_receipts.iter())
                        .filter(|(tx, r)| {
                            r.status
                                && tx.attestation.credential.algorithm
                                    == ace_runtime::crypto::SignatureAlgorithm::Ed25519
                        })
                        .count() as u32;
                    let pqc_ok = block
                        .transactions
                        .iter()
                        .zip(rpc_receipts.iter())
                        .filter(|(tx, r)| {
                            r.status
                                && tx.attestation.credential.algorithm
                                    == ace_runtime::crypto::SignatureAlgorithm::MlDsa44
                        })
                        .count() as u32;
                    crate::metrics::record_txs_success_by_algo("ed25519", ed_ok);
                    crate::metrics::record_txs_success_by_algo("ml-dsa-44", pqc_ok);
                    crate::metrics::set_mempool_size(
                        mempool.pending_count(),
                        mempool.ready_count(),
                    );
                }

                tx_receipt_store.write().put_receipts(rpc_receipts.clone());
                block_store.write().put_block(block.clone());
                publish_eth_block_events(eth_events, &block, &rpc_receipts);
                let (persist_state, persist_cert) =
                    sanitize_sync_finality(Some(FinalityState::Soft), &None, &block, verifier);
                persist_block_finality(block_store, block.header.slot, persist_state, persist_cert);
                // Persist state + governance after every commit so restarts
                // never see a gap between block store and state DB.
                persistence.persist_tree_async(state, genesis_hash, genesis_time_ms);
                if let Err(e) = governance.persist() {
                    warn!(height, %e, "Failed to persist governance after commit");
                }
                prepared_block_cache.retain(|_, prepared| prepared.height > height);

                latest_block_slot.store(height, std::sync::atomic::Ordering::Relaxed);
                *state_root_hex.write() = hex::encode(block.header.state_root);

                let committed_tx_ok;
                {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let sample_time = if block.header.timestamp > 0 {
                        block.header.timestamp
                    } else {
                        now_ms
                    };
                    let success_count = rpc_receipts.iter().filter(|r| r.status).count() as u32;
                    committed_tx_ok = success_count;

                    let mut fail_slot = 0_u32;
                    let mut fail_nonce = 0_u32;
                    let mut fail_sender = 0_u32;
                    let mut fail_balance = 0_u32;
                    let mut fail_other = 0_u32;
                    for receipt in rpc_receipts.iter().filter(|receipt| !receipt.status) {
                        match classify_tx_failure(receipt.error.as_deref()) {
                            TxFailureKind::Slot => fail_slot += 1,
                            TxFailureKind::Nonce => fail_nonce += 1,
                            TxFailureKind::Sender => fail_sender += 1,
                            TxFailureKind::Balance => fail_balance += 1,
                            TxFailureKind::Other => fail_other += 1,
                        }
                    }

                    let mut samples = tps_samples.write();
                    let tps_val = if let Some(prev) = samples.back() {
                        let dt_ms = sample_time.saturating_sub(prev.time);
                        if dt_ms > 0 {
                            (success_count as f64 / dt_ms as f64) * 1000.0
                        } else {
                            0.0
                        }
                    } else {
                        0.0
                    };
                    // Structured per-block TPS log for offline analysis.
                    // grep "BLOCK_COMMITTED" node-1.log | to extract raw data.
                    tracing::info!(
                        tag = "BLOCK_COMMITTED",
                        height,
                        round,
                        tx_total = block.header.tx_count,
                        tx_ok = success_count,
                        fail_slot,
                        fail_nonce,
                        fail_sender,
                        fail_balance,
                        fail_other,
                        timestamp_ms = sample_time,
                        tps = format_args!("{:.1}", tps_val),
                        mempool_pending = mempool.pending_count(),
                        mempool_ready = mempool.ready_count(),
                        "[{node_tag}] block committed"
                    );
                    samples.push_back(ace_rpc::types::RpcTpsSample {
                        time: sample_time,
                        tps: (tps_val * 10.0).round() / 10.0,
                    });
                    while samples.len() > 300 {
                        samples.pop_front();
                    }
                }

                // Update dynamic admission watermarks based on effective throughput (tx_ok),
                // not raw tx_total.  Using tx_total here would cause the mempool to
                // overestimate capacity when blocks contain many execution failures
                // (invalid nonce / slot expired), delaying recovery from bad states.
                mempool.record_committed_block(
                    committed_tx_ok as usize,
                    block.header.tx_count as usize,
                );

                // Compact-proposal budget recovery.
                // Decrement cooldown every committed block regardless of health.
                if *budget_cooldown > 0 {
                    *budget_cooldown -= 1;
                }
                // Attempt recovery when a sustained healthy window is observed.
                // Uses committed block's `round` (not current engine round) to
                // avoid async timing confusion across height boundaries.
                if *proposal_tx_budget < ace_runtime::config::PROPOSAL_TX_MAX_BUDGET {
                    let pending = mempool.pending_count();
                    let ready = mempool.ready_count();
                    // Require pending > 0 so idle periods (empty mempool) cannot
                    // satisfy ready_ok trivially and drive budget recovery.
                    let pending_ok = pending > 0 && pending <= *proposal_tx_budget * 2;
                    let ready_ok = ready >= (*proposal_tx_budget * 4 / 5).min(pending);
                    let consensus_ok = round == 0;
                    let ewma_ok = *hit_rate_ewma >= 0.95;
                    if *healthy_streak >= ace_runtime::config::HEALTHY_STREAK_THRESHOLD
                        && pending_ok
                        && ready_ok
                        && consensus_ok
                        && ewma_ok
                    {
                        let old_budget = *proposal_tx_budget;
                        *proposal_tx_budget = (*proposal_tx_budget
                            + ace_runtime::config::BUDGET_RECOVERY_STEP)
                            .min(ace_runtime::config::PROPOSAL_TX_MAX_BUDGET);
                        *healthy_streak = 0;
                        tracing::info!(
                            height,
                            round,
                            old_budget,
                            new_budget = *proposal_tx_budget,
                            hit_rate_ewma = (*hit_rate_ewma * 100.0) as u32,
                            healthy_streak = 0_u32,
                            "Recovering local proposal budget after healthy compact proposals"
                        );
                    }
                }

                // Broadcast CommitCertificate so peers stuck at this height
                // can verify the quorum and commit without waiting for
                // individual precommit messages.
                {
                    // Ensure local precommit is in the buffer.
                    // Dedup by (voter, round): if we're committing at round R, a round-<R
                    // entry for local_id would otherwise block this insertion, leaving the
                    // cert filter (height/round/hash) with zero matching precommits.
                    if !signed_precommits_for_cert
                        .iter()
                        .any(|p| p.voter == local_id.0 && p.round == round)
                    {
                        let sign_msg = precommit_sign_message(
                            height,
                            round,
                            &block_hash,
                            &local_id,
                            self.config.chain_id,
                        );
                        let sig = local_signing_key.sign(&sign_msg);
                        let local_stake = engine
                            .validator_set
                            .get_by_id(&local_id)
                            .map_or(0, |v| v.stake);
                        signed_precommits_for_cert.push(ace_p2p::messages::NetworkPrecommit {
                            height,
                            round,
                            block_hash,
                            voter: local_id.0,
                            voter_stake: local_stake,
                            signature: sig,
                            chain_id: self.config.chain_id,
                        });
                    }
                    // Filter to only precommits for this exact commit certificate.
                    let cert_precommits: Vec<_> = signed_precommits_for_cert
                        .iter()
                        .filter(|p| {
                            p.height == height && p.round == round && p.block_hash == block_hash
                        })
                        .cloned()
                        .collect();
                    if cert_precommits.len() < 2 {
                        tracing::warn!(
                            height,
                            round,
                            total_buffer = signed_precommits_for_cert.len(),
                            matching = cert_precommits.len(),
                            hash = hex::encode(&block_hash[..8]),
                            "CommitCertificate has fewer than 2 precommits"
                        );
                    }
                    if !cert_precommits.is_empty() {
                        let cert = ace_p2p::messages::CommitCertificate {
                            height,
                            round,
                            block_hash,
                            chain_id: self.config.chain_id,
                            precommits: cert_precommits,
                        };
                        if let Err(e) = consensus_outbound_tx
                            .send(NetworkMessage::CommitCertificate(cert))
                            .await
                        {
                            tracing::warn!(height, %e, "Failed to broadcast CommitCertificate");
                        }
                    }
                }

                self.maybe_emit_finality_cert(
                    height,
                    engine,
                    state,
                    block_store,
                    tx_receipt_store,
                    eth_events,
                    mempool,
                    net_outbound_tx,
                    verifier,
                    allow_mock_fc,
                    governance,
                    persistence,
                    genesis_hash,
                    genesis_time_ms,
                )
                .await;
            }
        }
    }

    /// Shared logic for processing a verified full proposal (from either full
    /// or compact proposal path).  Handles buffering, dedup, and async validation.
    #[allow(clippy::too_many_arguments)]
    fn process_full_proposal<B: BlockStore + 'static>(
        &self,
        proposal: NetworkProposal,
        engine: &mut ConsensusEngine,
        prepared_block_cache: &mut std::collections::HashMap<[u8; 32], PreparedBlockExecution>,
        pending_proposal_validations: &mut std::collections::HashMap<[u8; 32], (u64, u32)>,
        proposal_validation_tx: &mpsc::UnboundedSender<ConsensusLoopEvent>,
        governance: &mut RuntimeGovernance,
        genesis_time_ms: u64,
        state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        block_store: &Arc<RwLock<B>>,
        _node_tag: &u8,
        future_round_proposals: &mut std::collections::HashMap<u32, NetworkProposal>,
        next_height_proposal: &mut Option<NetworkProposal>,
        hfi_pay_state: Arc<ace_rpc::hfi_pay_rpc::HfiPayState>,
    ) {
        let block_hash = proposal.block.hash();

        // Buffer a proposal for the next height.
        if proposal.height == engine.current_height() + 1 && proposal.round == 0 {
            tracing::debug!(
                height = proposal.height,
                current_height = engine.current_height(),
                "Buffering next-height proposal"
            );
            *next_height_proposal = Some(proposal);
            return;
        }

        // Buffer proposals for future rounds at the same height.
        if proposal.height == engine.current_height() && proposal.round > engine.current_round() {
            let max_buffered_round = engine
                .current_round()
                .saturating_add(MAX_BUFFERED_FUTURE_ROUNDS);
            if proposal.round > max_buffered_round {
                tracing::warn!(
                    height = proposal.height,
                    proposal_round = proposal.round,
                    current_round = engine.current_round(),
                    max_buffered_round,
                    "Dropping far-future proposal beyond buffer window"
                );
                return;
            }
            tracing::debug!(
                height = proposal.height,
                proposal_round = proposal.round,
                current_round = engine.current_round(),
                "Buffering future-round proposal"
            );
            future_round_proposals.insert(proposal.round, proposal);
            return;
        }

        // Validate proposals asynchronously so the consensus loop can
        // keep processing votes and timeouts even under heavy blocks.
        if proposal.height == engine.current_height() && proposal.round == engine.current_round() {
            if prepared_block_cache.contains_key(&block_hash)
                || pending_proposal_validations.contains_key(&block_hash)
                || engine.proposals.contains_key(&block_hash)
            {
                return;
            }

            pending_proposal_validations.insert(block_hash, (proposal.height, proposal.round));
            let parent_stored_root = block_store
                .read()
                .get_block_by_hash(&proposal.block.header.parent_hash)
                .map(|b| b.header.state_root);
            Self::spawn_proposal_validation_task(
                proposal,
                Arc::clone(state),
                Arc::clone(block_store),
                engine.validator_set.clone(),
                engine.last_block_hash,
                governance.clone_for_preview(),
                genesis_time_ms,
                parent_stored_root,
                Arc::clone(&hfi_pay_state),
                self.config.mev_ace_activation_slot,
                self.config.mev_ace_full_activation_slot,
                proposal_validation_tx.clone(),
            );
        }
    }

    /// Returns `true` if the reconstruction deadline has not yet passed and
    /// another TxFetch attempt should be sent, `false` if we should abandon.
    fn tx_fetch_within_deadline(pending: &PendingCompactReconstruction) -> bool {
        if tokio::time::Instant::now() >= pending.reconstruct_deadline {
            tracing::warn!(
                height = pending.compact_proposal.height,
                round = pending.compact_proposal.round,
                hash = hex::encode(&pending.block_hash[..8]),
                attempts = pending.attempts,
                budget_ms = ace_runtime::config::TX_FETCH_RECONSTRUCT_BUDGET_MS,
                "Abandoning compact proposal: reconstruction budget exhausted"
            );
            false
        } else {
            true
        }
    }

    fn queue_tx_fetch_request(
        pending: &mut PendingCompactReconstruction,
        tx_fetch_cmd_tx: &mpsc::Sender<ace_p2p::TxFetchCommand>,
    ) -> bool {
        match tx_fetch_cmd_tx.try_send(ace_p2p::TxFetchCommand {
            peer_id: pending.proposer_peer_id.clone(),
            request: TxFetchRequest::CompactBlock {
                block_hash: pending.block_hash,
                tx_hashes: pending.missing_hashes.clone(),
            },
        }) {
            Ok(()) => {
                pending.attempts = pending.attempts.saturating_add(1);
                pending.request_sent = tokio::time::Instant::now();
                true
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    height = pending.compact_proposal.height,
                    round = pending.compact_proposal.round,
                    hash = hex::encode(&pending.block_hash[..8]),
                    "Dropping compact proposal: tx-fetch command queue is full"
                );
                false
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                warn!(
                    height = pending.compact_proposal.height,
                    round = pending.compact_proposal.round,
                    hash = hex::encode(&pending.block_hash[..8]),
                    "Dropping compact proposal: tx-fetch service channel is closed"
                );
                false
            }
        }
    }

    /// Handle a high-priority consensus message (Proposal, Prevote, Precommit).
    #[allow(clippy::too_many_arguments)]
    async fn handle_consensus_message<B: BlockStore + 'static>(
        &self,
        msg: NetworkMessage,
        engine: &mut ConsensusEngine,
        local_id: &AccountId,
        local_signing_key: &LocalSigningKey,
        state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        block_store: &Arc<RwLock<B>>,
        tx_receipt_store: &Arc<RwLock<TxReceiptStore>>,
        eth_events: &Arc<EthEventHub>,
        mempool: &Arc<Mempool>,
        net_outbound_tx: &mpsc::Sender<NetworkMessage>,
        consensus_outbound_tx: &mpsc::Sender<NetworkMessage>,
        verifier: &dyn ProofVerifier,
        allow_mock_fc: bool,
        governance: &mut RuntimeGovernance,
        persistence: &PersistenceHandles,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
        latest_block_slot: &Arc<AtomicU64>,
        state_root_hex: &Arc<RwLock<String>>,
        tps_samples: &Arc<
            parking_lot::RwLock<std::collections::VecDeque<ace_rpc::types::RpcTpsSample>>,
        >,
        consensus_wal: &mut ace_consensus::wal::ConsensusWal,
        node_tag: &u8,
        prepared_block_cache: &mut std::collections::HashMap<[u8; 32], PreparedBlockExecution>,
        proposal_validation_tx: &mpsc::UnboundedSender<ConsensusLoopEvent>,
        pending_proposal_validations: &mut std::collections::HashMap<[u8; 32], (u64, u32)>,
        pending_commit: &mut Option<PendingCommitApplication>,
        future_round_proposals: &mut std::collections::HashMap<u32, NetworkProposal>,
        next_height_proposal: &mut Option<NetworkProposal>,
        pending_compact_reconstructions: &mut std::collections::HashMap<
            [u8; 32],
            PendingCompactReconstruction,
        >,
        tx_fetch_cmd_tx: &mpsc::Sender<ace_p2p::TxFetchCommand>,
        signed_precommits_for_cert: &mut Vec<ace_p2p::messages::NetworkPrecommit>,
        hfi_pay_state: Arc<ace_rpc::hfi_pay_rpc::HfiPayState>,
        pending_credential_prefetch: &mut std::collections::HashMap<
            [u8; 32],
            PendingCredentialPrefetch,
        >,
        mempool_notify: &tokio::sync::Notify,
        proposal_tx_budget: &mut usize,
        hit_rate_ewma: &mut f64,
        severe_miss_streak: &mut u32,
        budget_cooldown: &mut u32,
        healthy_streak: &mut u32,
    ) {
        match msg {
            NetworkMessage::CompactProposal(compact_proposal) => {
                // Reconstruct full block from mempool, then process as normal proposal.
                let proposer = AccountId(compact_proposal.proposer);
                let expected_proposer =
                    engine.proposer_for(compact_proposal.height, compact_proposal.round);
                if proposer != expected_proposer {
                    tracing::debug!(
                        height = compact_proposal.height,
                        round = compact_proposal.round,
                        "Ignoring compact proposal from non-proposer"
                    );
                    return;
                }
                if !verify_compact_proposal(
                    engine,
                    &compact_proposal,
                    &expected_proposer,
                    self.config.chain_id,
                ) {
                    tracing::warn!(
                        height = compact_proposal.height,
                        round = compact_proposal.round,
                        "Rejecting invalid compact proposal"
                    );
                    return;
                }
                let block_hash = compact_proposal.header.hash();
                tracing::debug!(
                    height = compact_proposal.height,
                    round = compact_proposal.round,
                    tx_count = compact_proposal.tx_hashes.len(),
                    hash = hex::encode(&block_hash[..8]),
                    "[{node_tag}] Received CompactProposal"
                );

                // Skip if we already know about this block
                if prepared_block_cache.contains_key(&block_hash)
                    || pending_proposal_validations.contains_key(&block_hash)
                    || engine.proposals.contains_key(&block_hash)
                    || pending_compact_reconstructions.contains_key(&block_hash)
                {
                    return;
                }

                // Attempt to reconstruct full block from mempool
                let mut found_txs: Vec<Option<Transaction>> =
                    Vec::with_capacity(compact_proposal.tx_hashes.len());
                let mut missing_hashes: Vec<[u8; 32]> = Vec::new();
                let mut mismatched_wire_hashes = 0usize;
                for (tx_hash, tx_wire_hash) in compact_proposal
                    .tx_hashes
                    .iter()
                    .zip(&compact_proposal.tx_wire_hashes)
                {
                    if let Some(tx) = mempool.get(tx_hash) {
                        if tx.wire_hash() == *tx_wire_hash {
                            found_txs.push(Some(tx));
                        } else {
                            found_txs.push(None);
                            missing_hashes.push(*tx_hash);
                            mismatched_wire_hashes += 1;
                        }
                    } else {
                        found_txs.push(None);
                        missing_hashes.push(*tx_hash);
                    }
                }

                let total = compact_proposal.tx_hashes.len();
                let missing = missing_hashes.len();
                let hit = total.saturating_sub(missing);
                let current_hit_rate = if total > 0 {
                    hit as f64 / total as f64
                } else {
                    1.0_f64
                };

                // Update EWMA unconditionally — both hit and miss paths feed the filter.
                // α=0.2: last ~4-5 blocks weighted, stable against single-block spikes.
                *hit_rate_ewma = (1.0 - ace_runtime::config::HIT_RATE_EWMA_ALPHA) * *hit_rate_ewma
                    + ace_runtime::config::HIT_RATE_EWMA_ALPHA * current_hit_rate;

                let hit_rate_pct = (current_hit_rate * 100.0) as u32;
                let ewma_pct = (*hit_rate_ewma * 100.0) as u32;

                tracing::info!(
                    height = compact_proposal.height,
                    round = compact_proposal.round,
                    total,
                    missing,
                    mismatched_wire_hashes,
                    hit_rate = hit_rate_pct,
                    hit_rate_ewma = ewma_pct,
                    "Compact proposal mempool reconstruction"
                );

                if missing_hashes.is_empty() {
                    // Full hit: update healthy streak only for non-empty compact proposals.
                    // Empty proposals (total==0) resolve to full hit trivially and must not
                    // advance the healthy streak — doing so would allow budget recovery
                    // during idle periods and undermine the idle-reset conservative semantics.
                    if total > 0 {
                        *healthy_streak = healthy_streak.saturating_add(1);
                    }
                    *severe_miss_streak = 0;

                    let transactions: Vec<Transaction> =
                        found_txs.into_iter().map(|t| t.unwrap()).collect();
                    let block = ace_runtime::types::block::Block {
                        header: compact_proposal.header.clone(),
                        transactions,
                        mev_ace: compact_proposal.mev_ace.clone(),
                    };
                    let full_proposal = NetworkProposal {
                        height: compact_proposal.height,
                        round: compact_proposal.round,
                        block,
                        valid_round: compact_proposal.valid_round,
                        proposer: compact_proposal.proposer,
                        signature: compact_proposal.signature.clone(),
                        chain_id: compact_proposal.chain_id,
                    };
                    // Buffer/validate logic same as full proposal
                    self.process_full_proposal(
                        full_proposal,
                        engine,
                        prepared_block_cache,
                        pending_proposal_validations,
                        proposal_validation_tx,
                        governance,
                        genesis_time_ms,
                        state,
                        block_store,
                        node_tag,
                        future_round_proposals,
                        next_height_proposal,
                        Arc::clone(&hfi_pay_state),
                    );
                } else {
                    // Miss path: apply EWMA-based graduated budget feedback.
                    // EWMA and streak counters are always updated even during cooldown;
                    // only the budget write is suppressed to prevent rapid re-adjustment
                    // on the same miss cluster.
                    *healthy_streak = 0;

                    let old_budget = *proposal_tx_budget;

                    // Severe condition requires BOTH current block and EWMA to be poor,
                    // filtering proposer-switch / TxFetch jitter from true degradation.
                    // Non-severe miss resets the streak so it counts only consecutive
                    // severe blocks — matching the SEVERE_MISS_STREAK_THRESHOLD semantics.
                    let is_severe_block = current_hit_rate < 0.70 && *hit_rate_ewma < 0.85;
                    if is_severe_block {
                        *severe_miss_streak = severe_miss_streak.saturating_add(1);
                    } else {
                        *severe_miss_streak = 0;
                    }

                    if *budget_cooldown > 0 {
                        // Cooldown active: skip budget write, log observation only.
                        tracing::warn!(
                            height = compact_proposal.height,
                            round = compact_proposal.round,
                            total,
                            missing,
                            hit_rate = hit_rate_pct,
                            hit_rate_ewma = ewma_pct,
                            budget = old_budget,
                            severe_miss_streak = *severe_miss_streak,
                            budget_cooldown = *budget_cooldown,
                            "Compact budget miss observed (cooldown active)"
                        );
                    } else {
                        // Apply graduated penalty based on EWMA.
                        let new_budget = if *hit_rate_ewma >= 0.95 {
                            // Healthy EWMA — minor miss noise, no change.
                            *severe_miss_streak = 0;
                            old_budget
                        } else if *hit_rate_ewma >= 0.85 {
                            // Mild degradation — filter, no penalty.
                            old_budget
                        } else if *hit_rate_ewma >= 0.70 {
                            // Moderate miss: reduce ~10%, floor at normal.
                            let reduced = (old_budget as f64 * 0.9) as usize;
                            reduced
                                .max(ace_runtime::config::PROPOSAL_TX_NORMAL_FLOOR)
                                .min(old_budget)
                        } else {
                            // Severe EWMA: only drop to emergency after streak threshold.
                            if *severe_miss_streak
                                >= ace_runtime::config::SEVERE_MISS_STREAK_THRESHOLD
                            {
                                ace_runtime::config::PROPOSAL_TX_EMERGENCY_FLOOR
                            } else {
                                let reduced = (old_budget as f64 * 0.75) as usize;
                                reduced
                                    .max(ace_runtime::config::PROPOSAL_TX_NORMAL_FLOOR)
                                    .min(old_budget)
                            }
                        };

                        if new_budget < old_budget {
                            *proposal_tx_budget = new_budget;
                            *budget_cooldown = ace_runtime::config::BUDGET_COOLDOWN_BLOCKS;
                            tracing::warn!(
                                height = compact_proposal.height,
                                round = compact_proposal.round,
                                total,
                                missing,
                                hit_rate = hit_rate_pct,
                                hit_rate_ewma = ewma_pct,
                                old_budget,
                                new_budget,
                                severe_miss_streak = *severe_miss_streak,
                                budget_cooldown = *budget_cooldown,
                                healthy_streak = *healthy_streak,
                                "Reducing local proposal budget after compact proposal miss"
                            );
                        }
                    }

                    // Missing transactions: request from proposer
                    let Some(proposer_peer_id) = compact_proposal.proposer_peer_id.clone() else {
                        tracing::warn!(
                            height = compact_proposal.height,
                            round = compact_proposal.round,
                            hash = hex::encode(&block_hash[..8]),
                            "Dropping compact proposal: authenticated proposer peer id missing"
                        );
                        return;
                    };
                    let reconstruct_deadline = tokio::time::Instant::now()
                        + std::time::Duration::from_millis(
                            ace_runtime::config::TX_FETCH_RECONSTRUCT_BUDGET_MS,
                        );
                    let mut pending = PendingCompactReconstruction {
                        block_hash,
                        compact_proposal,
                        found_txs,
                        missing_hashes,
                        proposer_peer_id,
                        attempts: 0,
                        request_sent: tokio::time::Instant::now(),
                        reconstruct_deadline,
                    };
                    if Self::queue_tx_fetch_request(&mut pending, tx_fetch_cmd_tx) {
                        pending_compact_reconstructions.insert(block_hash, pending);
                    }
                }
            }
            NetworkMessage::TxFetchResponse(response) => {
                match response {
                    // Credential prefetch response: upgrade stripped PQC txs to full credential.
                    ace_p2p::messages::TxFetchResponse::Mempool { transactions_wire } => {
                        let mut upgraded = 0usize;
                        for wire in transactions_wire {
                            let full_tx = match Transaction::from_bytes(&wire) {
                                Ok(t) => t,
                                Err(e) => {
                                    tracing::warn!(
                                        err = e,
                                        "credential prefetch: invalid wire bytes"
                                    );
                                    continue;
                                }
                            };
                            let tx_hash = full_tx.tx_hash();
                            let Some(pending) = pending_credential_prefetch.get(&tx_hash) else {
                                tracing::debug!(
                                    tx_hash = hex::encode(tx_hash),
                                    "credential prefetch: ignoring unexpected tx"
                                );
                                continue;
                            };
                            if !credential_matches_commitment(&full_tx, &pending.commitment) {
                                tracing::warn!(
                                    tx_hash = hex::encode(tx_hash),
                                    "credential prefetch: commitment mismatch"
                                );
                                continue;
                            }
                            match mempool.insert(full_tx.clone()) {
                                Ok(_) => {
                                    pending_credential_prefetch.remove(&tx_hash);
                                    upgraded += 1;
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        err = %e,
                                        "credential prefetch: mempool insert"
                                    );
                                }
                            }
                        }
                        if upgraded > 0 {
                            tracing::debug!(
                                upgraded,
                                pending = pending_credential_prefetch.len(),
                                "Credential prefetch: upgraded PQC txs to full credential"
                            );
                            mempool_notify.notify_one();
                        }
                    }
                    // Compact proposal reconstruction response.
                    ace_p2p::messages::TxFetchResponse::CompactBlock {
                        block_hash,
                        transactions_wire,
                    } => {
                        if let Some(mut pending) =
                            pending_compact_reconstructions.remove(&block_hash)
                        {
                            let fetch_ms = pending.request_sent.elapsed().as_millis() as u64;
                            tracing::info!(
                                height = pending.compact_proposal.height,
                                round = pending.compact_proposal.round,
                                fetched = transactions_wire.len(),
                                fetch_ms,
                                "Compact proposal reconstruction: fetched missing txs"
                            );
                            let mut fetched_map = std::collections::HashMap::new();
                            for wire in transactions_wire {
                                let tx = match Transaction::from_bytes(&wire) {
                                    Ok(t) => t,
                                    Err(e) => {
                                        tracing::warn!(
                                            err = e,
                                            wire_len = wire.len(),
                                            "tx-fetch response contained invalid transaction wire bytes"
                                        );
                                        continue;
                                    }
                                };
                                let _ = mempool.insert_preverified(tx.clone());
                                fetched_map.insert(tx.tx_hash(), tx);
                            }
                            for (i, tx_opt) in pending.found_txs.iter_mut().enumerate() {
                                if tx_opt.is_none() {
                                    let hash = &pending.compact_proposal.tx_hashes[i];
                                    if let Some(tx) = fetched_map.remove(hash) {
                                        *tx_opt = Some(tx);
                                    }
                                }
                            }
                            // Check if all transactions are now present
                            if pending.found_txs.iter().all(|t| t.is_some()) {
                                let transactions: Vec<Transaction> =
                                    pending.found_txs.into_iter().map(|t| t.unwrap()).collect();
                                let block = ace_runtime::types::block::Block {
                                    header: pending.compact_proposal.header.clone(),
                                    transactions,
                                    mev_ace: pending.compact_proposal.mev_ace.clone(),
                                };
                                let full_proposal = NetworkProposal {
                                    height: pending.compact_proposal.height,
                                    round: pending.compact_proposal.round,
                                    block,
                                    valid_round: pending.compact_proposal.valid_round,
                                    proposer: pending.compact_proposal.proposer,
                                    signature: pending.compact_proposal.signature.clone(),
                                    chain_id: pending.compact_proposal.chain_id,
                                };
                                self.process_full_proposal(
                                    full_proposal,
                                    engine,
                                    prepared_block_cache,
                                    pending_proposal_validations,
                                    proposal_validation_tx,
                                    governance,
                                    genesis_time_ms,
                                    state,
                                    block_store,
                                    node_tag,
                                    future_round_proposals,
                                    next_height_proposal,
                                    Arc::clone(&hfi_pay_state),
                                );
                            } else {
                                pending.missing_hashes = pending
                                    .compact_proposal
                                    .tx_hashes
                                    .iter()
                                    .enumerate()
                                    .filter_map(|(i, tx_hash)| {
                                        pending.found_txs[i].is_none().then_some(*tx_hash)
                                    })
                                    .collect();
                                tracing::warn!(
                                    height = pending.compact_proposal.height,
                                    round = pending.compact_proposal.round,
                                    remaining = pending.missing_hashes.len(),
                                    attempts = pending.attempts,
                                    "Compact proposal reconstruction still incomplete after fetch"
                                );
                                if pending.attempts < COMPACT_TX_FETCH_MAX_RETRIES
                                    && Self::tx_fetch_within_deadline(&pending)
                                    && Self::queue_tx_fetch_request(&mut pending, tx_fetch_cmd_tx)
                                {
                                    pending_compact_reconstructions.insert(block_hash, pending);
                                } else if pending.attempts >= COMPACT_TX_FETCH_MAX_RETRIES {
                                    tracing::warn!(
                                        height = pending.compact_proposal.height,
                                        round = pending.compact_proposal.round,
                                        hash = hex::encode(&block_hash[..8]),
                                        attempts = pending.attempts,
                                        "Abandoning compact proposal after tx-fetch retries were exhausted"
                                    );
                                }
                            }
                        } // end if-let pending block
                    } // end CompactBlock arm body
                } // end match response { ... }
            } // end TxFetchResponse match-arm body
            NetworkMessage::TxFetchFailure(TxFetchFailure {
                block_hash,
                peer_id,
                error,
            }) => {
                let Some(mut pending) = pending_compact_reconstructions.remove(&block_hash) else {
                    return;
                };
                if peer_id != pending.proposer_peer_id {
                    pending_compact_reconstructions.insert(block_hash, pending);
                    return;
                }
                tracing::warn!(
                    height = pending.compact_proposal.height,
                    round = pending.compact_proposal.round,
                    hash = hex::encode(&block_hash[..8]),
                    %peer_id,
                    attempts = pending.attempts,
                    error,
                    "Tx-fetch request failed"
                );
                if pending.attempts < COMPACT_TX_FETCH_MAX_RETRIES
                    && Self::tx_fetch_within_deadline(&pending)
                    && Self::queue_tx_fetch_request(&mut pending, tx_fetch_cmd_tx)
                {
                    pending_compact_reconstructions.insert(block_hash, pending);
                } else if pending.attempts >= COMPACT_TX_FETCH_MAX_RETRIES {
                    tracing::warn!(
                        height = pending.compact_proposal.height,
                        round = pending.compact_proposal.round,
                        hash = hex::encode(&block_hash[..8]),
                        attempts = pending.attempts,
                        "Abandoning compact proposal after tx-fetch retries were exhausted"
                    );
                }
            }
            NetworkMessage::Proposal(proposal) => {
                // Full proposal (legacy / fallback): verify and delegate to shared handler.
                let proposer = AccountId(proposal.proposer);
                let expected_proposer = engine.proposer_for(proposal.height, proposal.round);
                if proposer != expected_proposer {
                    tracing::debug!(
                        height = proposal.height,
                        round = proposal.round,
                        "Ignoring proposal from non-proposer"
                    );
                    return;
                }
                if !verify_tendermint_proposal(
                    &engine,
                    &proposal,
                    &expected_proposer,
                    self.config.chain_id,
                ) {
                    tracing::warn!(
                        height = proposal.height,
                        round = proposal.round,
                        proposer = hex::encode(&proposal.proposer[..4]),
                        "Rejecting unauthenticated Tendermint proposal"
                    );
                    return;
                }
                let block_hash = proposal.block.hash();
                tracing::debug!(
                    height = proposal.height,
                    round = proposal.round,
                    hash = hex::encode(&block_hash[..8]),
                    proposer = hex::encode(&proposal.proposer[..4]),
                    "[{node_tag}] Received full Proposal (legacy)"
                );
                self.process_full_proposal(
                    proposal,
                    engine,
                    prepared_block_cache,
                    pending_proposal_validations,
                    proposal_validation_tx,
                    governance,
                    genesis_time_ms,
                    state,
                    block_store,
                    node_tag,
                    future_round_proposals,
                    next_height_proposal,
                    Arc::clone(&hfi_pay_state),
                );
            }
            NetworkMessage::Prevote(pv) => {
                let voter = AccountId(pv.voter);
                let canonical_stake = engine
                    .validator_set
                    .get_by_id(&voter)
                    .map_or(0, |v| v.stake);
                if canonical_stake == 0 {
                    return; // unknown validator
                }
                if !verify_tendermint_prevote(&engine, &pv, self.config.chain_id) {
                    tracing::warn!(
                        height = pv.height,
                        round = pv.round,
                        voter = hex::encode(&pv.voter[..4]),
                        "Rejecting unauthenticated Tendermint prevote"
                    );
                    return;
                }
                tracing::debug!(
                    height = pv.height,
                    round = pv.round,
                    voter = hex::encode(&pv.voter[..4]),
                    hash = hex::encode(&pv.block_hash[..4]),
                    "[{node_tag}] Received prevote"
                );
                let action =
                    engine.on_prevote(pv.height, pv.round, pv.block_hash, voter, canonical_stake);
                self.execute_tendermint_action(
                    action,
                    engine,
                    local_id,
                    local_signing_key,
                    state,
                    block_store,
                    tx_receipt_store,
                    eth_events,
                    mempool,
                    net_outbound_tx,
                    consensus_outbound_tx,
                    verifier,
                    allow_mock_fc,
                    governance,
                    persistence,
                    genesis_hash,
                    genesis_time_ms,
                    latest_block_slot,
                    state_root_hex,
                    tps_samples,
                    consensus_wal,
                    prepared_block_cache,
                    pending_commit,
                    proposal_validation_tx,
                    signed_precommits_for_cert,
                    Arc::clone(&hfi_pay_state),
                )
                .await;
            }
            NetworkMessage::Precommit(pc) => {
                let voter = AccountId(pc.voter);
                let canonical_stake = engine
                    .validator_set
                    .get_by_id(&voter)
                    .map_or(0, |v| v.stake);
                if canonical_stake == 0 {
                    return;
                }
                if !verify_tendermint_precommit(&engine, &pc, self.config.chain_id) {
                    tracing::warn!(
                        height = pc.height,
                        round = pc.round,
                        voter = hex::encode(&pc.voter[..4]),
                        "Rejecting unauthenticated Tendermint precommit"
                    );
                    return;
                }
                tracing::debug!(
                    height = pc.height,
                    round = pc.round,
                    voter = hex::encode(&pc.voter[..4]),
                    hash = hex::encode(&pc.block_hash[..4]),
                    "[{node_tag}] Received precommit"
                );
                // Buffer the signed precommit for CommitCertificate construction.
                // Dedup by (voter, round): allow one precommit per validator per round so
                // that when consensus advances to a new round the new precommit is captured
                // instead of being silently dropped because an earlier-round entry exists.
                if pc.height == engine.current_height() {
                    if !signed_precommits_for_cert
                        .iter()
                        .any(|p| p.voter == pc.voter && p.round == pc.round)
                    {
                        signed_precommits_for_cert.push(pc.clone());
                    }
                }
                let action =
                    engine.on_precommit(pc.height, pc.round, pc.block_hash, voter, canonical_stake);
                self.execute_tendermint_action(
                    action,
                    engine,
                    local_id,
                    local_signing_key,
                    state,
                    block_store,
                    tx_receipt_store,
                    eth_events,
                    mempool,
                    net_outbound_tx,
                    consensus_outbound_tx,
                    verifier,
                    allow_mock_fc,
                    governance,
                    persistence,
                    genesis_hash,
                    genesis_time_ms,
                    latest_block_slot,
                    state_root_hex,
                    tps_samples,
                    consensus_wal,
                    prepared_block_cache,
                    pending_commit,
                    proposal_validation_tx,
                    signed_precommits_for_cert,
                    Arc::clone(&hfi_pay_state),
                )
                .await;
            }
            NetworkMessage::CommitCertificate(cert) => {
                let current_height = engine.current_height();
                if cert.height != current_height {
                    // Not relevant — we're either ahead or behind by more than 1.
                    // If behind by >1, block sync handles it.
                    return;
                }
                if engine.current_step() == ace_consensus::RoundStep::CommitWait
                    || engine.current_step() == ace_consensus::RoundStep::Committed
                {
                    // Already committed this height.
                    return;
                }
                if cert.chain_id != self.config.chain_id {
                    return;
                }
                if cert.block_hash == [0u8; 32] {
                    return;
                }

                // Verify each precommit signature and accumulate stake.
                let mut verified_stake: u64 = 0;
                let total_stake = engine.validator_set.total_stake();
                let mut seen_voters = std::collections::HashSet::new();
                for pc in &cert.precommits {
                    if pc.height != cert.height
                        || pc.round != cert.round
                        || pc.block_hash != cert.block_hash
                    {
                        continue;
                    }
                    let voter = AccountId(pc.voter);
                    if !seen_voters.insert(voter) {
                        continue; // duplicate voter
                    }
                    let Some(validator) = engine.validator_set.get_by_id(&voter) else {
                        continue;
                    };
                    if !verify_tendermint_precommit(engine, pc, self.config.chain_id) {
                        tracing::warn!(
                            height = cert.height,
                            voter = hex::encode(&pc.voter[..4]),
                            "CommitCertificate: rejecting precommit with bad signature"
                        );
                        continue;
                    }
                    verified_stake += validator.stake;
                }

                if !ace_runtime::config::has_quorum(verified_stake, total_stake) {
                    tracing::warn!(
                        height = cert.height,
                        verified_stake,
                        total_stake,
                        "CommitCertificate: insufficient quorum, ignoring"
                    );
                    return;
                }

                tracing::info!(
                    height = cert.height,
                    round = cert.round,
                    hash = hex::encode(&cert.block_hash[..8]),
                    precommits = cert.precommits.len(),
                    "[{node_tag}] Accepted CommitCertificate — fast-committing"
                );

                // Merge verified precommits into our buffer for future cert broadcasts.
                // Dedup by (voter, round): a stale entry from an earlier round must not
                // prevent a same-round precommit from being stored.
                for pc in &cert.precommits {
                    if pc.height == cert.height
                        && pc.round == cert.round
                        && pc.block_hash == cert.block_hash
                        && !signed_precommits_for_cert
                            .iter()
                            .any(|p| p.voter == pc.voter && p.round == pc.round)
                    {
                        signed_precommits_for_cert.push(pc.clone());
                    }
                }
                // Rebroadcast the received cert so other lagging peers benefit.
                let _ = consensus_outbound_tx
                    .send(NetworkMessage::CommitCertificate(cert.clone()))
                    .await;

                // Force the state machine into CommitWait.
                engine
                    .tendermint
                    .force_commit(cert.height, cert.round, cert.block_hash);
                *pending_commit = Some(PendingCommitApplication {
                    height: cert.height,
                    round: cert.round,
                    block_hash: cert.block_hash,
                    apply_started: false,
                });
                engine
                    .round_timer
                    .start_step(cert.round, ace_consensus::RoundStep::CommitWait);
                Self::maybe_start_pending_commit_application(
                    engine,
                    state,
                    block_store,
                    governance,
                    genesis_time_ms,
                    prepared_block_cache,
                    pending_commit,
                    proposal_validation_tx,
                );
                if pending_commit.as_ref().is_some_and(|p| !p.apply_started) {
                    if let Some(block) = engine
                        .proposals
                        .get(&cert.block_hash)
                        .cloned()
                        .or_else(|| block_store.read().get_block_by_hash(&cert.block_hash))
                    {
                        let parent_stored_root = block_store
                            .read()
                            .get_block_by_hash(&block.header.parent_hash)
                            .map(|b| b.header.state_root);
                        Self::spawn_commit_preparation_task(
                            block,
                            cert.height,
                            cert.round,
                            Arc::clone(state),
                            Arc::clone(block_store),
                            engine.validator_set.clone(),
                            engine.last_block_hash,
                            governance.clone_for_preview(),
                            genesis_time_ms,
                            parent_stored_root,
                            Arc::clone(&hfi_pay_state),
                            self.config.mev_ace_activation_slot,
                            self.config.mev_ace_full_activation_slot,
                            proposal_validation_tx.clone(),
                        );
                    }
                }
            }
            _ => {} // Other messages ignored here
        }
    }

    /// Execute a TendermintAction returned by the state machine.
    ///
    /// Handles: BroadcastPrevote, BroadcastPrecommit, Commit, ScheduleProposal.
    #[allow(clippy::too_many_arguments)]
    async fn execute_tendermint_action<B: BlockStore + 'static>(
        &self,
        action: ace_consensus::TendermintAction,
        engine: &mut ConsensusEngine,
        local_id: &AccountId,
        local_signing_key: &LocalSigningKey,
        state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        block_store: &Arc<RwLock<B>>,
        tx_receipt_store: &Arc<RwLock<TxReceiptStore>>,
        eth_events: &Arc<EthEventHub>,
        mempool: &Arc<Mempool>,
        net_outbound_tx: &mpsc::Sender<NetworkMessage>,
        consensus_outbound_tx: &mpsc::Sender<NetworkMessage>,
        verifier: &dyn ProofVerifier,
        allow_mock_fc: bool,
        governance: &mut RuntimeGovernance,
        persistence: &PersistenceHandles,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
        latest_block_slot: &Arc<AtomicU64>,
        state_root_hex: &Arc<RwLock<String>>,
        tps_samples: &Arc<
            parking_lot::RwLock<std::collections::VecDeque<ace_rpc::types::RpcTpsSample>>,
        >,
        consensus_wal: &mut ace_consensus::wal::ConsensusWal,
        prepared_block_cache: &mut std::collections::HashMap<[u8; 32], PreparedBlockExecution>,
        pending_commit: &mut Option<PendingCommitApplication>,
        proposal_validation_tx: &mpsc::UnboundedSender<ConsensusLoopEvent>,
        signed_precommits_for_cert: &mut Vec<ace_p2p::messages::NetworkPrecommit>,
        hfi_pay_state: Arc<ace_rpc::hfi_pay_rpc::HfiPayState>,
    ) {
        use ace_consensus::TendermintAction;

        match action {
            TendermintAction::None => {}

            TendermintAction::BroadcastPrevote {
                height,
                round,
                block_hash,
            } => {
                tracing::debug!(
                    height,
                    round,
                    hash = hex::encode(&block_hash[..4]),
                    "Broadcasting prevote"
                );
                // Sign and broadcast prevote
                let sign_msg = prevote_sign_message(
                    height,
                    round,
                    &block_hash,
                    local_id,
                    self.config.chain_id,
                );
                let signature = local_signing_key.sign(&sign_msg);
                let stake = engine
                    .validator_set
                    .get_by_id(local_id)
                    .map_or(0, |v| v.stake);

                // Feed our own prevote to the SM
                let next_action = engine.on_prevote(height, round, block_hash, *local_id, stake);

                if let Err(e) = consensus_outbound_tx
                    .send(NetworkMessage::Prevote(NetworkPrevote {
                        height,
                        round,
                        block_hash,
                        voter: local_id.0,
                        voter_stake: stake,
                        signature,
                        chain_id: self.config.chain_id,
                    }))
                    .await
                {
                    warn!(height, round, %e, "Failed to enqueue prevote for broadcast");
                }

                engine
                    .round_timer
                    .start_step(round, ace_consensus::RoundStep::Prevote);

                if let Err(e) = consensus_wal.write(&ace_consensus::wal::WalEntry::Prevote {
                    height,
                    round,
                    block_hash,
                }) {
                    tracing::error!("FATAL: consensus WAL write failed: {:?}", e);
                    panic!("consensus WAL write failed — cannot guarantee safety");
                }

                // Recursively handle any follow-up action
                if next_action != TendermintAction::None {
                    Box::pin(self.execute_tendermint_action(
                        next_action,
                        engine,
                        local_id,
                        local_signing_key,
                        state,
                        block_store,
                        tx_receipt_store,
                        eth_events,
                        mempool,
                        net_outbound_tx,
                        consensus_outbound_tx,
                        verifier,
                        allow_mock_fc,
                        governance,
                        persistence,
                        genesis_hash,
                        genesis_time_ms,
                        latest_block_slot,
                        state_root_hex,
                        tps_samples,
                        consensus_wal,
                        prepared_block_cache,
                        pending_commit,
                        proposal_validation_tx,
                        signed_precommits_for_cert,
                        Arc::clone(&hfi_pay_state),
                    ))
                    .await;
                }
            }

            TendermintAction::BroadcastPrecommit {
                height,
                round,
                block_hash,
            } => {
                tracing::debug!(
                    height,
                    round,
                    hash = hex::encode(&block_hash[..4]),
                    "Broadcasting precommit"
                );
                // Sign and broadcast precommit
                let sign_msg = precommit_sign_message(
                    height,
                    round,
                    &block_hash,
                    local_id,
                    self.config.chain_id,
                );
                let signature = local_signing_key.sign(&sign_msg);
                let stake = engine
                    .validator_set
                    .get_by_id(local_id)
                    .map_or(0, |v| v.stake);

                // Feed our own precommit to the SM
                let next_action = engine.on_precommit(height, round, block_hash, *local_id, stake);

                let local_pc = NetworkPrecommit {
                    height,
                    round,
                    block_hash,
                    voter: local_id.0,
                    voter_stake: stake,
                    signature,
                    chain_id: self.config.chain_id,
                };
                // Buffer local precommit for CommitCertificate construction.
                // Dedup by (voter, round) — same rationale as the remote-precommit path above.
                if !signed_precommits_for_cert
                    .iter()
                    .any(|p| p.voter == local_id.0 && p.round == round)
                {
                    signed_precommits_for_cert.push(local_pc.clone());
                }
                if let Err(e) = consensus_outbound_tx
                    .send(NetworkMessage::Precommit(local_pc))
                    .await
                {
                    warn!(height, round, %e, "Failed to enqueue precommit for broadcast");
                }

                engine
                    .round_timer
                    .start_step(round, ace_consensus::RoundStep::Precommit);

                if let Err(e) = consensus_wal.write(&ace_consensus::wal::WalEntry::Precommit {
                    height,
                    round,
                    block_hash,
                }) {
                    tracing::error!("FATAL: consensus WAL write failed: {:?}", e);
                    panic!("consensus WAL write failed — cannot guarantee safety");
                }
                if block_hash != [0u8; 32] {
                    if let Err(e) = consensus_wal.write(&ace_consensus::wal::WalEntry::Lock {
                        height,
                        round,
                        block_hash,
                    }) {
                        tracing::error!("FATAL: consensus WAL write failed: {:?}", e);
                        panic!("consensus WAL write failed — cannot guarantee safety");
                    }
                }

                // Recursively handle any follow-up action
                if next_action != TendermintAction::None {
                    Box::pin(self.execute_tendermint_action(
                        next_action,
                        engine,
                        local_id,
                        local_signing_key,
                        state,
                        block_store,
                        tx_receipt_store,
                        eth_events,
                        mempool,
                        net_outbound_tx,
                        consensus_outbound_tx,
                        verifier,
                        allow_mock_fc,
                        governance,
                        persistence,
                        genesis_hash,
                        genesis_time_ms,
                        latest_block_slot,
                        state_root_hex,
                        tps_samples,
                        consensus_wal,
                        prepared_block_cache,
                        pending_commit,
                        proposal_validation_tx,
                        signed_precommits_for_cert,
                        Arc::clone(&hfi_pay_state),
                    ))
                    .await;
                }
            }

            TendermintAction::Commit {
                height,
                round,
                block_hash,
            } => {
                tracing::debug!(
                    height,
                    hash = hex::encode(&block_hash[..8]),
                    "Tendermint COMMIT"
                );
                engine.record_commit_round(round);
                *pending_commit = Some(PendingCommitApplication {
                    height,
                    round,
                    block_hash,
                    apply_started: false,
                });
                engine
                    .round_timer
                    .start_step(round, ace_consensus::RoundStep::CommitWait);
                Self::maybe_start_pending_commit_application(
                    engine,
                    state,
                    block_store,
                    governance,
                    genesis_time_ms,
                    prepared_block_cache,
                    pending_commit,
                    proposal_validation_tx,
                );
                if pending_commit
                    .as_ref()
                    .is_some_and(|pending| !pending.apply_started)
                {
                    if let Some(block) = engine
                        .proposals
                        .get(&block_hash)
                        .cloned()
                        .or_else(|| block_store.read().get_block_by_hash(&block_hash))
                    {
                        let parent_stored_root = block_store
                            .read()
                            .get_block_by_hash(&block.header.parent_hash)
                            .map(|b| b.header.state_root);
                        Self::spawn_commit_preparation_task(
                            block,
                            height,
                            round,
                            Arc::clone(state),
                            Arc::clone(block_store),
                            engine.validator_set.clone(),
                            engine.last_block_hash,
                            governance.clone_for_preview(),
                            genesis_time_ms,
                            parent_stored_root,
                            Arc::clone(&hfi_pay_state),
                            self.config.mev_ace_activation_slot,
                            self.config.mev_ace_full_activation_slot,
                            proposal_validation_tx.clone(),
                        );
                    }
                }
            }

            TendermintAction::ScheduleProposal { height, round } => {
                // Move to a new round — the proposer check happens at the top of the loop
                tracing::debug!(height, round, "New round scheduled");
                engine
                    .round_timer
                    .start_step(round, ace_consensus::RoundStep::Propose);

                // Replay any votes that were buffered while we were in an earlier round
                let buffered_actions = engine.drain_buffered_actions();
                for buffered_action in buffered_actions {
                    Box::pin(self.execute_tendermint_action(
                        buffered_action,
                        engine,
                        local_id,
                        local_signing_key,
                        state,
                        block_store,
                        tx_receipt_store,
                        eth_events,
                        mempool,
                        net_outbound_tx,
                        consensus_outbound_tx,
                        verifier,
                        allow_mock_fc,
                        governance,
                        persistence,
                        genesis_hash,
                        genesis_time_ms,
                        latest_block_slot,
                        state_root_hex,
                        tps_samples,
                        consensus_wal,
                        prepared_block_cache,
                        pending_commit,
                        proposal_validation_tx,
                        signed_precommits_for_cert,
                        Arc::clone(&hfi_pay_state),
                    ))
                    .await;
                }
            }
        }
    }

    async fn run_non_validator<B: BlockStore + 'static>(
        &self,
        slot_clock: SlotClock,
        genesis_hash: [u8; 32],
        genesis_time_ms: u64,
        local_identity: Option<&ace_identity::LoadedIdentity>,
        state: Arc<RwLock<ace_model::sharded_state::ShardedState>>,
        block_store: Arc<RwLock<B>>,
        mempool: Arc<Mempool>,
        current_slot: Arc<AtomicU64>,
        tx_receipt_store: Arc<RwLock<TxReceiptStore>>,
        eth_events: Arc<EthEventHub>,
        net_outbound_tx: mpsc::Sender<NetworkMessage>,
        _consensus_outbound_tx: mpsc::Sender<NetworkMessage>,
        mut net_inbound_rx: mpsc::Receiver<NetworkMessage>,
        governance: &mut RuntimeGovernance,
        persistence: &PersistenceHandles,
        hfi_pay_state: Arc<ace_rpc::hfi_pay_rpc::HfiPayState>,
    ) -> anyhow::Result<()> {
        info!("Running as non-validator (RPC + P2P only)");

        let validator_set = build_validator_set(&self.genesis)?;
        let leader_schedule = LeaderSchedule::new(genesis_hash);
        let poh = PohChain::new(genesis_hash);
        let n_vm = n_vm_with_hfi_pay_hook(&hfi_pay_state, governance.founder_id_com);
        let mut engine = ConsensusEngine::new(
            AccountId::ZERO,
            leader_schedule,
            validator_set,
            poh,
            n_vm,
            genesis_hash,
        );
        engine
            .rebuild_full_validator_set(&governance.approved_validators())
            .map_err(|e| anyhow::anyhow!("failed to rebuild full validator set at startup: {e}"))?;
        let tip_slot = canonical_tip_slot(&*block_store.read()).unwrap_or(0);
        sync_effective_validator_set(
            &mut engine,
            governance,
            slot_time_ms(genesis_time_ms, tip_slot),
        );
        engine.last_block_hash = canonical_tip_hash(&*block_store.read(), genesis_hash);
        let (verifier, _allow_mock_fc) = self.build_proof_system()?;
        info!("Using configured proof verifier in non-validator mode");

        info!(
            validators = engine.validator_set.len(),
            "Non-validator: loaded genesis validator set for block validation"
        );
        let mut takeover_manager = local_identity.and_then(|profile| {
            let idcom = profile.chain_identity().idcom;
            let local_id = AccountId(idcom);
            match resolve_local_auth_pubkey(state.read().default_shard(), &local_id, Some(profile)) {
                Ok(tagged_pubkey) => Some(TakeoverManager::new(idcom, tagged_pubkey)),
                Err(e) => {
                    warn!(error = %e, "Non-validator: could not resolve auth pubkey; takeover protection disabled");
                    None
                }
            }
        });

        let mut next_sync_slot_hint = 0u64;
        let mut recent_sync_requests = std::collections::HashMap::<u64, u64>::new();
        let mut relay_guard = RelayAbuseGuard::default();
        let mut _consecutive_defers = 0u32;
        loop {
            let until_genesis_ms = slot_clock.time_until_genesis_ms();
            if until_genesis_ms > 0 {
                current_slot.store(0, Ordering::Relaxed);
                info!(
                    until_genesis_ms,
                    genesis_time_ms, "Waiting for genesis before non-validator sync loop"
                );
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(until_genesis_ms)) => {
                        continue;
                    }
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received ctrl+c, shutting down");
                        tx_receipt_store.write().force_persist_snapshot();
                        break;
                    }
                }
            }

            let current = slot_clock.current_slot();
            current_slot.store(current, Ordering::Relaxed);

            // Process inbound messages
            while let Ok(msg) = net_inbound_rx.try_recv() {
                match msg {
                    NetworkMessage::NewTransaction {
                        tx, source_peer_id, ..
                    } => {
                        if !relay_guard.allow_tx(source_peer_id.as_deref(), &tx) {
                            continue;
                        }
                        // Relay admission re-validates full-credential txs and
                        // parks stripped PQC txs until a full credential arrives.
                        match mempool.insert_relay(tx.clone()) {
                            Ok(_outcome) => {
                                maybe_publish_pending_evm_tx(&eth_events, &tx);
                                relay_full_node_transaction(&net_outbound_tx, &tx);
                            }
                            Err(e) => {
                                relay_guard.record_rejection(source_peer_id.as_deref(), &e);
                                tracing::debug!(err = %e, "Mempool rejected tx");
                            }
                        }
                    }
                    NetworkMessage::NewBlock(block) => {
                        ingest_block_record(
                            BlockSyncRecord {
                                block,
                                finality_state: None,
                                finality_cert: None,
                            },
                            current,
                            &mut engine,
                            &state,
                            &block_store,
                            &tx_receipt_store,
                            &eth_events,
                            &mempool,
                            governance,
                            persistence,
                            genesis_time_ms,
                            &net_outbound_tx,
                            verifier.as_ref(),
                            false,
                            &self.config.weak_subjectivity_checkpoint,
                            &mut recent_sync_requests,
                            self.config.mev_ace_activation_slot,
                            self.config.mev_ace_full_activation_slot,
                        );
                    }
                    NetworkMessage::BlockSyncRequest(request) => {
                        if let Some(response) =
                            build_block_sync_response(&*block_store.read(), &request)
                        {
                            let _ = net_outbound_tx
                                .try_send(NetworkMessage::BlockSyncResponse(response));
                        }
                    }
                    NetworkMessage::BlockSyncResponse(response) => {
                        for record in response.records {
                            ingest_block_record(
                                record,
                                current,
                                &mut engine,
                                &state,
                                &block_store,
                                &tx_receipt_store,
                                &eth_events,
                                &mempool,
                                governance,
                                persistence,
                                genesis_time_ms,
                                &net_outbound_tx,
                                verifier.as_ref(),
                                true,
                                &self.config.weak_subjectivity_checkpoint,
                                &mut recent_sync_requests,
                                self.config.mev_ace_activation_slot,
                                self.config.mev_ace_full_activation_slot,
                            );
                        }
                    }
                    NetworkMessage::CommitteeApproval(_) => {}
                    NetworkMessage::FinalityCert(cert) => {
                        let slot = cert.slot;
                        // Skip FC processing if no active FSM exists for this slot
                        // or if the FSM is already in a terminal state.
                        if !engine
                            .finality_state(slot)
                            .is_some_and(|fsm| !fsm.state().is_terminal())
                        {
                            continue;
                        }
                        let Some(known_block) = block_store
                            .read()
                            .get_block_by_slot(slot)
                            .filter(|block| block.hash() == cert.block_hash)
                        else {
                            continue;
                        };
                        let action = engine.on_finality_cert(
                            cert.clone(),
                            Some(&known_block),
                            verifier.as_ref(),
                        );
                        if engine
                            .finality_state(slot)
                            .is_some_and(|fsm| fsm.state() == FinalityState::Hard)
                        {
                            block_store.write().put_finality_cert(cert);
                        }
                        handle_finality_action(
                            slot,
                            action,
                            &mut engine,
                            &state,
                            &block_store,
                            &tx_receipt_store,
                            &eth_events,
                            &mempool,
                            governance,
                            persistence,
                            genesis_time_ms,
                        );
                    }
                    NetworkMessage::IdentityTakeover(takeover_msg) => {
                        if takeover_manager
                            .as_mut()
                            .is_some_and(|manager| manager.on_takeover_msg(&takeover_msg))
                        {
                            warn!(
                                idcom = hex::encode(takeover_msg.idcom),
                                nonce = takeover_msg.nonce,
                                "Validated takeover message for local identity; shutting down non-validator"
                            );
                            return Ok(());
                        }
                    }
                    NetworkMessage::StateSyncRequest(_) => {
                        // State sync snapshots not yet served; ignore.
                    }
                    NetworkMessage::StateSyncResponse(response) => {
                        tracing::info!(
                            height = response.height,
                            snapshot_size = response.state_data.len(),
                            "Received state sync snapshot (not yet applied)"
                        );
                    }
                    NetworkMessage::MevAce(mev_msg) => {
                        if should_relay_mev_ace_message(&mev_msg) {
                            let _ = net_outbound_tx.try_send(NetworkMessage::MevAce(mev_msg));
                        }
                    }
                    // Tendermint messages: non-validator doesn't participate in consensus
                    NetworkMessage::Proposal(_)
                    | NetworkMessage::CompactProposal(_)
                    | NetworkMessage::TxFetchResponse(_)
                    | NetworkMessage::TxFetchFailure(_)
                    | NetworkMessage::DialPeer { .. }
                    | NetworkMessage::Prevote(_)
                    | NetworkMessage::Precommit(_)
                    | NetworkMessage::CommitCertificate(_) => {}
                }
            }

            let timeout_actions = engine.check_timeouts(current, verifier.as_ref());
            for (slot, action) in timeout_actions {
                handle_finality_action(
                    slot,
                    action,
                    &mut engine,
                    &state,
                    &block_store,
                    &tx_receipt_store,
                    &eth_events,
                    &mempool,
                    governance,
                    persistence,
                    genesis_time_ms,
                );
            }

            maybe_request_block_sync(
                current,
                &engine,
                &block_store,
                &net_outbound_tx,
                &mut next_sync_slot_hint,
                &mut recent_sync_requests,
            );

            if current % 50 == 0 {
                recent_sync_requests.retain(|_, last_requested_slot| {
                    current <= last_requested_slot.saturating_add(8)
                });
            }

            if current % 10 == 0 {
                engine.cleanup_finalized(current, 50);
            }

            let wait_ms = slot_clock.time_until_next_slot_ms();
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(wait_ms)) => {}
                _ = tokio::signal::ctrl_c() => {
                    info!("Received ctrl+c, shutting down");
                    tx_receipt_store.write().force_persist_snapshot();
                    break;
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, serde::Deserialize)]
struct JsonRpcEnvelope<T> {
    result: Option<T>,
}

#[derive(Debug, serde::Deserialize)]
struct PublicPeerRpc {
    peer_id: String,
    remote_addr: String,
}

#[derive(Debug, serde::Deserialize)]
struct PublicNodeRegistryEnvelope {
    nodes: Vec<PublicNodeRegistryEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct PublicNodeRegistryEntry {
    peer_id: String,
    remote_addr: String,
    chain_id: Option<u32>,
}

fn spawn_public_node_background_tasks(
    config: NodeConfig,
    net_outbound_tx: mpsc::Sender<NetworkMessage>,
) {
    let registry_url = effective_public_node_registry_url(&config);
    if let Some(registry_url) = registry_url.clone() {
        let register_config = config.clone();
        tokio::spawn(async move {
            run_public_node_registration_loop(register_config, registry_url).await;
        });
    }

    let discovery_urls = effective_peer_discovery_rpc_urls(&config);
    if registry_url.is_some() || !discovery_urls.is_empty() {
        tokio::spawn(async move {
            run_peer_discovery_loop(config, discovery_urls, net_outbound_tx).await;
        });
    }
}

fn effective_public_node_registry_url(config: &NodeConfig) -> Option<String> {
    config
        .public_node_registry_url
        .clone()
        .or_else(|| std::env::var("ACE_PUBLIC_NODE_REGISTRY_URL").ok())
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
}

fn effective_public_node_multiaddr(config: &NodeConfig) -> Option<String> {
    config
        .public_node_multiaddr
        .clone()
        .or_else(|| std::env::var("ACE_PUBLIC_NODE_MULTIADDR").ok())
        .map(|addr| addr.trim().to_string())
        .filter(|addr| !addr.is_empty())
}

fn effective_public_node_roles(config: &NodeConfig) -> Vec<String> {
    let mut roles = Vec::new();
    let mut push_role = |role: &str| {
        let role = role.trim().to_ascii_lowercase();
        let canonical = match role.as_str() {
            "rpc" | "relay" | "archive" | "light" | "indexer" => role,
            "fullnode" | "full-node" | "full_node" => "relay".to_string(),
            _ => return,
        };
        if !roles.contains(&canonical) {
            roles.push(canonical);
        }
    };

    push_role(&config.public_node_role);
    for role in &config.public_node_roles {
        push_role(role);
    }
    roles
}

fn is_public_rpc_bind_addr(addr: &str) -> bool {
    let addr = addr.trim();
    !(addr.is_empty() || addr == "127.0.0.1" || addr == "localhost" || addr == "::1")
}

fn effective_peer_discovery_rpc_urls(config: &NodeConfig) -> Vec<String> {
    let mut urls = config.peer_discovery_rpc_urls.clone();
    if let Ok(env_urls) = std::env::var("ACE_PEER_DISCOVERY_RPC_URLS") {
        urls.extend(env_urls.split(',').map(|url| url.trim().to_string()));
    }
    urls.into_iter()
        .map(|url| url.trim().trim_end_matches('/').to_string())
        .filter(|url| !url.is_empty())
        .collect()
}

async fn register_public_node(config: &NodeConfig, registry_url: &str) {
    let Some(peer_id) = ace_p2p::service::persistent_local_peer_id(
        config.data_dir.as_deref().map(std::path::Path::new),
    ) else {
        warn!("Skipping public node registration: data_dir is required for a stable P2P peer id");
        return;
    };

    let endpoint = format!(
        "{}/api/public-nodes/register",
        registry_url.trim_end_matches('/')
    );
    let roles = effective_public_node_roles(config);
    let mut body = serde_json::json!({
        "peer_id": peer_id.to_string(),
        "chain_id": config.chain_id,
        "version": env!("CARGO_PKG_VERSION"),
        "role": config.public_node_role,
        "roles": roles.clone(),
        "capabilities": {
            "public_rpc": is_public_rpc_bind_addr(&config.rpc_bind_addr)
                || roles.iter().any(|role| role == "rpc"),
            "tx_relay": !config.validator
                || roles.iter().any(|role| role == "relay"),
            "block_relay": !config.validator
                || roles.iter().any(|role| role == "relay"),
            "archive": roles.iter().any(|role| role == "archive"),
            "light_client_provider": roles.iter().any(|role| role == "light"),
            "indexer_backend": roles.iter().any(|role| role == "indexer"),
        },
        "p2p_port": config.p2p_port,
    });
    if let Some(remote_addr) = effective_public_node_multiaddr(config) {
        body["remote_addr"] = serde_json::Value::String(remote_addr);
    }

    let client = reqwest::Client::new();
    match client.post(&endpoint).json(&body).send().await {
        Ok(response) if response.status().is_success() => {
            info!(%endpoint, %peer_id, "Registered public full node");
        }
        Ok(response) => {
            warn!(
                %endpoint,
                status = %response.status(),
                "Public node registration was rejected"
            );
        }
        Err(e) => {
            warn!(%endpoint, error = %e, "Public node registration failed");
        }
    }
}

async fn run_public_node_registration_loop(config: NodeConfig, registry_url: String) {
    let interval_secs = config.peer_discovery_interval_secs.max(60);
    loop {
        register_public_node(&config, &registry_url).await;
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}

async fn run_peer_discovery_loop(
    config: NodeConfig,
    discovery_urls: Vec<String>,
    net_outbound_tx: mpsc::Sender<NetworkMessage>,
) {
    let interval_secs = config.peer_discovery_interval_secs.max(10);
    loop {
        discover_and_dial_public_peers(&config, &discovery_urls, &net_outbound_tx).await;
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}

async fn discover_and_dial_public_peers(
    config: &NodeConfig,
    discovery_urls: &[String],
    net_outbound_tx: &mpsc::Sender<NetworkMessage>,
) {
    let client = reqwest::Client::new();
    let local_peer_id = ace_p2p::service::persistent_local_peer_id(
        config.data_dir.as_deref().map(std::path::Path::new),
    )
    .map(|peer| peer.to_string());
    let mut dialed = 0usize;
    let mut seen = std::collections::HashSet::<String>::new();

    if let Some(registry_url) = effective_public_node_registry_url(config) {
        let endpoint = format!("{}/api/public-nodes", registry_url.trim_end_matches('/'));
        match client.get(&endpoint).send().await {
            Ok(response) => match response.json::<PublicNodeRegistryEnvelope>().await {
                Ok(envelope) => {
                    for node in envelope.nodes {
                        if node
                            .chain_id
                            .is_some_and(|chain_id| chain_id != config.chain_id)
                        {
                            continue;
                        }
                        if local_peer_id.as_deref() == Some(node.peer_id.as_str()) {
                            continue;
                        }
                        let addr = ensure_peer_id_in_multiaddr(&node.remote_addr, &node.peer_id);
                        if !seen.insert(addr.clone()) {
                            continue;
                        }
                        let _ = net_outbound_tx.try_send(NetworkMessage::DialPeer { addr });
                        dialed += 1;
                        if dialed >= config.peer_discovery_max_dial_per_round.max(1) {
                            return;
                        }
                    }
                }
                Err(e) => {
                    warn!(%endpoint, error = %e, "Public node registry returned invalid JSON")
                }
            },
            Err(e) => warn!(%endpoint, error = %e, "Public node registry request failed"),
        }
    }

    for rpc_url in discovery_urls {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "ace_getPublicPeers",
            "params": [],
            "id": 1,
        });
        let response = client.post(rpc_url).json(&body).send().await;
        let Ok(response) = response else {
            warn!(%rpc_url, "Peer discovery RPC request failed");
            continue;
        };
        let envelope = response.json::<JsonRpcEnvelope<Vec<PublicPeerRpc>>>().await;
        let Ok(envelope) = envelope else {
            warn!(%rpc_url, "Peer discovery RPC returned invalid JSON");
            continue;
        };
        let Some(peers) = envelope.result else {
            continue;
        };

        for peer in peers {
            if local_peer_id.as_deref() == Some(peer.peer_id.as_str()) {
                continue;
            }
            let addr = ensure_peer_id_in_multiaddr(&peer.remote_addr, &peer.peer_id);
            if !seen.insert(addr.clone()) {
                continue;
            }
            let _ = net_outbound_tx.try_send(NetworkMessage::DialPeer { addr });
            dialed += 1;
            if dialed >= config.peer_discovery_max_dial_per_round.max(1) {
                return;
            }
        }
    }
}

fn ensure_peer_id_in_multiaddr(addr: &str, peer_id: &str) -> String {
    if addr.contains("/p2p/") {
        addr.to_string()
    } else {
        format!("{}/p2p/{}", addr.trim_end_matches('/'), peer_id)
    }
}

#[derive(Default)]
struct RelayAbuseGuard {
    duplicate_cache: VecDeque<[u8; 32]>,
    duplicate_set: std::collections::HashSet<[u8; 32]>,
    peer_windows: HashMap<String, (std::time::Instant, u32)>,
    invalid_scores: HashMap<String, (std::time::Instant, u32)>,
}

impl RelayAbuseGuard {
    fn allow_tx(&mut self, source_peer_id: Option<&str>, tx: &Transaction) -> bool {
        const RELAY_DUPLICATE_CACHE_SIZE: usize = 8192;
        const RELAY_TXS_PER_PEER_PER_SEC: u32 = 80;
        const INVALID_SCORE_BLOCK_THRESHOLD: u32 = 20;
        const INVALID_SCORE_DECAY_SECS: u64 = 60;

        if let Some(peer) = source_peer_id {
            let now = std::time::Instant::now();
            let invalid = self
                .invalid_scores
                .entry(peer.to_string())
                .or_insert((now, 0));
            if now.duration_since(invalid.0).as_secs() >= INVALID_SCORE_DECAY_SECS {
                *invalid = (now, 0);
            }
            if invalid.1 >= INVALID_SCORE_BLOCK_THRESHOLD {
                tracing::debug!(
                    peer,
                    score = invalid.1,
                    "Dropping tx from penalized relay peer"
                );
                return false;
            }

            let window = self
                .peer_windows
                .entry(peer.to_string())
                .or_insert((now, 0));
            if now.duration_since(window.0).as_secs() >= 1 {
                *window = (now, 1);
            } else {
                window.1 += 1;
                if window.1 > RELAY_TXS_PER_PEER_PER_SEC {
                    tracing::debug!(peer, "Dropping tx from rate-limited relay peer");
                    return false;
                }
            }
        }

        let hash = tx.tx_hash();
        if !self.duplicate_set.insert(hash) {
            return false;
        }
        self.duplicate_cache.push_back(hash);
        while self.duplicate_cache.len() > RELAY_DUPLICATE_CACHE_SIZE {
            if let Some(old) = self.duplicate_cache.pop_front() {
                self.duplicate_set.remove(&old);
            }
        }
        true
    }

    fn record_rejection(
        &mut self,
        source_peer_id: Option<&str>,
        error: &ace_mempool::MempoolError,
    ) {
        if matches!(error, ace_mempool::MempoolError::DuplicateTransaction(_)) {
            return;
        }
        let Some(peer) = source_peer_id else {
            return;
        };
        let now = std::time::Instant::now();
        let entry = self
            .invalid_scores
            .entry(peer.to_string())
            .or_insert((now, 0));
        entry.1 = entry.1.saturating_add(1);
    }
}

fn relay_full_node_transaction(net_outbound_tx: &mpsc::Sender<NetworkMessage>, tx: &Transaction) {
    if tx.is_credential_stripped() {
        return;
    }
    let queued = net_outbound_tx.max_capacity() - net_outbound_tx.capacity();
    if queued > 2_000 {
        tracing::debug!(
            queued,
            "full-node relay skipped tx gossip: outbound back-pressure"
        );
        return;
    }

    if tx.attestation.credential.algorithm == SignatureAlgorithm::MlDsa44 {
        use sha2::{Digest, Sha256};

        let credential_bytes = &tx.attestation.credential.bytes;
        let credential_hash: [u8; 32] = Sha256::digest(credential_bytes).into();
        let commitment = ace_p2p::messages::CredentialCommitment {
            algorithm: SignatureAlgorithm::MlDsa44,
            credential_len: credential_bytes.len() as u16,
            credential_hash,
        };
        let _ = net_outbound_tx.try_send(NetworkMessage::NewTransaction {
            tx: tx.stripped_for_gossip(),
            credential_commitment: Some(commitment),
            source_peer_id: None,
        });
        return;
    }

    let _ = net_outbound_tx.try_send(NetworkMessage::NewTransaction {
        tx: tx.stripped_for_gossip(),
        credential_commitment: None,
        source_peer_id: None,
    });
}

fn should_relay_mev_ace_message(msg: &MevAceNetworkMessage) -> bool {
    if bincode::serialized_size(msg)
        .ok()
        .is_none_or(|size| size as usize > ace_runtime::config::MAX_P2P_MESSAGE_BYTES)
    {
        return false;
    }
    match msg {
        MevAceNetworkMessage::Opening(opening) => {
            opening.transaction_wire.len() <= ace_runtime::config::MAX_P2P_MESSAGE_BYTES
        }
        MevAceNetworkMessage::ProposalMaterial(material) => bincode::serialized_size(material)
            .ok()
            .is_some_and(|size| size as usize <= ace_runtime::config::MAX_BLOCK_BYTES),
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Tendermint signing helpers
// ---------------------------------------------------------------------------

/// Compute the signing message for a Tendermint proposal.
fn proposal_sign_message(
    height: u64,
    round: u32,
    block_hash: &[u8; 32],
    proposer: &AccountId,
    chain_id: u32,
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-PROPOSAL-V1");
    hasher.update(chain_id.to_le_bytes());
    hasher.update(height.to_le_bytes());
    hasher.update(round.to_le_bytes());
    hasher.update(block_hash);
    hasher.update(proposer.0);
    hasher.finalize().to_vec()
}

/// Compute the signing message for a Tendermint prevote.
fn prevote_sign_message(
    height: u64,
    round: u32,
    block_hash: &[u8; 32],
    voter: &AccountId,
    chain_id: u32,
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-PREVOTE-V1");
    hasher.update(chain_id.to_le_bytes());
    hasher.update(height.to_le_bytes());
    hasher.update(round.to_le_bytes());
    hasher.update(block_hash);
    hasher.update(voter.0);
    hasher.finalize().to_vec()
}

/// Compute the signing message for a Tendermint precommit.
fn precommit_sign_message(
    height: u64,
    round: u32,
    block_hash: &[u8; 32],
    voter: &AccountId,
    chain_id: u32,
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-PRECOMMIT-V1");
    hasher.update(chain_id.to_le_bytes());
    hasher.update(height.to_le_bytes());
    hasher.update(round.to_le_bytes());
    hasher.update(block_hash);
    hasher.update(voter.0);
    hasher.finalize().to_vec()
}

fn verify_tendermint_proposal(
    engine: &ConsensusEngine,
    proposal: &NetworkProposal,
    expected_proposer: &AccountId,
    chain_id: u32,
) -> bool {
    if proposal.chain_id != chain_id {
        return false;
    }
    if proposal.block.header.slot != proposal.height {
        return false;
    }
    if proposal.block.header.round != proposal.round {
        return false;
    }
    if proposal.block.header.leader_idcom != proposal.proposer {
        return false;
    }
    let proposer = AccountId(proposal.proposer);
    if &proposer != expected_proposer {
        return false;
    }
    let Some(validator) = engine.validator_set.get_by_id(&proposer) else {
        return false;
    };
    if !proposal.signature.is_well_formed() {
        return false;
    }
    let block_hash = proposal.block.hash();
    let msg = proposal_sign_message(
        proposal.height,
        proposal.round,
        &block_hash,
        &proposer,
        proposal.chain_id,
    );
    sig_algo::verify_signature(&validator.signing_pubkey, &msg, &proposal.signature)
}

/// Verify a compact proposal signature.  Same logic as verify_tendermint_proposal
/// but works with CompactNetworkProposal (header only, no full block).
fn verify_compact_proposal(
    engine: &ConsensusEngine,
    proposal: &CompactNetworkProposal,
    expected_proposer: &AccountId,
    chain_id: u32,
) -> bool {
    if proposal.chain_id != chain_id {
        return false;
    }
    if proposal.header.slot != proposal.height {
        return false;
    }
    if proposal.header.round != proposal.round {
        return false;
    }
    if proposal.header.leader_idcom != proposal.proposer {
        return false;
    }
    if proposal.header.tx_count != proposal.tx_hashes.len() as u32 {
        return false;
    }
    if proposal.tx_hashes.len() != proposal.tx_wire_hashes.len() {
        return false;
    }
    let expected_tx_root =
        ace_runtime::types::block::compute_merkle_root_from_hashes(&proposal.tx_wire_hashes);
    if proposal.header.tx_merkle_root != expected_tx_root {
        return false;
    }
    let proposer = AccountId(proposal.proposer);
    if &proposer != expected_proposer {
        return false;
    }
    let Some(validator) = engine.validator_set.get_by_id(&proposer) else {
        return false;
    };
    if !proposal.signature.is_well_formed() {
        return false;
    }
    let block_hash = proposal.header.hash();
    let msg = proposal_sign_message(
        proposal.height,
        proposal.round,
        &block_hash,
        &proposer,
        proposal.chain_id,
    );
    sig_algo::verify_signature(&validator.signing_pubkey, &msg, &proposal.signature)
}

fn credential_matches_commitment(
    tx: &Transaction,
    commitment: &ace_p2p::messages::CredentialCommitment,
) -> bool {
    use sha2::{Digest, Sha256};

    if tx.is_credential_stripped() {
        return false;
    }
    if tx.attestation.credential.algorithm != commitment.algorithm {
        return false;
    }
    if tx.attestation.credential.bytes.len() != commitment.credential_len as usize {
        return false;
    }
    let actual_hash: [u8; 32] = Sha256::digest(&tx.attestation.credential.bytes).into();
    actual_hash == commitment.credential_hash
}

fn verify_tendermint_prevote(
    engine: &ConsensusEngine,
    prevote: &NetworkPrevote,
    chain_id: u32,
) -> bool {
    if prevote.chain_id != chain_id {
        return false;
    }
    let voter = AccountId(prevote.voter);
    let Some(validator) = engine.validator_set.get_by_id(&voter) else {
        return false;
    };
    if !prevote.signature.is_well_formed() {
        return false;
    }
    let msg = prevote_sign_message(
        prevote.height,
        prevote.round,
        &prevote.block_hash,
        &voter,
        prevote.chain_id,
    );
    sig_algo::verify_signature(&validator.signing_pubkey, &msg, &prevote.signature)
}

fn verify_tendermint_precommit(
    engine: &ConsensusEngine,
    precommit: &NetworkPrecommit,
    chain_id: u32,
) -> bool {
    if precommit.chain_id != chain_id {
        return false;
    }
    let voter = AccountId(precommit.voter);
    let Some(validator) = engine.validator_set.get_by_id(&voter) else {
        return false;
    };
    if !precommit.signature.is_well_formed() {
        return false;
    }
    let msg = precommit_sign_message(
        precommit.height,
        precommit.round,
        &precommit.block_hash,
        &voter,
        precommit.chain_id,
    );
    sig_algo::verify_signature(&validator.signing_pubkey, &msg, &precommit.signature)
}

#[derive(Clone)]
struct PreparedBlockExecution {
    height: u64,
    post_tx_state: ace_model::sharded_state::ShardedState,
    receipts: Vec<ace_n_vm::VmReceipt>,
    charged_tx_count: u64,
}

struct PreparedProposal {
    block: ace_runtime::types::block::Block,
    execution: PreparedBlockExecution,
}

struct FinalizedCommit {
    block: ace_runtime::types::block::Block,
    snapshot: ace_model::sharded_state::ShardedStateSnapshot,
    post_commit_state: ace_model::sharded_state::ShardedState,
    governance: RuntimeGovernance,
    rpc_receipts: Vec<RpcTransactionReceipt>,
}

struct PendingCommitApplication {
    height: u64,
    round: u32,
    block_hash: [u8; 32],
    apply_started: bool,
}

/// State for a compact proposal that is waiting for missing transactions
/// from the proposer via the TxFetch protocol.
struct PendingCompactReconstruction {
    block_hash: [u8; 32],
    compact_proposal: CompactNetworkProposal,
    /// Transactions found in the local mempool (indexed by position in tx_hashes).
    found_txs: Vec<Option<Transaction>>,
    /// Hashes of missing transactions.
    missing_hashes: Vec<[u8; 32]>,
    /// Authenticated gossipsub author for the compact proposal.
    proposer_peer_id: String,
    /// Number of tx-fetch requests sent for this proposal.
    attempts: u8,
    /// When we sent the fetch request.
    request_sent: tokio::time::Instant,
    /// Absolute deadline for all TxFetch attempts combined.
    ///
    /// Set to `now + TX_FETCH_RECONSTRUCT_BUDGET_MS` when the pending
    /// reconstruction is first created.  Any retry that would start after
    /// this deadline is abandoned immediately so the validator can nil-prevote
    /// and let Tendermint advance instead of burning retries past the propose
    /// timeout.
    reconstruct_deadline: tokio::time::Instant,
}

struct PendingCredentialPrefetch {
    commitment: ace_p2p::messages::CredentialCommitment,
    peer_id: String,
    attempts: u8,
    next_retry_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
}

enum ConsensusLoopEvent {
    ProposalValidated {
        proposal: NetworkProposal,
        prepared: Option<PreparedBlockExecution>,
    },
    LocalProposalBuilt {
        height: u64,
        round: u32,
        budget: usize,
        build_ms: u64,
        requeue_txs: Vec<Transaction>,
        prepared: Result<PreparedProposal, String>,
    },
    CommitBlockPrepared {
        height: u64,
        round: u32,
        block: ace_runtime::types::block::Block,
        prepared: Option<PreparedBlockExecution>,
    },
    CommitFinalized {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        result: Result<FinalizedCommit, String>,
    },
}

struct HfiBlockTxLookup<B: ace_model::block_store::BlockStore> {
    inner: Arc<RwLock<B>>,
}

impl<B: ace_model::block_store::BlockStore + Send + Sync + 'static>
    ace_hfi_pay::onchain::CommittedTxLookup for HfiBlockTxLookup<B>
{
    fn find_transaction_by_hash(&self, tx_hash: &[u8; 32]) -> Option<Transaction> {
        self.inner.read().find_transaction_by_hash(tx_hash)
    }
}

/// Same n-VM configuration as [`ConsensusEngine::n_vm`]: Tendermint proposal preview,
/// validation, and commit preparation must attach the HFI Pay hook or lifecycle
/// opcodes `0x06..=0x0B` fail in receipts (while block sync replay used the hooked `engine.n_vm`).
fn n_vm_with_hfi_pay_hook(
    hfi_pay_state: &Arc<ace_rpc::hfi_pay_rpc::HfiPayState>,
    founder_id_com: Option<ace_model::account::AccountId>,
) -> ace_n_vm::NVm {
    let mut n_vm = ace_n_vm::NVm::with_defaults();
    n_vm.set_founder_id_com(founder_id_com);
    let vk_bytes = hfi_pay_state
        .claim_verifying_key_bytes
        .clone()
        .unwrap_or_else(|| Arc::new(Vec::new()));
    if vk_bytes.is_empty() {
        tracing::warn!(
            "HFI Pay Groth16 verifying key is not loaded; claim opcode 0x06 will fail until \
             ACE_HFIPAY_CLAIM_VK_PATH is set or ace-rpc/assets/zkace_hfipay_claim_vk.bin is available"
        );
    }
    let committed_tx = hfi_pay_state.committed_tx_lookup.read().clone();
    n_vm.set_hfi_claim_hook(Some(Arc::new(
        ace_hfi_pay::onchain::HfiPayOnChainHook::new(vk_bytes, committed_tx)
            .with_claim_relay(hfi_claim_relay_from_env()),
    )));
    n_vm
}

/// Parse the authorized HFI-Pay claim relay account from `ACE_HFI_CLAIM_RELAY`
/// (32-byte hex id_com). When unset, claims fall back to the legacy unauthenticated
/// path (devnet only) — the hook logs a warning in that case.
fn hfi_claim_relay_from_env() -> Option<ace_model::account::AccountId> {
    let raw = std::env::var("ACE_HFI_CLAIM_RELAY").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    match hex::decode(raw) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            Some(ace_model::account::AccountId::from_bytes(id))
        }
        _ => {
            tracing::error!(
                "ACE_HFI_CLAIM_RELAY is set but not a valid 32-byte hex id_com; ignoring"
            );
            None
        }
    }
}

fn prepare_block_execution<B: BlockStore>(
    n_vm: &ace_n_vm::NVm,
    validator_set: &ValidatorSet,
    height: u64,
    base_state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
    block_store: &Arc<RwLock<B>>,
    txs: &[Transaction],
    governance: &mut RuntimeGovernance,
) -> anyhow::Result<PreparedBlockExecution> {
    let mut preview_state = base_state.read().clone();
    let (receipts, charged_tx_count) = execute_transactions_with_fees(
        n_vm,
        validator_set,
        block_store,
        preview_state.default_shard_mut(),
        txs,
        height,
        governance,
    );

    update_touched_slots(preview_state.default_shard_mut(), &receipts, height);

    if height % SWEEP_INTERVAL_SLOTS == 0 {
        let expired_count = preview_state.sweep_expired(height, STATE_EXPIRY_PERIOD_SLOTS);
        if expired_count > 0 {
            info!(height, expired_count, "state expiry sweep completed");
        }
    }

    Ok(PreparedBlockExecution {
        height,
        post_tx_state: preview_state,
        receipts,
        charged_tx_count,
    })
}

fn preview_prepared_state_root(
    validator_set: &ValidatorSet,
    prepared: &PreparedBlockExecution,
    governance: &mut RuntimeGovernance,
    block_timestamp_ms: u64,
) -> anyhow::Result<[u8; 32]> {
    let mut preview_state = prepared.post_tx_state.clone();
    governance.snapshot(prepared.height);
    let result = governance.apply_completed_block(
        &mut preview_state,
        validator_set,
        prepared.charged_tx_count,
        block_timestamp_ms,
    );
    governance.rollback(prepared.height);
    result?;
    Ok(preview_state.compute_root())
}

fn mev_ace_fair_order_is_active(slot: u64, activation_slot: u64) -> bool {
    slot >= activation_slot
}

fn mev_ace_full_material_is_active(slot: u64, activation_slot: u64) -> bool {
    slot >= activation_slot
}

fn block_satisfies_mev_ace_fair_order(
    parent_hash: [u8; 32],
    slot: u64,
    txs: &[Transaction],
    activation_slot: u64,
) -> bool {
    !mev_ace_fair_order_is_active(slot, activation_slot) || is_fair_ordered(parent_hash, slot, txs)
}

struct StateBackedMevIdentityStore<'a> {
    state: &'a ace_model::sharded_state::ShardedState,
}

impl BondedIdentityStore for StateBackedMevIdentityStore<'_> {
    fn get(&self, idcom: &Idcom) -> Option<IdentityRecord> {
        let account = self.state.get(&AccountId(idcom.0))?;
        let pubkey = account
            .all_auth_keys()
            .into_iter()
            .find(|key| !key.is_zero())?;
        let alg = ace_alg_to_mev_alg(pubkey.algorithm)?;
        Some(IdentityRecord {
            idcom: *idcom,
            vk_auth: VerificationKey(pubkey.bytes.clone()),
            alg,
            bond: 1,
            activated_at: Slot(0),
            revoked_at: None,
        })
    }
}

struct TreeBackedMevIdentityStore<'a> {
    state: &'a ace_model::state_tree::StateTree,
}

impl BondedIdentityStore for TreeBackedMevIdentityStore<'_> {
    fn get(&self, idcom: &Idcom) -> Option<IdentityRecord> {
        let account = self.state.get(&AccountId(idcom.0))?;
        let pubkey = account
            .all_auth_keys()
            .into_iter()
            .find(|key| !key.is_zero())?;
        let alg = ace_alg_to_mev_alg(pubkey.algorithm)?;
        Some(IdentityRecord {
            idcom: *idcom,
            vk_auth: VerificationKey(pubkey.bytes.clone()),
            alg,
            bond: 1,
            activated_at: Slot(0),
            revoked_at: None,
        })
    }
}

#[derive(Default)]
struct MevAceNodeRuntime {
    slots: BTreeMap<u64, SlotState>,
    pending_commit_receipts: BTreeMap<([u8; 32], [u8; 32]), Vec<MevAceCommitReceipt>>,
    pending_open_receipts: BTreeMap<([u8; 32], [u8; 32]), Vec<MevAceOpenReceipt>>,
}

impl MevAceNodeRuntime {
    const MAX_PENDING_RECEIPTS_PER_KEY: usize = 128;

    fn slot_state_mut(&mut self, slot: u64) -> &mut SlotState {
        self.slots.entry(slot).or_insert_with(|| {
            SlotState::with_max_admissible_set_size(
                Slot(slot),
                ace_consensus::mev_ace::MevAcePolicy::default().per_identity_commit_quota,
                ace_consensus::mev_ace::MevAcePolicy::default().max_admissible_set_size,
            )
        })
    }

    fn handle_message(
        &mut self,
        msg: MevAceNetworkMessage,
        state: &ace_model::sharded_state::ShardedState,
        validator_set: &ValidatorSet,
        local_id: &AccountId,
        local_signing_key: &LocalSigningKey,
        parent_hash: [u8; 32],
        current_height: u64,
    ) -> Option<NetworkMessage> {
        match msg {
            MevAceNetworkMessage::Commitment(commitment) => self
                .handle_commitment(
                    commitment,
                    state,
                    validator_set,
                    local_id,
                    local_signing_key,
                    current_height,
                )
                .map(NetworkMessage::MevAce),
            MevAceNetworkMessage::CommitReceipt {
                idcom,
                commitment,
                receipt,
            } => {
                let slot = self
                    .slots
                    .iter_mut()
                    .find(|(_, slot_state)| {
                        slot_state
                            .commit_pool()
                            .get(&Idcom(idcom), &Hash32(commitment))
                            .is_some()
                    })
                    .map(|(slot, _)| *slot);
                if let Some(slot) = slot {
                    let Some(validators) = validator_snapshot_for_block(validator_set, local_id.0)
                    else {
                        return None;
                    };
                    let signatures = AceMevSignatureRegistry::default();
                    let _ = self.slot_state_mut(slot).handle_commit_receipt(
                        &Idcom(idcom),
                        &Hash32(commitment),
                        runtime_commit_receipt_to_core(&receipt),
                        &validators,
                        &signatures,
                    );
                } else {
                    let pending = self
                        .pending_commit_receipts
                        .entry((idcom, commitment))
                        .or_default();
                    if pending.len() < Self::MAX_PENDING_RECEIPTS_PER_KEY {
                        pending.push(receipt);
                    }
                }
                None
            }
            MevAceNetworkMessage::Opening(opening) => self
                .handle_opening(
                    opening,
                    validator_set,
                    local_id,
                    local_signing_key,
                    parent_hash,
                    current_height,
                )
                .map(NetworkMessage::MevAce),
            MevAceNetworkMessage::OpenReceipt {
                idcom,
                commitment,
                receipt,
            } => {
                let slot = self
                    .slots
                    .iter_mut()
                    .find(|(_, slot_state)| {
                        slot_state
                            .open_pool()
                            .get(&Idcom(idcom), &Hash32(commitment))
                            .is_some()
                    })
                    .map(|(slot, _)| *slot);
                if let Some(slot) = slot {
                    let Some(validators) = validator_snapshot_for_block(validator_set, local_id.0)
                    else {
                        return None;
                    };
                    let signatures = AceMevSignatureRegistry::default();
                    let _ = self.slot_state_mut(slot).handle_open_receipt(
                        &Idcom(idcom),
                        &Hash32(commitment),
                        runtime_open_receipt_to_core(&receipt),
                        &validators,
                        &signatures,
                    );
                } else {
                    let pending = self
                        .pending_open_receipts
                        .entry((idcom, commitment))
                        .or_default();
                    if pending.len() < Self::MAX_PENDING_RECEIPTS_PER_KEY {
                        pending.push(receipt);
                    }
                }
                None
            }
            MevAceNetworkMessage::ProposalMaterial(_) | MevAceNetworkMessage::OmissionProof(_) => {
                None
            }
        }
    }

    fn handle_commitment(
        &mut self,
        commitment: MevAceCommitment,
        state: &ace_model::sharded_state::ShardedState,
        validator_set: &ValidatorSet,
        local_id: &AccountId,
        local_signing_key: &LocalSigningKey,
        current_height: u64,
    ) -> Option<MevAceNetworkMessage> {
        if commitment.slot != current_height {
            return None;
        }
        let local_index = validator_set
            .validators()
            .iter()
            .find(|validator| validator.id_com == *local_id)?
            .index;
        let identities = StateBackedMevIdentityStore { state };
        let signatures = AceMevSignatureRegistry::default();
        self.slot_state_mut(commitment.slot)
            .handle_commitment(
                runtime_commitment_to_core(&commitment),
                &identities,
                &signatures,
            )
            .ok()?;
        let idcom = Idcom(commitment.idcom);
        let c = Hash32(commitment.commitment);
        let sign_msg = commit_signing_input(&idcom, &c, Slot(commitment.slot));
        let receipt = MevAceCommitReceipt {
            validator_idx: local_index,
            signature: local_signing_key.sign(&sign_msg).bytes,
        };
        let validators = validator_snapshot_for_block(validator_set, local_id.0)?;
        let _ = self.slot_state_mut(commitment.slot).handle_commit_receipt(
            &idcom,
            &c,
            runtime_commit_receipt_to_core(&receipt),
            &validators,
            &signatures,
        );
        if let Some(pending) = self
            .pending_commit_receipts
            .remove(&(commitment.idcom, commitment.commitment))
        {
            for receipt in pending {
                let _ = self.slot_state_mut(commitment.slot).handle_commit_receipt(
                    &idcom,
                    &c,
                    runtime_commit_receipt_to_core(&receipt),
                    &validators,
                    &signatures,
                );
            }
        }
        Some(MevAceNetworkMessage::CommitReceipt {
            idcom: commitment.idcom,
            commitment: commitment.commitment,
            receipt,
        })
    }

    fn handle_opening(
        &mut self,
        opening: MevAceOpening,
        validator_set: &ValidatorSet,
        local_id: &AccountId,
        local_signing_key: &LocalSigningKey,
        parent_hash: [u8; 32],
        current_height: u64,
    ) -> Option<MevAceNetworkMessage> {
        if opening.slot != current_height {
            return None;
        }
        let local_index = validator_set
            .validators()
            .iter()
            .find(|validator| validator.id_com == *local_id)?
            .index;
        let validators = validator_snapshot_for_block(validator_set, local_id.0)?;
        let hasher = AceMevHasher;
        let vdf = AceDevVdf;
        let signatures = AceMevSignatureRegistry::default();
        let slot_state = self.slot_state_mut(opening.slot);
        if slot_state.phase() == SlotPhase::Commit {
            slot_state.advance_to(SlotPhase::Vdf).ok()?;
            slot_state
                .compute_order(&Hash32(parent_hash), &validators, &hasher, &vdf)
                .ok()?;
            slot_state.advance_to(SlotPhase::Open).ok()?;
        }
        let idcom = Idcom(opening.idcom);
        let c = Hash32(opening.commitment);
        slot_state
            .handle_opening(runtime_opening_to_core(&opening), &validators, &hasher)
            .ok()?;
        let sign_msg = open_signing_input(&idcom, &c, Slot(opening.slot));
        let receipt = MevAceOpenReceipt {
            validator_idx: local_index,
            signature: local_signing_key.sign(&sign_msg).bytes,
        };
        let _ = slot_state.handle_open_receipt(
            &idcom,
            &c,
            runtime_open_receipt_to_core(&receipt),
            &validators,
            &signatures,
        );
        if let Some(pending) = self
            .pending_open_receipts
            .remove(&(opening.idcom, opening.commitment))
        {
            for receipt in pending {
                let _ = self.slot_state_mut(opening.slot).handle_open_receipt(
                    &idcom,
                    &c,
                    runtime_open_receipt_to_core(&receipt),
                    &validators,
                    &signatures,
                );
            }
        }
        Some(MevAceNetworkMessage::OpenReceipt {
            idcom: opening.idcom,
            commitment: opening.commitment,
            receipt,
        })
    }

    fn build_material_and_transactions(
        &mut self,
        slot: u64,
        parent_hash: [u8; 32],
        validator_set: &ValidatorSet,
        local_id: &AccountId,
        local_signing_key: &LocalSigningKey,
    ) -> anyhow::Result<(MevAceProposalMaterial, Vec<Transaction>)> {
        let validators = validator_snapshot_for_block(validator_set, local_id.0)
            .ok_or_else(|| anyhow::anyhow!("local validator is not in validator set"))?;
        let hasher = AceMevHasher;
        let vdf = AceDevVdf;
        let slot_state = self.slot_state_mut(slot);
        if slot_state.phase() == SlotPhase::Commit {
            slot_state.advance_to(SlotPhase::Vdf)?;
            slot_state.compute_order(&Hash32(parent_hash), &validators, &hasher, &vdf)?;
            slot_state.advance_to(SlotPhase::Open)?;
        }
        if slot_state.phase() == SlotPhase::Open {
            slot_state.advance_to(SlotPhase::Propose)?;
        }
        let proposal = slot_state.build_proposal(&validators)?;
        let proposer_signature = local_signing_key
            .sign(&proposal.signing_input(&hasher))
            .bytes;
        let transactions = proposal
            .executable_set
            .iter()
            .map(|opening| Transaction::from_bytes(&opening.opening.tx))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid MEV-ACE executable tx bytes: {e}"))?;
        let material = proposal_draft_to_runtime_material(proposal, proposer_signature);
        Ok((material, transactions))
    }

    fn build_empty_material(
        slot: u64,
        parent_hash: [u8; 32],
        validator_set: &ValidatorSet,
        local_id: &AccountId,
        local_signing_key: &LocalSigningKey,
    ) -> anyhow::Result<MevAceProposalMaterial> {
        let validators = validator_snapshot_for_block(validator_set, local_id.0)
            .ok_or_else(|| anyhow::anyhow!("local validator is not in validator set"))?;
        let hasher = AceMevHasher;
        let vdf = AceDevVdf;
        let mut slot_state = SlotState::with_max_admissible_set_size(
            Slot(slot),
            ace_consensus::mev_ace::MevAcePolicy::default().per_identity_commit_quota,
            ace_consensus::mev_ace::MevAcePolicy::default().max_admissible_set_size,
        );
        slot_state.advance_to(SlotPhase::Vdf)?;
        slot_state.compute_order(&Hash32(parent_hash), &validators, &hasher, &vdf)?;
        slot_state.advance_to(SlotPhase::Open)?;
        slot_state.advance_to(SlotPhase::Propose)?;
        let proposal = slot_state.build_proposal(&validators)?;
        let proposer_signature = local_signing_key
            .sign(&proposal.signing_input(&hasher))
            .bytes;
        Ok(proposal_draft_to_runtime_material(
            proposal,
            proposer_signature,
        ))
    }
}

fn runtime_commitment_to_core(value: &MevAceCommitment) -> CoreCommitment {
    CoreCommitment {
        idcom: Idcom(value.idcom),
        c: Hash32(value.commitment),
        slot: Slot(value.slot),
        sig_user: Signature(value.user_signature.clone()),
    }
}

fn runtime_commit_receipt_to_core(value: &MevAceCommitReceipt) -> CoreCommitReceipt {
    CoreCommitReceipt {
        validator_idx: value.validator_idx,
        sig_val: Signature(value.signature.clone()),
    }
}

fn runtime_opening_to_core(value: &MevAceOpening) -> CoreOpening {
    CoreOpening {
        idcom: Idcom(value.idcom),
        c: Hash32(value.commitment),
        slot: Slot(value.slot),
        tx: value.transaction_wire.clone(),
        r: Nonce(value.nonce),
    }
}

fn runtime_open_receipt_to_core(value: &MevAceOpenReceipt) -> CoreOpenReceipt {
    CoreOpenReceipt {
        validator_idx: value.validator_idx,
        sig_val: Signature(value.signature.clone()),
    }
}

fn proposal_draft_to_runtime_material(
    proposal: mev_ace_core::state::ProposalDraft,
    proposer_signature: Vec<u8>,
) -> MevAceProposalMaterial {
    MevAceProposalMaterial {
        slot: proposal.slot.0,
        cset_root: proposal.cset_root.0,
        vdf_seed: proposal.vdf_seed.0,
        vdf_proof: proposal.vdf_proof,
        sigma: proposal.sigma,
        omitted: proposal.omitted.into_iter().map(|idcom| idcom.0).collect(),
        admissible_set: proposal
            .admissible_set
            .into_iter()
            .map(core_certified_commitment_to_runtime)
            .collect(),
        executable_set: proposal
            .executable_set
            .into_iter()
            .map(core_certified_opening_to_runtime)
            .collect(),
        proposer_signature,
    }
}

fn core_certified_commitment_to_runtime(
    value: CoreCertifiedCommitment,
) -> MevAceCertifiedCommitment {
    MevAceCertifiedCommitment {
        idcom: value.leaf.idcom.0,
        commitment: value.leaf.c.0,
        receipts: value
            .receipts
            .into_iter()
            .map(|receipt| MevAceCommitReceipt {
                validator_idx: receipt.validator_idx,
                signature: receipt.sig_val.0,
            })
            .collect(),
    }
}

fn core_certified_opening_to_runtime(value: CoreCertifiedOpening) -> MevAceCertifiedOpening {
    MevAceCertifiedOpening {
        opening: MevAceOpening {
            idcom: value.opening.idcom.0,
            commitment: value.opening.c.0,
            slot: value.opening.slot.0,
            transaction_wire: value.opening.tx,
            nonce: value.opening.r.0,
        },
        receipts: value
            .receipts
            .into_iter()
            .map(|receipt| MevAceOpenReceipt {
                validator_idx: receipt.validator_idx,
                signature: receipt.sig_val.0,
            })
            .collect(),
    }
}

fn validator_snapshot_for_block(
    validator_set: &ValidatorSet,
    leader_idcom: [u8; 32],
) -> Option<MevAceValidatorSetSnapshot> {
    let leader_index = validator_set
        .validators()
        .iter()
        .find(|validator| validator.id_com.0 == leader_idcom)
        .map(|validator| validator.index)?;
    Some(MevAceValidatorSetSnapshot::from_ace_for_leader(
        validator_set,
        leader_index,
    ))
}

fn validator_set_contains_leader(validator_set: &ValidatorSet, leader_idcom: [u8; 32]) -> bool {
    validator_set
        .validators()
        .iter()
        .any(|validator| validator.id_com.0 == leader_idcom)
}

fn block_satisfies_mev_ace_full_material(
    block: &Block,
    validator_set: &ValidatorSet,
    state: &ace_model::sharded_state::ShardedState,
    activation_slot: u64,
) -> bool {
    if !mev_ace_full_material_is_active(block.header.slot, activation_slot) {
        return true;
    }
    let Some(material) = &block.mev_ace else {
        warn!(
            slot = block.header.slot,
            "Rejecting block: missing MEV-ACE material"
        );
        return false;
    };
    if material.slot != block.header.slot {
        warn!(
            slot = block.header.slot,
            material_slot = material.slot,
            "Rejecting block: MEV-ACE material slot mismatch"
        );
        return false;
    }
    let Ok(material_hash) = material.try_hash() else {
        warn!(
            slot = block.header.slot,
            "Rejecting block: MEV-ACE material cannot be hashed"
        );
        return false;
    };
    if block.header.mev_ace_material_hash != material_hash {
        warn!(
            slot = block.header.slot,
            "Rejecting block: MEV-ACE material hash mismatch"
        );
        return false;
    }
    if !validator_set_contains_leader(validator_set, block.header.leader_idcom) {
        warn!(
            slot = block.header.slot,
            "Rejecting block: MEV-ACE leader is not in validator set"
        );
        return false;
    }
    let identities = StateBackedMevIdentityStore { state };
    let Some(validators) = validator_snapshot_for_block(validator_set, block.header.leader_idcom)
    else {
        warn!(
            slot = block.header.slot,
            "Rejecting block: MEV-ACE leader snapshot is unavailable"
        );
        return false;
    };
    match verify_proposal_material_for_transactions(
        material,
        block.header.parent_hash,
        &block.transactions,
        &validators,
        &identities,
    ) {
        Ok(()) => true,
        Err(error) => {
            warn!(slot = block.header.slot, %error, "Rejecting block: invalid MEV-ACE material");
            false
        }
    }
}

fn verify_mev_ace_omission_proof_against_block(
    proof: &ace_runtime::types::block::MevAceOmissionProof,
    block: &Block,
    identities: &dyn BondedIdentityStore,
    validator_set: &ValidatorSet,
) -> Result<AccountId, String> {
    if proof.block_hash != block.hash() {
        return Err("MEV-ACE omission proof block_hash does not match target block".into());
    }
    if proof.slot != block.header.slot {
        return Err("MEV-ACE omission proof slot does not match target block".into());
    }
    if proof.producer != [0u8; 32] && proof.producer != block.header.leader_idcom {
        return Err("MEV-ACE omission proof producer does not match target block leader".into());
    }
    if !validator_set_contains_leader(validator_set, block.header.leader_idcom) {
        return Err("target block leader is not in validator set".into());
    }
    let Some(material) = &block.mev_ace else {
        return Err("target block has no MEV material".into());
    };
    let signed = proposal_material_to_signed(material)
        .map_err(|e| format!("target MEV material is malformed: {e}"))?;
    let core_proof = omission_proof_to_core(proof);
    let validators = validator_snapshot_for_block(validator_set, block.header.leader_idcom)
        .ok_or_else(|| "target block leader snapshot is unavailable".to_string())?;
    let signatures = AceMevSignatureRegistry::default();
    let hasher = AceMevHasher;
    verify_omission_proof(
        &core_proof,
        &signed.proposal,
        identities,
        &validators,
        &signatures,
        &hasher,
    )
    .map_err(|e| e.to_string())?;
    Ok(AccountId(block.header.leader_idcom))
}

fn validate_mev_ace_omission_proof_from_store<B: BlockStore>(
    proof: &MevAceOmissionProof,
    block_store: &Arc<RwLock<B>>,
    state: &ace_model::sharded_state::ShardedState,
    validator_set: &ValidatorSet,
) -> Result<AccountId, String> {
    let block = block_store
        .read()
        .get_block_by_hash(&proof.block_hash)
        .ok_or_else(|| "unknown target block".to_string())?;
    let identities = StateBackedMevIdentityStore { state };
    verify_mev_ace_omission_proof_against_block(proof, &block, &identities, validator_set)
}

fn build_mev_ace_omission_evidence_tx(
    proof: &MevAceOmissionProof,
    chain_id: u32,
    current_slot: u64,
) -> Result<Transaction, String> {
    use sha2::{Digest, Sha256};

    let payload = encode_mev_ace_omission_evidence_payload(proof)?;
    let idcom = mev_ace_omission_evidence_tx_idcom(proof);
    let obj_hash: [u8; 32] = Sha256::digest(&payload).into();
    let domain_slot = u32::try_from(current_slot).unwrap_or(u32::MAX);
    Ok(Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom,
            domain: Domain::new(chain_id, domain_slot),
            context_tag: ace_runtime::types::attestation::DEFAULT_CONTEXT_TAG,
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
    ))
}

fn mev_ace_omission_evidence_marker_slot(proof: &MevAceOmissionProof) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let evidence_id = mev_ace_omission_evidence_tx_idcom(proof);
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-MEV-ACE-OMISSION-EVIDENCE-CONSUMED-V1");
    hasher.update(evidence_id);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn execute_mev_ace_omission_evidence_system_tx<B: BlockStore>(
    state: &mut ace_model::state_tree::StateTree,
    tx: &Transaction,
    block_store: &Arc<RwLock<B>>,
    governance: &mut RuntimeGovernance,
    validator_set: &ValidatorSet,
) -> Result<ace_n_vm::VmReceipt, String> {
    let proof = decode_mev_ace_omission_evidence_payload(&tx.payload)?;
    let expected_idcom = mev_ace_omission_evidence_tx_idcom(&proof);
    if tx.attestation.idcom != expected_idcom {
        return Err("MEV-ACE omission evidence idcom does not match proof".into());
    }
    let marker_slot = mev_ace_omission_evidence_marker_slot(&proof);
    if state.get_storage(&TREASURY_ACCOUNT, &marker_slot) != [0u8; 32] {
        return Err("MEV-ACE omission evidence has already been consumed".into());
    }
    let block = block_store
        .read()
        .get_block_by_hash(&proof.block_hash)
        .ok_or_else(|| "unknown target block".to_string())?;
    let identities = TreeBackedMevIdentityStore { state };
    let producer =
        verify_mev_ace_omission_proof_against_block(&proof, &block, &identities, validator_set)?;

    let producer_old = state.get(&producer).map(|account| account.balance);
    let treasury_old = state.get(&TREASURY_ACCOUNT).map(|account| account.balance);
    match governance.slash_builder_in_tree(&producer, state) {
        Ok(_) => {
            let mut state_changes = Vec::new();
            if state.get(&TREASURY_ACCOUNT).is_none() {
                state.insert(Account::new(TREASURY_ACCOUNT));
            }
            if let Some(old) = producer_old {
                if let Some(account) = state.get(&producer) {
                    if account.balance != old {
                        state_changes.push(EngineStateChange::BalanceChange {
                            account: producer,
                            old,
                            new: account.balance,
                        });
                    }
                }
            }
            let new_treasury = state.get(&TREASURY_ACCOUNT).map(|account| account.balance);
            match (treasury_old, new_treasury) {
                (Some(old), Some(new)) if old != new => {
                    state_changes.push(EngineStateChange::BalanceChange {
                        account: TREASURY_ACCOUNT,
                        old,
                        new,
                    });
                }
                (None, Some(new)) => {
                    state_changes.push(EngineStateChange::AccountCreated {
                        account: TREASURY_ACCOUNT,
                    });
                    if new != 0 {
                        state_changes.push(EngineStateChange::BalanceChange {
                            account: TREASURY_ACCOUNT,
                            old: 0,
                            new,
                        });
                    }
                }
                _ => {}
            }
            let marker_old = state.get_storage(&TREASURY_ACCOUNT, &marker_slot);
            let mut marker_new = [0u8; 32];
            marker_new[0] = 1;
            state.set_storage(&TREASURY_ACCOUNT, marker_slot, marker_new);
            state_changes.push(EngineStateChange::StorageChange {
                account: TREASURY_ACCOUNT,
                slot: marker_slot,
                old_value: marker_old,
                new_value: marker_new,
            });
            Ok(ace_n_vm::VmReceipt {
                vm_id: ace_n_vm::VmId::AceNative,
                tx_hash: tx.tx_hash(),
                success: true,
                sender: AccountId::from_bytes(tx.attestation.idcom),
                state_changes,
                error: None,
                simulated: false,
                gas_used: None,
                contract_address: None,
                return_data: Some(producer.0.to_vec()),
                logs: vec![],
            })
        }
        Err(error) => Err(error.to_string()),
    }
}

fn validate_tendermint_proposal_with_context<B: BlockStore>(
    block: &ace_runtime::types::block::Block,
    height: u64,
    round: u32,
    parent_hash: [u8; 32],
    validator_set: &ValidatorSet,
    n_vm: &ace_n_vm::NVm,
    state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
    block_store: &Arc<RwLock<B>>,
    governance: &mut RuntimeGovernance,
    genesis_time_ms: u64,
    // If known: parent block's header.state_root in this node's block DB (cross-check in-memory state).
    canonical_parent_state_root: Option<[u8; 32]>,
    mev_ace_activation_slot: u64,
    mev_ace_full_activation_slot: u64,
) -> Option<PreparedBlockExecution> {
    if block.header.slot != height {
        warn!(height, "Rejecting proposal: height/header.slot mismatch");
        return None;
    }
    if block.header.round != round {
        warn!(height, "Rejecting proposal: round/header.round mismatch");
        return None;
    }
    if block.header.parent_hash != parent_hash {
        tracing::debug!(
            height,
            "Rejecting proposal: parent_hash does not match canonical tip"
        );
        return None;
    }
    if block.transactions.len() > ace_runtime::config::MAX_TXS_PER_BLOCK as usize {
        warn!(height, "Rejecting proposal: too many transactions");
        return None;
    }
    if block.wire_size() > ace_runtime::config::MAX_BLOCK_BYTES {
        warn!(height, "Rejecting proposal: block too large");
        return None;
    }
    if block.header.tx_count != block.transactions.len() as u32 {
        warn!(height, "Rejecting proposal: tx_count mismatch");
        return None;
    }
    if !block_satisfies_mev_ace_fair_order(
        parent_hash,
        height,
        &block.transactions,
        mev_ace_activation_slot,
    ) {
        warn!(
            height,
            round,
            tx_count = block.transactions.len(),
            "Rejecting proposal: transactions do not follow MEV-ACE fair ordering"
        );
        return None;
    }

    use ace_runtime::types::block::{compute_attest_merkle_root, compute_tx_merkle_root};
    let expected_tx_root = compute_tx_merkle_root(&block.transactions);
    if block.header.tx_merkle_root != expected_tx_root {
        warn!(height, "Rejecting proposal: tx_merkle_root mismatch");
        return None;
    }
    let expected_attest_root = compute_attest_merkle_root(&block.transactions);
    if block.header.attest_merkle_root != expected_attest_root {
        warn!(height, "Rejecting proposal: attest_merkle_root mismatch");
        return None;
    }
    {
        let state_guard = state.read();
        if !block_satisfies_mev_ace_full_material(
            block,
            validator_set,
            &state_guard,
            mev_ace_full_activation_slot,
        ) {
            return None;
        }
    }

    let preview_timestamp_ms = slot_time_ms(genesis_time_ms, height);
    let prepared = prepare_block_execution(
        n_vm,
        validator_set,
        height,
        state,
        block_store,
        &block.transactions,
        governance,
    );
    let Ok(prepared) = prepared else {
        warn!(
            height,
            "Rejecting proposal: governance/state preview failed"
        );
        return None;
    };

    let Ok(computed_root) =
        preview_prepared_state_root(validator_set, &prepared, governance, preview_timestamp_ms)
    else {
        warn!(
            height,
            "Rejecting proposal: governance/state preview failed"
        );
        return None;
    };

    if computed_root != block.header.state_root {
        let local_base_state_root = state.read().compute_root();
        let post_tx_pre_gov_state_root = prepared.post_tx_state.compute_root();
        let receipt_ok = prepared.receipts.iter().filter(|r| r.success).count();
        let receipt_fail = prepared.receipts.len() - receipt_ok;
        let tx_hashes_head: Vec<String> = block
            .transactions
            .iter()
            .take(8)
            .map(|t| hex::encode(t.tx_hash()))
            .collect();
        let governance_only_delta = post_tx_pre_gov_state_root != computed_root;
        let local_base_agrees_with_stored_parent =
            canonical_parent_state_root.map(|r| r == local_base_state_root);
        if local_base_agrees_with_stored_parent == Some(false) {
            warn!(
                height,
                round,
                in_memory_state_root = hex::encode(local_base_state_root),
                parent_block_in_store_state_root = ?canonical_parent_state_root.map(hex::encode),
                "State mismatch: in-memory ShardedState root does not match block-store parent block header.state_root (local DB inconsistent — restart with clean state or resync)"
            );
        }
        warn!(
            height,
            round,
            block_hash = hex::encode(block.hash()),
            parent_hash_local_canonical = hex::encode(parent_hash),
            block_header_parent_hash = hex::encode(block.header.parent_hash),
            leader_idcom = hex::encode(block.header.leader_idcom),
            block_timestamp_ms = block.header.timestamp,
            preview_timestamp_ms = preview_timestamp_ms,
            local_base_state_root = hex::encode(local_base_state_root),
            post_tx_pre_gov_state_root = hex::encode(post_tx_pre_gov_state_root),
            expected_header_state_root = hex::encode(block.header.state_root),
            computed_state_root = hex::encode(computed_root),
            tx_count = block.transactions.len(),
            ?tx_hashes_head,
            charged_tx_count = prepared.charged_tx_count,
            receipts_total = prepared.receipts.len(),
            receipt_ok,
            receipt_fail,
            sweep_interval_boundary = (height % SWEEP_INTERVAL_SLOTS == 0),
            governance_mutation_in_preview = governance_only_delta,
            parent_block_in_store_state_root = ?canonical_parent_state_root.map(hex::encode),
            ?local_base_agrees_with_stored_parent,
            "Rejecting proposal: state_root mismatch after preview execution (see diagnostic fields)"
        );
        return None;
    }

    Some(prepared)
}

/// Number of slots after which a zero-balance, non-contract account is eligible
/// for state expiry (~6 months at 400ms/slot).
const STATE_EXPIRY_PERIOD_SLOTS: u64 = 39_312_000;

/// Run the state expiry sweep every N slots (~1 hour at 400ms/slot).
const SWEEP_INTERVAL_SLOTS: u64 = 9_000;

/// Update `last_touched_slot` for all accounts referenced in successful receipts.
///
/// Called after block execution, before `compute_root()`, so the Merkle root
/// includes the updated touch timestamps.
fn update_touched_slots(
    state: &mut ace_model::state_tree::StateTree,
    receipts: &[ace_n_vm::VmReceipt],
    current_slot: u64,
) {
    use ace_engine::receipt::StateChange as SC;
    for receipt in receipts {
        if !receipt.success {
            continue;
        }
        for change in &receipt.state_changes {
            let account_id = match change {
                SC::BalanceChange { account, .. }
                | SC::NonceIncrement { account, .. }
                | SC::AccountCreated { account }
                | SC::StorageChange { account, .. }
                | SC::CodeDeployed { account, .. }
                | SC::AddressBound { account, .. }
                | SC::AuthKeyUpdated { account, .. }
                | SC::ZkReplayConsumed { account, .. } => account,
                SC::Fee { .. } | SC::IntentChange { .. } => continue,
            };
            if let Some(acct) = state.get_mut(account_id) {
                acct.last_touched_slot = current_slot;
            }
        }
    }
}

fn build_tendermint_proposal_with_context<B: BlockStore>(
    parent_hash: [u8; 32],
    proposer_id: AccountId,
    mut poh: PohChain,
    validator_set: &ValidatorSet,
    n_vm: &ace_n_vm::NVm,
    height: u64,
    round: u32,
    genesis_time_ms: u64,
    state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
    block_store: &Arc<RwLock<B>>,
    txs: Vec<Transaction>,
    governance: &mut RuntimeGovernance,
    canonical_parent_state_root: Option<[u8; 32]>,
    mev_ace_activation_slot: u64,
    mev_ace_full_activation_slot: u64,
    mev_ace_material: Option<MevAceProposalMaterial>,
) -> anyhow::Result<PreparedProposal> {
    if let Some(expected) = canonical_parent_state_root {
        let actual = state.read().compute_root();
        if actual != expected {
            anyhow::bail!(
                "refusing to build proposal: in-memory state_root {} != block-store parent state_root {} for parent_hash={} (divergent or lagging ShardedState vs committed parent — would broadcast invalid state_root)",
                hex::encode(actual),
                hex::encode(expected),
                hex::encode(parent_hash)
            );
        }
    }
    let preview_timestamp_ms = slot_time_ms(genesis_time_ms, height);
    let txs = if mev_ace_fair_order_is_active(height, mev_ace_activation_slot) {
        fair_order_transactions(parent_hash, height, txs)
    } else {
        txs
    };
    if mev_ace_full_material_is_active(height, mev_ace_full_activation_slot)
        && mev_ace_material.is_none()
    {
        anyhow::bail!("full MEV-ACE material is active at slot {height}, but no proposal material was supplied");
    }
    let execution = prepare_block_execution(
        n_vm,
        validator_set,
        height,
        state,
        block_store,
        &txs,
        governance,
    )?;
    let state_root =
        preview_prepared_state_root(validator_set, &execution, governance, preview_timestamp_ms)?;

    poh.record(&height.to_le_bytes());
    let poh_hash = poh.current_hash();
    let mut builder =
        BlockBuilder::new(height, parent_hash, poh_hash, proposer_id.0).with_round(round);
    if let Some(material) = mev_ace_material {
        builder = builder.with_mev_ace_material(material);
    }
    for tx in &txs {
        if let Err(e) = builder.add_transaction(tx.clone()) {
            return Err(anyhow::anyhow!("failed to build block: {e}"));
        }
    }

    Ok(PreparedProposal {
        block: builder.build(state_root, current_time_ms()),
        execution,
    })
}

fn execute_transactions_with_fees<B: BlockStore>(
    n_vm: &ace_n_vm::NVm,
    active_validator_set: &ValidatorSet,
    block_store: &Arc<RwLock<B>>,
    state: &mut ace_model::state_tree::StateTree,
    txs: &[Transaction],
    block_slot: u64,
    governance: &mut RuntimeGovernance,
) -> (Vec<ace_n_vm::VmReceipt>, u64) {
    use rayon::prelude::*;

    let phase_start = std::time::Instant::now();

    // ── Phase 1: pre-collect verification tasks (sequential, reads state) ──
    // For each tx we resolve the auth key so that Phase 2 can run without &state.
    enum PreVerifyTask {
        /// Slot tolerance failed — already a failure receipt.
        SlotFail(String),
        /// Needs certificate verification (raw-chain tx).
        Certificate,
        /// Needs credential verification with the resolved key.
        Credential(TaggedPubkey),
        /// Needs ZK-ACE proof verification (zk_auth tx).
        ZkAuth,
        /// No verification needed (raw_chain tx without committee domain).
        None,
    }

    let tasks: Vec<PreVerifyTask> = txs
        .iter()
        .map(|tx| {
            // Slot tolerance check (cheap, do it here to avoid wasting verify work).
            if should_enforce_domain_slot_tolerance(tx)
                && !domain_slot_within_tolerance(tx.attestation.domain.slot as u64, block_slot)
            {
                return PreVerifyTask::SlotFail(format!(
                    "transaction domain.slot {} is outside allowed range for block slot {}",
                    tx.attestation.domain.slot, block_slot
                ));
            }

            // ZK-ACE txs use proof verification — no state lookup needed.
            if tx.is_zk_auth() {
                return PreVerifyTask::ZkAuth;
            }

            // Raw-chain txs use certificate verification, not credential.
            if tx.raw_chain.is_some() {
                if tx
                    .raw_chain
                    .as_ref()
                    .and_then(|rc| rc.kind.committee_domain())
                    .is_some()
                {
                    return PreVerifyTask::Certificate;
                }
                return PreVerifyTask::None;
            }

            // Resolve auth key for credential verification.
            let sender = AccountId::from_bytes(tx.attestation.idcom);

            match state.get(&sender) {
                Some(sender_account) => {
                    let sig_alg = tx.attestation.credential.algorithm;
                    let auth_key = match ace_engine::executor::TransactionOp::decode(&tx.payload) {
                        Ok(ace_engine::executor::TransactionOp::SetAuthPubkey {
                            auth_pubkey,
                            ..
                        })
                        | Ok(ace_engine::executor::TransactionOp::AddAuthKey {
                            auth_pubkey, ..
                        }) => match sender_account.auth_key_for_algorithm(sig_alg) {
                            Some(k) if !k.is_zero() => k.clone(),
                            _ => auth_pubkey,
                        },
                        _ => sender_account
                            .auth_key_for_algorithm(sig_alg)
                            .unwrap_or(&sender_account.auth_pubkey)
                            .clone(),
                    };
                    PreVerifyTask::Credential(auth_key)
                }
                None => {
                    // CreateAccount — extract auth_pubkey from payload.
                    match ace_engine::executor::TransactionOp::decode(&tx.payload) {
                        Ok(ace_engine::executor::TransactionOp::CreateAccount {
                            id_com,
                            auth_pubkey,
                        }) if id_com == sender => PreVerifyTask::Credential(auth_pubkey),
                        _ => PreVerifyTask::None,
                    }
                }
            }
        })
        .collect();

    let phase1_ms = phase_start.elapsed().as_millis() as u64;

    // ── Phase 2: parallel signature verification (rayon) ──
    // Results: Ok(()) = verified, Err(msg) = failed, None = skipped (will verify in Phase 3).
    let phase_start = std::time::Instant::now();
    let state_view: &ace_model::state_tree::StateTree = &*state;
    let verify_results: Vec<Option<Result<(), String>>> = tasks
        .par_iter()
        .zip(txs.par_iter())
        .map(|(task, tx)| match task {
            PreVerifyTask::SlotFail(msg) => Some(Err(msg.clone())),
            PreVerifyTask::Certificate => {
                Some(verify_certificate(tx, state_view, active_validator_set))
            }
            PreVerifyTask::ZkAuth => {
                let Some(zk_auth) = tx.zk_auth.as_ref() else {
                    return Some(Err("ZkAuth task but zk_auth is None".into()));
                };
                Some(ace_runtime::crypto::verify_zk_auth(tx, zk_auth))
            }
            PreVerifyTask::Credential(auth_key) => {
                if verify_credential(&tx.attestation, &tx.payload, auth_key) {
                    Some(Ok(()))
                } else {
                    Some(Err(format!(
                        "invalid credential for sender {}",
                        AccountId::from_bytes(tx.attestation.idcom)
                    )))
                }
            }
            PreVerifyTask::None => None,
        })
        .collect();
    let phase2_ms = phase_start.elapsed().as_millis() as u64;

    // ── Phase 3: parallel-batched execution with pre-verified signatures ──
    //
    // Use the scheduler to group non-conflicting transactions into batches.
    // Transactions within a batch have disjoint write sets and execute in
    // parallel (clone state → execute → merge).  Batches run sequentially
    // to preserve determinism.
    //
    // DeFi settle (opcode 0x05) has Global write set, so it always lands in
    // its own single-tx batch. The node-level opcode remains fail-closed until
    // AMM pool metadata/reserves are persisted in StateTree.
    let phase_start = std::time::Instant::now();

    let batches = ace_n_vm::scheduler::build_batches(txs);
    let num_batches = batches.len();
    let mut receipts: Vec<Option<ace_n_vm::VmReceipt>> = vec![None; txs.len()];
    let mut charged_tx_count = 0u64;

    for batch in &batches {
        if batch.tx_indices.len() <= 1 {
            // ── Single-tx batch: execute directly on main state (no clone) ──
            for &idx in &batch.tx_indices {
                let tx = &txs[idx];
                match &verify_results[idx] {
                    Some(Err(error)) => {
                        receipts[idx] = Some(failure_receipt(tx, error.clone(), vec![]));
                        continue;
                    }
                    Some(Ok(())) => {}
                    None => {}
                }

                let snapshot = state.snapshot();
                let sig_pre_verified = matches!(&verify_results[idx], Some(Ok(())));

                if ace_defi::is_bridge_deposit_payload(&tx.payload) {
                    match execute_bridge_deposit_system_tx(state, tx) {
                        Ok(receipt) => receipts[idx] = Some(receipt),
                        Err(error) => {
                            state.rollback(snapshot);
                            receipts[idx] = Some(failure_receipt(tx, error, vec![]));
                        }
                    }
                    continue;
                }

                if ace_defi::is_withdrawal_completion_payload(&tx.payload) {
                    match execute_withdrawal_completion_system_tx(state, tx) {
                        Ok(receipt) => receipts[idx] = Some(receipt),
                        Err(error) => {
                            state.rollback(snapshot);
                            receipts[idx] = Some(failure_receipt(tx, error, vec![]));
                        }
                    }
                    continue;
                }

                if is_mev_ace_omission_evidence_payload(&tx.payload) {
                    match execute_mev_ace_omission_evidence_system_tx(
                        state,
                        tx,
                        block_store,
                        governance,
                        active_validator_set,
                    ) {
                        Ok(receipt) => receipts[idx] = Some(receipt),
                        Err(error) => {
                            state.rollback(snapshot);
                            receipts[idx] = Some(failure_receipt(tx, error, vec![]));
                        }
                    }
                    continue;
                }

                let fee_change = match charge_tx_fee_with_pre_verified(state, tx, sig_pre_verified)
                {
                    Ok(change) => change,
                    Err(error) => {
                        state.rollback(snapshot);
                        receipts[idx] = Some(failure_receipt(tx, error, vec![]));
                        continue;
                    }
                };

                // Opcode 0x13 interception: OmniLiquid oAsset withdrawal.
                if ace_defi::is_oasset_withdraw_payload(&tx.payload) {
                    match execute_oasset_withdraw_system_tx(state, tx, block_slot) {
                        Ok(mut receipt) => {
                            if let Some(change) = fee_change {
                                receipt.state_changes.insert(0, change);
                            }
                            charged_tx_count += 1;
                            receipts[idx] = Some(receipt);
                        }
                        Err(error) => {
                            state.rollback(snapshot);
                            receipts[idx] = Some(failure_receipt(tx, error, vec![]));
                        }
                    }
                    continue;
                }

                // Opcode 0x0F interception: ACE Liquid order-book tx.
                if ace_liquid::is_liquid_payload(&tx.payload) {
                    match execute_liquid_system_tx(state, tx) {
                        Ok(mut receipt) => {
                            if let Some(change) = fee_change {
                                receipt.state_changes.insert(0, change);
                            }
                            charged_tx_count += 1;
                            receipts[idx] = Some(receipt);
                        }
                        Err(error) => {
                            state.rollback(snapshot);
                            receipts[idx] = Some(failure_receipt(tx, error, vec![]));
                        }
                    }
                    continue;
                }

                // Opcode 0x05 interception: CrossVmSettle
                if ace_defi::DefiRuntime::is_settle_tx(&tx.payload) {
                    state.rollback(snapshot);
                    receipts[idx] = Some(failure_receipt(
                        tx,
                        "CrossVmSettle opcode disabled until AMM pools are state-backed".into(),
                        vec![],
                    ));
                    continue;
                }

                match n_vm.execute_transaction(state, tx, block_slot) {
                    Ok(mut receipt) => {
                        if let Some(change) = fee_change {
                            receipt.state_changes.insert(0, change);
                        }
                        charged_tx_count += 1;
                        receipts[idx] = Some(receipt);
                    }
                    Err(error) => {
                        state.rollback(snapshot);
                        receipts[idx] = Some(failure_receipt(tx, error.to_string(), vec![]));
                    }
                }
            }
        } else {
            // ── Multi-tx batch: parallel execution with cloned state ──
            // Each tx gets its own state clone.  On success the write set is
            // merged back; on failure the clone is discarded (equivalent to
            // snapshot + rollback).
            let state_snap: &ace_model::state_tree::StateTree = &*state;
            let batch_results: Vec<(
                usize,
                ace_n_vm::VmReceipt,
                bool,
                Option<ace_model::state_tree::StateTree>,
            )> = batch
                .tx_indices
                .par_iter()
                .map(|&idx| {
                    let tx = &txs[idx];

                    // Check pre-verification result.
                    if let Some(Err(error)) = &verify_results[idx] {
                        return (idx, failure_receipt(tx, error.clone(), vec![]), false, None);
                    }

                    let mut local_state = state_snap.clone();
                    let sig_pre_verified = matches!(&verify_results[idx], Some(Ok(())));

                    let fee_change = match charge_tx_fee_with_pre_verified(
                        &mut local_state,
                        tx,
                        sig_pre_verified,
                    ) {
                        Ok(change) => change,
                        Err(error) => {
                            return (idx, failure_receipt(tx, error, vec![]), false, None);
                        }
                    };

                    // Opcode 0x0F: ACE Liquid order-book tx (per-market write set,
                    // so it can land in a parallel batch).
                    if ace_liquid::is_liquid_payload(&tx.payload) {
                        return match execute_liquid_system_tx(&mut local_state, tx) {
                            Ok(mut receipt) => {
                                if let Some(change) = fee_change {
                                    receipt.state_changes.insert(0, change);
                                }
                                (idx, receipt, true, Some(local_state))
                            }
                            Err(error) => (idx, failure_receipt(tx, error, vec![]), false, None),
                        };
                    }

                    match n_vm.execute_transaction(&mut local_state, tx, block_slot) {
                        Ok(mut receipt) => {
                            if let Some(change) = fee_change {
                                receipt.state_changes.insert(0, change);
                            }
                            (idx, receipt, true, Some(local_state))
                        }
                        Err(error) => (
                            idx,
                            failure_receipt(tx, error.to_string(), vec![]),
                            false,
                            None,
                        ),
                    }
                })
                .collect();

            // Merge results back into main state (write sets are disjoint).
            for (idx, receipt, charged, maybe_local) in batch_results {
                if let Some(local_state) = maybe_local {
                    let ws = ace_n_vm::scheduler::extract_write_set(&txs[idx]);
                    match ws {
                        ace_n_vm::scheduler::WriteSet::Accounts(accounts) => {
                            for account_id in &accounts {
                                match local_state.get(account_id) {
                                    Some(acct) => {
                                        state.insert(acct.clone());
                                        if let Some(storage) =
                                            local_state.get_account_storage(account_id)
                                        {
                                            for (slot, value) in storage {
                                                state.set_storage(account_id, *slot, *value);
                                            }
                                        }
                                    }
                                    None => {
                                        state.remove(account_id);
                                    }
                                }
                            }
                        }
                        ace_n_vm::scheduler::WriteSet::Global => {
                            // Should not happen — Global txs are isolated in
                            // their own batch by the scheduler.
                            *state = local_state;
                        }
                    }
                }
                if charged {
                    charged_tx_count += 1;
                }
                receipts[idx] = Some(receipt);
            }
        }
    }

    let phase3_ms = phase_start.elapsed().as_millis() as u64;
    tracing::info!(
        tx_count = txs.len(),
        num_batches,
        phase1_ms,
        phase2_ms,
        phase3_ms,
        "execute_transactions_with_fees phases"
    );

    let receipts = receipts
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            r.unwrap_or_else(|| failure_receipt(&txs[i], "receipt missing".into(), vec![]))
        })
        .collect();

    (receipts, charged_tx_count)
}

fn domain_slot_within_tolerance(tx_slot: u64, block_slot: u64) -> bool {
    const SLOT_TOLERANCE: u64 = 100;
    let lo = block_slot.saturating_sub(SLOT_TOLERANCE);
    let hi = block_slot + SLOT_TOLERANCE;
    tx_slot >= lo && tx_slot <= hi
}

fn should_enforce_domain_slot_tolerance(tx: &Transaction) -> bool {
    if is_mev_ace_omission_evidence_payload(&tx.payload) {
        return false;
    }
    match tx.raw_chain.as_ref().map(|raw_chain| raw_chain.kind) {
        None => true,
        Some(RawChainKind::Tron) => false,
        Some(kind) => kind.committee_domain().is_none(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxFailureKind {
    Slot,
    Nonce,
    Sender,
    Balance,
    Other,
}

fn classify_tx_failure(error: Option<&str>) -> TxFailureKind {
    let Some(error) = error else {
        return TxFailureKind::Other;
    };
    if error.contains("outside allowed range") {
        TxFailureKind::Slot
    } else if error.contains("invalid nonce") {
        TxFailureKind::Nonce
    } else if error.contains("unknown sender") {
        TxFailureKind::Sender
    } else if error.contains("insufficient balance") {
        TxFailureKind::Balance
    } else {
        TxFailureKind::Other
    }
}

fn legacy_dummy_serializable_witness() -> crate::companion_protocol::SerializablePrivateWitness {
    crate::companion_protocol::SerializablePrivateWitness {
        root_secret: [0u8; 32],
        salt: [0u8; 32],
        alg_id: LEGACY_DUMMY_WITNESS_ALG_ID,
        index: 0,
        nonce: 0,
    }
}

fn witness_for_tx(
    tx: &Transaction,
    witness_map: Option<&BTreeMap<String, crate::companion_protocol::SerializablePrivateWitness>>,
) -> Option<crate::companion_protocol::SerializablePrivateWitness> {
    if tx.raw_chain.is_some() {
        return Some(legacy_dummy_serializable_witness());
    }
    let key = hex::encode(tx.attestation.obj_hash);
    witness_map.and_then(|map| map.get(&key).cloned())
}

/// Charge the transaction fee. When `sig_pre_verified` is true, skip the
/// expensive `verify_credential` call (already done in parallel Phase 2).
fn charge_tx_fee_with_pre_verified(
    state: &mut ace_model::state_tree::StateTree,
    tx: &Transaction,
    sig_pre_verified: bool,
) -> Result<Option<EngineStateChange>, String> {
    let sender = AccountId::from_bytes(tx.attestation.idcom);
    let sender_account = match state.get(&sender).cloned() {
        Some(account) => account,
        None => {
            let auth_pubkey = match ace_engine::executor::TransactionOp::decode(&tx.payload) {
                Ok(ace_engine::executor::TransactionOp::CreateAccount {
                    id_com,
                    auth_pubkey,
                }) if id_com == sender => auth_pubkey,
                _ => return Err(format!("unknown sender {}", sender)),
            };
            if !sig_pre_verified && !verify_credential(&tx.attestation, &tx.payload, &auth_pubkey) {
                return Err(format!("invalid credential for sender {}", sender));
            }
            return Ok(None);
        }
    };

    if tx.raw_chain.is_none() {
        let opcode = tx.payload.first().copied().unwrap_or(0);

        if !sig_pre_verified {
            let sig_alg = tx.attestation.credential.algorithm;
            let auth_key = match ace_engine::executor::TransactionOp::decode(&tx.payload) {
                Ok(ace_engine::executor::TransactionOp::SetAuthPubkey { auth_pubkey, .. })
                | Ok(ace_engine::executor::TransactionOp::AddAuthKey { auth_pubkey, .. }) => {
                    match sender_account.auth_key_for_algorithm(sig_alg) {
                        Some(k) if !k.is_zero() => k.clone(),
                        _ => auth_pubkey,
                    }
                }
                Ok(_) => sender_account
                    .auth_key_for_algorithm(sig_alg)
                    .unwrap_or(&sender_account.auth_pubkey)
                    .clone(),
                Err(error) => return Err(error.to_string()),
            };
            if !verify_credential(&tx.attestation, &tx.payload, &auth_key) {
                return Err(format!("invalid credential for sender {}", sender));
            }
        }

        if !sender_account.has_provisioned_auth_key() && opcode != 0x03 && opcode != 0x04 {
            return Err(format!("sender {} has no provisioned auth_pubkey", sender));
        }
    }

    if sender_account.balance < ace_consensus::rewards::TX_FEE {
        return Err(format!(
            "insufficient balance for transaction fee: have {}, need {}",
            sender_account.balance,
            ace_consensus::rewards::TX_FEE
        ));
    }

    let old_balance = sender_account.balance;
    let sender_account = state
        .get_mut(&sender)
        .ok_or_else(|| format!("unknown sender {}", sender))?;
    sender_account.balance -= ace_consensus::rewards::TX_FEE;

    Ok(Some(EngineStateChange::BalanceChange {
        account: sender,
        old: old_balance,
        new: sender_account.balance,
    }))
}

fn execute_bridge_deposit_system_tx(
    state: &mut ace_model::state_tree::StateTree,
    tx: &Transaction,
) -> Result<ace_n_vm::VmReceipt, String> {
    let signed = ace_defi::decode_signed_deposit_payload(&tx.payload).map_err(|e| e.to_string())?;
    let bridge_account = ace_defi::bridge_authority_id();
    let old_marker = state.get_storage(&bridge_account, &signed.deposit.deposit_id);
    let oasset_mapping =
        ace_defi::CanonicalAssetRegistry::get_mapping(state, &signed.deposit.asset)
            .map_err(|e| e.to_string())?;
    let mint_id = match &oasset_mapping {
        Some(mapping) => {
            ace_defi::CanonicalAssetRegistry::get_canonical_asset(state, &mapping.canonical_asset)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "canonical asset mapping points to missing asset".to_string())?
                .mint
        }
        None => ace_defi::wrapped_mint_id(&signed.deposit.asset),
    };
    let old_balance =
        ace_n_vm::token_runtime::balance_of(state, mint_id.as_bytes(), &signed.deposit.recipient);

    if oasset_mapping.is_some() {
        ace_defi::deposit::process_deposit_to_oasset(state, &signed, signed.deposit.processed_at)
            .map_err(|e| e.to_string())?;
    } else {
        let mut bridge = ace_defi::BridgeState::new();
        bridge.initialize(state).map_err(|e| e.to_string())?;
        bridge
            .process_state_approved_signed_deposit(state, &signed)
            .map_err(|e| e.to_string())?;
    }
    let new_marker = state.get_storage(&bridge_account, &signed.deposit.deposit_id);
    let new_balance =
        ace_n_vm::token_runtime::balance_of(state, mint_id.as_bytes(), &signed.deposit.recipient);

    let sender = AccountId::from_bytes(tx.attestation.idcom);
    Ok(ace_n_vm::VmReceipt {
        vm_id: ace_n_vm::VmId::AceNative,
        tx_hash: tx.tx_hash(),
        success: true,
        sender,
        state_changes: vec![
            EngineStateChange::StorageChange {
                account: bridge_account,
                slot: signed.deposit.deposit_id,
                old_value: old_marker,
                new_value: new_marker,
            },
            EngineStateChange::BalanceChange {
                account: signed.deposit.recipient,
                old: old_balance,
                new: new_balance,
            },
        ],
        error: None,
        simulated: false,
        gas_used: None,
        contract_address: None,
        return_data: Some(signed.deposit.deposit_id.to_vec()),
        logs: vec![],
    })
}

fn execute_oasset_withdraw_system_tx(
    state: &mut ace_model::state_tree::StateTree,
    tx: &Transaction,
    block_slot: u64,
) -> Result<ace_n_vm::VmReceipt, String> {
    let request =
        ace_defi::decode_oasset_withdraw_payload(&tx.payload).map_err(|e| e.to_string())?;
    let sender = AccountId::from_bytes(tx.attestation.idcom);

    let nonce_change = {
        let account = state
            .get_mut(&sender)
            .ok_or_else(|| format!("unknown sender {}", sender))?;
        if account.nonce != request.nonce {
            return Err(format!(
                "invalid nonce: expected {}, got {}",
                account.nonce, request.nonce
            ));
        }
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or_else(|| format!("nonce overflow for sender {}", sender))?;
        EngineStateChange::NonceIncrement {
            account: sender,
            new_nonce: account.nonce,
        }
    };

    let bridge_account = ace_defi::bridge_authority_id();
    let mut next_withdrawal_slot = [0u8; 32];
    next_withdrawal_slot[0..8].copy_from_slice(b"nxt_w_id");
    let old_next_withdrawal = state.get_storage(&bridge_account, &next_withdrawal_slot);
    let next_withdrawal_id =
        u64::from_le_bytes(old_next_withdrawal[0..8].try_into().unwrap_or([0u8; 8]));

    let canonical =
        ace_defi::CanonicalAssetRegistry::get_canonical_asset(state, &request.canonical_asset)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "canonical asset not found".to_string())?;
    let _old_oasset_balance =
        ace_n_vm::token_runtime::balance_of(state, canonical.mint.as_bytes(), &sender);

    let record = ace_defi::withdraw::request_oasset_withdrawal(
        state,
        &sender,
        request.intent_id,
        request.canonical_asset,
        request.amount,
        request.target_asset,
        request.external_dest,
        block_slot,
        next_withdrawal_id,
    )
    .map_err(|e| e.to_string())?;

    let _new_oasset_balance =
        ace_n_vm::token_runtime::balance_of(state, canonical.mint.as_bytes(), &sender);
    let mut new_next_withdrawal = [0u8; 32];
    let next_withdrawal_id_after = next_withdrawal_id
        .checked_add(1)
        .ok_or_else(|| "withdrawal id overflow".to_string())?;
    new_next_withdrawal[0..8].copy_from_slice(&next_withdrawal_id_after.to_le_bytes());
    state.set_storage(&bridge_account, next_withdrawal_slot, new_next_withdrawal);

    Ok(ace_n_vm::VmReceipt {
        vm_id: ace_n_vm::VmId::AceNative,
        tx_hash: tx.tx_hash(),
        success: true,
        sender,
        state_changes: vec![
            nonce_change,
            EngineStateChange::StorageChange {
                account: bridge_account,
                slot: next_withdrawal_slot,
                old_value: old_next_withdrawal,
                new_value: new_next_withdrawal,
            },
        ],
        error: None,
        simulated: false,
        gas_used: None,
        contract_address: None,
        return_data: Some(record.withdrawal_id.to_le_bytes().to_vec()),
        logs: vec![],
    })
}

fn execute_withdrawal_completion_system_tx(
    state: &mut ace_model::state_tree::StateTree,
    tx: &Transaction,
) -> Result<ace_n_vm::VmReceipt, String> {
    let completion =
        ace_defi::decode_withdrawal_completion_payload(&tx.payload).map_err(|e| e.to_string())?;
    let expected_idcom = ace_defi::withdrawal_completion_tx_idcom(&completion);
    if tx.attestation.idcom != expected_idcom {
        return Err("withdrawal completion idcom does not match relayer pubkey".into());
    }

    ace_defi::verify_withdrawal_completion_against_state(state, &completion)
        .map_err(|e| e.to_string())?;

    let bridge_account = ace_defi::bridge_authority_id();
    let completion_slot = ace_defi::withdraw::withdrawal_completed_slot(completion.withdrawal_id);
    let old_marker = state.get_storage(&bridge_account, &completion_slot);
    let record =
        ace_defi::complete_indexed_withdrawal(state, &completion).map_err(|e| e.to_string())?;
    let new_marker = state.get_storage(&bridge_account, &completion_slot);

    let sender = AccountId::from_bytes(tx.attestation.idcom);
    Ok(ace_n_vm::VmReceipt {
        vm_id: ace_n_vm::VmId::AceNative,
        tx_hash: tx.tx_hash(),
        success: true,
        sender,
        state_changes: vec![EngineStateChange::StorageChange {
            account: bridge_account,
            slot: completion_slot,
            old_value: old_marker,
            new_value: new_marker,
        }],
        error: None,
        simulated: false,
        gas_used: None,
        contract_address: None,
        return_data: Some(record.withdrawal_id.to_le_bytes().to_vec()),
        logs: vec![],
    })
}

fn execute_liquid_system_tx(
    state: &mut ace_model::state_tree::StateTree,
    tx: &Transaction,
) -> Result<ace_n_vm::VmReceipt, String> {
    let sender = AccountId::from_bytes(tx.attestation.idcom);

    // Capture state before execution
    let ws_accounts = match ace_n_vm::scheduler::extract_write_set(tx) {
        ace_n_vm::scheduler::WriteSet::Accounts(accounts) => accounts,
        ace_n_vm::scheduler::WriteSet::Global => std::collections::HashSet::new(),
    };

    let mut before_state = std::collections::HashMap::new();
    for acc in &ws_accounts {
        let account_data = state.get(acc).cloned();
        let storage = state.get_account_storage(acc).map(|s| s.clone());
        before_state.insert(*acc, (account_data, storage));
    }

    let outcome =
        ace_liquid::execute_liquid_tx(state, sender, &tx.payload).map_err(|e| e.to_string())?;

    // Diff state to populate state_changes
    let mut state_changes = Vec::new();
    for acc in &ws_accounts {
        let (old_acc, old_storage) = before_state.get(acc).unwrap();
        let new_acc = state.get(acc);

        match (old_acc, new_acc) {
            (None, Some(_)) => {
                state_changes.push(EngineStateChange::AccountCreated { account: *acc });
            }
            (Some(old), Some(new)) => {
                if old.balance != new.balance {
                    state_changes.push(EngineStateChange::BalanceChange {
                        account: *acc,
                        old: old.balance,
                        new: new.balance,
                    });
                }
                if old.nonce != new.nonce {
                    state_changes.push(EngineStateChange::NonceIncrement {
                        account: *acc,
                        new_nonce: new.nonce,
                    });
                }
            }
            _ => {}
        }

        let new_storage = state.get_account_storage(acc);
        if let Some(new_s) = new_storage {
            for (slot, new_val) in new_s {
                let old_val = old_storage
                    .as_ref()
                    .and_then(|s| s.get(slot))
                    .copied()
                    .unwrap_or([0u8; 32]);
                if old_val != *new_val {
                    state_changes.push(EngineStateChange::StorageChange {
                        account: *acc,
                        slot: *slot,
                        old_value: old_val,
                        new_value: *new_val,
                    });
                }
            }
        }
    }

    Ok(ace_n_vm::VmReceipt {
        vm_id: ace_n_vm::VmId::AceNative,
        tx_hash: tx.tx_hash(),
        success: true,
        sender,
        state_changes,
        error: None,
        simulated: false,
        gas_used: None,
        contract_address: None,
        return_data: Some(outcome.encode_return_data()),
        logs: vec![],
    })
}

fn failure_receipt(
    tx: &Transaction,
    error: String,
    state_changes: Vec<EngineStateChange>,
) -> ace_n_vm::VmReceipt {
    let sender = AccountId::from_bytes(tx.attestation.idcom);
    ace_n_vm::VmReceipt {
        vm_id: tx
            .payload
            .first()
            .and_then(|&opcode| ace_n_vm::vm::VmId::from_opcode(opcode))
            .unwrap_or(ace_n_vm::vm::VmId::AceNative),
        tx_hash: tx.tx_hash(),
        success: false,
        sender,
        state_changes,
        error: Some(error),
        simulated: false,
        gas_used: None,
        contract_address: None,
        return_data: None,
        logs: vec![],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundBlockDecision {
    Apply,
    AlreadyKnown,
    RequestSync { start_slot: u64 },
    Reorg { rollback_slot: u64 },
    Reject,
}

fn inbound_block_has_valid_leader(
    block: &ace_runtime::types::block::Block,
    engine: &ConsensusEngine,
    is_sync: bool,
) -> bool {
    let slot = block.header.slot;
    let expected_leader = engine
        .leader_schedule
        .leader_for_slot(slot, &engine.validator_set);
    if block.header.leader_idcom == expected_leader.0 {
        return true;
    }

    if is_sync {
        let fallback_leader = engine
            .leader_schedule
            .leader_for_slot(slot, &engine.full_validator_set);
        if block.header.leader_idcom == fallback_leader.0 {
            tracing::info!(
                slot,
                "Accepting sync block leader against full validator set while catching up"
            );
            return true;
        }
    }

    warn!(slot, "Rejecting block: wrong leader");
    false
}

/// Assess an inbound block before execution.
///
/// Unlike the old monotonic-only path, this accepts either canonical tip
/// extensions or explicit reorgs onto a known parent when the replaced range
/// has not reached hard finality.
fn assess_inbound_block<B: BlockStore>(
    block: &ace_runtime::types::block::Block,
    current_slot: u64,
    engine: &ConsensusEngine,
    block_store: &Arc<RwLock<B>>,
    is_sync: bool,
    mev_ace_activation_slot: u64,
) -> InboundBlockDecision {
    let slot = block.header.slot;

    if !is_sync && slot > current_slot + 2 {
        tracing::debug!(slot, "Rejecting block from far-future slot");
        return InboundBlockDecision::Reject;
    }

    if block.transactions.len() > ace_runtime::config::MAX_TXS_PER_BLOCK as usize {
        warn!(
            slot,
            tx_count = block.transactions.len(),
            "Rejecting block: too many transactions"
        );
        return InboundBlockDecision::Reject;
    }

    let block_wire_size = block.wire_size();
    if block_wire_size > ace_runtime::config::MAX_BLOCK_BYTES {
        warn!(
            slot,
            block_wire_size,
            max_block_bytes = ace_runtime::config::MAX_BLOCK_BYTES,
            "Rejecting block: too many bytes"
        );
        return InboundBlockDecision::Reject;
    }

    // No block is valid when there is no validator set (leader would be ZERO; reject to avoid
    // non-validators being able to produce accepted blocks).
    if engine.validator_set.is_empty() || engine.validator_set.total_stake() == 0 {
        warn!(
            slot,
            "Rejecting block: empty validator set or zero total stake"
        );
        return InboundBlockDecision::Reject;
    }

    if block.header.tx_count != block.transactions.len() as u32 {
        warn!(
            slot,
            header_count = block.header.tx_count,
            actual_count = block.transactions.len(),
            "Rejecting block: tx_count mismatch"
        );
        return InboundBlockDecision::Reject;
    }

    use ace_runtime::types::block::{compute_attest_merkle_root, compute_tx_merkle_root};
    let expected_tx_root = compute_tx_merkle_root(&block.transactions);
    if block.header.tx_merkle_root != expected_tx_root {
        warn!(slot, "Rejecting block: tx_merkle_root mismatch");
        return InboundBlockDecision::Reject;
    }

    let expected_attest_root = compute_attest_merkle_root(&block.transactions);
    if block.header.attest_merkle_root != expected_attest_root {
        warn!(slot, "Rejecting block: attest_merkle_root mismatch");
        return InboundBlockDecision::Reject;
    }

    if !block_satisfies_mev_ace_fair_order(
        block.header.parent_hash,
        block.header.slot,
        &block.transactions,
        mev_ace_activation_slot,
    ) {
        warn!(
            slot,
            tx_count = block.transactions.len(),
            "Rejecting block: transactions do not follow MEV-ACE fair ordering"
        );
        return InboundBlockDecision::Reject;
    }

    // Validate block timestamp: must be within ±30 seconds of local clock.
    // Skip during history sync — synced blocks may be arbitrarily old.
    if !is_sync {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let max_drift_ms: u64 = 30_000; // 30 seconds
        if block.header.timestamp > now_ms.saturating_add(max_drift_ms) {
            tracing::debug!(slot, "Rejecting block: timestamp too far in the future");
            return InboundBlockDecision::Reject;
        }
        if block.header.timestamp < now_ms.saturating_sub(max_drift_ms) {
            tracing::debug!(slot, "Rejecting block: timestamp too far in the past");
            return InboundBlockDecision::Reject;
        }
    }

    let store = block_store.read();
    let latest = store.latest_slot();

    // Enforce monotonic timestamps: block timestamp must be >= parent's timestamp.
    if let Some(parent) = store.get_block_by_hash(&block.header.parent_hash) {
        if block.header.timestamp < parent.header.timestamp {
            warn!(
                slot = block.header.slot,
                block_ts = block.header.timestamp,
                parent_ts = parent.header.timestamp,
                "Rejecting block: timestamp is before parent"
            );
            return InboundBlockDecision::Reject;
        }
    }

    let block_hash = block.hash();
    if let Some(existing) = store.get_block_by_hash(&block_hash) {
        if existing.header.slot == slot {
            return InboundBlockDecision::AlreadyKnown;
        }
    }

    if let Some(existing) = store.get_block_by_slot(slot) {
        let existing_hash = existing.hash();
        if existing_hash == block_hash {
            return InboundBlockDecision::AlreadyKnown;
        }
        let existing_finality_state = store.get_finality_state(slot);
        if existing_finality_state.is_some_and(|state| state.is_confirmed()) {
            warn!(slot, "Rejecting conflicting confirmed block");
            return InboundBlockDecision::Reject;
        }

        if compare_voted_hash_preference(engine, slot, existing_hash, block_hash)
            == std::cmp::Ordering::Greater
        {
            tracing::info!(
                slot,
                new_hash = %hex::encode(&block_hash[..8]),
                old_hash = %hex::encode(&existing_hash[..8]),
                "Same-height fork: choosing voted-preferred inbound block"
            );
            return InboundBlockDecision::Reorg {
                rollback_slot: slot,
            };
        }

        tracing::debug!(slot, "Same-height fork: keeping local block");
        return InboundBlockDecision::Reject;
    }

    // Genesis hash is the virtual parent of slot 0 (the very first block on
    // the chain).  We accept it here only when our own tip is still genesis;
    // otherwise we let the regular tip / parent-lookup logic decide so that
    // an attacker cannot bypass validation by claiming a far-future slot
    // points at genesis.
    //
    // NOTE: previously this branch unconditionally rejected any slot != 0 with
    // parent == genesis, which permanently stranded any node that started
    // late — when block-1 (parent == genesis) arrived via gossip or a sync
    // response, it was rejected on the genesis-hash check and the node could
    // never catch up to height 1, let alone any later height.
    let tip_hash = canonical_tip_hash(&*store, engine.genesis_hash);
    if block.header.parent_hash == engine.genesis_hash && tip_hash != engine.genesis_hash {
        tracing::debug!(
            slot,
            "Rejecting block that references genesis as parent while local tip is past genesis"
        );
        return InboundBlockDecision::Reject;
    }

    // Fast path: block extends the canonical tip directly.
    // With skip-slot support, parent_hash may point to a block many slots ago —
    // that is perfectly normal (skipped slots have no blocks). When the local
    // tip is still genesis, this branch also covers the very first block of
    // the chain (slot 1 with parent == genesis_hash).
    if block.header.parent_hash == tip_hash {
        // Skip leader validation during sync — the catching-up node's local
        // validator set may differ from the set that was effective when the
        // block was originally produced (e.g. due to suspensions changing
        // total_stake and thus the leader schedule).  Sync blocks are already
        // authenticated by finality certificates.
        if !is_sync && !inbound_block_has_valid_leader(block, engine, is_sync) {
            return InboundBlockDecision::Reject;
        }
        return InboundBlockDecision::Apply;
    }

    // Look up the parent block by hash.
    let Some(parent_block) = store.get_block_by_hash(&block.header.parent_hash) else {
        let start_slot = latest.saturating_add(1).min(slot.saturating_sub(1)).max(1);
        return InboundBlockDecision::RequestSync { start_slot };
    };

    if !is_sync && !inbound_block_has_valid_leader(block, engine, is_sync) {
        return InboundBlockDecision::Reject;
    }

    let parent_slot = parent_block.header.slot;
    if parent_slot >= slot {
        warn!(
            slot,
            parent_slot, "Rejecting block whose parent is not earlier"
        );
        return InboundBlockDecision::Reject;
    }

    // Reject forks that would rewrite confirmed history.
    if has_confirmed_real_block_in_range(&*store, parent_slot.saturating_add(1), latest) {
        tracing::debug!(
            slot,
            parent_slot,
            latest,
            "Rejecting branch that would cross confirmed local history"
        );
        return InboundBlockDecision::Reject;
    }

    // Check for existing (unconfirmed) blocks after the parent.
    if let Some(first_local_slot) = (parent_slot.saturating_add(1)..=latest)
        .find(|&candidate| store.get_block_by_slot(candidate).is_some())
    {
        // Gap-fill: the inbound block fills a slot *before* our first local
        // continuation block.  Example: we have slot 69 (parent=67), and now
        // slot 68 (parent=67) arrives.  Accept via Reorg — roll back
        // everything from `first_local_slot` onward so the gap-fill block
        // can be applied first, then the later blocks can be re-evaluated.
        if slot < first_local_slot {
            tracing::info!(
                slot,
                parent_slot,
                first_local_slot,
                latest,
                "Gap-fill block received — triggering reorg to insert it before existing chain"
            );
            return InboundBlockDecision::Reorg {
                rollback_slot: first_local_slot,
            };
        }

        // True fork: the inbound block is at or after an existing local
        // block.  Reject to avoid unbounded reorg oscillation.
        tracing::debug!(
            slot,
            parent_slot,
            first_local_slot,
            latest,
            "Rejecting inbound block that forks at or after existing local continuation"
        );
        return InboundBlockDecision::Reject;
    }

    InboundBlockDecision::Apply
}

fn has_confirmed_real_block_in_range<B: BlockStore>(store: &B, start: u64, end: u64) -> bool {
    if start > end {
        return false;
    }

    (start..=end).any(|slot| {
        store.get_block_by_slot(slot).is_some()
            && store
                .get_finality_state(slot)
                .is_some_and(|state| state.is_confirmed())
    })
}

fn send_block_sync_request(
    net_outbound_tx: &mpsc::Sender<NetworkMessage>,
    start_slot: u64,
    limit: u16,
) {
    let _ = net_outbound_tx.try_send(NetworkMessage::BlockSyncRequest(BlockSyncRequest {
        start_slot,
        limit: limit.max(1),
        requester_peer_id: None,
    }));
}

/// Rate-limited wrapper: skips the request if `start_slot` was already
/// requested recently.  The caller clears the set periodically.
fn send_block_sync_request_dedup(
    net_outbound_tx: &mpsc::Sender<NetworkMessage>,
    start_slot: u64,
    limit: u16,
    current_slot: u64,
    recent: &mut std::collections::HashMap<u64, u64>,
) {
    if recent.get(&start_slot).is_some_and(|last_requested_slot| {
        current_slot < last_requested_slot.saturating_add(SYNC_REQUEST_RETRY_INTERVAL_SLOTS)
    }) {
        return;
    }
    recent.insert(start_slot, current_slot);
    send_block_sync_request(net_outbound_tx, start_slot, limit);
}

fn maybe_request_block_sync<B: BlockStore>(
    current_slot: u64,
    engine: &ConsensusEngine,
    block_store: &Arc<RwLock<B>>,
    net_outbound_tx: &mpsc::Sender<NetworkMessage>,
    next_sync_slot_hint: &mut u64,
    recent_sync_requests: &mut std::collections::HashMap<u64, u64>,
) {
    if current_slot < *next_sync_slot_hint {
        return;
    }

    let latest_resolved =
        latest_resolved_slot_up_to(&*block_store.read(), engine, current_slot).unwrap_or(0);
    let start_slot = latest_resolved.saturating_add(1);
    if current_slot > latest_resolved.saturating_add(2) {
        let gap = current_slot.saturating_sub(latest_resolved);
        let batch_limit = if gap > STATE_SYNC_THRESHOLD as u64 {
            tracing::info!(
                current = latest_resolved,
                network = current_slot,
                gap,
                "Entering fast-sync mode (large height gap)"
            );
            FAST_SYNC_BATCH_LIMIT
        } else {
            BLOCK_SYNC_BATCH_LIMIT
        };
        send_block_sync_request_dedup(
            net_outbound_tx,
            start_slot,
            batch_limit,
            current_slot,
            recent_sync_requests,
        );
        *next_sync_slot_hint = current_slot.saturating_add(2);
    }
}

fn build_block_sync_response<B: BlockStore>(
    block_store: &B,
    request: &BlockSyncRequest,
) -> Option<BlockSyncResponse> {
    let latest_slot = block_store.latest_slot();
    if request.start_slot > latest_slot {
        return None;
    }

    // Slots may legitimately be empty in devnet. Start at the first available
    // block at or after the requested slot, then keep the returned range
    // contiguous from there so the requester can ingest a coherent segment.
    let Some(first_present_slot) = (request.start_slot..=latest_slot)
        .find(|&slot| block_store.get_block_by_slot(slot).is_some())
    else {
        return None;
    };

    let limit = request.limit.clamp(1, FAST_SYNC_BATCH_LIMIT) as usize;
    let mut records = Vec::with_capacity(limit);

    // Track the encoded size incrementally instead of re-serializing the entire
    // accumulated `records` vec on every iteration (which was O(n^2) CPU and a
    // mild amplification vector). bincode concatenates Vec elements without
    // delimiters, so the total message size is exactly the empty-records
    // envelope plus the sum of each record's own serialized size.
    let base_overhead = bincode::serialized_size(&BlockSyncResponse {
        start_slot: request.start_slot,
        latest_slot,
        records: Vec::new(),
        peer_id: None,
    })
    .map(|s| s as usize)
    .unwrap_or(usize::MAX);
    let mut running_len = base_overhead;
    let target_response_bytes =
        BLOCK_SYNC_RESPONSE_TARGET_BYTES.min(ace_runtime::config::MAX_P2P_MESSAGE_BYTES);

    for slot in first_present_slot..=latest_slot {
        if records.len() >= limit {
            break;
        }
        let Some(block) = block_store.get_block_by_slot(slot) else {
            break;
        };
        let record = BlockSyncRecord {
            finality_state: block_store.get_finality_state(slot),
            finality_cert: block_store.get_finality_cert(slot),
            block,
        };

        let Ok(record_len) = bincode::serialized_size(&record).map(|s| s as usize) else {
            break;
        };
        let next_len = running_len.saturating_add(record_len);
        if next_len > target_response_bytes {
            if records.is_empty() && next_len <= ace_runtime::config::MAX_P2P_MESSAGE_BYTES {
                records.push(record);
            }
            break;
        }
        running_len = next_len;
        records.push(record);
    }

    if records.is_empty() {
        None
    } else {
        Some(BlockSyncResponse {
            start_slot: request.start_slot,
            latest_slot,
            records,
            peer_id: request.requester_peer_id.clone(),
        })
    }
}

fn persist_block_finality<B: BlockStore>(
    block_store: &Arc<RwLock<B>>,
    slot: u64,
    finality_state: Option<FinalityState>,
    finality_cert: Option<ace_runtime::types::finality::FinalityCertificate>,
) {
    let mut store = block_store.write();
    store.set_finality_state(slot, finality_state.unwrap_or(FinalityState::Pending));
    if let Some(cert) = finality_cert {
        store.put_finality_cert(cert);
    }
}

/// When applying finality from a sync record, only trust Hard + cert if the FC verifies.
/// Otherwise persist at most Soft and no cert to avoid trusting unverified peer data.
fn sanitize_sync_finality(
    record_state: Option<FinalityState>,
    record_cert: &Option<FinalityCertificate>,
    block: &ace_runtime::types::block::Block,
    verifier: &dyn ProofVerifier,
) -> (Option<FinalityState>, Option<FinalityCertificate>) {
    match (record_state, record_cert.as_ref()) {
        (Some(FinalityState::Hard), Some(cert))
            if verifier.verify_finality_certificate_for_block(cert, block) =>
        {
            (record_state, record_cert.clone())
        }
        (Some(FinalityState::Hard), _) => (Some(FinalityState::Soft), None),
        other => {
            let verified_cert = record_cert
                .as_ref()
                .filter(|cert| verifier.verify_finality_certificate_for_block(cert, block))
                .cloned();
            (other.0, verified_cert)
        }
    }
}

fn apply_block_record<B: BlockStore>(
    record: BlockSyncRecord,
    engine: &mut ConsensusEngine,
    state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
    block_store: &Arc<RwLock<B>>,
    tx_receipt_store: &Arc<RwLock<TxReceiptStore>>,
    eth_events: &Arc<EthEventHub>,
    mempool: &Arc<Mempool>,
    governance: &mut RuntimeGovernance,
    _persistence: &PersistenceHandles,
    genesis_time_ms: u64,
    verifier: &dyn ProofVerifier,
    checkpoint: &Option<WeakSubjectivityCheckpoint>,
    mev_ace_full_activation_slot: u64,
) -> bool {
    let block = record.block;

    if let Some(cp) = checkpoint {
        if cp.is_active() {
            let block_hash_hex = hex::encode(block.hash());
            let state_root_hex = hex::encode(block.header.state_root);
            if let Err(e) = cp.verify(block.header.slot, &block_hash_hex, &state_root_hex) {
                tracing::error!(slot = block.header.slot, %e, "weak subjectivity checkpoint verification failed");
                return false;
            }
        }
    }

    let mut state_guard = state.write();
    if !block_satisfies_mev_ace_full_material(
        &block,
        &engine.validator_set,
        &state_guard,
        mev_ace_full_activation_slot,
    ) {
        return false;
    }
    let snapshot = state_guard.snapshot();
    governance.snapshot(block.header.slot);
    let (receipts, charged_tx_count) = execute_transactions_with_fees(
        &engine.n_vm,
        &engine.validator_set,
        block_store,
        state_guard.default_shard_mut(),
        &block.transactions,
        block.header.slot,
        governance,
    );

    // Update last_touched_slot for all accounts modified by this block
    update_touched_slots(
        state_guard.default_shard_mut(),
        &receipts,
        block.header.slot,
    );

    // Periodic state expiry sweep (deterministic — all nodes agree)
    if block.header.slot % SWEEP_INTERVAL_SLOTS == 0 {
        let expired_count = state_guard.sweep_expired(block.header.slot, STATE_EXPIRY_PERIOD_SLOTS);
        if expired_count > 0 {
            info!(
                slot = block.header.slot,
                expired_count, "state expiry sweep completed"
            );
        }
    }

    if let Err(e) = governance.apply_completed_block(
        &mut *state_guard,
        &engine.validator_set,
        charged_tx_count,
        slot_time_ms(genesis_time_ms, block.header.slot),
    ) {
        warn!(
            slot = block.header.slot,
            %e,
            "Rejecting block: failed to apply governance state"
        );
        state_guard.rollback(snapshot);
        governance.rollback(block.header.slot);
        return false;
    }

    let block_ts_ms = slot_time_ms(genesis_time_ms, block.header.slot);
    let computed_root = state_guard.compute_root();
    if computed_root != block.header.state_root {
        let tx_hashes_head: Vec<String> = block
            .transactions
            .iter()
            .take(8)
            .map(|t| hex::encode(t.tx_hash()))
            .collect();
        warn!(
            slot = block.header.slot,
            block_hash = hex::encode(block.hash()),
            parent_hash = hex::encode(block.header.parent_hash),
            expected_state_root = hex::encode(block.header.state_root),
            computed_state_root = hex::encode(computed_root),
            tx_count = block.transactions.len(),
            ?tx_hashes_head,
            charged_tx_count,
            "Rejecting block: state_root mismatch after re-execution (block sync; see fields)"
        );
        state_guard.rollback(snapshot);
        governance.rollback(block.header.slot);
        return false;
    }

    // Process on-chain validator admissions only after the block's state root
    // is accepted. This keeps rejected blocks from mutating the local full set.
    let mut post_admission_full_validator_set = engine.full_validator_set.clone();
    let admission_failures = process_block_validator_admissions(
        &block.transactions,
        governance,
        &mut post_admission_full_validator_set,
        block_ts_ms,
        block.header.slot,
        "sync path",
    );
    if let Err(error) = engine.rebuild_full_validator_set(&governance.approved_validators()) {
        warn!(
            slot = block.header.slot,
            %error,
            "Rejecting block: failed to rebuild validator set after admission"
        );
        state_guard.rollback(snapshot);
        governance.rollback(block.header.slot);
        return false;
    }
    sync_effective_validator_set(engine, governance, block_ts_ms);
    drop(state_guard);

    engine.store_snapshot(block.header.slot, snapshot);
    let block_hash = block.hash();
    engine.last_block_hash = block_hash;

    for tx in &block.transactions {
        let tx_hash = tx.tx_hash();
        let _ = mempool.remove(&tx_hash);
    }

    let block_hash_hex = hex::encode(block_hash);
    let mut rpc_receipts = vm_receipts_to_rpc(
        &block.transactions,
        &receipts,
        block.header.slot,
        &block_hash_hex,
    );
    mark_admission_failures(&mut rpc_receipts, admission_failures);
    tx_receipt_store.write().put_receipts(rpc_receipts.clone());
    block_store.write().put_block(block.clone());
    publish_eth_block_events(eth_events, &block, &rpc_receipts);
    let (persist_state, persist_cert) = sanitize_sync_finality(
        record.finality_state,
        &record.finality_cert,
        &block,
        verifier,
    );
    persist_block_finality(block_store, block.header.slot, persist_state, persist_cert);
    if maybe_advance_engine_to_synced_block(engine, block.header.slot) {
        tracing::info!(
            synced_slot = block.header.slot,
            new_height = engine.current_height(),
            "Advanced validator consensus height after sync"
        );
    }

    // Skip per-block persistence for inbound blocks — periodic persistence handles this.

    true
}

fn ingest_block_record<B: BlockStore>(
    record: BlockSyncRecord,
    current_slot: u64,
    engine: &mut ConsensusEngine,
    state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
    block_store: &Arc<RwLock<B>>,
    tx_receipt_store: &Arc<RwLock<TxReceiptStore>>,
    eth_events: &Arc<EthEventHub>,
    mempool: &Arc<Mempool>,
    governance: &mut RuntimeGovernance,
    persistence: &PersistenceHandles,
    genesis_time_ms: u64,
    net_outbound_tx: &mpsc::Sender<NetworkMessage>,
    verifier: &dyn ProofVerifier,
    is_sync: bool,
    checkpoint: &Option<WeakSubjectivityCheckpoint>,
    recent_sync_requests: &mut std::collections::HashMap<u64, u64>,
    mev_ace_activation_slot: u64,
    mev_ace_full_activation_slot: u64,
) {
    let block = record.block.clone();
    let mut reorg_attempts = 0u32;
    const MAX_REORG_ATTEMPTS: u32 = 3;
    loop {
        let decision = assess_inbound_block(
            &block,
            current_slot,
            engine,
            block_store,
            is_sync,
            mev_ace_activation_slot,
        );
        // Log non-trivial decisions for P2P debugging.
        match &decision {
            InboundBlockDecision::Apply | InboundBlockDecision::AlreadyKnown => {}
            InboundBlockDecision::Reorg { rollback_slot } => {
                tracing::info!(
                    slot = block.header.slot,
                    rollback_slot,
                    my_last_hash = %hex::encode(&engine.last_block_hash[..8]),
                    block_parent = %hex::encode(&block.header.parent_hash[..8]),
                    "Gap-fill reorg: rolling back to insert earlier block"
                );
            }
            InboundBlockDecision::RequestSync { start_slot } => {
                tracing::info!(
                    slot = block.header.slot,
                    start_slot,
                    my_last_hash = %hex::encode(&engine.last_block_hash[..8]),
                    block_parent = %hex::encode(&block.header.parent_hash[..8]),
                    "Requesting sync for unknown parent"
                );
            }
            InboundBlockDecision::Reject => {}
        }
        match decision {
            InboundBlockDecision::Apply => {
                if !apply_block_record(
                    record.clone(),
                    engine,
                    state,
                    block_store,
                    tx_receipt_store,
                    eth_events,
                    mempool,
                    governance,
                    persistence,
                    genesis_time_ms,
                    verifier,
                    checkpoint,
                    mev_ace_full_activation_slot,
                ) {
                    return;
                }
                return;
            }
            InboundBlockDecision::AlreadyKnown => {
                let (persist_state, persist_cert) = sanitize_sync_finality(
                    record.finality_state,
                    &record.finality_cert,
                    &block,
                    verifier,
                );
                persist_block_finality(block_store, block.header.slot, persist_state, persist_cert);
                return;
            }
            InboundBlockDecision::RequestSync { start_slot } => {
                let sync_gap = current_slot.saturating_sub(start_slot);
                let batch_limit = if sync_gap > STATE_SYNC_THRESHOLD as u64 {
                    FAST_SYNC_BATCH_LIMIT
                } else {
                    BLOCK_SYNC_BATCH_LIMIT
                };
                send_block_sync_request_dedup(
                    net_outbound_tx,
                    start_slot,
                    batch_limit,
                    current_slot,
                    recent_sync_requests,
                );
                tracing::debug!(
                    slot = block.header.slot,
                    start_slot,
                    "Missing parent for inbound block, requesting sync"
                );
                return;
            }
            InboundBlockDecision::Reorg { rollback_slot } => {
                reorg_attempts += 1;
                if reorg_attempts > MAX_REORG_ATTEMPTS {
                    tracing::warn!(
                        slot = block.header.slot,
                        reorg_attempts,
                        "Reorg loop limit reached, dropping block"
                    );
                    return;
                }
                if !do_rollback(
                    rollback_slot,
                    engine,
                    state,
                    block_store,
                    tx_receipt_store,
                    eth_events,
                    mempool,
                    governance,
                    persistence,
                    genesis_time_ms,
                ) {
                    return;
                }
            }
            InboundBlockDecision::Reject => return,
        }
    }
}

/// Build a ValidatorSet from the genesis configuration.
///
/// If `genesis.validators` is non-empty, uses those entries.
/// Otherwise, falls back to treating all `genesis.accounts` as validators
/// with stake=100 (backward compatible single-node default).
fn build_validator_set(genesis: &GenesisConfig) -> anyhow::Result<ValidatorSet> {
    if genesis.validators.is_empty() && genesis.accounts.is_empty() {
        anyhow::bail!("no validators defined in genesis");
    }

    let mut validators: Vec<Validator> = Vec::new();

    if !genesis.validators.is_empty() {
        // Use explicit validator entries when provided.
        for (i, gv) in genesis.validators.iter().enumerate() {
            let id_bytes = hex::decode(&gv.id_com).map_err(|e| {
                anyhow::anyhow!("invalid validator id_com hex '{}': {}", gv.id_com, e)
            })?;
            if id_bytes.len() != 32 {
                anyhow::bail!(
                    "validator id_com must be 32 bytes, got {} for '{}'",
                    id_bytes.len(),
                    gv.id_com
                );
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&id_bytes);

            // If an explicit signing_pubkey is provided, use it (detect algorithm from length).
            // Otherwise, derive a devnet signing key deterministically from id_com.
            // Devnet default: ML-DSA-44 (post-quantum).
            let signing_pubkey: TaggedPubkey = if !gv.signing_pubkey.is_empty() {
                let pk_bytes = hex::decode(&gv.signing_pubkey).map_err(|e| {
                    anyhow::anyhow!(
                        "invalid validator signing_pubkey hex '{}': {}",
                        gv.signing_pubkey,
                        e
                    )
                })?;
                match pk_bytes.len() {
                    32 => {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&pk_bytes);
                        TaggedPubkey::ed25519(pk)
                    }
                    1312 => {
                        if pk_bytes.iter().all(|&b| b == 0) {
                            anyhow::bail!(
                                "validator signing_pubkey must be non-zero for '{}'",
                                gv.signing_pubkey
                            );
                        }
                        TaggedPubkey::ml_dsa_44(pk_bytes)
                    }
                    other => {
                        anyhow::bail!(
                            "validator signing_pubkey has unsupported length {} for '{}'",
                            other,
                            gv.signing_pubkey
                        );
                    }
                }
            } else {
                // Devnet: derive ML-DSA-44 key from id_com
                let seed = derive_devnet_signing_seed(&id);
                let key = LocalSigningKey::from_seed(&seed, SignatureAlgorithm::MlDsa44)
                    .map_err(|e| anyhow::anyhow!("ML-DSA-44 keygen failed: {}", e))?;
                key.public_key()
            };

            validators.push(Validator {
                id_com: AccountId(id),
                stake: gv.stake,
                index: i as u32,
                signing_pubkey,
                capabilities: gv.capabilities,
            });
        }
    } else {
        // Backward compat: treat all genesis accounts as validators with equal stake.
        for (i, ga) in genesis.accounts.iter().enumerate() {
            let id_bytes = hex::decode(&ga.id_com).map_err(|e| {
                anyhow::anyhow!("invalid validator id_com hex '{}': {}", ga.id_com, e)
            })?;
            if id_bytes.len() != 32 {
                anyhow::bail!(
                    "validator id_com must be 32 bytes, got {} for '{}'",
                    id_bytes.len(),
                    ga.id_com
                );
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&id_bytes);
            let seed = derive_devnet_signing_seed(&id);
            let key = LocalSigningKey::from_seed(&seed, SignatureAlgorithm::MlDsa44)
                .map_err(|e| anyhow::anyhow!("ML-DSA-44 keygen failed: {}", e))?;
            let signing_pubkey = key.public_key();
            validators.push(Validator {
                id_com: AccountId(id),
                stake: 100,
                index: i as u32,
                signing_pubkey,
                capabilities: ValidatorCapabilities::default(),
            });
        }
    }

    let set = ValidatorSet::new(validators);
    if set.total_stake() == 0 {
        anyhow::bail!(
            "genesis validator set has total_stake 0; at least one validator must have stake > 0"
        );
    }
    Ok(set)
}

/// Resolve the local validator identity.
///
/// If `validator_key` is set, uses that. Otherwise falls back to the
/// first genesis account. Validates that the resolved identity exists
/// in the validator set.
fn resolve_local_identity(
    validator_key: &Option<String>,
    genesis: &GenesisConfig,
    validator_set: &ValidatorSet,
) -> anyhow::Result<AccountId> {
    let id_hex = match validator_key {
        Some(key) => key.clone(),
        None => genesis
            .accounts
            .first()
            .ok_or_else(|| anyhow::anyhow!("no genesis accounts and no --validator-key set"))?
            .id_com
            .clone(),
    };

    let id_bytes = hex::decode(&id_hex)
        .map_err(|e| anyhow::anyhow!("invalid validator_key hex '{}': {}", id_hex, e))?;
    if id_bytes.len() != 32 {
        anyhow::bail!(
            "validator_key must be 32 bytes, got {} for '{}'",
            id_bytes.len(),
            id_hex
        );
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&id_bytes);
    let local_id = AccountId(id);

    // Verify the identity is in the validator set
    if validator_set.get_by_id(&local_id).is_none() {
        anyhow::bail!(
            "validator_key {} is not in the genesis validator set",
            id_hex
        );
    }

    Ok(local_id)
}

/// Resolve the local validator signing key used for consensus votes.
fn resolve_local_signing_key(
    validator_signing_seed: &Option<String>,
    local_id: &AccountId,
    validator_set: &ValidatorSet,
    require_explicit_seed: bool,
) -> anyhow::Result<LocalSigningKey> {
    let expected_pubkey = validator_set
        .get_by_id(local_id)
        .ok_or_else(|| anyhow::anyhow!("validator {} is not in the validator set", local_id))?
        .signing_pubkey
        .clone();

    // Determine algorithm from what the genesis expects
    let algorithm = expected_pubkey.algorithm;

    let seed = match validator_signing_seed {
        Some(seed_hex) => {
            let seed_bytes = hex::decode(seed_hex)
                .map_err(|e| anyhow::anyhow!("invalid validator_signing_seed hex: {}", e))?;
            if seed_bytes.len() != 32 {
                anyhow::bail!(
                    "validator_signing_seed must be 32 bytes, got {}",
                    seed_bytes.len(),
                );
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            seed
        }
        None => {
            if require_explicit_seed {
                anyhow::bail!(
                    "selected production proof mode requires validator_signing_seed for validator {}",
                    local_id
                );
            }
            derive_devnet_signing_seed(&local_id.0)
        }
    };

    let signing_key = LocalSigningKey::from_seed(&seed, algorithm)
        .map_err(|e| anyhow::anyhow!("failed to create signing key: {}", e))?;

    let actual_pubkey = signing_key.public_key();
    if actual_pubkey != expected_pubkey {
        if validator_signing_seed.is_some() {
            anyhow::bail!(
                "provided validator_signing_seed does not match genesis signing_pubkey for validator {}",
                local_id
            );
        }
        anyhow::bail!(
            "validator {} uses a custom signing_pubkey in genesis; set validator_signing_seed in the config file or via --validator-signing-seed",
            local_id
        );
    }

    Ok(signing_key)
}

fn resolve_local_auth_pubkey(
    state: &ace_model::state_tree::StateTree,
    local_id: &AccountId,
    local_identity: Option<&ace_identity::LoadedIdentity>,
) -> anyhow::Result<TaggedPubkey> {
    if let Some(profile) = local_identity {
        if profile.chain_identity().idcom == local_id.0 {
            return Ok(TaggedPubkey::ed25519(profile.auth_pubkey()));
        }
    }

    let account = state
        .get(local_id)
        .ok_or_else(|| anyhow::anyhow!("validator {} is missing from state", local_id))?;
    if account.auth_pubkey.is_zero() {
        anyhow::bail!("validator {} has no provisioned auth_pubkey", local_id);
    }
    Ok(account.auth_pubkey.clone())
}

/// Handle a FinalityAction returned by the consensus engine.
#[allow(unused_variables)]
fn handle_finality_action<B: BlockStore>(
    slot: u64,
    action: FinalityAction,
    engine: &mut ConsensusEngine,
    state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
    block_store: &Arc<RwLock<B>>,
    tx_receipt_store: &Arc<RwLock<TxReceiptStore>>,
    eth_events: &Arc<EthEventHub>,
    mempool: &Arc<Mempool>,
    governance: &mut RuntimeGovernance,
    persistence: &PersistenceHandles,
    genesis_time_ms: u64,
) {
    let prev_finality_state = block_store.read().get_finality_state(slot);
    // Always sync FSM state to block store (e.g. Pending → Soft on quorum)
    if let Some(fsm) = engine.finality_state(slot) {
        block_store.write().set_finality_state(slot, fsm.state());
    }
    let current_finality_state = engine.finality_state(slot).map(|fsm| fsm.state());
    if prev_finality_state != Some(FinalityState::Hard)
        && current_finality_state == Some(FinalityState::Hard)
    {
        if let Some(block) = block_store.read().get_block_by_slot(slot) {
            governance.note_validator_success(&AccountId(block.header.leader_idcom));
            // Do not rotate the leader seed here: hard-finality observation is
            // not synchronized tightly enough across peers, and rotating on a
            // locally observed boundary can make nodes disagree on the leader
            // for the next slot.
        }
    }

    // When slot first reaches Soft finality, slash any equivocators for this slot.
    // In devnet mode, skip equivocator slashing — transient P2P delays can cause
    // brief duplicate blocks that look like equivocation but are benign.
    #[cfg(not(feature = "devnet"))]
    if prev_finality_state != Some(FinalityState::Soft)
        && current_finality_state == Some(FinalityState::Soft)
    {
        if let Some(equivocators) = engine.equivocators_for_slot(slot) {
            for (validator, _) in equivocators {
                match governance.slash_equivocator(validator, &mut state.write()) {
                    Ok(Some(amount)) => {
                        if amount > 0 {
                            info!(slot, equivocator = %validator, amount, "Slashed equivocator");
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(slot, equivocator = %validator, %e, "Failed to slash equivocator");
                    }
                }
            }
            if !equivocators.is_empty() {
                sync_effective_validator_set(engine, governance, current_time_ms());
                if let Err(e) =
                    persistence.persist_tree(state, engine.genesis_hash, genesis_time_ms)
                {
                    warn!(slot, %e, "Failed to persist state after slashing equivocators");
                }
                if let Err(e) = governance.persist() {
                    warn!(slot, %e, "Failed to persist governance after slashing equivocators");
                }
            }
        }
    }

    match action {
        FinalityAction::None => {
            // Periodic persistence: persist state every PERIODIC_PERSIST_INTERVAL
            // hard-finalized slots to limit data loss on crash.
            // Uses async persistence to avoid blocking the consensus loop.
            if engine
                .finality_state(slot)
                .is_some_and(|fsm| fsm.state() == FinalityState::Hard)
            {
                let last = LAST_PERSISTED_SLOT.load(Ordering::Relaxed);
                if slot >= last + PERIODIC_PERSIST_INTERVAL {
                    persistence.persist_tree_async(state, engine.genesis_hash, genesis_time_ms);
                    LAST_PERSISTED_SLOT.store(slot, Ordering::Relaxed);
                    info!(slot, "Periodic state persistence dispatched (async)");
                    if let Err(e) = governance.persist() {
                        warn!(slot, %e, "Failed periodic governance persistence");
                    }
                }
            }
        }
        FinalityAction::SlashBuilder => {
            // In devnet mode, skip slashing entirely — the aggressive timeout
            // (6 slots / 2.4s) suspends validators before mock finality certs
            // can propagate, causing a cascade where only one node remains.
            #[cfg(feature = "devnet")]
            {
                tracing::debug!(slot, "Devnet: skipping SlashBuilder");
            }
            #[cfg(not(feature = "devnet"))]
            {
                // Track leader absence for the expected leader of this slot.
                let expected_leader = engine
                    .leader_schedule
                    .leader_for_slot(slot, &engine.validator_set);
                governance.note_leader_absence(&expected_leader);

                let builder = block_store
                    .read()
                    .get_block_by_slot(slot)
                    .map(|block| AccountId(block.header.leader_idcom));
                if let Some(builder) = builder {
                    match governance.slash_builder(&builder, &mut state.write()) {
                        Ok(Some(amount)) => {
                            sync_effective_validator_set(engine, governance, current_time_ms());
                            info!(slot, builder = %builder, amount, "Slashed builder balance");
                        }
                        Ok(None) => {
                            warn!(slot, builder = %builder, "Builder account missing during slash");
                        }
                        Err(e) => {
                            warn!(slot, builder = %builder, %e, "Failed to slash builder");
                        }
                    }
                    if let Err(e) =
                        persistence.persist_tree(state, engine.genesis_hash, genesis_time_ms)
                    {
                        warn!(slot, %e, "Failed to persist state after slashing builder");
                    }
                    if let Err(e) = governance.persist() {
                        warn!(slot, %e, "Failed to persist governance after slashing builder");
                    }
                } else {
                    warn!(slot, "No block found for slash action");
                }
            }
        }
        FinalityAction::RequeueTxs => {
            #[cfg(feature = "devnet")]
            {
                tracing::debug!(slot, "Devnet: skipping RequeueTxs");
            }
            #[cfg(not(feature = "devnet"))]
            {
                info!(slot, "Rolling back state and requeuing transactions");
                let _ = do_rollback(
                    slot,
                    engine,
                    state,
                    block_store,
                    tx_receipt_store,
                    eth_events,
                    mempool,
                    governance,
                    persistence,
                    genesis_time_ms,
                );
            }
        }
        FinalityAction::SlashAndRequeue => {
            #[cfg(feature = "devnet")]
            {
                tracing::debug!(slot, "Devnet: skipping SlashAndRequeue");
            }
            #[cfg(not(feature = "devnet"))]
            {
                info!(slot, "Slashing builder + rolling back state");

                // Track leader absence for the expected leader of this slot.
                let expected_leader = engine
                    .leader_schedule
                    .leader_for_slot(slot, &engine.validator_set);
                governance.note_leader_absence(&expected_leader);

                let builder = block_store
                    .read()
                    .get_block_by_slot(slot)
                    .map(|block| AccountId(block.header.leader_idcom));
                if let Some(builder) = builder {
                    if let Err(e) = governance.slash_builder(&builder, &mut state.write()) {
                        warn!(slot, builder = %builder, %e, "Failed to slash builder before rollback");
                    } else {
                        sync_effective_validator_set(engine, governance, current_time_ms());
                    }
                }
                let _ = do_rollback(
                    slot,
                    engine,
                    state,
                    block_store,
                    tx_receipt_store,
                    eth_events,
                    mempool,
                    governance,
                    persistence,
                    genesis_time_ms,
                );
            }
        }
    }
}

/// Perform a state rollback for a given slot.
fn do_rollback<B: BlockStore>(
    slot: u64,
    engine: &mut ConsensusEngine,
    state: &Arc<RwLock<ace_model::sharded_state::ShardedState>>,
    block_store: &Arc<RwLock<B>>,
    tx_receipt_store: &Arc<RwLock<TxReceiptStore>>,
    eth_events: &Arc<EthEventHub>,
    mempool: &Arc<Mempool>,
    governance: &mut RuntimeGovernance,
    persistence: &PersistenceHandles,
    genesis_time_ms: u64,
) -> bool {
    let (latest_slot, first_present_slot) = {
        let store = block_store.read();
        let latest_slot = store.latest_slot();
        let first_present_slot = if latest_slot >= slot {
            (slot..=latest_slot).find(|&candidate| store.get_block_by_slot(candidate).is_some())
        } else {
            None
        };
        (latest_slot, first_present_slot)
    };

    // Prefer the exact slot snapshot when it exists. If the rollback slot itself is missing but a
    // later speculative block exists (for example we produced slot N+1 before slot N arrived),
    // fall back to the earliest later slot snapshot so we can still rewind the branch.
    let (snapshot_slot, snapshot) = if let Some(snapshot) = engine.take_snapshot(slot) {
        (Some(slot), Some(snapshot))
    } else if let Some(existing_slot) = first_present_slot.filter(|&s| s > slot) {
        (Some(existing_slot), engine.take_snapshot(existing_slot))
    } else {
        (None, None)
    };

    if snapshot.is_none() && first_present_slot.is_none() {
        tracing::debug!(
            slot,
            "Rollback with no local block and no later local branch; clearing slot state"
        );
        engine.reset_slot(slot);
        return true;
    }

    if let Some(snap) = snapshot {
        state.write().rollback(snap);
    } else {
        // No usable snapshot. This is only safe if every block we are about
        // to delete is empty, because empty blocks do not mutate state.
        let mut first_nonempty_slot = None;
        if latest_slot >= slot {
            let store = block_store.read();
            for candidate in slot..=latest_slot {
                let Some(block) = store.get_block_by_slot(candidate) else {
                    continue;
                };
                if !block.transactions.is_empty() {
                    first_nonempty_slot = Some(candidate);
                    break;
                }
            }
        }
        if let Some(nonempty_slot) = first_nonempty_slot {
            warn!(
                slot,
                nonempty_slot,
                "No usable snapshot for rollback and branch contains transactions; cannot restore state"
            );
            return false;
        }
        tracing::info!(
            slot,
            latest_slot,
            "Lightweight reorg: no snapshot needed (empty speculative branch), removing conflicting blocks"
        );
    }
    engine.reset_slot(slot);

    // Remove all blocks at and after the rollback slot and requeue their transactions.
    // This keeps `state` and `block_store` consistent even if later slots have been produced.
    let (removed_slots, new_last_hash) = {
        let mut store = block_store.write();
        let latest_slot = store.latest_slot();
        if latest_slot < slot {
            warn!(
                slot,
                latest_slot,
                "Rollback slot is beyond latest_slot; nothing to delete from block store"
            );
        }

        let mut removed_slots = Vec::new();
        if latest_slot >= slot {
            for s in slot..=latest_slot {
                if let Some(block) = store.delete_block_by_slot(s) {
                    mempool.requeue(block.transactions);
                    removed_slots.push(s);
                }
            }
        }

        // Recompute last_block_hash from the highest remaining block, or fall back to genesis_hash.
        (
            removed_slots,
            canonical_tip_hash(&*store, engine.genesis_hash),
        )
    };

    for &s in &removed_slots {
        engine.reset_slot(s);
    }

    if !removed_slots.is_empty() {
        let mut receipt_store = tx_receipt_store.write();
        let mut removed_logs = Vec::new();
        for removed_slot in removed_slots {
            removed_logs.extend(
                receipt_store
                    .get_receipts_for_slot(removed_slot)
                    .into_iter()
                    .flat_map(|receipt| receipt.evm_logs.into_iter()),
            );
            receipt_store.remove_receipts_for_slot(removed_slot);
        }
        drop(receipt_store);
        if !removed_logs.is_empty() {
            eth_events.publish_removed_logs(removed_logs);
        }
    }

    engine.last_block_hash = new_last_hash;
    governance.rollback(snapshot_slot.unwrap_or(slot));
    if let Err(error) = engine.rebuild_full_validator_set(&governance.approved_validators()) {
        tracing::error!(%error, slot, "failed to rebuild validator set after rollback");
        return false;
    }
    let tip_slot = {
        let store = block_store.read();
        canonical_tip_slot(&*store).unwrap_or(0)
    };
    sync_effective_validator_set(engine, governance, slot_time_ms(genesis_time_ms, tip_slot));

    if let Err(e) = persistence.persist_tree(state, engine.genesis_hash, genesis_time_ms) {
        warn!(slot, %e, "Failed to persist state after rollback");
    }
    if let Err(e) = governance.persist() {
        warn!(slot, %e, "Failed to persist governance after rollback");
    }

    true
}

fn sync_effective_validator_set(
    engine: &mut ConsensusEngine,
    governance: &RuntimeGovernance,
    now_ms: u64,
) {
    let effective = governance.effective_validator_set(&engine.full_validator_set, now_ms);
    let full_count = engine.full_validator_set.len();
    let eff_count = effective.len();
    if eff_count < full_count {
        tracing::warn!(
            full = full_count,
            effective = eff_count,
            "Effective validator set reduced — some validators suspended"
        );
    }
    engine.set_effective_validator_set(effective);
}

fn slot_time_ms(genesis_time_ms: u64, slot: u64) -> u64 {
    genesis_time_ms.saturating_add(slot.saturating_mul(ace_runtime::config::SLOT_DURATION_MS))
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_millis() as u64
}

#[derive(Debug)]
enum AutoDevFinalityCertificate {
    Ready(FinalityCertificate),
    RequiresProverCompanion,
    Unavailable(&'static str),
}

#[cfg(not(feature = "devnet"))]
fn block_has_provable_transactions(block: &Block) -> bool {
    block.transactions.iter().any(|tx| tx.raw_chain.is_none())
}

fn build_auto_dev_finality_certificate(
    block: &Block,
    verifier: &dyn ProofVerifier,
    proof_mode: ProofMode,
) -> AutoDevFinalityCertificate {
    match proof_mode {
        ProofMode::Production => AutoDevFinalityCertificate::RequiresProverCompanion,
        ProofMode::DevMock => {
            #[cfg(feature = "devnet")]
            {
                let cert = MockProver::create_mock_fc_with_block(block);
                if verifier.verify_finality_certificate_for_block(&cert, block) {
                    AutoDevFinalityCertificate::Ready(cert)
                } else {
                    AutoDevFinalityCertificate::Unavailable(
                        "generated mock finality certificate failed local verification",
                    )
                }
            }
            #[cfg(not(feature = "devnet"))]
            {
                let _ = (block, verifier);
                AutoDevFinalityCertificate::Unavailable(
                    "dev-mock automatic finality requires the `devnet` feature",
                )
            }
        }
        ProofMode::DevStark => {
            #[cfg(not(feature = "devnet"))]
            if block_has_provable_transactions(block) {
                return AutoDevFinalityCertificate::RequiresProverCompanion;
            }

            #[cfg(feature = "stark")]
            {
                let cert = ace_runtime::crypto::proof::create_stark_fc_for_block(block);
                if verifier.verify_finality_certificate_for_block(&cert, block) {
                    AutoDevFinalityCertificate::Ready(cert)
                } else {
                    AutoDevFinalityCertificate::Unavailable(
                        "generated STARK finality certificate failed local verification",
                    )
                }
            }
            #[cfg(not(feature = "stark"))]
            {
                let _ = (block, verifier);
                AutoDevFinalityCertificate::Unavailable(
                    "dev-stark automatic finality requires the `stark` feature",
                )
            }
        }
    }
}

/// Convert VM execution receipts to RPC receipt format and set block_slot, block_hash, transaction_index.
fn vm_receipts_to_rpc(
    txs: &[Transaction],
    receipts: &[ace_n_vm::VmReceipt],
    block_slot: u64,
    block_hash_hex: &str,
) -> Vec<RpcTransactionReceipt> {
    receipts
        .iter()
        .enumerate()
        .map(|(index, r)| {
            let tx = txs.get(index).expect("receipt/tx index mismatch");
            let state_changes = r.state_changes.iter().map(state_change_to_rpc).collect();
            let external_transaction_hash = tx.raw_chain.as_ref().and_then(|raw_chain| {
                (raw_chain.kind == ace_runtime::types::transaction::RawChainKind::Evm)
                    .then(|| hex::encode(evm_tx_hash(&raw_chain.raw_bytes)))
            });
            let tx_hash_for_logs = external_transaction_hash
                .clone()
                .unwrap_or_else(|| hex::encode(r.tx_hash));
            let evm_logs = r
                .logs
                .iter()
                .enumerate()
                .map(|(log_index, log)| EthLog {
                    address: format!("0x{}", hex::encode(log.address)),
                    topics: log
                        .topics
                        .iter()
                        .map(|topic| format!("0x{}", hex::encode(topic)))
                        .collect(),
                    data: format!("0x{}", hex::encode(&log.data)),
                    block_number: format!("0x{:x}", block_slot),
                    transaction_hash: format!("0x{}", tx_hash_for_logs),
                    transaction_index: format!("0x{:x}", index),
                    block_hash: format!("0x{}", block_hash_hex),
                    log_index: format!("0x{:x}", log_index),
                    removed: false,
                })
                .collect();
            RpcTransactionReceipt {
                transaction_hash: hex::encode(r.tx_hash),
                external_transaction_hash,
                block_slot,
                block_hash: block_hash_hex.to_string(),
                transaction_index: index as u32,
                from: hex::encode(r.sender.0),
                status: r.success,
                error: r.error.clone(),
                state_changes,
                gas_used: r.gas_used,
                contract_address: r.contract_address.map(hex::encode),
                evm_logs,
            }
        })
        .collect()
}

fn mark_admission_failures(receipts: &mut [RpcTransactionReceipt], failures: Vec<(usize, String)>) {
    for (index, error) in failures {
        if let Some(receipt) = receipts.get_mut(index) {
            receipt.status = false;
            receipt.error = Some(error);
        }
    }
}

fn process_block_validator_admissions(
    transactions: &[ace_runtime::types::transaction::Transaction],
    governance: &mut RuntimeGovernance,
    full_validator_set: &mut ace_consensus::validator_set::ValidatorSet,
    block_time_ms: u64,
    slot: u64,
    path: &'static str,
) -> Vec<(usize, String)> {
    use ace_engine::executor::{TransactionOp, OP_APPROVE_VALIDATOR};

    let mut admission_failures = Vec::new();
    for (tx_index, tx) in transactions.iter().enumerate() {
        if tx.payload.first() != Some(&OP_APPROVE_VALIDATOR) {
            continue;
        }
        match TransactionOp::decode(&tx.payload) {
            Ok(TransactionOp::ApproveValidator {
                candidate_id_com,
                signing_pubkey,
                ..
            }) => {
                let sender = ace_model::account::AccountId::from_bytes(tx.attestation.idcom);
                match governance.admit_validator(
                    sender,
                    candidate_id_com,
                    &signing_pubkey,
                    full_validator_set,
                    block_time_ms,
                ) {
                    Ok(_validator) => {
                        tracing::info!(
                            id_com = hex::encode(candidate_id_com.0),
                            slot,
                            %path,
                            "new validator admitted"
                        );
                    }
                    Err(e) => {
                        admission_failures.push((tx_index, e.to_string()));
                        tracing::warn!(
                            id_com = hex::encode(candidate_id_com.0),
                            slot,
                            %path,
                            %e,
                            "ApproveValidator admission failed"
                        );
                    }
                }
            }
            Ok(_) => {}
            Err(e) => {
                admission_failures.push((tx_index, e.to_string()));
                tracing::warn!(slot, %path, %e, "ApproveValidator payload decode failed");
            }
        }
    }
    admission_failures
}

fn state_change_to_rpc(sc: &EngineStateChange) -> RpcStateChange {
    match sc {
        EngineStateChange::BalanceChange { account, old, new } => RpcStateChange::BalanceChange {
            account: hex::encode(account.0),
            old: *old,
            new: *new,
        },
        EngineStateChange::NonceIncrement { account, new_nonce } => {
            RpcStateChange::NonceIncrement {
                account: hex::encode(account.0),
                new_nonce: *new_nonce,
            }
        }
        EngineStateChange::AccountCreated { account } => RpcStateChange::AccountCreated {
            account: hex::encode(account.0),
        },
        EngineStateChange::StorageChange {
            account,
            slot,
            old_value,
            new_value,
        } => RpcStateChange::StorageChange {
            account: hex::encode(account.0),
            slot: hex::encode(slot),
            old_value: hex::encode(old_value),
            new_value: hex::encode(new_value),
        },
        EngineStateChange::CodeDeployed { account, code_hash } => RpcStateChange::CodeDeployed {
            account: hex::encode(account.0),
            code_hash: hex::encode(code_hash),
        },
        EngineStateChange::Fee { amount } => RpcStateChange::Fee { amount: *amount },
        EngineStateChange::AddressBound {
            account,
            address_type,
        } => RpcStateChange::AddressBound {
            account: hex::encode(account.0),
            address_type: *address_type,
        },
        EngineStateChange::AuthKeyUpdated { account, algorithm } => {
            RpcStateChange::AuthKeyUpdated {
                account: hex::encode(account.0),
                algorithm: *algorithm,
            }
        }
        EngineStateChange::IntentChange {
            intent_id,
            old_status,
            new_status,
            claim_tag,
        } => RpcStateChange::IntentChange {
            intent_id: hex::encode(intent_id),
            old_status: *old_status,
            new_status: *new_status,
            claim_tag: claim_tag.as_ref().map(hex::encode),
        },
        EngineStateChange::ZkReplayConsumed { rp_com, account } => {
            RpcStateChange::ZkReplayConsumed {
                rp_com: hex::encode(rp_com),
                account: hex::encode(account.0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_local_identity_to_config, assess_inbound_block, build_block_sync_response,
        canonical_tip_hash, do_rollback, ensure_peer_id_in_multiaddr,
        ensure_persistent_chain_compatibility, legacy_dummy_serializable_witness,
        local_identity_path, mark_admission_failures, parse_config_proof_mode,
        resolve_loaded_identity, resolve_local_signing_key, should_defer_leader_production,
        should_enforce_domain_slot_tolerance, validate_multinode_genesis_time,
        validate_production_genesis, validate_runtime_chain_id, witness_for_tx,
        InboundBlockDecision, Node, PersistenceHandles, RelayAbuseGuard,
    };
    #[cfg(all(feature = "devnet", feature = "stark"))]
    use super::{build_auto_dev_finality_certificate, AutoDevFinalityCertificate};
    #[cfg(all(feature = "devnet", feature = "stark"))]
    use crate::capability::ApprovalCollector;
    use crate::cli::Cli;
    use crate::companion_protocol::SerializablePrivateWitness;
    use crate::config::{NodeConfig, DEFAULT_CHAIN_ID};
    use crate::genesis::{
        derive_devnet_auth_pubkey, genesis_config_hash, initialize_genesis, GenesisAccount,
        GenesisConfig, GenesisValidator,
    };
    use crate::governance::RuntimeGovernance;
    use crate::proof_material::ProofMode;
    use ace_consensus::engine::ConsensusEngine;
    use ace_consensus::leader_schedule::LeaderSchedule;
    use ace_consensus::poh::PohChain;
    use ace_consensus::validator_set::{Validator, ValidatorSet};
    use ace_identity::{AceChainIdentity, WalletPublicView, ACEGF};
    use ace_mempool::{Mempool, MempoolConfig};
    use ace_model::account::{Account, AccountId};
    use ace_model::block_store::{BlockStore, InMemoryBlockStore};
    use ace_model::rocks_state_db::ChainIdentityMetadata;
    use ace_model::sharded_state::ShardedState;
    use ace_p2p::messages::BlockSyncRequest;
    use ace_rpc::eth_rpc::EthEventHub;
    use ace_rpc::methods::TxReceiptStore;
    use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
    use ace_runtime::crypto::proof::AlwaysInvalidProver;
    use ace_runtime::crypto::sig_algo::{LocalSigningKey, SignatureAlgorithm};
    use ace_runtime::crypto::TaggedPubkey;
    use ace_runtime::crypto::TaggedSignature;
    use ace_runtime::types::attestation::{Attestation, Domain};
    use ace_runtime::types::block::{
        Block, BlockHeader, MevAceCommitment, MevAceOmissionKind, MevAceOmissionProof,
    };
    use ace_runtime::types::capability::ValidatorCapabilities;
    #[cfg(all(feature = "devnet", feature = "stark"))]
    use ace_runtime::types::finality::FinalityProofMode;
    use ace_runtime::types::finality::FinalityState;
    use ace_runtime::types::transaction::{RawChainKind, Transaction};
    use parking_lot::RwLock;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    fn make_block(slot: u64, parent_hash: [u8; 32]) -> Block {
        Block {
            header: BlockHeader {
                slot,
                parent_hash,
                state_root: [slot as u8; 32],
                tx_merkle_root: [0u8; 32],
                attest_merkle_root: [0u8; 32],
                poh_hash: [1u8; 32],
                leader_idcom: [2u8; 32],
                timestamp: 1000 + slot,
                tx_count: 0,
                round: 0,
                mev_ace_material_hash: [0u8; 32],
            },
            transactions: vec![],
            mev_ace: None,
        }
    }

    fn make_block_with_txs(
        slot: u64,
        parent_hash: [u8; 32],
        transactions: Vec<Transaction>,
    ) -> Block {
        let mut block = make_block(slot, parent_hash);
        block.header.tx_count = transactions.len() as u32;
        block.transactions = transactions;
        block
    }

    fn make_block_with_valid_roots(
        slot: u64,
        parent_hash: [u8; 32],
        transactions: Vec<Transaction>,
    ) -> Block {
        let mut block = make_block_with_txs(slot, parent_hash, transactions);
        block.header.tx_merkle_root =
            ace_runtime::types::block::compute_tx_merkle_root(&block.transactions);
        block.header.attest_merkle_root =
            ace_runtime::types::block::compute_attest_merkle_root(&block.transactions);
        block
    }

    fn single_validator_set(id_com: [u8; 32]) -> ValidatorSet {
        ValidatorSet::new(vec![Validator {
            id_com: AccountId(id_com),
            stake: 100,
            index: 0,
            signing_pubkey: TaggedPubkey::ed25519([0x22; 32]),
            capabilities: ValidatorCapabilities::default(),
        }])
    }

    fn validator_set_with_members(ids_and_stakes: &[([u8; 32], u64)]) -> ValidatorSet {
        ValidatorSet::new(
            ids_and_stakes
                .iter()
                .enumerate()
                .map(|(index, (id_com, stake))| Validator {
                    id_com: AccountId(*id_com),
                    stake: *stake,
                    index: index as u32,
                    signing_pubkey: TaggedPubkey::ed25519([index as u8 + 1; 32]),
                    capabilities: ValidatorCapabilities::default(),
                })
                .collect(),
        )
    }

    fn find_slot_led_by(
        validator_set: &ValidatorSet,
        genesis_hash: [u8; 32],
        expected_leader: [u8; 32],
        start_slot: u64,
    ) -> u64 {
        (start_slot..start_slot.saturating_add(512))
            .find(|&slot| {
                LeaderSchedule::new(genesis_hash)
                    .leader_for_slot(slot, validator_set)
                    .0
                    == expected_leader
            })
            .expect("should find a slot led by the requested validator")
    }

    fn make_test_engine(genesis_hash: [u8; 32], validator_set: ValidatorSet) -> ConsensusEngine {
        ace_consensus::engine::ConsensusEngine::new(
            validator_set.get_by_index(0).expect("validator").id_com,
            LeaderSchedule::new(genesis_hash),
            validator_set,
            PohChain::new(genesis_hash),
            ace_n_vm::NVm::with_defaults(),
            genesis_hash,
        )
    }

    fn signing_validator_set(id_com: [u8; 32], seed: [u8; 32]) -> (ValidatorSet, LocalSigningKey) {
        let signing_key = LocalSigningKey::from_seed(&seed, SignatureAlgorithm::Ed25519).unwrap();
        (
            ValidatorSet::new(vec![Validator {
                id_com: AccountId(id_com),
                stake: 100,
                index: 0,
                signing_pubkey: signing_key.public_key(),
                capabilities: ValidatorCapabilities::default(),
            }]),
            signing_key,
        )
    }

    fn set_expected_leader(
        block: &mut Block,
        slot: u64,
        validator_set: &ValidatorSet,
        genesis_hash: [u8; 32],
    ) {
        block.header.leader_idcom = LeaderSchedule::new(genesis_hash)
            .leader_for_slot(slot, validator_set)
            .0;
    }

    fn cast_signed_vote(
        engine: &mut ConsensusEngine,
        slot: u64,
        block_hash: [u8; 32],
        voter: AccountId,
        signing_key: &LocalSigningKey,
        chain_id: u32,
    ) {
        let vote_msg = ace_consensus::vote::Vote::sign_message(slot, &block_hash, &voter, chain_id);
        let vote = ace_consensus::vote::Vote {
            slot,
            block_hash,
            voter,
            voter_stake: 0,
            signature: signing_key.sign(&vote_msg),
            chain_id,
            round: 0,
            vote_type: ace_consensus::vote::VoteType::default(),
        };
        let verifier = AlwaysInvalidProver;
        let _ = engine.on_vote(vote, &verifier);
    }

    fn governance_for_test() -> RuntimeGovernance {
        RuntimeGovernance::load_or_new(
            &GenesisConfig {
                accounts: vec![],
                validators: vec![
                    GenesisValidator {
                        id_com: "11".repeat(32),
                        stake: 100,
                        signing_pubkey: String::new(),
                        capabilities: ValidatorCapabilities::default(),
                    },
                    GenesisValidator {
                        id_com: "22".repeat(32),
                        stake: 100,
                        signing_pubkey: String::new(),
                        capabilities: ValidatorCapabilities::default(),
                    },
                ],
                genesis_time_ms: 1_000,
                chain_id: 1,
                native_token: None,
                affiliates: vec![],
                founder_id_com: String::new(),
                validator_admission_policy: crate::genesis::default_validator_admission_policy(),
                protocol_version: crate::genesis::MIN_PROTOCOL_VERSION,
                ace_defi_approved_relayers: vec![],
            },
            1_000,
            None,
        )
        .unwrap()
    }

    fn make_native_tx(obj_tag: u8, slot: u32) -> Transaction {
        let payload = vec![0x30, obj_tag];
        let mut obj_hash = [0u8; 32];
        obj_hash[0] = obj_tag;
        Transaction::new(
            payload,
            Attestation {
                obj_hash,
                idcom: [obj_tag; 32],
                domain: Domain::new(1, slot),
                context_tag: [0u8; 16],
                credential: TaggedSignature::ed25519([0u8; 64]),
            },
        )
    }

    fn mev_reordering_case(slot: u64) -> ([u8; 32], Vec<Transaction>, Vec<Transaction>) {
        let input = vec![
            make_native_tx(0x41, slot as u32),
            make_native_tx(0x42, slot as u32),
            make_native_tx(0x43, slot as u32),
            make_native_tx(0x44, slot as u32),
        ];
        let input_hashes = input.iter().map(Transaction::tx_hash).collect::<Vec<_>>();
        for seed in 0u8..=u8::MAX {
            let parent_hash = [seed; 32];
            let ordered =
                ace_consensus::mev_ace::fair_order_transactions(parent_hash, slot, input.clone());
            let ordered_hashes = ordered.iter().map(Transaction::tx_hash).collect::<Vec<_>>();
            if ordered_hashes != input_hashes {
                return (parent_hash, input, ordered);
            }
        }
        panic!("test fixture should find a non-identity MEV-ACE permutation");
    }

    #[test]
    fn tendermint_proposal_builder_applies_mev_ace_fair_order() {
        let height = 23;
        let (parent_hash, txs, expected) = mev_reordering_case(height);
        let input_hashes = txs.iter().map(Transaction::tx_hash).collect::<Vec<_>>();
        let expected_hashes = expected
            .iter()
            .map(Transaction::tx_hash)
            .collect::<Vec<_>>();
        let validator_set = single_validator_set([0x11; 32]);
        let state = Arc::new(RwLock::new(ShardedState::new()));
        let block_store = Arc::new(RwLock::new(
            ace_model::block_store::InMemoryBlockStore::new(),
        ));
        let mut governance = governance_for_test();

        let prepared = super::build_tendermint_proposal_with_context(
            parent_hash,
            AccountId([0x11; 32]),
            PohChain::new(parent_hash),
            &validator_set,
            &ace_n_vm::NVm::with_defaults(),
            height,
            0,
            1_000,
            &state,
            &block_store,
            txs,
            &mut governance,
            Some(state.read().compute_root()),
            0,
            u64::MAX,
            None,
        )
        .expect("proposal should build");

        let output_hashes = prepared
            .block
            .transactions
            .iter()
            .map(Transaction::tx_hash)
            .collect::<Vec<_>>();
        assert_eq!(output_hashes, expected_hashes);
        assert_ne!(output_hashes, input_hashes);
        assert!(ace_consensus::mev_ace::is_fair_ordered(
            parent_hash,
            height,
            &prepared.block.transactions
        ));
    }

    #[test]
    fn tendermint_proposal_validator_rejects_non_mev_ace_order() {
        let height = 29;
        let (parent_hash, txs, _) = mev_reordering_case(height);
        let validator_set = single_validator_set([0x11; 32]);
        let state = Arc::new(RwLock::new(ShardedState::new()));
        let block_store = Arc::new(RwLock::new(
            ace_model::block_store::InMemoryBlockStore::new(),
        ));
        let mut governance = governance_for_test();
        let mut prepared = super::build_tendermint_proposal_with_context(
            parent_hash,
            AccountId([0x11; 32]),
            PohChain::new(parent_hash),
            &validator_set,
            &ace_n_vm::NVm::with_defaults(),
            height,
            0,
            1_000,
            &state,
            &block_store,
            txs,
            &mut governance,
            Some(state.read().compute_root()),
            0,
            u64::MAX,
            None,
        )
        .expect("proposal should build");

        prepared.block.transactions.reverse();
        assert!(!ace_consensus::mev_ace::is_fair_ordered(
            parent_hash,
            height,
            &prepared.block.transactions
        ));

        let mut validation_governance = governance_for_test();
        let rejected = super::validate_tendermint_proposal_with_context(
            &prepared.block,
            height,
            0,
            parent_hash,
            &validator_set,
            &ace_n_vm::NVm::with_defaults(),
            &state,
            &block_store,
            &mut validation_governance,
            1_000,
            Some(state.read().compute_root()),
            0,
            u64::MAX,
        );
        assert!(rejected.is_none());
    }

    #[test]
    fn inbound_block_validation_rejects_non_mev_ace_order_after_activation() {
        let height = 31;
        let (parent_hash, txs, ordered) = mev_reordering_case(height);
        let validator_set = single_validator_set([0x11; 32]);
        let engine = make_test_engine(parent_hash, validator_set);
        let block_store = Arc::new(RwLock::new(InMemoryBlockStore::new()));

        let block = make_block_with_valid_roots(height, parent_hash, txs);

        let active = assess_inbound_block(&block, height, &engine, &block_store, true, 0);
        assert_eq!(active, InboundBlockDecision::Reject);

        let inactive =
            assess_inbound_block(&block, height, &engine, &block_store, true, height + 1);
        assert_eq!(inactive, InboundBlockDecision::Apply);

        let ordered_block = make_block_with_valid_roots(height, parent_hash, ordered);
        let ordered_result =
            assess_inbound_block(&ordered_block, height, &engine, &block_store, true, 0);
        assert_eq!(ordered_result, InboundBlockDecision::Apply);
    }

    #[test]
    fn discovered_multiaddr_gets_peer_id_suffix() {
        assert_eq!(
            ensure_peer_id_in_multiaddr("/ip4/203.0.113.9/tcp/31333", "12D3KooWPeer"),
            "/ip4/203.0.113.9/tcp/31333/p2p/12D3KooWPeer"
        );
        assert_eq!(
            ensure_peer_id_in_multiaddr("/ip4/203.0.113.9/tcp/31333/p2p/12D3KooWPeer", "ignored"),
            "/ip4/203.0.113.9/tcp/31333/p2p/12D3KooWPeer"
        );
    }

    #[test]
    fn relay_abuse_guard_drops_duplicate_tx_hash() {
        let mut guard = RelayAbuseGuard::default();
        let tx = make_native_tx(0x41, 10);
        assert!(guard.allow_tx(Some("peer-a"), &tx));
        assert!(!guard.allow_tx(Some("peer-a"), &tx));
    }

    #[test]
    fn relay_abuse_guard_penalizes_invalid_peer() {
        let mut guard = RelayAbuseGuard::default();
        let err = ace_mempool::MempoolError::InvalidChainId {
            expected: 1,
            got: 2,
        };
        for _ in 0..20 {
            guard.record_rejection(Some("peer-b"), &err);
        }
        assert!(!guard.allow_tx(Some("peer-b"), &make_native_tx(0x42, 10)));
        assert!(guard.allow_tx(Some("peer-c"), &make_native_tx(0x43, 10)));
    }

    fn make_raw_tx(kind: RawChainKind, slot: u32) -> Transaction {
        let tag = kind.tag();
        let payload = vec![tag, 0xAA];
        let mut obj_hash = [0u8; 32];
        obj_hash[0] = tag;
        Transaction::with_raw_chain(
            payload,
            Attestation {
                obj_hash,
                idcom: [tag; 32],
                domain: Domain::new(1, slot),
                context_tag: [0u8; 16],
                credential: TaggedSignature::ed25519([0u8; 64]),
            },
            kind,
            vec![0x01],
        )
    }

    fn make_signed_svm_transfer_tx(
        auth_seed: [u8; 32],
        sender_idcom: [u8; 32],
        recipient_idcom: [u8; 32],
        amount: u64,
    ) -> Transaction {
        let mut payload = Vec::with_capacity(49);
        payload.push(0x21);
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&recipient_idcom);
        payload.extend_from_slice(&amount.to_le_bytes());

        let mut obj_hash = [0u8; 32];
        obj_hash.copy_from_slice(&Sha256::digest(&payload));
        let domain = Domain::new(1, 0);

        Transaction::new(
            payload,
            Attestation {
                obj_hash,
                idcom: sender_idcom,
                domain,
                context_tag: [0u8; 16],
                credential: make_credential(
                    &auth_seed,
                    &obj_hash,
                    &sender_idcom,
                    &domain,
                    &[0u8; 16],
                ),
            },
        )
    }

    fn make_signed_create_account_tx(auth_seed: [u8; 32], sender_idcom: [u8; 32]) -> Transaction {
        let payload = ace_engine::executor::TransactionOp::CreateAccount {
            id_com: AccountId(sender_idcom),
            auth_pubkey: auth_public_key_from_seed(&auth_seed),
        }
        .encode();

        let mut obj_hash = [0u8; 32];
        obj_hash.copy_from_slice(&Sha256::digest(&payload));
        let domain = Domain::new(1, 0);

        Transaction::new(
            payload,
            Attestation {
                obj_hash,
                idcom: sender_idcom,
                domain,
                context_tag: [0u8; 16],
                credential: make_credential(
                    &auth_seed,
                    &obj_hash,
                    &sender_idcom,
                    &domain,
                    &[0u8; 16],
                ),
            },
        )
    }

    #[test]
    fn resolve_local_signing_key_accepts_matching_custom_seed() {
        let local_id = AccountId([1u8; 32]);
        let seed = [7u8; 32];
        let expected_key = LocalSigningKey::from_seed(&seed, SignatureAlgorithm::Ed25519).unwrap();
        let validator_set = ValidatorSet::new(vec![Validator {
            id_com: local_id,
            stake: 100,
            index: 0,
            signing_pubkey: expected_key.public_key(),
            capabilities: ValidatorCapabilities::default(),
        }]);

        let resolved =
            resolve_local_signing_key(&Some(hex::encode(seed)), &local_id, &validator_set, false)
                .expect("custom signing seed should be accepted");

        assert_eq!(resolved.public_key(), expected_key.public_key());
    }

    #[test]
    fn resolve_local_signing_key_rejects_missing_custom_seed() {
        let local_id = AccountId([1u8; 32]);
        let custom_seed = [9u8; 32];
        let custom_key =
            LocalSigningKey::from_seed(&custom_seed, SignatureAlgorithm::Ed25519).unwrap();
        let validator_set = ValidatorSet::new(vec![Validator {
            id_com: local_id,
            stake: 100,
            index: 0,
            signing_pubkey: custom_key.public_key(),
            capabilities: ValidatorCapabilities::default(),
        }]);

        let err = resolve_local_signing_key(&None, &local_id, &validator_set, false)
            .expect_err("custom genesis pubkey should require an explicit seed");

        assert!(err.to_string().contains("validator_signing_seed"));
    }

    #[test]
    fn loaded_identity_profile_persists_and_reloads() {
        let tmp = TempDir::new().unwrap();
        let wallet = ACEGF::generate_wallet("test-passphrase", None).unwrap();
        std::env::set_var("ACE_TEST_IDENTITY_PASSPHRASE", "test-passphrase");
        let cli = Cli {
            config: "ace-node.json".into(),
            rpc_port: None,
            p2p_port: None,
            metrics_port: None,
            log_level: "info".into(),
            validator: false,
            validator_key: None,
            validator_signing_seed: None,
            proof_mode: None,
            genesis_path: None,
            data_dir: None,
            prover_companion_bin: None,
            prover_companion_args: Vec::new(),
            bootstrap_peers: Vec::new(),
            prover_companion_timeout_ms: None,
            prover_witness_file: None,
            restore_mnemonic: Some(wallet.mnemonic.clone()),
            restore_mnemonic_file: None,
            restore_mnemonic_stdin: false,
            identity_passphrase_file: None,
            identity_passphrase_env: Some("ACE_TEST_IDENTITY_PASSPHRASE".into()),
            identity_passphrase_stdin: false,
        };

        let (_, profile) =
            resolve_loaded_identity(&cli, Some(tmp.path().to_str().unwrap()), 1).unwrap();
        let profile = profile.expect("profile should be returned");

        assert!(local_identity_path(tmp.path().to_str().unwrap()).exists());

        let empty_cli = Cli {
            restore_mnemonic: None,
            ..cli
        };
        let (_, reloaded) =
            resolve_loaded_identity(&empty_cli, Some(tmp.path().to_str().unwrap()), 1).unwrap();
        let reloaded = reloaded.expect("persisted profile should exist");

        assert_eq!(profile, reloaded);
    }

    #[test]
    fn restored_identity_can_fill_validator_key() {
        let profile = ace_identity::IdentityPublicProfile {
            chain: AceChainIdentity {
                idcom: [0x11; 32],
                auth_pubkey: [0x22; 32],
                xidentity: "xidentity".into(),
            },
            wallet: WalletPublicView {
                solana_address: "sol".into(),
                evm_address: "0x0".into(),
                bitcoin_address: "btc".into(),
                cosmos_address: "cosmos".into(),
                polkadot_address: "dot".into(),
                xaddress: "xaddress".into(),
                xidentity: "xidentity".into(),
                xkem: String::new(),
            },
        };
        let mut config = NodeConfig::default();
        apply_local_identity_to_config(&mut config, &profile).unwrap();
        assert_eq!(config.validator_key, Some(hex::encode(profile.chain.idcom)));
    }

    #[test]
    fn production_genesis_requires_auth_pubkeys_and_signing_keys() {
        let genesis = GenesisConfig {
            accounts: vec![GenesisAccount {
                id_com: "11".repeat(32),
                balance: 1,
                auth_pubkey: None,
            }],
            validators: vec![GenesisValidator {
                id_com: "11".repeat(32),
                stake: 100,
                signing_pubkey: hex::encode([0x55; 32]),
                capabilities: ValidatorCapabilities::default(),
            }],
            ..GenesisConfig::default()
        };

        let err = validate_production_genesis(&genesis).expect_err("missing auth_pubkey must fail");
        assert!(err.to_string().contains("explicit auth_pubkey"));
    }

    #[test]
    fn production_genesis_rejects_missing_validator_signing_pubkey() {
        let genesis = GenesisConfig {
            accounts: vec![GenesisAccount {
                id_com: "11".repeat(32),
                balance: 1,
                auth_pubkey: Some(hex::encode(&derive_devnet_auth_pubkey(&[0x11; 32]).bytes)),
            }],
            validators: vec![GenesisValidator {
                id_com: "11".repeat(32),
                stake: 100,
                signing_pubkey: String::new(),
                capabilities: ValidatorCapabilities::default(),
            }],
            ..GenesisConfig::default()
        };

        let err = validate_production_genesis(&genesis)
            .expect_err("missing signing_pubkey must fail in production");
        assert!(err.to_string().contains("signing_pubkey"));
    }

    #[test]
    fn production_genesis_rejects_ethereum_mainnet_chain_id() {
        let genesis = GenesisConfig {
            accounts: vec![GenesisAccount {
                id_com: "11".repeat(32),
                balance: 1,
                auth_pubkey: Some(hex::encode(&derive_devnet_auth_pubkey(&[0x11; 32]).bytes)),
            }],
            validators: vec![GenesisValidator {
                id_com: "11".repeat(32),
                stake: 100,
                signing_pubkey: hex::encode([0x55; 32]),
                capabilities: ValidatorCapabilities::default(),
            }],
            chain_id: 1,
            ..GenesisConfig::default()
        };

        let err = validate_production_genesis(&genesis)
            .expect_err("ethereum mainnet chain_id must fail in production");
        assert!(err.to_string().contains("chain_id"));
    }

    #[test]
    fn runtime_chain_id_rejects_ethereum_mainnet_in_production() {
        let err =
            validate_runtime_chain_id(1, ProofMode::Production).expect_err("mainnet chain id");
        assert!(err.to_string().contains("collides"));
        assert!(validate_runtime_chain_id(DEFAULT_CHAIN_ID, ProofMode::Production).is_ok());
    }

    #[test]
    fn multi_node_devnet_requires_explicit_genesis_time() {
        let config = NodeConfig {
            bootnodes: vec!["/ip4/127.0.0.1/tcp/30333/p2p/12D3KooWTestPeer".to_string()],
            ..NodeConfig::default()
        };
        let genesis = GenesisConfig {
            validators: vec![
                GenesisValidator {
                    id_com: "11".repeat(32),
                    stake: 100,
                    signing_pubkey: String::new(),
                    capabilities: ValidatorCapabilities::default(),
                },
                GenesisValidator {
                    id_com: "22".repeat(32),
                    stake: 80,
                    signing_pubkey: String::new(),
                    capabilities: ValidatorCapabilities::default(),
                },
            ],
            genesis_time_ms: 0,
            ..GenesisConfig::default()
        };

        let err = validate_multinode_genesis_time(&config, &genesis)
            .expect_err("multi-node devnet should require explicit genesis time");
        assert!(err.to_string().contains("genesis_time_ms"));

        let mut fixed = genesis.clone();
        fixed.genesis_time_ms = 1_774_071_000_000;
        assert!(validate_multinode_genesis_time(&config, &fixed).is_ok());
    }

    #[cfg(feature = "mock-precompile-n-vm")]
    #[test]
    fn mock_precompile_build_rejects_non_dev_mock_modes() {
        let err = super::ensure_mock_precompile_compatible(ProofMode::Production)
            .expect_err("mock build must reject production");
        assert!(err.to_string().contains("dev-mock"));
        assert!(super::ensure_mock_precompile_compatible(ProofMode::DevMock).is_ok());
    }

    #[test]
    fn failed_execution_rolls_back_fee_and_state_changes() {
        let sender = AccountId([0x11; 32]);
        let recipient = AccountId([0x22; 32]);
        let auth_seed = [0x33; 32];
        let starting_balance = ace_consensus::rewards::TX_FEE + 1;

        let mut state = ace_model::state_tree::StateTree::new();
        state.insert(Account::with_auth(
            sender,
            starting_balance,
            auth_public_key_from_seed(&auth_seed),
        ));

        let tx = make_signed_svm_transfer_tx(auth_seed, sender.0, recipient.0, 2);
        let block_store = Arc::new(RwLock::new(
            ace_model::block_store::InMemoryBlockStore::new(),
        ));
        let mut governance = governance_for_test();
        let (receipts, charged) = super::execute_transactions_with_fees(
            &ace_n_vm::NVm::with_defaults(),
            &ValidatorSet::new(vec![]),
            &block_store,
            &mut state,
            &[tx],
            0,
            &mut governance,
        );

        assert_eq!(charged, 0);
        assert_eq!(receipts.len(), 1);
        assert!(!receipts[0].success);
        assert!(state.get(&recipient).is_none());
        assert_eq!(
            state.get(&sender).expect("sender").balance,
            starting_balance
        );
    }

    #[test]
    fn mev_ace_omission_evidence_consumed_marker_rejects_duplicate_before_slashing() {
        let producer = AccountId([0xA5; 32]);
        let proof = MevAceOmissionProof {
            kind: MevAceOmissionKind::Commit,
            slot: 42,
            commitment: MevAceCommitment {
                idcom: [0xB1; 32],
                commitment: [0xC2; 32],
                slot: 42,
                user_signature: vec![0xD3; 64],
            },
            commit_receipts: vec![],
            opening: None,
            open_receipts: vec![],
            block_hash: [0xE4; 32],
            producer: producer.0,
        };
        let tx = super::build_mev_ace_omission_evidence_tx(&proof, DEFAULT_CHAIN_ID, 100)
            .expect("evidence tx");
        let marker_slot = super::mev_ace_omission_evidence_marker_slot(&proof);
        let mut marker = [0u8; 32];
        marker[0] = 1;

        let mut state = ace_model::state_tree::StateTree::new();
        state.insert(Account::with_balance(producer, 10_000));
        state.insert(Account::new(crate::governance::TREASURY_ACCOUNT));
        state.set_storage(&crate::governance::TREASURY_ACCOUNT, marker_slot, marker);
        let before_producer = state.get(&producer).expect("producer").balance;
        let before_treasury = state
            .get(&crate::governance::TREASURY_ACCOUNT)
            .expect("treasury")
            .balance;

        let block_store = Arc::new(RwLock::new(InMemoryBlockStore::new()));
        let mut governance = governance_for_test();
        let err = super::execute_mev_ace_omission_evidence_system_tx(
            &mut state,
            &tx,
            &block_store,
            &mut governance,
            &single_validator_set(producer.0),
        )
        .expect_err("duplicate evidence must fail before proof verification or slashing");

        assert!(err.contains("already been consumed"));
        assert_eq!(
            state.get(&producer).expect("producer").balance,
            before_producer
        );
        assert_eq!(
            state
                .get(&crate::governance::TREASURY_ACCOUNT)
                .expect("treasury")
                .balance,
            before_treasury
        );
    }

    #[test]
    fn create_account_without_existing_sender_executes_without_fee() {
        let sender = AccountId([0x66; 32]);
        let auth_seed = [0x77; 32];
        let tx = make_signed_create_account_tx(auth_seed, sender.0);
        let mut state = ace_model::state_tree::StateTree::new();
        let block_store = Arc::new(RwLock::new(
            ace_model::block_store::InMemoryBlockStore::new(),
        ));
        let mut governance = governance_for_test();

        let (receipts, charged) = super::execute_transactions_with_fees(
            &ace_n_vm::NVm::with_defaults(),
            &ValidatorSet::new(vec![]),
            &block_store,
            &mut state,
            &[tx],
            0,
            &mut governance,
        );

        assert_eq!(charged, 1);
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].success);
        assert!(state.contains(&sender));
        assert_eq!(state.get(&sender).expect("created account").balance, 0);
    }

    #[test]
    fn proof_mode_parser_rejects_invalid() {
        assert!(parse_config_proof_mode("recursive-dev").is_err());
        assert!(parse_config_proof_mode("groth16-dev").is_err());
        assert!(parse_config_proof_mode("nonsense").is_err());
    }

    #[test]
    fn persistent_chain_compatibility_rejects_different_genesis_config_hash() {
        let genesis = GenesisConfig::default();
        let err = ensure_persistent_chain_compatibility(
            "/tmp/node-1",
            ChainIdentityMetadata {
                genesis_hash: [0x11; 32],
                genesis_time_ms: genesis.genesis_time_ms,
                genesis_config_hash: Some([0x22; 32]),
            },
            &genesis,
        )
        .expect_err("mismatched genesis config hash must fail");

        assert!(err.to_string().contains("different genesis config"));
    }

    #[test]
    fn persistent_chain_compatibility_accepts_matching_legacy_metadata() {
        let mut genesis = GenesisConfig {
            genesis_time_ms: 1_234_567,
            ..GenesisConfig::default()
        };
        genesis.accounts[0].auth_pubkey = Some("11".repeat(32));
        let (_, _, genesis_hash, genesis_time_ms) = initialize_genesis(&genesis).unwrap();

        let returned_hash = ensure_persistent_chain_compatibility(
            "/tmp/node-1",
            ChainIdentityMetadata {
                genesis_hash,
                genesis_time_ms,
                genesis_config_hash: None,
            },
            &genesis,
        )
        .expect("matching legacy metadata should be accepted");

        assert_eq!(returned_hash, genesis_config_hash(&genesis).unwrap());
    }

    #[test]
    fn block_sync_response_contains_requested_records() {
        let mut store = InMemoryBlockStore::new();
        let block1 = make_block(1, [0u8; 32]);
        let block2 = make_block(2, block1.hash());
        store.put_block(block1);
        store.put_block(block2.clone());
        store.set_finality_state(2, FinalityState::Hard);

        let response = build_block_sync_response(
            &store,
            &BlockSyncRequest {
                start_slot: 2,
                limit: 8,
                requester_peer_id: None,
            },
        )
        .expect("response should be built");

        assert_eq!(response.latest_slot, 2);
        assert_eq!(response.records.len(), 1);
        assert_eq!(response.records[0].block.hash(), block2.hash());
        assert_eq!(
            response.records[0].finality_state,
            Some(FinalityState::Hard)
        );
    }

    #[test]
    fn block_sync_response_skips_missing_requested_start_slot() {
        let mut store = InMemoryBlockStore::new();
        let block1 = make_block(1, [0u8; 32]);
        let block3 = make_block(3, block1.hash());
        store.put_block(block1);
        store.put_block(block3.clone());

        let response = build_block_sync_response(
            &store,
            &BlockSyncRequest {
                start_slot: 2,
                limit: 8,
                requester_peer_id: None,
            },
        )
        .expect("response should start at the first available later slot");

        assert_eq!(response.start_slot, 2);
        assert_eq!(response.latest_slot, 3);
        assert_eq!(response.records.len(), 1);
        assert_eq!(response.records[0].block.hash(), block3.hash());
    }

    #[test]
    fn block_sync_response_stops_at_first_gap() {
        let mut store = InMemoryBlockStore::new();
        let block1 = make_block(1, [0u8; 32]);
        let block2 = make_block(2, block1.hash());
        let block4 = make_block(4, block2.hash());
        store.put_block(block1);
        store.put_block(block2.clone());
        store.put_block(block4);

        let response = build_block_sync_response(
            &store,
            &BlockSyncRequest {
                start_slot: 2,
                limit: 8,
                requester_peer_id: None,
            },
        )
        .expect("response should be built");

        assert_eq!(response.records.len(), 1);
        assert_eq!(response.records[0].block.hash(), block2.hash());
    }

    #[test]
    fn sync_assessment_allows_blocks_beyond_live_height_window() {
        let genesis_hash = [9u8; 32];
        let validator_set = single_validator_set([0x11; 32]);
        let engine = make_test_engine(genesis_hash, validator_set.clone());

        let mut store = InMemoryBlockStore::new();
        let mut slot11 = make_block(11, genesis_hash);
        set_expected_leader(&mut slot11, 11, &validator_set, genesis_hash);
        let mut slot12 = make_block(12, slot11.hash());
        set_expected_leader(&mut slot12, 12, &validator_set, genesis_hash);
        let mut slot13 = make_block(13, slot12.hash());
        set_expected_leader(&mut slot13, 13, &validator_set, genesis_hash);
        store.put_block(slot11);
        store.put_block(slot12);
        let block_store = Arc::new(RwLock::new(store));

        let decision = assess_inbound_block(&slot13, 10, &engine, &block_store, true, 0);
        assert_eq!(decision, InboundBlockDecision::Apply);
    }

    #[test]
    fn sync_unknown_parent_requests_sync_before_wrong_leader_rejection() {
        let genesis_hash = [9u8; 32];
        let full_validator_set =
            validator_set_with_members(&[([0x11; 32], 100), ([0x22; 32], 100)]);
        let mut engine = make_test_engine(genesis_hash, full_validator_set.clone());
        engine.set_effective_validator_set(single_validator_set([0x11; 32]));
        let block_store = Arc::new(RwLock::new(InMemoryBlockStore::new()));

        let slot = find_slot_led_by(&full_validator_set, genesis_hash, [0x22; 32], 10);
        let mut block = make_block(slot, [0x44; 32]);
        block.header.leader_idcom = [0x22; 32];

        let decision = assess_inbound_block(&block, 5, &engine, &block_store, true, 0);
        assert_eq!(
            decision,
            InboundBlockDecision::RequestSync { start_slot: 1 }
        );
    }

    #[test]
    fn sync_accepts_full_validator_set_leader_when_effective_set_is_stale() {
        let genesis_hash = [9u8; 32];
        let full_validator_set =
            validator_set_with_members(&[([0x11; 32], 100), ([0x22; 32], 100)]);
        let mut engine = make_test_engine(genesis_hash, full_validator_set.clone());
        engine.set_effective_validator_set(single_validator_set([0x11; 32]));

        let slot = find_slot_led_by(&full_validator_set, genesis_hash, [0x22; 32], 10);
        let mut parent = make_block(slot.saturating_sub(1), genesis_hash);
        parent.header.leader_idcom = [0x11; 32];
        let mut store = InMemoryBlockStore::new();
        store.put_block(parent.clone());
        let block_store = Arc::new(RwLock::new(store));

        let mut block = make_block(slot, parent.hash());
        block.header.leader_idcom = [0x22; 32];

        let decision = assess_inbound_block(&block, slot, &engine, &block_store, true, 0);
        assert_eq!(decision, InboundBlockDecision::Apply);
    }

    #[test]
    fn witness_for_tx_uses_native_map_and_raw_dummy() {
        let native = make_native_tx(0x22, 5);
        let raw = make_raw_tx(RawChainKind::Btc, 5);
        let native_witness = SerializablePrivateWitness {
            root_secret: [0x11; 32],
            salt: [0x22; 32],
            alg_id: 7,
            index: 9,
            nonce: 0x33,
        };
        let mut map = BTreeMap::new();
        map.insert(
            hex::encode(native.attestation.obj_hash),
            native_witness.clone(),
        );

        assert_eq!(witness_for_tx(&native, Some(&map)), Some(native_witness));
        assert_eq!(
            witness_for_tx(&raw, Some(&map)),
            Some(legacy_dummy_serializable_witness())
        );
        assert_eq!(witness_for_tx(&native, None), None);
    }

    #[test]
    fn companion_request_witnesses_requires_native_entries() {
        let tmp = TempDir::new().unwrap();
        let native = make_native_tx(0x44, 9);
        let raw = make_raw_tx(RawChainKind::Solana, 9);
        let block = Block {
            header: BlockHeader {
                slot: 9,
                parent_hash: [0u8; 32],
                state_root: [0u8; 32],
                tx_merkle_root: [0u8; 32],
                attest_merkle_root: [0u8; 32],
                poh_hash: [0u8; 32],
                leader_idcom: [0u8; 32],
                timestamp: 0,
                tx_count: 2,
                round: 0,
                mev_ace_material_hash: [0u8; 32],
            },
            transactions: vec![native.clone(), raw.clone()],
            mev_ace: None,
        };

        let node = Node {
            config: NodeConfig {
                data_dir: Some(tmp.path().display().to_string()),
                prover_witness_file: Some(tmp.path().join("witnesses.json").display().to_string()),
                ..NodeConfig::default()
            },
            genesis: GenesisConfig::default(),
            local_identity: None,
        };

        let err = node
            .companion_request_witnesses(&block)
            .expect_err("native witness should be required");
        assert!(err.to_string().contains("require local witnesses"));

        std::fs::write(tmp.path().join("witnesses.json"), b"{}").unwrap();
        let err = node
            .companion_request_witnesses(&block)
            .expect_err("native witness entry should still be required");
        assert!(err.to_string().contains("missing witness"));

        let mut witness_map = BTreeMap::new();
        let native_witness = SerializablePrivateWitness {
            root_secret: [0xAB; 32],
            salt: [0xCD; 32],
            alg_id: 3,
            index: 1,
            nonce: 0xEF,
        };
        witness_map.insert(
            hex::encode(native.attestation.obj_hash),
            native_witness.clone(),
        );
        std::fs::write(
            tmp.path().join("witnesses.json"),
            serde_json::to_vec(&witness_map).unwrap(),
        )
        .unwrap();

        let witnesses = node
            .companion_request_witnesses(&block)
            .expect("witnesses should load")
            .expect("native block should carry explicit witnesses");
        assert_eq!(
            witnesses,
            vec![native_witness, legacy_dummy_serializable_witness()]
        );
    }

    #[test]
    fn committee_gated_raw_txs_skip_domain_slot_tolerance() {
        assert!(should_enforce_domain_slot_tolerance(&make_native_tx(
            0x55, 10
        )));
        assert!(should_enforce_domain_slot_tolerance(&make_raw_tx(
            RawChainKind::Evm,
            10
        )));
        assert!(!should_enforce_domain_slot_tolerance(&make_raw_tx(
            RawChainKind::Solana,
            1
        )));
        assert!(!should_enforce_domain_slot_tolerance(&make_raw_tx(
            RawChainKind::Btc,
            1
        )));
    }

    #[test]
    fn synced_block_advances_engine_height() {
        let genesis_hash = [9u8; 32];
        let validator_set = single_validator_set([0x11; 32]);
        let mut engine = make_test_engine(genesis_hash, validator_set);
        engine.advance_height(5);

        assert!(super::maybe_advance_engine_to_synced_block(&mut engine, 7));
        assert_eq!(engine.current_height(), 8);
        assert_eq!(engine.current_round(), 0);
        assert_eq!(engine.current_step(), ace_consensus::RoundStep::Propose);

        assert!(!super::maybe_advance_engine_to_synced_block(&mut engine, 6));
        assert_eq!(engine.current_height(), 8);
    }

    #[tokio::test]
    async fn local_proposal_build_panic_requeues_selected_txs() {
        let txs = vec![make_native_tx(0x66, 7), make_native_tx(0x67, 7)];
        let expected_hashes = txs.iter().map(Transaction::tx_hash).collect::<Vec<_>>();
        let (result_tx, mut result_rx) = mpsc::unbounded_channel();

        Node::spawn_local_proposal_build_task_with_builder(
            7,
            2,
            8,
            txs,
            result_tx,
            |_txs| -> Result<super::PreparedProposal, String> {
                panic!("test-induced proposal build panic");
            },
        );

        let event = tokio::time::timeout(Duration::from_secs(2), result_rx.recv())
            .await
            .expect("panic fallback should respond promptly")
            .expect("consensus loop event should be sent");

        match event {
            super::ConsensusLoopEvent::LocalProposalBuilt {
                height,
                round,
                budget,
                requeue_txs,
                prepared,
                ..
            } => {
                assert_eq!(height, 7);
                assert_eq!(round, 2);
                assert_eq!(budget, 8);
                assert_eq!(
                    requeue_txs
                        .iter()
                        .map(Transaction::tx_hash)
                        .collect::<Vec<_>>(),
                    expected_hashes
                );
                let error = match prepared {
                    Ok(_) => panic!("panic should surface as an error result"),
                    Err(error) => error,
                };
                assert!(error.contains("spawn_blocking task failed"));
            }
            _ => panic!("unexpected consensus loop event"),
        }
    }

    #[test]
    fn canonical_tip_hash_prefers_latest_persisted_block() {
        let mut store = InMemoryBlockStore::new();
        let genesis_hash = [9u8; 32];
        assert_eq!(canonical_tip_hash(&store, genesis_hash), genesis_hash);

        let block1 = make_block(1, genesis_hash);
        let hash1 = block1.hash();
        store.put_block(block1);

        assert_eq!(canonical_tip_hash(&store, genesis_hash), hash1);
    }

    #[test]
    fn should_defer_leader_production_when_tip_is_too_far_behind() {
        let mut store = InMemoryBlockStore::new();
        store.put_block(make_block(0, [0u8; 32]));
        store.put_block(make_block(1, [1u8; 32]));

        // Tip is 1, consensus at height 2.
        // We should NOT defer if network is at 1, 2, 3 or 4.
        assert!(!should_defer_leader_production(1, &store, 2));
        assert!(!should_defer_leader_production(4, &store, 2));
        // We SHOULD defer if network is at 5 (5 > 1 + 3) and consensus is behind.
        assert!(should_defer_leader_production(5, &store, 2));

        store.put_block(make_block(4, [4u8; 32]));
        // Tip is 4, consensus at height 5.
        // We should NOT defer if network is at 7.
        assert!(!should_defer_leader_production(7, &store, 5));
        // We SHOULD defer if network is at 8 (8 > 4 + 3) and consensus is behind.
        assert!(should_defer_leader_production(8, &store, 5));
    }

    #[test]
    fn should_not_defer_when_consensus_at_observed_height() {
        // Regression test: when all validators are stuck at the same height,
        // highest_observed_block_slot (from vote messages) equals the consensus
        // height. Deferring in this case deadlocks the chain.
        let mut store = InMemoryBlockStore::new();
        store.put_block(make_block(0, [0u8; 32]));
        store.put_block(make_block(1, [1u8; 32]));
        store.put_block(make_block(1394, [14u8; 32]));

        // All nodes stuck at consensus height 1395, last committed block is
        // 1394.  Observed slot = 1395 (from prevote/precommit messages).
        // Must NOT defer — otherwise no node will ever propose.
        assert!(!should_defer_leader_production(1395, &store, 1395));

        // Even if observed is slightly above consensus (e.g. from a brief
        // network glitch), still don't defer when consensus is close.
        assert!(!should_defer_leader_production(1396, &store, 1395));
    }

    #[test]
    fn unknown_parent_requests_sync_even_with_confirmed_local_chain() {
        // When the parent_hash is completely unknown, we request sync to learn
        // about the parent. The confirmed finality protection kicks in later
        // when the synced blocks are evaluated.
        let genesis_hash = [9u8; 32];
        let validator_set = single_validator_set([0x11; 32]);
        let engine = make_test_engine(genesis_hash, validator_set.clone());

        let mut store = InMemoryBlockStore::new();
        let slot104 = make_block(104, genesis_hash);
        store.put_block(slot104);
        store.set_finality_state(104, FinalityState::Soft);
        let block_store = Arc::new(RwLock::new(store));

        let mut incoming_slot105 = make_block(105, [0xAA; 32]);
        set_expected_leader(&mut incoming_slot105, 105, &validator_set, genesis_hash);

        let decision = assess_inbound_block(&incoming_slot105, 105, &engine, &block_store, true, 0);
        assert_eq!(
            decision,
            InboundBlockDecision::RequestSync { start_slot: 104 }
        );
    }

    #[test]
    fn same_height_fork_prefers_voted_block() {
        let genesis_hash = [9u8; 32];
        let validator_id = [0x11; 32];
        let (validator_set, signing_key) = signing_validator_set(validator_id, [7u8; 32]);
        let mut engine = make_test_engine(genesis_hash, validator_set.clone());

        let mut store = InMemoryBlockStore::new();
        let mut local_slot7 = make_block(7, genesis_hash);
        set_expected_leader(&mut local_slot7, 7, &validator_set, genesis_hash);
        store.put_block(local_slot7.clone());
        let block_store = Arc::new(RwLock::new(store));

        let mut inbound_slot7 = local_slot7.clone();
        inbound_slot7.header.timestamp = inbound_slot7.header.timestamp.saturating_add(1);

        cast_signed_vote(
            &mut engine,
            7,
            inbound_slot7.hash(),
            AccountId(validator_id),
            &signing_key,
            1,
        );

        let decision = assess_inbound_block(&inbound_slot7, 7, &engine, &block_store, true, 0);
        assert_eq!(decision, InboundBlockDecision::Reorg { rollback_slot: 7 });
    }

    #[test]
    fn unknown_parent_requests_sync_for_fork_resolution() {
        // When an inbound block references a parent we don't have (even if that
        // parent has votes), we request sync first. Sync will deliver the parent
        // block, which will then trigger the appropriate fork resolution.
        let genesis_hash = [9u8; 32];
        let validator_id = [0x11; 32];
        let (validator_set, signing_key) = signing_validator_set(validator_id, [8u8; 32]);
        let mut engine = make_test_engine(genesis_hash, validator_set.clone());

        let mut store = InMemoryBlockStore::new();
        let mut local_slot1 = make_block(1, genesis_hash);
        set_expected_leader(&mut local_slot1, 1, &validator_set, genesis_hash);
        let mut local_slot2 = make_block(2, local_slot1.hash());
        set_expected_leader(&mut local_slot2, 2, &validator_set, genesis_hash);
        store.put_block(local_slot1.clone());
        store.put_block(local_slot2);
        let block_store = Arc::new(RwLock::new(store));

        let mut alt_slot2 = make_block(2, local_slot1.hash());
        set_expected_leader(&mut alt_slot2, 2, &validator_set, genesis_hash);
        alt_slot2.header.timestamp = alt_slot2.header.timestamp.saturating_add(1);
        let mut inbound_slot3 = make_block(3, alt_slot2.hash());
        set_expected_leader(&mut inbound_slot3, 3, &validator_set, genesis_hash);

        cast_signed_vote(
            &mut engine,
            2,
            alt_slot2.hash(),
            AccountId(validator_id),
            &signing_key,
            1,
        );

        let decision = assess_inbound_block(&inbound_slot3, 3, &engine, &block_store, true, 0);
        assert_eq!(
            decision,
            InboundBlockDecision::RequestSync { start_slot: 2 }
        );
    }

    #[test]
    fn genesis_parent_is_accepted_when_tip_is_still_genesis() {
        // Regression for the cross-host stranding bug: a freshly-started node
        // (empty store, tip == genesis_hash) MUST accept the very first
        // block(s) on the chain even when their slot is >= 1, because that is
        // the legitimate skip-slot/bootstrap case.  Previously this returned
        // Reject and left the node permanently out of sync.
        let genesis_hash = [9u8; 32];
        let validator_set = single_validator_set([0x11; 32]);
        let engine = make_test_engine(genesis_hash, validator_set.clone());
        let block_store = Arc::new(RwLock::new(InMemoryBlockStore::new()));

        let mut block = make_block(3, genesis_hash);
        set_expected_leader(&mut block, 3, &validator_set, genesis_hash);

        let decision = assess_inbound_block(&block, 3, &engine, &block_store, true, 0);
        assert_eq!(decision, InboundBlockDecision::Apply);
    }

    #[test]
    fn nonzero_slot_genesis_parent_is_rejected_when_tip_advanced() {
        // Once we have committed at least one real block, an inbound block
        // claiming parent == genesis_hash is suspicious (it would orphan our
        // existing chain).  Continue rejecting it.
        let genesis_hash = [9u8; 32];
        let validator_set = single_validator_set([0x11; 32]);
        let engine = make_test_engine(genesis_hash, validator_set.clone());

        let mut store = InMemoryBlockStore::new();
        let mut local_slot1 = make_block(1, genesis_hash);
        set_expected_leader(&mut local_slot1, 1, &validator_set, genesis_hash);
        store.put_block(local_slot1);
        let block_store = Arc::new(RwLock::new(store));

        let mut block = make_block(3, genesis_hash);
        set_expected_leader(&mut block, 3, &validator_set, genesis_hash);

        let decision = assess_inbound_block(&block, 3, &engine, &block_store, true, 0);
        assert_eq!(decision, InboundBlockDecision::Reject);
    }

    #[test]
    fn sparse_gap_tip_extension_is_accepted_with_skip_slots() {
        // When parent_hash matches the canonical tip, the block is accepted
        // immediately even if there are empty (skipped) slots in between.
        // This is the core skip-slot behavior.
        let genesis_hash = [9u8; 32];
        let validator_set = single_validator_set([0x11; 32]);
        let engine = make_test_engine(genesis_hash, validator_set.clone());

        let mut store = InMemoryBlockStore::new();
        let slot128 = make_block(128, genesis_hash);
        store.put_block(slot128.clone());
        let block_store = Arc::new(RwLock::new(store));

        let mut incoming_slot132 = make_block(132, slot128.hash());
        set_expected_leader(&mut incoming_slot132, 132, &validator_set, genesis_hash);

        let decision = assess_inbound_block(&incoming_slot132, 132, &engine, &block_store, true, 0);
        assert_eq!(decision, InboundBlockDecision::Apply);
    }

    #[test]
    fn skip_slot_block_accepted_with_sparse_parent() {
        // When slot 68 is skipped, a block at slot 69 with parent_hash = slot67.hash()
        // should be accepted (this is the normal skip-slot path).
        let genesis_hash = [9u8; 32];
        let validator_set = single_validator_set([0x11; 32]);
        let engine = make_test_engine(genesis_hash, validator_set.clone());

        let mut store = InMemoryBlockStore::new();
        let slot67 = make_block(67, genesis_hash);
        store.put_block(slot67.clone());
        let block_store = Arc::new(RwLock::new(store));

        let mut inbound_slot69 = make_block(69, slot67.hash());
        set_expected_leader(&mut inbound_slot69, 69, &validator_set, genesis_hash);

        let decision = assess_inbound_block(&inbound_slot69, 69, &engine, &block_store, true, 0);
        assert_eq!(decision, InboundBlockDecision::Apply);
    }

    #[test]
    fn sparse_fork_behind_existing_local_continuation_rejected() {
        // When we have slot67 and slot68 locally, a block at slot 69 whose parent
        // is slot67 (skipping our slot68) should be rejected — it forks behind our
        // existing chain.
        let genesis_hash = [9u8; 32];
        let validator_set = single_validator_set([0x11; 32]);
        let engine = make_test_engine(genesis_hash, validator_set.clone());

        let mut store = InMemoryBlockStore::new();
        let slot67 = make_block(67, genesis_hash);
        let slot68 = make_block(68, slot67.hash());
        store.put_block(slot67.clone());
        store.put_block(slot68);
        let block_store = Arc::new(RwLock::new(store));

        let mut inbound_slot69 = make_block(69, slot67.hash());
        set_expected_leader(&mut inbound_slot69, 69, &validator_set, genesis_hash);

        let decision = assess_inbound_block(&inbound_slot69, 69, &engine, &block_store, true, 0);
        assert_eq!(decision, InboundBlockDecision::Reject);
    }

    #[test]
    fn gap_fill_block_triggers_reorg_instead_of_reject() {
        // When we have slot67 and slot69 (parent=slot67), and slot68 (parent=slot67)
        // arrives later (gap-fill), it should trigger a Reorg at slot69 so the
        // gap-fill can be inserted, then slot69 re-evaluated.
        let genesis_hash = [9u8; 32];
        let validator_set = single_validator_set([0x11; 32]);
        let engine = make_test_engine(genesis_hash, validator_set.clone());

        let mut store = InMemoryBlockStore::new();
        let slot67 = make_block(67, genesis_hash);
        let slot69 = make_block(69, slot67.hash());
        store.put_block(slot67.clone());
        store.put_block(slot69);
        let block_store = Arc::new(RwLock::new(store));

        let mut inbound_slot68 = make_block(68, slot67.hash());
        set_expected_leader(&mut inbound_slot68, 68, &validator_set, genesis_hash);

        let decision = assess_inbound_block(&inbound_slot68, 68, &engine, &block_store, true, 0);
        assert_eq!(decision, InboundBlockDecision::Reorg { rollback_slot: 69 });
    }

    #[test]
    fn rollback_missing_slot_removes_later_empty_branch() {
        let genesis_hash = [9u8; 32];
        let validator_set = ValidatorSet::new(vec![Validator {
            id_com: AccountId([0x11; 32]),
            stake: 100,
            index: 0,
            signing_pubkey: TaggedPubkey::ed25519([0x22; 32]),
            capabilities: ValidatorCapabilities::default(),
        }]);
        let mut engine = ace_consensus::engine::ConsensusEngine::new(
            AccountId([0x11; 32]),
            LeaderSchedule::new(genesis_hash),
            validator_set.clone(),
            PohChain::new(genesis_hash),
            ace_n_vm::NVm::with_defaults(),
            genesis_hash,
        );
        let state = Arc::new(RwLock::new(ShardedState::new()));
        let tx_receipt_store = Arc::new(RwLock::new(TxReceiptStore::new()));
        let eth_events = Arc::new(EthEventHub::new(16));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let persistence = PersistenceHandles::disabled();
        let mut governance = governance_for_test();

        let slot96 = make_block(96, genesis_hash);
        let slot98 = make_block(98, slot96.hash());
        let mut store = InMemoryBlockStore::new();
        store.put_block(slot96.clone());
        store.put_block(slot98.clone());
        let block_store = Arc::new(RwLock::new(store));

        engine.store_snapshot(98, state.read().snapshot());
        engine.last_block_hash = slot98.hash();
        governance.snapshot(98);

        assert!(do_rollback(
            97,
            &mut engine,
            &state,
            &block_store,
            &tx_receipt_store,
            &eth_events,
            &mempool,
            &mut governance,
            &persistence,
            1_000,
        ));

        let store = block_store.read();
        assert_eq!(store.latest_slot(), 96);
        assert!(store.get_block_by_slot(97).is_none());
        assert!(store.get_block_by_slot(98).is_none());
        assert_eq!(engine.last_block_hash, slot96.hash());
        assert!(engine.take_snapshot(98).is_none());

        let mut incoming_slot97 = make_block(97, slot96.hash());
        incoming_slot97.header.leader_idcom = LeaderSchedule::new(genesis_hash)
            .leader_for_slot(97, &validator_set)
            .0;
        incoming_slot97.header.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let decision = assess_inbound_block(&incoming_slot97, 98, &engine, &block_store, false, 0);
        assert_eq!(decision, InboundBlockDecision::Apply);
    }

    #[cfg(feature = "stark")]
    #[test]
    fn stark_production_build_proof_system_needs_no_files() {
        // STARK verification is transparent — no key files required.
        let node = super::Node {
            config: NodeConfig {
                proof_mode: "production".into(),
                ..NodeConfig::default()
            },
            genesis: GenesisConfig::default(),
            local_identity: None,
        };

        let (_verifier, allow_mock) = node.build_proof_system().unwrap();
        assert!(!allow_mock);
    }

    #[cfg(all(feature = "devnet", feature = "stark"))]
    #[test]
    fn dev_stark_auto_finality_accepts_provable_blocks_in_devnet() {
        let node = super::Node {
            config: NodeConfig {
                proof_mode: "dev-stark".into(),
                ..NodeConfig::default()
            },
            genesis: GenesisConfig::default(),
            local_identity: None,
        };
        let (verifier, allow_mock) = node.build_proof_system().unwrap();
        assert!(allow_mock);

        let block = make_block_with_valid_roots(9, [0u8; 32], vec![make_native_tx(0x44, 9)]);
        match build_auto_dev_finality_certificate(&block, verifier.as_ref(), ProofMode::DevStark) {
            AutoDevFinalityCertificate::Ready(cert) => {
                assert_eq!(cert.proof_mode, FinalityProofMode::StarkV1);
                assert!(verifier.verify_finality_certificate_for_block(&cert, &block));
            }
            other => panic!("expected verified STARK FC, got {other:?}"),
        }
    }

    #[cfg(all(feature = "devnet", feature = "stark"))]
    #[test]
    fn dev_stark_auto_finality_builds_verified_empty_bundle_for_raw_only_blocks() {
        let node = super::Node {
            config: NodeConfig {
                proof_mode: "dev-stark".into(),
                ..NodeConfig::default()
            },
            genesis: GenesisConfig::default(),
            local_identity: None,
        };
        let (verifier, allow_mock) = node.build_proof_system().unwrap();
        assert!(allow_mock);

        let block =
            make_block_with_valid_roots(9, [0u8; 32], vec![make_raw_tx(RawChainKind::Tron, 9)]);
        match build_auto_dev_finality_certificate(&block, verifier.as_ref(), ProofMode::DevStark) {
            AutoDevFinalityCertificate::Ready(cert) => {
                assert_eq!(cert.proof_mode, FinalityProofMode::StarkV1);
                assert!(verifier.verify_finality_certificate_for_block(&cert, &block));
            }
            other => panic!("expected verified STARK FC, got {other:?}"),
        }
    }

    #[cfg(all(feature = "devnet", feature = "stark"))]
    #[test]
    fn dev_stark_without_companion_selects_both_native_and_raw_txs() {
        let tmp = TempDir::new().unwrap();
        let node = super::Node {
            config: NodeConfig {
                proof_mode: "dev-stark".into(),
                data_dir: Some(tmp.path().display().to_string()),
                ..NodeConfig::default()
            },
            genesis: GenesisConfig::default(),
            local_identity: None,
        };
        let (verifier, allow_mock) = node.build_proof_system().unwrap();
        drop(verifier);
        assert!(allow_mock);

        let state = Arc::new(RwLock::new(ShardedState::new()));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        mempool.requeue(vec![
            make_native_tx(0x44, 9),
            make_raw_tx(RawChainKind::Tron, 9),
        ]);

        let local_id = AccountId([0x11; 32]);
        let (validator_set, local_signing_key) = signing_validator_set(local_id.0, [0x22; 32]);
        let engine = make_test_engine([0xAA; 32], validator_set);
        let mut approvals = ApprovalCollector::default();

        let selected = node.select_transactions_for_block(
            &state,
            &mempool,
            &mut approvals,
            &engine,
            &local_id,
            &local_signing_key,
            allow_mock,
            10,
        );

        assert_eq!(
            selected.len(),
            2,
            "both native and raw txs should be selected"
        );
        assert_eq!(mempool.pending_count(), 0);
    }

    #[test]
    fn mark_admission_failures_overwrites_receipt_status() {
        use ace_rpc::types::RpcTransactionReceipt;

        let mut receipts = vec![RpcTransactionReceipt {
            transaction_hash: "0x01".into(),
            external_transaction_hash: None,
            block_slot: 1,
            block_hash: "0xab".into(),
            transaction_index: 0,
            from: "0xcd".into(),
            status: true,
            error: None,
            state_changes: Vec::new(),
            gas_used: None,
            contract_address: None,
            evm_logs: Vec::new(),
        }];
        mark_admission_failures(&mut receipts, vec![(0, "admission denied".into())]);
        assert!(!receipts[0].status);
        assert_eq!(receipts[0].error.as_deref(), Some("admission denied"));
    }
}
