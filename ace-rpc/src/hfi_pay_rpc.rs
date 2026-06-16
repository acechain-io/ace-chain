//! HFI Pay JSON-RPC methods.
//!
//! Provides relay + payment intent operations as RPC endpoints,
//! integrated directly into the ACE RPC server for devnet simplicity.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use ace_engine::executor::TransactionOp;
#[cfg(test)]
use ace_hfi_pay::address::{derive_intent_evm_address, derive_intent_tvm_address};
use ace_hfi_pay::executor::IntentStore;
use ace_hfi_pay::intent::{ChainId, IntentStatus};
use ace_hfi_pay::onchain::OnChainIntent;
#[cfg(feature = "persistence")]
use ace_hfi_pay::persistence::replay_record;
use ace_hfi_pay::persistence::{HfiPayPersistence, RegistryRecord};
use ace_hfi_pay::registry::RecipientRegistry;
use ace_hfi_pay::relay::{
    binding_attestation_message, compute_binding_key_commitment, quote_proof_message,
    verify_attested_quote_proof, verify_verified_quote, BindingAttestation, RelayStore,
    VerifiedQuote,
};
#[cfg(test)]
use ace_model::account::Account;
use ace_model::account::AccountId;
use ace_model::block_store::BlockStore;
#[cfg(test)]
use ace_model::sharded_state::ShardedState;
use ace_runtime::crypto::sig_algo::{TaggedPubkey, TaggedSignature};
use ed25519_dalek::{Signer, SigningKey};

use crate::error::RpcError;
use crate::methods::RpcState;

#[cfg(any(test, feature = "devnet"))]
const DEV_OTP_HMAC_SECRET: &str = "ace-local-otp-dev-secret";
const TOKEN_PURPOSE_REGISTER: &str = "register";
const QUOTE_ATTESTOR_SEED_ENV: &str = "ACE_HFI_PAY_QUOTE_ATTESTOR_SEED_HEX";
const HFIPAY_CLAIM_VK_PATH_ENV: &str = "ACE_HFIPAY_CLAIM_VK_PATH";
#[cfg(any(test, feature = "devnet"))]
const DEV_QUOTE_ATTESTOR_SEED: [u8; 32] = [0x51; 32];
const VERIFIED_QUOTE_TTL_SLOTS: u64 = 300;
/// Verifying key basename — must be the Groth16 partner of the proving key shipped to browsers
/// (`zkace_hfipay_claim_pk.bin` / portal `VITE_HFIPAY_CLAIM_PK_URL`), generated from the same
/// `ace-hfi-pay` circuit revision.
const DEFAULT_HFIPAY_CLAIM_VK_FILE: &str = "zkace_hfipay_claim_vk.bin";

fn default_hfipay_claim_vk_repo_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join(DEFAULT_HFIPAY_CLAIM_VK_FILE)
}

fn load_hfipay_claim_vk_bytes(material_dir: Option<&Path>) -> Option<Vec<u8>> {
    let env_path = std::env::var(HFIPAY_CLAIM_VK_PATH_ENV)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from);

    let candidate_paths = [
        env_path,
        material_dir.map(|dir| dir.join(DEFAULT_HFIPAY_CLAIM_VK_FILE)),
        Some(default_hfipay_claim_vk_repo_path()),
    ];

    for path in candidate_paths.into_iter().flatten() {
        match fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => {
                tracing::info!(path = %path.display(), "loaded HFI Pay claim verifying key");
                return Some(bytes);
            }
            Ok(_) => {
                tracing::warn!(path = %path.display(), "ignoring empty HFI Pay claim verifying key file");
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::warn!(path = %path.display(), %err, "failed to read HFI Pay claim verifying key");
            }
        }
    }

    None
}

// ── RPC types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcIntent {
    pub intent_id: String,
    pub amount: u64,
    pub chain: String,
    pub mint_hex: Option<String>,
    pub blinded_binding: String,
    pub binding_epoch: u64,
    pub deposit_address: String,
    pub status: String,
    pub expiry: u64,
    pub created_at: u64,
    pub claim_nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVerifiedQuoteResult {
    pub intent_id: String,
    pub amount: u64,
    pub chain: String,
    pub mint_hex: Option<String>,
    pub binding_epoch: u64,
    pub blinded_binding: String,
    pub deposit_address: String,
    pub refund_dest: Option<String>,
    pub refund_authorizer: Option<String>,
    pub expiry: u64,
    pub created_at: u64,
    pub binding_key_commitment: String,
    pub attestor_pubkey_hex: String,
    pub attestation_signature_hex: String,
    pub attestation_valid_until: u64,
    pub quote_proof_hex: String,
    pub quote_proof_scheme: String,
    pub quote_expiry: u64,
    /// Serialized `0x07` payload (hex). Sign with the sender account whose `nonce` is embedded.
    pub hfi_create_payload_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
struct VerificationTokenClaims {
    exp: u64,
    identifier: String,
    #[serde(default)]
    intent_id: Option<String>,
    purpose: String,
    v: u8,
}

// ── RPC trait ──

#[rpc(server)]
pub trait HfiPayRpc {
    /// Create a sender-verifiable quote for a registered recipient binding.
    #[method(name = "ace_hfiPayCreateVerifiedQuote")]
    fn hfi_pay_create_verified_quote(
        &self,
        identifier: String,
        amount: u64,
        chain: u8,
        expiry_slots: u64,
        sender_id_com_hex: String,
    ) -> RpcResult<CreateVerifiedQuoteResult>;

    /// Withdraw claimed funds to a destination with an owner signature.
    #[method(name = "ace_hfiPayWithdraw")]
    fn hfi_pay_withdraw(
        &self,
        intent_id_hex: String,
        dest_id_com_hex: String,
        claim_pubkey_hex: String,
        claim_signature_hex: String,
        deadline: u64,
    ) -> RpcResult<String>;

    /// Refund an expired intent.
    #[method(name = "ace_hfiPayRefund")]
    fn hfi_pay_refund(&self, intent_id_hex: String) -> RpcResult<String>;

    /// Register a recipient together with the binding metadata needed for verified quotes.
    #[method(name = "ace_hfiPayRegisterRecipientWithBinding")]
    fn hfi_pay_register_recipient_with_binding(
        &self,
        identifier: String,
        verification_token: String,
        xid_hex: String,
        identity_commitment_hex: String,
        claim_binding_handle_hex: String,
        binding_epoch: u64,
        pubkey_hex: String,
        signature_hex: String,
    ) -> RpcResult<String>;

    /// Get intent by ID.
    #[method(name = "ace_hfiPayGetIntent")]
    fn hfi_pay_get_intent(&self, intent_id_hex: String) -> RpcResult<Option<RpcIntent>>;
}

/// Shared HFI Pay state.
pub struct HfiPayState {
    pub relay_store: RwLock<RelayStore>,
    pub intent_store: RwLock<IntentStore>,
    pub registry: RwLock<RecipientRegistry>,
    pub claim_verifying_key_bytes: Option<Arc<Vec<u8>>>,
    /// Set by the node after startup so `HfiPayFund` can verify `deposit_evidence` against committed blocks.
    pub committed_tx_lookup: RwLock<Option<Arc<dyn ace_hfi_pay::onchain::CommittedTxLookup>>>,
    /// Raw registration records (for Arweave persistence and replay).
    pub registry_records: RwLock<Vec<RegistryRecord>>,
    /// Persistence backend (None = in-memory only).
    pub persistence: Option<HfiPayPersistence>,
    /// RocksDB application store for durable write-through persistence.
    #[cfg(feature = "persistence")]
    pub app_store: Option<Arc<RwLock<ace_model::rocks_app_store::RocksDbAppStore>>>,
}

impl HfiPayState {
    /// Create a new in-memory-only state (no persistence).
    pub fn new() -> Self {
        Self {
            relay_store: RwLock::new(RelayStore::new()),
            intent_store: RwLock::new(IntentStore::new()),
            registry: RwLock::new(RecipientRegistry::new()),
            claim_verifying_key_bytes: load_hfipay_claim_vk_bytes(None).map(Arc::new),
            committed_tx_lookup: RwLock::new(None),
            registry_records: RwLock::new(Vec::new()),
            persistence: None,
            #[cfg(feature = "persistence")]
            app_store: None,
        }
    }

    /// Create state with file-based persistence, restoring from disk if available.
    pub fn with_persistence(data_dir: std::path::PathBuf) -> Self {
        let claim_vk_bytes = load_hfipay_claim_vk_bytes(Some(&data_dir)).map(Arc::new);
        let persistence = HfiPayPersistence::new(data_dir);
        if let Err(e) = persistence.ensure_dir() {
            tracing::warn!(%e, "failed to create hfi-pay data dir");
        }

        let mut registry = RecipientRegistry::new();
        let registry_records = persistence.load_registry_records().unwrap_or_default();

        if let Err(e) = persistence.replay_into_registry(&mut registry) {
            tracing::warn!(%e, "failed to replay registry records");
        }

        let intent_store = persistence
            .load_intent_store()
            .ok()
            .flatten()
            .unwrap_or_default();

        let relay_store = persistence
            .load_relay_store()
            .ok()
            .flatten()
            .unwrap_or_else(RelayStore::new);

        Self {
            relay_store: RwLock::new(relay_store),
            intent_store: RwLock::new(intent_store),
            registry: RwLock::new(registry),
            claim_verifying_key_bytes: claim_vk_bytes,
            committed_tx_lookup: RwLock::new(None),
            registry_records: RwLock::new(registry_records),
            persistence: Some(persistence),
            #[cfg(feature = "persistence")]
            app_store: None,
        }
    }

    /// Create state backed by RocksDB, loading existing data on startup.
    ///
    /// If `json_data_dir` is provided and the RocksDB store is empty (fresh
    /// database), existing JSON persistence files are migrated into RocksDB
    /// so that upgrades from JSON-only nodes do not lose state.
    #[cfg(feature = "persistence")]
    pub fn with_rocks_db(
        app_store: Arc<RwLock<ace_model::rocks_app_store::RocksDbAppStore>>,
        json_data_dir: Option<std::path::PathBuf>,
    ) -> Self {
        use ace_model::rocks_app_store::{
            CF_HFI_INTENTS, CF_HFI_META, CF_HFI_RECIPIENTS, CF_HFI_RELAY_INDEX,
            CF_HFI_RELAY_INTENTS,
        };

        // Detect fresh (empty) RocksDB and migrate from JSON if available.
        {
            let store = app_store.read();
            let rocks_is_empty = store.is_cf_empty(CF_HFI_RECIPIENTS).unwrap_or(true)
                && store.is_cf_empty(CF_HFI_INTENTS).unwrap_or(true);
            drop(store);

            if rocks_is_empty {
                if let Some(ref dir) = json_data_dir {
                    let hfi_dir = dir.join("hfi-pay");
                    if hfi_dir.exists() {
                        tracing::info!(path = %hfi_dir.display(), "RocksDB is empty, migrating from JSON persistence");
                        let migrated = Self::migrate_json_to_rocks(&hfi_dir, &app_store);
                        if migrated {
                            tracing::info!("JSON → RocksDB migration complete");
                        }
                    } else {
                        tracing::debug!(
                            "no JSON data dir at {}, starting fresh",
                            hfi_dir.display()
                        );
                    }
                }
            }
        }

        // Now load everything from RocksDB (which may have just been migrated).
        let store = app_store.read();

        // Load or generate salt.
        let salt: [u8; 32] = match store.get(CF_HFI_META, b"registry_salt") {
            Ok(Some(bytes)) if bytes.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&bytes);
                s
            }
            _ => {
                use rand::RngCore;
                let mut s = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut s);
                if let Err(e) = store.put(CF_HFI_META, b"registry_salt", &s) {
                    tracing::warn!(%e, "failed to persist registry salt");
                }
                s
            }
        };

        // Load recipients (RegistryRecord) and replay into registry.
        let mut registry = RecipientRegistry::with_salt(salt);
        let mut registry_records = Vec::new();
        match store.iter_cf(CF_HFI_RECIPIENTS) {
            Ok(entries) => {
                for (_key, value) in entries {
                    match bincode::deserialize::<RegistryRecord>(&value) {
                        Ok(rec) => match replay_record(&mut registry, &rec) {
                            Ok(()) => registry_records.push(rec),
                            Err(e) => {
                                tracing::warn!(error = %e, "skip invalid registry record from RocksDB")
                            }
                        },
                        Err(e) => {
                            tracing::warn!(%e, "failed to deserialize registry record from RocksDB")
                        }
                    }
                }
                tracing::info!(
                    count = registry_records.len(),
                    "loaded HFI recipients from RocksDB"
                );
            }
            Err(e) => tracing::warn!(%e, "failed to iterate HFI recipients from RocksDB"),
        }

        // Load intents.
        let mut intent_store = IntentStore::new();
        match store.iter_cf(CF_HFI_INTENTS) {
            Ok(entries) => {
                for (_key, value) in entries {
                    match bincode::deserialize::<ace_hfi_pay::intent::Intent>(&value) {
                        Ok(intent) => intent_store.insert(intent),
                        Err(e) => tracing::warn!(%e, "failed to deserialize intent from RocksDB"),
                    }
                }
                tracing::info!(
                    count = intent_store.len(),
                    "loaded HFI intents from RocksDB"
                );
            }
            Err(e) => tracing::warn!(%e, "failed to iterate HFI intents from RocksDB"),
        }

        // Load relay store: salt, intents, identifier index.
        let relay_salt: [u8; 32] = match store.get(CF_HFI_META, b"relay_salt") {
            Ok(Some(bytes)) if bytes.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&bytes);
                s
            }
            _ => {
                // No relay data yet; a fresh RelayStore will generate its own salt.
                // We'll save it on first persist.
                let rs = RelayStore::new();
                let snap = rs.snapshot();
                let _ = store.put(CF_HFI_META, b"relay_salt", &snap.salt);
                drop(store);
                return Self {
                    relay_store: RwLock::new(rs),
                    intent_store: RwLock::new(intent_store),
                    registry: RwLock::new(registry),
                    claim_verifying_key_bytes: load_hfipay_claim_vk_bytes(
                        json_data_dir
                            .as_deref()
                            .map(|dir| dir.join("hfi-pay"))
                            .as_deref(),
                    )
                    .map(Arc::new),
                    committed_tx_lookup: RwLock::new(None),
                    registry_records: RwLock::new(registry_records),
                    persistence: None,
                    app_store: Some(app_store),
                };
            }
        };

        let mut relay_intents = std::collections::HashMap::new();
        match store.iter_cf(CF_HFI_RELAY_INTENTS) {
            Ok(entries) => {
                for (_key, value) in entries {
                    match bincode::deserialize::<ace_hfi_pay::relay::RelayIntent>(&value) {
                        Ok(ri) => {
                            relay_intents.insert(ri.intent_id, ri);
                        }
                        Err(e) => {
                            tracing::warn!(%e, "failed to deserialize relay intent from RocksDB")
                        }
                    }
                }
                tracing::info!(
                    count = relay_intents.len(),
                    "loaded HFI relay intents from RocksDB"
                );
            }
            Err(e) => tracing::warn!(%e, "failed to iterate HFI relay intents from RocksDB"),
        }

        let mut identifier_intents: std::collections::HashMap<[u8; 32], Vec<[u8; 32]>> =
            std::collections::HashMap::new();
        match store.iter_cf(CF_HFI_RELAY_INDEX) {
            Ok(entries) => {
                for (key, value) in entries {
                    if key.len() == 32 {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&key);
                        if let Ok(ids) = bincode::deserialize::<Vec<[u8; 32]>>(&value) {
                            identifier_intents.insert(k, ids);
                        }
                    }
                }
            }
            Err(e) => tracing::warn!(%e, "failed to iterate HFI relay index from RocksDB"),
        }

        let relay_snapshot = ace_hfi_pay::relay::RelayStoreSnapshot {
            salt: relay_salt,
            identifier_intents,
            intents: relay_intents,
        };
        let relay_store = RelayStore::restore(relay_snapshot);

        drop(store);

        Self {
            relay_store: RwLock::new(relay_store),
            intent_store: RwLock::new(intent_store),
            registry: RwLock::new(registry),
            claim_verifying_key_bytes: load_hfipay_claim_vk_bytes(
                json_data_dir
                    .as_deref()
                    .map(|dir| dir.join("hfi-pay"))
                    .as_deref(),
            )
            .map(Arc::new),
            committed_tx_lookup: RwLock::new(None),
            registry_records: RwLock::new(registry_records),
            persistence: None,
            app_store: Some(app_store),
        }
    }

    /// Migrate data from JSON persistence files into RocksDB.
    ///
    /// Returns `true` if any data was migrated.
    #[cfg(feature = "persistence")]
    fn migrate_json_to_rocks(
        hfi_dir: &std::path::Path,
        app_store: &Arc<RwLock<ace_model::rocks_app_store::RocksDbAppStore>>,
    ) -> bool {
        use ace_model::rocks_app_store::{
            CF_HFI_INTENTS, CF_HFI_META, CF_HFI_RECIPIENTS, CF_HFI_RELAY_INDEX,
            CF_HFI_RELAY_INTENTS,
        };
        use sha2::{Digest, Sha256};

        let persistence = HfiPayPersistence::new(hfi_dir.to_path_buf());
        let store = app_store.read();
        let mut migrated = false;

        // Migrate registry records.
        let records = persistence.load_registry_records().unwrap_or_default();
        if !records.is_empty() {
            // We need the salt to compute identifier hashes.
            // Generate one and persist it since JSON doesn't store salt.
            let salt: [u8; 32] = {
                use rand::RngCore;
                let mut s = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut s);
                let _ = store.put(CF_HFI_META, b"registry_salt", &s);
                s
            };

            for rec in &records {
                // Compute identifier hash matching RecipientRegistry::hash_identifier().
                let mut hasher = Sha256::new();
                hasher.update(b"hfipay:registry:");
                hasher.update(&salt);
                hasher.update(rec.identifier.as_bytes());
                let hash: [u8; 32] = hasher.finalize().into();

                if let Ok(bytes) = bincode::serialize(rec) {
                    let _ = store.put(CF_HFI_RECIPIENTS, &hash, &bytes);
                }
            }
            tracing::info!(
                count = records.len(),
                "migrated registry records from JSON to RocksDB"
            );
            migrated = true;
        }

        // Migrate intents.
        if let Ok(Some(intent_store)) = persistence.load_intent_store() {
            let mut count = 0usize;
            for (id, intent) in intent_store.iter() {
                if let Ok(bytes) = bincode::serialize(intent) {
                    let _ = store.put(CF_HFI_INTENTS, id, &bytes);
                    count += 1;
                }
            }
            if count > 0 {
                tracing::info!(count, "migrated intents from JSON to RocksDB");
                migrated = true;
            }
        }

        // Migrate relay store.
        if let Ok(Some(relay_store)) = persistence.load_relay_store() {
            let snap = relay_store.snapshot();
            let _ = store.put(CF_HFI_META, b"relay_salt", &snap.salt);
            let mut count = 0usize;
            for (id, ri) in &snap.intents {
                if let Ok(bytes) = bincode::serialize(ri) {
                    let _ = store.put(CF_HFI_RELAY_INTENTS, id, &bytes);
                    count += 1;
                }
            }
            for (hash, ids) in &snap.identifier_intents {
                if let Ok(bytes) = bincode::serialize(ids) {
                    let _ = store.put(CF_HFI_RELAY_INDEX, hash, &bytes);
                }
            }
            if count > 0 {
                tracing::info!(count, "migrated relay intents from JSON to RocksDB");
                migrated = true;
            }
        }

        migrated
    }

    /// Write-through a recipient registration record to RocksDB.
    #[cfg(feature = "persistence")]
    fn persist_recipient_to_rocks(&self, id_hash: &[u8; 32], record: &RegistryRecord) {
        if let Some(ref store) = self.app_store {
            let store = store.read();
            match bincode::serialize(record) {
                Ok(bytes) => {
                    if let Err(e) = store.put(
                        ace_model::rocks_app_store::CF_HFI_RECIPIENTS,
                        id_hash,
                        &bytes,
                    ) {
                        tracing::warn!(%e, "failed to persist recipient to RocksDB");
                    }
                }
                Err(e) => tracing::warn!(%e, "failed to serialize recipient for RocksDB"),
            }
        }
    }

    /// Write-through an intent to RocksDB.
    #[cfg(feature = "persistence")]
    fn persist_intent_to_rocks(&self, intent: &ace_hfi_pay::intent::Intent) {
        if let Some(ref store) = self.app_store {
            let store = store.read();
            match bincode::serialize(intent) {
                Ok(bytes) => {
                    if let Err(e) = store.put(
                        ace_model::rocks_app_store::CF_HFI_INTENTS,
                        &intent.intent_id,
                        &bytes,
                    ) {
                        tracing::warn!(%e, "failed to persist intent to RocksDB");
                    }
                }
                Err(e) => tracing::warn!(%e, "failed to serialize intent for RocksDB"),
            }
        }
    }

    /// Write-through relay store state to RocksDB.
    #[cfg(feature = "persistence")]
    fn persist_relay_to_rocks(&self) {
        if let Some(ref store) = self.app_store {
            let store = store.read();
            let relay = self.relay_store.read();
            let snapshot = relay.snapshot();

            // Save relay salt.
            let _ = store.put(
                ace_model::rocks_app_store::CF_HFI_META,
                b"relay_salt",
                &snapshot.salt,
            );

            // Save each relay intent.
            for (id, ri) in &snapshot.intents {
                if let Ok(bytes) = bincode::serialize(ri) {
                    let _ = store.put(ace_model::rocks_app_store::CF_HFI_RELAY_INTENTS, id, &bytes);
                }
            }

            // Save identifier index.
            for (id_hash, intent_ids) in &snapshot.identifier_intents {
                if let Ok(bytes) = bincode::serialize(intent_ids) {
                    let _ = store.put(
                        ace_model::rocks_app_store::CF_HFI_RELAY_INDEX,
                        id_hash,
                        &bytes,
                    );
                }
            }
        }
    }

    /// Persist all state to disk (no-op if persistence is disabled).
    pub fn persist(&self) {
        if let Some(p) = &self.persistence {
            let records = self.registry_records.read();
            let intents = self.intent_store.read();
            let relay = self.relay_store.read();
            if let Err(e) = p.save_all(&records, &intents, &relay) {
                tracing::warn!(%e, "hfi-pay persist failed");
            }
        }
        #[cfg(feature = "persistence")]
        {
            self.persist_all_intents_to_rocks();
            self.persist_relay_to_rocks();
        }
    }

    /// Write-through all intents currently in the IntentStore to RocksDB.
    #[cfg(feature = "persistence")]
    fn persist_all_intents_to_rocks(&self) {
        if let Some(ref store) = self.app_store {
            let store = store.read();
            let intents = self.intent_store.read();
            for (_id, intent) in intents.iter() {
                if let Ok(bytes) = bincode::serialize(intent) {
                    let _ = store.put(
                        ace_model::rocks_app_store::CF_HFI_INTENTS,
                        &intent.intent_id,
                        &bytes,
                    );
                }
            }
        }
    }

    pub fn with_claim_verifying_key_bytes(mut self, vk_bytes: Vec<u8>) -> Self {
        self.claim_verifying_key_bytes = Some(Arc::new(vk_bytes));
        self
    }

    pub fn attach_committed_tx_lookup(
        &self,
        lookup: Arc<dyn ace_hfi_pay::onchain::CommittedTxLookup>,
    ) {
        *self.committed_tx_lookup.write() = Some(lookup);
    }
}

impl Default for HfiPayState {
    fn default() -> Self {
        Self::new()
    }
}

/// HFI Pay RPC method implementation.
pub struct HfiPayRpcImpl<B: BlockStore> {
    pub shared: Arc<RpcState<B>>,
    pub hfi_pay: Arc<HfiPayState>,
}

fn parse_hex_32(hex_str: &str) -> Result<[u8; 32], RpcError> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| RpcError::InvalidParameter(format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(RpcError::InvalidParameter(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_tagged_pubkey_hex(pubkey_hex: &str) -> Result<TaggedPubkey, RpcError> {
    let pubkey_bytes = hex::decode(pubkey_hex)
        .map_err(|e| RpcError::ServerError(format!("invalid pubkey hex: {e}")))?;
    match pubkey_bytes.len() {
        32 => {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&pubkey_bytes);
            Ok(TaggedPubkey::ed25519(pk))
        }
        1312 => Ok(TaggedPubkey::ml_dsa_44(pubkey_bytes)),
        other => Err(RpcError::ServerError(format!(
            "unsupported pubkey length {other} (expected 32 for Ed25519 or 1312 for ML-DSA-44)"
        ))),
    }
}

fn parse_tagged_signature_hex(signature_hex: &str) -> Result<TaggedSignature, RpcError> {
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| RpcError::ServerError(format!("invalid signature hex: {e}")))?;
    match sig_bytes.len() {
        64 => {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&sig_bytes);
            Ok(TaggedSignature::ed25519(sig))
        }
        2420 => Ok(TaggedSignature::ml_dsa_44(sig_bytes)),
        other => Err(RpcError::ServerError(format!(
            "unsupported signature length {other} (expected 64 for Ed25519 or 2420 for ML-DSA-44)"
        ))),
    }
}

fn chain_from_tag(tag: u8) -> Result<ChainId, RpcError> {
    ChainId::from_tag(tag)
        .ok_or_else(|| RpcError::InvalidParameter(format!("invalid chain tag: {tag}")))
}

/// Same rules as `ace-portal` `normalizeIdentifier` (email: lowercase, strip +tag in local part).
pub(crate) fn normalize_identifier(identifier: &str) -> String {
    let trimmed = identifier.trim().to_lowercase();
    if let Some((local, domain)) = trimmed.split_once('@') {
        let local = local.split_once('+').map(|(base, _)| base).unwrap_or(local);
        format!("{local}@{domain}")
    } else {
        trimmed
    }
}

fn otp_hmac_secret() -> Result<String, RpcError> {
    match std::env::var("ACE_OTP_HMAC_SECRET") {
        Ok(secret) if !secret.trim().is_empty() => Ok(secret),
        Ok(_) => Err(RpcError::ServerError(
            "ACE_OTP_HMAC_SECRET must not be empty".into(),
        )),
        Err(_) => {
            #[cfg(any(test, feature = "devnet"))]
            {
                Ok(DEV_OTP_HMAC_SECRET.to_string())
            }
            #[cfg(not(any(test, feature = "devnet")))]
            {
                Err(RpcError::ServerError(
                    "ACE_OTP_HMAC_SECRET is required for HFI Pay verification tokens".into(),
                ))
            }
        }
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build a verification token for the given identifier and purpose.
///
/// Uses the same HMAC key policy as [`verify_identifier_token`]: on mainnet builds
/// (`ACE_OTP_HMAC_SECRET` required), devnet/test may use the built-in dev default.
pub fn build_verification_token(identifier: &str, purpose: &str) -> Result<String, RpcError> {
    let secret = otp_hmac_secret()?;
    let claims = serde_json::json!({
        "v": 1,
        "identifier": identifier,
        "purpose": purpose,
        "exp": current_unix_secs() + 600, // 10 minutes
    });
    let payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| RpcError::ServerError(format!("invalid OTP HMAC secret: {e}")))?;
    mac.update(payload_b64.as_bytes());
    let sig = mac.finalize().into_bytes();
    Ok(format!(
        "{}.{}",
        payload_b64,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)
    ))
}

fn verify_identifier_token(
    token: &str,
    expected_purpose: &str,
    expected_identifier: &str,
    expected_intent_id: Option<&[u8; 32]>,
) -> Result<VerificationTokenClaims, RpcError> {
    let (payload_b64, sig_b64) = token
        .split_once('.')
        .ok_or_else(|| RpcError::InvalidParameter("malformed verification token".into()))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|e| {
            RpcError::InvalidParameter(format!("invalid verification token payload: {e}"))
        })?;
    let signature = URL_SAFE_NO_PAD.decode(sig_b64.as_bytes()).map_err(|e| {
        RpcError::InvalidParameter(format!("invalid verification token signature: {e}"))
    })?;

    let secret = otp_hmac_secret()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| RpcError::ServerError(format!("invalid OTP HMAC secret: {e}")))?;
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| RpcError::InvalidParameter("invalid verification token MAC".into()))?;

    let claims: VerificationTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| RpcError::InvalidParameter(format!("invalid verification token JSON: {e}")))?;

    if claims.v != 1 {
        return Err(RpcError::InvalidParameter(
            "unsupported verification token version".into(),
        ));
    }
    if claims.purpose != expected_purpose {
        return Err(RpcError::InvalidParameter(
            "verification token purpose mismatch".into(),
        ));
    }
    if claims.identifier != expected_identifier {
        return Err(RpcError::InvalidParameter(
            "verification token identifier mismatch".into(),
        ));
    }
    if claims.exp < current_unix_secs() {
        return Err(RpcError::InvalidParameter(
            "verification token expired".into(),
        ));
    }
    if let Some(intent_id) = expected_intent_id {
        let expected_intent_hex = hex::encode(intent_id);
        if claims.intent_id.as_deref() != Some(expected_intent_hex.as_str()) {
            return Err(RpcError::InvalidParameter(
                "verification token intent mismatch".into(),
            ));
        }
    }

    Ok(claims)
}

/// Test-only helper: production creates deposit accounts in block execution (`ace-hfi-pay` executor).
#[cfg(test)]
fn ensure_intent_deposit_account(
    state: &mut ShardedState,
    chain: ChainId,
    intent_id: &[u8; 32],
    deposit_address: AccountId,
) {
    match chain {
        ChainId::Evm => {
            let evm_address = derive_intent_evm_address(intent_id);
            let mut account = state
                .get(&deposit_address)
                .cloned()
                .unwrap_or_else(|| Account::with_evm_address(deposit_address, evm_address));
            account.evm_address = Some(evm_address);
            state.insert(account);
        }
        ChainId::Tvm => {
            let tron_address = derive_intent_tvm_address(intent_id);
            let mut account = state
                .get(&deposit_address)
                .cloned()
                .unwrap_or_else(|| Account::with_tron_address(deposit_address, tron_address));
            account.tron_address = Some(tron_address);
            state.insert(account);
        }
        ChainId::Native | ChainId::Svm | ChainId::Bvm => {
            if !state.contains(&deposit_address) {
                state.insert(Account::new(deposit_address));
            }
        }
    }
}

/// `RelayStore` and `IntentStore` should match, but RPC funding sync and block execution can
/// disagree (e.g. relay advanced while on-chain copy stayed `Created`). Claim opcode `0x06`
/// requires **both** to be `Funded` — surface a conservative status so the portal does not
/// show `Funded` when claim would still fail with `intent not funded`.
fn reconciled_intent_status_for_rpc(relay: IntentStatus, onchain: Option<IntentStatus>) -> String {
    match (relay, onchain) {
        // Relay ahead of chain: funding not committed yet — conservative for claim.
        (IntentStatus::Funded, Some(IntentStatus::Created)) => "Created".to_string(),
        // Chain ahead of relay (e.g. on-chain 0x08): execution state wins.
        (IntentStatus::Created, Some(IntentStatus::Funded)) => "Funded".to_string(),
        (_, Some(o)) => format!("{}", o),
        (r, None) => format!("{}", r),
    }
}

fn intent_to_rpc(
    intent: &ace_hfi_pay::relay::RelayIntent,
    onchain: Option<&OnChainIntent>,
) -> RpcIntent {
    let claim_nonce = onchain.map(|i| i.claim_nonce).unwrap_or(0);
    let status = reconciled_intent_status_for_rpc(intent.status, onchain.map(|i| i.status));
    RpcIntent {
        intent_id: hex::encode(intent.intent_id),
        amount: intent.amount,
        chain: format!("{}", intent.chain),
        mint_hex: intent.mint.map(hex::encode),
        blinded_binding: hex::encode(intent.blinded_binding),
        binding_epoch: intent.binding_epoch,
        deposit_address: hex::encode(intent.deposit_address.as_bytes()),
        status,
        expiry: intent.expiry,
        created_at: intent.created_at,
        claim_nonce,
    }
}

fn onchain_intent_to_rpc(oc: &OnChainIntent) -> RpcIntent {
    RpcIntent {
        intent_id: hex::encode(oc.intent_id),
        amount: oc.amount,
        chain: format!("{}", oc.chain),
        mint_hex: oc.mint.map(hex::encode),
        blinded_binding: hex::encode(oc.blinded_binding),
        binding_epoch: oc.binding_epoch,
        deposit_address: hex::encode(oc.deposit_address.as_bytes()),
        status: format!("{}", oc.status),
        expiry: oc.expiry,
        created_at: oc.created_at,
        claim_nonce: oc.claim_nonce,
    }
}

fn encode_hfi_pay_create_payload_for_quote(
    quote: &VerifiedQuote,
    sender_nonce: u64,
    identity_commitment: [u8; 32],
) -> Result<Vec<u8>, RpcError> {
    let mint = quote.intent.mint.unwrap_or([0u8; 32]);
    let refund_dest = quote
        .intent
        .refund_dest
        .map(|a| *a.as_bytes())
        .unwrap_or([0u8; 32]);
    let refund_authorizer = quote
        .intent
        .refund_authorizer
        .map(|a| *a.as_bytes())
        .unwrap_or([0u8; 32]);
    let op = TransactionOp::HfiPayCreate {
        nonce: sender_nonce,
        intent_id: quote.intent.intent_id,
        blinded_binding: quote.intent.blinded_binding,
        amount: quote.intent.amount,
        chain_id: quote.intent.chain.tag(),
        mint,
        deposit_address: *quote.intent.deposit_address.as_bytes(),
        binding_epoch: quote.intent.binding_epoch,
        expiry_slot: quote.intent.expiry,
        refund_dest,
        refund_authorizer,
        // Recipient's identity_commitment, looked up off-chain from the
        // relay's registry. The on-chain handler uses this to short-circuit
        // to direct_deposit when the recipient is registered in the
        // consensus-state recipient registry.
        identity_commitment,
    };
    Ok(op.encode())
}

fn quote_attestor_signing_key() -> Result<SigningKey, RpcError> {
    match std::env::var(QUOTE_ATTESTOR_SEED_ENV) {
        Ok(seed_hex) => {
            let seed = parse_hex_32(&seed_hex)?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(_) => {
            #[cfg(any(test, feature = "devnet"))]
            {
                Ok(SigningKey::from_bytes(&DEV_QUOTE_ATTESTOR_SEED))
            }
            #[cfg(not(any(test, feature = "devnet")))]
            {
                Err(RpcError::ServerError(format!(
                    "{QUOTE_ATTESTOR_SEED_ENV} is required for verified quotes"
                )))
            }
        }
    }
}

fn make_binding_attestation(
    identifier: &str,
    claim_binding_handle: &[u8; 32],
    binding_epoch: u64,
    valid_until: u64,
) -> Result<BindingAttestation, RpcError> {
    let signing_key = quote_attestor_signing_key()?;
    let attestor_pubkey = TaggedPubkey::ed25519(signing_key.verifying_key().to_bytes());
    let binding_key_commitment = compute_binding_key_commitment(claim_binding_handle);
    let msg = binding_attestation_message(
        identifier,
        &binding_key_commitment,
        binding_epoch,
        valid_until,
    );
    let signature = TaggedSignature::ed25519(signing_key.sign(&msg).to_bytes());
    Ok(BindingAttestation {
        binding_key_commitment,
        binding_epoch,
        valid_until,
        attestor_pubkey,
        signature,
    })
}

fn sign_quote_proof(quote: &mut VerifiedQuote) -> Result<(), RpcError> {
    let signing_key = quote_attestor_signing_key()?;
    let expected_pubkey = TaggedPubkey::ed25519(signing_key.verifying_key().to_bytes());
    if quote.binding_attestation.attestor_pubkey != expected_pubkey {
        return Err(RpcError::ServerError(
            "binding attestation pubkey does not match configured quote attestor".into(),
        ));
    }
    let msg = quote_proof_message(&quote.quote_proof.public_inputs);
    quote.quote_proof.proof_bytes =
        TaggedSignature::ed25519(signing_key.sign(&msg).to_bytes()).to_wire_bytes();
    Ok(())
}

fn verified_quote_to_rpc(
    quote: &VerifiedQuote,
    hfi_create_payload_hex: String,
) -> CreateVerifiedQuoteResult {
    CreateVerifiedQuoteResult {
        intent_id: hex::encode(quote.intent.intent_id),
        amount: quote.intent.amount,
        chain: format!("{}", quote.intent.chain),
        mint_hex: quote.intent.mint.map(hex::encode),
        binding_epoch: quote.intent.binding_epoch,
        blinded_binding: hex::encode(quote.intent.blinded_binding),
        deposit_address: hex::encode(quote.intent.deposit_address.as_bytes()),
        refund_dest: quote
            .intent
            .refund_dest
            .map(|dest| hex::encode(dest.as_bytes())),
        refund_authorizer: quote
            .intent
            .refund_authorizer
            .map(|dest| hex::encode(dest.as_bytes())),
        expiry: quote.intent.expiry,
        created_at: quote.intent.created_at,
        binding_key_commitment: hex::encode(quote.binding_attestation.binding_key_commitment),
        attestor_pubkey_hex: hex::encode(quote.binding_attestation.attestor_pubkey.to_wire_bytes()),
        attestation_signature_hex: hex::encode(quote.binding_attestation.signature.to_wire_bytes()),
        attestation_valid_until: quote.binding_attestation.valid_until,
        quote_proof_hex: hex::encode(&quote.quote_proof.proof_bytes),
        quote_proof_scheme: "tagged-signature".into(),
        quote_expiry: quote.quote_expiry,
        hfi_create_payload_hex,
    }
}

impl<B: BlockStore + Send + Sync + 'static> HfiPayRpcServer for HfiPayRpcImpl<B> {
    fn hfi_pay_create_verified_quote(
        &self,
        identifier: String,
        amount: u64,
        chain: u8,
        expiry_slots: u64,
        sender_id_com_hex: String,
    ) -> RpcResult<CreateVerifiedQuoteResult> {
        let identifier = normalize_identifier(&identifier);
        let chain_id = chain_from_tag(chain)?;
        let current_slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        let expiry = current_slot.saturating_add(expiry_slots);

        let sender_id = parse_hex_32(sender_id_com_hex.trim())?;
        let sender_account = AccountId::from_bytes(sender_id);
        let (confirmed_nonce, sender_id_com) = {
            let state = self.shared.state.read();
            let account = state.get(&sender_account).ok_or_else(|| {
                RpcError::ServerError(
                    "sender account not found on chain (fund the sender and ensure sender_id_com_hex matches ace_getAccount)".into(),
                )
            })?;
            (account.nonce, account.id_com.0)
        };
        let sender_nonce = self
            .shared
            .mempool
            .pending_nonce(&sender_id_com)
            .map(|pn| pn.max(confirmed_nonce))
            .unwrap_or(confirmed_nonce);

        let recipient = {
            let registry = self.hfi_pay.registry.read();
            registry
                .lookup(identifier.as_bytes())
                .cloned()
                .ok_or_else(|| RpcError::ServerError("recipient binding not registered".into()))?
        };
        if recipient.claim_binding_handle == [0u8; 32] || recipient.identity_commitment == [0u8; 32]
        {
            return Err(
                RpcError::ServerError(
                    "recipient lacks verified binding metadata; use ace_hfiPayRegisterRecipientWithBinding first"
                        .into(),
                )
                .into(),
            );
        }

        let quote_expiry = expiry.min(current_slot.saturating_add(VERIFIED_QUOTE_TTL_SLOTS));
        let binding_attestation = make_binding_attestation(
            &identifier,
            &recipient.claim_binding_handle,
            recipient.binding_epoch,
            quote_expiry,
        )?;

        let mut quote = {
            let mut relay = self.hfi_pay.relay_store.write();
            relay
                .create_verified_quote(
                    &identifier,
                    &recipient.claim_binding_handle,
                    amount,
                    chain_id,
                    None,
                    recipient.binding_epoch,
                    None,
                    None,
                    expiry,
                    None,
                    current_slot,
                    binding_attestation,
                    quote_expiry,
                    Vec::new(),
                )
                .map_err(|e| RpcError::ServerError(format!("create verified quote failed: {e}")))?
        };
        sign_quote_proof(&mut quote)?;
        verify_verified_quote(&identifier, &quote, current_slot, |proof| {
            verify_attested_quote_proof(&quote.binding_attestation.attestor_pubkey, proof)
        })
        .map_err(|e| RpcError::ServerError(format!("verified quote sanity-check failed: {e}")))?;

        let create_payload = encode_hfi_pay_create_payload_for_quote(
            &quote,
            sender_nonce,
            recipient.identity_commitment,
        )?;
        let hfi_create_payload_hex = hex::encode(&create_payload);

        // Intent state lives in `StateTree.hfi_intents` after a signed `0x07` tx is committed.
        // Relay keeps quote metadata (recipient identifier) for Portal verification only.
        self.hfi_pay.persist();

        Ok(verified_quote_to_rpc(&quote, hfi_create_payload_hex))
    }

    fn hfi_pay_withdraw(
        &self,
        intent_id_hex: String,
        dest_id_com_hex: String,
        claim_pubkey_hex: String,
        claim_signature_hex: String,
        deadline: u64,
    ) -> RpcResult<String> {
        let _ = (
            &intent_id_hex,
            &dest_id_com_hex,
            &claim_pubkey_hex,
            &claim_signature_hex,
            deadline,
        );
        Err(RpcError::ServerError(
            "hfi_pay_withdraw must be applied via an on-chain transaction; \
             direct state mutation is disabled to prevent leader/validator divergence"
                .into(),
        )
        .into())
    }

    fn hfi_pay_refund(&self, intent_id_hex: String) -> RpcResult<String> {
        let _ = &intent_id_hex;
        Err(RpcError::ServerError(
            "hfi_pay_refund must be applied via an on-chain transaction; \
             direct state mutation is disabled to prevent leader/validator divergence"
                .into(),
        )
        .into())
    }

    fn hfi_pay_register_recipient_with_binding(
        &self,
        identifier: String,
        verification_token: String,
        xid_hex: String,
        identity_commitment_hex: String,
        claim_binding_handle_hex: String,
        binding_epoch: u64,
        pubkey_hex: String,
        signature_hex: String,
    ) -> RpcResult<String> {
        let identifier = normalize_identifier(&identifier);
        verify_identifier_token(
            &verification_token,
            TOKEN_PURPOSE_REGISTER,
            &identifier,
            None,
        )?;

        let xid = parse_hex_32(&xid_hex)?;
        let identity_commitment = parse_hex_32(&identity_commitment_hex)?;
        let claim_binding_handle = parse_hex_32(&claim_binding_handle_hex)?;
        let pubkey = parse_tagged_pubkey_hex(&pubkey_hex)?;
        let signature = parse_tagged_signature_hex(&signature_hex)?;

        let recipient = {
            let mut registry = self.hfi_pay.registry.write();
            registry
                .register_with_binding_epoch(
                    identifier.as_bytes(),
                    xid,
                    identity_commitment,
                    claim_binding_handle,
                    binding_epoch,
                    &pubkey,
                    &signature,
                )
                .map_err(|e| RpcError::ServerError(format!("registration failed: {e}")))?
        };

        let record = RegistryRecord {
            identifier: identifier.clone(),
            xid_hex,
            identity_commitment_hex,
            claim_binding_handle_hex,
            pubkey_hex,
            signature_hex,
            registered_at: current_unix_secs(),
        };
        self.hfi_pay.registry_records.write().push(record.clone());

        #[cfg(feature = "persistence")]
        {
            let id_hash = self
                .hfi_pay
                .registry
                .read()
                .hash_identifier(identifier.as_bytes());
            self.hfi_pay.persist_recipient_to_rocks(&id_hash, &record);
        }

        self.hfi_pay.persist();
        Ok(hex::encode(recipient.account_id.as_bytes()))
    }

    fn hfi_pay_get_intent(&self, intent_id_hex: String) -> RpcResult<Option<RpcIntent>> {
        let intent_id = parse_hex_32(&intent_id_hex)?;
        let state = self.shared.state.read();
        let shard = state.default_shard();
        let relay = self.hfi_pay.relay_store.read();

        let onchain = shard
            .hfi_intent(&intent_id)
            .map(OnChainIntent::decode)
            .transpose()
            .map_err(RpcError::ServerError)?;

        match (relay.get(&intent_id), onchain.as_ref()) {
            (Some(ri), Some(oc)) => Ok(Some(intent_to_rpc(ri, Some(oc)))),
            (Some(ri), None) => Ok(Some(intent_to_rpc(ri, None))),
            (None, Some(oc)) => Ok(Some(onchain_intent_to_rpc(oc))),
            (None, None) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicU64;
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    use ace_mempool::pool::{Mempool, MempoolConfig};
    use ace_model::block_store::InMemoryBlockStore;
    use ace_model::sharded_state::ShardedState;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;

    use crate::eth_rpc::EthEventHub;
    use crate::methods::TxReceiptStore;

    fn sign_test_token(purpose: &str, identifier: &str, exp_offset_secs: u64) -> String {
        let payload = serde_json::json!({
            "exp": current_unix_secs() + exp_offset_secs,
            "identifier": normalize_identifier(identifier),
            "intent_id": serde_json::Value::Null,
            "purpose": purpose,
            "v": 1u8,
        })
        .to_string();
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let secret = std::env::var("ACE_OTP_HMAC_SECRET")
            .ok()
            .filter(|secret| !secret.trim().is_empty())
            .unwrap_or_else(|| DEV_OTP_HMAC_SECRET.to_string());
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        format!("{}.{}", payload_b64, URL_SAFE_NO_PAD.encode(sig))
    }

    fn test_rpc() -> HfiPayRpcImpl<InMemoryBlockStore> {
        let state = Arc::new(RwLock::new(ShardedState::new()));
        let current_slot = Arc::new(AtomicU64::new(1));
        let shared = Arc::new(RpcState {
            state: Arc::clone(&state),
            block_store: Arc::new(RwLock::new(InMemoryBlockStore::new())),
            mempool: Arc::new(Mempool::new(MempoolConfig::default())),
            mempool_notify: None,
            current_slot,
            peer_count: Arc::new(AtomicU64::new(0)),
            peer_snapshot: Arc::new(std::sync::RwLock::new(Vec::new())),
            latest_block_slot: Arc::new(AtomicU64::new(0)),
            state_root_hex: Arc::new(parking_lot::RwLock::new(String::new())),
            chain_id: 1,
            native_token: None,
            tx_receipt_store: Arc::new(RwLock::new(TxReceiptStore::new())),
            eth_events: Arc::new(EthEventHub::new(16)),
            outbound_tx: None,
            otp_store: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
            tps_samples: Arc::new(parking_lot::RwLock::new(std::collections::VecDeque::new())),
            validator_admission_policy: "devnet-derived".into(),
            founder_id_com: None,
            validator_count: 0,
            validator: false,
            public_node_roles: Vec::new(),
            public_rpc: false,
        });

        shared
            .state
            .write()
            .insert(Account::new(AccountId::from_bytes([0x77; 32])));

        HfiPayRpcImpl {
            shared,
            hfi_pay: Arc::new(HfiPayState::new()),
        }
    }

    fn test_sender_hex() -> String {
        hex::encode([0x77u8; 32])
    }

    fn register_verified_recipient(
        rpc: &HfiPayRpcImpl<InMemoryBlockStore>,
        identifier: &str,
        xid: [u8; 32],
        identity_commitment: [u8; 32],
        claim_binding_handle: [u8; 32],
        binding_epoch: u64,
        signing_key: &SigningKey,
    ) -> String {
        let normalized = normalize_identifier(identifier);
        let registration_msg =
            ace_hfi_pay::registry::registration_message(&xid, normalized.as_bytes());
        let signature = TaggedSignature::ed25519(signing_key.sign(&registration_msg).to_bytes());
        let token = sign_test_token(TOKEN_PURPOSE_REGISTER, identifier, 60);

        rpc.hfi_pay_register_recipient_with_binding(
            identifier.into(),
            token,
            hex::encode(xid),
            hex::encode(identity_commitment),
            hex::encode(claim_binding_handle),
            binding_epoch,
            hex::encode(signing_key.verifying_key().to_bytes()),
            hex::encode(signature.bytes.clone()),
        )
        .expect("binding-aware registration should succeed")
    }

    #[test]
    fn normalize_identifier_matches_frontend_rules() {
        assert_eq!(
            normalize_identifier("  User.Name+promo@Example.COM "),
            "user.name@example.com"
        );
        assert_eq!(normalize_identifier(" +1234567890 "), "+1234567890");
    }

    #[test]
    fn persistent_create_verified_quote_returns_without_deadlock() {
        let tmp = TempDir::new().unwrap();
        let state = Arc::new(RwLock::new(ShardedState::new()));
        let current_slot = Arc::new(AtomicU64::new(10));
        let shared = Arc::new(RpcState {
            state,
            block_store: Arc::new(RwLock::new(InMemoryBlockStore::new())),
            mempool: Arc::new(Mempool::new(MempoolConfig::default())),
            mempool_notify: None,
            current_slot,
            peer_count: Arc::new(AtomicU64::new(0)),
            peer_snapshot: Arc::new(std::sync::RwLock::new(Vec::new())),
            latest_block_slot: Arc::new(AtomicU64::new(0)),
            state_root_hex: Arc::new(parking_lot::RwLock::new(String::new())),
            chain_id: 1,
            native_token: None,
            tx_receipt_store: Arc::new(RwLock::new(TxReceiptStore::new())),
            eth_events: Arc::new(EthEventHub::new(16)),
            outbound_tx: None,
            otp_store: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
            tps_samples: Arc::new(parking_lot::RwLock::new(std::collections::VecDeque::new())),
            validator_admission_policy: "devnet-derived".into(),
            founder_id_com: None,
            validator_count: 0,
            validator: false,
            public_node_roles: Vec::new(),
            public_rpc: false,
        });
        shared
            .state
            .write()
            .insert(Account::new(AccountId::from_bytes([0x77; 32])));

        let rpc = HfiPayRpcImpl {
            shared,
            hfi_pay: Arc::new(HfiPayState::with_persistence(tmp.path().to_path_buf())),
        };
        let signing_key = SigningKey::from_bytes(&[0x41; 32]);
        register_verified_recipient(
            &rpc,
            "User+test@Example.com",
            [0x24; 32],
            [0xAA; 32],
            [0xBB; 32],
            7,
            &signing_key,
        );

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = rpc.hfi_pay_create_verified_quote(
                "User+test@Example.com".into(),
                25,
                0,
                100,
                test_sender_hex(),
            );
            tx.send(result).unwrap();
        });

        let result = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("persistent create_verified_quote timed out");
        let quote = result.expect("verified quote should succeed");
        assert_eq!(quote.intent_id.len(), 64);
        assert_eq!(quote.hfi_create_payload_hex.len(), 258 * 2);
    }

    #[test]
    fn create_verified_quote_does_not_mutate_chain_state() {
        let rpc = test_rpc();
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        register_verified_recipient(
            &rpc,
            "user@example.com",
            [0x25; 32],
            [0xAC; 32],
            [0xBC; 32],
            5,
            &signing_key,
        );
        let quote = rpc
            .hfi_pay_create_verified_quote("user@example.com".into(), 25, 0, 100, test_sender_hex())
            .expect("verified quote should succeed");
        assert!(quote.hfi_create_payload_hex.len() >= 64);
        let deposit = AccountId::from_bytes(parse_hex_32(&quote.deposit_address).unwrap());

        assert!(
            !rpc.shared.state.read().contains(&deposit),
            "deposit account is created on-chain when intent is executed, not from this RPC"
        );
    }

    #[test]
    fn get_intent_detects_manual_funding() {
        let rpc = test_rpc();
        let signing_key = SigningKey::from_bytes(&[0x43; 32]);
        register_verified_recipient(
            &rpc,
            "user@example.com",
            [0x26; 32],
            [0xAD; 32],
            [0xBD; 32],
            6,
            &signing_key,
        );
        let quote = rpc
            .hfi_pay_create_verified_quote("user@example.com".into(), 25, 0, 100, test_sender_hex())
            .expect("verified quote should succeed");
        let intent_id = parse_hex_32(&quote.intent_id).unwrap();
        let ri = rpc
            .hfi_pay
            .relay_store
            .read()
            .get(&intent_id)
            .expect("relay intent")
            .clone();
        let oc = OnChainIntent {
            intent_id: ri.intent_id,
            blinded_binding: ri.blinded_binding,
            amount: ri.amount,
            chain: ri.chain,
            mint: ri.mint,
            deposit_address: ri.deposit_address,
            binding_epoch: ri.binding_epoch,
            expiry: ri.expiry,
            refund_dest: ri.refund_dest,
            refund_authorizer: ri.refund_authorizer,
            created_at: ri.created_at,
            status: IntentStatus::Funded,
            claim_nonce: 0,
            refund_nonce: 0,
            withdrawn_amount: 0,
            owner: None,
        };
        rpc.shared
            .state
            .write()
            .default_shard_mut()
            .hfi_intent_put(intent_id, oc.encode());

        let fetched = rpc
            .hfi_pay_get_intent(hex::encode(intent_id))
            .expect("get intent should succeed")
            .expect("intent should exist");
        assert_eq!(fetched.status, "Funded");
    }

    #[test]
    fn register_with_binding_enables_verified_quote_rpc() {
        let rpc = test_rpc();
        let _ = std::env::remove_var(QUOTE_ATTESTOR_SEED_ENV);

        let signing_key = SigningKey::from_bytes(&[0x41; 32]);
        let xid = [0x24; 32];
        let identifier = "verified@example.com";
        let normalized = normalize_identifier(identifier);
        let msg = ace_hfi_pay::registry::registration_message(&xid, normalized.as_bytes());
        let signature = TaggedSignature::ed25519(signing_key.sign(&msg).to_bytes());
        let token = sign_test_token(TOKEN_PURPOSE_REGISTER, identifier, 60);

        let account_id = rpc
            .hfi_pay_register_recipient_with_binding(
                identifier.into(),
                token,
                hex::encode(xid),
                hex::encode([0xAA; 32]),
                hex::encode([0xBB; 32]),
                7,
                hex::encode(signing_key.verifying_key().to_bytes()),
                hex::encode(signature.bytes.clone()),
            )
            .expect("binding-aware registration should succeed");

        assert_eq!(account_id.len(), 64);

        let quote = rpc
            .hfi_pay_create_verified_quote(identifier.into(), 77, 0, 100, test_sender_hex())
            .expect("verified quote should succeed");

        assert_eq!(quote.amount, 77);
        assert_eq!(quote.chain, "Native");
        assert_eq!(quote.binding_epoch, 7);
        assert_eq!(quote.quote_proof_scheme, "tagged-signature");
        assert!(!quote.attestation_signature_hex.is_empty());
        assert!(!quote.quote_proof_hex.is_empty());
    }

    #[test]
    fn refund_requires_stored_authorization_even_after_manual_funding() {
        let rpc = test_rpc();
        let intent_id = {
            let mut relay = rpc.hfi_pay.relay_store.write();
            let intent = relay
                .create_intent(
                    "user@example.com",
                    &[0u8; 32],
                    25,
                    ChainId::Native,
                    None,
                    0,
                    None,
                    None,
                    10,
                    None,
                    1,
                )
                .unwrap();
            let on_chain = ace_hfi_pay::intent::Intent::new(
                intent.intent_id,
                intent.blinded_binding,
                intent.amount,
                intent.chain,
                intent.deposit_address,
                intent.mint,
                intent.binding_epoch,
                None,
                None,
                None,
                intent.expiry,
                intent.created_at,
            );
            rpc.hfi_pay.intent_store.write().insert(on_chain);
            intent.intent_id
        };
        let deposit = {
            let store = rpc.hfi_pay.intent_store.read();
            let intent = store.get(&intent_id).expect("intent should exist");
            ensure_intent_deposit_account(
                &mut rpc.shared.state.write(),
                intent.chain,
                &intent.intent_id,
                intent.deposit_address,
            );
            intent.deposit_address
        };

        rpc.shared
            .state
            .write()
            .get_mut(&deposit)
            .expect("deposit account")
            .balance = 25;
        rpc.shared
            .current_slot
            .store(200, std::sync::atomic::Ordering::Relaxed);

        let result = rpc.hfi_pay_refund(hex::encode(intent_id));
        assert!(result.is_err());
        assert_eq!(rpc.shared.state.read().get(&deposit).unwrap().balance, 25);
        // Refund is enforced on-chain; RPC does not mutate intent state.
        assert_eq!(
            rpc.hfi_pay
                .intent_store
                .read()
                .get(&intent_id)
                .expect("intent")
                .status,
            IntentStatus::Created
        );
    }
}
