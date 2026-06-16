//! Persistence backends for HFI Pay state.
//!
//! Three stores need persistence:
//!
//! | Store             | Backend              | Reason                            |
//! |-------------------|----------------------|-----------------------------------|
//! | RecipientRegistry | Arweave + local JSON | Permanent identity mapping        |
//! | IntentStore       | Local JSON (RocksDB) | Transactional, consensus-bound    |
//! | RelayStore        | Local JSON           | Private identifier→intent mapping |

use std::fs;
use std::path::PathBuf;

use tracing::{info, warn};

use crate::executor::IntentStore;
use crate::registry::RecipientRegistry;
use crate::relay::{RelayStore, RelayStoreSnapshot};

// ── Registry record (Arweave-storable) ──

/// A single registration record that can be stored on Arweave and replayed
/// on any node to reconstruct the local [`RecipientRegistry`].
///
/// Contains the original registration parameters so any node can verify
/// the signature and re-register the recipient.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegistryRecord {
    /// Normalized identifier (email, phone, etc.)
    pub identifier: String,
    /// XID hex (64 chars)
    pub xid_hex: String,
    /// Identity commitment `IDcom_B` hex (64 chars).
    #[serde(default)]
    pub identity_commitment_hex: String,
    /// Private claim-binding handle `u_B` hex (64 chars).
    #[serde(default)]
    pub claim_binding_handle_hex: String,
    /// Ed25519 public key hex (64 chars)
    pub pubkey_hex: String,
    /// Ed25519 signature hex (128 chars)
    pub signature_hex: String,
    /// Unix timestamp of registration
    pub registered_at: u64,
}

// ── File-based persistence ──

/// Directory-based persistence for all HFI Pay state.
///
/// Layout:
/// ```text
/// {base_dir}/
///   registry_records.json    — Vec<RegistryRecord> for Arweave sync
///   intent_store.json        — IntentStore serialized
///   relay_store.json         — RelayStoreSnapshot serialized
/// ```
pub struct HfiPayPersistence {
    base_dir: PathBuf,
}

const REGISTRY_FILE: &str = "registry_records.json";
const INTENT_FILE: &str = "intent_store.json";
const RELAY_FILE: &str = "relay_store.json";

impl HfiPayPersistence {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn ensure_dir(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.base_dir)
    }

    // ── Registry records ──

    pub fn save_registry_records(&self, records: &[RegistryRecord]) -> Result<(), String> {
        let path = self.base_dir.join(REGISTRY_FILE);
        let json = serde_json::to_string_pretty(records)
            .map_err(|e| format!("serialize registry records: {e}"))?;
        fs::write(&path, json).map_err(|e| format!("write {}: {e}", path.display()))?;
        info!(count = records.len(), path = %path.display(), "saved registry records");
        Ok(())
    }

    pub fn load_registry_records(&self) -> Result<Vec<RegistryRecord>, String> {
        let path = self.base_dir.join(REGISTRY_FILE);
        if !path.exists() {
            return Ok(vec![]);
        }
        let json =
            fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let records: Vec<RegistryRecord> =
            serde_json::from_str(&json).map_err(|e| format!("parse {}: {e}", path.display()))?;
        info!(count = records.len(), path = %path.display(), "loaded registry records");
        Ok(records)
    }

    /// Replay registry records into a [`RecipientRegistry`], verifying each
    /// signature.  Invalid records are skipped with a warning.
    pub fn replay_into_registry(&self, registry: &mut RecipientRegistry) -> Result<usize, String> {
        let records = self.load_registry_records()?;
        let mut count = 0;
        for rec in &records {
            match replay_record(registry, rec) {
                Ok(()) => count += 1,
                Err(e) => {
                    warn!(identifier = %rec.identifier, error = %e, "skip invalid registry record")
                }
            }
        }
        info!(
            replayed = count,
            total = records.len(),
            "registry replay complete"
        );
        Ok(count)
    }

    // ── IntentStore ──

    pub fn save_intent_store(&self, store: &IntentStore) -> Result<(), String> {
        let path = self.base_dir.join(INTENT_FILE);
        let json =
            serde_json::to_string(store).map_err(|e| format!("serialize intent store: {e}"))?;
        fs::write(&path, json).map_err(|e| format!("write {}: {e}", path.display()))?;
        Ok(())
    }

    pub fn load_intent_store(&self) -> Result<Option<IntentStore>, String> {
        let path = self.base_dir.join(INTENT_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let json =
            fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let store: IntentStore =
            serde_json::from_str(&json).map_err(|e| format!("parse {}: {e}", path.display()))?;
        info!(intents = store.len(), "loaded intent store");
        Ok(Some(store))
    }

    // ── RelayStore ──

    pub fn save_relay_store(&self, store: &RelayStore) -> Result<(), String> {
        let path = self.base_dir.join(RELAY_FILE);
        let snapshot = store.snapshot();
        let json =
            serde_json::to_string(&snapshot).map_err(|e| format!("serialize relay store: {e}"))?;
        fs::write(&path, json).map_err(|e| format!("write {}: {e}", path.display()))?;
        Ok(())
    }

    pub fn load_relay_store(&self) -> Result<Option<RelayStore>, String> {
        let path = self.base_dir.join(RELAY_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let json =
            fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let snapshot: RelayStoreSnapshot =
            serde_json::from_str(&json).map_err(|e| format!("parse {}: {e}", path.display()))?;
        let store = RelayStore::restore(snapshot);
        info!(intents = store.len(), "loaded relay store");
        Ok(Some(store))
    }

    // ── Snapshot all ──

    pub fn save_all(
        &self,
        registry_records: &[RegistryRecord],
        intent_store: &IntentStore,
        relay_store: &RelayStore,
    ) -> Result<(), String> {
        self.ensure_dir().map_err(|e| format!("create dir: {e}"))?;
        self.save_registry_records(registry_records)?;
        self.save_intent_store(intent_store)?;
        self.save_relay_store(relay_store)?;
        Ok(())
    }
}

// ── Arweave persistence (stub, no HTTP) ──

/// Arweave client for uploading and retrieving registry records.
///
/// When the `arweave` feature is **not** enabled this is a devnet stub that
/// computes a deterministic fake tx-id and never touches the network.
#[cfg(not(feature = "arweave"))]
pub struct ArweaveRegistryStore {
    gateway_url: String,
    app_name: String,
}

#[cfg(not(feature = "arweave"))]
impl ArweaveRegistryStore {
    pub fn new(gateway_url: String) -> Self {
        Self {
            gateway_url,
            app_name: "ace-hfi-pay".to_string(),
        }
    }

    /// Devnet stub: returns a deterministic hash as fake tx-id.
    pub fn upload_record(&self, record: &RegistryRecord) -> Result<String, String> {
        let data = serde_json::to_vec(record).map_err(|e| format!("serialize record: {e}"))?;

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"arweave-hfi-pay-registry:");
        hasher.update(&data);
        let hash = hasher.finalize();
        let tx_id = hex::encode(hash);

        info!(
            gateway = %self.gateway_url,
            app = %self.app_name,
            identifier = %record.identifier,
            tx_id = %tx_id,
            "arweave upload (devnet stub)"
        );

        Ok(tx_id)
    }

    /// Devnet stub: always returns an empty vec.
    pub fn fetch_all_records(&self) -> Result<Vec<RegistryRecord>, String> {
        info!(
            gateway = %self.gateway_url,
            app = %self.app_name,
            "arweave fetch_all_records (devnet stub: returning empty)"
        );
        Ok(vec![])
    }
}

// ── Arweave persistence (real HTTP, requires `arweave` feature) ──

/// Arweave client that performs real HTTP calls via `reqwest`.
///
/// - **upload_record** POSTs JSON to a configurable upload endpoint
///   (e.g. an Irys/Bundlr node) with standard Arweave tags.
/// - **fetch_all_records** queries the gateway GraphQL endpoint, then
///   GETs each transaction's data and deserializes it.
#[cfg(feature = "arweave")]
pub struct ArweaveRegistryStore {
    gateway_url: String,
    /// Upload endpoint (may differ from the read gateway, e.g. an Irys node).
    /// When `None`, defaults to `{gateway_url}/tx`.
    upload_url: Option<String>,
    app_name: String,
    client: reqwest::Client,
}

#[cfg(feature = "arweave")]
impl ArweaveRegistryStore {
    pub fn new(gateway_url: String) -> Self {
        Self {
            gateway_url,
            upload_url: None,
            app_name: "ace-hfi-pay".to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Set a custom upload endpoint (e.g. an Irys node URL).
    pub fn with_upload_url(mut self, url: String) -> Self {
        self.upload_url = Some(url);
        self
    }

    /// Upload a registry record as JSON to the configured upload endpoint.
    ///
    /// The request includes Arweave-style tags as HTTP headers so that an
    /// Irys/Bundlr-compatible node can index the data item.
    ///
    /// Returns the transaction ID on success.
    pub async fn upload_record(&self, record: &RegistryRecord) -> Result<String, String> {
        let data = serde_json::to_vec(record).map_err(|e| format!("serialize record: {e}"))?;

        let url = match &self.upload_url {
            Some(u) => u.clone(),
            None => format!("{}/tx", self.gateway_url),
        };

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Tag-App-Name", &self.app_name)
            .header("X-Tag-Type", "registration")
            .body(data)
            .send()
            .await
            .map_err(|e| format!("arweave upload POST failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("arweave upload failed (HTTP {status}): {body}"));
        }

        // The response body is expected to contain a JSON object with an `id`
        // field (standard Arweave / Irys upload response).
        #[derive(serde::Deserialize)]
        struct UploadResponse {
            id: String,
        }

        let body = resp
            .text()
            .await
            .map_err(|e| format!("read upload response body: {e}"))?;
        let parsed: UploadResponse = serde_json::from_str(&body)
            .map_err(|e| format!("parse upload response: {e} (body: {body})"))?;

        info!(
            gateway = %self.gateway_url,
            app = %self.app_name,
            identifier = %record.identifier,
            tx_id = %parsed.id,
            "arweave upload ok"
        );

        Ok(parsed.id)
    }

    /// Query all registry records from Arweave via GraphQL, then fetch each
    /// transaction's data and deserialize it as [`RegistryRecord`].
    pub async fn fetch_all_records(&self) -> Result<Vec<RegistryRecord>, String> {
        let graphql_url = format!("{}/graphql", self.gateway_url);

        let query = serde_json::json!({
            "query": r#"{
                transactions(
                    tags: [
                        {name: "App-Name", values: ["ace-hfi-pay"]},
                        {name: "Type", values: ["registration"]}
                    ],
                    first: 100
                ) {
                    edges {
                        node {
                            id
                        }
                    }
                }
            }"#
        });

        let resp = self
            .client
            .post(&graphql_url)
            .json(&query)
            .send()
            .await
            .map_err(|e| format!("arweave GraphQL request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("arweave GraphQL failed (HTTP {status}): {body}"));
        }

        #[derive(serde::Deserialize)]
        struct GqlResponse {
            data: GqlData,
        }
        #[derive(serde::Deserialize)]
        struct GqlData {
            transactions: GqlTransactions,
        }
        #[derive(serde::Deserialize)]
        struct GqlTransactions {
            edges: Vec<GqlEdge>,
        }
        #[derive(serde::Deserialize)]
        struct GqlEdge {
            node: GqlNode,
        }
        #[derive(serde::Deserialize)]
        struct GqlNode {
            id: String,
        }

        let gql: GqlResponse = resp
            .json()
            .await
            .map_err(|e| format!("parse GraphQL response: {e}"))?;

        let tx_ids: Vec<String> = gql
            .data
            .transactions
            .edges
            .into_iter()
            .map(|e| e.node.id)
            .collect();

        info!(
            gateway = %self.gateway_url,
            count = tx_ids.len(),
            "arweave: fetched transaction IDs"
        );

        let mut records = Vec::with_capacity(tx_ids.len());
        for tx_id in &tx_ids {
            let data_url = format!("{}/{}", self.gateway_url, tx_id);
            match self.fetch_record_data(&data_url).await {
                Ok(rec) => records.push(rec),
                Err(e) => {
                    warn!(tx_id = %tx_id, error = %e, "skip unreadable arweave record");
                }
            }
        }

        info!(
            fetched = records.len(),
            total_txs = tx_ids.len(),
            "arweave fetch_all_records complete"
        );

        Ok(records)
    }

    async fn fetch_record_data(&self, url: &str) -> Result<RegistryRecord, String> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(format!("GET {url} returned HTTP {status}"));
        }

        let record: RegistryRecord = resp
            .json()
            .await
            .map_err(|e| format!("deserialize record from {url}: {e}"))?;

        Ok(record)
    }
}

// ── Helper ──

#[cfg(test)]
mod tests {
    use super::*;

    fn make_persistence(dir: &std::path::Path) -> HfiPayPersistence {
        let p = HfiPayPersistence::new(dir.to_path_buf());
        p.ensure_dir().unwrap();
        p
    }

    // ── Registry records round-trip ──

    #[test]
    fn registry_records_round_trip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = make_persistence(tmp.path());

        let records = vec![
            RegistryRecord {
                identifier: "alice@example.com".into(),
                xid_hex: hex::encode([1u8; 32]),
                identity_commitment_hex: String::new(),
                claim_binding_handle_hex: String::new(),
                pubkey_hex: hex::encode([2u8; 32]),
                signature_hex: hex::encode([3u8; 64]),
                registered_at: 1000,
            },
            RegistryRecord {
                identifier: "bob@example.com".into(),
                xid_hex: hex::encode([4u8; 32]),
                identity_commitment_hex: String::new(),
                claim_binding_handle_hex: String::new(),
                pubkey_hex: hex::encode([5u8; 32]),
                signature_hex: hex::encode([6u8; 64]),
                registered_at: 2000,
            },
        ];

        p.save_registry_records(&records).unwrap();
        let loaded = p.load_registry_records().unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].identifier, "alice@example.com");
        assert_eq!(loaded[1].identifier, "bob@example.com");
        assert_eq!(loaded[0].registered_at, 1000);
        assert_eq!(loaded[1].xid_hex, hex::encode([4u8; 32]));
    }

    // ── IntentStore round-trip ──

    #[test]
    fn intent_store_round_trip() {
        use crate::executor::IntentStore;
        use crate::intent::{ChainId, Intent};
        use ace_model::account::AccountId;

        let tmp = tempfile::TempDir::new().unwrap();
        let p = make_persistence(tmp.path());

        let mut store = IntentStore::new();
        let intent_id = [99u8; 32];
        let deposit = AccountId::from_bytes([10u8; 32]);
        let intent = Intent::new(
            intent_id,
            [0u8; 32],
            500,
            ChainId::Native,
            deposit,
            None,
            0,
            None,
            None,
            None,
            9999,
            42,
        );
        store.insert(intent);

        p.save_intent_store(&store).unwrap();
        let loaded = p.load_intent_store().unwrap().expect("should load some");

        assert_eq!(loaded.len(), 1);
        let got = loaded.get(&intent_id).unwrap();
        assert_eq!(got.amount, 500);
        assert_eq!(got.expiry, 9999);
        assert_eq!(got.created_at, 42);
    }

    // ── RelayStore round-trip ──

    #[test]
    fn relay_store_round_trip() {
        use crate::intent::ChainId;

        let tmp = tempfile::TempDir::new().unwrap();
        let p = make_persistence(tmp.path());

        let mut store = RelayStore::new();
        let handle = &[7u8; 32];
        store
            .create_intent(
                "user@test.com",
                handle,
                1000,
                ChainId::Native,
                None,
                0,
                None,
                None,
                5000,
                None,
                1,
            )
            .unwrap();
        store
            .create_intent(
                "user@test.com",
                handle,
                2000,
                ChainId::Native,
                None,
                0,
                None,
                None,
                6000,
                None,
                2,
            )
            .unwrap();

        p.save_relay_store(&store).unwrap();
        let loaded = p.load_relay_store().unwrap().expect("should load some");

        assert_eq!(loaded.len(), 2);
        // Verify we can still query by identifier
        let pending = loaded.pending_intents("user@test.com");
        assert_eq!(pending.len(), 2);
    }

    // ── replay_into_registry with valid Ed25519 signature ──

    #[test]
    fn replay_into_registry_valid_signature() {
        use crate::registry::registration_message;
        use ed25519_dalek::{Signer, SigningKey};

        let tmp = tempfile::TempDir::new().unwrap();
        let p = make_persistence(tmp.path());

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let xid = [42u8; 32];
        let identifier = b"test@example.com";
        let msg = registration_message(&xid, identifier);
        let sig = signing_key.sign(&msg);

        let record = RegistryRecord {
            identifier: "test@example.com".into(),
            xid_hex: hex::encode(xid),
            identity_commitment_hex: hex::encode([0u8; 32]),
            claim_binding_handle_hex: hex::encode([0u8; 32]),
            pubkey_hex: hex::encode(verifying_key.to_bytes()),
            signature_hex: hex::encode(sig.to_bytes()),
            registered_at: 100,
        };
        p.save_registry_records(&[record]).unwrap();

        let mut registry = RecipientRegistry::new();
        let count = p.replay_into_registry(&mut registry).unwrap();
        assert_eq!(count, 1);
        assert!(registry.is_registered(b"test@example.com"));
    }

    // ── replay_into_registry with invalid signature (should skip) ──

    #[test]
    fn replay_into_registry_invalid_signature_skipped() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = make_persistence(tmp.path());

        let record = RegistryRecord {
            identifier: "bad@example.com".into(),
            xid_hex: hex::encode([10u8; 32]),
            identity_commitment_hex: String::new(),
            claim_binding_handle_hex: String::new(),
            pubkey_hex: hex::encode([20u8; 32]),
            signature_hex: hex::encode([0u8; 64]),
            registered_at: 100,
        };
        p.save_registry_records(&[record]).unwrap();

        let mut registry = RecipientRegistry::new();
        let count = p.replay_into_registry(&mut registry).unwrap();
        assert_eq!(count, 0);
        assert!(!registry.is_registered(b"bad@example.com"));
    }

    // ── Load from nonexistent dir returns empty/None ──

    #[test]
    fn load_from_nonexistent_dir_returns_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        let nonexistent = tmp.path().join("does_not_exist");
        let p = HfiPayPersistence::new(nonexistent);

        let records = p.load_registry_records().unwrap();
        assert!(records.is_empty());

        let intent = p.load_intent_store().unwrap();
        assert!(intent.is_none());

        let relay = p.load_relay_store().unwrap();
        assert!(relay.is_none());
    }
}

pub fn replay_record(registry: &mut RecipientRegistry, rec: &RegistryRecord) -> Result<(), String> {
    use ace_runtime::crypto::sig_algo::{TaggedPubkey, TaggedSignature};

    let xid_bytes = hex::decode(&rec.xid_hex).map_err(|e| format!("bad xid hex: {e}"))?;
    if xid_bytes.len() != 32 {
        return Err(format!("xid must be 32 bytes, got {}", xid_bytes.len()));
    }
    let mut xid = [0u8; 32];
    xid.copy_from_slice(&xid_bytes);

    let pk_bytes = hex::decode(&rec.pubkey_hex).map_err(|e| format!("bad pubkey hex: {e}"))?;
    if pk_bytes.len() != 32 {
        return Err(format!("pubkey must be 32 bytes, got {}", pk_bytes.len()));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);

    let sig_bytes = hex::decode(&rec.signature_hex).map_err(|e| format!("bad sig hex: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);

    let pubkey = TaggedPubkey::ed25519(pk);
    let signature = TaggedSignature::ed25519(sig);

    let identity_commitment = decode_hex_or_zero(&rec.identity_commitment_hex)
        .map_err(|e| format!("bad identity_commitment hex: {e}"))?;
    let claim_binding_handle = decode_hex_or_zero(&rec.claim_binding_handle_hex)
        .map_err(|e| format!("bad claim_binding_handle hex: {e}"))?;

    registry
        .register(
            rec.identifier.as_bytes(),
            xid,
            identity_commitment,
            claim_binding_handle,
            &pubkey,
            &signature,
        )
        .map_err(|e| format!("registration failed: {e}"))?;

    Ok(())
}

fn decode_hex_or_zero(hex_str: &str) -> Result<[u8; 32], String> {
    if hex_str.is_empty() {
        return Ok([0u8; 32]);
    }
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
