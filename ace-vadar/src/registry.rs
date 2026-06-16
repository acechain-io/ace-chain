//! On-chain VA-DAR discovery registry.
//!
//! Stores `DiscoveryID → DiscoveryRecord` mappings with signature-verified
//! updates and monotonic versioning.
//!
//! The registry is intentionally identifier-agnostic: the DiscoveryID is a
//! 32-byte keyed HMAC computed client-side from the user's passphrase and
//! an arbitrary identifier (email, phone, username, etc.). The chain never
//! sees the raw identifier.

use std::collections::BTreeMap;
#[cfg(feature = "persistence")]
use std::sync::Arc;

use ace_runtime::crypto::sig_algo::{verify_signature, TaggedPubkey, TaggedSignature};
use sha2::{Digest, Sha256};

use crate::error::VadarError;

/// Maximum inline sealed artifact size (4 KiB).
///
/// SA2 is typically ~256-512 bytes (Argon2 params + AEAD ciphertext of a
/// 32-byte REV).  4 KiB provides generous headroom for metadata and future
/// algorithm parameters without allowing state bloat.
const MAX_ARTIFACT_SIZE: usize = 4096;

/// Domain separator for registry authorization signatures.
const AUTH_DOMAIN: &[u8] = b"va-dar:registry:auth:v1";

/// A single discovery record in the on-chain registry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveryRecord {
    /// Content identifier of SA2 in external storage (Arweave, IPFS, etc.).
    /// All zeros if SA2 is stored inline.
    pub cid: [u8; 32],

    /// Monotonically increasing version counter (starts at 1).
    pub version: u64,

    /// Commitment: `SHA-256(sealed_artifact)` for integrity verification.
    pub commit: [u8; 32],

    /// Owner public key, bound atomically at first registration.
    /// All subsequent updates must be signed by this key.
    pub owner_pubkey: TaggedPubkey,

    /// Optional inline sealed artifact (SA2).
    /// When present, clients can recover without external storage.
    pub sealed_artifact: Option<Vec<u8>>,

    /// Slot at which this record was first created.
    pub created_at: u64,

    /// Slot of the most recent update.
    pub updated_at: u64,

    /// Whether this record has been tombstoned (migration/revocation).
    pub tombstoned: bool,
}

/// Compute the message that must be signed for a registry operation.
///
/// `SHA-256("va-dar:registry:auth:v1" || discovery_id || cid || version_le || commit)`
pub fn authorization_message(
    discovery_id: &[u8; 32],
    cid: &[u8; 32],
    version: u64,
    commit: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTH_DOMAIN);
    hasher.update(discovery_id);
    hasher.update(cid);
    hasher.update(version.to_le_bytes());
    hasher.update(commit);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute the artifact commitment: `SHA-256(artifact_bytes)`.
pub fn artifact_commitment(artifact: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(artifact);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// The on-chain VA-DAR registry.
#[derive(Default)]
pub struct VadarRegistry {
    records: BTreeMap<[u8; 32], DiscoveryRecord>,
    #[cfg(feature = "persistence")]
    app_store: Option<Arc<parking_lot::RwLock<ace_model::rocks_app_store::RocksDbAppStore>>>,
}

impl std::fmt::Debug for VadarRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VadarRegistry")
            .field("records", &self.records)
            .finish()
    }
}

impl VadarRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry backed by RocksDB, loading existing records.
    #[cfg(feature = "persistence")]
    pub fn with_rocks_db(
        app_store: Arc<parking_lot::RwLock<ace_model::rocks_app_store::RocksDbAppStore>>,
    ) -> Self {
        let mut records = BTreeMap::new();
        {
            let store = app_store.read();
            match store.iter_cf(ace_model::rocks_app_store::CF_VADAR_RECORDS) {
                Ok(entries) => {
                    for (key, value) in entries {
                        if key.len() == 32 {
                            let mut did = [0u8; 32];
                            did.copy_from_slice(&key);
                            match bincode::deserialize::<DiscoveryRecord>(&value) {
                                Ok(record) => {
                                    records.insert(did, record);
                                }
                                Err(e) => {
                                    tracing::warn!(%e, "failed to deserialize Vadar record from RocksDB")
                                }
                            }
                        }
                    }
                    tracing::info!(count = records.len(), "loaded Vadar records from RocksDB");
                }
                Err(e) => tracing::warn!(%e, "failed to iterate Vadar records from RocksDB"),
            }
        }
        Self {
            records,
            app_store: Some(app_store),
        }
    }

    /// Write-through a single record to RocksDB.
    #[cfg(feature = "persistence")]
    fn persist_record(&self, discovery_id: &[u8; 32], record: &DiscoveryRecord) {
        if let Some(ref store) = self.app_store {
            let store = store.read();
            match bincode::serialize(record) {
                Ok(bytes) => {
                    if let Err(e) = store.put(
                        ace_model::rocks_app_store::CF_VADAR_RECORDS,
                        discovery_id,
                        &bytes,
                    ) {
                        tracing::warn!(%e, "failed to persist Vadar record to RocksDB");
                    }
                }
                Err(e) => tracing::warn!(%e, "failed to serialize Vadar record for RocksDB"),
            }
        }
    }

    /// Look up a discovery record by its DiscoveryID.
    pub fn lookup(&self, discovery_id: &[u8; 32]) -> Option<&DiscoveryRecord> {
        self.records.get(discovery_id)
    }

    /// Number of registered discovery records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Register a new discovery record (first write).
    ///
    /// Atomically binds `owner_pubkey` to this DiscoveryID.  Fails if the
    /// DiscoveryID is already registered (use `update` instead).
    ///
    /// The caller provides either an inline `sealed_artifact` or an external
    /// `cid`.  If an inline artifact is provided, `commit` must equal
    /// `SHA-256(sealed_artifact)`.
    pub fn register(
        &mut self,
        discovery_id: [u8; 32],
        cid: [u8; 32],
        commit: [u8; 32],
        owner_pubkey: TaggedPubkey,
        signature: &TaggedSignature,
        sealed_artifact: Option<Vec<u8>>,
        current_slot: u64,
    ) -> Result<(), VadarError> {
        // M-8: Allow re-registration after tombstone (migration to new passphrase)
        if let Some(existing) = self.records.get(&discovery_id) {
            if !existing.tombstoned {
                return Err(VadarError::AlreadyRegistered);
            }
        }

        // Verify inline artifact commitment if provided.
        if let Some(ref artifact) = sealed_artifact {
            if artifact.len() > MAX_ARTIFACT_SIZE {
                return Err(VadarError::ArtifactTooLarge {
                    size: artifact.len(),
                    max: MAX_ARTIFACT_SIZE,
                });
            }
            let actual = artifact_commitment(artifact);
            if actual != commit {
                return Err(VadarError::CommitmentMismatch {
                    expected: hex::encode(commit),
                    actual: hex::encode(actual),
                });
            }
        }

        // Verify owner signature over (discovery_id, cid, version=1, commit).
        let msg = authorization_message(&discovery_id, &cid, 1, &commit);
        if !verify_signature(&owner_pubkey, &msg, signature) {
            return Err(VadarError::InvalidSignature);
        }

        let record = DiscoveryRecord {
            cid,
            version: 1,
            commit,
            owner_pubkey,
            sealed_artifact,
            created_at: current_slot,
            updated_at: current_slot,
            tombstoned: false,
        };
        #[cfg(feature = "persistence")]
        self.persist_record(&discovery_id, &record);
        self.records.insert(discovery_id, record);

        Ok(())
    }

    /// Update an existing discovery record.
    ///
    /// The new version must be strictly greater than the current version.
    /// The signature must be valid under the record's bound `owner_pubkey`.
    pub fn update(
        &mut self,
        discovery_id: &[u8; 32],
        cid: [u8; 32],
        version: u64,
        commit: [u8; 32],
        signature: &TaggedSignature,
        sealed_artifact: Option<Vec<u8>>,
        current_slot: u64,
    ) -> Result<(), VadarError> {
        let record = self
            .records
            .get(discovery_id)
            .ok_or_else(|| VadarError::NotFound(hex::encode(discovery_id)))?;

        if record.tombstoned {
            return Err(VadarError::Tombstoned);
        }

        if version <= record.version {
            return Err(VadarError::VersionNotMonotonic {
                current: record.version,
                proposed: version,
            });
        }

        if let Some(ref artifact) = sealed_artifact {
            if artifact.len() > MAX_ARTIFACT_SIZE {
                return Err(VadarError::ArtifactTooLarge {
                    size: artifact.len(),
                    max: MAX_ARTIFACT_SIZE,
                });
            }
            let actual = artifact_commitment(artifact);
            if actual != commit {
                return Err(VadarError::CommitmentMismatch {
                    expected: hex::encode(commit),
                    actual: hex::encode(actual),
                });
            }
        }

        // Verify signature under bound owner key.
        let msg = authorization_message(discovery_id, &cid, version, &commit);
        if !verify_signature(&record.owner_pubkey, &msg, signature) {
            return Err(VadarError::InvalidSignature);
        }

        {
            let record = self.records.get_mut(discovery_id).unwrap();
            record.cid = cid;
            record.version = version;
            record.commit = commit;
            record.sealed_artifact = sealed_artifact;
            record.updated_at = current_slot;
        }

        #[cfg(feature = "persistence")]
        if let Some(record) = self.records.get(discovery_id) {
            self.persist_record(discovery_id, record);
        }

        Ok(())
    }

    /// Tombstone a discovery record (soft delete for migration).
    ///
    /// The record remains queryable but is marked as inactive.
    /// Clients should treat tombstoned records as hints to re-register
    /// with a new passphrase if applicable.
    pub fn tombstone(
        &mut self,
        discovery_id: &[u8; 32],
        signature: &TaggedSignature,
        current_slot: u64,
    ) -> Result<(), VadarError> {
        let record = self
            .records
            .get(discovery_id)
            .ok_or_else(|| VadarError::NotFound(hex::encode(discovery_id)))?;

        if record.tombstoned {
            return Err(VadarError::Tombstoned);
        }

        // Sign over (discovery_id, zero_cid, version+1, zero_commit) as tombstone marker.
        let tombstone_version = record.version + 1;
        let msg = authorization_message(discovery_id, &[0u8; 32], tombstone_version, &[0u8; 32]);
        if !verify_signature(&record.owner_pubkey, &msg, signature) {
            return Err(VadarError::InvalidSignature);
        }

        {
            let record = self.records.get_mut(discovery_id).unwrap();
            record.tombstoned = true;
            record.version = tombstone_version;
            record.updated_at = current_slot;
        }

        #[cfg(feature = "persistence")]
        if let Some(record) = self.records.get(discovery_id) {
            self.persist_record(discovery_id, record);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_keypair() -> (TaggedPubkey, SigningKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
        (TaggedPubkey::ed25519(pk_bytes), sk)
    }

    fn sign_ed25519(sk: &SigningKey, msg: &[u8]) -> TaggedSignature {
        let sig = sk.sign(msg);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&sig.to_bytes());
        TaggedSignature::ed25519(sig_bytes)
    }

    #[test]
    fn register_and_lookup() {
        let mut registry = VadarRegistry::new();
        let (pk, sk) = make_keypair();

        let did = [0xAA; 32];
        let cid = [0xBB; 32];
        let artifact = b"encrypted-sa2-payload-here";
        let commit = artifact_commitment(artifact);

        let msg = authorization_message(&did, &cid, 1, &commit);
        let sig = sign_ed25519(&sk, &msg);

        registry
            .register(
                did,
                cid,
                commit,
                pk.clone(),
                &sig,
                Some(artifact.to_vec()),
                100,
            )
            .unwrap();

        let record = registry.lookup(&did).unwrap();
        assert_eq!(record.version, 1);
        assert_eq!(record.cid, cid);
        assert_eq!(record.commit, commit);
        assert!(!record.tombstoned);
        assert_eq!(record.sealed_artifact.as_deref(), Some(artifact.as_slice()));
    }

    #[test]
    fn register_rejects_duplicate() {
        let mut registry = VadarRegistry::new();
        let (pk, sk) = make_keypair();

        let did = [0x11; 32];
        let cid = [0x22; 32];
        let commit = [0x33; 32];
        let msg = authorization_message(&did, &cid, 1, &commit);
        let sig = sign_ed25519(&sk, &msg);

        registry
            .register(did, cid, commit, pk.clone(), &sig, None, 1)
            .unwrap();
        assert!(registry
            .register(did, cid, commit, pk, &sig, None, 2)
            .is_err());
    }

    #[test]
    fn update_enforces_monotonic_version() {
        let mut registry = VadarRegistry::new();
        let (pk, sk) = make_keypair();

        let did = [0x44; 32];
        let cid1 = [0x55; 32];
        let commit1 = [0x66; 32];
        let msg1 = authorization_message(&did, &cid1, 1, &commit1);
        let sig1 = sign_ed25519(&sk, &msg1);
        registry
            .register(did, cid1, commit1, pk, &sig1, None, 1)
            .unwrap();

        // version=1 should fail (not strictly greater)
        let cid2 = [0x77; 32];
        let commit2 = [0x88; 32];
        let msg_bad = authorization_message(&did, &cid2, 1, &commit2);
        let sig_bad = sign_ed25519(&sk, &msg_bad);
        assert!(registry
            .update(&did, cid2, 1, commit2, &sig_bad, None, 2)
            .is_err());

        // version=2 should succeed
        let msg2 = authorization_message(&did, &cid2, 2, &commit2);
        let sig2 = sign_ed25519(&sk, &msg2);
        registry
            .update(&did, cid2, 2, commit2, &sig2, None, 2)
            .unwrap();
        assert_eq!(registry.lookup(&did).unwrap().version, 2);
    }

    #[test]
    fn update_rejects_wrong_key() {
        let mut registry = VadarRegistry::new();
        let (pk, sk) = make_keypair();
        let (_, attacker_sk) = make_keypair();

        let did = [0xCC; 32];
        let cid = [0xDD; 32];
        let commit = [0xEE; 32];
        let msg = authorization_message(&did, &cid, 1, &commit);
        let sig = sign_ed25519(&sk, &msg);
        registry
            .register(did, cid, commit, pk, &sig, None, 1)
            .unwrap();

        // Attacker tries to update with their own key
        let cid2 = [0xFF; 32];
        let commit2 = [0x11; 32];
        let msg2 = authorization_message(&did, &cid2, 2, &commit2);
        let sig2 = sign_ed25519(&attacker_sk, &msg2);
        let result = registry.update(&did, cid2, 2, commit2, &sig2, None, 2);
        assert!(matches!(result, Err(VadarError::InvalidSignature)));
    }

    #[test]
    fn tombstone_prevents_further_updates() {
        let mut registry = VadarRegistry::new();
        let (pk, sk) = make_keypair();

        let did = [0xAA; 32];
        let cid = [0xBB; 32];
        let commit = [0xCC; 32];
        let msg = authorization_message(&did, &cid, 1, &commit);
        let sig = sign_ed25519(&sk, &msg);
        registry
            .register(did, cid, commit, pk, &sig, None, 1)
            .unwrap();

        // Tombstone
        let tombstone_msg = authorization_message(&did, &[0u8; 32], 2, &[0u8; 32]);
        let tombstone_sig = sign_ed25519(&sk, &tombstone_msg);
        registry.tombstone(&did, &tombstone_sig, 10).unwrap();

        assert!(registry.lookup(&did).unwrap().tombstoned);

        // Further update should fail
        let cid3 = [0xDD; 32];
        let commit3 = [0xEE; 32];
        let msg3 = authorization_message(&did, &cid3, 3, &commit3);
        let sig3 = sign_ed25519(&sk, &msg3);
        assert!(matches!(
            registry.update(&did, cid3, 3, commit3, &sig3, None, 11),
            Err(VadarError::Tombstoned)
        ));
    }

    #[test]
    fn inline_artifact_commitment_verified() {
        let mut registry = VadarRegistry::new();
        let (pk, sk) = make_keypair();

        let did = [0x11; 32];
        let cid = [0x22; 32];
        let artifact = b"the-sealed-artifact";
        let wrong_commit = [0xFF; 32]; // doesn't match artifact

        let msg = authorization_message(&did, &cid, 1, &wrong_commit);
        let sig = sign_ed25519(&sk, &msg);

        let result =
            registry.register(did, cid, wrong_commit, pk, &sig, Some(artifact.to_vec()), 1);
        assert!(matches!(result, Err(VadarError::CommitmentMismatch { .. })));
    }
}
