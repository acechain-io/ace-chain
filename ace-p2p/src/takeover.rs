//! Identity takeover protocol for ACE Chain ("New Kicks Old").
//!
//! A new node instance proves control over an existing identity by signing a
//! takeover message with the same account attestation key. The old node only
//! needs the corresponding public key to verify the request and shut down.
//!
//! Supports both Ed25519 and ML-DSA-44 signatures via TaggedSignature.

use ace_identity::LoadedIdentity;
use ace_runtime::crypto::sig_algo::{self, TaggedPubkey, TaggedSignature};
use serde::{Deserialize, Serialize};

/// Identity takeover message broadcast by a new node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityTakeoverMsg {
    /// Identity commitment (idcom) of the node being taken over.
    pub idcom: [u8; 32],
    /// Algorithm-tagged signature over `idcom || nonce || timestamp_ms`.
    pub credential: TaggedSignature,
    /// Monotonically increasing takeover nonce.
    pub nonce: u64,
    /// Timestamp of the takeover request (Unix ms).
    pub timestamp_ms: u64,
}

impl IdentityTakeoverMsg {
    /// Create a takeover message from a pre-computed TaggedSignature.
    pub fn new_signed(
        idcom: [u8; 32],
        credential: TaggedSignature,
        nonce: u64,
        timestamp_ms: u64,
    ) -> Self {
        Self {
            idcom,
            credential,
            nonce,
            timestamp_ms,
        }
    }

    /// Create a takeover message signed by a loaded ACE identity (Ed25519).
    pub fn new_with_identity(
        idcom: [u8; 32],
        identity: &LoadedIdentity,
        nonce: u64,
        timestamp_ms: u64,
    ) -> Self {
        let raw_sig = identity.sign_identity_message(&signing_message(&idcom, nonce, timestamp_ms));
        let credential = TaggedSignature::ed25519(raw_sig);
        Self::new_signed(idcom, credential, nonce, timestamp_ms)
    }

    /// Verify this takeover message against a known auth public key.
    /// Supports all algorithms via TaggedPubkey dispatch.
    pub fn verify(&self, auth_pubkey: &TaggedPubkey) -> bool {
        let message = signing_message(&self.idcom, self.nonce, self.timestamp_ms);
        sig_algo::verify_signature(auth_pubkey, &message, &self.credential)
    }

    /// Serialize to bytes for P2P transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

pub fn signing_message(idcom: &[u8; 32], nonce: u64, timestamp_ms: u64) -> [u8; 48] {
    let mut message = [0u8; 48];
    message[..32].copy_from_slice(idcom);
    message[32..40].copy_from_slice(&nonce.to_le_bytes());
    message[40..48].copy_from_slice(&timestamp_ms.to_le_bytes());
    message
}

/// Manages identity takeover state for a node.
pub struct TakeoverManager {
    /// This node's identity commitment.
    local_idcom: [u8; 32],
    /// This node's attestation public key for verifying takeover messages.
    local_auth_pubkey: TaggedPubkey,
    /// Highest nonce seen (prevents replay attacks).
    highest_nonce: u64,
    /// Whether a takeover has been triggered.
    taken_over: bool,
}

impl TakeoverManager {
    /// Create a new takeover manager with a TaggedPubkey.
    pub fn new(local_idcom: [u8; 32], local_auth_pubkey: TaggedPubkey) -> Self {
        Self {
            local_idcom,
            local_auth_pubkey,
            highest_nonce: 0,
            taken_over: false,
        }
    }

    /// Create from raw Ed25519 bytes (backward compat).
    pub fn from_ed25519(local_idcom: [u8; 32], ed25519_pubkey: [u8; 32]) -> Self {
        Self::new(local_idcom, TaggedPubkey::ed25519(ed25519_pubkey))
    }

    /// Process an incoming takeover message.
    ///
    /// Returns `true` if this node should shut down.
    pub fn on_takeover_msg(&mut self, msg: &IdentityTakeoverMsg) -> bool {
        if msg.idcom != self.local_idcom {
            return false;
        }
        if !msg.verify(&self.local_auth_pubkey) {
            return false;
        }
        if msg.nonce <= self.highest_nonce {
            return false;
        }

        // Reject messages with timestamps too far from current time (5 minute window).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_millis() as u64;
        let max_age_ms: u64 = 5 * 60 * 1000; // 5 minutes
        if msg.timestamp_ms > now_ms.saturating_add(max_age_ms) {
            return false; // too far in the future
        }
        if msg.timestamp_ms.saturating_add(max_age_ms) < now_ms {
            return false; // too old
        }

        self.highest_nonce = msg.nonce;
        self.taken_over = true;
        true
    }

    pub fn is_taken_over(&self) -> bool {
        self.taken_over
    }

    pub fn highest_nonce(&self) -> u64 {
        self.highest_nonce
    }

    /// Set the highest seen nonce (e.g. when restoring from persistent state).
    #[allow(dead_code)]
    pub(crate) fn set_highest_nonce(&mut self, nonce: u64) {
        self.highest_nonce = nonce;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_identity::ACEGF;
    use ace_runtime::crypto::sig_algo::{LocalSigningKey, SignatureAlgorithm};

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_millis() as u64
    }

    fn test_ed25519_key() -> LocalSigningKey {
        LocalSigningKey::from_seed(&[0xAA; 32], SignatureAlgorithm::Ed25519).unwrap()
    }

    fn test_idcom() -> [u8; 32] {
        [0xBB; 32]
    }

    #[test]
    fn test_create_and_verify_takeover_ed25519() {
        let key = test_ed25519_key();
        let idcom = test_idcom();
        let credential = key.sign(&signing_message(&idcom, 1, 1000));
        let msg = IdentityTakeoverMsg::new_signed(idcom, credential, 1, 1000);
        assert!(msg.verify(&key.public_key()));
    }

    #[test]
    fn test_create_and_verify_takeover_ml_dsa_44() {
        let key = LocalSigningKey::from_seed(&[0xCC; 32], SignatureAlgorithm::MlDsa44).unwrap();
        let idcom = test_idcom();
        let credential = key.sign(&signing_message(&idcom, 1, 1000));
        let msg = IdentityTakeoverMsg::new_signed(idcom, credential, 1, 1000);
        assert!(msg.verify(&key.public_key()));
    }

    #[test]
    fn test_wrong_pubkey_fails() {
        let key1 = test_ed25519_key();
        let key2 = LocalSigningKey::from_seed(&[0xFF; 32], SignatureAlgorithm::Ed25519).unwrap();
        let idcom = test_idcom();
        let credential = key1.sign(&signing_message(&idcom, 1, 1000));
        let msg = IdentityTakeoverMsg::new_signed(idcom, credential, 1, 1000);
        assert!(!msg.verify(&key2.public_key()));
    }

    #[test]
    fn test_manager_accepts_valid_takeover() {
        let key = test_ed25519_key();
        let idcom = test_idcom();
        let mut manager = TakeoverManager::new(idcom, key.public_key());
        let ts = now_ms();
        let credential = key.sign(&signing_message(&idcom, 1, ts));
        let msg = IdentityTakeoverMsg::new_signed(idcom, credential, 1, ts);
        assert!(manager.on_takeover_msg(&msg));
        assert!(manager.is_taken_over());
    }

    #[test]
    fn test_manager_ignores_other_identity() {
        let key = test_ed25519_key();
        let idcom = test_idcom();
        let mut manager = TakeoverManager::new(idcom, key.public_key());
        let ts = now_ms();
        let other_idcom = [0xCC; 32];
        let credential = key.sign(&signing_message(&other_idcom, 1, ts));
        let msg = IdentityTakeoverMsg::new_signed(other_idcom, credential, 1, ts);
        assert!(!manager.on_takeover_msg(&msg));
        assert!(!manager.is_taken_over());
    }

    #[test]
    fn test_manager_rejects_replay() {
        let key = test_ed25519_key();
        let idcom = test_idcom();
        let mut manager = TakeoverManager::new(idcom, key.public_key());
        let ts = now_ms();

        let msg1 = IdentityTakeoverMsg::new_signed(
            idcom,
            key.sign(&signing_message(&idcom, 1, ts)),
            1,
            ts,
        );
        assert!(manager.on_takeover_msg(&msg1));

        // Same nonce — should be rejected
        let msg2 = IdentityTakeoverMsg::new_signed(
            idcom,
            key.sign(&signing_message(&idcom, 1, ts + 1)),
            1,
            ts + 1,
        );
        assert!(!manager.on_takeover_msg(&msg2));

        // Higher nonce — should be accepted
        let msg3 = IdentityTakeoverMsg::new_signed(
            idcom,
            key.sign(&signing_message(&idcom, 2, ts + 3)),
            2,
            ts + 3,
        );
        assert!(manager.on_takeover_msg(&msg3));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let key = test_ed25519_key();
        let idcom = test_idcom();
        let credential = key.sign(&signing_message(&idcom, 42, 99999));
        let msg = IdentityTakeoverMsg::new_signed(idcom, credential, 42, 99999);

        let bytes = msg.to_bytes().unwrap();
        let recovered = IdentityTakeoverMsg::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.idcom, msg.idcom);
        assert_eq!(recovered.credential, msg.credential);
        assert_eq!(recovered.nonce, msg.nonce);
        assert_eq!(recovered.timestamp_ms, msg.timestamp_ms);
    }

    #[test]
    fn test_create_with_loaded_identity() {
        let generated = ACEGF::generate_wallet("passphrase", None).unwrap();
        let identity =
            LoadedIdentity::open(&generated.mnemonic, "passphrase", None, 1, b"").unwrap();
        let idcom = identity.chain_identity().idcom;

        let msg = IdentityTakeoverMsg::new_with_identity(idcom, &identity, 9, 777);

        let auth_pk = TaggedPubkey::ed25519(identity.auth_pubkey());
        assert!(msg.verify(&auth_pk));
        assert_eq!(msg.idcom, idcom);
        assert_eq!(msg.nonce, 9);
        assert_eq!(msg.timestamp_ms, 777);
    }
}
