//! Recipient registry for auto-claim.
//!
//! When a user registers their ACE-GF wallet (via XID), subsequent payments
//! to their identifier bypass the manual claim/withdraw flow and route
//! directly to their XID-derived AccountId.
//!
//! # Identifier agnosticism
//!
//! The registry is intentionally identifier-agnostic: the application layer
//! decides what constitutes an identifier (email, phone number, username,
//! social handle, etc.).  Internally the registry only ever sees a salted
//! SHA-256 hash of the raw identifier bytes.
//!
//! # Registration
//!
//! The user proves ownership of the XID by signing a registration message
//! with any chain-specific key derived from the same mnemonic.  The relay
//! stores the mapping `identifier_hash → RegisteredRecipient`.
//!
//! # Auto-claim
//!
//! When an intent is funded and the recipient identifier is registered, the
//! executor's [`direct_deposit`](crate::executor::direct_deposit) function
//! transfers funds straight to the registered AccountId in a single step,
//! skipping the claim and withdraw phases entirely.

use std::collections::HashMap;

use ace_model::account::AccountId;
use ace_runtime::crypto::idcom_xid;
use ace_runtime::crypto::sig_algo::{verify_signature, TaggedPubkey, TaggedSignature};
use sha2::{Digest, Sha256};

use crate::error::HfiPayError;

/// A registered recipient: XID + identity commitment + claim-binding handle.
///
/// # Security: `claim_binding_handle` (`u_B`) is high-sensitivity material
///
/// Leaking `u_B` lets an attacker link all of a recipient's funded intents
/// and forge blinded bindings.  The relay storage that persists this struct
/// MUST be encrypted at rest, access-controlled to the relay process only,
/// and excluded from public backups or diagnostic dumps.
// TODO(mainnet): evaluate moving u_B into a hardware-backed secret store
// (e.g. HSM, SGX enclave) so it is never in plaintext on disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegisteredRecipient {
    /// ACE-GF wallet fingerprint: `SHA3-256(sealed || "acegf:xid")`.
    pub xid: [u8; 32],
    /// Primary AccountId derived from XID via `idcom_xid`.
    pub account_id: AccountId,
    /// Identity commitment `IDcom_B = H(REV_B || s_B || domain_id)` as in ZK-ACE.
    pub identity_commitment: [u8; 32],
    /// Private claim-binding handle `u_B = H(Derive(REV_B, Ctx_bind))`.
    ///
    /// Used by the relay to compute intent-specific blinded bindings
    /// `ρ = H("hfipay:bind" || u_B || intentId)`.
    ///
    /// **High-sensitivity**: treat as equivalent to a per-recipient private key.
    pub claim_binding_handle: [u8; 32],
    /// Current coarse public binding epoch label for the registered handle.
    #[serde(default)]
    pub binding_epoch: u64,
    /// Public key used to sign the registration message (any chain key from the same mnemonic).
    pub pubkey: TaggedPubkey,
}

/// In-memory registry mapping identifier hashes to registered recipients.
#[derive(Debug)]
pub struct RecipientRegistry {
    salt: [u8; 32],
    entries: HashMap<[u8; 32], RegisteredRecipient>,
}

impl Default for RecipientRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Domain separator for the registration message (v1, legacy).
const REGISTER_DOMAIN: &[u8] = b"hfipay:register";

/// Domain separator for the v2 registration message that binds idcom, the
/// claim_binding_handle and the binding_epoch into the signed payload, so
/// these routing-critical fields cannot be substituted by a relay.
const REGISTER_DOMAIN_V2: &[u8] = b"hfipay:register:v2";

/// Compute the registration message that the user must sign.
///
/// `SHA-256("hfipay:register" || xid || identifier_bytes)`
///
/// The `identifier` is application-defined (email, phone, etc.) and is
/// passed as raw bytes.  Callers are responsible for canonical normalization
/// (e.g. lowercasing email, stripping whitespace).
pub fn registration_message(xid: &[u8; 32], identifier: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REGISTER_DOMAIN);
    hasher.update(xid);
    hasher.update(identifier);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// V2 registration message — binds the routing fields so the relay (and any
/// other intermediary) cannot rewrite `identity_commitment`,
/// `claim_binding_handle`, `binding_epoch`, the chain tag, or the validity
/// window for an already-signed registration. Used by the on-chain
/// auto-claim path (`HfiPayRegisterRecipient` opcode 0x0B).
///
/// `SHA-256("hfipay:register:v2" || xid || identifier
///          || identity_commitment || claim_binding_handle
///          || binding_epoch_le_u64 || chain_tag(1)
///          || valid_until_slot_le_u64)`
///
/// `chain_tag` is the `ChainId` tag of the chain that should accept the
/// registration (currently always `ChainId::Native = 0` for ACE-native
/// registrations). `valid_until_slot` is the latest block slot at which the
/// chain will accept the registration; bounds the bearer-credential lifetime
/// of a signed registration message.
pub fn registration_message_v2(
    xid: &[u8; 32],
    identifier: &[u8],
    identity_commitment: &[u8; 32],
    claim_binding_handle: &[u8; 32],
    binding_epoch: u64,
    chain_tag: u8,
    valid_until_slot: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REGISTER_DOMAIN_V2);
    hasher.update(xid);
    hasher.update(identifier);
    hasher.update(identity_commitment);
    hasher.update(claim_binding_handle);
    hasher.update(binding_epoch.to_le_bytes());
    hasher.update([chain_tag]);
    hasher.update(valid_until_slot.to_le_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

impl RecipientRegistry {
    pub fn new() -> Self {
        use rand::RngCore;
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            salt,
            entries: HashMap::new(),
        }
    }

    /// Create a registry with a pre-existing salt (for restoring from persistence).
    pub fn with_salt(salt: [u8; 32]) -> Self {
        Self {
            salt,
            entries: HashMap::new(),
        }
    }

    /// Return the salt used for identifier hashing.
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Register a recipient: verify the signature over the registration
    /// message, then store the XID → AccountId mapping.
    ///
    /// `identifier` is the raw identifier bytes (e.g. normalized email).
    /// `identity_commitment` is `IDcom_B` from ZK-ACE.
    /// `claim_binding_handle` is the private `u_B` used for blinded bindings.
    pub fn register(
        &mut self,
        identifier: &[u8],
        xid: [u8; 32],
        identity_commitment: [u8; 32],
        claim_binding_handle: [u8; 32],
        pubkey: &TaggedPubkey,
        signature: &TaggedSignature,
    ) -> Result<RegisteredRecipient, HfiPayError> {
        self.register_with_binding_epoch(
            identifier,
            xid,
            identity_commitment,
            claim_binding_handle,
            0,
            pubkey,
            signature,
        )
    }

    /// Register a recipient while explicitly setting the coarse binding epoch.
    pub fn register_with_binding_epoch(
        &mut self,
        identifier: &[u8],
        xid: [u8; 32],
        identity_commitment: [u8; 32],
        claim_binding_handle: [u8; 32],
        binding_epoch: u64,
        pubkey: &TaggedPubkey,
        signature: &TaggedSignature,
    ) -> Result<RegisteredRecipient, HfiPayError> {
        let msg = registration_message(&xid, identifier);
        if !verify_signature(pubkey, &msg, signature) {
            return Err(HfiPayError::InvalidRegistrationSignature);
        }

        let account_id = AccountId::from_bytes(idcom_xid(&xid));
        let recipient = RegisteredRecipient {
            xid,
            account_id,
            identity_commitment,
            claim_binding_handle,
            binding_epoch,
            pubkey: pubkey.clone(),
        };

        let id_hash = self.hash_identifier(identifier);
        self.entries.insert(id_hash, recipient.clone());
        Ok(recipient)
    }

    /// Look up a registered recipient by raw identifier.
    pub fn lookup(&self, identifier: &[u8]) -> Option<&RegisteredRecipient> {
        let id_hash = self.hash_identifier(identifier);
        self.entries.get(&id_hash)
    }

    /// Look up a registered recipient by pre-computed identifier hash.
    pub fn lookup_by_hash(&self, id_hash: &[u8; 32]) -> Option<&RegisteredRecipient> {
        self.entries.get(id_hash)
    }

    pub fn is_registered(&self, identifier: &[u8]) -> bool {
        self.lookup(identifier).is_some()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the salted identifier hash used as the storage key.
    pub fn hash_identifier(&self, identifier: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"hfipay:registry:");
        hasher.update(&self.salt);
        hasher.update(identifier);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}
