//! Relay service data types and in-memory store.
//!
//! The relay is the sole off-chain component that holds the private
//! identifier → intentId mappings.  It does not custody funds and cannot
//! unilaterally redirect withdrawals.
//!
//! This module provides the data model and in-memory store; a full
//! HTTP server is out of scope.

use std::collections::HashMap;

use ace_model::account::AccountId;
use ace_runtime::crypto::sig_algo::{verify_signature, TaggedPubkey, TaggedSignature};
use sha2::{Digest, Sha256};

use crate::address::derive_intent_address;
use crate::error::HfiPayError;
use crate::intent::{ChainId, IntentStatus};

/// A relay-side intent record (includes private identifier data).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayIntent {
    pub intent_id: [u8; 32],
    /// Intent-specific blinded binding: `ρ = H("hfipay:bind" || u_B || intentId)`.
    pub blinded_binding: [u8; 32],
    pub recipient_identifier: String,
    pub amount: u64,
    pub chain: ChainId,
    pub deposit_address: AccountId,
    /// Token mint ID (`None` = native balance).
    pub mint: Option<[u8; 32]>,
    /// Coarse public binding epoch label for the hidden handle used in `ρ`.
    #[serde(default)]
    pub binding_epoch: u64,
    pub refund_dest: Option<AccountId>,
    pub refund_authorizer: Option<AccountId>,
    pub expiry: u64,
    pub refund_auth: Option<(TaggedPubkey, TaggedSignature)>,
    pub status: IntentStatus,
    pub created_at: u64,
}

/// Public binding-key commitment used by sender-verifiable quotes.
///
/// `K_{B,e} = H("hfipay:bind-key" || u_{B,e})`
pub fn compute_binding_key_commitment(claim_binding_handle: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hfipay:bind-key");
    hasher.update(claim_binding_handle);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Message signed by the binding issuer / attester.
///
/// **Important**: `identifier` must be pre-normalized by the caller (e.g.
/// lowercased, trimmed) before being passed here.  This function hashes the
/// bytes as-is — if a non-normalized string is used, the attestation will
/// not verify against a correctly normalized quote-verification client.
pub fn binding_attestation_message(
    normalized_identifier: &str,
    binding_key_commitment: &[u8; 32],
    binding_epoch: u64,
    valid_until: u64,
) -> [u8; 32] {
    debug_assert!(
        normalized_identifier == normalized_identifier.trim()
            && normalized_identifier
                .chars()
                .all(|c| !c.is_ascii_uppercase()),
        "binding_attestation_message: identifier should be pre-normalized"
    );
    let mut hasher = Sha256::new();
    hasher.update(b"hfipay:bind-attest");
    hasher.update(normalized_identifier.as_bytes());
    hasher.update(binding_key_commitment);
    hasher.update(binding_epoch.to_le_bytes());
    hasher.update(valid_until.to_le_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BindingAttestation {
    pub binding_key_commitment: [u8; 32],
    pub binding_epoch: u64,
    pub valid_until: u64,
    pub attestor_pubkey: TaggedPubkey,
    pub signature: TaggedSignature,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuoteProofPublicInputs {
    pub binding_key_commitment: [u8; 32],
    pub blinded_binding: [u8; 32],
    pub intent_id: [u8; 32],
    pub chain: ChainId,
    pub mint: Option<[u8; 32]>,
    pub binding_epoch: u64,
    pub amount: u64,
    pub deposit_address: AccountId,
    pub refund_dest: Option<AccountId>,
    pub refund_authorizer: Option<AccountId>,
    pub expiry: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuoteProof {
    pub public_inputs: QuoteProofPublicInputs,
    pub proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifiedQuote {
    pub intent: RelayIntent,
    pub binding_attestation: BindingAttestation,
    pub quote_proof: QuoteProof,
    pub quote_expiry: u64,
}

/// Canonical message hashed by signature-backed verified-quote proofs.
///
/// Production deployments can replace the signature scheme with a stronger
/// proof system, but every implementation should commit to the same public
/// tuple bytes when proving sender-verifiable quote correctness.
pub fn quote_proof_message(inputs: &QuoteProofPublicInputs) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hfipay:quote-proof");
    hasher.update(inputs.binding_key_commitment);
    hasher.update(inputs.blinded_binding);
    hasher.update(inputs.intent_id);
    hasher.update([inputs.chain.tag()]);
    match inputs.mint {
        Some(mint) => {
            hasher.update([1u8]);
            hasher.update(mint);
        }
        None => hasher.update([0u8]),
    }
    hasher.update(inputs.binding_epoch.to_le_bytes());
    hasher.update(inputs.amount.to_le_bytes());
    hasher.update(inputs.deposit_address.as_bytes());
    match inputs.refund_dest {
        Some(dest) => {
            hasher.update([1u8]);
            hasher.update(dest.as_bytes());
        }
        None => hasher.update([0u8]),
    }
    match inputs.refund_authorizer {
        Some(authorizer) => {
            hasher.update([1u8]);
            hasher.update(authorizer.as_bytes());
        }
        None => hasher.update([0u8]),
    }
    hasher.update(inputs.expiry.to_le_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Verify a signature-backed quote proof.
///
/// The proof bytes are interpreted as a tagged signature over
/// [`quote_proof_message`]. This is a practical instantiation for the current
/// API layer until a dedicated quote-proof circuit is wired in.
pub fn verify_attested_quote_proof(attestor_pubkey: &TaggedPubkey, proof: &QuoteProof) -> bool {
    let Ok((signature, consumed)) = TaggedSignature::from_wire_bytes(&proof.proof_bytes) else {
        return false;
    };
    if consumed != proof.proof_bytes.len() {
        return false;
    }
    let msg = quote_proof_message(&proof.public_inputs);
    verify_signature(attestor_pubkey, &msg, &signature)
}

/// Verify a binding attestation.
///
/// `normalized_identifier` must be the same normalized form used when the
/// attestation was originally created.
pub fn verify_binding_attestation(
    normalized_identifier: &str,
    attestation: &BindingAttestation,
    current_slot: u64,
) -> Result<(), HfiPayError> {
    if current_slot > attestation.valid_until {
        return Err(HfiPayError::QuoteExpired);
    }
    let msg = binding_attestation_message(
        normalized_identifier,
        &attestation.binding_key_commitment,
        attestation.binding_epoch,
        attestation.valid_until,
    );
    if !verify_signature(&attestation.attestor_pubkey, &msg, &attestation.signature) {
        return Err(HfiPayError::InvalidBindingAttestation);
    }
    Ok(())
}

pub fn verify_quote_proof_inputs(intent: &RelayIntent, proof: &QuoteProof) -> bool {
    proof.public_inputs.blinded_binding == intent.blinded_binding
        && proof.public_inputs.intent_id == intent.intent_id
        && proof.public_inputs.chain == intent.chain
        && proof.public_inputs.mint == intent.mint
        && proof.public_inputs.binding_epoch == intent.binding_epoch
        && proof.public_inputs.amount == intent.amount
        && proof.public_inputs.deposit_address == intent.deposit_address
        && proof.public_inputs.refund_dest == intent.refund_dest
        && proof.public_inputs.refund_authorizer == intent.refund_authorizer
        && proof.public_inputs.expiry == intent.expiry
}

pub fn verify_verified_quote<F>(
    identifier: &str,
    quote: &VerifiedQuote,
    current_slot: u64,
    verify_quote_proof: F,
) -> Result<(), HfiPayError>
where
    F: FnOnce(&QuoteProof) -> bool,
{
    if current_slot > quote.quote_expiry {
        return Err(HfiPayError::QuoteExpired);
    }

    verify_binding_attestation(identifier, &quote.binding_attestation, current_slot)?;

    if quote.binding_attestation.binding_key_commitment
        != quote.quote_proof.public_inputs.binding_key_commitment
        || quote.binding_attestation.binding_epoch != quote.intent.binding_epoch
    {
        return Err(HfiPayError::InvalidBindingAttestation);
    }

    if !verify_quote_proof_inputs(&quote.intent, &quote.quote_proof) {
        return Err(HfiPayError::InvalidQuoteProofInputs);
    }

    let expected_deposit = derive_intent_address(quote.intent.chain, &quote.intent.intent_id);
    if expected_deposit != quote.intent.deposit_address {
        return Err(HfiPayError::InvalidQuoteProofInputs);
    }

    if !verify_quote_proof(&quote.quote_proof) {
        return Err(HfiPayError::InvalidQuoteProof);
    }

    Ok(())
}

/// In-memory store for the relay service.
#[derive(Debug)]
pub struct RelayStore {
    /// Per-instance salt mixed into identifier hashes to prevent cross-instance correlation.
    salt: [u8; 32],
    /// identifier_hash → [intent_ids] (hashed for defense-in-depth)
    identifier_intents: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// intent_id → RelayIntent
    intents: HashMap<[u8; 32], RelayIntent>,
}

impl Default for RelayStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayStore {
    pub fn new() -> Self {
        use rand::RngCore;
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            salt,
            identifier_intents: HashMap::new(),
            intents: HashMap::new(),
        }
    }

    /// Create a new intent for the given recipient identifier.
    ///
    /// Generates a random 256-bit `intentId`, computes the blinded binding
    /// `ρ = H("hfipay:bind" || claim_binding_handle || intentId)`, and
    /// derives the deposit address.
    ///
    /// `claim_binding_handle` is the recipient's private `u_B` looked up
    /// from the relay's directory by the normalized identifier.
    pub fn create_intent(
        &mut self,
        identifier: &str,
        claim_binding_handle: &[u8; 32],
        amount: u64,
        chain: ChainId,
        mint: Option<[u8; 32]>,
        binding_epoch: u64,
        refund_dest: Option<AccountId>,
        refund_authorizer: Option<AccountId>,
        expiry: u64,
        refund_auth: Option<(TaggedPubkey, TaggedSignature)>,
        current_slot: u64,
    ) -> Result<RelayIntent, HfiPayError> {
        if amount == 0 {
            return Err(HfiPayError::InvalidAmount("amount must be non-zero".into()));
        }
        match (&refund_dest, &refund_authorizer, &refund_auth) {
            (Some(_), Some(_), Some(_)) | (None, None, None) => {}
            (Some(_), None, _) | (None, Some(_), _) => {
                return Err(HfiPayError::MissingRefundAuthorizer)
            }
            (Some(_), Some(_), None) => return Err(HfiPayError::MissingRefundAuthorization),
            (None, _, Some(_)) => return Err(HfiPayError::NoRefundDestination),
        }

        let intent_id = generate_intent_id();
        let blinded_binding = crate::compute_blinded_binding(claim_binding_handle, &intent_id);
        let deposit_address = derive_intent_address(chain, &intent_id);

        let intent = RelayIntent {
            intent_id,
            blinded_binding,
            recipient_identifier: identifier.to_string(),
            amount,
            chain,
            deposit_address,
            mint,
            binding_epoch,
            refund_dest,
            refund_authorizer,
            expiry,
            refund_auth,
            status: IntentStatus::Created,
            created_at: current_slot,
        };

        let id_hash = hash_identifier(identifier, &self.salt);
        self.identifier_intents
            .entry(id_hash)
            .or_default()
            .push(intent_id);
        self.intents.insert(intent_id, intent.clone());

        Ok(intent)
    }

    /// Create a sender-verifiable quote for a new intent.
    ///
    /// The relay still samples the random `intentId` and computes the blinded
    /// binding, but the returned quote now carries:
    /// - an attestation over `(identifier, K_{B,e}, e, valid_until)`, and
    /// - a quote proof whose public inputs are tied to the exact intent tuple.
    ///
    /// The actual proof-system verification remains caller-supplied, mirroring
    /// the crate's treatment of ZK-ACE claim proofs.
    pub fn create_verified_quote(
        &mut self,
        identifier: &str,
        claim_binding_handle: &[u8; 32],
        amount: u64,
        chain: ChainId,
        mint: Option<[u8; 32]>,
        binding_epoch: u64,
        refund_dest: Option<AccountId>,
        refund_authorizer: Option<AccountId>,
        expiry: u64,
        refund_auth: Option<(TaggedPubkey, TaggedSignature)>,
        current_slot: u64,
        binding_attestation: BindingAttestation,
        quote_expiry: u64,
        proof_bytes: Vec<u8>,
    ) -> Result<VerifiedQuote, HfiPayError> {
        let expected_binding_key = compute_binding_key_commitment(claim_binding_handle);
        if binding_attestation.binding_key_commitment != expected_binding_key
            || binding_attestation.binding_epoch != binding_epoch
        {
            return Err(HfiPayError::InvalidBindingAttestation);
        }
        if quote_expiry > binding_attestation.valid_until {
            return Err(HfiPayError::QuoteExpired);
        }
        verify_binding_attestation(identifier, &binding_attestation, current_slot)?;

        let intent = self.create_intent(
            identifier,
            claim_binding_handle,
            amount,
            chain,
            mint,
            binding_epoch,
            refund_dest,
            refund_authorizer,
            expiry,
            refund_auth,
            current_slot,
        )?;

        let quote_proof = QuoteProof {
            public_inputs: QuoteProofPublicInputs {
                binding_key_commitment: expected_binding_key,
                blinded_binding: intent.blinded_binding,
                intent_id: intent.intent_id,
                chain: intent.chain,
                mint: intent.mint,
                binding_epoch: intent.binding_epoch,
                amount: intent.amount,
                deposit_address: intent.deposit_address,
                refund_dest: intent.refund_dest,
                refund_authorizer: intent.refund_authorizer,
                expiry: intent.expiry,
            },
            proof_bytes,
        };

        Ok(VerifiedQuote {
            intent,
            binding_attestation,
            quote_proof,
            quote_expiry,
        })
    }

    /// List all pending (unclaimed) intents for the given identifier.
    pub fn pending_intents(&self, identifier: &str) -> Vec<&RelayIntent> {
        let id_hash = hash_identifier(identifier, &self.salt);
        self.identifier_intents
            .get(&id_hash)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.intents.get(id))
                    .filter(|i| matches!(i.status, IntentStatus::Created | IntentStatus::Funded))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get an intent by ID.
    pub fn get(&self, intent_id: &[u8; 32]) -> Option<&RelayIntent> {
        self.intents.get(intent_id)
    }

    /// Mark an intent as funded.
    pub fn mark_funded(&mut self, intent_id: &[u8; 32]) -> Result<(), HfiPayError> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| HfiPayError::IntentNotFound(hex::encode(intent_id)))?;
        if intent.status != IntentStatus::Created {
            return Err(HfiPayError::InvalidTransition {
                from: intent.status.to_string(),
                to: "Funded".into(),
            });
        }
        intent.status = IntentStatus::Funded;
        Ok(())
    }

    /// Mark an intent as claimed.
    pub fn mark_claimed(&mut self, intent_id: &[u8; 32]) -> Result<(), HfiPayError> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| HfiPayError::IntentNotFound(hex::encode(intent_id)))?;
        if intent.status != IntentStatus::Funded {
            return Err(HfiPayError::InvalidTransition {
                from: intent.status.to_string(),
                to: "Claimed".into(),
            });
        }
        intent.status = IntentStatus::Claimed;
        Ok(())
    }

    /// Mark an intent as refunded.
    pub fn mark_refunded(
        &mut self,
        intent_id: &[u8; 32],
        current_slot: u64,
    ) -> Result<(), HfiPayError> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| HfiPayError::IntentNotFound(hex::encode(intent_id)))?;
        if intent.status == IntentStatus::Funded && current_slot > intent.expiry {
            intent.status = IntentStatus::Expired;
        } else if intent.status == IntentStatus::Funded {
            return Err(HfiPayError::IntentNotExpired {
                current_slot,
                expiry: intent.expiry,
            });
        }
        if intent.status != IntentStatus::Expired {
            return Err(HfiPayError::InvalidTransition {
                from: intent.status.to_string(),
                to: "Refunded".into(),
            });
        }
        intent.status = IntentStatus::Refunded;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.intents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
    }

    /// Snapshot the relay store for persistence.
    pub fn snapshot(&self) -> RelayStoreSnapshot {
        RelayStoreSnapshot {
            salt: self.salt,
            identifier_intents: self.identifier_intents.clone(),
            intents: self.intents.clone(),
        }
    }

    /// Restore from a snapshot.
    pub fn restore(snapshot: RelayStoreSnapshot) -> Self {
        Self {
            salt: snapshot.salt,
            identifier_intents: snapshot.identifier_intents,
            intents: snapshot.intents,
        }
    }
}

/// Serializable snapshot of a [`RelayStore`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayStoreSnapshot {
    pub salt: [u8; 32],
    #[serde(with = "crate::serde_hex_key::hash_vec")]
    pub identifier_intents: HashMap<[u8; 32], Vec<[u8; 32]>>,
    #[serde(with = "crate::serde_hex_key::hash")]
    pub intents: HashMap<[u8; 32], RelayIntent>,
}

fn generate_intent_id() -> [u8; 32] {
    use rand::RngCore;
    let mut id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

fn hash_identifier(identifier: &str, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hfipay:identifier:");
    hasher.update(salt);
    hasher.update(identifier.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::ChainId;

    #[test]
    fn snapshot_restore_preserves_intents() {
        let mut store = RelayStore::new();
        let handle = &[7u8; 32];
        store
            .create_intent(
                "alice@test.com",
                handle,
                100,
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
                "bob@test.com",
                handle,
                200,
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

        let snapshot = store.snapshot();
        let restored = RelayStore::restore(snapshot);

        assert_eq!(restored.len(), 2);

        let alice_pending = restored.pending_intents("alice@test.com");
        assert_eq!(alice_pending.len(), 1);
        assert_eq!(alice_pending[0].amount, 100);
        assert_eq!(alice_pending[0].recipient_identifier, "alice@test.com");

        let bob_pending = restored.pending_intents("bob@test.com");
        assert_eq!(bob_pending.len(), 1);
        assert_eq!(bob_pending[0].amount, 200);
    }

    #[test]
    fn snapshot_restore_preserves_salt_and_lookups() {
        let mut store = RelayStore::new();
        let handle = &[7u8; 32];
        let intent = store
            .create_intent(
                "user@x.com",
                handle,
                500,
                ChainId::Native,
                None,
                0,
                None,
                None,
                9000,
                None,
                10,
            )
            .unwrap();
        let intent_id = intent.intent_id;

        let snapshot = store.snapshot();
        let restored = RelayStore::restore(snapshot);

        // Can still look up by intent_id
        let got = restored.get(&intent_id).unwrap();
        assert_eq!(got.amount, 500);
        assert_eq!(got.expiry, 9000);
        assert_eq!(got.created_at, 10);
    }

    #[test]
    fn snapshot_restore_multiple_intents_same_identifier() {
        let mut store = RelayStore::new();
        let handle = &[7u8; 32];
        store
            .create_intent(
                "shared@x.com",
                handle,
                10,
                ChainId::Native,
                None,
                0,
                None,
                None,
                100,
                None,
                1,
            )
            .unwrap();
        store
            .create_intent(
                "shared@x.com",
                handle,
                20,
                ChainId::Native,
                None,
                0,
                None,
                None,
                200,
                None,
                2,
            )
            .unwrap();
        store
            .create_intent(
                "shared@x.com",
                handle,
                30,
                ChainId::Native,
                None,
                0,
                None,
                None,
                300,
                None,
                3,
            )
            .unwrap();

        let snapshot = store.snapshot();
        let restored = RelayStore::restore(snapshot);

        assert_eq!(restored.len(), 3);
        let pending = restored.pending_intents("shared@x.com");
        assert_eq!(pending.len(), 3);

        let amounts: Vec<u64> = {
            let mut v: Vec<u64> = pending.iter().map(|i| i.amount).collect();
            v.sort();
            v
        };
        assert_eq!(amounts, vec![10, 20, 30]);
    }

    #[test]
    fn snapshot_restore_empty_store() {
        let store = RelayStore::new();
        let snapshot = store.snapshot();
        let restored = RelayStore::restore(snapshot);
        assert_eq!(restored.len(), 0);
        assert!(restored.is_empty());
    }

    #[test]
    fn snapshot_roundtrip_via_serde() {
        let mut store = RelayStore::new();
        let handle = &[7u8; 32];
        store
            .create_intent(
                "serde@test.com",
                handle,
                777,
                ChainId::Native,
                None,
                0,
                None,
                None,
                4000,
                None,
                5,
            )
            .unwrap();

        let snapshot = store.snapshot();
        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: RelayStoreSnapshot = serde_json::from_str(&json).unwrap();
        let restored = RelayStore::restore(deserialized);

        assert_eq!(restored.len(), 1);
        let pending = restored.pending_intents("serde@test.com");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].amount, 777);
    }
}
