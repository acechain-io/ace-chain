//! Authorization construction and verification for claim, withdraw, and refund.
//!
//! Each authorization is a signature over a domain-separated message hash.
//! The protocol supports Ed25519, Secp256k1, and ML-DSA-44 via the
//! `TaggedPubkey` / `TaggedSignature` abstraction.

use ace_model::account::AccountId;
use ace_runtime::crypto::sig_algo::{verify_signature, TaggedPubkey, TaggedSignature};
use sha2::{Digest, Sha256};

use crate::intent::{ChainId, VmAddress};
use crate::zk::fr_from_fixed_be_bytes;

/// Deployment-domain tag mixed into every replay-sensitive authorization.
///
/// The paper models this as a deployment-specific value.  This crate keeps a
/// single constant for now; callers that need multi-deployment isolation
/// should thread an explicit domain through a thin wrapper or runtime config.
///
/// # Migration note (v1)
///
/// Domain tags changed from `email-pay-*` / `hfi-pay-*` to `hfipay:*` in
/// this version.  Any pre-existing intents whose refund authorization was
/// signed under the old tag will fail verification.  Testnet state should be
/// wiped on upgrade; mainnet deployments MUST NOT carry forward intents
/// created before this tag change.
const DEPLOYMENT_DOMAIN: &[u8] = b"ace-hfi-pay:v1";

fn update_asset_binding(hasher: &mut Sha256, mint: Option<&[u8; 32]>) {
    match mint {
        Some(mint) => {
            hasher.update([1u8]);
            hasher.update(mint);
        }
        None => hasher.update([0u8]),
    }
}

// ── Claim ──

/// Compute the claim authorization message hash.
///
/// `SHA-256("hfipay:claim" || deployment || chain_tag || asset || binding_epoch_le || intent_id || blinded_binding || amount_le || destination_auth_bytes || expiry_le || nonce_le)`
pub fn claim_message(
    chain: ChainId,
    mint: Option<&[u8; 32]>,
    binding_epoch: u64,
    intent_id: &[u8; 32],
    blinded_binding: &[u8; 32],
    amount: u64,
    destination: &VmAddress,
    expiry: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hfipay:claim");
    hasher.update(DEPLOYMENT_DOMAIN);
    hasher.update([chain.tag()]);
    update_asset_binding(&mut hasher, mint);
    hasher.update(binding_epoch.to_le_bytes());
    hasher.update(intent_id);
    hasher.update(blinded_binding);
    hasher.update(amount.to_le_bytes());
    hasher.update(destination.to_auth_bytes());
    hasher.update(expiry.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    into_array(hasher)
}

/// Verify a claim authorization signature.
pub fn verify_claim_auth(
    chain: ChainId,
    mint: Option<&[u8; 32]>,
    binding_epoch: u64,
    intent_id: &[u8; 32],
    blinded_binding: &[u8; 32],
    amount: u64,
    destination: &VmAddress,
    expiry: u64,
    nonce: u64,
    pubkey: &TaggedPubkey,
    signature: &TaggedSignature,
) -> bool {
    let msg = claim_message(
        chain,
        mint,
        binding_epoch,
        intent_id,
        blinded_binding,
        amount,
        destination,
        expiry,
        nonce,
    );
    verify_signature(pubkey, &msg, signature)
}

// ── Withdraw ──

/// Compute the withdraw authorization message hash.
///
/// `SHA-256("hfipay:withdraw" || deployment || chain_tag || asset || deposit || dest || amount_le || nonce_le || deadline_le)`
pub fn withdraw_message(
    chain: ChainId,
    mint: Option<&[u8; 32]>,
    deposit_address: &AccountId,
    dest: &AccountId,
    amount: u64,
    nonce: u64,
    deadline: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hfipay:withdraw");
    hasher.update(DEPLOYMENT_DOMAIN);
    hasher.update([chain.tag()]);
    update_asset_binding(&mut hasher, mint);
    hasher.update(deposit_address.as_bytes());
    hasher.update(dest.as_bytes());
    hasher.update(amount.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.update(deadline.to_le_bytes());
    into_array(hasher)
}

/// Verify a withdraw authorization signature.
pub fn verify_withdraw_auth(
    chain: ChainId,
    mint: Option<&[u8; 32]>,
    deposit_address: &AccountId,
    dest: &AccountId,
    amount: u64,
    nonce: u64,
    deadline: u64,
    pubkey: &TaggedPubkey,
    signature: &TaggedSignature,
) -> bool {
    let msg = withdraw_message(chain, mint, deposit_address, dest, amount, nonce, deadline);
    verify_signature(pubkey, &msg, signature)
}

// ── Refund ──

/// Compute the refund authorization message hash.
///
/// `SHA-256("hfipay:refund" || deployment || chain_tag || asset || intent_id || blinded_binding || amount_le || refund_authorizer || refund_dest || expiry_le || nonce_le)`
pub fn refund_message(
    chain: ChainId,
    mint: Option<&[u8; 32]>,
    intent_id: &[u8; 32],
    blinded_binding: &[u8; 32],
    amount: u64,
    refund_authorizer: &AccountId,
    refund_dest: &AccountId,
    expiry: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hfipay:refund");
    hasher.update(DEPLOYMENT_DOMAIN);
    hasher.update([chain.tag()]);
    update_asset_binding(&mut hasher, mint);
    hasher.update(intent_id);
    hasher.update(blinded_binding);
    hasher.update(amount.to_le_bytes());
    hasher.update(refund_authorizer.as_bytes());
    hasher.update(refund_dest.as_bytes());
    hasher.update(expiry.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    into_array(hasher)
}

/// Verify a refund authorization signature.
pub fn verify_refund_auth(
    chain: ChainId,
    mint: Option<&[u8; 32]>,
    intent_id: &[u8; 32],
    blinded_binding: &[u8; 32],
    amount: u64,
    refund_authorizer: &AccountId,
    refund_dest: &AccountId,
    expiry: u64,
    nonce: u64,
    pubkey: &TaggedPubkey,
    signature: &TaggedSignature,
) -> bool {
    let msg = refund_message(
        chain,
        mint,
        intent_id,
        blinded_binding,
        amount,
        refund_authorizer,
        refund_dest,
        expiry,
        nonce,
    );
    verify_signature(pubkey, &msg, signature)
}

// ── Cross-VM Claim ──

/// Compute the cross-VM claim authorization message hash.
///
/// `SHA-256("hfipay:cross-claim" || deployment || source_chain_tag || asset || binding_epoch_le || intent_id || blinded_binding || amount_le || dest_chain_tag || dest_address || expiry_le || nonce_le)`
pub fn cross_claim_message(
    source_chain: ChainId,
    mint: Option<&[u8; 32]>,
    binding_epoch: u64,
    intent_id: &[u8; 32],
    blinded_binding: &[u8; 32],
    amount: u64,
    dest: &VmAddress,
    expiry: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hfipay:cross-claim");
    hasher.update(DEPLOYMENT_DOMAIN);
    hasher.update([source_chain.tag()]);
    update_asset_binding(&mut hasher, mint);
    hasher.update(binding_epoch.to_le_bytes());
    hasher.update(intent_id);
    hasher.update(blinded_binding);
    hasher.update(amount.to_le_bytes());
    hasher.update([dest.chain().tag()]);
    hasher.update(dest.to_auth_bytes());
    hasher.update(expiry.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    into_array(hasher)
}

/// Verify a cross-VM claim authorization signature.
pub fn verify_cross_claim_auth(
    source_chain: ChainId,
    mint: Option<&[u8; 32]>,
    binding_epoch: u64,
    intent_id: &[u8; 32],
    blinded_binding: &[u8; 32],
    amount: u64,
    dest: &VmAddress,
    expiry: u64,
    nonce: u64,
    pubkey: &TaggedPubkey,
    signature: &TaggedSignature,
) -> bool {
    let msg = cross_claim_message(
        source_chain,
        mint,
        binding_epoch,
        intent_id,
        blinded_binding,
        amount,
        dest,
        expiry,
        nonce,
    );
    verify_signature(pubkey, &msg, signature)
}

// ── ZK-ACE Claim Proof ──

/// Public inputs for a ZK-ACE claim proof.
///
/// The prover demonstrates in zero knowledge that:
/// 1. `identity_commitment` is a valid commitment for the prover's identity root;
/// 2. `u_B = H(Derive(REV_B, Ctx_bind))` for that root;
/// 3. `blinded_binding = H("hfipay:bind" || u_B || intent_id)`;
/// 4. the identity underlying `identity_commitment` authorizes the claim message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClaimProofPublicInputs {
    pub identity_commitment: [u8; 32],
    pub claim_message_digest: [u8; 32],
    pub auth_commitment: [u8; 32],
    pub chain: ChainId,
    pub mint: Option<[u8; 32]>,
    #[serde(default)]
    pub binding_epoch: u64,
    pub blinded_binding: [u8; 32],
    pub intent_id: [u8; 32],
    pub amount: u64,
    pub destination: VmAddress,
    pub expiry: u64,
    pub nonce: u64,
}

/// An opaque ZK-ACE claim proof blob.
///
/// The verification circuit is defined in the `zk-ace` crate.  This type
/// carries the serialized proof bytes and the public inputs so that the
/// on-chain executor can verify the claim without learning the recipient's
/// human-friendly identifier or private identity root.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClaimProof {
    pub public_inputs: ClaimProofPublicInputs,
    /// Serialized proof bytes (circuit-specific).
    pub proof_bytes: Vec<u8>,
}

/// Verify a ZK-ACE claim proof.
///
/// This is a placeholder that checks structural validity.  Full circuit
/// verification requires the `zk-ace` verifier which is instantiated at
/// the node level.  The executor calls this to validate public-input
/// consistency; the actual cryptographic verification is delegated to the
/// proof system configured for the chain.
pub fn verify_claim_proof_inputs(
    chain: ChainId,
    mint: Option<&[u8; 32]>,
    binding_epoch: u64,
    intent_amount: u64,
    intent_expiry: u64,
    claim_nonce: u64,
    intent_id: &[u8; 32],
    intent_blinded_binding: &[u8; 32],
    expected_destination: &VmAddress,
    proof: &ClaimProof,
) -> bool {
    // Defense-in-depth: verify the proof's destination matches the caller's
    // expectation independently of the digest check.  Even if the digest is
    // correct, a mismatched destination would route funds to a wrong address.
    if proof.public_inputs.destination != *expected_destination {
        return false;
    }
    // Public-input consistency: the proof's blinded binding must match the
    // on-chain intent's committed value.
    fr_from_fixed_be_bytes(&proof.public_inputs.claim_message_digest)
        == fr_from_fixed_be_bytes(&claim_message(
            chain,
            mint,
            binding_epoch,
            intent_id,
            intent_blinded_binding,
            intent_amount,
            &proof.public_inputs.destination,
            intent_expiry,
            claim_nonce,
        ))
        && fr_from_fixed_be_bytes(&proof.public_inputs.blinded_binding)
            == fr_from_fixed_be_bytes(intent_blinded_binding)
        && fr_from_fixed_be_bytes(&proof.public_inputs.intent_id)
            == fr_from_fixed_be_bytes(intent_id)
        && proof.public_inputs.chain == chain
        && proof.public_inputs.mint.as_ref() == mint
        && proof.public_inputs.binding_epoch == binding_epoch
        && proof.public_inputs.amount == intent_amount
        && proof.public_inputs.expiry == intent_expiry
        && proof.public_inputs.nonce == claim_nonce
        && proof.public_inputs.identity_commitment != [0u8; 32]
        && proof.public_inputs.auth_commitment != [0u8; 32]
        && proof.public_inputs.intent_id != [0u8; 32]
}

fn into_array(hasher: Sha256) -> [u8; 32] {
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
