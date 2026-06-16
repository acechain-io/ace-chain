//! Cross-VM payment routing.
//!
//! When the deposit chain differs from the recipient's preferred withdrawal
//! chain, funds are routed through the n-VM unified token ledger:
//!
//! 1. Verify cross-chain claim authorization
//! 2. Transfer from intent deposit address to destination on target VM
//!
//! Within the ACE n-VM architecture this is a same-chain state transfer
//! (all VMs share the same state tree), so no external bridge is needed.

use ace_model::state_tree::StateTree;
use ace_runtime::crypto::sig_algo::{TaggedPubkey, TaggedSignature};

use crate::auth;
use crate::error::HfiPayError;
use crate::executor::{
    deposit_balance, ensure_vm_destination_account, transfer, DestinationAuthPolicy, IntentStore,
};
use crate::intent::{IntentStatus, VmAddress};
use crate::zk::fr_from_fixed_be_bytes;

/// Claim an intent with cross-VM routing: the recipient chooses a
/// destination chain different from the deposit chain.
///
/// On the ACE n-VM, all VMs share a unified `StateTree`, so cross-VM
/// transfers are direct balance moves with no bridge or wrap step.
pub fn cross_vm_claim(
    state: &mut StateTree,
    store: &mut IntentStore,
    intent_id: &[u8; 32],
    dest: VmAddress,
    pubkey: &TaggedPubkey,
    signature: &TaggedSignature,
    current_slot: u64,
) -> Result<(), HfiPayError> {
    let intent = store
        .get(intent_id)
        .ok_or_else(|| HfiPayError::IntentNotFound(hex::encode(intent_id)))?;

    if intent.status != IntentStatus::Funded {
        return Err(HfiPayError::IntentNotFunded);
    }
    if current_slot > intent.expiry {
        return Err(HfiPayError::IntentExpired);
    }
    if dest.chain() == intent.chain {
        return Err(HfiPayError::CrossVmError(
            "destination chain must differ from deposit chain".into(),
        ));
    }

    // Verify cross-chain claim authorization (distinct domain separator)
    if !auth::verify_cross_claim_auth(
        intent.chain,
        intent.mint.as_ref(),
        intent.binding_epoch,
        intent_id,
        &intent.blinded_binding,
        intent.amount,
        &dest,
        intent.expiry,
        intent.claim_nonce,
        pubkey,
        signature,
    ) {
        return Err(HfiPayError::InvalidClaimSignature);
    }

    let deposit_address = intent.deposit_address;
    let mint = intent.mint;
    let have = deposit_balance(state, &deposit_address, mint.as_ref());
    if have < intent.amount {
        return Err(HfiPayError::IntentUnderfunded {
            have,
            need: intent.amount,
        });
    }
    let amount = intent.amount;
    let dest_account_id =
        ensure_vm_destination_account(state, dest, Some(pubkey), DestinationAuthPolicy::Strict)?;

    // Transfer the quoted payment amount to the target VM destination.
    transfer(
        state,
        mint.as_ref(),
        &deposit_address,
        &dest_account_id,
        amount,
    )?;

    // Bind claim key to the deposit account.
    if let Some(deposit_acct) = state.get_mut(&deposit_address) {
        deposit_acct.auth_pubkey = pubkey.clone();
    }

    // Advance state machine
    let intent = store.get_mut(intent_id).unwrap();
    intent.owner = Some(dest_account_id);
    intent.claim_pubkey = Some(pubkey.clone());
    intent.withdrawn_amount = amount;
    intent.claim_nonce = intent
        .claim_nonce
        .checked_add(1)
        .ok_or(HfiPayError::NonceOverflow)?;
    intent.transition(IntentStatus::Claimed)
}

/// Cross-VM claim using a ZK-ACE proof instead of a direct signature.
///
/// The proof demonstrates that the claimant controls the identity whose
/// private claim-binding handle generated the committed blinded binding,
/// and the destination is on a different chain than the deposit.
pub fn cross_vm_claim_with_proof<F>(
    state: &mut StateTree,
    store: &mut IntentStore,
    intent_id: &[u8; 32],
    proof: &auth::ClaimProof,
    destination_auth_pubkey: Option<&TaggedPubkey>,
    verify_proof: F,
    current_slot: u64,
) -> Result<(), HfiPayError>
where
    F: FnOnce(&auth::ClaimProof) -> bool,
{
    let intent = store
        .get(intent_id)
        .ok_or_else(|| HfiPayError::IntentNotFound(hex::encode(intent_id)))?;

    if intent.status != IntentStatus::Funded {
        return Err(HfiPayError::IntentNotFunded);
    }
    if current_slot > intent.expiry {
        return Err(HfiPayError::IntentExpired);
    }

    let destination = proof.public_inputs.destination;
    if destination.chain() == intent.chain {
        return Err(HfiPayError::CrossVmError(
            "destination chain must differ from deposit chain for cross-VM claim".into(),
        ));
    }

    // Validate public-input consistency using the cross-claim message
    let cross_claim_digest = auth::cross_claim_message(
        intent.chain,
        intent.mint.as_ref(),
        intent.binding_epoch,
        intent_id,
        &intent.blinded_binding,
        intent.amount,
        &destination,
        intent.expiry,
        intent.claim_nonce,
    );
    if fr_from_fixed_be_bytes(&proof.public_inputs.claim_message_digest)
        != fr_from_fixed_be_bytes(&cross_claim_digest)
    {
        return Err(HfiPayError::InvalidClaimProofInputs);
    }
    if fr_from_fixed_be_bytes(&proof.public_inputs.blinded_binding)
        != fr_from_fixed_be_bytes(&intent.blinded_binding)
        || fr_from_fixed_be_bytes(&proof.public_inputs.intent_id)
            != fr_from_fixed_be_bytes(intent_id)
        || proof.public_inputs.chain != intent.chain
        || proof.public_inputs.mint.as_ref() != intent.mint.as_ref()
        || proof.public_inputs.binding_epoch != intent.binding_epoch
        || proof.public_inputs.amount != intent.amount
        || proof.public_inputs.expiry != intent.expiry
        || proof.public_inputs.nonce != intent.claim_nonce
        || proof.public_inputs.identity_commitment == [0u8; 32]
        || proof.public_inputs.auth_commitment == [0u8; 32]
    {
        return Err(HfiPayError::InvalidClaimProofInputs);
    }

    if !verify_proof(proof) {
        return Err(HfiPayError::InvalidClaimProof);
    }

    let deposit_address = intent.deposit_address;
    let mint = intent.mint;
    let have = deposit_balance(state, &deposit_address, mint.as_ref());
    if have < intent.amount {
        return Err(HfiPayError::IntentUnderfunded {
            have,
            need: intent.amount,
        });
    }
    let amount = intent.amount;
    let dest_account_id = ensure_vm_destination_account(
        state,
        destination,
        destination_auth_pubkey,
        DestinationAuthPolicy::ProofClaimCredit,
    )?;

    transfer(
        state,
        mint.as_ref(),
        &deposit_address,
        &dest_account_id,
        amount,
    )?;

    if let Some(pk) = destination_auth_pubkey {
        if let Some(deposit_acct) = state.get_mut(&deposit_address) {
            deposit_acct.auth_pubkey = pk.clone();
        }
    }

    let intent = store.get_mut(intent_id).unwrap();
    intent.owner = Some(dest_account_id);
    if let Some(pk) = destination_auth_pubkey {
        intent.claim_pubkey = Some(pk.clone());
    }
    intent.withdrawn_amount = amount;
    intent.claim_nonce = intent
        .claim_nonce
        .checked_add(1)
        .ok_or(HfiPayError::NonceOverflow)?;
    intent.transition(IntentStatus::Claimed)
}
