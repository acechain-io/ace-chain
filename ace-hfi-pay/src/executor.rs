//! On-chain intent execution logic.
//!
//! Operates on a `StateTree` (account balances) and an `IntentStore`
//! (intent lifecycle state).

use std::collections::BTreeMap;

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::sig_algo::{TaggedPubkey, TaggedSignature};

use crate::address::{derive_intent_address, derive_intent_evm_address, derive_intent_tvm_address};
use crate::auth;
use crate::error::HfiPayError;
use crate::intent::{ChainId, Intent, IntentStatus, VmAddress};

/// Persistent store for payment intents.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct IntentStore {
    #[serde(with = "crate::serde_hex_key::btree")]
    intents: BTreeMap<[u8; 32], Intent>,
}

impl IntentStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, intent_id: &[u8; 32]) -> Option<&Intent> {
        self.intents.get(intent_id)
    }

    pub fn get_mut(&mut self, intent_id: &[u8; 32]) -> Option<&mut Intent> {
        self.intents.get_mut(intent_id)
    }

    pub fn insert(&mut self, intent: Intent) {
        self.intents.insert(intent.intent_id, intent);
    }

    pub fn len(&self) -> usize {
        self.intents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
    }

    /// Iterate over all intents.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &Intent)> {
        self.intents.iter()
    }
}

fn ensure_account_with_auth(state: &mut StateTree, id: AccountId, auth_pubkey: &TaggedPubkey) {
    let mut account = state
        .get(&id)
        .cloned()
        .unwrap_or_else(|| Account::with_auth(id, 0, auth_pubkey.clone()));
    if account.auth_pubkey.is_zero() {
        account.auth_pubkey = auth_pubkey.clone();
    }
    state.insert(account);
}

/// How strictly `destination_auth` on the wire must match an existing account's `auth_pubkey`.
#[derive(Clone, Copy, Debug)]
pub(crate) enum DestinationAuthPolicy {
    /// Signature-based claims: signing key must match on-chain auth when the account exists.
    Strict,
    /// Groth16 proof claims: wire may carry the HFI Ed25519 claim key while the account uses
    /// another algorithm (e.g. ML-DSA); only balance credit is performed, auth is not rotated here.
    ProofClaimCredit,
}

pub(crate) fn ensure_vm_destination_account(
    state: &mut StateTree,
    dest: VmAddress,
    auth_pubkey: Option<&TaggedPubkey>,
    policy: DestinationAuthPolicy,
) -> Result<AccountId, HfiPayError> {
    let id = dest.to_account_id();
    match dest {
        VmAddress::Native(_) | VmAddress::Svm(_) | VmAddress::Bvm(_) => {
            if let Some(existing) = state.get(&id) {
                if !existing.auth_pubkey.is_zero() {
                    if matches!(policy, DestinationAuthPolicy::Strict) {
                        if let Some(pubkey) = auth_pubkey {
                            if existing.auth_pubkey != *pubkey {
                                return Err(HfiPayError::DestinationAuthConflict);
                            }
                        }
                    }
                    return Ok(id);
                }
            }

            let pubkey = auth_pubkey.ok_or(HfiPayError::MissingDestinationAuth)?;
            ensure_account_with_auth(state, id, pubkey);
        }
        VmAddress::Evm(address) => {
            let mut account = state
                .get(&id)
                .cloned()
                .unwrap_or_else(|| Account::with_evm_address(id, address));
            account.evm_address = Some(address);
            state.insert(account);
        }
        VmAddress::Tvm(address) => {
            let mut account = state
                .get(&id)
                .cloned()
                .unwrap_or_else(|| Account::with_tron_address(id, address));
            account.tron_address = Some(address);
            state.insert(account);
        }
    }
    Ok(id)
}

fn ensure_deposit_account(
    state: &mut StateTree,
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

/// Read the effective balance of a deposit account: native `balance` when
/// `mint` is `None`, or the token_runtime ledger balance otherwise.
/// Read effective balance at an intent's deposit address (native or token ledger).
pub fn deposit_balance(state: &StateTree, deposit: &AccountId, mint: Option<&[u8; 32]>) -> u64 {
    match mint {
        None => state.get(deposit).map(|a| a.balance).unwrap_or(0),
        Some(m) => ace_n_vm::token_runtime::balance_of(state, m, deposit),
    }
}

/// Transfer `amount` between two accounts: native balance when `mint` is
/// `None`, or via the token_runtime for wrapped assets.
pub(crate) fn transfer(
    state: &mut StateTree,
    mint: Option<&[u8; 32]>,
    from: &AccountId,
    to: &AccountId,
    amount: u64,
) -> Result<(), HfiPayError> {
    match mint {
        None => {
            let from_acct = state
                .get_mut(from)
                .ok_or_else(|| HfiPayError::AccountNotFound(hex::encode(from.as_bytes())))?;
            if from_acct.balance < amount {
                return Err(HfiPayError::InsufficientBalance {
                    have: from_acct.balance,
                    need: amount,
                });
            }
            from_acct.balance =
                from_acct
                    .balance
                    .checked_sub(amount)
                    .ok_or(HfiPayError::InsufficientBalance {
                        have: from_acct.balance,
                        need: amount,
                    })?;
            let to_acct = state
                .get_mut(to)
                .ok_or_else(|| HfiPayError::AccountNotFound(hex::encode(to.as_bytes())))?;
            to_acct.balance = to_acct
                .balance
                .checked_add(amount)
                .ok_or(HfiPayError::BalanceOverflow)?;
            Ok(())
        }
        Some(m) => ace_n_vm::token_runtime::transfer_between_owners(state, m, from, to, amount)
            .map(|_| ())
            .map_err(|e| HfiPayError::TokenRuntimeError(e)),
    }
}

/// Create a new intent and insert its deposit account into the state tree.
///
/// `mint` identifies the token: `None` for native balance, `Some(mint_id)`
/// for a wrapped asset managed by the token_runtime (e.g. the ACE-internal
/// mint derived from an ERC-20/TRC-20 contract address via
/// `ace_defi::types::wrapped_mint_id`).
///
/// Returns the derived deposit address.
pub fn create_intent(
    state: &mut StateTree,
    store: &mut IntentStore,
    intent_id: [u8; 32],
    blinded_binding: [u8; 32],
    amount: u64,
    chain: ChainId,
    mint: Option<[u8; 32]>,
    binding_epoch: u64,
    refund_dest: Option<AccountId>,
    refund_authorizer: Option<AccountId>,
    refund_auth: Option<(TaggedPubkey, TaggedSignature)>,
    expiry: u64,
    current_slot: u64,
) -> Result<AccountId, HfiPayError> {
    if amount == 0 {
        return Err(HfiPayError::InvalidAmount("amount must be non-zero".into()));
    }
    // M-7: Limit expiry to at most 1 year (~31_536_000 slots at 1s/slot)
    const MAX_EXPIRY_WINDOW: u64 = 31_536_000;
    if expiry > current_slot.saturating_add(MAX_EXPIRY_WINDOW) {
        return Err(HfiPayError::ExpiryTooFar);
    }
    match (&refund_dest, &refund_authorizer, &refund_auth) {
        (Some(_), Some(_), Some(_)) | (None, None, None) => {}
        (Some(_), None, _) | (None, Some(_), _) => {
            return Err(HfiPayError::MissingRefundAuthorizer)
        }
        (Some(_), Some(_), None) => return Err(HfiPayError::MissingRefundAuthorization),
        (None, _, Some(_)) => return Err(HfiPayError::NoRefundDestination),
    }
    if store.get(&intent_id).is_some() {
        return Err(HfiPayError::InvalidIntentId);
    }

    let deposit_address = derive_intent_address(chain, &intent_id);

    let intent = Intent::new(
        intent_id,
        blinded_binding,
        amount,
        chain,
        deposit_address,
        mint,
        binding_epoch,
        refund_dest,
        refund_authorizer,
        refund_auth,
        expiry,
        current_slot,
    );
    store.insert(intent);

    // Ensure the deposit account exists in the state tree.
    ensure_deposit_account(state, chain, &intent_id, deposit_address);

    Ok(deposit_address)
}

/// Record that the intent's deposit address has been funded.
///
/// The caller is responsible for actually transferring funds to the
/// deposit address (e.g. via the engine or token runtime).  This
/// function only advances the intent state machine.
pub fn mark_funded(
    state: &StateTree,
    store: &mut IntentStore,
    intent_id: &[u8; 32],
) -> Result<(), HfiPayError> {
    let intent = store
        .get(intent_id)
        .ok_or_else(|| HfiPayError::IntentNotFound(hex::encode(intent_id)))?;
    let have = deposit_balance(state, &intent.deposit_address, intent.mint.as_ref());
    if have < intent.amount {
        return Err(HfiPayError::IntentUnderfunded {
            have,
            need: intent.amount,
        });
    }
    let intent = store.get_mut(intent_id).unwrap();
    intent.transition(IntentStatus::Funded)
}

/// Fund an intent by transferring from the sender to the deposit address,
/// then mark the intent as funded.  Uses native balance when `mint` is
/// `None`, or the token_runtime for wrapped assets.
pub fn fund_intent(
    state: &mut StateTree,
    store: &mut IntentStore,
    intent_id: &[u8; 32],
    sender: &AccountId,
) -> Result<(), HfiPayError> {
    let intent = store
        .get(intent_id)
        .ok_or_else(|| HfiPayError::IntentNotFound(hex::encode(intent_id)))?;

    if intent.status != IntentStatus::Created {
        return Err(HfiPayError::InvalidTransition {
            from: intent.status.to_string(),
            to: "Funded".into(),
        });
    }

    let amount = intent.amount;
    let deposit_address = intent.deposit_address;
    let expected_refund_authorizer = intent.refund_authorizer;
    let mint = intent.mint;

    // Verify refund authorizer matches sender
    if let Some(refund_authorizer) = expected_refund_authorizer {
        if refund_authorizer != *sender {
            return Err(HfiPayError::RefundAuthorizerMismatch);
        }
        let (refund_pubkey, _) = intent
            .refund_auth
            .as_ref()
            .ok_or(HfiPayError::MissingRefundAuthorization)?;
        let sender_acct = state
            .get(sender)
            .ok_or_else(|| HfiPayError::AccountNotFound(hex::encode(sender.as_bytes())))?;
        if sender_acct.auth_pubkey.is_zero() || sender_acct.auth_pubkey != *refund_pubkey {
            return Err(HfiPayError::InvalidRefundSignature);
        }
    }

    transfer(state, mint.as_ref(), sender, &deposit_address, amount)?;

    // Advance state machine
    mark_funded(state, store, intent_id)
}

/// Claim an intent: verify the recipient's signature and bind ownership.
pub fn claim_intent(
    state: &mut StateTree,
    store: &mut IntentStore,
    intent_id: &[u8; 32],
    owner: AccountId,
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
    let have = deposit_balance(state, &intent.deposit_address, intent.mint.as_ref());
    if have < intent.amount {
        return Err(HfiPayError::IntentUnderfunded {
            have,
            need: intent.amount,
        });
    }

    // C-4: Include claim_nonce in authorization to prevent replay
    let claim_nonce = intent.claim_nonce;

    // Verify claim authorization (includes blinded binding in message)
    if !auth::verify_claim_auth(
        intent.chain,
        intent.mint.as_ref(),
        intent.binding_epoch,
        intent_id,
        &intent.blinded_binding,
        intent.amount,
        &VmAddress::Native(owner),
        intent.expiry,
        claim_nonce,
        pubkey,
        signature,
    ) {
        return Err(HfiPayError::InvalidClaimSignature);
    }

    // Bind ownership: set auth_pubkey on the deposit account so only the
    // recipient can authorize withdrawals.
    let deposit_address = intent.deposit_address;
    let deposit_acct = state
        .get_mut(&deposit_address)
        .ok_or_else(|| HfiPayError::AccountNotFound(hex::encode(deposit_address.as_bytes())))?;
    deposit_acct.auth_pubkey = pubkey.clone();

    // Materialize the claimed owner account with the claimant's key so
    // same-chain withdrawals do not strand funds in a zero-auth placeholder.
    ensure_account_with_auth(state, owner, pubkey);

    // Advance state machine
    let intent = store.get_mut(intent_id).unwrap();
    intent.owner = Some(owner);
    intent.claim_pubkey = Some(pubkey.clone());
    intent.claim_nonce = intent
        .claim_nonce
        .checked_add(1)
        .ok_or(HfiPayError::NonceOverflow)?;
    intent.transition(IntentStatus::Claimed)
}

/// Claim an intent using a ZK-ACE proof instead of a direct signature.
///
/// The proof demonstrates that the claimant controls the identity whose
/// private claim-binding handle `u_B` generated the committed blinded
/// binding `ρ`, without revealing `u_B` or the human-friendly identifier.
///
/// `verify_proof` is a caller-supplied closure that performs the actual
/// cryptographic proof verification (circuit-specific).
pub fn claim_intent_with_proof<F>(
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
    let have = deposit_balance(state, &intent.deposit_address, intent.mint.as_ref());
    if have < intent.amount {
        return Err(HfiPayError::IntentUnderfunded {
            have,
            need: intent.amount,
        });
    }

    let destination = proof.public_inputs.destination;

    // Validate public-input consistency (includes destination check)
    if !auth::verify_claim_proof_inputs(
        intent.chain,
        intent.mint.as_ref(),
        intent.binding_epoch,
        intent.amount,
        intent.expiry,
        intent.claim_nonce,
        intent_id,
        &intent.blinded_binding,
        &destination,
        proof,
    ) {
        return Err(HfiPayError::InvalidClaimProofInputs);
    }

    // Delegate cryptographic verification to the caller's proof system
    if !verify_proof(proof) {
        return Err(HfiPayError::InvalidClaimProof);
    }
    if destination.chain() != intent.chain {
        return Err(HfiPayError::CrossVmError(
            "proof-based same-chain claim requires a destination on the funded chain".into(),
        ));
    }
    let deposit_address = intent.deposit_address;
    let amount = intent.amount;
    let mint = intent.mint;

    let destination_id = ensure_vm_destination_account(
        state,
        destination,
        destination_auth_pubkey,
        DestinationAuthPolicy::ProofClaimCredit,
    )?;
    transfer(
        state,
        mint.as_ref(),
        &deposit_address,
        &destination_id,
        amount,
    )?;

    if let Some(pk) = destination_auth_pubkey {
        if let Some(deposit_acct) = state.get_mut(&deposit_address) {
            deposit_acct.auth_pubkey = pk.clone();
        }
    }

    // Advance state machine
    let intent = store.get_mut(intent_id).unwrap();
    intent.owner = Some(destination_id);
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

/// Withdraw funds from a claimed intent to the specified destination.
pub fn withdraw(
    state: &mut StateTree,
    store: &mut IntentStore,
    intent_id: &[u8; 32],
    dest: &AccountId,
    amount: u64,
    deadline: u64,
    pubkey: &TaggedPubkey,
    signature: &TaggedSignature,
    current_slot: u64,
) -> Result<(), HfiPayError> {
    let intent = store
        .get(intent_id)
        .ok_or_else(|| HfiPayError::IntentNotFound(hex::encode(intent_id)))?;

    if intent.status != IntentStatus::Claimed {
        return Err(HfiPayError::IntentNotFunded);
    }
    if current_slot > deadline {
        return Err(HfiPayError::IntentExpired);
    }
    let expected_pubkey = intent
        .claim_pubkey
        .clone()
        .ok_or(HfiPayError::MissingClaimBinding)?;
    let _owner = intent.owner.ok_or(HfiPayError::MissingClaimBinding)?;

    let deposit_address = intent.deposit_address;
    let nonce = intent.withdraw_nonce;
    let mint = intent.mint;
    let already_withdrawn = intent.withdrawn_amount;
    let deposit_acct = state
        .get(&deposit_address)
        .ok_or_else(|| HfiPayError::AccountNotFound(hex::encode(deposit_address.as_bytes())))?;
    if deposit_acct.auth_pubkey != expected_pubkey || *pubkey != expected_pubkey {
        return Err(HfiPayError::InvalidWithdrawSignature);
    }

    // Verify withdraw authorization
    if !auth::verify_withdraw_auth(
        intent.chain,
        intent.mint.as_ref(),
        &deposit_address,
        dest,
        amount,
        nonce,
        deadline,
        &expected_pubkey,
        signature,
    ) {
        return Err(HfiPayError::InvalidWithdrawSignature);
    }

    let released_after = already_withdrawn
        .checked_add(amount)
        .ok_or(HfiPayError::BalanceOverflow)?;
    if released_after > intent.amount {
        return Err(HfiPayError::InvalidAmount(
            "withdrawal exceeds quoted amount".into(),
        ));
    }

    // If the destination account has not been materialized yet, bind it to the
    // claimant's key so the withdrawn funds remain spendable.
    ensure_account_with_auth(state, *dest, &expected_pubkey);

    // Transfer funds (native or token_runtime)
    transfer(state, mint.as_ref(), &deposit_address, dest, amount)?;

    // Increment nonce
    let intent = store.get_mut(intent_id).unwrap();
    intent.withdraw_nonce = intent
        .withdraw_nonce
        .checked_add(1)
        .ok_or(HfiPayError::NonceOverflow)?;
    intent.withdrawn_amount = released_after;

    Ok(())
}

/// Expire a funded intent that has passed its expiry slot.
pub fn expire_intent(
    store: &mut IntentStore,
    intent_id: &[u8; 32],
    current_slot: u64,
) -> Result<(), HfiPayError> {
    let intent = store
        .get_mut(intent_id)
        .ok_or_else(|| HfiPayError::IntentNotFound(hex::encode(intent_id)))?;

    if intent.status != IntentStatus::Funded {
        return Err(HfiPayError::IntentNotFunded);
    }
    if current_slot <= intent.expiry {
        return Err(HfiPayError::IntentNotExpired {
            current_slot,
            expiry: intent.expiry,
        });
    }

    intent.transition(IntentStatus::Expired)
}

/// Refund an expired intent to the pre-authorized refund destination.
pub fn refund(
    state: &mut StateTree,
    store: &mut IntentStore,
    intent_id: &[u8; 32],
    current_slot: u64,
) -> Result<(), HfiPayError> {
    let intent = store
        .get(intent_id)
        .ok_or_else(|| HfiPayError::IntentNotFound(hex::encode(intent_id)))?;

    // Auto-expire if still funded and past expiry
    if intent.status == IntentStatus::Funded && current_slot > intent.expiry {
        let intent = store.get_mut(intent_id).unwrap();
        intent.transition(IntentStatus::Expired)?;
    }

    let intent = store
        .get(intent_id)
        .ok_or_else(|| HfiPayError::IntentNotFound(hex::encode(intent_id)))?;

    if intent.status != IntentStatus::Expired {
        return Err(HfiPayError::InvalidTransition {
            from: intent.status.to_string(),
            to: "Refunded".into(),
        });
    }

    let refund_dest = intent.refund_dest.ok_or(HfiPayError::NoRefundDestination)?;
    let refund_authorizer = intent
        .refund_authorizer
        .ok_or(HfiPayError::MissingRefundAuthorizer)?;
    let (refund_pubkey, refund_sig) = intent
        .refund_auth
        .clone()
        .ok_or(HfiPayError::MissingRefundAuthorization)?;

    // C-10: Include refund_nonce in authorization to prevent replay
    let refund_nonce = intent.refund_nonce;

    // Verify refund authorization (includes blinded binding in message)
    if !auth::verify_refund_auth(
        intent.chain,
        intent.mint.as_ref(),
        intent_id,
        &intent.blinded_binding,
        intent.amount,
        &refund_authorizer,
        &refund_dest,
        intent.expiry,
        refund_nonce,
        &refund_pubkey,
        &refund_sig,
    ) {
        return Err(HfiPayError::InvalidRefundSignature);
    }

    // Refund only the quoted amount. Any accidental surplus remains in the
    // deposit account for separate recovery instead of being silently swept.
    let deposit_address = intent.deposit_address;
    let mint = intent.mint;
    let remaining = deposit_balance(state, &deposit_address, mint.as_ref());

    if remaining < intent.amount {
        return Err(HfiPayError::IntentUnderfunded {
            have: remaining,
            need: intent.amount,
        });
    }

    ensure_account_with_auth(state, refund_dest, &refund_pubkey);
    transfer(
        state,
        mint.as_ref(),
        &deposit_address,
        &refund_dest,
        intent.amount,
    )?;

    let intent = store.get_mut(intent_id).unwrap();
    intent.withdrawn_amount = intent
        .withdrawn_amount
        .checked_add(intent.amount)
        .ok_or(HfiPayError::BalanceOverflow)?;
    intent.refund_nonce = intent
        .refund_nonce
        .checked_add(1)
        .ok_or(HfiPayError::NonceOverflow)?;
    intent.transition(IntentStatus::Refunded)
}

/// Direct deposit for registered recipients: create + fund + route in one step.
///
/// When the relay knows the recipient is registered (has an XID), this
/// function transfers funds directly from the sender to the recipient's
/// XID-derived AccountId, bypassing the deposit address, claim, and
/// withdraw phases entirely.
///
/// The intent is still recorded for auditability but transitions straight
/// to Claimed with the recipient's AccountId as owner.
pub fn direct_deposit(
    state: &mut StateTree,
    store: &mut IntentStore,
    intent_id: [u8; 32],
    blinded_binding: [u8; 32],
    amount: u64,
    chain: ChainId,
    mint: Option<[u8; 32]>,
    sender: &AccountId,
    recipient: &crate::registry::RegisteredRecipient,
    expiry: u64,
    current_slot: u64,
) -> Result<(), HfiPayError> {
    if amount == 0 {
        return Err(HfiPayError::InvalidAmount("amount must be non-zero".into()));
    }
    if store.get(&intent_id).is_some() {
        return Err(HfiPayError::InvalidIntentId);
    }

    let deposit_address = derive_intent_address(chain, &intent_id);

    // Record intent for auditability — deposit_address is set but never
    // actually used as an intermediate; funds go straight to recipient.
    let mut intent = Intent::new(
        intent_id,
        blinded_binding,
        amount,
        chain,
        deposit_address,
        mint,
        recipient.binding_epoch,
        None, // no refund needed — direct deposit
        None,
        None,
        expiry,
        current_slot,
    );

    // Ensure recipient account exists
    ensure_account_with_auth(state, recipient.account_id, &recipient.pubkey);

    // Transfer directly from sender to recipient
    transfer(state, mint.as_ref(), sender, &recipient.account_id, amount)?;

    // Mark as Funded then Claimed in one go
    intent.transition(IntentStatus::Funded)?;
    intent.transition(IntentStatus::Claimed)?;
    intent.owner = Some(recipient.account_id);
    intent.claim_pubkey = Some(recipient.pubkey.clone());
    intent.withdrawn_amount = amount;
    store.insert(intent);

    Ok(())
}
