//! Deposit verification and auto-wrap.
//!
//! When a deposit is verified on an external chain, the bridge mints
//! the corresponding wrapped token to the recipient's ACE account.
//! This is the "auto-wrap" step — from the user's perspective, they
//! deposited ETH and now have ACE-wETH, usable across all VMs.

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;

use crate::error::BridgeError;
use crate::registry::AssetRegistry;
use crate::types::{bridge_authority_id, wrapped_mint_id, DepositRecord, SignedDepositRecord};

/// Verify and process a deposit from an external chain.
///
/// In production, `deposit_proof` would be a light-client proof, SPV proof,
/// or committee attestation verifying the deposit on the external chain.
/// For now, we accept a pre-verified `DepositRecord` and perform the
/// auto-wrap (mint).
///
/// # Auto-wrap flow
///
/// 1. Verify the asset is registered
/// 2. Ensure the recipient account exists on ACE Chain
/// 3. Mint wrapped tokens to the recipient
pub fn process_deposit(
    state: &mut StateTree,
    registry: &AssetRegistry,
    deposit: &DepositRecord,
) -> Result<(), BridgeError> {
    if deposit.amount == 0 || deposit.amount > (u64::MAX / 2) {
        return Err(BridgeError::InvalidAmount);
    }

    // Verify asset is registered
    if !registry.is_registered(&deposit.asset, state) {
        return Err(BridgeError::AssetNotRegistered(format!(
            "{:?}",
            deposit.asset
        )));
    }

    let mint_id = wrapped_mint_id(&deposit.asset);
    let authority = bridge_authority_id();

    // Ensure recipient account exists
    if !state.contains(&deposit.recipient) {
        state.insert(Account::new(deposit.recipient));
    }

    // Auto-wrap: mint wrapped tokens to recipient
    ace_n_vm::token_runtime::mint_to_owner(
        state,
        mint_id.as_bytes(),
        deposit.recipient.as_bytes(),
        deposit.amount,
        &authority,
    )
    .map_err(|e| BridgeError::MintError(e))?;

    tracing::info!(
        deposit_id = hex::encode(deposit.deposit_id),
        asset = ?deposit.asset,
        amount = deposit.amount,
        recipient = hex::encode(deposit.recipient.as_bytes()),
        "Deposit processed: auto-wrapped to ACE token"
    );

    Ok(())
}

/// Verify a relayer-signed external deposit and mint the mapped OmniLiquid
/// canonical oAsset to the recipient.
pub fn process_deposit_to_oasset(
    state: &mut StateTree,
    signed: &SignedDepositRecord,
    current_slot: u64,
) -> Result<AccountId, BridgeError> {
    let snapshot = state.snapshot();
    match process_deposit_to_oasset_inner(state, signed, current_slot) {
        Ok(mint) => Ok(mint),
        Err(error) => {
            state.rollback(snapshot);
            Err(error)
        }
    }
}

fn process_deposit_to_oasset_inner(
    state: &mut StateTree,
    signed: &SignedDepositRecord,
    current_slot: u64,
) -> Result<AccountId, BridgeError> {
    crate::wire::verify_signed_deposit_against_state(state, signed)?;
    let deposit = &signed.deposit;
    if deposit.amount == 0 {
        return Err(BridgeError::InvalidAmount);
    }

    let bridge_account = bridge_authority_id();
    let processed = state.get_storage(&bridge_account, &deposit.deposit_id);
    if processed[0] == 0x01 {
        return Err(BridgeError::DepositAlreadyProcessed(hex::encode(
            deposit.deposit_id,
        )));
    }

    let mapping = crate::canonical::CanonicalAssetRegistry::get_mapping(state, &deposit.asset)?
        .ok_or_else(|| BridgeError::AssetNotMapped(format!("{:?}", deposit.asset)))?;
    if !mapping.mint_enabled {
        return Err(BridgeError::MintDisabled);
    }
    mapping
        .risk
        .check_and_record_deposit(state, &deposit.asset, deposit.amount, current_slot)?;

    let canonical = crate::canonical::CanonicalAssetRegistry::get_canonical_asset(
        state,
        &mapping.canonical_asset,
    )?
    .ok_or_else(|| BridgeError::CanonicalAssetNotFound(hex::encode(mapping.canonical_asset.0)))?;
    if !canonical.active {
        return Err(BridgeError::CanonicalAssetInactive(canonical.symbol));
    }

    let amount = crate::canonical::normalize_amount(
        deposit.amount,
        mapping.external_decimals,
        mapping.canonical_decimals,
    )?;
    crate::reserve::ReserveAccounting::record_deposit(
        state,
        &deposit.asset,
        &mapping.canonical_asset,
        amount,
        current_slot,
    )?;
    ace_n_vm::token_runtime::mint_to_owner(
        state,
        canonical.mint.as_bytes(),
        deposit.recipient.as_bytes(),
        amount,
        &bridge_authority_id(),
    )
    .map_err(BridgeError::MintError)?;
    crate::reserve::ReserveAccounting::increase_supply(state, &mapping.canonical_asset, amount)?;

    let mut marker = [0u8; 32];
    marker[0] = 0x01;
    state.set_storage(&bridge_account, deposit.deposit_id, marker);
    crate::reserve::ReserveAccounting::check_invariant(state, &mapping.canonical_asset)?;

    tracing::info!(
        deposit_id = hex::encode(deposit.deposit_id),
        asset = ?deposit.asset,
        canonical_asset = hex::encode(mapping.canonical_asset.as_bytes()),
        amount,
        recipient = hex::encode(deposit.recipient.as_bytes()),
        "OmniLiquid deposit processed: minted oAsset"
    );

    Ok(canonical.mint)
}

/// Compute the recipient's ACE AccountId from their external chain address.
///
/// XID-first: if the address is already aliased to an XID account in the
/// state tree, return that account. Otherwise fall back to legacy idcom.
pub fn recipient_from_evm_address(state: &StateTree, evm_addr: &[u8; 20]) -> AccountId {
    if let Some(id) = state.resolve_evm(evm_addr) {
        return *id;
    }
    AccountId::from_bytes(ace_runtime::crypto::legacy_idcom_evm(evm_addr))
}

pub fn recipient_from_solana_pubkey(state: &StateTree, pubkey: &[u8; 32]) -> AccountId {
    if let Some(id) = state.resolve_solana(pubkey) {
        return *id;
    }
    AccountId::from_bytes(ace_runtime::crypto::legacy_idcom_solana(pubkey))
}

pub fn recipient_from_btc_pubkey(state: &StateTree, compressed_pubkey: &[u8; 33]) -> AccountId {
    if let Some(id) = state.resolve_btc(compressed_pubkey) {
        return *id;
    }
    AccountId::from_bytes(ace_runtime::crypto::legacy_idcom_btc(compressed_pubkey))
}

pub fn recipient_from_tron_address(state: &StateTree, tron_addr: &[u8; 20]) -> AccountId {
    if let Some(id) = state.resolve_tron(tron_addr) {
        return *id;
    }
    AccountId::from_bytes(ace_runtime::crypto::legacy_idcom_tron(tron_addr))
}
