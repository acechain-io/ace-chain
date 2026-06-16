//! Withdrawal (unwrap) logic.
//!
//! When a user wants to exit to an external chain, they burn their
//! wrapped tokens and create a withdrawal record.  The withdrawal
//! record is stored in the state tree so that external chain bridge
//! contracts can verify it via a Merkle inclusion proof against the
//! ACE Chain state root.

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use sha2::{Digest, Sha256};

use crate::error::BridgeError;
use crate::registry::AssetRegistry;
use crate::types::{bridge_authority_id, wrapped_mint_id, ExternalAsset, WithdrawalRecord};

/// Request a withdrawal (unwrap) of wrapped tokens to an external chain.
///
/// 1. Verify the sender has sufficient wrapped token balance
/// 2. Burn the wrapped tokens (transfer to bridge authority, effectively burn)
/// 3. Create a WithdrawalRecord
///
/// The withdrawal record can later be proven against the ACE state root
/// by the external chain's bridge contract.
pub fn request_withdrawal(
    state: &mut StateTree,
    registry: &AssetRegistry,
    sender: &AccountId,
    intent_id: [u8; 32],
    asset: &ExternalAsset,
    amount: u64,
    external_dest: Vec<u8>,
    current_slot: u64,
    next_withdrawal_id: u64,
) -> Result<WithdrawalRecord, BridgeError> {
    if amount == 0 {
        return Err(BridgeError::InvalidAmount);
    }
    validate_external_destination(asset, &external_dest)?;

    if !registry.is_registered(asset, state) {
        return Err(BridgeError::AssetNotRegistered(format!("{:?}", asset)));
    }

    let mint_id = wrapped_mint_id(asset);
    let authority = bridge_authority_id();

    // Check balance
    let balance = ace_n_vm::token_runtime::balance_of(state, mint_id.as_bytes(), sender);
    if balance < amount {
        return Err(BridgeError::InsufficientBalance {
            have: balance,
            need: amount,
        });
    }

    // Burn: transfer from sender to bridge authority (acts as burn address)
    ace_n_vm::token_runtime::transfer_between_owners(
        state,
        mint_id.as_bytes(),
        sender,
        &authority,
        amount,
    )
    .map_err(|e| BridgeError::BurnError(e))?;

    let record = WithdrawalRecord {
        withdrawal_id: next_withdrawal_id,
        intent_id,
        asset: asset.clone(),
        amount,
        sender: *sender,
        external_dest,
        requested_at: current_slot,
        completed: false,
    };

    // Store the withdrawal record hash in the sender's contract storage
    // so it can be proven via Merkle inclusion proof.
    let record_slot = withdrawal_storage_slot(next_withdrawal_id);
    let record_hash = hash_withdrawal_record(&record);
    state.set_storage(sender, record_slot, record_hash);
    crate::wire::index_withdrawal_record(state, &record)?;

    tracing::info!(
        withdrawal_id = next_withdrawal_id,
        asset = ?asset,
        amount,
        sender = hex::encode(sender.as_bytes()),
        "Withdrawal requested: wrapped tokens burned"
    );

    Ok(record)
}

/// Burn a canonical oAsset and create a withdrawal record for a target
/// external reserve asset.
#[allow(clippy::too_many_arguments)]
pub fn request_oasset_withdrawal(
    state: &mut StateTree,
    sender: &AccountId,
    intent_id: [u8; 32],
    canonical_asset: crate::canonical::CanonicalAssetId,
    amount: u64,
    target_asset: ExternalAsset,
    external_dest: Vec<u8>,
    current_slot: u64,
    next_withdrawal_id: u64,
) -> Result<WithdrawalRecord, BridgeError> {
    let snapshot = state.snapshot();
    match request_oasset_withdrawal_inner(
        state,
        sender,
        intent_id,
        canonical_asset,
        amount,
        target_asset,
        external_dest,
        current_slot,
        next_withdrawal_id,
    ) {
        Ok(record) => Ok(record),
        Err(error) => {
            state.rollback(snapshot);
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn request_oasset_withdrawal_inner(
    state: &mut StateTree,
    sender: &AccountId,
    intent_id: [u8; 32],
    canonical_asset: crate::canonical::CanonicalAssetId,
    amount: u64,
    target_asset: ExternalAsset,
    external_dest: Vec<u8>,
    current_slot: u64,
    next_withdrawal_id: u64,
) -> Result<WithdrawalRecord, BridgeError> {
    if amount == 0 {
        return Err(BridgeError::InvalidAmount);
    }
    let canonical =
        crate::canonical::CanonicalAssetRegistry::get_canonical_asset(state, &canonical_asset)?
            .ok_or_else(|| BridgeError::CanonicalAssetNotFound(hex::encode(canonical_asset.0)))?;
    if !canonical.active {
        return Err(BridgeError::CanonicalAssetInactive(canonical.symbol));
    }

    let mapping = crate::canonical::CanonicalAssetRegistry::get_mapping(state, &target_asset)?
        .ok_or_else(|| BridgeError::AssetNotMapped(format!("{target_asset:?}")))?;
    if mapping.canonical_asset != canonical_asset {
        return Err(BridgeError::MappingMismatch);
    }
    if !mapping.withdraw_enabled {
        return Err(BridgeError::WithdrawDisabled);
    }
    mapping
        .risk
        .check_and_record_withdrawal(state, &target_asset, amount, current_slot)?;
    validate_external_destination(&target_asset, &external_dest)?;

    let external_amount = crate::canonical::normalize_amount(
        amount,
        mapping.canonical_decimals,
        mapping.external_decimals,
    )?;
    let balance = ace_n_vm::token_runtime::balance_of(state, canonical.mint.as_bytes(), sender);
    if balance < amount {
        return Err(BridgeError::InsufficientBalance {
            have: balance,
            need: amount,
        });
    }

    crate::reserve::ReserveAccounting::reserve_withdrawal(
        state,
        &target_asset,
        &canonical_asset,
        amount,
        current_slot,
    )?;
    ace_n_vm::token_runtime::transfer_between_owners(
        state,
        canonical.mint.as_bytes(),
        sender,
        &bridge_authority_id(),
        amount,
    )
    .map_err(BridgeError::BurnError)?;
    crate::reserve::ReserveAccounting::decrease_supply(state, &canonical_asset, amount)?;

    let record = WithdrawalRecord {
        withdrawal_id: next_withdrawal_id,
        intent_id,
        asset: target_asset,
        amount: external_amount,
        sender: *sender,
        external_dest,
        requested_at: current_slot,
        completed: false,
    };
    crate::wire::index_withdrawal_record(state, &record)?;
    crate::reserve::ReserveAccounting::check_invariant(state, &canonical_asset)?;

    tracing::info!(
        withdrawal_id = next_withdrawal_id,
        canonical_asset = hex::encode(canonical_asset.as_bytes()),
        amount,
        external_amount,
        sender = hex::encode(sender.as_bytes()),
        "OmniLiquid withdrawal requested: burned oAsset"
    );

    Ok(record)
}

/// Compute the storage slot for a withdrawal record.
///
/// `SHA-256("ace-withdrawal-slot:" || withdrawal_id_le)`
pub fn withdrawal_storage_slot(withdrawal_id: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-withdrawal-slot:");
    hasher.update(withdrawal_id.to_le_bytes());
    let result = hasher.finalize();
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&result);
    slot
}

/// Compute the storage slot for a withdrawal completion marker.
///
/// `SHA-256("ace-withdrawal-completed:" || withdrawal_id_le)`
pub fn withdrawal_completed_slot(withdrawal_id: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-withdrawal-completed:");
    hasher.update(withdrawal_id.to_le_bytes());
    let result = hasher.finalize();
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&result);
    slot
}

/// Hash a withdrawal record for storage and proof purposes.
///
/// `SHA-256("ace-withdrawal-v1:" || id_le || intent_id || chain || amount_le || sender || dest)`
pub fn hash_withdrawal_record(record: &WithdrawalRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-withdrawal-v1:");
    hasher.update(record.withdrawal_id.to_le_bytes());
    hasher.update(record.intent_id);
    let label = record.asset.label();
    hasher.update((label.len() as u32).to_le_bytes());
    hasher.update(label);
    hasher.update(record.amount.to_le_bytes());
    hasher.update(record.sender.as_bytes());
    hasher.update((record.external_dest.len() as u32).to_le_bytes());
    hasher.update(&record.external_dest);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

fn validate_external_destination(
    asset: &ExternalAsset,
    external_dest: &[u8],
) -> Result<(), BridgeError> {
    let valid =
        match asset {
            ExternalAsset::Native(crate::types::ExternalChain::Ethereum)
            | ExternalAsset::Erc20(_) => external_dest.len() == 20,
            ExternalAsset::Native(crate::types::ExternalChain::Bsc) | ExternalAsset::Bep20(_) => {
                external_dest.len() == 20
            }
            ExternalAsset::Native(crate::types::ExternalChain::Solana)
            | ExternalAsset::SplToken(_) => external_dest.len() == 32,
            ExternalAsset::Native(crate::types::ExternalChain::Tron) | ExternalAsset::Trc20(_) => {
                external_dest.len() == 20
            }
            ExternalAsset::Native(crate::types::ExternalChain::Bitcoin) => {
                matches!(external_dest.len(), 20 | 32 | 33)
            }
        };

    if valid {
        Ok(())
    } else {
        Err(BridgeError::InvalidDestination(format!(
            "asset={asset:?}, len={}",
            external_dest.len()
        )))
    }
}
