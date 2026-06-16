//! OmniLiquid reserve accounting for canonical oAssets.

use ace_model::state_tree::StateTree;
use serde::{Deserialize, Serialize};

use crate::canonical::{domain_slot, get_record, put_record, CanonicalAssetId};
use crate::error::BridgeError;
use crate::types::ExternalAsset;

const RESERVE_POSITION_DOMAIN: &[u8] = b"omni:reserve-position:v1:";
const CANONICAL_SUPPLY_DOMAIN: &[u8] = b"omni:canonical-supply:v1:";
const CANONICAL_RESERVE_TOTAL_DOMAIN: &[u8] = b"omni:canonical-reserve-total:v1:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservePosition {
    pub external_asset: ExternalAsset,
    pub canonical_asset: CanonicalAssetId,
    pub total_deposited: u64,
    pub total_withdrawn: u64,
    pub pending_withdrawal: u64,
    pub available: u64,
    pub last_updated_slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalSupply {
    pub canonical_asset: CanonicalAssetId,
    pub total_minted: u64,
    pub total_burned: u64,
    pub active_supply: u64,
    pub safety_buffer: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalReserveTotal {
    pub canonical_asset: CanonicalAssetId,
    pub backing_total: u64,
}

pub struct ReserveAccounting;

impl ReserveAccounting {
    pub fn init_position(
        state: &mut StateTree,
        external_asset: &ExternalAsset,
        canonical_asset: &CanonicalAssetId,
    ) -> Result<(), BridgeError> {
        if Self::get_position(state, external_asset)?.is_some() {
            return Ok(());
        }
        let position = ReservePosition {
            external_asset: external_asset.clone(),
            canonical_asset: *canonical_asset,
            total_deposited: 0,
            total_withdrawn: 0,
            pending_withdrawal: 0,
            available: 0,
            last_updated_slot: 0,
        };
        put_record(state, &reserve_slot(external_asset), &position)
    }

    pub fn init_supply(
        state: &mut StateTree,
        canonical_asset: &CanonicalAssetId,
    ) -> Result<(), BridgeError> {
        if Self::get_supply(state, canonical_asset)?.is_some() {
            return Ok(());
        }
        let supply = CanonicalSupply {
            canonical_asset: *canonical_asset,
            total_minted: 0,
            total_burned: 0,
            active_supply: 0,
            safety_buffer: 0,
        };
        put_record(state, &supply_slot(canonical_asset), &supply)?;
        let reserve = CanonicalReserveTotal {
            canonical_asset: *canonical_asset,
            backing_total: 0,
        };
        put_record(state, &reserve_total_slot(canonical_asset), &reserve)
    }

    pub fn get_position(
        state: &StateTree,
        external_asset: &ExternalAsset,
    ) -> Result<Option<ReservePosition>, BridgeError> {
        get_record(state, &reserve_slot(external_asset))
    }

    pub fn get_supply(
        state: &StateTree,
        canonical_asset: &CanonicalAssetId,
    ) -> Result<Option<CanonicalSupply>, BridgeError> {
        get_record(state, &supply_slot(canonical_asset))
    }

    pub fn record_deposit(
        state: &mut StateTree,
        external_asset: &ExternalAsset,
        canonical_asset: &CanonicalAssetId,
        amount: u64,
        slot: u64,
    ) -> Result<(), BridgeError> {
        if amount == 0 {
            return Err(BridgeError::InvalidAmount);
        }
        let mut position = Self::get_position(state, external_asset)?.unwrap_or(ReservePosition {
            external_asset: external_asset.clone(),
            canonical_asset: *canonical_asset,
            total_deposited: 0,
            total_withdrawn: 0,
            pending_withdrawal: 0,
            available: 0,
            last_updated_slot: 0,
        });
        if position.canonical_asset != *canonical_asset {
            return Err(BridgeError::MappingMismatch);
        }
        position.total_deposited = position
            .total_deposited
            .checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        position.available = position
            .available
            .checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        position.last_updated_slot = slot;
        put_record(state, &reserve_slot(external_asset), &position)?;
        Self::increase_reserve_total(state, canonical_asset, amount).map(|_| ())
    }

    pub fn reserve_withdrawal(
        state: &mut StateTree,
        external_asset: &ExternalAsset,
        canonical_asset: &CanonicalAssetId,
        amount: u64,
        slot: u64,
    ) -> Result<(), BridgeError> {
        if amount == 0 {
            return Err(BridgeError::InvalidAmount);
        }
        let mut position = Self::get_position(state, external_asset)?
            .ok_or(BridgeError::AssetNotMapped(format!("{external_asset:?}")))?;
        if position.canonical_asset != *canonical_asset {
            return Err(BridgeError::MappingMismatch);
        }
        if position.available < amount {
            return Err(BridgeError::InsufficientReserve {
                have: position.available,
                need: amount,
            });
        }
        position.available -= amount;
        position.pending_withdrawal = position
            .pending_withdrawal
            .checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        position.last_updated_slot = slot;
        put_record(state, &reserve_slot(external_asset), &position)
    }

    pub fn finalize_withdrawal(
        state: &mut StateTree,
        external_asset: &ExternalAsset,
        amount: u64,
        slot: u64,
    ) -> Result<(), BridgeError> {
        let mut position = Self::get_position(state, external_asset)?
            .ok_or(BridgeError::AssetNotMapped(format!("{external_asset:?}")))?;
        if position.pending_withdrawal < amount {
            return Err(BridgeError::InsufficientReserve {
                have: position.pending_withdrawal,
                need: amount,
            });
        }
        position.pending_withdrawal -= amount;
        position.total_withdrawn = position
            .total_withdrawn
            .checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        position.last_updated_slot = slot;
        let canonical_asset = position.canonical_asset;
        put_record(state, &reserve_slot(external_asset), &position)?;
        Self::decrease_reserve_total(state, &canonical_asset, amount).map(|_| ())
    }

    pub fn cancel_withdrawal(
        state: &mut StateTree,
        external_asset: &ExternalAsset,
        amount: u64,
        slot: u64,
    ) -> Result<(), BridgeError> {
        let mut position = Self::get_position(state, external_asset)?
            .ok_or(BridgeError::AssetNotMapped(format!("{external_asset:?}")))?;
        if position.pending_withdrawal < amount {
            return Err(BridgeError::InsufficientReserve {
                have: position.pending_withdrawal,
                need: amount,
            });
        }
        position.pending_withdrawal -= amount;
        position.available = position
            .available
            .checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        position.last_updated_slot = slot;
        put_record(state, &reserve_slot(external_asset), &position)
    }

    pub fn active_supply(
        state: &StateTree,
        canonical_asset: &CanonicalAssetId,
    ) -> Result<u64, BridgeError> {
        Ok(Self::get_supply(state, canonical_asset)?
            .map(|s| s.active_supply)
            .unwrap_or(0))
    }

    pub fn increase_supply(
        state: &mut StateTree,
        canonical_asset: &CanonicalAssetId,
        amount: u64,
    ) -> Result<(), BridgeError> {
        let mut supply = Self::get_supply(state, canonical_asset)?.unwrap_or(CanonicalSupply {
            canonical_asset: *canonical_asset,
            total_minted: 0,
            total_burned: 0,
            active_supply: 0,
            safety_buffer: 0,
        });
        supply.total_minted = supply
            .total_minted
            .checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        supply.active_supply = supply
            .active_supply
            .checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        put_record(state, &supply_slot(canonical_asset), &supply)
    }

    pub fn decrease_supply(
        state: &mut StateTree,
        canonical_asset: &CanonicalAssetId,
        amount: u64,
    ) -> Result<(), BridgeError> {
        let mut supply = Self::get_supply(state, canonical_asset)?.ok_or(
            BridgeError::CanonicalAssetNotFound(hex::encode(canonical_asset.as_bytes())),
        )?;
        if supply.active_supply < amount {
            return Err(BridgeError::InsufficientBalance {
                have: supply.active_supply,
                need: amount,
            });
        }
        supply.total_burned = supply
            .total_burned
            .checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        supply.active_supply -= amount;
        put_record(state, &supply_slot(canonical_asset), &supply)
    }

    pub fn check_invariant(
        state: &StateTree,
        canonical_asset: &CanonicalAssetId,
    ) -> Result<(), BridgeError> {
        let supply = Self::get_supply(state, canonical_asset)?.unwrap_or(CanonicalSupply {
            canonical_asset: *canonical_asset,
            total_minted: 0,
            total_burned: 0,
            active_supply: 0,
            safety_buffer: 0,
        });
        let reserve_total = Self::reserve_total(state, canonical_asset)?;
        let required = supply
            .active_supply
            .checked_add(supply.safety_buffer)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        if required > reserve_total {
            return Err(BridgeError::ReserveInvariantViolation(format!(
                "active supply {required} exceeds reserve total {reserve_total}"
            )));
        }
        Ok(())
    }

    pub fn reserve_total(
        state: &StateTree,
        canonical_asset: &CanonicalAssetId,
    ) -> Result<u64, BridgeError> {
        Ok(Self::get_reserve_total(state, canonical_asset)?
            .map(|r| r.backing_total)
            .unwrap_or(0))
    }

    pub fn get_reserve_total(
        state: &StateTree,
        canonical_asset: &CanonicalAssetId,
    ) -> Result<Option<CanonicalReserveTotal>, BridgeError> {
        get_record(state, &reserve_total_slot(canonical_asset))
    }

    fn increase_reserve_total(
        state: &mut StateTree,
        canonical_asset: &CanonicalAssetId,
        amount: u64,
    ) -> Result<u64, BridgeError> {
        let mut total =
            Self::get_reserve_total(state, canonical_asset)?.unwrap_or(CanonicalReserveTotal {
                canonical_asset: *canonical_asset,
                backing_total: 0,
            });
        total.backing_total = total
            .backing_total
            .checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        let out = total.backing_total;
        put_record(state, &reserve_total_slot(canonical_asset), &total)?;
        Ok(out)
    }

    fn decrease_reserve_total(
        state: &mut StateTree,
        canonical_asset: &CanonicalAssetId,
        amount: u64,
    ) -> Result<u64, BridgeError> {
        let mut total = Self::get_reserve_total(state, canonical_asset)?.ok_or(
            BridgeError::CanonicalAssetNotFound(hex::encode(canonical_asset.as_bytes())),
        )?;
        if total.backing_total < amount {
            return Err(BridgeError::InsufficientReserve {
                have: total.backing_total,
                need: amount,
            });
        }
        total.backing_total -= amount;
        let out = total.backing_total;
        put_record(state, &reserve_total_slot(canonical_asset), &total)?;
        Ok(out)
    }
}

fn reserve_slot(asset: &ExternalAsset) -> [u8; 32] {
    domain_slot(RESERVE_POSITION_DOMAIN, &asset.label())
}

fn supply_slot(asset: &CanonicalAssetId) -> [u8; 32] {
    domain_slot(CANONICAL_SUPPLY_DOMAIN, asset.as_bytes())
}

fn reserve_total_slot(asset: &CanonicalAssetId) -> [u8; 32] {
    domain_slot(CANONICAL_RESERVE_TOTAL_DOMAIN, asset.as_bytes())
}
