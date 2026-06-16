//! OmniLiquid oAsset risk configuration.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::BridgeError;
use crate::types::{bridge_authority_id, ExternalAsset};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskTier {
    Tier1,
    Tier2,
    Tier3,
    Experimental,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskConfig {
    pub deposit_paused: bool,
    pub withdraw_paused: bool,
    pub max_single_deposit: u64,
    pub max_single_withdrawal: u64,
    pub daily_deposit_limit: u64,
    pub daily_withdrawal_limit: u64,
    pub finality_blocks: u64,
    pub required_relayer_quorum: u8,
}

impl RiskConfig {
    pub fn tier1_stablecoin() -> Self {
        Self {
            deposit_paused: false,
            withdraw_paused: false,
            max_single_deposit: 1_000_000_000_000_000_000,
            max_single_withdrawal: 1_000_000_000_000_000_000,
            daily_deposit_limit: u64::MAX,
            daily_withdrawal_limit: u64::MAX,
            finality_blocks: 96,
            required_relayer_quorum: 1,
        }
    }

    pub fn check_deposit(&self, amount: u64) -> Result<(), BridgeError> {
        self.check_supported_quorum()?;
        if self.deposit_paused {
            return Err(BridgeError::DepositPaused);
        }
        if amount > self.max_single_deposit {
            return Err(BridgeError::LimitExceeded(format!(
                "deposit amount {amount} exceeds single deposit limit {}",
                self.max_single_deposit
            )));
        }
        Ok(())
    }

    pub fn check_and_record_deposit(
        &self,
        state: &mut ace_model::state_tree::StateTree,
        external_asset: &ExternalAsset,
        amount: u64,
        slot: u64,
    ) -> Result<(), BridgeError> {
        self.check_deposit(amount)?;
        record_daily_limit(
            state,
            b"omni:risk-daily-deposit:v1:",
            external_asset,
            amount,
            slot,
            self.daily_deposit_limit,
        )
    }

    pub fn check_withdrawal(&self, amount: u64) -> Result<(), BridgeError> {
        self.check_supported_quorum()?;
        if self.withdraw_paused {
            return Err(BridgeError::WithdrawPaused);
        }
        if amount > self.max_single_withdrawal {
            return Err(BridgeError::LimitExceeded(format!(
                "withdrawal amount {amount} exceeds single withdrawal limit {}",
                self.max_single_withdrawal
            )));
        }
        Ok(())
    }

    pub fn check_and_record_withdrawal(
        &self,
        state: &mut ace_model::state_tree::StateTree,
        external_asset: &ExternalAsset,
        amount: u64,
        slot: u64,
    ) -> Result<(), BridgeError> {
        self.check_withdrawal(amount)?;
        record_daily_limit(
            state,
            b"omni:risk-daily-withdraw:v1:",
            external_asset,
            amount,
            slot,
            self.daily_withdrawal_limit,
        )
    }

    fn check_supported_quorum(&self) -> Result<(), BridgeError> {
        if self.required_relayer_quorum != 1 {
            return Err(BridgeError::LimitExceeded(format!(
                "required relayer quorum {} is not supported by single-signature wire format",
                self.required_relayer_quorum
            )));
        }
        Ok(())
    }
}

fn record_daily_limit(
    state: &mut ace_model::state_tree::StateTree,
    domain: &[u8],
    external_asset: &ExternalAsset,
    amount: u64,
    slot: u64,
    limit: u64,
) -> Result<(), BridgeError> {
    if limit == u64::MAX {
        return Ok(());
    }
    let slots_per_day = (86_400_000u64 / ace_runtime::config::SLOT_DURATION_MS).max(1);
    let day = slot / slots_per_day;
    let counter_slot = daily_counter_slot(domain, external_asset, day);
    let owner = bridge_authority_id();
    let current_value = state.get_storage(&owner, &counter_slot);
    let current = u64::from_le_bytes(current_value[0..8].try_into().unwrap());
    let next = current
        .checked_add(amount)
        .ok_or(BridgeError::ArithmeticOverflow)?;
    if next > limit {
        return Err(BridgeError::LimitExceeded(format!(
            "daily amount {next} exceeds limit {limit}"
        )));
    }
    let mut encoded = [0u8; 32];
    encoded[0..8].copy_from_slice(&next.to_le_bytes());
    state.set_storage(&owner, counter_slot, encoded);
    Ok(())
}

fn daily_counter_slot(domain: &[u8], external_asset: &ExternalAsset, day: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(external_asset.label());
    hasher.update(day.to_le_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
