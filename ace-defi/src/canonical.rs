//! OmniLiquid canonical oAsset registry.

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::TaggedPubkey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::compartment::{
    canonical_asset_compartment_id, external_asset_mapping_compartment_id, RiskCompartmentId,
};
use crate::error::BridgeError;
use crate::risk::{RiskConfig, RiskTier};
use crate::types::{bridge_authority_id, wrapped_mint_id, ExternalAsset};

const CANONICAL_ASSET_DOMAIN: &[u8] = b"omni:canonical-asset:v1:";
const EXTERNAL_MAPPING_DOMAIN: &[u8] = b"omni:external-mapping:v1:";
const OASSET_MINT_DOMAIN: &[u8] = b"omni-oasset-mint:v1:";
const CANONICAL_ID_DOMAIN: &[u8] = b"omni-canonical-asset:v1:";
const RECORD_CHUNKS_DOMAIN: &[u8] = b"omni:record-chunks:v1:";
const RECORD_LEN_DOMAIN: &[u8] = b"omni:record-len:v1:";
const RECORD_CHUNK_DOMAIN: &[u8] = b"omni:record-chunk:v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanonicalAssetId(pub [u8; 32]);

impl CanonicalAssetId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn risk_compartment_id(&self) -> RiskCompartmentId {
        canonical_asset_compartment_id(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalAsset {
    pub id: CanonicalAssetId,
    pub symbol: String,
    pub decimals: u8,
    pub mint: AccountId,
    pub active: bool,
    pub risk_tier: RiskTier,
}

impl CanonicalAsset {
    pub fn risk_compartment_id(&self) -> RiskCompartmentId {
        self.id.risk_compartment_id()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAssetMapping {
    pub external_asset: ExternalAsset,
    pub reserve_mint: AccountId,
    pub canonical_asset: CanonicalAssetId,
    pub external_decimals: u8,
    pub canonical_decimals: u8,
    pub mint_enabled: bool,
    pub withdraw_enabled: bool,
    pub risk: RiskConfig,
}

impl ExternalAssetMapping {
    pub fn risk_compartment_id(&self) -> RiskCompartmentId {
        external_asset_mapping_compartment_id(&self.external_asset)
    }
}

pub struct CanonicalAssetRegistry;

impl CanonicalAssetRegistry {
    pub fn register_canonical_asset(
        state: &mut StateTree,
        symbol: &str,
        decimals: u8,
        risk_tier: RiskTier,
    ) -> Result<CanonicalAsset, BridgeError> {
        validate_symbol(symbol)?;
        validate_decimals(decimals)?;

        let id = canonical_asset_id(symbol, decimals)?;
        if Self::get_canonical_asset(state, &id)?.is_some() {
            return Err(BridgeError::CanonicalAssetAlreadyExists(symbol.to_string()));
        }

        let mint = oasset_mint_id(&id);
        ensure_bridge_authority(state);
        ace_n_vm::token_runtime::create_mint(
            state,
            mint.as_bytes(),
            decimals,
            bridge_authority_id().as_bytes(),
        )
        .map_err(BridgeError::MintError)?;

        let asset = CanonicalAsset {
            id,
            symbol: symbol.to_string(),
            decimals,
            mint,
            active: true,
            risk_tier,
        };
        put_record(state, &canonical_slot(&id), &asset)?;
        crate::reserve::ReserveAccounting::init_supply(state, &id)?;
        Ok(asset)
    }

    pub fn get_canonical_asset(
        state: &StateTree,
        id: &CanonicalAssetId,
    ) -> Result<Option<CanonicalAsset>, BridgeError> {
        get_record(state, &canonical_slot(id))
    }

    pub fn set_canonical_asset_active(
        state: &mut StateTree,
        id: &CanonicalAssetId,
        active: bool,
    ) -> Result<(), BridgeError> {
        let mut asset = Self::get_canonical_asset(state, id)?.ok_or(
            BridgeError::CanonicalAssetNotFound(hex::encode(id.as_bytes())),
        )?;
        asset.active = active;
        put_record(state, &canonical_slot(id), &asset)
    }

    pub fn map_external_asset(
        state: &mut StateTree,
        external_asset: ExternalAsset,
        canonical_asset: CanonicalAssetId,
        external_decimals: u8,
        risk: RiskConfig,
    ) -> Result<ExternalAssetMapping, BridgeError> {
        validate_decimals(external_decimals)?;
        let canonical = Self::get_canonical_asset(state, &canonical_asset)?.ok_or(
            BridgeError::CanonicalAssetNotFound(hex::encode(canonical_asset.as_bytes())),
        )?;
        if !canonical.active {
            return Err(BridgeError::CanonicalAssetInactive(canonical.symbol));
        }
        if Self::get_mapping(state, &external_asset)?.is_some() {
            return Err(BridgeError::ExternalAssetAlreadyMapped(format!(
                "{external_asset:?}"
            )));
        }

        let reserve_mint = wrapped_mint_id(&external_asset);
        if ace_n_vm::token_runtime::get_mint_meta(state, reserve_mint.as_bytes()).is_none() {
            ensure_bridge_authority(state);
            ace_n_vm::token_runtime::create_mint(
                state,
                reserve_mint.as_bytes(),
                external_decimals,
                bridge_authority_id().as_bytes(),
            )
            .map_err(BridgeError::MintError)?;
        }

        let mapping = ExternalAssetMapping {
            external_asset: external_asset.clone(),
            reserve_mint,
            canonical_asset,
            external_decimals,
            canonical_decimals: canonical.decimals,
            mint_enabled: true,
            withdraw_enabled: true,
            risk,
        };
        put_record(state, &mapping_slot(&external_asset), &mapping)?;
        crate::reserve::ReserveAccounting::init_position(state, &external_asset, &canonical_asset)?;
        Ok(mapping)
    }

    pub fn get_mapping(
        state: &StateTree,
        external_asset: &ExternalAsset,
    ) -> Result<Option<ExternalAssetMapping>, BridgeError> {
        get_record(state, &mapping_slot(external_asset))
    }

    pub fn set_mapping_mint_enabled(
        state: &mut StateTree,
        external_asset: &ExternalAsset,
        enabled: bool,
    ) -> Result<(), BridgeError> {
        let mut mapping = Self::get_mapping(state, external_asset)?
            .ok_or(BridgeError::AssetNotMapped(format!("{external_asset:?}")))?;
        mapping.mint_enabled = enabled;
        put_record(state, &mapping_slot(external_asset), &mapping)
    }

    pub fn set_mapping_withdraw_enabled(
        state: &mut StateTree,
        external_asset: &ExternalAsset,
        enabled: bool,
    ) -> Result<(), BridgeError> {
        let mut mapping = Self::get_mapping(state, external_asset)?
            .ok_or(BridgeError::AssetNotMapped(format!("{external_asset:?}")))?;
        mapping.withdraw_enabled = enabled;
        put_record(state, &mapping_slot(external_asset), &mapping)
    }
}

pub fn canonical_asset_id(symbol: &str, decimals: u8) -> Result<CanonicalAssetId, BridgeError> {
    validate_symbol(symbol)?;
    validate_decimals(decimals)?;
    let mut hasher = Sha256::new();
    hasher.update(CANONICAL_ID_DOMAIN);
    hasher.update((symbol.len() as u16).to_le_bytes());
    hasher.update(symbol.as_bytes());
    hasher.update([decimals]);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(CanonicalAssetId(out))
}

pub fn oasset_mint_id(id: &CanonicalAssetId) -> AccountId {
    let mut hasher = Sha256::new();
    hasher.update(OASSET_MINT_DOMAIN);
    hasher.update(id.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    AccountId::from_bytes(out)
}

pub fn normalize_amount(
    amount: u64,
    from_decimals: u8,
    to_decimals: u8,
) -> Result<u64, BridgeError> {
    validate_decimals(from_decimals)?;
    validate_decimals(to_decimals)?;
    if amount == 0 {
        return Err(BridgeError::InvalidAmount);
    }
    if from_decimals == to_decimals {
        return Ok(amount);
    }
    if from_decimals < to_decimals {
        let scale = 10u64
            .checked_pow((to_decimals - from_decimals) as u32)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        amount
            .checked_mul(scale)
            .ok_or(BridgeError::ArithmeticOverflow)
    } else {
        let scale = 10u64
            .checked_pow((from_decimals - to_decimals) as u32)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        let normalized = amount / scale;
        if normalized == 0 {
            return Err(BridgeError::AmountTooSmall);
        }
        Ok(normalized)
    }
}

pub(crate) fn put_record<T: Serialize>(
    state: &mut StateTree,
    key: &[u8; 32],
    value: &T,
) -> Result<(), BridgeError> {
    let bytes = bincode::serialize(value).map_err(|e| BridgeError::Serialization(e.to_string()))?;
    let owner = bridge_authority_id();
    let chunks = bytes.len().div_ceil(32) as u64;
    write_u64(state, &record_slot(RECORD_CHUNKS_DOMAIN, key, 0), chunks);
    write_u64(
        state,
        &record_slot(RECORD_LEN_DOMAIN, key, 0),
        bytes.len() as u64,
    );
    for (idx, chunk) in bytes.chunks(32).enumerate() {
        let mut slot_value = [0u8; 32];
        slot_value[..chunk.len()].copy_from_slice(chunk);
        state.set_storage(
            &owner,
            record_slot(RECORD_CHUNK_DOMAIN, key, idx as u64),
            slot_value,
        );
    }
    Ok(())
}

pub(crate) fn get_record<T: for<'de> Deserialize<'de>>(
    state: &StateTree,
    key: &[u8; 32],
) -> Result<Option<T>, BridgeError> {
    let chunks = read_u64(state, &record_slot(RECORD_CHUNKS_DOMAIN, key, 0));
    if chunks == 0 {
        return Ok(None);
    }
    let byte_len = read_u64(state, &record_slot(RECORD_LEN_DOMAIN, key, 0));
    let mut bytes = Vec::with_capacity(chunks as usize * 32);
    let owner = bridge_authority_id();
    for idx in 0..chunks {
        bytes.extend_from_slice(
            &state.get_storage(&owner, &record_slot(RECORD_CHUNK_DOMAIN, key, idx)),
        );
    }
    let byte_len = usize::try_from(byte_len)
        .map_err(|_| BridgeError::Serialization("record byte length overflow".into()))?;
    if byte_len > bytes.len() {
        return Err(BridgeError::Serialization(
            "record byte length exceeds stored chunks".into(),
        ));
    }
    bytes.truncate(byte_len);
    bincode::deserialize(&bytes)
        .map(Some)
        .map_err(|e| BridgeError::Serialization(e.to_string()))
}

pub(crate) fn domain_slot(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data);
    let result = hasher.finalize();
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&result);
    slot
}

fn canonical_slot(id: &CanonicalAssetId) -> [u8; 32] {
    domain_slot(CANONICAL_ASSET_DOMAIN, id.as_bytes())
}

fn mapping_slot(asset: &ExternalAsset) -> [u8; 32] {
    domain_slot(EXTERNAL_MAPPING_DOMAIN, &asset.label())
}

fn record_slot(domain: &[u8], key: &[u8; 32], idx: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(key);
    data.extend_from_slice(&idx.to_le_bytes());
    domain_slot(domain, &data)
}

fn read_u64(state: &StateTree, slot: &[u8; 32]) -> u64 {
    let value = state.get_storage(&bridge_authority_id(), slot);
    u64::from_le_bytes(value[0..8].try_into().unwrap())
}

fn write_u64(state: &mut StateTree, slot: &[u8; 32], value: u64) {
    let mut encoded = [0u8; 32];
    encoded[0..8].copy_from_slice(&value.to_le_bytes());
    state.set_storage(&bridge_authority_id(), *slot, encoded);
}

fn ensure_bridge_authority(state: &mut StateTree) {
    let authority = bridge_authority_id();
    if !state.contains(&authority) {
        let mut account = Account::new(authority);
        account.auth_pubkey = TaggedPubkey::ed25519([0u8; 32]);
        state.insert(account);
    }
}

fn validate_symbol(symbol: &str) -> Result<(), BridgeError> {
    if symbol.is_empty() || symbol.len() > 16 {
        return Err(BridgeError::InvalidCanonicalSymbol(symbol.to_string()));
    }
    if !symbol.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(BridgeError::InvalidCanonicalSymbol(symbol.to_string()));
    }
    Ok(())
}

fn validate_decimals(decimals: u8) -> Result<(), BridgeError> {
    if decimals > 18 {
        return Err(BridgeError::InvalidDecimals(decimals));
    }
    Ok(())
}
