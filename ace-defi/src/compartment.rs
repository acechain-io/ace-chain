//! Deterministic risk-compartment identifiers for shared liquidity.
//!
//! A compartment is a bounded fault domain. Liquidity can be shared through
//! canonical assets and common settlement, while risk controls remain scoped to
//! assets, mappings, markets, routes, oracle feeds, or relayer sets.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::CanonicalAssetId;
use crate::types::ExternalAsset;

const COMPARTMENT_DOMAIN: &[u8] = b"ace:risk-compartment:v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RiskCompartmentId(pub [u8; 32]);

impl RiskCompartmentId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskCompartmentKind {
    CanonicalAsset,
    ExternalAssetMapping,
    LiquidityPool,
    LiquidMarket,
    WithdrawalRoute,
    RelayerSet,
    OracleFeed,
}

impl RiskCompartmentKind {
    fn label(self) -> &'static [u8] {
        match self {
            Self::CanonicalAsset => b"canonical-asset",
            Self::ExternalAssetMapping => b"external-asset-mapping",
            Self::LiquidityPool => b"liquidity-pool",
            Self::LiquidMarket => b"liquid-market",
            Self::WithdrawalRoute => b"withdrawal-route",
            Self::RelayerSet => b"relayer-set",
            Self::OracleFeed => b"oracle-feed",
        }
    }
}

pub fn risk_compartment_id(kind: RiskCompartmentKind, key: &[u8]) -> RiskCompartmentId {
    let mut hasher = Sha256::new();
    hasher.update(COMPARTMENT_DOMAIN);
    hasher.update(kind.label());
    hasher.update((key.len() as u32).to_le_bytes());
    hasher.update(key);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    RiskCompartmentId(out)
}

pub fn canonical_asset_compartment_id(id: &CanonicalAssetId) -> RiskCompartmentId {
    risk_compartment_id(RiskCompartmentKind::CanonicalAsset, id.as_bytes())
}

pub fn external_asset_mapping_compartment_id(asset: &ExternalAsset) -> RiskCompartmentId {
    risk_compartment_id(RiskCompartmentKind::ExternalAssetMapping, &asset.label())
}

pub fn withdrawal_route_compartment_id(
    asset: &ExternalAsset,
    destination: &[u8],
) -> RiskCompartmentId {
    let mut key = asset.label();
    key.extend_from_slice(&(destination.len() as u32).to_le_bytes());
    key.extend_from_slice(destination);
    risk_compartment_id(RiskCompartmentKind::WithdrawalRoute, &key)
}
