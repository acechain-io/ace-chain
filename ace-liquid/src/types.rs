//! Core ACE Liquid data types.

use ace_defi::ExternalAsset;
use ace_defi::{risk_compartment_id, RiskCompartmentId, RiskCompartmentKind};
use ace_model::account::AccountId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MarketId(pub [u8; 32]);

impl MarketId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrderId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Market {
    pub market_id: MarketId,
    pub base_mint: AccountId,
    pub quote_mint: AccountId,
    pub tick_size: u64,
    pub lot_size: u64,
    pub maker_fee_bps: u16,
    pub taker_fee_bps: u16,
    pub active: bool,
}

impl Market {
    pub fn new(base_mint: AccountId, quote_mint: AccountId) -> Self {
        let market_id = derive_market_id(&base_mint, &quote_mint);
        Self {
            market_id,
            base_mint,
            quote_mint,
            tick_size: 1,
            lot_size: 1,
            maker_fee_bps: 0,
            taker_fee_bps: 0,
            active: true,
        }
    }

    pub fn from_assets(base: &ExternalAsset, quote: &ExternalAsset) -> Self {
        Self::new(
            ace_defi::wrapped_mint_id(base),
            ace_defi::wrapped_mint_id(quote),
        )
    }

    pub fn risk_compartment_id(&self) -> RiskCompartmentId {
        risk_compartment_id(RiskCompartmentKind::LiquidMarket, self.market_id.as_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    Buy,
    Sell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderType {
    Limit,
    Market,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeInForce {
    GoodTilCancelled,
    ImmediateOrCancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderStatus {
    Open,
    PartiallyFilled,
    Filled,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaceOrder {
    pub owner: AccountId,
    pub side: OrderSide,
    pub order_type: OrderType,
    pub price: u64,
    pub quantity: u64,
    pub time_in_force: TimeInForce,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    pub order_id: OrderId,
    pub market_id: MarketId,
    pub owner: AccountId,
    pub side: OrderSide,
    pub order_type: OrderType,
    pub price: u64,
    pub quantity: u64,
    pub remaining_quantity: u64,
    pub status: OrderStatus,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trade {
    pub market_id: MarketId,
    pub maker_order_id: OrderId,
    pub taker_order_id: OrderId,
    pub maker: AccountId,
    pub taker: AccountId,
    pub side: OrderSide,
    pub price: u64,
    pub quantity: u64,
    pub quote_quantity: u128,
}

pub fn derive_market_id(base_mint: &AccountId, quote_mint: &AccountId) -> MarketId {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-liquid:spot-market:v1:");
    hasher.update(base_mint.as_bytes());
    hasher.update(quote_mint.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    MarketId(out)
}
