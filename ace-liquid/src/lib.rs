//! ACE Liquid: order-book trading primitives built on top of ACE DeFi.
//!
//! This crate intentionally starts with the deterministic trading core. Chain
//! execution, RPC, margin, perps, and liquidation should sit on top of these
//! primitives rather than being mixed into the core matching logic.

pub mod clob;
pub mod critbit;
pub mod error;
pub mod state;
pub mod types;
pub mod wire;

pub use clob::SpotClob;
pub use error::LiquidError;
pub use state::{ace_liquid_authority_id, market_book_id, ASSET_BASE, ASSET_QUOTE};
pub use types::{
    Market, MarketId, Order, OrderId, OrderSide, OrderStatus, OrderType, PlaceOrder, TimeInForce,
    Trade,
};
pub use wire::{
    build_cancel_order_payload, build_create_market_payload, build_deposit_payload,
    build_place_order_payload, build_withdraw_payload, execute_liquid_tx, is_liquid_payload,
    LiquidOutcome, MARKET_ID_OFFSET, OP_LIQUID, SUB_CANCEL_ORDER, SUB_CREATE_MARKET, SUB_DEPOSIT,
    SUB_PLACE_ORDER, SUB_WITHDRAW,
};
