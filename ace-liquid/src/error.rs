//! ACE Liquid error types.

use thiserror::Error;

use crate::types::{MarketId, OrderId};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LiquidError {
    #[error("market not found: {0:?}")]
    MarketNotFound(MarketId),

    #[error("market already exists: {0:?}")]
    MarketAlreadyExists(MarketId),

    #[error("market is inactive: {0:?}")]
    MarketInactive(MarketId),

    #[error("invalid market config: {0}")]
    InvalidMarketConfig(String),

    #[error("order not found: {0:?}")]
    OrderNotFound(OrderId),

    #[error("order is not open: {0:?}")]
    OrderNotOpen(OrderId),

    #[error("amount must be greater than zero")]
    ZeroAmount,

    #[error("limit order price must be greater than zero")]
    ZeroPrice,

    #[error("order would cross without liquidity")]
    NoLiquidity,

    #[error("self trade is not allowed")]
    SelfTrade,

    #[error("arithmetic overflow")]
    ArithmeticOverflow,

    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("settlement failed: {0}")]
    Settlement(String),

    #[error("state serialization error: {0}")]
    Serialization(String),

    #[error("invalid payload: {0}")]
    InvalidPayload(String),

    #[error("nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: u64, got: u64 },

    #[error("not order owner")]
    NotOrderOwner,
}
