//! DeFi error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("unsupported external chain: {0}")]
    UnsupportedChain(String),

    #[error("asset not registered: {0}")]
    AssetNotRegistered(String),

    #[error("deposit already processed: {0}")]
    DepositAlreadyProcessed(String),

    #[error("risk limit exceeded: {0}")]
    RiskLimitExceeded(String),

    #[error("invalid deposit proof: {0}")]
    InvalidDepositProof(String),

    #[error("insufficient wrapped balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("withdrawal not found: {0}")]
    WithdrawalNotFound(String),

    #[error("withdrawal already completed: {0}")]
    WithdrawalAlreadyCompleted(String),

    #[error("mint error: {0}")]
    MintError(String),

    #[error("burn error: {0}")]
    BurnError(String),

    #[error("account not found: {0}")]
    AccountNotFound(String),

    #[error("invalid amount")]
    InvalidAmount,

    #[error("invalid destination address: {0}")]
    InvalidDestination(String),

    #[error("bridge authority mismatch")]
    AuthorityMismatch,

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("canonical asset already exists: {0}")]
    CanonicalAssetAlreadyExists(String),

    #[error("canonical asset not found: {0}")]
    CanonicalAssetNotFound(String),

    #[error("canonical asset inactive: {0}")]
    CanonicalAssetInactive(String),

    #[error("invalid canonical symbol: {0}")]
    InvalidCanonicalSymbol(String),

    #[error("invalid decimals: {0}")]
    InvalidDecimals(u8),

    #[error("external asset already mapped: {0}")]
    ExternalAssetAlreadyMapped(String),

    #[error("asset not mapped: {0}")]
    AssetNotMapped(String),

    #[error("external asset mapping does not match canonical asset")]
    MappingMismatch,

    #[error("mint disabled")]
    MintDisabled,

    #[error("withdraw disabled")]
    WithdrawDisabled,

    #[error("deposit paused")]
    DepositPaused,

    #[error("withdraw paused")]
    WithdrawPaused,

    #[error("limit exceeded: {0}")]
    LimitExceeded(String),

    #[error("amount too small after normalization")]
    AmountTooSmall,

    #[error("insufficient reserve: have {have}, need {need}")]
    InsufficientReserve { have: u64, need: u64 },

    #[error("reserve invariant violation: {0}")]
    ReserveInvariantViolation(String),

    #[error("arithmetic overflow")]
    ArithmeticOverflow,
}

#[derive(Debug, Error)]
pub enum SwapError {
    #[error("pool not found: {0}")]
    PoolNotFound(String),

    #[error("pool already exists: {0}")]
    PoolAlreadyExists(String),

    #[error("insufficient liquidity")]
    InsufficientLiquidity,

    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("zero amount")]
    ZeroAmount,

    #[error("slippage exceeded: expected at least {min_out}, got {actual_out}")]
    SlippageExceeded { min_out: u64, actual_out: u64 },

    #[error("invalid pool state: {0}")]
    InvalidPoolState(String),

    #[error("token runtime error: {0}")]
    TokenRuntime(String),

    #[error("identical tokens")]
    IdenticalTokens,

    #[error("amount overflow: u128 value exceeds u64::MAX")]
    AmountOverflow,
}
