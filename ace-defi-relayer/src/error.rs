//! Error types for ACE DeFi Relayer

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RelayerError {
    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Ethereum error: {0}")]
    EthereumError(String),

    #[error("ACE error: {0}")]
    AceError(String),

    #[error("Finality check failed: {0}")]
    FinalityError(String),

    #[error("Deposit processing failed: {0}")]
    DepositError(String),

    #[error("Withdrawal execution failed: {0}")]
    WithdrawalError(String),

    #[error("Oracle error: {0}")]
    OracleError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type Result<T> = std::result::Result<T, RelayerError>;
