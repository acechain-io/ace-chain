//! Error types for the RPC layer.

use ace_mempool::error::MempoolError as AdmissionError;

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    #[error("account not found: {0}")]
    AccountNotFound(String),

    #[error("block not found")]
    BlockNotFound,

    #[error("mempool error: {0}")]
    MempoolError(String),

    #[error("overloaded: {0}")]
    Overloaded(String),

    #[error("server error: {0}")]
    ServerError(String),

    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
}

impl From<RpcError> for jsonrpsee::types::ErrorObjectOwned {
    fn from(e: RpcError) -> Self {
        match e {
            RpcError::InvalidHex(_) | RpcError::InvalidParameter(_) => {
                jsonrpsee::types::ErrorObject::owned(-32602, e.to_string(), None::<()>)
            }
            RpcError::AccountNotFound(_) | RpcError::BlockNotFound => {
                jsonrpsee::types::ErrorObject::owned(-32001, e.to_string(), None::<()>)
            }
            RpcError::Overloaded(_) => {
                jsonrpsee::types::ErrorObject::owned(-32005, e.to_string(), None::<()>)
            }
            _ => jsonrpsee::types::ErrorObject::owned(-32603, e.to_string(), None::<()>),
        }
    }
}

impl RpcError {
    pub fn from_mempool_error(error: AdmissionError) -> Self {
        match error {
            AdmissionError::Overloaded { .. } | AdmissionError::PoolFull { .. } => {
                Self::Overloaded(error.to_string())
            }
            AdmissionError::StaleNonce { .. }
            | AdmissionError::FutureNonceGap { .. }
            | AdmissionError::FutureQueueFull { .. }
            | AdmissionError::SenderNonceConflict { .. }
            | AdmissionError::DuplicateTransaction(_) => Self::InvalidParameter(error.to_string()),
            _ => Self::MempoolError(error.to_string()),
        }
    }
}
