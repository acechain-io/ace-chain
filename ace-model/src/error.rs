//! Error types for the model layer.

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("account not found: {0}")]
    AccountNotFound(String),

    #[error("storage error: {0}")]
    StorageError(String),

    #[error("invalid state root")]
    InvalidStateRoot,

    #[error("block not found at slot {0}")]
    BlockNotFound(u64),

    #[error("block not found for hash {0}")]
    BlockNotFoundByHash(String),

    #[error("duplicate block at slot {0}")]
    DuplicateBlock(u64),
}
