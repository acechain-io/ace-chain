//! Error types for the execution engine.

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("account not found: {}", hex::encode(.0))]
    AccountNotFound([u8; 32]),

    #[error("invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    #[error("invalid transaction payload: {0}")]
    InvalidPayload(String),

    #[error("account already exists: {}", hex::encode(.0))]
    AccountAlreadyExists([u8; 32]),

    #[error("account expired (stubbed): {}", hex::encode(.0))]
    AccountExpired([u8; 32]),

    #[error("balance overflow: crediting {amount} to account with balance {balance}")]
    BalanceOverflow { balance: u64, amount: u64 },

    #[error("nonce overflow for account {}", hex::encode(.0))]
    NonceOverflow([u8; 32]),

    #[error("invalid credential for sender {}", hex::encode(.0))]
    InvalidCredential([u8; 32]),

    #[error("address already bound to account {}", hex::encode(.0))]
    AddressAlreadyBound([u8; 32]),

    #[error("invalid address binding proof for type 0x{0:02x}")]
    InvalidBindingProof(u8),

    #[error("model error: {0}")]
    ModelError(#[from] ace_model::error::ModelError),
}
