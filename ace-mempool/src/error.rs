//! Error types for the mempool.

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error(
        "mempool admission overloaded (queued {queued}, high watermark {high_watermark}, low watermark {low_watermark})"
    )]
    Overloaded {
        queued: usize,
        high_watermark: usize,
        low_watermark: usize,
    },

    #[error("mempool is full (max {max} transactions)")]
    PoolFull { max: usize },

    #[error("duplicate transaction: {}", hex::encode(.0))]
    DuplicateTransaction([u8; 32]),

    #[error("sender {} already has a pending transaction for nonce {nonce}", hex::encode(.sender))]
    SenderNonceConflict { sender: [u8; 32], nonce: u64 },

    #[error("stale nonce for sender {}: expected at least {expected}, got {got}", hex::encode(.sender))]
    StaleNonce {
        sender: [u8; 32],
        expected: u64,
        got: u64,
    },

    #[error(
        "future nonce too far ahead for sender {}: expected {expected}, got {got}, max gap {max_gap}",
        hex::encode(.sender)
    )]
    FutureNonceGap {
        sender: [u8; 32],
        expected: u64,
        got: u64,
        max_gap: u64,
    },

    #[error(
        "future queue full for sender {} (max {max_pending_future} future nonces)",
        hex::encode(.sender)
    )]
    FutureQueueFull {
        sender: [u8; 32],
        max_pending_future: usize,
    },

    #[error("invalid payload binding: SHA-256(payload) != obj_hash")]
    PayloadBindingMismatch,

    #[error("unknown sender account: {}", hex::encode(.0))]
    UnknownSender([u8; 32]),

    #[error("invalid attestation credential for sender: {}", hex::encode(.0))]
    InvalidCredential([u8; 32]),

    #[error("empty transaction payload")]
    EmptyPayload,

    #[error("invalid transaction format: {0}")]
    InvalidFormat(String),

    #[error("chain_id mismatch: expected {expected}, got {got}")]
    InvalidChainId { expected: u32, got: u32 },

    #[error("payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("domain.slot {tx_slot} out of range [{}..{}]", current.saturating_sub(*tolerance), current + tolerance)]
    SlotOutOfRange {
        tx_slot: u32,
        current: u64,
        tolerance: u64,
    },

    #[error("validation error: {0}")]
    ValidationError(String),
}

impl MempoolError {
    /// Short label suitable for a Prometheus metric label value.
    pub fn short_reason(&self) -> &'static str {
        match self {
            Self::Overloaded { .. } => "overloaded",
            Self::PoolFull { .. } => "pool_full",
            Self::DuplicateTransaction(_) => "duplicate",
            Self::SenderNonceConflict { .. } => "nonce_conflict",
            Self::StaleNonce { .. } => "stale_nonce",
            Self::FutureNonceGap { .. } => "future_nonce_gap",
            Self::FutureQueueFull { .. } => "future_queue_full",
            Self::PayloadBindingMismatch => "payload_mismatch",
            Self::UnknownSender(_) => "unknown_sender",
            Self::InvalidCredential(_) => "invalid_credential",
            Self::EmptyPayload => "empty_payload",
            Self::InvalidFormat(_) => "invalid_format",
            Self::InvalidChainId { .. } => "invalid_chain_id",
            Self::PayloadTooLarge { .. } => "payload_too_large",
            Self::SlotOutOfRange { .. } => "slot_out_of_range",
            Self::ValidationError(_) => "validation_error",
        }
    }
}
