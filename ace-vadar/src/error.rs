//! Error types for VA-DAR registry operations.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VadarError {
    #[error("discovery ID already registered")]
    AlreadyRegistered,

    #[error("discovery ID not found: {0}")]
    NotFound(String),

    #[error("record has been tombstoned")]
    Tombstoned,

    #[error("invalid owner signature")]
    InvalidSignature,

    #[error("version must be strictly greater than current (have {current}, got {proposed})")]
    VersionNotMonotonic { current: u64, proposed: u64 },

    #[error("commitment mismatch: expected {expected}, got {actual}")]
    CommitmentMismatch { expected: String, actual: String },

    #[error("sealed artifact too large ({size} bytes, max {max})")]
    ArtifactTooLarge { size: usize, max: usize },

    #[error("not authorized: signer does not match owner")]
    NotAuthorized,
}
