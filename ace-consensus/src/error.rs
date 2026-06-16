//! Error types for the consensus layer.

#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("not the leader for slot {0}")]
    NotLeader(u64),

    #[error("no transactions available for block production")]
    NoTransactions,

    #[error("block production failed: {0}")]
    BlockProductionFailed(String),

    #[error("invalid vote: {0}")]
    InvalidVote(String),

    #[error("engine error: {0}")]
    EngineError(#[from] ace_engine::error::EngineError),

    #[error("block builder error: {0}")]
    BlockBuilderError(String),
}
