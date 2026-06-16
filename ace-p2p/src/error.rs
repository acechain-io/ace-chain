//! Error types for the P2P networking layer.

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("transport error: {0}")]
    Transport(String),

    #[error("gossipsub publish error: {0}")]
    Publish(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid topic: {0}")]
    InvalidTopic(String),

    #[error("channel closed")]
    ChannelClosed,

    #[error("swarm error: {0}")]
    Swarm(String),
}
