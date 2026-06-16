//! # ace-p2p — P2P Networking for ACE Chain
//!
//! Uses libp2p with gossipsub for message propagation.
//! Supports 5 topics: transactions, blocks, votes, finality certificates,
//! and identity takeover.
//!
//! ## Module Structure
//!
//! - [`config`]: Network configuration
//! - [`messages`]: Network message types
//! - [`service`]: libp2p swarm and gossipsub service
//! - [`peer_manager`]: Connected peer tracking
//! - [`behaviour`]: Custom network behaviour definition
//! - [`error`]: Networking error types

pub mod behaviour;
pub mod config;
pub mod consensus_votes_protocol;
pub mod error;
pub mod messages;
pub mod peer_manager;
pub mod service;
pub mod state_sync;
pub mod sync_protocol;
pub mod takeover;
pub mod tx_fetch_protocol;

pub use config::NetworkConfig;
pub use error::NetworkError;
pub use messages::{
    CompactNetworkProposal, EncryptedNetworkEnvelope, IdentityAnnouncement, NetworkMessage,
    TxFetchFailure, TxFetchRequest, TxFetchResponse,
};
pub use peer_manager::PeerSnapshot;
pub use service::{NetworkService, TxFetchCommand, TxFetchInboundRequest, TxFetchResponseCommand};
pub use takeover::{IdentityTakeoverMsg, TakeoverManager};
