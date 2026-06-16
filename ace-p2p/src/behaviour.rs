//! Custom network behaviour combining gossipsub, mDNS, and request-response.

use libp2p::gossipsub;
use libp2p::mdns;
use libp2p::request_response;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;

use crate::consensus_votes_protocol::ConsensusVotesCodec;
use crate::sync_protocol::SyncCodec;
use crate::tx_fetch_protocol::TxFetchCodec;

/// Combined network behaviour for ACE Chain.
///
/// - **Gossipsub**: Broadcast propagation for txs, blocks, votes, finality certs
/// - **mDNS**: Local peer discovery for development/testing (disabled by default)
/// - **BlockSync**: Point-to-point block sync via libp2p request-response
/// - **TxFetch**: Point-to-point transaction fetch for compact block proposals
/// - **ConsensusVotes**: Direct peer-to-peer delivery of prevotes/precommits
///
/// mDNS is wrapped in `Toggle` so it can be disabled for production deployments
/// where local network peer discovery is undesirable.
#[derive(NetworkBehaviour)]
pub struct AceBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub block_sync: request_response::Behaviour<SyncCodec>,
    pub tx_fetch: request_response::Behaviour<TxFetchCodec>,
    pub consensus_votes: request_response::Behaviour<ConsensusVotesCodec>,
}
