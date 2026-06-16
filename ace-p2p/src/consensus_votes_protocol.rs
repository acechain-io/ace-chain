//! Point-to-point consensus message delivery protocol.
//!
//! All consensus messages (proposals, prevotes, precommits, commit
//! certificates) are sent directly to all connected peers via libp2p
//! request-response, bypassing gossipsub entirely.  This eliminates
//! gossipsub mesh relay delays and yamux head-of-line blocking that
//! cause consensus stalls under high transaction load.

use async_trait::async_trait;
use libp2p::request_response;
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};
use std::io;

use crate::messages::{
    CommitCertificate, CompactNetworkProposal, NetworkPrecommit, NetworkPrevote, NetworkProposal,
};

/// Protocol identifier for direct consensus message delivery.
pub const CONSENSUS_VOTES_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/ace/consensus-votes/1.0.0");

/// Maximum consensus message size (512 KiB — compact proposals can be large).
const MAX_CONSENSUS_MSG_BYTES: usize = 512 * 1024;

/// A consensus message sent directly to a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DirectVote {
    Prevote(NetworkPrevote),
    Precommit(NetworkPrecommit),
    CommitCertificate(CommitCertificate),
    Proposal(NetworkProposal),
    CompactProposal(CompactNetworkProposal),
}

/// Acknowledgment (empty — we only need delivery, not a real response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteAck;

#[derive(Debug, Clone, Default)]
pub struct ConsensusVotesCodec;

#[async_trait]
impl request_response::Codec for ConsensusVotesCodec {
    type Protocol = StreamProtocol;
    type Request = DirectVote;
    type Response = VoteAck;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        futures::AsyncReadExt::read_exact(&mut *io, &mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_CONSENSUS_MSG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "consensus message too large",
            ));
        }
        let mut buf = vec![0u8; len];
        futures::AsyncReadExt::read_exact(&mut *io, &mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        futures::AsyncReadExt::read_exact(&mut *io, &mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vote ack too large",
            ));
        }
        let mut buf = vec![0u8; len];
        futures::AsyncReadExt::read_exact(&mut *io, &mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let len = (data.len() as u32).to_be_bytes();
        futures::AsyncWriteExt::write_all(&mut *io, &len).await?;
        futures::AsyncWriteExt::write_all(&mut *io, &data).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&resp)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let len = (data.len() as u32).to_be_bytes();
        futures::AsyncWriteExt::write_all(&mut *io, &len).await?;
        futures::AsyncWriteExt::write_all(&mut *io, &data).await?;
        Ok(())
    }
}
