//! Point-to-point block sync protocol using libp2p request-response.
//!
//! Unlike gossipsub (broadcast to all peers), this sends sync requests to a
//! specific peer and receives the response only from that peer.  This avoids
//! the O(N²) message amplification that was causing sync storms in devnet.

use async_trait::async_trait;
use libp2p::request_response;
use libp2p::StreamProtocol;
use std::io;

use crate::messages::{BlockSyncRequest, BlockSyncResponse};

/// Protocol identifier for the ACE block sync request-response protocol.
pub const SYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/ace/sync/1.1.0");

/// Codec for serializing/deserializing block sync request and response messages.
#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

#[async_trait]
impl request_response::Codec for SyncCodec {
    type Protocol = StreamProtocol;
    type Request = BlockSyncRequest;
    type Response = BlockSyncResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        // Read 4-byte length prefix, then payload
        let mut len_buf = [0u8; 4];
        futures::AsyncReadExt::read_exact(&mut *io, &mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
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
        if len > 64 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response too large",
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
