//! Point-to-point transaction fetch protocol for compact block proposals.
//!
//! When a node receives a compact proposal containing only tx hashes, it
//! reconstructs the full block from its mempool.  Any transactions not found
//! locally are fetched from the proposer via this request-response protocol.

use async_trait::async_trait;
use libp2p::request_response;
use libp2p::StreamProtocol;
use std::io;

use crate::messages::{TxFetchRequest, TxFetchResponse};

/// Protocol identifier for the ACE tx-fetch request-response protocol.
///
/// Bump this when changing the **on-wire** response layout so mixed-version
/// validators do not silently mis-decode each other.
/// v1.1.0: TxFetchRequest and TxFetchResponse are now enums to support both
/// compact-block reconstruction and credential-prefetch (Mempool) modes.
pub const TX_FETCH_PROTOCOL: StreamProtocol = StreamProtocol::new("/ace/txfetch/1.1.0");

/// Maximum response size: 8 MiB (enough for ~2,800 PQC transactions).
const MAX_TX_FETCH_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// CompactBlock response: `magic` + `block_hash(32)` + `count(4)` + repeated `(u32 LE len, bytes)`.
const TX_FETCH_RESP_COMPACT_MAGIC: &[u8; 4] = b"TXF2";
/// Mempool (credential prefetch) response: `magic` + `count(4)` + repeated `(u32 LE len, bytes)`.
const TX_FETCH_RESP_MEMPOOL_MAGIC: &[u8; 4] = b"TXFM";

const TX_FETCH_RESP_COMPACT_HEADER_LEN: usize = 4 + 32 + 4;
const TX_FETCH_RESP_MEMPOOL_HEADER_LEN: usize = 4 + 4;

/// Defensive cap per wire blob (mempool default max tx is 64 KiB).
const MAX_TX_FETCH_WIRE_TX_BYTES: usize = 256 * 1024;

/// One fetch response should never exceed a full block's worth of txs.
const MAX_TX_FETCH_TX_COUNT: usize = 8192;

fn encode_tx_list(txs: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    let n: u32 = txs
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "tx-fetch encode: tx count"))?;
    if txs.len() > MAX_TX_FETCH_TX_COUNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tx-fetch encode: too many txs",
        ));
    }
    let mut body = Vec::new();
    body.extend_from_slice(&n.to_le_bytes());
    for w in txs {
        if w.len() > MAX_TX_FETCH_WIRE_TX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tx-fetch encode: tx too large",
            ));
        }
        let l: u32 = w
            .len()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "tx-fetch encode: tx len"))?;
        body.extend_from_slice(&l.to_le_bytes());
        body.extend_from_slice(w);
    }
    Ok(body)
}

fn decode_tx_list(buf: &[u8], off: usize) -> io::Result<Vec<Vec<u8>>> {
    if off + 4 > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tx-fetch decode: truncated count",
        ));
    }
    let n = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
    if n > MAX_TX_FETCH_TX_COUNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tx-fetch decode: too many txs",
        ));
    }
    let mut txs = Vec::with_capacity(n);
    let mut pos = off + 4;
    for _ in 0..n {
        if pos + 4 > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tx-fetch decode: truncated len",
            ));
        }
        let l = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if l > MAX_TX_FETCH_WIRE_TX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tx-fetch decode: tx too large",
            ));
        }
        if pos + l > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tx-fetch decode: truncated tx",
            ));
        }
        txs.push(buf[pos..pos + l].to_vec());
        pos += l;
    }
    if pos != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tx-fetch decode: trailing bytes",
        ));
    }
    Ok(txs)
}

fn encode_tx_fetch_response(resp: &TxFetchResponse) -> io::Result<Vec<u8>> {
    let out = match resp {
        TxFetchResponse::CompactBlock {
            block_hash,
            transactions_wire,
        } => {
            let mut out = Vec::new();
            out.extend_from_slice(TX_FETCH_RESP_COMPACT_MAGIC);
            out.extend_from_slice(block_hash);
            out.extend_from_slice(&encode_tx_list(transactions_wire)?);
            out
        }
        TxFetchResponse::Mempool { transactions_wire } => {
            let mut out = Vec::new();
            out.extend_from_slice(TX_FETCH_RESP_MEMPOOL_MAGIC);
            out.extend_from_slice(&encode_tx_list(transactions_wire)?);
            out
        }
    };
    if out.len() > MAX_TX_FETCH_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tx-fetch encode: response too large",
        ));
    }
    Ok(out)
}

fn decode_tx_fetch_response(buf: &[u8]) -> io::Result<TxFetchResponse> {
    if buf.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tx-fetch decode: truncated magic",
        ));
    }
    if buf[0..4] == *TX_FETCH_RESP_COMPACT_MAGIC {
        if buf.len() < TX_FETCH_RESP_COMPACT_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tx-fetch decode: truncated compact header",
            ));
        }
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&buf[4..36]);
        let transactions_wire = decode_tx_list(buf, 36)?;
        Ok(TxFetchResponse::CompactBlock {
            block_hash,
            transactions_wire,
        })
    } else if buf[0..4] == *TX_FETCH_RESP_MEMPOOL_MAGIC {
        let transactions_wire = decode_tx_list(buf, 4)?;
        Ok(TxFetchResponse::Mempool { transactions_wire })
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tx-fetch decode: unknown magic (upgrade all validators to the same ace-node image)",
        ))
    }
}

/// Codec for serializing/deserializing tx-fetch request and response messages.
#[derive(Debug, Clone, Default)]
pub struct TxFetchCodec;

#[async_trait]
impl request_response::Codec for TxFetchCodec {
    type Protocol = StreamProtocol;
    type Request = TxFetchRequest;
    type Response = TxFetchResponse;

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
        if len > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tx-fetch request too large",
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
        if len > MAX_TX_FETCH_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tx-fetch response too large",
            ));
        }
        let mut buf = vec![0u8; len];
        futures::AsyncReadExt::read_exact(&mut *io, &mut buf).await?;
        decode_tx_fetch_response(&buf)
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
        let data = encode_tx_fetch_response(&resp)?;
        let len = (data.len() as u32).to_be_bytes();
        futures::AsyncWriteExt::write_all(&mut *io, &len).await?;
        futures::AsyncWriteExt::write_all(&mut *io, &data).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_fetch_response_compact_roundtrip_empty() {
        let r = TxFetchResponse::CompactBlock {
            block_hash: [7u8; 32],
            transactions_wire: vec![],
        };
        let w = encode_tx_fetch_response(&r).unwrap();
        let d = decode_tx_fetch_response(&w).unwrap();
        assert_eq!(d, r);
    }

    #[test]
    fn tx_fetch_response_compact_roundtrip_payloads() {
        let r = TxFetchResponse::CompactBlock {
            block_hash: [9u8; 32],
            transactions_wire: vec![vec![1, 2, 3], vec![], vec![0xff; 100]],
        };
        let w = encode_tx_fetch_response(&r).unwrap();
        let d = decode_tx_fetch_response(&w).unwrap();
        assert_eq!(d, r);
    }

    #[test]
    fn tx_fetch_response_mempool_roundtrip() {
        let r = TxFetchResponse::Mempool {
            transactions_wire: vec![vec![0xAA; 50], vec![0xBB; 30]],
        };
        let w = encode_tx_fetch_response(&r).unwrap();
        let d = decode_tx_fetch_response(&w).unwrap();
        assert_eq!(d, r);
    }

    #[test]
    fn tx_fetch_response_rejects_bad_magic() {
        let mut w = encode_tx_fetch_response(&TxFetchResponse::CompactBlock {
            block_hash: [0u8; 32],
            transactions_wire: vec![],
        })
        .unwrap();
        w[0] ^= 0xff;
        assert!(decode_tx_fetch_response(&w).is_err());
    }
}
