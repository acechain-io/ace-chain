//! Attestation and Domain types (Definition 4 in the paper).
//!
//! An attestation binds a payload hash, account identity, and domain to a
//! signature derived from the user's authorized signing key.
//!
//! ## Wire format (v2 — PQC-ready, variable-length credential)
//! - `obj_hash`: 32 bytes (SHA-256 of payload)
//! - `idcom`: 32 bytes (identity commitment)
//! - `domain`: 8 bytes (chain_id + slot)
//! - `context_tag`: 16 bytes (shard routing tag)
//! - `alg_tag`: 1 byte (signature algorithm)
//! - `sig_len`: 2 bytes LE (credential length)
//! - `credential`: N bytes (signature)

use serde::{Deserialize, Serialize};

use crate::crypto::sig_algo::TaggedSignature;

/// Domain binding: chain_id || slot.
///
/// Ensures attestations are bound to a specific chain and slot,
/// preventing cross-chain and cross-slot replay attacks.
///
/// Wire format: 8 bytes total (4-byte chain_id + 4-byte slot), matching
/// the paper's Definition 4. Slot is u32 on the wire (covers ~54 years
/// at 400 ms/slot); `BlockHeader.slot` uses u64 internally for future-proofing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Domain {
    /// Chain identifier.
    pub chain_id: u32,
    /// Slot number (u32 on the wire per paper spec).
    pub slot: u32,
}

impl Domain {
    /// Create a new domain binding.
    pub fn new(chain_id: u32, slot: u32) -> Self {
        Self { chain_id, slot }
    }

    /// Serialize domain to bytes: chain_id (4 LE) || slot (4 LE).
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&self.chain_id.to_le_bytes());
        buf[4..8].copy_from_slice(&self.slot.to_le_bytes());
        buf
    }

    /// Deserialize domain from 8-byte buffer.
    pub fn from_bytes(bytes: &[u8; 8]) -> Self {
        let chain_id = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let slot = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Self { chain_id, slot }
    }
}

/// Size of the context tag field in bytes.
pub const CONTEXT_TAG_SIZE: usize = 16;

/// Default context tag (shard 0 — backward compatible).
pub const DEFAULT_CONTEXT_TAG: [u8; CONTEXT_TAG_SIZE] = [0u8; CONTEXT_TAG_SIZE];

/// Fixed-size portion of the attestation wire format.
const ATTESTATION_FIXED_SIZE: usize = 32 + 32 + 8 + CONTEXT_TAG_SIZE; // obj_hash + idcom + domain + context_tag = 88

/// Signature-based attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// SHA-256 hash of the transaction payload.
    pub obj_hash: [u8; 32],
    /// Identity commitment carried by the caller's wallet or proof layer.
    pub idcom: [u8; 32],
    /// Domain binding (chain_id, slot).
    pub domain: Domain,
    /// Context tag for shard routing (16 bytes).
    pub context_tag: [u8; CONTEXT_TAG_SIZE],
    /// Algorithm-tagged credential (signature over `obj_hash || idcom || domain || context_tag`).
    pub credential: TaggedSignature,
}

impl Attestation {
    /// Wire size of this attestation in bytes.
    ///
    /// obj_hash(32) + idcom(32) + domain(8) + context_tag(16) + alg_tag(1) + sig_len(2 LE) + sig_bytes(N).
    pub fn wire_size(&self) -> usize {
        ATTESTATION_FIXED_SIZE + 3 + self.credential.bytes.len()
    }

    /// Serialize the credential-independent identity portion of the attestation.
    ///
    /// Returns the fixed 88-byte prefix: obj_hash(32) + idcom(32) + domain(8) + context_tag(16).
    /// The credential is excluded so that `tx_hash` is stable across relay hops where
    /// the gossip credential may be stripped to a compact placeholder (AR-ACE relay path).
    pub fn to_identity_bytes(&self) -> [u8; ATTESTATION_FIXED_SIZE] {
        let mut buf = [0u8; ATTESTATION_FIXED_SIZE];
        buf[0..32].copy_from_slice(&self.obj_hash);
        buf[32..64].copy_from_slice(&self.idcom);
        buf[64..72].copy_from_slice(&self.domain.to_bytes());
        buf[72..88].copy_from_slice(&self.context_tag);
        buf
    }

    /// Serialize attestation to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        buf.extend_from_slice(&self.obj_hash);
        buf.extend_from_slice(&self.idcom);
        buf.extend_from_slice(&self.domain.to_bytes());
        buf.extend_from_slice(&self.context_tag);
        buf.extend_from_slice(&self.credential.to_wire_bytes());
        buf
    }

    /// Deserialize attestation from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ATTESTATION_FIXED_SIZE + 3 {
            return Err("attestation data too short");
        }
        let mut obj_hash = [0u8; 32];
        obj_hash.copy_from_slice(&data[0..32]);
        let mut idcom = [0u8; 32];
        idcom.copy_from_slice(&data[32..64]);
        let mut domain_bytes = [0u8; 8];
        domain_bytes.copy_from_slice(&data[64..72]);
        let domain = Domain::from_bytes(&domain_bytes);
        let mut context_tag = [0u8; CONTEXT_TAG_SIZE];
        context_tag.copy_from_slice(&data[72..72 + CONTEXT_TAG_SIZE]);
        let (credential, consumed) =
            TaggedSignature::from_wire_bytes(&data[72 + CONTEXT_TAG_SIZE..])?;
        if ATTESTATION_FIXED_SIZE + consumed != data.len() {
            return Err("attestation has trailing bytes");
        }
        Ok(Self {
            obj_hash,
            idcom,
            domain,
            context_tag,
            credential,
        })
    }

    /// Total bytes consumed by `from_bytes`. Useful for callers that need to
    /// know where the attestation ends in a larger buffer.
    pub fn bytes_consumed(data: &[u8]) -> Result<usize, &'static str> {
        if data.len() < ATTESTATION_FIXED_SIZE + 3 {
            return Err("attestation data too short");
        }
        let (_credential, consumed) =
            TaggedSignature::from_wire_bytes(&data[72 + CONTEXT_TAG_SIZE..])?;
        Ok(ATTESTATION_FIXED_SIZE + consumed)
    }
}
