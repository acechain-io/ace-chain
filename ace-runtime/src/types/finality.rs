//! Finality types: FinalityCertificate and FinalityState.
//!
//! ## FinalityCertificate (Definition 7 in the paper)
//! Base fields:
//! - block_hash: 32 bytes
//! - slot: 8 bytes
//! - proof: opaque bytes (mock fixed-size 256; STARK proofs are variable-size)
//! - id_com_commitment: 32 bytes
//!
//! ## FinalityState
//! Five states from Algorithm 2 (Finality State Machine):
//! {Pending, Soft, BackupWait, Hard, RolledBack}

use serde::{Deserialize, Serialize};

use crate::config::MOCK_PROOF_BYTES;

/// Header for an empty finality certificate proof (0-entry bundle).
/// Format: PROOF_BUNDLE_MAGIC (4) + version (1) + count=0 (4) = 9 bytes.
/// Used when a block has no ZK-provable transactions, such as an empty block
/// or an all-raw-chain block.
pub const EMPTY_FC_PROOF_HEADER: [u8; 9] = [0x41, 0x43, 0x50, 0x53, 3, 0, 0, 0, 0]; // ACPS, v3, 0 entries

/// A ZK proof representation.
///
/// In the reference implementation, this is an opaque byte array.
/// Mock mode uses a fixed 256-byte payload; STARK mode carries
/// variable-size proofs for block-level verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProof {
    /// Raw proof bytes.
    pub data: Vec<u8>,
}

impl ZkProof {
    /// Create a proof from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Mock proof size (used by MockProver).
    pub const SIZE: usize = MOCK_PROOF_BYTES;

    /// Check if the proof is structurally well-formed.
    ///
    /// STARK proofs are variable size — just check non-empty.
    /// Mock proofs are fixed-size (256 bytes).
    pub fn is_well_formed(&self) -> bool {
        !self.data.is_empty()
    }
}

/// Semantic mode for the finality proof payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FinalityProofMode {
    /// STARK proof bundle (`ACPS`) with STARK-based verification.
    #[default]
    StarkV1,
}

/// Serde default for `proof_mode` when deserializing historical FCs that
/// predate the field.
fn default_proof_mode() -> FinalityProofMode {
    FinalityProofMode::StarkV1
}

/// Finality certificate: proof that a block is finalized.
///
/// Mock mode uses a fixed-size 256-byte proof. STARK mode carries a
/// proof bundle whose entries contain variable-size STARK proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCertificate {
    /// SHA-256 hash of the finalized block header.
    pub block_hash: [u8; 32],
    /// Slot number of the finalized block.
    pub slot: u64,
    /// ZK proof (mock or STARK bundle).
    pub proof: ZkProof,
    /// Commitment to the list of identity commitments in the block.
    pub id_com_commitment: [u8; 32],
    /// Semantic interpretation of `proof`.
    ///
    /// Defaults to `StarkV1` when deserializing historical data that
    /// predates this field.
    #[serde(default = "default_proof_mode")]
    pub proof_mode: FinalityProofMode,
    /// Commitment to the ordered authorization statements in the block.
    #[serde(default)]
    pub statement_root: [u8; 32],
    /// Number of transactions covered by the proof.
    ///
    /// Legacy certificates created before this field existed deserialize with
    /// `0` and are still accepted via compatibility rules.
    #[serde(default)]
    pub tx_count: u32,
}

impl FinalityCertificate {
    /// Check structural well-formedness (not cryptographic validity).
    pub fn is_well_formed(&self) -> bool {
        match self.proof_mode {
            FinalityProofMode::StarkV1 => self.proof.is_well_formed(),
        }
    }
}

/// Finality state of a block (Algorithm 2 in the paper).
///
/// State machine transitions:
/// - `Pending` → `Soft`: on receiving ⅔ stake-weighted votes
/// - `Soft` → `Hard`: on receiving a valid finality certificate
/// - `Soft` → `BackupWait`: on builder timeout (K slots), builder slashed
/// - `Soft` → `RolledBack`: on receiving an invalid FC
/// - `BackupWait` → `Hard`: on receiving a valid FC from backup prover
/// - `BackupWait` → `RolledBack`: on backup timeout (K+K' slots), txs requeued
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FinalityState {
    /// Block has been proposed but not yet confirmed by ⅔ votes.
    Pending,
    /// Block has achieved soft finality (⅔ BFT votes, ~400 ms).
    Soft,
    /// Builder timed out; waiting for backup prover (slashed builder).
    BackupWait,
    /// Block has achieved hard finality (valid ZK proof verified).
    Hard,
    /// Block has been rolled back (invalid/missing FC or full timeout).
    RolledBack,
}

impl FinalityState {
    /// Returns true if this is a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, FinalityState::Hard | FinalityState::RolledBack)
    }

    /// Returns true if the block is considered confirmed (soft or hard).
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self,
            FinalityState::Soft | FinalityState::BackupWait | FinalityState::Hard
        )
    }
}
