//! Block and BlockHeader types (Section 3.4 in the paper).
//!
//! ## Block structure
//! - **Header** (~256 bytes): slot, parent_hash, state_root, tx_merkle_root,
//!   attest_merkle_root, poh_hash, leader_idcom, timestamp, tx_count
//! - **Body**: vector of transactions + attestations (no signatures, no proofs)
//!
//! Blocks are constrained by both transaction count (`MAX_TXS_PER_BLOCK` =
//! 80,000) and total wire size (`MAX_BLOCK_BYTES` = 32 MiB).  At ~300
//! bytes/tx a full native-transfer block is ~24 MB.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::transaction::Transaction;
use crate::config::{MAX_BLOCK_BYTES, MAX_TXS_PER_BLOCK};

pub const OP_MEV_ACE_OMISSION_EVIDENCE: u8 = 0x14;

/// Block header (~256 bytes on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Slot number.
    pub slot: u64,
    /// Hash of the parent block header.
    pub parent_hash: [u8; 32],
    /// Post-execution state root.
    pub state_root: [u8; 32],
    /// Merkle root of all full transaction bodies in this block.
    ///
    /// This commitment covers execution-relevant transaction data, including
    /// raw legacy ingress bytes and any attached committee certificates.
    pub tx_merkle_root: [u8; 32],
    /// Merkle root of all attestations in this block.
    pub attest_merkle_root: [u8; 32],
    /// Proof-of-History hash at slot boundary.
    pub poh_hash: [u8; 32],
    /// Leader's identity commitment for this slot.
    pub leader_idcom: [u8; 32],
    /// Block production timestamp (Unix milliseconds).
    pub timestamp: u64,
    /// Number of transactions in the block.
    pub tx_count: u32,
    /// Tendermint round number (metadata only; excluded from the canonical block hash
    /// so historical block hashes remain stable across the migration).
    #[serde(default)]
    pub round: u32,
    /// Hash commitment to MEV-ACE proposal material.
    ///
    /// Zero means that the block does not carry MEV-ACE material. Once the
    /// network activates full MEV-ACE, validators reject blocks with a zero or
    /// mismatching commitment.
    #[serde(default)]
    pub mev_ace_material_hash: [u8; 32],
}

impl BlockHeader {
    /// Approximate wire size: 8 + 32*6 + 8 + 4 = 212 bytes.
    /// With potential padding/alignment: ~256 bytes as stated in the paper.
    pub const APPROX_WIRE_SIZE: usize = 256;

    /// Compute the SHA-256 hash of this block header.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ACE-BLOCK-V1");
        hasher.update(self.slot.to_le_bytes());
        hasher.update(self.parent_hash);
        hasher.update(self.state_root);
        hasher.update(self.tx_merkle_root);
        hasher.update(self.attest_merkle_root);
        hasher.update(self.poh_hash);
        hasher.update(self.leader_idcom);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.tx_count.to_le_bytes());
        hasher.update(self.mev_ace_material_hash);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// MEV-ACE commitment signed by a user for a target slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevAceCommitment {
    pub idcom: [u8; 32],
    pub commitment: [u8; 32],
    pub slot: u64,
    pub user_signature: Vec<u8>,
}

/// Validator receipt over a MEV-ACE commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevAceCommitReceipt {
    pub validator_idx: u32,
    pub signature: Vec<u8>,
}

/// MEV-ACE opening carrying the transaction bytes and nonce for a commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevAceOpening {
    pub idcom: [u8; 32],
    pub commitment: [u8; 32],
    pub slot: u64,
    pub transaction_wire: Vec<u8>,
    pub nonce: [u8; 32],
}

/// Validator receipt over a MEV-ACE opening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevAceOpenReceipt {
    pub validator_idx: u32,
    pub signature: Vec<u8>,
}

/// A commitment with enough receipts to enter the admissible set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevAceCertifiedCommitment {
    pub idcom: [u8; 32],
    pub commitment: [u8; 32],
    pub receipts: Vec<MevAceCommitReceipt>,
}

/// An opening with enough receipts to enter execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevAceCertifiedOpening {
    pub opening: MevAceOpening,
    pub receipts: Vec<MevAceOpenReceipt>,
}

/// Producer-signed MEV-ACE proposal material committed by the block header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MevAceProposalMaterial {
    pub slot: u64,
    pub cset_root: [u8; 32],
    pub vdf_seed: [u8; 32],
    pub vdf_proof: Vec<u8>,
    pub sigma: Vec<u32>,
    pub omitted: Vec<[u8; 32]>,
    pub admissible_set: Vec<MevAceCertifiedCommitment>,
    pub executable_set: Vec<MevAceCertifiedOpening>,
    pub proposer_signature: Vec<u8>,
}

impl MevAceProposalMaterial {
    pub fn try_hash(&self) -> Result<[u8; 32], String> {
        let data = bincode::serialize(self)
            .map_err(|e| format!("failed to serialize MEV-ACE proposal material: {e}"))?;
        let digest = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    pub fn hash(&self) -> [u8; 32] {
        self.try_hash()
            .expect("MEV-ACE proposal material serialization must not fail")
    }
}

/// Omission evidence that can be verified against a MEV-ACE proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MevAceOmissionKind {
    Commit,
    Exec,
}

/// Wire-stable omission proof used by RPC, P2P, and governance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevAceOmissionProof {
    pub kind: MevAceOmissionKind,
    pub slot: u64,
    pub commitment: MevAceCommitment,
    pub commit_receipts: Vec<MevAceCommitReceipt>,
    pub opening: Option<MevAceOpening>,
    pub open_receipts: Vec<MevAceOpenReceipt>,
    /// Block hash of the proposal being challenged.
    pub block_hash: [u8; 32],
    /// Producer identity commitment claimed to have omitted the transaction.
    pub producer: [u8; 32],
}

pub fn encode_mev_ace_omission_evidence_payload(
    proof: &MevAceOmissionProof,
) -> Result<Vec<u8>, String> {
    let bytes = bincode::serialize(proof)
        .map_err(|e| format!("invalid MEV-ACE omission proof encoding: {e}"))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| "MEV-ACE omission proof payload exceeds u32 length".to_string())?;
    let mut payload = Vec::with_capacity(1 + 4 + bytes.len());
    payload.push(OP_MEV_ACE_OMISSION_EVIDENCE);
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(&bytes);
    Ok(payload)
}

pub fn is_mev_ace_omission_evidence_payload(payload: &[u8]) -> bool {
    payload.first() == Some(&OP_MEV_ACE_OMISSION_EVIDENCE)
}

pub fn decode_mev_ace_omission_evidence_payload(
    payload: &[u8],
) -> Result<MevAceOmissionProof, String> {
    if payload.len() < 5 || payload[0] != OP_MEV_ACE_OMISSION_EVIDENCE {
        return Err("not a MEV-ACE omission evidence payload".into());
    }
    let len = u32::from_le_bytes(
        payload[1..5]
            .try_into()
            .map_err(|_| "invalid MEV-ACE omission evidence length prefix")?,
    ) as usize;
    let end = 5usize
        .checked_add(len)
        .ok_or_else(|| "MEV-ACE omission evidence length overflow".to_string())?;
    if payload.len() != end {
        return Err(format!(
            "invalid MEV-ACE omission evidence length: expected {end}, got {}",
            payload.len()
        ));
    }
    bincode::deserialize(&payload[5..end])
        .map_err(|e| format!("invalid MEV-ACE omission evidence encoding: {e}"))
}

pub fn mev_ace_omission_evidence_tx_idcom(proof: &MevAceOmissionProof) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-MEV-ACE-OMISSION-EVIDENCE-TX-V1");
    hasher.update([match proof.kind {
        MevAceOmissionKind::Commit => 0,
        MevAceOmissionKind::Exec => 1,
    }]);
    hasher.update(proof.slot.to_le_bytes());
    hasher.update(proof.block_hash);
    hasher.update(proof.commitment.commitment);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// A complete ACE Runtime block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block header.
    pub header: BlockHeader,
    /// Ordered list of transactions (with embedded attestations).
    pub transactions: Vec<Transaction>,
    /// Optional MEV-ACE proposal material. Required after full MEV-ACE activation.
    #[serde(default)]
    pub mev_ace: Option<MevAceProposalMaterial>,
}

impl Block {
    /// Approximate total wire size of the block.
    pub fn wire_size(&self) -> usize {
        BlockHeader::APPROX_WIRE_SIZE
            + self
                .transactions
                .iter()
                .map(|tx| tx.wire_size())
                .sum::<usize>()
            + self
                .mev_ace
                .as_ref()
                .and_then(|material| bincode::serialized_size(material).ok())
                .map(|n| n as usize)
                .unwrap_or(0)
    }

    /// Compute the block hash (hash of the header).
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }
}

/// Builder for constructing blocks from validated transactions.
pub struct BlockBuilder {
    slot: u64,
    parent_hash: [u8; 32],
    poh_hash: [u8; 32],
    leader_idcom: [u8; 32],
    round: u32,
    mev_ace: Option<MevAceProposalMaterial>,
    estimated_wire_size: usize,
    transactions: Vec<Transaction>,
}

impl BlockBuilder {
    /// Create a new block builder for the given slot.
    pub fn new(
        slot: u64,
        parent_hash: [u8; 32],
        poh_hash: [u8; 32],
        leader_idcom: [u8; 32],
    ) -> Self {
        Self {
            slot,
            parent_hash,
            poh_hash,
            leader_idcom,
            round: 0,
            mev_ace: None,
            estimated_wire_size: BlockHeader::APPROX_WIRE_SIZE,
            transactions: Vec::new(),
        }
    }

    /// Set the Tendermint round number.
    pub fn with_round(mut self, round: u32) -> Self {
        self.round = round;
        self
    }

    /// Attach MEV-ACE proposal material to the block.
    pub fn with_mev_ace_material(mut self, material: MevAceProposalMaterial) -> Self {
        self.mev_ace = Some(material);
        self
    }

    /// Add a transaction to the block. Returns `Err` if the block is full.
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), BlockBuilderError> {
        if self.transactions.len() >= MAX_TXS_PER_BLOCK {
            return Err(BlockBuilderError::BlockFull);
        }
        let tx_wire_size = tx.wire_size();
        if self.estimated_wire_size + tx_wire_size > MAX_BLOCK_BYTES {
            return Err(BlockBuilderError::BlockTooLarge {
                current: self.estimated_wire_size,
                next_tx: tx_wire_size,
                limit: MAX_BLOCK_BYTES,
            });
        }
        self.estimated_wire_size += tx_wire_size;
        self.transactions.push(tx);
        Ok(())
    }

    /// Build the block, computing Merkle roots and state root.
    ///
    /// `state_root` is provided by the execution layer after processing
    /// all transactions.
    pub fn build(self, state_root: [u8; 32], timestamp: u64) -> Block {
        let tx_merkle_root = compute_tx_merkle_root(&self.transactions);
        let attest_merkle_root = compute_attest_merkle_root(&self.transactions);
        let mev_ace_material_hash = self
            .mev_ace
            .as_ref()
            .map(MevAceProposalMaterial::hash)
            .unwrap_or([0u8; 32]);

        let header = BlockHeader {
            slot: self.slot,
            parent_hash: self.parent_hash,
            state_root,
            tx_merkle_root,
            attest_merkle_root,
            poh_hash: self.poh_hash,
            leader_idcom: self.leader_idcom,
            timestamp,
            tx_count: self.transactions.len() as u32,
            round: self.round,
            mev_ace_material_hash,
        };

        Block {
            header,
            transactions: self.transactions,
            mev_ace: self.mev_ace,
        }
    }
}

/// Errors from the block builder.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BlockBuilderError {
    #[error("block is full (max {MAX_TXS_PER_BLOCK} transactions)")]
    BlockFull,
    #[error("block would exceed byte limit: current={current} next_tx={next_tx} limit={limit}")]
    BlockTooLarge {
        current: usize,
        next_tx: usize,
        limit: usize,
    },
}

/// Compute the Merkle root over a list of already-hashed leaves.
pub fn compute_merkle_root_from_hashes(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }

    let mut level = hashes.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() > 1 {
                let mut hasher = Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hasher.finalize());
                next.push(hash);
            } else {
                // Odd leaf: promote directly without double-hashing
                next.push(pair[0]);
            }
        }
        level = next;
    }

    level[0]
}

/// Compute a simple Merkle root over full transaction-body hashes.
///
/// Uses SHA-256 over [`Transaction::to_bytes`] so the block header commits the
/// full execution-relevant transaction body, not only the VM payload bytes.
/// For an empty set, returns the zero hash.
pub fn compute_tx_merkle_root(txs: &[Transaction]) -> [u8; 32] {
    let hashes: Vec<[u8; 32]> = txs.iter().map(Transaction::wire_hash).collect();
    compute_merkle_root_from_hashes(&hashes)
}

/// Compute a simple Merkle root over attestation bytes.
pub fn compute_attest_merkle_root(txs: &[Transaction]) -> [u8; 32] {
    let hashes: Vec<[u8; 32]> = txs
        .iter()
        .map(|tx| {
            let mut hasher = Sha256::new();
            hasher.update(tx.attestation.to_bytes());
            let result = hasher.finalize();
            let mut h = [0u8; 32];
            h.copy_from_slice(&result);
            h
        })
        .collect();
    compute_merkle_root_from_hashes(&hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sig_algo::{TaggedPubkey, TaggedSignature};
    use crate::types::attestation::{Attestation, Domain};
    use crate::types::capability::{CommitteeApproval, CommitteeCertificate, CommitteeDomain};
    use crate::types::transaction::RawChainKind;

    fn raw_btc_tx() -> Transaction {
        Transaction::with_raw_chain(
            vec![0x31, 0x01],
            Attestation {
                obj_hash: [0x11; 32],
                idcom: [0x22; 32],
                domain: Domain::new(1, 7),
                context_tag: [0u8; 16],
                credential: TaggedSignature::ed25519([0u8; 64]),
            },
            RawChainKind::Btc,
            vec![0x01, 0x02, 0x03],
        )
    }

    #[test]
    fn tx_merkle_root_commits_committee_certificate() {
        let tx = raw_btc_tx();
        let root_without_cert = compute_tx_merkle_root(std::slice::from_ref(&tx));

        let mut certified_tx = tx.clone();
        certified_tx.attach_committee_certificate(CommitteeCertificate {
            domain: CommitteeDomain::BtcPayments,
            tx_hash: tx.tx_hash(),
            approvals: vec![CommitteeApproval {
                signer: TaggedPubkey::ed25519([0x33; 32]),
                signature: TaggedSignature::ed25519([0x44; 64]),
            }],
        });
        let root_with_cert = compute_tx_merkle_root(&[certified_tx]);

        assert_ne!(root_without_cert, root_with_cert);
    }
}
