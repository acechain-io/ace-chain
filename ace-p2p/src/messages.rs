//! Network message types for gossipsub communication.

use ace_runtime::config::MAX_P2P_MESSAGE_BYTES;
use ace_runtime::crypto::sig_algo::{SignatureAlgorithm, TaggedSignature};
use ace_runtime::types::block::{Block, BlockHeader};
use ace_runtime::types::block::{
    MevAceCommitReceipt, MevAceCommitment, MevAceOmissionProof, MevAceOpenReceipt, MevAceOpening,
    MevAceProposalMaterial,
};
use ace_runtime::types::capability::CommitteeApprovalMessage;
use ace_runtime::types::finality::{FinalityCertificate, FinalityState};
use ace_runtime::types::transaction::Transaction;
use serde::{Deserialize, Serialize};

use crate::config::{
    TOPIC_BLOCKS, TOPIC_COMMITTEE, TOPIC_FINALITY, TOPIC_MEV_ACE, TOPIC_PRECOMMITS, TOPIC_PREVOTES,
    TOPIC_PROPOSALS, TOPIC_SYNC, TOPIC_TAKEOVER, TOPIC_TRANSACTIONS,
};
use crate::takeover::IdentityTakeoverMsg;

/// A block proposal for Tendermint consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProposal {
    pub height: u64,
    pub round: u32,
    pub block: Block,
    /// If re-proposing a previously locked block, the round in which it was locked.
    pub valid_round: Option<u32>,
    pub proposer: [u8; 32],
    pub signature: TaggedSignature,
    pub chain_id: u32,
}

/// A compact block proposal that carries only tx hashes instead of full
/// transactions.  Receivers reconstruct the full block from their local
/// mempool and request any missing transactions via the TxFetch protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactNetworkProposal {
    pub height: u64,
    pub round: u32,
    pub header: BlockHeader,
    /// Ordered list of canonical transaction identifiers for mempool lookup.
    pub tx_hashes: Vec<[u8; 32]>,
    /// Ordered list of hashes over the full serialized transaction bytes.
    ///
    /// This lets receivers distinguish a mempool hit whose wire bytes differ
    /// from the proposer's block body (for example after certificate attachment).
    #[serde(default)]
    pub tx_wire_hashes: Vec<[u8; 32]>,
    /// Optional MEV-ACE proposal material required to reconstruct full blocks
    /// after full MEV-ACE activation.
    #[serde(default)]
    pub mev_ace: Option<MevAceProposalMaterial>,
    pub valid_round: Option<u32>,
    pub proposer: [u8; 32],
    pub signature: TaggedSignature,
    pub chain_id: u32,
    /// PeerId of the authenticated gossipsub author (set locally after deserialization, not transmitted).
    #[serde(skip)]
    pub proposer_peer_id: Option<String>,
}

/// Relay-only credential commitment carried alongside a stripped PQC gossip tx.
///
/// Allows receivers to prefetch the full ML-DSA-44 credential asynchronously
/// (before a compact proposal arrives), so compact proposal hit rate is 100%
/// and TxFetch is eliminated from the consensus critical path.
///
/// Not part of the canonical `Transaction` — lives only in the gossip envelope.
/// The commitment is an availability guarantee, not a security proof: final
/// validity still requires `Verify(pubkey, msg, full_credential)` at block
/// inclusion time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialCommitment {
    pub algorithm: SignatureAlgorithm,
    /// Expected length of the full credential bytes (2420 for ML-DSA-44).
    pub credential_len: u16,
    /// SHA-256 of the full credential bytes.
    pub credential_hash: [u8; 32],
}

/// Request missing transactions via the TxFetch protocol.
///
/// Two modes:
/// - `CompactBlock`: validator needs missing txs to reconstruct a specific compact
///   proposal.  Responder looks up from the compact-block cache keyed by block_hash.
/// - `Mempool`: receiver of a stripped PQC gossip tx needs the full credential.
///   Responder looks up from its local mempool (full-credential path).
///   Each request carries the `CredentialCommitment` so the responder can verify
///   it is serving the right credential version, and the requester can verify the
///   response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxFetchRequest {
    /// Compact-proposal reconstruction: fetch txs missing from a specific block.
    CompactBlock {
        /// Block hash identifying which compact proposal triggered this fetch.
        block_hash: [u8; 32],
        /// Canonical tx hashes of the missing transactions.
        tx_hashes: Vec<[u8; 32]>,
    },
    /// Credential prefetch: fetch full-credential PQC txs from the peer's mempool.
    /// Sent immediately after receiving a stripped gossip tx with a commitment,
    /// so the full credential is in the local mempool before any compact proposal
    /// arrives.
    Mempool {
        tx_hashes: Vec<[u8; 32]>,
        /// Commitments in the same order as tx_hashes, for response verification.
        credential_commitments: Vec<CredentialCommitment>,
    },
}

impl TxFetchRequest {
    /// Returns the tx_hashes slice regardless of mode.
    pub fn tx_hashes(&self) -> &[[u8; 32]] {
        match self {
            TxFetchRequest::CompactBlock { tx_hashes, .. } => tx_hashes,
            TxFetchRequest::Mempool { tx_hashes, .. } => tx_hashes,
        }
    }
}

/// Response with the requested transactions.
///
/// Carries `Transaction::to_bytes()` payloads (canonical execution wire format).
/// The variant mirrors the request so the receiver can route the response correctly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxFetchResponse {
    /// Response to a CompactBlock request.  block_hash routes it to the pending
    /// compact reconstruction state machine.
    CompactBlock {
        block_hash: [u8; 32],
        transactions_wire: Vec<Vec<u8>>,
    },
    /// Response to a Mempool (credential prefetch) request.
    Mempool { transactions_wire: Vec<Vec<u8>> },
}

impl TxFetchResponse {
    pub fn transactions_wire(&self) -> &[Vec<u8>] {
        match self {
            TxFetchResponse::CompactBlock {
                transactions_wire, ..
            } => transactions_wire,
            TxFetchResponse::Mempool { transactions_wire } => transactions_wire,
        }
    }
}

/// Internal notification that a tx-fetch request failed before reconstruction completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxFetchFailure {
    pub block_hash: [u8; 32],
    pub peer_id: String,
    pub error: String,
}

/// A Tendermint prevote transmitted over the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPrevote {
    pub height: u64,
    pub round: u32,
    /// Block hash being voted for, or [0; 32] for nil.
    pub block_hash: [u8; 32],
    pub voter: [u8; 32],
    pub voter_stake: u64,
    pub signature: TaggedSignature,
    pub chain_id: u32,
}

/// A Tendermint precommit transmitted over the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPrecommit {
    pub height: u64,
    pub round: u32,
    /// Block hash being committed, or [0; 32] for nil.
    pub block_hash: [u8; 32],
    pub voter: [u8; 32],
    pub voter_stake: u64,
    pub signature: TaggedSignature,
    pub chain_id: u32,
}

/// A commit certificate proving that 2/3+ validators precommitted a block.
///
/// Broadcast after a node commits a block so that peers who missed
/// individual precommit messages can verify the quorum and commit directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitCertificate {
    pub height: u64,
    pub round: u32,
    pub block_hash: [u8; 32],
    pub chain_id: u32,
    /// The signed precommits that form the 2/3+ quorum.
    pub precommits: Vec<NetworkPrecommit>,
}

/// MEV-ACE commit/open/receipt message carried over public gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MevAceNetworkMessage {
    Commitment(MevAceCommitment),
    CommitReceipt {
        idcom: [u8; 32],
        commitment: [u8; 32],
        receipt: MevAceCommitReceipt,
    },
    Opening(MevAceOpening),
    OpenReceipt {
        idcom: [u8; 32],
        commitment: [u8; 32],
        receipt: MevAceOpenReceipt,
    },
    ProposalMaterial(MevAceProposalMaterial),
    OmissionProof(MevAceOmissionProof),
}

/// Request a contiguous block range from peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSyncRequest {
    pub start_slot: u64,
    pub limit: u16,
    /// Peer ID of the requester, stamped by the network layer after deserialization.
    /// Not transmitted over the wire — derived from libp2p connection metadata.
    #[serde(skip)]
    pub requester_peer_id: Option<String>,
}

/// A block plus its known finality metadata for catch-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSyncRecord {
    pub block: Block,
    pub finality_state: Option<FinalityState>,
    pub finality_cert: Option<FinalityCertificate>,
}

/// Respond to a block sync request with ordered canonical records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSyncResponse {
    pub start_slot: u64,
    pub latest_slot: u64,
    pub records: Vec<BlockSyncRecord>,
    /// Echoed from the request so the network layer can match by (peer_id, start_slot).
    #[serde(skip)]
    pub peer_id: Option<String>,
}

/// Request a state snapshot from peers for fast catch-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncRequest {
    /// The height we want a snapshot for (0 = latest available).
    pub target_height: u64,
}

/// Response with a compressed state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncResponse {
    /// The height this snapshot was taken at.
    pub height: u64,
    /// Block hash at this height (for verification).
    pub block_hash: [u8; 32],
    /// State root hash (for verification after applying).
    pub state_root: [u8; 32],
    /// Serialized state snapshot (bincode-encoded).
    pub state_data: Vec<u8>,
}

/// Plaintext public peer metadata used to bootstrap per-peer E2EE.
///
/// When `signature` is present it covers `SHA-256("ACE-IDANN-V1" || xidentity || idcom || timestamp_ms)`
/// and must verify against `auth_pubkey`. Unsigned announcements are accepted
/// for backward compatibility but logged as warnings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityAnnouncement {
    pub xidentity: String,
    pub idcom: Option<[u8; 32]>,
    pub auth_pubkey: Option<ace_runtime::crypto::TaggedPubkey>,
    #[serde(default)]
    pub timestamp_ms: u64,
    /// Ed25519 signature over SHA-256("ACE-IDANN-V1" || xidentity || idcom || timestamp_ms).
    #[serde(default)]
    pub signature: Option<Vec<u8>>,
}

impl IdentityAnnouncement {
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Per-recipient encrypted transport envelope for network messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedNetworkEnvelope {
    pub recipient_peer_id: String,
    pub sender_peer_id: String,
    pub sender_idcom: Option<[u8; 32]>,
    pub payload: ace_identity::AceEncryptedPayload,
}

impl EncryptedNetworkEnvelope {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let data = bincode::serialize(self).map_err(|e| e.to_string())?;
        if data.len() > MAX_MESSAGE_BYTES {
            return Err(format!(
                "message too large: {} bytes (max {})",
                data.len(),
                MAX_MESSAGE_BYTES
            ));
        }
        Ok(data)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() > MAX_MESSAGE_BYTES {
            return Err(format!(
                "message too large: {} bytes (max {})",
                data.len(),
                MAX_MESSAGE_BYTES
            ));
        }
        bincode::deserialize(data).map_err(|e| e.to_string())
    }
}

/// Maximum serialized message size in bytes.
pub const MAX_MESSAGE_BYTES: usize = MAX_P2P_MESSAGE_BYTES;

/// Messages exchanged over the P2P network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// A new transaction from the network.
    ///
    /// For stripped PQC (ML-DSA-44) txs, `credential_commitment` carries the
    /// SHA-256 of the full credential so receivers can prefetch it asynchronously.
    /// `source_peer_id` is injected by the P2P service after deserialization —
    /// never transmitted.  Both fields are `None` for Ed25519/non-PQC txs.
    NewTransaction {
        tx: Transaction,
        #[serde(default)]
        credential_commitment: Option<CredentialCommitment>,
        #[serde(skip)]
        source_peer_id: Option<String>,
    },
    /// A newly produced block.
    NewBlock(Block),
    /// A finality certificate.
    FinalityCert(FinalityCertificate),
    /// A request for historical block records.
    BlockSyncRequest(BlockSyncRequest),
    /// A response containing canonical block records.
    BlockSyncResponse(BlockSyncResponse),
    /// A committee approval for a raw BTC/Solana ingress transaction.
    CommitteeApproval(CommitteeApprovalMessage),
    /// An identity takeover request ("New Kicks Old").
    IdentityTakeover(IdentityTakeoverMsg),
    /// A Tendermint block proposal (full block — legacy / fallback).
    Proposal(NetworkProposal),
    /// A compact Tendermint block proposal (tx hashes only).
    CompactProposal(CompactNetworkProposal),
    /// A Tendermint prevote.
    Prevote(NetworkPrevote),
    /// A Tendermint precommit.
    Precommit(NetworkPrecommit),
    /// A commit certificate with 2/3+ signed precommits for catch-up.
    CommitCertificate(CommitCertificate),
    /// MEV-ACE commit/open/receipt/proposal/evidence message.
    MevAce(MevAceNetworkMessage),
    /// A state sync request for fast catch-up.
    StateSyncRequest(StateSyncRequest),
    /// A state sync response with snapshot data.
    StateSyncResponse(StateSyncResponse),
    /// A tx-fetch response received via request-response (not gossipsub).
    /// Routed through consensus channel for compact proposal reconstruction.
    TxFetchResponse(TxFetchResponse),
    /// Internal notification that a tx-fetch request failed.
    TxFetchFailure(TxFetchFailure),
    /// Internal command: dial a public peer address discovered out-of-band.
    DialPeer { addr: String },
}

impl NetworkMessage {
    /// Whether this is a consensus-critical message (Proposal, Prevote, Precommit).
    pub fn is_consensus(&self) -> bool {
        matches!(
            self,
            NetworkMessage::Proposal(_)
                | NetworkMessage::CompactProposal(_)
                | NetworkMessage::TxFetchResponse(_)
                | NetworkMessage::TxFetchFailure(_)
                | NetworkMessage::Prevote(_)
                | NetworkMessage::Precommit(_)
                | NetworkMessage::CommitCertificate(_)
                | NetworkMessage::MevAce(_)
        )
    }

    /// Whether this message carries public chain data that does not require
    /// per-peer E2EE.  Transactions, blocks, finality certificates, committee
    /// approvals, and consensus votes are all publicly verifiable — encrypting
    /// them per-peer only adds O(n) CPU cost and latency with no privacy gain.
    ///
    /// Only `IdentityTakeover` is considered private (contains identity
    /// migration credentials that should be encrypted in transit).
    pub fn is_public(&self) -> bool {
        !matches!(self, NetworkMessage::IdentityTakeover(_))
    }

    /// Get the gossipsub topic for this message type.
    pub fn topic(&self) -> &'static str {
        match self {
            NetworkMessage::NewTransaction { .. } => TOPIC_TRANSACTIONS,
            NetworkMessage::NewBlock(_) => TOPIC_BLOCKS,
            NetworkMessage::FinalityCert(_) => TOPIC_FINALITY,
            NetworkMessage::BlockSyncRequest(_) | NetworkMessage::BlockSyncResponse(_) => {
                TOPIC_SYNC
            }
            NetworkMessage::CommitteeApproval(_) => TOPIC_COMMITTEE,
            NetworkMessage::IdentityTakeover(_) => TOPIC_TAKEOVER,
            NetworkMessage::Proposal(_) | NetworkMessage::CompactProposal(_) => TOPIC_PROPOSALS,
            NetworkMessage::Prevote(_) => TOPIC_PREVOTES,
            NetworkMessage::Precommit(_) | NetworkMessage::CommitCertificate(_) => TOPIC_PRECOMMITS,
            NetworkMessage::MevAce(_) => TOPIC_MEV_ACE,
            NetworkMessage::StateSyncRequest(_) | NetworkMessage::StateSyncResponse(_) => {
                TOPIC_SYNC
            }
            // TxFetchResponse / TxFetchFailure are internal request-response events, not gossipsub.
            // This topic is never actually used for publishing.
            NetworkMessage::TxFetchResponse(_) | NetworkMessage::TxFetchFailure(_) => {
                TOPIC_PROPOSALS
            }
            NetworkMessage::DialPeer { .. } => TOPIC_SYNC,
        }
    }

    /// Serialize the message to bytes for gossipsub.
    pub fn encoded_len(&self) -> Result<usize, String> {
        let encoded_len = bincode::serialized_size(self).map_err(|e| e.to_string())? as usize;
        if encoded_len > MAX_MESSAGE_BYTES {
            return Err(format!(
                "message too large: {encoded_len} bytes (max {MAX_MESSAGE_BYTES})"
            ));
        }
        Ok(encoded_len)
    }

    /// Serialize the message to bytes for gossipsub.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let data = bincode::serialize(self).map_err(|e| e.to_string())?;
        if data.len() > MAX_MESSAGE_BYTES {
            return Err(format!(
                "message too large: {} bytes (max {})",
                data.len(),
                MAX_MESSAGE_BYTES
            ));
        }
        Ok(data)
    }

    /// Deserialize a message from bytes with a size limit.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() > MAX_MESSAGE_BYTES {
            return Err(format!(
                "message too large: {} bytes (max {})",
                data.len(),
                MAX_MESSAGE_BYTES
            ));
        }
        bincode::deserialize(data).map_err(|e| e.to_string())
    }
}
