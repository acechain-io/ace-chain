//! Core data structures matching the paper's definitions.
//!
//! - [`attestation`]: Attestation, Domain
//! - [`transaction`]: Transaction, payload types
//! - [`block`]: BlockHeader, Block, block builder
//! - [`finality`]: FinalityCertificate, FinalityState

pub mod attestation;
pub mod block;
pub mod capability;
pub mod finality;
pub mod transaction;

pub use attestation::{Attestation, Domain};
pub use block::{
    decode_mev_ace_omission_evidence_payload, encode_mev_ace_omission_evidence_payload,
    is_mev_ace_omission_evidence_payload, mev_ace_omission_evidence_tx_idcom, Block, BlockHeader,
    MevAceCertifiedCommitment, MevAceCertifiedOpening, MevAceCommitReceipt, MevAceCommitment,
    MevAceOmissionKind, MevAceOmissionProof, MevAceOpenReceipt, MevAceOpening,
    MevAceProposalMaterial, OP_MEV_ACE_OMISSION_EVIDENCE,
};
pub use capability::{
    CommitteeApproval, CommitteeApprovalMessage, CommitteeCertificate, CommitteeDomain,
    ValidatorCapabilities,
};
pub use finality::{FinalityCertificate, FinalityProofMode, FinalityState};
pub use transaction::{RawChainKind, RawChainPayload, Transaction};
