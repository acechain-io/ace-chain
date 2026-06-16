//! Capability and committee-certificate types for optional execution domains.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::sig_algo::{TaggedPubkey, TaggedSignature};

/// Static validator capabilities used by the minimal execution-committee flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorCapabilities {
    #[serde(default = "default_true")]
    pub evm_core: bool,
    #[serde(default)]
    pub btc_payments: bool,
    #[serde(default)]
    pub solana_light: bool,
}

impl Default for ValidatorCapabilities {
    fn default() -> Self {
        Self {
            evm_core: true,
            btc_payments: false,
            solana_light: false,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Optional execution domains that use a capability committee in the minimal design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CommitteeDomain {
    BtcPayments = 1,
    SolanaLight = 2,
}

impl CommitteeDomain {
    pub fn tag(self) -> u8 {
        self as u8
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::BtcPayments),
            2 => Some(Self::SolanaLight),
            _ => None,
        }
    }
}

/// A single validator approval for a capability-committee decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeApproval {
    pub signer: TaggedPubkey,
    pub signature: TaggedSignature,
}

impl CommitteeApproval {
    /// Wire size: signer wire bytes + signature wire bytes.
    pub fn wire_size(&self) -> usize {
        // Each tagged field: alg_tag(1) + len(2 LE) + bytes(N)
        (3 + self.signer.bytes.len()) + (3 + self.signature.bytes.len())
    }
}

/// Gossip message carrying a single committee approval for a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeApprovalMessage {
    pub domain: CommitteeDomain,
    pub tx_hash: [u8; 32],
    pub signer: TaggedPubkey,
    pub signature: TaggedSignature,
}

impl CommitteeApprovalMessage {
    pub fn signing_message(domain: CommitteeDomain, tx_hash: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ACE-COMMITTEE-APPROVAL-V1");
        hasher.update([domain.tag()]);
        hasher.update(tx_hash);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

/// Threshold committee certificate embedded into a transaction included in a block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeCertificate {
    pub domain: CommitteeDomain,
    pub tx_hash: [u8; 32],
    pub approvals: Vec<CommitteeApproval>,
}

impl CommitteeCertificate {
    pub fn wire_size(&self) -> usize {
        // domain_tag(1) + approval_count(1) + tx_hash(32) + sum(approval wire sizes)
        1 + 1 + 32 + self.approvals.iter().map(|a| a.wire_size()).sum::<usize>()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        debug_assert!(
            self.approvals.len() <= u8::MAX as usize,
            "CommitteeCertificate has {} approvals, exceeding the 255-entry wire limit",
            self.approvals.len()
        );
        let mut out = Vec::with_capacity(self.wire_size());
        out.push(self.domain.tag());
        out.push(self.approvals.len().min(u8::MAX as usize) as u8);
        out.extend_from_slice(&self.tx_hash);
        for approval in &self.approvals {
            out.extend_from_slice(&approval.signer.to_wire_bytes());
            out.extend_from_slice(&approval.signature.to_wire_bytes());
        }
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 34 {
            return Err("committee certificate truncated");
        }
        let domain =
            CommitteeDomain::from_tag(data[0]).ok_or("invalid committee certificate domain")?;
        let approval_count = data[1] as usize;
        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&data[2..34]);

        let mut approvals = Vec::with_capacity(approval_count);
        let mut offset = 34;
        for _ in 0..approval_count {
            let (signer, pk_consumed) = TaggedPubkey::from_wire_bytes(&data[offset..])
                .map_err(|_| "invalid committee approval signer")?;
            offset += pk_consumed;

            let (signature, sig_consumed) = TaggedSignature::from_wire_bytes(&data[offset..])
                .map_err(|_| "invalid committee approval signature")?;
            offset += sig_consumed;

            approvals.push(CommitteeApproval { signer, signature });
        }

        if offset != data.len() {
            return Err("committee certificate has trailing bytes");
        }

        Ok(Self {
            domain,
            tx_hash,
            approvals,
        })
    }
}
