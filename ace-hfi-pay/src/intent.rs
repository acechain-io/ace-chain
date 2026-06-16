//! Intent state machine.
//!
//! Each payment intent progresses through a deterministic lifecycle:
//!
//! ```text
//! Created → Funded → Claimed → (Withdrawn)
//!                  → Expired → Refunded
//! ```

use std::fmt;

use ace_model::account::AccountId;
use ace_runtime::crypto::{legacy_idcom_evm, legacy_idcom_tron, TaggedPubkey, TaggedSignature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Target VM chain for the payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainId {
    Native = 0,
    Evm = 1,
    Svm = 2,
    Bvm = 3,
    Tvm = 4,
}

impl ChainId {
    /// Single-byte tag used in domain separators.
    pub fn tag(self) -> u8 {
        self as u8
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Native),
            1 => Some(Self::Evm),
            2 => Some(Self::Svm),
            3 => Some(Self::Bvm),
            4 => Some(Self::Tvm),
            _ => None,
        }
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native => write!(f, "Native"),
            Self::Evm => write!(f, "EVM"),
            Self::Svm => write!(f, "SVM"),
            Self::Bvm => write!(f, "BVM"),
            Self::Tvm => write!(f, "TVM"),
        }
    }
}

/// Explicit VM-scoped destination address.
///
/// This keeps cross-VM claims honest about the address format they are
/// targeting instead of treating every destination as an opaque 32-byte
/// `AccountId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VmAddress {
    Native(AccountId),
    Evm([u8; 20]),
    Svm(AccountId),
    Bvm(AccountId),
    Tvm([u8; 20]),
}

impl VmAddress {
    pub fn chain(self) -> ChainId {
        match self {
            Self::Native(_) => ChainId::Native,
            Self::Evm(_) => ChainId::Evm,
            Self::Svm(_) => ChainId::Svm,
            Self::Bvm(_) => ChainId::Bvm,
            Self::Tvm(_) => ChainId::Tvm,
        }
    }

    /// Bytes committed into the cross-VM authorization message.
    pub fn to_auth_bytes(self) -> Vec<u8> {
        match self {
            Self::Native(id) => id.as_bytes().to_vec(),
            Self::Evm(addr) | Self::Tvm(addr) => addr.to_vec(),
            Self::Svm(id) => derive_vm_address_bytes(b"svm:", &id).to_vec(),
            Self::Bvm(id) => derive_vm_address_bytes(b"bvm:", &id).to_vec(),
        }
    }

    /// Canonical ACE account id used by the unified state tree.
    pub fn to_account_id(self) -> AccountId {
        match self {
            Self::Native(id) => id,
            Self::Evm(addr) => AccountId::from_bytes(legacy_idcom_evm(&addr)),
            Self::Svm(id) | Self::Bvm(id) => id,
            Self::Tvm(addr) => AccountId::from_bytes(legacy_idcom_tron(&addr)),
        }
    }
}

fn derive_vm_address_bytes(domain: &[u8], id: &AccountId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(id.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Lifecycle status of an intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentStatus {
    Created,
    Funded,
    Claimed,
    Expired,
    Refunded,
}

impl fmt::Display for IntentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => write!(f, "Created"),
            Self::Funded => write!(f, "Funded"),
            Self::Claimed => write!(f, "Claimed"),
            Self::Expired => write!(f, "Expired"),
            Self::Refunded => write!(f, "Refunded"),
        }
    }
}

impl IntentStatus {
    /// Check whether a transition to `next` is valid.
    ///
    /// Note: `Claimed → Expired` is intentionally **not** allowed.  Once an
    /// intent is claimed, the funds have been released to the destination and
    /// the lifecycle is terminal.  The previous "2× grace window" auto-expiry
    /// path was removed because it conflicted with the `withdrawn_amount` cap
    /// and could re-open a refund path after funds were already released.
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Funded)
                | (Self::Funded, Self::Claimed)
                | (Self::Funded, Self::Expired)
                | (Self::Expired, Self::Refunded)
        )
    }
}

/// A single payment intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    /// Cryptographically random 256-bit identifier.
    pub intent_id: [u8; 32],
    /// Intent-specific blinded recipient binding: `ρ = H("hfipay:bind" || u_B || intentId)`.
    ///
    /// Committed on-chain before or at funding time so the relay cannot
    /// substitute a different recipient identity after the fact.  An observer
    /// who knows the human-friendly identifier cannot link it to this intent
    /// without knowing the recipient's private claim-binding handle `u_B`.
    #[serde(default)]
    pub blinded_binding: [u8; 32],
    /// Amount in the smallest denomination of the payment token.
    pub amount: u64,
    /// Target VM chain.
    pub chain: ChainId,
    /// Deterministic deposit address derived from `intent_id`.
    pub deposit_address: AccountId,
    /// Optional token mint ID. `None` means native balance; `Some(mint)`
    /// routes through the token_runtime for wrapped/ERC-20/TRC-20 assets.
    /// The mint ID is typically derived from the contract address via
    /// `ace_defi::types::wrapped_mint_id`.
    pub mint: Option<[u8; 32]>,
    /// Coarse public binding epoch label carried into claim authorization.
    ///
    /// This does not reveal the underlying claim-binding handle, but it lets
    /// the claimant re-derive the correct epoch-scoped handle for the funded
    /// intent and keeps the on-chain/public tuple aligned with the paper.
    #[serde(default)]
    pub binding_epoch: u64,
    /// Sender's optional refund destination.
    pub refund_dest: Option<AccountId>,
    /// Sender identity that authorized the refund path.
    pub refund_authorizer: Option<AccountId>,
    /// Slot number after which the intent may be refunded.
    pub expiry: u64,
    /// Current lifecycle status.
    pub status: IntentStatus,
    /// Recipient's address, set upon claim.
    pub owner: Option<AccountId>,
    /// Public key that successfully claimed the intent.
    pub claim_pubkey: Option<TaggedPubkey>,
    /// Sender-provided refund authorization captured at intent creation.
    pub refund_auth: Option<(TaggedPubkey, TaggedSignature)>,
    /// Slot at which the intent was created.
    pub created_at: u64,
    /// Withdrawal nonce (incremented on each withdrawal).
    pub withdraw_nonce: u64,
    /// Total amount released so far through claim/withdraw paths.
    ///
    /// This caps legacy same-chain withdrawals at the originally quoted
    /// amount so accidental surplus sent to the deposit address is not
    /// silently swept by the claimant.
    #[serde(default)]
    pub withdrawn_amount: u64,
    /// Claim nonce (incremented on each claim attempt).
    pub claim_nonce: u64,
    /// Refund nonce (incremented on each refund).
    pub refund_nonce: u64,
}

impl Intent {
    /// Create a new intent in the `Created` state.
    pub fn new(
        intent_id: [u8; 32],
        blinded_binding: [u8; 32],
        amount: u64,
        chain: ChainId,
        deposit_address: AccountId,
        mint: Option<[u8; 32]>,
        binding_epoch: u64,
        refund_dest: Option<AccountId>,
        refund_authorizer: Option<AccountId>,
        refund_auth: Option<(TaggedPubkey, TaggedSignature)>,
        expiry: u64,
        created_at: u64,
    ) -> Self {
        Self {
            intent_id,
            blinded_binding,
            amount,
            chain,
            deposit_address,
            mint,
            binding_epoch,
            refund_dest,
            refund_authorizer,
            expiry,
            status: IntentStatus::Created,
            owner: None,
            claim_pubkey: None,
            refund_auth,
            created_at,
            withdraw_nonce: 0,
            withdrawn_amount: 0,
            claim_nonce: 0,
            refund_nonce: 0,
        }
    }

    /// Attempt a status transition, returning an error on invalid moves.
    pub fn transition(&mut self, next: IntentStatus) -> Result<(), crate::HfiPayError> {
        if self.status.can_transition_to(next) {
            self.status = next;
            Ok(())
        } else {
            Err(crate::HfiPayError::InvalidTransition {
                from: self.status.to_string(),
                to: next.to_string(),
            })
        }
    }
}
