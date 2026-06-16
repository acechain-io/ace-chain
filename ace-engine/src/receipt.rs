//! Execution receipts produced after transaction execution.
//!
//! Each successfully or unsuccessfully executed transaction produces
//! a receipt recording what happened. These are stored alongside
//! blocks for RPC queries.

use ace_model::account::AccountId;
use serde::{Deserialize, Serialize};

/// Receipt produced by executing a single transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    /// Canonical transaction hash (SHA-256 of the serialized transaction).
    pub tx_hash: [u8; 32],
    /// Whether execution succeeded.
    pub success: bool,
    /// Sender (identity commitment from attestation).
    pub sender: AccountId,
    /// State changes applied (empty on failure).
    pub state_changes: Vec<StateChange>,
    /// Error message if execution failed.
    pub error: Option<String>,
}

/// A single state change applied during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateChange {
    BalanceChange {
        account: AccountId,
        old: u64,
        new: u64,
    },
    NonceIncrement {
        account: AccountId,
        new_nonce: u64,
    },
    AccountCreated {
        account: AccountId,
    },
    StorageChange {
        account: AccountId,
        slot: [u8; 32],
        old_value: [u8; 32],
        new_value: [u8; 32],
    },
    CodeDeployed {
        account: AccountId,
        code_hash: [u8; 32],
    },
    /// Implicit fee (BVM: input_value - output_value).
    Fee {
        amount: u64,
    },
    /// An address was bound to an account via RegisterAddresses.
    AddressBound {
        account: AccountId,
        address_type: u8,
    },
    /// An auth key was installed or rotated (SetAuthPubkey / AddAuthKey).
    AuthKeyUpdated {
        account: AccountId,
        /// Raw algorithm tag (SignatureAlgorithm discriminant).
        algorithm: u8,
    },
    /// An HFI Pay intent was created, transitioned, or removed.
    /// Carries the `IntentStatus` discriminants (0..=4) for before/after.
    /// `old_status = 0xFF` means the intent did not exist prior.
    /// `claim_tag` is set only on Claimed transitions: SHA-256(intent_id || ACE_CLAIM_SALT).
    /// It is stored in the block receipt so observers see the tag but never the raw intent_id.
    IntentChange {
        intent_id: [u8; 32],
        old_status: u8,
        new_status: u8,
        claim_tag: Option<[u8; 32]>,
    },
    /// A ZK-ACE replay-prevention commitment was consumed.
    ZkReplayConsumed {
        rp_com: [u8; 32],
        account: AccountId,
    },
}
