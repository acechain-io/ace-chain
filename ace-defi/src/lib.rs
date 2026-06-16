//! ACE DeFi — bridge + swap primitives on the unified state tree.
//!
//! # Bridge (dual-mode VM)
//!
//! Each non-native VM (EVM, SVM, BVM, TVM) runs in two modes:
//!
//! - **L1 mode**: Part of ACE Chain's unified state, cross-VM atomic.
//! - **L2 mode**: Acts as a bridge entry point for its parent L1 chain.
//!
//! When a user deposits ETH via the L2 bridge, the bridge auto-wraps it
//! into ACE-wETH — a wrapped token on the unified token ledger.  The user
//! can then use ACE-wETH across all VMs with full cross-VM atomicity.
//!
//! # Swap (runtime-native AMM)
//!
//! Because all wrapped assets share the same StateTree, swaps are deterministic
//! balance mutations inside the ACE execution boundary. External-chain ingress
//! and egress still carry relayer/custody trust in Phase A.
//!
//! A user can swap ACE-wSOL → ACE-wUSDC(ETH) in a single transaction,
//! effectively performing a **cross-chain swap** at near-zero cost:
//!
//! ```text
//! SOL on Solana
//!   → deposit to ACE (auto-wrap to ACE-wSOL)
//!   → swap ACE-wSOL → ACE-wUSDC    ← runtime-internal execution
//!   → withdraw ACE-wUSDC to Ethereum
//! = SOL on Solana → USDC on Ethereum, single user intent
//! ```

pub mod bridge;
pub mod canonical;
pub mod compartment;
pub mod deposit;
pub mod error;
pub mod intent;
pub mod registry;
pub mod reserve;
pub mod risk;
pub mod runtime;
pub mod settle;
pub mod swap;
pub mod types;
pub mod wire;
pub mod withdraw;

pub use bridge::BridgeState;
pub use canonical::{
    canonical_asset_id, normalize_amount, oasset_mint_id, CanonicalAsset, CanonicalAssetId,
    CanonicalAssetRegistry, ExternalAssetMapping,
};
pub use compartment::{
    canonical_asset_compartment_id, external_asset_mapping_compartment_id, risk_compartment_id,
    withdrawal_route_compartment_id, RiskCompartmentId, RiskCompartmentKind,
};
pub use error::{BridgeError, SwapError};
pub use intent::{compute_intent_id, ConvertIntent};
pub use reserve::{CanonicalReserveTotal, CanonicalSupply, ReserveAccounting, ReservePosition};
pub use risk::{RiskConfig, RiskTier};
pub use runtime::{DefiRuntime, OP_CROSS_VM_SETTLE};
pub use settle::{cross_vm_settle, CrossVmSettleParams, SettleError, SettleResult};
pub use swap::SwapEngine;
pub use types::{
    bridge_authority_id, hash_deposit_record, hash_withdrawal_completion, wrapped_mint_id,
    DepositRecord, ExternalAsset, ExternalChain, SignedDepositRecord, WithdrawalCompletionRecord,
    WithdrawalRecord,
};
pub use wire::{
    approve_relayer_in_state, bridge_deposit_tx_idcom, build_oasset_withdraw_payload,
    complete_indexed_withdrawal, decode_oasset_withdraw_payload, decode_signed_deposit_payload,
    decode_withdrawal_completion_payload, encode_signed_deposit_payload,
    encode_withdrawal_completion_payload, is_bridge_deposit_payload, is_oasset_withdraw_payload,
    is_relayer_approved_in_state, is_withdrawal_completion_payload, list_pending_withdrawals,
    list_pending_withdrawals_page, verify_signed_deposit_against_state,
    verify_signed_deposit_signature, verify_withdrawal_completion_against_state,
    withdrawal_completion_tx_idcom, OAssetWithdrawRequest, PendingWithdrawalsPage,
    OP_BRIDGE_DEPOSIT, OP_OASSET_WITHDRAW, OP_WITHDRAWAL_COMPLETED,
};
