//! Atomic cross-VM settlement: swap + withdraw in a single atomic transaction.
//!
//! The user must **already hold** wrapped input tokens (obtained through the
//! normal bridge deposit path which requires relayer attestation).  This module
//! performs only the swap and withdrawal steps, preventing arbitrary minting.
//!
//! # Example
//!
//! ```text
//! Precondition: user already holds 100_000 wETH (deposited via bridge)
//!
//! User submits CrossVmSettle {
//!     swap_in_asset:  Native(Ethereum),  // wETH
//!     swap_in_amount: 100_000,
//!     swap_out_asset: Native(Solana),    // wSOL
//!     min_out:        15 SOL,            // slippage protection
//!     dest:           <solana pubkey>
//! }
//!
//! Execution (single snapshot boundary):
//!   1. Swap wETH → wSOL via AMM    (swap_engine.swap)
//!   2. Burn wSOL, create record     (withdraw::request_withdrawal)
//!
//! If step 1 returns SlippageExceeded → no state changes.
//! If step 2 fails → step 1 is rolled back.
//! ```

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;

use crate::error::BridgeError;
use crate::registry::AssetRegistry;
use crate::swap::SwapEngine;
use crate::types::{wrapped_mint_id, ExternalAsset, WithdrawalRecord};
use crate::withdraw;

/// Error type for cross-VM settlement.
#[derive(Debug, thiserror::Error)]
pub enum SettleError {
    #[error("swap failed: {0}")]
    Swap(#[from] crate::error::SwapError),

    #[error("withdraw failed: {source}")]
    Withdraw { source: BridgeError },

    #[error("zero amount")]
    ZeroAmount,

    #[error("payload decode error: {0}")]
    Decode(String),

    #[error("insufficient wrapped balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },
}

/// Parameters for an atomic cross-VM settlement (swap + withdraw).
///
/// The sender must already hold wrapped input tokens.  Deposits are handled
/// separately through the bridge path which requires relayer attestation.
pub struct CrossVmSettleParams {
    /// The sender's account ID.
    pub sender: AccountId,
    /// User-authorized conversion intent this settlement completes.
    pub intent_id: [u8; 32],
    /// Nonce for replay protection (must match sender's on-chain nonce).
    pub nonce: u64,
    /// The wrapped input asset to swap from.
    pub swap_in_asset: ExternalAsset,
    /// Amount of wrapped input tokens to swap.
    pub swap_in_amount: u64,
    /// The external asset to receive after the swap.
    pub swap_out_asset: ExternalAsset,
    /// Minimum acceptable output amount (slippage protection).
    pub min_amount_out: u64,
    /// Destination address on the external chain.
    pub withdraw_dest: Vec<u8>,
    /// Current slot number (for withdrawal record timestamping).
    pub current_slot: u64,
    /// Next withdrawal ID to assign.
    pub next_withdrawal_id: u64,
}

/// Result of a successful cross-VM settlement.
#[derive(Debug)]
pub struct SettleResult {
    /// Amount of input tokens consumed by the swap.
    pub amount_in: u64,
    /// Amount of output tokens received from the swap.
    pub amount_out: u64,
    /// The sender's account ID.
    pub sender: AccountId,
    /// Input wrapped mint AccountId.
    pub in_mint: AccountId,
    /// Output wrapped mint AccountId.
    pub out_mint: AccountId,
    /// The withdrawal record created for external-chain redemption.
    pub withdrawal: WithdrawalRecord,
}

/// Execute an atomic cross-VM settlement: swap → withdraw.
///
/// The sender must already hold wrapped input tokens.  All steps share the
/// caller's snapshot boundary — if any step fails, the entire operation
/// reverts via the dispatcher's `state.rollback()`.
///
/// # Security
///
/// This function does NOT mint tokens.  It only swaps existing wrapped tokens
/// and burns the output.  Token minting is exclusively handled by the bridge
/// deposit path (`bridge::process_signed_deposit`), which requires a valid
/// relayer attestation.
pub fn cross_vm_settle(
    state: &mut StateTree,
    registry: &AssetRegistry,
    swap_engine: &mut SwapEngine,
    params: CrossVmSettleParams,
) -> Result<SettleResult, SettleError> {
    if params.swap_in_amount == 0 {
        return Err(SettleError::ZeroAmount);
    }

    // ── Nonce check and increment (replay protection) ──
    // This is critical because 0x05 bypasses ace-engine::executor which
    // normally handles nonce validation.  Without this, the same settle
    // payload could be replayed across different slots.
    {
        let account = state
            .get_mut(&params.sender)
            .ok_or(SettleError::Decode("sender account not found".into()))?;
        if account.nonce != params.nonce {
            return Err(SettleError::Decode(format!(
                "nonce mismatch: expected {}, got {}",
                account.nonce, params.nonce
            )));
        }
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or(SettleError::Decode("nonce overflow".into()))?;
    }

    let in_mint = wrapped_mint_id(&params.swap_in_asset);
    let out_mint = wrapped_mint_id(&params.swap_out_asset);

    // Verify the sender actually holds sufficient wrapped input tokens.
    let balance = ace_n_vm::token_runtime::balance_of(state, in_mint.as_bytes(), &params.sender);
    if balance < params.swap_in_amount {
        return Err(SettleError::InsufficientBalance {
            have: balance,
            need: params.swap_in_amount,
        });
    }

    // Step 1: Swap — exchange wrapped input for wrapped output via AMM.
    let amount_out = swap_engine.swap(
        state,
        &in_mint,
        &out_mint,
        &params.sender,
        params.swap_in_amount,
        params.min_amount_out,
    )?;

    // Step 2: Withdraw — burn wrapped output tokens and create withdrawal record.
    let withdrawal = withdraw::request_withdrawal(
        state,
        registry,
        &params.sender,
        params.intent_id,
        &params.swap_out_asset,
        amount_out,
        params.withdraw_dest,
        params.current_slot,
        params.next_withdrawal_id,
    )
    .map_err(|e| SettleError::Withdraw { source: e })?;

    tracing::info!(
        sender = hex::encode(params.sender.as_bytes()),
        swap_in_asset = ?params.swap_in_asset,
        swap_in_amount = params.swap_in_amount,
        swap_out_asset = ?params.swap_out_asset,
        amount_out,
        withdrawal_id = withdrawal.withdrawal_id,
        "Cross-VM settlement completed atomically"
    );

    Ok(SettleResult {
        amount_in: params.swap_in_amount,
        amount_out,
        sender: params.sender,
        in_mint,
        out_mint,
        withdrawal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{bridge_authority_id, ExternalChain};
    use ace_model::account::Account;

    fn eth_native() -> ExternalAsset {
        ExternalAsset::Native(ExternalChain::Ethereum)
    }

    fn sol_native() -> ExternalAsset {
        ExternalAsset::Native(ExternalChain::Solana)
    }

    fn test_intent_id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn setup() -> (StateTree, AssetRegistry, SwapEngine, AccountId) {
        let mut state = StateTree::new();
        let mut registry = AssetRegistry::new();
        registry
            .register_asset(&mut state, &eth_native(), 18)
            .unwrap();
        registry
            .register_asset(&mut state, &sol_native(), 9)
            .unwrap();

        let mut swap_engine = SwapEngine::new();
        let eth_mint = wrapped_mint_id(&eth_native());
        let sol_mint = wrapped_mint_id(&sol_native());

        // Liquidity provider
        let lp = AccountId::from_bytes([0xAA; 32]);
        state.insert(Account::new(lp));
        let authority = bridge_authority_id();
        ace_n_vm::token_runtime::mint_to_owner(
            &mut state,
            eth_mint.as_bytes(),
            lp.as_bytes(),
            1_000_000,
            &authority,
        )
        .unwrap();
        ace_n_vm::token_runtime::mint_to_owner(
            &mut state,
            sol_mint.as_bytes(),
            lp.as_bytes(),
            15_000_000,
            &authority,
        )
        .unwrap();
        swap_engine
            .create_pool(&mut state, &eth_mint, &sol_mint)
            .unwrap();
        swap_engine
            .add_liquidity(&mut state, &eth_mint, &sol_mint, &lp, 1_000_000, 15_000_000)
            .unwrap();

        // User with pre-existing wrapped ETH (deposited via bridge)
        let user = AccountId::from_bytes([0xBB; 32]);
        state.insert(Account::new(user));
        ace_n_vm::token_runtime::mint_to_owner(
            &mut state,
            eth_mint.as_bytes(),
            user.as_bytes(),
            100_000,
            &authority,
        )
        .unwrap();

        (state, registry, swap_engine, user)
    }

    #[test]
    fn settle_swap_withdraw_atomically() {
        let (mut state, registry, mut swap_engine, user) = setup();

        let params = CrossVmSettleParams {
            sender: user,
            intent_id: test_intent_id(0xA1),
            nonce: 0,
            swap_in_asset: eth_native(),
            swap_in_amount: 100_000,
            swap_out_asset: sol_native(),
            min_amount_out: 1,
            withdraw_dest: vec![0xCC; 32],
            current_slot: 42,
            next_withdrawal_id: 1,
        };

        let result = cross_vm_settle(&mut state, &registry, &mut swap_engine, params).unwrap();
        assert!(result.amount_out > 0);
        assert_eq!(result.withdrawal.withdrawal_id, 1);
        assert_eq!(result.withdrawal.intent_id, test_intent_id(0xA1));

        // User should have zero of both wrapped tokens after settle
        let eth_mint = wrapped_mint_id(&eth_native());
        let sol_mint = wrapped_mint_id(&sol_native());
        assert_eq!(
            ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &user),
            0
        );
        assert_eq!(
            ace_n_vm::token_runtime::balance_of(&state, sol_mint.as_bytes(), &user),
            0
        );
    }

    #[test]
    fn settle_rejects_insufficient_balance() {
        let (mut state, registry, mut swap_engine, user) = setup();

        let params = CrossVmSettleParams {
            sender: user,
            intent_id: test_intent_id(0xA2),
            nonce: 0,
            swap_in_asset: eth_native(),
            swap_in_amount: 999_999_999, // way more than user has
            swap_out_asset: sol_native(),
            min_amount_out: 1,
            withdraw_dest: vec![0xCC; 32],
            current_slot: 42,
            next_withdrawal_id: 1,
        };

        let result = cross_vm_settle(&mut state, &registry, &mut swap_engine, params);
        assert!(matches!(
            result,
            Err(SettleError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn settle_reverts_on_slippage() {
        let (mut state, registry, mut swap_engine, user) = setup();

        let snapshot = state.snapshot();

        let params = CrossVmSettleParams {
            sender: user,
            intent_id: test_intent_id(0xA3),
            nonce: 0,
            swap_in_asset: eth_native(),
            swap_in_amount: 100_000,
            swap_out_asset: sol_native(),
            min_amount_out: u64::MAX, // impossible slippage
            withdraw_dest: vec![0xEE; 32],
            current_slot: 42,
            next_withdrawal_id: 1,
        };

        let result = cross_vm_settle(&mut state, &registry, &mut swap_engine, params);
        assert!(result.is_err());

        state.rollback(snapshot);

        // After rollback, user still has original wETH
        let eth_mint = wrapped_mint_id(&eth_native());
        assert_eq!(
            ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &user),
            100_000
        );
    }

    #[test]
    fn settle_rejects_zero_amount() {
        let (mut state, registry, mut swap_engine, user) = setup();

        let params = CrossVmSettleParams {
            sender: user,
            intent_id: test_intent_id(0xA4),
            nonce: 0,
            swap_in_asset: eth_native(),
            swap_in_amount: 0,
            swap_out_asset: sol_native(),
            min_amount_out: 1,
            withdraw_dest: vec![0xCC; 32],
            current_slot: 42,
            next_withdrawal_id: 1,
        };

        let result = cross_vm_settle(&mut state, &registry, &mut swap_engine, params);
        assert!(matches!(result, Err(SettleError::ZeroAmount)));
    }

    #[test]
    fn settle_rejects_nonce_replay() {
        let (mut state, registry, mut swap_engine, user) = setup();

        // First settle succeeds (nonce 0)
        let params = CrossVmSettleParams {
            sender: user,
            intent_id: test_intent_id(0xA5),
            nonce: 0,
            swap_in_asset: eth_native(),
            swap_in_amount: 50_000, // use half
            swap_out_asset: sol_native(),
            min_amount_out: 1,
            withdraw_dest: vec![0xCC; 32],
            current_slot: 42,
            next_withdrawal_id: 1,
        };
        let result = cross_vm_settle(&mut state, &registry, &mut swap_engine, params);
        assert!(result.is_ok());

        // Replay with same nonce 0 must fail (account nonce is now 1)
        let replay = CrossVmSettleParams {
            sender: user,
            intent_id: test_intent_id(0xA5),
            nonce: 0, // stale nonce
            swap_in_asset: eth_native(),
            swap_in_amount: 50_000,
            swap_out_asset: sol_native(),
            min_amount_out: 1,
            withdraw_dest: vec![0xCC; 32],
            current_slot: 43,
            next_withdrawal_id: 2,
        };
        let result = cross_vm_settle(&mut state, &registry, &mut swap_engine, replay);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce mismatch"));
    }

    #[test]
    fn settle_nonce_increments_on_success() {
        let (mut state, registry, mut swap_engine, user) = setup();

        assert_eq!(state.get(&user).unwrap().nonce, 0);

        let params = CrossVmSettleParams {
            sender: user,
            intent_id: test_intent_id(0xA6),
            nonce: 0,
            swap_in_asset: eth_native(),
            swap_in_amount: 50_000,
            swap_out_asset: sol_native(),
            min_amount_out: 1,
            withdraw_dest: vec![0xCC; 32],
            current_slot: 42,
            next_withdrawal_id: 1,
        };
        cross_vm_settle(&mut state, &registry, &mut swap_engine, params).unwrap();

        assert_eq!(state.get(&user).unwrap().nonce, 1);
    }
}
