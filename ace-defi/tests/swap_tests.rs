use ace_defi::types::{wrapped_mint_id, DepositRecord, ExternalAsset, ExternalChain};
use ace_defi::{BridgeState, SwapEngine};
use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::legacy_idcom_evm;

fn eth_asset() -> ExternalAsset {
    ExternalAsset::Native(ExternalChain::Ethereum)
}

fn sol_asset() -> ExternalAsset {
    ExternalAsset::Native(ExternalChain::Solana)
}

fn evm_user(seed: u8) -> AccountId {
    let mut addr = [0u8; 20];
    addr[0] = seed;
    AccountId::from_bytes(legacy_idcom_evm(&addr))
}

fn intent_id(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// Set up state with bridge initialized and deposit wrapped tokens to a user.
fn setup_with_deposits() -> (StateTree, BridgeState, SwapEngine, AccountId) {
    let mut state = StateTree::new();
    let mut bridge = BridgeState::new();
    bridge.initialize(&mut state).unwrap();

    let alice = evm_user(0xA0);

    // Deposit 1M wETH and 10M wSOL to Alice
    bridge
        .process_deposit(
            &mut state,
            &DepositRecord {
                deposit_id: [1u8; 32],
                intent_id: intent_id(1),
                asset: eth_asset(),
                amount: 1_000_000,
                recipient: alice,
                processed_at: 1,
            },
        )
        .unwrap();

    bridge
        .process_deposit(
            &mut state,
            &DepositRecord {
                deposit_id: [2u8; 32],
                intent_id: intent_id(2),
                asset: sol_asset(),
                amount: 10_000_000,
                recipient: alice,
                processed_at: 2,
            },
        )
        .unwrap();

    let swap = SwapEngine::new();
    (state, bridge, swap, alice)
}

// ── Pool creation ──

#[test]
fn create_pool() {
    let (mut state, _, mut swap, _) = setup_with_deposits();

    let eth_mint = wrapped_mint_id(&eth_asset());
    let sol_mint = wrapped_mint_id(&sol_asset());

    let pid = swap.create_pool(&mut state, &eth_mint, &sol_mint).unwrap();
    assert_eq!(swap.pool_count(), 1);

    let pool = swap.get_pool(&eth_mint, &sol_mint).unwrap();
    assert_eq!(pool.pool_id, pid);
    assert_eq!(pool.reserve_a, 0);
    assert_eq!(pool.reserve_b, 0);
}

#[test]
fn create_pool_duplicate_fails() {
    let (mut state, _, mut swap, _) = setup_with_deposits();

    let eth_mint = wrapped_mint_id(&eth_asset());
    let sol_mint = wrapped_mint_id(&sol_asset());

    swap.create_pool(&mut state, &eth_mint, &sol_mint).unwrap();
    let result = swap.create_pool(&mut state, &eth_mint, &sol_mint);
    assert!(result.is_err());
}

#[test]
fn create_pool_identical_tokens_fails() {
    let (mut state, _, mut swap, _) = setup_with_deposits();

    let eth_mint = wrapped_mint_id(&eth_asset());
    let result = swap.create_pool(&mut state, &eth_mint, &eth_mint);
    assert!(result.is_err());
}

// ── Liquidity ──

#[test]
fn add_liquidity_initial() {
    let (mut state, _, mut swap, alice) = setup_with_deposits();

    let eth_mint = wrapped_mint_id(&eth_asset());
    let sol_mint = wrapped_mint_id(&sol_asset());

    swap.create_pool(&mut state, &eth_mint, &sol_mint).unwrap();

    let lp = swap
        .add_liquidity(&mut state, &eth_mint, &sol_mint, &alice, 100_000, 1_000_000)
        .unwrap();

    assert!(lp > 0);

    let pool = swap.get_pool(&eth_mint, &sol_mint).unwrap();
    assert_eq!(pool.reserve_a + pool.reserve_b, 100_000 + 1_000_000);
    assert_eq!(pool.lp_supply, lp);
}

#[test]
fn remove_liquidity() {
    let (mut state, _, mut swap, alice) = setup_with_deposits();

    let eth_mint = wrapped_mint_id(&eth_asset());
    let sol_mint = wrapped_mint_id(&sol_asset());

    swap.create_pool(&mut state, &eth_mint, &sol_mint).unwrap();

    let lp = swap
        .add_liquidity(&mut state, &eth_mint, &sol_mint, &alice, 100_000, 1_000_000)
        .unwrap();

    let (out_a, out_b) = swap
        .remove_liquidity(&mut state, &eth_mint, &sol_mint, &alice, lp)
        .unwrap();

    // Should get back (approximately) what was deposited
    assert!(out_a > 0);
    assert!(out_b > 0);

    let pool = swap.get_pool(&eth_mint, &sol_mint).unwrap();
    assert_eq!(pool.lp_supply, 0);
}

// ── Swap ──

#[test]
fn swap_basic() {
    let (mut state, _, mut swap, alice) = setup_with_deposits();

    let eth_mint = wrapped_mint_id(&eth_asset());
    let sol_mint = wrapped_mint_id(&sol_asset());

    swap.create_pool(&mut state, &eth_mint, &sol_mint).unwrap();
    swap.add_liquidity(&mut state, &eth_mint, &sol_mint, &alice, 500_000, 5_000_000)
        .unwrap();

    // Alice swaps 10,000 wETH for wSOL
    let eth_before = ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &alice);
    let sol_before = ace_n_vm::token_runtime::balance_of(&state, sol_mint.as_bytes(), &alice);

    let out = swap
        .swap(&mut state, &eth_mint, &sol_mint, &alice, 10_000, 1)
        .unwrap();

    assert!(out > 0);

    let eth_after = ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &alice);
    let sol_after = ace_n_vm::token_runtime::balance_of(&state, sol_mint.as_bytes(), &alice);

    assert_eq!(eth_after, eth_before - 10_000);
    assert_eq!(sol_after, sol_before + out);
}

#[test]
fn swap_slippage_protection() {
    let (mut state, _, mut swap, alice) = setup_with_deposits();

    let eth_mint = wrapped_mint_id(&eth_asset());
    let sol_mint = wrapped_mint_id(&sol_asset());

    swap.create_pool(&mut state, &eth_mint, &sol_mint).unwrap();
    swap.add_liquidity(&mut state, &eth_mint, &sol_mint, &alice, 500_000, 5_000_000)
        .unwrap();

    // Set min_amount_out unreasonably high
    let result = swap.swap(&mut state, &eth_mint, &sol_mint, &alice, 10_000, u64::MAX);
    assert!(result.is_err());
}

#[test]
fn swap_preserves_k_invariant() {
    let (mut state, _, mut swap, alice) = setup_with_deposits();

    let eth_mint = wrapped_mint_id(&eth_asset());
    let sol_mint = wrapped_mint_id(&sol_asset());

    swap.create_pool(&mut state, &eth_mint, &sol_mint).unwrap();
    swap.add_liquidity(&mut state, &eth_mint, &sol_mint, &alice, 500_000, 5_000_000)
        .unwrap();

    let pool = swap.get_pool(&eth_mint, &sol_mint).unwrap();
    let k_before = pool.reserve_a as u128 * pool.reserve_b as u128;

    swap.swap(&mut state, &eth_mint, &sol_mint, &alice, 50_000, 1)
        .unwrap();

    let pool = swap.get_pool(&eth_mint, &sol_mint).unwrap();
    let k_after = pool.reserve_a as u128 * pool.reserve_b as u128;

    // k should increase (fees) or stay same
    assert!(k_after >= k_before);
}

#[test]
fn quote_matches_swap() {
    let (mut state, _, mut swap, alice) = setup_with_deposits();

    let eth_mint = wrapped_mint_id(&eth_asset());
    let sol_mint = wrapped_mint_id(&sol_asset());

    swap.create_pool(&mut state, &eth_mint, &sol_mint).unwrap();
    swap.add_liquidity(&mut state, &eth_mint, &sol_mint, &alice, 500_000, 5_000_000)
        .unwrap();

    let quoted = swap.quote(&eth_mint, &sol_mint, 10_000).unwrap();
    let actual = swap
        .swap(&mut state, &eth_mint, &sol_mint, &alice, 10_000, 1)
        .unwrap();

    assert_eq!(quoted, actual);
}

// ── Cross-chain swap: SOL → wSOL → swap → wETH → withdraw ETH ──

#[test]
fn cross_chain_swap_sol_to_eth() {
    let (mut state, mut bridge, mut swap, _) = setup_with_deposits();

    let eth_mint = wrapped_mint_id(&eth_asset());
    let sol_mint = wrapped_mint_id(&sol_asset());

    // LP provider seeds the pool
    let lp_provider = evm_user(0xEF);
    bridge
        .process_deposit(
            &mut state,
            &DepositRecord {
                deposit_id: [10u8; 32],
                intent_id: intent_id(10),
                asset: eth_asset(),
                amount: 1_000_000,
                recipient: lp_provider,
                processed_at: 10,
            },
        )
        .unwrap();
    bridge
        .process_deposit(
            &mut state,
            &DepositRecord {
                deposit_id: [11u8; 32],
                intent_id: intent_id(11),
                asset: sol_asset(),
                amount: 10_000_000,
                recipient: lp_provider,
                processed_at: 11,
            },
        )
        .unwrap();

    swap.create_pool(&mut state, &eth_mint, &sol_mint).unwrap();
    swap.add_liquidity(
        &mut state,
        &eth_mint,
        &sol_mint,
        &lp_provider,
        1_000_000,
        10_000_000,
    )
    .unwrap();

    // User deposits SOL from Solana
    let user = evm_user(0xBB);
    bridge
        .process_deposit(
            &mut state,
            &DepositRecord {
                deposit_id: [20u8; 32],
                intent_id: intent_id(20),
                asset: sol_asset(),
                amount: 100_000,
                recipient: user,
                processed_at: 20,
            },
        )
        .unwrap();

    // Swap wSOL → wETH (single tx, runtime-internal)
    let eth_out = swap
        .swap(&mut state, &sol_mint, &eth_mint, &user, 100_000, 1)
        .unwrap();
    assert!(eth_out > 0);

    // Withdraw wETH to Ethereum
    let record = bridge
        .request_withdrawal(
            &mut state,
            &user,
            intent_id(30),
            &eth_asset(),
            eth_out,
            vec![0xBB; 20], // user's ETH address
            30,
        )
        .unwrap();

    assert_eq!(record.amount, eth_out);

    // User started with SOL on Solana, ended with ETH on Ethereum.
    // The swap was a runtime-internal operation at near-zero cost.
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, sol_mint.as_bytes(), &user),
        0
    );
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &user),
        0
    );
}
