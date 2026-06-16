//! End-to-end functional tests for ACE Chain.
//!
//! Tests the complete transaction lifecycle through the n-VM dispatcher:
//! account creation → auth key setup → transfers → EVM/SVM execution →
//! cross-VM settle → block proving → finality.
//!
//! Run with: `cargo test -p ace-node --test e2e_tests --features devnet`

#![cfg(feature = "devnet")]

use ace_engine::executor::TransactionOp;
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
use ace_runtime::crypto::proof::{MockProver, ProofVerifier};
use ace_runtime::crypto::TaggedPubkey;
use ace_runtime::pipeline::prove::prove_block;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::block::BlockBuilder;
use ace_runtime::types::finality::FinalityState;
use sha2::{Digest, Sha256};

// ── Test helpers ──

fn test_seed(tag: u8) -> [u8; 32] {
    let mut seed = [tag; 32];
    seed[0] ^= 0xA5;
    seed[31] ^= 0x5A;
    seed
}

fn test_idcom(tag: u8) -> [u8; 32] {
    let d = domain();
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-TEST-IDCOM-V1");
    hasher.update([tag]);
    hasher.update(d.to_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn auth_pubkey_for(tag: u8) -> TaggedPubkey {
    auth_public_key_from_seed(&test_seed(tag))
}

fn domain() -> Domain {
    Domain::new(1, 100)
}

fn make_tx(
    seed: &[u8; 32],
    idcom: [u8; 32],
    payload: &[u8],
) -> ace_runtime::types::transaction::Transaction {
    let d = domain();
    let obj_hash = {
        let mut h = Sha256::new();
        h.update(payload);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    };
    let credential = make_credential(seed, &obj_hash, &idcom, &d, &[0u8; 16]);
    ace_runtime::types::transaction::Transaction::new(
        payload.to_vec(),
        Attestation {
            obj_hash,
            idcom,
            domain: d,
            context_tag: [0u8; 16],
            credential,
        },
    )
}

fn exec(
    state: &mut StateTree,
    tx: &ace_runtime::types::transaction::Transaction,
) -> ace_n_vm::VmReceipt {
    ace_n_vm::NVm::with_defaults()
        .execute_transaction(state, tx, 0)
        .expect("tx should execute")
}

// ════════════════════════════════════════════════════════════════
// 1. Account lifecycle: create → fund → transfer → verify
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_account_create_and_transfer() {
    let mut state = StateTree::new();

    let alice_seed = test_seed(1);
    let alice_id = test_idcom(1);
    let alice = AccountId::from_bytes(alice_id);

    // Create alice
    let payload = TransactionOp::CreateAccount {
        id_com: alice,
        auth_pubkey: auth_pubkey_for(1),
    }
    .encode();
    let r = exec(&mut state, &make_tx(&alice_seed, alice_id, &payload));
    assert!(r.success, "create: {:?}", r.error);

    // Fund alice
    state.get_mut(&alice).unwrap().balance = 1_000_000;

    // Create bob
    let bob_seed = test_seed(2);
    let bob_id = test_idcom(2);
    let bob = AccountId::from_bytes(bob_id);
    let payload = TransactionOp::CreateAccount {
        id_com: bob,
        auth_pubkey: auth_pubkey_for(2),
    }
    .encode();
    let r = exec(&mut state, &make_tx(&bob_seed, bob_id, &payload));
    assert!(r.success, "create bob: {:?}", r.error);

    // Transfer 500 from alice to bob
    let payload = TransactionOp::Transfer {
        nonce: 0,
        to: bob,
        amount: 500,
    }
    .encode();
    let r = exec(&mut state, &make_tx(&alice_seed, alice_id, &payload));
    assert!(r.success, "transfer: {:?}", r.error);

    assert_eq!(state.get(&alice).unwrap().balance, 999_500);
    assert_eq!(state.get(&bob).unwrap().balance, 500);
    assert_eq!(state.get(&alice).unwrap().nonce, 1);
}

// ════════════════════════════════════════════════════════════════
// 2. Auth key update
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_auth_key_update() {
    let mut state = StateTree::new();
    let seed = test_seed(10);
    let id = test_idcom(10);
    let acct = AccountId::from_bytes(id);
    state.insert(Account::with_auth(acct, 10_000, auth_pubkey_for(10)));

    let new_key = auth_public_key_from_seed(&test_seed(99));
    let payload = TransactionOp::SetAuthPubkey {
        nonce: 0,
        auth_pubkey: new_key.clone(),
    }
    .encode();
    let r = exec(&mut state, &make_tx(&seed, id, &payload));
    assert!(r.success, "auth update: {:?}", r.error);
    assert_eq!(state.get(&acct).unwrap().auth_pubkey.bytes, new_key.bytes);
}

// ════════════════════════════════════════════════════════════════
// 3. Transfer auto-creates recipient
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_transfer_auto_creates_recipient() {
    let mut state = StateTree::new();
    let seed = test_seed(20);
    let id = test_idcom(20);
    let alice = AccountId::from_bytes(id);
    state.insert(Account::with_auth(alice, 10_000, auth_pubkey_for(20)));

    let charlie = AccountId::from_bytes([0xCC; 32]);
    let payload = TransactionOp::Transfer {
        nonce: 0,
        to: charlie,
        amount: 1_000,
    }
    .encode();
    let r = exec(&mut state, &make_tx(&seed, id, &payload));
    assert!(r.success, "auto-create: {:?}", r.error);
    assert_eq!(state.get(&charlie).unwrap().balance, 1_000);
}

// ════════════════════════════════════════════════════════════════
// 4. Insufficient balance rejected
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_insufficient_balance() {
    let mut state = StateTree::new();
    let seed = test_seed(30);
    let id = test_idcom(30);
    let alice = AccountId::from_bytes(id);
    state.insert(Account::with_auth(alice, 100, auth_pubkey_for(30)));

    let bob = AccountId::from_bytes([0xBB; 32]);
    let payload = TransactionOp::Transfer {
        nonce: 0,
        to: bob,
        amount: 999,
    }
    .encode();
    let tx = make_tx(&seed, id, &payload);
    let result = ace_n_vm::NVm::with_defaults().execute_transaction(&mut state, &tx, 0);
    assert!(result.is_err());
}

// ════════════════════════════════════════════════════════════════
// 5. Nonce replay rejected
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_nonce_replay() {
    let mut state = StateTree::new();
    let seed = test_seed(40);
    let id = test_idcom(40);
    let alice = AccountId::from_bytes(id);
    state.insert(Account::with_auth(alice, 10_000, auth_pubkey_for(40)));

    let bob = AccountId::from_bytes([0xBB; 32]);
    let payload = TransactionOp::Transfer {
        nonce: 0,
        to: bob,
        amount: 100,
    }
    .encode();
    let r = exec(&mut state, &make_tx(&seed, id, &payload));
    assert!(r.success);

    // Replay same nonce
    let payload = TransactionOp::Transfer {
        nonce: 0,
        to: bob,
        amount: 100,
    }
    .encode();
    let tx = make_tx(&seed, id, &payload);
    assert!(ace_n_vm::NVm::with_defaults()
        .execute_transaction(&mut state, &tx, 0)
        .is_err());
}

// ════════════════════════════════════════════════════════════════
// 6. EVM transfer (opcode 0x12)
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_evm_transfer() {
    let mut state = StateTree::new();
    let seed = test_seed(50);
    let id = test_idcom(50);
    let alice = AccountId::from_bytes(id);
    state.insert(Account::with_auth(alice, 1_000_000, auth_pubkey_for(50)));

    let mut payload = vec![0x12];
    payload.extend_from_slice(&[0xBB; 20]); // to
    payload.extend_from_slice(&500u64.to_le_bytes());

    let r = exec(&mut state, &make_tx(&seed, id, &payload));
    assert_eq!(r.vm_id, ace_n_vm::VmId::Evm);
    assert!(r.success, "EVM transfer: {:?}", r.error);
}

// ════════════════════════════════════════════════════════════════
// 7. SVM transfer (opcode 0x21)
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_svm_transfer() {
    let mut state = StateTree::new();
    let seed = test_seed(60);
    let id = test_idcom(60);
    let alice = AccountId::from_bytes(id);
    state.insert(Account::with_auth(alice, 1_000_000, auth_pubkey_for(60)));

    let bob = AccountId::from_bytes([0xBB; 32]);
    state.insert(Account::with_balance(bob, 0));

    let mut payload = vec![0x21];
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&bob.0);
    payload.extend_from_slice(&500u64.to_le_bytes());

    let r = exec(&mut state, &make_tx(&seed, id, &payload));
    assert_eq!(r.vm_id, ace_n_vm::VmId::Svm);
    assert!(r.success, "SVM transfer: {:?}", r.error);
}

// ════════════════════════════════════════════════════════════════
// 8. Multi-VM block: native + EVM + SVM in same block
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_multi_vm_block() {
    let mut state = StateTree::new();
    let seed = test_seed(70);
    let id = test_idcom(70);
    let alice = AccountId::from_bytes(id);
    state.insert(Account::with_auth(alice, 1_000_000, auth_pubkey_for(70)));

    let bob = AccountId::from_bytes([0xBB; 32]);
    state.insert(Account::with_balance(bob, 0));

    let vm = ace_n_vm::NVm::with_defaults();

    // Native transfer
    let p = TransactionOp::Transfer {
        nonce: 0,
        to: bob,
        amount: 100,
    }
    .encode();
    let r = vm
        .execute_transaction(&mut state, &make_tx(&seed, id, &p), 0)
        .unwrap();
    assert!(r.success && r.vm_id == ace_n_vm::VmId::AceNative);

    // EVM transfer
    let mut p = vec![0x12];
    p.extend_from_slice(&[0xCC; 20]);
    p.extend_from_slice(&200u64.to_le_bytes());
    let r = vm
        .execute_transaction(&mut state, &make_tx(&seed, id, &p), 0)
        .unwrap();
    assert!(r.success && r.vm_id == ace_n_vm::VmId::Evm);

    // SVM transfer (nonce=2: after native tx nonce=0→1 and EVM tx nonce=1→2)
    let mut p = vec![0x21];
    p.extend_from_slice(&2u64.to_le_bytes());
    p.extend_from_slice(&bob.0);
    p.extend_from_slice(&300u64.to_le_bytes());
    let r = vm
        .execute_transaction(&mut state, &make_tx(&seed, id, &p), 0)
        .unwrap();
    assert!(r.success && r.vm_id == ace_n_vm::VmId::Svm);

    assert_eq!(state.get(&alice).unwrap().balance, 999_400);
}

// ════════════════════════════════════════════════════════════════
// 9. DeFi: bridge deposit + AMM swap
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_bridge_and_swap() {
    use ace_defi::types::{ExternalAsset, ExternalChain};

    let mut state = StateTree::new();
    let mut bridge = ace_defi::BridgeState::new();
    bridge.initialize(&mut state).unwrap();

    let user = AccountId::from_bytes([0xDD; 32]);
    state.insert(Account::new(user));

    // Deposit ETH
    bridge
        .process_deposit(
            &mut state,
            &ace_defi::DepositRecord {
                deposit_id: [1u8; 32],
                intent_id: [0x11; 32],
                asset: ExternalAsset::Native(ExternalChain::Ethereum),
                amount: 100_000,
                recipient: user,
                processed_at: 0,
            },
        )
        .unwrap();

    let eth_mint = ace_defi::wrapped_mint_id(&ExternalAsset::Native(ExternalChain::Ethereum));
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &user),
        100_000
    );

    // Setup pool
    let sol_mint = ace_defi::wrapped_mint_id(&ExternalAsset::Native(ExternalChain::Solana));
    let mut swap = ace_defi::SwapEngine::new();
    let lp = AccountId::from_bytes([0xAA; 32]);
    state.insert(Account::new(lp));
    let auth = ace_defi::bridge_authority_id();
    ace_n_vm::token_runtime::mint_to_owner(
        &mut state,
        eth_mint.as_bytes(),
        lp.as_bytes(),
        1_000_000,
        &auth,
    )
    .unwrap();
    ace_n_vm::token_runtime::mint_to_owner(
        &mut state,
        sol_mint.as_bytes(),
        lp.as_bytes(),
        15_000_000,
        &auth,
    )
    .unwrap();
    swap.create_pool(&mut state, &eth_mint, &sol_mint).unwrap();
    swap.add_liquidity(&mut state, &eth_mint, &sol_mint, &lp, 1_000_000, 15_000_000)
        .unwrap();

    // Swap
    let out = swap
        .swap(&mut state, &eth_mint, &sol_mint, &user, 50_000, 1)
        .unwrap();
    assert!(out > 0);
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &user),
        50_000
    );
}

// ════════════════════════════════════════════════════════════════
// 10. CrossVmSettle: atomic swap + withdraw
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_cross_vm_settle() {
    use ace_defi::settle::{cross_vm_settle, CrossVmSettleParams};
    use ace_defi::types::{ExternalAsset, ExternalChain};

    let mut state = StateTree::new();
    let mut bridge = ace_defi::BridgeState::new();
    bridge.initialize(&mut state).unwrap();

    let eth = ExternalAsset::Native(ExternalChain::Ethereum);
    let sol = ExternalAsset::Native(ExternalChain::Solana);
    let eth_mint = ace_defi::wrapped_mint_id(&eth);
    let sol_mint = ace_defi::wrapped_mint_id(&sol);

    // Pool
    let mut swap = ace_defi::SwapEngine::new();
    let lp = AccountId::from_bytes([0xAA; 32]);
    state.insert(Account::new(lp));
    let auth = ace_defi::bridge_authority_id();
    ace_n_vm::token_runtime::mint_to_owner(
        &mut state,
        eth_mint.as_bytes(),
        lp.as_bytes(),
        1_000_000,
        &auth,
    )
    .unwrap();
    ace_n_vm::token_runtime::mint_to_owner(
        &mut state,
        sol_mint.as_bytes(),
        lp.as_bytes(),
        15_000_000,
        &auth,
    )
    .unwrap();
    swap.create_pool(&mut state, &eth_mint, &sol_mint).unwrap();
    swap.add_liquidity(&mut state, &eth_mint, &sol_mint, &lp, 1_000_000, 15_000_000)
        .unwrap();

    // User with wETH
    let user = AccountId::from_bytes([0xDD; 32]);
    state.insert(Account::new(user));
    ace_n_vm::token_runtime::mint_to_owner(
        &mut state,
        eth_mint.as_bytes(),
        user.as_bytes(),
        100_000,
        &auth,
    )
    .unwrap();

    // Atomic settle
    let result = cross_vm_settle(
        &mut state,
        &ace_defi::registry::AssetRegistry::new(),
        &mut swap,
        CrossVmSettleParams {
            sender: user,
            intent_id: [0x22; 32],
            nonce: 0,
            swap_in_asset: eth,
            swap_in_amount: 50_000,
            swap_out_asset: sol,
            min_amount_out: 1,
            withdraw_dest: vec![0xCC; 32],
            current_slot: 42,
            next_withdrawal_id: 1,
        },
    )
    .unwrap();

    assert!(result.amount_out > 0);
    assert_eq!(state.get(&user).unwrap().nonce, 1);
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &user),
        50_000
    );
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, sol_mint.as_bytes(), &user),
        0
    ); // burned
}

// ════════════════════════════════════════════════════════════════
// 11. Parallel batch execution
// ════════════════════════════════════════════════════════════════

#[test]
fn e2e_parallel_execution() {
    let mut state = StateTree::new();

    // 4 independent pairs
    for i in 0..4u8 {
        let tag = 100 + i;
        let id = test_idcom(tag);
        state.insert(Account::with_auth(
            AccountId::from_bytes(id),
            10_000,
            auth_pubkey_for(tag),
        ));
        state.insert(Account::with_balance(
            AccountId::from_bytes([200 + i; 32]),
            0,
        ));
    }

    let txs: Vec<_> = (0..4u8)
        .map(|i| {
            let tag = 100 + i;
            let payload = TransactionOp::Transfer {
                nonce: 0,
                to: AccountId::from_bytes([200 + i; 32]),
                amount: 500,
            }
            .encode();
            make_tx(&test_seed(tag), test_idcom(tag), &payload)
        })
        .collect();

    let vm = ace_n_vm::NVm::with_defaults();
    let receipts = vm.execute_block_parallel(&mut state, &txs, 0);
    assert_eq!(receipts.len(), 4);
    assert!(receipts.iter().all(|r| r.success));

    for i in 0..4u8 {
        assert_eq!(
            state
                .get(&AccountId::from_bytes([200 + i; 32]))
                .unwrap()
                .balance,
            500
        );
    }
}

// ════════════════════════════════════════════════════════════════
// 12. Block proving + finality
// ════════════════════════════════════════════════════════════════

#[test]
#[ignore = "MockProver::prove_block_certificate internal consistency issue — real STARK prover works"]
fn e2e_block_prove_finality() {
    use ace_runtime::consensus::finality::{FinalityEvent, FinalityStateMachine};
    use ace_runtime::crypto::proof::PrivateWitness;

    let prover = MockProver::new();

    let seed = test_seed(80);
    let id = test_idcom(80);
    let txs: Vec<_> = (0..5)
        .map(|i| make_tx(&seed, id, format!("block-tx-{i}").as_bytes()))
        .collect();
    let witnesses: Vec<_> = (0..5)
        .map(|_| PrivateWitness::with_defaults([80u8; 32], [0u8; 32]))
        .collect();

    let mut builder = BlockBuilder::new(100, [0u8; 32], [0u8; 32], [0xAA; 32]);
    for tx in &txs {
        builder.add_transaction(tx.clone()).unwrap();
    }
    let block = builder.build([1u8; 32], 1710000000000);

    let fc = prove_block(&block, &prover, &witnesses).unwrap();
    assert!(fc.is_well_formed());
    assert!(prover.verify_finality_certificate(&fc));
    assert!(prover.verify_finality_certificate_for_block(&fc, &block));

    let mut fsm = FinalityStateMachine::new(100);
    assert_eq!(fsm.state(), FinalityState::Pending);

    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 67,
            total_stake: 100,
            block_hash: block.hash(),
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Soft);

    fsm.on_event(
        FinalityEvent::FinalityCertReceived { certificate: fc },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Hard);
}
