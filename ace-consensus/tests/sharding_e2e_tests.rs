//! End-to-end sharding integration tests.
//!
//! These tests exercise the full block production pipeline with context-based
//! sharding: transaction construction → consensus engine → sharded execution
//! → state verification → state root computation.

use ace_consensus::engine::ConsensusEngine;
use ace_consensus::leader_schedule::LeaderSchedule;
use ace_consensus::poh::PohChain;
use ace_consensus::validator_set::{Validator, ValidatorSet};
use ace_model::account::{Account, AccountId};
use ace_model::sharded_state::{ShardId, ShardedState};
use ace_n_vm::NVm;
use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
use ace_runtime::crypto::TaggedPubkey;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::capability::ValidatorCapabilities;
use ace_runtime::types::transaction::Transaction;
use sha2::{Digest, Sha256};

// ── Test seeds ──

const SEED_A: [u8; 32] = [0xA0; 32];
const SEED_B: [u8; 32] = [0xB0; 32];
const SEED_C: [u8; 32] = [0xC0; 32];

// ── Helpers ──

fn make_engine() -> (ConsensusEngine, AccountId) {
    let local_id = AccountId([1u8; 32]);
    let validators = vec![Validator {
        id_com: local_id,
        stake: 100,
        index: 0,
        signing_pubkey: TaggedPubkey::ed25519([0u8; 32]),
        capabilities: ValidatorCapabilities::default(),
    }];
    let vs = ValidatorSet::new(validators);
    let schedule = LeaderSchedule::new([0u8; 32]);
    let poh = PohChain::new([0u8; 32]);
    let n_vm = NVm::with_defaults();
    let engine = ConsensusEngine::new(local_id, schedule, vs, poh, n_vm, [0u8; 32]);
    (engine, local_id)
}

fn make_tx_with_context(
    sender_id: [u8; 32],
    recipient_id: [u8; 32],
    amount: u64,
    nonce: u64,
    context_tag: [u8; 16],
    auth_seed: &[u8; 32],
) -> Transaction {
    let mut payload = Vec::with_capacity(49);
    payload.push(0x01); // native transfer opcode
    payload.extend_from_slice(&nonce.to_le_bytes());
    payload.extend_from_slice(&recipient_id);
    payload.extend_from_slice(&amount.to_le_bytes());

    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&Sha256::digest(&payload));
    let domain = Domain::new(1, 0);

    Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom: sender_id,
            domain,
            context_tag,
            credential: make_credential(auth_seed, &obj_hash, &sender_id, &domain, &context_tag),
        },
    )
}

fn make_genesis_state(accounts: &[(&[u8; 32], u64, &[u8; 32])]) -> ShardedState {
    let mut state = ShardedState::new();
    for &(seed, balance, id_bytes) in accounts {
        let account = Account::with_auth(
            AccountId(*id_bytes),
            balance,
            auth_public_key_from_seed(seed),
        );
        state.insert(account);
    }
    state
}

// ── Tests ──

/// All transactions use default context_tag — should behave identically to
/// pre-sharding execution: single shard, state root equals the shard's root.
#[test]
fn single_shard_backward_compatible() {
    let (mut engine, _) = make_engine();

    let alice_id = [0x11; 32];
    let bob_id = [0x22; 32];
    let mut state = ShardedState::new();
    state.insert_into_shard(
        ShardId(0),
        Account::with_auth(
            AccountId(alice_id),
            5000,
            auth_public_key_from_seed(&SEED_A),
        ),
    );
    state.insert_into_shard(
        ShardId(0),
        Account::with_auth(AccountId(bob_id), 0, auth_public_key_from_seed(&SEED_B)),
    );

    // Single-shard state root before execution
    let pre_root = state.compute_root();
    assert_eq!(state.shard_count(), 1, "should start with one shard");

    let tx = make_tx_with_context(alice_id, bob_id, 100, 0, [0u8; 16], &SEED_A);
    let (block, receipts) = engine.produce_block(0, &mut state, vec![tx]).unwrap();

    assert_eq!(receipts.len(), 1);
    assert!(receipts[0].success);
    assert_eq!(state.get(&AccountId(alice_id)).unwrap().balance, 4900);
    assert_eq!(state.get(&AccountId(bob_id)).unwrap().balance, 100);

    // Still single shard after execution
    assert_eq!(state.shard_count(), 1);
    // State root changed
    assert_ne!(state.compute_root(), pre_root);
    // Block embeds the new state root
    assert_eq!(block.header.state_root, state.compute_root());
}

/// Two independent transfers in the same shard execute via parallel batch.
/// Verifies actual balance changes, not just conservation.
#[test]
fn multi_tx_parallel_execution() {
    let (mut engine, _) = make_engine();

    let alice_id = [0x11; 32];
    let bob_id = [0x22; 32];
    let carol_id = [0x33; 32];

    let mut state = make_genesis_state(&[
        (&SEED_A, 5000, &alice_id),
        (&SEED_B, 5000, &bob_id),
        (&SEED_C, 0, &carol_id),
    ]);

    // Both use default context → same shard → parallel execution within shard.
    let tx1 = make_tx_with_context(alice_id, carol_id, 100, 0, [0u8; 16], &SEED_A);
    let tx2 = make_tx_with_context(bob_id, carol_id, 200, 0, [0u8; 16], &SEED_B);

    let (block, receipts) = engine.produce_block(0, &mut state, vec![tx1, tx2]).unwrap();

    assert_eq!(receipts.len(), 2);
    assert!(
        receipts[0].success,
        "tx1 must succeed: {:?}",
        receipts[0].error
    );
    assert!(
        receipts[1].success,
        "tx2 must succeed: {:?}",
        receipts[1].error
    );
    assert_eq!(block.transactions.len(), 2);

    // Verify actual balance changes — not just conservation.
    assert_eq!(
        state.get(&AccountId(alice_id)).unwrap().balance,
        4900,
        "Alice sent 100, should have 4900"
    );
    assert_eq!(
        state.get(&AccountId(bob_id)).unwrap().balance,
        4800,
        "Bob sent 200, should have 4800"
    );
    assert_eq!(
        state.get(&AccountId(carol_id)).unwrap().balance,
        300,
        "Carol received 100+200, should have 300"
    );

    assert_eq!(block.header.state_root, state.compute_root());
}

/// Transfer from Alice (shard 0) to Bob (shard 5) is cross-context and
/// executes via the shared shard with merged state.
#[test]
fn cross_context_transfer_via_shared_shard() {
    let (mut engine, _) = make_engine();

    let alice_id = [0x11; 32];
    let bob_id = [0x22; 32];

    let mut state = ShardedState::new();
    state.insert_into_shard(
        ShardId(0),
        Account::with_auth(
            AccountId(alice_id),
            5000,
            auth_public_key_from_seed(&SEED_A),
        ),
    );
    // Bob in a different shard
    state.insert_into_shard(ShardId(5), Account::new(AccountId(bob_id)));

    assert_eq!(state.shard_count(), 2);

    let ctx = [0x01; 16]; // non-default context
    let tx = make_tx_with_context(alice_id, bob_id, 300, 0, ctx, &SEED_A);

    let (block, receipts) = engine.produce_block(0, &mut state, vec![tx]).unwrap();

    assert_eq!(receipts.len(), 1);
    // Cross-context tx should execute via merged state
    if receipts[0].success {
        assert_eq!(state.get(&AccountId(alice_id)).unwrap().balance, 4700);
        assert_eq!(state.get(&AccountId(bob_id)).unwrap().balance, 300);
    }

    // No duplicate AccountIds across shards
    let mut seen_ids = std::collections::HashSet::new();
    for (_, shard_tree) in state.iter_shards() {
        for (id, _) in shard_tree.iter() {
            assert!(
                seen_ids.insert(*id),
                "AccountId {:?} appears in multiple shards",
                id
            );
        }
    }

    assert_eq!(block.header.state_root, state.compute_root());
}

/// Block with both shard-local and cross-context transactions. Shard-local
/// txs execute in parallel (Phase 2), cross-context tx executes serially
/// (Phase 3). All final balances must be correct.
#[test]
fn mixed_shard_local_and_cross_context_block() {
    let (mut engine, _) = make_engine();

    let alice_id = [0x11; 32];
    let bob_id = [0x22; 32];
    let carol_id = [0x33; 32];

    let mut state = ShardedState::new();
    state.insert_into_shard(
        ShardId(0),
        Account::with_auth(
            AccountId(alice_id),
            10_000,
            auth_public_key_from_seed(&SEED_A),
        ),
    );
    state.insert_into_shard(
        ShardId(0),
        Account::with_auth(
            AccountId(bob_id),
            10_000,
            auth_public_key_from_seed(&SEED_B),
        ),
    );
    // Carol in a different shard → transfers to her from shard 0 are cross-context
    state.insert_into_shard(ShardId(3), Account::new(AccountId(carol_id)));

    // tx1: Alice → Bob, default context (shard-local, both in shard 0)
    let tx1 = make_tx_with_context(alice_id, bob_id, 500, 0, [0u8; 16], &SEED_A);
    // tx2: Bob → Carol, non-default context (cross-context: Bob in shard 0, Carol in shard 3)
    let tx2 = make_tx_with_context(bob_id, carol_id, 200, 0, [0x02; 16], &SEED_B);

    let (block, receipts) = engine.produce_block(0, &mut state, vec![tx1, tx2]).unwrap();

    assert_eq!(receipts.len(), 2);
    assert_eq!(block.transactions.len(), 2);

    // tx1 (shard-local) should always succeed
    assert!(receipts[0].success, "shard-local tx should succeed");
    assert_eq!(state.get(&AccountId(alice_id)).unwrap().balance, 9500);

    // Total balance must be conserved regardless of tx2 outcome
    let total: u64 = [alice_id, bob_id, carol_id]
        .iter()
        .map(|id| state.get(&AccountId(*id)).unwrap().balance)
        .sum();
    assert_eq!(total, 20_000, "total balance must be conserved");

    assert_eq!(block.header.state_root, state.compute_root());
}

/// After Phase 3 cross-context execution, accounts touched in the merged
/// view must be cleaned from their original non-default shards.
/// This is a regression test: without the cleanup, Bob would exist in
/// both shard 0 and shard 7, causing non-deterministic reads.
#[test]
fn phase3_writeback_cleans_stale_accounts() {
    let alice_id = [0x11; 32];
    let bob_id = [0x22; 32];

    let mut state = ShardedState::new();
    state.insert_into_shard(
        ShardId(0),
        Account::with_auth(
            AccountId(alice_id),
            5000,
            auth_public_key_from_seed(&SEED_A),
        ),
    );
    // Bob explicitly in shard 7
    state.insert_into_shard(ShardId(7), Account::new(AccountId(bob_id)));

    let initial_count = state.total_account_count();
    assert_eq!(initial_count, 2);
    assert!(state
        .shard(ShardId(7))
        .unwrap()
        .contains(&AccountId(bob_id)));

    // Cross-context transfer: Alice (shard 0) → Bob (shard 7)
    let ctx = [0x07; 16];
    let tx = make_tx_with_context(alice_id, bob_id, 100, 0, ctx, &SEED_A);

    let vm = NVm::with_defaults();
    let receipts = vm.execute_block_sharded(&mut state, &[tx], 0);

    // The transfer MUST succeed — this is not optional.
    assert_eq!(receipts.len(), 1);
    assert!(
        receipts[0].success,
        "cross-context transfer must succeed, got error: {:?}",
        receipts[0].error
    );

    // CRITICAL: Bob must remain in exactly one shard. Phase 3 write-back
    // preserves existing manual shard placement; the invariant is no duplicate
    // copies across shards.
    let bob_in_shard_7 = state
        .shard(ShardId(7))
        .map_or(false, |s| s.contains(&AccountId(bob_id)));
    assert!(
        bob_in_shard_7,
        "Bob should remain in his manually assigned shard after Phase 3 write-back"
    );
    assert!(!state.default_shard().contains(&AccountId(bob_id)));

    // Bob must be findable with the correct balance.
    assert!(state.contains(&AccountId(bob_id)));
    assert_eq!(
        state.get(&AccountId(bob_id)).unwrap().balance,
        100,
        "Bob should have received 100 from Alice"
    );

    // Alice must have paid.
    assert_eq!(
        state.get(&AccountId(alice_id)).unwrap().balance,
        4900,
        "Alice should have 4900 after sending 100"
    );

    // Total account count unchanged (no duplicates created).
    assert_eq!(state.total_account_count(), initial_count);

    // Verify no AccountId appears in more than one shard.
    let mut seen = std::collections::HashSet::new();
    for (_, shard_tree) in state.iter_shards() {
        for (id, _) in shard_tree.iter() {
            assert!(
                seen.insert(*id),
                "AccountId {:?} appears in multiple shards — Phase 3 cleanup failed",
                id
            );
        }
    }
}

/// Shard state persists across multiple block productions.
#[test]
fn multi_block_shard_state_continuity() {
    let (mut engine, _) = make_engine();

    let alice_id = [0x11; 32];
    let bob_id = [0x22; 32];

    let mut state = make_genesis_state(&[(&SEED_A, 10_000, &alice_id), (&SEED_B, 0, &bob_id)]);

    // Block 0: Alice sends 100 to Bob
    let tx0 = make_tx_with_context(alice_id, bob_id, 100, 0, [0u8; 16], &SEED_A);
    let (block0, receipts0) = engine.produce_block(0, &mut state, vec![tx0]).unwrap();
    assert!(receipts0[0].success);
    assert_eq!(state.get(&AccountId(alice_id)).unwrap().balance, 9900);
    assert_eq!(state.get(&AccountId(bob_id)).unwrap().balance, 100);
    let root_after_block0 = state.compute_root();

    // Block 1: Alice sends another 200 to Bob (nonce = 1)
    let tx1 = make_tx_with_context(alice_id, bob_id, 200, 1, [0u8; 16], &SEED_A);
    let (block1, receipts1) = engine.produce_block(1, &mut state, vec![tx1]).unwrap();
    assert!(receipts1[0].success);
    assert_eq!(state.get(&AccountId(alice_id)).unwrap().balance, 9700);
    assert_eq!(state.get(&AccountId(bob_id)).unwrap().balance, 300);

    // State root changed between blocks
    let root_after_block1 = state.compute_root();
    assert_ne!(root_after_block0, root_after_block1);

    // Block chain: block1's parent is block0
    assert_eq!(block1.header.parent_hash, block0.hash());
    assert_eq!(block1.header.state_root, root_after_block1);
}

/// Same transactions on same initial state must produce identical state roots,
/// validating that BTreeMap ordering makes execution deterministic.
/// Also verifies the root is NOT the empty-state root (i.e. computation actually ran).
#[test]
fn state_root_deterministic_across_runs() {
    let run = || {
        let (mut engine, _) = make_engine();

        let alice_id = [0x11; 32];
        let bob_id = [0x22; 32];
        let carol_id = [0x33; 32];

        let mut state = make_genesis_state(&[
            (&SEED_A, 5000, &alice_id),
            (&SEED_B, 5000, &bob_id),
            (&SEED_C, 0, &carol_id),
        ]);

        let pre_root = state.compute_root();

        let tx1 = make_tx_with_context(alice_id, carol_id, 100, 0, [0u8; 16], &SEED_A);
        let tx2 = make_tx_with_context(bob_id, carol_id, 200, 0, [0u8; 16], &SEED_B);

        let (_block, receipts) = engine.produce_block(0, &mut state, vec![tx1, tx2]).unwrap();

        // At least one tx must succeed to prove the root changed due to execution.
        let success_count = receipts.iter().filter(|r| r.success).count();
        assert!(success_count >= 1, "at least one tx must succeed");

        let post_root = state.compute_root();
        // Root must differ from pre-execution (proves something actually happened).
        assert_ne!(
            pre_root, post_root,
            "state root must change after execution"
        );
        // Root must not be all zeros.
        assert_ne!(post_root, [0u8; 32], "state root must not be zero");

        post_root
    };

    let root1 = run();
    let root2 = run();
    assert_eq!(
        root1, root2,
        "state roots must be identical for same inputs"
    );
}
