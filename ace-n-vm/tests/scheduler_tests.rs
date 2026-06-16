//! Tests for the parallel transaction scheduler.

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_n_vm::dispatcher::NVm;
use ace_n_vm::scheduler::{build_batches, extract_write_set, WriteSet};
use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
use ace_runtime::crypto::{TaggedPubkey, TaggedSignature};
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use sha2::{Digest, Sha256};

fn auth_seed(sender_id: [u8; 32]) -> [u8; 32] {
    sender_id
}

fn auth_pubkey(sender_id: [u8; 32]) -> TaggedPubkey {
    auth_public_key_from_seed(&auth_seed(sender_id))
}

fn funded_account(id: AccountId, balance: u64) -> Account {
    Account::with_auth(id, balance, auth_pubkey(id.0))
}

fn make_tx(sender_id: [u8; 32], payload: Vec<u8>) -> Transaction {
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&hasher.finalize());
    let domain = Domain::new(1, 0);
    let credential = make_credential(
        &auth_seed(sender_id),
        &obj_hash,
        &sender_id,
        &domain,
        &[0u8; 16],
    );

    Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom: sender_id,
            domain,
            context_tag: [0u8; 16],
            credential,
        },
    )
}

fn id(byte: u8) -> AccountId {
    AccountId::from_bytes([byte; 32])
}

fn native_transfer_payload(to: AccountId, amount: u64) -> Vec<u8> {
    let mut p = vec![0x01];
    p.extend_from_slice(&0u64.to_le_bytes());
    p.extend_from_slice(to.as_bytes());
    p.extend_from_slice(&amount.to_le_bytes());
    p
}

fn svm_transfer_payload(to: AccountId, amount: u64) -> Vec<u8> {
    let mut p = vec![0x21];
    p.extend_from_slice(&0u64.to_le_bytes());
    p.extend_from_slice(to.as_bytes());
    p.extend_from_slice(&amount.to_le_bytes());
    p
}

fn move_payload() -> Vec<u8> {
    let mut p = vec![0x50];
    p.extend_from_slice(&0u64.to_le_bytes());
    p.extend_from_slice(&[0u8; 32]);
    let mut module_name = [0u8; 32];
    module_name[..4].copy_from_slice(b"test");
    p.extend_from_slice(&module_name);
    p.extend_from_slice(&4u16.to_le_bytes());
    p.extend_from_slice(b"call");
    p.extend_from_slice(&0u16.to_le_bytes());
    p
}

/// Build a Move transfer payload: sender→recipient for the given nonce.
/// Layout: [0x50][nonce:8][module_addr:32][module_name:32]
///         [func_name_len:2]["transfer"][args_count:2][tag:1][recipient:32][tag:1][amount:8]
fn move_transfer_payload(recipient: AccountId, nonce: u64) -> Vec<u8> {
    let mut p = vec![0x50];
    p.extend_from_slice(&nonce.to_le_bytes());
    p.extend_from_slice(&[0u8; 32]); // module_addr
    let mut module_name = [0u8; 32];
    module_name[..5].copy_from_slice(b"coin0");
    p.extend_from_slice(&module_name);
    p.extend_from_slice(&8u16.to_le_bytes()); // func_name_len
    p.extend_from_slice(b"transfer");
    p.extend_from_slice(&2u16.to_le_bytes()); // args_count
    p.push(0x05); // Address tag
    p.extend_from_slice(&recipient.0);
    p.push(0x02); // U64 tag
    p.extend_from_slice(&100u64.to_le_bytes());
    p
}

// ── WriteSet extraction tests ──

#[test]
fn write_set_native_transfer() {
    let alice = id(1);
    let bob = id(2);
    let tx = make_tx(alice.0, native_transfer_payload(bob, 100));
    match extract_write_set(&tx) {
        WriteSet::Accounts(set) => {
            assert!(set.contains(&alice));
            assert!(set.contains(&bob));
            assert_eq!(set.len(), 2);
        }
        WriteSet::Global => panic!("expected Accounts"),
    }
}

#[test]
fn write_set_native_create() {
    let alice = id(1);
    let new_id = id(3);
    let mut payload = vec![0x02];
    payload.extend_from_slice(new_id.as_bytes());
    payload.extend_from_slice(&500u64.to_le_bytes());
    let tx = make_tx(alice.0, payload);
    match extract_write_set(&tx) {
        WriteSet::Accounts(set) => {
            assert!(set.contains(&alice));
            assert!(set.contains(&new_id));
        }
        WriteSet::Global => panic!("expected Accounts"),
    }
}

#[test]
fn write_set_evm_call_is_global() {
    let tx = make_tx([1u8; 32], vec![0x10, 0xAA, 0xBB]);
    assert!(matches!(extract_write_set(&tx), WriteSet::Global));
}

#[test]
fn write_set_evm_create_is_global() {
    let tx = make_tx([1u8; 32], vec![0x11, 0x00]);
    assert!(matches!(extract_write_set(&tx), WriteSet::Global));
}

#[test]
fn write_set_evm_transfer_is_global() {
    let tx = make_tx([1u8; 32], vec![0x12, 0x00]);
    assert!(matches!(extract_write_set(&tx), WriteSet::Global));
}

#[test]
fn write_set_move_is_global() {
    let tx = make_tx([1u8; 32], move_payload());
    assert!(matches!(extract_write_set(&tx), WriteSet::Global));
}

#[test]
fn write_set_svm_invoke_lists_declared_accounts() {
    let alice = id(1);
    let program = id(10);
    let acct_a = id(20);
    let acct_b = id(21);

    // 0x20 [program_id:32][num_accounts:1][[pubkey:32][is_signer:1][is_writable:1]]...[data...]
    let mut payload = vec![0x20];
    payload.extend_from_slice(program.as_bytes());
    payload.push(2); // num_accounts
    payload.extend_from_slice(acct_a.as_bytes());
    payload.push(1);
    payload.push(1);
    payload.extend_from_slice(acct_b.as_bytes());
    payload.push(1);
    payload.push(1);
    payload.extend_from_slice(&[0xDD; 4]); // data

    let tx = make_tx(alice.0, payload);
    match extract_write_set(&tx) {
        WriteSet::Accounts(set) => {
            assert!(set.contains(&alice));
            assert!(set.contains(&acct_a));
            assert!(set.contains(&acct_b));
            assert_eq!(set.len(), 3);
        }
        WriteSet::Global => panic!("expected Accounts write set for well-formed SVM invoke"),
    }
}

#[test]
fn write_set_svm_transfer() {
    let alice = id(1);
    let bob = id(2);
    let tx = make_tx(alice.0, svm_transfer_payload(bob, 100));
    match extract_write_set(&tx) {
        WriteSet::Accounts(set) => {
            assert!(set.contains(&alice));
            assert!(set.contains(&bob));
            assert_eq!(set.len(), 2);
        }
        WriteSet::Global => panic!("expected Accounts"),
    }
}

#[test]
fn write_set_empty_payload() {
    let tx = make_tx([1u8; 32], vec![]);
    match extract_write_set(&tx) {
        WriteSet::Accounts(set) => assert!(set.is_empty()),
        WriteSet::Global => panic!("expected empty Accounts"),
    }
}

#[test]
fn write_set_raw_btc_utxo_is_global() {
    let tx = Transaction::with_raw_chain(
        vec![0x32, 0x00, 0x00],
        Attestation {
            obj_hash: {
                let mut hasher = Sha256::new();
                hasher.update([0x32, 0x00, 0x00]);
                let mut out = [0u8; 32];
                out.copy_from_slice(&hasher.finalize());
                out
            },
            idcom: [1u8; 32],
            domain: Domain::new(1, 0),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
        RawChainKind::Btc,
        vec![0x00],
    );
    assert!(matches!(extract_write_set(&tx), WriteSet::Global));
}

// ── Batch building tests ──

#[test]
fn independent_txs_same_batch() {
    // Alice→Bob and Charlie→Dave: disjoint write sets
    let alice = id(1);
    let bob = id(2);
    let charlie = id(3);
    let dave = id(4);

    let txs = vec![
        make_tx(alice.0, native_transfer_payload(bob, 100)),
        make_tx(charlie.0, native_transfer_payload(dave, 200)),
    ];
    let batches = build_batches(&txs);
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].tx_indices.len(), 2);
}

#[test]
fn conflicting_recipient_separate_batches() {
    // Alice→Bob and Charlie→Bob: both write to Bob
    let alice = id(1);
    let bob = id(2);
    let charlie = id(3);

    let txs = vec![
        make_tx(alice.0, native_transfer_payload(bob, 100)),
        make_tx(charlie.0, native_transfer_payload(bob, 200)),
    ];
    let batches = build_batches(&txs);
    assert_eq!(batches.len(), 2);
}

#[test]
fn same_sender_separate_batches() {
    // Alice→Bob then Alice→Charlie: same sender nonce ordering
    let alice = id(1);
    let bob = id(2);
    let charlie = id(3);

    let txs = vec![
        make_tx(alice.0, native_transfer_payload(bob, 100)),
        make_tx(alice.0, native_transfer_payload(charlie, 200)),
    ];
    let batches = build_batches(&txs);
    assert_eq!(batches.len(), 2);
}

#[test]
fn evm_call_isolates() {
    // Native tx, then EVM call, then native tx
    let alice = id(1);
    let bob = id(2);
    let charlie = id(3);
    let dave = id(4);

    let txs = vec![
        make_tx(alice.0, native_transfer_payload(bob, 100)),
        make_tx(charlie.0, vec![0x10, 0xAA, 0xBB]), // EVM call → Global
        make_tx(dave.0, native_transfer_payload(id(5), 50)),
    ];
    let batches = build_batches(&txs);
    // EVM call (Global) can't share a batch with anything
    assert!(batches.len() >= 2);
    // The EVM tx should be alone in its batch
    let evm_batch = batches.iter().find(|b| b.tx_indices.contains(&1)).unwrap();
    assert_eq!(evm_batch.tx_indices.len(), 1);
}

#[test]
fn empty_block_no_batches() {
    assert!(build_batches(&[]).is_empty());
}

#[test]
fn many_independent_txs_single_batch() {
    // 10 transfers between disjoint account pairs
    let txs: Vec<Transaction> = (0..10u8)
        .map(|i| {
            let sender = id(i * 2 + 1);
            let recipient = id(i * 2 + 2);
            make_tx(sender.0, native_transfer_payload(recipient, 100))
        })
        .collect();
    let batches = build_batches(&txs);
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].tx_indices.len(), 10);
}

// ── Parallel execution integration tests ──

fn setup_multi_account() -> StateTree {
    let mut state = StateTree::new();
    for i in 1..=20u8 {
        state.insert(funded_account(id(i), 10_000));
    }
    state
}

#[test]
fn parallel_matches_serial_native_transfers() {
    let state = setup_multi_account();
    let vm = NVm::with_defaults();

    // 5 independent native transfers
    let txs = vec![
        make_tx(id(1).0, native_transfer_payload(id(2), 100)),
        make_tx(id(3).0, native_transfer_payload(id(4), 200)),
        make_tx(id(5).0, native_transfer_payload(id(6), 300)),
        make_tx(id(7).0, native_transfer_payload(id(8), 400)),
        make_tx(id(9).0, native_transfer_payload(id(10), 500)),
    ];

    let mut state_serial = state.clone();
    let mut state_parallel = state.clone();

    let receipts_serial = vm.execute_block(&mut state_serial, &txs, 0);
    let receipts_parallel = vm.execute_block_parallel(&mut state_parallel, &txs, 0);

    // Compare receipts
    assert_eq!(receipts_serial.len(), receipts_parallel.len());
    for (rs, rp) in receipts_serial.iter().zip(receipts_parallel.iter()) {
        assert_eq!(rs.success, rp.success, "success mismatch");
        assert_eq!(rs.tx_hash, rp.tx_hash, "tx_hash mismatch");
    }

    // Compare final state roots
    assert_eq!(
        state_serial.compute_root(),
        state_parallel.compute_root(),
        "state roots diverge"
    );
}

#[test]
fn parallel_matches_serial_mixed_vm() {
    let state = setup_multi_account();

    // Also add EVM-related accounts
    let bob_evm = ace_n_vm::cross_vm::AddressResolver::to_evm_address(&id(2));

    let vm = NVm::with_defaults();

    // Mix: native transfer + SVM transfer + EVM transfer
    let mut evm_payload = vec![0x12];
    evm_payload.extend_from_slice(&bob_evm);
    evm_payload.extend_from_slice(&100u64.to_le_bytes());

    let txs = vec![
        make_tx(id(3).0, native_transfer_payload(id(4), 100)),
        make_tx(id(1).0, evm_payload),
        make_tx(id(5).0, svm_transfer_payload(id(6), 200)),
    ];

    let mut state_serial = state.clone();
    let mut state_parallel = state.clone();

    let receipts_serial = vm.execute_block(&mut state_serial, &txs, 0);
    let receipts_parallel = vm.execute_block_parallel(&mut state_parallel, &txs, 0);

    assert_eq!(receipts_serial.len(), receipts_parallel.len());
    for (rs, rp) in receipts_serial.iter().zip(receipts_parallel.iter()) {
        assert_eq!(rs.success, rp.success);
        assert_eq!(rs.tx_hash, rp.tx_hash);
    }

    assert_eq!(
        state_serial.compute_root(),
        state_parallel.compute_root(),
        "state roots diverge for mixed VM block"
    );
}

#[test]
fn parallel_same_sender_ordering() {
    let mut state = StateTree::new();
    let alice = id(1);
    state.insert(funded_account(alice, 10_000));
    for i in 2..=5u8 {
        state.insert(Account::new(id(i)));
    }

    let vm = NVm::with_defaults();

    // Alice sends 4 sequential transfers
    let txs = vec![
        make_tx(alice.0, native_transfer_payload(id(2), 100)),
        make_tx(alice.0, native_transfer_payload(id(3), 100)),
        make_tx(alice.0, native_transfer_payload(id(4), 100)),
        make_tx(alice.0, native_transfer_payload(id(5), 100)),
    ];

    let mut state_serial = state.clone();
    let mut state_parallel = state.clone();

    let receipts_serial = vm.execute_block(&mut state_serial, &txs, 0);
    let receipts_parallel = vm.execute_block_parallel(&mut state_parallel, &txs, 0);

    // All should succeed
    for (i, (rs, rp)) in receipts_serial
        .iter()
        .zip(receipts_parallel.iter())
        .enumerate()
    {
        assert_eq!(rs.success, rp.success, "tx {i} success mismatch");
    }

    assert_eq!(
        state_serial.compute_root(),
        state_parallel.compute_root(),
        "state roots diverge for same-sender ordering"
    );
}

#[test]
fn parallel_handles_failing_tx() {
    let mut state = StateTree::new();
    let alice = id(1);
    state.insert(funded_account(alice, 100));
    let bob = id(2);
    state.insert(Account::new(bob));
    let charlie = id(3);
    state.insert(funded_account(charlie, 10_000));
    let dave = id(4);
    state.insert(Account::new(dave));

    let vm = NVm::with_defaults();

    let txs = vec![
        // Alice tries to send 999 but only has 100 → should fail
        make_tx(alice.0, native_transfer_payload(bob, 999)),
        // Charlie→Dave independent, should succeed
        make_tx(charlie.0, native_transfer_payload(dave, 500)),
    ];

    let mut state_serial = state.clone();
    let mut state_parallel = state.clone();

    let receipts_serial = vm.execute_block(&mut state_serial, &txs, 0);
    let receipts_parallel = vm.execute_block_parallel(&mut state_parallel, &txs, 0);

    assert!(!receipts_serial[0].success);
    assert!(receipts_serial[1].success);
    assert!(!receipts_parallel[0].success);
    assert!(receipts_parallel[1].success);

    assert_eq!(state_serial.compute_root(), state_parallel.compute_root(),);
}

#[test]
fn parallel_batching_stats() {
    // Verify batching produces fewer batches than total txs for independent txs
    let txs: Vec<Transaction> = (0..8u8)
        .map(|i| {
            let sender = id(i * 2 + 1);
            let recipient = id(i * 2 + 2);
            make_tx(sender.0, native_transfer_payload(recipient, 100))
        })
        .collect();
    let batches = build_batches(&txs);
    assert_eq!(batches.len(), 1, "8 independent txs should form 1 batch");

    // Same-sender chain: should produce N batches
    let alice = id(1);
    let chain_txs: Vec<Transaction> = (0..4u8)
        .map(|i| make_tx(alice.0, native_transfer_payload(id(10 + i), 10)))
        .collect();
    let chain_batches = build_batches(&chain_txs);
    assert_eq!(
        chain_batches.len(),
        4,
        "4 same-sender txs should form 4 batches"
    );
}

#[test]
fn write_set_move_transfer_is_accounts_not_global() {
    let alice = id(1);
    let bob = id(2);
    let tx = make_tx(alice.0, move_transfer_payload(bob, 0));
    match extract_write_set(&tx) {
        WriteSet::Accounts(set) => {
            assert!(set.contains(&alice), "sender must be in write set");
            assert!(set.contains(&bob), "recipient must be in write set");
            assert_eq!(set.len(), 2);
        }
        WriteSet::Global => panic!("Move transfer should not acquire Global lock"),
    }
}

#[test]
fn write_set_move_non_transfer_is_global() {
    let alice = id(1);
    let tx = make_tx(alice.0, move_payload()); // function = "call"
    match extract_write_set(&tx) {
        WriteSet::Global => {}
        WriteSet::Accounts(_) => panic!("non-transfer Move should use Global lock"),
    }
}

#[test]
fn move_transfers_parallelize() {
    // 4 independent Move transfers (different senders/recipients) should
    // fit in a single parallel batch.
    let txs: Vec<Transaction> = (0..4u8)
        .map(|i| {
            let sender = id(i * 2 + 1);
            let recipient = id(i * 2 + 2);
            make_tx(sender.0, move_transfer_payload(recipient, 0))
        })
        .collect();
    let batches = build_batches(&txs);
    assert_eq!(
        batches.len(),
        1,
        "4 independent Move transfers should form 1 batch"
    );
}
