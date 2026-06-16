//! Tests for BVM engine: transfers, script execution, and UTXO spending.

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_n_vm::bvm::engine::BvmEngine;
use ace_n_vm::bvm::utxo::{Utxo, UtxoState};
use ace_n_vm::bvm::{MockBvmEngine, OP_BVM_SCRIPT_EXEC, OP_BVM_TRANSFER, OP_BVM_UTXO_SPEND};
use ace_n_vm::vm::{VmEngine, VmId, VmReceipt};
use ace_runtime::crypto::TaggedSignature;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::transaction::Transaction;
use sha2::{Digest, Sha256};

fn make_tx(sender_id: [u8; 32], payload: Vec<u8>) -> Transaction {
    make_tx_with_domain(sender_id, payload, Domain::new(1, 0))
}

fn make_tx_with_domain(sender_id: [u8; 32], payload: Vec<u8>, domain: Domain) -> Transaction {
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let result = hasher.finalize();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&result);

    Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom: sender_id,
            domain,
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
    )
}

fn output_txid(receipt: &VmReceipt) -> [u8; 32] {
    let data = receipt
        .return_data
        .as_ref()
        .expect("BVM output txid should be present");
    let mut txid = [0u8; 32];
    txid.copy_from_slice(data);
    txid
}

fn bvm_transfer_payload(to: [u8; 32], nonce: u64, value: u64) -> Vec<u8> {
    let mut payload = vec![OP_BVM_TRANSFER];
    payload.extend_from_slice(&nonce.to_le_bytes());
    payload.extend_from_slice(&to);
    payload.extend_from_slice(&value.to_le_bytes());
    payload
}

fn bvm_script_payload(nonce: u64, script: &[u8]) -> Vec<u8> {
    let mut payload = vec![OP_BVM_SCRIPT_EXEC];
    payload.extend_from_slice(&nonce.to_le_bytes());
    payload.extend_from_slice(&(script.len() as u32).to_le_bytes());
    payload.extend_from_slice(script);
    payload
}

// ---------------------------------------------------------------------------
// MockBvmEngine tests
// ---------------------------------------------------------------------------

#[test]
fn mock_bvm_engine_id_and_name() {
    let engine = MockBvmEngine;
    assert_eq!(engine.vm_id(), VmId::Bvm);
    assert_eq!(engine.name(), "Mock BVM (Bitcoin Script)");
}

#[test]
fn mock_bvm_transfer_succeeds() {
    let mut state = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    state.insert(Account::new(alice));

    let engine = MockBvmEngine;
    let tx = make_tx(alice.0, vec![OP_BVM_TRANSFER, 0xAA]);
    let receipt = engine.execute(&mut state, &tx).unwrap();
    assert!(receipt.success);
    assert!(receipt.simulated);
    assert_eq!(receipt.vm_id, VmId::Bvm);
}

#[test]
fn mock_bvm_unsupported_opcode() {
    let mut state = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    state.insert(Account::new(alice));

    let engine = MockBvmEngine;
    let tx = make_tx(alice.0, vec![0x3F]);
    let err = engine.execute(&mut state, &tx).unwrap_err();
    assert!(err.to_string().contains("unsupported BVM opcode"));
}

// ---------------------------------------------------------------------------
// Real BvmEngine — transfer tests
// ---------------------------------------------------------------------------

#[test]
fn bvm_transfer_basic() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let bob_bytes = [2u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);
    let bob = AccountId::from_bytes(bob_bytes);

    let mut alice_acct = Account::new(alice);
    alice_acct.balance = 1000;
    state.insert(alice_acct);

    let engine = BvmEngine;
    let value: u64 = 250;
    let tx = make_tx(alice_bytes, bvm_transfer_payload(bob_bytes, 0, value));
    let receipt = engine.execute(&mut state, &tx).unwrap();
    assert!(receipt.success);
    assert!(!receipt.simulated);

    // Check balances
    assert_eq!(state.get(&alice).unwrap().balance, 750);
    assert_eq!(state.get(&bob).unwrap().balance, 250);
    // Sender nonce incremented
    assert_eq!(state.get(&alice).unwrap().nonce, 1);
}

#[test]
fn bvm_transfer_insufficient_balance() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let bob_bytes = [2u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);

    let mut alice_acct = Account::new(alice);
    alice_acct.balance = 100;
    state.insert(alice_acct);

    let engine = BvmEngine;
    let value: u64 = 500;
    let tx = make_tx(alice_bytes, bvm_transfer_payload(bob_bytes, 0, value));
    let err = engine.execute(&mut state, &tx).unwrap_err();
    assert!(err.to_string().contains("insufficient balance"));
}

#[test]
fn bvm_transfer_zero_value() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let bob_bytes = [2u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);

    let mut alice_acct = Account::new(alice);
    alice_acct.balance = 1000;
    state.insert(alice_acct);

    let engine = BvmEngine;
    let value: u64 = 0;
    let tx = make_tx(alice_bytes, bvm_transfer_payload(bob_bytes, 0, value));
    let err = engine.execute(&mut state, &tx).unwrap_err();
    assert!(err.to_string().contains("non-zero"));
}

#[test]
fn bvm_transfer_payload_too_short() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);
    state.insert(Account::new(alice));

    let engine = BvmEngine;
    let tx = make_tx(alice_bytes, vec![OP_BVM_TRANSFER; 10]);
    let err = engine.execute(&mut state, &tx).unwrap_err();
    assert!(err.to_string().contains("too short"));
}

// ---------------------------------------------------------------------------
// Real BvmEngine — script_exec tests
// ---------------------------------------------------------------------------

#[test]
fn bvm_script_exec_op_true() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);

    let mut alice_acct = Account::new(alice);
    alice_acct.balance = 100;
    state.insert(alice_acct);

    let engine = BvmEngine;
    // Script: OP_1 (0x51) — pushes true onto stack
    let script = vec![0x51];
    let tx = make_tx(alice_bytes, bvm_script_payload(0, &script));
    let receipt = engine.execute(&mut state, &tx).unwrap();
    assert!(receipt.success);
    // Nonce should be incremented
    assert_eq!(state.get(&alice).unwrap().nonce, 1);
}

#[test]
fn bvm_script_exec_op_false() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);

    let mut alice_acct = Account::new(alice);
    alice_acct.balance = 100;
    state.insert(alice_acct);

    let engine = BvmEngine;
    // Script: OP_0 (0x00) — pushes false/empty onto stack
    let script = vec![0x00];
    let tx = make_tx(alice_bytes, bvm_script_payload(0, &script));
    let err = engine.execute(&mut state, &tx).unwrap_err();
    assert!(err.to_string().contains("false"));
}

#[test]
fn bvm_script_exec_arithmetic() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);
    state.insert(Account::new(alice));

    let engine = BvmEngine;
    // Script: OP_2 OP_3 OP_ADD OP_5 OP_EQUAL → true
    let script = vec![0x52, 0x53, 0x93, 0x55, 0x87];
    let tx = make_tx(alice_bytes, bvm_script_payload(0, &script));
    let receipt = engine.execute(&mut state, &tx).unwrap();
    assert!(receipt.success);
}

// ---------------------------------------------------------------------------
// Real BvmEngine — unsupported opcode
// ---------------------------------------------------------------------------

#[test]
fn bvm_unsupported_opcode() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);
    state.insert(Account::new(alice));

    let engine = BvmEngine;
    let tx = make_tx(alice_bytes, vec![0x3F]);
    let err = engine.execute(&mut state, &tx).unwrap_err();
    assert!(err.to_string().contains("unsupported BVM opcode"));
}

// ---------------------------------------------------------------------------
// Real BvmEngine — UTXO transfer and spend round-trip
// ---------------------------------------------------------------------------

#[test]
fn bvm_transfer_creates_utxo_then_visible_in_storage() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let bob_bytes = [2u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);
    let bob = AccountId::from_bytes(bob_bytes);

    let mut alice_acct = Account::new(alice);
    alice_acct.balance = 500;
    state.insert(alice_acct);

    let engine = BvmEngine;
    let value: u64 = 200;
    let tx = make_tx(alice_bytes, bvm_transfer_payload(bob_bytes, 0, value));
    let receipt = engine.execute(&mut state, &tx).unwrap();
    assert!(receipt.success);

    // Bob now has balance and a UTXO stored in his account storage
    assert_eq!(state.get(&bob).unwrap().balance, 200);
    assert_eq!(state.get(&alice).unwrap().balance, 300);
    assert_eq!(UtxoState::utxo_count(&state, &bob), 1);
    assert!(UtxoState::is_unspent(
        &state,
        &bob,
        &output_txid(&receipt),
        0
    ));
}

#[test]
fn bvm_multiple_transfers() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let bob_bytes = [2u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);
    let bob = AccountId::from_bytes(bob_bytes);

    let mut alice_acct = Account::new(alice);
    alice_acct.balance = 1000;
    state.insert(alice_acct);

    let engine = BvmEngine;

    // Transfer 1: 300 to bob
    let payload1 = bvm_transfer_payload(bob_bytes, 0, 300);
    let tx1 = make_tx(alice_bytes, payload1);
    let receipt1 = engine.execute(&mut state, &tx1).unwrap();

    // Transfer 2: 200 to bob
    let payload2 = bvm_transfer_payload(bob_bytes, 1, 200);
    let tx2 = make_tx(alice_bytes, payload2);
    let receipt2 = engine.execute(&mut state, &tx2).unwrap();

    assert_eq!(state.get(&alice).unwrap().balance, 500);
    assert_eq!(state.get(&bob).unwrap().balance, 500);
    assert_eq!(state.get(&alice).unwrap().nonce, 2);
    assert_eq!(UtxoState::utxo_count(&state, &bob), 2);
    assert!(UtxoState::is_unspent(
        &state,
        &bob,
        &output_txid(&receipt1),
        0,
    ));
    assert!(UtxoState::is_unspent(
        &state,
        &bob,
        &output_txid(&receipt2),
        0,
    ));
}

#[test]
fn bvm_replayed_transfer_nonce_is_rejected() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let bob_bytes = [2u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);
    let bob = AccountId::from_bytes(bob_bytes);

    let mut alice_acct = Account::new(alice);
    alice_acct.balance = 1000;
    state.insert(alice_acct);

    let engine = BvmEngine;
    let payload = bvm_transfer_payload(bob_bytes, 0, 200);

    let tx1 = make_tx(alice_bytes, payload.clone());
    let tx2 = make_tx(alice_bytes, payload);

    let receipt1 = engine.execute(&mut state, &tx1).unwrap();
    let err = engine.execute(&mut state, &tx2).unwrap_err();

    assert_eq!(tx1.tx_hash(), tx2.tx_hash());
    assert!(err.to_string().contains("invalid nonce"));
    assert_eq!(state.get(&bob).unwrap().balance, 200);
    assert_eq!(UtxoState::utxo_count(&state, &bob), 1);
    assert!(UtxoState::is_unspent(
        &state,
        &bob,
        &output_txid(&receipt1),
        0
    ));
}

#[test]
fn bvm_utxo_spend_uses_stored_script_pubkey() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);
    state.insert(Account::new(alice));

    let funding_utxo = Utxo {
        txid: [0xAA; 32],
        vout: 0,
        value: 600,
        script_pubkey: vec![0x51], // OP_1
    };
    UtxoState::add_utxo(&mut state, &alice, &funding_utxo).expect("seed utxo");

    let engine = BvmEngine;
    let mut payload = vec![OP_BVM_UTXO_SPEND, 1];
    payload.extend_from_slice(&funding_utxo.txid);
    payload.extend_from_slice(&funding_utxo.vout.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes()); // empty scriptSig
    payload.push(1); // one output
    payload.extend_from_slice(&alice_bytes);
    payload.extend_from_slice(&600u64.to_le_bytes());
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.push(0x51); // OP_1

    let tx = make_tx(alice_bytes, payload);
    let receipt = engine.execute(&mut state, &tx).unwrap();

    assert!(receipt.success);
    assert_eq!(state.get(&alice).unwrap().nonce, 1);
    assert_eq!(state.get(&alice).unwrap().balance, 600);
    assert_eq!(UtxoState::utxo_count(&state, &alice), 1);
    assert!(!UtxoState::is_unspent(
        &state,
        &alice,
        &funding_utxo.txid,
        funding_utxo.vout,
    ));
    assert!(UtxoState::is_unspent(
        &state,
        &alice,
        &output_txid(&receipt),
        0,
    ));
}

#[test]
fn bvm_utxo_spend_rolls_back_on_failure() {
    let mut state = StateTree::new();
    let alice_bytes = [1u8; 32];
    let bob_bytes = [2u8; 32];
    let alice = AccountId::from_bytes(alice_bytes);
    let bob = AccountId::from_bytes(bob_bytes);
    state.insert(Account::new(alice));

    let funding_utxo = Utxo {
        txid: [0xBB; 32],
        vout: 0,
        value: 600,
        script_pubkey: vec![0x51], // OP_1
    };
    UtxoState::add_utxo(&mut state, &alice, &funding_utxo).expect("seed utxo");
    let root_before = state.compute_root();

    let engine = BvmEngine;
    let mut payload = vec![OP_BVM_UTXO_SPEND, 1];
    payload.extend_from_slice(&funding_utxo.txid);
    payload.extend_from_slice(&funding_utxo.vout.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes()); // empty scriptSig
    payload.push(1); // one output
    payload.extend_from_slice(&bob_bytes);
    payload.extend_from_slice(&700u64.to_le_bytes()); // exceeds input value but stays above dust
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.push(0x51); // OP_1

    let tx = make_tx(alice_bytes, payload);
    let err = engine.execute(&mut state, &tx).unwrap_err();

    assert!(err.to_string().contains("insufficient input value"));
    assert_eq!(state.compute_root(), root_before);
    assert_eq!(state.get(&alice).unwrap().balance, 600);
    assert_eq!(state.get(&alice).unwrap().nonce, 0);
    assert_eq!(UtxoState::utxo_count(&state, &alice), 1);
    assert!(UtxoState::is_unspent(
        &state,
        &alice,
        &funding_utxo.txid,
        funding_utxo.vout,
    ));
    assert!(state.get(&bob).is_none());
}
