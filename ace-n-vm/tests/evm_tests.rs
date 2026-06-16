//! Tests for MockEvmEngine, RevmEngine, and precompiles.

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_n_vm::evm::engine::RevmEngine;
use ace_n_vm::evm::precompile::{all_precompiles, PRECOMPILE_BASE};
use ace_n_vm::evm::{MockEvmEngine, OP_EVM_CALL, OP_EVM_CREATE, OP_EVM_TRANSFER};
use ace_n_vm::vm::{VmEngine, VmId};
use ace_runtime::crypto::TaggedSignature;
use ace_runtime::crypto::{legacy_idcom_evm, legacy_idcom_tron};
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use sha2::{Digest, Sha256};

fn make_tx(sender_id: [u8; 32], payload: Vec<u8>) -> Transaction {
    make_tx_with_raw_kind(sender_id, payload, None)
}

fn make_tx_with_raw_kind(
    sender_id: [u8; 32],
    payload: Vec<u8>,
    raw_kind: Option<RawChainKind>,
) -> Transaction {
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let result = hasher.finalize();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&result);

    let attestation = Attestation {
        obj_hash,
        idcom: sender_id,
        domain: Domain::new(1, 0),
        context_tag: [0u8; 16],
        credential: TaggedSignature::ed25519([0u8; 64]),
    };

    match raw_kind {
        Some(kind) => Transaction::with_raw_chain(payload, attestation, kind, vec![0x00]),
        None => Transaction::new(payload, attestation),
    }
}

#[test]
fn evm_engine_id_and_name() {
    let engine = MockEvmEngine;
    assert_eq!(engine.vm_id(), VmId::Evm);
    assert_eq!(engine.name(), "Mock EVM (Shanghai)");
}

#[test]
fn evm_call_succeeds() {
    let mut state = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    state.insert(Account::new(alice));

    let engine = MockEvmEngine;
    let tx = make_tx(alice.0, vec![OP_EVM_CALL, 0xAA]);
    let receipt = engine.execute(&mut state, &tx).unwrap();
    assert!(receipt.success);
    assert_eq!(receipt.vm_id, VmId::Evm);
}

#[test]
fn evm_create_succeeds() {
    let mut state = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    state.insert(Account::new(alice));

    let engine = MockEvmEngine;
    let tx = make_tx(alice.0, vec![OP_EVM_CREATE, 0x00]);
    let receipt = engine.execute(&mut state, &tx).unwrap();
    assert!(receipt.success);
}

#[test]
fn evm_transfer_succeeds() {
    let mut state = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    state.insert(Account::new(alice));

    let engine = MockEvmEngine;
    let tx = make_tx(alice.0, vec![OP_EVM_TRANSFER, 0x01]);
    let receipt = engine.execute(&mut state, &tx).unwrap();
    assert!(receipt.success);
}

#[test]
fn evm_unsupported_opcode() {
    let mut state = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    state.insert(Account::new(alice));

    let engine = MockEvmEngine;
    // 0x1F is in EVM range but not a known sub-opcode
    let tx = make_tx(alice.0, vec![0x1F]);
    let err = engine.execute(&mut state, &tx).unwrap_err();
    assert!(err.to_string().contains("unsupported EVM opcode"));
}

#[test]
#[cfg(feature = "mock-precompile")]
fn precompile_stubs_all_succeed() {
    let precompiles = all_precompiles();
    assert_eq!(precompiles.len(), 8);

    for (i, pc) in precompiles.iter().enumerate() {
        let expected_addr = PRECOMPILE_BASE + i as u16;
        assert_eq!(pc.address(), expected_addr);

        if expected_addr == 0x0106 {
            // CrossVmCall: opcode 0x01 + 20-byte EVM address -> 32-byte ACE AccountId
            let mut input = vec![0x01];
            input.extend_from_slice(&[0xAA; 20]);
            let result = pc.execute(&input).unwrap();
            assert_eq!(result.len(), 32);
        } else if expected_addr == 0x0107 {
            // ResolveSvmAddress: 32-byte ACE AccountId -> 32-byte SVM address
            let result = pc.execute(&[0xBB; 32]).unwrap();
            assert_eq!(result.len(), 32);
        } else {
            let result = pc.execute(&[0x00, 0x01]).unwrap();
            assert_eq!(
                result,
                vec![0xFF, 0x00],
                "mock marker expected for 0x{:04X}",
                expected_addr
            );
        }
    }
}

#[test]
fn revm_transfer_preserves_explicit_raw_evm_addresses() {
    let mut state = StateTree::new();
    let sender_addr = [0x11; 20];
    let sender_id = AccountId::from_bytes(legacy_idcom_evm(&sender_addr));
    let mut sender = Account::with_evm_address(sender_id, sender_addr);
    sender.balance = 1_000;
    state.insert(sender);

    let recipient_addr = [0x22; 20];
    let recipient_id = AccountId::from_bytes(legacy_idcom_evm(&recipient_addr));

    let mut payload = vec![OP_EVM_TRANSFER];
    payload.extend_from_slice(&recipient_addr);
    payload.extend_from_slice(&250u64.to_le_bytes());

    let engine = RevmEngine;
    let receipt = engine
        .execute(&mut state, &make_tx(sender_id.0, payload))
        .unwrap();

    assert!(receipt.success);
    assert_eq!(state.get(&sender_id).unwrap().balance, 750);
    assert_eq!(state.get(&sender_id).unwrap().nonce, 1);
    assert_eq!(state.resolve_evm(&sender_addr), Some(&sender_id));
    assert_eq!(state.resolve_evm(&recipient_addr), Some(&recipient_id));
    assert_eq!(state.evm_address(&recipient_id), Some(recipient_addr));
    assert_eq!(state.get(&recipient_id).unwrap().balance, 250);
}

#[test]
fn revm_create_tracks_contract_under_original_evm_address() {
    let mut state = StateTree::new();
    let sender_addr = [0x33; 20];
    let sender_id = AccountId::from_bytes(legacy_idcom_evm(&sender_addr));
    let mut sender = Account::with_evm_address(sender_id, sender_addr);
    sender.balance = 1_000_000;
    state.insert(sender);

    let init_code = hex::decode("600a600c600039600a6000f3602a60005260206000f3").unwrap();
    let mut payload = vec![OP_EVM_CREATE];
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&200_000u64.to_le_bytes());
    payload.extend_from_slice(&init_code);

    let engine = RevmEngine;
    let receipt = engine
        .execute(&mut state, &make_tx(sender_id.0, payload))
        .unwrap();
    let contract_addr = receipt.contract_address.expect("contract address");
    let contract_id = *state
        .resolve_evm(&contract_addr)
        .expect("contract indexed by canonical address");

    assert!(receipt.success);
    assert!(state.get_code(&contract_id).is_some());
    assert_eq!(state.evm_address(&contract_id), Some(contract_addr));
}

#[test]
fn revm_tron_namespace_keeps_tron_addresses_separate_from_evm() {
    let mut state = StateTree::new();
    let sender_addr = [0x44; 20];
    let sender_id = AccountId::from_bytes(legacy_idcom_tron(&sender_addr));
    let mut sender = Account::with_tron_address(sender_id, sender_addr);
    sender.balance = 100;
    state.insert(sender);

    let recipient_addr = [0x55; 20];
    let recipient_id = AccountId::from_bytes(legacy_idcom_tron(&recipient_addr));

    let mut payload = vec![OP_EVM_TRANSFER];
    payload.extend_from_slice(&recipient_addr);
    payload.extend_from_slice(&40u64.to_le_bytes());

    let engine = RevmEngine;
    let receipt = engine.execute(
        &mut state,
        &make_tx_with_raw_kind(sender_id.0, payload, Some(RawChainKind::Tron)),
    );

    let receipt = receipt.expect("tron transfer");
    assert!(receipt.success);
    assert_eq!(state.resolve_tron(&recipient_addr), Some(&recipient_id));
    assert_eq!(state.resolve_evm(&recipient_addr), None);
    assert_eq!(state.get(&recipient_id).unwrap().balance, 40);
}

#[test]
fn revm_state_diff_rolls_back_when_balance_exceeds_u64() {
    let mut state = StateTree::new();
    let sender_addr = [0x66; 20];
    let sender_id = AccountId::from_bytes(legacy_idcom_evm(&sender_addr));
    let mut sender = Account::with_evm_address(sender_id, sender_addr);
    sender.balance = 10;
    state.insert(sender);

    let recipient_addr = [0x77; 20];
    let recipient_id = AccountId::from_bytes(legacy_idcom_evm(&recipient_addr));
    let mut recipient = Account::with_evm_address(recipient_id, recipient_addr);
    recipient.balance = u64::MAX;
    state.insert(recipient);

    let mut payload = vec![OP_EVM_TRANSFER];
    payload.extend_from_slice(&recipient_addr);
    payload.extend_from_slice(&1u64.to_le_bytes());

    let engine = RevmEngine;
    let err = engine
        .execute(&mut state, &make_tx(sender_id.0, payload))
        .unwrap_err();

    assert!(err.to_string().contains("u64::MAX"));
    assert_eq!(state.get(&sender_id).unwrap().balance, 10);
    assert_eq!(state.get(&sender_id).unwrap().nonce, 0);
    assert_eq!(state.get(&recipient_id).unwrap().balance, u64::MAX);
}
