//! Tests for MockSvmEngine and syscalls.

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_n_vm::svm::syscall::all_syscalls;
use ace_n_vm::svm::{MockSvmEngine, OP_SVM_INVOKE, OP_SVM_TRANSFER};
use ace_n_vm::vm::{VmEngine, VmId};
use ace_runtime::crypto::TaggedSignature;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::transaction::Transaction;
use sha2::{Digest, Sha256};

fn make_tx(sender_id: [u8; 32], payload: Vec<u8>) -> Transaction {
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
            domain: Domain::new(1, 0),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
    )
}

#[test]
fn svm_engine_id_and_name() {
    let engine = MockSvmEngine;
    assert_eq!(engine.vm_id(), VmId::Svm);
    assert_eq!(engine.name(), "Mock SVM (BPF)");
}

#[test]
fn svm_invoke_succeeds() {
    let mut state = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    state.insert(Account::new(alice));

    let engine = MockSvmEngine;
    let tx = make_tx(alice.0, vec![OP_SVM_INVOKE, 0xDD]);
    let receipt = engine.execute(&mut state, &tx).unwrap();
    assert!(receipt.success);
    assert_eq!(receipt.vm_id, VmId::Svm);
}

#[test]
fn svm_transfer_succeeds() {
    let mut state = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    state.insert(Account::new(alice));

    let engine = MockSvmEngine;
    let tx = make_tx(alice.0, vec![OP_SVM_TRANSFER, 0xEE]);
    let receipt = engine.execute(&mut state, &tx).unwrap();
    assert!(receipt.success);
}

#[test]
fn svm_unsupported_opcode() {
    let mut state = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    state.insert(Account::new(alice));

    let engine = MockSvmEngine;
    // 0x2F is in SVM range but not a known sub-opcode
    let tx = make_tx(alice.0, vec![0x2F]);
    let err = engine.execute(&mut state, &tx).unwrap_err();
    assert!(err.to_string().contains("unsupported SVM opcode"));
}

#[test]
#[cfg(feature = "mock-precompile")]
fn syscall_stubs_all_succeed() {
    let syscalls = all_syscalls();
    assert_eq!(syscalls.len(), 4);

    let expected_names = [
        "attest_check",
        "id_com_verify",
        "cross_vm_call",
        "resolve_evm_address",
    ];
    for (i, sc) in syscalls.iter().enumerate() {
        assert_eq!(sc.name(), expected_names[i]);
        let result = sc.execute(&[0x00]).unwrap();
        assert_eq!(result, vec![0xFF, 0x00], "mock marker expected");
    }
}
