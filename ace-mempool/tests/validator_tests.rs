use ace_engine::executor::{TransactionOp, OP_APPROVE_VALIDATOR};
use ace_mempool::error::MempoolError;
use ace_mempool::validator::TransactionValidator;
use ace_model::account::AccountId;
use ace_runtime::crypto::TaggedSignature;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use sha2::{Digest, Sha256};

fn make_tx_with_hash_and_chain(payload: &[u8], obj_hash: [u8; 32], chain_id: u32) -> Transaction {
    Transaction::new(
        payload.to_vec(),
        Attestation {
            obj_hash,
            idcom: [1u8; 32],
            domain: Domain::new(chain_id, 0),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
    )
}

fn make_tx_with_hash(payload: &[u8], obj_hash: [u8; 32]) -> Transaction {
    make_tx_with_hash_and_chain(payload, obj_hash, 1)
}

fn correct_hash(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let result = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&result);
    h
}

#[test]
fn valid_transaction_accepted() {
    let payload = b"valid payload";
    let tx = make_tx_with_hash(payload, correct_hash(payload));
    assert!(TransactionValidator::validate(&tx, 1, 0).is_ok());
}

#[test]
fn empty_payload_rejected() {
    let tx = make_tx_with_hash(&[], [0u8; 32]);
    let result = TransactionValidator::validate(&tx, 1, 0);
    assert!(matches!(result, Err(MempoolError::EmptyPayload)));
}

#[test]
fn payload_binding_mismatch_rejected() {
    let tx = make_tx_with_hash(b"payload", [0xFFu8; 32]); // Wrong hash
    let result = TransactionValidator::validate(&tx, 1, 0);
    assert!(matches!(result, Err(MempoolError::PayloadBindingMismatch)));
}

#[test]
fn wrong_chain_id_rejected() {
    let payload = b"valid payload";
    let tx = make_tx_with_hash_and_chain(payload, correct_hash(payload), 999);
    let result = TransactionValidator::validate(&tx, 1, 0);
    assert!(matches!(
        result,
        Err(MempoolError::InvalidChainId {
            expected: 1,
            got: 999
        })
    ));
}

#[test]
fn chain_id_zero_skips_check() {
    let payload = b"valid payload";
    let tx = make_tx_with_hash_and_chain(payload, correct_hash(payload), 999);
    // chain_id=0 means skip the check
    assert!(TransactionValidator::validate(&tx, 0, 0).is_ok());
}

#[test]
fn payload_too_large_rejected() {
    let payload = vec![0xABu8; 1024]; // 1 KB payload
    let tx = make_tx_with_hash(&payload, correct_hash(&payload));
    // max_tx_bytes = 100 → rejected
    let result = TransactionValidator::validate(&tx, 1, 100);
    assert!(matches!(
        result,
        Err(MempoolError::PayloadTooLarge { size, max: 100 }) if size == tx.wire_size()
    ));
}

#[test]
fn payload_within_limit_accepted() {
    let payload = b"small payload";
    let tx = make_tx_with_hash(payload, correct_hash(payload));
    // max_tx_bytes = 1000 → accepted
    assert!(TransactionValidator::validate(&tx, 1, 1000).is_ok());
}

#[test]
fn oversized_raw_chain_transaction_rejected_by_wire_size() {
    let payload = b"tiny";
    let tx = Transaction::with_raw_chain(
        payload.to_vec(),
        Attestation {
            obj_hash: correct_hash(payload),
            idcom: [1u8; 32],
            domain: Domain::new(1, 0),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
        RawChainKind::Btc,
        vec![0x42; 2_048],
    );

    let result = TransactionValidator::validate(&tx, 1, 512);
    assert!(matches!(
        result,
        Err(MempoolError::PayloadTooLarge { size, max: 512 }) if size == tx.wire_size()
    ));
}

fn approve_validator_payload(candidate: AccountId, signing_pubkey: Vec<u8>) -> Vec<u8> {
    TransactionOp::ApproveValidator {
        nonce: 1,
        candidate_id_com: candidate,
        signing_pubkey,
    }
    .encode()
}

fn approve_validator_tx(sender: [u8; 32], payload: &[u8]) -> Transaction {
    Transaction::new(
        payload.to_vec(),
        Attestation {
            obj_hash: correct_hash(payload),
            idcom: sender,
            domain: Domain::new(1, 0),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
    )
}

#[test]
fn approve_validator_rejected_when_founder_not_configured() {
    let candidate = AccountId([0xC0; 32]);
    let payload = approve_validator_payload(candidate, vec![0xAB; 32]);
    let tx = approve_validator_tx([0xF0; 32], &payload);

    let err = TransactionValidator::validate_approve_validator(&tx, None).unwrap_err();
    assert!(err.to_string().contains("disabled"));
}

#[test]
fn approve_validator_rejected_for_non_founder_sender() {
    let founder = AccountId([0xF0; 32]);
    let candidate = AccountId([0xC0; 32]);
    let payload = approve_validator_payload(candidate, vec![0xAB; 32]);
    let tx = approve_validator_tx([0x01; 32], &payload);

    let err = TransactionValidator::validate_approve_validator(&tx, Some(founder)).unwrap_err();
    assert!(err.to_string().contains("not the founder"));
}

#[test]
fn approve_validator_accepted_for_founder_sender() {
    let founder = AccountId([0xF0; 32]);
    let candidate = AccountId([0xC0; 32]);
    let payload = approve_validator_payload(candidate, vec![0xAB; 32]);
    let tx = approve_validator_tx(founder.0, &payload);

    assert!(TransactionValidator::validate_approve_validator(&tx, Some(founder)).is_ok());
    assert_eq!(payload.first(), Some(&OP_APPROVE_VALIDATOR));
}
