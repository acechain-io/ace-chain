#![cfg(feature = "test-utils")]

mod support;

use ace_runtime::crypto::proof::{
    compute_statement_root, MockProver, PrivateWitness, ProofVerifier,
};
use ace_runtime::crypto::TaggedSignature;
use ace_runtime::pipeline::attest::{
    attest_check, attest_check_sequential, HashSetRegistry, OpenRegistry, RejectReason,
};
use ace_runtime::pipeline::execute::{compute_state_root, execute_transactions};
use ace_runtime::pipeline::prove::prove_block;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::block::BlockBuilder;
use ace_runtime::types::transaction::Transaction;
use support::{
    auth_pubkey_for, make_mock_witness, make_test_tx, payload_hash, test_idcom, test_root_secret,
    test_seed,
};

fn make_valid_tx(identity_tag: u8, payload: &[u8], domain: Domain) -> Transaction {
    make_test_tx(
        &test_seed(identity_tag),
        test_idcom(identity_tag, domain),
        payload,
        domain,
    )
}

fn make_invalid_hash_tx(domain: Domain) -> Transaction {
    let attestation = Attestation {
        obj_hash: [0xFF; 32],
        idcom: [0u8; 32],
        domain,
        context_tag: [0u8; 16],
        credential: TaggedSignature::ed25519([0u8; 64]),
    };
    Transaction::new(b"some payload".to_vec(), attestation)
}

#[test]
fn test_attest_check_valid_transactions() {
    let domain = Domain::new(1, 100);
    let txs = vec![
        make_valid_tx(1, b"tx-1", domain),
        make_valid_tx(1, b"tx-2", domain),
        make_valid_tx(1, b"tx-3", domain),
    ];

    let result = attest_check(txs, &domain, &OpenRegistry);
    assert_eq!(result.valid.len(), 3);
    assert_eq!(result.rejected.len(), 0);
}

#[test]
fn test_attest_check_rejects_invalid_hash() {
    let domain = Domain::new(1, 100);
    let txs = vec![
        make_valid_tx(1, b"valid-tx", domain),
        make_invalid_hash_tx(domain),
    ];

    let result = attest_check(txs, &domain, &OpenRegistry);
    assert_eq!(result.valid.len(), 1);
    assert_eq!(result.rejected.len(), 1);
    assert_eq!(result.rejected[0].1, RejectReason::PayloadBindingMismatch);
}

#[test]
fn test_attest_check_rejects_wrong_domain() {
    let domain = Domain::new(1, 100);
    let wrong_domain = Domain::new(1, 999);
    let txs = vec![
        make_valid_tx(1, b"tx-1", domain),
        make_valid_tx(1, b"tx-wrong-domain", wrong_domain),
    ];

    let result = attest_check(txs, &domain, &OpenRegistry);
    assert_eq!(result.valid.len(), 1);
    assert_eq!(result.rejected.len(), 1);
    assert_eq!(result.rejected[0].1, RejectReason::DomainMismatch);
}

#[test]
fn test_attest_check_rejects_empty_payload() {
    let domain = Domain::new(1, 100);
    let attestation = Attestation {
        obj_hash: [0u8; 32],
        idcom: [0u8; 32],
        domain,
        context_tag: [0u8; 16],
        credential: TaggedSignature::ed25519([0u8; 64]),
    };
    let tx = Transaction::new(vec![], attestation);

    let result = attest_check(vec![tx], &domain, &OpenRegistry);
    assert_eq!(result.valid.len(), 0);
    assert_eq!(result.rejected.len(), 1);
    assert_eq!(result.rejected[0].1, RejectReason::EmptyPayload);
}

#[test]
fn test_attest_check_parallel_consistency() {
    let domain = Domain::new(1, 50);
    let txs: Vec<Transaction> = (0..100)
        .map(|i| make_valid_tx(42, format!("transaction-{i}").as_bytes(), domain))
        .collect();

    let par_result = attest_check(txs.clone(), &domain, &OpenRegistry);
    let seq_result = attest_check_sequential(txs, &domain, &OpenRegistry);

    assert_eq!(par_result.valid.len(), seq_result.valid.len());
    assert_eq!(par_result.rejected.len(), seq_result.rejected.len());
}

#[test]
fn test_attest_check_rejects_hmac_credentials_consistently() {
    let domain = Domain::new(1, 77);
    let payload = b"hmac-native-tx";
    let idcom = test_idcom(9, domain);
    let tx = Transaction::new(
        payload.to_vec(),
        Attestation {
            obj_hash: payload_hash(payload),
            idcom,
            domain,
            context_tag: [0u8; 16],
            credential: TaggedSignature::hmac_sha256([0xAB; 32]),
        },
    );

    let mut registry = HashSetRegistry::new();
    registry.register_with_pubkey(idcom, auth_pubkey_for(9));

    let par_result = attest_check(vec![tx.clone()], &domain, &registry);
    let seq_result = attest_check_sequential(vec![tx], &domain, &registry);

    assert_eq!(par_result.valid.len(), 0);
    assert_eq!(seq_result.valid.len(), 0);
    assert_eq!(par_result.rejected.len(), 1);
    assert_eq!(seq_result.rejected.len(), 1);
    assert_eq!(par_result.rejected[0].1, RejectReason::InvalidCredential);
    assert_eq!(seq_result.rejected[0].1, RejectReason::InvalidCredential);
}

#[test]
fn test_execute_transactions() {
    let domain = Domain::new(1, 100);
    let txs = vec![
        make_valid_tx(1, b"tx-1", domain),
        make_valid_tx(1, b"tx-2", domain),
    ];
    let deltas = execute_transactions(&txs);

    assert_eq!(deltas.len(), 2);
    assert!(deltas[0].success);
    assert!(deltas[1].success);
    assert_ne!(deltas[0].delta_hash, deltas[1].delta_hash);
}

#[test]
fn test_execute_deterministic() {
    let domain = Domain::new(1, 100);
    let txs = vec![make_valid_tx(1, b"same-payload", domain)];

    let deltas1 = execute_transactions(&txs);
    let deltas2 = execute_transactions(&txs);

    assert_eq!(deltas1[0].delta_hash, deltas2[0].delta_hash);
}

#[test]
fn test_compute_state_root() {
    let domain = Domain::new(1, 100);
    let txs = vec![
        make_valid_tx(1, b"tx-1", domain),
        make_valid_tx(1, b"tx-2", domain),
        make_valid_tx(1, b"tx-3", domain),
    ];

    let deltas = execute_transactions(&txs);
    let root = compute_state_root(&deltas);
    let root2 = compute_state_root(&deltas);

    assert_ne!(root, [0u8; 32]);
    assert_eq!(root, root2);
}

#[test]
fn test_compute_state_root_empty() {
    assert_eq!(compute_state_root(&[]), [0u8; 32]);
}

#[test]
fn test_prove_block_single_tx() {
    let domain = Domain::new(1, 100);
    let tx = make_valid_tx(1, b"single-transaction", domain);
    let mut builder = BlockBuilder::new(100, [0u8; 32], [0u8; 32], [0u8; 32]);
    builder.add_transaction(tx).unwrap();
    let block = builder.build([0u8; 32], 0);

    let witnesses = vec![PrivateWitness {
        root_secret: test_root_secret(1),
        salt: [0u8; 32],
        alg_id: 0,
        index: 0,
        nonce: 0,
    }];

    let prover = MockProver::new();
    let fc = prove_block(&block, &prover, &witnesses).unwrap();

    assert_eq!(fc.slot, 100);
    assert_eq!(fc.block_hash, block.hash());
    assert_eq!(fc.tx_count, 1);
    assert_eq!(fc.statement_root, compute_statement_root(&block));
    assert!(fc.is_well_formed());
    assert!(prover.verify_finality_certificate_for_block(&fc, &block));
}

#[test]
fn test_prove_block_aggregation() {
    let domain = Domain::new(1, 100);
    let mut builder = BlockBuilder::new(100, [0u8; 32], [0u8; 32], [0u8; 32]);
    let mut witnesses = Vec::new();

    for i in 0..8 {
        let payload = format!("tx-{i}");
        builder
            .add_transaction(make_valid_tx(1, payload.as_bytes(), domain))
            .unwrap();
        witnesses.push(make_mock_witness(1));
    }

    let block = builder.build([0u8; 32], 0);
    let prover = MockProver::new();
    let fc = prove_block(&block, &prover, &witnesses).unwrap();

    assert_eq!(fc.slot, 100);
    assert_eq!(fc.tx_count, 8);
    assert_eq!(fc.statement_root, compute_statement_root(&block));
    assert!(fc.is_well_formed());
    assert!(prover.verify_finality_certificate_for_block(&fc, &block));
}

#[test]
fn test_prove_block_odd_number_of_txs() {
    let domain = Domain::new(1, 100);
    let mut builder = BlockBuilder::new(100, [0u8; 32], [0u8; 32], [0u8; 32]);
    let mut witnesses = Vec::new();

    for i in 0..5 {
        let payload = format!("tx-{i}");
        builder
            .add_transaction(make_valid_tx(1, payload.as_bytes(), domain))
            .unwrap();
        witnesses.push(make_mock_witness(1));
    }

    let block = builder.build([0u8; 32], 0);
    let prover = MockProver::new();
    let fc = prove_block(&block, &prover, &witnesses).unwrap();

    assert_eq!(fc.tx_count, 5);
    assert_eq!(fc.statement_root, compute_statement_root(&block));
    assert!(fc.is_well_formed());
    assert!(prover.verify_finality_certificate_for_block(&fc, &block));
}

#[test]
fn test_prove_empty_block() {
    let builder = BlockBuilder::new(0, [0u8; 32], [0u8; 32], [0u8; 32]);
    let block = builder.build([0u8; 32], 0);

    let prover = MockProver::new();
    let fc = prove_block(&block, &prover, &[]).unwrap();

    assert_eq!(fc.slot, 0);
    assert_eq!(fc.id_com_commitment, [0u8; 32]);
    assert_eq!(fc.statement_root, [0u8; 32]);
    assert_eq!(fc.tx_count, 0);
    assert!(prover.verify_finality_certificate_for_block(&fc, &block));
}

#[test]
fn test_full_pipeline_flow() {
    let domain = Domain::new(1, 500);
    let txs: Vec<Transaction> = (0..10)
        .map(|i| make_valid_tx(77, format!("pipeline-tx-{i}").as_bytes(), domain))
        .collect();

    let check_result = attest_check(txs, &domain, &OpenRegistry);
    assert_eq!(check_result.valid.len(), 10);
    assert_eq!(check_result.rejected.len(), 0);

    let deltas = execute_transactions(&check_result.valid);
    assert_eq!(deltas.len(), 10);
    assert!(deltas.iter().all(|d| d.success));

    let state_root = compute_state_root(&deltas);
    let mut builder = BlockBuilder::new(500, [0u8; 32], [0u8; 32], [0u8; 32]);
    for tx in &check_result.valid {
        builder.add_transaction(tx.clone()).unwrap();
    }
    let block = builder.build(state_root, 1234567890);

    let witnesses: Vec<PrivateWitness> = (0..10).map(|_| make_mock_witness(77)).collect();
    let prover = MockProver::new();
    let fc = prove_block(&block, &prover, &witnesses).unwrap();

    assert_eq!(fc.slot, 500);
    assert_eq!(fc.block_hash, block.hash());
    assert_eq!(fc.tx_count, 10);
    assert_eq!(fc.statement_root, compute_statement_root(&block));
    assert!(fc.is_well_formed());
    assert!(prover.verify_finality_certificate(&fc));
    assert!(prover.verify_finality_certificate_for_block(&fc, &block));
}

#[test]
fn test_attest_check_rejects_unregistered_identity() {
    let domain = Domain::new(1, 100);
    let txs: Vec<Transaction> = (0..3)
        .map(|i| make_valid_tx(1, format!("identity-tx-{i}").as_bytes(), domain))
        .collect();

    let mut registry = HashSetRegistry::new();
    registry.register(txs[0].attestation.idcom);

    let result = attest_check(txs, &domain, &registry);
    assert_eq!(result.valid.len(), 3);
    assert_eq!(result.rejected.len(), 0);
}

#[test]
fn test_attest_check_rejects_foreign_identity() {
    let domain = Domain::new(1, 100);
    let tx_alice = make_valid_tx(1, b"alice-tx", domain);
    let tx_bob = make_valid_tx(2, b"bob-tx", domain);

    let mut registry = HashSetRegistry::new();
    registry.register(tx_alice.attestation.idcom);

    let result = attest_check(vec![tx_alice, tx_bob], &domain, &registry);
    assert_eq!(result.valid.len(), 1);
    assert_eq!(result.rejected.len(), 1);
    assert_eq!(result.rejected[0].1, RejectReason::UnregisteredIdentity);
}
