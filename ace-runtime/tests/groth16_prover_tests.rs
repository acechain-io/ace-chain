#![cfg(feature = "prover")]

mod support;

use ace_runtime::crypto::proof::{
    compute_statement_root, derive_public_inputs, PrivateWitness, ProofProducer, ProofReplayMode,
    ProofVerifier, StarkProver,
};
use ace_runtime::pipeline::execute::{compute_state_root, execute_transactions};
use ace_runtime::pipeline::prove::prove_block;
use ace_runtime::types::attestation::Domain;
use ace_runtime::types::block::BlockBuilder;
use ace_runtime::types::finality::{
    FinalityCertificate, FinalityProofMode, ZkProof, EMPTY_FC_PROOF_HEADER,
};
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use sha2::{Digest, Sha256};
use support::{make_test_attestation, proof_bound_idcom, test_root_secret, test_seed};

fn idcom_commitment(values: &[[u8; 32]]) -> [u8; 32] {
    if values.is_empty() {
        return [0u8; 32];
    }

    let mut hashes: Vec<[u8; 32]> = values
        .iter()
        .map(|idcom| {
            let mut h = Sha256::new();
            h.update(idcom);
            let digest = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            out
        })
        .collect();

    while hashes.len() > 1 {
        let mut next = Vec::with_capacity(hashes.len().div_ceil(2));
        for pair in hashes.chunks(2) {
            let mut h = Sha256::new();
            h.update(pair[0]);
            if pair.len() == 2 {
                h.update(pair[1]);
            } else {
                h.update(pair[0]);
            }
            let digest = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            next.push(out);
        }
        hashes = next;
    }

    hashes[0]
}

fn make_raw_chain_test_tx(tag: u8, payload: &[u8], domain: Domain) -> Transaction {
    let idcom = idcom_commitment(&[[tag; 32]]);
    let att = make_test_attestation(&test_seed(tag), idcom, payload, domain);
    Transaction::with_raw_chain(
        payload.to_vec(),
        att,
        RawChainKind::Evm,
        vec![0x02, tag, 0xA5],
    )
}

#[test]
fn stark_single_proof_roundtrip_and_fc_verify() {
    let prover = StarkProver::new_nonce_registry();
    let domain = Domain::new(1, 100);
    let payload = b"stark-single";
    let root_secret = test_root_secret(0x11);
    let idcom = proof_bound_idcom(root_secret, [0u8; 32], domain);
    let att = make_test_attestation(&test_seed(0x11), idcom, payload, domain);

    let witness = PrivateWitness {
        root_secret,
        salt: [0u8; 32],
        alg_id: 0,
        index: 0,
        nonce: 0,
    };

    let public = derive_public_inputs(
        att.obj_hash,
        att.idcom,
        att.domain.to_bytes(),
        &witness,
        ProofReplayMode::NonceRegistry,
    );
    let proof = prover.prove(&public, &witness);
    assert!(prover.verify(&proof, &public));

    let fc = FinalityCertificate {
        block_hash: [7u8; 32],
        slot: domain.slot as u64,
        proof,
        id_com_commitment: idcom_commitment(&[att.idcom]),
        proof_mode: FinalityProofMode::StarkV1,
        statement_root: [0u8; 32],
        tx_count: 0,
    };

    assert!(prover.verify_finality_certificate(&fc));

    let mut bad_fc = fc.clone();
    bad_fc.id_com_commitment[0] ^= 0x01;
    assert!(!prover.verify_finality_certificate(&bad_fc));
}

#[test]
fn stark_bundle_aggregation_verifies() {
    let prover = StarkProver::new_nonce_registry();
    let domain = Domain::new(1, 200);

    let root_secret_a = test_root_secret(0xA1);
    let root_secret_b = test_root_secret(0xB2);
    let att_a = make_test_attestation(
        &test_seed(0xA1),
        proof_bound_idcom(root_secret_a, [0u8; 32], domain),
        b"tx-a",
        domain,
    );
    let att_b = make_test_attestation(
        &test_seed(0xB2),
        proof_bound_idcom(root_secret_b, [0u8; 32], domain),
        b"tx-b",
        domain,
    );

    let witness_a = PrivateWitness {
        root_secret: root_secret_a,
        salt: [0u8; 32],
        alg_id: 0,
        index: 0,
        nonce: 1,
    };
    let witness_b = PrivateWitness {
        root_secret: root_secret_b,
        salt: [0u8; 32],
        alg_id: 0,
        index: 0,
        nonce: 2,
    };

    let public_a = derive_public_inputs(
        att_a.obj_hash,
        att_a.idcom,
        att_a.domain.to_bytes(),
        &witness_a,
        ProofReplayMode::NonceRegistry,
    );
    let public_b = derive_public_inputs(
        att_b.obj_hash,
        att_b.idcom,
        att_b.domain.to_bytes(),
        &witness_b,
        ProofReplayMode::NonceRegistry,
    );

    let proof_a = prover.prove(&public_a, &witness_a);
    let proof_b = prover.prove(&public_b, &witness_b);
    let aggregated = prover.aggregate(&proof_a, &proof_b);

    let fc = FinalityCertificate {
        block_hash: [9u8; 32],
        slot: domain.slot as u64,
        proof: aggregated,
        id_com_commitment: idcom_commitment(&[att_a.idcom, att_b.idcom]),
        proof_mode: FinalityProofMode::StarkV1,
        statement_root: [0u8; 32],
        tx_count: 0,
    };

    assert!(prover.verify_finality_certificate(&fc));
}

#[test]
fn stark_pipeline_prove_block_roundtrip() {
    let prover = StarkProver::new_nonce_registry();
    let domain = Domain::new(1, 300);
    let root_secret = test_root_secret(0xCC);
    let idcom = proof_bound_idcom(root_secret, [0u8; 32], domain);

    let txs: Vec<Transaction> = (0..3)
        .map(|i| {
            let payload = format!("tx-{i}");
            let att = make_test_attestation(&test_seed(0xCC), idcom, payload.as_bytes(), domain);
            Transaction::new(payload.into_bytes(), att)
        })
        .collect();

    let witnesses: Vec<PrivateWitness> = (0..txs.len())
        .map(|i| PrivateWitness {
            root_secret,
            salt: [0u8; 32],
            alg_id: 0,
            index: i as u64,
            nonce: [i as u8 + 1; 32],
        })
        .collect();

    let deltas = execute_transactions(&txs);
    let state_root = compute_state_root(&deltas);
    let mut builder = BlockBuilder::new(domain.slot as u64, [0u8; 32], [0u8; 32], [0u8; 32]);
    for tx in &txs {
        builder.add_transaction(tx.clone()).expect("tx should fit");
    }
    let block = builder.build(state_root, 0);

    let fc = prove_block(&block, &prover, &witnesses).unwrap();
    assert!(prover.verify_finality_certificate(&fc));
    assert_eq!(fc.tx_count, txs.len() as u32);
    assert_eq!(fc.statement_root, compute_statement_root(&block));
    assert!(prover.verify_finality_certificate_for_block(&fc, &block));
}

#[test]
fn stark_all_raw_chain_block_roundtrip() {
    let prover = StarkProver::new_nonce_registry();
    let domain = Domain::new(1, 400);
    let txs: Vec<Transaction> = (0..2)
        .map(|i| {
            let payload = format!("raw-{i}");
            make_raw_chain_test_tx(0x40 + i as u8, payload.as_bytes(), domain)
        })
        .collect();

    let witnesses = vec![
        PrivateWitness::legacy_dummy(),
        PrivateWitness::legacy_dummy(),
    ];

    let mut builder = BlockBuilder::new(domain.slot as u64, [0u8; 32], [0u8; 32], [0u8; 32]);
    for tx in &txs {
        builder.add_transaction(tx.clone()).expect("tx should fit");
    }
    let block = builder.build([0u8; 32], 0);

    let fc = prove_block(&block, &prover, &witnesses).unwrap();
    assert_eq!(fc.proof.data, EMPTY_FC_PROOF_HEADER.to_vec());
    assert_eq!(fc.id_com_commitment, [0u8; 32]);
    assert_eq!(fc.tx_count, txs.len() as u32);
    assert_eq!(fc.statement_root, compute_statement_root(&block));
    assert!(prover.verify_finality_certificate(&fc));
    assert!(prover.verify_finality_certificate_for_block(&fc, &block));
}

#[test]
fn stark_all_raw_chain_block_rejects_noncanonical_empty_proof() {
    let prover = StarkProver::new_nonce_registry();
    let domain = Domain::new(1, 401);
    let tx = make_raw_chain_test_tx(0x51, b"raw-canonical", domain);
    let witnesses = vec![PrivateWitness::legacy_dummy()];

    let mut builder = BlockBuilder::new(domain.slot as u64, [0u8; 32], [0u8; 32], [0u8; 32]);
    builder.add_transaction(tx).expect("tx should fit");
    let block = builder.build([0u8; 32], 0);

    let mut fc = prove_block(&block, &prover, &witnesses).unwrap();
    fc.proof = ZkProof::from_bytes(vec![0x41, 0x43, 0x50, 0x53, 3, 0, 0, 0, 1]);

    assert!(!prover.verify_finality_certificate(&fc));
    assert!(!prover.verify_finality_certificate_for_block(&fc, &block));
}
