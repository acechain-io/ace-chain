#![cfg(feature = "test-utils")]

mod support;

use ace_runtime::config;
use ace_runtime::consensus::finality::{FinalityAction, FinalityEvent, FinalityStateMachine};
use ace_runtime::consensus::timeout::{TimeoutPhase, TimeoutProtocol, WitnessAvailability};
use ace_runtime::crypto::proof::{MockProver, PrivateWitness, ProofVerifier};
use ace_runtime::crypto::TaggedSignature;
use ace_runtime::pipeline::attest::{attest_check, OpenRegistry};
use ace_runtime::pipeline::execute::{compute_state_root, execute_transactions};
use ace_runtime::pipeline::prove::prove_block;
use ace_runtime::types::attestation::Domain;
use ace_runtime::types::block::BlockBuilder;
use ace_runtime::types::finality::FinalityState;
use ace_runtime::types::transaction::Transaction;
use support::{make_test_tx, test_idcom, test_root_secret, test_seed};

fn make_tx_batch(identity_tag: u8, domain: Domain, prefix: &str, count: usize) -> Vec<Transaction> {
    (0..count)
        .map(|i| {
            let payload = format!("{prefix}-{i}");
            make_test_tx(
                &test_seed(identity_tag),
                test_idcom(identity_tag, domain),
                payload.as_bytes(),
                domain,
            )
        })
        .collect()
}

fn make_witnesses(identity_tag: u8, count: usize) -> Vec<PrivateWitness> {
    (0..count)
        .map(|_| PrivateWitness {
            root_secret: test_root_secret(identity_tag),
            salt: [0u8; 32],
            alg_id: 0,
            index: 0,
            nonce: 0,
        })
        .collect()
}

#[test]
fn test_end_to_end_happy_path() {
    let domain = Domain::new(1, 1000);
    let prover = MockProver::new();
    let txs = make_tx_batch(42, domain, "e2e-tx", 20);

    let check_result = attest_check(txs, &domain, &OpenRegistry);
    assert_eq!(check_result.valid.len(), 20);
    assert_eq!(check_result.rejected.len(), 0);

    let deltas = execute_transactions(&check_result.valid);
    assert_eq!(deltas.len(), 20);
    assert!(deltas.iter().all(|d| d.success));

    let state_root = compute_state_root(&deltas);
    let leader_idcom = [0xAA; 32];
    let mut builder = BlockBuilder::new(1000, [0u8; 32], [0u8; 32], leader_idcom);
    for tx in &check_result.valid {
        builder.add_transaction(tx.clone()).unwrap();
    }
    let block = builder.build(state_root, 1710000000000);

    let fc = prove_block(&block, &prover, &make_witnesses(42, 20)).unwrap();
    assert_eq!(fc.slot, 1000);
    assert_eq!(fc.block_hash, block.hash());
    assert!(fc.is_well_formed());
    assert!(prover.verify_finality_certificate(&fc));

    let mut fsm = FinalityStateMachine::new(1000);
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

    let action = fsm.on_event(
        FinalityEvent::FinalityCertReceived { certificate: fc },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Hard);
    assert_eq!(action, FinalityAction::None);
    assert!(!fsm.is_builder_slashed());
}

#[test]
fn test_end_to_end_builder_failure_backup_recovery() {
    let domain = Domain::new(1, 500);
    let prover = MockProver::new();
    let txs = make_tx_batch(88, domain, "backup-tx", 5);

    let check_result = attest_check(txs, &domain, &OpenRegistry);
    let deltas = execute_transactions(&check_result.valid);
    let state_root = compute_state_root(&deltas);

    let mut builder = BlockBuilder::new(500, [0u8; 32], [0u8; 32], [0u8; 32]);
    for tx in &check_result.valid {
        builder.add_transaction(tx.clone()).unwrap();
    }
    let block = builder.build(state_root, 0);

    let mut fsm = FinalityStateMachine::new(500);
    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 100,
            total_stake: 100,
            block_hash: block.hash(),
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Soft);

    let mut tp = TimeoutProtocol::new(500);
    assert!(tp.is_builder_expired(504));
    assert_eq!(tp.phase(504), TimeoutPhase::BackupWindow);

    let action = fsm.on_event(FinalityEvent::BuilderTimeout, &prover);
    assert_eq!(fsm.state(), FinalityState::BackupWait);
    assert_eq!(action, FinalityAction::SlashBuilder);
    assert!(fsm.is_builder_slashed());

    let mut wa = WitnessAvailability::new(100);
    for i in 0..67u64 {
        wa.record_receipt(i);
    }
    assert!(wa.is_available());

    let fc = prove_block(&block, &prover, &make_witnesses(88, 5)).unwrap();
    let action = fsm.on_event(
        FinalityEvent::FinalityCertReceived { certificate: fc },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Hard);
    assert_eq!(action, FinalityAction::None);

    tp.resolve();
    assert_eq!(tp.phase(510), TimeoutPhase::Resolved);
}

#[test]
fn test_end_to_end_full_timeout_rollback() {
    let prover = MockProver::new();
    let mut fsm = FinalityStateMachine::new(200);
    let tp = TimeoutProtocol::new(200);

    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 80,
            total_stake: 100,
            block_hash: [0u8; 32],
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Soft);

    let action = fsm.on_event(FinalityEvent::BuilderTimeout, &prover);
    assert_eq!(fsm.state(), FinalityState::BackupWait);
    assert_eq!(action, FinalityAction::SlashBuilder);

    assert!(tp.is_builder_expired(204));
    assert!(!tp.is_fully_expired(204));
    assert_eq!(tp.phase(204), TimeoutPhase::BackupWindow);

    assert!(tp.is_fully_expired(207));
    assert_eq!(tp.phase(207), TimeoutPhase::Expired);

    let action = fsm.on_event(FinalityEvent::BackupTimeout, &prover);
    assert_eq!(fsm.state(), FinalityState::RolledBack);
    assert_eq!(action, FinalityAction::RequeueTxs);

    let action = fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 100,
            total_stake: 100,
            block_hash: [0u8; 32],
        },
        &prover,
    );
    assert_eq!(action, FinalityAction::None);
    assert_eq!(fsm.state(), FinalityState::RolledBack);
}

#[test]
fn test_wire_size_compliance() {
    use ace_runtime::types::attestation::Attestation;
    use ace_runtime::types::block::BlockHeader;

    assert_eq!(BlockHeader::APPROX_WIRE_SIZE, 256);

    let attestation = Attestation {
        obj_hash: [0u8; 32],
        idcom: [0u8; 32],
        domain: Domain::new(1, 0),
        context_tag: [0u8; 16],
        credential: TaggedSignature::ed25519([0u8; 64]),
    };
    // Ed25519 attestation: 32 + 32 + 8 + 16 (context_tag) + 1 (alg_tag) + 2 (sig_len) + 64 = 155
    assert_eq!(attestation.wire_size(), 155);
    let tx = Transaction::new(vec![0u8; 140], attestation);
    // wire_size = payload(140) + attestation(155) = 295
    assert_eq!(tx.wire_size(), 295);

    // HMAC-SHA256 attestation: 32 + 32 + 8 + 16 (context_tag) + 1 (alg_tag) + 2 (sig_len) + 32 = 123
    let hmac_att = Attestation {
        obj_hash: [0u8; 32],
        idcom: [0u8; 32],
        domain: Domain::new(1, 0),
        context_tag: [0u8; 16],
        credential: TaggedSignature::hmac_sha256([0u8; 32]),
    };
    assert_eq!(hmac_att.wire_size(), 123);
    let hmac_tx = Transaction::new(vec![0u8; 140], hmac_att);
    // wire_size = payload(140) + attestation(123) = 263  (32 bytes saved vs Ed25519)
    assert_eq!(hmac_tx.wire_size(), 263);
}

#[test]
fn test_timing_constants() {
    assert!(
        config::SLOT_DURATION_MS == 400
            || config::SLOT_DURATION_MS == 800
            || config::SLOT_DURATION_MS == 1000
    );
    assert_eq!(config::K_BUILDER_SLOTS, 3);
    assert_eq!(config::K_BACKUP_SLOTS, 3);
    assert_eq!(
        config::BUILDER_TIMEOUT_MS,
        config::K_BUILDER_SLOTS * config::SLOT_DURATION_MS
    );
    assert_eq!(
        config::TOTAL_TIMEOUT_MS,
        (config::K_BUILDER_SLOTS + config::K_BACKUP_SLOTS) * config::SLOT_DURATION_MS
    );
    assert_eq!(config::MAX_PROOF_BUNDLE_ENTRIES, 1536);
    assert_eq!(config::MAX_TXS_PER_BLOCK, 80_000);
    assert_eq!(config::MAX_BLOCK_BYTES, 32 * 1024 * 1024);
    assert_eq!(config::MAX_P2P_MESSAGE_BYTES, 64 * 1024 * 1024);
    assert_eq!(config::MOCK_PROOF_BYTES, 256);
}

#[test]
fn test_cross_context_isolation() {
    let seed = test_seed(55);
    let payload = b"cross-context-tx";
    let domain_treasury = Domain::new(1, 100);
    let domain_payroll = Domain::new(2, 100);

    let tx_treasury = make_test_tx(
        &seed,
        test_idcom(55, domain_treasury),
        payload,
        domain_treasury,
    );
    let tx_payroll = make_test_tx(
        &seed,
        test_idcom(55, domain_payroll),
        payload,
        domain_payroll,
    );

    assert_ne!(
        tx_treasury.attestation.credential,
        tx_payroll.attestation.credential
    );
    assert_ne!(tx_treasury.attestation.idcom, tx_payroll.attestation.idcom);
}
