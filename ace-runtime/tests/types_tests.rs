//! Types module tests: serialization, size bounds, block building.

use ace_runtime::config::{MAX_BLOCK_BYTES, MAX_TXS_PER_BLOCK};
use ace_runtime::crypto::TaggedSignature;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::block::{BlockBuilder, BlockHeader};
use ace_runtime::types::finality::{
    FinalityCertificate, FinalityProofMode, FinalityState, ZkProof,
};
use ace_runtime::types::transaction::Transaction;

// ---------------------------------------------------------------------------
// Domain tests
// ---------------------------------------------------------------------------

#[test]
fn test_domain_serialization() {
    let domain = Domain::new(1, 42);
    let bytes = domain.to_bytes();
    assert_eq!(bytes.len(), 8);
    let recovered = Domain::from_bytes(&bytes);
    assert_eq!(domain, recovered);
}

#[test]
fn test_domain_different_chains() {
    let d1 = Domain::new(1, 100);
    let d2 = Domain::new(2, 100);
    assert_ne!(d1.to_bytes(), d2.to_bytes());
}

// ---------------------------------------------------------------------------
// Attestation tests
// ---------------------------------------------------------------------------

#[test]
fn test_attestation_size_bounds() {
    // 32 (obj_hash) + 32 (idcom) + 8 (domain) + 1 (alg_tag) + 2 (sig_len) + 64 (credential) = 139 bytes.
    let attestation = Attestation {
        obj_hash: [1u8; 32],
        idcom: [2u8; 32],
        domain: Domain::new(1, 42),
        context_tag: [0u8; 16],
        credential: TaggedSignature::ed25519([3u8; 64]),
    };
    let bytes = attestation.to_bytes();
    assert_eq!(bytes.len(), attestation.wire_size());
}

#[test]
fn test_attestation_serialization_roundtrip() {
    let attestation = Attestation {
        obj_hash: [0xAA; 32],
        idcom: [0xBB; 32],
        domain: Domain::new(7, 999),
        context_tag: [0u8; 16],
        credential: TaggedSignature::ed25519([0xCC; 64]),
    };
    let bytes = attestation.to_bytes();
    let recovered = Attestation::from_bytes(&bytes).expect("should deserialize");
    assert_eq!(attestation, recovered);
}

#[test]
fn test_attestation_from_bytes_too_short() {
    let short_data = [0u8; 50];
    assert!(Attestation::from_bytes(&short_data).is_err());
}

// ---------------------------------------------------------------------------
// Transaction tests
// ---------------------------------------------------------------------------

#[test]
fn test_transaction_wire_size() {
    let attestation = Attestation {
        obj_hash: [0u8; 32],
        idcom: [0u8; 32],
        domain: Domain::new(1, 0),
        context_tag: [0u8; 16],
        credential: TaggedSignature::ed25519([0u8; 64]),
    };
    let payload = vec![0u8; 140]; // Typical payload ~154 bytes in the paper
    let tx = Transaction::new(payload.clone(), attestation);

    // wire_size = payload(140) + attestation(155) = 295
    // attestation: 32 (obj_hash) + 32 (idcom) + 8 (domain) + 16 (context_tag) + 1 (alg_tag) + 2 (sig_len) + 64 (sig) = 155
    assert_eq!(tx.wire_size(), 295);
}

#[test]
fn test_transaction_serialization_roundtrip() {
    let attestation = Attestation {
        obj_hash: [1u8; 32],
        idcom: [2u8; 32],
        domain: Domain::new(1, 42),
        context_tag: [0u8; 16],
        credential: TaggedSignature::ed25519([3u8; 64]),
    };
    let tx = Transaction::new(b"hello world".to_vec(), attestation);

    let bytes = tx.to_bytes();
    let recovered = Transaction::from_bytes(&bytes).expect("should deserialize");
    assert_eq!(tx, recovered);
}

#[test]
fn test_transaction_hash_changes_with_attestation() {
    let payload = b"hello world".to_vec();

    let tx_a = Transaction::new(
        payload.clone(),
        Attestation {
            obj_hash: [1u8; 32],
            idcom: [2u8; 32],
            domain: Domain::new(1, 42),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([3u8; 64]),
        },
    );
    let tx_b = Transaction::new(
        payload,
        Attestation {
            obj_hash: [1u8; 32],
            idcom: [9u8; 32],
            domain: Domain::new(1, 43),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([4u8; 64]),
        },
    );

    assert_ne!(tx_a.tx_hash(), tx_b.tx_hash());
}

// ---------------------------------------------------------------------------
// BlockHeader tests
// ---------------------------------------------------------------------------

#[test]
fn test_block_header_size() {
    // Paper says ~256 bytes.
    assert_eq!(BlockHeader::APPROX_WIRE_SIZE, 256);
}

#[test]
fn test_block_header_hash_deterministic() {
    let header = BlockHeader {
        slot: 100,
        parent_hash: [0u8; 32],
        state_root: [1u8; 32],
        tx_merkle_root: [2u8; 32],
        attest_merkle_root: [3u8; 32],
        poh_hash: [4u8; 32],
        leader_idcom: [5u8; 32],
        timestamp: 1234567890,
        tx_count: 50,
        round: 0,
        mev_ace_material_hash: [0u8; 32],
    };

    let hash1 = header.hash();
    let hash2 = header.hash();
    assert_eq!(hash1, hash2, "block header hash must be deterministic");
    assert_ne!(hash1, [0u8; 32], "hash should not be zero");
}

#[test]
fn test_block_header_different_slot_different_hash() {
    let header1 = BlockHeader {
        slot: 100,
        parent_hash: [0u8; 32],
        state_root: [0u8; 32],
        tx_merkle_root: [0u8; 32],
        attest_merkle_root: [0u8; 32],
        poh_hash: [0u8; 32],
        leader_idcom: [0u8; 32],
        timestamp: 0,
        tx_count: 0,
        round: 0,
        mev_ace_material_hash: [0u8; 32],
    };
    let header2 = BlockHeader {
        slot: 101,
        ..header1.clone()
    };

    assert_ne!(header1.hash(), header2.hash());
}

// ---------------------------------------------------------------------------
// Block builder tests
// ---------------------------------------------------------------------------

#[test]
fn test_block_building() {
    let mut builder = BlockBuilder::new(42, [0u8; 32], [1u8; 32], [2u8; 32]);

    let attestation = Attestation {
        obj_hash: [10u8; 32],
        idcom: [20u8; 32],
        domain: Domain::new(1, 42),
        context_tag: [0u8; 16],
        credential: TaggedSignature::ed25519([30u8; 64]),
    };
    let tx = Transaction::new(vec![0u8; 100], attestation);

    builder.add_transaction(tx.clone()).expect("should add tx");
    builder.add_transaction(tx).expect("should add second tx");

    let block = builder.build([99u8; 32], 1234567890);

    assert_eq!(block.header.slot, 42);
    assert_eq!(block.header.tx_count, 2);
    assert_eq!(block.transactions.len(), 2);
    assert_eq!(block.header.state_root, [99u8; 32]);
    assert_ne!(block.header.tx_merkle_root, [0u8; 32]);
    assert_ne!(block.header.attest_merkle_root, [0u8; 32]);
}

#[test]
fn test_block_builder_full() {
    let mut builder = BlockBuilder::new(0, [0u8; 32], [0u8; 32], [0u8; 32]);

    let attestation = Attestation {
        obj_hash: [0u8; 32],
        idcom: [0u8; 32],
        domain: Domain::new(1, 0),
        context_tag: [0u8; 16],
        credential: TaggedSignature::ed25519([0u8; 64]),
    };
    let tx = Transaction::new(vec![0u8; 10], attestation);

    // Fill to max
    for _ in 0..MAX_TXS_PER_BLOCK {
        builder.add_transaction(tx.clone()).expect("should add");
    }

    // Next should fail
    let result = builder.add_transaction(tx);
    assert!(result.is_err(), "should reject when block is full");
}

#[test]
fn test_block_builder_rejects_oversized_block() {
    let mut builder = BlockBuilder::new(0, [0u8; 32], [0u8; 32], [0u8; 32]);

    let attestation = Attestation {
        obj_hash: [0u8; 32],
        idcom: [0u8; 32],
        domain: Domain::new(1, 0),
        context_tag: [0u8; 16],
        credential: TaggedSignature::ed25519([0u8; 64]),
    };
    let tx = Transaction::new(vec![0u8; MAX_BLOCK_BYTES], attestation);

    let result = builder.add_transaction(tx);
    assert!(
        result.is_err(),
        "should reject transaction beyond block byte cap"
    );
}

// ---------------------------------------------------------------------------
// Finality types tests
// ---------------------------------------------------------------------------

#[test]
fn test_finality_proof_mode_default_is_stark_v1() {
    assert_eq!(FinalityProofMode::default(), FinalityProofMode::StarkV1);
}

#[test]
fn test_finality_certificate_well_formed() {
    let fc = FinalityCertificate {
        block_hash: [1u8; 32],
        slot: 42,
        proof: ZkProof::from_bytes(vec![0u8; 256]),
        id_com_commitment: [2u8; 32],
        proof_mode: FinalityProofMode::StarkV1,
        statement_root: [0u8; 32],
        tx_count: 0,
    };
    assert!(fc.is_well_formed());

    // STARK proofs are variable-size; a 128-byte proof is still well-formed.
    let fc_small = FinalityCertificate {
        proof: ZkProof::from_bytes(vec![0u8; 128]),
        ..fc.clone()
    };
    assert!(fc_small.is_well_formed());

    // Empty proof is not well-formed.
    let fc_empty = FinalityCertificate {
        proof: ZkProof::from_bytes(vec![]),
        ..fc
    };
    assert!(!fc_empty.is_well_formed());
}

#[test]
fn test_finality_state_properties() {
    assert!(!FinalityState::Pending.is_terminal());
    assert!(!FinalityState::Soft.is_terminal());
    assert!(!FinalityState::BackupWait.is_terminal());
    assert!(FinalityState::Hard.is_terminal());
    assert!(FinalityState::RolledBack.is_terminal());

    assert!(!FinalityState::Pending.is_confirmed());
    assert!(FinalityState::Soft.is_confirmed());
    assert!(FinalityState::BackupWait.is_confirmed());
    assert!(FinalityState::Hard.is_confirmed());
    assert!(!FinalityState::RolledBack.is_confirmed());
}

#[test]
fn test_groth16_proof_size() {
    assert_eq!(ZkProof::SIZE, 256);
}
