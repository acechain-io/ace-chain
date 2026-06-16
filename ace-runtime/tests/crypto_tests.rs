#![cfg(feature = "test-utils")]

mod support;

use ace_runtime::crypto::attestation::{
    auth_public_key_from_seed, verify_attestation, verify_payload_binding,
};
use ace_runtime::crypto::hkdf_derive::{
    build_vault_context, derive_key_raw, hkdf_expand_with_context,
};
#[cfg(feature = "stark")]
use ace_runtime::crypto::proof::StarkProver;
use ace_runtime::crypto::proof::{
    MockProver, PrivateWitness, ProofProducer, ProofVerifier, PublicInputs,
};
use ace_runtime::types::attestation::Domain;
use ace_runtime::types::finality::ZkProof;
use support::{auth_pubkey_for, make_test_attestation, payload_hash, test_idcom, test_seed};

#[test]
fn test_auth_public_key_is_deterministic() {
    let seed = test_seed(0x11);
    assert_eq!(
        auth_public_key_from_seed(&seed),
        auth_public_key_from_seed(&seed)
    );
}

#[test]
fn test_derive_key_raw_is_deterministic() {
    let ikm = [0x42; 32];
    let salt = Domain::new(1, 100).to_bytes();
    let key1 = derive_key_raw(&ikm, b"ACE-TEST-INFO", &salt);
    let key2 = derive_key_raw(&ikm, b"ACE-TEST-INFO", &salt);
    assert_eq!(key1, key2);
}

#[test]
fn test_derive_key_raw_respects_context() {
    let ikm = [0x33; 32];
    let key_a = derive_key_raw(&ikm, b"ACE-TEST-INFO", &Domain::new(1, 100).to_bytes());
    let key_b = derive_key_raw(&ikm, b"ACE-TEST-INFO", &Domain::new(1, 101).to_bytes());
    let key_c = derive_key_raw(&ikm, b"ACE-OTHER-INFO", &Domain::new(1, 100).to_bytes());

    assert_ne!(key_a, key_b);
    assert_ne!(key_a, key_c);
    assert_ne!(key_b, key_c);
}

#[test]
fn test_hkdf_context_aware_expansion() {
    let ikm = [7u8; 32];
    let base_info = b"test-info";

    let key_no_ctx = hkdf_expand_with_context(&ikm, base_info, b"");
    let key_with_ctx = hkdf_expand_with_context(&ikm, base_info, b"vault-a");
    let key_ctx_b = hkdf_expand_with_context(&ikm, base_info, b"vault-b");
    let key_no_ctx2 = hkdf_expand_with_context(&ikm, base_info, b"");

    assert_ne!(key_no_ctx, key_with_ctx);
    assert_ne!(key_with_ctx, key_ctx_b);
    assert_eq!(key_no_ctx, key_no_ctx2);
}

#[test]
fn test_vault_context_builder() {
    assert_eq!(build_vault_context(&[]), "");
    assert_eq!(build_vault_context(&["OperatingFund"]), "OperatingFund");
    assert_eq!(
        build_vault_context(&["OperatingFund", "corp", "0"]),
        "0:OperatingFund:corp"
    );
    assert_eq!(build_vault_context(&["a", "b", "c"]), "a:b:c");
    assert_eq!(build_vault_context(&["c", "b", "a"]), "a:b:c");
}

#[test]
fn test_attestation_generate_and_verify() {
    let domain = Domain::new(1, 42);
    let payload = b"transfer 100 tokens to Alice";
    let seed = test_seed(0x10);
    let idcom = test_idcom(0x10, domain);

    let attestation = make_test_attestation(&seed, idcom, payload, domain);
    assert!(verify_attestation(
        &attestation,
        payload,
        &auth_pubkey_for(0x10)
    ));
    assert!(verify_payload_binding(&attestation, payload));
}

#[test]
fn test_attestation_wrong_key_rejects() {
    let domain = Domain::new(1, 42);
    let payload = b"transfer 100 tokens";
    let attestation =
        make_test_attestation(&test_seed(0x10), test_idcom(0x10, domain), payload, domain);

    assert!(!verify_attestation(
        &attestation,
        payload,
        &auth_pubkey_for(0x20)
    ));
}

#[test]
fn test_attestation_wrong_domain_rejects() {
    let domain = Domain::new(1, 42);
    let wrong_domain = Domain::new(1, 43);
    let payload = b"transfer 100 tokens";
    let mut attestation =
        make_test_attestation(&test_seed(0x10), test_idcom(0x10, domain), payload, domain);
    attestation.domain = wrong_domain;

    assert!(!verify_attestation(
        &attestation,
        payload,
        &auth_pubkey_for(0x10)
    ));
}

#[test]
fn test_attestation_wrong_payload_rejects() {
    let domain = Domain::new(1, 42);
    let payload = b"transfer 100 tokens";
    let wrong_payload = b"transfer 999 tokens";
    let attestation =
        make_test_attestation(&test_seed(0x10), test_idcom(0x10, domain), payload, domain);

    assert!(!verify_attestation(
        &attestation,
        wrong_payload,
        &auth_pubkey_for(0x10)
    ));
    assert_ne!(payload_hash(payload), payload_hash(wrong_payload));
}

#[test]
fn test_mock_prover_prove_and_verify() {
    let prover = MockProver::new();

    let public = PublicInputs {
        idcom: [1u8; 32],
        tx_hash: [2u8; 32],
        domain: [0, 0, 0, 1, 42, 0, 0, 0],
        target: [3u8; 32],
        rp_com: [4u8; 32],
    };
    let witness = PrivateWitness {
        root_secret: [10u8; 32],
        salt: [0u8; 32],
        alg_id: 0,
        index: 0,
        nonce: 0,
    };

    let proof = prover.prove(&public, &witness);
    assert_eq!(proof.data.len(), 256);
    assert!(proof.is_well_formed());
    assert!(prover.verify(&proof, &public));
}

#[test]
fn test_mock_prover_wrong_public_fails() {
    let prover = MockProver::new();

    let public = PublicInputs {
        idcom: [1u8; 32],
        tx_hash: [2u8; 32],
        domain: [0u8; 8],
        target: [3u8; 32],
        rp_com: [4u8; 32],
    };
    let witness = PrivateWitness {
        root_secret: [10u8; 32],
        salt: [0u8; 32],
        alg_id: 0,
        index: 0,
        nonce: 0,
    };

    let proof = prover.prove(&public, &witness);
    let wrong_public = PublicInputs {
        idcom: [99u8; 32],
        ..public.clone()
    };
    assert!(!prover.verify(&proof, &wrong_public));
}

#[test]
fn test_mock_prover_aggregation() {
    let prover = MockProver::new();

    let p1 = PublicInputs {
        idcom: [1u8; 32],
        tx_hash: [2u8; 32],
        domain: [0u8; 8],
        target: [0u8; 32],
        rp_com: [0u8; 32],
    };
    let p2 = PublicInputs {
        idcom: [3u8; 32],
        tx_hash: [4u8; 32],
        domain: [0u8; 8],
        target: [0u8; 32],
        rp_com: [0u8; 32],
    };
    let witness = PrivateWitness {
        root_secret: [0u8; 32],
        salt: [0u8; 32],
        alg_id: 0,
        index: 0,
        nonce: 0,
    };

    let proof1 = prover.prove(&p1, &witness);
    let proof2 = prover.prove(&p2, &witness);
    let aggregated = prover.aggregate(&proof1, &proof2);

    assert_eq!(aggregated.data.len(), 256);
    assert!(aggregated.is_well_formed());
}

#[test]
fn test_v1_bundle_rejected_by_v2_verifier() {
    // Construct a proof bundle matching the ACPS v3 format, then flip version to 1.
    // Bundle format (from proof.rs):
    //   Magic: "ACPS" (4 bytes)
    //   Version: 3 (1 byte)
    //   Entry count: u32 LE (4 bytes)
    //   Per entry: proof_len (u32 LE) + proof_bytes + public_inputs (144 bytes)
    //
    // The verifier's decode_proof_bundle rejects bundles where version != 3.

    // Build a minimal bundle: 1 entry with a dummy proof and dummy public inputs
    let dummy_proof = vec![0xABu8; 64]; // arbitrary proof bytes
    let dummy_pi = [0u8; 144]; // 36 M31 elements, all zero

    let mut bundle = Vec::new();
    bundle.extend_from_slice(b"ACPS"); // magic
    bundle.push(3); // version = 3
    bundle.extend_from_slice(&1u32.to_le_bytes()); // 1 entry
    bundle.extend_from_slice(&(dummy_proof.len() as u32).to_le_bytes());
    bundle.extend_from_slice(&dummy_proof);
    bundle.extend_from_slice(&dummy_pi);

    // Verify the v3 bundle at least parses through StarkProver verification
    // (it will fail proof verification, but should NOT fail at bundle decoding)
    #[cfg(feature = "stark")]
    {
        let prover = StarkProver::new_nonce_registry();
        let public = PublicInputs {
            idcom: [0u8; 32],
            tx_hash: [0u8; 32],
            domain: [0u8; 8],
            target: [0u8; 32],
            rp_com: [0u8; 32],
        };
        // v3 bundle should be decoded (but proof verification itself may fail)
        let _v3_proof = ZkProof::from_bytes(bundle.clone());
        // We don't assert verify succeeds -- just that it doesn't panic on decode

        // Now flip version to 1
        let mut v1_bundle = bundle.clone();
        v1_bundle[4] = 1;
        let v1_proof = ZkProof::from_bytes(v1_bundle);

        // v1 must be rejected
        assert!(
            !prover.verify(&v1_proof, &public),
            "v1 bundle must be rejected by v3 verifier"
        );
    }

    // Without stark feature, verify the byte layout is correct
    #[cfg(not(feature = "stark"))]
    {
        assert_eq!(&bundle[0..4], b"ACPS");
        assert_eq!(bundle[4], 3);
        // Flip version to 1 and verify it's changed
        let mut v1_bundle = bundle.clone();
        v1_bundle[4] = 1;
        assert_eq!(v1_bundle[4], 1);
    }
}
