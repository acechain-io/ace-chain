use ace_hfi_pay::intent::ChainId;
use ace_hfi_pay::relay::{
    binding_attestation_message, compute_binding_key_commitment, quote_proof_message,
    verify_attested_quote_proof, verify_verified_quote, BindingAttestation, RelayStore,
};
use ace_model::account::AccountId;
use ace_runtime::crypto::sig_algo::{TaggedPubkey, TaggedSignature};
use ed25519_dalek::{Signer, SigningKey};

fn make_keypair(seed: u8) -> (TaggedPubkey, SigningKey) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = TaggedPubkey::ed25519(sk.verifying_key().to_bytes());
    (pk, sk)
}

fn sign_msg(sk: &SigningKey, msg: &[u8; 32]) -> TaggedSignature {
    let sig = sk.sign(msg);
    TaggedSignature::ed25519(sig.to_bytes())
}

#[test]
fn create_intent_requires_refund_authorization_if_refund_dest_present() {
    let mut relay = RelayStore::new();
    let handle = &[7u8; 32];
    let result = relay.create_intent(
        "alice@example.com",
        handle,
        1000,
        ChainId::Native,
        None,
        0,
        Some(AccountId::from_bytes([1u8; 32])),
        None,
        100,
        None,
        10,
    );
    assert!(result.is_err());
}

#[test]
fn mark_refunded_before_expiry_is_rejected() {
    let mut relay = RelayStore::new();
    let handle = &[7u8; 32];
    let intent = relay
        .create_intent(
            "bob@example.com",
            handle,
            2000,
            ChainId::Native,
            None,
            0,
            None,
            None,
            100,
            None,
            10,
        )
        .unwrap();
    relay.mark_funded(&intent.intent_id).unwrap();

    let result = relay.mark_refunded(&intent.intent_id, 50);
    assert!(result.is_err());
    assert_eq!(relay.pending_intents("bob@example.com").len(), 1);
}

#[test]
fn mark_refunded_auto_expires_funded_intent() {
    let mut relay = RelayStore::new();
    let handle = &[7u8; 32];
    let intent = relay
        .create_intent(
            "carol@example.com",
            handle,
            2000,
            ChainId::Native,
            None,
            0,
            None,
            None,
            100,
            None,
            10,
        )
        .unwrap();
    relay.mark_funded(&intent.intent_id).unwrap();
    relay.mark_refunded(&intent.intent_id, 101).unwrap();

    assert!(relay.pending_intents("carol@example.com").is_empty());
}

#[test]
fn stored_refund_authorization_round_trips() {
    let mut relay = RelayStore::new();
    let handle = &[7u8; 32];
    let (pk, sk) = make_keypair(3);
    let refund_authorizer = AccountId::from_bytes([2u8; 32]);
    let refund_dest = AccountId::from_bytes([3u8; 32]);
    let intent_id = [0xAB; 32];
    let blinded_binding = [0xBBu8; 32];
    let refund_msg = ace_hfi_pay::auth::refund_message(
        ChainId::Evm,
        None,
        &intent_id,
        &blinded_binding,
        3000,
        &refund_authorizer,
        &refund_dest,
        80,
        0,
    );
    let refund_sig = sign_msg(&sk, &refund_msg);

    let intent = relay
        .create_intent(
            "dave@example.com",
            handle,
            3000,
            ChainId::Evm,
            None,
            0,
            Some(refund_dest),
            Some(refund_authorizer),
            80,
            Some((pk, refund_sig.clone())),
            10,
        )
        .unwrap();
    assert_eq!(intent.refund_auth.unwrap().1, refund_sig);
    assert_eq!(intent.refund_authorizer, Some(refund_authorizer));
}

#[test]
fn create_and_verify_verified_quote() {
    let mut relay = RelayStore::new();
    let handle = &[0x77u8; 32];
    let (attestor_pk, attestor_sk) = make_keypair(9);
    let binding_key = compute_binding_key_commitment(handle);
    let attestation_msg = binding_attestation_message("erin@example.com", &binding_key, 3, 1_000);
    let attestation_sig = sign_msg(&attestor_sk, &attestation_msg);
    let attestation = BindingAttestation {
        binding_key_commitment: binding_key,
        binding_epoch: 3,
        valid_until: 1_000,
        attestor_pubkey: attestor_pk,
        signature: attestation_sig,
    };

    let mut quote = relay
        .create_verified_quote(
            "erin@example.com",
            handle,
            4_200,
            ChainId::Native,
            None,
            3,
            None,
            None,
            2_000,
            None,
            100,
            attestation,
            500,
            vec![1, 2, 3, 4],
        )
        .unwrap();
    let quote_msg = quote_proof_message(&quote.quote_proof.public_inputs);
    quote.quote_proof.proof_bytes = sign_msg(&attestor_sk, &quote_msg).to_wire_bytes();

    verify_verified_quote("erin@example.com", &quote, 100, |proof| {
        verify_attested_quote_proof(&quote.binding_attestation.attestor_pubkey, proof)
    })
    .unwrap();
}

#[test]
fn verified_quote_rejects_wrong_identifier_attestation_context() {
    let mut relay = RelayStore::new();
    let handle = &[0x78u8; 32];
    let (attestor_pk, attestor_sk) = make_keypair(10);
    let binding_key = compute_binding_key_commitment(handle);
    let attestation_msg = binding_attestation_message("frank@example.com", &binding_key, 0, 1_000);
    let attestation_sig = sign_msg(&attestor_sk, &attestation_msg);
    let attestation = BindingAttestation {
        binding_key_commitment: binding_key,
        binding_epoch: 0,
        valid_until: 1_000,
        attestor_pubkey: attestor_pk,
        signature: attestation_sig,
    };

    let mut quote = relay
        .create_verified_quote(
            "frank@example.com",
            handle,
            1_000,
            ChainId::Evm,
            None,
            0,
            None,
            None,
            2_000,
            None,
            100,
            attestation,
            500,
            vec![5, 6, 7],
        )
        .unwrap();
    let quote_msg = quote_proof_message(&quote.quote_proof.public_inputs);
    quote.quote_proof.proof_bytes = sign_msg(&attestor_sk, &quote_msg).to_wire_bytes();

    assert!(
        verify_verified_quote("mallory@example.com", &quote, 100, |proof| {
            verify_attested_quote_proof(&quote.binding_attestation.attestor_pubkey, proof)
        })
        .is_err()
    );
}

#[test]
fn verified_quote_rejects_tampered_quote_proof_inputs() {
    let mut relay = RelayStore::new();
    let handle = &[0x79u8; 32];
    let (attestor_pk, attestor_sk) = make_keypair(11);
    let binding_key = compute_binding_key_commitment(handle);
    let attestation_msg = binding_attestation_message("gina@example.com", &binding_key, 1, 1_000);
    let attestation_sig = sign_msg(&attestor_sk, &attestation_msg);
    let attestation = BindingAttestation {
        binding_key_commitment: binding_key,
        binding_epoch: 1,
        valid_until: 1_000,
        attestor_pubkey: attestor_pk,
        signature: attestation_sig,
    };

    let mut quote = relay
        .create_verified_quote(
            "gina@example.com",
            handle,
            2_500,
            ChainId::Native,
            None,
            1,
            None,
            None,
            2_000,
            None,
            100,
            attestation,
            500,
            vec![8, 9],
        )
        .unwrap();
    let quote_msg = quote_proof_message(&quote.quote_proof.public_inputs);
    quote.quote_proof.proof_bytes = sign_msg(&attestor_sk, &quote_msg).to_wire_bytes();
    quote.quote_proof.public_inputs.amount += 1;

    assert!(
        verify_verified_quote("gina@example.com", &quote, 100, |proof| {
            verify_attested_quote_proof(&quote.binding_attestation.attestor_pubkey, proof)
        })
        .is_err()
    );
}
