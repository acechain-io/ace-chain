use ace_hfi_pay::auth;
use ace_hfi_pay::intent::{ChainId, VmAddress};
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
fn claim_auth_valid() {
    let (pk, sk) = make_keypair(1);
    let intent_id = [10u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let owner = AccountId::from_bytes([20u8; 32]);
    let amount = 777u64;
    let expiry = 500u64;

    let msg = auth::claim_message(
        ChainId::Evm,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        &VmAddress::Native(owner),
        expiry,
        0,
    );
    let sig = sign_msg(&sk, &msg);

    assert!(auth::verify_claim_auth(
        ChainId::Evm,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        &VmAddress::Native(owner),
        expiry,
        0,
        &pk,
        &sig,
    ));
}

#[test]
fn claim_auth_wrong_key_rejected() {
    let (_pk, sk) = make_keypair(1);
    let (wrong_pk, _) = make_keypair(2);
    let intent_id = [10u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let owner = AccountId::from_bytes([20u8; 32]);
    let amount = 777u64;
    let expiry = 500u64;

    let msg = auth::claim_message(
        ChainId::Evm,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        &VmAddress::Native(owner),
        expiry,
        0,
    );
    let sig = sign_msg(&sk, &msg);

    assert!(!auth::verify_claim_auth(
        ChainId::Evm,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        &VmAddress::Native(owner),
        expiry,
        0,
        &wrong_pk,
        &sig,
    ));
}

#[test]
fn claim_auth_wrong_chain_rejected() {
    let (pk, sk) = make_keypair(1);
    let intent_id = [10u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let owner = AccountId::from_bytes([20u8; 32]);
    let amount = 777u64;
    let expiry = 500u64;

    let msg = auth::claim_message(
        ChainId::Evm,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        &VmAddress::Native(owner),
        expiry,
        0,
    );
    let sig = sign_msg(&sk, &msg);

    // Verify with wrong chain
    assert!(!auth::verify_claim_auth(
        ChainId::Svm,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        &VmAddress::Native(owner),
        expiry,
        0,
        &pk,
        &sig,
    ));
}

#[test]
fn withdraw_auth_valid() {
    let (pk, sk) = make_keypair(3);
    let deposit = AccountId::from_bytes([30u8; 32]);
    let dest = AccountId::from_bytes([40u8; 32]);
    let amount = 1000u64;
    let nonce = 0u64;
    let deadline = 999u64;

    let msg = auth::withdraw_message(
        ChainId::Native,
        None,
        &deposit,
        &dest,
        amount,
        nonce,
        deadline,
    );
    let sig = sign_msg(&sk, &msg);

    assert!(auth::verify_withdraw_auth(
        ChainId::Native,
        None,
        &deposit,
        &dest,
        amount,
        nonce,
        deadline,
        &pk,
        &sig,
    ));
}

#[test]
fn withdraw_auth_wrong_amount_rejected() {
    let (pk, sk) = make_keypair(3);
    let deposit = AccountId::from_bytes([30u8; 32]);
    let dest = AccountId::from_bytes([40u8; 32]);
    let amount = 1000u64;
    let nonce = 0u64;
    let deadline = 999u64;

    let msg = auth::withdraw_message(
        ChainId::Native,
        None,
        &deposit,
        &dest,
        amount,
        nonce,
        deadline,
    );
    let sig = sign_msg(&sk, &msg);

    // Verify with different amount
    assert!(!auth::verify_withdraw_auth(
        ChainId::Native,
        None,
        &deposit,
        &dest,
        9999,
        nonce,
        deadline,
        &pk,
        &sig,
    ));
}

#[test]
fn refund_auth_valid() {
    let (pk, sk) = make_keypair(5);
    let intent_id = [50u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let refund_authorizer = AccountId::from_bytes([55u8; 32]);
    let refund_dest = AccountId::from_bytes([60u8; 32]);
    let amount = 444u64;
    let expiry = 200u64;

    let msg = auth::refund_message(
        ChainId::Bvm,
        None,
        &intent_id,
        &blinded_binding,
        amount,
        &refund_authorizer,
        &refund_dest,
        expiry,
        0,
    );
    let sig = sign_msg(&sk, &msg);

    assert!(auth::verify_refund_auth(
        ChainId::Bvm,
        None,
        &intent_id,
        &blinded_binding,
        amount,
        &refund_authorizer,
        &refund_dest,
        expiry,
        0,
        &pk,
        &sig,
    ));
}

#[test]
fn cross_claim_auth_valid() {
    let (pk, sk) = make_keypair(7);
    let intent_id = [70u8; 32];
    let blinded_binding = [0xCCu8; 32];
    let dest = VmAddress::Svm(AccountId::from_bytes([80u8; 32]));
    let amount = 900u64;
    let expiry = 300u64;

    let msg = auth::cross_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        &dest,
        expiry,
        0,
    );
    let sig = sign_msg(&sk, &msg);

    assert!(auth::verify_cross_claim_auth(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        &dest,
        expiry,
        0,
        &pk,
        &sig
    ));
}

#[test]
fn cross_claim_auth_wrong_dest_chain_rejected() {
    let (pk, sk) = make_keypair(7);
    let intent_id = [70u8; 32];
    let blinded_binding = [0xCCu8; 32];
    let dest = VmAddress::Svm(AccountId::from_bytes([80u8; 32]));
    let wrong_dest = VmAddress::Bvm(AccountId::from_bytes([80u8; 32]));
    let amount = 900u64;
    let expiry = 300u64;

    let msg = auth::cross_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        &dest,
        expiry,
        0,
    );
    let sig = sign_msg(&sk, &msg);

    assert!(!auth::verify_cross_claim_auth(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        &wrong_dest,
        expiry,
        0,
        &pk,
        &sig,
    ));
}
