use ace_hfi_pay::address::{derive_intent_evm_address, derive_intent_tvm_address};
use ace_hfi_pay::auth;
use ace_hfi_pay::executor::{self, IntentStore};
use ace_hfi_pay::intent::{ChainId, IntentStatus, VmAddress};
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
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

fn native_claim_message(
    chain: ChainId,
    mint: Option<&[u8; 32]>,
    binding_epoch: u64,
    intent_id: &[u8; 32],
    blinded_binding: &[u8; 32],
    amount: u64,
    owner: AccountId,
    expiry: u64,
    nonce: u64,
) -> [u8; 32] {
    auth::claim_message(
        chain,
        mint,
        binding_epoch,
        intent_id,
        blinded_binding,
        amount,
        &VmAddress::Native(owner),
        expiry,
        nonce,
    )
}

fn setup() -> (StateTree, IntentStore, AccountId) {
    let mut state = StateTree::new();
    let sender = AccountId::from_bytes([1u8; 32]);
    let sender_pubkey = make_keypair(1).0;
    state.insert(Account::with_auth(sender, 100_000, sender_pubkey));
    (state, IntentStore::new(), sender)
}

#[test]
fn full_flow_create_fund_claim_withdraw() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [10u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let (recipient_pk, recipient_sk) = make_keypair(2);
    let recipient = AccountId::from_bytes([20u8; 32]);
    let dest = AccountId::from_bytes([30u8; 32]);
    let amount = 5000u64;
    let expiry = 100u64;

    // 1. Create intent
    let deposit_addr = executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        amount,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        expiry,
        10,
    )
    .unwrap();
    assert_eq!(store.get(&intent_id).unwrap().status, IntentStatus::Created);
    assert!(state.contains(&deposit_addr));

    // 2. Fund intent
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();
    assert_eq!(store.get(&intent_id).unwrap().status, IntentStatus::Funded);
    assert_eq!(state.get(&deposit_addr).unwrap().balance, amount);
    assert_eq!(state.get(&sender).unwrap().balance, 100_000 - amount);

    // 3. Claim intent
    let claim_msg = native_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        recipient,
        expiry,
        0,
    );
    let claim_sig = sign_msg(&recipient_sk, &claim_msg);
    executor::claim_intent(
        &mut state,
        &mut store,
        &intent_id,
        recipient,
        &recipient_pk,
        &claim_sig,
        50, // current_slot < expiry
    )
    .unwrap();
    assert_eq!(store.get(&intent_id).unwrap().status, IntentStatus::Claimed);
    assert_eq!(store.get(&intent_id).unwrap().owner, Some(recipient));
    assert_eq!(state.get(&recipient).unwrap().auth_pubkey, recipient_pk);

    // 4. Withdraw
    let wd_msg =
        auth::withdraw_message(ChainId::Native, None, &deposit_addr, &dest, amount, 0, 200);
    let wd_sig = sign_msg(&recipient_sk, &wd_msg);
    executor::withdraw(
        &mut state,
        &mut store,
        &intent_id,
        &dest,
        amount,
        200,
        &recipient_pk,
        &wd_sig,
        55,
    )
    .unwrap();
    assert_eq!(state.get(&deposit_addr).unwrap().balance, 0);
    assert_eq!(state.get(&dest).unwrap().balance, amount);
    assert_eq!(state.get(&dest).unwrap().auth_pubkey, recipient_pk);
    assert_eq!(store.get(&intent_id).unwrap().withdraw_nonce, 1);
}

#[test]
fn create_evm_intent_registers_raw_deposit_alias() {
    let (mut state, mut store, _sender) = setup();
    let intent_id = [0xA1; 32];
    let deposit_addr = executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
        5_000,
        ChainId::Evm,
        None,
        0,
        None,
        None,
        None,
        100,
        10,
    )
    .unwrap();

    let evm_addr = derive_intent_evm_address(&intent_id);
    assert_eq!(state.resolve_evm(&evm_addr), Some(&deposit_addr));
    assert_eq!(
        state.get(&deposit_addr).unwrap().evm_address,
        Some(evm_addr)
    );
}

#[test]
fn create_tvm_intent_registers_raw_deposit_alias() {
    let (mut state, mut store, _sender) = setup();
    let intent_id = [0xA2; 32];
    let deposit_addr = executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
        5_000,
        ChainId::Tvm,
        None,
        0,
        None,
        None,
        None,
        100,
        10,
    )
    .unwrap();

    let tron_addr = derive_intent_tvm_address(&intent_id);
    assert_eq!(state.resolve_tron(&tron_addr), Some(&deposit_addr));
    assert_eq!(
        state.get(&deposit_addr).unwrap().tron_address,
        Some(tron_addr)
    );
}

#[test]
fn full_flow_fund_expire_refund() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [11u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let (sender_pk, sender_sk) = make_keypair(1);
    let refund_dest = AccountId::from_bytes([99u8; 32]);
    let amount = 3000u64;
    let expiry = 50u64;
    let ref_msg = auth::refund_message(
        ChainId::Evm,
        None,
        &intent_id,
        &blinded_binding,
        amount,
        &sender,
        &refund_dest,
        expiry,
        0,
    );
    let ref_sig = sign_msg(&sender_sk, &ref_msg);
    let refund_auth = Some((sender_pk.clone(), ref_sig.clone()));

    // Create + fund
    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        amount,
        ChainId::Evm,
        None,
        0,
        Some(refund_dest),
        Some(sender),
        refund_auth,
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    // Expire
    executor::expire_intent(&mut store, &intent_id, 51).unwrap();
    assert_eq!(store.get(&intent_id).unwrap().status, IntentStatus::Expired);

    // Refund
    executor::refund(&mut state, &mut store, &intent_id, 60).unwrap();
    assert_eq!(
        store.get(&intent_id).unwrap().status,
        IntentStatus::Refunded
    );
    assert_eq!(state.get(&refund_dest).unwrap().balance, amount);
    assert_eq!(state.get(&refund_dest).unwrap().auth_pubkey, sender_pk);
}

#[test]
fn fund_intent_rejects_mismatched_refund_authorizer() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [0xEE; 32];
    let blinded_binding = [0xBBu8; 32];
    let (sender_pk, sender_sk) = make_keypair(1);
    let refund_dest = AccountId::from_bytes([0x44; 32]);
    let wrong_authorizer = AccountId::from_bytes([0x45; 32]);
    let expiry = 100u64;
    let refund_msg = auth::refund_message(
        ChainId::Native,
        None,
        &intent_id,
        &blinded_binding,
        1_000,
        &wrong_authorizer,
        &refund_dest,
        expiry,
        0,
    );
    let refund_sig = sign_msg(&sender_sk, &refund_msg);

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        1_000,
        ChainId::Native,
        None,
        0,
        Some(refund_dest),
        Some(wrong_authorizer),
        Some((sender_pk, refund_sig)),
        expiry,
        10,
    )
    .unwrap();

    let result = executor::fund_intent(&mut state, &mut store, &intent_id, &sender);
    assert!(result.is_err());
}

#[test]
fn claim_before_fund_fails() {
    let (mut state, mut store, _sender) = setup();
    let intent_id = [12u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let (pk, sk) = make_keypair(5);
    let owner = AccountId::from_bytes([50u8; 32]);

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        1000,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        100,
        10,
    )
    .unwrap();

    let msg = native_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &blinded_binding,
        1000,
        owner,
        100,
        0,
    );
    let sig = sign_msg(&sk, &msg);
    let result = executor::claim_intent(&mut state, &mut store, &intent_id, owner, &pk, &sig, 20);
    assert!(result.is_err());
}

#[test]
fn claim_after_expiry_fails() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [13u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let (pk, sk) = make_keypair(6);
    let owner = AccountId::from_bytes([60u8; 32]);
    let expiry = 50u64;

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        1000,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    let msg = native_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &blinded_binding,
        1000,
        owner,
        expiry,
        0,
    );
    let sig = sign_msg(&sk, &msg);
    let result = executor::claim_intent(
        &mut state, &mut store, &intent_id, owner, &pk, &sig, 51, // past expiry
    );
    assert!(result.is_err());
}

#[test]
fn wrong_claim_signature_rejected() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [14u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let (pk, _sk) = make_keypair(7);
    let (_wrong_pk, wrong_sk) = make_keypair(8);
    let owner = AccountId::from_bytes([70u8; 32]);
    let expiry = 100u64;

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        1000,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    let msg = native_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &blinded_binding,
        1000,
        owner,
        expiry,
        0,
    );
    let sig = sign_msg(&wrong_sk, &msg); // signed with wrong key
    let result = executor::claim_intent(&mut state, &mut store, &intent_id, owner, &pk, &sig, 20);
    assert!(result.is_err());
}

#[test]
fn insufficient_balance_fails() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [15u8; 32];

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
        999_999, // more than sender has
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        100,
        10,
    )
    .unwrap();

    let result = executor::fund_intent(&mut state, &mut store, &intent_id, &sender);
    assert!(result.is_err());
}

#[test]
fn expire_before_expiry_slot_fails() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [16u8; 32];

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
        1000,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        100,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    let result = executor::expire_intent(&mut store, &intent_id, 50); // before expiry
    assert!(result.is_err());
}

#[test]
fn refund_auto_expires_funded_intent() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [17u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let (pk, sk) = make_keypair(1);
    let refund_dest = AccountId::from_bytes([90u8; 32]);
    let expiry = 50u64;
    let msg = auth::refund_message(
        ChainId::Tvm,
        None,
        &intent_id,
        &blinded_binding,
        2000,
        &sender,
        &refund_dest,
        expiry,
        0,
    );
    let sig = sign_msg(&sk, &msg);
    let refund_auth = Some((pk.clone(), sig));

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        2000,
        ChainId::Tvm,
        None,
        0,
        Some(refund_dest),
        Some(sender),
        refund_auth,
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    // Refund without explicitly expiring first — should auto-expire
    executor::refund(&mut state, &mut store, &intent_id, 60).unwrap();
    assert_eq!(
        store.get(&intent_id).unwrap().status,
        IntentStatus::Refunded
    );
    assert_eq!(state.get(&refund_dest).unwrap().balance, 2000);
}

#[test]
fn withdraw_with_different_key_after_claim_fails() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [18u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let (recipient_pk, recipient_sk) = make_keypair(10);
    let (attacker_pk, attacker_sk) = make_keypair(11);
    let recipient = AccountId::from_bytes([0x10; 32]);
    let dest = AccountId::from_bytes([0x11; 32]);
    let amount = 2500u64;
    let expiry = 100u64;

    let deposit_addr = executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        amount,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    let claim_msg = native_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        recipient,
        expiry,
        0,
    );
    let claim_sig = sign_msg(&recipient_sk, &claim_msg);
    executor::claim_intent(
        &mut state,
        &mut store,
        &intent_id,
        recipient,
        &recipient_pk,
        &claim_sig,
        20,
    )
    .unwrap();

    let wd_msg =
        auth::withdraw_message(ChainId::Native, None, &deposit_addr, &dest, amount, 0, 200);
    let attacker_sig = sign_msg(&attacker_sk, &wd_msg);
    let result = executor::withdraw(
        &mut state,
        &mut store,
        &intent_id,
        &dest,
        amount,
        200,
        &attacker_pk,
        &attacker_sig,
        30,
    );
    assert!(result.is_err());
    assert_eq!(state.get(&deposit_addr).unwrap().balance, amount);
    assert!(state.get(&dest).is_none());
}

#[test]
fn mark_funded_requires_full_quote_balance() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [19u8; 32];
    let deposit_addr = executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
        5000,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        100,
        10,
    )
    .unwrap();

    state.get_mut(&sender).unwrap().balance -= 1000;
    state.get_mut(&deposit_addr).unwrap().balance += 1000;
    let result = executor::mark_funded(&state, &mut store, &intent_id);
    assert!(result.is_err());
}

#[test]
fn claim_rejects_underfunded_intent_even_if_status_was_forced() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [20u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let (pk, sk) = make_keypair(12);
    let owner = AccountId::from_bytes([0x20; 32]);
    let deposit_addr = executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        5000,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        100,
        10,
    )
    .unwrap();

    state.get_mut(&sender).unwrap().balance -= 1000;
    state.get_mut(&deposit_addr).unwrap().balance += 1000;
    store.get_mut(&intent_id).unwrap().status = IntentStatus::Funded;

    let msg = native_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &blinded_binding,
        5000,
        owner,
        100,
        0,
    );
    let sig = sign_msg(&sk, &msg);
    let result = executor::claim_intent(&mut state, &mut store, &intent_id, owner, &pk, &sig, 20);
    assert!(result.is_err());
}

#[test]
fn refund_requires_stored_authorization() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [21u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let (sender_pk, sender_sk) = make_keypair(1);
    let refund_dest = AccountId::from_bytes([0x21; 32]);
    let expiry = 50u64;
    let refund_msg = auth::refund_message(
        ChainId::Evm,
        None,
        &intent_id,
        &blinded_binding,
        3000,
        &sender,
        &refund_dest,
        expiry,
        0,
    );
    let refund_sig = sign_msg(&sender_sk, &refund_msg);

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        3000,
        ChainId::Evm,
        None,
        0,
        Some(refund_dest),
        Some(sender),
        Some((sender_pk, refund_sig)),
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();
    executor::expire_intent(&mut store, &intent_id, 60).unwrap();
    store.get_mut(&intent_id).unwrap().refund_auth = None;

    let result = executor::refund(&mut state, &mut store, &intent_id, 60);
    assert!(result.is_err());
}

#[test]
fn refund_does_not_sweep_surplus_balance() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [22u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let (sender_pk, sender_sk) = make_keypair(1);
    let refund_dest = AccountId::from_bytes([0x22; 32]);
    let amount = 3_000u64;
    let expiry = 50u64;
    let refund_msg = auth::refund_message(
        ChainId::Native,
        None,
        &intent_id,
        &blinded_binding,
        amount,
        &sender,
        &refund_dest,
        expiry,
        0,
    );
    let refund_sig = sign_msg(&sender_sk, &refund_msg);

    let deposit_addr = executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        amount,
        ChainId::Native,
        None,
        0,
        Some(refund_dest),
        Some(sender),
        Some((sender_pk, refund_sig)),
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    state.get_mut(&sender).unwrap().balance -= 500;
    state.get_mut(&deposit_addr).unwrap().balance += 500;

    executor::expire_intent(&mut store, &intent_id, 60).unwrap();
    executor::refund(&mut state, &mut store, &intent_id, 60).unwrap();

    assert_eq!(state.get(&refund_dest).unwrap().balance, amount);
    assert_eq!(state.get(&deposit_addr).unwrap().balance, 500);
}

#[test]
fn withdraw_cannot_exceed_quoted_amount_even_with_surplus() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [23u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let (recipient_pk, recipient_sk) = make_keypair(13);
    let recipient = AccountId::from_bytes([0x23; 32]);
    let dest = AccountId::from_bytes([0x24; 32]);
    let amount = 3_000u64;
    let expiry = 100u64;

    let deposit_addr = executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        amount,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    state.get_mut(&sender).unwrap().balance -= 500;
    state.get_mut(&deposit_addr).unwrap().balance += 500;

    let claim_msg = native_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &blinded_binding,
        amount,
        recipient,
        expiry,
        0,
    );
    let claim_sig = sign_msg(&recipient_sk, &claim_msg);
    executor::claim_intent(
        &mut state,
        &mut store,
        &intent_id,
        recipient,
        &recipient_pk,
        &claim_sig,
        20,
    )
    .unwrap();

    let overdraw_msg = auth::withdraw_message(
        ChainId::Native,
        None,
        &deposit_addr,
        &dest,
        amount + 500,
        0,
        200,
    );
    let overdraw_sig = sign_msg(&recipient_sk, &overdraw_msg);
    let result = executor::withdraw(
        &mut state,
        &mut store,
        &intent_id,
        &dest,
        amount + 500,
        200,
        &recipient_pk,
        &overdraw_sig,
        30,
    );
    assert!(result.is_err());
    assert_eq!(state.get(&deposit_addr).unwrap().balance, amount + 500);
}

#[test]
fn claim_with_proof_rejects_mismatched_public_inputs() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [24u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let destination = VmAddress::Native(AccountId::from_bytes([0x25; 32]));
    let amount = 4_000u64;
    let expiry = 100u64;

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        amount,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    let proof = auth::ClaimProof {
        public_inputs: auth::ClaimProofPublicInputs {
            identity_commitment: [0x11; 32],
            claim_message_digest: auth::claim_message(
                ChainId::Native,
                None,
                0,
                &intent_id,
                &blinded_binding,
                amount,
                &destination,
                expiry,
                0,
            ),
            auth_commitment: [0x41; 32],
            chain: ChainId::Native,
            mint: None,
            binding_epoch: 0,
            blinded_binding,
            intent_id,
            amount: amount + 1,
            destination,
            expiry,
            nonce: 0,
        },
        proof_bytes: vec![1, 2, 3],
    };

    let result = executor::claim_intent_with_proof(
        &mut state,
        &mut store,
        &intent_id,
        &proof,
        Some(&make_keypair(14).0),
        |_| true,
        20,
    );
    assert!(result.is_err());
}

#[test]
fn claim_with_proof_can_materialize_new_native_destination() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [25u8; 32];
    let blinded_binding = [0xBCu8; 32];
    let (dest_pk, _dest_sk) = make_keypair(15);
    let destination_id = AccountId::from_bytes([0x26; 32]);
    let destination = VmAddress::Native(destination_id);
    let amount = 4_500u64;
    let expiry = 100u64;

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        amount,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    let proof = auth::ClaimProof {
        public_inputs: auth::ClaimProofPublicInputs {
            identity_commitment: [0x12; 32],
            claim_message_digest: auth::claim_message(
                ChainId::Native,
                None,
                0,
                &intent_id,
                &blinded_binding,
                amount,
                &destination,
                expiry,
                0,
            ),
            auth_commitment: [0x42; 32],
            chain: ChainId::Native,
            mint: None,
            binding_epoch: 0,
            blinded_binding,
            intent_id,
            amount,
            destination,
            expiry,
            nonce: 0,
        },
        proof_bytes: vec![9, 9, 9],
    };

    executor::claim_intent_with_proof(
        &mut state,
        &mut store,
        &intent_id,
        &proof,
        Some(&dest_pk),
        |_| true,
        20,
    )
    .unwrap();

    assert_eq!(store.get(&intent_id).unwrap().owner, Some(destination_id));
    assert_eq!(state.get(&destination_id).unwrap().balance, amount);
    assert_eq!(state.get(&destination_id).unwrap().auth_pubkey, dest_pk);
}

#[test]
fn claim_with_proof_credits_existing_native_when_wire_claim_key_differs() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [0xC5u8; 32];
    let blinded_binding = [0xBEu8; 32];
    let destination_id = AccountId::from_bytes([0x28; 32]);
    let destination = VmAddress::Native(destination_id);
    let amount = 3_000u64;
    let expiry = 100u64;

    let on_chain_auth = TaggedPubkey::ed25519([0x77; 32]);
    state.insert(Account::with_auth(destination_id, 0, on_chain_auth.clone()));

    let (wire_claim_pk, _) = make_keypair(99);
    assert_ne!(on_chain_auth, wire_claim_pk);

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        amount,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    let proof = auth::ClaimProof {
        public_inputs: auth::ClaimProofPublicInputs {
            identity_commitment: [0x13; 32],
            claim_message_digest: auth::claim_message(
                ChainId::Native,
                None,
                0,
                &intent_id,
                &blinded_binding,
                amount,
                &destination,
                expiry,
                0,
            ),
            auth_commitment: [0x43; 32],
            chain: ChainId::Native,
            mint: None,
            binding_epoch: 0,
            blinded_binding,
            intent_id,
            amount,
            destination,
            expiry,
            nonce: 0,
        },
        proof_bytes: vec![8, 8, 8],
    };

    executor::claim_intent_with_proof(
        &mut state,
        &mut store,
        &intent_id,
        &proof,
        Some(&wire_claim_pk),
        |_| true,
        20,
    )
    .unwrap();

    assert_eq!(state.get(&destination_id).unwrap().balance, amount);
    assert_eq!(
        state.get(&destination_id).unwrap().auth_pubkey,
        on_chain_auth,
        "proof claim must not rotate auth when account already exists"
    );
}

#[test]
fn claim_with_proof_requires_auth_material_for_new_native_destination() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [26u8; 32];
    let blinded_binding = [0xBDu8; 32];
    let destination_id = AccountId::from_bytes([0x27; 32]);
    let destination = VmAddress::Native(destination_id);
    let amount = 4_500u64;
    let expiry = 100u64;

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        amount,
        ChainId::Native,
        None,
        0,
        None,
        None,
        None,
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    let proof = auth::ClaimProof {
        public_inputs: auth::ClaimProofPublicInputs {
            identity_commitment: [0x13; 32],
            claim_message_digest: auth::claim_message(
                ChainId::Native,
                None,
                0,
                &intent_id,
                &blinded_binding,
                amount,
                &destination,
                expiry,
                0,
            ),
            auth_commitment: [0x43; 32],
            chain: ChainId::Native,
            mint: None,
            binding_epoch: 0,
            blinded_binding,
            intent_id,
            amount,
            destination,
            expiry,
            nonce: 0,
        },
        proof_bytes: vec![8, 8, 8],
    };

    let result = executor::claim_intent_with_proof(
        &mut state,
        &mut store,
        &intent_id,
        &proof,
        None,
        |_| true,
        20,
    );
    assert!(result.is_err());
}
