use ace_hfi_pay::auth;
use ace_hfi_pay::cross_vm;
use ace_hfi_pay::executor::{self, IntentStore};
use ace_hfi_pay::intent::{ChainId, IntentStatus, VmAddress};
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::legacy_idcom_evm;
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

fn setup() -> (StateTree, IntentStore, AccountId) {
    let mut state = StateTree::new();
    let sender = AccountId::from_bytes([1u8; 32]);
    state.insert(Account::with_auth(
        sender,
        50_000,
        TaggedPubkey::ed25519([1u8; 32]),
    ));
    (state, IntentStore::new(), sender)
}

#[test]
fn cross_vm_deposit_native_claim_evm() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [20u8; 32];
    let (recipient_pk, recipient_sk) = make_keypair(3);
    let dest_evm_addr = [40u8; 20];
    let dest_evm = VmAddress::Evm(dest_evm_addr);
    let expected_owner = AccountId::from_bytes(legacy_idcom_evm(&dest_evm_addr));
    let amount = 10_000u64;
    let expiry = 100u64;

    // Create and fund on Native
    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
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

    // Cross-VM claim: deposit on Native, claim to EVM address
    let msg = auth::cross_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &[0u8; 32],
        amount,
        &dest_evm,
        expiry,
        0,
    );
    let sig = sign_msg(&recipient_sk, &msg);

    cross_vm::cross_vm_claim(
        &mut state,
        &mut store,
        &intent_id,
        dest_evm,
        &recipient_pk,
        &sig,
        50,
    )
    .unwrap();

    assert_eq!(store.get(&intent_id).unwrap().status, IntentStatus::Claimed);
    assert_eq!(store.get(&intent_id).unwrap().owner, Some(expected_owner));
    assert_eq!(state.get(&expected_owner).unwrap().balance, amount);
    assert_eq!(state.resolve_evm(&dest_evm_addr), Some(&expected_owner));
}

#[test]
fn cross_vm_deposit_evm_claim_svm() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [21u8; 32];
    let (recipient_pk, recipient_sk) = make_keypair(4);
    let expected_owner = AccountId::from_bytes([50u8; 32]);
    let dest_svm = VmAddress::Svm(expected_owner);
    let amount = 7_500u64;
    let expiry = 200u64;

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
        amount,
        ChainId::Evm,
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

    let msg = auth::cross_claim_message(
        ChainId::Evm,
        None,
        0,
        &intent_id,
        &[0u8; 32],
        amount,
        &dest_svm,
        expiry,
        0,
    );
    let sig = sign_msg(&recipient_sk, &msg);

    cross_vm::cross_vm_claim(
        &mut state,
        &mut store,
        &intent_id,
        dest_svm,
        &recipient_pk,
        &sig,
        100,
    )
    .unwrap();

    assert_eq!(state.get(&expected_owner).unwrap().balance, amount);
}

#[test]
fn cross_vm_claim_wrong_signature_rejected() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [22u8; 32];
    let (recipient_pk, _) = make_keypair(5);
    let (_, wrong_sk) = make_keypair(6);
    let dest = VmAddress::Bvm(AccountId::from_bytes([60u8; 32]));
    let expiry = 100u64;

    executor::create_intent(
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
        expiry,
        10,
    )
    .unwrap();
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    let msg = auth::cross_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &[0u8; 32],
        5000,
        &dest,
        expiry,
        0,
    );
    let sig = sign_msg(&wrong_sk, &msg);

    let result = cross_vm::cross_vm_claim(
        &mut state,
        &mut store,
        &intent_id,
        dest,
        &recipient_pk,
        &sig,
        50,
    );
    assert!(result.is_err());
}

#[test]
fn cross_vm_claim_after_expiry_rejected() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [23u8; 32];
    let (pk, sk) = make_keypair(7);
    let dest = VmAddress::Tvm([70u8; 20]);
    let expiry = 50u64;

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
        3000,
        ChainId::Svm,
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

    let msg = auth::cross_claim_message(
        ChainId::Svm,
        None,
        0,
        &intent_id,
        &[0u8; 32],
        3000,
        &dest,
        expiry,
        0,
    );
    let sig = sign_msg(&sk, &msg);

    let result = cross_vm::cross_vm_claim(
        &mut state, &mut store, &intent_id, dest, &pk, &sig, 51, // past expiry
    );
    assert!(result.is_err());
}

#[test]
fn cross_vm_claim_same_chain_rejected() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [24u8; 32];
    let (pk, sk) = make_keypair(8);
    let dest = VmAddress::Native(AccountId::from_bytes([0x99; 32]));

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
        4000,
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

    let msg = auth::cross_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &[0u8; 32],
        4000,
        &dest,
        100,
        0,
    );
    let sig = sign_msg(&sk, &msg);
    let result = cross_vm::cross_vm_claim(&mut state, &mut store, &intent_id, dest, &pk, &sig, 20);
    assert!(result.is_err());
}

#[test]
fn cross_vm_claim_requires_full_quote_balance() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [25u8; 32];
    let (pk, sk) = make_keypair(9);
    let dest = VmAddress::Evm([0x55; 20]);
    let deposit = executor::create_intent(
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
    state.get_mut(&deposit).unwrap().balance += 1000;
    store.get_mut(&intent_id).unwrap().status = IntentStatus::Funded;

    let msg = auth::cross_claim_message(
        ChainId::Native,
        None,
        0,
        &intent_id,
        &[0u8; 32],
        5000,
        &dest,
        100,
        0,
    );
    let sig = sign_msg(&sk, &msg);
    let result = cross_vm::cross_vm_claim(&mut state, &mut store, &intent_id, dest, &pk, &sig, 20);
    assert!(result.is_err());
}

#[test]
fn cross_vm_claim_to_new_native_account_sets_auth_key() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [26u8; 32];
    let (pk, sk) = make_keypair(10);
    let dest_owner = AccountId::from_bytes([0x66; 32]);
    let dest = VmAddress::Native(dest_owner);

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
        5000,
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
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    let msg = auth::cross_claim_message(
        ChainId::Evm,
        None,
        0,
        &intent_id,
        &[0u8; 32],
        5000,
        &dest,
        100,
        0,
    );
    let sig = sign_msg(&sk, &msg);
    cross_vm::cross_vm_claim(&mut state, &mut store, &intent_id, dest, &pk, &sig, 20).unwrap();

    assert_eq!(state.get(&dest_owner).unwrap().auth_pubkey, pk);
}

#[test]
fn cross_vm_claim_to_existing_native_account_with_different_key_fails() {
    let (mut state, mut store, sender) = setup();
    let intent_id = [27u8; 32];
    let (pk, sk) = make_keypair(11);
    let existing_owner = AccountId::from_bytes([0x67; 32]);
    state.insert(Account::with_auth(
        existing_owner,
        0,
        TaggedPubkey::ed25519([0x68; 32]),
    ));
    let dest = VmAddress::Native(existing_owner);

    executor::create_intent(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
        5000,
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
    executor::fund_intent(&mut state, &mut store, &intent_id, &sender).unwrap();

    let msg = auth::cross_claim_message(
        ChainId::Evm,
        None,
        0,
        &intent_id,
        &[0u8; 32],
        5000,
        &dest,
        100,
        0,
    );
    let sig = sign_msg(&sk, &msg);
    let result = cross_vm::cross_vm_claim(&mut state, &mut store, &intent_id, dest, &pk, &sig, 20);
    assert!(result.is_err());
}
