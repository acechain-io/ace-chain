use ace_hfi_pay::executor::{self, IntentStore};
use ace_hfi_pay::intent::ChainId;
use ace_hfi_pay::registry::{self, RecipientRegistry};
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::idcom_xid;
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
    let sender_pubkey = make_keypair(1).0;
    state.insert(Account::with_auth(sender, 100_000, sender_pubkey));
    (state, IntentStore::new(), sender)
}

#[test]
fn register_and_lookup() {
    let mut reg = RecipientRegistry::new();
    let xid = [0xBBu8; 32];
    let (pk, sk) = make_keypair(5);
    let identifier = b"bob@example.com";
    let identity_commitment = [0x11u8; 32];
    let claim_binding_handle = [0x22u8; 32];

    let msg = registry::registration_message(&xid, identifier);
    let sig = sign_msg(&sk, &msg);

    let recipient = reg
        .register(
            identifier,
            xid,
            identity_commitment,
            claim_binding_handle,
            &pk,
            &sig,
        )
        .unwrap();
    assert_eq!(recipient.xid, xid);
    assert_eq!(recipient.account_id, AccountId::from_bytes(idcom_xid(&xid)));

    assert!(reg.is_registered(identifier));
    assert!(!reg.is_registered(b"other@example.com"));

    let looked_up = reg.lookup(identifier).unwrap();
    assert_eq!(looked_up.xid, xid);
}

#[test]
fn register_wrong_signature_rejected() {
    let mut reg = RecipientRegistry::new();
    let xid = [0xCCu8; 32];
    let (pk, _sk) = make_keypair(6);
    let (_wrong_pk, wrong_sk) = make_keypair(7);

    let msg = registry::registration_message(&xid, b"alice@example.com");
    let bad_sig = sign_msg(&wrong_sk, &msg);

    let result = reg.register(
        b"alice@example.com",
        xid,
        [0u8; 32],
        [0u8; 32],
        &pk,
        &bad_sig,
    );
    assert!(result.is_err());
    assert!(!reg.is_registered(b"alice@example.com"));
}

#[test]
fn direct_deposit_full_flow() {
    let (mut state, mut store, sender) = setup();
    let mut reg = RecipientRegistry::new();

    // Bob registers with XID
    let xid = [0xDDu8; 32];
    let (bob_pk, bob_sk) = make_keypair(10);
    let identifier = b"bob@example.com";
    let identity_commitment = [0x11u8; 32];
    let claim_binding_handle = [0x22u8; 32];
    let msg = registry::registration_message(&xid, identifier);
    let sig = sign_msg(&bob_sk, &msg);
    let recipient = reg
        .register(
            identifier,
            xid,
            identity_commitment,
            claim_binding_handle,
            &bob_pk,
            &sig,
        )
        .unwrap();

    let intent_id = [0x42u8; 32];
    let blinded_binding = [0xBBu8; 32];
    let amount = 8_000u64;

    // Alice sends to Bob via direct deposit
    executor::direct_deposit(
        &mut state,
        &mut store,
        intent_id,
        blinded_binding,
        amount,
        ChainId::Native,
        None,
        &sender,
        &recipient,
        100,
        10,
    )
    .unwrap();

    // Verify sender debited
    assert_eq!(state.get(&sender).unwrap().balance, 100_000 - amount);

    // Verify recipient credited
    let bob_account_id = AccountId::from_bytes(idcom_xid(&xid));
    assert_eq!(state.get(&bob_account_id).unwrap().balance, amount);
    assert_eq!(state.get(&bob_account_id).unwrap().auth_pubkey, bob_pk);

    // Verify intent recorded as Claimed
    let intent = store.get(&intent_id).unwrap();
    assert_eq!(intent.status, ace_hfi_pay::IntentStatus::Claimed);
    assert_eq!(intent.owner, Some(bob_account_id));
}

#[test]
fn direct_deposit_with_token_mint() {
    let (mut state, mut store, sender) = setup();
    let mut reg = RecipientRegistry::new();

    let xid = [0xEEu8; 32];
    let (bob_pk, bob_sk) = make_keypair(11);
    let identifier = b"bob@example.com";
    let msg = registry::registration_message(&xid, identifier);
    let sig = sign_msg(&bob_sk, &msg);
    let recipient = reg
        .register(identifier, xid, [0u8; 32], [0u8; 32], &bob_pk, &sig)
        .unwrap();

    // Set up a token mint and give sender some balance
    let mint = [0xFFu8; 32];
    let authority = AccountId::from_bytes([0xA0u8; 32]);
    ace_n_vm::token_runtime::create_mint(&mut state, &mint, 6, authority.as_bytes()).unwrap();
    ace_n_vm::token_runtime::mint_to_owner(
        &mut state,
        &mint,
        sender.as_bytes(),
        50_000,
        &authority,
    )
    .unwrap();

    let intent_id = [0x43u8; 32];
    let amount = 10_000u64;

    executor::direct_deposit(
        &mut state,
        &mut store,
        intent_id,
        [0u8; 32],
        amount,
        ChainId::Evm,
        Some(mint),
        &sender,
        &recipient,
        100,
        10,
    )
    .unwrap();

    // Verify token balances
    let bob_account_id = AccountId::from_bytes(idcom_xid(&xid));
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, &mint, &sender),
        40_000
    );
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, &mint, &bob_account_id),
        10_000
    );
}

#[test]
fn direct_deposit_insufficient_balance_fails() {
    let (mut state, mut store, sender) = setup();
    let mut reg = RecipientRegistry::new();

    let xid = [0xAAu8; 32];
    let (pk, sk) = make_keypair(12);
    let msg = registry::registration_message(&xid, b"test@example.com");
    let sig = sign_msg(&sk, &msg);
    let recipient = reg
        .register(b"test@example.com", xid, [0u8; 32], [0u8; 32], &pk, &sig)
        .unwrap();

    let result = executor::direct_deposit(
        &mut state,
        &mut store,
        [0x44u8; 32],
        [0u8; 32],
        999_999, // more than sender has
        ChainId::Native,
        None,
        &sender,
        &recipient,
        100,
        10,
    );
    assert!(result.is_err());
}

#[test]
fn xid_derived_account_id_is_deterministic() {
    let xid = [0x42u8; 32];
    let id1 = idcom_xid(&xid);
    let id2 = idcom_xid(&xid);
    assert_eq!(id1, id2);

    let other_xid = [0x43u8; 32];
    let id3 = idcom_xid(&other_xid);
    assert_ne!(id1, id3);
}
