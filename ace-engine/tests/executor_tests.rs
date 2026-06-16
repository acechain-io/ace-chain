use ace_engine::executor::{execute_block, execute_transaction, ExecutionPolicy, TransactionOp};
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
use ace_runtime::crypto::TaggedPubkey;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::transaction::Transaction;
use sha2::{Digest, Sha256};

fn make_tx(sender_id: [u8; 32], sender_seed: [u8; 32], payload: Vec<u8>) -> Transaction {
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let result = hasher.finalize();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&result);
    let domain = Domain::new(1, 0);

    Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom: sender_id,
            domain,
            context_tag: [0u8; 16],
            credential: make_credential(&sender_seed, &obj_hash, &sender_id, &domain, &[0u8; 16]),
        },
    )
}

fn setup() -> (StateTree, AccountId, [u8; 32], AccountId, [u8; 32]) {
    let mut tree = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    let bob = AccountId::from_bytes([2u8; 32]);
    let alice_seed = make_auth_pubkey_seed(0x11);
    let bob_seed = make_auth_pubkey_seed(0x22);
    tree.insert(Account::with_auth(
        alice,
        10_000,
        auth_public_key_from_seed(&alice_seed),
    ));
    tree.insert(Account::with_auth(
        bob,
        5_000,
        auth_public_key_from_seed(&bob_seed),
    ));
    (tree, alice, alice_seed, bob, bob_seed)
}

fn make_auth_pubkey_seed(seed: u8) -> [u8; 32] {
    [seed; 32]
}

#[test]
fn execute_transfer_transaction() {
    let (mut tree, alice, alice_seed, bob, _) = setup();
    let op = TransactionOp::Transfer {
        nonce: 0,
        to: bob,
        amount: 100,
    };
    let tx = make_tx(alice.0, alice_seed, op.encode());

    let policy = ExecutionPolicy::default();
    let receipt = execute_transaction(&mut tree, &tx, &policy).unwrap();
    assert!(receipt.success);
    assert_eq!(tree.get(&alice).unwrap().balance, 9_900);
    assert_eq!(tree.get(&bob).unwrap().balance, 5_100);
}

#[test]
fn execute_create_account() {
    let (mut tree, _alice, _alice_seed, _, _) = setup();
    // Self-creation: sender == id_com (sender does not yet exist in tree)
    let new_id = AccountId::from_bytes([99u8; 32]);
    let new_seed = make_auth_pubkey_seed(0x44);
    let auth_pubkey = auth_public_key_from_seed(&new_seed);
    let op = TransactionOp::CreateAccount {
        id_com: new_id,
        auth_pubkey: auth_pubkey.clone(),
    };
    // Sender is new_id itself (self-creation)
    let tx = make_tx(new_id.0, new_seed, op.encode());

    let policy = ExecutionPolicy::default();
    let receipt = execute_transaction(&mut tree, &tx, &policy).unwrap();
    assert!(receipt.success);
    assert!(tree.contains(&new_id));
    assert_eq!(tree.get(&new_id).unwrap().balance, 0);
    assert_eq!(tree.get(&new_id).unwrap().auth_pubkey, auth_pubkey);
}

#[test]
fn execute_create_duplicate_account_fails() {
    let (mut tree, alice, alice_seed, bob, _) = setup();
    let op = TransactionOp::CreateAccount {
        id_com: bob,
        auth_pubkey: auth_public_key_from_seed(&make_auth_pubkey_seed(0x55)),
    };
    let tx = make_tx(alice.0, alice_seed, op.encode());

    let policy = ExecutionPolicy::default();
    let result = execute_transaction(&mut tree, &tx, &policy);
    assert!(result.is_err());
}

#[test]
fn execute_block_mixed_results() {
    let (mut tree, alice, alice_seed, bob, _) = setup();

    let txs = vec![
        // Valid transfer
        make_tx(
            alice.0,
            alice_seed,
            TransactionOp::Transfer {
                nonce: 0,
                to: bob,
                amount: 100,
            }
            .encode(),
        ),
        // Invalid: insufficient balance
        make_tx(
            alice.0,
            alice_seed,
            TransactionOp::Transfer {
                nonce: 1,
                to: bob,
                amount: 999_999,
            }
            .encode(),
        ),
        // Valid transfer
        make_tx(
            alice.0,
            alice_seed,
            TransactionOp::Transfer {
                nonce: 1,
                to: bob,
                amount: 50,
            }
            .encode(),
        ),
    ];

    let policy = ExecutionPolicy::default();
    let receipts = execute_block(&mut tree, &txs, &policy);
    assert_eq!(receipts.len(), 3);
    assert!(receipts[0].success);
    assert!(!receipts[1].success);
    assert!(receipts[1].error.is_some());
    assert!(receipts[2].success);

    assert_eq!(tree.get(&alice).unwrap().balance, 10_000 - 100 - 50);
}

#[test]
fn transaction_op_encode_decode_roundtrip() {
    let to = AccountId::from_bytes([42u8; 32]);
    let op = TransactionOp::Transfer {
        nonce: 7,
        to,
        amount: 12345,
    };
    let encoded = op.encode();
    let decoded = TransactionOp::decode(&encoded).unwrap();
    match decoded {
        TransactionOp::Transfer {
            nonce,
            to: t,
            amount: a,
        } => {
            assert_eq!(nonce, 7);
            assert_eq!(t, to);
            assert_eq!(a, 12345);
        }
        _ => panic!("wrong op type"),
    }

    let id = AccountId::from_bytes([77u8; 32]);
    let auth_pubkey = auth_public_key_from_seed(&make_auth_pubkey_seed(0x66));
    let op2 = TransactionOp::CreateAccount {
        id_com: id,
        auth_pubkey: auth_pubkey.clone(),
    };
    let encoded2 = op2.encode();
    let decoded2 = TransactionOp::decode(&encoded2).unwrap();
    match decoded2 {
        TransactionOp::CreateAccount {
            id_com,
            auth_pubkey: decoded_auth_pubkey,
        } => {
            assert_eq!(id_com, id);
            assert_eq!(decoded_auth_pubkey, auth_pubkey);
        }
        _ => panic!("wrong op type"),
    }
}

#[test]
fn create_account_rejects_zero_auth_pubkey() {
    let id = AccountId::from_bytes([7u8; 32]);
    let payload = TransactionOp::CreateAccount {
        id_com: id,
        auth_pubkey: TaggedPubkey::ed25519([0u8; 32]),
    }
    .encode();
    let result = TransactionOp::decode(&payload);
    assert!(result.is_err());
}

#[test]
fn invalid_opcode_rejected() {
    let result = TransactionOp::decode(&[0xFF, 0, 0]);
    assert!(result.is_err());
}

#[test]
fn empty_payload_rejected() {
    let result = TransactionOp::decode(&[]);
    assert!(result.is_err());
}

#[test]
fn state_root_changes_after_execution() {
    let (mut tree, alice, alice_seed, bob, _) = setup();
    let root_before = tree.compute_root();

    let op = TransactionOp::Transfer {
        nonce: 0,
        to: bob,
        amount: 1,
    };
    let tx = make_tx(alice.0, alice_seed, op.encode());
    let policy = ExecutionPolicy::default();
    execute_transaction(&mut tree, &tx, &policy).unwrap();

    let root_after = tree.compute_root();
    assert_ne!(root_before, root_after);
}

#[test]
fn replayed_transfer_nonce_is_rejected() {
    let (mut tree, alice, alice_seed, bob, _) = setup();
    let payload = TransactionOp::Transfer {
        nonce: 0,
        to: bob,
        amount: 100,
    }
    .encode();

    let first = make_tx(alice.0, alice_seed, payload.clone());
    let policy = ExecutionPolicy::default();
    execute_transaction(&mut tree, &first, &policy).unwrap();

    let replay = make_tx(alice.0, alice_seed, payload);
    let err = execute_transaction(&mut tree, &replay, &policy).unwrap_err();
    assert!(err.to_string().contains("invalid nonce"));
}

// ── Multi-key authentication tests ──

fn make_tx_ml_dsa(sender_id: [u8; 32], sender_seed: [u8; 32], payload: Vec<u8>) -> Transaction {
    use ace_runtime::crypto::attestation::make_credential_ml_dsa_44;
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let result = hasher.finalize();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&result);
    let domain = Domain::new(1, 0);

    Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom: sender_id,
            domain,
            context_tag: [0u8; 16],
            credential: make_credential_ml_dsa_44(
                &sender_seed,
                &obj_hash,
                &sender_id,
                &domain,
                &[0u8; 16],
            ),
        },
    )
}

fn ml_dsa_pubkey_from_seed(seed: &[u8; 32]) -> TaggedPubkey {
    use ace_runtime::crypto::sig_algo::{LocalSigningKey, SignatureAlgorithm};
    LocalSigningKey::from_seed(seed, SignatureAlgorithm::MlDsa44)
        .unwrap()
        .public_key()
}

#[test]
fn add_auth_key_success() {
    let (mut tree, alice, alice_seed, _bob, _) = setup();
    let ml_dsa_seed = [0x77u8; 32];
    let ml_dsa_pk = ml_dsa_pubkey_from_seed(&ml_dsa_seed);

    // Add ML-DSA-44 key to Alice's account (which uses Ed25519 primary key)
    let op = TransactionOp::AddAuthKey {
        nonce: 0,
        auth_pubkey: ml_dsa_pk.clone(),
    };
    let tx = make_tx(alice.0, alice_seed, op.encode());
    let policy = ExecutionPolicy::default();
    let receipt = execute_transaction(&mut tree, &tx, &policy).unwrap();
    assert!(receipt.success);

    // Verify the key was added
    let account = tree.get(&alice).unwrap();
    assert_eq!(account.auth_keys.len(), 1);
    assert_eq!(account.auth_keys[0], ml_dsa_pk);
    assert_eq!(account.nonce, 1);

    // Original primary key should be unchanged
    assert_eq!(account.auth_pubkey, auth_public_key_from_seed(&alice_seed));
}

#[test]
fn add_auth_key_duplicate_algorithm_rejected() {
    let (mut tree, alice, _alice_seed, _bob, _) = setup();

    // Alice already has Ed25519 primary key. Try adding another Ed25519 key.
    let another_ed_seed = [0x88u8; 32];
    let another_ed_pk = auth_public_key_from_seed(&another_ed_seed);
    let op = TransactionOp::AddAuthKey {
        nonce: 0,
        auth_pubkey: another_ed_pk,
    };
    let tx = make_tx(alice.0, make_auth_pubkey_seed(0x11), op.encode());
    let policy = ExecutionPolicy::default();
    let result = execute_transaction(&mut tree, &tx, &policy);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("primary key already uses"),
        "should reject duplicate algorithm"
    );
}

#[test]
fn add_auth_key_max_keys() {
    let alice = AccountId::from_bytes([1u8; 32]);
    let alice_seed = make_auth_pubkey_seed(0x11);
    let mut tree = StateTree::new();
    // Create alice with Ed25519 primary key
    tree.insert(Account::with_auth(
        alice,
        10_000,
        auth_public_key_from_seed(&alice_seed),
    ));

    // Manually add keys for Secp256k1 and HmacSha256 to fill up slots
    // (max 4 total = 1 primary + 3 additional)
    {
        let account = tree.get_mut(&alice).unwrap();
        account
            .add_auth_key(TaggedPubkey::secp256k1([0xAA; 33]))
            .unwrap();
        account
            .add_auth_key(TaggedPubkey::hmac_sha256([0xBB; 32]))
            .unwrap();
    }

    // Now add ML-DSA-44 (3rd additional = 4th total, should succeed)
    let ml_dsa_seed = [0xCC; 32];
    let ml_dsa_pk = ml_dsa_pubkey_from_seed(&ml_dsa_seed);
    let op = TransactionOp::AddAuthKey {
        nonce: 0,
        auth_pubkey: ml_dsa_pk,
    };
    let tx = make_tx(alice.0, alice_seed, op.encode());
    let policy = ExecutionPolicy::default();
    let result = execute_transaction(&mut tree, &tx, &policy);
    // Should fail because we already have 3 additional keys (total 4 = max)
    // The add_auth_key check: auth_keys.len() + 1 >= MAX_AUTH_KEYS (4)
    // auth_keys.len() = 2, 2 + 1 = 3, 3 >= 4 is false, so this should succeed
    // After adding: auth_keys.len() = 3, next would be 3 + 1 = 4 >= 4 = true, rejected
    assert!(result.is_ok());

    // Verify account now has 3 additional keys
    assert_eq!(tree.get(&alice).unwrap().auth_keys.len(), 3);
}

#[test]
fn set_auth_pubkey_rotates_by_algorithm() {
    let (mut tree, alice, _alice_seed, _bob, _) = setup();

    // First add an ML-DSA-44 key
    let ml_dsa_seed = [0x77u8; 32];
    let ml_dsa_pk = ml_dsa_pubkey_from_seed(&ml_dsa_seed);
    {
        let account = tree.get_mut(&alice).unwrap();
        account.add_auth_key(ml_dsa_pk.clone()).unwrap();
    }

    // Now rotate the Ed25519 key (primary) using SetAuthPubkey
    let new_ed_seed = [0x99u8; 32];
    let new_ed_pk = auth_public_key_from_seed(&new_ed_seed);
    let op = TransactionOp::SetAuthPubkey {
        nonce: 0,
        auth_pubkey: new_ed_pk.clone(),
    };
    let tx = make_tx(alice.0, make_auth_pubkey_seed(0x11), op.encode());
    let policy = ExecutionPolicy::default();
    let receipt = execute_transaction(&mut tree, &tx, &policy).unwrap();
    assert!(receipt.success);

    // Verify primary key was rotated
    let account = tree.get(&alice).unwrap();
    assert_eq!(account.auth_pubkey, new_ed_pk);
    // ML-DSA-44 key should be unchanged
    assert_eq!(account.auth_keys.len(), 1);
    assert_eq!(account.auth_keys[0], ml_dsa_pk);
}

#[test]
fn set_auth_pubkey_promotes_first_real_key_when_primary_is_zero() {
    let sender = AccountId::from_bytes([9u8; 32]);
    let mut tree = StateTree::new();
    tree.insert(Account::with_balance(sender, 1_000));

    let ml_dsa_seed = [0x5Au8; 32];
    let ml_dsa_pk = ml_dsa_pubkey_from_seed(&ml_dsa_seed);
    let op = TransactionOp::SetAuthPubkey {
        nonce: 0,
        auth_pubkey: ml_dsa_pk.clone(),
    };
    let tx = make_tx_ml_dsa(sender.0, ml_dsa_seed, op.encode());

    let policy = ExecutionPolicy::default();
    let receipt = execute_transaction(&mut tree, &tx, &policy).unwrap();
    assert!(receipt.success);

    let account = tree.get(&sender).unwrap();
    assert_eq!(account.auth_pubkey, ml_dsa_pk);
    assert!(account.auth_keys.is_empty());
    assert!(account.has_provisioned_auth_key());
}

#[test]
fn add_auth_key_encode_decode_roundtrip() {
    let ml_dsa_pk = ml_dsa_pubkey_from_seed(&[0x55u8; 32]);
    let op = TransactionOp::AddAuthKey {
        nonce: 7,
        auth_pubkey: ml_dsa_pk.clone(),
    };
    let encoded = op.encode();
    let decoded = TransactionOp::decode(&encoded).unwrap();
    match decoded {
        TransactionOp::AddAuthKey { nonce, auth_pubkey } => {
            assert_eq!(nonce, 7);
            assert_eq!(auth_pubkey, ml_dsa_pk);
        }
        _ => panic!("wrong op type"),
    }
}

/// Portal `buildSetAuthPubkeyPayload` appends `TaggedPubkey::to_wire_bytes()` (not raw 1312).
#[test]
fn set_auth_pubkey_decodes_ml_dsa_wire_after_nonce() {
    let ml_dsa_pk = ml_dsa_pubkey_from_seed(&[0x55u8; 32]);
    let nonce = 42u64;
    let wire = ml_dsa_pk.to_wire_bytes();
    assert_eq!(wire.len(), 1315);

    let mut payload = Vec::with_capacity(9 + wire.len());
    payload.push(0x03);
    payload.extend_from_slice(&nonce.to_le_bytes());
    payload.extend_from_slice(&wire);

    let decoded = TransactionOp::decode(&payload).unwrap();
    match decoded {
        TransactionOp::SetAuthPubkey {
            nonce: n,
            auth_pubkey,
        } => {
            assert_eq!(n, nonce);
            assert_eq!(auth_pubkey, ml_dsa_pk);
        }
        _ => panic!("wrong op type"),
    }
}

#[test]
fn set_auth_pubkey_replay_nonce_is_rejected() {
    let (mut tree, alice, alice_seed, _bob, _) = setup();
    let new_ed_pk = auth_public_key_from_seed(&[0x99; 32]);
    let payload = TransactionOp::SetAuthPubkey {
        nonce: 0,
        auth_pubkey: new_ed_pk,
    }
    .encode();

    let first = make_tx(alice.0, alice_seed, payload.clone());
    let policy = ExecutionPolicy::default();
    execute_transaction(&mut tree, &first, &policy).expect("first key rotation");
    assert_eq!(tree.get(&alice).unwrap().nonce, 1);

    let replay = make_tx(alice.0, [0x99; 32], payload);
    let err = execute_transaction(&mut tree, &replay, &policy).expect_err("replay should fail");
    assert!(err.to_string().contains("invalid nonce"));
}

#[test]
fn provisioned_account_auth_updates_require_current_key_signature() {
    let (mut tree, alice, _alice_seed, _bob, _) = setup();
    let ml_dsa_seed = [0x77u8; 32];
    let ml_dsa_pk = ml_dsa_pubkey_from_seed(&ml_dsa_seed);
    let tx = make_tx_ml_dsa(
        alice.0,
        ml_dsa_seed,
        TransactionOp::AddAuthKey {
            nonce: 0,
            auth_pubkey: ml_dsa_pk,
        }
        .encode(),
    );

    let policy = ExecutionPolicy::default();
    let err = execute_transaction(&mut tree, &tx, &policy)
        .expect_err("new-key signature must be rejected");
    assert!(err.to_string().contains("invalid credential"));
}

// ── ApproveValidator founder gate (execution layer) ──

fn approve_validator_payload(candidate: AccountId, nonce: u64, signing_pubkey: Vec<u8>) -> Vec<u8> {
    TransactionOp::ApproveValidator {
        nonce,
        candidate_id_com: candidate,
        signing_pubkey,
    }
    .encode()
}

#[test]
fn approve_validator_rejected_when_founder_not_configured_at_execution() {
    let founder_seed = make_auth_pubkey_seed(0xF0);
    let founder = AccountId::from_bytes([0xF0; 32]);
    let mut tree = StateTree::new();
    tree.insert(Account::with_auth(
        founder,
        1_000,
        auth_public_key_from_seed(&founder_seed),
    ));

    let candidate = AccountId::from_bytes([0xC0; 32]);
    let tx = make_tx(
        founder.0,
        founder_seed,
        approve_validator_payload(candidate, 0, vec![0xAB; 32]),
    );
    let policy = ExecutionPolicy::default();

    let err = execute_transaction(&mut tree, &tx, &policy).unwrap_err();
    assert!(err.to_string().contains("disabled"));
}

#[test]
fn approve_validator_rejected_for_non_founder_at_execution() {
    let founder = AccountId::from_bytes([0xF0; 32]);
    let impostor_seed = make_auth_pubkey_seed(0x11);
    let impostor = AccountId::from_bytes([0x11; 32]);
    let mut tree = StateTree::new();
    tree.insert(Account::with_auth(
        impostor,
        1_000,
        auth_public_key_from_seed(&impostor_seed),
    ));

    let candidate = AccountId::from_bytes([0xC0; 32]);
    let tx = make_tx(
        impostor.0,
        impostor_seed,
        approve_validator_payload(candidate, 0, vec![0xAB; 32]),
    );
    let policy = ExecutionPolicy {
        founder_id_com: Some(founder),
    };

    let err = execute_transaction(&mut tree, &tx, &policy).unwrap_err();
    assert!(err.to_string().contains("not the founder"));
}

#[test]
fn approve_validator_founders_nonce_consumed_at_execution() {
    let founder_seed = make_auth_pubkey_seed(0xF0);
    let founder = AccountId::from_bytes([0xF0; 32]);
    let mut tree = StateTree::new();
    tree.insert(Account::with_auth(
        founder,
        1_000,
        auth_public_key_from_seed(&founder_seed),
    ));

    let candidate = AccountId::from_bytes([0xC0; 32]);
    let tx = make_tx(
        founder.0,
        founder_seed,
        approve_validator_payload(candidate, 0, vec![0xAB; 32]),
    );
    let policy = ExecutionPolicy {
        founder_id_com: Some(founder),
    };

    let receipt = execute_transaction(&mut tree, &tx, &policy).unwrap();
    assert!(receipt.success);
    assert_eq!(tree.get(&founder).unwrap().nonce, 1);
}
