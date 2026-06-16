use ace_engine::executor::TransactionOp;
use ace_mempool::error::MempoolError;
use ace_mempool::pool::{Mempool, MempoolConfig, MempoolStateCounts};
use ace_model::account::AccountId;
use ace_model::sharded_state::ShardedState;
use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
use ace_runtime::crypto::sig_algo::SignatureAlgorithm;
use ace_runtime::crypto::TaggedSignature;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::transaction::Transaction;
use ed25519_dalek::{Signer, SigningKey};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn make_valid_tx(payload: &[u8]) -> Transaction {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let result = hasher.finalize();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&result);

    Transaction::new(
        payload.to_vec(),
        Attestation {
            obj_hash,
            idcom: [1u8; 32],
            domain: Domain::new(122_766, 0),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
    )
}

fn make_signed_create_account_tx(sender_seed: [u8; 32], sender: AccountId) -> Transaction {
    let payload = TransactionOp::CreateAccount {
        id_com: sender,
        auth_pubkey: auth_public_key_from_seed(&sender_seed),
    }
    .encode();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&Sha256::digest(&payload));
    let domain = Domain::new(122_766, 0);
    Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom: sender.0,
            domain,
            context_tag: [0u8; 16],
            credential: make_credential(&sender_seed, &obj_hash, &sender.0, &domain, &[0u8; 16]),
        },
    )
}

fn make_signed_transfer_tx(
    sender_seed: [u8; 32],
    sender: AccountId,
    nonce: u64,
    recipient: AccountId,
    amount: u64,
) -> Transaction {
    let payload = TransactionOp::Transfer {
        nonce,
        to: recipient,
        amount,
    }
    .encode();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&Sha256::digest(&payload));
    let domain = Domain::new(122_766, 0);
    Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom: sender.0,
            domain,
            context_tag: [0u8; 16],
            credential: make_credential(&sender_seed, &obj_hash, &sender.0, &domain, &[0u8; 16]),
        },
    )
}

fn make_bridge_deposit_tx(signing_key: &SigningKey) -> Transaction {
    let deposit = ace_defi::DepositRecord {
        deposit_id: [0xA1; 32],
        intent_id: [0xA2; 32],
        asset: ace_defi::ExternalAsset::Native(ace_defi::ExternalChain::Ethereum),
        amount: 100,
        recipient: AccountId([0xA3; 32]),
        processed_at: 10,
    };
    let signature = signing_key.sign(&ace_defi::hash_deposit_record(&deposit));
    let signed = ace_defi::SignedDepositRecord {
        deposit,
        relayer_pubkey: signing_key.verifying_key().to_bytes(),
        relayer_signature: signature.to_bytes(),
    };
    let payload = ace_defi::encode_signed_deposit_payload(&signed).unwrap();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&Sha256::digest(&payload));
    Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom: ace_defi::bridge_deposit_tx_idcom(&signed),
            domain: Domain::new(122_766, 0),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
    )
}

fn make_signed_add_auth_key_tx(
    sender_seed: [u8; 32],
    sender: AccountId,
    nonce: u64,
    auth_pubkey: ace_runtime::crypto::TaggedPubkey,
) -> Transaction {
    let payload = TransactionOp::AddAuthKey { nonce, auth_pubkey }.encode();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&Sha256::digest(&payload));
    let domain = Domain::new(122_766, 0);
    Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom: sender.0,
            domain,
            context_tag: [0u8; 16],
            credential: make_credential(&sender_seed, &obj_hash, &sender.0, &domain, &[0u8; 16]),
        },
    )
}

#[test]
fn insert_and_get() {
    let pool = Mempool::new(MempoolConfig::default());
    let tx = make_valid_tx(b"hello");
    let hash = pool.insert(tx.clone()).unwrap();

    assert!(pool.contains(&hash));
    assert_eq!(pool.pending_count(), 1);
    assert_eq!(pool.get(&hash).unwrap().payload, b"hello");
}

#[test]
fn reject_duplicate() {
    let pool = Mempool::new(MempoolConfig::default());
    let tx = make_valid_tx(b"hello");
    pool.insert(tx.clone()).unwrap();
    let result = pool.insert(tx);
    assert!(matches!(result, Err(MempoolError::DuplicateTransaction(_))));
}

#[test]
fn reject_when_full() {
    let pool = Mempool::new(MempoolConfig {
        max_size: 2,
        ..MempoolConfig::default()
    });
    pool.insert(make_valid_tx(b"tx1")).unwrap();
    pool.insert(make_valid_tx(b"tx2")).unwrap();
    let result = pool.insert(make_valid_tx(b"tx3"));
    assert!(matches!(result, Err(MempoolError::PoolFull { .. })));
}

#[test]
fn drain_batch_fifo() {
    let pool = Mempool::new(MempoolConfig::default());
    pool.insert(make_valid_tx(b"first")).unwrap();
    pool.insert(make_valid_tx(b"second")).unwrap();
    pool.insert(make_valid_tx(b"third")).unwrap();

    let batch = pool.drain_batch(2);
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].payload, b"first");
    assert_eq!(batch[1].payload, b"second");
    assert_eq!(pool.pending_count(), 1);
}

#[test]
fn drain_batch_more_than_available() {
    let pool = Mempool::new(MempoolConfig::default());
    pool.insert(make_valid_tx(b"only")).unwrap();

    let batch = pool.drain_batch(100);
    assert_eq!(batch.len(), 1);
    assert_eq!(pool.pending_count(), 0);
}

#[test]
fn requeue_after_drain() {
    let pool = Mempool::new(MempoolConfig::default());
    pool.insert(make_valid_tx(b"tx1")).unwrap();
    pool.insert(make_valid_tx(b"tx2")).unwrap();

    let batch = pool.drain_batch(2);
    assert_eq!(pool.pending_count(), 0);

    pool.requeue(batch);
    assert_eq!(pool.pending_count(), 2);

    // Requeued txs should be drained again
    let batch2 = pool.drain_batch(2);
    assert_eq!(batch2.len(), 2);
}

#[test]
fn drain_releases_sender_quota() {
    let pool = Mempool::new(MempoolConfig {
        max_size: 256,
        ..MempoolConfig::default()
    });

    for i in 0..100 {
        let payload = format!("sender-quota-{i}");
        pool.insert(make_valid_tx(payload.as_bytes())).unwrap();
    }

    let drained = pool.drain_batch(100);
    assert_eq!(drained.len(), 100);
    assert_eq!(pool.pending_count(), 0);

    let hash = pool
        .insert(make_valid_tx(b"sender-quota-after-drain"))
        .expect("drained sender quota should be released");
    assert!(pool.contains(&hash));
}

#[test]
fn requeue_restores_sender_quota() {
    let pool = Mempool::new(MempoolConfig {
        max_size: 256,
        ..MempoolConfig::default()
    });

    for i in 0..100 {
        let payload = format!("sender-requeue-{i}");
        pool.insert(make_valid_tx(payload.as_bytes())).unwrap();
    }

    let drained = pool.drain_batch(100);
    assert_eq!(drained.len(), 100);

    pool.requeue(drained);
    assert_eq!(pool.pending_count(), 100);

    let hash = pool
        .insert(make_valid_tx(b"sender-requeue-overflow"))
        .expect("requeued transactions should remain present and not corrupt sender accounting");
    assert!(pool.contains(&hash));
}

#[test]
fn remove_transaction() {
    let pool = Mempool::new(MempoolConfig::default());
    let tx = make_valid_tx(b"removeme");
    let hash = pool.insert(tx).unwrap();

    let removed = pool.remove(&hash);
    assert!(removed.is_some());
    assert!(!pool.contains(&hash));
    assert_eq!(pool.pending_count(), 0);
}

#[test]
fn ready_count_ignores_lazily_removed_hashes() {
    let pool = Mempool::new(MempoolConfig::default());
    let hash1 = pool.insert(make_valid_tx(b"ready-1")).unwrap();
    pool.insert(make_valid_tx(b"ready-2")).unwrap();

    let removed = pool.remove(&hash1);
    assert!(removed.is_some());
    assert_eq!(pool.ready_count(), 1);

    let ready = pool.ready_transactions();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].payload, b"ready-2");

    let drained = pool.drain_batch(10);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].payload, b"ready-2");
}

#[test]
fn insert_accepts_self_create_account_for_unknown_sender() {
    let state = Arc::new(RwLock::new(ShardedState::new()));
    let pool = Mempool::with_slot_and_state(
        MempoolConfig::default(),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
        state,
    );
    let sender = AccountId([0x44; 32]);
    let tx = make_signed_create_account_tx([0x55; 32], sender);

    let hash = pool.insert(tx).expect("self-create should be admitted");
    assert!(pool.contains(&hash));
}

#[test]
fn bridge_deposit_relay_requires_state_approved_relayer() {
    let signing_key = SigningKey::from_bytes(&[0xB1; 32]);
    let tx = make_bridge_deposit_tx(&signing_key);
    let state = Arc::new(RwLock::new(ShardedState::new()));
    let pool = Mempool::with_slot_and_state(
        MempoolConfig::default(),
        Arc::new(AtomicU64::new(0)),
        state.clone(),
    );

    let err = pool
        .insert_relay(tx.clone())
        .expect_err("unapproved bridge relayer must be rejected");
    assert!(err.to_string().contains("state-approved"));

    ace_defi::approve_relayer_in_state(
        state.write().default_shard_mut(),
        signing_key.verifying_key().to_bytes(),
    );
    pool.insert_relay(tx)
        .expect("approved bridge relayer should be admitted");
}

#[test]
fn stale_nonce_is_rejected_before_entering_ready_queue() {
    let sender_seed = [0x11; 32];
    let sender = AccountId([0x21; 32]);
    let recipient = AccountId([0x22; 32]);
    let mut state = ShardedState::new();
    let mut account = ace_model::account::Account::with_auth(
        sender,
        1_000,
        auth_public_key_from_seed(&sender_seed),
    );
    account.nonce = 1;
    state.insert(account);
    let pool = Mempool::with_slot_and_state(
        MempoolConfig::default(),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
        Arc::new(RwLock::new(state)),
    );

    let tx = make_signed_transfer_tx(sender_seed, sender, 0, recipient, 1);
    let err = pool.insert(tx).expect_err("stale nonce should be rejected");
    assert!(matches!(
        err,
        MempoolError::StaleNonce {
            expected: 1,
            got: 0,
            ..
        }
    ));
}

#[test]
fn future_nonce_promotes_when_gap_is_filled() {
    let sender_seed = [0x31; 32];
    let sender = AccountId([0x41; 32]);
    let recipient = AccountId([0x42; 32]);
    let mut state = ShardedState::new();
    state.insert(ace_model::account::Account::with_auth(
        sender,
        1_000,
        auth_public_key_from_seed(&sender_seed),
    ));
    let pool = Mempool::with_slot_and_state(
        MempoolConfig::default(),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
        Arc::new(RwLock::new(state)),
    );

    let tx1 = make_signed_transfer_tx(sender_seed, sender, 1, recipient, 1);
    let tx0 = make_signed_transfer_tx(sender_seed, sender, 0, recipient, 1);
    let future_outcome = pool
        .insert_with_ready_transition(tx1.clone())
        .expect("future tx should be tracked");
    assert!(!future_outcome.became_ready);
    assert_eq!(pool.ready_count(), 0);

    let gap_fill_outcome = pool
        .insert_with_ready_transition(tx0.clone())
        .expect("gap-filling tx should be admitted");
    assert!(gap_fill_outcome.became_ready);
    let ready = pool.ready_transactions();
    assert_eq!(ready.len(), 2);
    assert_eq!(ready[0].tx_hash(), tx0.tx_hash());
    assert_eq!(ready[1].tx_hash(), tx1.tx_hash());
}

#[test]
fn auth_key_updates_follow_sender_nonce_ordering() {
    let sender_seed = [0x51; 32];
    let sender = AccountId([0x61; 32]);
    let recipient = AccountId([0x62; 32]);
    let mut state = ShardedState::new();
    state.insert(ace_model::account::Account::with_auth(
        sender,
        1_000,
        auth_public_key_from_seed(&sender_seed),
    ));
    let pool = Mempool::with_slot_and_state(
        MempoolConfig::default(),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
        Arc::new(RwLock::new(state)),
    );

    let future_auth_update = make_signed_add_auth_key_tx(
        sender_seed,
        sender,
        1,
        ace_runtime::crypto::TaggedPubkey::secp256k1([0x33; 33]),
    );
    let gap_fill = make_signed_transfer_tx(sender_seed, sender, 0, recipient, 1);

    let future_outcome = pool
        .insert_with_ready_transition(future_auth_update.clone())
        .expect("future auth update should be tracked");
    assert!(!future_outcome.became_ready);
    assert_eq!(pool.ready_count(), 0);

    let gap_fill_outcome = pool
        .insert_with_ready_transition(gap_fill.clone())
        .expect("gap-filling transfer should be admitted");
    assert!(gap_fill_outcome.became_ready);
    let ready = pool.ready_transactions();
    assert_eq!(ready.len(), 2);
    assert_eq!(ready[0].tx_hash(), gap_fill.tx_hash());
    assert_eq!(ready[1].tx_hash(), future_auth_update.tx_hash());
}

#[test]
fn overload_watermark_rejects_before_pool_is_full() {
    let pool = Mempool::new(MempoolConfig {
        max_size: 10,
        admission_high_watermark: 4,
        admission_low_watermark: 2,
        ..MempoolConfig::default()
    });
    // Below low watermark: always accepted
    for i in 0..2 {
        let payload = format!("overload-{i}");
        pool.insert(make_valid_tx(payload.as_bytes()))
            .expect("pool should admit below low watermark");
    }
    // Fill up to high watermark (some may be probabilistically rejected)
    let mut admitted = 2;
    for i in 2..20 {
        let payload = format!("overload-{i}");
        match pool.insert(make_valid_tx(payload.as_bytes())) {
            Ok(_) => admitted += 1,
            Err(MempoolError::Overloaded { .. }) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
        if admitted >= 4 {
            break;
        }
    }
    assert_eq!(pool.pending_count(), 4);

    // At high watermark: must reject (100% probability)
    let err = pool
        .insert(make_valid_tx(b"overload-reject-at-high"))
        .expect_err("pool should reject at/above the high watermark");
    assert!(matches!(err, MempoolError::Overloaded { .. }));
}

// ── AR-ACE stripped-tx regression tests ───────────────────────────────────

/// Build a gossip-stripped ML-DSA-44 transaction (empty credential bytes).
/// The sender idcom and nonce are embedded so nonce-lane logic applies.
fn make_stripped_transfer_tx(sender: [u8; 32], nonce: u64) -> Transaction {
    let recipient = AccountId([2u8; 32]);
    let payload = TransactionOp::Transfer {
        nonce,
        to: recipient,
        amount: 1,
    }
    .encode();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&Sha256::digest(&payload));
    let domain = Domain::new(122_766, 0);
    // Stripped: algorithm = ML-DSA-44, bytes = empty
    let stripped_cred = TaggedSignature {
        algorithm: SignatureAlgorithm::MlDsa44,
        bytes: vec![],
    };
    Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom: sender,
            domain,
            context_tag: [0u8; 16],
            credential: stripped_cred,
        },
    )
}

/// Build a full-credential ed25519 transfer tx for the same sender/nonce.
/// Used in the upgrade test to replace a previously parked stripped entry.
fn make_full_transfer_tx(sender_seed: [u8; 32], sender: [u8; 32], nonce: u64) -> Transaction {
    let sender_id = AccountId(sender);
    let recipient = AccountId([2u8; 32]);
    make_signed_transfer_tx(sender_seed, sender_id, nonce, recipient, 1)
}

/// Regression: stripped relay txs are parked and never enter the executable
/// ready queue before their full credential arrives.
#[test]
fn stripped_relay_txs_are_parked_not_ready() {
    let pool = Mempool::new(MempoolConfig::default());
    let sender = [10u8; 32];

    let tx0 = make_stripped_transfer_tx(sender, 0);
    let tx1 = make_stripped_transfer_tx(sender, 1);
    pool.insert_preverified(tx0).unwrap();
    pool.insert_preverified(tx1).unwrap();

    assert_eq!(pool.ready_count(), 0, "stripped txs are not executable");
    assert_eq!(pool.pending_count(), 2);
    assert_eq!(
        pool.state_counts(),
        MempoolStateCounts {
            pending_total: 2,
            parked_stripped_credential: 2,
            ..MempoolStateCounts::default()
        }
    );

    let batch = pool.drain_batch(100);
    assert_eq!(batch.len(), 0, "stripped txs must not be drained");
    assert_eq!(pool.pending_count(), 2, "parked txs remain fetchable");
}

/// Regression: a stripped tx at nonce 0 must block promotion of nonce 1 from future.
///
/// Insert order matters: nonce 1 (full) first so it lands in future (expected=0,
/// gap=1>0). Then insert nonce 0 (stripped) which satisfies expected=0 and parks,
/// after which promote_future_ready_locked fires — it must NOT promote nonce 1
/// because nonce 0 in lane.ready is stripped.
#[test]
fn stripped_nonce_blocks_future_promotion() {
    let pool = Mempool::new(MempoolConfig::default());
    let sender_seed = [20u8; 32];
    let sender = [20u8; 32];
    let sender_id = AccountId(sender);
    let recipient = AccountId([2u8; 32]);

    // Insert nonce 1 first → expected=0, nonce 1 > expected → future.
    let tx1_full = make_signed_transfer_tx(sender_seed, sender_id, 1, recipient, 1);
    pool.insert_preverified(tx1_full).unwrap();
    assert_eq!(
        pool.ready_count(),
        0,
        "nonce-1 should be in future, not ready"
    );

    // Insert nonce 0 stripped → satisfies expected=0, parks,
    // then promote_future_ready_locked is called and must stop here.
    let tx0_stripped = make_stripped_transfer_tx(sender, 0);
    pool.insert_preverified(tx0_stripped).unwrap();

    // Nonce 0 is parked; nonce 1 must remain in future.
    assert_eq!(
        pool.ready_count(),
        0,
        "stripped nonce-0 is parked; nonce-1 must stay future"
    );

    let batch = pool.drain_batch(100);
    assert_eq!(batch.len(), 0, "stripped tx must not be drained");
    assert_eq!(
        pool.ready_count(),
        0,
        "nonce-0 parked; nonce-1 still future"
    );
}

/// Upgrade path: stripped tx parked by relay admission can enter ready when
/// the full-credential variant arrives (insert_preverified upgrade branch).
#[test]
fn stripped_parked_then_upgraded_to_full_drains_correctly() {
    let pool = Mempool::new(MempoolConfig::default());
    let sender_seed = [30u8; 32];
    let sender = [30u8; 32];

    // Step 1: gossip-stripped tx at nonce 0 enters pool as parked.
    let tx_stripped = make_stripped_transfer_tx(sender, 0);
    pool.insert_preverified(tx_stripped).unwrap();
    assert_eq!(pool.ready_count(), 0);

    // Step 2: full-credential tx with same hash arrives (originating node relay
    // or tx_fetch response). insert_preverified should detect the stripped entry,
    // upgrade it in-place, and re-admit to ready_members.
    let tx_full = make_full_transfer_tx(sender_seed, sender, 0);
    // The two txs must share the same tx_hash (payload identical).
    // insert_preverified returns Ok (upgrade, not duplicate).
    pool.insert_preverified(tx_full.clone()).unwrap();

    // Step 3: now drain_batch must return the full-credential tx.
    let batch = pool.drain_batch(100);
    assert_eq!(
        batch.len(),
        1,
        "full-credential tx must be drained after upgrade"
    );
    assert!(
        !batch[0].is_credential_stripped(),
        "drained tx must carry full credential"
    );
}

// ── GC (evict_stale_future_txs) regression tests ──────────────────────────

/// GC must not evict parked stripped txs; they are retained as credential-fetch
/// placeholders and nonce blockers until upgraded or committed elsewhere.
#[test]
fn gc_does_not_evict_parked_stripped_or_dependent_futures() {
    let current_slot = Arc::new(AtomicU64::new(0));
    let pool = Mempool::with_slot(MempoolConfig::default(), Arc::clone(&current_slot));
    let sender_seed = [40u8; 32];
    let sender = [40u8; 32];
    let sender_id = AccountId(sender);
    let recipient = AccountId([2u8; 32]);

    // nonce 1 (full) goes to future first.
    let tx1 = make_signed_transfer_tx(sender_seed, sender_id, 1, recipient, 1);
    pool.insert_preverified(tx1).unwrap();

    // nonce 0 (stripped) parks, blocks nonce 1 promotion.
    let tx0_stripped = make_stripped_transfer_tx(sender, 0);
    pool.insert_preverified(tx0_stripped).unwrap();

    assert_eq!(pool.ready_count(), 0);
    assert_eq!(
        pool.pending_count(),
        2,
        "parked stripped tx and dependent future remain before GC"
    );

    current_slot.store(11, Ordering::Relaxed);
    pool.evict_stale_future_txs();

    assert_eq!(pool.pending_count(), 2, "GC must preserve parked lane");
    assert_eq!(pool.ready_count(), 0);
}

/// Parked stripped lanes do not prevent unrelated senders from draining.
#[test]
fn parked_stripped_lane_does_not_block_unrelated_sender() {
    let pool = Mempool::new(MempoolConfig::default());
    let sender_seed = [50u8; 32];
    let sender = [50u8; 32];
    let recipient = AccountId([2u8; 32]);

    let tx0_stripped = make_stripped_transfer_tx(sender, 0);
    pool.insert_preverified(tx0_stripped).unwrap();

    let new_sender_seed = [51u8; 32];
    let new_sender = [51u8; 32];
    let new_sender_id = AccountId(new_sender);
    let fresh_tx = make_signed_transfer_tx(new_sender_seed, new_sender_id, 0, recipient, 1);
    pool.insert_preverified(fresh_tx).unwrap();

    assert_eq!(pool.ready_count(), 1, "fresh tx must be ready");
    let batch = pool.drain_batch(100);
    assert_eq!(batch.len(), 1, "fresh tx must drain normally");
    assert_eq!(pool.pending_count(), 1, "parked stripped tx remains");
    let _ = sender_seed;
}

#[test]
fn stale_future_only_lanes_clear_admission_backpressure() {
    let current_slot = Arc::new(AtomicU64::new(0));
    let pool = Mempool::with_slot(
        MempoolConfig {
            max_size: 10,
            admission_high_watermark: 4,
            admission_low_watermark: 3,
            ..MempoolConfig::default()
        },
        Arc::clone(&current_slot),
    );
    let recipient = AccountId([2u8; 32]);

    // Four senders each contribute a future-only tx.  This is not drainable:
    // there is no nonce-0 gap filler for any sender.
    for i in 0..4u8 {
        let sender_seed = [70 + i; 32];
        let sender = AccountId([70 + i; 32]);
        let tx = make_signed_transfer_tx(sender_seed, sender, 1, recipient, 1);
        pool.insert_preverified(tx).unwrap();
    }
    assert_eq!(pool.pending_count(), 4);
    assert_eq!(pool.ready_count(), 0);

    let extra = make_signed_transfer_tx([90u8; 32], AccountId([90u8; 32]), 1, recipient, 1);
    assert!(matches!(
        pool.insert_preverified(extra),
        Err(MempoolError::Overloaded { .. })
    ));

    current_slot.store(11, Ordering::Relaxed);
    pool.evict_stale_future_txs();
    assert_eq!(pool.pending_count(), 0);
    assert_eq!(pool.ready_count(), 0);

    let fresh = make_signed_transfer_tx([91u8; 32], AccountId([91u8; 32]), 0, recipient, 1);
    pool.insert_preverified(fresh).unwrap();
    assert_eq!(pool.ready_count(), 1);
}

#[test]
fn ready_starvation_admits_immediately_ready_tx_despite_pending_backlog() {
    let pool = Mempool::new(MempoolConfig {
        max_size: 10,
        admission_high_watermark: 4,
        admission_low_watermark: 3,
        ..MempoolConfig::default()
    });
    let recipient = AccountId([2u8; 32]);

    for i in 0..4u8 {
        let sender_seed = [100 + i; 32];
        let sender = AccountId([100 + i; 32]);
        let tx = make_signed_transfer_tx(sender_seed, sender, 1, recipient, 1);
        pool.insert_preverified(tx).unwrap();
    }
    assert_eq!(pool.pending_count(), 4);
    assert_eq!(pool.ready_count(), 0);

    let future = make_signed_transfer_tx([110u8; 32], AccountId([110u8; 32]), 1, recipient, 1);
    assert!(matches!(
        pool.insert_preverified(future),
        Err(MempoolError::Overloaded { .. })
    ));

    let ready = make_signed_transfer_tx([111u8; 32], AccountId([111u8; 32]), 0, recipient, 1);
    pool.insert_preverified(ready).unwrap();
    assert_eq!(pool.pending_count(), 5);
    assert_eq!(pool.ready_count(), 1);
}
