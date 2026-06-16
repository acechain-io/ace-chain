use ace_consensus::engine::ConsensusEngine;
use ace_consensus::leader_schedule::LeaderSchedule;
use ace_consensus::poh::PohChain;
use ace_consensus::validator_set::{Validator, ValidatorSet};
use ace_consensus::vote::Vote;
use ace_model::account::AccountId;
use ace_model::sharded_state::ShardedState;
use ace_n_vm::NVm;
use ace_runtime::crypto::proof::MockProver;
use ace_runtime::crypto::TaggedPubkey;
use ace_runtime::types::capability::ValidatorCapabilities;

fn make_engine() -> (ConsensusEngine, AccountId) {
    let local_id = AccountId([1u8; 32]);
    let validators = vec![Validator {
        id_com: local_id,
        stake: 100,
        index: 0,
        signing_pubkey: TaggedPubkey::ed25519([0u8; 32]),
        capabilities: ValidatorCapabilities::default(),
    }];
    let vs = ValidatorSet::new(validators);

    // With a single validator, any seed works
    let seed = [0u8; 32];
    let schedule = LeaderSchedule::new(seed);
    // With a single validator, any seed works
    assert_eq!(schedule.leader_for_slot(0, &vs), local_id);

    let poh = PohChain::new([0u8; 32]);
    let n_vm = NVm::with_defaults();
    let engine = ConsensusEngine::new(local_id, schedule, vs, poh, n_vm, [0u8; 32]);
    (engine, local_id)
}

fn make_state_with_account(id: AccountId, balance: u64) -> ShardedState {
    use ace_model::account::Account;
    let mut state = ShardedState::new();
    let account = Account {
        id_com: id,
        balance,
        nonce: 0,
        code_hash: None,
        code: None,
        storage_root: [0u8; 32],
        xid: None,
        xaddress: None,
        evm_address: None,
        tron_address: None,
        solana_address: None,
        btc_address: None,
        auth_pubkey: TaggedPubkey::ed25519([0u8; 32]),
        auth_keys: Vec::new(),
        last_touched_slot: 0,
    };
    state.insert(account);
    state
}

#[test]
fn is_leader_single_validator() {
    let (engine, _) = make_engine();
    // Single validator is always the leader
    assert!(engine.is_leader(0));
    assert!(engine.is_leader(1));
    assert!(engine.is_leader(100));
}

#[test]
fn rebuild_full_validator_set_rejects_invalid_persisted_admission() {
    let (mut engine, local_id) = make_engine();
    let duplicate = Validator {
        id_com: local_id,
        stake: 100,
        index: 1,
        signing_pubkey: TaggedPubkey::ed25519([1u8; 32]),
        capabilities: ValidatorCapabilities::default(),
    };
    let err = engine.rebuild_full_validator_set(&[duplicate]).unwrap_err();
    assert!(err.contains("invalid persisted validator admission"));
}

#[test]
fn produce_block_empty_txs() {
    let (mut engine, local_id) = make_engine();
    let mut state = make_state_with_account(local_id, 1_000_000);

    let result = engine.produce_block(0, &mut state, vec![]);
    assert!(result.is_ok());
    let (block, _receipts) = result.unwrap();
    assert_eq!(block.header.slot, 0);
    assert_eq!(block.header.leader_idcom, local_id.0);
    assert_eq!(block.transactions.len(), 0);
}

#[test]
fn produce_block_updates_last_hash() {
    let (mut engine, local_id) = make_engine();
    let mut state = make_state_with_account(local_id, 1_000_000);

    let initial_hash = engine.last_block_hash;
    let (block, _) = engine.produce_block(0, &mut state, vec![]).unwrap();
    assert_ne!(engine.last_block_hash, initial_hash);
    assert_eq!(engine.last_block_hash, block.hash());
}

#[test]
fn produce_block_creates_snapshot() {
    let (mut engine, local_id) = make_engine();
    let mut state = make_state_with_account(local_id, 1_000_000);

    let _ = engine.produce_block(0, &mut state, vec![]).unwrap();

    let snapshot = engine.take_snapshot(0);
    assert!(
        snapshot.is_some(),
        "snapshot should exist for produced block"
    );

    // Taking it again should return None (it was removed)
    let snapshot2 = engine.take_snapshot(0);
    assert!(snapshot2.is_none());
}

#[test]
fn finality_state_after_production() {
    let (mut engine, local_id) = make_engine();
    let mut state = make_state_with_account(local_id, 1_000_000);

    let _ = engine.produce_block(0, &mut state, vec![]).unwrap();

    let fsm = engine.finality_state(0);
    assert!(
        fsm.is_some(),
        "finality state machine should exist for slot 0"
    );
}

#[test]
fn on_vote_no_quorum_without_enough_stake() {
    let (mut engine, local_id) = make_engine();
    let mut state = make_state_with_account(local_id, 1_000_000);

    let (block, _) = engine.produce_block(0, &mut state, vec![]).unwrap();
    let verifier = MockProver::new();

    // Vote with less than 2/3 stake (total is 100, need > 66.67)
    let vote = Vote {
        slot: 0,
        block_hash: block.hash(),
        voter: AccountId([2u8; 32]),
        voter_stake: 50,
        signature: Default::default(),
        chain_id: 0,
        round: 0,
        vote_type: Default::default(),
    };

    let action = engine.on_vote(vote, &verifier);
    assert_eq!(
        action,
        ace_runtime::consensus::finality::FinalityAction::None
    );
}

#[test]
fn finality_state_nonexistent_slot() {
    let (engine, _) = make_engine();
    assert!(engine.finality_state(999).is_none());
}

#[test]
fn check_timeouts_empty() {
    let (mut engine, _) = make_engine();
    let verifier = MockProver::new();
    let actions = engine.check_timeouts(0, &verifier);
    assert!(actions.is_empty());
}

#[test]
fn cleanup_finalized_drops_snapshots_past_rollback_window() {
    let (mut engine, local_id) = make_engine();
    let state = make_state_with_account(local_id, 1_000_000);

    engine.store_snapshot(1, state.snapshot());
    engine.cleanup_finalized(20, 50);

    assert!(
        engine.take_snapshot(1).is_none(),
        "snapshot older than the rollback window should be released"
    );
}

#[test]
fn cleanup_finalized_keeps_recent_unresolved_snapshot() {
    let (mut engine, local_id) = make_engine();
    let state = make_state_with_account(local_id, 1_000_000);

    engine.store_snapshot(15, state.snapshot());
    engine.cleanup_finalized(20, 50);

    assert!(
        engine.take_snapshot(15).is_some(),
        "recent unresolved snapshot should remain available for rollback"
    );
}
