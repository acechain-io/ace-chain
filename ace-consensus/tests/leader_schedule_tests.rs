use ace_consensus::leader_schedule::LeaderSchedule;
use ace_consensus::validator_set::{Validator, ValidatorSet};
use ace_model::account::AccountId;
use ace_runtime::crypto::TaggedPubkey;
use ace_runtime::types::capability::ValidatorCapabilities;

fn make_validators(count: usize) -> ValidatorSet {
    let validators: Vec<Validator> = (0..count)
        .map(|i| {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            Validator {
                id_com: AccountId(id),
                stake: 100,
                index: i as u32,
                signing_pubkey: TaggedPubkey::ed25519([0u8; 32]),
                capabilities: ValidatorCapabilities::default(),
            }
        })
        .collect();
    ValidatorSet::new(validators)
}

fn make_weighted_validators() -> ValidatorSet {
    // V0: 700, V1: 200, V2: 100 — total 1000
    let validators = vec![
        Validator {
            id_com: AccountId([0u8; 32]),
            stake: 700,
            index: 0,
            signing_pubkey: TaggedPubkey::ed25519([0u8; 32]),
            capabilities: ValidatorCapabilities::default(),
        },
        Validator {
            id_com: AccountId([1u8; 32]),
            stake: 200,
            index: 1,
            signing_pubkey: TaggedPubkey::ed25519([0u8; 32]),
            capabilities: ValidatorCapabilities::default(),
        },
        Validator {
            id_com: AccountId([2u8; 32]),
            stake: 100,
            index: 2,
            signing_pubkey: TaggedPubkey::ed25519([0u8; 32]),
            capabilities: ValidatorCapabilities::default(),
        },
    ];
    ValidatorSet::new(validators)
}

#[test]
fn leader_is_deterministic() {
    let schedule = LeaderSchedule::new([42u8; 32]);
    let vs = make_validators(4);

    let leader1 = schedule.leader_for_slot(0, &vs);
    let leader2 = schedule.leader_for_slot(0, &vs);
    assert_eq!(leader1, leader2, "same slot must yield same leader");
}

#[test]
fn different_slots_can_differ() {
    let schedule = LeaderSchedule::new([42u8; 32]);
    let vs = make_validators(10);

    // Over 100 slots, we should see at least 2 distinct leaders
    let leaders: std::collections::HashSet<AccountId> = (0..100)
        .map(|slot| schedule.leader_for_slot(slot, &vs))
        .collect();
    assert!(
        leaders.len() > 1,
        "leader schedule should vary across slots"
    );
}

#[test]
fn different_seeds_produce_different_schedules() {
    let s1 = LeaderSchedule::new([1u8; 32]);
    let s2 = LeaderSchedule::new([2u8; 32]);
    let vs = make_validators(4);

    // Over 50 slots, the two schedules should differ at least once
    let differs =
        (0..50).any(|slot| s1.leader_for_slot(slot, &vs) != s2.leader_for_slot(slot, &vs));
    assert!(
        differs,
        "different seeds should produce different schedules"
    );
}

#[test]
fn leader_always_from_validator_set() {
    let schedule = LeaderSchedule::new([99u8; 32]);
    let vs = make_validators(5);

    for slot in 0..200 {
        let leader = schedule.leader_for_slot(slot, &vs);
        assert!(
            vs.get_by_id(&leader).is_some(),
            "leader at slot {slot} must be in validator set"
        );
    }
}

#[test]
fn stake_weight_affects_selection() {
    let schedule = LeaderSchedule::new([7u8; 32]);
    let vs = make_weighted_validators();

    let mut counts = [0u32; 3];
    let total_slots = 10_000;
    for slot in 0..total_slots {
        let leader = schedule.leader_for_slot(slot, &vs);
        if leader == AccountId([0u8; 32]) {
            counts[0] += 1;
        } else if leader == AccountId([1u8; 32]) {
            counts[1] += 1;
        } else {
            counts[2] += 1;
        }
    }

    // V0 has 70% stake, should be selected significantly more than V2 (10%)
    assert!(
        counts[0] > counts[2],
        "higher-stake validator should be selected more often: {:?}",
        counts
    );
}

#[test]
fn single_validator() {
    let schedule = LeaderSchedule::new([0u8; 32]);
    let vs = make_validators(1);

    for slot in 0..10 {
        let leader = schedule.leader_for_slot(slot, &vs);
        let mut expected = [0u8; 32];
        expected[0] = 0;
        assert_eq!(leader, AccountId(expected));
    }
}

#[test]
fn empty_validator_set_returns_zero() {
    let schedule = LeaderSchedule::new([0u8; 32]);
    let vs = ValidatorSet::new(vec![]);
    let leader = schedule.leader_for_slot(0, &vs);
    assert_eq!(leader, AccountId::ZERO);
}
