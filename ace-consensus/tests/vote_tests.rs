use ace_consensus::vote::{Vote, VoteCollector};
use ace_model::account::AccountId;

fn make_vote(slot: u64, voter_byte: u8, stake: u64) -> Vote {
    let mut voter = [0u8; 32];
    voter[0] = voter_byte;
    Vote {
        slot,
        block_hash: [0xAB; 32],
        voter: AccountId(voter),
        voter_stake: stake,
        signature: Default::default(),
        chain_id: 0,
        round: 0,
        vote_type: Default::default(),
    }
}

fn make_vote_for_hash(slot: u64, voter_byte: u8, stake: u64, hash: [u8; 32]) -> Vote {
    let mut voter = [0u8; 32];
    voter[0] = voter_byte;
    Vote {
        slot,
        block_hash: hash,
        voter: AccountId(voter),
        voter_stake: stake,
        signature: Default::default(),
        chain_id: 0,
        round: 0,
        vote_type: Default::default(),
    }
}

#[test]
fn quorum_at_two_thirds() {
    // Total stake = 300, quorum at >= 2/3 (i.e., >= 200)
    let mut collector = VoteCollector::new(1, 300);

    collector.add_vote(make_vote(1, 0, 100));
    assert!(!collector.has_quorum());
    assert_eq!(collector.voted_stake(), 100);

    // 199 < 200 → no quorum yet
    collector.add_vote(make_vote(1, 1, 99));
    assert!(!collector.has_quorum());
    assert_eq!(collector.voted_stake(), 199);

    // 200 >= 200 → quorum reached
    collector.add_vote(make_vote(1, 2, 1));
    assert!(collector.has_quorum());
    assert_eq!(collector.voted_stake(), 200);
}

#[test]
fn exact_two_thirds_is_quorum() {
    // Total = 300, 2/3 = 200 exactly. has_quorum uses >= so this IS quorum.
    let mut collector = VoteCollector::new(1, 300);
    collector.add_vote(make_vote(1, 0, 200));
    // 200 * 3 >= 2 * 300 (600 >= 600) → quorum
    assert!(collector.has_quorum());
}

#[test]
fn duplicate_voter_rejected() {
    let mut collector = VoteCollector::new(1, 300);

    let added1 = collector.add_vote(make_vote(1, 0, 100));
    assert!(added1);

    // Same voter (same voter byte) again for same block_hash
    let added2 = collector.add_vote(make_vote(1, 0, 100));
    assert!(!added2);

    assert_eq!(collector.vote_count(), 1);
    assert_eq!(collector.voted_stake(), 100);
}

#[test]
fn wrong_slot_rejected() {
    let mut collector = VoteCollector::new(1, 300);

    let added = collector.add_vote(make_vote(2, 0, 100)); // slot 2 vs collector for slot 1
    assert!(!added);
    assert_eq!(collector.vote_count(), 0);
}

#[test]
fn vote_count_and_slot() {
    let mut collector = VoteCollector::new(5, 1000);
    assert_eq!(collector.slot(), 5);
    assert_eq!(collector.vote_count(), 0);

    collector.add_vote(make_vote(5, 0, 100));
    collector.add_vote(make_vote(5, 1, 200));
    assert_eq!(collector.vote_count(), 2);
}

#[test]
fn votes_accessor() {
    let mut collector = VoteCollector::new(1, 1000);
    collector.add_vote(make_vote(1, 10, 50));
    collector.add_vote(make_vote(1, 20, 75));

    let votes = collector.votes();
    assert_eq!(votes.len(), 2);
    let stakes: Vec<u64> = votes.iter().map(|v| v.voter_stake).collect();
    assert!(stakes.contains(&50));
    assert!(stakes.contains(&75));
}

#[test]
fn single_validator_quorum() {
    // Single validator with all stake
    let mut collector = VoteCollector::new(1, 100);
    collector.add_vote(make_vote(1, 0, 100));
    // 100 * 3 > 100 * 2 → quorum
    assert!(collector.has_quorum());
}

// --- Fork-merging prevention tests ---

#[test]
fn cross_fork_votes_not_merged() {
    // Total stake = 300, quorum requires >= 200.
    // Fork A gets 100 stake, fork B gets 100 stake.
    // Neither fork should reach quorum.
    let mut collector = VoteCollector::new(1, 300);

    let hash_a = [0xAA; 32];
    let hash_b = [0xBB; 32];

    collector.add_vote(make_vote_for_hash(1, 0, 100, hash_a));
    collector.add_vote(make_vote_for_hash(1, 1, 100, hash_b));

    assert!(!collector.has_quorum(), "cross-fork votes must not merge");
    assert_eq!(collector.voted_stake(), 200); // total across all forks
    assert_eq!(collector.voted_stake_for(&hash_a), 100);
    assert_eq!(collector.voted_stake_for(&hash_b), 100);
    assert!(collector.quorum_block_hash().is_none());
}

#[test]
fn quorum_on_correct_fork() {
    // Total stake = 300. Fork A gets 200 (quorum), fork B gets 50.
    let mut collector = VoteCollector::new(1, 300);

    let hash_a = [0xAA; 32];
    let hash_b = [0xBB; 32];

    collector.add_vote(make_vote_for_hash(1, 0, 100, hash_a));
    collector.add_vote(make_vote_for_hash(1, 1, 50, hash_b));
    assert!(!collector.has_quorum());

    collector.add_vote(make_vote_for_hash(1, 2, 100, hash_a));
    assert!(collector.has_quorum());

    assert_eq!(collector.quorum_block_hash().unwrap(), hash_a);
    assert_eq!(collector.voted_stake_for(&hash_a), 200);
}

#[test]
fn same_voter_different_forks_rejected_as_equivocation() {
    // Equivocation detection: voting for two different block hashes
    // in the same slot is rejected and recorded.
    let mut collector = VoteCollector::new(1, 300);

    let hash_a = [0xAA; 32];
    let hash_b = [0xBB; 32];

    let added1 = collector.add_vote(make_vote_for_hash(1, 0, 100, hash_a));
    assert!(added1);

    // Second vote for a different hash should be rejected
    let added2 = collector.add_vote(make_vote_for_hash(1, 0, 100, hash_b));
    assert!(!added2);

    // Only the first vote should count
    assert_eq!(collector.vote_count(), 1);
    assert_eq!(collector.voted_stake_for(&hash_a), 100);
    assert_eq!(collector.voted_stake_for(&hash_b), 0);

    // Equivocator should be recorded
    assert_eq!(collector.equivocators().len(), 1);
}

#[test]
fn same_voter_same_fork_rejected() {
    let mut collector = VoteCollector::new(1, 300);
    let hash_a = [0xAA; 32];

    let added1 = collector.add_vote(make_vote_for_hash(1, 0, 100, hash_a));
    assert!(added1);

    let added2 = collector.add_vote(make_vote_for_hash(1, 0, 100, hash_a));
    assert!(!added2);

    assert_eq!(collector.vote_count(), 1);
}
