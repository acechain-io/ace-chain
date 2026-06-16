//! BFT vote types and collection.
//!
//! Wraps ace-runtime's `has_quorum` for 2/3 supermajority checks.
//! Votes are partitioned by `block_hash` so that conflicting-fork
//! votes in the same slot cannot be merged to forge quorum.

use std::collections::HashMap;

use ace_model::account::AccountId;
use ace_runtime::config::has_quorum;
use ace_runtime::crypto::sig_algo::{self, TaggedPubkey, TaggedSignature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::validator_set::ValidatorSet;

/// Vote type for Tendermint consensus phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Prevote phase (first voting round).
    Prevote,
    /// Precommit phase (second voting round).
    Precommit,
}

/// A BFT vote for a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Slot/height of the block being voted on.
    pub slot: u64,
    /// Hash of the block being voted on.
    pub block_hash: [u8; 32],
    /// Identity commitment of the voter.
    pub voter: AccountId,
    /// Stake weight of the voter.
    pub voter_stake: u64,
    /// Signature over the vote message.
    #[serde(default)]
    pub signature: TaggedSignature,
    /// Chain identifier for domain separation.
    #[serde(default)]
    pub chain_id: u32,
    /// Tendermint round number (`0` is reserved for legacy slot-era votes).
    #[serde(default)]
    pub round: u32,
    /// Type of vote (Prevote or Precommit).
    #[serde(default = "default_vote_type")]
    pub vote_type: VoteType,
}

impl Default for VoteType {
    fn default() -> Self {
        VoteType::Prevote
    }
}

fn default_vote_type() -> VoteType {
    VoteType::Prevote
}

impl Vote {
    /// Compute the message bytes that are signed (legacy, no round/type).
    pub fn sign_message(
        slot: u64,
        block_hash: &[u8; 32],
        voter: &AccountId,
        chain_id: u32,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ACE-VOTE-V1");
        hasher.update(&chain_id.to_le_bytes());
        hasher.update(&slot.to_le_bytes());
        hasher.update(block_hash);
        hasher.update(&voter.0);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }

    /// Compute the message bytes for a Tendermint vote (includes round and type).
    pub fn sign_message_tendermint(
        slot: u64,
        round: u32,
        vote_type: VoteType,
        block_hash: &[u8; 32],
        voter: &AccountId,
        chain_id: u32,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        match vote_type {
            VoteType::Prevote => hasher.update(b"ACE-PREVOTE-V1"),
            VoteType::Precommit => hasher.update(b"ACE-PRECOMMIT-V1"),
        };
        hasher.update(&chain_id.to_le_bytes());
        hasher.update(&slot.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        hasher.update(block_hash);
        hasher.update(&voter.0);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }

    /// Verify the vote's signature against the given public key (PQC-ready).
    pub fn verify_signature(&self, pubkey: &TaggedPubkey) -> bool {
        if !self.signature.is_well_formed() {
            return false;
        }
        if self.signature.algorithm != pubkey.algorithm {
            return false;
        }
        let msg = if self.round == 0 && self.vote_type == VoteType::Prevote {
            Self::sign_message(self.slot, &self.block_hash, &self.voter, self.chain_id)
        } else {
            Self::sign_message_tendermint(
                self.slot,
                self.round,
                self.vote_type,
                &self.block_hash,
                &self.voter,
                self.chain_id,
            )
        };
        sig_algo::verify_signature(pubkey, &msg, &self.signature)
    }
}

/// Per-block-hash vote bucket.
struct VoteBucket {
    votes: Vec<Vote>,
    voted_stake: u64,
}

impl VoteBucket {
    fn new() -> Self {
        Self {
            votes: Vec::new(),
            voted_stake: 0,
        }
    }
}

/// Collects votes for a single slot, partitioned by block hash.
///
/// The consensus engine creates a `VoteCollector` per slot and
/// feeds incoming votes. When `quorum_block_hash()` returns `Some`,
/// the corresponding block achieves soft finality.
///
/// Tracks equivocation: if a validator votes for two different block
/// hashes in the same slot, the second vote is rejected and the
/// validator is recorded as an equivocator for future slashing.
pub struct VoteCollector {
    slot: u64,
    /// Votes grouped by block_hash.
    buckets: HashMap<[u8; 32], VoteBucket>,
    /// Total network stake for quorum calculation.
    total_stake: u64,
    /// Maps voter → first block_hash they voted for (equivocation detection).
    voter_first_hash: HashMap<AccountId, [u8; 32]>,
    /// Voters who have been detected equivocating (voted for different hashes).
    equivocators: HashMap<AccountId, ([u8; 32], [u8; 32])>,
    /// Generation of the validator set last reconciled against.
    /// Allows short-circuiting reconcile_validator_set when the set is unchanged.
    validator_set_generation: u64,
}

impl VoteCollector {
    /// Create a collector for the given slot with known total stake.
    pub fn new(slot: u64, total_stake: u64) -> Self {
        Self {
            slot,
            buckets: HashMap::new(),
            total_stake,
            voter_first_hash: HashMap::new(),
            equivocators: HashMap::new(),
            validator_set_generation: 0,
        }
    }

    /// Add a vote after verifying its signature against the validator set.
    ///
    /// Returns `true` if this vote contributes new stake.
    /// Rejects votes with invalid or missing signatures.
    ///
    /// Emits a `tracing::debug!` event with the algorithm and verification
    /// latency in microseconds.  Under PQC load, filter on
    /// `ml_dsa_verify_us` to observe signer/verifier queue pressure; correlate
    /// with `consensus timeout` events to attribute round failures.
    pub fn add_vote_verified(&mut self, vote: Vote, validator_set: &ValidatorSet) -> bool {
        if vote.slot != self.slot {
            return false;
        }

        // Verify voter is a known validator
        let validator = match validator_set.get_by_id(&vote.voter) {
            Some(v) => v,
            None => return false,
        };

        // Time the signature verification — this is the PQC hot path.
        // ML-DSA-44 verify (fips204 pure-Rust) costs ~300–600 µs per call.
        // Under load, N concurrent verify calls share CPU; the tail latency
        // here directly determines whether prevotes arrive before the prevote
        // timeout fires (see on_prevote_timeout attribution comment).
        let verify_start = std::time::Instant::now();
        let valid = vote.verify_signature(&validator.signing_pubkey);
        let verify_us = verify_start.elapsed().as_micros() as u64;

        let algo = validator.signing_pubkey.algorithm;
        if valid {
            tracing::debug!(
                voter = %vote.voter,
                slot = vote.slot,
                round = vote.round,
                algo = ?algo,
                verify_us,
                "vote signature verified"
            );
        } else {
            tracing::warn!(
                voter = %vote.voter,
                slot = vote.slot,
                algo = ?algo,
                verify_us,
                "rejecting vote with invalid signature"
            );
            return false;
        }

        self.add_vote_internal(vote, validator.stake)
    }

    /// Add a vote without signature verification (test-only).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn add_vote(&mut self, vote: Vote) -> bool {
        if vote.slot != self.slot {
            return false;
        }
        let stake = vote.voter_stake;
        self.add_vote_internal(vote, stake)
    }

    /// Reconcile stored votes against a new effective validator set.
    ///
    /// Re-verifies each vote's signature against the **current** validator set.
    /// Votes that fail verification (e.g. after key rotation or compromised old key)
    /// are dropped so that only votes valid under the new set are counted.
    pub fn reconcile_validator_set(&mut self, validator_set: &ValidatorSet) {
        // Short-circuit: if the validator set generation hasn't changed, the
        // effective set is identical — no re-verification needed. This matters
        // because reconcile is called on every consensus-loop tick in steady state;
        // without the short-circuit each tick would do O(votes) PQC re-verification.
        // Note: after a process restart, VoteCollector buckets are empty, so
        // short-circuiting on an already-matching generation is safe (no-op either way).
        if self.validator_set_generation == validator_set.generation() {
            return;
        }

        let votes: Vec<Vote> = self
            .buckets
            .values()
            .flat_map(|bucket| bucket.votes.iter().cloned())
            .collect();

        self.buckets.clear();
        self.voter_first_hash.clear();
        self.equivocators.clear();
        self.total_stake = validator_set.total_stake();
        self.validator_set_generation = validator_set.generation();

        for vote in votes {
            let _ = self.add_vote_verified(vote, validator_set);
        }
    }

    fn add_vote_internal(&mut self, mut vote: Vote, canonical_stake: u64) -> bool {
        vote.voter_stake = canonical_stake;

        // Equivocation detection: check if voter already voted for a different hash
        if let Some(&first_hash) = self.voter_first_hash.get(&vote.voter) {
            if first_hash != vote.block_hash {
                // Equivocation detected: same voter, different block_hash
                tracing::warn!(
                    voter = %vote.voter,
                    slot = self.slot,
                    "Equivocation detected: validator voted for conflicting blocks"
                );
                self.equivocators
                    .insert(vote.voter, (first_hash, vote.block_hash));
                return false;
            }
            // Same hash — dedup (already voted for this hash)
            return false;
        }

        let bucket = self
            .buckets
            .entry(vote.block_hash)
            .or_insert_with(VoteBucket::new);

        // Record this voter's first hash
        self.voter_first_hash.insert(vote.voter, vote.block_hash);

        bucket.voted_stake += vote.voter_stake;
        bucket.votes.push(vote);
        true
    }

    /// Check whether any block hash has reached 2/3 supermajority.
    pub fn has_quorum(&self) -> bool {
        self.quorum_block_hash().is_some()
    }

    /// Return the block hash that reached quorum, if any.
    ///
    /// In a correct BFT run at most one hash can reach 2/3 quorum, so iteration
    /// order does not affect correctness. Keys are sorted for determinism during
    /// testing and equivocation edge cases.
    pub fn quorum_block_hash(&self) -> Option<[u8; 32]> {
        // Fast path: single bucket (overwhelmingly common case) — no allocation.
        if self.buckets.len() <= 1 {
            return self.buckets.iter().find_map(|(hash, bucket)| {
                has_quorum(bucket.voted_stake, self.total_stake).then_some(*hash)
            });
        }
        let mut keys: Vec<&[u8; 32]> = self.buckets.keys().collect();
        keys.sort_unstable();
        for hash in keys {
            let bucket = &self.buckets[hash];
            if has_quorum(bucket.voted_stake, self.total_stake) {
                return Some(*hash);
            }
        }
        None
    }

    /// Return the currently leading block hash for this slot, if any votes exist.
    ///
    /// Higher voted stake wins. Ties break deterministically toward the lower hash
    /// so every node that has seen the same votes chooses the same preferred branch.
    pub fn leading_block_hash(&self) -> Option<[u8; 32]> {
        self.buckets
            .iter()
            .map(|(hash, bucket)| (*hash, bucket.voted_stake))
            .max_by(|(hash_a, stake_a), (hash_b, stake_b)| {
                stake_a.cmp(stake_b).then_with(|| hash_b.cmp(hash_a))
            })
            .map(|(hash, _)| hash)
    }

    /// Get the voted stake for a specific block hash.
    pub fn voted_stake_for(&self, block_hash: &[u8; 32]) -> u64 {
        self.buckets.get(block_hash).map_or(0, |b| b.voted_stake)
    }

    /// Get total voted stake across all block hashes.
    pub fn voted_stake(&self) -> u64 {
        self.buckets.values().map(|b| b.voted_stake).sum()
    }

    /// Return the first block hash a specific voter cast for this slot, if any.
    pub fn voter_block_hash(&self, voter: &AccountId) -> Option<[u8; 32]> {
        self.voter_first_hash.get(voter).copied()
    }

    /// Get the number of votes collected across all block hashes.
    pub fn vote_count(&self) -> usize {
        self.buckets.values().map(|b| b.votes.len()).sum()
    }

    /// Get the slot this collector is for.
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Get all votes across all block hashes.
    pub fn votes(&self) -> Vec<&Vote> {
        self.buckets.values().flat_map(|b| &b.votes).collect()
    }

    /// Get detected equivocators: voter → (first_hash, second_hash).
    pub fn equivocators(&self) -> &HashMap<AccountId, ([u8; 32], [u8; 32])> {
        &self.equivocators
    }

    /// Add a raw vote by voter, block hash, and canonical stake.
    ///
    /// Used by the Tendermint state machine after external signature
    /// verification. Skips signature check and uses the provided stake.
    pub fn add_vote_raw(&mut self, voter: AccountId, block_hash: [u8; 32], stake: u64) -> bool {
        let vote = Vote {
            slot: self.slot,
            block_hash,
            voter,
            voter_stake: stake,
            signature: ace_runtime::crypto::sig_algo::TaggedSignature::ed25519([0u8; 64]),
            chain_id: 0,
            round: 0,
            vote_type: VoteType::Prevote,
        };
        self.add_vote_internal(vote, stake)
    }
}
