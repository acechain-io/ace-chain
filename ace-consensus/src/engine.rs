//! ConsensusEngine: Tendermint/CometBFT-style consensus.
//!
//! Height-based consensus with Propose → Prevote → Precommit rounds.
//! No forks, no reorgs — committed blocks are final (soft finality).
//! FC arrival transitions to hard finality.
//!
//! Legacy slot-era finality helpers remain only for old tests/storage paths;
//! runtime consensus flows through Tendermint messages exclusively.

use std::collections::{HashMap, HashSet};

use ace_model::account::AccountId;
use ace_model::sharded_state::{ShardedState, ShardedStateSnapshot};
use ace_runtime::consensus::finality::{FinalityAction, FinalityEvent, FinalityStateMachine};
use ace_runtime::consensus::timeout::TimeoutProtocol;
use ace_runtime::crypto::proof::ProofVerifier;
use ace_runtime::types::block::Block;
use ace_runtime::types::finality::FinalityCertificate;

use ace_n_vm::NVm;

use crate::block_producer::BlockProducer;
use crate::error::ConsensusError;
use crate::leader_schedule::LeaderSchedule;
use crate::metrics::PercentilesReport;
use crate::poh::PohChain;
use crate::round_timer::{RoundTimer, TimeoutConfig};
use crate::tendermint::{TendermintAction, TendermintState};
use crate::validator_set::{Validator, ValidatorSet};
use crate::vote::{Vote, VoteCollector};

/// Top-level consensus engine.
///
/// Wraps the Tendermint state machine for consensus rounds
/// and retains FC tracking for ZK-ACE hard finality.
pub struct ConsensusEngine {
    /// This node's validator identity.
    pub local_id: AccountId,
    /// Leader schedule for proposer assignment.
    pub leader_schedule: LeaderSchedule,
    /// Active validator set.
    pub validator_set: ValidatorSet,
    /// Validator set derived from immutable genesis config.
    genesis_validator_set: ValidatorSet,
    /// Full validator set derived from genesis/admission state.
    pub full_validator_set: ValidatorSet,

    // --- Tendermint consensus ---
    /// Core Tendermint state machine.
    pub tendermint: TendermintState,
    /// Round timer for propose/prevote/precommit timeouts.
    pub round_timer: RoundTimer,
    /// Proposals received for the current height (block_hash → Block).
    pub proposals: HashMap<[u8; 32], Block>,

    // --- FC tracking (Soft → Hard finality) ---
    /// Per-height finality state machines (committed → hard via FC).
    finality_machines: HashMap<u64, FinalityStateMachine>,
    /// Per-height timeout trackers for FC delivery.
    timeout_trackers: HashMap<u64, TimeoutProtocol>,
    /// Per-slot vote collectors retained for legacy finality/test paths only.
    vote_collectors: HashMap<u64, VoteCollector>,
    /// First observed vote hash per (slot, voter).
    observed_votes: HashMap<(u64, AccountId), [u8; 32]>,
    /// Per-slot state snapshots (kept for FC tracking only, no rollback).
    state_snapshots: HashMap<u64, ShardedStateSnapshot>,

    /// PoH chain (preserved as optional timestamp, not consensus-critical).
    pub poh: PohChain,
    /// n-VM dispatcher for multi-VM execution.
    pub n_vm: NVm,
    /// Hash of the last committed block.
    pub last_block_hash: [u8; 32],
    /// Genesis state root hash.
    pub genesis_hash: [u8; 32],

    // ---- Observability counters (Meter.io suggestions) ----
    /// Number of heights committed at round 0 (no leader rotation needed).
    pub round0_commits: u64,
    /// Total heights committed (any round).
    pub total_commits: u64,
}

impl ConsensusEngine {
    /// Create a new consensus engine.
    pub fn new(
        local_id: AccountId,
        leader_schedule: LeaderSchedule,
        validator_set: ValidatorSet,
        poh: PohChain,
        n_vm: NVm,
        genesis_hash: [u8; 32],
    ) -> Self {
        let total_stake = validator_set.total_stake();
        let timeout_config = TimeoutConfig {
            propose_ms: ace_runtime::config::PROPOSE_TIMEOUT_MS,
            prevote_ms: ace_runtime::config::PREVOTE_TIMEOUT_MS,
            precommit_ms: ace_runtime::config::PRECOMMIT_TIMEOUT_MS,
            delta_ms: ace_runtime::config::TIMEOUT_DELTA_MS,
            commit_wait_ms: ace_runtime::config::COMMIT_WAIT_MS,
        };

        Self {
            local_id,
            leader_schedule,
            validator_set: validator_set.clone(),
            genesis_validator_set: validator_set.clone(),
            full_validator_set: validator_set,
            tendermint: TendermintState::new(1, total_stake),
            round_timer: RoundTimer::new(timeout_config),
            proposals: HashMap::new(),
            finality_machines: HashMap::new(),
            timeout_trackers: HashMap::new(),
            vote_collectors: HashMap::new(),
            observed_votes: HashMap::new(),
            state_snapshots: HashMap::new(),
            poh,
            n_vm,
            last_block_hash: genesis_hash,
            genesis_hash,
            round0_commits: 0,
            total_commits: 0,
        }
    }

    /// Rebuild the full validator set from immutable genesis validators plus
    /// persisted on-chain admissions.
    pub fn rebuild_full_validator_set(
        &mut self,
        admitted_validators: &[Validator],
    ) -> Result<(), String> {
        let mut full = self.genesis_validator_set.clone();
        for validator in admitted_validators {
            full.add_validator(validator.clone()).map_err(|error| {
                format!(
                    "invalid persisted validator admission for {}: {error}",
                    hex::encode(validator.id_com.0)
                )
            })?;
        }
        self.full_validator_set = full;
        Ok(())
    }

    // ---- Tendermint interface ----

    /// Check if this node is the proposer for the current height and round.
    pub fn is_proposer(&self, height: u64, round: u32) -> bool {
        self.leader_schedule
            .proposer_for_height_round(height, round, &self.validator_set)
            == self.local_id
    }

    /// Get the current Tendermint height.
    pub fn current_height(&self) -> u64 {
        self.tendermint.height
    }

    /// Get the current Tendermint round.
    pub fn current_round(&self) -> u32 {
        self.tendermint.round
    }

    /// Get the current round step.
    pub fn current_step(&self) -> crate::tendermint::RoundStep {
        self.tendermint.step
    }

    /// Record that a block was committed at the given round.
    ///
    /// Call this immediately after processing a `TendermintAction::Commit`.
    /// Updates round-0 rate counters and pushes the round-to-commit duration
    /// into the `RoundTimer`'s percentile tracker.
    ///
    /// Emits a structured `tracing::info!` with height, round, and elapsed_ms
    /// so that p95/p99 view-change timelines can be computed from log exports.
    pub fn record_commit_round(&mut self, round: u32) {
        self.total_commits += 1;
        if round == 0 {
            self.round0_commits += 1;
        }
        self.round_timer.record_round_commit();

        let elapsed_ms = self.round_timer.round_elapsed_ms();
        let round0_rate = self.round0_rate();
        tracing::info!(
            height = self.tendermint.height,
            commit_round = round,
            elapsed_ms,
            round0_commits = self.round0_commits,
            total_commits = self.total_commits,
            round0_rate_pct = format!("{:.2}", round0_rate * 100.0),
            "block committed"
        );
    }

    /// Fraction of heights committed at round 0 (0.0–1.0).
    /// Returns 1.0 if no commits recorded yet.
    pub fn round0_rate(&self) -> f64 {
        if self.total_commits == 0 {
            return 1.0;
        }
        self.round0_commits as f64 / self.total_commits as f64
    }

    /// Drain round-to-commit duration percentiles (ms) from the round timer.
    /// Returns p50/p95/p99 for the interval since the last call.
    pub fn drain_round_duration_report(&mut self) -> PercentilesReport {
        self.round_timer.drain_round_durations()
    }

    /// Advance to a new height after commit.
    pub fn advance_height(&mut self, new_height: u64) {
        let total_stake = self.validator_set.total_stake();
        self.tendermint.new_height(new_height, total_stake);
        self.round_timer.reset();
        self.proposals.clear();
    }

    /// Process a proposal and return the Tendermint action.
    pub fn on_proposal(
        &mut self,
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        block: Block,
        valid_round: Option<u32>,
    ) -> TendermintAction {
        self.proposals.insert(block_hash, block);
        self.tendermint
            .on_proposal(height, round, block_hash, valid_round)
    }

    /// Process a prevote and return the Tendermint action.
    pub fn on_prevote(
        &mut self,
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        voter: AccountId,
        stake: u64,
    ) -> TendermintAction {
        self.tendermint
            .on_prevote(height, round, block_hash, voter, stake)
    }

    /// Process a precommit and return the Tendermint action.
    pub fn on_precommit(
        &mut self,
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        voter: AccountId,
        stake: u64,
    ) -> TendermintAction {
        self.tendermint
            .on_precommit(height, round, block_hash, voter, stake)
    }

    /// Drain buffered future-round votes that are now current.
    pub fn drain_buffered_actions(&mut self) -> Vec<TendermintAction> {
        self.tendermint.drain_buffered_votes()
    }

    /// Return equivocators detected by the Tendermint state machine.
    pub fn tendermint_equivocators(&self) -> HashMap<AccountId, ([u8; 32], [u8; 32])> {
        self.tendermint.equivocators()
    }

    /// Handle round timeout. Returns the appropriate action.
    pub fn on_timeout(&mut self) -> TendermintAction {
        use crate::tendermint::RoundStep;
        match self.tendermint.step {
            RoundStep::Propose => self.tendermint.on_propose_timeout(),
            RoundStep::Prevote => self.tendermint.on_prevote_timeout(),
            RoundStep::Precommit => self.tendermint.on_precommit_timeout(),
            RoundStep::CommitWait => self.tendermint.on_commit_wait_timeout(),
            RoundStep::Committed => TendermintAction::None,
        }
    }

    /// Take a stored proposal block by hash.
    pub fn take_proposal(&mut self, block_hash: &[u8; 32]) -> Option<Block> {
        self.proposals.remove(block_hash)
    }

    /// Get the proposer for a given height and round.
    pub fn proposer_for(&self, height: u64, round: u32) -> AccountId {
        self.leader_schedule
            .proposer_for_height_round(height, round, &self.validator_set)
    }

    // ---- Legacy finality helpers retained outside the Tendermint runtime path ----

    /// Check if this node is the leader for the given slot (legacy).
    pub fn is_leader(&self, slot: u64) -> bool {
        self.leader_schedule
            .leader_for_slot(slot, &self.validator_set)
            == self.local_id
    }

    /// Produce a block for the given slot (called when this node is leader).
    pub fn produce_block(
        &mut self,
        slot: u64,
        state: &mut ShardedState,
        txs: Vec<ace_runtime::types::transaction::Transaction>,
    ) -> Result<(Block, Vec<ace_n_vm::VmReceipt>), ConsensusError> {
        self.state_snapshots.insert(slot, state.snapshot());

        let (block, receipts) = BlockProducer::produce_block(
            slot,
            self.last_block_hash,
            self.local_id,
            &mut self.poh,
            state,
            &self.n_vm,
            txs,
        )?;

        self.finality_machines
            .insert(slot, FinalityStateMachine::new(slot));
        self.timeout_trackers
            .insert(slot, TimeoutProtocol::new(slot));
        self.vote_collectors.insert(
            slot,
            VoteCollector::new(slot, self.validator_set.total_stake()),
        );

        self.last_block_hash = block.hash();

        Ok((block, receipts))
    }

    /// Register a locally produced block that was built outside the engine.
    pub fn register_produced_block(
        &mut self,
        slot: u64,
        snapshot: ShardedStateSnapshot,
        block_hash: [u8; 32],
    ) {
        self.state_snapshots.insert(slot, snapshot);
        self.finality_machines
            .insert(slot, FinalityStateMachine::new(slot));
        self.timeout_trackers
            .insert(slot, TimeoutProtocol::new(slot));
        self.vote_collectors.insert(
            slot,
            VoteCollector::new(slot, self.validator_set.total_stake()),
        );
        self.last_block_hash = block_hash;
    }

    /// Process an incoming vote (legacy slot-based).
    pub fn on_vote(&mut self, vote: Vote, verifier: &dyn ProofVerifier) -> FinalityAction {
        let slot = vote.slot;
        let voter = vote.voter;
        let block_hash = vote.block_hash;

        if let Some(existing_hash) = self.observed_votes.get(&(slot, voter)) {
            if *existing_hash != block_hash {
                tracing::warn!(
                    voter = %voter,
                    slot,
                    "Equivocation detected: validator voted for conflicting blocks"
                );
                return FinalityAction::None;
            }
        }

        let collector = self
            .vote_collectors
            .entry(slot)
            .or_insert_with(|| VoteCollector::new(slot, self.validator_set.total_stake()));

        let added = collector.add_vote_verified(vote, &self.validator_set);
        if added {
            self.observed_votes.insert((slot, voter), block_hash);
        }

        if let Some(quorum_hash) = collector.quorum_block_hash() {
            let fsm = self
                .finality_machines
                .entry(slot)
                .or_insert_with(|| FinalityStateMachine::new(slot));

            return fsm.on_event(
                FinalityEvent::BlockReceived {
                    votes: collector.voted_stake_for(&quorum_hash),
                    total_stake: self.validator_set.total_stake(),
                    block_hash: quorum_hash,
                },
                verifier,
            );
        }

        FinalityAction::None
    }

    /// Process an incoming finality certificate.
    pub fn on_finality_cert(
        &mut self,
        cert: FinalityCertificate,
        block: Option<&Block>,
        verifier: &dyn ProofVerifier,
    ) -> FinalityAction {
        let slot = cert.slot;

        let fsm = self
            .finality_machines
            .entry(slot)
            .or_insert_with(|| FinalityStateMachine::new(slot));

        let action = fsm.on_finality_certificate(cert, block, verifier);

        if fsm.state() == ace_runtime::types::finality::FinalityState::Hard {
            if let Some(timeout) = self.timeout_trackers.get_mut(&slot) {
                timeout.resolve();
            }
        }

        action
    }

    /// Check and process timeouts for a given current slot (legacy).
    pub fn check_timeouts(
        &mut self,
        current_slot: u64,
        verifier: &dyn ProofVerifier,
    ) -> Vec<(u64, FinalityAction)> {
        let mut actions = Vec::new();

        let slots: Vec<u64> = self.timeout_trackers.keys().copied().collect();
        for block_slot in slots {
            let Some(timeout) = self.timeout_trackers.get(&block_slot) else {
                continue;
            };
            let phase = timeout.phase(current_slot);

            use ace_runtime::consensus::timeout::TimeoutPhase;
            let event = match phase {
                TimeoutPhase::BackupWindow => {
                    if timeout.is_builder_expired(current_slot) {
                        Some(FinalityEvent::BuilderTimeout)
                    } else {
                        None
                    }
                }
                TimeoutPhase::Expired => Some(FinalityEvent::BackupTimeout),
                _ => None,
            };

            if let Some(ev) = event {
                if let Some(fsm) = self.finality_machines.get_mut(&block_slot) {
                    let action = fsm.on_event(ev, verifier);
                    if action != FinalityAction::None {
                        actions.push((block_slot, action));
                    }
                }
            }
        }

        actions
    }

    /// Store a state snapshot.
    pub fn store_snapshot(&mut self, slot: u64, snapshot: ShardedStateSnapshot) {
        self.state_snapshots.insert(slot, snapshot);
        self.finality_machines
            .entry(slot)
            .or_insert_with(|| FinalityStateMachine::new(slot));
        self.timeout_trackers
            .entry(slot)
            .or_insert_with(|| TimeoutProtocol::new(slot));
        self.vote_collectors
            .entry(slot)
            .or_insert_with(|| VoteCollector::new(slot, self.validator_set.total_stake()));
    }

    /// Get a state snapshot.
    pub fn take_snapshot(&mut self, slot: u64) -> Option<ShardedStateSnapshot> {
        self.state_snapshots.remove(&slot)
    }

    /// Get the finality state machine for a slot.
    pub fn finality_state(&self, slot: u64) -> Option<&FinalityStateMachine> {
        self.finality_machines.get(&slot)
    }

    /// Return the block hash that currently has quorum votes for the slot, if any.
    pub fn quorum_block_hash(&self, slot: u64) -> Option<[u8; 32]> {
        self.vote_collectors
            .get(&slot)
            .and_then(VoteCollector::quorum_block_hash)
    }

    /// Return the currently leading voted hash for the slot, if any votes exist.
    pub fn leading_block_hash(&self, slot: u64) -> Option<[u8; 32]> {
        self.vote_collectors
            .get(&slot)
            .and_then(VoteCollector::leading_block_hash)
    }

    /// Return the observed voted stake for a specific hash in a slot.
    pub fn voted_stake_for(&self, slot: u64, block_hash: &[u8; 32]) -> u64 {
        self.vote_collectors
            .get(&slot)
            .map_or(0, |collector| collector.voted_stake_for(block_hash))
    }

    /// Return the block hash this voter has already cast for the slot, if any.
    pub fn voter_block_hash(&self, slot: u64, voter: &AccountId) -> Option<[u8; 32]> {
        self.observed_votes
            .get(&(slot, *voter))
            .copied()
            .or_else(|| {
                self.vote_collectors
                    .get(&slot)
                    .and_then(|collector| collector.voter_block_hash(voter))
            })
    }

    /// Get equivocators for a slot.
    pub fn equivocators_for_slot(
        &self,
        slot: u64,
    ) -> Option<&HashMap<AccountId, ([u8; 32], [u8; 32])>> {
        self.vote_collectors.get(&slot).map(|c| c.equivocators())
    }

    /// Replace the effective validator set.
    ///
    /// Only bumps the generation counter (triggering per-collector reconcile) when
    /// the new set is structurally different. This matters because this method is
    /// called on every consensus-loop tick in steady state; bumping unconditionally
    /// would defeat the reconcile_validator_set short-circuit and force O(votes)
    /// PQC re-verification on every tick, stalling the consensus thread.
    pub fn set_effective_validator_set(&mut self, mut validator_set: ValidatorSet) {
        let changed = self.validator_set.total_stake() != validator_set.total_stake()
            || self.validator_set.validators().len() != validator_set.validators().len()
            || self
                .validator_set
                .validators()
                .iter()
                .zip(validator_set.validators())
                .any(|(a, b)| {
                    a.id_com != b.id_com
                        || a.stake != b.stake
                        || a.index != b.index
                        || a.signing_pubkey != b.signing_pubkey
                        || a.capabilities != b.capabilities
                });
        if !changed {
            return;
        }
        let new_generation = self.validator_set.generation().wrapping_add(1);
        validator_set.set_generation(new_generation);
        self.validator_set = validator_set;
        for collector in self.vote_collectors.values_mut() {
            collector.reconcile_validator_set(&self.validator_set);
        }
    }

    /// Clean up finalized slot data to prevent unbounded memory growth.
    pub fn cleanup_finalized(&mut self, current_slot: u64, retention: u64) {
        let cutoff = current_slot.saturating_sub(retention);

        let terminal: HashSet<u64> = self
            .finality_machines
            .iter()
            .filter(|(&s, fsm)| s < cutoff && fsm.state().is_terminal())
            .map(|(&s, _)| s)
            .collect();

        for s in &terminal {
            self.finality_machines.remove(s);
            self.timeout_trackers.remove(s);
            self.vote_collectors.remove(s);
            self.state_snapshots.remove(s);
        }
        self.observed_votes
            .retain(|(slot, _), _| !terminal.contains(slot));

        // Snapshots are only needed while a slot can still roll back.
        // Once the slot reaches a terminal finality state, or ages past the
        // builder+backup timeout window, keeping a full cloned state tree just
        // burns memory with no recovery value.
        let snapshot_window =
            ace_runtime::config::K_BUILDER_SLOTS + ace_runtime::config::K_BACKUP_SLOTS + 2;
        let snapshot_cutoff = current_slot.saturating_sub(snapshot_window);
        let finality_machines = &self.finality_machines;
        self.state_snapshots.retain(|&slot, _| {
            slot >= snapshot_cutoff
                && finality_machines
                    .get(&slot)
                    .is_some_and(|fsm| !fsm.state().is_terminal())
        });
    }

    /// Remove all tracking state for a specific slot.
    pub fn reset_slot(&mut self, slot: u64) {
        self.finality_machines.remove(&slot);
        self.timeout_trackers.remove(&slot);
        self.vote_collectors.remove(&slot);
        self.state_snapshots.remove(&slot);
    }
}
