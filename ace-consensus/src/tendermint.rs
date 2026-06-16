//! Tendermint/CometBFT-style consensus state machine.
//!
//! Height-based consensus with three phases per round:
//! Propose → Prevote → Precommit.
//!
//! Each height may have multiple rounds if the proposer fails.
//! A block is committed when ⅔ precommits are collected (instant finality).
//! No forks, no reorgs — committed blocks are final.

use std::collections::HashMap;

use ace_model::account::AccountId;

use crate::vote::VoteCollector;

/// The current step within a Tendermint round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundStep {
    /// Waiting for the proposer's block proposal.
    Propose,
    /// Collecting prevotes (⅔ needed to advance to Precommit).
    Prevote,
    /// Collecting precommits (⅔ needed to commit).
    Precommit,
    /// Waiting briefly after commit to collect additional precommits.
    CommitWait,
    /// Block has been committed at this height.
    Committed,
}

/// Nil block hash sentinel (all zeros). SHA-256 preimage resistance
/// guarantees this is never a valid block hash.
pub const NIL_BLOCK_HASH: [u8; 32] = [0u8; 32];

/// Actions returned by the Tendermint state machine for the caller to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TendermintAction {
    /// No action needed.
    None,
    /// Caller should build a block and broadcast a proposal.
    ScheduleProposal { height: u64, round: u32 },
    /// Broadcast a prevote for the given block hash (or nil).
    BroadcastPrevote {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
    },
    /// Broadcast a precommit for the given block hash (or nil).
    BroadcastPrecommit {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
    },
    /// Block committed — caller should apply it to state.
    Commit {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
    },
}

/// Tendermint round state machine.
///
/// Implements the core Tendermint algorithm:
/// - Each height starts at round 0
/// - The proposer for (height, round) broadcasts a block proposal
/// - Validators send prevotes (for the proposed block or nil on timeout)
/// - On ⅔ prevotes for a hash → validators send precommits
/// - On ⅔ precommits for a hash → block is committed
/// - On ⅔ precommits for nil or timeout → advance to next round
pub struct TendermintState {
    /// Current height (= slot in BlockHeader).
    pub height: u64,
    /// Current round within the height.
    pub round: u32,
    /// Current step within the round.
    pub step: RoundStep,

    /// The proposed block hash for the current round (if received).
    proposal_hash: Option<[u8; 32]>,
    /// Whether we have received a valid proposal for the current round.
    proposal_received: bool,

    /// Round at which we locked on a block (Tendermint locking rule).
    locked_round: Option<u32>,
    /// Block hash we are locked on.
    locked_hash: Option<[u8; 32]>,

    /// Round at which we saw a valid proposal + ⅔ prevotes.
    valid_round: Option<u32>,
    /// The valid block hash.
    valid_hash: Option<[u8; 32]>,

    /// Prevote collector for (height, round).
    prevotes: VoteCollector,
    /// Precommit collector for (height, round).
    precommits: VoteCollector,

    /// Total stake for quorum checks.
    total_stake: u64,

    /// Whether we have already sent a prevote for this round.
    prevoted: bool,
    /// Whether we have already sent a precommit for this round.
    precommitted: bool,

    /// The block hash that was committed (set when step = Committed).
    committed_hash: Option<[u8; 32]>,

    /// Buffered votes for future rounds at the same height.
    /// Key: round number. Value: Vec of (voter, block_hash, stake, is_precommit).
    future_votes: HashMap<u32, Vec<(AccountId, [u8; 32], u64, bool)>>,

    /// Records rounds at which ⅔ prevotes were observed for a specific block hash.
    /// Key: (round, block_hash). Used to verify `valid_round` in re-proposals.
    past_quorums: HashMap<(u32, [u8; 32]), bool>,
}

impl TendermintState {
    /// Create a new Tendermint state machine starting at the given height.
    pub fn new(height: u64, total_stake: u64) -> Self {
        Self {
            height,
            round: 0,
            step: RoundStep::Propose,
            proposal_hash: None,
            proposal_received: false,
            locked_round: None,
            locked_hash: None,
            valid_round: None,
            valid_hash: None,
            prevotes: VoteCollector::new(height, total_stake),
            precommits: VoteCollector::new(height, total_stake),
            total_stake,
            prevoted: false,
            precommitted: false,
            committed_hash: None,
            future_votes: HashMap::new(),
            past_quorums: HashMap::new(),
        }
    }

    /// Whether a proposal has been received for the current round.
    pub fn has_proposal(&self) -> bool {
        self.proposal_received
    }

    /// Advance to a new height after a commit.
    pub fn new_height(&mut self, height: u64, total_stake: u64) {
        self.height = height;
        self.round = 0;
        self.step = RoundStep::Propose;
        self.proposal_hash = None;
        self.proposal_received = false;
        self.locked_round = None;
        self.locked_hash = None;
        self.valid_round = None;
        self.valid_hash = None;
        self.prevotes = VoteCollector::new(height, total_stake);
        self.precommits = VoteCollector::new(height, total_stake);
        self.total_stake = total_stake;
        self.prevoted = false;
        self.precommitted = false;
        self.committed_hash = None;
        self.future_votes.clear();
        self.past_quorums.clear();
    }

    /// Advance to the next round (proposer failed or ⅔ nil precommits).
    pub fn new_round(&mut self, round: u32) {
        self.round = round;
        self.step = RoundStep::Propose;
        self.proposal_hash = None;
        self.proposal_received = false;
        // locked_round and locked_hash persist across rounds (Tendermint locking rule)
        self.prevotes = VoteCollector::new(self.height, self.total_stake);
        self.precommits = VoteCollector::new(self.height, self.total_stake);
        self.prevoted = false;
        self.precommitted = false;
    }

    /// Process a proposal from the proposer.
    ///
    /// Returns a prevote action if the proposal is valid.
    pub fn on_proposal(
        &mut self,
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        valid_round: Option<u32>,
    ) -> TendermintAction {
        // Ignore proposals for wrong height/round
        if height != self.height || round != self.round {
            return TendermintAction::None;
        }
        // Ignore if we already have a proposal
        if self.proposal_received {
            return TendermintAction::None;
        }
        // Ignore if we're past the Propose step
        if self.step != RoundStep::Propose {
            return TendermintAction::None;
        }

        self.proposal_hash = Some(block_hash);
        self.proposal_received = true;

        // Tendermint locking rule: if we're locked, only prevote for the locked hash
        // unless the proposal comes with a valid_round > locked_round with ⅔ prevotes
        if let Some(locked_hash) = self.locked_hash {
            if block_hash == locked_hash {
                // Proposal matches our lock — prevote for it
                return self.do_prevote(block_hash);
            }
            if let (Some(vr), Some(lr)) = (valid_round, self.locked_round) {
                if vr >= lr {
                    // Proposal has a valid_round >= our lock. The vr == lr case
                    // means the same round had two blocks each reaching 2/3
                    // prevotes, implying 1/3+ double-signed — impossible under
                    // the BFT assumption, so treating it identically to vr > lr
                    // is safe. We still require past_quorums evidence.
                    if self.past_quorums.contains_key(&(vr, block_hash)) {
                        return self.do_prevote(block_hash);
                    }
                    // No verified quorum at vr — cannot trust the valid_round claim
                    return self.do_prevote(NIL_BLOCK_HASH);
                }
            }
            // Locked on a different block — prevote nil
            return self.do_prevote(NIL_BLOCK_HASH);
        }

        // Not locked — if valid_round is claimed, verify we saw ⅔ prevotes at that round
        if let Some(vr) = valid_round {
            if !self.past_quorums.contains_key(&(vr, block_hash)) {
                return self.do_prevote(NIL_BLOCK_HASH);
            }
        }
        // Emit our prevote first. The caller must broadcast this and feed it back
        // via on_prevote before any precommit can be issued — do NOT shortcut to
        // precommit here, even if ⅔ prevotes are already buffered in the collector.
        // Skipping the BroadcastPrevote action would omit the WAL write, the
        // network broadcast, and the self-feed into the state machine, breaking
        // crash recovery and certificate completeness.
        //
        // The fast-path for already-accumulated prevote quorum is handled in
        // on_prevote: when the caller feeds our own prevote back after broadcasting,
        // on_prevote will detect the existing quorum and emit BroadcastPrecommit
        // immediately without waiting for the prevote timeout.
        self.do_prevote(block_hash)
    }

    /// Process a prevote from a validator.
    pub fn on_prevote(
        &mut self,
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        voter: AccountId,
        stake: u64,
    ) -> TendermintAction {
        if height != self.height {
            return TendermintAction::None;
        }
        if round > self.round {
            self.future_votes
                .entry(round)
                .or_default()
                .push((voter, block_hash, stake, false));
            return TendermintAction::None;
        }
        if round != self.round {
            return TendermintAction::None;
        }
        if self.step == RoundStep::Committed || self.step == RoundStep::CommitWait {
            return TendermintAction::None;
        }

        // Add to prevote collector using internal method
        self.prevotes.add_vote_raw(voter, block_hash, stake);

        // Check if ⅔ prevotes for a specific block hash
        if let Some(quorum_hash) = self.prevotes.quorum_block_hash() {
            if quorum_hash != NIL_BLOCK_HASH {
                // ⅔ prevotes for a block → set valid block and lock
                self.past_quorums.insert((self.round, quorum_hash), true);
                self.valid_round = Some(self.round);
                self.valid_hash = Some(quorum_hash);

                if self.step == RoundStep::Prevote {
                    // Lock on this block
                    self.locked_round = Some(self.round);
                    self.locked_hash = Some(quorum_hash);
                    self.step = RoundStep::Precommit;
                    return self.do_precommit(quorum_hash);
                }
            } else {
                // ⅔ prevotes for nil
                if self.step == RoundStep::Prevote {
                    self.step = RoundStep::Precommit;
                    return self.do_precommit(NIL_BLOCK_HASH);
                }
            }
        }

        // If we haven't prevoted yet and received a proposal, prevote now
        if self.step == RoundStep::Propose && self.proposal_received && !self.prevoted {
            let hash = self.proposal_hash.unwrap_or(NIL_BLOCK_HASH);
            if let Some(locked_hash) = self.locked_hash {
                if hash != locked_hash {
                    return self.do_prevote(NIL_BLOCK_HASH);
                }
            }
            return self.do_prevote(hash);
        }

        TendermintAction::None
    }

    /// Process a precommit from a validator.
    pub fn on_precommit(
        &mut self,
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        voter: AccountId,
        stake: u64,
    ) -> TendermintAction {
        if height != self.height {
            return TendermintAction::None;
        }
        if round > self.round {
            self.future_votes
                .entry(round)
                .or_default()
                .push((voter, block_hash, stake, true));
            return TendermintAction::None;
        }
        if round != self.round {
            return TendermintAction::None;
        }
        if self.step == RoundStep::Committed || self.step == RoundStep::CommitWait {
            // Still collect precommits during CommitWait for certificate completeness,
            // but don't trigger another Commit action.
            if self.step == RoundStep::CommitWait {
                self.precommits.add_vote_raw(voter, block_hash, stake);
            }
            return TendermintAction::None;
        }

        self.precommits.add_vote_raw(voter, block_hash, stake);

        // Check if ⅔ precommits for a specific block hash
        if let Some(quorum_hash) = self.precommits.quorum_block_hash() {
            if quorum_hash != NIL_BLOCK_HASH {
                // ⅔ precommits for a block → COMMIT (enter CommitWait phase)
                self.step = RoundStep::CommitWait;
                self.committed_hash = Some(quorum_hash);
                return TendermintAction::Commit {
                    height: self.height,
                    round: self.round,
                    block_hash: quorum_hash,
                };
            }
            // ⅔ precommits for nil → advance round (handled by timeout)
        }

        TendermintAction::None
    }

    /// Called when the propose timeout fires.
    ///
    /// If we haven't received a proposal, prevote nil.
    ///
    /// **Timeout attribution:** fires when the proposer did not deliver a block
    /// in time.  Possible causes: proposer crash, network partition, or the
    /// proposer's ML-DSA-44 signing queue stalling block construction.
    pub fn on_propose_timeout(&mut self) -> TendermintAction {
        if self.step != RoundStep::Propose {
            return TendermintAction::None;
        }
        tracing::warn!(
            height = self.height,
            round = self.round,
            timeout_type = "propose",
            cause = "no_proposal_received",
            "consensus timeout: proposer did not deliver block"
        );
        self.do_prevote(NIL_BLOCK_HASH)
    }

    /// Called when the prevote timeout fires (⅔ prevotes received but
    /// no ⅔ for any single hash).
    ///
    /// **Timeout attribution:** fires after ⅔ prevotes are seen but no single
    /// hash reaches quorum.  Under PQC load the most likely causes are:
    /// (a) ML-DSA-44 verify latency delaying some validators from casting their
    /// prevote before others; (b) split votes from a transient partition;
    /// (c) mempool admission back-pressure slowing validators' block validation.
    pub fn on_prevote_timeout(&mut self) -> TendermintAction {
        if self.step != RoundStep::Prevote {
            return TendermintAction::None;
        }
        let prevote_stake = self.prevotes.voted_stake();
        let quorum_hash = self.prevotes.quorum_block_hash();
        tracing::warn!(
            height = self.height,
            round = self.round,
            timeout_type = "prevote",
            cause = "no_single_hash_quorum",
            prevote_stake,
            has_any_quorum = quorum_hash.is_some(),
            "consensus timeout: ⅔ prevotes seen but no hash reached quorum \
             (check ML-DSA verify latency and mempool admission)"
        );
        self.step = RoundStep::Precommit;
        self.do_precommit(NIL_BLOCK_HASH)
    }

    /// Called when the precommit timeout fires.
    ///
    /// Advances to the next round (leader rotation).
    ///
    /// **Timeout attribution:** this is the leader-rotation trigger.  Under PQC
    /// load, if the proposer's signing queue is saturated, it may build a block
    /// late enough that prevotes / precommits do not complete before this fires.
    /// Watch for this event correlated with high `ml_dsa_verify_us` in vote logs.
    pub fn on_precommit_timeout(&mut self) -> TendermintAction {
        if self.step == RoundStep::Committed || self.step == RoundStep::CommitWait {
            return TendermintAction::None;
        }
        let new_round = self.round + 1;
        let precommit_stake = self.precommits.voted_stake();
        tracing::warn!(
            height = self.height,
            old_round = self.round,
            new_round,
            timeout_type = "precommit",
            cause = "leader_rotation",
            precommit_stake,
            "consensus timeout: advancing round — leader rotation triggered \
             (watch ml_dsa_verify_us and signer queue depth)"
        );
        self.new_round(new_round);
        TendermintAction::ScheduleProposal {
            height: self.height,
            round: new_round,
        }
    }

    /// Called when the commit-wait timeout expires.
    /// Transitions from CommitWait to Committed.
    pub fn on_commit_wait_timeout(&mut self) -> TendermintAction {
        if self.step == RoundStep::CommitWait {
            self.step = RoundStep::Committed;
        }
        TendermintAction::None
    }

    /// Get the committed block hash, if any.
    pub fn committed_hash(&self) -> Option<[u8; 32]> {
        self.committed_hash
    }

    /// Force-commit from an externally verified commit certificate.
    ///
    /// Called when a peer's `CommitCertificate` has been verified to contain
    /// 2/3+ valid precommit signatures.  Transitions directly to CommitWait
    /// so the node can apply the block without waiting for individual
    /// precommit messages.
    pub fn force_commit(&mut self, height: u64, round: u32, block_hash: [u8; 32]) {
        if height != self.height {
            return;
        }
        self.round = round;
        self.step = RoundStep::CommitWait;
        self.committed_hash = Some(block_hash);
    }

    /// Restore lock state from WAL recovery (crash recovery).
    pub fn restore_lock(&mut self, round: u32, hash: [u8; 32]) {
        self.locked_round = Some(round);
        self.locked_hash = Some(hash);
    }

    /// Return all equivocators detected in the current round (prevotes + precommits).
    pub fn equivocators(&self) -> HashMap<AccountId, ([u8; 32], [u8; 32])> {
        let mut all = self.prevotes.equivocators().clone();
        all.extend(self.precommits.equivocators().iter().map(|(k, v)| (*k, *v)));
        all
    }

    /// Drain buffered votes for the current round and replay them.
    ///
    /// Returns all non-None actions produced by replaying the buffered votes.
    pub fn drain_buffered_votes(&mut self) -> Vec<TendermintAction> {
        // Drain votes for the current round
        let votes = match self.future_votes.remove(&self.round) {
            Some(v) => v,
            None => return Vec::new(),
        };

        // Cleanup older rounds only when we advance to a new round, not on every drain.
        if self.round > 0 {
            self.future_votes.retain(|&r, _| r >= self.round);
        }

        let mut actions = Vec::new();
        for (voter, block_hash, stake, is_precommit) in votes {
            let action = if is_precommit {
                self.on_precommit(self.height, self.round, block_hash, voter, stake)
            } else {
                self.on_prevote(self.height, self.round, block_hash, voter, stake)
            };
            if action != TendermintAction::None {
                actions.push(action);
            }
        }
        actions
    }

    fn do_prevote(&mut self, block_hash: [u8; 32]) -> TendermintAction {
        if self.prevoted {
            return TendermintAction::None;
        }
        self.prevoted = true;
        if self.step == RoundStep::Propose {
            self.step = RoundStep::Prevote;
        }
        TendermintAction::BroadcastPrevote {
            height: self.height,
            round: self.round,
            block_hash,
        }
    }

    fn do_precommit(&mut self, block_hash: [u8; 32]) -> TendermintAction {
        if self.precommitted {
            return TendermintAction::None;
        }
        self.precommitted = true;
        TendermintAction::BroadcastPrecommit {
            height: self.height,
            round: self.round,
            block_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> TendermintState {
        TendermintState::new(1, 300) // 3 validators × 100 stake each
    }

    fn voter(n: u8) -> AccountId {
        AccountId([n; 32])
    }

    #[test]
    fn basic_commit_flow() {
        let mut state = make_state();
        let block_hash = [0xAA; 32];

        // Proposal received
        let action = state.on_proposal(1, 0, block_hash, None);
        assert_eq!(
            action,
            TendermintAction::BroadcastPrevote {
                height: 1,
                round: 0,
                block_hash,
            }
        );

        // Receive ⅔ prevotes (200/300 stake)
        let a1 = state.on_prevote(1, 0, block_hash, voter(1), 100);
        assert_eq!(a1, TendermintAction::None);
        let a2 = state.on_prevote(1, 0, block_hash, voter(2), 100);
        assert_eq!(
            a2,
            TendermintAction::BroadcastPrecommit {
                height: 1,
                round: 0,
                block_hash,
            }
        );

        // Receive ⅔ precommits
        let a3 = state.on_precommit(1, 0, block_hash, voter(1), 100);
        assert_eq!(a3, TendermintAction::None);
        let a4 = state.on_precommit(1, 0, block_hash, voter(2), 100);
        assert_eq!(
            a4,
            TendermintAction::Commit {
                height: 1,
                round: 0,
                block_hash,
            }
        );
        assert_eq!(state.step, RoundStep::CommitWait);
    }

    #[test]
    fn propose_timeout_triggers_nil_prevote() {
        let mut state = make_state();
        let action = state.on_propose_timeout();
        assert_eq!(
            action,
            TendermintAction::BroadcastPrevote {
                height: 1,
                round: 0,
                block_hash: NIL_BLOCK_HASH,
            }
        );
    }

    #[test]
    fn nil_precommits_advance_round() {
        let mut state = make_state();

        // Propose timeout → prevote nil
        state.on_propose_timeout();
        // Prevote nil from two voters
        state.on_prevote(1, 0, NIL_BLOCK_HASH, voter(1), 100);
        state.on_prevote(1, 0, NIL_BLOCK_HASH, voter(2), 100);
        // Now in precommit step, precommit nil
        state.on_precommit(1, 0, NIL_BLOCK_HASH, voter(1), 100);
        state.on_precommit(1, 0, NIL_BLOCK_HASH, voter(2), 100);
        // Precommit timeout advances round
        let action = state.on_precommit_timeout();
        match action {
            TendermintAction::ScheduleProposal { height, round } => {
                assert_eq!(height, 1);
                assert_eq!(round, 1);
            }
            _ => panic!("expected ScheduleProposal"),
        }
        assert_eq!(state.round, 1);
        assert_eq!(state.step, RoundStep::Propose);
    }

    #[test]
    fn new_height_resets_state() {
        let mut state = make_state();
        let block_hash = [0xBB; 32];

        // Commit at height 1
        state.on_proposal(1, 0, block_hash, None);
        state.on_prevote(1, 0, block_hash, voter(1), 100);
        state.on_prevote(1, 0, block_hash, voter(2), 100);
        state.on_precommit(1, 0, block_hash, voter(1), 100);
        state.on_precommit(1, 0, block_hash, voter(2), 100);
        assert_eq!(state.step, RoundStep::CommitWait);

        // Advance to height 2
        state.new_height(2, 300);
        assert_eq!(state.height, 2);
        assert_eq!(state.round, 0);
        assert_eq!(state.step, RoundStep::Propose);
        assert!(state.locked_hash.is_none());
        assert!(state.committed_hash.is_none());
        assert!(state.future_votes.is_empty());
    }

    #[test]
    fn future_round_votes_are_buffered() {
        let mut state = make_state();
        let block_hash = [0xCC; 32];

        // Send prevotes for round 1 while still in round 0
        let a1 = state.on_prevote(1, 1, block_hash, voter(1), 100);
        assert_eq!(a1, TendermintAction::None);
        let a2 = state.on_prevote(1, 1, block_hash, voter(2), 100);
        assert_eq!(a2, TendermintAction::None);

        // Send a precommit for round 1 as well
        let a3 = state.on_precommit(1, 1, block_hash, voter(1), 100);
        assert_eq!(a3, TendermintAction::None);

        // Verify they are buffered
        assert_eq!(state.future_votes.get(&1).unwrap().len(), 3);

        // Votes for wrong height should not be buffered
        let a4 = state.on_prevote(2, 1, block_hash, voter(3), 100);
        assert_eq!(a4, TendermintAction::None);
        assert_eq!(state.future_votes.get(&1).unwrap().len(), 3); // unchanged

        // Advance to round 1 via precommit timeout
        // First go through round 0 steps
        state.on_propose_timeout();
        state.on_prevote(1, 0, NIL_BLOCK_HASH, voter(1), 100);
        state.on_prevote(1, 0, NIL_BLOCK_HASH, voter(2), 100);
        state.on_precommit(1, 0, NIL_BLOCK_HASH, voter(1), 100);
        state.on_precommit(1, 0, NIL_BLOCK_HASH, voter(2), 100);
        let action = state.on_precommit_timeout();
        assert!(matches!(
            action,
            TendermintAction::ScheduleProposal {
                height: 1,
                round: 1
            }
        ));
        assert_eq!(state.round, 1);

        // Drain buffered votes — replays 2 prevotes and 1 precommit into collectors.
        // No actions yet because we're in Propose step with no proposal, but
        // the votes are now in the collectors.
        let actions = state.drain_buffered_votes();
        // Buffer for round 1 should now be drained
        assert!(state.future_votes.get(&1).is_none());

        // Now receive a proposal for round 1 — the ⅔ prevotes already in the
        // collector should cause an immediate lock + precommit.
        let proposal_action = state.on_proposal(1, 1, block_hash, None);
        // Proposal triggers prevote for the block
        assert_eq!(
            proposal_action,
            TendermintAction::BroadcastPrevote {
                height: 1,
                round: 1,
                block_hash,
            }
        );
        // After our own prevote, quorum is reached (voter(1) + voter(2) = 200 stake).
        // The prevote processing already happened inside on_proposal -> do_prevote
        // doesn't add to collector, but step advanced to Prevote.
        // Feed our own prevote to reach quorum check via on_prevote.
        let pv_action = state.on_prevote(1, 1, block_hash, voter(3), 100);
        // With 3 prevotes already in collector (voter(1), voter(2) from buffer +
        // voter(3) now), quorum is definitely reached → precommit.
        assert!(
            matches!(pv_action, TendermintAction::BroadcastPrecommit { .. })
                || actions
                    .iter()
                    .any(|a| matches!(a, TendermintAction::BroadcastPrecommit { .. })),
            "Expected a precommit after prevote quorum from buffered + new votes"
        );
    }

    #[test]
    fn future_round_precommits_produce_commit_on_drain() {
        // 4 validators × 100 stake = 400 total. ⅔ quorum = 267+ stake.
        let mut state = TendermintState::new(1, 400);
        let block_hash = [0xDD; 32];

        // Buffer precommits for round 1 from 3 validators (300/400 > ⅔)
        state.on_precommit(1, 1, block_hash, voter(1), 100);
        state.on_precommit(1, 1, block_hash, voter(2), 100);
        state.on_precommit(1, 1, block_hash, voter(3), 100);
        assert_eq!(state.future_votes.get(&1).unwrap().len(), 3);

        // Advance to round 1
        state.new_round(1);

        // Drain — the 3 precommits should produce a Commit action
        let actions = state.drain_buffered_votes();
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, TendermintAction::Commit {
                height: 1,
                round: 1,
                block_hash: bh,
            } if *bh == block_hash)),
            "Expected Commit from ⅔ buffered precommits, got: {:?}",
            actions
        );
    }
}
