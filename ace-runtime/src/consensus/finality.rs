//! Finality state machine (Algorithm 2 in the paper).
//!
//! ## States
//! {Pending, Soft, BackupWait, Hard, RolledBack}
//!
//! ## Events (4 transitions)
//! 1. `BlockReceived(votes, block_hash)` → Pending → Soft (if ⅔ quorum)
//! 2. `FinalityCertReceived(fc)` → Soft/BackupWait → Hard (valid FC)
//!    Soft → RolledBack (invalid FC)
//!    BackupWait: invalid FC ignored
//! 3. `Timeout(K)` → Soft → BackupWait (slash builder)
//! 4. `Timeout(K+K')` → BackupWait → RolledBack (requeue txs)

use crate::config;
use crate::crypto::proof::ProofVerifier;
use crate::types::block::Block;
use crate::types::finality::{FinalityCertificate, FinalityState};

/// Events that drive the finality state machine.
#[derive(Debug, Clone)]
pub enum FinalityEvent {
    /// Block received with the given number of votes, total stake, and block hash.
    BlockReceived {
        votes: u64,
        total_stake: u64,
        block_hash: [u8; 32],
    },
    /// Finality certificate received.
    FinalityCertReceived { certificate: FinalityCertificate },
    /// Builder timeout: K slots have elapsed without a finality certificate.
    BuilderTimeout,
    /// Backup timeout: K+K' slots have elapsed without a finality certificate.
    BackupTimeout,
}

/// Side effects produced by state machine transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalityAction {
    /// No action needed.
    None,
    /// Slash the builder's stake.
    SlashBuilder,
    /// Requeue the block's transactions back to the mempool.
    RequeueTxs,
    /// Both slash and rollback (should not happen in normal flow).
    SlashAndRequeue,
}

/// The finality state machine for a single block.
///
/// Implements Algorithm 2 from the paper exactly:
/// - 5 states
/// - 4 event types
/// - Deterministic transitions with side effects (slash, requeue)
///
/// The FSM performs **context binding** on finality certificates:
/// it rejects any FC whose `slot` or `block_hash` does not match the
/// block being tracked, preventing cross-block FC replay attacks.
pub struct FinalityStateMachine {
    /// Current finality state.
    state: FinalityState,
    /// Slot number of the block being tracked.
    slot: u64,
    /// Whether the builder has already been slashed (prevent double-slash).
    builder_slashed: bool,
    /// Expected block hash — set when transitioning to Soft.
    expected_block_hash: Option<[u8; 32]>,
    /// Whether an invalid FC has been seen in Soft state.
    /// Used to defer RolledBack until builder timeout instead of instant rollback on any invalid FC.
    invalid_fc_seen: bool,
}

impl FinalityStateMachine {
    /// Create a new state machine for a block at the given slot.
    /// Initial state is always Pending.
    pub fn new(slot: u64) -> Self {
        Self {
            state: FinalityState::Pending,
            slot,
            builder_slashed: false,
            expected_block_hash: None,
            invalid_fc_seen: false,
        }
    }

    /// Get the current finality state.
    pub fn state(&self) -> FinalityState {
        self.state
    }

    /// Get the slot this state machine tracks.
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Whether the builder has been slashed.
    pub fn is_builder_slashed(&self) -> bool {
        self.builder_slashed
    }

    /// Process an event and return the resulting action.
    ///
    /// This is the core of Algorithm 2. State transitions are
    /// deterministic and depend only on the current state and event.
    pub fn on_event(
        &mut self,
        event: FinalityEvent,
        verifier: &dyn ProofVerifier,
    ) -> FinalityAction {
        // Terminal states accept no more events.
        if self.state.is_terminal() {
            return FinalityAction::None;
        }

        match event {
            FinalityEvent::BlockReceived {
                votes,
                total_stake,
                block_hash,
            } => self.on_block_received(votes, total_stake, block_hash),

            FinalityEvent::FinalityCertReceived { certificate } => {
                self.on_finality_cert_received(certificate, None, verifier)
            }

            FinalityEvent::BuilderTimeout => self.on_builder_timeout(),

            FinalityEvent::BackupTimeout => self.on_backup_timeout(),
        }
    }

    /// Handle BlockReceived event.
    ///
    /// Pending → Soft if ⅔ quorum is met. Stores expected block hash.
    fn on_block_received(
        &mut self,
        votes: u64,
        total_stake: u64,
        block_hash: [u8; 32],
    ) -> FinalityAction {
        if self.state != FinalityState::Pending {
            return FinalityAction::None;
        }

        if config::has_quorum(votes, total_stake) {
            self.state = FinalityState::Soft;
            self.expected_block_hash = Some(block_hash);
        }

        FinalityAction::None
    }

    /// Handle FinalityCertReceived event.
    ///
    /// **Context binding**: Before cryptographic verification, the FSM checks
    /// that the FC's slot and block_hash match the block being tracked.
    /// A mismatched FC is treated as invalid (same as a cryptographically
    /// invalid proof).
    ///
    /// - Soft + valid FC → Hard
    /// - BackupWait + valid FC → Hard
    /// - Soft + invalid FC → ignored (deferred to builder timeout to prevent griefing)
    /// - BackupWait + invalid FC → ignored (await K+K' timeout)
    fn on_finality_cert_received(
        &mut self,
        fc: FinalityCertificate,
        block: Option<&Block>,
        verifier: &dyn ProofVerifier,
    ) -> FinalityAction {
        // Context binding check: FC must reference the correct block
        let context_valid =
            fc.slot == self.slot && self.expected_block_hash.is_some_and(|h| fc.block_hash == h);

        let valid = context_valid
            && match block {
                Some(block) => verifier.verify_finality_certificate_for_block(&fc, block),
                None => verifier.verify_finality_certificate(&fc),
            };

        match self.state {
            FinalityState::Soft => {
                if valid {
                    self.state = FinalityState::Hard;
                    FinalityAction::None
                } else {
                    // Do NOT immediately rollback on invalid FC in Soft state.
                    // An unauthenticated peer could send garbage FCs to grief the network.
                    // Instead, record that an invalid FC was seen and defer to builder timeout.
                    self.invalid_fc_seen = true;
                    FinalityAction::None
                }
            }
            FinalityState::BackupWait => {
                if valid {
                    self.state = FinalityState::Hard;
                    FinalityAction::None
                } else {
                    // In BackupWait, invalid FC is ignored per Algorithm 2.
                    // We wait for the K+K' timeout instead.
                    FinalityAction::None
                }
            }
            _ => FinalityAction::None,
        }
    }

    /// Handle a finality certificate with an optional concrete block context.
    pub fn on_finality_certificate(
        &mut self,
        fc: FinalityCertificate,
        block: Option<&Block>,
        verifier: &dyn ProofVerifier,
    ) -> FinalityAction {
        self.on_finality_cert_received(fc, block, verifier)
    }

    /// Handle builder timeout (K slots elapsed).
    ///
    /// Soft → BackupWait + slash builder.
    fn on_builder_timeout(&mut self) -> FinalityAction {
        if self.state != FinalityState::Soft {
            return FinalityAction::None;
        }

        self.state = FinalityState::BackupWait;
        if !self.builder_slashed {
            self.builder_slashed = true;
            FinalityAction::SlashBuilder
        } else {
            FinalityAction::None
        }
    }

    /// Handle backup timeout (K+K' slots elapsed).
    ///
    /// BackupWait → RolledBack + requeue transactions.
    fn on_backup_timeout(&mut self) -> FinalityAction {
        if self.state != FinalityState::BackupWait {
            return FinalityAction::None;
        }

        self.state = FinalityState::RolledBack;
        FinalityAction::RequeueTxs
    }
}
