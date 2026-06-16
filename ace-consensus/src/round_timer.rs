//! Round-based timeout management for Tendermint consensus.
//!
//! Replaces the slot-based `SlotClock` for consensus timing.
//! Each round step (Propose, Prevote, Precommit) has its own timeout
//! that increases linearly with round number to ensure liveness.

use std::time::{Duration, Instant};

use crate::metrics::{PercentilesReport, PercentilesTracker};
use crate::tendermint::RoundStep;

/// Timeout configuration for Tendermint rounds.
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Base propose timeout in milliseconds.
    pub propose_ms: u64,
    /// Base prevote timeout in milliseconds.
    pub prevote_ms: u64,
    /// Base precommit timeout in milliseconds.
    pub precommit_ms: u64,
    /// Per-round timeout increase in milliseconds.
    pub delta_ms: u64,
    /// Commit-wait timeout in milliseconds (no round scaling).
    pub commit_wait_ms: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            propose_ms: 3000,
            prevote_ms: 1000,
            precommit_ms: 1000,
            delta_ms: 500,
            commit_wait_ms: 200,
        }
    }
}

/// Devnet timeout configuration.
impl TimeoutConfig {
    pub fn devnet() -> Self {
        Self {
            propose_ms: 2000,
            prevote_ms: 1000,
            precommit_ms: 1000,
            delta_ms: 500,
            commit_wait_ms: 200,
        }
    }
}

/// Manages per-round-step timeouts and collects round-completion latencies.
///
/// The timeout for each step increases with the round number:
/// `timeout(round) = base + round * delta`
///
/// This ensures liveness: even if the network is slow, eventually
/// the timeout will be long enough for messages to propagate.
///
/// Additionally tracks when each height and each round started so that
/// `record_round_commit` can push the round-to-commit duration into a
/// `PercentilesTracker`.  Call `drain_round_durations` at each report
/// interval to get p50/p95/p99 view-change timeline data.
pub struct RoundTimer {
    config: TimeoutConfig,
    /// When the current step started.
    step_started: Instant,
    /// Current step being timed.
    current_step: RoundStep,
    /// Current round (for timeout calculation).
    current_round: u32,
    /// When the current height started (reset on `reset()`).
    height_start: Instant,
    /// When the current round's Propose step started.
    round_start: Instant,
    /// Round-to-commit durations in ms (capped at 2000 samples).
    round_duration_tracker: PercentilesTracker,
}

impl RoundTimer {
    /// Create a new round timer with the given configuration.
    pub fn new(config: TimeoutConfig) -> Self {
        let now = Instant::now();
        Self {
            config,
            step_started: now,
            current_step: RoundStep::Propose,
            current_round: 0,
            height_start: now,
            round_start: now,
            round_duration_tracker: PercentilesTracker::new(2000),
        }
    }

    /// Start timing a new step. Records `round_start` when step is Propose
    /// (i.e. the beginning of each new round).
    pub fn start_step(&mut self, round: u32, step: RoundStep) {
        let now = Instant::now();
        if step == RoundStep::Propose {
            self.round_start = now;
        }
        self.current_round = round;
        self.current_step = step;
        self.step_started = now;
    }

    /// Reset to round 0, Propose step (called on new height).
    pub fn reset(&mut self) {
        let now = Instant::now();
        self.height_start = now;
        self.round_start = now;
        self.step_started = now;
        self.current_round = 0;
        self.current_step = RoundStep::Propose;
    }

    /// Record that the current round committed. Pushes the elapsed time since
    /// `round_start` into the duration tracker.
    pub fn record_round_commit(&mut self) {
        let elapsed_ms = self.round_start.elapsed().as_millis() as u64;
        self.round_duration_tracker.push(elapsed_ms);
    }

    /// Drain round-completion latency samples and return percentile report (ms).
    pub fn drain_round_durations(&mut self) -> PercentilesReport {
        self.round_duration_tracker.drain_report()
    }

    /// Milliseconds elapsed since this height started.
    pub fn height_elapsed_ms(&self) -> u64 {
        self.height_start.elapsed().as_millis() as u64
    }

    /// Milliseconds elapsed since the current round's Propose step started.
    pub fn round_elapsed_ms(&self) -> u64 {
        self.round_start.elapsed().as_millis() as u64
    }

    /// Get the timeout duration for the current step and round.
    pub fn timeout_duration(&self) -> Duration {
        self.timeout_for(self.current_round, self.current_step)
    }

    /// Get the timeout duration for a specific round and step.
    pub fn timeout_for(&self, round: u32, step: RoundStep) -> Duration {
        let base_ms = match step {
            RoundStep::Propose => self.config.propose_ms,
            RoundStep::Prevote => self.config.prevote_ms,
            RoundStep::Precommit => self.config.precommit_ms,
            RoundStep::CommitWait => return Duration::from_millis(self.config.commit_wait_ms),
            RoundStep::Committed => u64::MAX / 2, // No timeout in committed state
        };
        let total_ms = base_ms.saturating_add((round as u64).saturating_mul(self.config.delta_ms));
        Duration::from_millis(total_ms)
    }

    /// Check if the current step has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.step_started.elapsed() >= self.timeout_duration()
    }

    /// Time remaining until the current step times out.
    /// Returns Duration::ZERO if already timed out.
    pub fn time_remaining(&self) -> Duration {
        let timeout = self.timeout_duration();
        let elapsed = self.step_started.elapsed();
        timeout.saturating_sub(elapsed)
    }

    /// The `std::time::Instant` at which the current step will time out.
    ///
    /// Returns `None` if the timeout has already expired.
    pub fn step_deadline(&self) -> Option<Instant> {
        self.step_started.checked_add(self.timeout_duration())
    }

    /// Get the current step being timed.
    pub fn current_step(&self) -> RoundStep {
        self.current_step
    }

    /// Get the current round.
    pub fn current_round(&self) -> u32 {
        self.current_round
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_increases_with_round() {
        let config = TimeoutConfig {
            propose_ms: 1000,
            prevote_ms: 500,
            precommit_ms: 500,
            delta_ms: 200,
            commit_wait_ms: 200,
        };
        let timer = RoundTimer::new(config);

        assert_eq!(
            timer.timeout_for(0, RoundStep::Propose),
            Duration::from_millis(1000)
        );
        assert_eq!(
            timer.timeout_for(1, RoundStep::Propose),
            Duration::from_millis(1200)
        );
        assert_eq!(
            timer.timeout_for(5, RoundStep::Propose),
            Duration::from_millis(2000)
        );
    }

    #[test]
    fn different_step_timeouts() {
        let config = TimeoutConfig::default();
        let timer = RoundTimer::new(config);

        let propose = timer.timeout_for(0, RoundStep::Propose);
        let prevote = timer.timeout_for(0, RoundStep::Prevote);
        let precommit = timer.timeout_for(0, RoundStep::Precommit);

        assert_eq!(propose, Duration::from_millis(3000));
        assert_eq!(prevote, Duration::from_millis(1000));
        assert_eq!(precommit, Duration::from_millis(1000));
    }
}
