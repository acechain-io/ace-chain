//! Slot tracking based on genesis time and SLOT_DURATION_MS.
//!
//! Each slot is 400ms (from ace-runtime config). The slot clock
//! determines the current slot and time boundaries.

use ace_runtime::config::SLOT_DURATION_MS;
use std::time::{SystemTime, UNIX_EPOCH};

/// Slot clock that maps wall-clock time to slot numbers.
///
/// Used by the consensus engine to determine when to produce blocks
/// and when timeouts expire.
pub struct SlotClock {
    /// Genesis timestamp in milliseconds since Unix epoch.
    genesis_time_ms: u64,
}

impl SlotClock {
    /// Create a new slot clock with the given genesis time.
    pub fn new(genesis_time_ms: u64) -> Self {
        Self { genesis_time_ms }
    }

    /// Get the current slot based on wall-clock time.
    pub fn current_slot(&self) -> u64 {
        let now_ms = Self::now_ms();
        now_ms.saturating_sub(self.genesis_time_ms) / SLOT_DURATION_MS
    }

    /// Returns true once wall-clock time has reached genesis.
    pub fn has_started(&self) -> bool {
        Self::now_ms() >= self.genesis_time_ms
    }

    /// Get the start time (in ms) of the given slot.
    pub fn slot_start_time_ms(&self, slot: u64) -> u64 {
        self.genesis_time_ms + slot * SLOT_DURATION_MS
    }

    /// Milliseconds remaining until genesis starts.
    pub fn time_until_genesis_ms(&self) -> u64 {
        self.genesis_time_ms.saturating_sub(Self::now_ms())
    }

    /// Milliseconds until the next slot boundary.
    pub fn time_until_next_slot_ms(&self) -> u64 {
        let now_ms = Self::now_ms();
        if now_ms < self.genesis_time_ms {
            return self.genesis_time_ms - now_ms;
        }
        let elapsed = now_ms.saturating_sub(self.genesis_time_ms);
        let current_slot_start = (elapsed / SLOT_DURATION_MS) * SLOT_DURATION_MS;
        let next_slot_start = current_slot_start + SLOT_DURATION_MS;
        (self.genesis_time_ms + next_slot_start).saturating_sub(now_ms)
    }

    /// Get the genesis time.
    pub fn genesis_time_ms(&self) -> u64 {
        self.genesis_time_ms
    }

    /// Current time in milliseconds since Unix epoch.
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::SlotClock;
    use ace_runtime::config::SLOT_DURATION_MS;

    #[test]
    fn future_genesis_waits_until_slot_zero() {
        let now_ms = SlotClock::now_ms();
        let clock = SlotClock::new(now_ms + 5_000);

        assert!(!clock.has_started());
        assert_eq!(clock.current_slot(), 0);

        let until_genesis = clock.time_until_genesis_ms();
        assert!(until_genesis > 4_000);
        assert!(until_genesis <= 5_000);

        let until_next_slot = clock.time_until_next_slot_ms();
        assert!(until_next_slot > 4_000);
        assert!(until_next_slot <= 5_000);
    }

    #[test]
    fn started_clock_reports_next_slot_boundary() {
        let now_ms = SlotClock::now_ms();
        let clock = SlotClock::new(now_ms.saturating_sub(1_000));

        assert!(clock.has_started());
        assert_eq!(clock.time_until_genesis_ms(), 0);

        let until_next_slot = clock.time_until_next_slot_ms();
        assert!(until_next_slot <= SLOT_DURATION_MS);
    }
}
