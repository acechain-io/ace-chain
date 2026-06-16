//! Proof-of-History: sequential SHA-256 chain.
//!
//! Each PoH tick is `SHA-256(previous_hash)`. This provides a
//! verifiable time ordering without requiring a wall clock.
//! `record(data)` mixes in external data: `SHA-256(previous_hash || data)`.

use sha2::{Digest, Sha256};

/// Proof-of-History chain.
///
/// Maintains a sequential hash chain that provides verifiable
/// ordering of events. Used by the block producer to include
/// a PoH hash in each block header.
#[derive(Clone)]
pub struct PohChain {
    current_hash: [u8; 32],
    tick_count: u64,
}

impl PohChain {
    /// Create a new PoH chain starting from the given initial hash.
    pub fn new(initial_hash: [u8; 32]) -> Self {
        Self {
            current_hash: initial_hash,
            tick_count: 0,
        }
    }

    /// Advance the chain by one tick: `hash = SHA-256(current)`.
    /// Returns the new hash.
    pub fn tick(&mut self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.current_hash);
        let result = hasher.finalize();
        self.current_hash.copy_from_slice(&result);
        self.tick_count = self.tick_count.wrapping_add(1);
        self.current_hash
    }

    /// Record external data into the chain: `hash = SHA-256(current || data)`.
    /// Returns the new hash.
    pub fn record(&mut self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.current_hash);
        hasher.update(data);
        let result = hasher.finalize();
        self.current_hash.copy_from_slice(&result);
        self.tick_count = self.tick_count.wrapping_add(1);
        self.current_hash
    }

    /// Get the current hash.
    pub fn current_hash(&self) -> [u8; 32] {
        self.current_hash
    }

    /// Get the total number of ticks.
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }
}

/// Verify a PoH sequence by replaying ticks from a start hash.
///
/// Returns `true` if replaying `ticks` iterations of SHA-256
/// from `start_hash` produces `expected_end`.
pub fn verify_sequence(start_hash: [u8; 32], ticks: u64, expected_end: [u8; 32]) -> bool {
    let mut hash = start_hash;
    for _ in 0..ticks {
        let mut hasher = Sha256::new();
        hasher.update(hash);
        hash.copy_from_slice(&hasher.finalize());
    }
    hash == expected_end
}
