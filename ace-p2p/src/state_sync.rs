//! State-sync protocol for fast catch-up.
//!
//! When a node is far behind (> STATE_SYNC_THRESHOLD heights), it can
//! request a state snapshot from peers to jump directly to a recent
//! committed height, bypassing individual block replay.

/// Number of heights a node must be behind before triggering fast-sync mode.
pub const STATE_SYNC_THRESHOLD: u64 = 256;

/// Batch limit used during fast-sync (larger than normal to catch up faster).
pub const FAST_SYNC_BATCH_LIMIT: u16 = 1024;
