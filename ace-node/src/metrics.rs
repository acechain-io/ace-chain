//! Prometheus metrics for the ACE Chain node.
//!
//! All counters/gauges are registered lazily on first use via the `metrics`
//! facade crate.  The exporter is started once in [`init`] and serves a
//! standard `/metrics` HTTP endpoint that Prometheus can scrape.

use metrics::{counter, gauge, histogram};
use std::net::SocketAddr;

/// Start the Prometheus HTTP exporter on `port`.  Idempotent — calling this
/// more than once is harmless (the second call is a no-op logged as a warning).
pub fn init(port: u16) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new().with_http_listener(addr);
    match builder.install() {
        Ok(()) => tracing::info!(%addr, "Prometheus metrics endpoint started"),
        Err(e) => tracing::warn!(%e, "Failed to start Prometheus exporter (already running?)"),
    }
}

// ── Block commit metrics ─────────────────────────────────────────────

/// Increment after a block is finalized by consensus.
pub fn record_block_committed(tx_total: u32, tx_success: u32, height: u64) {
    counter!("ace_blocks_committed_total").increment(1);
    counter!("ace_txs_committed_total").increment(tx_total as u64);
    counter!("ace_txs_success_total").increment(tx_success as u64);
    counter!("ace_txs_failed_total").increment((tx_total - tx_success) as u64);
    gauge!("ace_latest_slot").set(height as f64);
    histogram!("ace_block_tx_count").record(tx_total as f64);
}

/// Increment per-algorithm success counter for TPS chart algo split.
/// `algo` should be a stable lowercase string, e.g. "ed25519" or "ml-dsa-44".
pub fn record_txs_success_by_algo(algo: &'static str, count: u32) {
    if count > 0 {
        counter!("ace_txs_success_by_algo_total", "algo" => algo).increment(count as u64);
    }
}

// ── Proposal build metrics ───────────────────────────────────────────

/// Record proposal build timing after a block is proposed.
pub fn record_proposal_build(build_ms: u64, budget: usize, tx_count: usize) {
    histogram!("ace_proposal_build_ms").record(build_ms as f64);
    gauge!("ace_proposal_budget").set(budget as f64);
    histogram!("ace_proposal_tx_count").record(tx_count as f64);
}

// ── Mempool metrics ──────────────────────────────────────────────────

/// A transaction was accepted into the mempool.
pub fn record_mempool_accepted() {
    counter!("ace_mempool_accepted_total").increment(1);
}

/// A transaction was rejected by the mempool.
pub fn record_mempool_rejected(reason: &str) {
    counter!("ace_mempool_rejected_total", "reason" => reason.to_string()).increment(1);
}

/// Update the current mempool size gauge.
pub fn set_mempool_size(pending: usize, ready: usize) {
    gauge!("ace_mempool_pending").set(pending as f64);
    gauge!("ace_mempool_ready").set(ready as f64);
}

// ── Consensus round metrics ──────────────────────────────────────────

/// Record the consensus round that produced the committed block.
pub fn record_consensus_round(round: u32) {
    histogram!("ace_consensus_round").record(round as f64);
}
