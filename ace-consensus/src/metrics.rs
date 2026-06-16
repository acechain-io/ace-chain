//! Lightweight percentile tracker for consensus observability.
//!
//! Used to measure p50/p95/p99 latency for ML-DSA-44 verification,
//! round completion times, and view-change timelines.

/// Accumulates u64 samples (caller chooses units: µs, ms, …).
/// Call `drain_report` at each report interval to get percentiles and clear.
pub struct PercentilesTracker {
    samples: Vec<u64>,
    cap: usize,
}

/// Output of `drain_report`. Units match whatever the caller pushed.
#[derive(Debug, Clone, Copy, Default)]
pub struct PercentilesReport {
    pub count: usize,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub max: u64,
}

impl PercentilesTracker {
    pub fn new(cap: usize) -> Self {
        Self {
            samples: Vec::with_capacity(cap.min(4096)),
            cap,
        }
    }

    /// Add one sample. Silently drops when at capacity (back-pressure).
    #[inline]
    pub fn push(&mut self, value: u64) {
        if self.samples.len() < self.cap {
            self.samples.push(value);
        }
    }

    /// Sort, compute percentiles, clear the buffer. Returns zero report if empty.
    pub fn drain_report(&mut self) -> PercentilesReport {
        if self.samples.is_empty() {
            return PercentilesReport::default();
        }
        self.samples.sort_unstable();
        let n = self.samples.len();
        let pct = |p: f64| -> u64 {
            // nearest-rank: index = ceil(p/100 * n) - 1, clamped to [0, n-1]
            let idx = ((p / 100.0 * n as f64).ceil() as usize).saturating_sub(1).min(n - 1);
            self.samples[idx]
        };
        let report = PercentilesReport {
            count: n,
            p50: pct(50.0),
            p95: pct(95.0),
            p99: pct(99.0),
            max: *self.samples.last().unwrap(),
        };
        self.samples.clear();
        report
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_gives_zero_report() {
        let mut t = PercentilesTracker::new(100);
        let r = t.drain_report();
        assert_eq!(r.count, 0);
        assert_eq!(r.p99, 0);
    }

    #[test]
    fn percentiles_correct() {
        let mut t = PercentilesTracker::new(1000);
        for i in 1u64..=100 {
            t.push(i);
        }
        let r = t.drain_report();
        assert_eq!(r.count, 100);
        assert_eq!(r.p50, 50);
        assert_eq!(r.p95, 95);
        assert_eq!(r.p99, 99);
        assert_eq!(r.max, 100);
        // drained
        assert!(t.is_empty());
    }

    #[test]
    fn cap_respected() {
        let mut t = PercentilesTracker::new(10);
        for i in 0..100 {
            t.push(i);
        }
        assert_eq!(t.len(), 10);
    }
}
