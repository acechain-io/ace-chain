//! Resource monitoring and limiting for ACE Chain nodes.
//!
//! Enforces the "People's Blockchain" hardware limits:
//! - CPU: max cores (e.g., 2-4 vCPU)
//! - Memory: max RAM (e.g., 4-8 GB)
//! - Disk: monitored but not capped here
//!
//! Also implements the PoH speed governor — nodes that produce PoH hashes
//! too fast are penalized, preventing hardware arms races.

use serde::{Deserialize, Serialize};
use sysinfo::System;

/// Hardware resource limits for a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum CPU cores allowed.
    pub max_cpu_cores: u32,
    /// Maximum memory in MB.
    pub max_memory_mb: u64,
    /// Maximum PoH hashes per slot (speed governor).
    /// Nodes exceeding this are penalized.
    pub max_poh_hashes_per_slot: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_cpu_cores: 4,
            max_memory_mb: 8192, // 8 GB
            max_poh_hashes_per_slot: 10_000,
        }
    }
}

/// Current hardware metrics snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    /// Number of physical CPU cores.
    pub cpu_cores: u32,
    /// Total system memory in MB.
    pub total_memory_mb: u64,
    /// Used memory in MB.
    pub used_memory_mb: u64,
    /// CPU usage percentage (0-100).
    pub cpu_usage_percent: f32,
    /// Available disk space in MB.
    pub disk_available_mb: u64,
}

/// Monitors hardware resources and enforces limits.
pub struct ResourceMonitor {
    limits: ResourceLimits,
    sys: System,
}

impl ResourceMonitor {
    /// Create a new resource monitor with the given limits.
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            sys: System::new_all(),
        }
    }

    /// Create with default limits.
    pub fn with_defaults() -> Self {
        Self::new(ResourceLimits::default())
    }

    /// Get the current resource limits.
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Collect current hardware metrics.
    pub fn collect_metrics(&mut self) -> ResourceMetrics {
        self.sys.refresh_all();

        let cpu_cores = self.sys.physical_core_count().unwrap_or(0) as u32;
        let total_memory_mb = self.sys.total_memory() / (1024 * 1024);
        let used_memory_mb = self.sys.used_memory() / (1024 * 1024);

        let cpu_usage_percent = {
            let cpus = self.sys.cpus();
            if cpus.is_empty() {
                0.0
            } else {
                cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
            }
        };

        let disk_available_mb = {
            let disks = sysinfo::Disks::new_with_refreshed_list();
            disks
                .iter()
                .map(|d| d.available_space() / (1024 * 1024))
                .sum()
        };

        ResourceMetrics {
            cpu_cores,
            total_memory_mb,
            used_memory_mb,
            cpu_usage_percent,
            disk_available_mb,
        }
    }

    /// Check if the current hardware exceeds the configured limits.
    ///
    /// Returns a list of violations (empty if within limits).
    pub fn check_violations(&mut self) -> Vec<ResourceViolation> {
        let metrics = self.collect_metrics();
        let mut violations = Vec::new();

        if metrics.cpu_cores > self.limits.max_cpu_cores {
            violations.push(ResourceViolation::CpuExceeded {
                actual: metrics.cpu_cores,
                limit: self.limits.max_cpu_cores,
            });
        }

        if metrics.total_memory_mb > self.limits.max_memory_mb {
            violations.push(ResourceViolation::MemoryExceeded {
                actual_mb: metrics.total_memory_mb,
                limit_mb: self.limits.max_memory_mb,
            });
        }

        violations
    }

    /// Check if a PoH speed measurement violates the speed governor.
    pub fn check_poh_speed(&self, hashes_in_slot: u64) -> Option<ResourceViolation> {
        if hashes_in_slot > self.limits.max_poh_hashes_per_slot {
            Some(ResourceViolation::PohTooFast {
                actual_hashes: hashes_in_slot,
                limit: self.limits.max_poh_hashes_per_slot,
            })
        } else {
            None
        }
    }
}

/// A resource limit violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceViolation {
    /// Node has more CPU cores than allowed.
    CpuExceeded { actual: u32, limit: u32 },
    /// Node has more memory than allowed.
    MemoryExceeded { actual_mb: u64, limit_mb: u64 },
    /// Node's PoH chain is too fast (suspected overpowered hardware).
    PohTooFast { actual_hashes: u64, limit: u64 },
}

impl std::fmt::Display for ResourceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceViolation::CpuExceeded { actual, limit } => {
                write!(f, "CPU cores {actual} exceeds limit {limit}")
            }
            ResourceViolation::MemoryExceeded {
                actual_mb,
                limit_mb,
            } => {
                write!(f, "memory {actual_mb}MB exceeds limit {limit_mb}MB")
            }
            ResourceViolation::PohTooFast {
                actual_hashes,
                limit,
            } => {
                write!(
                    f,
                    "PoH speed {actual_hashes} hashes/slot exceeds limit {limit}"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_cpu_cores, 4);
        assert_eq!(limits.max_memory_mb, 8192);
    }

    #[test]
    fn test_poh_speed_within_limit() {
        let monitor = ResourceMonitor::with_defaults();
        assert!(monitor.check_poh_speed(5_000).is_none());
    }

    #[test]
    fn test_poh_speed_exceeds_limit() {
        let monitor = ResourceMonitor::with_defaults();
        let violation = monitor.check_poh_speed(20_000);
        assert!(violation.is_some());
        match violation.unwrap() {
            ResourceViolation::PohTooFast {
                actual_hashes,
                limit,
            } => {
                assert_eq!(actual_hashes, 20_000);
                assert_eq!(limit, 10_000);
            }
            _ => panic!("expected PohTooFast"),
        }
    }

    #[test]
    fn test_collect_metrics() {
        let mut monitor = ResourceMonitor::with_defaults();
        let metrics = monitor.collect_metrics();
        // Just verify it doesn't panic and returns reasonable values
        assert!(metrics.total_memory_mb > 0);
    }

    #[test]
    fn test_resource_violation_display() {
        let v = ResourceViolation::CpuExceeded {
            actual: 8,
            limit: 4,
        };
        assert!(v.to_string().contains("CPU cores 8"));
    }
}
