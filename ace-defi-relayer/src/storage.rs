//! Durable relayer checkpoint storage.
//!
//! Phase A uses a simple local JSON file. This is not a production database,
//! but it makes scan checkpoints and idempotency survive process restarts.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainCheckpoint {
    pub last_scanned_block: u64,
    pub processed_deposits: HashSet<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EgressCheckpoint {
    pub last_checked_slot: u64,
    pub processed_withdrawals: HashSet<u64>,
    #[serde(default)]
    pub external_tx_hashes: HashMap<u64, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayerCheckpoints {
    pub chains: HashMap<String, ChainCheckpoint>,
    pub egress: EgressCheckpoint,
}

pub struct CheckpointStore {
    path: PathBuf,
    checkpoints: RelayerCheckpoints,
}

impl CheckpointStore {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let checkpoints = if Path::new(&path).exists() {
            let bytes = std::fs::read(&path)?;
            serde_json::from_slice(&bytes)?
        } else {
            RelayerCheckpoints::default()
        };
        Ok(Self { path, checkpoints })
    }

    pub fn chain(&self, chain: &str) -> ChainCheckpoint {
        self.checkpoints
            .chains
            .get(chain)
            .cloned()
            .unwrap_or_default()
    }

    pub fn egress(&self) -> EgressCheckpoint {
        self.checkpoints.egress.clone()
    }

    pub fn set_chain(&mut self, chain: &str, checkpoint: ChainCheckpoint) -> Result<()> {
        self.checkpoints
            .chains
            .insert(chain.to_string(), checkpoint);
        self.flush()
    }

    pub fn set_egress(&mut self, checkpoint: EgressCheckpoint) -> Result<()> {
        self.checkpoints.egress = checkpoint;
        self.flush()
    }

    pub fn flush(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let bytes = serde_json::to_vec_pretty(&self.checkpoints)?;
        let temp_path = self.path.with_extension("tmp");
        std::fs::write(&temp_path, bytes)?;
        std::fs::rename(temp_path, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let unique = format!(
            "{}-{}-{}.json",
            name,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        std::env::temp_dir().join(unique)
    }

    #[test]
    fn checkpoint_store_survives_restart() {
        let path = temp_path("ace-defi-checkpoint");
        let mut first = CheckpointStore::load(&path).unwrap();
        let mut checkpoint = ChainCheckpoint {
            last_scanned_block: 123,
            processed_deposits: HashSet::new(),
        };
        checkpoint
            .processed_deposits
            .insert("deposit-1".to_string());
        first.set_chain("ethereum", checkpoint).unwrap();

        let restarted = CheckpointStore::load(&path).unwrap();
        let restored = restarted.chain("ethereum");
        assert_eq!(restored.last_scanned_block, 123);
        assert!(restored.processed_deposits.contains("deposit-1"));

        let _ = std::fs::remove_file(path);
    }
}
