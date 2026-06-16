//! Write-Ahead Log for Tendermint consensus crash recovery.
//!
//! Persists consensus messages (proposals received, votes cast, locks)
//! so that after a crash the node can reconstruct its pre-crash state
//! and avoid violating safety (e.g., voting for a different block).

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A WAL entry representing a consensus action that must survive crashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalEntry {
    /// We received a valid proposal at this height/round.
    Proposal {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
    },
    /// We cast a prevote.
    Prevote {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
    },
    /// We cast a precommit.
    Precommit {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
    },
    /// We locked on a block.
    Lock {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
    },
    /// Height advanced (safe to truncate older entries).
    HeightAdvance { new_height: u64 },
}

/// Write-ahead log for consensus state.
pub struct ConsensusWal {
    path: PathBuf,
    file: Option<File>,
}

impl ConsensusWal {
    /// Open or create a WAL file at the given path.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            file: Some(file),
        })
    }

    /// Create a no-op WAL (for nodes without data_dir).
    pub fn noop() -> Self {
        Self {
            path: PathBuf::new(),
            file: None,
        }
    }

    /// Append an entry to the WAL.
    pub fn write(&mut self, entry: &WalEntry) -> io::Result<()> {
        let Some(ref mut file) = self.file else {
            return Ok(());
        };
        let line =
            serde_json::to_string(entry).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        writeln!(file, "{}", line)?;
        file.flush()?;
        file.sync_data()?;
        Ok(())
    }

    /// Read all entries from the WAL.
    pub fn read_all(&self) -> io::Result<Vec<WalEntry>> {
        if self.file.is_none() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<WalEntry>(&line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    tracing::warn!(%e, "Skipping corrupt WAL entry");
                }
            }
        }
        Ok(entries)
    }

    /// Truncate the WAL (called after height advance to keep it small).
    pub fn truncate(&mut self) -> io::Result<()> {
        let Some(_) = self.file else {
            return Ok(());
        };
        // Close, truncate, reopen
        self.file = None;
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        self.file = Some(file);
        Ok(())
    }

    /// Recover the latest consensus state from WAL entries.
    pub fn recover(&self) -> WalRecovery {
        let entries = self.read_all().unwrap_or_default();
        let mut recovery = WalRecovery::default();

        for entry in entries {
            match entry {
                WalEntry::HeightAdvance { new_height } => {
                    recovery = WalRecovery {
                        height: new_height,
                        ..Default::default()
                    };
                }
                WalEntry::Lock {
                    height,
                    round,
                    block_hash,
                } => {
                    if height >= recovery.height {
                        recovery.height = height;
                        recovery.locked_round = Some(round);
                        recovery.locked_hash = Some(block_hash);
                    }
                }
                WalEntry::Prevote {
                    height,
                    round,
                    block_hash,
                } => {
                    if height >= recovery.height {
                        recovery.height = height;
                        recovery.prevoted_round = Some(round);
                        recovery.prevoted_hash = Some(block_hash);
                    }
                }
                WalEntry::Precommit {
                    height,
                    round,
                    block_hash,
                } => {
                    if height >= recovery.height {
                        recovery.height = height;
                        recovery.precommitted_round = Some(round);
                        recovery.precommitted_hash = Some(block_hash);
                    }
                }
                WalEntry::Proposal { height, .. } => {
                    if height >= recovery.height {
                        recovery.height = height;
                    }
                }
            }
        }
        recovery
    }
}

/// Recovered consensus state from WAL.
#[derive(Debug, Default)]
pub struct WalRecovery {
    pub height: u64,
    pub locked_round: Option<u32>,
    pub locked_hash: Option<[u8; 32]>,
    pub prevoted_round: Option<u32>,
    pub prevoted_hash: Option<[u8; 32]>,
    pub precommitted_round: Option<u32>,
    pub precommitted_hash: Option<[u8; 32]>,
}
