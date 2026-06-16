//! # ace-consensus — Consensus + Block Production for ACE Chain
//!
//! Ties together proposer rotation, Tendermint voting, block production,
//! and Proof-of-History into a height-based consensus engine.
//! Wraps ace-runtime's `FinalityStateMachine` and `TimeoutProtocol`
//! for post-commit soft→hard finality tracking.
//!
//! ## Module Structure
//!
//! - [`validator_set`]: Validator management with stake weights
//! - [`leader_schedule`]: Deterministic proposer election per height/round
//! - [`slot_clock`]: Height progression from genesis time
//! - [`poh`]: Proof-of-History sequential hash chain
//! - [`vote`]: BFT vote types and quorum collection
//! - [`block_producer`]: Block construction using ace-engine + ace-runtime
//! - [`engine`]: Top-level `ConsensusEngine` tying everything together
//! - [`error`]: Consensus error types

pub mod admission;
pub mod block_producer;
pub mod engine;
pub mod error;
pub mod leader_schedule;
pub mod mev_ace;
pub mod metrics;
pub mod poh;
pub mod rewards;
pub mod round_timer;
pub mod slot_clock;
pub mod tendermint;
pub mod validator_set;
pub mod vote;
pub mod wal;

pub use admission::{AdmissionController, AdmissionDecision};
pub use engine::ConsensusEngine;
pub use error::ConsensusError;
pub use leader_schedule::LeaderSchedule;
pub use mev_ace::{AceMevHasher, MevAcePolicy, MevAceValidatorSetSnapshot};
pub use poh::PohChain;
pub use metrics::{PercentilesReport, PercentilesTracker};
pub use round_timer::{RoundTimer, TimeoutConfig};
pub use slot_clock::SlotClock;
pub use tendermint::{RoundStep, TendermintAction, TendermintState};
pub use validator_set::{Validator, ValidatorSet};
pub use vote::{Vote, VoteCollector, VoteType};
