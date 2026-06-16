//! Consensus: finality state machine and timeout protocol.
//!
//! - [`finality`]: Five-state finality state machine (Algorithm 2)
//! - [`timeout`]: Two-phase timeout protocol (Definition 5)

pub mod finality;
pub mod timeout;

pub use finality::FinalityStateMachine;
pub use timeout::{TimeoutProtocol, WitnessAvailability};
