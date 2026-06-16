//! Attest–Execute–Prove pipeline (Algorithm 1 in the paper).
//!
//! - [`attest`]: Phase 1a — parallel AttestCheck (~1–5 μs/tx on CPU)
//! - [`execute`]: Phase 1b — parallel execution via Sealevel model

pub mod attest;
pub mod execute;
#[cfg(any(feature = "prover", feature = "recursive", feature = "test-utils"))]
pub mod prove;

pub use attest::{
    attest_check, AttestCheckResult, HashSetRegistry, IdentityRegistry, OpenRegistry, RejectReason,
};
pub use execute::{execute_transactions, StateDelta};
#[cfg(any(feature = "prover", feature = "test-utils"))]
pub use prove::prove_block;
