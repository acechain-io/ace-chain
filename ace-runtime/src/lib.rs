//! # ACE Runtime — Reference Implementation
//!
//! A micro-runtime reference implementation of the ACE Runtime core protocol,
//! based on the paper "ACE Runtime — A ZKP-Native Blockchain Runtime with
//! Sub-Second Cryptographic Finality".
//!
//! ## Architecture
//!
//! The implementation follows the paper's Attest–Execute–Prove pipeline:
//!
//! - **Phase 1a** (AttestCheck): Parallel attestation verification
//! - **Phase 1b** (Execute): Parallel transaction execution via Sealevel model
//! - **Phase 2** (Prove): GPU-parallel ZK proof generation with tree aggregation
//!
//! ## Module Structure
//!
//! - [`config`]: Protocol constants (slot duration, quorum, HKDF info strings)
//! - [`types`]: Core data structures (Transaction, Block, Attestation, FinalityCertificate)
//! - [`crypto`]: Cryptographic operations (HKDF helpers, attestation, proof system)
//! - [`pipeline`]: Attest–Execute–Prove pipeline stages
//! - [`consensus`]: Finality state machine and timeout protocol

pub mod config;
pub mod consensus;
pub mod crypto;
pub mod pipeline;
pub mod types;
