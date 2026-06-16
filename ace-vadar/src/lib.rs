//! VA-DAR: Vendor-Agnostic Deterministic Artifact Resolution.
//!
//! On-chain discovery registry that maps passphrase-derived `DiscoveryID`s
//! to sealed artifact locations, enabling serverless wallet recovery.
//!
//! # Design principles
//!
//! - The chain never sees raw identifiers (email, phone, etc.) — only the
//!   keyed `DiscoveryID`, a 32-byte HMAC output derived from the user's
//!   passphrase and identifier.
//! - First-write atomically binds `owner_pubkey`; subsequent updates require
//!   a valid signature under that key.
//! - Version numbers are strictly monotonic per DiscoveryID.
//! - Sealed artifacts (SA2) can be stored inline on-chain or referenced by
//!   an external content identifier (CID).

pub mod error;
pub mod registry;

pub use error::VadarError;
pub use registry::{DiscoveryRecord, VadarRegistry};
