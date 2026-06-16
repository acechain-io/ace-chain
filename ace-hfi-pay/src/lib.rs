//! HFIPay: Privacy-preserving, cross-chain cryptocurrency payments to
//! human-friendly identifiers (email, phone, social handle).
//!
//! The core mechanism separates **private routing** from **on-chain claim
//! authorization**.  For each payment the relay samples a fresh random
//! `intentId` and derives a one-time deposit address.  For a registered
//! recipient with committed identity `IDcom_B` and private claim-binding
//! handle `u_B`, the relay commits only an intent-specific blinded binding
//!
//! ```text
//!     ρ = H("hfipay:bind" || u_B || intentId)
//! ```
//!
//! so the chain sees neither the human-friendly identifier nor a reusable
//! recipient tag.  To claim, the recipient proves in zero knowledge that the
//! funded intent's blinded binding matches the same deterministic identity
//! that underlies `IDcom_B`.
//!
//! # Protocol phases
//!
//! 1. **Recipient setup** — recipient derives `IDcom_B` and `u_B`, registers with relay
//! 2. **Intent creation** — relay computes `ρ`, commits on-chain before funding
//! 3. **Funding** — sender transfers funds to the deterministic deposit address
//! 4. **Claim** — recipient proves (via ZK-ACE proof or signature) claim authority
//! 5. **Refund** (optional) — after expiry, sender's pre-authorized refund executes

pub mod address;
pub mod auth;
pub mod cross_vm;
pub mod error;
pub mod executor;
pub mod intent;
pub mod onchain;
pub mod persistence;
pub mod registry;
pub mod relay;
pub mod serde_hex_key;
pub mod zk;

pub use error::HfiPayError;
pub use intent::{ChainId, Intent, IntentStatus, VmAddress};
pub use registry::{RecipientRegistry, RegisteredRecipient};

/// Compute the intent-specific blinded recipient binding.
///
/// `ρ = SHA-256("hfipay:bind" || u_B || intentId)`
///
/// This is committed on-chain before funding so an observer who knows the
/// human-friendly identifier cannot determine which on-chain intents belong
/// to that identifier without the private claim-binding handle `u_B`.
pub fn compute_blinded_binding(claim_binding_handle: &[u8; 32], intent_id: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"hfipay:bind");
    hasher.update(claim_binding_handle);
    hasher.update(intent_id);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
