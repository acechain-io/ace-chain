//! Phase 1a: Parallel AttestCheck (Algorithm 1, lines 3–9 in the paper).
//!
//! For each transaction in parallel:
//! 1. Verify payload binding: SHA-256(payload) == attestation.obj_hash
//! 2. Verify domain binding: attestation.domain matches current slot
//! 3. Verify identity existence: attestation.idcom ∈ RegisteredIdentities
//!
//! Invalid transactions are rejected before execution.
//! Runs on CPU at ~1–5 μs per transaction using rayon parallel iterators.

use std::collections::HashMap;

use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::crypto::sig_algo::TaggedPubkey;
use crate::types::attestation::Domain;
use crate::types::transaction::Transaction;

// ---------------------------------------------------------------------------
// Identity registry trait (paper: RegisteredIdentities)
// ---------------------------------------------------------------------------

/// Registry of known identity commitments.
///
/// Corresponds to the paper's `RegisteredIdentities` set referenced in the
/// `VerifyAttestation` algorithm: `A.idcom ∉ RegisteredIdentities → Reject`.
///
/// Implementations must be `Sync` to support parallel attestation checking.
pub trait IdentityRegistry: Sync {
    /// Returns `true` if the given identity commitment is registered on-chain.
    fn is_registered(&self, idcom: &[u8; 32]) -> bool;

    /// Returns the authentication public key for a registered identity, if available.
    ///
    /// Used for credential signature verification in Phase 1a.
    /// Returns `None` if the identity is not registered or has no auth key on file.
    fn get_auth_pubkey(&self, idcom: &[u8; 32]) -> Option<TaggedPubkey>;
}

/// A `HashMap`-backed identity registry mapping idcom to auth pubkey.
///
/// Suitable for testing and lightweight validators. Production deployments
/// would use a database-backed implementation.
#[derive(Debug, Clone, Default)]
pub struct HashSetRegistry {
    identities: HashMap<[u8; 32], TaggedPubkey>,
}

impl HashSetRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new identity commitment with its authentication public key.
    pub fn register_with_pubkey(&mut self, idcom: [u8; 32], pubkey: TaggedPubkey) {
        self.identities.insert(idcom, pubkey);
    }

    /// Register a new identity commitment (uses zero pubkey, skipping signature verification).
    pub fn register(&mut self, idcom: [u8; 32]) {
        self.identities
            .insert(idcom, TaggedPubkey::ed25519([0u8; 32]));
    }

    /// Number of registered identities.
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

impl IdentityRegistry for HashSetRegistry {
    fn is_registered(&self, idcom: &[u8; 32]) -> bool {
        self.identities.contains_key(idcom)
    }

    fn get_auth_pubkey(&self, idcom: &[u8; 32]) -> Option<TaggedPubkey> {
        self.identities.get(idcom).cloned()
    }
}

/// An open registry that accepts all identity commitments.
///
/// Useful in test scenarios where identity registration is not the focus.
/// **Not for production use** — bypasses the identity existence check entirely.
pub struct OpenRegistry;

impl IdentityRegistry for OpenRegistry {
    fn is_registered(&self, _idcom: &[u8; 32]) -> bool {
        true
    }

    fn get_auth_pubkey(&self, _idcom: &[u8; 32]) -> Option<TaggedPubkey> {
        // OpenRegistry skips credential verification. Return a zero pubkey so
        // the attest_check fast-path (`is_zero()` branch) skips signature
        // verification without rejecting the tx as UnknownAuthKey.
        Some(TaggedPubkey::default())
    }
}

// ---------------------------------------------------------------------------
// AttestCheck
// ---------------------------------------------------------------------------

/// Result of the attestation check phase.
#[derive(Debug, Clone)]
pub struct AttestCheckResult {
    /// Transactions that passed all checks.
    pub valid: Vec<Transaction>,
    /// Transactions that failed checks, with rejection reasons.
    pub rejected: Vec<(Transaction, RejectReason)>,
}

/// Reason a transaction was rejected during attestation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// SHA-256(payload) doesn't match attestation.obj_hash.
    PayloadBindingMismatch,
    /// Attestation domain doesn't match the expected domain.
    DomainMismatch,
    /// Empty payload is not allowed.
    EmptyPayload,
    /// Identity commitment is not in the RegisteredIdentities set
    /// (paper Algorithm, VerifyAttestation step 2).
    UnregisteredIdentity,
    /// Attestation credential signature is invalid (fails verify_credential).
    InvalidCredential,
    /// Identity is registered but has no authentication public key on file.
    UnknownAuthKey,
    /// Transaction carries a ZK-ACE proof but ZK verification is not yet implemented.
    ZkAuthNotSupported,
}

/// Perform parallel attestation checks on a batch of transactions.
///
/// This is Phase 1a of the Attest–Execute–Prove pipeline.
/// Uses rayon for CPU-parallel processing.
///
/// Checks performed (per the paper's `VerifyAttestation`):
/// 1. Non-empty payload
/// 2. Payload binding: `SHA-256(payload) == obj_hash`
/// 3. Domain binding: `attestation.domain == expected_domain`
/// 4. Identity existence: `idcom ∈ RegisteredIdentities`
/// 5. Credential signature: `verify_credential(attestation, payload, auth_pubkey)`
///    (skipped for raw-chain transactions and identities with no auth pubkey on file)
///
/// # Arguments
/// - `txs`: Batch of transactions to check.
/// - `expected_domain`: The domain (chain_id, slot) for the current slot.
/// - `registry`: Identity registry for checking `idcom` membership.
///
/// # Returns
/// An [`AttestCheckResult`] with valid and rejected transactions.
pub fn attest_check(
    txs: Vec<Transaction>,
    expected_domain: &Domain,
    registry: &dyn IdentityRegistry,
) -> AttestCheckResult {
    let results: Vec<Result<Transaction, (Transaction, RejectReason)>> = txs
        .into_par_iter()
        .map(|tx| {
            // Check 1: non-empty payload
            if tx.payload.is_empty() {
                return Err((tx, RejectReason::EmptyPayload));
            }

            // Check 2: payload binding — SHA-256(payload) == obj_hash
            let hash = sha256(&tx.payload);
            if hash != tx.attestation.obj_hash {
                return Err((tx, RejectReason::PayloadBindingMismatch));
            }

            // Check 3: domain binding
            if tx.attestation.domain != *expected_domain {
                return Err((tx, RejectReason::DomainMismatch));
            }

            // Check 4: identity existence (paper: A.idcom ∉ RegisteredIdentities → Reject)
            if !registry.is_registered(&tx.attestation.idcom) {
                return Err((tx, RejectReason::UnregisteredIdentity));
            }

            // Check 5: credential signature verification
            // Skip only for raw-chain transactions (they use chain-native signatures).
            if tx.raw_chain.is_none() {
                // ZK-auth transactions carry a zk_auth proof instead of a raw credential.
                // Full ZK verification is not yet implemented — reject to avoid fail-open.
                if tx.zk_auth.is_some() {
                    return Err((tx, RejectReason::ZkAuthNotSupported));
                }
                match registry.get_auth_pubkey(&tx.attestation.idcom) {
                    None => {
                        // No auth key on file — reject to avoid silent admission (fail-open).
                        return Err((tx, RejectReason::UnknownAuthKey));
                    }
                    Some(auth_pubkey) => {
                        if !auth_pubkey.is_zero()
                            && !crate::crypto::attestation::verify_credential(
                                &tx.attestation,
                                &tx.payload,
                                &auth_pubkey,
                            )
                        {
                            return Err((tx, RejectReason::InvalidCredential));
                        }
                    }
                }
            }

            Ok(tx)
        })
        .collect();

    let mut valid = Vec::new();
    let mut rejected = Vec::new();

    for result in results {
        match result {
            Ok(tx) => valid.push(tx),
            Err(pair) => rejected.push(pair),
        }
    }

    AttestCheckResult { valid, rejected }
}

/// Sequential attestation check (for testing / single-threaded contexts).
pub fn attest_check_sequential(
    txs: Vec<Transaction>,
    expected_domain: &Domain,
    registry: &dyn IdentityRegistry,
) -> AttestCheckResult {
    let mut valid = Vec::new();
    let mut rejected = Vec::new();

    for tx in txs {
        if tx.payload.is_empty() {
            rejected.push((tx, RejectReason::EmptyPayload));
            continue;
        }

        let hash = sha256(&tx.payload);
        if hash != tx.attestation.obj_hash {
            rejected.push((tx, RejectReason::PayloadBindingMismatch));
            continue;
        }

        if tx.attestation.domain != *expected_domain {
            rejected.push((tx, RejectReason::DomainMismatch));
            continue;
        }

        if !registry.is_registered(&tx.attestation.idcom) {
            rejected.push((tx, RejectReason::UnregisteredIdentity));
            continue;
        }

        // Check 5: credential signature verification (skip for raw-chain txs)
        if tx.raw_chain.is_none() {
            if tx.zk_auth.is_some() {
                rejected.push((tx, RejectReason::ZkAuthNotSupported));
                continue;
            }
            match registry.get_auth_pubkey(&tx.attestation.idcom) {
                None => {
                    rejected.push((tx, RejectReason::UnknownAuthKey));
                    continue;
                }
                Some(auth_pubkey) => {
                    if !auth_pubkey.is_zero()
                        && !crate::crypto::attestation::verify_credential(
                            &tx.attestation,
                            &tx.payload,
                            &auth_pubkey,
                        )
                    {
                        rejected.push((tx, RejectReason::InvalidCredential));
                        continue;
                    }
                }
            }
        }

        valid.push(tx);
    }

    AttestCheckResult { valid, rejected }
}

/// Compute SHA-256 of data.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
