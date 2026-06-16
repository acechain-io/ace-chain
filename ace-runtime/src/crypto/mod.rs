//! Cryptographic operations for ACE Runtime.
//!
//! - [`sig_algo`]: PQC-ready multi-algorithm signature abstraction
//! - [`hkdf_derive`]: Generic HKDF-SHA256 helpers
//! - [`attestation`]: Attestation signing and verification
//! - [`proof`]: ZK proof system trait with mock implementation

pub mod attestation;
pub mod hkdf_derive;
pub mod legacy;
pub mod proof;
pub mod sig_algo;
pub mod zk_auth;

pub use attestation::{
    auth_public_key_from_seed, make_credential, verify_attestation, verify_credential,
    verify_payload_binding,
};
pub use hkdf_derive::{build_vault_context, derive_key_raw, hkdf_expand_with_context};
pub use legacy::{
    idcom_xid, legacy_idcom_btc, legacy_idcom_btc_script, legacy_idcom_evm, legacy_idcom_solana,
    legacy_idcom_tron, register_address_message, xaddress_hash,
};
#[cfg(feature = "test-utils")]
pub use proof::MockProver;
#[cfg(feature = "prover")]
pub use proof::StarkProver;
#[cfg(any(feature = "stark", feature = "test-utils"))]
pub use proof::{derive_public_inputs, PrivateWitness, ProofProducer, ProofReplayMode};
pub use proof::{AlwaysInvalidProver, ProofVerifier};
pub use sig_algo::{SignatureAlgorithm, TaggedPubkey, TaggedSignature};
pub use zk_auth::verify_zk_auth;
