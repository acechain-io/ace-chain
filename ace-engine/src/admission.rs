//! Validator admission helpers shared by node, RPC, and governance paths.

use ace_runtime::crypto::sig_algo::{LocalSigningKey, SignatureAlgorithm};
use ace_runtime::crypto::TaggedPubkey;
use sha2::{Digest, Sha256};

use crate::error::EngineError;

/// Derive a deterministic devnet ed25519 signing keypair seed from an id_com.
///
/// seed = SHA-256("ACE-DEVNET-SIGN" || id_com).
pub fn derive_devnet_signing_seed(id_com: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-DEVNET-SIGN");
    hasher.update(id_com);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hasher.finalize());
    seed
}

/// Derive the devnet ML-DSA-44 signing pubkey for a validator candidate.
pub fn devnet_signing_pubkey(id_com: &[u8; 32]) -> Result<TaggedPubkey, EngineError> {
    let seed = derive_devnet_signing_seed(id_com);
    let key = LocalSigningKey::from_seed(&seed, SignatureAlgorithm::MlDsa44)
        .map_err(|e| EngineError::InvalidPayload(format!("ML-DSA-44 keygen failed: {e}")))?;
    Ok(key.public_key())
}
