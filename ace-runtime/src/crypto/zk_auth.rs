//! ZK-ACE per-transaction authorization verification.
//!
//! Verifies a [`ZkAuth`] proof carried by a [`Transaction`] using the stwo
//! Circle STARK backend.  The proof proves knowledge of the Root Entropy Value
//! (REV) behind the identity commitment without revealing the REV, and binds
//! the proof to the specific (id_com, tx_hash, domain, target, rp_com) tuple.
//!
//! This replaces raw ML-DSA-44 / Ed25519 credential verification on the hot
//! paths (mempool admission, Phase-2 pre-verification), eliminating the PQC
//! performance penalty.

use crate::types::attestation::Domain;
use crate::types::transaction::{Transaction, ZkAuth};

/// Encode the attestation [`Domain`] into the single `u64` the ZK-ACE circuit binds
/// as `domain` (into both `id_com` and `rp_com`).
///
/// Only `chain_id` is bound; the per-tx `slot` is deliberately excluded so that
/// `id_com = Poseidon2(REV || salt || domain)` — which is the on-chain account
/// identity — stays stable across slots. Replay is enforced separately via `rp_com`
/// (`tx_hash` + `nonce`). The proof producer must use this identical encoding.
pub fn zk_domain_u64(domain: &Domain) -> u64 {
    domain.chain_id as u64
}

/// Verify the ZK-ACE proof carried in `zk_auth` against `tx`.
///
/// Returns `Ok(())` if the proof is valid, `Err(String)` with a human-readable
/// reason otherwise.
///
/// # Feature gate
/// Requires the `stark` feature.  Without it the function always returns an
/// error so that callers that somehow receive a ZK-ACE tx on a non-stark build
/// reject it safely rather than silently accepting it.
pub fn verify_zk_auth(tx: &Transaction, zk_auth: &ZkAuth) -> Result<(), String> {
    #[cfg(not(feature = "stark"))]
    {
        let _ = (tx, zk_auth);
        return Err("ZK-ACE requires the 'stark' feature to be enabled".into());
    }

    #[cfg(feature = "stark")]
    {
        use zk_ace::{PublicInputs, ReplayMode, StwoEngine, ZkAceEngine};

        // See `zk_domain_u64`: only chain_id is bound (slot excluded) so that the
        // account `id_com` stays stable across slots. Replay is enforced via `rp_com`.
        let domain_u64 = zk_domain_u64(&tx.attestation.domain);
        let pi = PublicInputs {
            id_com: tx.attestation.idcom,
            tx_hash: tx.tx_hash(),
            domain: domain_u64,
            target: zk_auth.target,
            rp_com: zk_auth.rp_com,
        };

        match StwoEngine::verify(&zk_auth.proof, &pi, ReplayMode::NonceRegistry) {
            Ok(true) => Ok(()),
            Ok(false) => Err("ZK-ACE proof is invalid".into()),
            Err(e) => Err(format!("ZK-ACE verification error: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zk_domain_is_slot_independent() {
        // id_com = Poseidon2(REV || salt || domain) is the on-chain account identity,
        // so the ZK domain binding must NOT vary with the per-tx slot.
        let chain_id = 7;
        let d0 = Domain::new(chain_id, 0);
        let d1 = Domain::new(chain_id, 12_345);
        let d2 = Domain::new(chain_id, u32::MAX);
        assert_eq!(zk_domain_u64(&d0), zk_domain_u64(&d1));
        assert_eq!(zk_domain_u64(&d0), zk_domain_u64(&d2));
        assert_eq!(zk_domain_u64(&d0), chain_id as u64);
    }

    #[test]
    fn zk_domain_binds_chain_id() {
        // Different chains must produce different identity domains.
        assert_ne!(
            zk_domain_u64(&Domain::new(1, 5)),
            zk_domain_u64(&Domain::new(2, 5))
        );
    }
}
