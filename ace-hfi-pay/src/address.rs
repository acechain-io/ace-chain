//! Deterministic address derivation from intent IDs.
//!
//! Each VM gets a distinct domain separator so that the same `intentId`
//! produces a different deposit address on each chain.  This mirrors the
//! paper's `DeriveAddress(c, intentId)` function.

use ace_model::account::AccountId;
use sha2::{Digest, Sha256};

use crate::intent::ChainId;

/// Derive the deposit `AccountId` for an intent on the given chain.
pub fn derive_intent_address(chain: ChainId, intent_id: &[u8; 32]) -> AccountId {
    let hash = hash_with_domain(domain_for_chain(chain), intent_id);
    AccountId::from_bytes(hash)
}

/// Derive the 20-byte EVM address for an intent.
///
/// Analogous to CREATE2(factory, intentId, keccak(initcode)) in the paper.
pub fn derive_intent_evm_address(intent_id: &[u8; 32]) -> [u8; 20] {
    let hash = hash_with_domain(b"hfipay:evm:", intent_id);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

/// Derive the 20-byte Tron address for an intent.
pub fn derive_intent_tvm_address(intent_id: &[u8; 32]) -> [u8; 20] {
    let hash = hash_with_domain(b"hfipay:tvm:", intent_id);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

fn domain_for_chain(chain: ChainId) -> &'static [u8] {
    match chain {
        ChainId::Native => b"hfipay:native:",
        ChainId::Evm => b"hfipay:evm:",
        ChainId::Svm => b"hfipay:svm:",
        ChainId::Bvm => b"hfipay:bvm:",
        ChainId::Tvm => b"hfipay:tvm:",
    }
}

fn hash_with_domain(domain: &[u8], intent_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(intent_id);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let id = [42u8; 32];
        let a1 = derive_intent_address(ChainId::Native, &id);
        let a2 = derive_intent_address(ChainId::Native, &id);
        assert_eq!(a1, a2);
    }

    #[test]
    fn different_chains_produce_different_addresses() {
        let id = [7u8; 32];
        let chains = [
            ChainId::Native,
            ChainId::Evm,
            ChainId::Svm,
            ChainId::Bvm,
            ChainId::Tvm,
        ];
        let addrs: Vec<_> = chains
            .iter()
            .map(|c| derive_intent_address(*c, &id))
            .collect();
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(
                    addrs[i], addrs[j],
                    "chains {:?} and {:?} collide",
                    chains[i], chains[j]
                );
            }
        }
    }

    #[test]
    fn different_intents_produce_different_addresses() {
        let a = derive_intent_address(ChainId::Evm, &[1u8; 32]);
        let b = derive_intent_address(ChainId::Evm, &[2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn evm_address_is_20_bytes_from_tail() {
        let id = [0xAA; 32];
        let evm = derive_intent_evm_address(&id);
        let full = derive_intent_address(ChainId::Evm, &id);
        // The EVM 20-byte address should match bytes [12..32] of the full hash
        assert_eq!(&evm[..], &full.0[12..32]);
    }
}
