//! Cross-VM address resolution.
//!
//! Maps a unified ACE id_com (32 bytes) to VM-specific addresses:
//! - EVM:  20-byte address = SHA-256("evm:"  || id_com)[12..32]
//! - TRON: 20-byte address = SHA-256("tron:" || id_com)[12..32]
//! - SVM:  32-byte address = SHA-256("svm:"  || id_com)

use ace_model::account::AccountId;
use ace_model::state_tree::{derive_evm_address, derive_tron_address};
use sha2::{Digest, Sha256};

/// Resolves id_com to VM-specific addresses.
pub struct AddressResolver;

impl AddressResolver {
    /// Derive a 20-byte EVM address from an id_com.
    ///
    /// `SHA-256("evm:" || id_com)[12..32]`
    ///
    /// Delegates to [`ace_model::state_tree::derive_evm_address`] — single
    /// source of truth shared with the incremental index inside StateTree.
    pub fn to_evm_address(id_com: &AccountId) -> [u8; 20] {
        derive_evm_address(id_com)
    }

    /// Derive a 20-byte TRON address from an id_com.
    ///
    /// `SHA-256("tron:" || id_com)[12..32]`
    ///
    /// Delegates to [`ace_model::state_tree::derive_tron_address`].
    pub fn to_tron_address(id_com: &AccountId) -> [u8; 20] {
        derive_tron_address(id_com)
    }

    /// Derive a 32-byte SVM address from an id_com.
    ///
    /// `SHA-256("svm:" || id_com)`
    pub fn to_svm_address(id_com: &AccountId) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"svm:");
        hasher.update(id_com.as_bytes());
        let result = hasher.finalize();

        let mut addr = [0u8; 32];
        addr.copy_from_slice(&result);
        addr
    }

    /// Derive a canonical ACE AccountId from a 20-byte EVM address.
    ///
    /// `SHA-256("ace_from_evm:" || evm_address)`
    ///
    /// This is a deterministic mapping used by the CrossVmCall precompile
    /// so EVM contracts can obtain the ACE-side identity for an EVM address.
    pub fn ace_id_from_evm(evm_address: &[u8; 20]) -> AccountId {
        let mut hasher = Sha256::new();
        hasher.update(b"ace_from_evm:");
        hasher.update(evm_address);
        let result = hasher.finalize();

        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        AccountId(id)
    }
}
