//! Legacy account idcom for standard-chain signers (EVM/Solana/BTC).
//!
//! When a tx is submitted as raw EIP-155 / Solana / Bitcoin, the signer is
//! recovered from the chain-native signature and mapped to a 32-byte idcom
//! so the rest of the runtime (state, VM) can treat it as an account id.

use sha2::{Digest, Sha256};

/// Legacy idcom for an EVM signer (20-byte address): SHA-256(b"ace-legacy-evm" || addr).
pub fn legacy_idcom_evm(addr: &[u8; 20]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-legacy-evm");
    hasher.update(addr);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Legacy idcom for a Solana signer (32-byte Ed25519 public key): SHA-256(b"ace-legacy-solana" || pubkey).
pub fn legacy_idcom_solana(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-legacy-solana");
    hasher.update(pubkey);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Legacy idcom for a Bitcoin signer (33-byte compressed public key): SHA-256(b"ace-legacy-btc" || compressed_pubkey).
pub fn legacy_idcom_btc(compressed_pubkey: &[u8; 33]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-legacy-btc");
    hasher.update(compressed_pubkey);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Legacy idcom for a TRON signer (20-byte address): SHA-256(b"ace-legacy-tron" || addr).
///
/// Uses a distinct domain separator from EVM so the same secp256k1 key maps to
/// different ACE account IDs depending on whether it signs TRON or Ethereum txs.
pub fn legacy_idcom_tron(addr: &[u8; 20]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-legacy-tron");
    hasher.update(addr);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Native idcom for an ACE-GF XID (32-byte wallet fingerprint).
///
/// XID is computed by the ACE-GF wallet as `SHA3-256(sealed || "acegf:xid")`.
/// This function maps it to an ACE AccountId so the unified state tree can
/// hold assets for the XID owner regardless of which chain-specific key they
/// used to register.  All legacy chain addresses derived from the same
/// mnemonic are effectively aliases of this primary identity.
pub fn idcom_xid(xid: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-native-xid");
    hasher.update(xid);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hash an ML-DSA-44 public key to a 32-byte xaddress fingerprint.
///
/// Used as the on-chain representation of a PQC address.  The full
/// 1312-byte ML-DSA-44 public key is hashed down to 32 bytes so the
/// index stays compact while still being collision-resistant.
pub fn xaddress_hash(ml_dsa_pubkey: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-xaddress-v1");
    hasher.update(ml_dsa_pubkey);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Canonical message for address-binding ownership proofs.
///
/// Each chain-native private key signs this message to prove that the
/// key owner consents to binding the address to `sender_idcom`.
/// The domain separator, idcom, address type, and address bytes are all
/// included so the proof cannot be replayed across accounts or types.
pub fn register_address_message(
    sender_idcom: &[u8; 32],
    address_type: u8,
    address_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-register-address-v1");
    hasher.update(sender_idcom);
    hasher.update([address_type]);
    hasher.update(address_bytes);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Legacy idcom for a Bitcoin output script (maps scriptPubKey to an ACE AccountId).
///
/// Used to derive the recipient's ACE account from a Bitcoin output script.
pub fn legacy_idcom_btc_script(script_pubkey: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-legacy-btc-output");
    hasher.update(script_pubkey);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
