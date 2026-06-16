//! Generic HKDF-SHA256 helpers and canonical ACE-GF stream label constants.
//!
//! ## Stream labels
//!
//! All HKDF info strings used across ACE-GF implementations are defined in
//! [`labels`].  Defining them here (in ace-runtime, the chain-side crate) makes
//! this the single source of truth for any implementation that verifies or
//! derives credentials on-chain.
//!
//! There are two derivation paths:
//! - **Sealed path** (`ACEGF-V1-*`): IKM is a 16-byte material derived from a
//!   Argon2id-stretched mnemonic/passphrase.
//! - **REV32 path** (`ACEGF-REV32-V1-*`): IKM is the raw 32-byte REV.  This is
//!   the path used in ZK circuits and on the chain hot-path.
//!
//! The HMAC mempool-attestation key is a special REV32-path stream that derives
//! the 32-byte symmetric key stored as an `HmacSha256` account's `auth_pubkey`.

/// Canonical ACE-GF HKDF info strings (stream labels).
///
/// Keep these in sync with `ace-wallet/src/acegf_core.rs` and the ACE-GF paper.
pub mod labels {
    // ── Sealed path (ACEGF-V1-*) ─────────────────────────────────────────────
    // IKM = 16-byte material derived via Argon2id from mnemonic + passphrase.

    pub const SEALED_ED25519_SOLANA: &[u8] = b"ACEGF-V1-ED25519-SOLANA";
    pub const SEALED_ED25519_POLKADOT: &[u8] = b"ACEGF-V1-ED25519-POLKADOT";
    pub const SEALED_SECP256K1_EVM: &[u8] = b"ACEGF-V1-SECP256K1-EVM";
    pub const SEALED_SECP256K1_BTC: &[u8] = b"ACEGF-V1-SECP256K1-BTC";
    pub const SEALED_SECP256K1_COSMOS: &[u8] = b"ACEGF-V1-SECP256K1-COSMOS";
    pub const SEALED_SECP256K1_TRON: &[u8] = b"ACEGF-V1-SECP256K1-TRON";
    pub const SEALED_X25519_IDENTITY: &[u8] = b"ACEGF-V1-X25519-IDENTITY";
    /// Stream 7 — ML-DSA-44 post-quantum signing key (sealed path).
    pub const SEALED_ML_DSA_44: &[u8] = b"ACEGF-V1-ML-DSA-44-PQC-IDENTITY";
    pub const SEALED_ML_KEM_768: &[u8] = b"ACEGF-V1-ML-KEM-768-PQC-IDENTITY";

    // ── REV32 path (ACEGF-REV32-V1-*) ───────────────────────────────────────
    // IKM = raw 32-byte REV.  Used in ZK circuits and the chain hot-path.

    pub const REV32_ED25519_SOLANA: &[u8] = b"ACEGF-REV32-V1-ED25519-SOLANA";
    pub const REV32_ED25519_POLKADOT: &[u8] = b"ACEGF-REV32-V1-ED25519-POLKADOT";
    pub const REV32_SECP256K1_EVM: &[u8] = b"ACEGF-REV32-V1-SECP256K1-EVM";
    pub const REV32_SECP256K1_BTC: &[u8] = b"ACEGF-REV32-V1-SECP256K1-BTC";
    pub const REV32_SECP256K1_COSMOS: &[u8] = b"ACEGF-REV32-V1-SECP256K1-COSMOS";
    pub const REV32_SECP256K1_TRON: &[u8] = b"ACEGF-REV32-V1-SECP256K1-TRON";
    pub const REV32_X25519_IDENTITY: &[u8] = b"ACEGF-REV32-V1-X25519-IDENTITY";
    /// Stream 7 — ML-DSA-44 post-quantum signing key (REV32 path).
    pub const REV32_ML_DSA_44: &[u8] = b"ACEGF-REV32-V1-ML-DSA-44-PQC-IDENTITY";
    pub const REV32_ML_KEM_768: &[u8] = b"ACEGF-REV32-V1-ML-KEM-768-PQC-IDENTITY";

    // ── Chain-specific streams ────────────────────────────────────────────────

    /// Mempool HMAC attestation key (REV32 path).
    /// Derives the 32-byte symmetric key stored as an `HmacSha256` account's
    /// `auth_pubkey`.  Used by the ACE Runtime Phase 1 AttestCheck hot-path.
    pub const REV32_MEMPOOL_ATTEST: &[u8] = b"ACEGF-REV32-V1-ED25519-MEMPOOL-ATTEST";

    /// ACE Chain identity commitment derivation label.
    /// Used by `ace-identity` to derive the on-chain `id_com` from an `AceChainIdentity`.
    /// Standard (non-ZK) accounts use SHA-256-based `idcom_xid` instead; this label
    /// is specifically for the `ace-identity` crate's HKDF-based derivation path.
    pub const ACE_CHAIN_IDCOM: &[u8] = b"ACE-CHAIN-IDCOM-V1";
}

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a 32-byte key from raw IKM, info, and salt.
///
/// Low-level API for custom derivation scenarios.
pub fn derive_key_raw(ikm: &[u8], info: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand should not fail for 32-byte output");
    okm
}

/// Context-aware HKDF expansion with unambiguous length-prefixed separator.
///
/// If `context` is empty: standard `HKDF(None, ikm).expand(base_info)`.
/// If `context` is non-empty: `HKDF(None, ikm).expand(LE32(base_info.len()) || base_info || context)`.
///
/// The 4-byte little-endian length prefix prevents ambiguity between
/// different `(base_info, context)` pairs that could collide under simple
/// concatenation with a single-byte separator (e.g. `("a:b","c")` vs
/// `("a","b:c")`).
///
/// Matches acegf-wallet `hkdf_expand_with_context()`.
pub fn hkdf_expand_with_context(ikm: &[u8], base_info: &[u8], context: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut output = [0u8; 32];

    if context.is_empty() {
        hk.expand(base_info, &mut output)
            .expect("HKDF expand should not fail for 32-byte output");
    } else {
        let mut info = Vec::with_capacity(4 + base_info.len() + context.len());
        info.extend_from_slice(&(base_info.len() as u32).to_le_bytes());
        info.extend_from_slice(base_info);
        info.extend_from_slice(context);
        hk.expand(&info, &mut output)
            .expect("HKDF expand should not fail for 32-byte output");
    }

    output
}

/// Build a vault context string from path segments.
///
/// Sorts segments lexicographically and joins with `:`.
///
/// Example: `["OperatingFund", "corp", "0"]` → `"0:OperatingFund:corp"`
///
/// Matches acegf-wallet `build_vault_context()`.
pub fn build_vault_context(segments: &[&str]) -> String {
    if segments.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<&str> = segments.to_vec();
    sorted.sort();
    sorted.join(":")
}
