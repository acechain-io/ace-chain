//! Signature algorithm abstraction for PQC-ready multi-algorithm support.
//!
//! Provides [`SignatureAlgorithm`], [`TaggedPubkey`], and [`TaggedSignature`]
//! types that tag cryptographic material with an algorithm identifier.
//! All signature verification in the runtime should flow through
//! [`verify_signature`] which dispatches to the correct backend.
//!
//! Currently active: Ed25519 (algorithm 0), Secp256k1 (1), ML-DSA-44 (2).
//! ML-DSA-44 verification and signing use the `fips204` pure-Rust crate
//! (no PQClean C dependency), available on all platforms including WASM.

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use k256::ecdsa::{
    signature::Verifier as _, Signature as K256Signature, VerifyingKey as K256VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ──────────────────────────────────────────────────────────────
// SignatureAlgorithm
// ──────────────────────────────────────────────────────────────

/// Signature algorithm identifier.
///
/// Encoded as a single byte on the wire, matching `zk-ace`'s
/// `DerivationContext.alg_id` convention:
///   0 = Ed25519, 1 = Secp256k1, 2 = ML-DSA-44, 3 = HMAC-SHA256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    Ed25519 = 0,
    Secp256k1 = 1,
    MlDsa44 = 2,
    HmacSha256 = 3,
}

impl SignatureAlgorithm {
    /// Decode from a wire byte.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Ed25519),
            1 => Some(Self::Secp256k1),
            2 => Some(Self::MlDsa44),
            3 => Some(Self::HmacSha256),
            _ => None,
        }
    }

    /// Encode as a wire byte.
    pub fn tag(self) -> u8 {
        self as u8
    }

    /// Expected public key byte length for this algorithm.
    pub fn pubkey_len(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::Secp256k1 => 33, // compressed
            Self::MlDsa44 => 1312,
            Self::HmacSha256 => 32, // symmetric key
        }
    }

    /// Expected signature byte length for this algorithm.
    pub fn signature_len(self) -> usize {
        match self {
            Self::Ed25519 => 64,
            Self::Secp256k1 => 64, // compact (r, s)
            Self::MlDsa44 => 2420,
            Self::HmacSha256 => 32, // HMAC-SHA256 tag
        }
    }
}

// ──────────────────────────────────────────────────────────────
// TaggedPubkey
// ──────────────────────────────────────────────────────────────

/// An algorithm-tagged public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct TaggedPubkey {
    pub algorithm: SignatureAlgorithm,
    pub bytes: Vec<u8>,
}

impl<'de> serde::Deserialize<'de> for TaggedPubkey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            algorithm: SignatureAlgorithm,
            bytes: Vec<u8>,
        }
        let raw = Raw::deserialize(deserializer)?;
        if raw.bytes.len() != raw.algorithm.pubkey_len() {
            return Err(serde::de::Error::custom(format!(
                "pubkey length {} does not match algorithm {:?} (expected {})",
                raw.bytes.len(),
                raw.algorithm,
                raw.algorithm.pubkey_len()
            )));
        }
        Ok(TaggedPubkey {
            algorithm: raw.algorithm,
            bytes: raw.bytes,
        })
    }
}

impl TaggedPubkey {
    /// Construct an Ed25519 tagged public key.
    pub fn ed25519(bytes: [u8; 32]) -> Self {
        Self {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: bytes.to_vec(),
        }
    }

    /// Construct a Secp256k1 tagged public key from 33-byte compressed key.
    pub fn secp256k1(bytes: [u8; 33]) -> Self {
        Self {
            algorithm: SignatureAlgorithm::Secp256k1,
            bytes: bytes.to_vec(),
        }
    }

    /// Construct an HMAC-SHA256 tagged public key (32-byte symmetric key).
    pub fn hmac_sha256(key: [u8; 32]) -> Self {
        Self {
            algorithm: SignatureAlgorithm::HmacSha256,
            bytes: key.to_vec(),
        }
    }

    /// Construct an ML-DSA-44 tagged public key.
    /// Panics if `bytes.len() != 1312` (required by FIPS 204).
    /// For untrusted input, use `from_wire_bytes` or serde deserialization which validate length.
    pub fn ml_dsa_44(bytes: Vec<u8>) -> Self {
        assert_eq!(
            bytes.len(),
            SignatureAlgorithm::MlDsa44.pubkey_len(),
            "ML-DSA-44 public key must be 1312 bytes"
        );
        Self {
            algorithm: SignatureAlgorithm::MlDsa44,
            bytes,
        }
    }

    /// True if the byte length matches the algorithm's expected key size.
    pub fn is_well_formed(&self) -> bool {
        self.bytes.len() == self.algorithm.pubkey_len()
    }

    /// True if all bytes are zero (sentinel / unset key).
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    /// Try to extract as a fixed Ed25519 `[u8; 32]`.
    pub fn as_ed25519_bytes(&self) -> Option<&[u8; 32]> {
        if self.algorithm == SignatureAlgorithm::Ed25519 && self.bytes.len() == 32 {
            Some(self.bytes[..32].try_into().unwrap())
        } else {
            None
        }
    }

    /// Try to extract as a compressed Secp256k1 `[u8; 33]`.
    pub fn as_secp256k1_bytes(&self) -> Option<&[u8; 33]> {
        if self.algorithm == SignatureAlgorithm::Secp256k1 && self.bytes.len() == 33 {
            Some(self.bytes[..33].try_into().unwrap())
        } else {
            None
        }
    }

    /// Compute a canonical 32-byte fingerprint: `SHA-256(alg_tag || raw_bytes)`.
    ///
    /// Used for Merkle hashing so the state tree always hashes a fixed-size
    /// value regardless of the underlying key algorithm.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.algorithm.tag()]);
        hasher.update(&self.bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    /// Serialize to wire bytes: `alg_tag(1) || key_len(2 LE) || key_bytes`.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        assert!(
            self.bytes.len() <= u16::MAX as usize,
            "crypto material too large for wire format"
        );
        let len = self.bytes.len() as u16;
        let mut buf = Vec::with_capacity(3 + self.bytes.len());
        buf.push(self.algorithm.tag());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&self.bytes);
        buf
    }

    /// Deserialize from wire bytes.
    pub fn from_wire_bytes(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.len() < 3 {
            return Err("tagged pubkey too short");
        }
        let algorithm =
            SignatureAlgorithm::from_tag(data[0]).ok_or("unknown signature algorithm tag")?;
        let key_len = u16::from_le_bytes([data[1], data[2]]) as usize;
        if key_len != algorithm.pubkey_len() {
            return Err("key length does not match algorithm");
        }
        let total = 3 + key_len;
        if data.len() < total {
            return Err("tagged pubkey bytes truncated");
        }
        Ok((
            Self {
                algorithm,
                bytes: data[3..total].to_vec(),
            },
            total,
        ))
    }
}

impl Default for TaggedPubkey {
    fn default() -> Self {
        Self::ed25519([0u8; 32])
    }
}

impl Ord for TaggedPubkey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.algorithm as u8, &self.bytes).cmp(&(other.algorithm as u8, &other.bytes))
    }
}

impl PartialOrd for TaggedPubkey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ──────────────────────────────────────────────────────────────
// TaggedSignature
// ──────────────────────────────────────────────────────────────

/// An algorithm-tagged signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaggedSignature {
    pub algorithm: SignatureAlgorithm,
    pub bytes: Vec<u8>,
}

impl<'de> serde::Deserialize<'de> for TaggedSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            algorithm: SignatureAlgorithm,
            bytes: Vec<u8>,
        }
        let raw = Raw::deserialize(deserializer)?;
        // Length rule: must match algorithm.signature_len() exactly, with one
        // exception — a zero-length ML-DSA-44 payload is accepted as the
        // stripped placeholder used by the AR-ACE relay path.  The placeholder
        // is deliberately NOT well-formed (`is_well_formed` returns false) so
        // `verify_signature` refuses it; it exists only for gossip-relay
        // bandwidth savings and mempool dedup.
        let is_ml_dsa_44_stripped =
            raw.algorithm == SignatureAlgorithm::MlDsa44 && raw.bytes.is_empty();
        if !is_ml_dsa_44_stripped && raw.bytes.len() != raw.algorithm.signature_len() {
            return Err(serde::de::Error::custom(format!(
                "signature length {} does not match algorithm {:?} (expected {})",
                raw.bytes.len(),
                raw.algorithm,
                raw.algorithm.signature_len()
            )));
        }
        Ok(TaggedSignature {
            algorithm: raw.algorithm,
            bytes: raw.bytes,
        })
    }
}

impl TaggedSignature {
    /// Construct an Ed25519 tagged signature.
    pub fn ed25519(bytes: [u8; 64]) -> Self {
        Self {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: bytes.to_vec(),
        }
    }

    /// Construct a Secp256k1 tagged signature from 64-byte compact (r, s).
    pub fn secp256k1(bytes: [u8; 64]) -> Self {
        Self {
            algorithm: SignatureAlgorithm::Secp256k1,
            bytes: bytes.to_vec(),
        }
    }

    /// Construct an HMAC-SHA256 tagged signature (32-byte MAC).
    pub fn hmac_sha256(mac: [u8; 32]) -> Self {
        Self {
            algorithm: SignatureAlgorithm::HmacSha256,
            bytes: mac.to_vec(),
        }
    }

    /// Construct an ML-DSA-44 tagged signature (2420 bytes).
    /// Panics on wrong length. For untrusted input, use `from_wire_bytes` or serde.
    pub fn ml_dsa_44(bytes: Vec<u8>) -> Self {
        assert_eq!(
            bytes.len(),
            SignatureAlgorithm::MlDsa44.signature_len(),
            "ML-DSA-44 signature must be 2420 bytes"
        );
        Self {
            algorithm: SignatureAlgorithm::MlDsa44,
            bytes,
        }
    }

    /// Construct a stripped ML-DSA-44 placeholder (empty credential, algorithm tag preserved).
    ///
    /// Used by the AR-ACE relay path (`Transaction::stripped_for_gossip`) to remove
    /// the 2,420-byte PQC signature from gossiped transactions while keeping the
    /// algorithm discriminant intact.  The placeholder:
    ///   - serializes to 3 wire bytes: `alg_tag(1) || len=0(2 LE)`;
    ///   - round-trips through `from_wire_bytes` and serde (both special-case
    ///     zero-length ML-DSA-44);
    ///   - reports `is_well_formed() == false`, so `verify_signature` refuses it
    ///     as a defence-in-depth guard against accidental execution.
    ///
    /// Callers detect the placeholder via `Transaction::is_credential_stripped()`.
    pub fn ml_dsa_44_stripped() -> Self {
        Self {
            algorithm: SignatureAlgorithm::MlDsa44,
            bytes: Vec::new(),
        }
    }

    /// True if the byte length matches the algorithm's expected signature size.
    ///
    /// A stripped ML-DSA-44 placeholder (`ml_dsa_44_stripped`) is deliberately
    /// NOT well-formed — verification must refuse it.
    pub fn is_well_formed(&self) -> bool {
        self.bytes.len() == self.algorithm.signature_len()
    }

    /// Serialize to wire bytes: `alg_tag(1) || sig_len(2 LE) || sig_bytes`.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        assert!(
            self.bytes.len() <= u16::MAX as usize,
            "crypto material too large for wire format"
        );
        let len = self.bytes.len() as u16;
        let mut buf = Vec::with_capacity(3 + self.bytes.len());
        buf.push(self.algorithm.tag());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&self.bytes);
        buf
    }

    /// Deserialize from wire bytes. Returns the parsed signature and bytes consumed.
    ///
    /// Length rule: `sig_len` must match `algorithm.signature_len()` exactly, with
    /// one exception — a zero-length ML-DSA-44 payload is accepted as the stripped
    /// placeholder used by the AR-ACE relay path (see `ml_dsa_44_stripped`).
    pub fn from_wire_bytes(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.len() < 3 {
            return Err("tagged signature too short");
        }
        let algorithm =
            SignatureAlgorithm::from_tag(data[0]).ok_or("unknown signature algorithm tag")?;
        let sig_len = u16::from_le_bytes([data[1], data[2]]) as usize;
        let is_ml_dsa_44_stripped = algorithm == SignatureAlgorithm::MlDsa44 && sig_len == 0;
        if !is_ml_dsa_44_stripped && sig_len != algorithm.signature_len() {
            return Err("signature length does not match algorithm");
        }
        let total = 3 + sig_len;
        if data.len() < total {
            return Err("tagged signature bytes truncated");
        }
        Ok((
            Self {
                algorithm,
                bytes: data[3..total].to_vec(),
            },
            total,
        ))
    }
}

impl Default for TaggedSignature {
    fn default() -> Self {
        Self::ed25519([0u8; 64])
    }
}

// ──────────────────────────────────────────────────────────────
// Verification dispatch
// ──────────────────────────────────────────────────────────────

/// Unified signature verification.
///
/// Dispatches to the correct backend based on the algorithm tag.
/// Returns `false` if the algorithm is not yet implemented (e.g. ML-DSA-44
/// before the `pqc` feature is enabled).
pub fn verify_signature(pubkey: &TaggedPubkey, message: &[u8], sig: &TaggedSignature) -> bool {
    if pubkey.algorithm != sig.algorithm {
        return false;
    }
    if !pubkey.is_well_formed() || !sig.is_well_formed() {
        return false;
    }
    match pubkey.algorithm {
        SignatureAlgorithm::Ed25519 => verify_ed25519(&pubkey.bytes, message, &sig.bytes),
        SignatureAlgorithm::Secp256k1 => verify_secp256k1(&pubkey.bytes, message, &sig.bytes),
        SignatureAlgorithm::MlDsa44 => verify_ml_dsa_44(&pubkey.bytes, message, &sig.bytes),
        SignatureAlgorithm::HmacSha256 => {
            // The account stores a derived HMAC attestation key (not the root REV).
            // Phase 1 hot-path: ~1-5µs constant-time MAC verification.
            // Phase 2 ZK proof proves the key was correctly derived from REV.
            // NOTE: The key is visible on-chain; full security requires Phase 2
            // (`stark` feature). Safe on a trusted validator set (devnet).
            verify_hmac_sha256(&pubkey.bytes, message, &sig.bytes)
        }
    }
}

// ── HMAC-SHA256 verification ──

fn verify_hmac_sha256(key: &[u8], message: &[u8], mac_bytes: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(message);
    mac.verify_slice(mac_bytes).is_ok()
}

// ── ML-DSA-44 (FIPS 204) verification via fips204 pure Rust ──
// Always available on all platforms (native, WASM, iOS, Android).

fn verify_ml_dsa_44(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use fips204::ml_dsa_44;
    use fips204::traits::{SerDes, Verifier};

    if pubkey.len() != 1312 || signature.len() != 2420 {
        return false;
    }
    let pk: [u8; 1312] = match pubkey.try_into() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig: [u8; 2420] = match signature.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let Ok(vk) = ml_dsa_44::PublicKey::try_from_bytes(pk) else {
        return false;
    };
    vk.verify(message, &sig, &[]) // empty context for standard verification
}

// ── Secp256k1 verification ──

fn verify_secp256k1(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(vk) = K256VerifyingKey::from_sec1_bytes(pubkey) else {
        return false;
    };
    let sig_bytes: &[u8; 64] = match signature.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let Ok(sig) = K256Signature::from_bytes(sig_bytes.into()) else {
        return false;
    };
    vk.verify(message, &sig).is_ok()
}

// ── Ed25519 verification ──

fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pubkey: [u8; 32] = match pubkey.try_into() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey) else {
        return false;
    };
    let sig_bytes: &[u8; 64] = match signature.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let sig = Ed25519Signature::from_bytes(sig_bytes);
    verifying_key.verify_strict(message, &sig).is_ok()
}

// ──────────────────────────────────────────────────────────────
// LocalSigningKey — multi-algorithm signing abstraction
// ──────────────────────────────────────────────────────────────

/// A local signing key that supports Ed25519 or ML-DSA-44.
///
/// Used by validators for signing votes, committee approvals, and
/// attestations. The algorithm is determined at node startup based
/// on the genesis validator set configuration.
#[allow(dead_code)]
pub enum LocalSigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    MlDsa44 {
        pk_bytes: [u8; 1312],
        sk_bytes: [u8; 2560], // fips204 expanded secret key
    },
}

impl LocalSigningKey {
    /// Create from a 32-byte seed using the specified algorithm.
    pub fn from_seed(seed: &[u8; 32], algorithm: SignatureAlgorithm) -> Result<Self, String> {
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                Ok(Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed)))
            }
            SignatureAlgorithm::MlDsa44 => {
                use fips204::ml_dsa_44::KG;
                use fips204::traits::{KeyGen, SerDes};
                let (pk, sk) = KG::keygen_from_seed(seed);
                Ok(Self::MlDsa44 {
                    pk_bytes: pk.into_bytes(),
                    sk_bytes: sk.into_bytes(),
                })
            }
            other => Err(format!("{other:?} is not supported for validator signing")),
        }
    }

    /// Sign a message and return a TaggedSignature.
    pub fn sign(&self, message: &[u8]) -> TaggedSignature {
        match self {
            Self::Ed25519(sk) => {
                use ed25519_dalek::Signer;
                TaggedSignature::ed25519(sk.sign(message).to_bytes())
            }
            Self::MlDsa44 { sk_bytes, .. } => {
                use fips204::ml_dsa_44;
                use fips204::traits::{SerDes, Signer};
                let sk = ml_dsa_44::PrivateKey::try_from_bytes(*sk_bytes)
                    .expect("LocalSigningKey holds a valid ML-DSA-44 secret key");
                let sig = sk
                    .try_sign(message, &[])
                    .expect("ML-DSA-44 signing should not fail");
                TaggedSignature::ml_dsa_44(sig.to_vec())
            }
        }
    }

    /// Return the corresponding TaggedPubkey.
    pub fn public_key(&self) -> TaggedPubkey {
        match self {
            Self::Ed25519(sk) => TaggedPubkey::ed25519(sk.verifying_key().to_bytes()),
            Self::MlDsa44 { pk_bytes, .. } => TaggedPubkey::ml_dsa_44(pk_bytes.to_vec()),
        }
    }

    /// Return the signature algorithm.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            Self::Ed25519(_) => SignatureAlgorithm::Ed25519,
            Self::MlDsa44 { .. } => SignatureAlgorithm::MlDsa44,
        }
    }
}

impl std::fmt::Debug for LocalSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519(_) => write!(f, "LocalSigningKey::Ed25519(<hidden>)"),
            Self::MlDsa44 { .. } => write!(f, "LocalSigningKey::MlDsa44(<hidden>)"),
        }
    }
}

// ──────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn tagged_pubkey_roundtrip() {
        let pk = TaggedPubkey::ed25519([0xAA; 32]);
        let wire = pk.to_wire_bytes();
        let (decoded, consumed) = TaggedPubkey::from_wire_bytes(&wire).unwrap();
        assert_eq!(decoded, pk);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn tagged_signature_roundtrip() {
        let sig = TaggedSignature::ed25519([0xBB; 64]);
        let wire = sig.to_wire_bytes();
        let (decoded, consumed) = TaggedSignature::from_wire_bytes(&wire).unwrap();
        assert_eq!(decoded, sig);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn tagged_pubkey_ml_dsa_roundtrip() {
        let pk = TaggedPubkey::ml_dsa_44(vec![0xCC; 1312]);
        assert!(pk.is_well_formed());
        let wire = pk.to_wire_bytes();
        let (decoded, consumed) = TaggedPubkey::from_wire_bytes(&wire).unwrap();
        assert_eq!(decoded, pk);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn ed25519_verify_roundtrip() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let pubkey = TaggedPubkey::ed25519(signing_key.verifying_key().to_bytes());
        let message = b"test message for PQC-ready verification";
        let sig_bytes = signing_key.sign(message).to_bytes();
        let signature = TaggedSignature::ed25519(sig_bytes);

        assert!(verify_signature(&pubkey, message, &signature));
        // Tamper with message
        assert!(!verify_signature(&pubkey, b"wrong message", &signature));
    }

    #[test]
    fn ml_dsa_verify_rejects_invalid_signature() {
        let pk = TaggedPubkey::ml_dsa_44(vec![0; 1312]);
        let sig = TaggedSignature {
            algorithm: SignatureAlgorithm::MlDsa44,
            bytes: vec![0; 2420],
        };
        // All-zero pubkey + signature is never a valid ML-DSA-44 pair.
        assert!(!verify_signature(&pk, b"msg", &sig));
    }

    #[test]
    fn algorithm_mismatch_fails() {
        let pk = TaggedPubkey::ed25519([0; 32]);
        let sig = TaggedSignature {
            algorithm: SignatureAlgorithm::MlDsa44,
            bytes: vec![0; 2420],
        };
        assert!(!verify_signature(&pk, b"msg", &sig));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let pk = TaggedPubkey::ed25519([0x42; 32]);
        assert_eq!(pk.fingerprint(), pk.fingerprint());

        // Different algorithm produces different fingerprint even with same-length bytes
        let pk2 = TaggedPubkey {
            algorithm: SignatureAlgorithm::Secp256k1,
            bytes: vec![0x42; 33],
        };
        assert_ne!(pk.fingerprint(), pk2.fingerprint());
    }

    #[test]
    fn default_is_ed25519_zero() {
        let pk = TaggedPubkey::default();
        assert_eq!(pk.algorithm, SignatureAlgorithm::Ed25519);
        assert!(pk.is_zero());
        assert_eq!(pk.bytes.len(), 32);
    }

    #[test]
    fn secp256k1_verify_roundtrip() {
        use k256::ecdsa::{signature::Signer as _, SigningKey as K256SigningKey};

        let sk = K256SigningKey::from_bytes(&[42u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let compressed: [u8; 33] = vk.to_sec1_bytes()[..33].try_into().unwrap();
        let pubkey = TaggedPubkey::secp256k1(compressed);

        let message = b"test message for secp256k1 verification";
        let sig: k256::ecdsa::Signature = sk.sign(message);
        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        let signature = TaggedSignature::secp256k1(sig_bytes);

        assert!(verify_signature(&pubkey, message, &signature));
        assert!(!verify_signature(&pubkey, b"wrong message", &signature));
    }

    #[test]
    fn secp256k1_rejects_wrong_key() {
        use k256::ecdsa::{signature::Signer as _, SigningKey as K256SigningKey};

        let sk1 = K256SigningKey::from_bytes(&[42u8; 32].into()).unwrap();
        let sk2 = K256SigningKey::from_bytes(&[43u8; 32].into()).unwrap();
        let vk2 = sk2.verifying_key();
        let compressed: [u8; 33] = vk2.to_sec1_bytes()[..33].try_into().unwrap();
        let wrong_pubkey = TaggedPubkey::secp256k1(compressed);

        let message = b"key mismatch test";
        let sig: k256::ecdsa::Signature = sk1.sign(message);
        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        let signature = TaggedSignature::secp256k1(sig_bytes);

        assert!(!verify_signature(&wrong_pubkey, message, &signature));
    }

    #[test]
    fn secp256k1_pubkey_wire_roundtrip() {
        let pk = TaggedPubkey::secp256k1([0xAA; 33]);
        assert!(pk.is_well_formed());
        let wire = pk.to_wire_bytes();
        let (decoded, consumed) = TaggedPubkey::from_wire_bytes(&wire).unwrap();
        assert_eq!(decoded, pk);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn secp256k1_signature_wire_roundtrip() {
        let sig = TaggedSignature::secp256k1([0xBB; 64]);
        let wire = sig.to_wire_bytes();
        let (decoded, consumed) = TaggedSignature::from_wire_bytes(&wire).unwrap();
        assert_eq!(decoded, sig);
        assert_eq!(consumed, wire.len());
    }

    fn hmac_compute(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        let mut m = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        m.update(message);
        let mut out = [0u8; 32];
        out.copy_from_slice(&m.finalize().into_bytes());
        out
    }

    #[test]
    fn hmac_sha256_primitive_roundtrip() {
        // verify_hmac_sha256 is a primitive for ZK circuits / off-chain use.
        let key = [42u8; 32];
        let message = b"test message for HMAC-SHA256 verification";
        let mac = hmac_compute(&key, message);
        assert!(verify_hmac_sha256(&key, message, &mac));
    }

    #[test]
    fn hmac_sha256_primitive_rejects_wrong_key() {
        let key = [42u8; 32];
        let message = b"test message";
        let mac = hmac_compute(&key, message);
        assert!(!verify_hmac_sha256(&[43u8; 32], message, &mac));
    }

    #[test]
    fn hmac_sha256_primitive_rejects_wrong_message() {
        let key = [42u8; 32];
        let mac = hmac_compute(&key, b"correct message");
        assert!(!verify_hmac_sha256(&key, b"wrong message", &mac));
    }

    #[test]
    fn hmac_sha256_public_verifier_roundtrip() {
        // Phase 1 hot-path: account stores the derived HMAC attestation key;
        // verify_signature performs constant-time MAC verification.
        let key = [42u8; 32];
        let message = b"test message";
        let mac = hmac_compute(&key, message);
        let pubkey = TaggedPubkey::hmac_sha256(key);
        let signature = TaggedSignature::hmac_sha256(mac);
        assert!(verify_signature(&pubkey, message, &signature));
        // Wrong key must fail.
        let wrong_pubkey = TaggedPubkey::hmac_sha256([43u8; 32]);
        assert!(!verify_signature(&wrong_pubkey, message, &signature));
        // Tampered MAC must fail.
        let mut bad_mac = mac;
        bad_mac[0] ^= 0xff;
        let bad_sig = TaggedSignature::hmac_sha256(bad_mac);
        assert!(!verify_signature(&pubkey, message, &bad_sig));
    }

    #[test]
    fn hmac_sha256_wire_roundtrip() {
        let pk = TaggedPubkey::hmac_sha256([0xDD; 32]);
        assert!(pk.is_well_formed());
        let wire = pk.to_wire_bytes();
        let (decoded, consumed) = TaggedPubkey::from_wire_bytes(&wire).unwrap();
        assert_eq!(decoded, pk);
        assert_eq!(consumed, wire.len());

        let sig = TaggedSignature::hmac_sha256([0xEE; 32]);
        assert!(sig.is_well_formed());
        let wire = sig.to_wire_bytes();
        let (decoded, consumed) = TaggedSignature::from_wire_bytes(&wire).unwrap();
        assert_eq!(decoded, sig);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn hmac_sha256_cross_algorithm_rejected() {
        let ed_pk = TaggedPubkey::ed25519([0; 32]);
        let hmac_sig = TaggedSignature::hmac_sha256([0; 32]);
        assert!(!verify_signature(&ed_pk, b"msg", &hmac_sig));
    }

    /// End-to-end ML-DSA-44 keygen → sign → verify via fips204 pure Rust.
    /// Always available on all platforms (no feature gate needed).
    mod pqc_tests {
        use super::*;

        #[test]
        fn ml_dsa_44_sign_and_verify() {
            let seed = [0x42u8; 32];
            let key = LocalSigningKey::from_seed(&seed, SignatureAlgorithm::MlDsa44).unwrap();
            let message = b"ACE Chain PQC verification test";

            let signature = key.sign(message);
            let pubkey = key.public_key();

            assert_eq!(pubkey.algorithm, SignatureAlgorithm::MlDsa44);
            assert_eq!(pubkey.bytes.len(), 1312);
            assert_eq!(signature.algorithm, SignatureAlgorithm::MlDsa44);
            assert_eq!(signature.bytes.len(), 2420);
            assert!(verify_signature(&pubkey, message, &signature));
        }

        #[test]
        fn ml_dsa_44_rejects_wrong_message() {
            let key =
                LocalSigningKey::from_seed(&[0x42u8; 32], SignatureAlgorithm::MlDsa44).unwrap();
            let signature = key.sign(b"correct message");
            let pubkey = key.public_key();

            assert!(!verify_signature(&pubkey, b"wrong message", &signature));
        }

        #[test]
        fn ml_dsa_44_rejects_wrong_key() {
            let key1 =
                LocalSigningKey::from_seed(&[0x11u8; 32], SignatureAlgorithm::MlDsa44).unwrap();
            let key2 =
                LocalSigningKey::from_seed(&[0x22u8; 32], SignatureAlgorithm::MlDsa44).unwrap();
            let message = b"key mismatch test";
            let signature = key1.sign(message);

            assert!(!verify_signature(&key2.public_key(), message, &signature));
        }

        #[test]
        fn ml_dsa_44_deterministic_keygen() {
            let seed = [0xAAu8; 32];
            let key1 = LocalSigningKey::from_seed(&seed, SignatureAlgorithm::MlDsa44).unwrap();
            let key2 = LocalSigningKey::from_seed(&seed, SignatureAlgorithm::MlDsa44).unwrap();
            assert_eq!(key1.public_key(), key2.public_key());
        }
    }
}
