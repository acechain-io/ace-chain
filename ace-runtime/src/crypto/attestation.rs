//! Attestation signing and verification helpers.
//!
//! The runtime treats attestation signing material as an opaque caller-managed
//! 32-byte seed. It does not derive or recover wallet root secrets internally.
//!
//! Validators verify:
//! - Payload binding: `SHA-256(payload) == obj_hash`
//! - Signature validity against the account's on-chain `auth_pubkey`
//!
//! ## Algorithm dispatch
//!
//! On-chain attestation verification dispatches by the account's `auth_pubkey.algorithm`:
//! - `make_credential` → Ed25519 (legacy, for existing accounts)
//! - `make_credential_ml_dsa_44` → ML-DSA-44 (default for new accounts)
//! - `make_credential_for_algorithm` → unified entry point (recommended)
//!
//! ## Identity takeover (separate path)
//!
//! Identity takeover messages use `TaggedSignature` and verify via the
//! `sig_algo::verify_signature` dispatcher. This is a P2P protocol concern,
//! not an on-chain attestation.

use ed25519_dalek::{Signer, SigningKey};
use k256::ecdsa::SigningKey as K256SigningKey;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::sig_algo::{self, TaggedPubkey, TaggedSignature};
use crate::types::attestation::{Attestation, Domain};

/// Compute the attestation public key from a signing seed.
/// Returns an Ed25519 tagged public key.
pub fn auth_public_key_from_seed(auth_signing_seed: &[u8; 32]) -> TaggedPubkey {
    TaggedPubkey::ed25519(
        SigningKey::from_bytes(auth_signing_seed)
            .verifying_key()
            .to_bytes(),
    )
}

/// Verify an attestation against a known attestation public key.
pub fn verify_attestation(
    attestation: &Attestation,
    payload: &[u8],
    auth_pubkey: &TaggedPubkey,
) -> bool {
    verify_credential(attestation, payload, auth_pubkey)
}

/// Verify only the payload binding (lightweight check for Phase 1a).
/// Uses constant-time comparison to avoid timing leaks.
pub fn verify_payload_binding(attestation: &Attestation, payload: &[u8]) -> bool {
    let expected_hash = sha256(payload);
    bool::from(attestation.obj_hash.ct_eq(&expected_hash))
}

/// Verify the signature credential of an attestation against the account's public key.
pub fn verify_credential(
    attestation: &Attestation,
    payload: &[u8],
    auth_pubkey: &TaggedPubkey,
) -> bool {
    let binding_ok = verify_payload_binding(attestation, payload);
    let key_ok = !auth_pubkey.is_zero();
    if !binding_ok || !key_ok {
        return false;
    }

    // HMAC-SHA256 attestation stores the symmetric key on-chain in the clear, so
    // anyone who can read chain state can forge a credential. It is only sound on a
    // trusted validator set (devnet) or behind a Phase-2 ZK proof. Refuse it outright
    // on non-devnet builds instead of relying on policy/comments.
    #[cfg(not(feature = "devnet"))]
    if auth_pubkey.algorithm == sig_algo::SignatureAlgorithm::HmacSha256 {
        return false;
    }

    let mut message = signing_message(
        auth_pubkey.algorithm.tag(),
        &attestation.obj_hash,
        &attestation.idcom,
        &attestation.domain,
        &attestation.context_tag,
    );
    let result = sig_algo::verify_signature(auth_pubkey, &message, &attestation.credential);
    message.iter_mut().for_each(|b| *b = 0);
    result
}

/// Sign an attestation credential using the caller's private seed.
/// Produces an Ed25519 tagged signature.
pub fn make_credential(
    auth_signing_seed: &[u8; 32],
    obj_hash: &[u8; 32],
    idcom: &[u8; 32],
    domain: &Domain,
    context_tag: &[u8; 16],
) -> TaggedSignature {
    let signing_key = SigningKey::from_bytes(auth_signing_seed);
    let mut message = signing_message(
        sig_algo::SignatureAlgorithm::Ed25519.tag(),
        obj_hash,
        idcom,
        domain,
        context_tag,
    );
    let sig = TaggedSignature::ed25519(signing_key.sign(&message).to_bytes());
    message.iter_mut().for_each(|b| *b = 0);
    sig
}

/// Sign an attestation credential using the algorithm that matches the
/// account's on-chain `auth_pubkey`. This is the recommended entry point
/// for callers that don't know (or shouldn't hardcode) the algorithm.
pub fn make_credential_for_algorithm(
    auth_signing_seed: &[u8; 32],
    obj_hash: &[u8; 32],
    idcom: &[u8; 32],
    domain: &Domain,
    context_tag: &[u8; 16],
    algorithm: sig_algo::SignatureAlgorithm,
) -> Result<TaggedSignature, &'static str> {
    match algorithm {
        sig_algo::SignatureAlgorithm::Ed25519 => Ok(make_credential(
            auth_signing_seed,
            obj_hash,
            idcom,
            domain,
            context_tag,
        )),
        sig_algo::SignatureAlgorithm::Secp256k1 => {
            make_credential_secp256k1(auth_signing_seed, obj_hash, idcom, domain, context_tag)
        }
        sig_algo::SignatureAlgorithm::MlDsa44 => Ok(make_credential_ml_dsa_44(
            auth_signing_seed,
            obj_hash,
            idcom,
            domain,
            context_tag,
        )),
        sig_algo::SignatureAlgorithm::HmacSha256 => Ok(make_credential_hmac(
            auth_signing_seed,
            obj_hash,
            idcom,
            domain,
            context_tag,
        )),
    }
}

/// Compute the attestation public key from a Secp256k1 private key.
/// Returns a Secp256k1 tagged public key (33-byte compressed).
pub fn auth_public_key_from_secp256k1(
    private_key: &[u8; 32],
) -> Result<TaggedPubkey, &'static str> {
    let signing_key = K256SigningKey::from_bytes(private_key.into())
        .map_err(|_| "invalid secp256k1 private key")?;
    let vk = signing_key.verifying_key();
    let compressed: [u8; 33] = vk.to_sec1_bytes()[..33].try_into().unwrap();
    Ok(TaggedPubkey::secp256k1(compressed))
}

/// Sign an attestation credential using a Secp256k1 private key.
/// Produces a Secp256k1 tagged signature (64-byte compact r||s).
pub fn make_credential_secp256k1(
    private_key: &[u8; 32],
    obj_hash: &[u8; 32],
    idcom: &[u8; 32],
    domain: &Domain,
    context_tag: &[u8; 16],
) -> Result<TaggedSignature, &'static str> {
    let signing_key = K256SigningKey::from_bytes(private_key.into())
        .map_err(|_| "invalid secp256k1 private key")?;
    let mut message = signing_message(
        sig_algo::SignatureAlgorithm::Secp256k1.tag(),
        obj_hash,
        idcom,
        domain,
        context_tag,
    );
    let sig: k256::ecdsa::Signature = signing_key.sign(&message);
    let sig_bytes: [u8; 64] = sig.to_bytes().into();
    message.iter_mut().for_each(|b| *b = 0);
    Ok(TaggedSignature::secp256k1(sig_bytes))
}

/// Build an HMAC-SHA256 attestation credential.
///
/// `attest_key` is the 32-byte HMAC attestation key stored as the account's
/// `auth_pubkey` on-chain.  It is derived from the user's REV via HKDF
/// (never the REV itself).  Phase 2 ZK proves the derivation.
///
/// NOTE: The HMAC key is stored on-chain as `auth_pubkey` and is therefore
/// visible to all validators.  Full security depends on Phase 2 ZK proof
/// (requires the `stark` feature) for accountability.  On a trusted validator
/// set (e.g. devnet) this is acceptable; for permissionless deployments
/// Phase 2 must be active.
pub fn make_credential_hmac(
    attest_key: &[u8; 32],
    obj_hash: &[u8; 32],
    idcom: &[u8; 32],
    domain: &Domain,
    context_tag: &[u8; 16],
) -> TaggedSignature {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut message = signing_message(
        sig_algo::SignatureAlgorithm::HmacSha256.tag(),
        obj_hash,
        idcom,
        domain,
        context_tag,
    );
    let mut mac = HmacSha256::new_from_slice(attest_key).expect("HMAC key is 32 bytes");
    mac.update(&message);
    let result = mac.finalize().into_bytes();
    let mut mac_bytes = [0u8; 32];
    mac_bytes.copy_from_slice(&result);
    message.iter_mut().for_each(|b| *b = 0);
    TaggedSignature::hmac_sha256(mac_bytes)
}

/// Return the HMAC-SHA256 "public key" for an attestation key.
///
/// For HMAC accounts the on-chain `auth_pubkey` IS the symmetric attestation key
/// (a 32-byte HKDF-derived value, not the root REV).
pub fn auth_public_key_from_hmac_attest_key(attest_key: &[u8; 32]) -> TaggedPubkey {
    TaggedPubkey::hmac_sha256(*attest_key)
}

/// Compute the attestation public key from a seed using ML-DSA-44.
/// Returns an ML-DSA-44 tagged public key (1312 bytes).
pub fn auth_public_key_from_ml_dsa_44_seed(seed: &[u8; 32]) -> TaggedPubkey {
    use crate::crypto::sig_algo::{LocalSigningKey, SignatureAlgorithm};
    let key = LocalSigningKey::from_seed(seed, SignatureAlgorithm::MlDsa44)
        .expect("ML-DSA-44 keygen from valid seed should not fail");
    key.public_key()
}

/// Sign an attestation credential using ML-DSA-44.
/// Produces an ML-DSA-44 tagged signature (2420 bytes).
pub fn make_credential_ml_dsa_44(
    seed: &[u8; 32],
    obj_hash: &[u8; 32],
    idcom: &[u8; 32],
    domain: &Domain,
    context_tag: &[u8; 16],
) -> TaggedSignature {
    use crate::crypto::sig_algo::{LocalSigningKey, SignatureAlgorithm};
    let key = LocalSigningKey::from_seed(seed, SignatureAlgorithm::MlDsa44)
        .expect("ML-DSA-44 keygen from valid seed should not fail");
    let mut message = signing_message(
        SignatureAlgorithm::MlDsa44.tag(),
        obj_hash,
        idcom,
        domain,
        context_tag,
    );
    let sig = key.sign(&message);
    message.iter_mut().for_each(|b| *b = 0);
    sig
}

/// Compute SHA-256 hash of data.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

fn signing_message(
    alg_tag: u8,
    obj_hash: &[u8; 32],
    idcom: &[u8; 32],
    domain: &Domain,
    context_tag: &[u8; 16],
) -> [u8; 89] {
    let mut message = [0u8; 89];
    message[0] = alg_tag;
    message[1..33].copy_from_slice(obj_hash);
    message[33..65].copy_from_slice(idcom);
    message[65..73].copy_from_slice(&domain.to_bytes());
    message[73..89].copy_from_slice(context_tag);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};

    #[test]
    fn make_hmac_credential_matches_reference_mac() {
        type HmacSha256 = Hmac<sha2::Sha256>;

        let attest_key = [0x42; 32];
        let obj_hash = [0x11; 32];
        let idcom = [0x22; 32];
        let domain = Domain::new(7, 123);

        let credential = make_credential_hmac(&attest_key, &obj_hash, &idcom, &domain, &[0u8; 16]);
        assert_eq!(
            credential.algorithm,
            sig_algo::SignatureAlgorithm::HmacSha256
        );
        assert_eq!(credential.bytes.len(), 32);

        let message = signing_message(
            sig_algo::SignatureAlgorithm::HmacSha256.tag(),
            &obj_hash,
            &idcom,
            &domain,
            &[0u8; 16],
        );
        let mut mac = HmacSha256::new_from_slice(&attest_key).unwrap();
        mac.update(&message);
        let expected = mac.finalize().into_bytes();

        assert_eq!(credential.bytes.as_slice(), expected.as_slice());
    }

    // ── E2E: ML-DSA-44 attestation sign → verify ──

    #[test]
    fn ml_dsa_44_credential_sign_and_verify() {
        let seed = [0x55u8; 32];
        let auth_pubkey = auth_public_key_from_ml_dsa_44_seed(&seed);
        assert_eq!(auth_pubkey.algorithm, sig_algo::SignatureAlgorithm::MlDsa44);
        assert_eq!(auth_pubkey.bytes.len(), 1312);

        let obj_hash = sha256(b"test payload");
        let idcom = [0x33; 32];
        let domain = Domain::new(1, 42);

        let credential = make_credential_ml_dsa_44(&seed, &obj_hash, &idcom, &domain, &[0u8; 16]);
        assert_eq!(credential.algorithm, sig_algo::SignatureAlgorithm::MlDsa44);
        assert_eq!(credential.bytes.len(), 2420);

        let attestation = Attestation {
            obj_hash,
            idcom,
            domain,
            context_tag: [0u8; 16],
            credential,
        };

        // Verify passes with correct pubkey
        assert!(verify_credential(
            &attestation,
            b"test payload",
            &auth_pubkey
        ));
        // Verify fails with wrong payload
        assert!(!verify_credential(
            &attestation,
            b"wrong payload",
            &auth_pubkey
        ));
        // Verify fails with wrong pubkey
        let wrong_pubkey = auth_public_key_from_ml_dsa_44_seed(&[0x99; 32]);
        assert!(!verify_credential(
            &attestation,
            b"test payload",
            &wrong_pubkey
        ));
    }

    #[test]
    fn make_credential_for_algorithm_dispatches_correctly() {
        let seed = [0x44u8; 32];
        let payload = b"test transaction payload";
        let obj_hash = sha256(payload);
        let idcom = [0x22; 32];
        let domain = Domain::new(1, 7);

        // Ed25519
        let ed_cred = make_credential_for_algorithm(
            &seed,
            &obj_hash,
            &idcom,
            &domain,
            &[0u8; 16],
            sig_algo::SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        assert_eq!(ed_cred.algorithm, sig_algo::SignatureAlgorithm::Ed25519);
        assert_eq!(ed_cred.bytes.len(), 64);
        let ed_pk = auth_public_key_from_seed(&seed);
        let att_ed = Attestation {
            obj_hash,
            idcom,
            domain,
            context_tag: [0u8; 16],
            credential: ed_cred,
        };
        assert!(verify_credential(&att_ed, payload, &ed_pk));

        // ML-DSA-44
        let pqc_cred = make_credential_for_algorithm(
            &seed,
            &obj_hash,
            &idcom,
            &domain,
            &[0u8; 16],
            sig_algo::SignatureAlgorithm::MlDsa44,
        )
        .unwrap();
        assert_eq!(pqc_cred.algorithm, sig_algo::SignatureAlgorithm::MlDsa44);
        assert_eq!(pqc_cred.bytes.len(), 2420);
        let pqc_pk = auth_public_key_from_ml_dsa_44_seed(&seed);
        let att_pqc = Attestation {
            obj_hash,
            idcom,
            domain,
            context_tag: [0u8; 16],
            credential: pqc_cred,
        };
        assert!(verify_credential(&att_pqc, payload, &pqc_pk));

        // HMAC-SHA256
        let hmac_cred = make_credential_for_algorithm(
            &seed,
            &obj_hash,
            &idcom,
            &domain,
            &[0u8; 16],
            sig_algo::SignatureAlgorithm::HmacSha256,
        )
        .unwrap();
        assert_eq!(
            hmac_cred.algorithm,
            sig_algo::SignatureAlgorithm::HmacSha256
        );
        assert_eq!(hmac_cred.bytes.len(), 32);
        let hmac_pk = auth_public_key_from_hmac_attest_key(&seed);
        let att_hmac = Attestation {
            obj_hash,
            idcom,
            domain,
            context_tag: [0u8; 16],
            credential: hmac_cred,
        };
        // HMAC attestation is only honored on devnet builds (insecure: key is public).
        #[cfg(feature = "devnet")]
        assert!(verify_credential(&att_hmac, payload, &hmac_pk));
        #[cfg(not(feature = "devnet"))]
        assert!(!verify_credential(&att_hmac, payload, &hmac_pk));

        // Cross-algorithm: Ed25519 credential won't verify with ML-DSA pubkey
        let ed_cred2 = make_credential_for_algorithm(
            &seed,
            &obj_hash,
            &idcom,
            &domain,
            &[0u8; 16],
            sig_algo::SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let att_cross = Attestation {
            obj_hash,
            idcom,
            domain,
            context_tag: [0u8; 16],
            credential: ed_cred2,
        };
        assert!(!verify_credential(&att_cross, payload, &pqc_pk));
    }
}
