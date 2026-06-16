#![allow(dead_code)]

use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
#[cfg(feature = "test-utils")]
use ace_runtime::crypto::proof::PrivateWitness;
use ace_runtime::crypto::TaggedPubkey;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::transaction::Transaction;
use sha2::{Digest, Sha256};

pub fn test_seed(tag: u8) -> [u8; 32] {
    let mut seed = [tag; 32];
    seed[0] ^= 0xA5;
    seed[31] ^= 0x5A;
    seed
}

pub fn test_root_secret(tag: u8) -> [u8; 32] {
    let mut secret = [tag; 32];
    secret[0] = tag.wrapping_mul(17).wrapping_add(3);
    secret[31] = tag.wrapping_mul(29).wrapping_add(11);
    secret
}

pub fn test_idcom(tag: u8, domain: Domain) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-TEST-IDCOM-V1");
    hasher.update([tag]);
    hasher.update(domain.to_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn payload_hash(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn make_test_attestation(
    auth_signing_seed: &[u8; 32],
    idcom: [u8; 32],
    payload: &[u8],
    domain: Domain,
) -> Attestation {
    let obj_hash = payload_hash(payload);
    let credential = make_credential(auth_signing_seed, &obj_hash, &idcom, &domain, &[0u8; 16]);
    Attestation {
        obj_hash,
        idcom,
        domain,
        context_tag: [0u8; 16],
        credential,
    }
}

pub fn make_test_tx(
    auth_signing_seed: &[u8; 32],
    idcom: [u8; 32],
    payload: &[u8],
    domain: Domain,
) -> Transaction {
    Transaction::new(
        payload.to_vec(),
        make_test_attestation(auth_signing_seed, idcom, payload, domain),
    )
}

#[cfg(feature = "test-utils")]
pub fn make_mock_witness(tag: u8) -> PrivateWitness {
    PrivateWitness::with_defaults(test_root_secret(tag), [0u8; 32])
}

pub fn auth_pubkey_for(tag: u8) -> TaggedPubkey {
    auth_public_key_from_seed(&test_seed(tag))
}

/// Compute a proof-bound identity commitment using the ZK-ACE native
/// Poseidon2 hash (M31 field). This produces the same id_com
/// that the STARK circuit would verify.
#[cfg(feature = "stark")]
pub fn proof_bound_idcom(root_secret: [u8; 32], salt: [u8; 32], domain: Domain) -> [u8; 32] {
    use zk_ace::native::commitment::compute_id_com;
    use zk_ace::stwo::types::{bytes_to_elements, elements_to_bytes, u64_to_domain_elements};

    let root_elems = bytes_to_elements(&root_secret); // [M31; 9]
    let salt_elems = bytes_to_elements(&salt); // [M31; 9]
    let domain_u64 = u64::from_le_bytes(domain.to_bytes());
    let domain_elems = u64_to_domain_elements(domain_u64); // [M31; 3]
    let idcom = compute_id_com(&root_elems, &salt_elems, &domain_elems);
    elements_to_bytes(&idcom) // [M31; 8] -> [u8; 32], still correct for hash output
}
