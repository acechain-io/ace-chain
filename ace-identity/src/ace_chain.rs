//! ACE Chain native attestation: build and verify.
//!
//! All signing / verification for ACE Runtime should go through the functions
//! exposed by this module. Sensitive material (identity_root, REV32, etc.) stays
//! inside the wallet and is not exposed to callers.
//!
//! Since AR-ACE PR2: the deprecated HMAC-SHA256 104-byte wire attestation was removed.
//! New public APIs:
//!   - `ace_build_relay_attestation_rev32` — 152-byte Ed25519 relay attestation
//!   - `ace_build_auth_credential_v2_ml_dsa_44_rev32` — ML-DSA-44 v2 auth credential

use acegf::acegf_core::ACEGFCore;
use acegf::acegf_structs::AcegfError;
use acegf::utils::acegf_rev_generator::AceRevGenerator;
use acegf::utils::acegf_rev_generator::Rev32;
use acegf::utils::passphrase_sealing_util::PassphraseSealingUtil;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// ────────────────────────────────────────────────────────────────────────────
// AR-ACE Profile A — wallet-side relay attestation builder (paper 11 §5.1)
// ────────────────────────────────────────────────────────────────────────────

/// Wire size of an AR-ACE [`RelayAttestation`] (mirrors the runtime constant).
pub const ACE_RELAY_ATTESTATION_WIRE_SIZE: usize = 32 + 32 + 8 + 16 + 64; // 152
/// Domain-separation prefix mixed into relay signing messages.
/// MUST stay in sync with `ace_runtime::crypto::contexts::RELAY_SIGNING_PREFIX`.
const RELAY_SIGNING_PREFIX: &[u8; 2] = b"R1";
const ML_DSA_44_ALG_TAG: u8 = 2;

/// Compose the canonical 90-byte relay signing message used by AR-ACE.
fn relay_signing_message(
    obj_hash: &[u8; 32],
    idcom: &[u8; 32],
    domain: &[u8; 8],
    context_tag: &[u8; 16],
) -> [u8; 90] {
    let mut msg = [0u8; 90];
    msg[0..2].copy_from_slice(RELAY_SIGNING_PREFIX);
    msg[2..34].copy_from_slice(obj_hash);
    msg[34..66].copy_from_slice(idcom);
    msg[66..74].copy_from_slice(domain);
    msg[74..90].copy_from_slice(context_tag);
    msg
}

/// Compose the canonical v2 auth signing message used by ACE Runtime.
fn auth_signing_message_v2(
    obj_hash: &[u8; 32],
    idcom: &[u8; 32],
    domain: &[u8; 8],
    context_tag: &[u8; 16],
) -> [u8; 89] {
    let mut msg = [0u8; 89];
    msg[0] = ML_DSA_44_ALG_TAG;
    msg[1..33].copy_from_slice(obj_hash);
    msg[33..65].copy_from_slice(idcom);
    msg[65..73].copy_from_slice(domain);
    msg[73..89].copy_from_slice(context_tag);
    msg
}

/// Build domain bytes: `chain_id` (4 LE) || `slot` (4 LE).
fn domain_bytes(chain_id: u32, slot: u32) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&chain_id.to_le_bytes());
    buf[4..8].copy_from_slice(&slot.to_le_bytes());
    buf
}

fn get_identity_root_rev32(
    mnemonic: &str,
    passphrase: &str,
    secondary_passphrase: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>, AcegfError> {
    let sealed = ACEGFCore::decode_mnemonic_to_sealed(mnemonic.trim())
        .map_err(|_| AcegfError::InvalidFormat)?;

    if !AceRevGenerator::is_rev32(&sealed as &Rev32) {
        return Err(AcegfError::InvalidFormat);
    }

    let full_passphrase =
        PassphraseSealingUtil::combine_passphrase(passphrase, secondary_passphrase);

    let kmaster =
        PassphraseSealingUtil::derive_kmaster_from_rev32(full_passphrase.as_bytes(), &sealed)?;
    let identity_root = PassphraseSealingUtil::derive_identity_root(&*kmaster)?;
    Ok(identity_root)
}

/// Extract `idcom` (32 bytes at offset 32..64) from attestation wire bytes.
pub fn ace_attestation_idcom(attestation_wire: &[u8]) -> Option<[u8; 32]> {
    if attestation_wire.len() < 64 {
        return None;
    }
    let mut idcom = [0u8; 32];
    idcom.copy_from_slice(&attestation_wire[32..64]);
    Some(idcom)
}

// ────────────────────────────────────────────────────────────────────────────
// AR-ACE Profile A — public API
// ────────────────────────────────────────────────────────────────────────────

pub fn ace_derive_relay_pubkey_rev32(
    mnemonic: &str,
    passphrase: &str,
    vault_context: &[u8],
) -> Result<[u8; 32], AcegfError> {
    let identity_root = get_identity_root_rev32(mnemonic, passphrase, None)?;
    let seed = ACEGFCore::derive_ed25519_relay_seed_from_rev32_with_context(
        &*identity_root,
        vault_context,
    )?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&*seed);
    Ok(signing_key.verifying_key().to_bytes())
}

pub fn ace_build_relay_attestation_rev32(
    mnemonic: &str,
    passphrase: &str,
    payload: &[u8],
    idcom: &[u8; 32],
    chain_id: u32,
    slot: u32,
    context_tag: &[u8; 16],
    vault_context: &[u8],
) -> Result<[u8; ACE_RELAY_ATTESTATION_WIRE_SIZE], AcegfError> {
    use ed25519_dalek::Signer;

    let identity_root = get_identity_root_rev32(mnemonic, passphrase, None)?;
    let relay_seed = ACEGFCore::derive_ed25519_relay_seed_from_rev32_with_context(
        &*identity_root,
        vault_context,
    )?;

    let domain = domain_bytes(chain_id, slot);
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let obj_hash_arr = hasher.finalize();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&obj_hash_arr);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&*relay_seed);
    let mut message = relay_signing_message(&obj_hash, idcom, &domain, context_tag);
    let sig = signing_key.sign(&message).to_bytes();
    message.iter_mut().for_each(|b| *b = 0);

    let mut wire = [0u8; ACE_RELAY_ATTESTATION_WIRE_SIZE];
    wire[0..32].copy_from_slice(&obj_hash);
    wire[32..64].copy_from_slice(idcom);
    wire[64..72].copy_from_slice(&domain);
    wire[72..88].copy_from_slice(context_tag);
    wire[88..152].copy_from_slice(&sig);
    Ok(wire)
}

pub fn ace_build_auth_credential_v2_ml_dsa_44_rev32(
    mnemonic: &str,
    passphrase: &str,
    payload: &[u8],
    idcom: &[u8; 32],
    chain_id: u32,
    slot: u32,
    context_tag: &[u8; 16],
    vault_context: &[u8],
) -> Result<Vec<u8>, AcegfError> {
    use fips204::ml_dsa_44;
    use fips204::traits::{KeyGen, Signer as PqcSigner};

    let identity_root = get_identity_root_rev32(mnemonic, passphrase, None)?;
    let auth_seed =
        ACEGFCore::derive_ml_dsa_seed_from_rev32_with_context(&*identity_root, vault_context)?;

    let (_pk, sk) = ml_dsa_44::KG::keygen_from_seed(&*auth_seed);
    let domain = domain_bytes(chain_id, slot);
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let obj_hash_arr = hasher.finalize();
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&obj_hash_arr);

    let mut message = auth_signing_message_v2(&obj_hash, idcom, &domain, context_tag);
    let sig = sk
        .try_sign(&message, &[])
        .map_err(|_| AcegfError::KdfError)?;
    message.iter_mut().for_each(|b| *b = 0);

    let mut wire = Vec::with_capacity(88 + 3 + sig.len());
    wire.extend_from_slice(&obj_hash);
    wire.extend_from_slice(idcom);
    wire.extend_from_slice(&domain);
    wire.extend_from_slice(context_tag);
    wire.push(ML_DSA_44_ALG_TAG);
    let sig_len = sig.len() as u16;
    wire.extend_from_slice(&sig_len.to_le_bytes());
    wire.extend_from_slice(&sig);
    Ok(wire)
}

pub fn ace_derive_auth_pubkey_ml_dsa_44_rev32(
    mnemonic: &str,
    passphrase: &str,
    vault_context: &[u8],
) -> Result<Vec<u8>, AcegfError> {
    use fips204::ml_dsa_44;
    use fips204::traits::{KeyGen, SerDes};

    let identity_root = get_identity_root_rev32(mnemonic, passphrase, None)?;
    let seed =
        ACEGFCore::derive_ml_dsa_seed_from_rev32_with_context(&*identity_root, vault_context)?;
    let (pk, _sk) = ml_dsa_44::KG::keygen_from_seed(&*seed);
    Ok(pk.into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;

    fn rev32_entropy_24word() -> [u8; 32] {
        let mut e = [0u8; 32];
        e[28] = 0xA0;
        e[31] = 0x00;
        e
    }

    #[test]
    fn test_domain_bytes() {
        let d = domain_bytes(1, 100);
        assert_eq!(d[..4], 1u32.to_le_bytes());
        assert_eq!(d[4..8], 100u32.to_le_bytes());
    }

    #[test]
    fn test_attestation_idcom_extract_from_relay_layout() {
        let mut wire = vec![0u8; 152];
        wire[32..64].copy_from_slice(&[0x42; 32]);
        let idcom = ace_attestation_idcom(&wire).unwrap();
        assert_eq!(idcom, [0x42; 32]);
    }

    #[test]
    fn test_relay_pubkey_derivation_is_deterministic_and_isolated() {
        let entropy = rev32_entropy_24word();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap().to_string();

        let pk1 = ace_derive_relay_pubkey_rev32(&mnemonic, "pp", b"").unwrap();
        let pk2 = ace_derive_relay_pubkey_rev32(&mnemonic, "pp", b"").unwrap();
        assert_eq!(pk1, pk2);

        let pk3 = ace_derive_relay_pubkey_rev32(&mnemonic, "pp", b"vault-A").unwrap();
        assert_ne!(pk1, pk3);

        let pk4 = ace_derive_relay_pubkey_rev32(&mnemonic, "qq", b"").unwrap();
        assert_ne!(pk1, pk4);

        let auth_pk = ace_derive_auth_pubkey_ml_dsa_44_rev32(&mnemonic, "pp", b"").unwrap();
        assert_ne!(&pk1[..], &auth_pk[..32]);
    }

    #[test]
    fn test_relay_attestation_wire_layout() {
        let entropy = rev32_entropy_24word();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap().to_string();
        let payload = b"relay tx body";
        let idcom = [0xAB; 32];
        let ctx_tag = [0u8; 16];
        let wire = ace_build_relay_attestation_rev32(
            &mnemonic, "pp", payload, &idcom, 122_766, 999, &ctx_tag, b"",
        )
        .unwrap();

        assert_eq!(wire.len(), ACE_RELAY_ATTESTATION_WIRE_SIZE);
        let expected_obj_hash = Sha256::digest(payload);
        assert_eq!(&wire[0..32], expected_obj_hash.as_slice());
        assert_eq!(&wire[32..64], &idcom);
        assert_eq!(&wire[64..68], 122_766u32.to_le_bytes());
        assert_eq!(&wire[68..72], 999u32.to_le_bytes());
        assert_eq!(&wire[72..88], &ctx_tag);
        assert!(wire[88..152].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_relay_attestation_signature_verifies_against_relay_pubkey() {
        use ed25519_dalek::Verifier;

        let entropy = rev32_entropy_24word();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap().to_string();
        let payload = b"verify me";
        let idcom = [0x55; 32];
        let ctx_tag = [0u8; 16];
        let chain_id = 7u32;
        let slot = 42u32;

        let wire = ace_build_relay_attestation_rev32(
            &mnemonic, "pp", payload, &idcom, chain_id, slot, &ctx_tag, b"",
        )
        .unwrap();
        let pk_bytes = ace_derive_relay_pubkey_rev32(&mnemonic, "pp", b"").unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();

        let obj_hash: [u8; 32] = wire[0..32].try_into().unwrap();
        let domain = domain_bytes(chain_id, slot);
        let message = relay_signing_message(&obj_hash, &idcom, &domain, &ctx_tag);
        let sig_bytes: [u8; 64] = wire[88..152].try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(&message, &sig).is_ok());

        let mut bad = message;
        bad[10] ^= 0x01;
        assert!(vk.verify(&bad, &sig).is_err());
    }

    #[test]
    fn test_v2_auth_credential_wire_layout_and_size() {
        let entropy = rev32_entropy_24word();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap().to_string();
        let payload = b"v2 auth body";
        let idcom = [0xCC; 32];
        let ctx_tag = [0u8; 16];

        let wire = ace_build_auth_credential_v2_ml_dsa_44_rev32(
            &mnemonic, "pp", payload, &idcom, 1, 7, &ctx_tag, b"",
        )
        .unwrap();
        assert_eq!(wire.len(), 2511);
        let obj_hash = Sha256::digest(payload);
        assert_eq!(&wire[0..32], obj_hash.as_slice());
        assert_eq!(&wire[32..64], &idcom);
        assert_eq!(&wire[88], &2u8);
        assert_eq!(&wire[89..91], 2420u16.to_le_bytes());
    }
}
