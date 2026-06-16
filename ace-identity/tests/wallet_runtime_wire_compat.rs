//! Cross-crate wire compatibility between acegf-wallet and ace-runtime.
//!
//! This test lives on the chain side so dependency flow stays one-way:
//! `ace-chain -> acegf-wallet`, never `acegf-wallet -> ace-chain`.

#![cfg(not(target_arch = "wasm32"))]

use ace_identity::ace_chain::{
    ace_build_auth_credential_v2_ml_dsa_44_rev32, ace_derive_auth_pubkey_ml_dsa_44_rev32,
};
use ace_runtime::crypto::attestation::verify_credential;
use ace_runtime::crypto::sig_algo::{SignatureAlgorithm, TaggedPubkey};
use ace_runtime::types::attestation::Attestation;
use bip39::Mnemonic;

fn rev32_mnemonic() -> String {
    let mut entropy = [0u8; 32];
    entropy[28] = 0xA0;
    entropy[31] = 0x00;
    Mnemonic::from_entropy(&entropy).unwrap().to_string()
}

#[test]
fn wallet_v2_auth_credential_verifies_under_runtime() {
    let mnemonic = rev32_mnemonic();
    let passphrase = "test-pp";
    let payload = b"v2 auth wire compat";
    let idcom = [0xCC; 32];
    let context_tag = [0u8; 16];
    let chain_id = 1u32;
    let slot = 7u32;
    let vault_context = b"";

    let auth_wire = ace_build_auth_credential_v2_ml_dsa_44_rev32(
        &mnemonic,
        passphrase,
        payload,
        &idcom,
        chain_id,
        slot,
        &context_tag,
        vault_context,
    )
    .expect("wallet builds runtime auth credential");

    let attestation = Attestation::from_bytes(&auth_wire).expect("runtime decodes wallet wire");
    assert_eq!(attestation.idcom, idcom);
    assert_eq!(attestation.domain.chain_id, chain_id);
    assert_eq!(attestation.domain.slot, slot);
    assert_eq!(attestation.context_tag, context_tag);
    assert_eq!(
        attestation.credential.algorithm,
        SignatureAlgorithm::MlDsa44
    );

    let pk_bytes =
        ace_derive_auth_pubkey_ml_dsa_44_rev32(&mnemonic, passphrase, vault_context).unwrap();
    let auth_pk = TaggedPubkey::ml_dsa_44(pk_bytes);

    assert!(verify_credential(&attestation, payload, &auth_pk));
    assert!(!verify_credential(&attestation, b"other payload", &auth_pk));

    let wrong_pk_bytes =
        ace_derive_auth_pubkey_ml_dsa_44_rev32(&mnemonic, "different-pp", vault_context).unwrap();
    let wrong_auth_pk = TaggedPubkey::ml_dsa_44(wrong_pk_bytes);
    assert!(!verify_credential(&attestation, payload, &wrong_auth_pk));
}
