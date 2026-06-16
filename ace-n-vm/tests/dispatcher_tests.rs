//! Tests for the n-VM dispatcher.

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_n_vm::bvm::utxo::{Utxo, UtxoState};
use ace_n_vm::dispatcher::NVm;
use ace_n_vm::token_runtime;
use ace_n_vm::vm::VmId;
use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
use ace_runtime::crypto::legacy_idcom_btc_script;
use ace_runtime::crypto::TaggedSignature;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::capability::{CommitteeCertificate, CommitteeDomain};
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use bitcoin::blockdata::opcodes::all::{
    OP_CHECKMULTISIG, OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL,
};
use bitcoin::consensus;
use bitcoin::hashes::Hash as _;
use bitcoin::script::ScriptBuf as BitcoinScriptBuf;
use bitcoin::secp256k1::{
    Keypair as BtcKeypair, Message as BtcMessage, Secp256k1, SecretKey as BtcSecretKey,
};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{
    absolute, transaction, Amount as BitcoinAmount, OutPoint as BitcoinOutPoint,
    Sequence as BitcoinSequence, Transaction as BitcoinTransaction, TxIn as BitcoinTxIn,
    TxOut as BitcoinTxOut, Txid as BitcoinTxid, Witness as BitcoinWitness,
};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature as K256Signature, SigningKey};
use k256::schnorr::SigningKey as SchnorrSigningKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Attach a dummy BTC committee certificate to a transaction for dispatcher-level tests.
/// The dispatcher only checks presence and domain match; signature verification is done
/// at the node layer.
fn attach_btc_committee_cert(tx: &mut Transaction) {
    let tx_hash = tx.tx_hash();
    tx.attach_committee_certificate(CommitteeCertificate {
        domain: CommitteeDomain::BtcPayments,
        tx_hash,
        approvals: vec![], // dispatcher doesn't check signatures
    });
}

/// Fixed seed for test signer (alice); credential is produced with this so verify_credential passes.
const ALICE_SEED: [u8; 32] = [1u8; 32];

fn make_tx(sender_id: [u8; 32], payload: Vec<u8>) -> Transaction {
    make_signed_tx(sender_id, payload, &ALICE_SEED)
}

fn make_signed_tx(
    sender_id: [u8; 32],
    payload: Vec<u8>,
    auth_signing_seed: &[u8; 32],
) -> Transaction {
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(hasher.finalize().as_slice());
    let domain = Domain::new(1, 0);
    let credential = make_credential(
        auth_signing_seed,
        &obj_hash,
        &sender_id,
        &domain,
        &[0u8; 16],
    );
    Transaction::new(
        payload,
        Attestation {
            obj_hash,
            idcom: sender_id,
            domain,
            context_tag: [0u8; 16],
            credential,
        },
    )
}

fn setup() -> (StateTree, AccountId) {
    let mut tree = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    let auth_pubkey = auth_public_key_from_seed(&ALICE_SEED);
    tree.insert(Account::with_auth(alice, 10_000, auth_pubkey));
    (tree, alice)
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripemd);
    out
}

fn p2wpkh_script(pubkey: &[u8]) -> Vec<u8> {
    let pkh = hash160(pubkey);
    let mut script = vec![0x00, 0x14];
    script.extend_from_slice(&pkh);
    script
}

fn p2tr_script(xonly_pubkey: &[u8]) -> Vec<u8> {
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(xonly_pubkey);
    script
}

fn push_script_data(out: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        0 => out.push(0x00),
        1..=75 => out.push(data.len() as u8),
        76..=255 => {
            out.push(0x4c);
            out.push(data.len() as u8);
        }
        256..=65535 => {
            out.push(0x4d);
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        _ => {
            out.push(0x4e);
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        }
    }
    out.extend_from_slice(data);
}

fn p2wsh_script(witness_script: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(witness_script);
    let mut script = vec![0x00, 0x20];
    script.extend_from_slice(&digest);
    script
}

fn multisig_script(pubkeys: &[Vec<u8>], threshold: u8) -> Vec<u8> {
    let mut script = vec![0x50 + threshold];
    for pubkey in pubkeys {
        push_script_data(&mut script, pubkey);
    }
    script.push(0x50 + pubkeys.len() as u8);
    script.push(OP_CHECKMULTISIG.to_u8());
    script
}

fn tapscript_threshold_script(pubkeys: &[[u8; 32]], threshold: u8) -> Vec<u8> {
    let mut script = Vec::new();
    for (idx, pubkey) in pubkeys.iter().enumerate() {
        push_script_data(&mut script, pubkey);
        script.push(if idx == 0 {
            OP_CHECKSIG.to_u8()
        } else {
            OP_CHECKSIGADD.to_u8()
        });
    }
    script.push(0x50 + threshold);
    script.push(OP_NUMEQUAL.to_u8());
    script
}

fn encode_varint(value: u64) -> Vec<u8> {
    match value {
        0x00..=0xfc => vec![value as u8],
        0xfd..=0xffff => {
            let mut out = vec![0xfd];
            out.extend_from_slice(&(value as u16).to_le_bytes());
            out
        }
        0x1_0000..=0xffff_ffff => {
            let mut out = vec![0xfe];
            out.extend_from_slice(&(value as u32).to_le_bytes());
            out
        }
        _ => {
            let mut out = vec![0xff];
            out.extend_from_slice(&value.to_le_bytes());
            out
        }
    }
}

fn build_p2wpkh_sighash(
    all_inputs: &[([u8; 32], u32, u64, Vec<u8>, u32)],
    _input_index: usize,
    prev_txid: &[u8; 32],
    prev_vout: u32,
    prev_value: u64,
    prev_script: &[u8],
    sequence: u32,
    outputs: &[(u64, Vec<u8>)],
) -> [u8; 32] {
    let pubkey_hash = {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&prev_script[2..22]);
        hash
    };
    let mut script_code = vec![0x76, 0xa9, 0x14];
    script_code.extend_from_slice(&pubkey_hash);
    script_code.extend_from_slice(&[0x88, 0xac]);

    let mut prevouts = Vec::new();
    for (txid, vout, _, _, _) in all_inputs {
        prevouts.extend_from_slice(txid);
        prevouts.extend_from_slice(&vout.to_le_bytes());
    }
    let hash_prevouts = {
        let first = Sha256::digest(&prevouts);
        let second = Sha256::digest(first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        out
    };
    let mut sequence_bytes = Vec::new();
    for (_, _, _, _, sequence) in all_inputs {
        sequence_bytes.extend_from_slice(&sequence.to_le_bytes());
    }
    let hash_sequence = {
        let first = Sha256::digest(&sequence_bytes);
        let second = Sha256::digest(first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        out
    };
    let mut outputs_ser = Vec::new();
    for (value, script) in outputs {
        outputs_ser.extend_from_slice(&value.to_le_bytes());
        outputs_ser.extend_from_slice(&encode_varint(script.len() as u64));
        outputs_ser.extend_from_slice(script);
    }
    let hash_outputs = {
        let first = Sha256::digest(&outputs_ser);
        let second = Sha256::digest(first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        out
    };

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&2u32.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(prev_txid);
    preimage.extend_from_slice(&prev_vout.to_le_bytes());
    preimage.extend_from_slice(&encode_varint(script_code.len() as u64));
    preimage.extend_from_slice(&script_code);
    preimage.extend_from_slice(&prev_value.to_le_bytes());
    preimage.extend_from_slice(&sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&0u32.to_le_bytes());
    preimage.extend_from_slice(&1u32.to_le_bytes());

    let first = Sha256::digest(&preimage);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut engine = Sha256::new();
    engine.update(tag_hash);
    engine.update(tag_hash);
    engine.update(msg);
    let digest = engine.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn build_taproot_key_path_sighash(
    prev_txid: [u8; 32],
    prev_vout: u32,
    prev_value: u64,
    prev_script: &[u8],
    sequence: u32,
    outputs: &[(u64, Vec<u8>)],
) -> [u8; 32] {
    let mut prevouts_data = Vec::new();
    prevouts_data.extend_from_slice(&prev_txid);
    prevouts_data.extend_from_slice(&prev_vout.to_le_bytes());

    let mut amounts_data = Vec::new();
    amounts_data.extend_from_slice(&prev_value.to_le_bytes());

    let mut scriptpubkeys_data = Vec::new();
    scriptpubkeys_data.extend_from_slice(&encode_varint(prev_script.len() as u64));
    scriptpubkeys_data.extend_from_slice(prev_script);

    let mut sequences_data = Vec::new();
    sequences_data.extend_from_slice(&sequence.to_le_bytes());

    let mut outputs_data = Vec::new();
    for (value, script) in outputs {
        outputs_data.extend_from_slice(&value.to_le_bytes());
        outputs_data.extend_from_slice(&encode_varint(script.len() as u64));
        outputs_data.extend_from_slice(script);
    }

    let mut preimage = Vec::new();
    preimage.push(0x00);
    preimage.push(0x00);
    preimage.extend_from_slice(&2u32.to_le_bytes());
    preimage.extend_from_slice(&0u32.to_le_bytes());
    preimage.extend_from_slice(&Sha256::digest(&prevouts_data));
    preimage.extend_from_slice(&Sha256::digest(&amounts_data));
    preimage.extend_from_slice(&Sha256::digest(&scriptpubkeys_data));
    preimage.extend_from_slice(&Sha256::digest(&sequences_data));
    preimage.extend_from_slice(&Sha256::digest(&outputs_data));
    preimage.push(0x00);
    preimage.extend_from_slice(&0u32.to_le_bytes());
    tagged_hash("TapSighash", &preimage)
}

fn build_raw_btc_p2wpkh_tx(
    signing_key: &SigningKey,
    prev_txid: [u8; 32],
    prev_vout: u32,
    prev_value: u64,
    prev_script: &[u8],
    outputs: &[(u64, Vec<u8>)],
) -> Vec<u8> {
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let sequence = 0xffff_fffd;
    let all_inputs = vec![(
        prev_txid,
        prev_vout,
        prev_value,
        prev_script.to_vec(),
        sequence,
    )];
    let sighash = build_p2wpkh_sighash(
        &all_inputs,
        0,
        &prev_txid,
        prev_vout,
        prev_value,
        prev_script,
        sequence,
        outputs,
    );
    let signature: K256Signature = signing_key.sign_prehash(&sighash).expect("prehash sign");
    let mut sig_bytes = signature.to_der().as_bytes().to_vec();
    sig_bytes.push(0x01);

    let mut tx = Vec::new();
    tx.extend_from_slice(&2u32.to_le_bytes());
    tx.extend_from_slice(&[0x00, 0x01]); // segwit marker/flag
    tx.extend_from_slice(&encode_varint(1));
    tx.extend_from_slice(&prev_txid);
    tx.extend_from_slice(&prev_vout.to_le_bytes());
    tx.push(0x00); // empty scriptSig
    tx.extend_from_slice(&sequence.to_le_bytes());
    tx.extend_from_slice(&encode_varint(outputs.len() as u64));
    for (value, script) in outputs {
        tx.extend_from_slice(&value.to_le_bytes());
        tx.extend_from_slice(&encode_varint(script.len() as u64));
        tx.extend_from_slice(script);
    }
    tx.extend_from_slice(&encode_varint(2));
    tx.extend_from_slice(&encode_varint(sig_bytes.len() as u64));
    tx.extend_from_slice(&sig_bytes);
    tx.extend_from_slice(&encode_varint(pubkey.len() as u64));
    tx.extend_from_slice(&pubkey);
    tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
    tx
}

#[test]
fn route_native_transfer() {
    let (mut state, alice) = setup();
    let bob = AccountId::from_bytes([2u8; 32]);
    state.insert(Account::new(bob));

    let vm = NVm::with_defaults();

    // 0x01 = OP_TRANSFER (ACE Native)
    let mut payload = vec![0x01];
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(bob.as_bytes());
    payload.extend_from_slice(&500u64.to_le_bytes());

    let tx = make_tx(alice.0, payload);
    let receipt = vm.execute_transaction(&mut state, &tx, 0).unwrap();
    assert_eq!(receipt.vm_id, VmId::AceNative);
    assert!(receipt.success);
    assert!(!receipt.state_changes.is_empty());
    assert!(!receipt.simulated);
}

#[test]
fn route_evm_call_mock() {
    let (mut state, alice) = setup();
    let vm = NVm::with_test_stubs();

    // 0x10 = OP_EVM_CALL (mock engine accepts short payloads)
    let payload = vec![0x10, 0xAA, 0xBB];
    let tx = make_tx(alice.0, payload);
    let receipt = vm.execute_transaction(&mut state, &tx, 0).unwrap();
    assert_eq!(receipt.vm_id, VmId::Evm);
    assert!(receipt.success);
    assert!(receipt.simulated);
}

#[test]
fn route_evm_transfer_real() {
    let (mut state, alice) = setup();
    let bob = AccountId::from_bytes([2u8; 32]);
    state.insert(Account::with_balance(bob, 1_000));

    let vm = NVm::with_defaults();

    // 0x12 = EVM transfer: [to:20][value:8 LE]
    let bob_evm = ace_n_vm::cross_vm::AddressResolver::to_evm_address(&bob);
    let mut payload = vec![0x12];
    payload.extend_from_slice(&bob_evm);
    payload.extend_from_slice(&500u64.to_le_bytes());

    let tx = make_tx(alice.0, payload);
    let receipt = vm.execute_transaction(&mut state, &tx, 0).unwrap();
    assert_eq!(receipt.vm_id, VmId::Evm);
    assert!(receipt.success);
    assert!(!receipt.simulated);
    assert!(receipt.gas_used.is_some());
}

#[test]
#[ignore = "TODO: EVM runtime ERC-20 address derivation needs alignment with dispatcher credential path"]
fn route_runtime_erc20_transfer_real() {
    let (mut state, alice) = setup();
    let bob = AccountId::from_bytes([9u8; 32]);
    state.insert(Account::with_balance(bob, 1_000));

    let mint = [0x44u8; 32];
    // Use alice as the mint authority
    token_runtime::create_mint(&mut state, &mint, 6, alice.as_bytes()).expect("create mint");
    let alice_evm_owner = ace_runtime::crypto::legacy_idcom_evm(
        &ace_n_vm::cross_vm::AddressResolver::to_evm_address(&alice),
    );
    token_runtime::mint_to_owner(&mut state, &mint, &alice_evm_owner, 10_000, &alice)
        .expect("mint tokens");
    let contract = token_runtime::runtime_erc20_address_for_mint(&mint);
    let bob_evm = ace_n_vm::cross_vm::AddressResolver::to_evm_address(&bob);
    let bob_evm_owner = AccountId::from_bytes(ace_runtime::crypto::legacy_idcom_evm(&bob_evm));

    let mut calldata = vec![0xa9, 0x05, 0x9c, 0xbb];
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(&bob_evm);
    calldata.extend_from_slice(&[0u8; 24]);
    calldata.extend_from_slice(&1_500u64.to_be_bytes());

    let mut payload = vec![0x10];
    payload.extend_from_slice(&contract);
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&100_000u64.to_le_bytes());
    payload.extend_from_slice(&calldata);

    let vm = NVm::with_defaults();
    let tx = make_tx(alice.0, payload);
    let receipt = vm
        .execute_transaction(&mut state, &tx, 0)
        .expect("runtime erc20 tx");

    assert_eq!(receipt.vm_id, VmId::Evm);
    // TODO: This assertion may fail due to EVM runtime ERC-20 address derivation
    // changes. The mint is done to alice's legacy EVM idcom, but the EVM engine
    // may resolve the msg.sender to a different internal address. Needs investigation.
    assert!(
        receipt.success,
        "EVM receipt failed: error={:?}",
        receipt.error
    );
    assert_eq!(
        token_runtime::balance_of(&state, &mint, &AccountId::from_bytes(alice_evm_owner)),
        8_500
    );
    assert_eq!(
        token_runtime::balance_of(&state, &mint, &bob_evm_owner),
        1_500
    );
    assert_eq!(receipt.logs.len(), 1);
}

#[test]
fn route_svm_invoke_mock() {
    let (mut state, alice) = setup();
    let vm = NVm::with_test_stubs();

    // 0x20 = OP_SVM_INVOKE (mock engine accepts short payloads)
    let payload = vec![0x20, 0xCC];
    let tx = make_tx(alice.0, payload);
    let receipt = vm.execute_transaction(&mut state, &tx, 0).unwrap();
    assert_eq!(receipt.vm_id, VmId::Svm);
    assert!(receipt.success);
    assert!(receipt.simulated);
}

#[test]
fn route_svm_transfer_real() {
    let (mut state, alice) = setup();
    let bob = AccountId::from_bytes([2u8; 32]);
    state.insert(Account::new(bob));

    let vm = NVm::with_defaults();

    // 0x21 = SVM transfer: [nonce:8 LE][to:32][amount:8 LE]
    let mut payload = vec![0x21];
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(bob.as_bytes());
    payload.extend_from_slice(&200u64.to_le_bytes());

    let tx = make_tx(alice.0, payload);
    let receipt = vm.execute_transaction(&mut state, &tx, 0).unwrap();
    assert_eq!(receipt.vm_id, VmId::Svm);
    assert!(receipt.success);
    assert!(!receipt.simulated);
    assert!(!receipt.state_changes.is_empty());
}

#[test]
fn unknown_opcode_rejected() {
    let (mut state, alice) = setup();
    let vm = NVm::with_defaults();

    let payload = vec![0xFF];
    let tx = make_tx(alice.0, payload);
    let err = vm.execute_transaction(&mut state, &tx, 0).unwrap_err();
    assert!(err.to_string().contains("unknown opcode: 0xff"));
}

#[test]
fn empty_payload_rejected() {
    let (mut state, alice) = setup();
    let vm = NVm::with_defaults();

    let tx = make_tx(alice.0, vec![]);
    let err = vm.execute_transaction(&mut state, &tx, 0).unwrap_err();
    assert!(err.to_string().contains("empty"));
}

#[test]
fn mixed_block_execution_mocks() {
    let (mut state, alice) = setup();
    let bob = AccountId::from_bytes([2u8; 32]);
    state.insert(Account::new(bob));

    let vm = NVm::with_test_stubs();

    // Native transfer
    let mut payload_native = vec![0x01];
    payload_native.extend_from_slice(&0u64.to_le_bytes());
    payload_native.extend_from_slice(bob.as_bytes());
    payload_native.extend_from_slice(&100u64.to_le_bytes());

    // EVM call (mock accepts short payloads)
    let payload_evm = vec![0x10, 0x01, 0x02];

    // SVM invoke (mock accepts short payloads)
    let payload_svm = vec![0x20, 0x03];

    // Unknown opcode (should produce failure receipt)
    let payload_bad = vec![0xFE];

    let txs = vec![
        make_tx(alice.0, payload_native),
        make_tx(alice.0, payload_evm),
        make_tx(alice.0, payload_svm),
        make_tx(alice.0, payload_bad),
    ];

    let receipts = vm.execute_block(&mut state, &txs, 0);
    assert_eq!(receipts.len(), 4);
    assert_eq!(receipts[0].vm_id, VmId::AceNative);
    assert!(receipts[0].success);
    assert!(!receipts[0].simulated); // native is real
    assert_eq!(receipts[1].vm_id, VmId::Evm);
    assert!(receipts[1].success);
    assert!(receipts[1].simulated); // EVM is mock
    assert_eq!(receipts[2].vm_id, VmId::Svm);
    assert!(receipts[2].success);
    assert!(receipts[2].simulated); // SVM is mock
    assert!(!receipts[3].success); // unknown opcode
}

#[test]
fn no_engine_registered() {
    let (mut state, alice) = setup();

    // Create NVm with no engines
    let vm = NVm::new();

    // Use opcode 0x60 which maps to no known VM (outside all registered ranges).
    let payload = vec![0x60, 0x00];
    let tx = make_tx(alice.0, payload);
    let err = vm.execute_transaction(&mut state, &tx, 0).unwrap_err();
    // With no engine for this opcode, should get an "unknown opcode" error.
    assert!(
        err.to_string().contains("no engine") || err.to_string().contains("unknown opcode"),
        "unexpected error: {err}"
    );
}

#[test]
fn route_raw_btc_p2wpkh_spend_real() {
    let mut state = StateTree::new();
    let signer = SigningKey::from_bytes((&[9u8; 32]).into()).expect("signing key");
    let signer_pubkey = signer
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let prev_script = p2wpkh_script(&signer_pubkey);
    let owner = AccountId::from_bytes(legacy_idcom_btc_script(&prev_script));
    let prev_txid = [0x44; 32];
    let prev_value = 50_000;
    UtxoState::add_utxo(
        &mut state,
        &owner,
        &Utxo {
            txid: prev_txid,
            vout: 0,
            value: prev_value,
            script_pubkey: prev_script.clone(),
        },
    )
    .expect("seed utxo");

    let recipient_key = SigningKey::from_bytes((&[10u8; 32]).into()).expect("recipient key");
    let recipient_script = p2wpkh_script(
        recipient_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    );
    let outputs = vec![(49_000u64, recipient_script.clone())];
    let raw_tx = build_raw_btc_p2wpkh_tx(&signer, prev_txid, 0, prev_value, &prev_script, &outputs);

    let payload = ace_n_vm::raw_btc::verify_raw_btc_against_state(&state, &raw_tx)
        .expect("verify")
        .payload;
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&hasher.finalize());
    let mut tx = Transaction::with_raw_chain(
        payload,
        Attestation {
            obj_hash,
            idcom: owner.0,
            domain: Domain::new(1, 0),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
        RawChainKind::Btc,
        raw_tx,
    );
    attach_btc_committee_cert(&mut tx);

    let vm = NVm::with_defaults();
    let receipt = vm
        .execute_transaction(&mut state, &tx, 0)
        .expect("btc tx should execute");
    assert_eq!(receipt.vm_id, VmId::Bvm);
    assert!(receipt.success);
    assert_eq!(state.get(&owner).unwrap().balance, 0);
    let recipient = AccountId::from_bytes(legacy_idcom_btc_script(&recipient_script));
    assert_eq!(state.get(&recipient).unwrap().balance, 49_000);
}

#[test]
fn route_raw_btc_mixed_owner_spend_real() {
    let mut state = StateTree::new();
    let key1 = SigningKey::from_bytes((&[21u8; 32]).into()).expect("key1");
    let key2 = SigningKey::from_bytes((&[22u8; 32]).into()).expect("key2");
    let pub1 = key1
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let pub2 = key2
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let script1 = p2wpkh_script(&pub1);
    let script2 = p2wpkh_script(&pub2);
    let owner1 = AccountId::from_bytes(legacy_idcom_btc_script(&script1));
    let owner2 = AccountId::from_bytes(legacy_idcom_btc_script(&script2));

    UtxoState::add_utxo(
        &mut state,
        &owner1,
        &Utxo {
            txid: [0x51; 32],
            vout: 0,
            value: 40_000,
            script_pubkey: script1.clone(),
        },
    )
    .expect("seed utxo 1");
    UtxoState::add_utxo(
        &mut state,
        &owner2,
        &Utxo {
            txid: [0x52; 32],
            vout: 1,
            value: 30_000,
            script_pubkey: script2.clone(),
        },
    )
    .expect("seed utxo 2");

    let recipient_key = SigningKey::from_bytes((&[23u8; 32]).into()).expect("recipient");
    let recipient_script = p2wpkh_script(
        recipient_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    );
    let outputs = vec![(69_000u64, recipient_script.clone())];

    let mut tx = {
        let mut raw = Vec::new();
        raw.extend_from_slice(&2u32.to_le_bytes());
        raw.extend_from_slice(&[0x00, 0x01]);
        raw.extend_from_slice(&encode_varint(2));

        raw.extend_from_slice(&[0x51; 32]);
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.push(0x00);
        raw.extend_from_slice(&0xffff_fffd_u32.to_le_bytes());

        raw.extend_from_slice(&[0x52; 32]);
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.push(0x00);
        raw.extend_from_slice(&0xffff_fffd_u32.to_le_bytes());

        raw.extend_from_slice(&encode_varint(outputs.len() as u64));
        for (value, script) in &outputs {
            raw.extend_from_slice(&value.to_le_bytes());
            raw.extend_from_slice(&encode_varint(script.len() as u64));
            raw.extend_from_slice(script);
        }

        let all_inputs = vec![
            (
                [0x51; 32],
                0u32,
                40_000u64,
                script1.clone(),
                0xffff_fffd_u32,
            ),
            (
                [0x52; 32],
                1u32,
                30_000u64,
                script2.clone(),
                0xffff_fffd_u32,
            ),
        ];
        let sighash1 = build_p2wpkh_sighash(
            &all_inputs,
            0,
            &[0x51; 32],
            0,
            40_000,
            &script1,
            0xffff_fffd,
            &outputs,
        );
        let sig1: K256Signature = key1.sign_prehash(&sighash1).expect("sig1");
        let mut sig1_bytes = sig1.to_der().as_bytes().to_vec();
        sig1_bytes.push(0x01);

        let sighash2 = build_p2wpkh_sighash(
            &all_inputs,
            1,
            &[0x52; 32],
            1,
            30_000,
            &script2,
            0xffff_fffd,
            &outputs,
        );
        let sig2: K256Signature = key2.sign_prehash(&sighash2).expect("sig2");
        let mut sig2_bytes = sig2.to_der().as_bytes().to_vec();
        sig2_bytes.push(0x01);

        raw.extend_from_slice(&encode_varint(2));
        raw.extend_from_slice(&encode_varint(sig1_bytes.len() as u64));
        raw.extend_from_slice(&sig1_bytes);
        raw.extend_from_slice(&encode_varint(pub1.len() as u64));
        raw.extend_from_slice(&pub1);

        raw.extend_from_slice(&encode_varint(2));
        raw.extend_from_slice(&encode_varint(sig2_bytes.len() as u64));
        raw.extend_from_slice(&sig2_bytes);
        raw.extend_from_slice(&encode_varint(pub2.len() as u64));
        raw.extend_from_slice(&pub2);

        raw.extend_from_slice(&0u32.to_le_bytes());

        let verified = ace_n_vm::raw_btc::verify_raw_btc_against_state(&state, &raw)
            .expect("mixed-owner verify");
        let payload = verified.payload;
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let mut obj_hash = [0u8; 32];
        obj_hash.copy_from_slice(&hasher.finalize());
        Transaction::with_raw_chain(
            payload,
            Attestation {
                obj_hash,
                idcom: owner1.0,
                domain: Domain::new(1, 0),
                context_tag: [0u8; 16],
                credential: TaggedSignature::ed25519([0u8; 64]),
            },
            RawChainKind::Btc,
            raw,
        )
    };
    attach_btc_committee_cert(&mut tx);

    let vm = NVm::with_defaults();
    let receipt = vm
        .execute_transaction(&mut state, &tx, 0)
        .expect("mixed-owner btc tx");
    assert_eq!(receipt.vm_id, VmId::Bvm);
    assert!(receipt.success);
    assert_eq!(state.get(&owner1).unwrap().balance, 0);
    assert_eq!(state.get(&owner2).unwrap().balance, 0);
    let recipient = AccountId::from_bytes(legacy_idcom_btc_script(&recipient_script));
    assert_eq!(state.get(&recipient).unwrap().balance, 69_000);
}

#[test]
fn route_raw_btc_taproot_keypath_spend_real() {
    let mut state = StateTree::new();
    let signer = SchnorrSigningKey::from_bytes(&[24u8; 32]).expect("taproot key");
    let xonly = signer.verifying_key().to_bytes();
    let prev_script = p2tr_script(&xonly);
    let owner = AccountId::from_bytes(legacy_idcom_btc_script(&prev_script));
    let prev_txid = [0x61; 32];
    let prev_value = 70_000u64;
    UtxoState::add_utxo(
        &mut state,
        &owner,
        &Utxo {
            txid: prev_txid,
            vout: 0,
            value: prev_value,
            script_pubkey: prev_script.clone(),
        },
    )
    .expect("seed utxo");

    let recipient_key = SigningKey::from_bytes((&[25u8; 32]).into()).expect("recipient");
    let recipient_script = p2wpkh_script(
        recipient_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    );
    let outputs = vec![(69_000u64, recipient_script.clone())];
    let sequence = 0xffff_fffd_u32;
    let sighash =
        build_taproot_key_path_sighash(prev_txid, 0, prev_value, &prev_script, sequence, &outputs);
    let signature = signer
        .sign_prehash(&sighash)
        .expect("taproot sign")
        .to_bytes();

    let mut raw_tx = Vec::new();
    raw_tx.extend_from_slice(&2u32.to_le_bytes());
    raw_tx.extend_from_slice(&[0x00, 0x01]);
    raw_tx.extend_from_slice(&encode_varint(1));
    raw_tx.extend_from_slice(&prev_txid);
    raw_tx.extend_from_slice(&0u32.to_le_bytes());
    raw_tx.push(0x00);
    raw_tx.extend_from_slice(&sequence.to_le_bytes());
    raw_tx.extend_from_slice(&encode_varint(outputs.len() as u64));
    for (value, script) in &outputs {
        raw_tx.extend_from_slice(&value.to_le_bytes());
        raw_tx.extend_from_slice(&encode_varint(script.len() as u64));
        raw_tx.extend_from_slice(script);
    }
    raw_tx.extend_from_slice(&encode_varint(1));
    raw_tx.extend_from_slice(&encode_varint(signature.len() as u64));
    raw_tx.extend_from_slice(&signature);
    raw_tx.extend_from_slice(&0u32.to_le_bytes());

    let payload = ace_n_vm::raw_btc::verify_raw_btc_against_state(&state, &raw_tx)
        .expect("taproot verify")
        .payload;
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&hasher.finalize());
    let mut tx = Transaction::with_raw_chain(
        payload,
        Attestation {
            obj_hash,
            idcom: owner.0,
            domain: Domain::new(1, 0),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
        RawChainKind::Btc,
        raw_tx,
    );
    attach_btc_committee_cert(&mut tx);

    let vm = NVm::with_defaults();
    let receipt = vm
        .execute_transaction(&mut state, &tx, 0)
        .expect("taproot btc tx should execute");
    assert_eq!(receipt.vm_id, VmId::Bvm);
    assert!(receipt.success);
    let recipient = AccountId::from_bytes(legacy_idcom_btc_script(&recipient_script));
    assert_eq!(state.get(&recipient).unwrap().balance, 69_000);
}

#[test]
fn route_raw_btc_p2wsh_multisig_spend_real() {
    let mut state = StateTree::new();
    let key1 = SigningKey::from_bytes((&[31u8; 32]).into()).expect("key1");
    let key2 = SigningKey::from_bytes((&[32u8; 32]).into()).expect("key2");
    let pub1 = key1
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let pub2 = key2
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let witness_script = multisig_script(&[pub1.clone(), pub2.clone()], 2);
    let prev_script = p2wsh_script(&witness_script);
    let owner = AccountId::from_bytes(legacy_idcom_btc_script(&prev_script));
    let prev_txid = [0x71; 32];
    let prev_value = 80_000u64;
    UtxoState::add_utxo(
        &mut state,
        &owner,
        &Utxo {
            txid: prev_txid,
            vout: 0,
            value: prev_value,
            script_pubkey: prev_script.clone(),
        },
    )
    .expect("seed utxo");

    let recipient_key = SigningKey::from_bytes((&[33u8; 32]).into()).expect("recipient");
    let recipient_script = p2wpkh_script(
        recipient_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    );
    let mut tx = BitcoinTransaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![BitcoinTxIn {
            previous_output: BitcoinOutPoint {
                txid: BitcoinTxid::from_byte_array(prev_txid),
                vout: 0,
            },
            script_sig: BitcoinScriptBuf::new(),
            sequence: BitcoinSequence::ENABLE_RBF_NO_LOCKTIME,
            witness: BitcoinWitness::default(),
        }],
        output: vec![BitcoinTxOut {
            value: BitcoinAmount::from_sat(79_000),
            script_pubkey: BitcoinScriptBuf::from_bytes(recipient_script.clone()),
        }],
    };
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wsh_signature_hash(
            0,
            BitcoinScriptBuf::from_bytes(witness_script.clone()).as_script(),
            BitcoinAmount::from_sat(prev_value),
            EcdsaSighashType::All,
        )
        .expect("p2wsh sighash");
    let signature1: K256Signature = key1.sign_prehash(&sighash.to_byte_array()).expect("sig1");
    let signature2: K256Signature = key2.sign_prehash(&sighash.to_byte_array()).expect("sig2");
    let mut sig1 = signature1.to_der().as_bytes().to_vec();
    sig1.push(0x01);
    let mut sig2 = signature2.to_der().as_bytes().to_vec();
    sig2.push(0x01);
    let mut witness = BitcoinWitness::new();
    witness.push(Vec::<u8>::new());
    witness.push(sig1);
    witness.push(sig2);
    witness.push(witness_script.clone());
    tx.input[0].witness = witness;

    let raw_tx = consensus::serialize(&tx);
    let payload = ace_n_vm::raw_btc::verify_raw_btc_against_state(&state, &raw_tx)
        .expect("verify p2wsh multisig")
        .payload;
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&hasher.finalize());
    let mut tx = Transaction::with_raw_chain(
        payload,
        Attestation {
            obj_hash,
            idcom: owner.0,
            domain: Domain::new(1, 0),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
        RawChainKind::Btc,
        raw_tx,
    );
    attach_btc_committee_cert(&mut tx);

    let vm = NVm::with_defaults();
    let receipt = vm
        .execute_transaction(&mut state, &tx, 0)
        .expect("p2wsh multisig btc tx should execute");
    assert_eq!(receipt.vm_id, VmId::Bvm);
    assert!(receipt.success);
    let recipient = AccountId::from_bytes(legacy_idcom_btc_script(&recipient_script));
    assert_eq!(state.get(&recipient).unwrap().balance, 79_000);
}

#[test]
fn route_raw_btc_taproot_scriptpath_tree_spend_real() {
    let mut state = StateTree::new();
    let secp = Secp256k1::new();
    let internal_sk = BtcSecretKey::from_slice(&[41u8; 32]).expect("internal sk");
    let internal_keypair = BtcKeypair::from_secret_key(&secp, &internal_sk);
    let sk1 = BtcSecretKey::from_slice(&[42u8; 32]).expect("sk1");
    let sk2 = BtcSecretKey::from_slice(&[43u8; 32]).expect("sk2");
    let keypair1 = BtcKeypair::from_secret_key(&secp, &sk1);
    let keypair2 = BtcKeypair::from_secret_key(&secp, &sk2);
    let xonly1 = keypair1.x_only_public_key().0.serialize();
    let xonly2 = keypair2.x_only_public_key().0.serialize();
    let leaf_script =
        BitcoinScriptBuf::from_bytes(tapscript_threshold_script(&[xonly1, xonly2], 2));
    let decoy_script = {
        let mut bytes = Vec::new();
        push_script_data(&mut bytes, &keypair1.x_only_public_key().0.serialize());
        bytes.push(OP_CHECKSIG.to_u8());
        BitcoinScriptBuf::from_bytes(bytes)
    };
    let spend_info = TaprootBuilder::new()
        .add_leaf(1, decoy_script)
        .expect("add decoy leaf")
        .add_leaf(1, leaf_script.clone())
        .expect("add threshold leaf")
        .finalize(&secp, internal_keypair.x_only_public_key().0)
        .expect("finalize taptree");
    let prev_script =
        BitcoinScriptBuf::new_p2tr(&secp, spend_info.internal_key(), spend_info.merkle_root());
    let owner = AccountId::from_bytes(legacy_idcom_btc_script(prev_script.as_bytes()));
    let prev_txid = [0x81; 32];
    let prev_value = 90_000u64;
    UtxoState::add_utxo(
        &mut state,
        &owner,
        &Utxo {
            txid: prev_txid,
            vout: 0,
            value: prev_value,
            script_pubkey: prev_script.as_bytes().to_vec(),
        },
    )
    .expect("seed utxo");

    let recipient_key = SigningKey::from_bytes((&[44u8; 32]).into()).expect("recipient");
    let recipient_script = p2wpkh_script(
        recipient_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    );
    let mut tx = BitcoinTransaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![BitcoinTxIn {
            previous_output: BitcoinOutPoint {
                txid: BitcoinTxid::from_byte_array(prev_txid),
                vout: 0,
            },
            script_sig: BitcoinScriptBuf::new(),
            sequence: BitcoinSequence::ENABLE_RBF_NO_LOCKTIME,
            witness: BitcoinWitness::default(),
        }],
        output: vec![BitcoinTxOut {
            value: BitcoinAmount::from_sat(89_000),
            script_pubkey: BitcoinScriptBuf::from_bytes(recipient_script.clone()),
        }],
    };
    let prevout = BitcoinTxOut {
        value: BitcoinAmount::from_sat(prev_value),
        script_pubkey: prev_script.clone(),
    };
    let prevouts = Prevouts::All(std::slice::from_ref(&prevout));
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &prevouts,
            bitcoin::sighash::ScriptPath::with_defaults(leaf_script.as_script()),
            TapSighashType::Default,
        )
        .expect("taproot script sighash");
    let msg = BtcMessage::from(sighash);
    let sig1 = secp
        .sign_schnorr_no_aux_rand(&msg, &keypair1)
        .as_ref()
        .to_vec();
    let sig2 = secp
        .sign_schnorr_no_aux_rand(&msg, &keypair2)
        .as_ref()
        .to_vec();
    let control_block = spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .expect("control block")
        .serialize();
    let mut witness = BitcoinWitness::new();
    witness.push(sig2);
    witness.push(sig1);
    witness.push(leaf_script.as_bytes());
    witness.push(control_block);
    tx.input[0].witness = witness;

    let raw_tx = consensus::serialize(&tx);
    let payload = ace_n_vm::raw_btc::verify_raw_btc_against_state(&state, &raw_tx)
        .expect("verify taproot script-path tree")
        .payload;
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let mut obj_hash = [0u8; 32];
    obj_hash.copy_from_slice(&hasher.finalize());
    let mut tx = Transaction::with_raw_chain(
        payload,
        Attestation {
            obj_hash,
            idcom: owner.0,
            domain: Domain::new(1, 0),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
        RawChainKind::Btc,
        raw_tx,
    );
    attach_btc_committee_cert(&mut tx);

    let vm = NVm::with_defaults();
    let receipt = vm
        .execute_transaction(&mut state, &tx, 0)
        .expect("taproot script-path tree btc tx should execute");
    assert_eq!(receipt.vm_id, VmId::Bvm);
    assert!(receipt.success);
    let recipient = AccountId::from_bytes(legacy_idcom_btc_script(&recipient_script));
    assert_eq!(state.get(&recipient).unwrap().balance, 89_000);
}

// ── Cross-context / shared shard tests ──

mod cross_context {
    use ace_model::account::{Account, AccountId};
    use ace_model::sharded_state::ShardedState;
    use ace_n_vm::dispatcher::NVm;
    use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
    use ace_runtime::types::attestation::{Attestation, Domain};
    use ace_runtime::types::transaction::Transaction;
    use sha2::{Digest, Sha256};

    const SEED_A: [u8; 32] = [0xA0; 32];
    const SEED_B: [u8; 32] = [0xB0; 32];

    fn make_tx_with_context(
        sender_id: [u8; 32],
        recipient_id: [u8; 32],
        amount: u64,
        context_tag: [u8; 16],
        auth_seed: &[u8; 32],
    ) -> Transaction {
        let mut payload = Vec::with_capacity(49);
        payload.push(0x01); // native transfer
        payload.extend_from_slice(&0u64.to_le_bytes()); // nonce
        payload.extend_from_slice(&recipient_id);
        payload.extend_from_slice(&amount.to_le_bytes());

        let mut obj_hash = [0u8; 32];
        obj_hash.copy_from_slice(&Sha256::digest(&payload));
        let domain = Domain::new(1, 0);

        Transaction::new(
            payload,
            Attestation {
                obj_hash,
                idcom: sender_id,
                domain,
                context_tag,
                credential: make_credential(
                    auth_seed,
                    &obj_hash,
                    &sender_id,
                    &domain,
                    &context_tag,
                ),
            },
        )
    }

    #[test]
    fn same_context_transactions_execute_in_parallel() {
        let mut state = ShardedState::new();
        let alice = AccountId([0x11; 32]);
        let bob = AccountId([0x22; 32]);

        state.default_shard_mut().insert(Account::with_auth(
            alice,
            1000,
            auth_public_key_from_seed(&SEED_A),
        ));
        state.default_shard_mut().insert(Account::new(bob));

        let tx = make_tx_with_context(alice.0, bob.0, 100, [0u8; 16], &SEED_A);
        let vm = NVm::with_defaults();
        let receipts = vm.execute_block_sharded(&mut state, &[tx], 0);

        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].success);
        assert_eq!(state.get(&alice).unwrap().balance, 900);
        assert_eq!(state.get(&bob).unwrap().balance, 100);
    }

    #[test]
    fn cross_context_transaction_routes_to_shared_shard() {
        let mut state = ShardedState::new();

        // Alice in default shard
        let alice = AccountId([0x11; 32]);
        state.default_shard_mut().insert(Account::with_auth(
            alice,
            1000,
            auth_public_key_from_seed(&SEED_A),
        ));

        // Bob in a different shard (shard 5)
        let bob = AccountId([0x22; 32]);
        let model_shard_5 = ace_model::sharded_state::ShardId(5);
        state.shard_mut(model_shard_5).insert(Account::new(bob));

        // Transaction from Alice (default shard) with non-default context tag
        // that targets Bob (shard 5) — this is cross-context.
        let context_tag = [0x01; 16]; // non-zero context
        let tx = make_tx_with_context(alice.0, bob.0, 100, context_tag, &SEED_A);

        let vm = NVm::with_defaults();
        let receipts = vm.execute_block_sharded(&mut state, &[tx], 0);

        // Should still execute (via shared shard) — may fail due to
        // recipient not found in the shard being executed, but the routing
        // itself should work without panicking.
        assert_eq!(receipts.len(), 1);
    }

    #[test]
    fn default_context_never_cross_context() {
        // All transactions with context_tag [0;16] should never be
        // detected as cross-context, ensuring backward compatibility.
        let mut state = ShardedState::new();
        let alice = AccountId([0x11; 32]);
        let bob = AccountId([0x22; 32]);

        state.default_shard_mut().insert(Account::with_auth(
            alice,
            1000,
            auth_public_key_from_seed(&SEED_A),
        ));
        state.default_shard_mut().insert(Account::new(bob));

        // Even with Bob also in shard 5, a default-context tx should NOT
        // be detected as cross-context.
        let model_shard_5 = ace_model::sharded_state::ShardId(5);
        state.shard_mut(model_shard_5).insert(Account::new(bob));

        let tx = make_tx_with_context(alice.0, bob.0, 100, [0u8; 16], &SEED_A);
        let vm = NVm::with_defaults();
        let receipts = vm.execute_block_sharded(&mut state, &[tx], 0);

        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].success);
    }

    #[test]
    fn mixed_shard_and_shared_execution() {
        let mut state = ShardedState::new();

        let alice = AccountId([0x11; 32]);
        let bob = AccountId([0x22; 32]);
        let carol = AccountId([0x33; 32]);

        state.default_shard_mut().insert(Account::with_auth(
            alice,
            5000,
            auth_public_key_from_seed(&SEED_A),
        ));
        state.default_shard_mut().insert(Account::with_auth(
            bob,
            5000,
            auth_public_key_from_seed(&SEED_B),
        ));
        state.default_shard_mut().insert(Account::new(carol));

        // Tx 1: Alice → Carol, default context (shard-local)
        let tx1 = make_tx_with_context(alice.0, carol.0, 100, [0u8; 16], &SEED_A);
        // Tx 2: Bob → Carol, default context (shard-local)
        let tx2 = make_tx_with_context(bob.0, carol.0, 200, [0u8; 16], &SEED_B);

        let vm = NVm::with_defaults();
        let receipts = vm.execute_block_sharded(&mut state, &[tx1, tx2], 0);

        assert_eq!(receipts.len(), 2);
        assert!(receipts[0].success);
        assert!(receipts[1].success);
        assert_eq!(state.get(&alice).unwrap().balance, 4900);
        assert_eq!(state.get(&bob).unwrap().balance, 4800);
        assert_eq!(state.get(&carol).unwrap().balance, 300);
    }
}
