//! Verify raw Bitcoin transactions against ACE-side UTXO state.
//!
//! This module intentionally supports a minimal, safety-first subset:
//! - P2PKH (`76a914...88ac`)
//! - P2WPKH (`0014...`)
//! - P2WSH multisig (`0020...`)
//! - P2SH-P2WPKH / P2SH-P2WSH (`a914...87`)
//! - P2SH bare multisig
//! - P2TR key-path and script-path (`5120...`)
//! - mixed-owner multi-input spends
//! - legacy/segwit `SIGHASH_ALL`
//! - Taproot `SIGHASH_DEFAULT` / `SIGHASH_ALL`
//!
//! The goal is to accept standard wallet transactions without pretending to be
//! a full Bitcoin node. Arbitrary legacy script templates, Taproot annex handling,
//! and non-ALL legacy/segwit sighash flags are still out of scope.

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::legacy_idcom_btc_script;
use bitcoin::blockdata::opcodes::all::{
    OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
};
use bitcoin::blockdata::script::Instruction;
use bitcoin::consensus;
use bitcoin::hashes::Hash as _;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::{Prevouts, ScriptPath, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion};
use bitcoin::{
    Amount as BitcoinAmount, ScriptBuf as BitcoinScriptBuf, Transaction as BitcoinTransaction,
    TxOut as BitcoinTxOut,
};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature as K256Signature, VerifyingKey};
use k256::schnorr::{Signature as SchnorrSignature, VerifyingKey as SchnorrVerifyingKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::bvm::utxo::{Utxo, UtxoState};
use crate::error::NVmError;

#[derive(Debug, Clone)]
pub struct ParsedBtcInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ParsedBtcOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ParsedBtcTx {
    pub version: u32,
    pub lock_time: u32,
    pub is_segwit: bool,
    pub inputs: Vec<ParsedBtcInput>,
    pub outputs: Vec<ParsedBtcOutput>,
}

#[derive(Debug, Clone)]
pub struct VerifiedBtcIngress {
    pub sender_idcom: [u8; 32],
    pub input_owners: Vec<AccountId>,
    pub payload: Vec<u8>,
    pub txid: [u8; 32],
}

#[derive(Debug, Clone)]
enum ScriptToken {
    Op(u8),
    Push(Vec<u8>),
}

#[derive(Debug, Clone)]
struct MultisigDescriptor {
    threshold: usize,
    pubkeys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
enum TapscriptDescriptor {
    SingleSig([u8; 32]),
    ChecksigAddThreshold {
        threshold: usize,
        pubkeys: Vec<[u8; 32]>,
    },
}

pub fn btc_txid_from_raw(raw_bytes: &[u8]) -> Result<[u8; 32], NVmError> {
    let tx = parse_raw_btc_tx(raw_bytes)?;
    Ok(double_sha256(&serialize_base_tx(&tx)?))
}

pub fn verify_raw_btc_against_state(
    state: &StateTree,
    raw_bytes: &[u8],
) -> Result<VerifiedBtcIngress, NVmError> {
    let tx = parse_raw_btc_tx(raw_bytes)?;
    let btc_tx = parse_bitcoin_tx(raw_bytes)?;
    if tx.inputs.is_empty() {
        return Err(NVmError::RawChainVerify(
            "btc tx must contain at least one input".into(),
        ));
    }
    if tx.inputs.len() > u8::MAX as usize {
        return Err(NVmError::RawChainVerify(
            "btc tx has too many inputs for BVM payload encoding".into(),
        ));
    }
    if tx.outputs.is_empty() {
        return Err(NVmError::RawChainVerify(
            "btc tx must contain at least one output".into(),
        ));
    }
    if tx.outputs.len() > u8::MAX as usize {
        return Err(NVmError::RawChainVerify(
            "btc tx has too many outputs for BVM payload encoding".into(),
        ));
    }

    let txid = double_sha256(&serialize_base_tx(&tx)?);
    let mut sender_owner: Option<AccountId> = None;
    let mut input_owners = Vec::with_capacity(tx.inputs.len());
    let mut resolved_prevouts = Vec::with_capacity(tx.inputs.len());
    let mut prevouts_txouts = Vec::with_capacity(tx.inputs.len());
    let mut seen_inputs = BTreeSet::new();
    let mut total_input_value = 0u64;

    for input in &tx.inputs {
        if !seen_inputs.insert((input.txid, input.vout)) {
            return Err(NVmError::RawChainVerify(
                "btc tx contains duplicate prevouts".into(),
            ));
        }
        let (owner, prevout) = locate_prevout_owner(state, &input.txid, input.vout)?;
        if sender_owner.is_none() {
            sender_owner = Some(owner);
        }
        input_owners.push(owner);
        resolved_prevouts.push(prevout.clone());
        prevouts_txouts.push(to_bitcoin_tx_out(&prevout));
        total_input_value = total_input_value
            .checked_add(prevout.value)
            .ok_or_else(|| NVmError::RawChainVerify("btc total input value overflow".into()))?;
    }

    for (input_idx, (input, prevout)) in tx.inputs.iter().zip(resolved_prevouts.iter()).enumerate()
    {
        verify_input_against_prevout(
            &tx,
            &btc_tx,
            &resolved_prevouts,
            &prevouts_txouts,
            input_idx,
            input,
            prevout,
        )?;
    }

    let mut total_output_value = 0u64;
    for output in &tx.outputs {
        if !is_supported_output_script(&output.script_pubkey) {
            return Err(NVmError::RawChainVerify(
                "btc raw ingress currently only accepts P2PKH, P2WPKH, P2SH, and P2TR outputs"
                    .into(),
            ));
        }
        total_output_value = total_output_value
            .checked_add(output.value)
            .ok_or_else(|| NVmError::RawChainVerify("btc total output value overflow".into()))?;
    }
    if total_output_value > total_input_value {
        return Err(NVmError::RawChainVerify(format!(
            "btc outputs exceed inputs: inputs={total_input_value}, outputs={total_output_value}"
        )));
    }

    let sender_idcom = sender_owner
        .ok_or_else(|| NVmError::RawChainVerify("btc tx has no sender owner".into()))?
        .0;
    let payload = build_bvm_payload(&tx)?;

    Ok(VerifiedBtcIngress {
        sender_idcom,
        input_owners,
        payload,
        txid,
    })
}

pub fn parse_raw_btc_tx(raw_bytes: &[u8]) -> Result<ParsedBtcTx, NVmError> {
    if raw_bytes.len() < 10 {
        return Err(NVmError::RawChainVerify("btc tx too short".into()));
    }

    let mut offset = 0usize;
    let version = read_u32_le(raw_bytes, &mut offset, "version")?;

    let is_segwit =
        offset + 1 < raw_bytes.len() && raw_bytes[offset] == 0x00 && raw_bytes[offset + 1] == 0x01;
    if is_segwit {
        offset += 2;
    }

    let input_count = decode_varint(raw_bytes, &mut offset)? as usize;
    if input_count == 0 {
        return Err(NVmError::RawChainVerify("btc tx has no inputs".into()));
    }
    // Cap the pre-allocation by the remaining byte count: the varint count is
    // attacker-controlled (up to u64::MAX) and each input consumes >= 1 byte, so
    // an unbounded `with_capacity` would let a tiny message trigger a huge
    // allocation (OOM/abort DoS). The loop still validates real bytes below.
    let mut inputs = Vec::with_capacity(input_count.min(raw_bytes.len()));
    for _ in 0..input_count {
        let txid = read_array32(raw_bytes, &mut offset, "input txid")?;
        let vout = read_u32_le(raw_bytes, &mut offset, "input vout")?;
        let script_sig_len = decode_varint(raw_bytes, &mut offset)? as usize;
        let script_sig = read_vec(raw_bytes, &mut offset, script_sig_len, "scriptSig")?;
        let sequence = read_u32_le(raw_bytes, &mut offset, "sequence")?;
        inputs.push(ParsedBtcInput {
            txid,
            vout,
            script_sig,
            sequence,
            witness: Vec::new(),
        });
    }

    let output_count = decode_varint(raw_bytes, &mut offset)? as usize;
    if output_count == 0 {
        return Err(NVmError::RawChainVerify("btc tx has no outputs".into()));
    }
    // Cap pre-allocation by remaining bytes (attacker-controlled varint, see inputs).
    let mut outputs = Vec::with_capacity(output_count.min(raw_bytes.len()));
    for _ in 0..output_count {
        let value = read_u64_le(raw_bytes, &mut offset, "output value")?;
        let script_len = decode_varint(raw_bytes, &mut offset)? as usize;
        let script_pubkey = read_vec(raw_bytes, &mut offset, script_len, "scriptPubKey")?;
        outputs.push(ParsedBtcOutput {
            value,
            script_pubkey,
        });
    }

    if is_segwit {
        for input in &mut inputs {
            let item_count = decode_varint(raw_bytes, &mut offset)? as usize;
            // Cap pre-allocation by remaining bytes (attacker-controlled varint).
            let mut witness = Vec::with_capacity(item_count.min(raw_bytes.len()));
            for _ in 0..item_count {
                let item_len = decode_varint(raw_bytes, &mut offset)? as usize;
                witness.push(read_vec(raw_bytes, &mut offset, item_len, "witness item")?);
            }
            input.witness = witness;
        }
    }

    let lock_time = read_u32_le(raw_bytes, &mut offset, "lock_time")?;
    if offset != raw_bytes.len() {
        return Err(NVmError::RawChainVerify(
            "btc tx contains unexpected trailing bytes".into(),
        ));
    }

    Ok(ParsedBtcTx {
        version,
        lock_time,
        is_segwit,
        inputs,
        outputs,
    })
}

fn parse_bitcoin_tx(raw_bytes: &[u8]) -> Result<BitcoinTransaction, NVmError> {
    consensus::deserialize(raw_bytes)
        .map_err(|e| NVmError::RawChainVerify(format!("btc tx consensus decode failed: {e}")))
}

fn to_bitcoin_tx_out(utxo: &Utxo) -> BitcoinTxOut {
    BitcoinTxOut {
        value: BitcoinAmount::from_sat(utxo.value),
        script_pubkey: BitcoinScriptBuf::from_bytes(utxo.script_pubkey.clone()),
    }
}

fn locate_prevout_owner(
    state: &StateTree,
    txid: &[u8; 32],
    vout: u32,
) -> Result<(AccountId, Utxo), NVmError> {
    let mut found: Option<(AccountId, Utxo)> = None;
    for (account_id, _) in state.iter() {
        if let Some(utxo) = UtxoState::get_utxo(state, account_id, txid, vout) {
            if found.is_some() {
                return Err(NVmError::RawChainVerify(format!(
                    "btc prevout {}:{} resolves to multiple owners in ACE state",
                    hex::encode(txid),
                    vout
                )));
            }
            found = Some((*account_id, utxo));
        }
    }

    found.ok_or_else(|| {
        NVmError::RawChainVerify(format!(
            "btc prevout {}:{} not found in ACE state",
            hex::encode(txid),
            vout
        ))
    })
}

fn verify_input_against_prevout(
    tx: &ParsedBtcTx,
    btc_tx: &BitcoinTransaction,
    prevouts: &[Utxo],
    prevouts_txouts: &[BitcoinTxOut],
    input_index: usize,
    input: &ParsedBtcInput,
    prevout: &Utxo,
) -> Result<(), NVmError> {
    if let Some(pubkey_hash) = parse_p2pkh(&prevout.script_pubkey) {
        let pushes = parse_pushes(&input.script_sig)?;
        if pushes.len() != 2 {
            return Err(NVmError::RawChainVerify(
                "btc P2PKH input must contain exactly signature + pubkey pushes".into(),
            ));
        }
        let signature = &pushes[0];
        let pubkey = &pushes[1];
        if hash160(pubkey) != pubkey_hash {
            return Err(NVmError::RawChainVerify(
                "btc P2PKH pubkey hash does not match prevout".into(),
            ));
        }
        let sighash = legacy_sighash_all(tx, input_index, &prevout.script_pubkey)?;
        verify_ecdsa_signature(pubkey, signature, &sighash)?;
        return Ok(());
    }

    if let Some(pubkey_hash) = parse_p2wpkh(&prevout.script_pubkey) {
        if !input.script_sig.is_empty() {
            return Err(NVmError::RawChainVerify(
                "btc native P2WPKH input must have empty scriptSig".into(),
            ));
        }
        verify_witness_v0_keyhash(tx, input_index, input, prevout.value, pubkey_hash)?;
        return Ok(());
    }

    if let Some(script_hash) = parse_p2wsh(&prevout.script_pubkey) {
        verify_witness_v0_script(
            tx,
            btc_tx,
            prevouts_txouts,
            input_index,
            input,
            prevout.value,
            script_hash,
        )?;
        return Ok(());
    }

    if let Some(script_hash) = parse_p2sh(&prevout.script_pubkey) {
        let pushes = parse_pushes(&input.script_sig)?;
        let redeem_script = pushes.last().ok_or_else(|| {
            NVmError::RawChainVerify("btc P2SH input missing redeem script".into())
        })?;
        if hash160(redeem_script) != script_hash {
            return Err(NVmError::RawChainVerify(
                "btc redeem script hash does not match prevout P2SH script".into(),
            ));
        }
        if let Some(pubkey_hash) = parse_p2wpkh(redeem_script) {
            if pushes.len() != 1 {
                return Err(NVmError::RawChainVerify(
                    "btc P2SH-P2WPKH input must contain exactly one redeem script push".into(),
                ));
            }
            verify_witness_v0_keyhash(tx, input_index, input, prevout.value, pubkey_hash)?;
            return Ok(());
        }
        if let Some(witness_script_hash) = parse_p2wsh(redeem_script) {
            if pushes.len() != 1 {
                return Err(NVmError::RawChainVerify(
                    "btc P2SH-P2WSH input must contain exactly one redeem script push".into(),
                ));
            }
            verify_witness_v0_script(
                tx,
                btc_tx,
                prevouts_txouts,
                input_index,
                input,
                prevout.value,
                witness_script_hash,
            )?;
            return Ok(());
        }
        if let Some(multisig) = parse_standard_multisig_script(redeem_script)? {
            verify_legacy_multisig(
                tx,
                btc_tx,
                input_index,
                &pushes[..pushes.len() - 1],
                redeem_script,
                &multisig,
            )?;
            return Ok(());
        }
        return Err(NVmError::RawChainVerify(
            "btc P2SH raw ingress only supports nested P2WPKH, nested P2WSH multisig, or bare multisig redeem scripts".into(),
        ));
    }

    if let Some(output_key) = parse_p2tr(&prevout.script_pubkey) {
        if !input.script_sig.is_empty() {
            return Err(NVmError::RawChainVerify(
                "btc Taproot key-path input must have empty scriptSig".into(),
            ));
        }
        if input.witness.len() == 1 {
            verify_taproot_key_path(tx, prevouts, input_index, input, output_key, 0x00)?;
        } else {
            verify_taproot_script_path(btc_tx, prevouts_txouts, input_index, input, output_key)?;
        }
        return Ok(());
    }

    Err(NVmError::RawChainVerify(
        "btc raw ingress only supports P2PKH, P2WPKH, P2WSH, supported P2SH variants, and P2TR prevouts"
            .into(),
    ))
}

fn verify_witness_v0_keyhash(
    tx: &ParsedBtcTx,
    input_index: usize,
    input: &ParsedBtcInput,
    prevout_value: u64,
    pubkey_hash: [u8; 20],
) -> Result<(), NVmError> {
    if input.witness.len() != 2 {
        return Err(NVmError::RawChainVerify(
            "btc witness keyhash spend must provide signature + pubkey".into(),
        ));
    }
    let signature = &input.witness[0];
    let pubkey = &input.witness[1];
    if hash160(pubkey) != pubkey_hash {
        return Err(NVmError::RawChainVerify(
            "btc witness pubkey hash does not match prevout".into(),
        ));
    }
    let script_code = standard_p2pkh_script(&pubkey_hash);
    let sighash = bip143_sighash_all(tx, input_index, &script_code, prevout_value)?;
    verify_ecdsa_signature(pubkey, signature, &sighash)
}

fn verify_ecdsa_signature(
    pubkey_bytes: &[u8],
    signature_with_type: &[u8],
    sighash: &[u8; 32],
) -> Result<(), NVmError> {
    if signature_with_type.len() < 2 {
        return Err(NVmError::RawChainVerify(
            "btc signature is too short".into(),
        ));
    }
    let sighash_flag = signature_with_type[signature_with_type.len() - 1];
    if sighash_flag != 0x01 {
        return Err(NVmError::RawChainVerify(format!(
            "btc raw ingress only supports SIGHASH_ALL, got 0x{sighash_flag:02x}"
        )));
    }
    let signature = K256Signature::from_der(&signature_with_type[..signature_with_type.len() - 1])
        .map_err(|e| NVmError::RawChainVerify(format!("btc DER signature invalid: {e}")))?;
    let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes).map_err(|e| {
        NVmError::RawChainVerify(format!("btc pubkey is not valid secp256k1 point: {e}"))
    })?;
    verifying_key
        .verify_prehash(sighash, &signature)
        .map_err(|e| NVmError::RawChainVerify(format!("btc signature verification failed: {e}")))?;
    Ok(())
}

fn verify_taproot_key_path(
    tx: &ParsedBtcTx,
    prevouts: &[Utxo],
    input_index: usize,
    input: &ParsedBtcInput,
    output_key: [u8; 32],
    default_hash_type: u8,
) -> Result<(), NVmError> {
    if input.witness.len() != 1 {
        return Err(NVmError::RawChainVerify(
            "btc Taproot key-path spend must provide exactly one witness item".into(),
        ));
    }
    let signature_item = &input.witness[0];
    let (signature_bytes, hash_type) = match signature_item.len() {
        64 => (signature_item.as_slice(), default_hash_type),
        65 => {
            let hash_type = signature_item[64];
            if hash_type != 0x00 && hash_type != 0x01 {
                return Err(NVmError::RawChainVerify(format!(
                    "btc Taproot raw ingress only supports SIGHASH_DEFAULT/ALL, got 0x{hash_type:02x}"
                )));
            }
            (&signature_item[..64], hash_type)
        }
        other => {
            return Err(NVmError::RawChainVerify(format!(
                "btc Taproot Schnorr signature must be 64 or 65 bytes, got {other}"
            )))
        }
    };

    let sighash = taproot_key_path_sighash(tx, prevouts, input_index, hash_type)?;
    let signature = SchnorrSignature::try_from(signature_bytes).map_err(|e| {
        NVmError::RawChainVerify(format!("btc Taproot Schnorr signature invalid: {e}"))
    })?;
    let verifying_key = SchnorrVerifyingKey::from_bytes(&output_key)
        .map_err(|e| NVmError::RawChainVerify(format!("btc Taproot output key invalid: {e}")))?;
    verifying_key
        .verify_prehash(&sighash, &signature)
        .map_err(|e| {
            NVmError::RawChainVerify(format!("btc Taproot signature verification failed: {e}"))
        })?;
    Ok(())
}

fn verify_witness_v0_script(
    tx: &ParsedBtcTx,
    btc_tx: &BitcoinTransaction,
    prevouts_txouts: &[BitcoinTxOut],
    input_index: usize,
    input: &ParsedBtcInput,
    prevout_value: u64,
    script_hash: [u8; 32],
) -> Result<(), NVmError> {
    if input.witness.is_empty() {
        return Err(NVmError::RawChainVerify(
            "btc witness script spend must provide a witness stack".into(),
        ));
    }
    let witness_script = input.witness.last().ok_or_else(|| {
        NVmError::RawChainVerify("btc witness script missing witnessScript".into())
    })?;
    if sha256_bytes(witness_script) != script_hash {
        return Err(NVmError::RawChainVerify(
            "btc witnessScript hash does not match prevout".into(),
        ));
    }
    let multisig = parse_standard_multisig_script(witness_script)?.ok_or_else(|| {
        NVmError::RawChainVerify(
            "btc witnessScript raw ingress currently only supports standard multisig scripts"
                .into(),
        )
    })?;
    let sighash = bip143_sighash_all(tx, input_index, witness_script, prevout_value)?;
    let stack_items = &input.witness[..input.witness.len() - 1];
    verify_ecdsa_multisig_stack(&multisig, stack_items, &sighash)?;

    // Cross-check against rust-bitcoin's BIP143 implementation for the executed script.
    let witness_script = BitcoinScriptBuf::from_bytes(witness_script.to_vec());
    let mut cache = SighashCache::new(btc_tx);
    let btc_sighash = cache
        .p2wsh_signature_hash(
            input_index,
            witness_script.as_script(),
            BitcoinAmount::from_sat(prevout_value),
            bitcoin::sighash::EcdsaSighashType::All,
        )
        .map_err(|e| NVmError::RawChainVerify(format!("btc p2wsh sighash failed: {e}")))?;
    if btc_sighash.to_byte_array() != sighash {
        return Err(NVmError::RawChainVerify(
            "btc witnessScript sighash mismatch".into(),
        ));
    }
    if prevouts_txouts.len() != btc_tx.input.len() {
        return Err(NVmError::RawChainVerify(
            "btc prevout context does not match witness transaction".into(),
        ));
    }
    Ok(())
}

fn verify_legacy_multisig(
    tx: &ParsedBtcTx,
    btc_tx: &BitcoinTransaction,
    input_index: usize,
    stack_items: &[Vec<u8>],
    redeem_script: &[u8],
    multisig: &MultisigDescriptor,
) -> Result<(), NVmError> {
    let sighash = legacy_sighash_all(tx, input_index, redeem_script)?;
    verify_ecdsa_multisig_stack(multisig, stack_items, &sighash)?;

    let redeem_script = BitcoinScriptBuf::from_bytes(redeem_script.to_vec());
    let cache = SighashCache::new(btc_tx);
    let btc_sighash = cache
        .legacy_signature_hash(
            input_index,
            redeem_script.as_script(),
            bitcoin::sighash::EcdsaSighashType::All as u32,
        )
        .map_err(|e| NVmError::RawChainVerify(format!("btc legacy sighash failed: {e}")))?;
    if btc_sighash.to_byte_array() != sighash {
        return Err(NVmError::RawChainVerify(
            "btc legacy multisig sighash mismatch".into(),
        ));
    }
    Ok(())
}

fn verify_ecdsa_multisig_stack(
    multisig: &MultisigDescriptor,
    stack_items: &[Vec<u8>],
    sighash: &[u8; 32],
) -> Result<(), NVmError> {
    if stack_items.is_empty() || !stack_items[0].is_empty() {
        return Err(NVmError::RawChainVerify(
            "btc multisig spend must start with the CHECKMULTISIG dummy element".into(),
        ));
    }
    let signatures = &stack_items[1..];
    if signatures.len() != multisig.threshold {
        return Err(NVmError::RawChainVerify(format!(
            "btc multisig witness provides {} signatures, expected {}",
            signatures.len(),
            multisig.threshold
        )));
    }
    let mut sig_index = 0usize;
    let mut key_index = 0usize;
    while sig_index < signatures.len() && key_index < multisig.pubkeys.len() {
        if signatures[sig_index].is_empty() {
            return Err(NVmError::RawChainVerify(
                "btc multisig signature slots must not be empty".into(),
            ));
        }
        if verify_ecdsa_signature(
            &multisig.pubkeys[key_index],
            &signatures[sig_index],
            sighash,
        )
        .is_ok()
        {
            sig_index += 1;
        }
        key_index += 1;
    }
    if sig_index != signatures.len() {
        return Err(NVmError::RawChainVerify(
            "btc multisig signatures do not satisfy redeem script".into(),
        ));
    }
    Ok(())
}

fn verify_taproot_script_path(
    btc_tx: &BitcoinTransaction,
    prevouts_txouts: &[BitcoinTxOut],
    input_index: usize,
    input: &ParsedBtcInput,
    output_key: [u8; 32],
) -> Result<(), NVmError> {
    if input.witness.len() < 2 {
        return Err(NVmError::RawChainVerify(
            "btc Taproot script-path spend must provide script + control block".into(),
        ));
    }
    let tapscript = input.witness[input.witness.len() - 2].clone();
    let control_block = ControlBlock::decode(
        input
            .witness
            .last()
            .ok_or_else(|| NVmError::RawChainVerify("btc Taproot control block missing".into()))?,
    )
    .map_err(|e| NVmError::RawChainVerify(format!("btc Taproot control block invalid: {e}")))?;
    if control_block.leaf_version != LeafVersion::TapScript {
        return Err(NVmError::RawChainVerify(
            "btc raw ingress only supports tapscript leaves".into(),
        ));
    }
    let script = BitcoinScriptBuf::from_bytes(tapscript.clone());
    let secp = Secp256k1::verification_only();
    let output_key = XOnlyPublicKey::from_slice(&output_key)
        .map_err(|e| NVmError::RawChainVerify(format!("btc Taproot output key invalid: {e}")))?;
    if !control_block.verify_taproot_commitment(&secp, output_key, script.as_script()) {
        return Err(NVmError::RawChainVerify(
            "btc Taproot control block does not match prevout output key".into(),
        ));
    }
    let descriptor = parse_tapscript_descriptor(&tapscript)?.ok_or_else(|| {
        NVmError::RawChainVerify(
            "btc raw ingress currently only supports simple tapscript single-sig or CHECKSIGADD threshold leaves".into(),
        )
    })?;
    let stack_items = &input.witness[..input.witness.len() - 2];
    let prevouts = Prevouts::All(prevouts_txouts);
    match descriptor {
        TapscriptDescriptor::SingleSig(pubkey) => {
            if stack_items.len() != 1 {
                return Err(NVmError::RawChainVerify(
                    "btc tapscript single-sig leaf expects exactly one witness signature".into(),
                ));
            }
            let hash_type = taproot_signature_hash_type(&stack_items[0])?;
            let sighash = SighashCache::new(btc_tx)
                .taproot_script_spend_signature_hash(
                    input_index,
                    &prevouts,
                    ScriptPath::with_defaults(script.as_script()),
                    hash_type,
                )
                .map_err(|e| {
                    NVmError::RawChainVerify(format!("btc Taproot script-path sighash failed: {e}"))
                })?;
            verify_taproot_signature(&pubkey, &stack_items[0], &sighash.to_byte_array())?;
        }
        TapscriptDescriptor::ChecksigAddThreshold { threshold, pubkeys } => {
            if stack_items.len() != pubkeys.len() {
                return Err(NVmError::RawChainVerify(format!(
                    "btc tapscript threshold leaf expects {} witness items, got {}",
                    pubkeys.len(),
                    stack_items.len()
                )));
            }
            let mut satisfied = 0usize;
            for (idx, pubkey) in pubkeys.iter().enumerate() {
                let stack_item = &stack_items[pubkeys.len() - 1 - idx];
                if stack_item.is_empty() {
                    continue;
                }
                let hash_type = taproot_signature_hash_type(stack_item)?;
                let sighash = SighashCache::new(btc_tx)
                    .taproot_script_spend_signature_hash(
                        input_index,
                        &prevouts,
                        ScriptPath::with_defaults(script.as_script()),
                        hash_type,
                    )
                    .map_err(|e| {
                        NVmError::RawChainVerify(format!(
                            "btc Taproot threshold sighash failed: {e}"
                        ))
                    })?;
                verify_taproot_signature(pubkey, stack_item, &sighash.to_byte_array())?;
                satisfied += 1;
            }
            if satisfied != threshold {
                return Err(NVmError::RawChainVerify(format!(
                    "btc tapscript threshold leaf satisfied by {satisfied} signatures, expected {threshold}"
                )));
            }
        }
    }
    Ok(())
}

fn verify_taproot_signature(
    pubkey_bytes: &[u8; 32],
    signature_with_type: &[u8],
    sighash: &[u8; 32],
) -> Result<(), NVmError> {
    let (signature_bytes, _) = parse_taproot_signature(signature_with_type)?;
    let signature = SchnorrSignature::try_from(signature_bytes).map_err(|e| {
        NVmError::RawChainVerify(format!("btc Taproot Schnorr signature invalid: {e}"))
    })?;
    let verifying_key = SchnorrVerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|e| NVmError::RawChainVerify(format!("btc Taproot output key invalid: {e}")))?;
    verifying_key
        .verify_prehash(sighash, &signature)
        .map_err(|e| {
            NVmError::RawChainVerify(format!("btc Taproot signature verification failed: {e}"))
        })?;
    Ok(())
}

fn parse_taproot_signature(signature_item: &[u8]) -> Result<(&[u8], TapSighashType), NVmError> {
    match signature_item.len() {
        64 => Ok((signature_item, TapSighashType::Default)),
        65 => {
            let hash_type =
                TapSighashType::from_consensus_u8(signature_item[64]).map_err(|_| {
                    NVmError::RawChainVerify(format!(
                        "btc Taproot raw ingress got unsupported sighash byte 0x{:02x}",
                        signature_item[64]
                    ))
                })?;
            match hash_type {
                TapSighashType::Default | TapSighashType::All => {
                    Ok((&signature_item[..64], hash_type))
                }
                _ => Err(NVmError::RawChainVerify(format!(
                    "btc Taproot raw ingress only supports SIGHASH_DEFAULT/ALL, got {hash_type}"
                ))),
            }
        }
        other => Err(NVmError::RawChainVerify(format!(
            "btc Taproot Schnorr signature must be 64 or 65 bytes, got {other}"
        ))),
    }
}

fn taproot_signature_hash_type(signature_item: &[u8]) -> Result<TapSighashType, NVmError> {
    let (_, hash_type) = parse_taproot_signature(signature_item)?;
    Ok(hash_type)
}

fn build_bvm_payload(tx: &ParsedBtcTx) -> Result<Vec<u8>, NVmError> {
    let mut payload = Vec::new();
    payload.push(0x32);
    payload.push(tx.inputs.len() as u8);
    for input in &tx.inputs {
        payload.extend_from_slice(&input.txid);
        payload.extend_from_slice(&input.vout.to_le_bytes());
        let unlocking_script = canonical_unlocking_script(input);
        let len = u32::try_from(unlocking_script.len()).map_err(|_| {
            NVmError::RawChainVerify("btc unlocking script too large for payload".into())
        })?;
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(&unlocking_script);
    }

    payload.push(tx.outputs.len() as u8);
    for output in &tx.outputs {
        let recipient = legacy_idcom_btc_script(&output.script_pubkey);
        payload.extend_from_slice(&recipient);
        payload.extend_from_slice(&output.value.to_le_bytes());
        let len = u32::try_from(output.script_pubkey.len()).map_err(|_| {
            NVmError::RawChainVerify("btc scriptPubKey too large for payload".into())
        })?;
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(&output.script_pubkey);
    }

    Ok(payload)
}

fn canonical_unlocking_script(input: &ParsedBtcInput) -> Vec<u8> {
    if input.witness.is_empty() {
        return input.script_sig.clone();
    }
    let mut script = Vec::new();
    for item in &input.witness {
        push_data(&mut script, item);
    }
    script
}

fn parse_p2pkh(script_pubkey: &[u8]) -> Option<[u8; 20]> {
    if script_pubkey.len() == 25
        && script_pubkey[0] == 0x76
        && script_pubkey[1] == 0xa9
        && script_pubkey[2] == 0x14
        && script_pubkey[23] == 0x88
        && script_pubkey[24] == 0xac
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script_pubkey[3..23]);
        Some(hash)
    } else {
        None
    }
}

fn parse_p2wpkh(script_pubkey: &[u8]) -> Option<[u8; 20]> {
    if script_pubkey.len() == 22 && script_pubkey[0] == 0x00 && script_pubkey[1] == 0x14 {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script_pubkey[2..22]);
        Some(hash)
    } else {
        None
    }
}

fn parse_p2wsh(script_pubkey: &[u8]) -> Option<[u8; 32]> {
    if script_pubkey.len() == 34 && script_pubkey[0] == 0x00 && script_pubkey[1] == 0x20 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&script_pubkey[2..34]);
        Some(hash)
    } else {
        None
    }
}

fn parse_p2sh(script_pubkey: &[u8]) -> Option<[u8; 20]> {
    if script_pubkey.len() == 23
        && script_pubkey[0] == 0xa9
        && script_pubkey[1] == 0x14
        && script_pubkey[22] == 0x87
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script_pubkey[2..22]);
        Some(hash)
    } else {
        None
    }
}

fn parse_p2tr(script_pubkey: &[u8]) -> Option<[u8; 32]> {
    if script_pubkey.len() == 34 && script_pubkey[0] == 0x51 && script_pubkey[1] == 0x20 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&script_pubkey[2..34]);
        Some(key)
    } else {
        None
    }
}

fn is_supported_output_script(script_pubkey: &[u8]) -> bool {
    parse_p2pkh(script_pubkey).is_some()
        || parse_p2wpkh(script_pubkey).is_some()
        || parse_p2wsh(script_pubkey).is_some()
        || parse_p2sh(script_pubkey).is_some()
        || parse_p2tr(script_pubkey).is_some()
}

fn parse_script_tokens(script: &[u8]) -> Result<Vec<ScriptToken>, NVmError> {
    bitcoin::Script::from_bytes(script)
        .instructions()
        .map(|instruction| {
            let instruction = instruction
                .map_err(|e| NVmError::RawChainVerify(format!("btc script parse failed: {e}")))?;
            Ok(match instruction {
                Instruction::Op(op) => ScriptToken::Op(op.to_u8()),
                Instruction::PushBytes(bytes) => ScriptToken::Push(bytes.as_bytes().to_vec()),
            })
        })
        .collect()
}

fn opcode_small_int(op: u8) -> Option<usize> {
    match op {
        0x00 => Some(0),
        0x51..=0x60 => Some((op - 0x50) as usize),
        _ => None,
    }
}

fn parse_standard_multisig_script(script: &[u8]) -> Result<Option<MultisigDescriptor>, NVmError> {
    let tokens = parse_script_tokens(script)?;
    if tokens.len() < 4 {
        return Ok(None);
    }
    let Some(threshold) = (match tokens.first() {
        Some(ScriptToken::Op(op)) => opcode_small_int(*op),
        _ => None,
    }) else {
        return Ok(None);
    };
    let Some(pubkey_count) = (match tokens.get(tokens.len() - 2) {
        Some(ScriptToken::Op(op)) => opcode_small_int(*op),
        _ => None,
    }) else {
        return Ok(None);
    };
    let is_checkmultisig = matches!(
        tokens.last(),
        Some(ScriptToken::Op(op))
            if *op == OP_CHECKMULTISIG.to_u8() || *op == OP_CHECKMULTISIGVERIFY.to_u8()
    );
    if !is_checkmultisig {
        return Ok(None);
    }
    let pubkey_tokens = &tokens[1..tokens.len() - 2];
    if pubkey_tokens.len() != pubkey_count {
        return Ok(None);
    }
    let mut pubkeys = Vec::with_capacity(pubkey_tokens.len());
    for token in pubkey_tokens {
        let ScriptToken::Push(pubkey) = token else {
            return Ok(None);
        };
        if pubkey.len() != 33 && pubkey.len() != 65 {
            return Ok(None);
        }
        pubkeys.push(pubkey.clone());
    }
    if threshold == 0 || threshold > pubkey_count {
        return Ok(None);
    }
    Ok(Some(MultisigDescriptor { threshold, pubkeys }))
}

fn parse_tapscript_descriptor(script: &[u8]) -> Result<Option<TapscriptDescriptor>, NVmError> {
    let tokens = parse_script_tokens(script)?;
    if tokens.len() == 2 && matches!(tokens[1], ScriptToken::Op(op) if op == OP_CHECKSIG.to_u8()) {
        if let ScriptToken::Push(pubkey) = &tokens[0] {
            if pubkey.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(pubkey);
                return Ok(Some(TapscriptDescriptor::SingleSig(out)));
            }
        }
    }

    if tokens.len() >= 4
        && matches!(tokens.last(), Some(ScriptToken::Op(op)) if *op == OP_NUMEQUAL.to_u8() || *op == OP_NUMEQUALVERIFY.to_u8())
    {
        let Some(threshold) = (match tokens.get(tokens.len() - 2) {
            Some(ScriptToken::Op(op)) => opcode_small_int(*op),
            _ => None,
        }) else {
            return Ok(None);
        };
        let seq = &tokens[..tokens.len() - 2];
        if seq.len() >= 2 && seq.len() % 2 == 0 {
            let mut pubkeys = Vec::with_capacity(seq.len() / 2);
            for (idx, pair) in seq.chunks_exact(2).enumerate() {
                let ScriptToken::Push(pubkey) = &pair[0] else {
                    return Ok(None);
                };
                if pubkey.len() != 32 {
                    return Ok(None);
                }
                let expected_op = if idx == 0 {
                    OP_CHECKSIG.to_u8()
                } else {
                    OP_CHECKSIGADD.to_u8()
                };
                if !matches!(pair[1], ScriptToken::Op(op) if op == expected_op) {
                    return Ok(None);
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(pubkey);
                pubkeys.push(key);
            }
            if threshold == 0 || threshold > pubkeys.len() {
                return Ok(None);
            }
            return Ok(Some(TapscriptDescriptor::ChecksigAddThreshold {
                threshold,
                pubkeys,
            }));
        }
    }

    Ok(None)
}

fn parse_pushes(script: &[u8]) -> Result<Vec<Vec<u8>>, NVmError> {
    let mut pushes = Vec::new();
    let mut offset = 0usize;
    while offset < script.len() {
        let opcode = script[offset];
        offset += 1;
        let len = match opcode {
            0x00 => {
                pushes.push(Vec::new());
                continue;
            }
            0x01..=0x4b => opcode as usize,
            0x4c => read_u8(script, &mut offset, "OP_PUSHDATA1")? as usize,
            0x4d => read_u16_le(script, &mut offset, "OP_PUSHDATA2")? as usize,
            _ => {
                return Err(NVmError::RawChainVerify(
                    "btc raw ingress only supports push-only unlocking scripts".into(),
                ))
            }
        };
        pushes.push(read_vec(script, &mut offset, len, "pushdata")?);
    }
    Ok(pushes)
}

fn legacy_sighash_all(
    tx: &ParsedBtcTx,
    input_index: usize,
    script_code: &[u8],
) -> Result<[u8; 32], NVmError> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    write_varint(&mut preimage, tx.inputs.len() as u64);
    for (idx, input) in tx.inputs.iter().enumerate() {
        preimage.extend_from_slice(&input.txid);
        preimage.extend_from_slice(&input.vout.to_le_bytes());
        if idx == input_index {
            write_varint(&mut preimage, script_code.len() as u64);
            preimage.extend_from_slice(script_code);
        } else {
            write_varint(&mut preimage, 0);
        }
        preimage.extend_from_slice(&input.sequence.to_le_bytes());
    }
    write_outputs(&mut preimage, &tx.outputs);
    preimage.extend_from_slice(&tx.lock_time.to_le_bytes());
    preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL
    Ok(double_sha256(&preimage))
}

fn bip143_sighash_all(
    tx: &ParsedBtcTx,
    input_index: usize,
    script_code: &[u8],
    prevout_value: u64,
) -> Result<[u8; 32], NVmError> {
    let mut prevouts = Vec::with_capacity(tx.inputs.len() * 36);
    let mut sequences = Vec::with_capacity(tx.inputs.len() * 4);
    for input in &tx.inputs {
        prevouts.extend_from_slice(&input.txid);
        prevouts.extend_from_slice(&input.vout.to_le_bytes());
        sequences.extend_from_slice(&input.sequence.to_le_bytes());
    }

    let outputs = serialize_outputs_without_count(&tx.outputs);
    let hash_prevouts = double_sha256(&prevouts);
    let hash_sequences = double_sha256(&sequences);
    let hash_outputs = double_sha256(&outputs);
    let input = &tx.inputs[input_index];

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequences);
    preimage.extend_from_slice(&input.txid);
    preimage.extend_from_slice(&input.vout.to_le_bytes());
    write_varint(&mut preimage, script_code.len() as u64);
    preimage.extend_from_slice(script_code);
    preimage.extend_from_slice(&prevout_value.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&tx.lock_time.to_le_bytes());
    preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL
    Ok(double_sha256(&preimage))
}

fn taproot_key_path_sighash(
    tx: &ParsedBtcTx,
    prevouts: &[Utxo],
    input_index: usize,
    hash_type: u8,
) -> Result<[u8; 32], NVmError> {
    if input_index >= tx.inputs.len() {
        return Err(NVmError::RawChainVerify(format!(
            "btc Taproot input index {input_index} out of range"
        )));
    }
    if hash_type != 0x00 && hash_type != 0x01 {
        return Err(NVmError::RawChainVerify(format!(
            "btc Taproot raw ingress only supports SIGHASH_DEFAULT/ALL, got 0x{hash_type:02x}"
        )));
    }
    if prevouts.len() != tx.inputs.len() {
        return Err(NVmError::RawChainVerify(
            "btc Taproot prevout set does not match input count".into(),
        ));
    }

    let mut prevouts_data = Vec::new();
    let mut amounts_data = Vec::new();
    let mut scriptpubkeys_data = Vec::new();
    let mut sequences_data = Vec::new();
    for (input, prevout) in tx.inputs.iter().zip(prevouts.iter()) {
        prevouts_data.extend_from_slice(&input.txid);
        prevouts_data.extend_from_slice(&input.vout.to_le_bytes());
        amounts_data.extend_from_slice(&prevout.value.to_le_bytes());
        write_varint(&mut scriptpubkeys_data, prevout.script_pubkey.len() as u64);
        scriptpubkeys_data.extend_from_slice(&prevout.script_pubkey);
        sequences_data.extend_from_slice(&input.sequence.to_le_bytes());
    }
    let outputs_data = serialize_outputs_without_count(&tx.outputs);

    let mut preimage = Vec::new();
    preimage.push(0x00); // epoch
    preimage.push(hash_type);
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.extend_from_slice(&tx.lock_time.to_le_bytes());
    preimage.extend_from_slice(&Sha256::digest(&prevouts_data));
    preimage.extend_from_slice(&Sha256::digest(&amounts_data));
    preimage.extend_from_slice(&Sha256::digest(&scriptpubkeys_data));
    preimage.extend_from_slice(&Sha256::digest(&sequences_data));
    preimage.extend_from_slice(&Sha256::digest(&outputs_data));
    preimage.push(0x00); // spend_type = key path, no annex
    preimage.extend_from_slice(&(input_index as u32).to_le_bytes());
    Ok(tagged_hash("TapSighash", &preimage))
}

fn standard_p2pkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76);
    script.push(0xa9);
    script.push(0x14);
    script.extend_from_slice(pubkey_hash);
    script.push(0x88);
    script.push(0xac);
    script
}

fn write_outputs(out: &mut Vec<u8>, outputs: &[ParsedBtcOutput]) {
    write_varint(out, outputs.len() as u64);
    for output in outputs {
        out.extend_from_slice(&output.value.to_le_bytes());
        write_varint(out, output.script_pubkey.len() as u64);
        out.extend_from_slice(&output.script_pubkey);
    }
}

fn serialize_outputs_without_count(outputs: &[ParsedBtcOutput]) -> Vec<u8> {
    let mut out = Vec::new();
    for output in outputs {
        out.extend_from_slice(&output.value.to_le_bytes());
        write_varint(&mut out, output.script_pubkey.len() as u64);
        out.extend_from_slice(&output.script_pubkey);
    }
    out
}

fn serialize_base_tx(tx: &ParsedBtcTx) -> Result<Vec<u8>, NVmError> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    write_varint(&mut out, tx.inputs.len() as u64);
    for input in &tx.inputs {
        out.extend_from_slice(&input.txid);
        out.extend_from_slice(&input.vout.to_le_bytes());
        write_varint(&mut out, input.script_sig.len() as u64);
        out.extend_from_slice(&input.script_sig);
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }
    write_outputs(&mut out, &tx.outputs);
    out.extend_from_slice(&tx.lock_time.to_le_bytes());
    Ok(out)
}

#[cfg(test)]
fn serialize_full_tx(tx: &ParsedBtcTx) -> Result<Vec<u8>, NVmError> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    if tx.is_segwit {
        out.extend_from_slice(&[0x00, 0x01]);
    }
    write_varint(&mut out, tx.inputs.len() as u64);
    for input in &tx.inputs {
        out.extend_from_slice(&input.txid);
        out.extend_from_slice(&input.vout.to_le_bytes());
        write_varint(&mut out, input.script_sig.len() as u64);
        out.extend_from_slice(&input.script_sig);
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }
    write_outputs(&mut out, &tx.outputs);
    if tx.is_segwit {
        for input in &tx.inputs {
            write_varint(&mut out, input.witness.len() as u64);
            for item in &input.witness {
                write_varint(&mut out, item.len() as u64);
                out.extend_from_slice(item);
            }
        }
    }
    out.extend_from_slice(&tx.lock_time.to_le_bytes());
    Ok(out)
}

fn read_u8(data: &[u8], offset: &mut usize, label: &str) -> Result<u8, NVmError> {
    if *offset >= data.len() {
        return Err(NVmError::RawChainVerify(format!("btc truncated {label}")));
    }
    let out = data[*offset];
    *offset += 1;
    Ok(out)
}

fn read_u16_le(data: &[u8], offset: &mut usize, label: &str) -> Result<u16, NVmError> {
    if *offset + 2 > data.len() {
        return Err(NVmError::RawChainVerify(format!("btc truncated {label}")));
    }
    let out = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
    *offset += 2;
    Ok(out)
}

fn read_u32_le(data: &[u8], offset: &mut usize, label: &str) -> Result<u32, NVmError> {
    if *offset + 4 > data.len() {
        return Err(NVmError::RawChainVerify(format!("btc truncated {label}")));
    }
    let out = u32::from_le_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]);
    *offset += 4;
    Ok(out)
}

fn read_u64_le(data: &[u8], offset: &mut usize, label: &str) -> Result<u64, NVmError> {
    if *offset + 8 > data.len() {
        return Err(NVmError::RawChainVerify(format!("btc truncated {label}")));
    }
    let out = u64::from_le_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
        data[*offset + 4],
        data[*offset + 5],
        data[*offset + 6],
        data[*offset + 7],
    ]);
    *offset += 8;
    Ok(out)
}

fn read_array32(data: &[u8], offset: &mut usize, label: &str) -> Result<[u8; 32], NVmError> {
    if *offset + 32 > data.len() {
        return Err(NVmError::RawChainVerify(format!("btc truncated {label}")));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[*offset..*offset + 32]);
    *offset += 32;
    Ok(out)
}

fn read_vec(data: &[u8], offset: &mut usize, len: usize, label: &str) -> Result<Vec<u8>, NVmError> {
    if *offset + len > data.len() {
        return Err(NVmError::RawChainVerify(format!("btc truncated {label}")));
    }
    let out = data[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(out)
}

fn decode_varint(data: &[u8], offset: &mut usize) -> Result<u64, NVmError> {
    let tag = read_u8(data, offset, "varint tag")?;
    match tag {
        0x00..=0xfc => Ok(tag as u64),
        0xfd => Ok(read_u16_le(data, offset, "varint u16")? as u64),
        0xfe => Ok(read_u32_le(data, offset, "varint u32")? as u64),
        0xff => Ok(read_u64_le(data, offset, "varint u64")?),
    }
}

fn write_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0x00..=0xfc => out.push(value as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn push_data(out: &mut Vec<u8>, data: &[u8]) {
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

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripemd);
    out
}

fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;
    use k256::schnorr::SigningKey as SchnorrSigningKey;

    fn p2wpkh_script(pubkey: &[u8]) -> Vec<u8> {
        let pkh = hash160(pubkey);
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&pkh);
        script
    }

    fn p2sh_script(redeem_script: &[u8]) -> Vec<u8> {
        let mut script = vec![0xa9, 0x14];
        script.extend_from_slice(&hash160(redeem_script));
        script.push(0x87);
        script
    }

    fn multisig_script(pubkeys: &[Vec<u8>], threshold: u8) -> Vec<u8> {
        let mut script = vec![0x50 + threshold];
        for pubkey in pubkeys {
            push_data(&mut script, pubkey);
        }
        script.push(0x50 + pubkeys.len() as u8);
        script.push(0xae);
        script
    }

    fn sign_witness_input(
        tx: &ParsedBtcTx,
        input_index: usize,
        prevout_value: u64,
        pubkey_hash: [u8; 20],
        signing_key: &SigningKey,
    ) -> Vec<u8> {
        let script_code = standard_p2pkh_script(&pubkey_hash);
        let sighash =
            bip143_sighash_all(tx, input_index, &script_code, prevout_value).expect("sighash");
        let signature: K256Signature = signing_key.sign_prehash(&sighash).expect("sign");
        let mut der = signature.to_der().as_bytes().to_vec();
        der.push(0x01);
        der
    }

    #[test]
    fn verifies_minimal_p2wpkh_ingress_against_state() {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).expect("signing key");
        let pubkey = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let prev_script = p2wpkh_script(&pubkey);
        let next_signing_key = SigningKey::from_bytes((&[8u8; 32]).into()).expect("next key");
        let next_pubkey = next_signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let next_script = p2wpkh_script(&next_pubkey);

        let prev_txid = [0x11; 32];
        let prevout = Utxo {
            txid: prev_txid,
            vout: 0,
            value: 50_000,
            script_pubkey: prev_script.clone(),
        };
        let owner = AccountId(legacy_idcom_btc_script(&prev_script));
        let mut state = StateTree::new();
        UtxoState::add_utxo(&mut state, &owner, &prevout).expect("seed utxo");

        let mut tx = ParsedBtcTx {
            version: 2,
            lock_time: 0,
            is_segwit: true,
            inputs: vec![ParsedBtcInput {
                txid: prev_txid,
                vout: 0,
                script_sig: Vec::new(),
                sequence: 0xffff_fffd,
                witness: Vec::new(),
            }],
            outputs: vec![ParsedBtcOutput {
                value: 49_000,
                script_pubkey: next_script,
            }],
        };
        let pkh = parse_p2wpkh(&prev_script).unwrap();
        let signature = sign_witness_input(&tx, 0, prevout.value, pkh, &signing_key);
        tx.inputs[0].witness = vec![signature, pubkey.clone()];

        let raw = serialize_full_tx(&tx).expect("serialize");
        let verified = verify_raw_btc_against_state(&state, &raw).expect("verify raw btc");

        assert_eq!(verified.sender_idcom, owner.0);
        assert_eq!(verified.input_owners, vec![owner]);
        assert_eq!(verified.txid, btc_txid_from_raw(&raw).unwrap());
        assert_eq!(verified.payload[0], 0x32);
    }

    #[test]
    fn rejects_unsupported_output_scripts() {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).expect("signing key");
        let pubkey = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let prev_script = p2wpkh_script(&pubkey);
        let prev_txid = [0x22; 32];
        let prevout = Utxo {
            txid: prev_txid,
            vout: 0,
            value: 50_000,
            script_pubkey: prev_script.clone(),
        };
        let owner = AccountId(legacy_idcom_btc_script(&prev_script));
        let mut state = StateTree::new();
        UtxoState::add_utxo(&mut state, &owner, &prevout).expect("seed utxo");

        // Unsupported script: OP_RETURN <data>
        let taproot_script = vec![0x6a, 0x02, 0xaa, 0xbb];
        let mut tx = ParsedBtcTx {
            version: 2,
            lock_time: 0,
            is_segwit: true,
            inputs: vec![ParsedBtcInput {
                txid: prev_txid,
                vout: 0,
                script_sig: Vec::new(),
                sequence: 0xffff_fffd,
                witness: Vec::new(),
            }],
            outputs: vec![ParsedBtcOutput {
                value: 49_000,
                script_pubkey: taproot_script,
            }],
        };
        let pkh = parse_p2wpkh(&prev_script).unwrap();
        let signature = sign_witness_input(&tx, 0, prevout.value, pkh, &signing_key);
        tx.inputs[0].witness = vec![signature, pubkey];

        let raw = serialize_full_tx(&tx).expect("serialize");
        let err = verify_raw_btc_against_state(&state, &raw)
            .unwrap_err()
            .to_string();
        assert!(err.contains("only accepts P2PKH, P2WPKH, P2SH, and P2TR outputs"));
    }

    #[test]
    fn verifies_taproot_key_path_ingress() {
        let taproot_key = SchnorrSigningKey::from_bytes(&[9u8; 32]).expect("taproot key");
        let xonly = taproot_key.verifying_key().to_bytes();
        let mut prev_script = vec![0x51, 0x20];
        prev_script.extend_from_slice(&xonly);
        let prev_txid = [0x77; 32];
        let prevout = Utxo {
            txid: prev_txid,
            vout: 0,
            value: 60_000,
            script_pubkey: prev_script.clone(),
        };
        let owner = AccountId(legacy_idcom_btc_script(&prev_script));
        let mut state = StateTree::new();
        UtxoState::add_utxo(&mut state, &owner, &prevout).expect("seed utxo");

        let next_key = SigningKey::from_bytes((&[10u8; 32]).into()).expect("next key");
        let next_pubkey = next_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let next_script = p2wpkh_script(&next_pubkey);

        let tx = ParsedBtcTx {
            version: 2,
            lock_time: 0,
            is_segwit: true,
            inputs: vec![ParsedBtcInput {
                txid: prev_txid,
                vout: 0,
                script_sig: Vec::new(),
                sequence: 0xffff_fffd,
                witness: Vec::new(),
            }],
            outputs: vec![ParsedBtcOutput {
                value: 59_000,
                script_pubkey: next_script,
            }],
        };
        let sighash = taproot_key_path_sighash(&tx, std::slice::from_ref(&prevout), 0, 0x00)
            .expect("taproot sighash");
        let signature = taproot_key
            .sign_prehash(&sighash)
            .expect("taproot schnorr sign");

        let mut signed_tx = tx.clone();
        signed_tx.inputs[0].witness = vec![signature.to_bytes().to_vec()];

        let raw = serialize_full_tx(&signed_tx).expect("serialize");
        let verified = verify_raw_btc_against_state(&state, &raw).expect("taproot verify");
        assert_eq!(verified.sender_idcom, owner.0);
        assert_eq!(verified.input_owners, vec![owner]);
    }

    #[test]
    fn verifies_p2sh_multisig_ingress() {
        let key1 = SigningKey::from_bytes((&[14u8; 32]).into()).expect("key1");
        let key2 = SigningKey::from_bytes((&[15u8; 32]).into()).expect("key2");
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
        let redeem_script = multisig_script(&[pub1.clone(), pub2.clone()], 2);
        let prev_script = p2sh_script(&redeem_script);
        let prev_txid = [0x41; 32];
        let prevout = Utxo {
            txid: prev_txid,
            vout: 0,
            value: 75_000,
            script_pubkey: prev_script.clone(),
        };
        let owner = AccountId(legacy_idcom_btc_script(&prev_script));
        let mut state = StateTree::new();
        UtxoState::add_utxo(&mut state, &owner, &prevout).expect("seed utxo");

        let next_key = SigningKey::from_bytes((&[16u8; 32]).into()).expect("next key");
        let next_pubkey = next_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let next_script = p2wpkh_script(&next_pubkey);

        let mut tx = ParsedBtcTx {
            version: 2,
            lock_time: 0,
            is_segwit: false,
            inputs: vec![ParsedBtcInput {
                txid: prev_txid,
                vout: 0,
                script_sig: Vec::new(),
                sequence: 0xffff_fffd,
                witness: Vec::new(),
            }],
            outputs: vec![ParsedBtcOutput {
                value: 74_000,
                script_pubkey: next_script,
            }],
        };
        let sighash = legacy_sighash_all(&tx, 0, &redeem_script).expect("legacy sighash");
        let sig1: K256Signature = key1.sign_prehash(&sighash).expect("sig1");
        let sig2: K256Signature = key2.sign_prehash(&sighash).expect("sig2");
        let mut sig1_bytes = sig1.to_der().as_bytes().to_vec();
        sig1_bytes.push(0x01);
        let mut sig2_bytes = sig2.to_der().as_bytes().to_vec();
        sig2_bytes.push(0x01);
        let mut script_sig = Vec::new();
        push_data(&mut script_sig, &[]);
        push_data(&mut script_sig, &sig1_bytes);
        push_data(&mut script_sig, &sig2_bytes);
        push_data(&mut script_sig, &redeem_script);
        tx.inputs[0].script_sig = script_sig;

        let raw = serialize_full_tx(&tx).expect("serialize");
        let verified = verify_raw_btc_against_state(&state, &raw).expect("p2sh multisig verify");
        assert_eq!(verified.sender_idcom, owner.0);
        assert_eq!(verified.input_owners, vec![owner]);
    }

    #[test]
    fn supports_mixed_owner_multi_input() {
        let key1 = SigningKey::from_bytes((&[11u8; 32]).into()).expect("key1");
        let key2 = SigningKey::from_bytes((&[12u8; 32]).into()).expect("key2");
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
        let owner1 = AccountId(legacy_idcom_btc_script(&script1));
        let owner2 = AccountId(legacy_idcom_btc_script(&script2));

        let prev1 = Utxo {
            txid: [0x31; 32],
            vout: 0,
            value: 40_000,
            script_pubkey: script1.clone(),
        };
        let prev2 = Utxo {
            txid: [0x32; 32],
            vout: 1,
            value: 30_000,
            script_pubkey: script2.clone(),
        };
        let mut state = StateTree::new();
        UtxoState::add_utxo(&mut state, &owner1, &prev1).expect("seed utxo 1");
        UtxoState::add_utxo(&mut state, &owner2, &prev2).expect("seed utxo 2");

        let recipient_key = SigningKey::from_bytes((&[13u8; 32]).into()).expect("recipient");
        let recipient_pub = recipient_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let recipient_script = p2wpkh_script(&recipient_pub);

        let mut tx = ParsedBtcTx {
            version: 2,
            lock_time: 0,
            is_segwit: true,
            inputs: vec![
                ParsedBtcInput {
                    txid: prev1.txid,
                    vout: prev1.vout,
                    script_sig: Vec::new(),
                    sequence: 0xffff_fffd,
                    witness: Vec::new(),
                },
                ParsedBtcInput {
                    txid: prev2.txid,
                    vout: prev2.vout,
                    script_sig: Vec::new(),
                    sequence: 0xffff_fffd,
                    witness: Vec::new(),
                },
            ],
            outputs: vec![ParsedBtcOutput {
                value: 69_000,
                script_pubkey: recipient_script,
            }],
        };
        let sig1 = sign_witness_input(&tx, 0, prev1.value, parse_p2wpkh(&script1).unwrap(), &key1);
        let sig2 = sign_witness_input(&tx, 1, prev2.value, parse_p2wpkh(&script2).unwrap(), &key2);
        tx.inputs[0].witness = vec![sig1, pub1];
        tx.inputs[1].witness = vec![sig2, pub2];

        let raw = serialize_full_tx(&tx).expect("serialize");
        let verified = verify_raw_btc_against_state(&state, &raw).expect("mixed owner verify");
        assert_eq!(verified.sender_idcom, owner1.0);
        assert_eq!(verified.input_owners, vec![owner1, owner2]);
    }

    #[test]
    fn rejects_missing_prevout() {
        let raw = vec![1, 0, 0, 0, 1, 0, 0, 0, 0, 0];
        let state = StateTree::new();
        let err = verify_raw_btc_against_state(&state, &raw)
            .unwrap_err()
            .to_string();
        assert!(err.contains("btc"));
    }
}
