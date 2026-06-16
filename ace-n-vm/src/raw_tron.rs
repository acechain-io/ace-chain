//! Verify raw TRON transaction and recover signer for raw-chain execution path.
//!
//! TRON transactions use Protobuf encoding (not RLP like EVM).
//! The signature is secp256k1 ECDSA over SHA-256(raw_data_bytes).
//! The signer's 20-byte address is derived the same way as Ethereum:
//! `keccak256(uncompressed_pubkey)[12..32]`.
//!
//! ## Supported Contract Types
//!
//! - `TransferContract` (type 1): TRX native transfers
//! - `TriggerSmartContract` (type 31): smart contract calls (TVM/Solidity)

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::legacy_idcom_tron;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use k256::elliptic_curve::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use crate::error::NVmError;

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

/// TRON protobuf contract types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
enum TronContractType {
    TransferContract = 1,
    TriggerSmartContract = 31,
}

/// Parsed TRON transaction fields needed for verification.
#[derive(Debug)]
struct TronTxParsed {
    /// The raw_data bytes (field 1 of the outer Transaction message).
    raw_data: Vec<u8>,
    /// The signature bytes (field 2 of the outer Transaction message).
    /// 65 bytes: r(32) + s(32) + v(1).
    signature: Vec<u8>,
    /// Contract type extracted from raw_data.
    contract_type: TronContractType,
    /// Contract parameter bytes (the `Any.value` field).
    contract_parameter: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTronIngress {
    pub signer: [u8; 20],
    pub sender_idcom: [u8; 32],
    pub canonical_payload: Vec<u8>,
    pub raw_tx_hash: [u8; 32],
    pub replay_slot: [u8; 32],
    pub domain_slot: u32,
}

// ── Protobuf wire-format helpers ──
//
// TRON's protobuf is simple enough to parse manually without pulling in prost.
// Wire types: 0=varint, 2=length-delimited.

/// Read a varint from `data[*pos..]`, advancing `*pos`.
fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, NVmError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return Err(NVmError::RawChainVerify(
                "tron protobuf: unexpected end reading varint".into(),
            ));
        }
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(NVmError::RawChainVerify(
                "tron protobuf: varint too long".into(),
            ));
        }
    }
}

/// Read a length-delimited field value from `data[*pos..]`, advancing `*pos`.
fn read_bytes<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], NVmError> {
    let len = read_varint(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(NVmError::RawChainVerify(
            "tron protobuf: length-delimited field truncated".into(),
        ));
    }
    let result = &data[*pos..*pos + len];
    *pos += len;
    Ok(result)
}

/// Skip a protobuf field based on its wire type.
fn skip_field(data: &[u8], pos: &mut usize, wire_type: u8) -> Result<(), NVmError> {
    match wire_type {
        0 => {
            // varint
            read_varint(data, pos)?;
        }
        1 => {
            // 64-bit
            if *pos + 8 > data.len() {
                return Err(NVmError::RawChainVerify(
                    "tron protobuf: truncated 64-bit field".into(),
                ));
            }
            *pos += 8;
        }
        2 => {
            // length-delimited
            read_bytes(data, pos)?;
        }
        5 => {
            // 32-bit
            if *pos + 4 > data.len() {
                return Err(NVmError::RawChainVerify(
                    "tron protobuf: truncated 32-bit field".into(),
                ));
            }
            *pos += 4;
        }
        _ => {
            return Err(NVmError::RawChainVerify(format!(
                "tron protobuf: unknown wire type {wire_type}"
            )));
        }
    }
    Ok(())
}

/// Parse the outer TRON Transaction protobuf.
///
/// ```text
/// message Transaction {
///   message raw {
///     repeated Contract contract = 11;
///     ...
///   }
///   bytes raw_data = 1;      // serialized `raw` message
///   repeated bytes signature = 2;
/// }
/// ```
fn parse_tron_tx(data: &[u8]) -> Result<TronTxParsed, NVmError> {
    let mut pos = 0;
    let mut raw_data: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;

    while pos < data.len() {
        let tag = read_varint(data, &mut pos)?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        match (field_number, wire_type) {
            (1, 2) => {
                // raw_data (length-delimited)
                let bytes = read_bytes(data, &mut pos)?;
                raw_data = Some(bytes.to_vec());
            }
            (2, 2) => {
                // signature (length-delimited)
                let bytes = read_bytes(data, &mut pos)?;
                signature = Some(bytes.to_vec());
            }
            (_, _) => {
                skip_field(data, &mut pos, wire_type)?;
            }
        }
    }

    let raw_data = raw_data
        .ok_or_else(|| NVmError::RawChainVerify("tron tx: missing raw_data field".into()))?;
    let signature = signature
        .ok_or_else(|| NVmError::RawChainVerify("tron tx: missing signature field".into()))?;

    if signature.len() != 65 {
        return Err(NVmError::RawChainVerify(format!(
            "tron tx: signature must be 65 bytes, got {}",
            signature.len()
        )));
    }

    // Parse raw_data to extract contract type and parameter
    let (contract_type, contract_parameter) = parse_raw_data_contracts(&raw_data)?;

    Ok(TronTxParsed {
        raw_data,
        signature,
        contract_type,
        contract_parameter,
    })
}

/// Parse the contracts from the raw_data message.
///
/// ```text
/// message raw {
///   ...
///   repeated Contract contract = 11;
///   ...
/// }
///
/// message Contract {
///   ContractType type = 1;
///   google.protobuf.Any parameter = 2;
/// }
///
/// message Any {
///   string type_url = 1;
///   bytes value = 2;
/// }
/// ```
fn parse_raw_data_contracts(raw_data: &[u8]) -> Result<(TronContractType, Vec<u8>), NVmError> {
    let mut pos = 0;
    let mut contract_bytes: Option<&[u8]> = None;

    while pos < raw_data.len() {
        let tag = read_varint(raw_data, &mut pos)?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        if field_number == 11 && wire_type == 2 {
            // contract (field 11, length-delimited)
            contract_bytes = Some(read_bytes(raw_data, &mut pos)?);
        } else {
            skip_field(raw_data, &mut pos, wire_type)?;
        }
    }

    let contract_bytes = contract_bytes.ok_or_else(|| {
        NVmError::RawChainVerify("tron raw_data: no contract field (field 11)".into())
    })?;

    // Parse the Contract message
    let mut cpos = 0;
    let mut contract_type_val: Option<i32> = None;
    let mut parameter_any: Option<&[u8]> = None;

    while cpos < contract_bytes.len() {
        let tag = read_varint(contract_bytes, &mut cpos)?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        match (field_number, wire_type) {
            (1, 0) => {
                // type (varint)
                contract_type_val = Some(read_varint(contract_bytes, &mut cpos)? as i32);
            }
            (2, 2) => {
                // parameter (Any, length-delimited)
                parameter_any = Some(read_bytes(contract_bytes, &mut cpos)?);
            }
            (_, _) => {
                skip_field(contract_bytes, &mut cpos, wire_type)?;
            }
        }
    }

    let contract_type_val = contract_type_val
        .ok_or_else(|| NVmError::RawChainVerify("tron contract: missing type field".into()))?;

    let contract_type = match contract_type_val {
        1 => TronContractType::TransferContract,
        31 => TronContractType::TriggerSmartContract,
        other => {
            return Err(NVmError::RawChainVerify(format!(
                "tron: unsupported contract type {other}"
            )));
        }
    };

    let parameter_any = parameter_any
        .ok_or_else(|| NVmError::RawChainVerify("tron contract: missing parameter field".into()))?;

    // Parse the Any message to extract the value bytes
    let mut apos = 0;
    let mut value_bytes: Option<&[u8]> = None;
    while apos < parameter_any.len() {
        let tag = read_varint(parameter_any, &mut apos)?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        if field_number == 2 && wire_type == 2 {
            // value (bytes, field 2)
            value_bytes = Some(read_bytes(parameter_any, &mut apos)?);
        } else {
            skip_field(parameter_any, &mut apos, wire_type)?;
        }
    }

    let value_bytes = value_bytes
        .ok_or_else(|| NVmError::RawChainVerify("tron Any: missing value field".into()))?;

    Ok((contract_type, value_bytes.to_vec()))
}

/// ECDSA recovery: recover the 20-byte address from a signature and message hash.
fn ecrecover_addr(
    hash: &[u8; 32],
    recovery_byte: u8,
    r: &[u8],
    s: &[u8],
) -> Result<[u8; 20], NVmError> {
    if r.len() != 32 || s.len() != 32 {
        return Err(NVmError::RawChainVerify(
            "tron: r/s must be 32 bytes each".into(),
        ));
    }

    let rec_id = RecoveryId::try_from(recovery_byte % 4)
        .map_err(|_| NVmError::RawChainVerify("tron: invalid recovery id".into()))?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);

    let sig = K256Signature::from_bytes(GenericArray::from_slice(&sig_bytes))
        .map_err(|e| NVmError::RawChainVerify(format!("tron: invalid signature: {e}")))?;

    let vk = VerifyingKey::recover_from_prehash(hash, &sig, rec_id)
        .map_err(|e| NVmError::RawChainVerify(format!("tron: ecrecover failed: {e}")))?;

    // Uncompressed public key (65 bytes: 04 || x || y), take last 64 bytes
    let uncompressed = vk.to_encoded_point(false);
    let pubkey_bytes = &uncompressed.as_bytes()[1..]; // skip 0x04 prefix
    let hash = keccak256(pubkey_bytes);

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Ok(addr)
}

fn tron_raw_data_hash(raw_data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(raw_data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn recover_signer_from_parsed(parsed: &TronTxParsed) -> Result<[u8; 20], NVmError> {
    let tx_hash = tron_raw_data_hash(&parsed.raw_data);
    let r = &parsed.signature[0..32];
    let s = &parsed.signature[32..64];
    let v = parsed.signature[64];
    ecrecover_addr(&tx_hash, v, r, s)
}

/// Verify a raw TRON signed transaction and return the recovered signer address (20 bytes).
///
/// The signer address is the standard 20-byte form (without the 0x41 TRON prefix).
pub fn verify_raw_tron_recover_signer(raw_bytes: &[u8]) -> Result<[u8; 20], NVmError> {
    let parsed = parse_tron_tx(raw_bytes)?;
    recover_signer_from_parsed(&parsed)
}

/// Parsed transfer fields from a TRON TransferContract.
struct TransferFields {
    /// Owner address (21 bytes with 0x41 prefix, we store 20).
    _owner: [u8; 20],
    /// Recipient address (21 bytes with 0x41 prefix, we store 20).
    to: [u8; 20],
    /// Amount in SUN (1 TRX = 1,000,000 SUN).
    amount: u64,
}

/// Parsed TriggerSmartContract fields.
struct TriggerFields {
    /// Owner address (20 bytes).
    _owner: [u8; 20],
    /// Contract address (20 bytes).
    contract: [u8; 20],
    /// Call value in SUN.
    call_value: u64,
    /// ABI-encoded calldata.
    data: Vec<u8>,
}

/// Parse a TransferContract parameter.
///
/// ```text
/// message TransferContract {
///   bytes owner_address = 1;   // 21 bytes (0x41 + 20)
///   bytes to_address = 2;      // 21 bytes (0x41 + 20)
///   int64 amount = 3;
/// }
/// ```
fn parse_transfer_contract(data: &[u8]) -> Result<TransferFields, NVmError> {
    let mut pos = 0;
    let mut owner: Option<[u8; 20]> = None;
    let mut to: Option<[u8; 20]> = None;
    let mut amount: u64 = 0;

    while pos < data.len() {
        let tag = read_varint(data, &mut pos)?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        match (field_number, wire_type) {
            (1, 2) => {
                let bytes = read_bytes(data, &mut pos)?;
                owner = Some(tron_addr_to_20(bytes)?);
            }
            (2, 2) => {
                let bytes = read_bytes(data, &mut pos)?;
                to = Some(tron_addr_to_20(bytes)?);
            }
            (3, 0) => {
                amount = read_varint(data, &mut pos)?;
            }
            (_, _) => {
                skip_field(data, &mut pos, wire_type)?;
            }
        }
    }

    Ok(TransferFields {
        _owner: owner.ok_or_else(|| {
            NVmError::RawChainVerify("tron TransferContract: missing owner_address".into())
        })?,
        to: to.ok_or_else(|| {
            NVmError::RawChainVerify("tron TransferContract: missing to_address".into())
        })?,
        amount,
    })
}

/// Parse a TriggerSmartContract parameter.
///
/// ```text
/// message TriggerSmartContract {
///   bytes owner_address = 1;      // 21 bytes
///   bytes contract_address = 2;   // 21 bytes
///   int64 call_value = 3;
///   bytes data = 4;               // ABI calldata
/// }
/// ```
fn parse_trigger_smart_contract(data: &[u8]) -> Result<TriggerFields, NVmError> {
    let mut pos = 0;
    let mut owner: Option<[u8; 20]> = None;
    let mut contract: Option<[u8; 20]> = None;
    let mut call_value: u64 = 0;
    let mut calldata: Vec<u8> = Vec::new();

    while pos < data.len() {
        let tag = read_varint(data, &mut pos)?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        match (field_number, wire_type) {
            (1, 2) => {
                let bytes = read_bytes(data, &mut pos)?;
                owner = Some(tron_addr_to_20(bytes)?);
            }
            (2, 2) => {
                let bytes = read_bytes(data, &mut pos)?;
                contract = Some(tron_addr_to_20(bytes)?);
            }
            (3, 0) => {
                call_value = read_varint(data, &mut pos)?;
            }
            (4, 2) => {
                let bytes = read_bytes(data, &mut pos)?;
                calldata = bytes.to_vec();
            }
            (_, _) => {
                skip_field(data, &mut pos, wire_type)?;
            }
        }
    }

    Ok(TriggerFields {
        _owner: owner.ok_or_else(|| {
            NVmError::RawChainVerify("tron TriggerSmartContract: missing owner_address".into())
        })?,
        contract: contract.ok_or_else(|| {
            NVmError::RawChainVerify("tron TriggerSmartContract: missing contract_address".into())
        })?,
        call_value,
        data: calldata,
    })
}

/// Convert a TRON address (21 bytes with 0x41 prefix) to a 20-byte address.
/// Also accepts a bare 20-byte address.
fn tron_addr_to_20(bytes: &[u8]) -> Result<[u8; 20], NVmError> {
    let mut addr = [0u8; 20];
    if bytes.len() == 21 && bytes[0] == 0x41 {
        addr.copy_from_slice(&bytes[1..21]);
    } else if bytes.len() == 20 {
        addr.copy_from_slice(bytes);
    } else {
        return Err(NVmError::RawChainVerify(format!(
            "tron: invalid address length {} (expected 20 or 21)",
            bytes.len()
        )));
    }
    Ok(addr)
}

/// Reconstruct the canonical ACE payload from a raw TRON transaction.
///
/// Maps TRON contract types to ACE TVM opcodes:
/// - `TransferContract` → opcode `0x42` (TVM transfer)
/// - `TriggerSmartContract` → opcode `0x40` (TVM call)
fn canonical_tron_payload_from_parsed(parsed: &TronTxParsed) -> Result<Vec<u8>, NVmError> {
    match parsed.contract_type {
        TronContractType::TransferContract => {
            let tf = parse_transfer_contract(&parsed.contract_parameter)?;
            let mut payload = Vec::with_capacity(1 + 20 + 8);
            payload.push(0x42);
            payload.extend_from_slice(&tf.to);
            payload.extend_from_slice(&tf.amount.to_le_bytes());
            Ok(payload)
        }
        TronContractType::TriggerSmartContract => {
            let tf = parse_trigger_smart_contract(&parsed.contract_parameter)?;
            let gas_limit: u64 = 30_000_000;
            let mut payload = Vec::with_capacity(1 + 20 + 8 + 8 + tf.data.len());
            payload.push(0x40);
            payload.extend_from_slice(&tf.contract);
            payload.extend_from_slice(&tf.call_value.to_le_bytes());
            payload.extend_from_slice(&gas_limit.to_le_bytes());
            payload.extend_from_slice(&tf.data);
            Ok(payload)
        }
    }
}

pub fn tron_replay_slot(raw_tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-TRON-REPLAY-V1");
    hasher.update(raw_tx_hash);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

pub fn tron_ace_domain_slot(raw_tx_hash: &[u8; 32]) -> u32 {
    u32::from_le_bytes(raw_tx_hash[..4].try_into().expect("32-byte hash"))
}

fn tron_replay_marker(domain_slot: u64) -> [u8; 32] {
    let mut marker = [0u8; 32];
    marker[0] = 1;
    marker[1..9].copy_from_slice(&domain_slot.to_le_bytes());
    marker
}

pub fn tron_replay_state(
    raw_bytes: &[u8],
    domain_slot: u64,
) -> Result<([u8; 32], [u8; 32]), NVmError> {
    let raw_tx_hash = tron_raw_tx_hash(raw_bytes)?;
    Ok((
        tron_replay_slot(&raw_tx_hash),
        tron_replay_marker(domain_slot),
    ))
}

pub fn tron_raw_tx_hash(raw_bytes: &[u8]) -> Result<[u8; 32], NVmError> {
    let parsed = parse_tron_tx(raw_bytes)?;
    Ok(tron_raw_data_hash(&parsed.raw_data))
}

pub fn canonical_tron_payload_from_raw(raw_bytes: &[u8]) -> Result<Vec<u8>, NVmError> {
    let parsed = parse_tron_tx(raw_bytes)?;
    canonical_tron_payload_from_parsed(&parsed)
}

pub fn verify_raw_tron_against_state(
    state: &StateTree,
    raw_bytes: &[u8],
) -> Result<VerifiedTronIngress, NVmError> {
    let parsed = parse_tron_tx(raw_bytes)?;
    let raw_tx_hash = tron_raw_data_hash(&parsed.raw_data);
    let signer = recover_signer_from_parsed(&parsed)?;
    let sender_idcom = legacy_idcom_tron(&signer);
    let sender = AccountId::from_bytes(sender_idcom);
    if !state.contains(&sender) {
        return Err(NVmError::RawChainVerify(
            "tron sender account does not exist on ACE".into(),
        ));
    }

    let replay_slot = tron_replay_slot(&raw_tx_hash);
    if state.get_storage(&sender, &replay_slot) != [0u8; 32] {
        return Err(NVmError::RawChainVerify(
            "tron transaction has already been used on ACE".into(),
        ));
    }

    Ok(VerifiedTronIngress {
        signer,
        sender_idcom,
        canonical_payload: canonical_tron_payload_from_parsed(&parsed)?,
        raw_tx_hash,
        replay_slot,
        domain_slot: tron_ace_domain_slot(&raw_tx_hash),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_model::account::{Account, AccountId};
    use ace_model::state_tree::StateTree;
    use ace_runtime::crypto::legacy_idcom_tron;

    /// Build a minimal TRON TransferContract protobuf for testing.
    fn build_test_transfer_tx(
        owner: &[u8; 20],
        to: &[u8; 20],
        amount: u64,
        signing_key: &k256::ecdsa::SigningKey,
    ) -> Vec<u8> {
        // Build TransferContract parameter
        let mut transfer = Vec::new();
        // field 1: owner_address (21 bytes with 0x41 prefix)
        let mut owner_addr = vec![0x41];
        owner_addr.extend_from_slice(owner);
        write_pb_bytes(&mut transfer, 1, &owner_addr);
        // field 2: to_address
        let mut to_addr = vec![0x41];
        to_addr.extend_from_slice(to);
        write_pb_bytes(&mut transfer, 2, &to_addr);
        // field 3: amount
        write_pb_varint(&mut transfer, 3, amount);

        // Build Any wrapper
        let mut any = Vec::new();
        write_pb_bytes(
            &mut any,
            1,
            b"type.googleapis.com/protocol.TransferContract",
        );
        write_pb_bytes(&mut any, 2, &transfer);

        // Build Contract message
        let mut contract = Vec::new();
        write_pb_varint(&mut contract, 1, 1); // type = TransferContract
        write_pb_bytes(&mut contract, 2, &any);

        // Build raw_data
        let mut raw_data = Vec::new();
        write_pb_bytes(&mut raw_data, 11, &contract);

        // Sign: SHA-256(raw_data)
        let mut hasher = Sha256::new();
        hasher.update(&raw_data);
        let tx_hash: [u8; 32] = hasher.finalize().into();

        let (sig, rec_id) = signing_key
            .sign_prehash_recoverable(&tx_hash)
            .expect("sign");
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&sig.to_bytes());
        sig_bytes.push(rec_id.to_byte());

        // Build outer Transaction
        let mut tx = Vec::new();
        write_pb_bytes(&mut tx, 1, &raw_data);
        write_pb_bytes(&mut tx, 2, &sig_bytes);

        tx
    }

    fn write_pb_varint(buf: &mut Vec<u8>, field: u32, value: u64) {
        let tag = (field << 3); // wire type 0
        write_raw_varint(buf, tag as u64);
        write_raw_varint(buf, value);
    }

    fn write_pb_bytes(buf: &mut Vec<u8>, field: u32, data: &[u8]) {
        let tag = (field << 3) | 2; // wire type 2
        write_raw_varint(buf, tag as u64);
        write_raw_varint(buf, data.len() as u64);
        buf.extend_from_slice(data);
    }

    fn write_raw_varint(buf: &mut Vec<u8>, mut value: u64) {
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                buf.push(byte);
                break;
            }
            buf.push(byte | 0x80);
        }
    }

    #[test]
    fn test_recover_signer_from_transfer() {
        use k256::ecdsa::SigningKey;

        let sk = SigningKey::from_slice(&[0x42; 32]).expect("valid key");
        let vk = sk.verifying_key();

        // Derive expected 20-byte address
        let uncompressed = vk.to_encoded_point(false);
        let pubkey_bytes = &uncompressed.as_bytes()[1..];
        let hash = keccak256(pubkey_bytes);
        let mut expected_addr = [0u8; 20];
        expected_addr.copy_from_slice(&hash[12..32]);

        let to = [0xBB; 20];
        let tx_bytes = build_test_transfer_tx(&expected_addr, &to, 1_000_000, &sk);

        let recovered = verify_raw_tron_recover_signer(&tx_bytes).unwrap();
        assert_eq!(recovered, expected_addr);
    }

    #[test]
    fn test_canonical_transfer_payload() {
        use k256::ecdsa::SigningKey;

        let sk = SigningKey::from_slice(&[0x43; 32]).expect("valid key");
        let owner = [0xAA; 20];
        let to = [0xBB; 20];
        let amount: u64 = 5_000_000;

        let tx_bytes = build_test_transfer_tx(&owner, &to, amount, &sk);
        let payload = canonical_tron_payload_from_raw(&tx_bytes).unwrap();

        assert_eq!(payload[0], 0x42); // TVM transfer opcode
        assert_eq!(&payload[1..21], &to);
        assert_eq!(
            u64::from_le_bytes(payload[21..29].try_into().unwrap()),
            amount
        );
    }

    #[test]
    fn test_tron_idcom_domain_separation() {
        use ace_runtime::crypto::{legacy_idcom_evm, legacy_idcom_tron};

        let addr = [0xAA; 20];
        let evm_idcom = legacy_idcom_evm(&addr);
        let tron_idcom = legacy_idcom_tron(&addr);

        // Same address must produce different id_coms
        assert_ne!(evm_idcom, tron_idcom);
    }

    #[test]
    fn test_tron_replay_binding_uses_canonical_domain_slot() {
        use k256::ecdsa::SigningKey;

        let sk = SigningKey::from_slice(&[0x44; 32]).expect("valid key");
        let vk = sk.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        let pubkey_bytes = &uncompressed.as_bytes()[1..];
        let hash = keccak256(pubkey_bytes);
        let mut owner = [0u8; 20];
        owner.copy_from_slice(&hash[12..32]);

        let to = [0xCC; 20];
        let tx_bytes = build_test_transfer_tx(&owner, &to, 7_000_000, &sk);
        let sender_idcom = legacy_idcom_tron(&owner);
        let sender = AccountId::from_bytes(sender_idcom);

        let mut state = StateTree::new();
        state.insert(Account::new(sender));

        let verified = verify_raw_tron_against_state(&state, &tx_bytes).expect("tron tx verifies");
        assert_eq!(verified.sender_idcom, sender_idcom);
        assert_eq!(
            verified.domain_slot,
            tron_ace_domain_slot(&verified.raw_tx_hash)
        );

        let (replay_slot, marker) =
            tron_replay_state(&tx_bytes, verified.domain_slot as u64).expect("replay state");
        assert_eq!(replay_slot, verified.replay_slot);

        state.set_storage(&sender, replay_slot, marker);
        let err = verify_raw_tron_against_state(&state, &tx_bytes).expect_err("replay must fail");
        assert!(err.to_string().contains("already been used"));
    }
}
