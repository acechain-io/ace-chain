//! Verify raw EVM transaction and recover signer for raw-chain execution path.
//!
//! Supports: legacy EIP-155, EIP-2930 (Type 1), EIP-1559 (Type 2),
//! EIP-4844 blob (Type 3), and EIP-7702 (Type 4).

use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use k256::elliptic_curve::generic_array::GenericArray;
use rlp::{Rlp, RlpStream};
use tiny_keccak::{Hasher, Keccak};

use crate::error::NVmError;

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

/// Reject EVM envelopes whose execution semantics ACE does not yet preserve.
pub fn ensure_supported_evm_execution_semantics(raw_bytes: &[u8]) -> Result<(), NVmError> {
    match raw_bytes.first().copied() {
        Some(0x03) => Err(NVmError::RawChainVerify(
            "EIP-4844 blob transactions are not yet supported for ACE execution semantics".into(),
        )),
        Some(0x04) => Err(NVmError::RawChainVerify(
            "EIP-7702 transactions are not yet supported for ACE execution semantics".into(),
        )),
        _ => Ok(()),
    }
}

/// Verify a raw EVM signed transaction (legacy or typed) and return the recovered signer address (20 bytes).
///
/// Auto-detects format: legacy (RLP list, 0xc0+), Type 1 (0x01), or Type 2 (0x02).
pub fn verify_raw_evm_recover_signer(raw_bytes: &[u8]) -> Result<[u8; 20], NVmError> {
    verify_raw_evm_recover_signer_and_chain_id(raw_bytes).map(|(signer, _)| signer)
}

/// Verify a raw EVM signed transaction and return `(signer, chain_id)`.
pub fn verify_raw_evm_recover_signer_and_chain_id(
    raw_bytes: &[u8],
) -> Result<([u8; 20], u64), NVmError> {
    ensure_supported_evm_execution_semantics(raw_bytes)?;
    if raw_bytes.is_empty() {
        return Err(NVmError::RawChainVerify("empty EVM tx".into()));
    }

    match raw_bytes[0] {
        0x01 => verify_typed_tx(0x01, raw_bytes, 11, 8),
        0x02 => verify_typed_tx(0x02, raw_bytes, 12, 9),
        0x03 => verify_typed_tx(0x03, raw_bytes, 14, 11),
        0x04 => verify_typed_tx(0x04, raw_bytes, 13, 10),
        b if b >= 0xc0 => verify_legacy(raw_bytes),
        _ => Err(NVmError::RawChainVerify(format!(
            "unrecognized EVM tx format: first byte 0x{:02x}",
            raw_bytes[0]
        ))),
    }
}

/// Reconstruct the canonical ACE EVM payload from a signed raw envelope.
///
/// This binds raw-chain authorization to the exact internal execution intent.
pub fn canonical_evm_payload_from_raw(raw_bytes: &[u8]) -> Result<Vec<u8>, NVmError> {
    ensure_supported_evm_execution_semantics(raw_bytes)?;
    if raw_bytes.is_empty() {
        return Err(NVmError::RawChainVerify("empty EVM tx".into()));
    }

    let decoded = match raw_bytes[0] {
        0x01 | 0x02 => decode_typed_payload(raw_bytes)?,
        0x03 | 0x04 => {
            return Err(NVmError::RawChainVerify(
                "unsupported EVM execution semantics".into(),
            ))
        }
        b if b >= 0xc0 => decode_legacy_payload(raw_bytes)?,
        _ => {
            return Err(NVmError::RawChainVerify(format!(
                "unrecognized EVM tx format: first byte 0x{:02x}",
                raw_bytes[0]
            )))
        }
    };

    Ok(build_evm_payload(
        decoded.is_create,
        &decoded.to,
        decoded.value,
        decoded.gas_limit,
        &decoded.data,
    ))
}

/// Decode the signed EVM transaction nonce from a raw envelope.
pub fn decode_raw_evm_nonce(raw_bytes: &[u8]) -> Result<u64, NVmError> {
    if raw_bytes.is_empty() {
        return Err(NVmError::RawChainVerify("empty EVM tx".into()));
    }

    match raw_bytes[0] {
        0x01..=0x04 => decode_typed_nonce(raw_bytes),
        b if b >= 0xc0 => decode_legacy_nonce(raw_bytes),
        _ => Err(NVmError::RawChainVerify(format!(
            "unrecognized EVM tx format: first byte 0x{:02x}",
            raw_bytes[0]
        ))),
    }
}

/// Verify legacy EIP-155 RLP-signed transaction.
fn verify_legacy(raw_bytes: &[u8]) -> Result<([u8; 20], u64), NVmError> {
    let rlp = Rlp::new(raw_bytes);
    if !rlp.is_list() {
        return Err(NVmError::RawChainVerify("EVM tx must be RLP list".into()));
    }
    let item_count = rlp
        .item_count()
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    if item_count != 9 {
        return Err(NVmError::RawChainVerify(format!(
            "expected 9 RLP items, got {item_count}"
        )));
    }

    let nonce: u64 = rlp
        .val_at(0)
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    let gas_price: u64 = rlp
        .val_at(1)
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    let gas_limit: u64 = rlp
        .val_at(2)
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    let to_vec: Vec<u8> = rlp
        .val_at(3)
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    let value_vec: Vec<u8> = rlp
        .val_at(4)
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    let data: Vec<u8> = rlp
        .val_at(5)
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;

    let v: u64 = rlp
        .val_at(6)
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    let r_vec: Vec<u8> = rlp
        .val_at(7)
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    let s_vec: Vec<u8> = rlp
        .val_at(8)
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;

    let chain_id = if v >= 35 {
        (v - 35) / 2
    } else {
        return Err(NVmError::RawChainVerify("EIP-155 v >= 35 required".into()));
    };

    let mut stream = RlpStream::new_list(9);
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    stream.append(&to_vec);
    stream.append(&value_vec);
    stream.append(&data);
    stream.append(&chain_id);
    stream.append(&0u8);
    stream.append(&0u8);
    let encoded = stream.out();
    let hash = keccak256(&encoded);

    let recovery_byte = ((v - 35) % 2) as u8;
    let signer = ecrecover_addr(&hash, recovery_byte, &r_vec, &s_vec)?;
    Ok((signer, chain_id))
}

fn decode_legacy_nonce(raw_bytes: &[u8]) -> Result<u64, NVmError> {
    let rlp = Rlp::new(raw_bytes);
    if !rlp.is_list() {
        return Err(NVmError::RawChainVerify("EVM tx must be RLP list".into()));
    }
    rlp.val_at(0)
        .map_err(|e| NVmError::RawChainVerify(format!("nonce: {e}")))
}

/// Verify EIP-2718 typed transaction (Type 1 or Type 2).
///
/// - `expected_items`: 11 for EIP-2930, 12 for EIP-1559
/// - `num_sign_fields`: 8 for EIP-2930 (signing first 8), 9 for EIP-1559 (signing first 9)
fn verify_typed_tx(
    tx_type: u8,
    raw_bytes: &[u8],
    expected_items: usize,
    num_sign_fields: usize,
) -> Result<([u8; 20], u64), NVmError> {
    if raw_bytes.len() < 2 {
        return Err(NVmError::RawChainVerify(format!(
            "EIP-2718 type 0x{tx_type:02x} tx too short"
        )));
    }
    let payload = &raw_bytes[1..];
    let rlp = Rlp::new(payload);
    let item_count = rlp
        .item_count()
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    if item_count != expected_items {
        return Err(NVmError::RawChainVerify(format!(
            "type 0x{tx_type:02x} expects {expected_items} items, got {item_count}"
        )));
    }

    let chain_id: u64 = rlp
        .val_at(0)
        .map_err(|e| NVmError::RawChainVerify(format!("chain_id: {e}")))?;

    // Signature: y_parity, r, s are the last 3 items
    let y_parity: u64 = rlp
        .val_at(expected_items - 3)
        .map_err(|e| NVmError::RawChainVerify(format!("y_parity: {e}")))?;
    let r_vec: Vec<u8> = rlp
        .val_at(expected_items - 2)
        .map_err(|e| NVmError::RawChainVerify(format!("r: {e}")))?;
    let s_vec: Vec<u8> = rlp
        .val_at(expected_items - 1)
        .map_err(|e| NVmError::RawChainVerify(format!("s: {e}")))?;

    // Build signing hash from raw RLP bytes (avoids u256 overflow for fee fields)
    let mut stream = RlpStream::new_list(num_sign_fields);
    for i in 0..num_sign_fields {
        let item = rlp
            .at(i)
            .map_err(|e| NVmError::RawChainVerify(format!("rlp field {i}: {e}")))?;
        stream.append_raw(item.as_raw(), 1);
    }
    let encoded = stream.out();
    let mut signing_input = Vec::with_capacity(1 + encoded.len());
    signing_input.push(tx_type);
    signing_input.extend_from_slice(&encoded);
    let hash = keccak256(&signing_input);

    let signer = ecrecover_addr(&hash, y_parity as u8, &r_vec, &s_vec)?;
    Ok((signer, chain_id))
}

fn decode_typed_nonce(raw_bytes: &[u8]) -> Result<u64, NVmError> {
    if raw_bytes.len() < 2 {
        return Err(NVmError::RawChainVerify("typed tx too short".into()));
    }
    let payload = &raw_bytes[1..];
    let rlp = Rlp::new(payload);
    rlp.val_at(1)
        .map_err(|e| NVmError::RawChainVerify(format!("nonce: {e}")))
}

struct DecodedExecPayload {
    is_create: bool,
    to: [u8; 20],
    value: u64,
    gas_limit: u64,
    data: Vec<u8>,
}

fn decode_legacy_payload(raw_bytes: &[u8]) -> Result<DecodedExecPayload, NVmError> {
    let rlp = Rlp::new(raw_bytes);
    if !rlp.is_list() {
        return Err(NVmError::RawChainVerify("EVM tx must be RLP list".into()));
    }
    let item_count = rlp
        .item_count()
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    if item_count != 9 {
        return Err(NVmError::RawChainVerify(format!(
            "expected 9 RLP items, got {item_count}"
        )));
    }

    let gas_limit: u64 = rlp
        .val_at(2)
        .map_err(|e| NVmError::RawChainVerify(format!("gas_limit: {e}")))?;
    let to_vec: Vec<u8> = rlp
        .val_at(3)
        .map_err(|e| NVmError::RawChainVerify(format!("to: {e}")))?;
    let value_vec: Vec<u8> = rlp
        .val_at(4)
        .map_err(|e| NVmError::RawChainVerify(format!("value: {e}")))?;
    let data: Vec<u8> = rlp
        .val_at(5)
        .map_err(|e| NVmError::RawChainVerify(format!("data: {e}")))?;

    Ok(DecodedExecPayload {
        is_create: to_vec.is_empty(),
        to: decode_evm_address(&to_vec),
        value: value_to_u64(&value_vec)?,
        gas_limit,
        data,
    })
}

fn decode_typed_payload(raw_bytes: &[u8]) -> Result<DecodedExecPayload, NVmError> {
    if raw_bytes.len() < 2 {
        return Err(NVmError::RawChainVerify("typed tx too short".into()));
    }

    let tx_type = raw_bytes[0];
    let payload = &raw_bytes[1..];
    let rlp = Rlp::new(payload);
    let item_count = rlp
        .item_count()
        .map_err(|e| NVmError::RawChainVerify(format!("invalid RLP: {e}")))?;

    let (gas_limit_idx, to_idx, value_idx, data_idx, expected_items) = match tx_type {
        0x01 => (3usize, 4usize, 5usize, 6usize, 11usize),
        0x02 => (4usize, 5usize, 6usize, 7usize, 12usize),
        other => {
            return Err(NVmError::RawChainVerify(format!(
                "unsupported EVM tx type: 0x{other:02x}"
            )))
        }
    };

    if item_count != expected_items {
        return Err(NVmError::RawChainVerify(format!(
            "type 0x{tx_type:02x} expects {expected_items} items, got {item_count}"
        )));
    }

    let gas_limit: u64 = rlp
        .val_at(gas_limit_idx)
        .map_err(|e| NVmError::RawChainVerify(format!("gas_limit: {e}")))?;
    let to_vec: Vec<u8> = rlp
        .val_at(to_idx)
        .map_err(|e| NVmError::RawChainVerify(format!("to: {e}")))?;
    let value_vec: Vec<u8> = rlp
        .val_at(value_idx)
        .map_err(|e| NVmError::RawChainVerify(format!("value: {e}")))?;
    let data: Vec<u8> = rlp
        .val_at(data_idx)
        .map_err(|e| NVmError::RawChainVerify(format!("data: {e}")))?;

    Ok(DecodedExecPayload {
        is_create: to_vec.is_empty(),
        to: decode_evm_address(&to_vec),
        value: value_to_u64(&value_vec)?,
        gas_limit,
        data,
    })
}

fn decode_evm_address(bytes: &[u8]) -> [u8; 20] {
    let mut to = [0u8; 20];
    if bytes.len() >= 20 {
        to.copy_from_slice(&bytes[bytes.len() - 20..]);
    } else if !bytes.is_empty() {
        to[20 - bytes.len()..].copy_from_slice(bytes);
    }
    to
}

fn value_to_u64(bytes: &[u8]) -> Result<u64, NVmError> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 8 && bytes[..bytes.len() - 8].iter().any(|byte| *byte != 0) {
        return Err(NVmError::RawChainVerify(
            "EVM value exceeds u64::MAX".into(),
        ));
    }
    let mut buf = [0u8; 8];
    let start = bytes.len().saturating_sub(8);
    let len = (bytes.len() - start).min(8);
    buf[8 - len..].copy_from_slice(&bytes[start..start + len]);
    Ok(u64::from_be_bytes(buf))
}

fn build_evm_payload(
    is_create: bool,
    to: &[u8; 20],
    value: u64,
    gas_limit: u64,
    data: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 20 + 8 + 8 + data.len());
    if is_create {
        payload.push(0x11);
        payload.extend_from_slice(&value.to_le_bytes());
        payload.extend_from_slice(&gas_limit.to_le_bytes());
    } else {
        payload.push(0x10);
        payload.extend_from_slice(to);
        payload.extend_from_slice(&value.to_le_bytes());
        payload.extend_from_slice(&gas_limit.to_le_bytes());
    }
    payload.extend_from_slice(data);
    payload
}

/// ECDSA ecrecover: recover 20-byte Ethereum address from signature.
fn ecrecover_addr(
    hash: &[u8; 32],
    recovery_byte: u8,
    r_vec: &[u8],
    s_vec: &[u8],
) -> Result<[u8; 20], NVmError> {
    let mut r = [0u8; 32];
    let r_len = r_vec.len().min(32);
    r[32 - r_len..].copy_from_slice(&r_vec[r_vec.len().saturating_sub(32)..]);
    let mut s = [0u8; 32];
    let s_len = s_vec.len().min(32);
    s[32 - s_len..].copy_from_slice(&s_vec[s_vec.len().saturating_sub(32)..]);

    // EIP-2: reject high-S signatures to prevent signature malleability.
    // s must be <= secp256k1n / 2.
    let secp256k1_n_over_2: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B,
        0x20, 0xA0,
    ];
    if s > secp256k1_n_over_2 {
        return Err(NVmError::RawChainVerify(
            "high-S signature rejected (EIP-2)".into(),
        ));
    }

    let recovery_id = RecoveryId::from_byte(recovery_byte)
        .ok_or_else(|| NVmError::RawChainVerify("invalid recovery id".into()))?;
    let r_ga: GenericArray<u8, _> = GenericArray::clone_from_slice(&r);
    let s_ga: GenericArray<u8, _> = GenericArray::clone_from_slice(&s);
    let sig = K256Signature::from_scalars(r_ga, s_ga)
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    let recovering_key = VerifyingKey::recover_from_prehash(hash, &sig, recovery_id)
        .map_err(|e| NVmError::RawChainVerify(e.to_string()))?;
    let uncompressed = recovering_key.to_sec1_bytes();
    let addr_hash = keccak256(&uncompressed[1..65]);
    let mut signer = [0u8; 20];
    signer.copy_from_slice(&addr_hash[12..32]);
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::{canonical_evm_payload_from_raw, ensure_supported_evm_execution_semantics};
    use rlp::RlpStream;

    #[test]
    fn rejects_blob_and_7702_execution_semantics() {
        let err = ensure_supported_evm_execution_semantics(&[0x03]).unwrap_err();
        assert!(err.to_string().contains("EIP-4844"));

        let err = ensure_supported_evm_execution_semantics(&[0x04]).unwrap_err();
        assert!(err.to_string().contains("EIP-7702"));

        ensure_supported_evm_execution_semantics(&[0x02]).unwrap();
    }

    #[test]
    fn reconstructs_legacy_call_payload() {
        let mut stream = RlpStream::new_list(9);
        stream.append(&1u64);
        stream.append(&2u64);
        stream.append(&55_000u64);
        stream.append(&vec![0x11u8; 20]);
        stream.append(&vec![0x22u8]);
        stream.append(&vec![0xAAu8, 0xBB]);
        stream.append(&37u64);
        stream.append(&vec![1u8]);
        stream.append(&vec![2u8]);
        let raw = stream.out().to_vec();

        let payload = canonical_evm_payload_from_raw(&raw).expect("payload");
        assert_eq!(payload[0], 0x10);
        assert_eq!(&payload[1..21], &[0x11u8; 20]);
    }
}
