//! Raw transaction format detection and parsing for industry-standard wallets.
//!
//! Supports EVM (legacy EIP-155, EIP-2930, EIP-1559), Solana, and Bitcoin wire formats.
//! Used by `ace_sendRawTransaction` / `eth_sendRawTransaction` to detect format,
//! parse chain identifier, verify signature, map to legacy idcom, and build ACE
//! Transaction for execution.

use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use k256::elliptic_curve::generic_array::GenericArray;
use rlp::{Rlp, RlpStream};
use tiny_keccak::{Hasher, Keccak};

use crate::error::RpcError;

/// Detected format of a raw signed transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawTxFormat {
    /// EIP-155 (and legacy) RLP-signed transaction (EVM).
    Evm,
    /// Solana serialized transaction.
    Solana,
    /// Bitcoin raw transaction.
    Bitcoin,
    /// Tron protobuf-encoded transaction.
    Tron,
    /// ACE native (payload_len + payload + attestation); not "raw" from other chains.
    AceNative,
    /// Unknown or invalid.
    Unknown,
}

/// Result of parsing an EVM signed transaction (works for all EVM tx types).
#[derive(Debug)]
pub struct EvmParsed {
    /// Chain ID from the signature/payload.
    pub chain_id: u64,
    /// Recovered signer address (20 bytes).
    pub signer: [u8; 20],
}

/// Full decode of an EVM tx for building ACE payload (to, value, data, gas_limit).
#[derive(Debug)]
pub struct EvmDecoded {
    pub parsed: EvmParsed,
    /// Transaction nonce from the signed EVM envelope.
    pub nonce: u64,
    /// Ethereum transaction type: 0 = legacy, 1 = EIP-2930, 2 = EIP-1559.
    pub tx_type: u8,
    /// Recipient (20 bytes); empty for contract create.
    pub to: [u8; 20],
    /// Value as u64 (EVM value clamped to 8 bytes).
    pub value: u64,
    /// Gas price style field used for RPC display.
    /// Legacy / Type 1: gas_price, Type 2: max_fee_per_gas.
    pub gas_price: u64,
    /// EIP-1559 max fee per gas, when present.
    pub max_fee_per_gas: Option<u64>,
    /// EIP-1559 max priority fee per gas, when present.
    pub max_priority_fee_per_gas: Option<u64>,
    /// Access list for typed transactions, when present.
    pub access_list: Option<serde_json::Value>,
    /// EIP-4844 max fee per blob gas, when present.
    pub max_fee_per_blob_gas: Option<u64>,
    /// EIP-4844 blob versioned hashes, when present.
    pub blob_versioned_hashes: Option<Vec<[u8; 32]>>,
    /// EIP-7702 authorization list, when present.
    pub authorization_list: Option<serde_json::Value>,
    /// Calldata or init code.
    pub data: Vec<u8>,
    /// Gas limit from the original transaction.
    pub gas_limit: u64,
    /// Raw signature `v` / y-parity value from the original transaction.
    pub signature_v: u64,
    /// Raw signature `r` value, left-padded to 32 bytes.
    pub signature_r: [u8; 32],
    /// Raw signature `s` value, left-padded to 32 bytes.
    pub signature_s: [u8; 32],
    /// True if this is a contract creation (to is empty).
    pub is_create: bool,
}

/// Result of parsing a Solana transaction.
#[derive(Debug)]
pub struct SolanaParsed {
    /// Fee payer / signer public key (32 bytes, Ed25519).
    pub signer: [u8; 32],
}

/// Full decode of a Solana transaction for building ACE SVM payload.
#[derive(Debug)]
pub struct SolanaDecoded {
    pub parsed: SolanaParsed,
    /// Program ID of the first instruction (32 bytes).
    pub program_id: [u8; 32],
    /// Account keys referenced by the first instruction (32 bytes each).
    pub accounts: Vec<[u8; 32]>,
    /// Instruction data for the first instruction.
    pub instruction_data: Vec<u8>,
    /// Number of instructions (for informational purposes).
    pub num_instructions: u16,
}

/// Result of parsing a Bitcoin transaction.
#[derive(Debug)]
pub struct BtcParsed {
    /// Sender's compressed public key (33 bytes).
    pub sender_pubkey: [u8; 33],
}

/// A single Bitcoin transaction output.
#[derive(Debug, Clone)]
pub struct BtcOutput {
    /// Output value in satoshis.
    pub value: u64,
    /// ScriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
}

/// Full decode of a Bitcoin transaction for building ACE BVM payload.
#[derive(Debug)]
pub struct BtcDecoded {
    pub parsed: BtcParsed,
    /// All outputs.
    pub outputs: Vec<BtcOutput>,
    /// Transaction version.
    pub version: u32,
}

/// Re-export for building ACE tx; implementation in ace-runtime.
pub use ace_runtime::crypto::{
    legacy_idcom_btc, legacy_idcom_btc_script, legacy_idcom_evm, legacy_idcom_solana,
};

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

fn left_pad_32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[32 - len..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    out
}

/// Canonical Ethereum transaction hash: `keccak256(raw_signed_tx_bytes)`.
pub fn evm_tx_hash(raw_bytes: &[u8]) -> [u8; 32] {
    keccak256(raw_bytes)
}

/// Detect the format of raw transaction bytes without full parsing.
///
/// Order: try EVM RLP (list of 9 for legacy, or typed prefix), then Solana heuristics,
/// then Bitcoin version bytes, then ACE native (4-byte len prefix + attestation-sized tail).
pub fn detect_format(data: &[u8]) -> RawTxFormat {
    if data.is_empty() {
        return RawTxFormat::Unknown;
    }

    // EVM: RLP-encoded. Legacy is a list of 9 items (0xc0–0xf7 short list or 0xf8+ long list); typed tx starts with 0x01/0x02/0x03/0x04.
    if data[0] >= 0xc0 {
        if let Ok(parsed) = parse_evm(data) {
            if parsed.chain_id > 0 {
                return RawTxFormat::Evm;
            }
        }
    }
    if data.len() >= 1 && (data[0] == 0x01 || data[0] == 0x02 || data[0] == 0x03 || data[0] == 0x04)
    {
        // EIP-2718 typed envelope; treat as EVM
        if parse_evm_typed(data).is_ok() {
            return RawTxFormat::Evm;
        }
    }

    // ACE native: 4-byte LE payload len + payload + 136-byte attestation.
    // Check before Solana so that [1,0,0,0,…] (payload_len=1) is not mis-detected as Solana (num_sig=1).
    if data.len() >= 4 + 136 {
        let payload_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if payload_len <= 65_536 && data.len() >= 4 + payload_len + 136 {
            return RawTxFormat::AceNative;
        }
    }

    // Solana: compact-u16 num_signatures at start; typically 1–2 bytes, then 64*N signature bytes.
    if data.len() >= 2 && data[0] != 0 && data[0] < 255 && data.len() > 64 {
        if is_likely_solana(data) {
            return RawTxFormat::Solana;
        }
    }

    // Bitcoin: version 4 bytes (e.g. 0x01 0x00 0x00 0x00 or 0x02 0x00 0x00 0x00).
    if data.len() >= 4
        && (data[0] == 0x01 || data[0] == 0x02)
        && data[1] == 0
        && data[2] == 0
        && data[3] == 0
    {
        return RawTxFormat::Bitcoin;
    }

    // Tron: protobuf-encoded. Field 1, wire type 2 (length-delimited) starts with 0x0a.
    if data.len() > 2 && data[0] == 0x0a {
        if ace_n_vm::raw_tron::verify_raw_tron_recover_signer(data).is_ok() {
            return RawTxFormat::Tron;
        }
    }

    RawTxFormat::Unknown
}

// ── EVM parsing ──

/// Parse EVM legacy (EIP-155) RLP signed transaction: chain_id and recovered signer.
pub fn parse_evm(data: &[u8]) -> Result<EvmParsed, RpcError> {
    decode_evm_legacy_full(data).map(|d| d.parsed)
}

/// Full decode of legacy EIP-155 tx: chain_id, signer (ecrecover), to, value, data, gas_limit.
pub fn decode_evm_legacy_full(data: &[u8]) -> Result<EvmDecoded, RpcError> {
    let rlp = Rlp::new(data);
    if !rlp.is_list() {
        return Err(RpcError::InvalidParameter("EVM tx must be RLP list".into()));
    }
    let item_count = rlp
        .item_count()
        .map_err(|_| RpcError::InvalidParameter("invalid RLP".into()))?;
    if item_count != 9 {
        return Err(RpcError::InvalidParameter(format!(
            "EVM legacy tx expects 9 RLP items, got {}",
            item_count
        )));
    }

    let nonce: u64 = rlp
        .val_at(0)
        .map_err(|e| RpcError::InvalidParameter(format!("nonce: {}", e)))?;
    let gas_price: u64 = rlp
        .val_at(1)
        .map_err(|e| RpcError::InvalidParameter(format!("gas_price: {}", e)))?;
    let gas_limit: u64 = rlp
        .val_at(2)
        .map_err(|e| RpcError::InvalidParameter(format!("gas_limit: {}", e)))?;
    let to_vec: Vec<u8> = rlp
        .val_at(3)
        .map_err(|e| RpcError::InvalidParameter(format!("to: {}", e)))?;
    let value_vec: Vec<u8> = rlp
        .val_at(4)
        .map_err(|e| RpcError::InvalidParameter(format!("value: {}", e)))?;
    let data: Vec<u8> = rlp
        .val_at(5)
        .map_err(|e| RpcError::InvalidParameter(format!("data: {}", e)))?;

    let v: u64 = rlp
        .val_at(6)
        .map_err(|e| RpcError::InvalidParameter(format!("v: {}", e)))?;
    let r_vec: Vec<u8> = rlp
        .val_at(7)
        .map_err(|e| RpcError::InvalidParameter(format!("r: {}", e)))?;
    let s_vec: Vec<u8> = rlp
        .val_at(8)
        .map_err(|e| RpcError::InvalidParameter(format!("s: {}", e)))?;

    let chain_id = if v >= 35 {
        (v - 35) / 2
    } else {
        return Err(RpcError::InvalidParameter(
            "EVM tx must use EIP-155 (v >= 35) for chain_id".into(),
        ));
    };

    // EIP-155 signing hash: keccak256(RLP([nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0]))
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
    let signer = ecrecover(&hash, recovery_byte, &r_vec, &s_vec)?;

    let is_create = to_vec.is_empty();
    let mut to = [0u8; 20];
    if to_vec.len() >= 20 {
        to.copy_from_slice(&to_vec[to_vec.len() - 20..]);
    } else if !to_vec.is_empty() {
        to[20 - to_vec.len()..].copy_from_slice(&to_vec);
    }

    let value = value_to_u64(&value_vec)?;

    Ok(EvmDecoded {
        parsed: EvmParsed { chain_id, signer },
        nonce,
        tx_type: 0,
        to,
        value,
        gas_price,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        authorization_list: None,
        data,
        gas_limit,
        signature_v: v,
        signature_r: left_pad_32(&r_vec),
        signature_s: left_pad_32(&s_vec),
        is_create,
    })
}

/// Full decode of EIP-2718 typed EVM tx (Type 1: EIP-2930, Type 2: EIP-1559).
///
/// Recovers the signer address via ECDSA ecrecover and extracts to/value/data/gas_limit
/// for building the ACE payload.
pub fn decode_evm_typed_full(data: &[u8]) -> Result<EvmDecoded, RpcError> {
    if data.len() < 2 {
        return Err(RpcError::InvalidParameter("typed tx too short".into()));
    }
    let tx_type = data[0];
    let payload = &data[1..];
    let rlp = Rlp::new(payload);

    if !rlp.is_list() {
        return Err(RpcError::InvalidParameter(
            "typed tx payload must be RLP list".into(),
        ));
    }

    match tx_type {
        0x01 => decode_eip2930(tx_type, &rlp),
        0x02 => decode_eip1559(tx_type, &rlp),
        0x03 => decode_eip4844(tx_type, &rlp),
        0x04 => decode_eip7702(tx_type, &rlp),
        other => Err(RpcError::InvalidParameter(format!(
            "unsupported EVM tx type: 0x{:02x}",
            other
        ))),
    }
}

/// Decode any EVM tx (legacy or typed) — tries typed first, then legacy.
pub fn decode_evm_auto(data: &[u8]) -> Result<EvmDecoded, RpcError> {
    if data.is_empty() {
        return Err(RpcError::InvalidParameter("empty tx data".into()));
    }

    // Typed transactions start with 0x01 or 0x02
    if matches!(data[0], 0x01 | 0x02 | 0x03 | 0x04) {
        return decode_evm_typed_full(data);
    }

    // Legacy transactions start with RLP list prefix (0xc0+)
    if data[0] >= 0xc0 {
        return decode_evm_legacy_full(data);
    }

    Err(RpcError::InvalidParameter(
        "unrecognized EVM tx format".into(),
    ))
}

/// EIP-2930 (Type 1): [chain_id, nonce, gas_price, gas_limit, to, value, data, access_list, y_parity, r, s]
fn decode_eip2930(tx_type: u8, rlp: &Rlp) -> Result<EvmDecoded, RpcError> {
    let item_count = rlp
        .item_count()
        .map_err(|e| RpcError::InvalidParameter(format!("invalid RLP: {e}")))?;
    if item_count != 11 {
        return Err(RpcError::InvalidParameter(format!(
            "EIP-2930 expects 11 RLP items, got {}",
            item_count
        )));
    }

    // Decode fields we need for the ACE payload
    let chain_id: u64 = rlp
        .val_at(0)
        .map_err(|e| RpcError::InvalidParameter(format!("chain_id: {e}")))?;
    let nonce: u64 = rlp
        .val_at(1)
        .map_err(|e| RpcError::InvalidParameter(format!("nonce: {e}")))?;
    let gas_price: u64 = rlp
        .val_at(2)
        .map_err(|e| RpcError::InvalidParameter(format!("gas_price: {e}")))?;
    let gas_limit: u64 = rlp
        .val_at(3)
        .map_err(|e| RpcError::InvalidParameter(format!("gas_limit: {e}")))?;
    let to_vec: Vec<u8> = rlp
        .val_at(4)
        .map_err(|e| RpcError::InvalidParameter(format!("to: {e}")))?;
    let value_vec: Vec<u8> = rlp
        .val_at(5)
        .map_err(|e| RpcError::InvalidParameter(format!("value: {e}")))?;
    let data: Vec<u8> = rlp
        .val_at(6)
        .map_err(|e| RpcError::InvalidParameter(format!("data: {e}")))?;

    // Signature fields (y_parity is 0 or 1 for typed txs, not 27+)
    let y_parity: u64 = rlp
        .val_at(8)
        .map_err(|e| RpcError::InvalidParameter(format!("y_parity: {e}")))?;
    let r_vec: Vec<u8> = rlp
        .val_at(9)
        .map_err(|e| RpcError::InvalidParameter(format!("r: {e}")))?;
    let s_vec: Vec<u8> = rlp
        .val_at(10)
        .map_err(|e| RpcError::InvalidParameter(format!("s: {e}")))?;

    // Reconstruct signing payload using raw RLP bytes (avoids u256 overflow issues)
    // 0x01 || RLP([chain_id, nonce, gas_price, gas_limit, to, value, data, access_list])
    let signing_hash = build_typed_signing_hash(tx_type, rlp, 8)?;

    let signer = ecrecover(&signing_hash, y_parity as u8, &r_vec, &s_vec)?;

    let is_create = to_vec.is_empty();
    let mut to = [0u8; 20];
    if to_vec.len() >= 20 {
        to.copy_from_slice(&to_vec[to_vec.len() - 20..]);
    } else if !to_vec.is_empty() {
        to[20 - to_vec.len()..].copy_from_slice(&to_vec);
    }

    Ok(EvmDecoded {
        parsed: EvmParsed { chain_id, signer },
        nonce,
        tx_type,
        to,
        value: value_to_u64(&value_vec)?,
        gas_price,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: Some(parse_access_list(
            &rlp.at(7)
                .map_err(|e| RpcError::InvalidParameter(format!("access_list: {e}")))?,
        )?),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        authorization_list: None,
        data,
        gas_limit,
        signature_v: y_parity,
        signature_r: left_pad_32(&r_vec),
        signature_s: left_pad_32(&s_vec),
        is_create,
    })
}

/// EIP-1559 (Type 2): [chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list, y_parity, r, s]
fn decode_eip1559(tx_type: u8, rlp: &Rlp) -> Result<EvmDecoded, RpcError> {
    let item_count = rlp
        .item_count()
        .map_err(|e| RpcError::InvalidParameter(format!("invalid RLP: {e}")))?;
    if item_count != 12 {
        return Err(RpcError::InvalidParameter(format!(
            "EIP-1559 expects 12 RLP items, got {}",
            item_count
        )));
    }

    // Decode fields we need for the ACE payload
    let chain_id: u64 = rlp
        .val_at(0)
        .map_err(|e| RpcError::InvalidParameter(format!("chain_id: {e}")))?;
    let nonce: u64 = rlp
        .val_at(1)
        .map_err(|e| RpcError::InvalidParameter(format!("nonce: {e}")))?;
    let max_priority_fee_per_gas: u64 = rlp
        .val_at(2)
        .map_err(|e| RpcError::InvalidParameter(format!("max_priority_fee_per_gas: {e}")))?;
    let max_fee_per_gas: u64 = rlp
        .val_at(3)
        .map_err(|e| RpcError::InvalidParameter(format!("max_fee_per_gas: {e}")))?;
    let gas_limit: u64 = rlp
        .val_at(4)
        .map_err(|e| RpcError::InvalidParameter(format!("gas_limit: {e}")))?;
    let to_vec: Vec<u8> = rlp
        .val_at(5)
        .map_err(|e| RpcError::InvalidParameter(format!("to: {e}")))?;
    let value_vec: Vec<u8> = rlp
        .val_at(6)
        .map_err(|e| RpcError::InvalidParameter(format!("value: {e}")))?;
    let data: Vec<u8> = rlp
        .val_at(7)
        .map_err(|e| RpcError::InvalidParameter(format!("data: {e}")))?;

    // Signature fields
    let y_parity: u64 = rlp
        .val_at(9)
        .map_err(|e| RpcError::InvalidParameter(format!("y_parity: {e}")))?;
    let r_vec: Vec<u8> = rlp
        .val_at(10)
        .map_err(|e| RpcError::InvalidParameter(format!("r: {e}")))?;
    let s_vec: Vec<u8> = rlp
        .val_at(11)
        .map_err(|e| RpcError::InvalidParameter(format!("s: {e}")))?;

    // Reconstruct signing payload using raw RLP bytes
    // 0x02 || RLP([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list])
    let signing_hash = build_typed_signing_hash(tx_type, rlp, 9)?;

    let signer = ecrecover(&signing_hash, y_parity as u8, &r_vec, &s_vec)?;

    let is_create = to_vec.is_empty();
    let mut to = [0u8; 20];
    if to_vec.len() >= 20 {
        to.copy_from_slice(&to_vec[to_vec.len() - 20..]);
    } else if !to_vec.is_empty() {
        to[20 - to_vec.len()..].copy_from_slice(&to_vec);
    }

    Ok(EvmDecoded {
        parsed: EvmParsed { chain_id, signer },
        nonce,
        tx_type,
        to,
        value: value_to_u64(&value_vec)?,
        gas_price: max_fee_per_gas,
        max_fee_per_gas: Some(max_fee_per_gas),
        max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
        access_list: Some(parse_access_list(
            &rlp.at(8)
                .map_err(|e| RpcError::InvalidParameter(format!("access_list: {e}")))?,
        )?),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        authorization_list: None,
        data,
        gas_limit,
        signature_v: y_parity,
        signature_r: left_pad_32(&r_vec),
        signature_s: left_pad_32(&s_vec),
        is_create,
    })
}

/// EIP-4844 (Type 3):
/// [chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data,
///  access_list, max_fee_per_blob_gas, blob_versioned_hashes, y_parity, r, s]
fn decode_eip4844(tx_type: u8, rlp: &Rlp) -> Result<EvmDecoded, RpcError> {
    let item_count = rlp
        .item_count()
        .map_err(|e| RpcError::InvalidParameter(format!("invalid RLP: {e}")))?;
    if item_count != 14 {
        return Err(RpcError::InvalidParameter(format!(
            "EIP-4844 expects 14 RLP items, got {}",
            item_count
        )));
    }

    let chain_id: u64 = rlp
        .val_at(0)
        .map_err(|e| RpcError::InvalidParameter(format!("chain_id: {e}")))?;
    let nonce: u64 = rlp
        .val_at(1)
        .map_err(|e| RpcError::InvalidParameter(format!("nonce: {e}")))?;
    let max_priority_fee_per_gas: u64 = rlp
        .val_at(2)
        .map_err(|e| RpcError::InvalidParameter(format!("max_priority_fee_per_gas: {e}")))?;
    let max_fee_per_gas: u64 = rlp
        .val_at(3)
        .map_err(|e| RpcError::InvalidParameter(format!("max_fee_per_gas: {e}")))?;
    let gas_limit: u64 = rlp
        .val_at(4)
        .map_err(|e| RpcError::InvalidParameter(format!("gas_limit: {e}")))?;
    let to_vec: Vec<u8> = rlp
        .val_at(5)
        .map_err(|e| RpcError::InvalidParameter(format!("to: {e}")))?;
    let value_vec: Vec<u8> = rlp
        .val_at(6)
        .map_err(|e| RpcError::InvalidParameter(format!("value: {e}")))?;
    let data: Vec<u8> = rlp
        .val_at(7)
        .map_err(|e| RpcError::InvalidParameter(format!("data: {e}")))?;
    let access_list = parse_access_list(
        &rlp.at(8)
            .map_err(|e| RpcError::InvalidParameter(format!("access_list: {e}")))?,
    )?;
    let max_fee_per_blob_gas: u64 = rlp
        .val_at(9)
        .map_err(|e| RpcError::InvalidParameter(format!("max_fee_per_blob_gas: {e}")))?;
    let blob_versioned_hashes = parse_blob_versioned_hashes(
        &rlp.at(10)
            .map_err(|e| RpcError::InvalidParameter(format!("blob_versioned_hashes: {e}")))?,
    )?;
    let y_parity: u64 = rlp
        .val_at(11)
        .map_err(|e| RpcError::InvalidParameter(format!("y_parity: {e}")))?;
    let r_vec: Vec<u8> = rlp
        .val_at(12)
        .map_err(|e| RpcError::InvalidParameter(format!("r: {e}")))?;
    let s_vec: Vec<u8> = rlp
        .val_at(13)
        .map_err(|e| RpcError::InvalidParameter(format!("s: {e}")))?;

    let signing_hash = build_typed_signing_hash(tx_type, rlp, 11)?;
    let signer = ecrecover(&signing_hash, y_parity as u8, &r_vec, &s_vec)?;

    let is_create = to_vec.is_empty();
    let mut to = [0u8; 20];
    if to_vec.len() >= 20 {
        to.copy_from_slice(&to_vec[to_vec.len() - 20..]);
    } else if !to_vec.is_empty() {
        to[20 - to_vec.len()..].copy_from_slice(&to_vec);
    }

    Ok(EvmDecoded {
        parsed: EvmParsed { chain_id, signer },
        nonce,
        tx_type,
        to,
        value: value_to_u64(&value_vec)?,
        gas_price: max_fee_per_gas,
        max_fee_per_gas: Some(max_fee_per_gas),
        max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
        access_list: Some(access_list),
        max_fee_per_blob_gas: Some(max_fee_per_blob_gas),
        blob_versioned_hashes: Some(blob_versioned_hashes),
        authorization_list: None,
        data,
        gas_limit,
        signature_v: y_parity,
        signature_r: left_pad_32(&r_vec),
        signature_s: left_pad_32(&s_vec),
        is_create,
    })
}

/// EIP-7702 (Type 4):
/// [chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data,
///  access_list, authorization_list, y_parity, r, s]
fn decode_eip7702(tx_type: u8, rlp: &Rlp) -> Result<EvmDecoded, RpcError> {
    let item_count = rlp
        .item_count()
        .map_err(|e| RpcError::InvalidParameter(format!("invalid RLP: {e}")))?;
    if item_count != 13 {
        return Err(RpcError::InvalidParameter(format!(
            "EIP-7702 expects 13 RLP items, got {}",
            item_count
        )));
    }

    let chain_id: u64 = rlp
        .val_at(0)
        .map_err(|e| RpcError::InvalidParameter(format!("chain_id: {e}")))?;
    let nonce: u64 = rlp
        .val_at(1)
        .map_err(|e| RpcError::InvalidParameter(format!("nonce: {e}")))?;
    let max_priority_fee_per_gas: u64 = rlp
        .val_at(2)
        .map_err(|e| RpcError::InvalidParameter(format!("max_priority_fee_per_gas: {e}")))?;
    let max_fee_per_gas: u64 = rlp
        .val_at(3)
        .map_err(|e| RpcError::InvalidParameter(format!("max_fee_per_gas: {e}")))?;
    let gas_limit: u64 = rlp
        .val_at(4)
        .map_err(|e| RpcError::InvalidParameter(format!("gas_limit: {e}")))?;
    let to_vec: Vec<u8> = rlp
        .val_at(5)
        .map_err(|e| RpcError::InvalidParameter(format!("to: {e}")))?;
    let value_vec: Vec<u8> = rlp
        .val_at(6)
        .map_err(|e| RpcError::InvalidParameter(format!("value: {e}")))?;
    let data: Vec<u8> = rlp
        .val_at(7)
        .map_err(|e| RpcError::InvalidParameter(format!("data: {e}")))?;
    let access_list = parse_access_list(
        &rlp.at(8)
            .map_err(|e| RpcError::InvalidParameter(format!("access_list: {e}")))?,
    )?;
    let authorization_list = parse_authorization_list(
        &rlp.at(9)
            .map_err(|e| RpcError::InvalidParameter(format!("authorization_list: {e}")))?,
    )?;
    let y_parity: u64 = rlp
        .val_at(10)
        .map_err(|e| RpcError::InvalidParameter(format!("y_parity: {e}")))?;
    let r_vec: Vec<u8> = rlp
        .val_at(11)
        .map_err(|e| RpcError::InvalidParameter(format!("r: {e}")))?;
    let s_vec: Vec<u8> = rlp
        .val_at(12)
        .map_err(|e| RpcError::InvalidParameter(format!("s: {e}")))?;

    let signing_hash = build_typed_signing_hash(tx_type, rlp, 10)?;
    let signer = ecrecover(&signing_hash, y_parity as u8, &r_vec, &s_vec)?;

    let is_create = to_vec.is_empty();
    let mut to = [0u8; 20];
    if to_vec.len() >= 20 {
        to.copy_from_slice(&to_vec[to_vec.len() - 20..]);
    } else if !to_vec.is_empty() {
        to[20 - to_vec.len()..].copy_from_slice(&to_vec);
    }

    Ok(EvmDecoded {
        parsed: EvmParsed { chain_id, signer },
        nonce,
        tx_type,
        to,
        value: value_to_u64(&value_vec)?,
        gas_price: max_fee_per_gas,
        max_fee_per_gas: Some(max_fee_per_gas),
        max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
        access_list: Some(access_list),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        authorization_list: Some(authorization_list),
        data,
        gas_limit,
        signature_v: y_parity,
        signature_r: left_pad_32(&r_vec),
        signature_s: left_pad_32(&s_vec),
        is_create,
    })
}

/// Build the signing hash for a typed EVM transaction.
///
/// Uses raw RLP bytes to avoid u256 decode issues with fee fields.
/// Result: keccak256(tx_type || RLP([field_0, ..., field_{n-1}]))
fn build_typed_signing_hash(
    tx_type: u8,
    rlp: &Rlp,
    num_sign_fields: usize,
) -> Result<[u8; 32], RpcError> {
    let mut stream = RlpStream::new_list(num_sign_fields);
    for i in 0..num_sign_fields {
        let item = rlp
            .at(i)
            .map_err(|e| RpcError::InvalidParameter(format!("rlp field {i}: {e}")))?;
        stream.append_raw(item.as_raw(), 1);
    }
    let encoded = stream.out();

    let mut signing_input = Vec::with_capacity(1 + encoded.len());
    signing_input.push(tx_type);
    signing_input.extend_from_slice(&encoded);
    Ok(keccak256(&signing_input))
}

/// ECDSA signature recovery — returns 20-byte Ethereum address.
fn ecrecover(
    hash: &[u8; 32],
    recovery_byte: u8,
    r_vec: &[u8],
    s_vec: &[u8],
) -> Result<[u8; 20], RpcError> {
    let mut r = [0u8; 32];
    let r_len = r_vec.len().min(32);
    r[32 - r_len..].copy_from_slice(&r_vec[r_vec.len().saturating_sub(32)..]);
    let mut s = [0u8; 32];
    let s_len = s_vec.len().min(32);
    s[32 - s_len..].copy_from_slice(&s_vec[s_vec.len().saturating_sub(32)..]);

    let recovery_id = RecoveryId::from_byte(recovery_byte)
        .ok_or_else(|| RpcError::InvalidParameter("invalid recovery id".into()))?;
    let r_ga = GenericArray::clone_from_slice(&r);
    let s_ga = GenericArray::clone_from_slice(&s);
    let sig = K256Signature::from_scalars(r_ga, s_ga)
        .map_err(|e| RpcError::InvalidParameter(format!("EVM signature: {}", e)))?;
    let recovering_key = VerifyingKey::recover_from_prehash(hash, &sig, recovery_id)
        .map_err(|e| RpcError::InvalidParameter(format!("ecrecover: {}", e)))?;
    let uncompressed = recovering_key.to_sec1_bytes();
    let addr_hash = keccak256(&uncompressed[1..65]);
    let mut signer = [0u8; 20];
    signer.copy_from_slice(&addr_hash[12..32]);
    Ok(signer)
}

/// Decode EVM value (up to 32 bytes) to u64. Fails if value exceeds u64::MAX.
fn value_to_u64(bytes: &[u8]) -> Result<u64, RpcError> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 8 {
        let leading = &bytes[..bytes.len() - 8];
        if leading.iter().any(|&b| b != 0) {
            return Err(RpcError::InvalidParameter(
                "EVM value exceeds u64::MAX; ACE only supports u64 value".into(),
            ));
        }
    }
    let mut buf = [0u8; 8];
    let start = bytes.len().saturating_sub(8);
    let len = (bytes.len() - start).min(8);
    buf[8 - len..].copy_from_slice(&bytes[start..start + len]);
    Ok(u64::from_be_bytes(buf))
}

/// Parse EIP-2718 typed EVM tx (0x01/0x02) — minimal parse for format detection.
pub(crate) fn parse_evm_typed(data: &[u8]) -> Result<EvmParsed, RpcError> {
    if data.len() < 2 {
        return Err(RpcError::InvalidParameter("typed tx too short".into()));
    }
    let _tx_type = data[0];
    let payload = &data[1..];
    let rlp = Rlp::new(payload);
    let chain_id: u64 = rlp
        .val_at(0)
        .map_err(|e| RpcError::InvalidParameter(e.to_string()))?;
    // For format detection we only need chain_id. Full signer recovery uses decode_evm_typed_full.
    Ok(EvmParsed {
        chain_id,
        signer: [0u8; 20],
    })
}

fn parse_access_list(rlp: &Rlp) -> Result<serde_json::Value, RpcError> {
    let item_count = rlp
        .item_count()
        .map_err(|e| RpcError::InvalidParameter(format!("access_list: {e}")))?;
    let mut entries = Vec::with_capacity(item_count);
    for i in 0..item_count {
        let entry = rlp
            .at(i)
            .map_err(|e| RpcError::InvalidParameter(format!("access_list[{i}]: {e}")))?;
        let address: Vec<u8> = entry
            .val_at(0)
            .map_err(|e| RpcError::InvalidParameter(format!("access_list[{i}].address: {e}")))?;
        let storage_keys = entry.at(1).map_err(|e| {
            RpcError::InvalidParameter(format!("access_list[{i}].storageKeys: {e}"))
        })?;
        let storage_count = storage_keys.item_count().map_err(|e| {
            RpcError::InvalidParameter(format!("access_list[{i}].storageKeys: {e}"))
        })?;
        let mut keys = Vec::with_capacity(storage_count);
        for key_idx in 0..storage_count {
            let key: Vec<u8> = storage_keys.val_at(key_idx).map_err(|e| {
                RpcError::InvalidParameter(format!("access_list[{i}].storageKeys[{key_idx}]: {e}"))
            })?;
            keys.push(format!("0x{}", hex::encode(left_pad_32(&key))));
        }
        let address_hex = if address.is_empty() {
            "0x0000000000000000000000000000000000000000".to_string()
        } else {
            let mut padded = [0u8; 20];
            let len = address.len().min(20);
            padded[20 - len..].copy_from_slice(&address[address.len().saturating_sub(20)..]);
            format!("0x{}", hex::encode(padded))
        };
        entries.push(serde_json::json!({
            "address": address_hex,
            "storageKeys": keys,
        }));
    }
    Ok(serde_json::Value::Array(entries))
}

fn parse_blob_versioned_hashes(rlp: &Rlp) -> Result<Vec<[u8; 32]>, RpcError> {
    let item_count = rlp
        .item_count()
        .map_err(|e| RpcError::InvalidParameter(format!("blob_versioned_hashes: {e}")))?;
    let mut hashes = Vec::with_capacity(item_count);
    for i in 0..item_count {
        let value: Vec<u8> = rlp
            .val_at(i)
            .map_err(|e| RpcError::InvalidParameter(format!("blob_versioned_hashes[{i}]: {e}")))?;
        hashes.push(left_pad_32(&value));
    }
    Ok(hashes)
}

fn parse_authorization_list(rlp: &Rlp) -> Result<serde_json::Value, RpcError> {
    let item_count = rlp
        .item_count()
        .map_err(|e| RpcError::InvalidParameter(format!("authorization_list: {e}")))?;
    let mut entries = Vec::with_capacity(item_count);
    for i in 0..item_count {
        let entry = rlp
            .at(i)
            .map_err(|e| RpcError::InvalidParameter(format!("authorization_list[{i}]: {e}")))?;
        let chain_id: u64 = entry.val_at(0).map_err(|e| {
            RpcError::InvalidParameter(format!("authorization_list[{i}].chainId: {e}"))
        })?;
        let address: Vec<u8> = entry.val_at(1).map_err(|e| {
            RpcError::InvalidParameter(format!("authorization_list[{i}].address: {e}"))
        })?;
        let nonce: u64 = entry.val_at(2).map_err(|e| {
            RpcError::InvalidParameter(format!("authorization_list[{i}].nonce: {e}"))
        })?;
        let y_parity: u64 = entry.val_at(3).map_err(|e| {
            RpcError::InvalidParameter(format!("authorization_list[{i}].yParity: {e}"))
        })?;
        let r: Vec<u8> = entry
            .val_at(4)
            .map_err(|e| RpcError::InvalidParameter(format!("authorization_list[{i}].r: {e}")))?;
        let s: Vec<u8> = entry
            .val_at(5)
            .map_err(|e| RpcError::InvalidParameter(format!("authorization_list[{i}].s: {e}")))?;
        let mut padded = [0u8; 20];
        let len = address.len().min(20);
        padded[20 - len..].copy_from_slice(&address[address.len().saturating_sub(20)..]);
        entries.push(serde_json::json!({
            "chainId": format!("0x{:x}", chain_id),
            "address": format!("0x{}", hex::encode(padded)),
            "nonce": format!("0x{:x}", nonce),
            "yParity": format!("0x{:x}", y_parity),
            "r": format!("0x{}", hex::encode(left_pad_32(&r))),
            "s": format!("0x{}", hex::encode(left_pad_32(&s))),
        }));
    }
    Ok(serde_json::Value::Array(entries))
}

/// Heuristic: Solana txs start with compact-u16 (1–3 bytes) then 64 bytes per signature.
fn is_likely_solana(data: &[u8]) -> bool {
    let n_sig = data[0] as usize;
    if n_sig == 0 || n_sig > 16 {
        return false;
    }
    let sig_len = 64 * n_sig;
    data.len() > sig_len + 1
}

/// Build ACE payload for EVM call: 0x10 || to (20) || value (8 LE) || gas_limit (8 LE) || data.
pub fn evm_payload_call(to: &[u8; 20], value: u64, gas_limit: u64, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 20 + 8 + 8 + data.len());
    payload.push(0x10);
    payload.extend_from_slice(to);
    payload.extend_from_slice(&value.to_le_bytes());
    payload.extend_from_slice(&gas_limit.to_le_bytes());
    payload.extend_from_slice(data);
    payload
}

/// Build ACE payload for EVM create: 0x11 || value (8 LE) || gas_limit (8 LE) || init_code.
pub fn evm_payload_create(value: u64, gas_limit: u64, init_code: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 8 + 8 + init_code.len());
    payload.push(0x11);
    payload.extend_from_slice(&value.to_le_bytes());
    payload.extend_from_slice(&gas_limit.to_le_bytes());
    payload.extend_from_slice(init_code);
    payload
}

/// Validate that the raw tx is intended for this chain.
///
/// - EVM: decoded chain_id must equal `expected_chain_id` (u32, so compared as u64).
/// - Solana / Bitcoin: no chain_id in wire format; we accept by format (caller may restrict later).
pub fn validate_chain(
    format: RawTxFormat,
    expected_chain_id: u32,
    evm_parsed: Option<&EvmParsed>,
) -> Result<(), RpcError> {
    match format {
        RawTxFormat::Evm => {
            let p = evm_parsed
                .ok_or_else(|| RpcError::InvalidParameter("EVM parse required".into()))?;
            if p.chain_id != expected_chain_id as u64 {
                return Err(RpcError::InvalidParameter(format!(
                    "wrong chain: tx chain_id {} != expected {}",
                    p.chain_id, expected_chain_id
                )));
            }
        }
        RawTxFormat::Solana | RawTxFormat::Bitcoin | RawTxFormat::Tron => {
            // No chain_id in wire format; accept by format. Node only runs one chain.
        }
        RawTxFormat::AceNative => {
            // Native ACE tx; chain_id is validated by mempool via attestation.domain.
        }
        RawTxFormat::Unknown => {
            return Err(RpcError::InvalidParameter("unknown raw tx format".into()))
        }
    }
    Ok(())
}

// ── Solana parsing ──

/// Decode a Solana compact-u16 value from bytes at the given offset.
fn decode_compact_u16(data: &[u8], offset: &mut usize) -> Result<u16, RpcError> {
    if *offset >= data.len() {
        return Err(RpcError::InvalidParameter(
            "solana: unexpected end of data (compact-u16)".into(),
        ));
    }
    let byte0 = data[*offset] as u16;
    *offset += 1;
    if byte0 < 0x80 {
        return Ok(byte0);
    }
    if *offset >= data.len() {
        return Err(RpcError::InvalidParameter(
            "solana: truncated compact-u16".into(),
        ));
    }
    let byte1 = data[*offset] as u16;
    *offset += 1;
    let value = (byte0 & 0x7F) | ((byte1 & 0x7F) << 7);
    if byte1 < 0x80 {
        return Ok(value);
    }
    if *offset >= data.len() {
        return Err(RpcError::InvalidParameter(
            "solana: truncated compact-u16 (3rd byte)".into(),
        ));
    }
    let byte2 = data[*offset] as u16;
    *offset += 1;
    Ok(value | ((byte2 & 0x03) << 14))
}

/// Ensure we can read `n` more bytes from `offset`.
fn ensure_remaining(data: &[u8], offset: usize, n: usize, ctx: &str) -> Result<(), RpcError> {
    if offset + n > data.len() {
        return Err(RpcError::InvalidParameter(format!(
            "solana: unexpected end of data at {ctx} (need {n} bytes, have {})",
            data.len() - offset
        )));
    }
    Ok(())
}

/// Full decode of a Solana transaction.
///
/// Extracts the fee payer (signer), signatures, and first instruction details
/// for building an ACE SVM payload.
pub fn decode_solana_full(data: &[u8]) -> Result<SolanaDecoded, RpcError> {
    let mut offset = 0;

    // 1. Read num_signatures (compact-u16)
    let num_signatures = decode_compact_u16(data, &mut offset)? as usize;
    if num_signatures == 0 {
        return Err(RpcError::InvalidParameter("solana: no signatures".into()));
    }

    // 2. Read signatures (64 bytes each) — we store the first for verification
    ensure_remaining(data, offset, 64 * num_signatures, "signatures")?;
    // Skip signatures for now (verification happens in the dispatcher)
    offset += 64 * num_signatures;

    // 3. Message starts here — support legacy and versioned v0 without ALT.
    if offset >= data.len() {
        return Err(RpcError::InvalidParameter("solana: missing message".into()));
    }
    let versioned = data[offset] & 0x80 != 0;
    if versioned {
        let version = data[offset] & 0x7f;
        if version != 0 {
            return Err(RpcError::InvalidParameter(format!(
                "solana: unsupported message version {version}"
            )));
        }
        offset += 1;
    }

    // Message header: 3 bytes
    ensure_remaining(data, offset, 3, "message header")?;
    let num_required_signatures = data[offset] as usize;
    let _num_readonly_signed = data[offset + 1];
    let _num_readonly_unsigned = data[offset + 2];
    offset += 3;

    if num_required_signatures == 0 {
        return Err(RpcError::InvalidParameter(
            "solana: num_required_signatures is 0".into(),
        ));
    }
    if num_required_signatures != num_signatures {
        return Err(RpcError::InvalidParameter(format!(
            "solana: signature count {} does not match num_required_signatures {}",
            num_signatures, num_required_signatures
        )));
    }

    // 4. Read account keys
    let num_account_keys = decode_compact_u16(data, &mut offset)? as usize;
    if num_account_keys == 0 {
        return Err(RpcError::InvalidParameter("solana: no account keys".into()));
    }
    if num_account_keys < num_required_signatures {
        return Err(RpcError::InvalidParameter(format!(
            "solana: account key count {} is smaller than required signers {}",
            num_account_keys, num_required_signatures
        )));
    }
    ensure_remaining(data, offset, 32 * num_account_keys, "account keys")?;
    let mut account_keys = Vec::with_capacity(num_account_keys);
    for _ in 0..num_account_keys {
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[offset..offset + 32]);
        account_keys.push(key);
        offset += 32;
    }

    // Fee payer = first account key (first required signer)
    let signer = account_keys[0];

    // 5. Recent blockhash (32 bytes) — skip
    ensure_remaining(data, offset, 32, "recent_blockhash")?;
    offset += 32;

    // 6. Read instructions
    let num_instructions = decode_compact_u16(data, &mut offset)?;
    if num_instructions == 0 {
        return Err(RpcError::InvalidParameter("solana: no instructions".into()));
    }

    // Parse the first instruction for building the ACE SVM payload
    // program_id_index (1 byte)
    ensure_remaining(data, offset, 1, "program_id_index")?;
    let program_id_index = data[offset] as usize;
    offset += 1;
    if program_id_index >= account_keys.len() {
        return Err(RpcError::InvalidParameter(format!(
            "solana: program_id_index {} out of range (have {} keys)",
            program_id_index,
            account_keys.len()
        )));
    }
    let program_id = account_keys[program_id_index];

    // Account indices (compact-u16 count + 1 byte each)
    let num_ix_accounts = decode_compact_u16(data, &mut offset)? as usize;
    ensure_remaining(data, offset, num_ix_accounts, "instruction account indices")?;
    let mut accounts = Vec::with_capacity(num_ix_accounts);
    for _ in 0..num_ix_accounts {
        let acct_idx = data[offset] as usize;
        offset += 1;
        if acct_idx >= account_keys.len() {
            return Err(RpcError::InvalidParameter(format!(
                "solana: account index {} out of range",
                acct_idx
            )));
        }
        accounts.push(account_keys[acct_idx]);
    }

    // Instruction data (compact-u16 length + data bytes)
    let ix_data_len = decode_compact_u16(data, &mut offset)? as usize;
    ensure_remaining(data, offset, ix_data_len, "instruction data")?;
    let instruction_data = data[offset..offset + ix_data_len].to_vec();
    offset += ix_data_len;

    if versioned {
        let lookup_count = decode_compact_u16(data, &mut offset)? as usize;
        if lookup_count != 0 {
            return Err(RpcError::InvalidParameter(
                "solana address lookup tables are not supported yet".into(),
            ));
        }
    }
    if offset != data.len() {
        return Err(RpcError::InvalidParameter(
            "solana: unexpected trailing bytes".into(),
        ));
    }

    Ok(SolanaDecoded {
        parsed: SolanaParsed { signer },
        program_id,
        accounts,
        instruction_data,
        num_instructions,
    })
}

/// Build ACE SVM invoke payload from a decoded Solana instruction.
///
/// Format: 0x20 || program_id (32) || num_accounts (1) || accounts (N*32) || data
pub fn solana_payload_invoke(decoded: &SolanaDecoded) -> Vec<u8> {
    let num_accounts = decoded.accounts.len().min(255) as u8;
    let mut payload = Vec::with_capacity(
        1 + 32 + 1 + (num_accounts as usize) * 32 + decoded.instruction_data.len(),
    );
    payload.push(0x20); // SVM invoke opcode
    payload.extend_from_slice(&decoded.program_id);
    payload.push(num_accounts);
    for acct in &decoded.accounts[..num_accounts as usize] {
        payload.extend_from_slice(acct);
    }
    payload.extend_from_slice(&decoded.instruction_data);
    payload
}

// ── Bitcoin parsing ──

/// Decode a Bitcoin varint from bytes at the given offset.
fn decode_btc_varint(data: &[u8], offset: &mut usize) -> Result<u64, RpcError> {
    if *offset >= data.len() {
        return Err(RpcError::InvalidParameter(
            "btc: unexpected end of data (varint)".into(),
        ));
    }
    let first = data[*offset];
    *offset += 1;
    match first {
        0..=0xFC => Ok(first as u64),
        0xFD => {
            if *offset + 2 > data.len() {
                return Err(RpcError::InvalidParameter(
                    "btc: truncated varint u16".into(),
                ));
            }
            let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]) as u64;
            *offset += 2;
            Ok(val)
        }
        0xFE => {
            if *offset + 4 > data.len() {
                return Err(RpcError::InvalidParameter(
                    "btc: truncated varint u32".into(),
                ));
            }
            let val = u32::from_le_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]) as u64;
            *offset += 4;
            Ok(val)
        }
        0xFF => {
            if *offset + 8 > data.len() {
                return Err(RpcError::InvalidParameter(
                    "btc: truncated varint u64".into(),
                ));
            }
            let val = u64::from_le_bytes([
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
            Ok(val)
        }
    }
}

/// Full decode of a Bitcoin raw transaction.
///
/// Extracts the sender's compressed public key (from first input's scriptSig or witness),
/// and all outputs for building ACE BVM payload.
pub fn decode_btc_full(data: &[u8]) -> Result<BtcDecoded, RpcError> {
    if data.len() < 10 {
        return Err(RpcError::InvalidParameter("btc: tx too short".into()));
    }

    let mut offset = 0;

    // Version (4 bytes LE)
    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    offset += 4;

    // Check for segwit marker/flag (0x00 0x01)
    let is_segwit = offset + 1 < data.len() && data[offset] == 0x00 && data[offset + 1] == 0x01;
    if is_segwit {
        offset += 2;
    }

    // num_inputs (varint)
    let num_inputs = decode_btc_varint(data, &mut offset)? as usize;
    if num_inputs == 0 {
        return Err(RpcError::InvalidParameter("btc: no inputs".into()));
    }

    // Parse inputs — we need the first input's scriptSig to extract the pubkey
    let mut first_script_sig = Vec::new();
    for i in 0..num_inputs {
        // txid (32 bytes, reversed in wire format)
        if offset + 32 > data.len() {
            return Err(RpcError::InvalidParameter(
                "btc: truncated input txid".into(),
            ));
        }
        offset += 32; // skip txid

        // vout (4 bytes LE)
        if offset + 4 > data.len() {
            return Err(RpcError::InvalidParameter(
                "btc: truncated input vout".into(),
            ));
        }
        offset += 4; // skip vout

        // scriptSig length (varint)
        let script_sig_len = decode_btc_varint(data, &mut offset)? as usize;
        if offset + script_sig_len > data.len() {
            return Err(RpcError::InvalidParameter(
                "btc: truncated scriptSig".into(),
            ));
        }
        if i == 0 {
            first_script_sig = data[offset..offset + script_sig_len].to_vec();
        }
        offset += script_sig_len;

        // sequence (4 bytes)
        if offset + 4 > data.len() {
            return Err(RpcError::InvalidParameter("btc: truncated sequence".into()));
        }
        offset += 4;
    }

    // num_outputs (varint)
    let num_outputs = decode_btc_varint(data, &mut offset)? as usize;
    if num_outputs == 0 {
        return Err(RpcError::InvalidParameter("btc: no outputs".into()));
    }

    // Parse outputs. Cap the pre-allocation by the remaining byte count: the BTC
    // varint count is attacker-controlled (up to u64::MAX), so an unbounded
    // `with_capacity` would let a tiny tx trigger a huge allocation (OOM DoS).
    let mut outputs = Vec::with_capacity(num_outputs.min(data.len()));
    for _ in 0..num_outputs {
        // value (8 bytes LE, in satoshis)
        if offset + 8 > data.len() {
            return Err(RpcError::InvalidParameter(
                "btc: truncated output value".into(),
            ));
        }
        let value = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;

        // scriptPubKey length (varint)
        let script_len = decode_btc_varint(data, &mut offset)? as usize;
        if offset + script_len > data.len() {
            return Err(RpcError::InvalidParameter(
                "btc: truncated scriptPubKey".into(),
            ));
        }
        let script_pubkey = data[offset..offset + script_len].to_vec();
        offset += script_len;

        outputs.push(BtcOutput {
            value,
            script_pubkey,
        });
    }

    // Parse witness data (if segwit) to extract pubkey
    let mut first_witness = Vec::new();
    if is_segwit {
        for i in 0..num_inputs {
            let num_items = decode_btc_varint(data, &mut offset)? as usize;
            // Cap pre-allocation by remaining bytes (attacker-controlled varint).
            let mut items = Vec::with_capacity(num_items.min(data.len()));
            for _ in 0..num_items {
                let item_len = decode_btc_varint(data, &mut offset)? as usize;
                if offset + item_len > data.len() {
                    return Err(RpcError::InvalidParameter(
                        "btc: truncated witness item".into(),
                    ));
                }
                items.push(data[offset..offset + item_len].to_vec());
                offset += item_len;
            }
            if i == 0 {
                first_witness = items;
            }
        }
    }

    // Extract sender's compressed public key
    let sender_pubkey = extract_btc_sender_pubkey(&first_script_sig, &first_witness)?;

    Ok(BtcDecoded {
        parsed: BtcParsed { sender_pubkey },
        outputs,
        version,
    })
}

/// Extract the sender's compressed public key from a Bitcoin input.
///
/// Handles P2PKH (from scriptSig) and P2WPKH (from witness data).
fn extract_btc_sender_pubkey(script_sig: &[u8], witness: &[Vec<u8>]) -> Result<[u8; 33], RpcError> {
    // P2WPKH: witness = [signature, pubkey]
    if witness.len() == 2 && (witness[1].len() == 33 || witness[1].len() == 65) {
        return compress_pubkey(&witness[1]);
    }

    // P2PKH: scriptSig = <sig_len><sig><pubkey_len><pubkey>
    // The public key is the last push data item
    if !script_sig.is_empty() {
        if let Some(pubkey) = extract_last_push(script_sig) {
            if pubkey.len() == 33 || pubkey.len() == 65 {
                return compress_pubkey(pubkey);
            }
        }
    }

    // P2SH-P2WPKH: scriptSig has a push of the witness script, pubkey is in witness
    if !witness.is_empty() && witness.len() >= 2 {
        let last = &witness[witness.len() - 1];
        if last.len() == 33 || last.len() == 65 {
            return compress_pubkey(last);
        }
    }

    Err(RpcError::InvalidParameter(
        "btc: cannot extract sender public key from input (unsupported script type)".into(),
    ))
}

/// Compress a public key to 33 bytes using k256.
fn compress_pubkey(pubkey: &[u8]) -> Result<[u8; 33], RpcError> {
    if pubkey.len() == 33 {
        let mut out = [0u8; 33];
        out.copy_from_slice(pubkey);
        return Ok(out);
    }
    if pubkey.len() == 65 {
        // Uncompressed: 0x04 || x (32) || y (32)
        // Compressed: (0x02 if y is even, 0x03 if y is odd) || x (32)
        let prefix = if pubkey[64] % 2 == 0 { 0x02 } else { 0x03 };
        let mut out = [0u8; 33];
        out[0] = prefix;
        out[1..].copy_from_slice(&pubkey[1..33]);
        return Ok(out);
    }
    Err(RpcError::InvalidParameter(format!(
        "btc: unexpected pubkey length: {}",
        pubkey.len()
    )))
}

/// Extract the last push-data item from a Bitcoin script.
fn extract_last_push(script: &[u8]) -> Option<&[u8]> {
    let mut offset = 0;
    let mut last_push: Option<(usize, usize)> = None; // (start, len)

    while offset < script.len() {
        let opcode = script[offset];
        offset += 1;

        if opcode == 0 {
            // OP_0
            continue;
        } else if opcode <= 75 {
            // Direct push: next `opcode` bytes
            let len = opcode as usize;
            if offset + len > script.len() {
                break;
            }
            last_push = Some((offset, len));
            offset += len;
        } else if opcode == 76 {
            // OP_PUSHDATA1
            if offset >= script.len() {
                break;
            }
            let len = script[offset] as usize;
            offset += 1;
            if offset + len > script.len() {
                break;
            }
            last_push = Some((offset, len));
            offset += len;
        } else if opcode == 77 {
            // OP_PUSHDATA2
            if offset + 2 > script.len() {
                break;
            }
            let len = u16::from_le_bytes([script[offset], script[offset + 1]]) as usize;
            offset += 2;
            if offset + len > script.len() {
                break;
            }
            last_push = Some((offset, len));
            offset += len;
        } else {
            // Non-push opcode — skip
            continue;
        }
    }

    last_push.map(|(start, len)| &script[start..start + len])
}

/// Build ACE BVM transfer payload from a Bitcoin output.
///
/// Format: 0x30 || to (32) || value (8 LE)
pub fn btc_payload_transfer(recipient_idcom: &[u8; 32], value: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 32 + 8);
    payload.push(0x30); // BVM transfer opcode
    payload.extend_from_slice(recipient_idcom);
    payload.extend_from_slice(&value.to_le_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_format_empty() {
        assert_eq!(detect_format(&[]), RawTxFormat::Unknown);
    }

    #[test]
    fn detect_format_ace_native_heuristic() {
        // payload_len=0 → 4 + 0 + 136 = 140 bytes; first 4 bytes [0,0,0,0].
        let mut data = vec![0u8; 4 + 0 + 136];
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(detect_format(&data), RawTxFormat::AceNative);
    }

    #[test]
    fn ecrecover_roundtrip() {
        // Smoke test: ecrecover with an all-zero hash and known-bad sig should fail gracefully.
        let hash = [0u8; 32];
        let result = ecrecover(&hash, 0, &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_compact_u16_single_byte() {
        let data = [42u8];
        let mut offset = 0;
        assert_eq!(decode_compact_u16(&data, &mut offset).unwrap(), 42);
        assert_eq!(offset, 1);
    }

    #[test]
    fn decode_compact_u16_two_bytes() {
        // 200 = (200 & 0x7F) | 0x80 in first byte, (200 >> 7) in second byte
        // 200 = 0xC8 → first byte: 0x48 | 0x80 = 0xC8, second byte: 0x01
        let data = [0xC8, 0x01];
        let mut offset = 0;
        assert_eq!(decode_compact_u16(&data, &mut offset).unwrap(), 200);
        assert_eq!(offset, 2);
    }

    #[test]
    fn decode_solana_full_accepts_v0_without_alt() {
        let signer = [1u8; 32];
        let recipient = [2u8; 32];
        let program = [0u8; 32];
        let mut data = vec![1u8];
        data.extend_from_slice(&[0u8; 64]); // signature bytes are opaque here
        data.push(0x80); // versioned v0
        data.extend_from_slice(&[1, 0, 1]); // header
        data.push(3); // account key count
        data.extend_from_slice(&signer);
        data.extend_from_slice(&recipient);
        data.extend_from_slice(&program);
        data.extend_from_slice(&[9u8; 32]); // recent blockhash
        data.push(1); // one instruction
        data.push(2); // program id index
        data.push(2); // account count
        data.push(0);
        data.push(1);
        data.push(12); // ix data len
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&55u64.to_le_bytes());
        data.push(0); // no ALT lookups

        let decoded = decode_solana_full(&data).expect("versioned v0 tx should decode");
        assert_eq!(decoded.parsed.signer, signer);
        assert_eq!(decoded.program_id, program);
        assert_eq!(decoded.accounts, vec![signer, recipient]);
        assert_eq!(decoded.num_instructions, 1);
    }

    #[test]
    fn decode_solana_full_rejects_signature_count_mismatch() {
        let mut data = vec![1u8];
        data.extend_from_slice(&[0u8; 64]);
        data.extend_from_slice(&[2, 0, 0]);
        data.push(2); // two account keys
        data.extend_from_slice(&[0u8; 64]);
        data.extend_from_slice(&[0u8; 32]); // recent blockhash
        data.push(0); // no instructions

        let err = decode_solana_full(&data).unwrap_err().to_string();
        assert!(err.contains("signature count 1 does not match num_required_signatures 2"));
    }

    #[test]
    fn decode_btc_varint_single() {
        let data = [42u8];
        let mut offset = 0;
        assert_eq!(decode_btc_varint(&data, &mut offset).unwrap(), 42);
    }

    #[test]
    fn decode_btc_varint_u16() {
        let data = [0xFD, 0x00, 0x01]; // 256
        let mut offset = 0;
        assert_eq!(decode_btc_varint(&data, &mut offset).unwrap(), 256);
    }

    #[test]
    fn compress_pubkey_already_compressed() {
        let mut key = [0u8; 33];
        key[0] = 0x02;
        key[1] = 0xFF;
        let result = compress_pubkey(&key).unwrap();
        assert_eq!(result, key);
    }

    #[test]
    fn extract_last_push_p2pkh_like() {
        // scriptSig-like: <71-byte sig> <33-byte pubkey>
        let mut script = Vec::new();
        script.push(71); // push 71 bytes (sig)
        script.extend_from_slice(&[0xAA; 71]);
        script.push(33); // push 33 bytes (pubkey)
        script.extend_from_slice(&[0xBB; 33]);

        let last = extract_last_push(&script).unwrap();
        assert_eq!(last.len(), 33);
        assert_eq!(last[0], 0xBB);
    }
}
