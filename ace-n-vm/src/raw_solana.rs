//! Verify raw Solana transaction and reconstruct a canonical ACE payload.
//!
//! Supported ingress subset:
//! - Legacy transactions
//! - Versioned v0 transactions without ALT lookups
//! - Single-instruction native transfers
//! - Single-instruction SPL `Transfer` / `TransferChecked`
//!
//! ACE binds Solana freshness to a deterministic per-slot `recent_blockhash`
//! derived from `(chain_id, slot)`. This lets standard Solana wallets sign a
//! familiar message shape while ACE enforces expiry and replay protection.

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::legacy_idcom_solana;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::NVmError;
use crate::svm::programs::TOKEN_PROGRAM_ID;
use crate::token_runtime;

pub const SOLANA_RECENT_BLOCKHASH_WINDOW: u64 = 10;
pub const SOLANA_SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];
const SOLANA_SYSTEM_TRANSFER_DISCRIMINANT: u32 = 2;
const SPL_TRANSFER_DISCRIMINANT: u8 = 3;
const SPL_TRANSFER_CHECKED_DISCRIMINANT: u8 = 12;
const ASSOCIATED_TOKEN_CREATE_DISCRIMINANT: u8 = 0;
const ASSOCIATED_TOKEN_CREATE_IDEMPOTENT_DISCRIMINANT: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSolanaTransfer {
    pub signer_pubkey: [u8; 32],
    pub sender_idcom: [u8; 32],
    pub recipient_idcom: [u8; 32],
    pub amount: u64,
    pub recent_slot: u64,
    pub canonical_payload: Vec<u8>,
    pub first_signature: [u8; 64],
    pub replay_slot: [u8; 32],
}

struct ParsedSolanaTransfer {
    signer_pubkey: [u8; 32],
    recipient_pubkey: [u8; 32],
    amount: u64,
    recent_blockhash: [u8; 32],
    first_signature: [u8; 64],
    canonical_payload: Vec<u8>,
}

struct ParsedSolanaMessage {
    signer_pubkey: [u8; 32],
    recent_blockhash: [u8; 32],
    instructions: Vec<ParsedInstruction>,
    first_signature: [u8; 64],
}

struct ParsedAtaCreate {
    token_account: [u8; 32],
    owner_pubkey: [u8; 32],
    mint: [u8; 32],
    idempotent: bool,
}

#[derive(Clone)]
struct ParsedInstruction {
    program_id: [u8; 32],
    accounts: Vec<[u8; 32]>,
    data: Vec<u8>,
}

pub fn derive_ace_solana_blockhash(chain_id: u32, slot: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-SOL-BLOCKHASH-V1");
    hasher.update(chain_id.to_le_bytes());
    hasher.update(slot.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

pub fn recover_recent_ace_solana_slot(
    chain_id: u32,
    current_slot: u64,
    recent_blockhash: &[u8; 32],
) -> Option<u64> {
    let start = current_slot.saturating_sub(SOLANA_RECENT_BLOCKHASH_WINDOW);
    (start..=current_slot)
        .rev()
        .find(|&slot| derive_ace_solana_blockhash(chain_id, slot) == *recent_blockhash)
}

pub fn solana_signature_replay_slot(signature: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ACE-SOL-REPLAY-V1");
    hasher.update(signature);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

pub fn extract_first_solana_signature(raw_bytes: &[u8]) -> Result<[u8; 64], NVmError> {
    let mut offset = 0;
    let num_signatures = decode_compact_u16(raw_bytes, &mut offset)? as usize;
    if num_signatures == 0 {
        return Err(NVmError::RawChainVerify(
            "Solana tx has no signatures".into(),
        ));
    }
    if offset + 64 > raw_bytes.len() {
        return Err(NVmError::RawChainVerify(
            "Solana tx: truncated first signature".into(),
        ));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&raw_bytes[offset..offset + 64]);
    Ok(sig)
}

pub fn verify_raw_solana_transfer_against_state(
    state: &StateTree,
    raw_bytes: &[u8],
    chain_id: u32,
    current_slot: u64,
) -> Result<VerifiedSolanaTransfer, NVmError> {
    let parsed = parse_supported_transfer(raw_bytes)?;
    let Some(recent_slot) =
        recover_recent_ace_solana_slot(chain_id, current_slot, &parsed.recent_blockhash)
    else {
        return Err(NVmError::RawChainVerify(
            "Solana recent_blockhash is unknown or expired for ACE".into(),
        ));
    };

    let sender_idcom = legacy_idcom_solana(&parsed.signer_pubkey);
    let replay_slot = solana_signature_replay_slot(&parsed.first_signature);
    let sender = AccountId::from_bytes(sender_idcom);
    if !state.contains(&sender) {
        return Err(NVmError::RawChainVerify(
            "Solana sender account does not exist on ACE".into(),
        ));
    }
    if state.get_storage(&sender, &replay_slot) != [0u8; 32] {
        return Err(NVmError::RawChainVerify(
            "Solana transaction signature has already been used on ACE".into(),
        ));
    }
    validate_runtime_token_payload(state, &sender_idcom, &parsed.canonical_payload)?;

    Ok(VerifiedSolanaTransfer {
        signer_pubkey: parsed.signer_pubkey,
        sender_idcom,
        recipient_idcom: legacy_idcom_solana(&parsed.recipient_pubkey),
        amount: parsed.amount,
        recent_slot,
        canonical_payload: parsed.canonical_payload,
        first_signature: parsed.first_signature,
        replay_slot,
    })
}

pub fn verify_raw_solana_transfer_for_slot(
    state: &StateTree,
    raw_bytes: &[u8],
    chain_id: u32,
    expected_slot: u64,
) -> Result<VerifiedSolanaTransfer, NVmError> {
    let parsed = parse_supported_transfer(raw_bytes)?;
    let expected_hash = derive_ace_solana_blockhash(chain_id, expected_slot);
    if parsed.recent_blockhash != expected_hash {
        return Err(NVmError::RawChainVerify(
            "Solana recent_blockhash does not match ACE domain slot".into(),
        ));
    }

    let sender_idcom = legacy_idcom_solana(&parsed.signer_pubkey);
    let replay_slot = solana_signature_replay_slot(&parsed.first_signature);
    let sender = AccountId::from_bytes(sender_idcom);
    if !state.contains(&sender) {
        return Err(NVmError::RawChainVerify(
            "Solana sender account does not exist on ACE".into(),
        ));
    }
    if state.get_storage(&sender, &replay_slot) != [0u8; 32] {
        return Err(NVmError::RawChainVerify(
            "Solana transaction signature has already been used on ACE".into(),
        ));
    }
    validate_runtime_token_payload(state, &sender_idcom, &parsed.canonical_payload)?;

    Ok(VerifiedSolanaTransfer {
        signer_pubkey: parsed.signer_pubkey,
        sender_idcom,
        recipient_idcom: legacy_idcom_solana(&parsed.recipient_pubkey),
        amount: parsed.amount,
        recent_slot: expected_slot,
        canonical_payload: parsed.canonical_payload,
        first_signature: parsed.first_signature,
        replay_slot,
    })
}

fn validate_runtime_token_payload(
    state: &StateTree,
    sender_idcom: &[u8; 32],
    payload: &[u8],
) -> Result<(), NVmError> {
    if payload.first().copied() != Some(0x20) {
        return Ok(());
    }
    if payload.len() < 34 {
        return Err(NVmError::RawChainVerify(
            "solana canonical payload too short".into(),
        ));
    }
    let mut program_id = [0u8; 32];
    program_id.copy_from_slice(&payload[1..33]);
    if program_id != TOKEN_PROGRAM_ID {
        return Ok(());
    }
    let num_accounts = payload[33] as usize;
    let accounts_end = 34 + num_accounts * 32;
    if payload.len() < accounts_end + 1 {
        return Err(NVmError::RawChainVerify(
            "solana token canonical payload truncated".into(),
        ));
    }
    let mut accounts = Vec::with_capacity(num_accounts);
    for i in 0..num_accounts {
        let start = 34 + i * 32;
        let mut account = [0u8; 32];
        account.copy_from_slice(&payload[start..start + 32]);
        accounts.push(account);
    }
    let data = &payload[accounts_end..];
    match data.first().copied() {
        Some(0x11) => {
            if accounts.len() < 3 || data.len() < 9 {
                return Err(NVmError::RawChainVerify(
                    "invalid canonical spl transfer payload".into(),
                ));
            }
            let source = token_runtime::get_token_account_meta(state, &accounts[0])
                .ok_or_else(|| NVmError::RawChainVerify("unknown source token account".into()))?;
            let destination = token_runtime::get_token_account_meta(state, &accounts[1])
                .ok_or_else(|| {
                    NVmError::RawChainVerify("unknown destination token account".into())
                })?;
            if source.owner_idcom != *sender_idcom || accounts[2] != source.owner_sol_pubkey {
                return Err(NVmError::RawChainVerify(
                    "spl transfer authority mismatch".into(),
                ));
            }
            if source.mint != destination.mint {
                return Err(NVmError::RawChainVerify(
                    "spl transfer mint mismatch".into(),
                ));
            }
        }
        Some(0x12) => {
            if accounts.len() < 4 || data.len() < 10 {
                return Err(NVmError::RawChainVerify(
                    "invalid canonical spl transferChecked payload".into(),
                ));
            }
            let source = token_runtime::get_token_account_meta(state, &accounts[0])
                .ok_or_else(|| NVmError::RawChainVerify("unknown source token account".into()))?;
            let destination = token_runtime::get_token_account_meta(state, &accounts[2])
                .ok_or_else(|| {
                    NVmError::RawChainVerify("unknown destination token account".into())
                })?;
            if source.owner_idcom != *sender_idcom || accounts[3] != source.owner_sol_pubkey {
                return Err(NVmError::RawChainVerify(
                    "spl transfer authority mismatch".into(),
                ));
            }
            if source.mint != accounts[1] || destination.mint != accounts[1] {
                return Err(NVmError::RawChainVerify(
                    "spl transferChecked mint mismatch".into(),
                ));
            }
            let mint = token_runtime::get_mint_meta(state, &accounts[1])
                .ok_or_else(|| NVmError::RawChainVerify("mint does not exist".into()))?;
            if mint.decimals != data[9] {
                return Err(NVmError::RawChainVerify(
                    "spl transferChecked decimals mismatch".into(),
                ));
            }
        }
        Some(0x13) => {
            if accounts.len() < 4 || data.len() < 9 {
                return Err(NVmError::RawChainVerify(
                    "invalid canonical spl transfer-with-ata payload".into(),
                ));
            }
            let source = token_runtime::get_token_account_meta(state, &accounts[0])
                .ok_or_else(|| NVmError::RawChainVerify("unknown source token account".into()))?;
            if source.owner_idcom != *sender_idcom || accounts[2] != source.owner_sol_pubkey {
                return Err(NVmError::RawChainVerify(
                    "spl transfer authority mismatch".into(),
                ));
            }
            if let Some(destination) = token_runtime::get_token_account_meta(state, &accounts[1]) {
                if destination.mint != source.mint || destination.owner_sol_pubkey != accounts[3] {
                    return Err(NVmError::RawChainVerify(
                        "destination token account metadata mismatch".into(),
                    ));
                }
            } else if token_runtime::derive_associated_token_address(&accounts[3], &source.mint)
                != accounts[1]
            {
                return Err(NVmError::RawChainVerify(
                    "destination token account is not the expected ATA".into(),
                ));
            }
        }
        Some(0x14) => {
            if accounts.len() < 5 || data.len() < 10 {
                return Err(NVmError::RawChainVerify(
                    "invalid canonical spl transferChecked-with-ata payload".into(),
                ));
            }
            let source = token_runtime::get_token_account_meta(state, &accounts[0])
                .ok_or_else(|| NVmError::RawChainVerify("unknown source token account".into()))?;
            if source.owner_idcom != *sender_idcom || accounts[3] != source.owner_sol_pubkey {
                return Err(NVmError::RawChainVerify(
                    "spl transfer authority mismatch".into(),
                ));
            }
            if source.mint != accounts[1] {
                return Err(NVmError::RawChainVerify(
                    "spl transferChecked source mint mismatch".into(),
                ));
            }
            let mint = token_runtime::get_mint_meta(state, &accounts[1])
                .ok_or_else(|| NVmError::RawChainVerify("mint does not exist".into()))?;
            if mint.decimals != data[9] {
                return Err(NVmError::RawChainVerify(
                    "spl transferChecked decimals mismatch".into(),
                ));
            }
            if let Some(destination) = token_runtime::get_token_account_meta(state, &accounts[2]) {
                if destination.mint != accounts[1] || destination.owner_sol_pubkey != accounts[4] {
                    return Err(NVmError::RawChainVerify(
                        "destination token account metadata mismatch".into(),
                    ));
                }
            } else if token_runtime::derive_associated_token_address(&accounts[4], &accounts[1])
                != accounts[2]
            {
                return Err(NVmError::RawChainVerify(
                    "destination token account is not the expected ATA".into(),
                ));
            }
        }
        Some(0x15) => {
            if accounts.len() < 3 {
                return Err(NVmError::RawChainVerify(
                    "invalid canonical ensure-token-account payload".into(),
                ));
            }
            if token_runtime::get_mint_meta(state, &accounts[1]).is_none() {
                return Err(NVmError::RawChainVerify("mint does not exist".into()));
            }
            if token_runtime::derive_associated_token_address(&accounts[2], &accounts[1])
                != accounts[0]
            {
                return Err(NVmError::RawChainVerify(
                    "token account does not match ATA derivation".into(),
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

/// Verify a raw Solana signed transaction and return the signer's Ed25519 public key (32 bytes).
///
/// Verifies the first signature (fee payer) over the message bytes using Ed25519.
pub fn verify_raw_solana_recover_signer(raw_bytes: &[u8]) -> Result<[u8; 32], NVmError> {
    if raw_bytes.len() < 3 {
        return Err(NVmError::RawChainVerify("Solana tx too short".into()));
    }

    let mut offset = 0;

    // Parse num_signatures (compact-u16)
    let num_signatures = decode_compact_u16(raw_bytes, &mut offset)?;
    if num_signatures == 0 {
        return Err(NVmError::RawChainVerify(
            "Solana tx has no signatures".into(),
        ));
    }

    let sig_count = num_signatures as usize;
    let signatures_len = sig_count
        .checked_mul(64)
        .ok_or_else(|| NVmError::RawChainVerify("Solana tx: signature section overflow".into()))?;
    if offset + signatures_len > raw_bytes.len() {
        return Err(NVmError::RawChainVerify(
            "Solana tx: truncated signatures".into(),
        ));
    }

    // The message starts here — this is what's signed
    let signatures_start = offset;
    let message_start = offset + signatures_len;
    let message_bytes = &raw_bytes[message_start..];

    if message_bytes.is_empty() {
        return Err(NVmError::RawChainVerify(
            "Solana tx: missing message".into(),
        ));
    }
    let message_offset = if message_bytes[0] & 0x80 != 0 {
        let version = message_bytes[0] & 0x7f;
        if version != 0 {
            return Err(NVmError::RawChainVerify(format!(
                "unsupported Solana message version {version}"
            )));
        }
        1
    } else {
        0
    };

    if message_bytes.len() < message_offset + 3 {
        return Err(NVmError::RawChainVerify(
            "Solana tx: message header too short".into(),
        ));
    }
    let num_required_sigs = message_bytes[message_offset] as usize;
    if num_required_sigs == 0 {
        return Err(NVmError::RawChainVerify(
            "Solana tx: num_required_signatures is 0".into(),
        ));
    }
    if num_required_sigs != sig_count {
        return Err(NVmError::RawChainVerify(format!(
            "Solana tx: signature count {sig_count} does not match num_required_signatures {num_required_sigs}"
        )));
    }
    offset = message_start + message_offset + 3; // skip message version + header

    // Parse num_account_keys (compact-u16)
    let num_account_keys = decode_compact_u16(raw_bytes, &mut offset)?;
    let num_account_keys = num_account_keys as usize;
    if num_account_keys == 0 {
        return Err(NVmError::RawChainVerify(
            "Solana tx: no account keys".into(),
        ));
    }
    if num_account_keys < num_required_sigs {
        return Err(NVmError::RawChainVerify(format!(
            "Solana tx: account key count {num_account_keys} is smaller than required signers {num_required_sigs}"
        )));
    }

    if offset + (32 * num_required_sigs) > raw_bytes.len() {
        return Err(NVmError::RawChainVerify(
            "Solana tx: truncated signer key list".into(),
        ));
    }

    let mut fee_payer = [0u8; 32];
    for signer_idx in 0..num_required_sigs {
        let key_offset = offset + (signer_idx * 32);
        let mut signer_key = [0u8; 32];
        signer_key.copy_from_slice(&raw_bytes[key_offset..key_offset + 32]);
        if signer_idx == 0 {
            fee_payer = signer_key;
        }

        let sig_offset = signatures_start + (signer_idx * 64);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&raw_bytes[sig_offset..sig_offset + 64]);

        let verifying_key = VerifyingKey::from_bytes(&signer_key)
            .map_err(|e| NVmError::RawChainVerify(format!("invalid Ed25519 pubkey: {e}")))?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify_strict(message_bytes, &signature)
            .map_err(|e| {
                NVmError::RawChainVerify(format!(
                    "Ed25519 signature invalid for signer {signer_idx}: {e}"
                ))
            })?;
    }

    Ok(fee_payer)
}

fn parse_supported_transfer(raw_bytes: &[u8]) -> Result<ParsedSolanaTransfer, NVmError> {
    let parsed = parse_message(raw_bytes)?;
    match parsed.instructions.len() {
        1 => {
            let instruction = parsed.instructions[0].clone();
            if instruction.program_id == SOLANA_SYSTEM_PROGRAM_ID {
                return parse_native_transfer(parsed, &instruction);
            }
            if instruction.program_id == token_runtime::spl_token_program_id() {
                return parse_spl_transfer(parsed, &instruction);
            }
            if instruction.program_id == token_runtime::associated_token_program_id() {
                return parse_associated_token_account_create(parsed, &instruction);
            }
        }
        2 => {
            let ata_instruction = parsed.instructions[0].clone();
            let transfer_instruction = parsed.instructions[1].clone();
            if ata_instruction.program_id == token_runtime::associated_token_program_id()
                && transfer_instruction.program_id == token_runtime::spl_token_program_id()
            {
                return parse_ata_then_spl_transfer(
                    parsed,
                    &ata_instruction,
                    &transfer_instruction,
                );
            }
        }
        _ => {}
    }
    Err(NVmError::RawChainVerify(
        "ACE currently supports only SystemProgram transfer, SPL transfer, and ATA create(+transfer) ingress".into(),
    ))
}

fn parse_native_transfer(
    parsed: ParsedSolanaMessage,
    instruction: &ParsedInstruction,
) -> Result<ParsedSolanaTransfer, NVmError> {
    if instruction.accounts.len() < 2 {
        return Err(NVmError::RawChainVerify(
            "SystemProgram transfer requires source and destination accounts".into(),
        ));
    }
    if instruction.accounts[0] != parsed.signer_pubkey {
        return Err(NVmError::RawChainVerify(
            "ACE currently supports only fee-payer sourced Solana transfers".into(),
        ));
    }
    if instruction.data.len() != 12 {
        return Err(NVmError::RawChainVerify(
            "ACE currently supports only SystemProgram::Transfer instruction data".into(),
        ));
    }
    let discriminant = u32::from_le_bytes(instruction.data[0..4].try_into().unwrap());
    if discriminant != SOLANA_SYSTEM_TRANSFER_DISCRIMINANT {
        return Err(NVmError::RawChainVerify(
            "ACE currently supports only Solana native lamport transfers".into(),
        ));
    }
    let amount = u64::from_le_bytes(instruction.data[4..12].try_into().unwrap());
    Ok(ParsedSolanaTransfer {
        signer_pubkey: parsed.signer_pubkey,
        recipient_pubkey: instruction.accounts[1],
        amount,
        recent_blockhash: parsed.recent_blockhash,
        first_signature: parsed.first_signature,
        canonical_payload: build_transfer_payload(
            &legacy_idcom_solana(&instruction.accounts[1]),
            amount,
        ),
    })
}

fn parse_spl_transfer(
    parsed: ParsedSolanaMessage,
    instruction: &ParsedInstruction,
) -> Result<ParsedSolanaTransfer, NVmError> {
    match instruction.data.first().copied() {
        Some(SPL_TRANSFER_DISCRIMINANT) => {
            if instruction.accounts.len() < 3 || instruction.data.len() != 9 {
                return Err(NVmError::RawChainVerify(
                    "SPL Token Transfer requires source, destination, authority, amount".into(),
                ));
            }
            let amount = u64::from_le_bytes(instruction.data[1..9].try_into().unwrap());
            let mut payload = Vec::with_capacity(1 + 32 + 1 + 32 * 3 + 1 + 8);
            payload.push(0x20);
            payload.extend_from_slice(&TOKEN_PROGRAM_ID);
            payload.push(3);
            payload.extend_from_slice(&instruction.accounts[0]);
            payload.extend_from_slice(&instruction.accounts[1]);
            payload.extend_from_slice(&instruction.accounts[2]);
            payload.push(0x11);
            payload.extend_from_slice(&amount.to_le_bytes());
            Ok(ParsedSolanaTransfer {
                signer_pubkey: parsed.signer_pubkey,
                recipient_pubkey: instruction.accounts[1],
                amount,
                recent_blockhash: parsed.recent_blockhash,
                first_signature: parsed.first_signature,
                canonical_payload: payload,
            })
        }
        Some(SPL_TRANSFER_CHECKED_DISCRIMINANT) => {
            if instruction.accounts.len() < 4 || instruction.data.len() != 10 {
                return Err(NVmError::RawChainVerify(
                    "SPL Token TransferChecked requires source, mint, destination, authority, amount, decimals".into(),
                ));
            }
            let amount = u64::from_le_bytes(instruction.data[1..9].try_into().unwrap());
            let decimals = instruction.data[9];
            let mut payload = Vec::with_capacity(1 + 32 + 1 + 32 * 4 + 1 + 8 + 1);
            payload.push(0x20);
            payload.extend_from_slice(&TOKEN_PROGRAM_ID);
            payload.push(4);
            payload.extend_from_slice(&instruction.accounts[0]);
            payload.extend_from_slice(&instruction.accounts[1]);
            payload.extend_from_slice(&instruction.accounts[2]);
            payload.extend_from_slice(&instruction.accounts[3]);
            payload.push(0x12);
            payload.extend_from_slice(&amount.to_le_bytes());
            payload.push(decimals);
            Ok(ParsedSolanaTransfer {
                signer_pubkey: parsed.signer_pubkey,
                recipient_pubkey: instruction.accounts[2],
                amount,
                recent_blockhash: parsed.recent_blockhash,
                first_signature: parsed.first_signature,
                canonical_payload: payload,
            })
        }
        _ => Err(NVmError::RawChainVerify(
            "ACE currently supports only SPL Transfer/TransferChecked".into(),
        )),
    }
}

fn parse_associated_token_account_create(
    parsed: ParsedSolanaMessage,
    instruction: &ParsedInstruction,
) -> Result<ParsedSolanaTransfer, NVmError> {
    let ata = parse_ata_create(&parsed, instruction)?;
    let mut payload = Vec::with_capacity(1 + 32 + 1 + 32 * 3 + 1);
    payload.push(0x20);
    payload.extend_from_slice(&TOKEN_PROGRAM_ID);
    payload.push(3);
    payload.extend_from_slice(&ata.token_account);
    payload.extend_from_slice(&ata.mint);
    payload.extend_from_slice(&ata.owner_pubkey);
    payload.push(if ata.idempotent { 0x15 } else { 0x10 });
    Ok(ParsedSolanaTransfer {
        signer_pubkey: parsed.signer_pubkey,
        recipient_pubkey: ata.owner_pubkey,
        amount: 0,
        recent_blockhash: parsed.recent_blockhash,
        first_signature: parsed.first_signature,
        canonical_payload: payload,
    })
}

fn parse_ata_then_spl_transfer(
    parsed: ParsedSolanaMessage,
    ata_instruction: &ParsedInstruction,
    transfer_instruction: &ParsedInstruction,
) -> Result<ParsedSolanaTransfer, NVmError> {
    let ata = parse_ata_create(&parsed, ata_instruction)?;
    match transfer_instruction.data.first().copied() {
        Some(SPL_TRANSFER_DISCRIMINANT) => {
            if transfer_instruction.accounts.len() < 3 || transfer_instruction.data.len() != 9 {
                return Err(NVmError::RawChainVerify(
                    "SPL Token Transfer requires source, destination, authority, amount".into(),
                ));
            }
            if transfer_instruction.accounts[1] != ata.token_account {
                return Err(NVmError::RawChainVerify(
                    "ATA destination does not match SPL transfer destination".into(),
                ));
            }
            let amount = u64::from_le_bytes(transfer_instruction.data[1..9].try_into().unwrap());
            let mut payload = Vec::with_capacity(1 + 32 + 1 + 32 * 4 + 1 + 8);
            payload.push(0x20);
            payload.extend_from_slice(&TOKEN_PROGRAM_ID);
            payload.push(4);
            payload.extend_from_slice(&transfer_instruction.accounts[0]);
            payload.extend_from_slice(&transfer_instruction.accounts[1]);
            payload.extend_from_slice(&transfer_instruction.accounts[2]);
            payload.extend_from_slice(&ata.owner_pubkey);
            payload.push(0x13);
            payload.extend_from_slice(&amount.to_le_bytes());
            Ok(ParsedSolanaTransfer {
                signer_pubkey: parsed.signer_pubkey,
                recipient_pubkey: ata.owner_pubkey,
                amount,
                recent_blockhash: parsed.recent_blockhash,
                first_signature: parsed.first_signature,
                canonical_payload: payload,
            })
        }
        Some(SPL_TRANSFER_CHECKED_DISCRIMINANT) => {
            if transfer_instruction.accounts.len() < 4 || transfer_instruction.data.len() != 10 {
                return Err(NVmError::RawChainVerify(
                    "SPL Token TransferChecked requires source, mint, destination, authority, amount, decimals".into(),
                ));
            }
            if transfer_instruction.accounts[1] != ata.mint
                || transfer_instruction.accounts[2] != ata.token_account
            {
                return Err(NVmError::RawChainVerify(
                    "ATA mint/destination does not match SPL transferChecked".into(),
                ));
            }
            let amount = u64::from_le_bytes(transfer_instruction.data[1..9].try_into().unwrap());
            let decimals = transfer_instruction.data[9];
            let mut payload = Vec::with_capacity(1 + 32 + 1 + 32 * 5 + 1 + 8 + 1);
            payload.push(0x20);
            payload.extend_from_slice(&TOKEN_PROGRAM_ID);
            payload.push(5);
            payload.extend_from_slice(&transfer_instruction.accounts[0]);
            payload.extend_from_slice(&transfer_instruction.accounts[1]);
            payload.extend_from_slice(&transfer_instruction.accounts[2]);
            payload.extend_from_slice(&transfer_instruction.accounts[3]);
            payload.extend_from_slice(&ata.owner_pubkey);
            payload.push(0x14);
            payload.extend_from_slice(&amount.to_le_bytes());
            payload.push(decimals);
            Ok(ParsedSolanaTransfer {
                signer_pubkey: parsed.signer_pubkey,
                recipient_pubkey: ata.owner_pubkey,
                amount,
                recent_blockhash: parsed.recent_blockhash,
                first_signature: parsed.first_signature,
                canonical_payload: payload,
            })
        }
        _ => Err(NVmError::RawChainVerify(
            "ACE currently supports only SPL Transfer/TransferChecked after ATA create".into(),
        )),
    }
}

fn parse_ata_create(
    parsed: &ParsedSolanaMessage,
    instruction: &ParsedInstruction,
) -> Result<ParsedAtaCreate, NVmError> {
    if instruction.accounts.len() < 4 {
        return Err(NVmError::RawChainVerify(
            "Associated Token create requires payer, ata, owner, mint".into(),
        ));
    }
    if instruction.accounts[0] != parsed.signer_pubkey {
        return Err(NVmError::RawChainVerify(
            "ACE currently supports only fee-payer initiated ATA creation".into(),
        ));
    }
    let idempotent = match instruction.data.first().copied().unwrap_or(0) {
        ASSOCIATED_TOKEN_CREATE_DISCRIMINANT => false,
        ASSOCIATED_TOKEN_CREATE_IDEMPOTENT_DISCRIMINANT => true,
        _ => {
            return Err(NVmError::RawChainVerify(
                "ACE currently supports only ATA Create/CreateIdempotent".into(),
            ))
        }
    };
    let expected = token_runtime::derive_associated_token_address(
        &instruction.accounts[2],
        &instruction.accounts[3],
    );
    if instruction.accounts[1] != expected {
        return Err(NVmError::RawChainVerify(
            "ATA address does not match owner+mint derivation".into(),
        ));
    }
    Ok(ParsedAtaCreate {
        token_account: instruction.accounts[1],
        owner_pubkey: instruction.accounts[2],
        mint: instruction.accounts[3],
        idempotent,
    })
}

fn parse_message(raw_bytes: &[u8]) -> Result<ParsedSolanaMessage, NVmError> {
    if raw_bytes.len() < 3 {
        return Err(NVmError::RawChainVerify("Solana tx too short".into()));
    }

    let mut offset = 0;
    let num_signatures = decode_compact_u16(raw_bytes, &mut offset)? as usize;
    if num_signatures == 0 {
        return Err(NVmError::RawChainVerify(
            "Solana tx has no signatures".into(),
        ));
    }
    let signatures_start = offset;
    let signatures_len = num_signatures
        .checked_mul(64)
        .ok_or_else(|| NVmError::RawChainVerify("Solana tx: signature section overflow".into()))?;
    ensure_remaining(raw_bytes, offset, signatures_len, "signatures")?;
    let message_start = offset + signatures_len;
    let message_bytes = &raw_bytes[message_start..];
    if message_bytes.is_empty() {
        return Err(NVmError::RawChainVerify(
            "Solana tx: missing message".into(),
        ));
    }

    let (message_header_start, versioned) = if message_bytes[0] & 0x80 != 0 {
        let version = message_bytes[0] & 0x7f;
        if version != 0 {
            return Err(NVmError::RawChainVerify(format!(
                "unsupported Solana message version {version}"
            )));
        }
        (message_start + 1, true)
    } else {
        (message_start, false)
    };
    ensure_remaining(raw_bytes, message_header_start, 3, "message header")?;
    let num_required_sigs = raw_bytes[message_header_start] as usize;
    if num_required_sigs == 0 {
        return Err(NVmError::RawChainVerify(
            "Solana tx: num_required_signatures is 0".into(),
        ));
    }
    if num_required_sigs != num_signatures {
        return Err(NVmError::RawChainVerify(format!(
            "Solana tx: signature count {num_signatures} does not match num_required_signatures {num_required_sigs}"
        )));
    }

    let mut first_signature = [0u8; 64];
    first_signature.copy_from_slice(&raw_bytes[signatures_start..signatures_start + 64]);

    offset = message_header_start + 3;
    let num_account_keys = decode_compact_u16(raw_bytes, &mut offset)? as usize;
    if num_account_keys == 0 {
        return Err(NVmError::RawChainVerify(
            "Solana tx: no account keys".into(),
        ));
    }
    if num_account_keys < num_required_sigs {
        return Err(NVmError::RawChainVerify(format!(
            "Solana tx: account key count {num_account_keys} is smaller than required signers {num_required_sigs}"
        )));
    }
    ensure_remaining(raw_bytes, offset, 32 * num_account_keys, "account keys")?;
    let mut account_keys = Vec::with_capacity(num_account_keys);
    for _ in 0..num_account_keys {
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw_bytes[offset..offset + 32]);
        account_keys.push(key);
        offset += 32;
    }

    let mut recent_blockhash = [0u8; 32];
    ensure_remaining(raw_bytes, offset, 32, "recent_blockhash")?;
    recent_blockhash.copy_from_slice(&raw_bytes[offset..offset + 32]);
    offset += 32;

    let num_instructions = decode_compact_u16(raw_bytes, &mut offset)? as usize;
    let mut instructions = Vec::with_capacity(num_instructions);
    for _ in 0..num_instructions {
        ensure_remaining(raw_bytes, offset, 1, "program_id_index")?;
        let program_id_index = raw_bytes[offset] as usize;
        offset += 1;
        if program_id_index >= account_keys.len() {
            return Err(NVmError::RawChainVerify(format!(
                "Solana tx: program_id_index {program_id_index} out of range"
            )));
        }
        let num_ix_accounts = decode_compact_u16(raw_bytes, &mut offset)? as usize;
        ensure_remaining(
            raw_bytes,
            offset,
            num_ix_accounts,
            "instruction account indices",
        )?;
        let mut accounts = Vec::with_capacity(num_ix_accounts);
        for _ in 0..num_ix_accounts {
            let acct_idx = raw_bytes[offset] as usize;
            offset += 1;
            if acct_idx >= account_keys.len() {
                return Err(NVmError::RawChainVerify(format!(
                    "Solana tx: account index {acct_idx} out of range"
                )));
            }
            accounts.push(account_keys[acct_idx]);
        }
        let data_len = decode_compact_u16(raw_bytes, &mut offset)? as usize;
        ensure_remaining(raw_bytes, offset, data_len, "instruction data")?;
        let data = raw_bytes[offset..offset + data_len].to_vec();
        offset += data_len;
        instructions.push(ParsedInstruction {
            program_id: account_keys[program_id_index],
            accounts,
            data,
        });
    }

    if versioned {
        let lookup_count = decode_compact_u16(raw_bytes, &mut offset)? as usize;
        if lookup_count != 0 {
            return Err(NVmError::RawChainVerify(
                "Solana address lookup tables are not supported yet".into(),
            ));
        }
    }
    if offset != raw_bytes.len() {
        return Err(NVmError::RawChainVerify(
            "unexpected trailing bytes in Solana transaction".into(),
        ));
    }

    for signer_idx in 0..num_required_sigs {
        let signer_key = account_keys[signer_idx];
        let sig_offset = signatures_start + signer_idx * 64;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&raw_bytes[sig_offset..sig_offset + 64]);
        let verifying_key = VerifyingKey::from_bytes(&signer_key)
            .map_err(|e| NVmError::RawChainVerify(format!("invalid Ed25519 pubkey: {e}")))?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify_strict(message_bytes, &signature)
            .map_err(|e| {
                NVmError::RawChainVerify(format!(
                    "Ed25519 signature invalid for signer {signer_idx}: {e}"
                ))
            })?;
    }

    Ok(ParsedSolanaMessage {
        signer_pubkey: account_keys[0],
        recent_blockhash,
        instructions,
        first_signature,
    })
}

fn build_transfer_payload(recipient_idcom: &[u8; 32], amount: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 32 + 8);
    payload.push(0x21);
    payload.extend_from_slice(recipient_idcom);
    payload.extend_from_slice(&amount.to_le_bytes());
    payload
}

fn ensure_remaining(data: &[u8], offset: usize, needed: usize, ctx: &str) -> Result<(), NVmError> {
    if offset + needed > data.len() {
        return Err(NVmError::RawChainVerify(format!(
            "Solana tx: truncated {ctx}"
        )));
    }
    Ok(())
}

/// Decode Solana compact-u16 encoding.
fn decode_compact_u16(data: &[u8], offset: &mut usize) -> Result<u16, NVmError> {
    if *offset >= data.len() {
        return Err(NVmError::RawChainVerify(
            "compact-u16: unexpected end".into(),
        ));
    }
    let byte0 = data[*offset] as u16;
    *offset += 1;
    if byte0 < 0x80 {
        return Ok(byte0);
    }
    if *offset >= data.len() {
        return Err(NVmError::RawChainVerify("compact-u16: truncated".into()));
    }
    let byte1 = data[*offset] as u16;
    *offset += 1;
    let value = (byte0 & 0x7F) | ((byte1 & 0x7F) << 7);
    if byte1 < 0x80 {
        return Ok(value);
    }
    if *offset >= data.len() {
        return Err(NVmError::RawChainVerify(
            "compact-u16: truncated (3rd byte)".into(),
        ));
    }
    let byte2 = data[*offset] as u16;
    *offset += 1;
    Ok(value | ((byte2 & 0x03) << 14))
}

#[cfg(test)]
mod tests {
    use super::{
        derive_ace_solana_blockhash, solana_signature_replay_slot,
        verify_raw_solana_recover_signer, verify_raw_solana_transfer_against_state,
        SOLANA_RECENT_BLOCKHASH_WINDOW, SPL_TRANSFER_CHECKED_DISCRIMINANT,
    };
    use crate::token_runtime;
    use ace_model::account::{Account, AccountId};
    use ace_model::state_tree::StateTree;
    use ace_runtime::crypto::legacy_idcom_solana;
    use ed25519_dalek::{Signer, SigningKey};

    fn encode_compact_u16(value: u16) -> Vec<u8> {
        if value < 0x80 {
            return vec![value as u8];
        }
        if value < 0x4000 {
            return vec![((value & 0x7f) as u8) | 0x80, ((value >> 7) & 0x7f) as u8];
        }
        vec![
            ((value & 0x7f) as u8) | 0x80,
            (((value >> 7) & 0x7f) as u8) | 0x80,
            ((value >> 14) & 0x03) as u8,
        ]
    }

    fn build_legacy_tx(signers: &[SigningKey], recent_blockhash: [u8; 32]) -> Vec<u8> {
        let program_id = [9u8; 32];
        let mut message = vec![signers.len() as u8, 0, 1];
        message.extend_from_slice(&encode_compact_u16((signers.len() + 1) as u16));
        for signer in signers {
            message.extend_from_slice(&signer.verifying_key().to_bytes());
        }
        message.extend_from_slice(&program_id);
        message.extend_from_slice(&recent_blockhash);
        message.extend_from_slice(&encode_compact_u16(1)); // one instruction
        message.push(signers.len() as u8); // program id index
        message.extend_from_slice(&encode_compact_u16(0)); // no account indices
        message.extend_from_slice(&encode_compact_u16(0)); // no ix data

        let mut tx = encode_compact_u16(signers.len() as u16);
        for signer in signers {
            tx.extend_from_slice(&signer.sign(&message).to_bytes());
        }
        tx.extend_from_slice(&message);
        tx
    }

    fn build_supported_transfer_tx(
        signer: &SigningKey,
        recipient: [u8; 32],
        recent_blockhash: [u8; 32],
        amount: u64,
    ) -> Vec<u8> {
        let mut message = vec![1, 0, 1];
        message.extend_from_slice(&encode_compact_u16(3));
        message.extend_from_slice(&signer.verifying_key().to_bytes());
        message.extend_from_slice(&recipient);
        message.extend_from_slice(&[0u8; 32]); // SystemProgram
        message.extend_from_slice(&recent_blockhash);
        message.extend_from_slice(&encode_compact_u16(1));
        message.push(2); // program id index
        message.extend_from_slice(&encode_compact_u16(2));
        message.push(0); // source
        message.push(1); // destination
        message.extend_from_slice(&encode_compact_u16(12));
        message.extend_from_slice(&2u32.to_le_bytes());
        message.extend_from_slice(&amount.to_le_bytes());

        let mut tx = encode_compact_u16(1);
        tx.extend_from_slice(&signer.sign(&message).to_bytes());
        tx.extend_from_slice(&message);
        tx
    }

    fn build_supported_transfer_tx_v0(
        signer: &SigningKey,
        recipient: [u8; 32],
        recent_blockhash: [u8; 32],
        amount: u64,
    ) -> Vec<u8> {
        let mut message = vec![0x80, 1, 0, 1];
        message.extend_from_slice(&encode_compact_u16(3));
        message.extend_from_slice(&signer.verifying_key().to_bytes());
        message.extend_from_slice(&recipient);
        message.extend_from_slice(&[0u8; 32]); // SystemProgram
        message.extend_from_slice(&recent_blockhash);
        message.extend_from_slice(&encode_compact_u16(1));
        message.push(2);
        message.extend_from_slice(&encode_compact_u16(2));
        message.push(0);
        message.push(1);
        message.extend_from_slice(&encode_compact_u16(12));
        message.extend_from_slice(&2u32.to_le_bytes());
        message.extend_from_slice(&amount.to_le_bytes());
        message.extend_from_slice(&encode_compact_u16(0)); // no ALT lookups

        let mut tx = encode_compact_u16(1);
        tx.extend_from_slice(&signer.sign(&message).to_bytes());
        tx.extend_from_slice(&message);
        tx
    }

    fn build_ata_then_transfer_checked_tx(
        signer: &SigningKey,
        source_token_account: [u8; 32],
        destination_owner: [u8; 32],
        mint: [u8; 32],
        recent_blockhash: [u8; 32],
        amount: u64,
        decimals: u8,
    ) -> Vec<u8> {
        let destination_ata =
            token_runtime::derive_associated_token_address(&destination_owner, &mint);
        let ata_program = token_runtime::associated_token_program_id();
        let token_program = token_runtime::spl_token_program_id();

        let mut message = vec![0x80, 1, 0, 3];
        message.extend_from_slice(&encode_compact_u16(7));
        message.extend_from_slice(&signer.verifying_key().to_bytes()); // 0 payer/authority
        message.extend_from_slice(&source_token_account); // 1
        message.extend_from_slice(&destination_ata); // 2
        message.extend_from_slice(&destination_owner); // 3
        message.extend_from_slice(&mint); // 4
        message.extend_from_slice(&ata_program); // 5
        message.extend_from_slice(&token_program); // 6
        message.extend_from_slice(&recent_blockhash);
        message.extend_from_slice(&encode_compact_u16(2));

        // ATA create idempotent
        message.push(5);
        message.extend_from_slice(&encode_compact_u16(4));
        message.push(0); // payer
        message.push(2); // ata
        message.push(3); // owner
        message.push(4); // mint
        message.extend_from_slice(&encode_compact_u16(1));
        message.push(1); // idempotent

        // SPL transferChecked
        message.push(6);
        message.extend_from_slice(&encode_compact_u16(4));
        message.push(1); // source
        message.push(4); // mint
        message.push(2); // destination
        message.push(0); // authority
        message.extend_from_slice(&encode_compact_u16(10));
        message.push(SPL_TRANSFER_CHECKED_DISCRIMINANT);
        message.extend_from_slice(&amount.to_le_bytes());
        message.push(decimals);

        message.extend_from_slice(&encode_compact_u16(0)); // no ALT lookups

        let mut tx = encode_compact_u16(1);
        tx.extend_from_slice(&signer.sign(&message).to_bytes());
        tx.extend_from_slice(&message);
        tx
    }

    #[test]
    fn verifies_all_required_signatures() {
        let k1 = SigningKey::from_bytes(&[1u8; 32]);
        let k2 = SigningKey::from_bytes(&[2u8; 32]);
        let tx = build_legacy_tx(&[k1.clone(), k2.clone()], [0u8; 32]);

        let signer = verify_raw_solana_recover_signer(&tx).expect("tx should verify");
        assert_eq!(signer, k1.verifying_key().to_bytes());
    }

    #[test]
    fn rejects_when_non_fee_payer_required_signature_is_invalid() {
        let k1 = SigningKey::from_bytes(&[1u8; 32]);
        let k2 = SigningKey::from_bytes(&[2u8; 32]);
        let mut tx = build_legacy_tx(&[k1.clone(), k2.clone()], [0u8; 32]);
        tx[70] ^= 0x55; // Corrupt the second required signature.

        let err = verify_raw_solana_recover_signer(&tx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("signer 1"));
    }

    #[test]
    fn accepts_versioned_v0_transactions_without_alt() {
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let tx = build_supported_transfer_tx_v0(&signer, [8u8; 32], [7u8; 32], 55);
        let recovered = verify_raw_solana_recover_signer(&tx).expect("versioned tx should verify");
        assert_eq!(recovered, signer.verifying_key().to_bytes());
    }

    #[test]
    fn reconstructs_supported_system_transfer_and_checks_freshness() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let recipient = [8u8; 32];
        let chain_id = 9u32;
        let current_slot = 42u64;
        let recent_slot = current_slot - 2;
        let recent_blockhash = derive_ace_solana_blockhash(chain_id, recent_slot);
        let tx = build_supported_transfer_tx(&signer, recipient, recent_blockhash, 123);

        let mut state = StateTree::new();
        let sender_idcom = legacy_idcom_solana(&signer.verifying_key().to_bytes());
        state.insert(Account::new(AccountId::from_bytes(sender_idcom)));

        let verified =
            verify_raw_solana_transfer_against_state(&state, &tx, chain_id, current_slot)
                .expect("transfer should verify");
        assert_eq!(verified.recent_slot, recent_slot);
        assert_eq!(verified.amount, 123);
        assert_eq!(verified.canonical_payload[0], 0x21);

        // Mark the signature as used and ensure replay is rejected.
        state.set_storage(
            &AccountId::from_bytes(sender_idcom),
            solana_signature_replay_slot(&verified.first_signature),
            [1u8; 32],
        );
        let err = verify_raw_solana_transfer_against_state(&state, &tx, chain_id, current_slot)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already been used"));
    }

    #[test]
    fn rejects_expired_recent_blockhash() {
        let signer = SigningKey::from_bytes(&[5u8; 32]);
        let tx = build_supported_transfer_tx(
            &signer,
            [6u8; 32],
            derive_ace_solana_blockhash(1, SOLANA_RECENT_BLOCKHASH_WINDOW + 20),
            1,
        );
        let mut state = StateTree::new();
        let sender_idcom = legacy_idcom_solana(&signer.verifying_key().to_bytes());
        state.insert(Account::new(AccountId::from_bytes(sender_idcom)));
        let err = verify_raw_solana_transfer_against_state(&state, &tx, 1, 3)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown or expired"));
    }

    #[test]
    fn reconstructs_v0_ata_create_then_transfer_checked() {
        let signer = SigningKey::from_bytes(&[21u8; 32]);
        let destination_owner = [22u8; 32];
        let mint = [23u8; 32];
        let source_token_account = [24u8; 32];
        let chain_id = 7u32;
        let current_slot = 100u64;
        let recent_blockhash = derive_ace_solana_blockhash(chain_id, current_slot);
        let tx = build_ata_then_transfer_checked_tx(
            &signer,
            source_token_account,
            destination_owner,
            mint,
            recent_blockhash,
            1_500,
            6,
        );

        let mut state = StateTree::new();
        let signer_idcom = legacy_idcom_solana(&signer.verifying_key().to_bytes());
        state.insert(Account::new(AccountId::from_bytes(signer_idcom)));
        let authority = AccountId::from_bytes(signer_idcom);
        token_runtime::create_mint(&mut state, &mint, 6, authority.as_bytes()).expect("mint");
        token_runtime::register_token_account(
            &mut state,
            &source_token_account,
            &mint,
            &signer.verifying_key().to_bytes(),
            &signer_idcom,
        )
        .expect("source token account");
        token_runtime::mint_to_owner(&mut state, &mint, &signer_idcom, 5_000, &authority)
            .expect("mint tokens");

        let verified =
            verify_raw_solana_transfer_against_state(&state, &tx, chain_id, current_slot)
                .expect("v0 ata+transferChecked should verify");
        assert_eq!(verified.amount, 1_500);
        assert_eq!(verified.canonical_payload[0], 0x20);
        let destination_ata =
            token_runtime::derive_associated_token_address(&destination_owner, &mint);
        assert!(verified
            .canonical_payload
            .windows(32)
            .any(|window| window == destination_ata));
        assert_eq!(verified.canonical_payload.last().copied(), Some(6));
    }
}
