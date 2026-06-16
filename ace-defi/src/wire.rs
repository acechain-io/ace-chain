//! Consensus wire formats for ACE DeFi system transactions and indexes.

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::BridgeError;
use crate::types::{
    bridge_authority_id, hash_deposit_record, hash_withdrawal_completion, SignedDepositRecord,
    WithdrawalCompletionRecord, WithdrawalRecord,
};

pub const OP_BRIDGE_DEPOSIT: u8 = 0x0D;
pub const OP_WITHDRAWAL_COMPLETED: u8 = 0x0E;
pub const OP_OASSET_WITHDRAW: u8 = 0x13;

const BRIDGE_DEPOSIT_DOMAIN: &[u8] = b"ace-defi:bridge-deposit:v1:";
const WITHDRAWAL_COMPLETED_DOMAIN: &[u8] = b"ace-defi:withdrawal-completed:v1:";
const WITHDRAWAL_INDEX_COUNT_DOMAIN: &[u8] = b"ace-defi:withdrawal-index-count:v1";
const WITHDRAWAL_INDEX_ID_DOMAIN: &[u8] = b"ace-defi:withdrawal-index-id:v1:";
const WITHDRAWAL_RECORD_CHUNKS_DOMAIN: &[u8] = b"ace-defi:withdrawal-record-chunks:v1:";
const WITHDRAWAL_RECORD_LEN_DOMAIN: &[u8] = b"ace-defi:withdrawal-record-len:v1:";
const WITHDRAWAL_RECORD_CHUNK_DOMAIN: &[u8] = b"ace-defi:withdrawal-record-chunk:v1:";
const RELAYER_APPROVAL_DOMAIN: &[u8] = b"ace-defi:relayer-approved:v1:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAssetWithdrawRequest {
    pub nonce: u64,
    pub intent_id: [u8; 32],
    pub canonical_asset: crate::CanonicalAssetId,
    pub amount: u64,
    pub target_asset: crate::ExternalAsset,
    pub external_dest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWithdrawalsPage {
    pub withdrawals: Vec<WithdrawalRecord>,
    pub next_index: u64,
    pub total_indexed: u64,
}

pub fn encode_signed_deposit_payload(signed: &SignedDepositRecord) -> Result<Vec<u8>, BridgeError> {
    let bytes =
        bincode::serialize(signed).map_err(|e| BridgeError::Serialization(e.to_string()))?;
    let len = u32::try_from(bytes.len()).map_err(|_| {
        BridgeError::Serialization("signed deposit payload exceeds u32 length".into())
    })?;
    let mut payload = Vec::with_capacity(1 + 4 + bytes.len());
    payload.push(OP_BRIDGE_DEPOSIT);
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(&bytes);
    Ok(payload)
}

pub fn is_bridge_deposit_payload(payload: &[u8]) -> bool {
    payload.first() == Some(&OP_BRIDGE_DEPOSIT)
}

pub fn decode_signed_deposit_payload(payload: &[u8]) -> Result<SignedDepositRecord, BridgeError> {
    if payload.len() < 5 || payload[0] != OP_BRIDGE_DEPOSIT {
        return Err(BridgeError::InvalidDepositProof(
            "not an ACE DeFi bridge deposit payload".into(),
        ));
    }
    let len = u32::from_le_bytes(payload[1..5].try_into().unwrap()) as usize;
    let end = 5usize.checked_add(len).ok_or_else(|| {
        BridgeError::InvalidDepositProof("deposit payload length overflow".into())
    })?;
    if payload.len() != end {
        return Err(BridgeError::InvalidDepositProof(format!(
            "invalid deposit payload length: expected {end}, got {}",
            payload.len()
        )));
    }
    bincode::deserialize(&payload[5..end]).map_err(|e| {
        BridgeError::InvalidDepositProof(format!("invalid signed deposit encoding: {e}"))
    })
}

pub fn bridge_deposit_tx_idcom(signed: &SignedDepositRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BRIDGE_DEPOSIT_DOMAIN);
    hasher.update(signed.relayer_pubkey);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

pub fn encode_withdrawal_completion_payload(
    completion: &WithdrawalCompletionRecord,
) -> Result<Vec<u8>, BridgeError> {
    let bytes =
        bincode::serialize(completion).map_err(|e| BridgeError::Serialization(e.to_string()))?;
    let len = u32::try_from(bytes.len()).map_err(|_| {
        BridgeError::Serialization("withdrawal completion payload exceeds u32 length".into())
    })?;
    let mut payload = Vec::with_capacity(1 + 4 + bytes.len());
    payload.push(OP_WITHDRAWAL_COMPLETED);
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(&bytes);
    Ok(payload)
}

pub fn is_withdrawal_completion_payload(payload: &[u8]) -> bool {
    payload.first() == Some(&OP_WITHDRAWAL_COMPLETED)
}

pub fn is_oasset_withdraw_payload(payload: &[u8]) -> bool {
    payload.first() == Some(&OP_OASSET_WITHDRAW)
}

pub fn build_oasset_withdraw_payload(
    nonce: u64,
    intent_id: [u8; 32],
    canonical_asset: crate::CanonicalAssetId,
    amount: u64,
    target_asset: &crate::ExternalAsset,
    external_dest: &[u8],
) -> Result<Vec<u8>, BridgeError> {
    let dest_len = u16::try_from(external_dest.len())
        .map_err(|_| BridgeError::Serialization("external destination too long".into()))?;
    let encoded_asset = crate::runtime::encode_asset(target_asset);
    let mut payload =
        Vec::with_capacity(1 + 8 + 32 + 32 + 8 + encoded_asset.len() + 2 + external_dest.len());
    payload.push(OP_OASSET_WITHDRAW);
    payload.extend_from_slice(&nonce.to_le_bytes());
    payload.extend_from_slice(&intent_id);
    payload.extend_from_slice(canonical_asset.as_bytes());
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.extend_from_slice(&encoded_asset);
    payload.extend_from_slice(&dest_len.to_le_bytes());
    payload.extend_from_slice(external_dest);
    Ok(payload)
}

pub fn decode_oasset_withdraw_payload(
    payload: &[u8],
) -> Result<OAssetWithdrawRequest, BridgeError> {
    if payload.len() < 1 + 8 + 32 + 32 + 8 + 2 || payload[0] != OP_OASSET_WITHDRAW {
        return Err(BridgeError::InvalidDepositProof(
            "not an OmniLiquid oAsset withdrawal payload".into(),
        ));
    }
    let mut cursor = 1;
    let nonce = u64::from_le_bytes(payload[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let mut intent_id = [0u8; 32];
    intent_id.copy_from_slice(&payload[cursor..cursor + 32]);
    cursor += 32;
    let mut canonical = [0u8; 32];
    canonical.copy_from_slice(&payload[cursor..cursor + 32]);
    cursor += 32;
    let amount = u64::from_le_bytes(payload[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let (target_asset, consumed) = decode_asset_for_wire(&payload[cursor..])?;
    cursor += consumed;
    if cursor + 2 > payload.len() {
        return Err(BridgeError::InvalidDepositProof(
            "missing external destination length".into(),
        ));
    }
    let dest_len = u16::from_le_bytes(payload[cursor..cursor + 2].try_into().unwrap()) as usize;
    cursor += 2;
    if cursor + dest_len != payload.len() {
        return Err(BridgeError::InvalidDepositProof(
            "invalid external destination length".into(),
        ));
    }
    Ok(OAssetWithdrawRequest {
        nonce,
        intent_id,
        canonical_asset: crate::CanonicalAssetId(canonical),
        amount,
        target_asset,
        external_dest: payload[cursor..].to_vec(),
    })
}

pub fn decode_withdrawal_completion_payload(
    payload: &[u8],
) -> Result<WithdrawalCompletionRecord, BridgeError> {
    if payload.len() < 5 || payload[0] != OP_WITHDRAWAL_COMPLETED {
        return Err(BridgeError::InvalidDepositProof(
            "not an ACE DeFi withdrawal completion payload".into(),
        ));
    }
    let len = u32::from_le_bytes(payload[1..5].try_into().unwrap()) as usize;
    let end = 5usize.checked_add(len).ok_or_else(|| {
        BridgeError::InvalidDepositProof("withdrawal completion payload length overflow".into())
    })?;
    if payload.len() != end {
        return Err(BridgeError::InvalidDepositProof(format!(
            "invalid withdrawal completion payload length: expected {end}, got {}",
            payload.len()
        )));
    }
    bincode::deserialize(&payload[5..end]).map_err(|e| {
        BridgeError::InvalidDepositProof(format!("invalid withdrawal completion encoding: {e}"))
    })
}

pub fn withdrawal_completion_tx_idcom(completion: &WithdrawalCompletionRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WITHDRAWAL_COMPLETED_DOMAIN);
    hasher.update(completion.relayer_pubkey);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

pub fn approve_relayer_in_state(state: &mut StateTree, relayer_pubkey: [u8; 32]) {
    let mut marker = [0u8; 32];
    marker[0] = 0x01;
    state.set_storage(
        &bridge_authority_id(),
        relayer_approval_slot(&relayer_pubkey),
        marker,
    );
}

pub fn is_relayer_approved_in_state(state: &StateTree, relayer_pubkey: &[u8; 32]) -> bool {
    let stored = state.get_storage(
        &bridge_authority_id(),
        &relayer_approval_slot(relayer_pubkey),
    );
    stored[0] == 0x01
}

pub fn verify_signed_deposit_against_state(
    state: &StateTree,
    signed: &SignedDepositRecord,
) -> Result<(), BridgeError> {
    if !is_relayer_approved_in_state(state, &signed.relayer_pubkey) {
        return Err(BridgeError::InvalidDepositProof(
            "relayer not in state-approved set".into(),
        ));
    }
    verify_signed_deposit_signature(signed)
}

pub fn verify_signed_deposit_signature(signed: &SignedDepositRecord) -> Result<(), BridgeError> {
    let deposit_hash = hash_deposit_record(&signed.deposit);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&signed.relayer_pubkey)
        .map_err(|e| BridgeError::InvalidDepositProof(format!("invalid relayer pubkey: {e}")))?;
    let signature = ed25519_dalek::Signature::from_bytes(&signed.relayer_signature);
    verifying_key
        .verify_strict(&deposit_hash, &signature)
        .map_err(|e| BridgeError::InvalidDepositProof(format!("invalid signature: {e}")))
}

pub fn verify_withdrawal_completion_against_state(
    state: &StateTree,
    completion: &WithdrawalCompletionRecord,
) -> Result<(), BridgeError> {
    if !is_relayer_approved_in_state(state, &completion.relayer_pubkey) {
        return Err(BridgeError::InvalidDepositProof(
            "relayer not in state-approved set".into(),
        ));
    }
    let Some(record) = load_indexed_withdrawal_record(state, completion.withdrawal_id)? else {
        return Err(BridgeError::InvalidDepositProof(format!(
            "withdrawal {} not found",
            completion.withdrawal_id
        )));
    };
    if record.completed {
        return Err(BridgeError::InvalidDepositProof(format!(
            "withdrawal {} already completed",
            completion.withdrawal_id
        )));
    }
    if record.asset.chain() != completion.destination_chain {
        return Err(BridgeError::InvalidDepositProof(format!(
            "withdrawal chain mismatch: record {}, completion {}",
            record.asset.chain(),
            completion.destination_chain
        )));
    }
    if record.asset != completion.released_asset {
        return Err(BridgeError::InvalidDepositProof(format!(
            "withdrawal {} released asset mismatch",
            completion.withdrawal_id
        )));
    }
    if record.external_dest != completion.released_recipient {
        return Err(BridgeError::InvalidDepositProof(format!(
            "withdrawal {} released recipient mismatch",
            completion.withdrawal_id
        )));
    }
    if record.amount != completion.released_amount {
        return Err(BridgeError::InvalidDepositProof(format!(
            "withdrawal {} released amount mismatch",
            completion.withdrawal_id
        )));
    }
    let expected_record_hash = crate::withdraw::hash_withdrawal_record(&record);
    if completion.withdrawal_record_hash != expected_record_hash {
        return Err(BridgeError::InvalidDepositProof(format!(
            "withdrawal {} record hash mismatch",
            completion.withdrawal_id
        )));
    }

    let completion_hash = hash_withdrawal_completion(completion);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&completion.relayer_pubkey)
        .map_err(|e| BridgeError::InvalidDepositProof(format!("invalid relayer pubkey: {e}")))?;
    let signature = ed25519_dalek::Signature::from_bytes(&completion.relayer_signature);
    verifying_key
        .verify_strict(&completion_hash, &signature)
        .map_err(|e| BridgeError::InvalidDepositProof(format!("invalid signature: {e}")))
}

pub fn index_withdrawal_record(
    state: &mut StateTree,
    record: &WithdrawalRecord,
) -> Result<(), BridgeError> {
    let owner = bridge_authority_id();
    let existing = load_indexed_withdrawal_record(state, record.withdrawal_id)?;
    if existing.is_none() {
        let index = read_u64_slot(state, &owner, withdrawal_index_count_slot());
        write_u64_slot(
            state,
            &owner,
            withdrawal_index_id_slot(index),
            record.withdrawal_id,
        );
        write_u64_slot(state, &owner, withdrawal_index_count_slot(), index + 1);
    }
    write_withdrawal_record(state, &owner, record)
}

pub fn mark_indexed_withdrawal_completed(
    state: &mut StateTree,
    withdrawal_id: u64,
) -> Result<(), BridgeError> {
    if let Some(mut record) = load_indexed_withdrawal_record(state, withdrawal_id)? {
        record.completed = true;
        write_withdrawal_record(state, &bridge_authority_id(), &record)?;
    }
    Ok(())
}

pub fn complete_indexed_withdrawal(
    state: &mut StateTree,
    completion: &WithdrawalCompletionRecord,
) -> Result<WithdrawalRecord, BridgeError> {
    let snapshot = state.snapshot();
    match complete_indexed_withdrawal_inner(state, completion) {
        Ok(record) => Ok(record),
        Err(error) => {
            state.rollback(snapshot);
            Err(error)
        }
    }
}

fn complete_indexed_withdrawal_inner(
    state: &mut StateTree,
    completion: &WithdrawalCompletionRecord,
) -> Result<WithdrawalRecord, BridgeError> {
    verify_withdrawal_completion_against_state(state, completion)?;
    let mut record = load_indexed_withdrawal_record(state, completion.withdrawal_id)?
        .ok_or_else(|| BridgeError::InvalidDepositProof("withdrawal not found".into()))?;
    record.completed = true;
    write_withdrawal_record(state, &bridge_authority_id(), &record)?;
    if let Some(mapping) =
        crate::canonical::CanonicalAssetRegistry::get_mapping(state, &record.asset)?
    {
        let canonical_amount = crate::canonical::normalize_amount(
            record.amount,
            mapping.external_decimals,
            mapping.canonical_decimals,
        )?;
        crate::reserve::ReserveAccounting::finalize_withdrawal(
            state,
            &record.asset,
            canonical_amount,
            record.requested_at,
        )?;
    }
    let mut marker = [0u8; 32];
    marker[0] = 0x01;
    state.set_storage(
        &bridge_authority_id(),
        crate::withdraw::withdrawal_completed_slot(completion.withdrawal_id),
        marker,
    );
    Ok(record)
}

pub fn list_pending_withdrawals(
    state: &StateTree,
    _since_slot: u64,
) -> Result<Vec<WithdrawalRecord>, BridgeError> {
    let owner = bridge_authority_id();
    let count = read_u64_slot(state, &owner, withdrawal_index_count_slot());
    let mut out = Vec::new();

    for index in 0..count {
        let withdrawal_id = read_u64_slot(state, &owner, withdrawal_index_id_slot(index));
        if let Some(record) = load_indexed_withdrawal_record(state, withdrawal_id)? {
            if !record.completed {
                out.push(record);
            }
        }
    }
    out.sort_by_key(|record| record.withdrawal_id);
    Ok(out)
}

pub fn list_pending_withdrawals_page(
    state: &StateTree,
    start_index: u64,
    limit: u64,
) -> Result<PendingWithdrawalsPage, BridgeError> {
    let owner = bridge_authority_id();
    let count = read_u64_slot(state, &owner, withdrawal_index_count_slot());
    let limit = limit.clamp(1, 1_000);
    let mut out = Vec::new();
    let mut index = start_index.min(count);
    while index < count && (out.len() as u64) < limit {
        let withdrawal_id = read_u64_slot(state, &owner, withdrawal_index_id_slot(index));
        if let Some(record) = load_indexed_withdrawal_record(state, withdrawal_id)? {
            if !record.completed {
                out.push(record);
            }
        }
        index += 1;
    }
    Ok(PendingWithdrawalsPage {
        withdrawals: out,
        next_index: index,
        total_indexed: count,
    })
}

pub fn load_indexed_withdrawal_record(
    state: &StateTree,
    withdrawal_id: u64,
) -> Result<Option<WithdrawalRecord>, BridgeError> {
    let owner = bridge_authority_id();
    let chunks = read_u64_slot(
        state,
        &owner,
        withdrawal_record_chunk_count_slot(withdrawal_id),
    );
    if chunks == 0 {
        return Ok(None);
    }
    let byte_len = read_u64_slot(state, &owner, withdrawal_record_len_slot(withdrawal_id));
    let mut bytes = Vec::with_capacity(chunks as usize * 32);
    for idx in 0..chunks {
        let chunk = state.get_storage(&owner, &withdrawal_record_chunk_slot(withdrawal_id, idx));
        bytes.extend_from_slice(&chunk);
    }
    let byte_len = usize::try_from(byte_len)
        .map_err(|_| BridgeError::Serialization("withdrawal byte length overflow".into()))?;
    if byte_len > bytes.len() {
        return Err(BridgeError::Serialization(
            "withdrawal byte length exceeds stored chunks".into(),
        ));
    }
    bytes.truncate(byte_len);
    let record = bincode::deserialize(&bytes)
        .map_err(|e| BridgeError::Serialization(format!("withdrawal decode failed: {e}")))?;
    Ok(Some(record))
}

fn write_withdrawal_record(
    state: &mut StateTree,
    owner: &AccountId,
    record: &WithdrawalRecord,
) -> Result<(), BridgeError> {
    let bytes =
        bincode::serialize(record).map_err(|e| BridgeError::Serialization(e.to_string()))?;
    let chunks = bytes.len().div_ceil(32) as u64;
    write_u64_slot(
        state,
        owner,
        withdrawal_record_chunk_count_slot(record.withdrawal_id),
        chunks,
    );
    write_u64_slot(
        state,
        owner,
        withdrawal_record_len_slot(record.withdrawal_id),
        bytes.len() as u64,
    );
    for (idx, chunk) in bytes.chunks(32).enumerate() {
        let mut slot_value = [0u8; 32];
        slot_value[..chunk.len()].copy_from_slice(chunk);
        state.set_storage(
            owner,
            withdrawal_record_chunk_slot(record.withdrawal_id, idx as u64),
            slot_value,
        );
    }
    Ok(())
}

fn read_u64_slot(state: &StateTree, owner: &AccountId, slot: [u8; 32]) -> u64 {
    let value = state.get_storage(owner, &slot);
    u64::from_le_bytes(value[0..8].try_into().unwrap())
}

fn write_u64_slot(state: &mut StateTree, owner: &AccountId, slot: [u8; 32], value: u64) {
    let mut encoded = [0u8; 32];
    encoded[0..8].copy_from_slice(&value.to_le_bytes());
    state.set_storage(owner, slot, encoded);
}

fn withdrawal_index_count_slot() -> [u8; 32] {
    domain_slot(WITHDRAWAL_INDEX_COUNT_DOMAIN, &[])
}

fn withdrawal_index_id_slot(index: u64) -> [u8; 32] {
    domain_slot(WITHDRAWAL_INDEX_ID_DOMAIN, &index.to_le_bytes())
}

fn relayer_approval_slot(relayer_pubkey: &[u8; 32]) -> [u8; 32] {
    domain_slot(RELAYER_APPROVAL_DOMAIN, relayer_pubkey)
}

fn withdrawal_record_chunk_count_slot(withdrawal_id: u64) -> [u8; 32] {
    domain_slot(
        WITHDRAWAL_RECORD_CHUNKS_DOMAIN,
        &withdrawal_id.to_le_bytes(),
    )
}

fn withdrawal_record_len_slot(withdrawal_id: u64) -> [u8; 32] {
    domain_slot(WITHDRAWAL_RECORD_LEN_DOMAIN, &withdrawal_id.to_le_bytes())
}

fn withdrawal_record_chunk_slot(withdrawal_id: u64, chunk_index: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&withdrawal_id.to_le_bytes());
    data.extend_from_slice(&chunk_index.to_le_bytes());
    domain_slot(WITHDRAWAL_RECORD_CHUNK_DOMAIN, &data)
}

fn domain_slot(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data);
    let result = hasher.finalize();
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&result);
    slot
}

fn decode_asset_for_wire(data: &[u8]) -> Result<(crate::ExternalAsset, usize), BridgeError> {
    use crate::ExternalChain;
    if data.is_empty() {
        return Err(BridgeError::InvalidDepositProof("empty asset tag".into()));
    }
    match data[0] {
        0x01 => {
            if data.len() < 2 {
                return Err(BridgeError::InvalidDepositProof("missing chain id".into()));
            }
            let chain = match data[1] {
                1 => ExternalChain::Ethereum,
                2 => ExternalChain::Solana,
                3 => ExternalChain::Bitcoin,
                4 => ExternalChain::Tron,
                5 => ExternalChain::Bsc,
                other => {
                    return Err(BridgeError::InvalidDepositProof(format!(
                        "unknown native chain id {other}"
                    )))
                }
            };
            Ok((crate::ExternalAsset::Native(chain), 2))
        }
        0x02 => {
            if data.len() < 21 {
                return Err(BridgeError::InvalidDepositProof(
                    "truncated ERC20 asset".into(),
                ));
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&data[1..21]);
            Ok((crate::ExternalAsset::Erc20(addr), 21))
        }
        0x03 => {
            if data.len() < 33 {
                return Err(BridgeError::InvalidDepositProof(
                    "truncated SPL asset".into(),
                ));
            }
            let mut mint = [0u8; 32];
            mint.copy_from_slice(&data[1..33]);
            Ok((crate::ExternalAsset::SplToken(mint), 33))
        }
        0x04 => {
            if data.len() < 21 {
                return Err(BridgeError::InvalidDepositProof(
                    "truncated TRC20 asset".into(),
                ));
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&data[1..21]);
            Ok((crate::ExternalAsset::Trc20(addr), 21))
        }
        0x05 => {
            if data.len() < 21 {
                return Err(BridgeError::InvalidDepositProof(
                    "truncated BEP20 asset".into(),
                ));
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&data[1..21]);
            Ok((crate::ExternalAsset::Bep20(addr), 21))
        }
        other => Err(BridgeError::InvalidDepositProof(format!(
            "unknown asset tag {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_model::state_tree::StateTree;
    use ed25519_dalek::{Signer, SigningKey};

    use crate::types::{
        hash_deposit_record, hash_withdrawal_completion, DepositRecord, ExternalAsset,
        ExternalChain, WithdrawalCompletionRecord,
    };

    #[test]
    fn withdrawal_index_round_trips_and_filters_completed() {
        let mut state = StateTree::new();
        let mut record = WithdrawalRecord {
            withdrawal_id: 7,
            intent_id: [1u8; 32],
            asset: ExternalAsset::Native(ExternalChain::Ethereum),
            amount: 42,
            sender: AccountId::from_bytes([2u8; 32]),
            external_dest: vec![3u8; 20],
            requested_at: 10,
            completed: false,
        };

        index_withdrawal_record(&mut state, &record).unwrap();
        assert_eq!(
            list_pending_withdrawals(&state, 0).unwrap(),
            vec![record.clone()]
        );
        assert_eq!(
            list_pending_withdrawals(&state, 11).unwrap(),
            vec![record.clone()]
        );

        record.completed = true;
        index_withdrawal_record(&mut state, &record).unwrap();
        assert!(list_pending_withdrawals(&state, 0).unwrap().is_empty());
    }

    #[test]
    fn signed_deposit_requires_state_approved_relayer() {
        let mut state = StateTree::new();
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let deposit = DepositRecord {
            deposit_id: [1u8; 32],
            intent_id: [2u8; 32],
            asset: ExternalAsset::Native(ExternalChain::Ethereum),
            amount: 10,
            recipient: AccountId::from_bytes([3u8; 32]),
            processed_at: 4,
        };
        let signature = signing_key.sign(&hash_deposit_record(&deposit));
        let signed = SignedDepositRecord {
            deposit,
            relayer_pubkey: signing_key.verifying_key().to_bytes(),
            relayer_signature: signature.to_bytes(),
        };

        assert!(verify_signed_deposit_against_state(&state, &signed).is_err());
        approve_relayer_in_state(&mut state, signed.relayer_pubkey);
        assert!(verify_signed_deposit_against_state(&state, &signed).is_ok());
    }

    #[test]
    fn oasset_withdraw_payload_round_trips_evm_assets() {
        let canonical = crate::CanonicalAssetId([9u8; 32]);
        let intent_id = [7u8; 32];
        let external_dest = vec![6u8; 20];

        for target_asset in [
            ExternalAsset::Erc20([1u8; 20]),
            ExternalAsset::Bep20([2u8; 20]),
        ] {
            let payload = build_oasset_withdraw_payload(
                11,
                intent_id,
                canonical,
                1_000_000,
                &target_asset,
                &external_dest,
            )
            .unwrap();
            assert!(is_oasset_withdraw_payload(&payload));

            let decoded = decode_oasset_withdraw_payload(&payload).unwrap();
            assert_eq!(decoded.nonce, 11);
            assert_eq!(decoded.intent_id, intent_id);
            assert_eq!(decoded.canonical_asset, canonical);
            assert_eq!(decoded.amount, 1_000_000);
            assert_eq!(decoded.target_asset, target_asset);
            assert_eq!(decoded.external_dest, external_dest);
        }
    }

    #[test]
    fn withdrawal_completion_requires_approved_relayer_and_marks_index() {
        let mut state = StateTree::new();
        let record = WithdrawalRecord {
            withdrawal_id: 9,
            intent_id: [1u8; 32],
            asset: ExternalAsset::Native(ExternalChain::Ethereum),
            amount: 42,
            sender: AccountId::from_bytes([2u8; 32]),
            external_dest: vec![3u8; 20],
            requested_at: 10,
            completed: false,
        };
        index_withdrawal_record(&mut state, &record).unwrap();

        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let mut completion = WithdrawalCompletionRecord {
            withdrawal_id: record.withdrawal_id,
            destination_chain: ExternalChain::Ethereum,
            external_tx_hash: [4u8; 32],
            withdrawal_record_hash: crate::withdraw::hash_withdrawal_record(&record),
            released_asset: record.asset.clone(),
            released_recipient: record.external_dest.clone(),
            released_amount: record.amount,
            gateway_address: vec![5u8; 20],
            relayer_pubkey: signing_key.verifying_key().to_bytes(),
            relayer_signature: [0u8; 64],
        };
        let signature = signing_key.sign(&hash_withdrawal_completion(&completion));
        completion.relayer_signature = signature.to_bytes();

        assert!(verify_withdrawal_completion_against_state(&state, &completion).is_err());
        approve_relayer_in_state(&mut state, completion.relayer_pubkey);
        assert!(verify_withdrawal_completion_against_state(&state, &completion).is_ok());

        let completed = complete_indexed_withdrawal(&mut state, &completion).unwrap();
        assert!(completed.completed);
        assert!(list_pending_withdrawals(&state, 0).unwrap().is_empty());
        assert!(verify_withdrawal_completion_against_state(&state, &completion).is_err());
    }
}
