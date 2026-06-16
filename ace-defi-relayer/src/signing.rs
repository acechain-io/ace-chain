//! Cryptographic signing for relayer attestations

use crate::error::{RelayerError, Result};
use crate::types::{DepositAttestation, DepositEvent};
use ace_defi::types::{
    hash_deposit_record, hash_withdrawal_completion, DepositRecord, ExternalAsset, ExternalChain,
    SignedDepositRecord, WithdrawalCompletionRecord, WithdrawalRecord,
};
use ace_model::account::AccountId;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Signs a deposit event with the relayer's private key
pub fn sign_deposit(
    event: &DepositEvent,
    _relayer_id: &str,
    private_key_hex: &str,
) -> Result<DepositAttestation> {
    // Decode private key from hex
    let key_bytes = hex::decode(private_key_hex)
        .map_err(|_| RelayerError::SigningError("Invalid hex private key".to_string()))?;

    if key_bytes.len() != 32 {
        return Err(RelayerError::SigningError(
            "Private key must be 32 bytes".to_string(),
        ));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);

    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.to_bytes());

    // Construct message to sign
    let message = construct_attestation_message(event, &public_key_hex);

    // Sign the message
    let signature = signing_key.sign(&message);
    let signature_hex = hex::encode(signature.to_bytes());

    Ok(DepositAttestation {
        deposit_id: event.deposit_id.clone(),
        intent_id: event.intent_id.clone(),
        source_chain: event.source_chain.clone(),
        token: event.token.clone(),
        amount: event.amount,
        recipient: event.recipient.clone(),
        block_number: event.block_number,
        tx_hash: event.tx_hash.clone(),
        timestamp: event.timestamp,
        signature: signature_hex,
        relayer_id: public_key_hex,
    })
}

/// Build the exact signed deposit record expected by ACE Chain.
///
/// This is the production signing path. The signature covers
/// `ace_defi::types::hash_deposit_record`, which is the same digest verified
/// by `BridgeState::process_signed_deposit` on ACE.
pub fn sign_ace_deposit(
    event: &DepositEvent,
    private_key_hex: &str,
) -> Result<SignedDepositRecord> {
    let key_bytes = hex::decode(private_key_hex)
        .map_err(|_| RelayerError::SigningError("Invalid hex private key".to_string()))?;
    if key_bytes.len() != 32 {
        return Err(RelayerError::SigningError(
            "Private key must be 32 bytes".to_string(),
        ));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&key_array);

    let deposit = event_to_ace_deposit(event)?;
    let deposit_hash = hash_deposit_record(&deposit);
    let signature = signing_key.sign(&deposit_hash);

    Ok(SignedDepositRecord {
        deposit,
        relayer_pubkey: signing_key.verifying_key().to_bytes(),
        relayer_signature: signature.to_bytes(),
    })
}

pub fn sign_withdrawal_completion(
    withdrawal: &WithdrawalRecord,
    external_tx_hash_hex: &str,
    gateway_address: Vec<u8>,
    private_key_hex: &str,
) -> Result<WithdrawalCompletionRecord> {
    let key_bytes = hex::decode(private_key_hex)
        .map_err(|_| RelayerError::SigningError("Invalid hex private key".to_string()))?;
    if key_bytes.len() != 32 {
        return Err(RelayerError::SigningError(
            "Private key must be 32 bytes".to_string(),
        ));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&key_array);

    let tx_hash_bytes = parse_hex_32(external_tx_hash_hex, "external_tx_hash")?;
    let mut completion = WithdrawalCompletionRecord {
        withdrawal_id: withdrawal.withdrawal_id,
        destination_chain: withdrawal.asset.chain(),
        external_tx_hash: tx_hash_bytes,
        withdrawal_record_hash: ace_defi::withdraw::hash_withdrawal_record(withdrawal),
        released_asset: withdrawal.asset.clone(),
        released_recipient: withdrawal.external_dest.clone(),
        released_amount: withdrawal.amount,
        gateway_address,
        relayer_pubkey: signing_key.verifying_key().to_bytes(),
        relayer_signature: [0u8; 64],
    };
    let digest = hash_withdrawal_completion(&completion);
    let signature = signing_key.sign(&digest);
    completion.relayer_signature = signature.to_bytes();
    Ok(completion)
}

fn event_to_ace_deposit(event: &DepositEvent) -> Result<DepositRecord> {
    let deposit_id = parse_hex_32(&event.deposit_id, "deposit_id")?;
    let intent_id = parse_hex_32(&event.intent_id, "intent_id")?;
    let recipient = AccountId::from_bytes(parse_hex_32(&event.recipient, "recipient")?);
    let amount = u64::try_from(event.amount).map_err(|_| {
        RelayerError::DepositError(format!("amount exceeds ACE u64 limit: {}", event.amount))
    })?;
    let asset = parse_asset(&event.source_chain, &event.token)?;

    Ok(DepositRecord {
        deposit_id,
        intent_id,
        asset,
        amount,
        recipient,
        processed_at: event.block_number,
    })
}

fn parse_asset(source_chain: &str, token: &str) -> Result<ExternalAsset> {
    let chain = match source_chain.to_ascii_lowercase().as_str() {
        "ethereum" | "eth" => ExternalChain::Ethereum,
        "bsc" | "bnb" | "binance-smart-chain" => ExternalChain::Bsc,
        "solana" | "sol" => ExternalChain::Solana,
        "bitcoin" | "btc" => ExternalChain::Bitcoin,
        "tron" | "trx" => ExternalChain::Tron,
        other => {
            return Err(RelayerError::DepositError(format!(
                "unsupported source chain: {other}"
            )))
        }
    };

    if token.is_empty()
        || token.eq_ignore_ascii_case("native")
        || token == "0x0000000000000000000000000000000000000000"
    {
        return Ok(ExternalAsset::Native(chain));
    }

    match chain {
        ExternalChain::Ethereum => Ok(ExternalAsset::Erc20(parse_hex_20(token, "token")?)),
        ExternalChain::Bsc => Ok(ExternalAsset::Bep20(parse_hex_20(token, "token")?)),
        ExternalChain::Tron => Ok(ExternalAsset::Trc20(parse_hex_20(token, "token")?)),
        ExternalChain::Solana => Ok(ExternalAsset::SplToken(parse_hex_32(token, "token")?)),
        ExternalChain::Bitcoin => Err(RelayerError::DepositError(
            "bitcoin token deposits are not supported".into(),
        )),
    }
}

fn parse_hex_20(value: &str, field: &str) -> Result<[u8; 20]> {
    let bytes = parse_hex(value, field)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RelayerError::DepositError(format!("{field} must be 20 bytes, got {}", bytes.len()))
    })
}

fn parse_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex(value, field)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RelayerError::DepositError(format!("{field} must be 32 bytes, got {}", bytes.len()))
    })
}

fn parse_hex(value: &str, field: &str) -> Result<Vec<u8>> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed)
        .map_err(|e| RelayerError::DepositError(format!("invalid {field} hex: {e}")))
}

/// Constructs the message to be signed for a deposit
fn construct_attestation_message(event: &DepositEvent, relayer_id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();

    hasher.update(b"ace-defi-relayer:deposit:v1");
    hasher.update(event.deposit_id.as_bytes());
    hasher.update(event.intent_id.as_bytes());
    hasher.update(event.source_chain.as_bytes());
    hasher.update(event.token.as_bytes());
    hasher.update(event.amount.to_le_bytes());
    hasher.update(event.recipient.as_bytes());
    hasher.update(event.block_number.to_le_bytes());
    hasher.update(event.tx_hash.as_bytes());
    hasher.update(event.timestamp.to_le_bytes());
    hasher.update(relayer_id.as_bytes());

    hasher.finalize().to_vec()
}

/// Verifies a deposit attestation signature
pub fn verify_attestation(attestation: &DepositAttestation) -> Result<bool> {
    // Decode signature and public key
    let signature_bytes = hex::decode(&attestation.signature)
        .map_err(|_| RelayerError::SigningError("Invalid signature hex".to_string()))?;

    let public_key_bytes = hex::decode(&attestation.relayer_id)
        .map_err(|_| RelayerError::SigningError("Invalid public key hex".to_string()))?;

    if public_key_bytes.len() != 32 || signature_bytes.len() != 64 {
        return Err(RelayerError::SigningError(
            "Invalid key or signature length".to_string(),
        ));
    }

    // Reconstruct message
    let event = DepositEvent {
        deposit_id: attestation.deposit_id.clone(),
        intent_id: attestation.intent_id.clone(),
        source_chain: attestation.source_chain.clone(),
        token: attestation.token.clone(),
        amount: attestation.amount,
        recipient: attestation.recipient.clone(),
        block_number: attestation.block_number,
        tx_hash: attestation.tx_hash.clone(),
        timestamp: attestation.timestamp,
    };
    let message = construct_attestation_message(&event, &attestation.relayer_id);

    // Verify signature
    let mut public_key_array = [0u8; 32];
    public_key_array.copy_from_slice(&public_key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| RelayerError::SigningError("Invalid public key".to_string()))?;

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    match verifying_key.verify_strict(&message, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        // Generate a test keypair
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let private_key_hex = hex::encode(signing_key.to_bytes());

        let event = DepositEvent {
            deposit_id: "test-deposit-id".to_string(),
            intent_id: "test-intent-id".to_string(),
            source_chain: "ethereum".to_string(),
            token: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
            amount: 1_000_000_000_000_000_000,
            recipient: "ace1234567890".to_string(),
            block_number: 19000000,
            tx_hash: "0xabc123".to_string(),
            timestamp: 1700000000,
        };

        let attestation =
            sign_deposit(&event, "test-relayer", &private_key_hex).expect("Failed to sign deposit");

        // Verify the attestation
        let is_valid = verify_attestation(&attestation).expect("Failed to verify");
        assert!(is_valid, "Attestation should be valid");
    }

    #[test]
    fn test_sign_ace_deposit_matches_ace_hash() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let private_key_hex = hex::encode(signing_key.to_bytes());

        let event = DepositEvent {
            deposit_id: format!("0x{}", hex::encode([0x11u8; 32])),
            intent_id: format!("0x{}", hex::encode([0x33u8; 32])),
            source_chain: "ethereum".to_string(),
            token: "native".to_string(),
            amount: 1_000_000,
            recipient: format!("0x{}", hex::encode([0x22u8; 32])),
            block_number: 19000000,
            tx_hash: "0xabc123".to_string(),
            timestamp: 1700000000,
        };

        let signed = sign_ace_deposit(&event, &private_key_hex).unwrap();
        let digest = hash_deposit_record(&signed.deposit);
        let verifying_key = signing_key.verifying_key();
        let signature = ed25519_dalek::Signature::from_bytes(&signed.relayer_signature);
        assert!(verifying_key.verify_strict(&digest, &signature).is_ok());
    }
}
