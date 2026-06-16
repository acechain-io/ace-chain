//! Transaction executor: validates and applies state transitions.
//!
//! Replaces ace-runtime's simplified `execute_transactions` with real
//! account state changes. The executor decodes transaction payloads
//! into operations and applies them against the state tree.

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::legacy::{idcom_xid, register_address_message, xaddress_hash};
use ace_runtime::crypto::sig_algo::{
    verify_signature, SignatureAlgorithm, TaggedPubkey, TaggedSignature,
};
use ace_runtime::types::transaction::Transaction;

use crate::error::EngineError;
use crate::receipt::{ExecutionReceipt, StateChange};
use crate::transfer;

/// Chain-level execution policy threaded from genesis into the executor.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecutionPolicy {
    /// When set, only this account may send `OP_APPROVE_VALIDATOR`.
    pub founder_id_com: Option<AccountId>,
}

/// Fail closed on validator admission at execution time (not just mempool).
pub fn validate_approve_validator_sender(
    policy: &ExecutionPolicy,
    sender: AccountId,
) -> Result<(), EngineError> {
    let founder = policy.founder_id_com.ok_or_else(|| {
        EngineError::InvalidPayload(
            "validator admission is disabled (no founder_id_com in genesis)".into(),
        )
    })?;
    if sender != founder {
        return Err(EngineError::InvalidPayload(format!(
            "OP_APPROVE_VALIDATOR sender {} is not the founder",
            hex::encode(sender.0)
        )));
    }
    Ok(())
}

fn apply_approve_validator_nonce(
    state: &mut StateTree,
    tx_hash: [u8; 32],
    sender: AccountId,
    nonce: u64,
    policy: &ExecutionPolicy,
) -> Result<ExecutionReceipt, EngineError> {
    validate_approve_validator_sender(policy, sender)?;
    let account = state
        .get_mut(&sender)
        .ok_or(EngineError::AccountNotFound(sender.0))?;
    let nonce_change = consume_account_nonce(account, &sender, nonce)?;
    Ok(ExecutionReceipt {
        tx_hash,
        sender,
        success: true,
        state_changes: vec![nonce_change],
        error: None,
    })
}

/// MVP transaction payload opcodes.
///
/// Encoded as: `opcode(1 byte) || args`
///
/// This is a simple format for the MVP. A production implementation
/// would use a richer instruction set or EVM bytecode.
const OP_TRANSFER: u8 = 0x01;
const OP_CREATE_ACCOUNT: u8 = 0x02;
const OP_SET_AUTH_PUBKEY: u8 = 0x03;
const OP_ADD_AUTH_KEY: u8 = 0x04;
const OP_REGISTER_ADDRESSES: u8 = 0x05;
/// HFI Pay: claim a funded intent with a Groth16 proof (native VM only).
/// On-chain execution requires `HfiPayHook` in the n-VM — see `ace_n_vm`.
pub const OP_HFI_PAY_CLAIM: u8 = 0x06;
/// HFI Pay: create a new intent in `Created` state. Authorized by the owner.
pub const OP_HFI_PAY_CREATE: u8 = 0x07;
/// HFI Pay: mark a `Created` intent as `Funded` after on-chain deposit.
pub const OP_HFI_PAY_FUND: u8 = 0x08;
/// HFI Pay: permissionless transition `Funded` → `Expired` once past `expiry`.
pub const OP_HFI_PAY_EXPIRE: u8 = 0x09;
/// HFI Pay: transition `Expired` → `Refunded`, signed by `refund_authorizer`.
pub const OP_HFI_PAY_REFUND: u8 = 0x0A;
/// HFI Pay: register (or refresh) a recipient binding so subsequent intents
/// addressed to the same `identity_commitment` auto-route via `direct_deposit`.
/// Idempotent — the latest registration overwrites the previous record. Variable
/// length: see `decode_hfi_pay_register_recipient`.
pub const OP_HFI_PAY_REGISTER_RECIPIENT: u8 = 0x0B;
/// Approve a new validator for admission after the containing block commits.
/// Payload: 0x0C || nonce(8 LE) || candidate_id_com(32) || signing_pubkey(32 or 1312)
/// Only effective when the sender is the designated founder account.
pub const OP_APPROVE_VALIDATOR: u8 = 0x0C;

/// Address type tags for RegisterAddresses bindings.
pub const ADDR_TYPE_EVM: u8 = 0x01;
pub const ADDR_TYPE_TRON: u8 = 0x02;
pub const ADDR_TYPE_SOLANA: u8 = 0x03;
pub const ADDR_TYPE_BTC: u8 = 0x04;
pub const ADDR_TYPE_XID: u8 = 0x10;
pub const ADDR_TYPE_XADDRESS: u8 = 0x11;

/// A single address binding with ownership proof.
#[derive(Debug, Clone)]
pub struct AddressBinding {
    pub address_type: u8,
    pub address: Vec<u8>,
    pub proof_pubkey: Option<Vec<u8>>,
    pub proof_sig: TaggedSignature,
}

/// Decoded transaction operation.
#[derive(Debug, Clone)]
pub enum TransactionOp {
    /// Transfer `amount` from the sender (attestation.idcom) to `to`.
    Transfer {
        nonce: u64,
        to: AccountId,
        amount: u64,
    },
    /// Create a new account with the given identity commitment.
    CreateAccount {
        id_com: AccountId,
        auth_pubkey: TaggedPubkey,
    },
    /// Update the sender's auth_pubkey (e.g., after HFI Pay bind with Yallet).
    /// Payload: 0x03 || nonce(8 bytes LE) || new_auth_pubkey_bytes
    /// Legacy payloads without a nonce decode with implicit nonce 0 so
    /// unprovisioned accounts can bootstrap their first auth key once.
    SetAuthPubkey {
        nonce: u64,
        auth_pubkey: TaggedPubkey,
    },
    /// Add an additional auth key of a different algorithm.
    /// Payload: 0x04 || nonce(8 bytes LE) || tagged_pubkey_wire_bytes
    /// Legacy payloads without a nonce decode with implicit nonce 0 so
    /// unprovisioned accounts can bootstrap their first auth key once.
    AddAuthKey {
        nonce: u64,
        auth_pubkey: TaggedPubkey,
    },
    /// Register one or more address bindings with ownership proofs.
    /// Payload: 0x05 || nonce(8 LE) || count(1) || [binding]*
    RegisterAddresses {
        nonce: u64,
        bindings: Vec<AddressBinding>,
    },
    /// HFI Pay AR-ACE claim. Variable-length. Not applied by
    /// `ace_engine::execute_transaction` — n-VM routes this to the HFI hook.
    /// The relay verifies the ZK proof off-path; the chain verifies binding deterministically.
    HfiPayClaim {
        intent_id: [u8; 32],
        /// Raw destination bytes (same as hex-decoded `destination` in RPC).
        destination: Vec<u8>,
        /// Optional `TaggedPubkey` for Native/SVM/BVM claim destinations.
        destination_auth: Option<TaggedPubkey>,
        /// auth_commitment = H(lazy_rev, binding_epoch) — 32 bytes.
        auth_commitment: [u8; 32],
    },
    /// HFI Pay: create a new intent in `Created` state.
    /// Sender (attestation.idcom) is the intent owner.
    HfiPayCreate {
        nonce: u64,
        intent_id: [u8; 32],
        blinded_binding: [u8; 32],
        amount: u64,
        chain_id: u8,
        /// 32-byte mint (all zeros = native balance).
        mint: [u8; 32],
        /// Deposit AccountId (deterministic from intent_id by convention).
        deposit_address: [u8; 32],
        binding_epoch: u64,
        expiry_slot: u64,
        /// Optional AccountId (all zeros = none).
        refund_dest: [u8; 32],
        /// Optional AccountId (all zeros = none).
        refund_authorizer: [u8; 32],
        /// Recipient's `identity_commitment` (`IDcom_B`). Used by the chain
        /// to consult the on-chain recipient registry: if a registered
        /// recipient owns this `IDcom_B`, the intent is delivered via
        /// `direct_deposit` (auto-claim) instead of the create / fund / claim
        /// dance. All-zeros means "no idcom hint" — equivalent to never being
        /// registered, so the intent always takes the regular path.
        identity_commitment: [u8; 32],
    },
    /// HFI Pay: mark a `Created` intent as `Funded` after the deposit lands.
    HfiPayFund {
        nonce: u64,
        intent_id: [u8; 32],
        /// Tx hash (or equivalent evidence) of the deposit.
        deposit_evidence: [u8; 32],
        deposit_amount: u64,
    },
    /// HFI Pay: permissionless `Funded` → `Expired` once past expiry.
    HfiPayExpire { intent_id: [u8; 32] },
    /// HFI Pay: `Expired` → `Refunded`, signed by refund_authorizer.
    HfiPayRefund {
        nonce: u64,
        intent_id: [u8; 32],
        /// Pre-signed refund authorization from the refund_authorizer (ML-DSA-44).
        /// When present, `handle_refund` verifies this instead of checking
        /// `tx.sender == refund_authorizer`, enabling relay-submitted auto-refunds.
        /// Format: (pubkey_bytes 1312B, signature_bytes 2420B).
        refund_auth: Option<(Vec<u8>, Vec<u8>)>,
    },
    /// Approve a new validator for admission after the containing block commits.
    /// Must be signed by the founder account. Executed by all nodes identically.
    ApproveValidator {
        nonce: u64,
        /// Identity commitment of the candidate validator.
        candidate_id_com: AccountId,
        /// Signing public key bytes (Ed25519 = 32 bytes, ML-DSA-44 = 1312 bytes).
        signing_pubkey: Vec<u8>,
    },
    /// HFI Pay: register a recipient binding so subsequent intents whose
    /// `identity_commitment` matches `identity_commitment` are routed directly
    /// to the recipient's account (auto-claim). Recipient signs a deterministic
    /// message over `(xid || identifier || identity_commitment ||
    /// claim_binding_handle || binding_epoch)` with `pubkey`. Sender of this
    /// transaction may be a relay (the recipient's signature, not the tx
    /// sender, authorizes the registration).
    HfiPayRegisterRecipient {
        nonce: u64,
        /// 32-byte ACE-GF wallet fingerprint of the recipient. Drives the
        /// derived `account_id` that auto-routed deposits will be credited to.
        xid: [u8; 32],
        /// Normalized identifier bytes (e.g. lowercased email or `@handle`).
        /// Hashed into `id_hash` by the chain handler — never stored verbatim
        /// in consensus state.
        identifier: Vec<u8>,
        /// Public commitment derived from the recipient's secret `rev`.
        /// Used as the secondary index for auto-routing.
        identity_commitment: [u8; 32],
        /// Public commitment derived from `(rev, binding_epoch)`.
        claim_binding_handle: [u8; 32],
        binding_epoch: u64,
        /// Tag of the chain that should accept this registration
        /// (`ChainId::Native = 0` for ACE-native). Domain-separates against
        /// cross-chain replay between EVM/SVM/BVM bridges.
        chain_tag: u8,
        /// Latest block slot at which the chain will accept this registration.
        /// Bounds bearer-credential lifetime — a leaked signed registration
        /// becomes inert once the chain advances past `valid_until_slot`.
        valid_until_slot: u64,
        /// Recipient's tagged pubkey (ed25519 / ML-DSA-44) — wire format.
        pubkey: Vec<u8>,
        /// Tagged signature over the registration message — wire format.
        signature: Vec<u8>,
    },
}

impl TransactionOp {
    /// Decode a transaction payload into an operation.
    ///
    /// Format:
    /// - Transfer: `0x01 || nonce(8 bytes LE) || to(32 bytes) || amount(8 bytes LE)` = 49 bytes
    /// - CreateAccount: `0x02 || id_com(32 bytes) || auth_pubkey(32 bytes)` = 65 bytes
    pub fn decode(payload: &[u8]) -> Result<Self, EngineError> {
        if payload.is_empty() {
            return Err(EngineError::InvalidPayload("empty payload".into()));
        }

        match payload[0] {
            OP_TRANSFER => {
                if payload.len() != 49 {
                    return Err(EngineError::InvalidPayload(
                        "transfer payload must be exactly 49 bytes".into(),
                    ));
                }
                let nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
                let mut to = [0u8; 32];
                to.copy_from_slice(&payload[9..41]);
                let amount = u64::from_le_bytes([
                    payload[41],
                    payload[42],
                    payload[43],
                    payload[44],
                    payload[45],
                    payload[46],
                    payload[47],
                    payload[48],
                ]);
                Ok(TransactionOp::Transfer {
                    nonce,
                    to: AccountId::from_bytes(to),
                    amount,
                })
            }
            OP_CREATE_ACCOUNT => {
                if payload.len() < 33 {
                    return Err(EngineError::InvalidPayload(
                        "create_account payload too short".into(),
                    ));
                }
                let mut id_com = [0u8; 32];
                id_com.copy_from_slice(&payload[1..33]);
                // Two wire formats:
                //   Legacy (65 bytes): id_com(32) || ed25519_key(32)  — no alg tag
                //   Extended (≥36 bytes): id_com(32) || alg_tag(1) || pk_len(2 LE) || pk_bytes(N)
                let auth_pubkey = if payload.len() == 65 {
                    let mut auth_bytes = [0u8; 32];
                    auth_bytes.copy_from_slice(&payload[33..65]);
                    if auth_bytes == [0u8; 32] {
                        return Err(EngineError::InvalidPayload(
                            "create_account auth_pubkey must be non-zero".into(),
                        ));
                    }
                    TaggedPubkey::ed25519(auth_bytes)
                } else {
                    if payload.len() < 36 {
                        return Err(EngineError::InvalidPayload(
                            "create_account extended payload too short for alg+len".into(),
                        ));
                    }
                    let alg_tag = payload[33];
                    let pk_len = u16::from_le_bytes([payload[34], payload[35]]) as usize;
                    if payload.len() != 36 + pk_len {
                        return Err(EngineError::InvalidPayload(
                            "create_account extended payload length mismatch".into(),
                        ));
                    }
                    let pk_bytes = payload[36..36 + pk_len].to_vec();
                    let algorithm = SignatureAlgorithm::from_tag(alg_tag).ok_or_else(|| {
                        EngineError::InvalidPayload(format!(
                            "create_account unknown alg_tag 0x{alg_tag:02x}"
                        ))
                    })?;
                    TaggedPubkey {
                        algorithm,
                        bytes: pk_bytes,
                    }
                };
                if auth_pubkey.is_zero() {
                    return Err(EngineError::InvalidPayload(
                        "create_account auth_pubkey must be non-zero".into(),
                    ));
                }
                Ok(TransactionOp::CreateAccount {
                    id_com: AccountId::from_bytes(id_com),
                    auth_pubkey,
                })
            }
            OP_SET_AUTH_PUBKEY => {
                // Accepted payload shapes (opcode byte not counted in key sizes):
                //   33 bytes  = opcode(1) + ed25519_key(32)            [legacy, no nonce]
                //   41 bytes  = opcode(1) + nonce(8) + ed25519_key(32) [nonce-bearing]
                //   1313 bytes = opcode(1) + ml_dsa_44_raw(1312)       [legacy, no nonce]
                //   1321 bytes = opcode(1) + nonce(8) + ml_dsa_44_raw(1312) [nonce-bearing]
                //   ≥12 bytes (other) = opcode(1) + nonce(8) + tagged_wire [nonce-bearing]
                //
                // Exact length dispatch eliminates the speculative-parse ambiguity
                // where payload[1..9] would be misinterpreted as a nonce when the
                // payload is actually a legacy no-nonce format.
                match payload.len() {
                    33 => {
                        // Legacy Ed25519, no nonce.
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&payload[1..33]);
                        Ok(TransactionOp::SetAuthPubkey {
                            nonce: 0,
                            auth_pubkey: TaggedPubkey::ed25519(pk),
                        })
                    }
                    41 => {
                        // Nonce-bearing Ed25519.
                        let nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&payload[9..41]);
                        Ok(TransactionOp::SetAuthPubkey {
                            nonce,
                            auth_pubkey: TaggedPubkey::ed25519(pk),
                        })
                    }
                    1313 => {
                        // Legacy ML-DSA-44 raw, no nonce.
                        Ok(TransactionOp::SetAuthPubkey {
                            nonce: 0,
                            auth_pubkey: TaggedPubkey::ml_dsa_44(payload[1..].to_vec()),
                        })
                    }
                    1321 => {
                        // Nonce-bearing ML-DSA-44 raw.
                        let nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
                        Ok(TransactionOp::SetAuthPubkey {
                            nonce,
                            auth_pubkey: TaggedPubkey::ml_dsa_44(payload[9..].to_vec()),
                        })
                    }
                    n if n >= 12 => {
                        // Nonce-bearing tagged wire format: nonce(8) + alg_tag(1) + len(2) + key.
                        let nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
                        let key_bytes = &payload[9..];
                        let (auth_pubkey, consumed) = TaggedPubkey::from_wire_bytes(key_bytes)
                            .map_err(|e| {
                                EngineError::InvalidPayload(format!("SetAuthPubkey: {e}"))
                            })?;
                        if consumed != key_bytes.len() {
                            return Err(EngineError::InvalidPayload(
                                "SetAuthPubkey: trailing bytes after pubkey".into(),
                            ));
                        }
                        Ok(TransactionOp::SetAuthPubkey { nonce, auth_pubkey })
                    }
                    _ => Err(EngineError::InvalidPayload(
                        "SetAuthPubkey: invalid payload length".into(),
                    )),
                }
            }
            OP_ADD_AUTH_KEY => {
                // AddAuthKey payload shapes (tagged wire = alg_tag(1) + len(2) + key(N)):
                //   Legacy (no nonce): opcode(1) + tagged_wire(≥3)
                //   Nonce-bearing:     opcode(1) + nonce(8) + tagged_wire(≥3)
                //
                // Disambiguate by checking if the bytes starting at offset 9 parse as
                // a complete tagged wire pubkey with no trailing bytes. If so, treat it
                // as nonce-bearing. Otherwise treat the entire payload[1..] as legacy.
                // This avoids the speculative fallback that could misparse a legacy
                // payload whose first 8 bytes happen to decode as a plausible nonce.
                //
                // Minimum nonce-bearing size: 1 + 8 + 3 = 12 bytes.
                let parse_tagged = |key_bytes: &[u8]| -> Result<TaggedPubkey, EngineError> {
                    let (auth_pubkey, consumed) = TaggedPubkey::from_wire_bytes(key_bytes)
                        .map_err(|e| EngineError::InvalidPayload(format!("AddAuthKey: {e}")))?;
                    if consumed != key_bytes.len() {
                        return Err(EngineError::InvalidPayload(
                            "AddAuthKey: trailing bytes after pubkey".into(),
                        ));
                    }
                    Ok(auth_pubkey)
                };

                if payload.len() >= 12 {
                    // Check whether bytes[9..] is a self-contained tagged wire pubkey.
                    // If yes, this is the nonce-bearing format. If no, fall through to legacy.
                    if let Ok((pk, consumed)) = TaggedPubkey::from_wire_bytes(&payload[9..]) {
                        if consumed == payload.len() - 9 {
                            let nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
                            return Ok(TransactionOp::AddAuthKey {
                                nonce,
                                auth_pubkey: pk,
                            });
                        }
                    }
                }

                // Legacy (no nonce): entire payload[1..] is the tagged wire pubkey.
                let auth_pubkey = parse_tagged(&payload[1..])?;
                Ok(TransactionOp::AddAuthKey {
                    nonce: 0,
                    auth_pubkey,
                })
            }
            OP_REGISTER_ADDRESSES => {
                if payload.len() < 10 {
                    return Err(EngineError::InvalidPayload(
                        "RegisterAddresses payload too short".into(),
                    ));
                }
                let nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
                let count = payload[9] as usize;
                if count == 0 || count > 6 {
                    return Err(EngineError::InvalidPayload(
                        "RegisterAddresses binding count must be 1..=6".into(),
                    ));
                }
                let mut offset = 10;
                let mut bindings = Vec::with_capacity(count);
                for _ in 0..count {
                    let binding = Self::decode_binding(payload, &mut offset)?;
                    bindings.push(binding);
                }
                Ok(TransactionOp::RegisterAddresses { nonce, bindings })
            }
            OP_HFI_PAY_CLAIM => Self::decode_hfi_pay_claim(payload),
            OP_HFI_PAY_CREATE => Self::decode_hfi_pay_create(payload),
            OP_HFI_PAY_FUND => Self::decode_hfi_pay_fund(payload),
            OP_HFI_PAY_EXPIRE => Self::decode_hfi_pay_expire(payload),
            OP_HFI_PAY_REFUND => Self::decode_hfi_pay_refund(payload),
            OP_HFI_PAY_REGISTER_RECIPIENT => Self::decode_hfi_pay_register_recipient(payload),
            OP_APPROVE_VALIDATOR => Self::decode_approve_validator(payload),
            other => Err(EngineError::InvalidPayload(format!(
                "unknown opcode: 0x{other:02x}"
            ))),
        }
    }

    /// `0x07 || nonce(8) || intent_id(32) || blinded_binding(32) || amount(8)
    ///   || chain_id(1) || mint(32) || deposit_address(32) || binding_epoch(8)
    ///   || expiry_slot(8) || refund_dest(32) || refund_authorizer(32)
    ///   || identity_commitment(32)` = 258 bytes
    fn decode_hfi_pay_create(payload: &[u8]) -> Result<TransactionOp, EngineError> {
        const LEN: usize = 1 + 8 + 32 + 32 + 8 + 1 + 32 + 32 + 8 + 8 + 32 + 32 + 32;
        if payload.len() != LEN {
            return Err(EngineError::InvalidPayload(format!(
                "HfiPayCreate payload must be {LEN} bytes"
            )));
        }
        let mut p = 1;
        let nonce = u64::from_le_bytes(payload[p..p + 8].try_into().unwrap());
        p += 8;
        let mut intent_id = [0u8; 32];
        intent_id.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let mut blinded_binding = [0u8; 32];
        blinded_binding.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let amount = u64::from_le_bytes(payload[p..p + 8].try_into().unwrap());
        p += 8;
        let chain_id = payload[p];
        p += 1;
        let mut mint = [0u8; 32];
        mint.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let mut deposit_address = [0u8; 32];
        deposit_address.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let binding_epoch = u64::from_le_bytes(payload[p..p + 8].try_into().unwrap());
        p += 8;
        let expiry_slot = u64::from_le_bytes(payload[p..p + 8].try_into().unwrap());
        p += 8;
        let mut refund_dest = [0u8; 32];
        refund_dest.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let mut refund_authorizer = [0u8; 32];
        refund_authorizer.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let mut identity_commitment = [0u8; 32];
        identity_commitment.copy_from_slice(&payload[p..p + 32]);
        Ok(TransactionOp::HfiPayCreate {
            nonce,
            intent_id,
            blinded_binding,
            amount,
            chain_id,
            mint,
            deposit_address,
            binding_epoch,
            expiry_slot,
            refund_dest,
            refund_authorizer,
            identity_commitment,
        })
    }

    /// `0x08 || nonce(8) || intent_id(32) || deposit_evidence(32) || deposit_amount(8)` = 81 bytes
    fn decode_hfi_pay_fund(payload: &[u8]) -> Result<TransactionOp, EngineError> {
        const LEN: usize = 1 + 8 + 32 + 32 + 8;
        if payload.len() != LEN {
            return Err(EngineError::InvalidPayload(format!(
                "HfiPayFund payload must be {LEN} bytes"
            )));
        }
        let nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
        let mut intent_id = [0u8; 32];
        intent_id.copy_from_slice(&payload[9..41]);
        let mut deposit_evidence = [0u8; 32];
        deposit_evidence.copy_from_slice(&payload[41..73]);
        let deposit_amount = u64::from_le_bytes(payload[73..81].try_into().unwrap());
        Ok(TransactionOp::HfiPayFund {
            nonce,
            intent_id,
            deposit_evidence,
            deposit_amount,
        })
    }

    /// `0x09 || intent_id(32)` = 33 bytes
    fn decode_hfi_pay_expire(payload: &[u8]) -> Result<TransactionOp, EngineError> {
        if payload.len() != 33 {
            return Err(EngineError::InvalidPayload(
                "HfiPayExpire payload must be 33 bytes".into(),
            ));
        }
        let mut intent_id = [0u8; 32];
        intent_id.copy_from_slice(&payload[1..33]);
        Ok(TransactionOp::HfiPayExpire { intent_id })
    }

    /// `0x0A || nonce(8) || intent_id(32)` = 41 bytes
    fn decode_hfi_pay_refund(payload: &[u8]) -> Result<TransactionOp, EngineError> {
        // Minimum: 0x0A(1) + nonce(8) + intent_id(32) = 41 bytes.
        // Extended: + auth_present(1) + pubkey_len(2 LE) + pubkey + sig_len(2 LE) + sig.
        if payload.len() < 41 {
            return Err(EngineError::InvalidPayload(
                "HfiPayRefund payload must be at least 41 bytes".into(),
            ));
        }
        let nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
        let mut intent_id = [0u8; 32];
        intent_id.copy_from_slice(&payload[9..41]);

        // Legacy format is exactly 41 bytes — no refund_auth.
        if payload.len() == 41 {
            return Ok(TransactionOp::HfiPayRefund {
                nonce,
                intent_id,
                refund_auth: None,
            });
        }

        // Extended format: auth_present must be exactly 1 (not any non-zero).
        let auth_present = payload[41];
        if auth_present != 1 {
            return Err(EngineError::InvalidPayload(
                "HfiPayRefund extended: auth_present must be 0x01".into(),
            ));
        }
        // pubkey_len(2 LE) + pubkey + sig_len(2 LE) + sig
        if payload.len() < 44 {
            return Err(EngineError::InvalidPayload(
                "HfiPayRefund extended: truncated".into(),
            ));
        }
        let pk_len = u16::from_le_bytes([payload[42], payload[43]]) as usize;
        if payload.len() < 44 + pk_len + 2 {
            return Err(EngineError::InvalidPayload(
                "HfiPayRefund extended: pubkey truncated".into(),
            ));
        }
        let pk = payload[44..44 + pk_len].to_vec();
        let sig_offset = 44 + pk_len;
        let sig_len = u16::from_le_bytes([payload[sig_offset], payload[sig_offset + 1]]) as usize;
        let expected_total = sig_offset + 2 + sig_len;
        if payload.len() < expected_total {
            return Err(EngineError::InvalidPayload(
                "HfiPayRefund extended: sig truncated".into(),
            ));
        }
        // Reject trailing bytes — payload must be exactly consumed.
        if payload.len() != expected_total {
            return Err(EngineError::InvalidPayload(
                "HfiPayRefund extended: trailing bytes after sig".into(),
            ));
        }
        let sig = payload[sig_offset + 2..expected_total].to_vec();
        Ok(TransactionOp::HfiPayRefund {
            nonce,
            intent_id,
            refund_auth: Some((pk, sig)),
        })
    }

    /// Decode `OP_APPROVE_VALIDATOR` payload.
    /// Format: `0x0C || nonce(8 LE) || candidate_id_com(32) || signing_pubkey(32 or 1312)`
    fn decode_approve_validator(payload: &[u8]) -> Result<TransactionOp, EngineError> {
        // minimum: 1 + 8 + 32 + 32 = 73 bytes (Ed25519 pubkey)
        if payload.len() < 73 {
            return Err(EngineError::InvalidPayload(format!(
                "ApproveValidator payload too short: {} bytes",
                payload.len()
            )));
        }
        let nonce = u64::from_le_bytes(payload[1..9].try_into().unwrap());
        let mut id = [0u8; 32];
        id.copy_from_slice(&payload[9..41]);
        let signing_pubkey = payload[41..].to_vec();
        let pk_len = signing_pubkey.len();
        if pk_len != 32 && pk_len != 1312 {
            return Err(EngineError::InvalidPayload(format!(
                "ApproveValidator: signing_pubkey must be 32 or 1312 bytes, got {pk_len}"
            )));
        }
        Ok(TransactionOp::ApproveValidator {
            nonce,
            candidate_id_com: AccountId(id),
            signing_pubkey,
        })
    }

    /// Decode `OP_HFI_PAY_REGISTER_RECIPIENT` payload.
    /// Format: `0x0B || nonce(8) || xid(32) || identifier_len(2) || identifier
    ///    || identity_commitment(32) || claim_binding_handle(32) || binding_epoch(8)
    ///    || chain_tag(1) || valid_until_slot(8)
    ///    || pubkey_len(2) || pubkey || sig_len(2) || sig`
    fn decode_hfi_pay_register_recipient(payload: &[u8]) -> Result<TransactionOp, EngineError> {
        // Minimum: 1 + 8 + 32 + 2 + 0 + 32 + 32 + 8 + 1 + 8 + 2 + 0 + 2 + 0 = 128 bytes (empty identifier/pk/sig).
        const MIN_LEN: usize = 1 + 8 + 32 + 2 + 32 + 32 + 8 + 1 + 8 + 2 + 2;
        if payload.len() < MIN_LEN {
            return Err(EngineError::InvalidPayload(format!(
                "HfiPayRegisterRecipient payload must be at least {MIN_LEN} bytes"
            )));
        }
        let mut p = 1;
        let nonce = u64::from_le_bytes(payload[p..p + 8].try_into().unwrap());
        p += 8;
        let mut xid = [0u8; 32];
        xid.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let id_len = u16::from_le_bytes([payload[p], payload[p + 1]]) as usize;
        p += 2;
        // Bound at decode for DoS protection — the chain handler enforces
        // the same cap on commit, but we reject early to save deserialization
        // work on obviously-malicious payloads.
        const MAX_ID_LEN: usize = 256;
        if id_len > MAX_ID_LEN {
            return Err(EngineError::InvalidPayload(format!(
                "HfiPayRegisterRecipient: identifier length {id_len} exceeds max {MAX_ID_LEN}"
            )));
        }
        if payload.len() < p + id_len + 32 + 32 + 8 + 1 + 8 + 2 + 2 {
            return Err(EngineError::InvalidPayload(
                "HfiPayRegisterRecipient: identifier truncated".into(),
            ));
        }
        let identifier = payload[p..p + id_len].to_vec();
        p += id_len;
        let mut identity_commitment = [0u8; 32];
        identity_commitment.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let mut claim_binding_handle = [0u8; 32];
        claim_binding_handle.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let binding_epoch = u64::from_le_bytes(payload[p..p + 8].try_into().unwrap());
        p += 8;
        let chain_tag = payload[p];
        p += 1;
        let valid_until_slot = u64::from_le_bytes(payload[p..p + 8].try_into().unwrap());
        p += 8;
        let pk_len = u16::from_le_bytes([payload[p], payload[p + 1]]) as usize;
        p += 2;
        if payload.len() < p + pk_len + 2 {
            return Err(EngineError::InvalidPayload(
                "HfiPayRegisterRecipient: pubkey truncated".into(),
            ));
        }
        let pubkey = payload[p..p + pk_len].to_vec();
        p += pk_len;
        let sig_len = u16::from_le_bytes([payload[p], payload[p + 1]]) as usize;
        p += 2;
        let expected = p + sig_len;
        if payload.len() != expected {
            return Err(EngineError::InvalidPayload(
                "HfiPayRegisterRecipient: trailing or truncated signature".into(),
            ));
        }
        let signature = payload[p..expected].to_vec();
        Ok(TransactionOp::HfiPayRegisterRecipient {
            nonce,
            xid,
            identifier,
            identity_commitment,
            claim_binding_handle,
            binding_epoch,
            chain_tag,
            valid_until_slot,
            pubkey,
            signature,
        })
    }

    /// AR-ACE short format: `0x06 || intent_id(32) || dest_len(1) || dest || has_auth(1) || [u16+pk]? || auth_commitment(32)`
    fn decode_hfi_pay_claim(payload: &[u8]) -> Result<TransactionOp, EngineError> {
        if payload.len() < 1 + 32 + 1 + 1 + 32 {
            return Err(EngineError::InvalidPayload(
                "HFI claim payload too short".into(),
            ));
        }
        let mut p = 1;
        let mut intent_id = [0u8; 32];
        intent_id.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let dest_len = payload[p] as usize;
        p += 1;
        if dest_len > 32 || p + dest_len + 1 + 32 > payload.len() {
            return Err(EngineError::InvalidPayload(
                "HFI claim: invalid dest_len or truncated payload".into(),
            ));
        }
        let destination = payload[p..p + dest_len].to_vec();
        p += dest_len;
        let has_auth = payload[p];
        p += 1;
        let destination_auth = if has_auth == 0 {
            None
        } else if has_auth != 1 {
            return Err(EngineError::InvalidPayload(
                "HFI claim: has_auth must be 0 or 1".into(),
            ));
        } else {
            if p + 2 > payload.len() {
                return Err(EngineError::InvalidPayload(
                    "HFI claim: truncated dest auth length".into(),
                ));
            }
            let auth_len = u16::from_le_bytes([payload[p], payload[p + 1]]) as usize;
            p += 2;
            if p + auth_len + 32 > payload.len() {
                return Err(EngineError::InvalidPayload(
                    "HFI claim: truncated dest auth pubkey".into(),
                ));
            }
            let (pk, consumed) = TaggedPubkey::from_wire_bytes(&payload[p..p + auth_len])
                .map_err(|e| EngineError::InvalidPayload(format!("HFI claim dest auth: {e}")))?;
            if consumed != auth_len {
                return Err(EngineError::InvalidPayload(
                    "HFI claim: dest auth wire format mismatch".into(),
                ));
            }
            p += auth_len;
            Some(pk)
        };
        if p + 32 != payload.len() {
            return Err(EngineError::InvalidPayload(format!(
                "HFI claim: expected 32-byte auth_commitment at end, remaining {}",
                payload.len() - p
            )));
        }
        let mut auth_commitment = [0u8; 32];
        auth_commitment.copy_from_slice(&payload[p..p + 32]);
        Ok(TransactionOp::HfiPayClaim {
            intent_id,
            destination,
            destination_auth,
            auth_commitment,
        })
    }

    /// Decode a single address binding from the payload at the given offset.
    fn decode_binding(payload: &[u8], offset: &mut usize) -> Result<AddressBinding, EngineError> {
        if payload.len().saturating_sub(*offset) < 4 {
            return Err(EngineError::InvalidPayload(
                "binding: truncated header".into(),
            ));
        }
        let address_type = payload[*offset];
        let address_len =
            u16::from_le_bytes(payload[*offset + 1..*offset + 3].try_into().unwrap()) as usize;
        *offset += 3;
        if payload.len().saturating_sub(*offset) < address_len {
            return Err(EngineError::InvalidPayload(
                "binding: truncated address".into(),
            ));
        }
        let address = payload[*offset..*offset + address_len].to_vec();
        *offset += address_len;

        if *offset >= payload.len() {
            return Err(EngineError::InvalidPayload(
                "binding: missing has_pubkey flag".into(),
            ));
        }
        let has_pubkey = payload[*offset] != 0;
        *offset += 1;

        let proof_pubkey = if has_pubkey {
            let (pk, consumed) = TaggedPubkey::from_wire_bytes(&payload[*offset..])
                .map_err(|e| EngineError::InvalidPayload(format!("binding proof_pubkey: {e}")))?;
            *offset += consumed;
            Some(pk.bytes)
        } else {
            None
        };

        let (proof_sig, consumed) = TaggedSignature::from_wire_bytes(&payload[*offset..])
            .map_err(|e| EngineError::InvalidPayload(format!("binding proof_sig: {e}")))?;
        *offset += consumed;

        Ok(AddressBinding {
            address_type,
            address,
            proof_pubkey,
            proof_sig,
        })
    }

    /// Encode a TransactionOp into payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            TransactionOp::Transfer { nonce, to, amount } => {
                let mut buf = Vec::with_capacity(49);
                buf.push(OP_TRANSFER);
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(to.as_bytes());
                buf.extend_from_slice(&amount.to_le_bytes());
                buf
            }
            TransactionOp::CreateAccount {
                id_com,
                auth_pubkey,
            } => {
                if auth_pubkey.algorithm == SignatureAlgorithm::Ed25519
                    && auth_pubkey.bytes.len() == 32
                {
                    // Legacy 65-byte format for Ed25519 — backward compatible.
                    let mut buf = Vec::with_capacity(65);
                    buf.push(OP_CREATE_ACCOUNT);
                    buf.extend_from_slice(id_com.as_bytes());
                    buf.extend_from_slice(&auth_pubkey.bytes);
                    buf
                } else {
                    // Extended format for PQC and other algorithms:
                    // id_com(32) || alg_tag(1) || pk_len(2 LE) || pk_bytes(N)
                    let pk_len = auth_pubkey.bytes.len() as u16;
                    let mut buf = Vec::with_capacity(36 + auth_pubkey.bytes.len());
                    buf.push(OP_CREATE_ACCOUNT);
                    buf.extend_from_slice(id_com.as_bytes());
                    buf.push(auth_pubkey.algorithm as u8);
                    buf.extend_from_slice(&pk_len.to_le_bytes());
                    buf.extend_from_slice(&auth_pubkey.bytes);
                    buf
                }
            }
            TransactionOp::SetAuthPubkey { nonce, auth_pubkey } => {
                let mut buf = Vec::with_capacity(9 + auth_pubkey.bytes.len());
                buf.push(OP_SET_AUTH_PUBKEY);
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(&auth_pubkey.bytes);
                buf
            }
            TransactionOp::AddAuthKey { nonce, auth_pubkey } => {
                let wire = auth_pubkey.to_wire_bytes();
                let mut buf = Vec::with_capacity(9 + wire.len());
                buf.push(OP_ADD_AUTH_KEY);
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(&wire);
                buf
            }
            TransactionOp::RegisterAddresses { nonce, bindings } => {
                let mut buf = Vec::with_capacity(256);
                buf.push(OP_REGISTER_ADDRESSES);
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.push(bindings.len() as u8);
                for b in bindings {
                    buf.push(b.address_type);
                    buf.extend_from_slice(&(b.address.len() as u16).to_le_bytes());
                    buf.extend_from_slice(&b.address);
                    if let Some(ref pk_bytes) = b.proof_pubkey {
                        buf.push(1);
                        // Re-derive the algorithm from address_type for wire encoding.
                        let alg = match b.address_type {
                            ADDR_TYPE_EVM | ADDR_TYPE_TRON | ADDR_TYPE_BTC => {
                                SignatureAlgorithm::Secp256k1
                            }
                            ADDR_TYPE_SOLANA => SignatureAlgorithm::Ed25519,
                            ADDR_TYPE_XADDRESS => SignatureAlgorithm::MlDsa44,
                            _ => SignatureAlgorithm::Ed25519,
                        };
                        let pk = TaggedPubkey {
                            algorithm: alg,
                            bytes: pk_bytes.clone(),
                        };
                        buf.extend_from_slice(&pk.to_wire_bytes());
                    } else {
                        buf.push(0);
                    }
                    buf.extend_from_slice(&b.proof_sig.to_wire_bytes());
                }
                buf
            }
            TransactionOp::HfiPayClaim {
                intent_id,
                destination,
                destination_auth,
                auth_commitment,
            } => {
                let mut buf = vec![];
                buf.push(OP_HFI_PAY_CLAIM);
                buf.extend_from_slice(intent_id);
                let dest_len = destination.len();
                if dest_len > 32 {
                    panic!("HfiPayClaim encode: destination > 32 bytes");
                }
                buf.push(dest_len as u8);
                buf.extend_from_slice(destination);
                match destination_auth {
                    None => {
                        buf.push(0);
                    }
                    Some(pk) => {
                        buf.push(1);
                        let wire = pk.to_wire_bytes();
                        let ln =
                            u16::try_from(wire.len()).expect("HfiPayClaim: dest auth wire length");
                        buf.extend_from_slice(&ln.to_le_bytes());
                        buf.extend_from_slice(&wire);
                    }
                }
                buf.extend_from_slice(auth_commitment);
                buf
            }
            TransactionOp::HfiPayCreate {
                nonce,
                intent_id,
                blinded_binding,
                amount,
                chain_id,
                mint,
                deposit_address,
                binding_epoch,
                expiry_slot,
                refund_dest,
                refund_authorizer,
                identity_commitment,
            } => {
                let mut buf = Vec::with_capacity(258);
                buf.push(OP_HFI_PAY_CREATE);
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(intent_id);
                buf.extend_from_slice(blinded_binding);
                buf.extend_from_slice(&amount.to_le_bytes());
                buf.push(*chain_id);
                buf.extend_from_slice(mint);
                buf.extend_from_slice(deposit_address);
                buf.extend_from_slice(&binding_epoch.to_le_bytes());
                buf.extend_from_slice(&expiry_slot.to_le_bytes());
                buf.extend_from_slice(refund_dest);
                buf.extend_from_slice(refund_authorizer);
                buf.extend_from_slice(identity_commitment);
                buf
            }
            TransactionOp::HfiPayFund {
                nonce,
                intent_id,
                deposit_evidence,
                deposit_amount,
            } => {
                let mut buf = Vec::with_capacity(81);
                buf.push(OP_HFI_PAY_FUND);
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(intent_id);
                buf.extend_from_slice(deposit_evidence);
                buf.extend_from_slice(&deposit_amount.to_le_bytes());
                buf
            }
            TransactionOp::HfiPayExpire { intent_id } => {
                let mut buf = Vec::with_capacity(33);
                buf.push(OP_HFI_PAY_EXPIRE);
                buf.extend_from_slice(intent_id);
                buf
            }
            TransactionOp::HfiPayRefund {
                nonce,
                intent_id,
                refund_auth,
            } => {
                match refund_auth {
                    None => {
                        let mut buf = Vec::with_capacity(41);
                        buf.push(OP_HFI_PAY_REFUND);
                        buf.extend_from_slice(&nonce.to_le_bytes());
                        buf.extend_from_slice(intent_id);
                        buf
                    }
                    Some((pk, sig)) => {
                        let mut buf = Vec::with_capacity(41 + 1 + 2 + pk.len() + 2 + sig.len());
                        buf.push(OP_HFI_PAY_REFUND);
                        buf.extend_from_slice(&nonce.to_le_bytes());
                        buf.extend_from_slice(intent_id);
                        buf.push(1u8); // auth_present
                        buf.extend_from_slice(&(pk.len() as u16).to_le_bytes());
                        buf.extend_from_slice(pk);
                        buf.extend_from_slice(&(sig.len() as u16).to_le_bytes());
                        buf.extend_from_slice(sig);
                        buf
                    }
                }
            }
            TransactionOp::HfiPayRegisterRecipient {
                nonce,
                xid,
                identifier,
                identity_commitment,
                claim_binding_handle,
                binding_epoch,
                chain_tag,
                valid_until_slot,
                pubkey,
                signature,
            } => {
                let mut buf = Vec::with_capacity(
                    1 + 8
                        + 32
                        + 2
                        + identifier.len()
                        + 32
                        + 32
                        + 8
                        + 1
                        + 8
                        + 2
                        + pubkey.len()
                        + 2
                        + signature.len(),
                );
                buf.push(OP_HFI_PAY_REGISTER_RECIPIENT);
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(xid);
                buf.extend_from_slice(&(identifier.len() as u16).to_le_bytes());
                buf.extend_from_slice(identifier);
                buf.extend_from_slice(identity_commitment);
                buf.extend_from_slice(claim_binding_handle);
                buf.extend_from_slice(&binding_epoch.to_le_bytes());
                buf.push(*chain_tag);
                buf.extend_from_slice(&valid_until_slot.to_le_bytes());
                buf.extend_from_slice(&(pubkey.len() as u16).to_le_bytes());
                buf.extend_from_slice(pubkey);
                buf.extend_from_slice(&(signature.len() as u16).to_le_bytes());
                buf.extend_from_slice(signature);
                buf
            }
            TransactionOp::ApproveValidator {
                nonce,
                candidate_id_com,
                signing_pubkey,
            } => {
                let mut buf = Vec::with_capacity(41 + signing_pubkey.len());
                buf.push(OP_APPROVE_VALIDATOR);
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(candidate_id_com.as_bytes());
                buf.extend_from_slice(signing_pubkey);
                buf
            }
        }
    }
}

/// Compute HASH160 (SHA-256 then RIPEMD-160) of data — standard Bitcoin digest.
fn btc_hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;
    use sha2::Digest as _;
    let sha = sha2::Sha256::digest(data);
    let r = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&r);
    out
}

/// Derive a standard Keccak-256 EVM address from a compressed secp256k1 public key.
fn evm_address_from_secp256k1(compressed_pubkey: &[u8]) -> Result<[u8; 20], EngineError> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha3::{Digest as _, Keccak256};

    let pk = k256::PublicKey::from_sec1_bytes(compressed_pubkey)
        .map_err(|_| EngineError::InvalidPayload("invalid secp256k1 pubkey".into()))?;
    let uncompressed = pk.to_encoded_point(false);
    // Skip the 0x04 prefix byte, hash the 64 raw bytes.
    let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Ok(addr)
}

/// Verify a single address binding proof and apply it to the account.
///
/// Returns the StateChange on success. The caller must call `state.insert()`
/// after all bindings are applied so indexes are updated atomically.
fn verify_and_apply_binding(
    state: &StateTree,
    account: &mut Account,
    sender_idcom: &[u8; 32],
    binding: &AddressBinding,
) -> Result<StateChange, EngineError> {
    let msg = register_address_message(sender_idcom, binding.address_type, &binding.address);

    match binding.address_type {
        ADDR_TYPE_EVM => {
            let pk_bytes = binding
                .proof_pubkey
                .as_ref()
                .ok_or(EngineError::InvalidBindingProof(ADDR_TYPE_EVM))?;
            // Verify signature with the secp256k1 key.
            let pk33: [u8; 33] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| EngineError::InvalidBindingProof(ADDR_TYPE_EVM))?;
            let tagged_pk = TaggedPubkey::secp256k1(pk33);
            if !verify_signature(&tagged_pk, &msg, &binding.proof_sig) {
                return Err(EngineError::InvalidBindingProof(ADDR_TYPE_EVM));
            }
            // Derive EVM address from pubkey and check it matches.
            let derived_addr = evm_address_from_secp256k1(pk_bytes)?;
            let declared: [u8; 20] =
                binding.address.as_slice().try_into().map_err(|_| {
                    EngineError::InvalidPayload("EVM address must be 20 bytes".into())
                })?;
            if derived_addr != declared {
                return Err(EngineError::InvalidBindingProof(ADDR_TYPE_EVM));
            }
            // Check for conflicts.
            if let Some(existing) = state.resolve_evm(&declared) {
                if *existing != account.id_com {
                    return Err(EngineError::AddressAlreadyBound(existing.0));
                }
            }
            account.evm_address = Some(declared);
        }
        ADDR_TYPE_TRON => {
            let pk_bytes = binding
                .proof_pubkey
                .as_ref()
                .ok_or(EngineError::InvalidBindingProof(ADDR_TYPE_TRON))?;
            let pk33: [u8; 33] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| EngineError::InvalidBindingProof(ADDR_TYPE_TRON))?;
            let tagged_pk = TaggedPubkey::secp256k1(pk33);
            if !verify_signature(&tagged_pk, &msg, &binding.proof_sig) {
                return Err(EngineError::InvalidBindingProof(ADDR_TYPE_TRON));
            }
            let derived_addr = evm_address_from_secp256k1(pk_bytes)?;
            let declared: [u8; 20] =
                binding.address.as_slice().try_into().map_err(|_| {
                    EngineError::InvalidPayload("TRON address must be 20 bytes".into())
                })?;
            if derived_addr != declared {
                return Err(EngineError::InvalidBindingProof(ADDR_TYPE_TRON));
            }
            if let Some(existing) = state.resolve_tron(&declared) {
                if *existing != account.id_com {
                    return Err(EngineError::AddressAlreadyBound(existing.0));
                }
            }
            account.tron_address = Some(declared);
        }
        ADDR_TYPE_SOLANA => {
            // Solana address IS the Ed25519 pubkey.
            let sol_pk: [u8; 32] = binding.address.as_slice().try_into().map_err(|_| {
                EngineError::InvalidPayload("Solana address must be 32 bytes".into())
            })?;
            let tagged_pk = TaggedPubkey::ed25519(sol_pk);
            if !verify_signature(&tagged_pk, &msg, &binding.proof_sig) {
                return Err(EngineError::InvalidBindingProof(ADDR_TYPE_SOLANA));
            }
            if let Some(existing) = state.resolve_solana(&sol_pk) {
                if *existing != account.id_com {
                    return Err(EngineError::AddressAlreadyBound(existing.0));
                }
            }
            account.solana_address = Some(sol_pk);
        }
        ADDR_TYPE_BTC => {
            let pk_bytes = binding
                .proof_pubkey
                .as_ref()
                .ok_or(EngineError::InvalidBindingProof(ADDR_TYPE_BTC))?;
            let pk33: [u8; 33] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| EngineError::InvalidBindingProof(ADDR_TYPE_BTC))?;
            let tagged_pk = TaggedPubkey::secp256k1(pk33);
            if !verify_signature(&tagged_pk, &msg, &binding.proof_sig) {
                return Err(EngineError::InvalidBindingProof(ADDR_TYPE_BTC));
            }
            // Verify that the provided pubkey actually corresponds to the declared
            // script address. We check the two most common script formats:
            //   P2PKH  (25 bytes): 76 a9 14 <hash160:20> 88 ac
            //   P2WPKH (22 bytes): 00 14 <hash160:20>
            // Other script types (P2SH, P2TR, P2WSH) involve indirect key
            // relationships that cannot be verified with just the compressed key,
            // so we reject them — callers using those formats must bind without a
            // proof_pubkey and rely on committee approval instead.
            let pk_hash = btc_hash160(pk_bytes);
            let addr = &binding.address;
            let valid_script = if addr.len() == 25
                && addr[0] == 0x76
                && addr[1] == 0xa9
                && addr[2] == 0x14
                && addr[23] == 0x88
                && addr[24] == 0xac
            {
                addr[3..23] == pk_hash
            } else if addr.len() == 22 && addr[0] == 0x00 && addr[1] == 0x14 {
                addr[2..22] == pk_hash
            } else {
                return Err(EngineError::InvalidPayload(
                    "BTC binding with proof_pubkey requires P2PKH or P2WPKH script".into(),
                ));
            };
            if !valid_script {
                return Err(EngineError::InvalidBindingProof(ADDR_TYPE_BTC));
            }
            if let Some(existing) = state.resolve_btc(&binding.address) {
                if *existing != account.id_com {
                    return Err(EngineError::AddressAlreadyBound(existing.0));
                }
            }
            account.btc_address = Some(binding.address.clone());
        }
        ADDR_TYPE_XID => {
            // XID binding: verify that idcom_xid(xid) == sender's idcom.
            let xid: [u8; 32] = binding
                .address
                .as_slice()
                .try_into()
                .map_err(|_| EngineError::InvalidPayload("XID must be 32 bytes".into()))?;
            if idcom_xid(&xid) != *sender_idcom {
                return Err(EngineError::InvalidBindingProof(ADDR_TYPE_XID));
            }
            if let Some(existing) = state.resolve_xid(&xid) {
                if *existing != account.id_com {
                    return Err(EngineError::AddressAlreadyBound(existing.0));
                }
            }
            account.xid = Some(xid);
        }
        ADDR_TYPE_XADDRESS => {
            let pk_bytes = binding
                .proof_pubkey
                .as_ref()
                .ok_or(EngineError::InvalidBindingProof(ADDR_TYPE_XADDRESS))?;
            // Verify that hash of the ML-DSA-44 pubkey matches the declared xaddress.
            let declared: [u8; 32] = binding
                .address
                .as_slice()
                .try_into()
                .map_err(|_| EngineError::InvalidPayload("xaddress must be 32 bytes".into()))?;
            if xaddress_hash(pk_bytes) != declared {
                return Err(EngineError::InvalidBindingProof(ADDR_TYPE_XADDRESS));
            }
            let tagged_pk = TaggedPubkey {
                algorithm: SignatureAlgorithm::MlDsa44,
                bytes: pk_bytes.clone(),
            };
            if !verify_signature(&tagged_pk, &msg, &binding.proof_sig) {
                return Err(EngineError::InvalidBindingProof(ADDR_TYPE_XADDRESS));
            }
            if let Some(existing) = state.resolve_xaddress(&declared) {
                if *existing != account.id_com {
                    return Err(EngineError::AddressAlreadyBound(existing.0));
                }
            }
            account.xaddress = Some(declared);
        }
        other => {
            return Err(EngineError::InvalidPayload(format!(
                "unknown address type: 0x{other:02x}"
            )));
        }
    }

    Ok(StateChange::AddressBound {
        account: account.id_com,
        address_type: binding.address_type,
    })
}

/// Execute a single transaction against the state tree.
///
/// The sender is identified by `tx.attestation.idcom`.
/// Verifies the sender's attestation signature before executing.
pub fn execute_transaction(
    state: &mut StateTree,
    tx: &Transaction,
    policy: &ExecutionPolicy,
) -> Result<ExecutionReceipt, EngineError> {
    let sender = AccountId::from_bytes(tx.attestation.idcom);
    let tx_hash = tx.tx_hash();

    // Decode the operation first so we can check for CreateAccount exceptions.
    let op = TransactionOp::decode(&tx.payload)?;

    // ZK-ACE auth has no per-op nonce and its replay registry (rp_com) is only
    // consumed on the Transfer path; restrict it to Transfer so no other op can
    // execute (and potentially replay) without proper replay accounting.
    if tx.is_zk_auth() && !matches!(op, TransactionOp::Transfer { .. }) {
        return Err(EngineError::InvalidPayload(
            "ZK-ACE authorization is only permitted for Transfer operations".into(),
        ));
    }

    // ZK-ACE: re-verify the proof as defense-in-depth even though the mempool
    // and NVm dispatcher already checked it.  Closes the gap where
    // execute_transaction is called directly without prior ZK validation.
    if tx.is_zk_auth() {
        let zk = tx
            .zk_auth
            .as_ref()
            .ok_or(EngineError::InvalidCredential(tx.attestation.idcom))?;
        ace_runtime::crypto::verify_zk_auth(tx, zk)
            .map_err(|_| EngineError::InvalidCredential(tx.attestation.idcom))?;
    } else {
        // Verify credential against the appropriate attestation public key.
        // For CreateAccount: verify with the pubkey being registered.
        // For auth-key updates on an already provisioned account: verify with the
        // current on-chain key so key rotation is nonce-ordered and replay-safe.
        // For auth-key bootstrapping on an unprovisioned account: verify with the
        // new key so a zero-key account can install its first signer once.
        let verify_pubkey = match &op {
            TransactionOp::CreateAccount {
                id_com,
                auth_pubkey,
            } if *id_com == sender => auth_pubkey.clone(),
            TransactionOp::SetAuthPubkey { auth_pubkey, .. }
            | TransactionOp::AddAuthKey { auth_pubkey, .. } => {
                let sender_account = state
                    .get(&sender)
                    .ok_or(EngineError::AccountNotFound(sender.0))?;
                let sig_alg = tx.attestation.credential.algorithm;
                match sender_account.auth_key_for_algorithm(sig_alg) {
                    Some(k) if !k.is_zero() => k.clone(),
                    _ => {
                        // Installing or rotating a key for an algorithm not yet on-chain:
                        // only the *bootstrap* path may verify against the new pubkey from
                        // the payload.  Once any signer is provisioned, further auth-key
                        // changes must be signed with an existing key (typically primary).
                        if sender_account.has_provisioned_auth_key() {
                            if !sender_account.auth_pubkey.is_zero() {
                                sender_account.auth_pubkey.clone()
                            } else if let Some(k) =
                                sender_account.auth_keys.iter().find(|k| !k.is_zero())
                            {
                                k.clone()
                            } else {
                                auth_pubkey.clone()
                            }
                        } else {
                            auth_pubkey.clone()
                        }
                    }
                }
            }
            _ => {
                if let Some(sender_account) = state.get(&sender) {
                    let sig_alg = tx.attestation.credential.algorithm;
                    sender_account
                        .auth_key_for_algorithm(sig_alg)
                        .cloned()
                        .unwrap_or_else(|| sender_account.auth_pubkey.clone())
                } else {
                    return Err(EngineError::AccountNotFound(sender.0));
                }
            }
        };

        if !ace_runtime::crypto::attestation::verify_credential(
            &tx.attestation,
            &tx.payload,
            &verify_pubkey,
        ) {
            return Err(EngineError::InvalidCredential(tx.attestation.idcom));
        }
    }

    let state_changes = match op {
        TransactionOp::HfiPayClaim { .. }
        | TransactionOp::HfiPayCreate { .. }
        | TransactionOp::HfiPayFund { .. }
        | TransactionOp::HfiPayExpire { .. }
        | TransactionOp::HfiPayRefund { .. }
        | TransactionOp::HfiPayRegisterRecipient { .. } => {
            return Err(EngineError::InvalidPayload(
                "HFI Pay opcode (0x06..=0x0B) is executed by the n-VM HFI hook".into(),
            ));
        }
        TransactionOp::ApproveValidator { nonce, .. } => {
            // Governance hook executed after block commit by node.rs.
            return apply_approve_validator_nonce(state, tx_hash, sender, nonce, policy);
        }
        TransactionOp::Transfer { nonce, to, amount } => {
            if tx.is_zk_auth() {
                let mut changes = consume_zk_replay(state, tx, sender)?;
                changes.extend(transfer::transfer_with_nonce_policy(
                    state, &sender, &to, amount, None, false,
                )?);
                changes
            } else {
                transfer::transfer(state, &sender, &to, amount, Some(nonce))?
            }
        }
        TransactionOp::CreateAccount {
            id_com,
            auth_pubkey,
        } => {
            // Enforce that only the account owner can create their own account.
            if id_com != sender {
                return Err(EngineError::InvalidPayload(
                    "CreateAccount id_com must equal sender".into(),
                ));
            }
            if state.contains(&id_com) {
                return Err(EngineError::AccountAlreadyExists(id_com.0));
            }
            state.insert(Account::with_auth(id_com, 0, auth_pubkey));
            vec![StateChange::AccountCreated { account: id_com }]
        }
        TransactionOp::SetAuthPubkey { nonce, auth_pubkey } => {
            // Sender updates their own auth_pubkey.
            // This is used after HFI Pay bind with a new ML-DSA-44 key from Yallet.
            // Algorithm-aware: replaces key of matching algorithm wherever it lives.
            if let Some(account) = state.get_mut(&sender) {
                let nonce_change = consume_account_nonce(account, &sender, nonce)?;
                let algorithm = auth_pubkey.algorithm as u8;
                if account.auth_pubkey.is_zero() {
                    if let Some(pos) = account
                        .auth_keys
                        .iter()
                        .position(|k| k.algorithm == auth_pubkey.algorithm)
                    {
                        account.auth_keys.remove(pos);
                    }
                    account.auth_pubkey = auth_pubkey;
                } else if auth_pubkey.algorithm == account.auth_pubkey.algorithm {
                    account.auth_pubkey = auth_pubkey;
                } else if let Some(pos) = account
                    .auth_keys
                    .iter()
                    .position(|k| k.algorithm == auth_pubkey.algorithm)
                {
                    account.auth_keys[pos] = auth_pubkey;
                } else {
                    account
                        .add_auth_key(auth_pubkey)
                        .map_err(EngineError::InvalidPayload)?;
                }
                vec![
                    nonce_change,
                    StateChange::AuthKeyUpdated {
                        account: sender,
                        algorithm,
                    },
                ]
            } else {
                return Err(EngineError::AccountNotFound(sender.0));
            }
        }
        TransactionOp::AddAuthKey { nonce, auth_pubkey } => {
            // Add a new auth key of a different algorithm.
            if let Some(account) = state.get_mut(&sender) {
                let nonce_change = consume_account_nonce(account, &sender, nonce)?;
                let algorithm = auth_pubkey.algorithm as u8;
                account
                    .add_auth_key(auth_pubkey)
                    .map_err(EngineError::InvalidPayload)?;
                vec![
                    nonce_change,
                    StateChange::AuthKeyUpdated {
                        account: sender,
                        algorithm,
                    },
                ]
            } else {
                return Err(EngineError::AccountNotFound(sender.0));
            }
        }
        TransactionOp::RegisterAddresses { nonce, bindings } => {
            let account = state
                .get_mut(&sender)
                .ok_or(EngineError::AccountNotFound(sender.0))?;
            let nonce_change = consume_account_nonce(account, &sender, nonce)?;
            // Clone account for binding verification (needs immutable state for conflict checks).
            let mut updated = account.clone();
            let mut changes = vec![nonce_change];
            for binding in &bindings {
                let change = verify_and_apply_binding(state, &mut updated, &sender.0, binding)?;
                changes.push(change);
            }
            state.insert(updated);
            changes
        }
    };

    Ok(ExecutionReceipt {
        tx_hash,
        success: true,
        sender,
        state_changes,
        error: None,
    })
}

fn consume_account_nonce(
    account: &mut Account,
    sender: &AccountId,
    nonce: u64,
) -> Result<StateChange, EngineError> {
    if account.nonce != nonce {
        return Err(EngineError::InvalidNonce {
            expected: account.nonce,
            got: nonce,
        });
    }
    account.nonce = account
        .nonce
        .checked_add(1)
        .ok_or(EngineError::NonceOverflow(sender.0))?;
    Ok(StateChange::NonceIncrement {
        account: *sender,
        new_nonce: account.nonce,
    })
}

fn consume_zk_replay(
    state: &mut StateTree,
    tx: &Transaction,
    sender: AccountId,
) -> Result<Vec<StateChange>, EngineError> {
    let zk_auth = tx
        .zk_auth
        .as_ref()
        .ok_or(EngineError::InvalidCredential(tx.attestation.idcom))?;
    if !state.zk_replay_consume(zk_auth.rp_com, sender.0) {
        return Err(EngineError::InvalidPayload(
            "ZK-ACE replay commitment already consumed".into(),
        ));
    }
    Ok(vec![StateChange::ZkReplayConsumed {
        rp_com: zk_auth.rp_com,
        account: sender,
    }])
}

/// Execute a block of transactions, collecting receipts.
///
/// Transactions that fail produce a failure receipt but do not
/// halt execution of subsequent transactions.
///
/// Phase 1 (parallel): verify all signatures using rayon.
/// Phase 2 (sequential): apply state changes for verified transactions.
pub fn execute_block(
    state: &mut StateTree,
    txs: &[Transaction],
    policy: &ExecutionPolicy,
) -> Vec<ExecutionReceipt> {
    use rayon::prelude::*;

    if txs.is_empty() {
        return Vec::new();
    }

    // ── Phase 1: parallel signature pre-verification ──────────────
    // Resolve the verification pubkey for each tx.  For most txs
    // (Transfer) this reads the sender's on-chain key which is cheap.
    // CreateAccount uses the embedded key.  We snapshot pubkeys from
    // the *current* state — this is safe because Phase 2 may only
    // invalidate a few edge-case reorderings (SetAuthPubkey during the
    // same block), which will fail at nonce check anyway.
    let pre_results: Vec<Option<TaggedPubkey>> = txs
        .iter()
        .map(|tx| {
            let sender = AccountId::from_bytes(tx.attestation.idcom);
            let op = match TransactionOp::decode(&tx.payload) {
                Ok(op) => op,
                Err(_) => return None,
            };
            match &op {
                TransactionOp::CreateAccount {
                    id_com,
                    auth_pubkey,
                } if *id_com == sender => Some(auth_pubkey.clone()),
                TransactionOp::SetAuthPubkey { auth_pubkey, .. }
                | TransactionOp::AddAuthKey { auth_pubkey, .. } => {
                    if let Some(acct) = state.get(&sender) {
                        let sig_alg = tx.attestation.credential.algorithm;
                        match acct.auth_key_for_algorithm(sig_alg) {
                            Some(k) if !k.is_zero() => Some(k.clone()),
                            _ => {
                                let pk = if acct.has_provisioned_auth_key() {
                                    if !acct.auth_pubkey.is_zero() {
                                        acct.auth_pubkey.clone()
                                    } else if let Some(k) =
                                        acct.auth_keys.iter().find(|k| !k.is_zero())
                                    {
                                        k.clone()
                                    } else {
                                        auth_pubkey.clone()
                                    }
                                } else {
                                    auth_pubkey.clone()
                                };
                                Some(pk)
                            }
                        }
                    } else {
                        None
                    }
                }
                _ => state.get(&sender).map(|acct| {
                    let sig_alg = tx.attestation.credential.algorithm;
                    acct.auth_key_for_algorithm(sig_alg)
                        .cloned()
                        .unwrap_or_else(|| acct.auth_pubkey.clone())
                }),
            }
        })
        .collect();

    // Parallel signature / ZK pre-verification — the expensive part.
    let sig_ok: Vec<bool> = txs
        .par_iter()
        .zip(pre_results.par_iter())
        .map(|(tx, maybe_pk)| {
            if tx.is_zk_auth() {
                return match tx.zk_auth.as_ref() {
                    Some(zk) => ace_runtime::crypto::verify_zk_auth(tx, zk).is_ok(),
                    None => false,
                };
            }
            let Some(pk) = maybe_pk else { return false };
            if pk.is_zero() {
                return false;
            }
            ace_runtime::crypto::attestation::verify_credential(&tx.attestation, &tx.payload, pk)
        })
        .collect();

    // ── Phase 2: sequential state application ─────────────────────
    let mut receipts = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        let receipt = if sig_ok[i] {
            match execute_transaction_presigned(state, tx, policy) {
                Ok(r) => r,
                Err(e) => ExecutionReceipt {
                    tx_hash: tx.tx_hash(),
                    success: false,
                    sender: AccountId::from_bytes(tx.attestation.idcom),
                    state_changes: vec![],
                    error: Some(e.to_string()),
                },
            }
        } else {
            ExecutionReceipt {
                tx_hash: tx.tx_hash(),
                success: false,
                sender: AccountId::from_bytes(tx.attestation.idcom),
                state_changes: vec![],
                error: Some("Invalid attestation signature".to_string()),
            }
        };
        receipts.push(receipt);
    }
    receipts
}

/// Execute a transaction whose signature has already been verified.
/// Skips the expensive `verify_credential` call.
fn execute_transaction_presigned(
    state: &mut StateTree,
    tx: &Transaction,
    policy: &ExecutionPolicy,
) -> Result<ExecutionReceipt, EngineError> {
    let sender = AccountId::from_bytes(tx.attestation.idcom);
    let tx_hash = tx.tx_hash();
    let op = TransactionOp::decode(&tx.payload)?;

    // ZK-ACE auth is only valid for Transfer (see execute_transaction): other ops
    // have no rp_com replay accounting on the zk path.
    if tx.is_zk_auth() && !matches!(op, TransactionOp::Transfer { .. }) {
        return Err(EngineError::InvalidPayload(
            "ZK-ACE authorization is only permitted for Transfer operations".into(),
        ));
    }

    let state_changes = match op {
        TransactionOp::HfiPayClaim { .. }
        | TransactionOp::HfiPayCreate { .. }
        | TransactionOp::HfiPayFund { .. }
        | TransactionOp::HfiPayExpire { .. }
        | TransactionOp::HfiPayRefund { .. }
        | TransactionOp::HfiPayRegisterRecipient { .. } => {
            return Err(EngineError::InvalidPayload(
                "HFI Pay opcode (0x06..=0x0B) is executed by the n-VM HFI hook".into(),
            ));
        }
        TransactionOp::ApproveValidator { nonce, .. } => {
            return apply_approve_validator_nonce(state, tx_hash, sender, nonce, policy);
        }
        TransactionOp::Transfer { nonce, to, amount } => {
            if tx.is_zk_auth() {
                let mut changes = consume_zk_replay(state, tx, sender)?;
                changes.extend(transfer::transfer_with_nonce_policy(
                    state, &sender, &to, amount, None, false,
                )?);
                changes
            } else {
                transfer::transfer(state, &sender, &to, amount, Some(nonce))?
            }
        }
        TransactionOp::CreateAccount {
            id_com,
            auth_pubkey,
        } => {
            if id_com != sender {
                return Err(EngineError::InvalidPayload(
                    "CreateAccount id_com must equal sender".into(),
                ));
            }
            if state.contains(&id_com) {
                return Err(EngineError::AccountAlreadyExists(id_com.0));
            }
            state.insert(Account::with_auth(id_com, 0, auth_pubkey));
            vec![StateChange::AccountCreated { account: id_com }]
        }
        TransactionOp::SetAuthPubkey { nonce, auth_pubkey } => {
            if let Some(account) = state.get_mut(&sender) {
                let nonce_change = consume_account_nonce(account, &sender, nonce)?;
                let algorithm = auth_pubkey.algorithm as u8;
                if account.auth_pubkey.is_zero() {
                    if let Some(pos) = account
                        .auth_keys
                        .iter()
                        .position(|k| k.algorithm == auth_pubkey.algorithm)
                    {
                        account.auth_keys.remove(pos);
                    }
                    account.auth_pubkey = auth_pubkey;
                } else if auth_pubkey.algorithm == account.auth_pubkey.algorithm {
                    account.auth_pubkey = auth_pubkey;
                } else if let Some(pos) = account
                    .auth_keys
                    .iter()
                    .position(|k| k.algorithm == auth_pubkey.algorithm)
                {
                    account.auth_keys[pos] = auth_pubkey;
                } else {
                    account
                        .add_auth_key(auth_pubkey)
                        .map_err(EngineError::InvalidPayload)?;
                }
                vec![
                    nonce_change,
                    StateChange::AuthKeyUpdated {
                        account: sender,
                        algorithm,
                    },
                ]
            } else {
                return Err(EngineError::AccountNotFound(sender.0));
            }
        }
        TransactionOp::AddAuthKey { nonce, auth_pubkey } => {
            if let Some(account) = state.get_mut(&sender) {
                let nonce_change = consume_account_nonce(account, &sender, nonce)?;
                let algorithm = auth_pubkey.algorithm as u8;
                account
                    .add_auth_key(auth_pubkey)
                    .map_err(EngineError::InvalidPayload)?;
                vec![
                    nonce_change,
                    StateChange::AuthKeyUpdated {
                        account: sender,
                        algorithm,
                    },
                ]
            } else {
                return Err(EngineError::AccountNotFound(sender.0));
            }
        }
        TransactionOp::RegisterAddresses { nonce, bindings } => {
            let account = state
                .get_mut(&sender)
                .ok_or(EngineError::AccountNotFound(sender.0))?;
            let nonce_change = consume_account_nonce(account, &sender, nonce)?;
            let mut updated = account.clone();
            let mut changes = vec![nonce_change];
            for binding in &bindings {
                let change = verify_and_apply_binding(state, &mut updated, &sender.0, binding)?;
                changes.push(change);
            }
            state.insert(updated);
            changes
        }
    };

    Ok(ExecutionReceipt {
        tx_hash,
        success: true,
        sender,
        state_changes,
        error: None,
    })
}
