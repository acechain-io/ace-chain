//! Transaction validation before mempool admission.
//!
//! Wraps ace-runtime's `verify_payload_binding` for attestation checks
//! and validates transaction format including domain chain_id.

use ace_engine::executor::{TransactionOp, OP_APPROVE_VALIDATOR};
use ace_model::account::AccountId;
use ace_runtime::crypto::attestation::verify_payload_binding;
use ace_runtime::types::transaction::{RawChainKind, Transaction};

use crate::error::MempoolError;

/// Stateless transaction validator.
///
/// Performs lightweight checks suitable for mempool admission:
/// - Non-empty payload
/// - Payload binding: `SHA-256(payload) == attestation.obj_hash`
/// - Domain chain_id matches the node's expected chain_id
///
/// Does NOT verify the HMAC credential (that requires the user's
/// attestation key; full binding is proven in Phase 2 via Groth16).
pub struct TransactionValidator;

/// Maximum slot drift allowed between tx domain.slot and current slot.
const SLOT_TOLERANCE: u64 = 100;
/// Default max payload size when config gives 0 (production must never rely on "no limit").
const DEFAULT_MAX_TX_BYTES: usize = 65_536;

impl TransactionValidator {
    /// Validate a transaction for mempool admission.
    ///
    /// `expected_chain_id` of 0 skips the chain_id check.
    /// `max_tx_bytes` of 0 uses `DEFAULT_MAX_TX_BYTES` (64 KB); do not use 0 in production to mean "no limit".
    pub fn validate(
        tx: &Transaction,
        expected_chain_id: u32,
        max_tx_bytes: usize,
    ) -> Result<(), MempoolError> {
        // Check 1: non-empty payload
        if tx.payload.is_empty() {
            return Err(MempoolError::EmptyPayload);
        }

        // Check 2: full transaction size limit (0 => use default so we never disable the check)
        let effective_max = if max_tx_bytes == 0 {
            DEFAULT_MAX_TX_BYTES
        } else {
            max_tx_bytes
        };
        let wire_size = tx.wire_size();
        if wire_size > effective_max {
            return Err(MempoolError::PayloadTooLarge {
                size: wire_size,
                max: effective_max,
            });
        }

        // Check 3: payload binding (SHA-256)
        if !verify_payload_binding(&tx.attestation, &tx.payload) {
            return Err(MempoolError::PayloadBindingMismatch);
        }

        // Check 4: domain chain_id
        if expected_chain_id != 0 && tx.attestation.domain.chain_id != expected_chain_id {
            return Err(MempoolError::InvalidChainId {
                expected: expected_chain_id,
                got: tx.attestation.domain.chain_id,
            });
        }

        Ok(())
    }

    /// Reject doomed `OP_APPROVE_VALIDATOR` transactions before mempool admission.
    ///
    /// Full registry/policy checks still run at block commit; this gate only
    /// enforces founder authorization and payload decodability so non-founders
    /// do not burn fees on txs that cannot succeed.
    pub fn validate_approve_validator(
        tx: &Transaction,
        founder_id_com: Option<AccountId>,
    ) -> Result<(), MempoolError> {
        if tx.payload.first() != Some(&OP_APPROVE_VALIDATOR) {
            return Ok(());
        }
        let founder = founder_id_com.ok_or_else(|| {
            MempoolError::ValidationError(
                "validator admission is disabled (no founder_id_com in genesis)".into(),
            )
        })?;
        let sender = AccountId::from_bytes(tx.attestation.idcom);
        if sender != founder {
            return Err(MempoolError::ValidationError(format!(
                "OP_APPROVE_VALIDATOR sender {} is not the founder",
                hex::encode(sender.0)
            )));
        }
        match TransactionOp::decode(&tx.payload) {
            Ok(TransactionOp::ApproveValidator { .. }) => Ok(()),
            Ok(_) => Err(MempoolError::ValidationError(
                "unexpected opcode after OP_APPROVE_VALIDATOR prefix".into(),
            )),
            Err(e) => Err(MempoolError::ValidationError(e.to_string())),
        }
    }

    /// Validate that a transaction's domain.slot is within tolerance of the
    /// current slot. At genesis (current_slot == 0), only slots in [0, SLOT_TOLERANCE] are allowed.
    pub fn validate_slot(tx: &Transaction, current_slot: u64) -> Result<(), MempoolError> {
        if matches!(
            tx.raw_chain.as_ref().map(|raw_chain| raw_chain.kind),
            Some(RawChainKind::Tron)
        ) {
            return Ok(());
        }
        let tx_slot = tx.attestation.domain.slot as u64;
        let lo = current_slot.saturating_sub(SLOT_TOLERANCE);
        let hi = current_slot + SLOT_TOLERANCE;
        if tx_slot < lo || tx_slot > hi {
            return Err(MempoolError::SlotOutOfRange {
                tx_slot: tx.attestation.domain.slot,
                current: current_slot,
                tolerance: SLOT_TOLERANCE,
            });
        }
        Ok(())
    }
}
