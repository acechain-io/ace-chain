//! User conversion intent binding for Phase A bridge flows.
//!
//! A `ConvertIntent` is the stable tuple that deposits, swaps, withdrawals,
//! and refunds must reference. Phase A does not yet implement full HFI-Pay
//! private claim proofs, but it still needs an immutable intent ID so relayers
//! cannot reinterpret a deposit as a different route.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::ExternalAsset;

/// User-authorized route and settlement constraints for a cross-chain conversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvertIntent {
    pub intent_id: [u8; 32],
    pub source_asset: ExternalAsset,
    pub source_amount: u64,
    pub target_asset: ExternalAsset,
    pub min_amount_out: u64,
    pub recipient: Vec<u8>,
    pub refund_destination: Vec<u8>,
    pub expiry_slot: u64,
    pub fee_quote_bps: u64,
    pub relayer_set_id: u64,
    pub nonce: u64,
}

impl ConvertIntent {
    /// Build an intent and derive its deterministic `intent_id`.
    pub fn new(
        source_asset: ExternalAsset,
        source_amount: u64,
        target_asset: ExternalAsset,
        min_amount_out: u64,
        recipient: Vec<u8>,
        refund_destination: Vec<u8>,
        expiry_slot: u64,
        fee_quote_bps: u64,
        relayer_set_id: u64,
        nonce: u64,
    ) -> Self {
        let intent_id = compute_intent_id(
            &source_asset,
            source_amount,
            &target_asset,
            min_amount_out,
            &recipient,
            &refund_destination,
            expiry_slot,
            fee_quote_bps,
            relayer_set_id,
            nonce,
        );
        Self {
            intent_id,
            source_asset,
            source_amount,
            target_asset,
            min_amount_out,
            recipient,
            refund_destination,
            expiry_slot,
            fee_quote_bps,
            relayer_set_id,
            nonce,
        }
    }

    /// Verify that `intent_id` matches the canonical tuple.
    pub fn validate_id(&self) -> bool {
        self.intent_id
            == compute_intent_id(
                &self.source_asset,
                self.source_amount,
                &self.target_asset,
                self.min_amount_out,
                &self.recipient,
                &self.refund_destination,
                self.expiry_slot,
                self.fee_quote_bps,
                self.relayer_set_id,
                self.nonce,
            )
    }
}

#[allow(clippy::too_many_arguments)]
pub fn compute_intent_id(
    source_asset: &ExternalAsset,
    source_amount: u64,
    target_asset: &ExternalAsset,
    min_amount_out: u64,
    recipient: &[u8],
    refund_destination: &[u8],
    expiry_slot: u64,
    fee_quote_bps: u64,
    relayer_set_id: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-defi:convert-intent:v1");
    update_asset(&mut hasher, source_asset);
    hasher.update(source_amount.to_le_bytes());
    update_asset(&mut hasher, target_asset);
    hasher.update(min_amount_out.to_le_bytes());
    hasher.update((recipient.len() as u32).to_le_bytes());
    hasher.update(recipient);
    hasher.update((refund_destination.len() as u32).to_le_bytes());
    hasher.update(refund_destination);
    hasher.update(expiry_slot.to_le_bytes());
    hasher.update(fee_quote_bps.to_le_bytes());
    hasher.update(relayer_set_id.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn update_asset(hasher: &mut Sha256, asset: &ExternalAsset) {
    let label = asset.label();
    hasher.update((label.len() as u32).to_le_bytes());
    hasher.update(label);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExternalAsset, ExternalChain};

    #[test]
    fn intent_id_is_stable_and_tuple_bound() {
        let base = ConvertIntent::new(
            ExternalAsset::Native(ExternalChain::Ethereum),
            1_000,
            ExternalAsset::Native(ExternalChain::Solana),
            900,
            vec![0x11; 32],
            vec![0x22; 20],
            100,
            10,
            7,
            1,
        );
        let same = ConvertIntent::new(
            ExternalAsset::Native(ExternalChain::Ethereum),
            1_000,
            ExternalAsset::Native(ExternalChain::Solana),
            900,
            vec![0x11; 32],
            vec![0x22; 20],
            100,
            10,
            7,
            1,
        );
        let different = ConvertIntent::new(
            ExternalAsset::Native(ExternalChain::Ethereum),
            1_000,
            ExternalAsset::Native(ExternalChain::Solana),
            901,
            vec![0x11; 32],
            vec![0x22; 20],
            100,
            10,
            7,
            1,
        );

        assert!(base.validate_id());
        assert_eq!(base.intent_id, same.intent_id);
        assert_ne!(base.intent_id, different.intent_id);
    }
}
