//! DeFi runtime state holder for node-level integration.
//!
//! Bundles `AssetRegistry` and `SwapEngine` into a single handle that
//! the node passes into the transaction execution pipeline.  When the
//! pipeline encounters an opcode-0x05 (`CrossVmSettle`) transaction,
//! it calls [`DefiRuntime::execute_settle`] instead of dispatching
//! through the n-VM.
//!
//! # Security
//!
//! CrossVmSettle does NOT mint tokens.  The user must already hold
//! wrapped tokens obtained through the authenticated bridge deposit
//! path (`BridgeState::process_signed_deposit`, which requires a
//! valid relayer attestation).  This prevents arbitrary minting.
//!
//! Phase A also does not yet persist AMM pool metadata in `StateTree`.
//! Nodes must preload/initialize pools into the in-memory `SwapEngine`
//! before accepting `CrossVmSettle`; otherwise the runtime fails closed.

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;

use crate::registry::AssetRegistry;
use crate::settle::{self, CrossVmSettleParams, SettleError, SettleResult};
use crate::swap::SwapEngine;
use crate::types::ExternalAsset;

/// Opcode for cross-VM settlement transactions.
pub const OP_CROSS_VM_SETTLE: u8 = 0x05;

/// Bundled DeFi runtime state for node-level integration.
///
/// Created once at node startup and passed (by mutable reference) into
/// `execute_transactions_with_fees` so that opcode-0x05 transactions
/// can access the swap engine and asset registry without introducing
/// a circular dependency between `ace-n-vm` and `ace-defi`.
pub struct DefiRuntime {
    pub registry: AssetRegistry,
    pub swap_engine: SwapEngine,
    next_withdrawal_id: u64,
    initialized: bool,
}

impl DefiRuntime {
    pub fn new() -> Self {
        Self {
            registry: AssetRegistry::new(),
            swap_engine: SwapEngine::new(),
            next_withdrawal_id: 1,
            initialized: false,
        }
    }

    /// Initialize the asset registry with all native chain tokens and
    /// restore `next_withdrawal_id` from on-chain state.
    ///
    /// This is idempotent — safe to call on every node restart.
    pub fn initialize(&mut self, state: &mut StateTree) -> Result<(), crate::error::BridgeError> {
        self.registry.register_all_natives(state)?;

        // Restore next_withdrawal_id from the bridge account's storage.
        // BridgeState persists it under the well-known slot "nxt_w_id".
        let bridge_account = crate::types::bridge_authority_id();
        let mut nwid_slot = [0u8; 32];
        nwid_slot[0..8].copy_from_slice(b"nxt_w_id");
        let stored = state.get_storage(&bridge_account, &nwid_slot);
        if stored != [0u8; 32] {
            self.next_withdrawal_id = u64::from_le_bytes(stored[0..8].try_into().unwrap_or([0; 8]));
        }

        self.initialized = true;
        Ok(())
    }

    /// Ensure the runtime is initialized, initializing lazily if needed.
    fn ensure_initialized(&mut self, state: &mut StateTree) -> Result<(), SettleError> {
        if !self.initialized {
            self.initialize(state)
                .map_err(|e| SettleError::Decode(format!("DeFi runtime init failed: {e}")))?;
        }
        Ok(())
    }

    /// Check whether a transaction payload starts with the CrossVmSettle opcode.
    pub fn is_settle_tx(payload: &[u8]) -> bool {
        !payload.is_empty() && payload[0] == OP_CROSS_VM_SETTLE
    }

    /// Decode a CrossVmSettle payload and execute the atomic settlement.
    ///
    /// Payload format (swap + withdraw only, no minting):
    /// ```text
    /// 0x05 || intent_id(32) || nonce(8 LE)
    ///      || swap_in_asset_tag(1) || swap_in_asset_body(var)
    ///      || swap_in_amount(8 LE)
    ///      || swap_out_asset_tag(1) || swap_out_asset_body(var)
    ///      || min_amount_out(8 LE)
    ///      || withdraw_dest_len(2 LE) || withdraw_dest(var)
    /// ```
    ///
    /// The sender is extracted from `tx.attestation.idcom` by the caller.
    pub fn execute_settle(
        &mut self,
        state: &mut StateTree,
        sender: AccountId,
        payload: &[u8],
        block_slot: u64,
    ) -> Result<SettleResult, SettleError> {
        self.ensure_initialized(state)?;
        if self.swap_engine.pool_count() == 0 {
            return Err(SettleError::Decode(
                "CrossVmSettle requires pre-initialized in-memory AMM pools in Phase A".into(),
            ));
        }
        let params =
            Self::decode_settle_payload(payload, sender, block_slot, self.next_withdrawal_id)?;
        let result = settle::cross_vm_settle(state, &self.registry, &mut self.swap_engine, params)?;
        self.next_withdrawal_id += 1;

        // Persist next_withdrawal_id to the bridge account's storage (same
        // slot used by BridgeState) so it survives node restarts.
        let bridge_account = crate::types::bridge_authority_id();
        let mut nwid_slot = [0u8; 32];
        nwid_slot[0..8].copy_from_slice(b"nxt_w_id");
        let mut nwid_val = [0u8; 32];
        nwid_val[0..8].copy_from_slice(&self.next_withdrawal_id.to_le_bytes());
        state.set_storage(&bridge_account, nwid_slot, nwid_val);

        Ok(result)
    }

    fn decode_settle_payload(
        payload: &[u8],
        sender: AccountId,
        block_slot: u64,
        withdrawal_id: u64,
    ) -> Result<CrossVmSettleParams, SettleError> {
        if payload.is_empty() || payload[0] != OP_CROSS_VM_SETTLE {
            return Err(SettleError::Decode("not a CrossVmSettle payload".into()));
        }

        // Minimum: opcode(1) + intent_id(32) + nonce(8) + asset(2) + amount(8) + asset(2) + min_out(8) + dest_len(2) = 63
        if payload.len() < 63 {
            return Err(SettleError::Decode(
                "payload too short for CrossVmSettle".into(),
            ));
        }

        let mut cursor = 1; // skip opcode

        // intent_id (32 bytes)
        let mut intent_id = [0u8; 32];
        intent_id.copy_from_slice(&payload[cursor..cursor + 32]);
        cursor += 32;

        // nonce (8 bytes LE) — checked and incremented in cross_vm_settle()
        let nonce = u64::from_le_bytes(payload[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;

        // swap input asset
        let (swap_in_asset, consumed) = decode_asset(&payload[cursor..])?;
        cursor += consumed;

        // swap input amount (8 bytes LE)
        if cursor + 8 > payload.len() {
            return Err(SettleError::Decode("missing swap_in_amount".into()));
        }
        let swap_in_amount = u64::from_le_bytes(payload[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;

        // swap output asset
        let (swap_out_asset, consumed) = decode_asset(&payload[cursor..])?;
        cursor += consumed;

        // min_amount_out (8 bytes LE)
        if cursor + 8 > payload.len() {
            return Err(SettleError::Decode("missing min_amount_out".into()));
        }
        let min_amount_out = u64::from_le_bytes(payload[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;

        // withdraw_dest_len (2 bytes LE) + withdraw_dest
        if cursor + 2 > payload.len() {
            return Err(SettleError::Decode("missing withdraw_dest_len".into()));
        }
        let dest_len = u16::from_le_bytes(payload[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        if cursor + dest_len > payload.len() {
            return Err(SettleError::Decode("withdraw_dest truncated".into()));
        }
        let withdraw_dest = payload[cursor..cursor + dest_len].to_vec();

        Ok(CrossVmSettleParams {
            sender,
            intent_id,
            nonce,
            swap_in_asset,
            swap_in_amount,
            swap_out_asset,
            min_amount_out,
            withdraw_dest,
            current_slot: block_slot,
            next_withdrawal_id: withdrawal_id,
        })
    }
}

impl Default for DefiRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode an `ExternalAsset` into a tagged byte sequence.
pub fn encode_asset(asset: &ExternalAsset) -> Vec<u8> {
    match asset {
        ExternalAsset::Native(chain) => vec![0x01, *chain as u8],
        ExternalAsset::Erc20(addr) => {
            let mut buf = Vec::with_capacity(21);
            buf.push(0x02);
            buf.extend_from_slice(addr);
            buf
        }
        ExternalAsset::Bep20(addr) => {
            let mut buf = Vec::with_capacity(21);
            buf.push(0x05);
            buf.extend_from_slice(addr);
            buf
        }
        ExternalAsset::SplToken(mint) => {
            let mut buf = Vec::with_capacity(33);
            buf.push(0x03);
            buf.extend_from_slice(mint);
            buf
        }
        ExternalAsset::Trc20(addr) => {
            let mut buf = Vec::with_capacity(21);
            buf.push(0x04);
            buf.extend_from_slice(addr);
            buf
        }
    }
}

fn decode_asset(data: &[u8]) -> Result<(ExternalAsset, usize), SettleError> {
    use crate::types::ExternalChain;

    if data.is_empty() {
        return Err(SettleError::Decode("empty asset tag".into()));
    }

    match data[0] {
        0x01 => {
            if data.len() < 2 {
                return Err(SettleError::Decode("missing chain id".into()));
            }
            let chain = match data[1] {
                1 => ExternalChain::Ethereum,
                2 => ExternalChain::Solana,
                3 => ExternalChain::Bitcoin,
                4 => ExternalChain::Tron,
                5 => ExternalChain::Bsc,
                other => return Err(SettleError::Decode(format!("unknown chain: {other}"))),
            };
            Ok((ExternalAsset::Native(chain), 2))
        }
        0x02 => {
            if data.len() < 21 {
                return Err(SettleError::Decode("erc20 address truncated".into()));
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&data[1..21]);
            Ok((ExternalAsset::Erc20(addr), 21))
        }
        0x03 => {
            if data.len() < 33 {
                return Err(SettleError::Decode("spl token mint truncated".into()));
            }
            let mut mint = [0u8; 32];
            mint.copy_from_slice(&data[1..33]);
            Ok((ExternalAsset::SplToken(mint), 33))
        }
        0x04 => {
            if data.len() < 21 {
                return Err(SettleError::Decode("trc20 address truncated".into()));
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&data[1..21]);
            Ok((ExternalAsset::Trc20(addr), 21))
        }
        0x05 => {
            if data.len() < 21 {
                return Err(SettleError::Decode("bep20 address truncated".into()));
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&data[1..21]);
            Ok((ExternalAsset::Bep20(addr), 21))
        }
        other => Err(SettleError::Decode(format!(
            "unknown asset tag: 0x{other:02x}"
        ))),
    }
}

/// Build a CrossVmSettle payload from typed parameters.
///
/// Used by client SDKs and tests to construct the opcode-0x05 payload.
pub fn build_settle_payload(
    intent_id: [u8; 32],
    nonce: u64,
    swap_in_asset: &ExternalAsset,
    swap_in_amount: u64,
    swap_out_asset: &ExternalAsset,
    min_amount_out: u64,
    withdraw_dest: &[u8],
) -> Vec<u8> {
    let in_bytes = encode_asset(swap_in_asset);
    let out_bytes = encode_asset(swap_out_asset);
    let dest_len = withdraw_dest.len() as u16;

    let mut buf = Vec::with_capacity(
        1 + 32 + 8 + in_bytes.len() + 8 + out_bytes.len() + 8 + 2 + withdraw_dest.len(),
    );
    buf.push(OP_CROSS_VM_SETTLE);
    buf.extend_from_slice(&intent_id);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(&in_bytes);
    buf.extend_from_slice(&swap_in_amount.to_le_bytes());
    buf.extend_from_slice(&out_bytes);
    buf.extend_from_slice(&min_amount_out.to_le_bytes());
    buf.extend_from_slice(&dest_len.to_le_bytes());
    buf.extend_from_slice(withdraw_dest);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ExternalChain;

    #[test]
    fn encode_decode_native_asset_roundtrip() {
        let asset = ExternalAsset::Native(ExternalChain::Solana);
        let bytes = encode_asset(&asset);
        let (decoded, consumed) = decode_asset(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(format!("{decoded:?}"), format!("{asset:?}"));
    }

    #[test]
    fn encode_decode_erc20_roundtrip() {
        let asset = ExternalAsset::Erc20([0xAB; 20]);
        let bytes = encode_asset(&asset);
        let (decoded, consumed) = decode_asset(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(format!("{decoded:?}"), format!("{asset:?}"));
    }

    #[test]
    fn build_and_decode_settle_payload() {
        let swap_in = ExternalAsset::Native(ExternalChain::Ethereum);
        let swap_out = ExternalAsset::Native(ExternalChain::Solana);
        let sender = AccountId::from_bytes([0xBB; 32]);
        let intent_id = [0xAA; 32];

        let payload = build_settle_payload(
            intent_id,
            42,
            &swap_in,
            100_000,
            &swap_out,
            50_000,
            &[0xCC; 32],
        );

        assert_eq!(payload[0], OP_CROSS_VM_SETTLE);

        let params = DefiRuntime::decode_settle_payload(&payload, sender, 100, 1).unwrap();
        assert_eq!(params.intent_id, intent_id);
        assert_eq!(params.swap_in_amount, 100_000);
        assert_eq!(params.min_amount_out, 50_000);
        assert_eq!(params.withdraw_dest, vec![0xCC; 32]);
        assert_eq!(params.sender, sender);
    }

    #[test]
    fn decode_rejects_wrong_opcode() {
        let sender = AccountId::from_bytes([0xBB; 32]);
        let payload = vec![0x01; 50]; // opcode 0x01, not 0x05
        let result = DefiRuntime::decode_settle_payload(&payload, sender, 0, 1);
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let sender = AccountId::from_bytes([0xBB; 32]);
        let payload = vec![0x05, 0, 0]; // too short
        let result = DefiRuntime::decode_settle_payload(&payload, sender, 0, 1);
        assert!(result.is_err());
    }
}
