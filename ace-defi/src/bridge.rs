//! Unified BridgeState manager.
//!
//! Ties together the asset registry, deposit processing, and withdrawal
//! management into a single entry point.

use std::collections::HashSet;

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use sha2::{Digest, Sha256};

use crate::deposit;
use crate::error::BridgeError;
use crate::registry::AssetRegistry;
use crate::types::{
    bridge_authority_id, native_decimals, DepositRecord, ExternalAsset, SignedDepositRecord,
    WithdrawalRecord,
};
use crate::withdraw;

/// The unified bridge manager for dual-mode VM architecture.
///
/// Each external chain (Ethereum, Solana, Bitcoin, Tron) has a corresponding
/// "L2 portal" that funnels deposits into the ACE Chain unified state.
/// This struct manages the full lifecycle:
///
/// ```text
/// External L1 deposit
///   → verify deposit proof
///   → auto-wrap (mint ACE-wETH/wSOL/wBTC/wTRX)
///   → recipient uses wrapped token across all VMs (cross-VM atomic)
///   → user requests withdrawal (unwrap)
///   → burn wrapped token
///   → external L1 bridge contract verifies proof and releases funds
/// ```
pub struct BridgeState {
    pub registry: AssetRegistry,
    processed_deposits: HashSet<[u8; 32]>,
    next_withdrawal_id: u64,
    withdrawals: Vec<WithdrawalRecord>,
    bridge_account: AccountId,
    governance_pubkey: Option<[u8; 32]>,
    approved_relayers: Vec<[u8; 32]>,
}

impl BridgeState {
    pub fn new() -> Self {
        Self {
            registry: AssetRegistry::new(),
            processed_deposits: HashSet::new(),
            next_withdrawal_id: 0,
            withdrawals: Vec::new(),
            bridge_account: bridge_authority_id(),
            governance_pubkey: None,
            approved_relayers: Vec::new(),
        }
    }

    /// Create a bridge state whose relayer set can be governed by `governance_pubkey`.
    pub fn new_with_governance(governance_pubkey: [u8; 32]) -> Self {
        let mut state = Self::new();
        state.governance_pubkey = Some(governance_pubkey);
        state
    }

    /// Initialize the bridge: register all native wrapped assets and restore
    /// persisted state (next_withdrawal_id) from the StateTree.
    pub fn initialize(&mut self, state: &mut StateTree) -> Result<(), BridgeError> {
        // Restore next_withdrawal_id from the well-known storage slot written by
        // request_withdrawal. If the slot is zero-initialised the value stays 0.
        let mut nwid_slot = [0u8; 32];
        nwid_slot[0..8].copy_from_slice(b"nxt_w_id");
        let nwid_val = state.get_storage(&self.bridge_account, &nwid_slot);
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&nwid_val[0..8]);
        self.next_withdrawal_id = u64::from_le_bytes(buf);

        self.registry.register_all_natives(state)
    }

    /// Register a custom external token (ERC-20, SPL, TRC-20).
    pub fn register_asset(
        &mut self,
        state: &mut StateTree,
        asset: &ExternalAsset,
        decimals: u8,
    ) -> Result<AccountId, BridgeError> {
        self.registry.register_asset(state, asset, decimals)
    }

    /// Check risk limits for Phase A
    fn check_limits(
        &self,
        state: &StateTree,
        asset: &ExternalAsset,
        amount: u64,
        current_slot: u64,
        is_deposit: bool,
    ) -> Result<(), BridgeError> {
        let mint_id = crate::types::wrapped_mint_id(asset);
        let decimals = match asset {
            ExternalAsset::Native(crate::types::ExternalChain::Ethereum)
            | ExternalAsset::Erc20(_) => 18,
            ExternalAsset::Native(crate::types::ExternalChain::Bsc) | ExternalAsset::Bep20(_) => 18,
            ExternalAsset::Native(crate::types::ExternalChain::Solana)
            | ExternalAsset::SplToken(_) => 9,
            ExternalAsset::Native(crate::types::ExternalChain::Tron) | ExternalAsset::Trc20(_) => 6,
            ExternalAsset::Native(crate::types::ExternalChain::Bitcoin) => 8,
        };

        let multiplier = 10u64.pow(decimals as u32);
        let amount_normalized = amount / multiplier.max(1);

        let single_tx_limit = 50_000;
        if amount_normalized > single_tx_limit {
            return Err(BridgeError::RiskLimitExceeded("single tx limit 50k".into()));
        }

        if is_deposit {
            let tvl_limit = 1_000_000;
            let current_supply = ace_n_vm::token_runtime::get_mint_meta(state, mint_id.as_bytes())
                .map(|m| m.supply)
                .unwrap_or(0);
            let supply_normalized = current_supply / multiplier.max(1);
            if supply_normalized + amount_normalized > tvl_limit {
                return Err(BridgeError::RiskLimitExceeded("TVL limit 1M".into()));
            }
        } else {
            let daily_limit = 250_000;
            let day_index = current_slot / 86400;
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, b"ace-daily-out:");
            sha2::Digest::update(&mut hasher, day_index.to_le_bytes());
            let mut slot_key = [0u8; 32];
            slot_key.copy_from_slice(&hasher.finalize());

            let daily_total_bytes = state.get_storage(&self.bridge_account, &slot_key);
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&daily_total_bytes[0..8]);
            let daily_total = u64::from_le_bytes(buf);

            if daily_total + amount_normalized > daily_limit {
                return Err(BridgeError::RiskLimitExceeded("daily limit 250k".into()));
            }
        }

        Ok(())
    }

    /// Process a verified deposit from an external chain.
    ///
    /// This is the "L2 → L1 portal" entry point.  The deposit proof
    /// verification is chain-specific and assumed to have been done by
    /// the caller (light client, SPV, committee attestation, etc.).
    ///
    /// Idempotent: reprocessing the same deposit_id is a no-op.
    pub fn process_deposit(
        &mut self,
        state: &mut StateTree,
        deposit_record: &DepositRecord,
    ) -> Result<(), BridgeError> {
        // Dedup: check both in-memory cache and state tree
        if self.is_deposit_processed(state, &deposit_record.deposit_id) {
            return Err(BridgeError::DepositAlreadyProcessed(hex::encode(
                deposit_record.deposit_id,
            )));
        }

        self.check_limits(
            state,
            &deposit_record.asset,
            deposit_record.amount,
            deposit_record.processed_at,
            true,
        )?;

        deposit::process_deposit(state, &self.registry, deposit_record)?;

        self.processed_deposits.insert(deposit_record.deposit_id);
        // Persist to state tree for cross-restart dedup
        let mut marker = [0u8; 32];
        marker[0] = 0x01;
        state.set_storage(&self.bridge_account, deposit_record.deposit_id, marker);
        Ok(())
    }

    /// Check if a deposit has already been processed (in-memory or state tree).
    pub fn is_deposit_processed(&self, state: &StateTree, deposit_hash: &[u8; 32]) -> bool {
        if self.processed_deposits.contains(deposit_hash) {
            return true;
        }
        let stored = state.get_storage(&self.bridge_account, deposit_hash);
        stored[0] == 0x01
    }

    /// Request a withdrawal to an external chain.
    ///
    /// Burns wrapped tokens and creates a withdrawal record that can be
    /// proven against the ACE state root.
    pub fn request_withdrawal(
        &mut self,
        state: &mut StateTree,
        sender: &AccountId,
        intent_id: [u8; 32],
        asset: &ExternalAsset,
        amount: u64,
        external_dest: Vec<u8>,
        current_slot: u64,
    ) -> Result<WithdrawalRecord, BridgeError> {
        self.check_limits(state, asset, amount, current_slot, false)?;

        let record = withdraw::request_withdrawal(
            state,
            &self.registry,
            sender,
            intent_id,
            asset,
            amount,
            external_dest,
            current_slot,
            self.next_withdrawal_id,
        )?;
        self.next_withdrawal_id += 1;
        self.withdrawals.push(record.clone());

        // Update daily total
        let decimals = match asset {
            ExternalAsset::Native(crate::types::ExternalChain::Ethereum)
            | ExternalAsset::Erc20(_) => 18,
            ExternalAsset::Native(crate::types::ExternalChain::Bsc) | ExternalAsset::Bep20(_) => 18,
            ExternalAsset::Native(crate::types::ExternalChain::Solana)
            | ExternalAsset::SplToken(_) => 9,
            ExternalAsset::Native(crate::types::ExternalChain::Tron) | ExternalAsset::Trc20(_) => 6,
            ExternalAsset::Native(crate::types::ExternalChain::Bitcoin) => 8,
        };
        let multiplier = 10u64.pow(decimals as u32);
        let amount_normalized = amount / multiplier.max(1);

        let day_index = current_slot / 86400;
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"ace-daily-out:");
        sha2::Digest::update(&mut hasher, day_index.to_le_bytes());
        let mut slot_key = [0u8; 32];
        slot_key.copy_from_slice(&hasher.finalize());
        let daily_total_bytes = state.get_storage(&self.bridge_account, &slot_key);
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&daily_total_bytes[0..8]);
        let new_daily_total = u64::from_le_bytes(buf) + amount_normalized;
        let mut new_total_bytes = [0u8; 32];
        new_total_bytes[0..8].copy_from_slice(&new_daily_total.to_le_bytes());
        state.set_storage(&self.bridge_account, slot_key, new_total_bytes);

        // Persist next_withdrawal_id to a well-known storage slot
        let mut nwid_slot = [0u8; 32];
        nwid_slot[0..8].copy_from_slice(b"nxt_w_id");
        let mut nwid_val = [0u8; 32];
        nwid_val[0..8].copy_from_slice(&self.next_withdrawal_id.to_le_bytes());
        state.set_storage(&self.bridge_account, nwid_slot, nwid_val);

        Ok(record)
    }

    /// Mark a withdrawal as completed (finalized on external chain).
    pub fn complete_withdrawal(
        &mut self,
        state: &mut StateTree,
        authority: &AccountId,
        withdrawal_id: u64,
    ) -> Result<(), BridgeError> {
        if *authority != bridge_authority_id() {
            return Err(BridgeError::AuthorityMismatch);
        }
        let completed_slot = withdraw::withdrawal_completed_slot(withdrawal_id);
        let stored = state.get_storage(&self.bridge_account, &completed_slot);
        if stored[0] == 0x01 {
            return Err(BridgeError::WithdrawalAlreadyCompleted(
                withdrawal_id.to_string(),
            ));
        }
        let record = self
            .withdrawals
            .iter_mut()
            .find(|r| r.withdrawal_id == withdrawal_id)
            .ok_or_else(|| BridgeError::WithdrawalNotFound(withdrawal_id.to_string()))?;
        if record.completed {
            return Err(BridgeError::WithdrawalAlreadyCompleted(
                withdrawal_id.to_string(),
            ));
        }
        record.completed = true;

        let mut marker = [0u8; 32];
        marker[0] = 0x01;
        state.set_storage(&self.bridge_account, completed_slot, marker);
        crate::wire::mark_indexed_withdrawal_completed(state, withdrawal_id)?;
        Ok(())
    }

    /// Get a withdrawal record by ID.
    pub fn get_withdrawal(&self, withdrawal_id: u64) -> Option<&WithdrawalRecord> {
        self.withdrawals
            .iter()
            .find(|r| r.withdrawal_id == withdrawal_id)
    }

    /// List all pending (not yet completed) withdrawals.
    pub fn pending_withdrawals(&self) -> Vec<&WithdrawalRecord> {
        self.withdrawals.iter().filter(|r| !r.completed).collect()
    }

    pub fn total_deposits_processed(&self) -> usize {
        self.processed_deposits.len()
    }

    pub fn total_withdrawals(&self) -> usize {
        self.withdrawals.len()
    }

    /// Add an approved relayer public key.
    ///
    /// Requires a valid Ed25519 signature from the configured governance key
    /// over the message `b"bridge:add-relayer:v1" || relayer_pubkey`.
    /// This prevents unauthorized addition of relayers.
    ///
    /// For test-only usage without signature verification, use [`add_relayer_unchecked`].
    pub fn add_relayer(
        &mut self,
        pubkey: [u8; 32],
        governance_signature: &[u8; 64],
    ) -> Result<(), BridgeError> {
        // Verify governance signature.
        let mut msg = Vec::with_capacity(21 + 32);
        msg.extend_from_slice(b"bridge:add-relayer:v1");
        msg.extend_from_slice(&pubkey);

        let governance_pubkey = self.governance_pubkey.ok_or_else(|| {
            BridgeError::InvalidDepositProof("bridge governance key not configured".into())
        })?;
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(&governance_pubkey).map_err(|e| {
                BridgeError::InvalidDepositProof(format!("invalid governance key: {e}"))
            })?;
        let signature = ed25519_dalek::Signature::from_bytes(governance_signature);
        verifying_key.verify_strict(&msg, &signature).map_err(|e| {
            BridgeError::InvalidDepositProof(format!("governance signature invalid: {e}"))
        })?;

        if !self.approved_relayers.contains(&pubkey) {
            self.approved_relayers.push(pubkey);
        }
        Ok(())
    }

    /// Add a relayer without governance verification.
    ///
    /// # Safety
    /// Only available with the `test-utils` feature. Do **not** use in production.
    #[cfg(feature = "test-utils")]
    pub fn add_relayer_unchecked(&mut self, pubkey: [u8; 32]) {
        if !self.approved_relayers.contains(&pubkey) {
            self.approved_relayers.push(pubkey);
        }
    }

    /// Check if a public key belongs to an approved relayer.
    pub fn is_approved_relayer(&self, pubkey: &[u8; 32]) -> bool {
        self.approved_relayers.contains(pubkey)
    }

    /// Process a signed deposit with relayer signature verification.
    pub fn process_signed_deposit(
        &mut self,
        state: &mut StateTree,
        signed: &SignedDepositRecord,
    ) -> Result<(), BridgeError> {
        // 1. Check relayer is approved
        if !self.is_approved_relayer(&signed.relayer_pubkey) {
            return Err(BridgeError::InvalidDepositProof(
                "relayer not in approved set".into(),
            ));
        }

        // 2. Verify Ed25519 signature over deposit hash
        crate::wire::verify_signed_deposit_signature(signed)?;

        // 3. Delegate to existing deposit processing (dedup + mint)
        self.process_deposit(state, &signed.deposit)
    }

    /// Process a signed deposit through the consensus system tx path.
    pub fn process_state_approved_signed_deposit(
        &mut self,
        state: &mut StateTree,
        signed: &SignedDepositRecord,
    ) -> Result<(), BridgeError> {
        crate::wire::verify_signed_deposit_against_state(state, signed)?;

        if !self.registry.is_registered(&signed.deposit.asset, state) {
            let decimals = match signed.deposit.asset {
                ExternalAsset::Native(chain) => native_decimals(chain),
                ExternalAsset::Erc20(_) | ExternalAsset::Bep20(_) => 18,
                ExternalAsset::SplToken(_) => 9,
                ExternalAsset::Trc20(_) => 6,
            };
            self.registry
                .register_asset(state, &signed.deposit.asset, decimals)?;
        }

        self.process_deposit(state, &signed.deposit)
    }
}

impl Default for BridgeState {
    fn default() -> Self {
        Self::new()
    }
}
