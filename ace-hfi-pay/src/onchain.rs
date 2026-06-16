//! On-chain HFI Pay hook: consensus-deterministic intent lifecycle.
//!
//! All intent state transitions (Create / Fund / Claim / Expire / Refund)
//! live in `StateTree.hfi_intents` keyed by `intent_id`.  The hook is
//! registered on the n-VM and runs inside block execution, so every
//! validator sees the same `state_root` after each opcode.
//!
//! Wire format of an on-chain intent (version 1, fixed 287 bytes):
//!
//! ```text
//! version(1=0x01) ||
//! intent_id(32) || blinded_binding(32) || amount(8 LE) ||
//! chain_id(1) || mint_present(1) || mint(32) ||
//! deposit_address(32) || binding_epoch(8 LE) || expiry(8 LE) ||
//! refund_dest_present(1)       || refund_dest(32)       ||
//! refund_authorizer_present(1) || refund_authorizer(32) ||
//! created_at(8 LE) || status(1) ||
//! claim_nonce(8 LE) || refund_nonce(8 LE) || withdrawn_amount(8 LE) ||
//! owner_present(1) || owner(32)
//! ```

use std::sync::{Arc, OnceLock};

use ace_engine::executor::TransactionOp;
use ace_engine::receipt::StateChange;
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_n_vm::vm::{HfiPayHook, VmId, VmReceipt};
use ace_runtime::types::transaction::Transaction;

use ace_runtime::crypto::legacy_idcom_evm;
use sha2::{Digest, Sha256};

use crate::address::derive_intent_address;
use crate::intent::{ChainId, IntentStatus, VmAddress};

/// Resolve a finalized transaction by hash (implemented by the node via [`ace_model::block_store::BlockStore`]).
pub trait CommittedTxLookup: Send + Sync {
    fn find_transaction_by_hash(&self, tx_hash: &[u8; 32]) -> Option<Transaction>;
}

/// Byte length of the on-chain intent wire encoding (version 1).
pub const ONCHAIN_INTENT_LEN: usize = 287;

/// Maximum allowed expiry window (≈1 year at 1s slot).
pub const MAX_EXPIRY_WINDOW: u64 = 31_536_000;

/// Compact on-chain projection of an intent.
///
/// Only fields consensus validators need to replay state transitions.
/// Human-friendly metadata (claim_pubkey, refund_auth signatures) is kept
/// off-chain in the relay store because the tx attestation already
/// authorizes the action.
#[derive(Debug, Clone)]
pub struct OnChainIntent {
    pub intent_id: [u8; 32],
    pub blinded_binding: [u8; 32],
    pub amount: u64,
    pub chain: ChainId,
    pub mint: Option<[u8; 32]>,
    pub deposit_address: AccountId,
    pub binding_epoch: u64,
    pub expiry: u64,
    pub refund_dest: Option<AccountId>,
    pub refund_authorizer: Option<AccountId>,
    pub created_at: u64,
    pub status: IntentStatus,
    pub claim_nonce: u64,
    pub refund_nonce: u64,
    pub withdrawn_amount: u64,
    pub owner: Option<AccountId>,
}

impl OnChainIntent {
    fn status_tag(status: IntentStatus) -> u8 {
        match status {
            IntentStatus::Created => 0,
            IntentStatus::Funded => 1,
            IntentStatus::Claimed => 2,
            IntentStatus::Expired => 3,
            IntentStatus::Refunded => 4,
        }
    }

    fn status_from_tag(tag: u8) -> Option<IntentStatus> {
        match tag {
            0 => Some(IntentStatus::Created),
            1 => Some(IntentStatus::Funded),
            2 => Some(IntentStatus::Claimed),
            3 => Some(IntentStatus::Expired),
            4 => Some(IntentStatus::Refunded),
            _ => None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ONCHAIN_INTENT_LEN);
        out.push(0x01);
        out.extend_from_slice(&self.intent_id);
        out.extend_from_slice(&self.blinded_binding);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.push(self.chain.tag());
        match self.mint {
            Some(m) => {
                out.push(1);
                out.extend_from_slice(&m);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
        }
        out.extend_from_slice(self.deposit_address.as_bytes());
        out.extend_from_slice(&self.binding_epoch.to_le_bytes());
        out.extend_from_slice(&self.expiry.to_le_bytes());
        match self.refund_dest {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(id.as_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
        }
        match self.refund_authorizer {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(id.as_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
        }
        out.extend_from_slice(&self.created_at.to_le_bytes());
        out.push(Self::status_tag(self.status));
        out.extend_from_slice(&self.claim_nonce.to_le_bytes());
        out.extend_from_slice(&self.refund_nonce.to_le_bytes());
        out.extend_from_slice(&self.withdrawn_amount.to_le_bytes());
        match self.owner {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(id.as_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
        }
        debug_assert_eq!(out.len(), ONCHAIN_INTENT_LEN);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != ONCHAIN_INTENT_LEN {
            return Err(format!(
                "OnChainIntent: expected {ONCHAIN_INTENT_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        if bytes[0] != 0x01 {
            return Err(format!("OnChainIntent: unknown version {}", bytes[0]));
        }
        let mut p = 1usize;
        let mut intent_id = [0u8; 32];
        intent_id.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let mut blinded_binding = [0u8; 32];
        blinded_binding.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let amount = u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
        p += 8;
        let chain_tag = bytes[p];
        p += 1;
        let chain = ChainId::from_tag(chain_tag)
            .ok_or_else(|| format!("OnChainIntent: invalid chain tag {chain_tag}"))?;
        let mint_present = bytes[p];
        p += 1;
        let mut mint_bytes = [0u8; 32];
        mint_bytes.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let mint = if mint_present != 0 {
            Some(mint_bytes)
        } else {
            None
        };
        let mut dep = [0u8; 32];
        dep.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let deposit_address = AccountId::from_bytes(dep);
        let binding_epoch = u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
        p += 8;
        let expiry = u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
        p += 8;
        let refund_dest_present = bytes[p];
        p += 1;
        let mut rd = [0u8; 32];
        rd.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let refund_dest = if refund_dest_present != 0 {
            Some(AccountId::from_bytes(rd))
        } else {
            None
        };
        let refund_auth_present = bytes[p];
        p += 1;
        let mut ra = [0u8; 32];
        ra.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let refund_authorizer = if refund_auth_present != 0 {
            Some(AccountId::from_bytes(ra))
        } else {
            None
        };
        let created_at = u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
        p += 8;
        let status = Self::status_from_tag(bytes[p])
            .ok_or_else(|| format!("OnChainIntent: invalid status tag {}", bytes[p]))?;
        p += 1;
        let claim_nonce = u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
        p += 8;
        let refund_nonce = u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
        p += 8;
        let withdrawn_amount = u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
        p += 8;
        let owner_present = bytes[p];
        p += 1;
        let mut ow = [0u8; 32];
        ow.copy_from_slice(&bytes[p..p + 32]);
        let owner = if owner_present != 0 {
            Some(AccountId::from_bytes(ow))
        } else {
            None
        };

        Ok(Self {
            intent_id,
            blinded_binding,
            amount,
            chain,
            mint,
            deposit_address,
            binding_epoch,
            expiry,
            refund_dest,
            refund_authorizer,
            created_at,
            status,
            claim_nonce,
            refund_nonce,
            withdrawn_amount,
            owner,
        })
    }
}

fn load_intent(state: &StateTree, intent_id: &[u8; 32]) -> Result<OnChainIntent, String> {
    let bytes = state
        .hfi_intent(intent_id)
        .ok_or_else(|| format!("intent {} not found on chain", hex::encode(intent_id)))?;
    OnChainIntent::decode(bytes)
}

fn store_intent(state: &mut StateTree, intent: &OnChainIntent) {
    state.hfi_intent_put(intent.intent_id, intent.encode());
}

fn deposit_balance_native(state: &StateTree, deposit: &AccountId) -> u64 {
    state.get(deposit).map(|a| a.balance).unwrap_or(0)
}

fn ensure_native_account(state: &mut StateTree, id: AccountId) {
    if !state.contains(&id) {
        state.insert(Account::new(id));
    }
}

/// Transfer native balance; accounts are materialized on demand.
fn native_transfer(
    state: &mut StateTree,
    from: &AccountId,
    to: &AccountId,
    amount: u64,
) -> Result<(u64, u64, u64, u64), String> {
    ensure_native_account(state, *to);
    let from_before = state.get(from).map(|a| a.balance).unwrap_or(0);
    if from_before < amount {
        return Err(format!(
            "insufficient balance at {}: have {from_before}, need {amount}",
            hex::encode(from.as_bytes())
        ));
    }
    let to_before = state.get(to).map(|a| a.balance).unwrap_or(0);
    let from_after = from_before - amount;
    let to_after = to_before
        .checked_add(amount)
        .ok_or_else(|| "balance overflow".to_string())?;

    let from_acct = state
        .get_mut(from)
        .ok_or_else(|| format!("account {} missing", hex::encode(from.as_bytes())))?;
    from_acct.balance = from_after;
    let to_acct = state
        .get_mut(to)
        .ok_or_else(|| format!("account {} missing", hex::encode(to.as_bytes())))?;
    to_acct.balance = to_after;

    Ok((from_before, from_after, to_before, to_after))
}

fn consume_nonce(
    state: &mut StateTree,
    sender: &AccountId,
    nonce: u64,
) -> Result<StateChange, String> {
    let account = state
        .get_mut(sender)
        .ok_or_else(|| format!("sender {} not found", hex::encode(sender.as_bytes())))?;
    if account.nonce != nonce {
        return Err(format!(
            "invalid nonce: expected {}, got {}",
            account.nonce, nonce
        ));
    }
    account.nonce = account
        .nonce
        .checked_add(1)
        .ok_or_else(|| "nonce overflow".to_string())?;
    Ok(StateChange::NonceIncrement {
        account: *sender,
        new_nonce: account.nonce,
    })
}

fn ok_receipt(tx: &Transaction, sender: AccountId, state_changes: Vec<StateChange>) -> VmReceipt {
    VmReceipt {
        vm_id: VmId::AceNative,
        tx_hash: tx.tx_hash(),
        success: true,
        sender,
        state_changes,
        error: None,
        simulated: false,
        gas_used: None,
        contract_address: None,
        return_data: None,
        logs: vec![],
    }
}

/// On-chain HFI Pay hook instance held by the n-VM dispatcher.
pub struct HfiPayOnChainHook {
    /// Serialized Groth16 verifying key (matches the browser-side proving key
    /// rotation).  Wrapped in `Arc` so node hot-reload can swap keys without
    /// rebuilding the n-VM.
    pub vk_bytes: Arc<Vec<u8>>,
    /// Used to validate `HfiPayFund.deposit_evidence` against a committed native transfer.
    pub committed_tx: Option<Arc<dyn CommittedTxLookup>>,
    /// Authorized HFI-Pay claim relay account.
    ///
    /// The on-chain claim authorization is a `blinded_binding` preimage
    /// (`auth_commitment`) revealed in the tx payload, while the destination is
    /// supplied by the submitter and is NOT bound by that preimage. Without a
    /// gate, a mempool observer can lift `auth_commitment` from a pending claim
    /// and front-run it with their own destination to steal the funds.
    ///
    /// When set, claims must be submitted by this relay account: the dispatcher
    /// verifies the relay's attestation signature over the full claim payload
    /// (including `destination`), so an attacker cannot re-point the destination
    /// without forging the relay's signature. `None` keeps the legacy
    /// (unauthenticated) behavior for devnet and is logged as a warning.
    pub claim_relay: Option<AccountId>,
}

fn compute_refund_message(
    chain_tag: u8,
    mint: Option<&[u8; 32]>,
    intent_id: &[u8; 32],
    blinded_binding: &[u8; 32],
    amount: u64,
    refund_authorizer: &[u8],
    refund_dest: &[u8],
    expiry: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hfipay:refund");
    hasher.update(b"ace-hfi-pay:v1");
    hasher.update([chain_tag]);
    match mint {
        Some(m) => {
            hasher.update([1u8]);
            hasher.update(m);
        }
        None => {
            hasher.update([0u8]);
        }
    }
    hasher.update(intent_id);
    hasher.update(blinded_binding);
    hasher.update(amount.to_le_bytes());
    hasher.update(refund_authorizer);
    hasher.update(refund_dest);
    hasher.update(expiry.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

impl HfiPayOnChainHook {
    pub fn new(vk_bytes: Arc<Vec<u8>>, committed_tx: Option<Arc<dyn CommittedTxLookup>>) -> Self {
        Self {
            vk_bytes,
            committed_tx,
            claim_relay: None,
        }
    }

    /// Set the authorized claim relay account (see [`HfiPayOnChainHook::claim_relay`]).
    pub fn with_claim_relay(mut self, claim_relay: Option<AccountId>) -> Self {
        self.claim_relay = claim_relay;
        self
    }

    fn handle_create(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
        block_slot: u64,
    ) -> Result<VmReceipt, String> {
        let op = TransactionOp::decode(&tx.payload).map_err(|e| e.to_string())?;
        let (
            nonce,
            intent_id,
            blinded_binding,
            amount,
            chain_id,
            mint_raw,
            deposit_address_raw,
            binding_epoch,
            expiry_slot,
            refund_dest_raw,
            refund_authorizer_raw,
            identity_commitment,
        ) = match op {
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
            } => (
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
            ),
            _ => return Err("not an HfiPayCreate op".into()),
        };

        if amount == 0 {
            return Err("amount must be non-zero".into());
        }
        if expiry_slot > block_slot.saturating_add(MAX_EXPIRY_WINDOW) {
            return Err("expiry too far in the future".into());
        }
        if state.hfi_intent(&intent_id).is_some() {
            return Err("intent already exists".into());
        }
        let chain =
            ChainId::from_tag(chain_id).ok_or_else(|| format!("invalid chain_id {chain_id}"))?;

        // ── Auto-claim short-circuit ─────────────────────────────────────────
        // If the recipient identified by `identity_commitment` is already
        // registered on-chain, route funds directly from the sender to the
        // recipient's `account_id` and emit a single intent in `Claimed`
        // state. The sender pays gas and supplies funds; no separate
        // Fund / Claim transactions are needed. Maintains the HFI Pay
        // semantics: intent record is preserved (auditability) while the
        // settlement is atomic.
        if identity_commitment != [0u8; 32] {
            if let Some((_, recipient_bytes)) = state.hfi_recipient_by_idcom(&identity_commitment) {
                let decoded = decode_recipient_record(recipient_bytes)?;
                if decoded.identity_commitment != identity_commitment {
                    return Err("registry idcom index inconsistent with stored record".into());
                }

                let sender = AccountId::from_bytes(tx.attestation.idcom);

                let mint = if mint_raw == [0u8; 32] {
                    None
                } else {
                    Some(mint_raw)
                };

                // Native-only auto-claim for now. Reject token mints before
                // consuming the nonce so the caller can resubmit unchanged.
                if mint.is_some() {
                    return Err("auto-claim not yet supported for non-native mints; \
                         resubmit with identity_commitment = 0 to use the \
                         standard claim flow (nonce NOT consumed)"
                        .into());
                }

                let nonce_change = consume_nonce(state, &sender, nonce)?;

                let recipient_acct = decoded.account_id;
                let (sender_before, sender_after, recip_before, recip_after) =
                    native_transfer(state, &sender, &recipient_acct, amount)?;

                // Record an intent in Claimed state for audit. deposit_address
                // is set to the recipient (no escrow) and withdrawn = amount.
                // The registry's `binding_epoch` is canonical; the payload's
                // value is treated as a hint and overwritten so audit tooling
                // and downstream replay use the registered epoch consistently.
                let intent = OnChainIntent {
                    intent_id,
                    blinded_binding,
                    amount,
                    chain,
                    mint,
                    deposit_address: recipient_acct,
                    binding_epoch: decoded.binding_epoch,
                    expiry: expiry_slot,
                    refund_dest: None,
                    refund_authorizer: None,
                    created_at: block_slot,
                    status: IntentStatus::Claimed,
                    claim_nonce: 0,
                    refund_nonce: 0,
                    withdrawn_amount: amount,
                    owner: Some(recipient_acct),
                };
                store_intent(state, &intent);
                let _ = binding_epoch; // silence unused-variable on registry hit

                // Compute claim_tag for the audit receipt.
                // NOTE: this uses a salt-free domain-separated hash, which
                // differs from handle_claim's ACE_CLAIM_SALT-based hash.
                // The two paths are intentionally separate: auto-claim is
                // relay-free and doesn't need the relay's salt; handle_claim
                // requires the salt to authenticate the relay's involvement.
                // Do NOT unify without coordinating the relay's receipt format.
                let claim_tag = {
                    let mut h = Sha256::new();
                    h.update(b"ace:claim:tag:v1");
                    h.update(&intent_id);
                    let r = h.finalize();
                    let mut t = [0u8; 32];
                    t.copy_from_slice(&r);
                    t
                };

                let changes = vec![
                    nonce_change,
                    StateChange::BalanceChange {
                        account: sender,
                        old: sender_before,
                        new: sender_after,
                    },
                    StateChange::BalanceChange {
                        account: recipient_acct,
                        old: recip_before,
                        new: recip_after,
                    },
                    StateChange::IntentChange {
                        intent_id,
                        old_status: 0xFF,
                        new_status: OnChainIntent::status_tag(IntentStatus::Claimed),
                        claim_tag: Some(claim_tag),
                    },
                ];
                return Ok(ok_receipt(tx, sender, changes));
            }
        }
        // ─────────────────────────────────────────────────────────────────────
        let mint = if mint_raw == [0u8; 32] {
            None
        } else {
            Some(mint_raw)
        };
        let deposit_address = AccountId::from_bytes(deposit_address_raw);
        let expected_deposit = derive_intent_address(chain, &intent_id);
        if deposit_address != expected_deposit {
            return Err(format!(
                "deposit_address does not match derived address for this intent: expected {}, got {}",
                hex::encode(expected_deposit.as_bytes()),
                hex::encode(deposit_address.as_bytes())
            ));
        }
        let refund_dest = if refund_dest_raw == [0u8; 32] {
            None
        } else {
            Some(AccountId::from_bytes(refund_dest_raw))
        };
        let refund_authorizer = if refund_authorizer_raw == [0u8; 32] {
            None
        } else {
            Some(AccountId::from_bytes(refund_authorizer_raw))
        };
        match (refund_dest, refund_authorizer) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => return Err("refund_dest and refund_authorizer must be set together".into()),
        }

        let sender = AccountId::from_bytes(tx.attestation.idcom);
        let nonce_change = consume_nonce(state, &sender, nonce)?;

        // Materialize the deposit account so later Fund / Claim can transfer.
        ensure_native_account(state, deposit_address);

        let intent = OnChainIntent {
            intent_id,
            blinded_binding,
            amount,
            chain,
            mint,
            deposit_address,
            binding_epoch,
            expiry: expiry_slot,
            refund_dest,
            refund_authorizer,
            created_at: block_slot,
            status: IntentStatus::Created,
            claim_nonce: 0,
            refund_nonce: 0,
            withdrawn_amount: 0,
            owner: None,
        };
        store_intent(state, &intent);

        let mut changes = vec![nonce_change];
        changes.push(StateChange::IntentChange {
            intent_id,
            old_status: 0xFF,
            new_status: OnChainIntent::status_tag(IntentStatus::Created),
            claim_tag: None,
        });
        Ok(ok_receipt(tx, sender, changes))
    }

    fn handle_fund(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
        _block_slot: u64,
    ) -> Result<VmReceipt, String> {
        let op = TransactionOp::decode(&tx.payload).map_err(|e| e.to_string())?;
        let (nonce, intent_id, deposit_evidence, deposit_amount) = match op {
            TransactionOp::HfiPayFund {
                nonce,
                intent_id,
                deposit_evidence,
                deposit_amount,
            } => (nonce, intent_id, deposit_evidence, deposit_amount),
            _ => return Err("not an HfiPayFund op".into()),
        };

        let mut intent = load_intent(state, &intent_id)?;
        if intent.status != IntentStatus::Created {
            return Err(format!(
                "intent not in Created state (is {:?})",
                intent.status
            ));
        }
        if deposit_amount != intent.amount {
            return Err(format!(
                "deposit_amount {deposit_amount} must match intent amount {}",
                intent.amount
            ));
        }
        if deposit_evidence == [0u8; 32] {
            return Err("deposit_evidence (funding transfer tx hash) required".into());
        }

        let lookup = self.committed_tx.as_ref().ok_or_else(|| {
            "HfiPayFund requires committed_tx lookup (node must attach block store)".to_string()
        })?;
        let dep_tx = lookup
            .find_transaction_by_hash(&deposit_evidence)
            .ok_or_else(|| {
                format!(
                    "deposit_evidence tx {} not found in block store",
                    hex::encode(deposit_evidence)
                )
            })?;

        let fund_sender = AccountId::from_bytes(tx.attestation.idcom);
        let dep_sender = AccountId::from_bytes(dep_tx.attestation.idcom);
        if dep_sender != fund_sender {
            return Err("deposit evidence tx sender must match fund tx sender (same idcom)".into());
        }
        if let Some(ref ra) = intent.refund_authorizer {
            if fund_sender != *ra {
                return Err(
                    "fund transaction sender must match intent refund_authorizer when refund metadata is set"
                        .into(),
                );
            }
        }

        let dep_op = TransactionOp::decode(&dep_tx.payload).map_err(|e| e.to_string())?;
        match dep_op {
            TransactionOp::Transfer {
                to,
                amount: transfer_amt,
                ..
            } => {
                if to != intent.deposit_address {
                    return Err(
                        "deposit evidence is not a transfer to the intent deposit address".into(),
                    );
                }
                if transfer_amt != intent.amount {
                    return Err(format!(
                        "deposit transfer amount {transfer_amt} must match intent amount {}",
                        intent.amount
                    ));
                }
            }
            _ => return Err("deposit evidence must be a native Transfer (0x01)".into()),
        }

        let have = deposit_balance_native(state, &intent.deposit_address);
        if have < intent.amount {
            return Err(format!(
                "intent underfunded: have {have}, need {}",
                intent.amount
            ));
        }

        let sender = fund_sender;
        let nonce_change = consume_nonce(state, &sender, nonce)?;

        let old_status = OnChainIntent::status_tag(intent.status);
        intent.status = IntentStatus::Funded;
        let new_status = OnChainIntent::status_tag(intent.status);
        store_intent(state, &intent);

        Ok(ok_receipt(
            tx,
            sender,
            vec![
                nonce_change,
                StateChange::IntentChange {
                    intent_id,
                    old_status,
                    new_status,
                    claim_tag: None,
                },
            ],
        ))
    }

    fn handle_expire(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
        block_slot: u64,
    ) -> Result<VmReceipt, String> {
        let op = TransactionOp::decode(&tx.payload).map_err(|e| e.to_string())?;
        let intent_id = match op {
            TransactionOp::HfiPayExpire { intent_id } => intent_id,
            _ => return Err("not an HfiPayExpire op".into()),
        };

        let mut intent = load_intent(state, &intent_id)?;
        if intent.status != IntentStatus::Funded {
            return Err(format!(
                "intent not in Funded state (is {:?})",
                intent.status
            ));
        }
        if block_slot <= intent.expiry {
            return Err(format!(
                "intent not yet expired: slot {block_slot} <= expiry {}",
                intent.expiry
            ));
        }

        let sender = AccountId::from_bytes(tx.attestation.idcom);
        let old_status = OnChainIntent::status_tag(intent.status);
        intent.status = IntentStatus::Expired;
        let new_status = OnChainIntent::status_tag(intent.status);
        store_intent(state, &intent);

        Ok(ok_receipt(
            tx,
            sender,
            vec![StateChange::IntentChange {
                intent_id,
                old_status,
                new_status,
                claim_tag: None,
            }],
        ))
    }

    fn handle_refund(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
        block_slot: u64,
    ) -> Result<VmReceipt, String> {
        let op = TransactionOp::decode(&tx.payload).map_err(|e| e.to_string())?;
        let (nonce, intent_id, refund_auth_payload) = match op {
            TransactionOp::HfiPayRefund {
                nonce,
                intent_id,
                refund_auth,
            } => (nonce, intent_id, refund_auth),
            _ => return Err("not an HfiPayRefund op".into()),
        };

        let mut intent = load_intent(state, &intent_id)?;

        // Accept Expired, or Funded/Created past expiry when refund_auth is present
        // (allows relay to atomically expire-and-refund without a separate 0x09 tx).
        let already_expired = intent.status == IntentStatus::Expired;
        let funded_past_expiry = refund_auth_payload.is_some()
            && matches!(intent.status, IntentStatus::Funded | IntentStatus::Created)
            && block_slot > intent.expiry;
        if !already_expired && !funded_past_expiry {
            return Err(format!(
                "intent not eligible for refund (status={:?}, slot={}, expiry={})",
                intent.status, block_slot, intent.expiry
            ));
        }

        let refund_dest = intent
            .refund_dest
            .ok_or_else(|| "intent has no refund destination".to_string())?;
        let refund_authorizer = intent
            .refund_authorizer
            .ok_or_else(|| "intent has no refund authorizer".to_string())?;

        let sender = AccountId::from_bytes(tx.attestation.idcom);

        // Authorization: ML-DSA-44 refund_auth (relay path) or tx.sender == refund_authorizer.
        // Returns None for the relay path (no account nonce consumed; replay protection is
        // provided by the intent status transition Funded→Refunded).
        let nonce_change: Option<StateChange> =
            if let Some((pk_bytes, sig_bytes)) = refund_auth_payload {
                // nonce must equal intent.refund_nonce (replay protection without consuming relay account nonce).
                if nonce != intent.refund_nonce {
                    return Err(format!(
                        "refund_auth nonce mismatch: got {}, expected {}",
                        nonce, intent.refund_nonce
                    ));
                }
                let refund_msg = compute_refund_message(
                    intent.chain.tag(),
                    intent.mint.as_ref(),
                    &intent_id,
                    &intent.blinded_binding,
                    intent.amount,
                    refund_authorizer.as_bytes(),
                    refund_dest.as_bytes(),
                    intent.expiry,
                    nonce,
                );
                use ace_runtime::crypto::sig_algo::{
                    verify_signature, SignatureAlgorithm, TaggedPubkey, TaggedSignature,
                };
                if pk_bytes.len() != 1312 {
                    return Err(format!(
                        "refund_auth: unexpected pubkey length {}",
                        pk_bytes.len()
                    ));
                }
                if sig_bytes.len() != 2420 {
                    return Err(format!(
                        "refund_auth: unexpected sig length {}",
                        sig_bytes.len()
                    ));
                }
                // Bind: the ML-DSA-44 pubkey must match refund_authorizer's registered on-chain key.
                let authorizer_ml_dsa_key = state
                    .get(&refund_authorizer)
                    .and_then(|a| {
                        a.auth_key_for_algorithm(SignatureAlgorithm::MlDsa44)
                            .cloned()
                    })
                    .ok_or_else(|| {
                        "refund_auth: refund_authorizer has no ML-DSA-44 key on chain".to_string()
                    })?;
                if authorizer_ml_dsa_key.bytes != pk_bytes {
                    return Err(
                    "refund_auth: pubkey does not match refund_authorizer's on-chain ML-DSA-44 key"
                        .into(),
                );
                }
                let pk = TaggedPubkey::ml_dsa_44(pk_bytes);
                let sig = TaggedSignature::ml_dsa_44(sig_bytes);
                if !verify_signature(&pk, &refund_msg, &sig) {
                    return Err("refund_auth signature verification failed".into());
                }
                None
            } else {
                if sender != refund_authorizer {
                    return Err("sender is not the refund authorizer".into());
                }
                Some(consume_nonce(state, &sender, nonce)?)
            };

        let (dep_before, dep_after, dest_before, dest_after) =
            native_transfer(state, &intent.deposit_address, &refund_dest, intent.amount)?;

        let old_status = OnChainIntent::status_tag(intent.status);
        intent.status = IntentStatus::Refunded;
        intent.withdrawn_amount = intent
            .withdrawn_amount
            .checked_add(intent.amount)
            .ok_or_else(|| "withdrawn overflow".to_string())?;
        intent.refund_nonce = intent
            .refund_nonce
            .checked_add(1)
            .ok_or_else(|| "refund nonce overflow".to_string())?;
        let new_status = OnChainIntent::status_tag(intent.status);
        store_intent(state, &intent);

        let mut changes = vec![
            StateChange::BalanceChange {
                account: intent.deposit_address,
                old: dep_before,
                new: dep_after,
            },
            StateChange::BalanceChange {
                account: refund_dest,
                old: dest_before,
                new: dest_after,
            },
            StateChange::IntentChange {
                intent_id,
                old_status,
                new_status,
                claim_tag: None,
            },
        ];
        if let Some(nc) = nonce_change {
            changes.insert(0, nc);
        }
        Ok(ok_receipt(tx, sender, changes))
    }

    fn handle_claim(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
        block_slot: u64,
    ) -> Result<VmReceipt, String> {
        let op = TransactionOp::decode(&tx.payload).map_err(|e| e.to_string())?;
        let (intent_id, dest_wire, destination_auth, auth_commitment) = match op {
            TransactionOp::HfiPayClaim {
                intent_id,
                destination,
                destination_auth,
                auth_commitment,
            } => (intent_id, destination, destination_auth, auth_commitment),
            _ => return Err("not an HfiPayClaim op".into()),
        };

        // Front-running guard: `auth_commitment` is a bearer preimage revealed in
        // the payload and the destination is NOT bound by it, so without a gate a
        // mempool observer could lift `auth_commitment` and re-point the claim to
        // their own destination. Require the claim to come from the authorized
        // relay account; the dispatcher has already verified the relay's
        // attestation signature over this payload (including `destination`), so
        // the destination cannot be altered without forging the relay's signature.
        match self.claim_relay {
            Some(relay) => {
                let sender = AccountId::from_bytes(tx.attestation.idcom);
                if sender != relay {
                    return Err("HFI claim must be submitted by the authorized relay".into());
                }
            }
            None => {
                tracing::warn!(
                    "HFI claim relay not configured — claims are unauthenticated and \
                     front-runnable; set the claim relay for any non-devnet deployment"
                );
            }
        }

        let mut intent = load_intent(state, &intent_id)?;
        if intent.status != IntentStatus::Funded {
            return Err(format!(
                "intent not in Funded state (is {:?})",
                intent.status
            ));
        }
        if block_slot > intent.expiry {
            return Err("intent expired".into());
        }

        // AR-ACE proof-off-path: relay verified the ZK proof; chain verifies binding deterministically.
        // blinded_binding = SHA-256("hfipay:bind" || auth_commitment || intent_id)
        let derived_blinded_binding = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"hfipay:bind");
            h.update(auth_commitment);
            h.update(intent_id);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        if derived_blinded_binding != intent.blinded_binding {
            return Err("auth_commitment does not match intent blinded_binding".into());
        }

        let destination = vm_address_from_raw(intent.chain, &dest_wire)?;

        // Materialize destination account.
        let destination_id = match destination {
            VmAddress::Native(id) => {
                if let Some(pk) = destination_auth.as_ref().filter(|k| !k.is_zero()) {
                    let mut account = state
                        .get(&id)
                        .cloned()
                        .unwrap_or_else(|| Account::with_auth(id, 0, pk.clone()));
                    if account.auth_pubkey.is_zero() {
                        account.auth_pubkey = pk.clone();
                    }
                    state.insert(account);
                } else {
                    ensure_native_account(state, id);
                }
                id
            }
            VmAddress::Evm(addr) => {
                let id = AccountId::from_bytes(legacy_idcom_evm(&addr));
                ensure_native_account(state, id);
                id
            }
            VmAddress::Svm(id) => {
                ensure_native_account(state, id);
                id
            }
            _ => return Err("unsupported destination chain for Claim".into()),
        };

        // Transfer deposit → destination.
        let (dep_before, dep_after, dest_before, dest_after) = native_transfer(
            state,
            &intent.deposit_address,
            &destination_id,
            intent.amount,
        )?;

        // Update intent state.
        let old_status = OnChainIntent::status_tag(intent.status);
        intent.status = IntentStatus::Claimed;
        intent.owner = Some(destination_id);
        intent.withdrawn_amount = intent
            .withdrawn_amount
            .checked_add(intent.amount)
            .ok_or_else(|| "withdrawn overflow".to_string())?;
        intent.claim_nonce = intent
            .claim_nonce
            .checked_add(1)
            .ok_or_else(|| "claim nonce overflow".to_string())?;
        let new_status = OnChainIntent::status_tag(intent.status);
        store_intent(state, &intent);

        // Compute claim_tag at execution time so it is recorded in the block receipt.
        // All validators must have ACE_CLAIM_SALT set to the same value.
        //
        // TODO: thread `claim_salt` through executor/genesis config so it is
        // consensus-committed and validators cannot diverge. The OnceLock below is a
        // stop-gap: it reads the env var once at startup, which at least prevents
        // per-call variance within a single process, but cross-node divergence is
        // still possible if operators set different values.
        static CLAIM_SALT: OnceLock<Option<String>> = OnceLock::new();
        let claim_tag = {
            use sha2::{Digest, Sha256};
            let cached = CLAIM_SALT.get_or_init(|| std::env::var("ACE_CLAIM_SALT").ok());
            let salt = cached
                .as_deref()
                .ok_or_else(|| "ACE_CLAIM_SALT is not configured".to_string())?;
            let mut h = Sha256::new();
            h.update(intent_id);
            h.update(salt.as_bytes());
            h.finalize().into()
        };

        let sender = AccountId::from_bytes(tx.attestation.idcom);
        Ok(ok_receipt(
            tx,
            sender,
            vec![
                StateChange::BalanceChange {
                    account: intent.deposit_address,
                    old: dep_before,
                    new: dep_after,
                },
                StateChange::BalanceChange {
                    account: destination_id,
                    old: dest_before,
                    new: dest_after,
                },
                StateChange::IntentChange {
                    intent_id,
                    old_status,
                    new_status,
                    claim_tag: Some(claim_tag),
                },
            ],
        ))
    }

    /// Handle `0x0B HfiPayRegisterRecipient` — verify the recipient's v2
    /// signature over `(xid || identifier || idcom || handle || epoch)`,
    /// then commit the registration to consensus state via
    /// `StateTree::hfi_recipient_put`. Idempotent: re-registering with new
    /// metadata simply overwrites the previous record.
    ///
    /// Authorization rules:
    /// - The transaction's `tx.attestation.idcom` (sender) consumes its own
    ///   nonce, so a relay can submit on behalf of the recipient. The
    ///   *registration message* is signed by the recipient's chain key
    ///   (carried in payload), independently of the tx sender.
    fn handle_register_recipient(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
        block_slot: u64,
    ) -> Result<VmReceipt, String> {
        use ace_runtime::crypto::idcom_xid;
        use ace_runtime::crypto::sig_algo::{verify_signature, TaggedPubkey, TaggedSignature};

        let op = TransactionOp::decode(&tx.payload).map_err(|e| e.to_string())?;
        let (
            nonce,
            xid,
            identifier,
            identity_commitment,
            claim_binding_handle,
            binding_epoch,
            chain_tag,
            valid_until_slot,
            pubkey_wire,
            signature_wire,
        ) = match op {
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
            } => (
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
            ),
            _ => return Err("not an HfiPayRegisterRecipient op".into()),
        };

        // Reject registrations targeting a different chain tag (cross-chain
        // replay protection) and registrations whose validity window has
        // already closed (bearer-credential lifetime cap).
        if chain_tag != ChainId::Native.tag() {
            return Err(format!(
                "register: chain_tag {chain_tag} does not match this chain ({})",
                ChainId::Native.tag()
            ));
        }
        if block_slot > valid_until_slot {
            return Err(format!(
                "register: registration expired (slot {block_slot} > valid_until {valid_until_slot})"
            ));
        }

        if identifier.is_empty() {
            return Err("identifier must not be empty".into());
        }
        // Bound identifier length to keep StateTree leaves cheap and to prevent
        // a single registration from bloating the consensus state. 256 bytes
        // covers any realistic email / phone / handle.
        if identifier.len() > MAX_REGISTER_IDENTIFIER_LEN {
            return Err(format!(
                "identifier too long: {} bytes > max {MAX_REGISTER_IDENTIFIER_LEN}",
                identifier.len()
            ));
        }

        // Verify recipient's signature over the v2 registration message.
        let pubkey_tagged = TaggedPubkey::from_wire_bytes(&pubkey_wire)
            .map_err(|e| format!("invalid pubkey wire: {e}"))?
            .0;
        let signature_tagged = TaggedSignature::from_wire_bytes(&signature_wire)
            .map_err(|e| format!("invalid signature wire: {e}"))?
            .0;
        let msg = crate::registry::registration_message_v2(
            &xid,
            &identifier,
            &identity_commitment,
            &claim_binding_handle,
            binding_epoch,
            chain_tag,
            valid_until_slot,
        );
        if !verify_signature(&pubkey_tagged, &msg, &signature_tagged) {
            return Err("registration signature verification failed".into());
        }

        // ── Anti-hijack: bind registration to xid ownership ─────────────────
        // The signature alone proves the *holder of `pubkey_tagged`* signed
        // over `(xid, identifier, idcom, handle, epoch)`. Without an
        // additional check, anyone could sign a registration over a victim's
        // xid+idcom and redirect future intents to their own account. We
        // require the signer's pubkey to be one of the auth keys already
        // recorded on the recipient's on-chain account (which is keyed by
        // `idcom_xid(xid)`) — that account's auth keys can only be set via
        // the recipient's own mnemonic-derived key (CreateAccount /
        // SetAuthPubkey paths), so this proves ownership of `xid`.
        let account_id = AccountId::from_bytes(idcom_xid(&xid));
        let recipient_account = state.get(&account_id).ok_or_else(|| {
            "register: recipient account not found on-chain — \
                 create the account and register an auth key for this xid \
                 before enrolling auto-claim"
                .to_string()
        })?;
        let xid_owns_pubkey = recipient_account
            .all_auth_keys()
            .into_iter()
            .any(|k| k.algorithm == pubkey_tagged.algorithm && k.bytes == pubkey_tagged.bytes);
        if !xid_owns_pubkey {
            return Err(
                "register: signer pubkey is not an auth key for the account \
                 derived from xid; refusing potentially-hijacked registration"
                    .into(),
            );
        }

        // Encode the record and commit to StateTree.
        let id_hash = onchain_id_hash(&identifier);
        let record_bytes = encode_recipient_record(
            &xid,
            &account_id,
            &identity_commitment,
            &claim_binding_handle,
            binding_epoch,
            &pubkey_wire,
            &signature_wire,
        );
        state.hfi_recipient_put(id_hash, identity_commitment, record_bytes);

        // Consume the tx sender's nonce (replay protection).
        let sender = AccountId::from_bytes(tx.attestation.idcom);
        let nonce_change = consume_nonce(state, &sender, nonce)?;

        Ok(ok_receipt(tx, sender, vec![nonce_change]))
    }
}

impl HfiPayHook for HfiPayOnChainHook {
    fn execute(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
        block_slot: u64,
    ) -> Result<VmReceipt, String> {
        if tx.payload.is_empty() {
            return Err("empty payload".into());
        }
        match tx.payload[0] {
            0x06 => self.handle_claim(state, tx, block_slot),
            0x07 => self.handle_create(state, tx, block_slot),
            0x08 => self.handle_fund(state, tx, block_slot),
            0x09 => self.handle_expire(state, tx, block_slot),
            0x0A => self.handle_refund(state, tx, block_slot),
            0x0B => self.handle_register_recipient(state, tx, block_slot),
            other => Err(format!("HfiPayHook: unsupported opcode 0x{other:02x}")),
        }
    }
}

/// Domain separator for on-chain identifier hashing (v1).
/// Deterministic across all validators — no random salt.
const HFI_ID_HASH_DOMAIN_V1: &[u8] = b"hfipay:idhash:v1";

/// Hard cap on the raw identifier length accepted by
/// `HfiPayRegisterRecipient`. Each registration adds a permanent leaf to
/// consensus state — bounding the identifier prevents state-bloat DoS.
pub const MAX_REGISTER_IDENTIFIER_LEN: usize = 256;

/// Compute the deterministic, on-chain identifier hash. Stored as the
/// primary key of the recipient registry leaf in `StateTree`.
pub fn onchain_id_hash(identifier: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HFI_ID_HASH_DOMAIN_V1);
    hasher.update(identifier);
    let result = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&result);
    h
}

/// Encode a registered recipient for storage in `StateTree.hfi_recipients`.
///
/// Layout (little-endian for integers, length-prefixed `u16` for
/// variable-length tagged-key/sig wire bytes):
///
/// ```text
/// [0..32]    xid
/// [32..64]   account_id  (= idcom_xid(xid))
/// [64..96]   identity_commitment
/// [96..128]  claim_binding_handle
/// [128..136] binding_epoch (u64 LE)
/// [136..138] pubkey_len (u16 LE)
/// [138..138+pk_len] pubkey wire bytes
/// [..]       sig_len (u16 LE) + signature wire bytes
/// ```
///
/// The 32-byte `identity_commitment` slice MUST start at offset 64 — this is
/// load-bearing for `StateTree::hfi_recipient_put`, which uses bytes 64..96
/// to maintain the secondary `idcom → id_hash` index.
pub fn encode_recipient_record(
    xid: &[u8; 32],
    account_id: &AccountId,
    identity_commitment: &[u8; 32],
    claim_binding_handle: &[u8; 32],
    binding_epoch: u64,
    pubkey_wire: &[u8],
    signature_wire: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128 + 8 + 2 + pubkey_wire.len() + 2 + signature_wire.len());
    buf.extend_from_slice(xid);
    buf.extend_from_slice(account_id.as_bytes());
    buf.extend_from_slice(identity_commitment);
    buf.extend_from_slice(claim_binding_handle);
    buf.extend_from_slice(&binding_epoch.to_le_bytes());
    buf.extend_from_slice(&(pubkey_wire.len() as u16).to_le_bytes());
    buf.extend_from_slice(pubkey_wire);
    buf.extend_from_slice(&(signature_wire.len() as u16).to_le_bytes());
    buf.extend_from_slice(signature_wire);
    buf
}

/// Decoded view over an on-chain registered recipient record.
#[derive(Debug, Clone)]
pub struct DecodedRecipient {
    pub xid: [u8; 32],
    pub account_id: AccountId,
    pub identity_commitment: [u8; 32],
    pub claim_binding_handle: [u8; 32],
    pub binding_epoch: u64,
}

/// Decode the fixed-prefix fields (xid, account_id, idcom, handle, epoch).
/// Ignores the trailing pubkey/signature blobs (audit data only).
pub fn decode_recipient_record(bytes: &[u8]) -> Result<DecodedRecipient, String> {
    if bytes.len() < 136 {
        return Err(format!(
            "registered recipient record too short: {} < 136 bytes",
            bytes.len()
        ));
    }
    let mut xid = [0u8; 32];
    xid.copy_from_slice(&bytes[0..32]);
    let mut acct = [0u8; 32];
    acct.copy_from_slice(&bytes[32..64]);
    let mut ic = [0u8; 32];
    ic.copy_from_slice(&bytes[64..96]);
    let mut handle = [0u8; 32];
    handle.copy_from_slice(&bytes[96..128]);
    let binding_epoch = u64::from_le_bytes(bytes[128..136].try_into().unwrap());
    Ok(DecodedRecipient {
        xid,
        account_id: AccountId::from_bytes(acct),
        identity_commitment: ic,
        claim_binding_handle: handle,
        binding_epoch,
    })
}

fn vm_address_from_raw(chain: ChainId, dest: &[u8]) -> Result<VmAddress, String> {
    match chain {
        ChainId::Native | ChainId::Svm | ChainId::Bvm => {
            if dest.len() != 32 {
                return Err(format!(
                    "destination must be 32 bytes for chain {chain:?}, got {}",
                    dest.len()
                ));
            }
            let mut b = [0u8; 32];
            b.copy_from_slice(dest);
            let id = AccountId::from_bytes(b);
            match chain {
                ChainId::Native => Ok(VmAddress::Native(id)),
                ChainId::Svm => Ok(VmAddress::Svm(id)),
                ChainId::Bvm => Ok(VmAddress::Bvm(id)),
                _ => unreachable!(),
            }
        }
        ChainId::Evm | ChainId::Tvm => {
            if dest.len() != 20 {
                return Err(format!(
                    "destination must be 20 bytes for chain {chain:?}, got {}",
                    dest.len()
                ));
            }
            let mut a = [0u8; 20];
            a.copy_from_slice(dest);
            match chain {
                ChainId::Evm => Ok(VmAddress::Evm(a)),
                ChainId::Tvm => Ok(VmAddress::Tvm(a)),
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onchain_intent_roundtrip() {
        let intent = OnChainIntent {
            intent_id: [1u8; 32],
            blinded_binding: [2u8; 32],
            amount: 1_000_000,
            chain: ChainId::Native,
            mint: None,
            deposit_address: AccountId::from_bytes([3u8; 32]),
            binding_epoch: 42,
            expiry: 100_000,
            refund_dest: Some(AccountId::from_bytes([4u8; 32])),
            refund_authorizer: Some(AccountId::from_bytes([5u8; 32])),
            created_at: 1,
            status: IntentStatus::Funded,
            claim_nonce: 0,
            refund_nonce: 0,
            withdrawn_amount: 0,
            owner: None,
        };
        let bytes = intent.encode();
        assert_eq!(bytes.len(), ONCHAIN_INTENT_LEN);
        let decoded = OnChainIntent::decode(&bytes).expect("decode");
        assert_eq!(decoded.intent_id, intent.intent_id);
        assert_eq!(decoded.blinded_binding, intent.blinded_binding);
        assert_eq!(decoded.amount, intent.amount);
        assert_eq!(decoded.chain, intent.chain);
        assert_eq!(decoded.mint, intent.mint);
        assert_eq!(decoded.deposit_address, intent.deposit_address);
        assert_eq!(decoded.binding_epoch, intent.binding_epoch);
        assert_eq!(decoded.expiry, intent.expiry);
        assert_eq!(decoded.refund_dest, intent.refund_dest);
        assert_eq!(decoded.refund_authorizer, intent.refund_authorizer);
        assert_eq!(decoded.status, intent.status);
    }

    #[test]
    fn onchain_intent_mint_some_vs_none_differ() {
        let base = OnChainIntent {
            intent_id: [1u8; 32],
            blinded_binding: [0u8; 32],
            amount: 1,
            chain: ChainId::Native,
            mint: None,
            deposit_address: AccountId::from_bytes([0u8; 32]),
            binding_epoch: 0,
            expiry: 0,
            refund_dest: None,
            refund_authorizer: None,
            created_at: 0,
            status: IntentStatus::Created,
            claim_nonce: 0,
            refund_nonce: 0,
            withdrawn_amount: 0,
            owner: None,
        };
        let mut with_mint = base.clone();
        with_mint.mint = Some([0u8; 32]);
        assert_ne!(base.encode(), with_mint.encode());
    }

    #[test]
    fn state_root_includes_intents() {
        let mut s1 = StateTree::new();
        let s2 = StateTree::new();
        assert_eq!(s1.compute_root(), s2.compute_root());
        s1.hfi_intent_put([9u8; 32], vec![0x01u8; ONCHAIN_INTENT_LEN]);
        assert_ne!(s1.compute_root(), s2.compute_root());
    }

    #[test]
    fn compute_refund_message_is_deterministic() {
        let intent_id = [0x11u8; 32];
        let blinded_binding = [0x22u8; 32];
        let authorizer = [0x33u8; 32];
        let dest = [0x44u8; 32];
        let msg1 = compute_refund_message(
            1,
            None,
            &intent_id,
            &blinded_binding,
            1000,
            &authorizer,
            &dest,
            9000,
            0,
        );
        let msg2 = compute_refund_message(
            1,
            None,
            &intent_id,
            &blinded_binding,
            1000,
            &authorizer,
            &dest,
            9000,
            0,
        );
        assert_eq!(msg1, msg2, "refund message must be deterministic");
    }

    #[test]
    fn compute_refund_message_differs_by_field() {
        let intent_id = [0x11u8; 32];
        let blinded_binding = [0x22u8; 32];
        let authorizer = [0x33u8; 32];
        let dest = [0x44u8; 32];
        let base = compute_refund_message(
            1,
            None,
            &intent_id,
            &blinded_binding,
            1000,
            &authorizer,
            &dest,
            9000,
            0,
        );
        // Different nonce
        let diff_nonce = compute_refund_message(
            1,
            None,
            &intent_id,
            &blinded_binding,
            1000,
            &authorizer,
            &dest,
            9000,
            1,
        );
        assert_ne!(base, diff_nonce);
        // Different amount
        let diff_amount = compute_refund_message(
            1,
            None,
            &intent_id,
            &blinded_binding,
            999,
            &authorizer,
            &dest,
            9000,
            0,
        );
        assert_ne!(base, diff_amount);
        // Different chain_tag
        let diff_chain = compute_refund_message(
            2,
            None,
            &intent_id,
            &blinded_binding,
            1000,
            &authorizer,
            &dest,
            9000,
            0,
        );
        assert_ne!(base, diff_chain);
        // With mint vs. without mint
        let mint = [0xFFu8; 32];
        let with_mint = compute_refund_message(
            1,
            Some(&mint),
            &intent_id,
            &blinded_binding,
            1000,
            &authorizer,
            &dest,
            9000,
            0,
        );
        assert_ne!(base, with_mint);
    }

    #[test]
    fn handle_refund_ml_dsa_sig_verify() {
        use ace_runtime::crypto::sig_algo::{
            verify_signature, LocalSigningKey, SignatureAlgorithm,
        };

        let intent_id = [0xAAu8; 32];
        let blinded_binding = [0xBBu8; 32];
        let refund_authorizer = AccountId::from_bytes([0xCCu8; 32]);
        let refund_dest = AccountId::from_bytes([0xDDu8; 32]);
        let amount = 500u64;
        let expiry = 50u64;
        let nonce = 0u64;

        // Generate ML-DSA-44 keypair from a fixed seed.
        let seed = [0x42u8; 32];
        let key = LocalSigningKey::from_seed(&seed, SignatureAlgorithm::MlDsa44).unwrap();
        let tagged_pk = key.public_key();

        let correct_msg = compute_refund_message(
            1,
            None,
            &intent_id,
            &blinded_binding,
            amount,
            refund_authorizer.as_bytes(),
            refund_dest.as_bytes(),
            expiry,
            nonce,
        );
        let correct_sig = key.sign(&correct_msg);

        // Happy path: correct sig must pass.
        assert!(
            verify_signature(&tagged_pk, &correct_msg, &correct_sig),
            "correct sig should verify"
        );

        // Unhappy path: sig over wrong message (different amount) must fail.
        let wrong_msg = compute_refund_message(
            1,
            None,
            &intent_id,
            &blinded_binding,
            amount + 1,
            refund_authorizer.as_bytes(),
            refund_dest.as_bytes(),
            expiry,
            nonce,
        );
        assert!(
            !verify_signature(&tagged_pk, &wrong_msg, &correct_sig),
            "sig over wrong msg should fail"
        );

        // Unhappy path: sig from different key must fail.
        let other_key =
            LocalSigningKey::from_seed(&[0x99u8; 32], SignatureAlgorithm::MlDsa44).unwrap();
        let other_pk = other_key.public_key();
        assert!(
            !verify_signature(&other_pk, &correct_msg, &correct_sig),
            "sig from different key should fail"
        );
    }
}
