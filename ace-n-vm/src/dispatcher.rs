//! n-VM dispatcher — routes transactions to the appropriate engine.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ace_engine::executor::{
    TransactionOp, OP_HFI_PAY_CLAIM, OP_HFI_PAY_CREATE, OP_HFI_PAY_EXPIRE, OP_HFI_PAY_FUND,
    OP_HFI_PAY_REFUND, OP_HFI_PAY_REGISTER_RECIPIENT,
};
use ace_engine::receipt::StateChange;
use ace_model::account::{Account, AccountId};
use ace_model::sharded_state::{ShardId as ModelShardId, ShardedState};
use ace_model::state_tree::StateTree;
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use rayon::prelude::*;

use crate::bvm::engine::BvmEngine;
use crate::bvm::MockBvmEngine;
use crate::context::ShardId;
use crate::error::NVmError;
use crate::evm::engine::RevmEngine;
use crate::evm::MockEvmEngine;
use crate::native::AceNativeEngine;
use crate::raw_btc::verify_raw_btc_against_state;
use crate::raw_evm::{canonical_evm_payload_from_raw, verify_raw_evm_recover_signer_and_chain_id};
use crate::raw_solana::verify_raw_solana_transfer_for_slot;
use crate::raw_tron::{tron_replay_state, verify_raw_tron_against_state};
use crate::scheduler::{self, WriteSet};
use crate::svm::engine::SvmEngine;
use crate::svm::MockSvmEngine;
use crate::tvm::engine::TvmEngine;
use crate::tvm::MockTvmEngine;
use crate::vm::{HfiPayHook, VmEngine, VmId, VmReceipt};
use ace_mvm::MoveVmEngine;

/// The unified n-VM dispatcher.
///
/// Holds registered execution engines and routes each transaction
/// to the appropriate VM based on its opcode prefix byte.
pub struct NVm {
    engines: HashMap<VmId, Box<dyn VmEngine>>,
    /// When set, native `0x06` HFI Pay claim txs apply here instead of `ace_engine`.
    hfi_claim: Option<Arc<dyn HfiPayHook>>,
}

impl NVm {
    /// Create a NVm with no engines registered.
    pub fn new() -> Self {
        Self {
            engines: HashMap::new(),
            hfi_claim: None,
        }
    }

    /// Genesis founder gate for `OP_APPROVE_VALIDATOR` at execution time.
    pub fn set_founder_id_com(&mut self, founder: Option<AccountId>) {
        let mut native = AceNativeEngine::new();
        native.set_founder_id_com(founder);
        self.engines.insert(VmId::AceNative, Box::new(native));
    }

    /// Attach on-chain HFI Pay claim execution (native opcode 0x06). Required for
    /// mainnet-style HFI claims that mutate intent/relay state.
    pub fn set_hfi_claim_hook(&mut self, hook: Option<Arc<dyn HfiPayHook>>) {
        self.hfi_claim = hook;
    }

    /// Create a NVm with real execution engines (ACE native + EVM + SVM + BVM + TVM + Move).
    pub fn with_defaults() -> Self {
        let mut vm = Self::new();
        vm.register(Box::new(AceNativeEngine::new()));
        vm.register(Box::new(MoveVmEngine::new()));
        vm.register(Box::new(RevmEngine));
        vm.register(Box::new(SvmEngine::new()));
        vm.register(Box::new(BvmEngine));
        vm.register(Box::new(TvmEngine));
        vm
    }

    /// Create a NVm with test-only stub engines (for backward-compatible tests).
    pub fn with_test_stubs() -> Self {
        let mut vm = Self::new();
        vm.register(Box::new(AceNativeEngine::new()));
        vm.register(Box::new(MoveVmEngine::new()));
        vm.register(Box::new(MockEvmEngine));
        vm.register(Box::new(MockSvmEngine));
        vm.register(Box::new(MockBvmEngine));
        vm.register(Box::new(MockTvmEngine));
        vm.hfi_claim = None;
        vm
    }

    /// Register a VM engine.
    pub fn register(&mut self, engine: Box<dyn VmEngine>) {
        self.engines.insert(engine.vm_id(), engine);
    }

    pub fn prepare_raw_chain_accounts(
        state: &mut StateTree,
        tx: &Transaction,
    ) -> Result<(), NVmError> {
        let Some(raw) = &tx.raw_chain else {
            return Ok(());
        };

        let sender = AccountId::from_bytes(tx.attestation.idcom);
        match raw.kind {
            RawChainKind::Evm => {
                let (signer, chain_id) =
                    verify_raw_evm_recover_signer_and_chain_id(&raw.raw_bytes)?;
                if chain_id != tx.attestation.domain.chain_id as u64 {
                    return Err(NVmError::RawChainVerify(format!(
                        "evm chain_id {} does not match attestation domain {}",
                        chain_id, tx.attestation.domain.chain_id
                    )));
                }
                let expected_idcom = ace_runtime::crypto::legacy_idcom_evm(&signer);
                if tx.attestation.idcom != expected_idcom {
                    return Err(NVmError::InvalidCredential(tx.attestation.idcom));
                }
                let expected_payload = canonical_evm_payload_from_raw(&raw.raw_bytes)?;
                if tx.payload != expected_payload {
                    return Err(NVmError::RawChainVerify(
                        "evm raw payload does not match canonical reconstruction".into(),
                    ));
                }
                bind_evm_alias_account(state, sender, signer)?;
            }
            RawChainKind::Solana => {
                let verified = verify_raw_solana_transfer_for_slot(
                    state,
                    &raw.raw_bytes,
                    tx.attestation.domain.chain_id,
                    tx.attestation.domain.slot as u64,
                )?;
                let expected_sender_idcom = verified.sender_idcom;
                if tx.attestation.idcom != expected_sender_idcom {
                    return Err(NVmError::InvalidCredential(tx.attestation.idcom));
                }
                if tx.payload != verified.canonical_payload {
                    return Err(NVmError::RawChainVerify(
                        "solana raw payload does not match canonical reconstruction".into(),
                    ));
                }
                let recipient = AccountId::from_bytes(verified.recipient_idcom);
                if !state.contains(&recipient) {
                    state.insert(Account::new(recipient));
                }
            }
            RawChainKind::Btc => {
                let verified = verify_raw_btc_against_state(state, &raw.raw_bytes)?;
                if tx.attestation.idcom != verified.sender_idcom {
                    return Err(NVmError::InvalidCredential(tx.attestation.idcom));
                }
                if tx.payload != verified.payload {
                    return Err(NVmError::RawChainVerify(
                        "btc raw payload does not match canonical reconstruction".into(),
                    ));
                }
            }
            RawChainKind::Tron => {
                let verified = verify_raw_tron_against_state(state, &raw.raw_bytes)?;
                if tx.attestation.idcom != verified.sender_idcom {
                    return Err(NVmError::InvalidCredential(tx.attestation.idcom));
                }
                if tx.payload != verified.canonical_payload {
                    return Err(NVmError::RawChainVerify(
                        "tron raw payload does not match canonical reconstruction".into(),
                    ));
                }
                if tx.attestation.domain.slot != verified.domain_slot {
                    return Err(NVmError::RawChainVerify(
                        "tron attestation slot does not match canonical ACE domain slot".into(),
                    ));
                }
                bind_tron_alias_account(state, sender, verified.signer)?;
            }
        }

        Ok(())
    }

    /// `block_slot` is the consensus block slot when applying a block; pass `0` for
    /// mempool simulation or tests if the transaction is not an HFI Pay 0x06 claim.
    pub fn execute_transaction(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
        block_slot: u64,
    ) -> Result<VmReceipt, NVmError> {
        if tx.payload.is_empty() {
            return Err(NVmError::EmptyPayload);
        }
        if tx.raw_chain.is_some() && tx.zk_auth.is_some() {
            return Err(NVmError::InternalError(
                "raw_chain and zk_auth are mutually exclusive".into(),
            ));
        }

        let sender = AccountId::from_bytes(tx.attestation.idcom);
        let snapshot = state.snapshot();
        let result = (|| {
            let tron_replay_marker = tx
                .raw_chain
                .as_ref()
                .filter(|raw_chain| raw_chain.kind == RawChainKind::Tron)
                .map(|raw_chain| {
                    tron_replay_state(&raw_chain.raw_bytes, tx.attestation.domain.slot as u64)
                })
                .transpose()?;

            if let Some(ref raw) = tx.raw_chain {
                // Verify committee certificate for raw chain transactions that require it.
                // Full certificate signature verification is done at the node layer
                // (capability::verify_certificate) before reaching the dispatcher;
                // here we verify the certificate exists and has correct domain binding.
                if let Some(domain) = raw.kind.committee_domain() {
                    match &raw.committee_certificate {
                        None => {
                            tracing::warn!(
                                "Rejecting raw {:?} tx: missing committee certificate",
                                raw.kind
                            );
                            return Err(NVmError::RawChainVerify(format!(
                                "raw {:?} transaction requires a committee certificate",
                                raw.kind
                            )));
                        }
                        Some(cert) => {
                            if cert.domain != domain {
                                return Err(NVmError::RawChainVerify(
                                    "committee certificate domain mismatch".into(),
                                ));
                            }
                        }
                    }
                }

                Self::prepare_raw_chain_accounts(state, tx)?;
            } else if tx.is_zk_auth() {
                // ZK-ACE authorization carries no per-op account nonce and its replay
                // registry (rp_com) is only consumed on the native Transfer path. Any
                // other opcode (EVM/SVM/BVM/TVM or native non-transfer) would execute
                // without replay accounting, so restrict zk_auth to native Transfer (0x01).
                if tx.payload[0] != 0x01 {
                    return Err(NVmError::InvalidCredential(tx.attestation.idcom));
                }
                // Defense-in-depth: re-verify the ZK proof at execution time even though
                // the mempool and pre-verify pipeline already checked it.  This closes the
                // gap where execute_transaction could be called without prior validation
                // (e.g. block replay, test harnesses, future code paths).
                let zk_auth = tx.zk_auth.as_ref().ok_or_else(|| {
                    NVmError::InternalError("is_zk_auth() true but zk_auth field is None".into())
                })?;
                ace_runtime::crypto::verify_zk_auth(tx, zk_auth)
                    .map_err(|e| NVmError::InternalError(format!("ZK-ACE: {e}")))?;
            } else {
                // Verify credential for non-raw-chain, non-ZK-auth transactions.
                let opcode = tx.payload[0];
                let is_native = matches!(VmId::from_opcode(opcode), Some(VmId::AceNative));

                if is_native {
                    // Native ACE: verify credential with special handling for
                    // key bootstrapping (SetAuthPubkey/AddAuthKey on unprovisioned
                    // accounts) and CreateAccount.
                    let decoded_op = TransactionOp::decode(&tx.payload)
                        .map_err(|e| NVmError::NativeError(e.to_string()))?;
                    let sig_alg = tx.attestation.credential.algorithm;
                    let auth_key = if let Some(sender_account) = state.get(&sender) {
                        match decoded_op {
                            TransactionOp::SetAuthPubkey { auth_pubkey, .. }
                            | TransactionOp::AddAuthKey { auth_pubkey, .. } => match sender_account
                                .auth_key_for_algorithm(sig_alg)
                            {
                                Some(k) if !k.is_zero() => k.clone(),
                                _ => {
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
                            },
                            _ => sender_account
                                .auth_key_for_algorithm(sig_alg)
                                .ok_or(NVmError::InvalidCredential(tx.attestation.idcom))?
                                .clone(),
                        }
                    } else if opcode == 0x02 {
                        match TransactionOp::decode(&tx.payload)
                            .map_err(|e| NVmError::NativeError(e.to_string()))?
                        {
                            TransactionOp::CreateAccount {
                                id_com,
                                auth_pubkey,
                            } if id_com == sender => auth_pubkey,
                            _ => return Err(NVmError::InvalidCredential(tx.attestation.idcom)),
                        }
                    } else {
                        return Err(NVmError::AccountNotFound(tx.attestation.idcom));
                    };

                    if !ace_runtime::crypto::attestation::verify_credential(
                        &tx.attestation,
                        &tx.payload,
                        &auth_key,
                    ) {
                        return Err(NVmError::InvalidCredential(tx.attestation.idcom));
                    }
                } else {
                    // Non-native VM (EVM/SVM/BVM/TVM): verify credential using
                    // the sender's on-chain auth key directly (no payload decode).
                    if let Some(sender_account) = state.get(&sender) {
                        let sig_alg = tx.attestation.credential.algorithm;
                        let auth_key = sender_account
                            .auth_key_for_algorithm(sig_alg)
                            .ok_or(NVmError::InvalidCredential(tx.attestation.idcom))?;
                        if !ace_runtime::crypto::attestation::verify_credential(
                            &tx.attestation,
                            &tx.payload,
                            auth_key,
                        ) {
                            return Err(NVmError::InvalidCredential(tx.attestation.idcom));
                        }
                    } else {
                        return Err(NVmError::AccountNotFound(tx.attestation.idcom));
                    }
                }
            }

            if matches!(
                tx.payload[0],
                OP_HFI_PAY_CLAIM
                    | OP_HFI_PAY_CREATE
                    | OP_HFI_PAY_FUND
                    | OP_HFI_PAY_EXPIRE
                    | OP_HFI_PAY_REFUND
                    | OP_HFI_PAY_REGISTER_RECIPIENT
            ) {
                if let Some(ref hook) = self.hfi_claim {
                    let mut receipt = hook
                        .execute(state, tx, block_slot)
                        .map_err(NVmError::HfiPayClaim)?;
                    if let Some((replay_slot, marker)) = tron_replay_marker {
                        let old_value = [0u8; 32];
                        state.set_storage(&sender, replay_slot, marker);
                        receipt.state_changes.push(StateChange::StorageChange {
                            account: sender,
                            slot: replay_slot,
                            old_value,
                            new_value: marker,
                        });
                    }
                    return Ok(receipt);
                }
                return Err(NVmError::HfiPayClaimNotConfigured);
            }

            let opcode = tx.payload[0];
            let vm_id = VmId::from_opcode(opcode).ok_or(NVmError::UnknownOpcode(opcode))?;

            let engine = self.engines.get(&vm_id).ok_or(NVmError::NoEngine(vm_id))?;
            let mut receipt = engine.execute(state, tx)?;

            if let Some((replay_slot, marker)) = tron_replay_marker {
                let old_value = [0u8; 32];
                state.set_storage(&sender, replay_slot, marker);
                receipt.state_changes.push(StateChange::StorageChange {
                    account: sender,
                    slot: replay_slot,
                    old_value,
                    new_value: marker,
                });
            }

            Ok(receipt)
        })();

        match result {
            Ok(receipt) => Ok(receipt),
            Err(error) => {
                state.rollback(snapshot);
                Err(error)
            }
        }
    }

    /// Execute a block of transactions, collecting receipts.
    ///
    /// Failed transactions produce failure receipts but do not halt
    /// execution of subsequent transactions.
    pub fn execute_block(
        &self,
        state: &mut StateTree,
        txs: &[Transaction],
        block_slot: u64,
    ) -> Vec<VmReceipt> {
        let mut receipts = Vec::with_capacity(txs.len());

        for tx in txs {
            let receipt = match self.execute_transaction(state, tx, block_slot) {
                Ok(r) => r,
                Err(e) => {
                    let sender = ace_model::account::AccountId::from_bytes(tx.attestation.idcom);
                    VmReceipt {
                        vm_id: tx
                            .payload
                            .first()
                            .and_then(|&op| VmId::from_opcode(op))
                            .unwrap_or(VmId::AceNative),
                        tx_hash: tx.tx_hash(),
                        success: false,
                        sender,
                        state_changes: vec![],
                        error: Some(e.to_string()),
                        simulated: false,
                        gas_used: None,
                        contract_address: None,
                        return_data: None,
                        logs: vec![],
                    }
                }
            };
            receipts.push(receipt);
        }

        receipts
    }
}

fn bind_evm_alias_account(
    state: &mut StateTree,
    id: AccountId,
    evm_address: [u8; 20],
) -> Result<(), NVmError> {
    let mut account = state
        .get(&id)
        .cloned()
        .ok_or(NVmError::AccountNotFound(id.0))?;
    if account.evm_address != Some(evm_address) {
        account.evm_address = Some(evm_address);
        state.insert(account);
    }
    Ok(())
}

fn bind_tron_alias_account(
    state: &mut StateTree,
    id: AccountId,
    tron_address: [u8; 20],
) -> Result<(), NVmError> {
    let mut account = state
        .get(&id)
        .cloned()
        .ok_or(NVmError::AccountNotFound(id.0))?;
    if account.tron_address != Some(tron_address) {
        account.tron_address = Some(tron_address);
        state.insert(account);
    }
    Ok(())
}

// ── Parallel execution ──

impl NVm {
    /// Execute a block with parallel batch scheduling.
    ///
    /// Transactions with disjoint write sets run concurrently within each
    /// batch. Batches execute sequentially. Receipts are returned in the
    /// same order as the input transactions.
    pub fn execute_block_parallel(
        &self,
        state: &mut StateTree,
        txs: &[Transaction],
        block_slot: u64,
    ) -> Vec<VmReceipt> {
        if txs.is_empty() {
            return Vec::new();
        }

        let batches = scheduler::build_batches(txs);
        let mut receipts: Vec<Option<VmReceipt>> = vec![None; txs.len()];

        for batch in &batches {
            if batch.tx_indices.len() == 1 {
                // Single-tx batch: execute directly, no clone overhead.
                let idx = batch.tx_indices[0];
                let receipt = match self.execute_transaction(state, &txs[idx], block_slot) {
                    Ok(r) => r,
                    Err(e) => Self::failure_receipt(&txs[idx], e),
                };
                receipts[idx] = Some(receipt);
            } else {
                // Multi-tx batch: clone state per tx, execute in parallel, merge.
                let batch_results: Vec<(usize, VmReceipt, StateTree)> = batch
                    .tx_indices
                    .par_iter()
                    .map(|&idx| {
                        let mut local_state = state.clone();
                        let receipt =
                            match self.execute_transaction(&mut local_state, &txs[idx], block_slot)
                            {
                                Ok(r) => r,
                                Err(e) => Self::failure_receipt(&txs[idx], e),
                            };
                        (idx, receipt, local_state)
                    })
                    .collect();

                // Merge: write sets are disjoint by construction, so we can
                // safely copy each tx's affected accounts back.
                for (idx, receipt, local_state) in batch_results {
                    if receipt.success {
                        Self::merge_write_set(state, &local_state, &txs[idx]);
                    }
                    receipts[idx] = Some(receipt);
                }
            }
        }

        receipts
            .into_iter()
            .enumerate()
            .map(|(i, r)| {
                r.unwrap_or_else(|| {
                    Self::failure_receipt(
                        &txs[i],
                        NVmError::InternalError(format!("receipt missing for tx index {i}")),
                    )
                })
            })
            .collect()
    }

    /// Merge state changes from a parallel execution back into main state.
    ///
    /// Correctly handles account deletions by comparing local vs main state.
    fn merge_write_set(main_state: &mut StateTree, local_state: &StateTree, tx: &Transaction) {
        let ws = scheduler::extract_write_set(tx);
        match ws {
            WriteSet::Accounts(accounts) => {
                for account_id in &accounts {
                    match local_state.get(account_id) {
                        Some(acct) => {
                            // Account exists in local state: insert/update.
                            main_state.insert(acct.clone());
                            // Sync contract storage for this account
                            if let Some(storage) = local_state.get_account_storage(account_id) {
                                for (slot, value) in storage {
                                    main_state.set_storage(account_id, *slot, *value);
                                }
                            }
                        }
                        None => {
                            // Account was deleted in local state: remove from main.
                            main_state.remove(account_id);
                        }
                    }
                }
            }
            WriteSet::Global => {
                // Global write set: tx was alone in its batch.
                *main_state = local_state.clone();
            }
        }
    }

    pub fn shard_for_tx(tx: &Transaction) -> ShardId {
        if tx.payload.is_empty() {
            return ShardId(0);
        }
        ShardId::from_tx(tx.payload[0], &tx.attestation.context_tag)
    }

    /// Determine if a transaction is cross-context by checking whether its
    /// write set touches accounts in shards different from its context shard.
    ///
    /// Cross-context transactions are routed to the shared shard for serial
    /// execution to ensure atomicity (Strategy B from the paper).
    ///
    /// A transaction is cross-context if:
    /// 1. Its write set is `Global` (EVM/TVM calls with unbounded state access)
    ///    AND it has a non-default context tag, OR
    /// 2. Its write set accounts exist in a shard different from the tx's context shard.
    fn is_cross_context(state: &ShardedState, tx: &Transaction, tx_shard: ShardId) -> bool {
        // Only skip cross-context check when there is a single shard
        // (pure backward-compatible mode).
        if state.shard_count() <= 1 {
            return false;
        }

        let ws = scheduler::extract_write_set(tx);
        match ws {
            WriteSet::Global => {
                // Global write set with non-default context: conservatively
                // route to shared shard since we can't predict state access.
                true
            }
            WriteSet::Accounts(accounts) => {
                // Check if any account in the write set exists in a different shard.
                let model_tx_shard = ModelShardId(tx_shard.0);
                for account_id in &accounts {
                    // If the account exists in any shard other than the tx's shard,
                    // this is a cross-context transaction.
                    for (shard_id, shard_tree) in state.iter_shards() {
                        if *shard_id != model_tx_shard && shard_tree.contains(account_id) {
                            return true;
                        }
                    }
                }
                false
            }
        }
    }

    /// Execute a block with context-based shard partitioning and shared shard.
    ///
    /// Transaction routing:
    /// 1. Each transaction is assigned to a shard by its `context_tag`
    /// 2. Cross-context transactions (touching accounts in multiple shards)
    ///    are routed to the shared shard for serial execution
    /// 3. Independent shards execute in parallel via rayon
    /// 4. Shared shard executes last against the merged state
    ///
    /// This implements Strategy B from the context-sharded-state paper.
    pub fn execute_block_sharded(
        &self,
        state: &mut ShardedState,
        txs: &[Transaction],
        block_slot: u64,
    ) -> Vec<VmReceipt> {
        if txs.is_empty() {
            return Vec::new();
        }

        // Phase 1: Partition transactions into context shards vs shared shard.
        let mut shard_groups: HashMap<ShardId, Vec<usize>> = HashMap::new();
        let mut shared_indices: Vec<usize> = Vec::new();

        for (i, tx) in txs.iter().enumerate() {
            let shard = Self::shard_for_tx(tx);
            if Self::is_cross_context(state, tx, shard) {
                shared_indices.push(i);
            } else {
                shard_groups.entry(shard).or_default().push(i);
            }
        }

        tracing::info!(
            total_txs = txs.len(),
            shard_count = shard_groups.len(),
            cross_context_txs = shared_indices.len(),
            active_shards = state.shard_count(),
            "Phase 1: partitioned transactions into shards"
        );

        let mut receipts: Vec<Option<VmReceipt>> = vec![None; txs.len()];

        // Phase 2: Execute independent shards in parallel.
        if !shard_groups.is_empty() {
            if shard_groups.len() == 1 && shared_indices.is_empty() {
                // Optimization: single shard, no cross-context → execute directly.
                let (_shard_id, indices) = shard_groups.into_iter().next().unwrap();
                let shard_id = Self::shard_for_tx(&txs[indices[0]]);
                tracing::debug!(
                    shard_id = shard_id.0,
                    tx_count = indices.len(),
                    "Phase 2: single-shard fast path"
                );
                let shard_state = state.shard_mut(ModelShardId(shard_id.0));
                let shard_receipts = self.execute_block_parallel(shard_state, txs, block_slot);
                return shard_receipts;
            }

            let mut shard_entries: Vec<(ShardId, Vec<usize>)> = shard_groups.into_iter().collect();
            shard_entries.sort_by_key(|(id, _)| id.0);
            let shard_states: Vec<(ShardId, Vec<usize>, StateTree)> = shard_entries
                .into_iter()
                .map(|(shard_id, indices)| {
                    let model_shard_id = ModelShardId(shard_id.0);
                    let shard_tree = state.shard_mut(model_shard_id).clone();
                    (shard_id, indices, shard_tree)
                })
                .collect();

            let shard_results: Vec<(ShardId, Vec<usize>, Vec<VmReceipt>, StateTree)> = shard_states
                .into_par_iter()
                .map(|(shard_id, indices, mut shard_tree)| {
                    let shard_tx_owned: Vec<Transaction> =
                        indices.iter().map(|&i| txs[i].clone()).collect();
                    let shard_receipts =
                        self.execute_block_parallel(&mut shard_tree, &shard_tx_owned, block_slot);
                    (shard_id, indices, shard_receipts, shard_tree)
                })
                .collect();

            // Merge independent shard results back.
            tracing::info!(
                parallel_shards = shard_results.len(),
                "Phase 2: parallel shard execution complete"
            );
            for (shard_id, indices, shard_receipts, shard_tree) in shard_results {
                let model_shard_id = ModelShardId(shard_id.0);
                *state.shard_mut(model_shard_id) = shard_tree;

                for (local_idx, global_idx) in indices.into_iter().enumerate() {
                    receipts[global_idx] = Some(shard_receipts[local_idx].clone());
                }
            }
        }

        // Phase 3: Execute cross-context transactions in the shared shard.
        // These run serially against a merged view of all shard state to
        // ensure visibility across context boundaries.
        if !shared_indices.is_empty() {
            tracing::info!(
                cross_context_txs = shared_indices.len(),
                merged_shards = state.shard_count(),
                "Phase 3: executing cross-context transactions serially"
            );
            let mut account_shards = Self::collect_account_shards(state);
            let mut touched_accounts = HashSet::new();

            let mut global_fallback = false;
            let mut shared_ws_accounts = HashSet::new();
            for &idx in &shared_indices {
                match scheduler::extract_write_set(&txs[idx]) {
                    WriteSet::Global => {
                        global_fallback = true;
                        break;
                    }
                    WriteSet::Accounts(accounts) => {
                        for a in accounts {
                            shared_ws_accounts.insert(a);
                        }
                    }
                }
            }

            let mut merged = if global_fallback {
                Self::build_merged_state_full(state)
            } else {
                Self::build_merged_state_partial(state, &shared_ws_accounts)
            };

            for &idx in &shared_indices {
                let receipt = match self.execute_transaction(&mut merged, &txs[idx], block_slot) {
                    Ok(r) => r,
                    Err(e) => Self::failure_receipt(&txs[idx], e),
                };
                Self::record_shared_receipt_accounts(
                    &mut account_shards,
                    &mut touched_accounts,
                    &receipt,
                    ModelShardId(Self::shard_for_tx(&txs[idx]).0),
                );
                receipts[idx] = Some(receipt);
            }

            Self::write_back_shared_accounts(state, &merged, &touched_accounts, &account_shards);
        }

        receipts
            .into_iter()
            .enumerate()
            .map(|(i, r)| {
                r.unwrap_or_else(|| {
                    Self::failure_receipt(
                        &txs[i],
                        NVmError::InternalError(format!("receipt missing for tx index {i}")),
                    )
                })
            })
            .collect()
    }

    /// Build a failure receipt for a transaction that errored.
    fn failure_receipt(tx: &Transaction, e: NVmError) -> VmReceipt {
        let sender = AccountId::from_bytes(tx.attestation.idcom);
        let vm_id = tx
            .payload
            .first()
            .and_then(|&op| VmId::from_opcode(op))
            .unwrap_or_else(|| {
                tracing::warn!(
                    tx_hash = hex::encode(tx.tx_hash()),
                    opcode = tx.payload.first().copied(),
                    "cannot determine VmId for failed tx, defaulting to AceNative"
                );
                VmId::AceNative
            });
        VmReceipt {
            vm_id,
            tx_hash: tx.tx_hash(),
            success: false,
            sender,
            state_changes: vec![],
            error: Some(e.to_string()),
            simulated: false,
            gas_used: None,
            contract_address: None,
            return_data: None,
            logs: vec![],
        }
    }

    fn build_merged_state_full(state: &ShardedState) -> StateTree {
        let mut merged = StateTree::new();

        for (shard_id, shard_tree) in state.iter_shards() {
            for (account_id, account) in shard_tree.iter() {
                if merged.contains(account_id) {
                    // Invariant violation: account exists in multiple shards.
                    // Keep the first copy (lower shard ID) and log a warning.
                    tracing::warn!(
                        account = hex::encode(account_id.as_bytes()),
                        shard = shard_id.0,
                        "duplicate account in multiple shards during merge, skipping"
                    );
                    continue;
                }
                merged.insert(account.clone());

                if let Some(storage) = shard_tree.get_account_storage(account_id) {
                    for (slot, value) in storage {
                        merged.set_storage(account_id, *slot, *value);
                    }
                }
            }

            for (account_id, stub) in shard_tree.iter_stubs() {
                if !merged.contains(account_id) && !merged.is_stubbed(account_id) {
                    merged.insert_stub(*stub);
                }
            }
        }

        merged
    }

    fn build_merged_state_partial(
        state: &ShardedState,
        accounts: &HashSet<AccountId>,
    ) -> StateTree {
        let mut merged = StateTree::new();

        for (shard_id, shard_tree) in state.iter_shards() {
            for account_id in accounts {
                if let Some(account) = shard_tree.get(account_id) {
                    if merged.contains(account_id) {
                        tracing::warn!(
                            account = hex::encode(account_id.as_bytes()),
                            shard = shard_id.0,
                            "duplicate account in multiple shards during merge, skipping"
                        );
                        continue;
                    }
                    merged.insert(account.clone());

                    if let Some(storage) = shard_tree.get_account_storage(account_id) {
                        for (slot, value) in storage {
                            merged.set_storage(account_id, *slot, *value);
                        }
                    }
                } else if let Some(stub) = shard_tree.get_stub(account_id) {
                    if !merged.contains(account_id) && !merged.is_stubbed(account_id) {
                        merged.insert_stub(*stub);
                    }
                }
            }
        }

        merged
    }

    fn collect_account_shards(state: &ShardedState) -> HashMap<AccountId, ModelShardId> {
        let mut account_shards = HashMap::new();

        for (shard_id, shard_tree) in state.iter_shards() {
            for (account_id, _) in shard_tree.iter() {
                account_shards.insert(*account_id, *shard_id);
            }
            for (account_id, _) in shard_tree.iter_stubs() {
                account_shards.entry(*account_id).or_insert(*shard_id);
            }
        }

        account_shards
    }

    fn record_shared_receipt_accounts(
        account_shards: &mut HashMap<AccountId, ModelShardId>,
        touched_accounts: &mut HashSet<AccountId>,
        receipt: &VmReceipt,
        _tx_shard: ModelShardId,
    ) {
        for change in &receipt.state_changes {
            match change {
                StateChange::BalanceChange { account, .. }
                | StateChange::NonceIncrement { account, .. }
                | StateChange::StorageChange { account, .. }
                | StateChange::CodeDeployed { account, .. } => {
                    touched_accounts.insert(*account);
                }
                StateChange::AccountCreated { account } => {
                    touched_accounts.insert(*account);
                    // New accounts MUST be placed in their deterministic shard to remain
                    // reachable after persistence reload (rocks_state_db doesn't rebuild index).
                    account_shards
                        .entry(*account)
                        .or_insert_with(|| ShardedState::deterministic_shard(account));
                }
                StateChange::AddressBound { account, .. }
                | StateChange::AuthKeyUpdated { account, .. } => {
                    touched_accounts.insert(*account);
                }
                StateChange::ZkReplayConsumed { account, .. } => {
                    touched_accounts.insert(*account);
                }
                StateChange::Fee { .. } => {}
                StateChange::IntentChange { .. } => {}
            }
        }
    }

    fn write_back_shared_accounts(
        state: &mut ShardedState,
        merged: &StateTree,
        touched_accounts: &HashSet<AccountId>,
        account_shards: &HashMap<AccountId, ModelShardId>,
    ) {
        for account_id in touched_accounts {
            let Some(account) = merged.get(account_id).cloned() else {
                continue;
            };

            // Phase 3 write-back preserves existing shards for manually sharded accounts.
            // New accounts or unindexed accounts fall back to deterministic shard.
            let target_shard = account_shards
                .get(account_id)
                .cloned()
                .unwrap_or_else(|| ShardedState::deterministic_shard(account_id));

            state.insert_into_shard(target_shard, account);

            if let Some(storage) = merged.get_account_storage(account_id) {
                let shard_tree = state.shard_mut(target_shard);
                for (slot, value) in storage {
                    shard_tree.set_storage(account_id, *slot, *value);
                }
            }
        }
    }
}

impl Default for NVm {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::NVm;
    use ace_model::account::{Account, AccountId};
    use ace_model::sharded_state::{ShardId as ModelShardId, ShardedState};
    use ace_model::state_tree::StateTree;
    use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
    use ace_runtime::types::attestation::{Attestation, Domain};
    use ace_runtime::types::transaction::Transaction;
    use sha2::{Digest, Sha256};

    fn make_signed_svm_transfer_tx(
        auth_seed: [u8; 32],
        sender_idcom: [u8; 32],
        recipient_idcom: [u8; 32],
        amount: u64,
    ) -> Transaction {
        let mut payload = Vec::with_capacity(49);
        payload.push(0x01);
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&recipient_idcom);
        payload.extend_from_slice(&amount.to_le_bytes());

        let mut obj_hash = [0u8; 32];
        obj_hash.copy_from_slice(&Sha256::digest(&payload));
        let domain = Domain::new(1, 0);

        Transaction::new(
            payload,
            Attestation {
                obj_hash,
                idcom: sender_idcom,
                domain,
                context_tag: [0u8; 16],
                credential: make_credential(
                    &auth_seed,
                    &obj_hash,
                    &sender_idcom,
                    &domain,
                    &[0u8; 16],
                ),
            },
        )
    }

    #[test]
    fn failed_execution_rolls_back_state() {
        let sender = AccountId([0x11; 32]);
        let recipient = AccountId([0x22; 32]);
        let auth_seed = [0x33; 32];

        let mut state = StateTree::new();
        state.insert(Account::with_auth(
            sender,
            1,
            auth_public_key_from_seed(&auth_seed),
        ));

        let tx = make_signed_svm_transfer_tx(auth_seed, sender.0, recipient.0, 2);
        let n_vm = NVm::with_defaults();
        let err = n_vm
            .execute_transaction(&mut state, &tx, 0)
            .expect_err("transfer should fail");

        println!("ERROR WAS: {}", err.to_string());
        assert!(err.to_string().contains("insufficient"));
        assert!(state.get(&recipient).is_none());
        assert_eq!(state.get(&sender).expect("sender").balance, 1);
    }

    #[test]
    fn cross_context_execution_preserves_non_default_shard_accounts_and_storage() {
        let sender = AccountId([0x41; 32]);
        let recipient = AccountId([0x42; 32]);
        let anchored = AccountId([0x43; 32]);
        let auth_seed = [0x51; 32];
        let shard = ModelShardId(7);
        let slot = [0x61; 32];
        let value = [0x71; 32];

        let mut state = ShardedState::new();
        state.insert_into_shard(
            shard,
            Account::with_auth(sender, 10, auth_public_key_from_seed(&auth_seed)),
        );
        state.insert_into_shard(ModelShardId(0), Account::new(recipient));
        state.insert_into_shard(shard, Account::new(anchored));
        state.shard_mut(shard).set_storage(&anchored, slot, value);

        let receipts = NVm::with_defaults().execute_block_sharded(
            &mut state,
            &[make_signed_svm_transfer_tx(
                auth_seed,
                sender.0,
                recipient.0,
                3,
            )],
            0,
        );

        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].success);
        assert_eq!(
            state
                .shard(shard)
                .expect("sender shard")
                .get(&sender)
                .unwrap()
                .balance,
            7
        );
        assert_eq!(
            state
                .default_shard()
                .get(&recipient)
                .expect("recipient")
                .balance,
            3
        );
        assert!(state
            .shard(shard)
            .expect("anchored shard")
            .contains(&anchored));
        assert!(!state.default_shard().contains(&anchored));
        assert_eq!(
            state
                .shard(shard)
                .expect("anchored shard")
                .get_storage(&anchored, &slot),
            value
        );
    }
}
