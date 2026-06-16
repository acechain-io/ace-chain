//! Concurrent transaction mempool.
//!
//! The mempool separates transactions into:
//! - ready: immediately eligible for block production
//! - future: nonce-bearing transactions waiting on earlier sender nonces
//!
//! Under load, admission applies hard backpressure before the mempool is full so
//! consensus can continue building blocks from the ready queue instead of being
//! buried under backlog.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use ace_engine::executor::TransactionOp;
use ace_model::account::AccountId;
use ace_model::sharded_state::ShardedState;
use ace_n_vm::raw_btc::verify_raw_btc_against_state;
use ace_n_vm::raw_evm::{
    canonical_evm_payload_from_raw, decode_raw_evm_nonce,
    verify_raw_evm_recover_signer_and_chain_id,
};
use ace_n_vm::raw_solana::verify_raw_solana_transfer_against_state;
use ace_n_vm::raw_tron::verify_raw_tron_against_state;
use ace_runtime::crypto::{attestation::verify_credential, legacy_idcom_evm};
use ace_runtime::types::block::{
    decode_mev_ace_omission_evidence_payload, is_mev_ace_omission_evidence_payload,
    mev_ace_omission_evidence_tx_idcom,
};
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use metrics::gauge;
use parking_lot::RwLock;

use crate::error::MempoolError;
use crate::validator::TransactionValidator;
use crate::zk_authorization::{verify_zk_authorization, StateReplayGuard};

/// Configuration for the mempool.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of pending transactions.
    pub max_size: usize,
    /// Start rejecting new external traffic at this watermark so consensus
    /// continues draining ready transactions before the pool is saturated.
    pub admission_high_watermark: usize,
    /// After overload mode starts, resume admission only once the pending set
    /// drains to or below this lower watermark.
    pub admission_low_watermark: usize,
    /// Expected chain_id for domain validation (0 = skip check).
    pub chain_id: u32,
    /// Maximum transaction payload size in bytes (0 = no limit).
    pub max_tx_bytes: usize,
    /// Maximum nonce gap accepted per sender for future transactions.
    pub max_future_nonce_gap: u64,
    /// Maximum future-nonce transactions tracked per sender.
    pub max_future_txs_per_sender: usize,
    /// Founder allowed to submit `OP_APPROVE_VALIDATOR`. `None` rejects all 0x0C txs.
    pub founder_id_com: Option<AccountId>,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10_000,
            admission_high_watermark: 8_000,
            admission_low_watermark: 6_000,
            chain_id: 122_766,
            max_tx_bytes: 65_536, // 64 KB
            max_future_nonce_gap: 512,
            max_future_txs_per_sender: 512,
            founder_id_com: None,
        }
    }
}

/// Maximum transactions per sender in the mempool.
const MAX_TXS_PER_SENDER: usize = 10_000;

#[derive(Debug, Default)]
struct SenderLane {
    onchain_nonce: u64,
    ready: BTreeMap<u64, [u8; 32]>,
    future: BTreeMap<u64, [u8; 32]>,
    unordered: BTreeSet<[u8; 32]>,
    future_only_since_slot: Option<u64>,
}

impl SenderLane {
    fn total_count(&self) -> usize {
        self.ready.len() + self.future.len() + self.unordered.len()
    }

    fn next_expected_nonce(&self) -> u64 {
        let mut expected = self.onchain_nonce;
        while self.ready.contains_key(&expected) {
            expected = expected.saturating_add(1);
        }
        expected
    }

    fn is_empty(&self) -> bool {
        self.ready.is_empty() && self.future.is_empty() && self.unordered.is_empty()
    }
}

#[derive(Debug, Default)]
struct PoolState {
    pending: HashMap<[u8; 32], Transaction>,
    tx_states: HashMap<[u8; 32], TxMempoolState>,
    ready_queue: VecDeque<[u8; 32]>,
    ready_members: HashSet<[u8; 32]>,
    senders: HashMap<[u8; 32], SenderLane>,
    last_chain_sync_slot: Option<u64>,
}

/// Protocol-level admission state for a transaction resident in the mempool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxMempoolState {
    /// Locally executable and eligible for proposal.
    ReadyExecutable,
    /// Waiting for earlier sender nonces.
    FutureNonce,
    /// Relay-stripped credential is parked until the full credential arrives.
    ParkedStrippedCredential,
    /// Native ACE tx is waiting for local witness material.
    ParkedMissingWitness,
    /// Raw n-VM tx is waiting for a committee certificate.
    ParkedMissingCommitteeCertificate,
    /// Nonce-less transaction that can be proposed once selected.
    UnorderedExecutable,
}

/// Reason a drained transaction is parked instead of immediately requeued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkedTxReason {
    /// Local native witness material is not available.
    MissingWitness,
    /// Capability-committee certificate threshold is not available yet.
    MissingCommitteeCertificate,
}

impl ParkedTxReason {
    fn state(self) -> TxMempoolState {
        match self {
            Self::MissingWitness => TxMempoolState::ParkedMissingWitness,
            Self::MissingCommitteeCertificate => TxMempoolState::ParkedMissingCommitteeCertificate,
        }
    }
}

/// Snapshot of mempool protocol states.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MempoolStateCounts {
    pub pending_total: usize,
    pub ready_executable: usize,
    pub future_nonce: usize,
    pub parked_stripped_credential: usize,
    pub parked_missing_witness: usize,
    pub parked_missing_committee_certificate: usize,
    pub unordered_executable: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsertOutcome {
    pub tx_hash: [u8; 32],
    pub became_ready: bool,
}

/// Thread-safe transaction mempool with ready/future sender lanes.
pub struct Mempool {
    config: MempoolConfig,
    state: RwLock<PoolState>,
    /// Current slot for domain.slot validation (shared with consensus).
    current_slot: Arc<AtomicU64>,
    /// Live state view used for sender existence and credential checks.
    state_view: Option<Arc<RwLock<ShardedState>>>,
    /// Exponential moving average of committed block tx counts.
    /// Used to derive dynamic admission watermarks that adapt to the
    /// chain's actual throughput regardless of hardware configuration.
    avg_block_txs: AtomicUsize,
    /// Number of non-empty blocks recorded.  Dynamic watermarks only
    /// activate after MIN_BLOCKS_FOR_DYNAMIC samples so that startup /
    /// low-traffic periods keep the generous static thresholds.
    committed_block_count: AtomicUsize,
    /// Monotonic counter for probabilistic admission rejection entropy.
    admission_counter: AtomicU64,
}

impl Mempool {
    const FUTURE_ONLY_EVICT_AFTER_SLOTS: u64 = 10;
    /// Maximum senders whose future-only lanes are evicted in a single GC run.
    /// Keep this large enough that a broad nonce-gap backlog clears promptly
    /// after aging out, without requiring many consensus-height sweeps.
    const FUTURE_ONLY_EVICT_PER_RUN: usize = 256;
    /// Native tx domain.slot tolerance enforced during node execution.
    const DOMAIN_SLOT_TOLERANCE: u64 = 100;
    /// Evict native txs before they are close enough to slot expiry that normal
    /// proposal/validation delay could make them fail execution.
    const SLOT_FRESHNESS_GUARD: u64 = 20;
    /// If the proposer has fewer ready txs than this, admit txs that can become
    /// ready immediately even when total pending is in the overload band.
    const READY_STARVATION_BYPASS_BELOW: usize = 64;

    /// Create a new mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        let mempool = Self {
            config,
            state: RwLock::new(PoolState::default()),
            current_slot: Arc::new(AtomicU64::new(0)),
            state_view: None,
            avg_block_txs: AtomicUsize::new(0),
            committed_block_count: AtomicUsize::new(0),
            admission_counter: AtomicU64::new(0),
        };
        mempool.update_metrics();
        mempool
    }

    /// Create a new mempool with a shared current_slot counter.
    pub fn with_slot(config: MempoolConfig, current_slot: Arc<AtomicU64>) -> Self {
        let mempool = Self {
            config,
            state: RwLock::new(PoolState::default()),
            current_slot,
            state_view: None,
            avg_block_txs: AtomicUsize::new(0),
            committed_block_count: AtomicUsize::new(0),
            admission_counter: AtomicU64::new(0),
        };
        mempool.update_metrics();
        mempool
    }

    /// Create a new mempool with a shared current_slot and sharded state view.
    pub fn with_slot_and_state(
        config: MempoolConfig,
        current_slot: Arc<AtomicU64>,
        state: Arc<RwLock<ShardedState>>,
    ) -> Self {
        let mempool = Self {
            config,
            state: RwLock::new(PoolState::default()),
            current_slot,
            state_view: Some(state),
            avg_block_txs: AtomicUsize::new(0),
            committed_block_count: AtomicUsize::new(0),
            admission_counter: AtomicU64::new(0),
        };
        mempool.update_metrics();
        mempool
    }

    /// Compute the canonical transaction hash (SHA-256 of serialized tx).
    pub fn tx_hash(tx: &Transaction) -> [u8; 32] {
        tx.tx_hash()
    }

    /// Validate and insert a transaction. Returns the tx hash.
    pub fn insert(&self, tx: Transaction) -> Result<[u8; 32], MempoolError> {
        self.insert_with_ready_transition(tx)
            .map(|outcome| outcome.tx_hash)
    }

    /// Validate and insert a transaction, reporting whether this insert made
    /// the ready queue transition from empty to non-empty.
    pub fn insert_with_ready_transition(
        &self,
        tx: Transaction,
    ) -> Result<InsertOutcome, MempoolError> {
        self.insert_inner(tx, false)
    }

    /// Insert a transaction whose credential has already been verified by the
    /// caller (e.g. the RPC layer).  Skips the expensive signature verification
    /// inside the mempool to avoid double-verifying ML-DSA-44 (~1 ms each).
    /// All other validations (format, slot, nonce, pool limits) still apply.
    /// Use this only for trusted local paths that already verified the
    /// credential, such as RPC admission and tx-fetch full-credential upgrade.
    pub fn insert_preverified(&self, tx: Transaction) -> Result<InsertOutcome, MempoolError> {
        self.insert_inner(tx, true)
    }

    /// Insert a transaction received from relay gossip.
    ///
    /// Full-credential transactions are re-validated locally. Relay-stripped
    /// transactions are admitted only as parked placeholders until the full
    /// credential arrives through tx-fetch or direct relay.
    pub fn insert_relay(&self, tx: Transaction) -> Result<InsertOutcome, MempoolError> {
        let skip_credential = tx.is_credential_stripped();
        self.insert_inner(tx, skip_credential)
    }

    fn insert_inner(
        &self,
        tx: Transaction,
        skip_credential: bool,
    ) -> Result<InsertOutcome, MempoolError> {
        TransactionValidator::validate(&tx, self.config.chain_id, self.config.max_tx_bytes)?;
        TransactionValidator::validate_approve_validator(&tx, self.config.founder_id_com)?;
        let is_mev_ace_omission_evidence = is_mev_ace_omission_evidence_payload(&tx.payload);
        if !is_mev_ace_omission_evidence {
            TransactionValidator::validate_slot(&tx, self.current_slot.load(Ordering::Acquire))?;
        }

        let hash = Self::tx_hash(&tx);

        if tx.raw_chain.is_some() && tx.zk_auth.is_some() {
            return Err(MempoolError::ValidationError(
                "raw_chain and zk_auth are mutually exclusive".into(),
            ));
        }
        let sender = tx.attestation.idcom;
        let nonce = sender_sequence_nonce(&tx)?;

        let is_bridge_deposit = ace_defi::is_bridge_deposit_payload(&tx.payload);
        let is_withdrawal_completion = ace_defi::is_withdrawal_completion_payload(&tx.payload);

        if is_bridge_deposit {
            self.validate_bridge_deposit_system_tx(&tx)?;
        } else if is_withdrawal_completion {
            self.validate_withdrawal_completion_system_tx(&tx)?;
        } else if is_mev_ace_omission_evidence {
            self.validate_mev_ace_omission_evidence_system_tx(&tx)?;
        } else if tx.is_zk_auth() {
            self.validate_zk_auth(&tx)?;
        } else if !skip_credential {
            self.validate_sender_credential(&tx)?;
        }

        // AR-ACE: originating node inserts a full-credential ML-DSA-44 tx into its
        // own mempool.  Other nodes receive the gossip-stripped version.  If the
        // full-credential variant arrives after the stripped one (race), upgrade the
        // entry in-place so the tx can be proposed with the real signature.
        if !tx.is_credential_stripped() {
            // Peek under a read lock first (cheap) before acquiring write lock.
            let is_upgrade = self
                .state
                .read()
                .pending
                .get(&hash)
                .map(|e| e.is_credential_stripped())
                .unwrap_or(false);
            if is_upgrade {
                let mut pool = self.state.write();
                // Re-check under write lock to avoid TOCTOU.
                if let Some(existing) = pool.pending.get(&hash) {
                    if existing.is_credential_stripped() {
                        let nonce_val = nonce;

                        pool.pending.insert(hash, tx);
                        pool.tx_states.insert(
                            hash,
                            if nonce_val.is_some() {
                                TxMempoolState::ReadyExecutable
                            } else {
                                TxMempoolState::UnorderedExecutable
                            },
                        );

                        // Fix Zombie Upgrade: Re-insert into lane.ready if it was demoted by drain_batch
                        if let Some(nonce_val) = nonce_val {
                            let lane = pool.senders.entry(sender).or_insert_with(|| SenderLane {
                                onchain_nonce: self.sender_onchain_nonce(sender),
                                ..SenderLane::default()
                            });
                            lane.ready.insert(nonce_val, hash);
                            self.promote_future_ready_locked(&mut pool, sender);
                        } else {
                            let lane = pool.senders.entry(sender).or_default();
                            lane.unordered.insert(hash);
                        }

                        // Re-admit to the ready set in case this tx was demoted by
                        // drain_batch while it was still stripped.  enqueue_ready_hash_locked
                        // is idempotent (no-op if already present).
                        self.enqueue_ready_hash_locked(&mut pool, hash);
                        return Ok(InsertOutcome {
                            tx_hash: hash,
                            became_ready: false,
                        });
                    }
                    // Was concurrently upgraded — treat as duplicate.
                    return Err(MempoolError::DuplicateTransaction(hash));
                }
                // Entry was removed (committed) between the read and write lock — fall through.
            }
        }

        let chain_nonce = self.sender_onchain_nonce(sender);

        let mut pool = self.state.write();
        self.sync_sender_lane_to_chain_locked(&mut pool, sender, chain_nonce);
        let was_ready_empty = pool.ready_members.is_empty();

        if let Some(_existing) = pool.pending.get(&hash) {
            return Err(MempoolError::DuplicateTransaction(hash));
        }
        if pool.pending.len() >= self.config.max_size {
            return Err(MempoolError::PoolFull {
                max: self.config.max_size,
            });
        }
        let lane_next_nonce = pool
            .senders
            .get(&sender)
            .map(SenderLane::next_expected_nonce)
            .unwrap_or(chain_nonce);
        let would_be_ready = nonce.is_some_and(|nonce_val| nonce_val == lane_next_nonce);
        let is_gap_fill = nonce.is_some_and(|nonce_val| {
            pool.senders
                .get(&sender)
                .is_some_and(|lane| lane.ready.is_empty() && !lane.future.is_empty())
                && nonce_val == lane_next_nonce
        });
        let ready_starved = pool.ready_members.len() < Self::READY_STARVATION_BYPASS_BELOW;
        if !(is_gap_fill || (ready_starved && would_be_ready)) {
            if let Some(err) = self.admission_overload_error(pool.pending.len()) {
                return Err(err);
            }
        }

        self.insert_validated_locked(&mut pool, tx, hash, sender, nonce, chain_nonce, false)?;

        self.update_metrics_locked(&pool);
        Ok(InsertOutcome {
            tx_hash: hash,
            became_ready: was_ready_empty && !pool.ready_members.is_empty(),
        })
    }

    fn validate_sender_credential(&self, tx: &Transaction) -> Result<(), MempoolError> {
        let Some(state) = &self.state_view else {
            #[cfg(feature = "test-utils")]
            return Ok(());
            #[cfg(not(feature = "test-utils"))]
            return Err(MempoolError::ValidationError(
                "mempool state not configured — cannot validate credentials".into(),
            ));
        };

        if let Some(raw_chain) = &tx.raw_chain {
            let state_guard = state.read();
            let state_tree = state_guard.default_shard();
            match raw_chain.kind {
                RawChainKind::Evm => {
                    let (signer, chain_id) =
                        verify_raw_evm_recover_signer_and_chain_id(&raw_chain.raw_bytes)
                            .map_err(|e| MempoolError::InvalidFormat(e.to_string()))?;
                    if chain_id != tx.attestation.domain.chain_id as u64 {
                        return Err(MempoolError::InvalidChainId {
                            expected: tx.attestation.domain.chain_id,
                            got: chain_id.try_into().unwrap_or(u32::MAX),
                        });
                    }
                    let expected_idcom = legacy_idcom_evm(&signer);
                    if tx.attestation.idcom != expected_idcom {
                        return Err(MempoolError::InvalidCredential(tx.attestation.idcom));
                    }
                    let expected_payload = canonical_evm_payload_from_raw(&raw_chain.raw_bytes)
                        .map_err(|e| MempoolError::InvalidFormat(e.to_string()))?;
                    if tx.payload != expected_payload {
                        return Err(MempoolError::InvalidFormat(
                            "evm raw payload does not match canonical reconstruction".into(),
                        ));
                    }
                }
                RawChainKind::Solana => {
                    let current_slot = self.current_slot.load(Ordering::Relaxed);
                    let verified = verify_raw_solana_transfer_against_state(
                        state_tree,
                        &raw_chain.raw_bytes,
                        self.config.chain_id,
                        current_slot,
                    )
                    .map_err(|e| MempoolError::InvalidFormat(e.to_string()))?;
                    if tx.attestation.idcom != verified.sender_idcom {
                        return Err(MempoolError::InvalidCredential(tx.attestation.idcom));
                    }
                    if tx.payload != verified.canonical_payload {
                        return Err(MempoolError::InvalidFormat(
                            "solana raw payload does not match canonical reconstruction".into(),
                        ));
                    }
                    if tx.attestation.domain.slot as u64 != verified.recent_slot {
                        return Err(MempoolError::InvalidFormat(
                            "solana attestation slot does not match recent blockhash slot".into(),
                        ));
                    }
                }
                RawChainKind::Btc => {
                    let verified = verify_raw_btc_against_state(state_tree, &raw_chain.raw_bytes)
                        .map_err(|e| MempoolError::InvalidFormat(e.to_string()))?;
                    if tx.attestation.idcom != verified.sender_idcom {
                        return Err(MempoolError::InvalidCredential(tx.attestation.idcom));
                    }
                    if tx.payload != verified.payload {
                        return Err(MempoolError::InvalidFormat(
                            "btc raw payload does not match canonical reconstruction".into(),
                        ));
                    }
                }
                RawChainKind::Tron => {
                    let verified = verify_raw_tron_against_state(state_tree, &raw_chain.raw_bytes)
                        .map_err(|e| MempoolError::InvalidFormat(e.to_string()))?;
                    if tx.attestation.idcom != verified.sender_idcom {
                        return Err(MempoolError::InvalidCredential(tx.attestation.idcom));
                    }
                    if tx.payload != verified.canonical_payload {
                        return Err(MempoolError::InvalidFormat(
                            "tron raw payload does not match canonical reconstruction".into(),
                        ));
                    }
                    if tx.attestation.domain.slot != verified.domain_slot {
                        return Err(MempoolError::InvalidFormat(
                            "tron attestation slot does not match canonical ACE domain slot".into(),
                        ));
                    }
                }
            }
            return Ok(());
        }

        let sender = AccountId::from_bytes(tx.attestation.idcom);
        let state_guard = state.read();

        let auth_pubkey = match (state_guard.get(&sender), TransactionOp::decode(&tx.payload)) {
            (
                Some(account),
                Ok(TransactionOp::SetAuthPubkey { auth_pubkey, .. })
                | Ok(TransactionOp::AddAuthKey { auth_pubkey, .. }),
            ) => {
                // If the account already has a non-zero key for this
                // algorithm, verify against it (key rotation).  Otherwise
                // bootstrap with the new key from the payload.
                let sig_alg = tx.attestation.credential.algorithm;
                match account.auth_key_for_algorithm(sig_alg) {
                    Some(k) if !k.is_zero() => k.clone(),
                    _ => {
                        // Mirror the executor guard (ace-engine): once any signer is
                        // provisioned, installing a key for a new algorithm must be
                        // signed with an existing key — not self-signed by the new
                        // payload key. Only a fully unprovisioned account may bootstrap
                        // against the payload key. Keeping mempool admission consistent
                        // with execution avoids admitting txs that always fail.
                        if account.has_provisioned_auth_key() {
                            if !account.auth_pubkey.is_zero() {
                                account.auth_pubkey.clone()
                            } else if let Some(k) = account.auth_keys.iter().find(|k| !k.is_zero())
                            {
                                k.clone()
                            } else {
                                auth_pubkey
                            }
                        } else {
                            auth_pubkey
                        }
                    }
                }
            }
            (Some(account), _) => {
                let sig_alg = tx.attestation.credential.algorithm;
                account
                    .auth_key_for_algorithm(sig_alg)
                    .unwrap_or(&account.auth_pubkey)
                    .clone()
            }
            (
                None,
                Ok(TransactionOp::CreateAccount {
                    id_com,
                    auth_pubkey,
                }),
            ) if id_com == sender => auth_pubkey,
            _ => return Err(MempoolError::UnknownSender(sender.0)),
        };

        if !verify_credential(&tx.attestation, &tx.payload, &auth_pubkey) {
            return Err(MempoolError::InvalidCredential(sender.0));
        }
        Ok(())
    }

    fn validate_bridge_deposit_system_tx(&self, tx: &Transaction) -> Result<(), MempoolError> {
        let Some(state) = &self.state_view else {
            return Err(MempoolError::ValidationError(
                "mempool state not configured — cannot validate bridge deposit".into(),
            ));
        };
        let signed = ace_defi::decode_signed_deposit_payload(&tx.payload)
            .map_err(|e| MempoolError::ValidationError(e.to_string()))?;
        let expected_idcom = ace_defi::bridge_deposit_tx_idcom(&signed);
        if tx.attestation.idcom != expected_idcom {
            return Err(MempoolError::ValidationError(
                "bridge deposit idcom does not match relayer pubkey".into(),
            ));
        }
        let state_guard = state.read();
        ace_defi::verify_signed_deposit_against_state(state_guard.default_shard(), &signed)
            .map_err(|e| MempoolError::ValidationError(e.to_string()))
    }

    fn validate_withdrawal_completion_system_tx(
        &self,
        tx: &Transaction,
    ) -> Result<(), MempoolError> {
        let Some(state) = &self.state_view else {
            return Err(MempoolError::ValidationError(
                "mempool state not configured — cannot validate withdrawal completion".into(),
            ));
        };
        let completion = ace_defi::decode_withdrawal_completion_payload(&tx.payload)
            .map_err(|e| MempoolError::ValidationError(e.to_string()))?;
        let expected_idcom = ace_defi::withdrawal_completion_tx_idcom(&completion);
        if tx.attestation.idcom != expected_idcom {
            return Err(MempoolError::ValidationError(
                "withdrawal completion idcom does not match relayer pubkey".into(),
            ));
        }
        let state_guard = state.read();
        ace_defi::verify_withdrawal_completion_against_state(
            state_guard.default_shard(),
            &completion,
        )
        .map_err(|e| MempoolError::ValidationError(e.to_string()))
    }

    fn validate_mev_ace_omission_evidence_system_tx(
        &self,
        tx: &Transaction,
    ) -> Result<(), MempoolError> {
        let proof = decode_mev_ace_omission_evidence_payload(&tx.payload)
            .map_err(MempoolError::ValidationError)?;
        let expected_idcom = mev_ace_omission_evidence_tx_idcom(&proof);
        if tx.attestation.idcom != expected_idcom {
            return Err(MempoolError::ValidationError(
                "MEV-ACE omission evidence idcom does not match proof".into(),
            ));
        }
        Ok(())
    }

    /// Validate a ZK-ACE authorization proof on mempool admission.
    ///
    /// This is the fast path: Circle STARK verification is ~sub-ms and the same
    /// cost regardless of whether the underlying key is Ed25519 or ML-DSA-44.
    fn validate_zk_auth(&self, tx: &Transaction) -> Result<(), MempoolError> {
        let Some(zk_auth) = tx.zk_auth.as_ref() else {
            return Err(MempoolError::ValidationError(
                "tx.is_zk_auth() true but zk_auth field is None".into(),
            ));
        };

        if self.state.read().pending.values().any(|pending| {
            pending
                .zk_auth
                .as_ref()
                .is_some_and(|pending_zk| pending_zk.rp_com == zk_auth.rp_com)
        }) {
            return Err(MempoolError::ValidationError(
                "ZK-ACE replay commitment already pending".into(),
            ));
        }

        let Some(state) = &self.state_view else {
            #[cfg(feature = "test-utils")]
            return Ok(());
            #[cfg(not(feature = "test-utils"))]
            return Err(MempoolError::ValidationError(
                "mempool state not configured — cannot validate ZK replay registry".into(),
            ));
        };

        let state_guard = state.read();
        let replay_guard = StateReplayGuard::new(state_guard.default_shard());
        verify_zk_authorization(tx, &replay_guard)
    }

    /// Remove a transaction by hash. Returns the transaction if found.
    pub fn remove(&self, tx_hash: &[u8; 32]) -> Option<Transaction> {
        let mut pool = self.state.write();
        let removed = pool.pending.remove(tx_hash);
        if let Some(ref tx) = removed {
            pool.tx_states.remove(tx_hash);
            self.remove_from_sender_lane_locked(&mut pool, tx, tx_hash);
            self.remove_hash_from_ready_queue(&mut pool, tx_hash);
            self.sync_sender_lane_to_chain_locked(
                &mut pool,
                tx.attestation.idcom,
                self.sender_onchain_nonce(tx.attestation.idcom),
            );

            self.update_metrics_locked(&pool);
        }
        removed
    }

    /// Check whether a transaction is in the mempool.
    pub fn contains(&self, tx_hash: &[u8; 32]) -> bool {
        self.state.read().pending.contains_key(tx_hash)
    }

    /// Get a transaction by hash.
    pub fn get(&self, tx_hash: &[u8; 32]) -> Option<Transaction> {
        self.state.read().pending.get(tx_hash).cloned()
    }

    /// Snapshot all pending transactions, including future nonces.
    pub fn pending_transactions(&self) -> Vec<Transaction> {
        self.state.read().pending.values().cloned().collect()
    }

    /// Snapshot only the ready transactions visible to block production.
    pub fn ready_transactions(&self) -> Vec<Transaction> {
        let mut pool = self.state.write();
        self.sync_all_sender_lanes_to_chain_locked(&mut pool);
        self.update_metrics_locked(&pool);
        pool.ready_queue
            .iter()
            .filter(|hash| pool.ready_members.contains(*hash))
            .filter_map(|hash| pool.pending.get(hash).cloned())
            .filter(|tx| !tx.is_credential_stripped())
            .collect()
    }

    /// Evict stale future-only lanes whose gap-filling nonce never arrived.
    ///
    /// Stripped relay placeholders are protocol-level parked entries and are
    /// intentionally not reclaimed here; they remain available for tx-fetch
    /// upgrade or until the nonce advances on chain.
    ///
    /// Called periodically from the consensus loop.  After eviction, sender lanes
    /// are re-synced so any remaining txs resume normal processing immediately.
    pub fn evict_stale_future_txs(&self) {
        let mut pool = self.state.write();
        self.sync_all_sender_lanes_to_chain_locked(&mut pool);

        let senders: Vec<[u8; 32]> = pool.senders.keys().copied().collect();
        let mut future_only_evict_budget = Self::FUTURE_ONLY_EVICT_PER_RUN;
        let mut evicted = 0usize;

        for sender in senders {
            let Some(lane) = pool.senders.get(&sender) else {
                continue;
            };

            // ── Stale future-only lane ─────────────────────────────────────
            // A future-only lane is healthy briefly: tx N+1 can arrive before tx N
            // under high fan-out or peer delay. It becomes unhealthy once it
            // persists across multiple consensus heights with no ready tx, because
            // the missing gap nonce may never arrive. Keeping those futures resident
            // pins pending_count above admission watermarks while block production
            // has nothing for this sender to drain.
            let current_slot = self.current_slot.load(Ordering::Acquire);
            let evict_future_only = lane.ready.is_empty()
                && !lane.future.is_empty()
                && lane.future_only_since_slot.is_some_and(|since| {
                    current_slot.saturating_sub(since) >= Self::FUTURE_ONLY_EVICT_AFTER_SLOTS
                });

            if evict_future_only && future_only_evict_budget > 0 {
                future_only_evict_budget -= 1;
                let future_hashes: Vec<[u8; 32]> = lane.future.values().copied().collect();
                evicted += future_hashes.len();
                for hash in &future_hashes {
                    pool.pending.remove(hash);
                    pool.tx_states.remove(hash);
                    pool.ready_members.remove(hash);
                    self.remove_hash_from_ready_queue(&mut pool, hash);
                }
                if let Some(lane) = pool.senders.get_mut(&sender) {
                    lane.future.clear();
                    lane.future_only_since_slot = None;
                }
                if pool.senders.get(&sender).is_some_and(SenderLane::is_empty) {
                    pool.senders.remove(&sender);
                }
            } else if let Some(lane) = pool.senders.get_mut(&sender) {
                if lane.ready.is_empty() && !lane.future.is_empty() {
                    lane.future_only_since_slot.get_or_insert(current_slot);
                } else {
                    lane.future_only_since_slot = None;
                }
            }
        }

        if evicted > 0 {
            self.update_metrics_locked(&pool);
            tracing::warn!(
                evicted,
                pending = pool.pending.len(),
                "mempool GC: evicted stale future-only lanes"
            );
        }
    }

    /// Drain up to `max` ready transactions in FIFO order for block production.
    pub fn drain_batch(&self, max: usize) -> Vec<Transaction> {
        let mut pool = self.state.write();
        self.sync_all_sender_lanes_to_chain_locked(&mut pool);
        let mut batch = Vec::with_capacity(max.min(pool.ready_members.len()));
        while batch.len() < max {
            let Some(hash) = pool.ready_queue.pop_front() else {
                break;
            };
            if !pool.ready_members.contains(&hash) {
                continue;
            }
            let Some(tx) = pool.pending.get(&hash) else {
                pool.ready_members.remove(&hash);
                continue;
            };
            // Stripped relay placeholders are not locally executable and should
            // not normally reach ready_members. If an old entry is present, park
            // it and leave the nonce lane intact until full credential upgrade.
            if tx.is_credential_stripped() {
                pool.ready_members.remove(&hash);
                pool.tx_states
                    .insert(hash, TxMempoolState::ParkedStrippedCredential);
                continue;
            }
            pool.ready_members.remove(&hash);
            let tx = pool.pending.remove(&hash).expect("pending entry present");
            pool.tx_states.remove(&hash);
            self.remove_from_sender_lane_locked(&mut pool, &tx, &hash);
            batch.push(tx);
        }

        self.update_metrics_locked(&pool);
        batch
    }

    /// Requeue transactions back into the mempool (after rollback/defer).
    pub fn requeue(&self, txs: Vec<Transaction>) {
        let mut pool = self.state.write();
        self.sync_all_sender_lanes_to_chain_locked(&mut pool);

        for tx in txs {
            if pool.pending.len() >= self.config.max_size {
                break;
            }
            let hash = Self::tx_hash(&tx);
            if pool.pending.contains_key(&hash) {
                continue;
            }
            let sender = tx.attestation.idcom;
            let nonce = match sender_sequence_nonce(&tx) {
                Ok(nonce) => nonce,
                Err(_) => continue,
            };
            let chain_nonce = self.sender_onchain_nonce(sender);
            self.sync_sender_lane_to_chain_locked(&mut pool, sender, chain_nonce);
            if self
                .insert_validated_locked(&mut pool, tx, hash, sender, nonce, chain_nonce, true)
                .is_err()
            {
                continue;
            }
        }

        self.update_metrics_locked(&pool);
    }

    /// Park drained transactions that are known not to be currently proposable.
    pub fn requeue_parked(&self, txs: Vec<Transaction>, reason: ParkedTxReason) {
        let mut pool = self.state.write();
        self.sync_all_sender_lanes_to_chain_locked(&mut pool);

        for tx in txs {
            if pool.pending.len() >= self.config.max_size {
                break;
            }
            let hash = Self::tx_hash(&tx);
            if pool.pending.contains_key(&hash) {
                pool.tx_states.insert(hash, reason.state());
                self.remove_hash_from_ready_queue(&mut pool, &hash);
                continue;
            }
            let sender = tx.attestation.idcom;
            let nonce = match sender_sequence_nonce(&tx) {
                Ok(nonce) => nonce,
                Err(_) => continue,
            };
            let chain_nonce = self.sender_onchain_nonce(sender);
            self.sync_sender_lane_to_chain_locked(&mut pool, sender, chain_nonce);
            if self
                .insert_validated_locked(&mut pool, tx, hash, sender, nonce, chain_nonce, true)
                .is_err()
            {
                continue;
            }
            pool.tx_states.insert(hash, reason.state());
            self.remove_hash_from_ready_queue(&mut pool, &hash);
        }

        self.update_metrics_locked(&pool);
    }

    /// Re-activate a committee-parked transaction after new approval material arrives.
    pub fn promote_parked_committee(&self, tx_hash: &[u8; 32]) -> bool {
        let mut pool = self.state.write();
        if !matches!(
            pool.tx_states.get(tx_hash),
            Some(TxMempoolState::ParkedMissingCommitteeCertificate)
        ) {
            return false;
        }
        let Some(tx) = pool.pending.get(tx_hash) else {
            pool.tx_states.remove(tx_hash);
            return false;
        };
        if tx.is_credential_stripped() {
            pool.tx_states
                .insert(*tx_hash, TxMempoolState::ParkedStrippedCredential);
            return false;
        }
        let sender = tx.attestation.idcom;
        let executable = match sender_sequence_nonce(tx) {
            Ok(Some(nonce)) => pool
                .senders
                .get(&sender)
                .is_some_and(|lane| lane.ready.get(&nonce) == Some(tx_hash)),
            Ok(None) => pool
                .senders
                .get(&sender)
                .is_some_and(|lane| lane.unordered.contains(tx_hash)),
            Err(_) => false,
        };
        if !executable {
            return false;
        }
        pool.tx_states
            .insert(*tx_hash, TxMempoolState::ReadyExecutable);
        self.enqueue_ready_hash_locked(&mut pool, *tx_hash);
        self.update_metrics_locked(&pool);
        true
    }

    /// Re-activate witness-parked transactions whose local witness has become available.
    pub fn promote_parked_witnesses<F>(&self, mut can_promote: F) -> usize
    where
        F: FnMut(&Transaction) -> bool,
    {
        let mut pool = self.state.write();
        let hashes: Vec<[u8; 32]> = pool
            .tx_states
            .iter()
            .filter_map(|(hash, state)| {
                matches!(state, TxMempoolState::ParkedMissingWitness).then_some(*hash)
            })
            .filter(|hash| pool.pending.get(hash).is_some_and(|tx| can_promote(tx)))
            .collect();

        let mut promoted = 0usize;
        for hash in hashes {
            let Some(tx) = pool.pending.get(&hash) else {
                pool.tx_states.remove(&hash);
                continue;
            };
            if tx.is_credential_stripped() {
                pool.tx_states
                    .insert(hash, TxMempoolState::ParkedStrippedCredential);
                continue;
            }
            let sender = tx.attestation.idcom;
            let executable = match sender_sequence_nonce(tx) {
                Ok(Some(nonce)) => pool
                    .senders
                    .get(&sender)
                    .is_some_and(|lane| lane.ready.get(&nonce) == Some(&hash)),
                Ok(None) => pool
                    .senders
                    .get(&sender)
                    .is_some_and(|lane| lane.unordered.contains(&hash)),
                Err(_) => false,
            };
            if executable {
                pool.tx_states.insert(hash, TxMempoolState::ReadyExecutable);
                self.enqueue_ready_hash_locked(&mut pool, hash);
                promoted += 1;
            }
        }

        if promoted > 0 {
            self.update_metrics_locked(&pool);
        }
        promoted
    }

    /// Number of pending transactions (ready + future).
    pub fn pending_count(&self) -> usize {
        self.state.read().pending.len()
    }

    /// Number of ready transactions currently eligible for proposal.
    pub fn ready_count(&self) -> usize {
        self.state.read().ready_members.len()
    }

    /// Count transactions by protocol admission state.
    pub fn state_counts(&self) -> MempoolStateCounts {
        let pool = self.state.read();
        self.state_counts_locked(&pool)
    }

    /// Return the next nonce a sender should use, accounting for pending
    /// transactions in the mempool.  Falls back to `None` when the sender has
    /// no lane (caller should use the on-chain nonce instead).
    pub fn pending_nonce(&self, sender: &[u8; 32]) -> Option<u64> {
        let pool = self.state.read();
        pool.senders
            .get(sender)
            .map(|lane| lane.next_expected_nonce())
    }

    fn insert_validated_locked(
        &self,
        pool: &mut PoolState,
        tx: Transaction,
        hash: [u8; 32],
        sender: [u8; 32],
        nonce: Option<u64>,
        chain_nonce: u64,
        bypass_overload: bool,
    ) -> Result<(), MempoolError> {
        let lane = pool.senders.entry(sender).or_insert_with(|| SenderLane {
            onchain_nonce: chain_nonce,
            ..SenderLane::default()
        });
        if chain_nonce > lane.onchain_nonce {
            lane.onchain_nonce = chain_nonce;
        }
        if lane.total_count() >= MAX_TXS_PER_SENDER {
            return Err(MempoolError::PoolFull {
                max: MAX_TXS_PER_SENDER,
            });
        }

        match nonce {
            Some(nonce) => {
                if lane.ready.contains_key(&nonce) || lane.future.contains_key(&nonce) {
                    return Err(MempoolError::SenderNonceConflict { sender, nonce });
                }

                let expected = lane.next_expected_nonce();
                if nonce < expected {
                    return Err(MempoolError::StaleNonce {
                        sender,
                        expected,
                        got: nonce,
                    });
                }

                if nonce == expected {
                    // Insert into pending BEFORE promote so that
                    // promote_future_ready_locked can inspect this tx's
                    // credential (e.g. is_credential_stripped) correctly.
                    let is_stripped = tx.is_credential_stripped();
                    pool.pending.insert(hash, tx);
                    pool.tx_states.insert(
                        hash,
                        if is_stripped {
                            TxMempoolState::ParkedStrippedCredential
                        } else {
                            TxMempoolState::ReadyExecutable
                        },
                    );
                    lane.ready.insert(nonce, hash);
                    lane.future_only_since_slot = None;
                    self.enqueue_ready_hash_locked(pool, hash);
                    self.promote_future_ready_locked(pool, sender);
                    return Ok(());
                } else {
                    if lane.future.len() >= self.config.max_future_txs_per_sender {
                        return Err(MempoolError::FutureQueueFull {
                            sender,
                            max_pending_future: self.config.max_future_txs_per_sender,
                        });
                    }
                    if nonce.saturating_sub(expected) > self.config.max_future_nonce_gap {
                        return Err(MempoolError::FutureNonceGap {
                            sender,
                            expected,
                            got: nonce,
                            max_gap: self.config.max_future_nonce_gap,
                        });
                    }
                    lane.future.insert(nonce, hash);
                    pool.tx_states.insert(hash, TxMempoolState::FutureNonce);
                    if lane.ready.is_empty() {
                        let current_slot = self.current_slot.load(Ordering::Acquire);
                        lane.future_only_since_slot.get_or_insert(current_slot);
                    }
                }
            }
            None => {
                if !bypass_overload {
                    if let Some(err) = self.admission_overload_error(pool.pending.len()) {
                        return Err(err);
                    }
                }
                let is_stripped = tx.is_credential_stripped();
                lane.unordered.insert(hash);
                pool.tx_states.insert(
                    hash,
                    if is_stripped {
                        TxMempoolState::ParkedStrippedCredential
                    } else {
                        TxMempoolState::UnorderedExecutable
                    },
                );
                if !is_stripped {
                    self.enqueue_ready_hash_locked(pool, hash);
                }
            }
        }

        pool.pending.insert(hash, tx);
        Ok(())
    }

    fn sender_onchain_nonce(&self, sender: [u8; 32]) -> u64 {
        let Some(state) = &self.state_view else {
            return 0;
        };
        state
            .read()
            .get(&AccountId::from_bytes(sender))
            .map(|account| account.nonce)
            .unwrap_or(0)
    }

    fn sync_all_sender_lanes_to_chain_locked(&self, pool: &mut PoolState) {
        let Some(state_view) = &self.state_view else {
            return;
        };
        let current_slot = self.current_slot.load(Ordering::Acquire);
        if pool.last_chain_sync_slot == Some(current_slot) {
            self.compact_ready_queue_locked(pool);
            return;
        }
        let state_guard = state_view.read();
        let senders: Vec<[u8; 32]> = pool.senders.keys().copied().collect();
        for sender in senders {
            let chain_nonce = state_guard
                .get(&AccountId::from_bytes(sender))
                .map(|account| account.nonce)
                .unwrap_or(0);
            self.sync_sender_lane_to_chain_locked(pool, sender, chain_nonce);
            if current_slot > 100 {
                self.evict_stale_slot_txs_locked(pool, sender, current_slot);
            }
        }
        pool.last_chain_sync_slot = Some(current_slot);
        self.compact_ready_queue_locked(pool);
    }

    fn sync_sender_lane_to_chain_locked(
        &self,
        pool: &mut PoolState,
        sender: [u8; 32],
        chain_nonce: u64,
    ) {
        let Some(current_lane) = pool.senders.get(&sender) else {
            return;
        };
        if chain_nonce <= current_lane.onchain_nonce {
            return;
        }

        let (stale_ready, stale_future) = {
            let lane = pool
                .senders
                .get_mut(&sender)
                .expect("sender lane must exist");
            let stale_ready: Vec<[u8; 32]> = lane
                .ready
                .iter()
                .filter(|(nonce, _)| **nonce < chain_nonce)
                .map(|(_, hash)| *hash)
                .collect();
            let stale_future: Vec<[u8; 32]> = lane
                .future
                .iter()
                .filter(|(nonce, _)| **nonce < chain_nonce)
                .map(|(_, hash)| *hash)
                .collect();

            lane.ready.retain(|nonce, _| *nonce >= chain_nonce);
            lane.future.retain(|nonce, _| *nonce >= chain_nonce);
            lane.onchain_nonce = chain_nonce;
            if lane.ready.is_empty() && !lane.future.is_empty() {
                let current_slot = self.current_slot.load(Ordering::Acquire);
                lane.future_only_since_slot.get_or_insert(current_slot);
            } else {
                lane.future_only_since_slot = None;
            }
            (stale_ready, stale_future)
        };

        for hash in stale_ready.into_iter().chain(stale_future) {
            pool.pending.remove(&hash);
            pool.tx_states.remove(&hash);
            self.remove_hash_from_ready_queue(pool, &hash);
        }

        self.promote_future_ready_locked(pool, sender);
        if pool.senders.get(&sender).is_some_and(SenderLane::is_empty) {
            pool.senders.remove(&sender);
        }
    }

    /// Evict native ACE txs whose domain.slot is expired or close enough to expiry
    /// that proposal/validation delay can make them fail execution.  This keeps
    /// near-expired txs out of blocks and avoids repeatedly draining/requeueing
    /// the same tx during proposal selection.
    fn evict_stale_slot_txs_locked(
        &self,
        pool: &mut PoolState,
        sender: [u8; 32],
        current_slot: u64,
    ) {
        let freshness_cutoff = current_slot
            .saturating_sub(Self::DOMAIN_SLOT_TOLERANCE.saturating_sub(Self::SLOT_FRESHNESS_GUARD));
        let stale_hashes: Vec<[u8; 32]> = {
            let Some(lane) = pool.senders.get(&sender) else {
                return;
            };
            let hashes: Vec<[u8; 32]> = lane
                .ready
                .values()
                .chain(lane.future.values())
                .copied()
                .collect();
            hashes
                .into_iter()
                .filter(|hash| {
                    pool.pending.get(hash).map_or(false, |tx| {
                        // Only evict native ACE txs (raw_chain = None).
                        // Raw-chain txs (Tron, committee-approved EVM, etc.) do not
                        // have domain.slot enforced at execution time, so evicting
                        // them based on slot staleness would be incorrect.
                        tx.raw_chain.is_none()
                            && (tx.attestation.domain.slot as u64) < freshness_cutoff
                    })
                })
                .collect()
        };
        if stale_hashes.is_empty() {
            return;
        }
        {
            let lane = pool.senders.get_mut(&sender).expect("lane must exist");
            lane.ready.retain(|_, h| !stale_hashes.contains(h));
            lane.future.retain(|_, h| !stale_hashes.contains(h));
        }
        for hash in &stale_hashes {
            pool.pending.remove(hash);
            pool.tx_states.remove(hash);
            self.remove_hash_from_ready_queue(pool, hash);
        }
        self.promote_future_ready_locked(pool, sender);
        if pool.senders.get(&sender).is_some_and(SenderLane::is_empty) {
            pool.senders.remove(&sender);
        }
    }

    fn promote_future_ready_locked(&self, pool: &mut PoolState, sender: [u8; 32]) {
        let mut promoted = Vec::new();
        loop {
            let expected = {
                let Some(lane) = pool.senders.get(&sender) else {
                    break;
                };
                let e = lane.next_expected_nonce();
                // Do not promote futures past a stripped tx in lane.ready.
                // Stripped txs block this sender's nonce pipeline until committed
                // by another proposer (the one holding the full credential).
                let blocked = lane.ready.range(lane.onchain_nonce..e).any(|(_, h)| {
                    pool.pending
                        .get(h)
                        .map_or(false, |tx| tx.is_credential_stripped())
                });
                if blocked || !lane.future.contains_key(&e) {
                    break;
                }
                e
            };
            let Some(lane) = pool.senders.get_mut(&sender) else {
                break;
            };
            let Some(hash) = lane.future.remove(&expected) else {
                break;
            };
            lane.ready.insert(expected, hash);
            lane.future_only_since_slot = None;
            pool.tx_states.insert(
                hash,
                if pool
                    .pending
                    .get(&hash)
                    .map_or(false, |tx| tx.is_credential_stripped())
                {
                    TxMempoolState::ParkedStrippedCredential
                } else {
                    TxMempoolState::ReadyExecutable
                },
            );
            promoted.push(hash);
        }
        for hash in promoted {
            self.enqueue_ready_hash_locked(pool, hash);
        }
    }

    fn remove_from_sender_lane_locked(
        &self,
        pool: &mut PoolState,
        tx: &Transaction,
        tx_hash: &[u8; 32],
    ) {
        let sender = tx.attestation.idcom;
        let Some(lane) = pool.senders.get_mut(&sender) else {
            return;
        };
        match sender_sequence_nonce(tx) {
            Ok(Some(nonce)) => {
                lane.ready.remove(&nonce);
                lane.future.remove(&nonce);
            }
            _ => {
                lane.unordered.remove(tx_hash);
            }
        }
        if lane.is_empty() {
            pool.senders.remove(&sender);
        }
    }

    fn enqueue_ready_hash_locked(&self, pool: &mut PoolState, tx_hash: [u8; 32]) {
        if pool
            .pending
            .get(&tx_hash)
            .map_or(false, |tx| tx.is_credential_stripped())
        {
            pool.tx_states
                .insert(tx_hash, TxMempoolState::ParkedStrippedCredential);
            return;
        }
        if pool.ready_members.insert(tx_hash) {
            pool.ready_queue.push_back(tx_hash);
        }
    }

    fn remove_hash_from_ready_queue(&self, pool: &mut PoolState, tx_hash: &[u8; 32]) {
        if pool.ready_members.remove(tx_hash)
            && pool.ready_members.is_empty()
            && pool.ready_queue.len() > 64
        {
            pool.ready_queue.clear();
        }
    }

    fn compact_ready_queue_locked(&self, pool: &mut PoolState) {
        let live = pool.ready_members.len();
        let max_queue_len = live.saturating_mul(2).saturating_add(64);
        if pool.ready_queue.len() <= max_queue_len {
            return;
        }
        let ready_members = &pool.ready_members;
        pool.ready_queue.retain(|hash| ready_members.contains(hash));
    }

    fn admission_high_watermark(&self) -> usize {
        self.config
            .admission_high_watermark
            .min(self.config.max_size)
    }

    fn admission_low_watermark(&self) -> usize {
        self.config
            .admission_low_watermark
            .min(self.admission_high_watermark().saturating_sub(1))
    }

    fn update_metrics(&self) {
        let pool = self.state.read();
        self.update_metrics_locked(&pool);
    }

    fn update_metrics_locked(&self, pool: &PoolState) {
        gauge!("ace_mempool_pending").set(pool.pending.len() as f64);
        gauge!("ace_mempool_ready").set(pool.ready_members.len() as f64);
        let counts = self.state_counts_locked(pool);
        gauge!("ace_mempool_ready_executable").set(counts.ready_executable as f64);
        gauge!("ace_mempool_future_nonce").set(counts.future_nonce as f64);
        gauge!("ace_mempool_parked_stripped_credential")
            .set(counts.parked_stripped_credential as f64);
        gauge!("ace_mempool_parked_missing_witness").set(counts.parked_missing_witness as f64);
        gauge!("ace_mempool_parked_missing_committee_certificate")
            .set(counts.parked_missing_committee_certificate as f64);
        gauge!("ace_mempool_unordered_executable").set(counts.unordered_executable as f64);
    }

    fn state_counts_locked(&self, pool: &PoolState) -> MempoolStateCounts {
        let mut counts = MempoolStateCounts {
            pending_total: pool.pending.len(),
            ..MempoolStateCounts::default()
        };
        for state in pool.tx_states.values() {
            match state {
                TxMempoolState::ReadyExecutable => counts.ready_executable += 1,
                TxMempoolState::FutureNonce => counts.future_nonce += 1,
                TxMempoolState::ParkedStrippedCredential => counts.parked_stripped_credential += 1,
                TxMempoolState::ParkedMissingWitness => counts.parked_missing_witness += 1,
                TxMempoolState::ParkedMissingCommitteeCertificate => {
                    counts.parked_missing_committee_certificate += 1
                }
                TxMempoolState::UnorderedExecutable => counts.unordered_executable += 1,
            }
        }
        counts
    }

    /// Record a committed block's effective throughput.  Updates the EMA used
    /// to derive dynamic admission watermarks.
    ///
    /// `tx_ok` is the number of successfully executed transactions; `tx_total`
    /// is the total number of transactions in the block.  Pass both so the
    /// guard can distinguish two cases:
    ///
    /// - `tx_total == 0`: truly empty block (idle period) — skip to avoid
    ///   dragging the average to zero during low-traffic windows.
    /// - `tx_ok == 0` but `tx_total > 0`: bad-execution block (all txs failed
    ///   due to slot expiry, invalid nonce, etc.) — update EMA with 0 so the
    ///   watermark reflects the actual effective throughput and admission
    ///   tightens, helping the mempool recover faster.
    pub fn record_committed_block(&self, tx_ok: usize, tx_total: usize) {
        if tx_total == 0 {
            return; // truly empty block: don't distort the EMA during idle periods
        }
        self.committed_block_count.fetch_add(1, Ordering::Relaxed);
        let old = self.avg_block_txs.load(Ordering::Relaxed);
        let new_avg = if old == 0 {
            tx_ok
        } else {
            // EMA alpha ≈ 0.2: new = old * 4/5 + sample * 1/5
            (old * 4 + tx_ok) / 5
        };
        self.avg_block_txs.store(new_avg, Ordering::Relaxed);
    }

    /// Dynamic admission watermarks derived from recent block throughput.
    /// Returns (high, low) or `None` if no blocks have been committed yet
    /// (falls back to static config).
    /// Minimum dynamic high watermark.  Ensures the mempool always admits
    /// a reasonable burst even when average block size is tiny (e.g. during
    /// account preparation or low-traffic periods).  Set high enough that
    /// non-proposer nodes (which accumulate gossip delay) don't enter the
    /// probabilistic rejection zone during normal operation.
    const MIN_DYNAMIC_HIGH: usize = 2_000;

    /// Minimum number of non-empty committed blocks before switching from
    /// static to dynamic watermarks.  Prevents the first few small blocks
    /// (e.g. account preparation during warm-up) from collapsing the
    /// watermarks to MIN_DYNAMIC_HIGH and throttling startup throughput.
    ///
    /// Set to 30 so the EMA spans the full proposal-budget ramp-up period
    /// (~5 blocks to reach MAX_BUDGET from INITIAL_BUDGET) plus a healthy
    /// margin.  With a 3-node round-robin schedule, 30 non-empty blocks
    /// committed ≈ 12 s of real load, at which point the EMA reflects the
    /// chain's true steady-state throughput rather than small startup blocks.
    const MIN_BLOCKS_FOR_DYNAMIC: usize = 30;

    fn dynamic_watermarks(&self) -> Option<(usize, usize)> {
        if self.committed_block_count.load(Ordering::Relaxed) < Self::MIN_BLOCKS_FOR_DYNAMIC {
            // Not enough history yet — fall back to static watermarks.
            return None;
        }
        // avg == 0 no longer means "no data" (that case is handled above);
        // it means the EMA was dragged to zero by consecutive bad-execution
        // blocks (tx_ok=0).  In that state we must NOT fall back to the
        // static high watermark (8000), which would re-open admission and
        // slow recovery.  Instead, clamp to MIN_DYNAMIC_HIGH so the mempool
        // stays tight but doesn't completely reject new txs.
        let avg = self.avg_block_txs.load(Ordering::Relaxed);
        // high = 5× average block size (generous buffer for multi-node
        //        topologies where non-proposer mempools accumulate during
        //        gossip delay), floored at MIN_DYNAMIC_HIGH.
        // low  = 3× average block size (start gradual backpressure),
        //        floored at MIN_DYNAMIC_HIGH / 2.
        let high = (avg * 5)
            .max(Self::MIN_DYNAMIC_HIGH)
            .min(self.config.max_size);
        let low = (avg * 3)
            .max(Self::MIN_DYNAMIC_HIGH / 2)
            .min(high.saturating_sub(1));
        Some((high, low))
    }

    fn admission_overload_error(&self, pending_len: usize) -> Option<MempoolError> {
        // Use dynamic watermarks when available, otherwise static config.
        let (high, low) = self.dynamic_watermarks().unwrap_or_else(|| {
            (
                self.admission_high_watermark(),
                self.admission_low_watermark(),
            )
        });
        // Hard reject above high watermark.
        if pending_len >= high {
            return Some(MempoolError::Overloaded {
                queued: pending_len,
                high_watermark: high,
                low_watermark: low,
            });
        }
        // Probabilistic rejection between low and high watermark.
        // Reject probability grows linearly from 0% at low to 100% at high,
        // giving clients a gradual backpressure signal instead of a cliff.
        if pending_len > low {
            let range = high.saturating_sub(low).max(1);
            let excess = pending_len - low;
            let reject_pct = (excess * 100) / range;
            let seq = self.admission_counter.fetch_add(1, Ordering::Relaxed);
            // splitmix64 finalizer for uniform distribution
            let mut h = seq;
            h ^= h >> 30;
            h = h.wrapping_mul(0xbf58476d1ce4e5b9);
            h ^= h >> 27;
            h = h.wrapping_mul(0x94d049bb133111eb);
            h ^= h >> 31;
            let r = h % 100;
            if (r as usize) < reject_pct {
                return Some(MempoolError::Overloaded {
                    queued: pending_len,
                    high_watermark: high,
                    low_watermark: low,
                });
            }
        }
        None
    }
}

fn sender_sequence_nonce(tx: &Transaction) -> Result<Option<u64>, MempoolError> {
    if tx.is_zk_auth() {
        return Ok(None);
    }

    if let Some(raw_chain) = &tx.raw_chain {
        return match raw_chain.kind {
            RawChainKind::Evm => decode_raw_evm_nonce(&raw_chain.raw_bytes)
                .map(Some)
                .map_err(|e| MempoolError::InvalidFormat(e.to_string())),
            RawChainKind::Solana | RawChainKind::Btc | RawChainKind::Tron => Ok(None),
        };
    }

    if tx.payload.len() >= 9 {
        match tx.payload[0] {
            0x21 | 0x30 | 0x31 | 0x50..=0x5F => {
                let nonce = u64::from_le_bytes(tx.payload[1..9].try_into().unwrap());
                return Ok(Some(nonce));
            }
            _ => {}
        }
    }

    match TransactionOp::decode(&tx.payload) {
        Ok(TransactionOp::Transfer { nonce, .. }) => Ok(Some(nonce)),
        Ok(TransactionOp::SetAuthPubkey { nonce, .. }) => Ok(Some(nonce)),
        Ok(TransactionOp::AddAuthKey { nonce, .. }) => Ok(Some(nonce)),
        Ok(_) => Ok(None),
        Err(_) => Ok(None),
    }
}
