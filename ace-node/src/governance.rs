//! Runtime economics and governance state.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ace_consensus::admission::{AdmissionController, AdmissionDecision};
use ace_consensus::rewards::{
    EpochTracker, RewardEngine, RewardProfile, AGE_CAP_MONTHS, BLOCKS_PER_EPOCH, BPS_DENOMINATOR,
    PERF_EMA_CUR_BPS, PERF_EMA_PREV_BPS, TX_FEE,
};
use ace_consensus::validator_set::{Validator, ValidatorSet};
use ace_engine::executor::{validate_approve_validator_sender, ExecutionPolicy};
use ace_model::account::{Account, AccountId};
use ace_model::affiliate::AffiliateRegistry;
use ace_model::node_registry::{
    InMemoryNodeRegistry, NodeInfo, NodeRegistry, NodeStatus, DEFAULT_MAX_NODES,
};
use ace_model::sharded_state::ShardedState;
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::TaggedPubkey;
use serde::{Deserialize, Serialize};

use crate::genesis::{genesis_config_hash, GenesisConfig};
use crate::resource_monitor::ResourceMonitor;

/// Protocol treasury account (receives slashed funds).
pub const TREASURY_ACCOUNT: AccountId = AccountId([0xFFu8; 32]);

/// Fixed stake assigned to all on-chain approved validators.
pub const APPROVED_VALIDATOR_STAKE: u64 = 100;

const GOVERNANCE_FILE: &str = "governance.json";
const BUILDER_SLASH_DIVISOR: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GovernanceState {
    epoch_tracker: EpochTracker,
    node_registry: InMemoryNodeRegistry,
    affiliate_registry: AffiliateRegistry,
    /// Dynamic node admission controller (BTC-style load-based quota adjustment).
    #[serde(default)]
    admission_controller: AdmissionController,
    /// Fingerprint of the genesis config that initialized this governance view.
    #[serde(default)]
    genesis_config_hash: Option<String>,
    /// Validators admitted on-chain after genesis. This is the durable source
    /// for rebuilding the consensus full validator set on restart/rollback.
    #[serde(default)]
    approved_validators: Vec<Validator>,
}

#[derive(Debug, Default, Clone)]
pub struct EpochSettlement {
    pub completed_epoch: Option<u64>,
    pub rewards: Vec<(AccountId, u64)>,
    pub affiliate_payouts: Vec<(AccountId, AccountId, u64)>,
    /// Admission decision made at this epoch boundary (if any).
    pub admission_decision: Option<AdmissionDecision>,
    /// Standby nodes promoted to Active as a result of admission expansion.
    pub promoted_nodes: Vec<AccountId>,
}

pub struct RuntimeGovernance {
    state: GovernanceState,
    snapshots: BTreeMap<u64, GovernanceState>,
    persistence_path: Option<PathBuf>,
    genesis_time_ms: u64,
    /// Tracks consecutive leader slot misses per validator for absence penalties.
    leader_miss_counts: BTreeMap<AccountId, u32>,
    /// Founder account — the only identity allowed to submit OP_APPROVE_VALIDATOR.
    /// None means validator admission is disabled.
    pub founder_id_com: Option<AccountId>,
    validator_admission_policy: String,
}

impl RuntimeGovernance {
    pub fn clone_for_preview(&self) -> Self {
        Self {
            state: self.state.clone(),
            snapshots: BTreeMap::new(),
            persistence_path: None,
            genesis_time_ms: self.genesis_time_ms,
            leader_miss_counts: self.leader_miss_counts.clone(),
            founder_id_com: self.founder_id_com,
            validator_admission_policy: self.validator_admission_policy.clone(),
        }
    }

    pub fn replace_from_preview(&mut self, preview: Self) {
        self.state = preview.state;
        self.snapshots.clear();
        self.leader_miss_counts = preview.leader_miss_counts;
        self.founder_id_com = preview.founder_id_com;
        self.validator_admission_policy = preview.validator_admission_policy;
    }

    pub fn approved_validators(&self) -> Vec<Validator> {
        self.state.approved_validators.clone()
    }

    pub fn load_or_new(
        genesis: &GenesisConfig,
        genesis_time_ms: u64,
        data_dir: Option<&str>,
    ) -> anyhow::Result<Self> {
        let persistence_path = data_dir.map(|dir| Path::new(dir).join(GOVERNANCE_FILE));
        let expected_genesis_config_hash = hex::encode(genesis_config_hash(genesis)?);
        let state = if let Some(path) = &persistence_path {
            if path.exists() {
                let bytes = std::fs::read(path)?;
                let mut state: GovernanceState = serde_json::from_slice(&bytes)?;
                sync_affiliate_counts(&mut state)?;
                if let Some(found_hash) = &state.genesis_config_hash {
                    if found_hash != &expected_genesis_config_hash {
                        anyhow::bail!(
                            "persisted governance at '{}' was created with a different genesis config; clean the data_dir or restore the matching genesis file",
                            path.display()
                        );
                    }
                } else {
                    let expected_ids = expected_genesis_node_ids(genesis)?;
                    let persisted_ids = state.node_registry.registered_node_ids();
                    if persisted_ids != expected_ids {
                        anyhow::bail!(
                            "persisted governance at '{}' does not match the current genesis validator identities; clean the data_dir or restore the matching genesis file",
                            path.display()
                        );
                    }
                    state.genesis_config_hash = Some(expected_genesis_config_hash.clone());
                }
                state
            } else {
                build_governance_state(genesis, genesis_time_ms)?
            }
        } else {
            build_governance_state(genesis, genesis_time_ms)?
        };

        let founder_id_com = crate::genesis::parse_founder_id_com(genesis)?;
        let validator_admission_policy = genesis.validator_admission_policy.clone();
        validate_admission_policy(&validator_admission_policy)?;

        Ok(Self {
            state,
            snapshots: BTreeMap::new(),
            persistence_path,
            genesis_time_ms,
            leader_miss_counts: BTreeMap::new(),
            founder_id_com,
            validator_admission_policy,
        })
    }

    pub fn persist(&self) -> anyhow::Result<()> {
        let Some(path) = &self.persistence_path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(&self.state)?;
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, &bytes)?;
        std::fs::rename(&temp_path, path)?;
        Ok(())
    }

    /// Serialize the governance state and return (path, bytes) for off-thread persistence.
    /// Returns None if no persistence path is configured.
    pub fn serialize_for_persist(&self) -> Option<(std::path::PathBuf, Vec<u8>)> {
        let path = self.persistence_path.clone()?;
        let bytes = serde_json::to_vec_pretty(&self.state).ok()?;
        Some((path, bytes))
    }

    pub fn snapshot(&mut self, slot: u64) {
        self.snapshots.insert(slot, self.state.clone());
    }

    pub fn rollback(&mut self, slot: u64) {
        if let Some(snapshot) = self.snapshots.get(&slot).cloned() {
            self.state = snapshot;
        }
        self.snapshots.retain(|snap_slot, _| *snap_slot < slot);
    }

    pub fn ensure_validator_active(&self, local_id: &AccountId) -> anyhow::Result<()> {
        let now_ms = current_time_ms();
        let node = self
            .state
            .node_registry
            .get_node(local_id)
            .ok_or_else(|| anyhow::anyhow!("validator {} is not registered", local_id))?;
        if !node.is_consensus_eligible(now_ms) {
            anyhow::bail!("validator {} is not active", local_id);
        }
        Ok(())
    }

    pub fn enforce_local_resources(
        &self,
        local_id: &AccountId,
        monitor: &mut ResourceMonitor,
    ) -> anyhow::Result<()> {
        let violations = monitor.check_violations();
        if violations.is_empty() {
            return Ok(());
        }
        let reasons = violations
            .into_iter()
            .map(|violation| violation.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "validator {} exceeds local resource limits: {reasons}",
            local_id
        );
    }

    pub fn apply_completed_block(
        &mut self,
        state: &mut ShardedState,
        validator_set: &ValidatorSet,
        charged_tx_count: u64,
        block_timestamp_ms: u64,
    ) -> anyhow::Result<EpochSettlement> {
        let mut settlement = EpochSettlement::default();
        if let Some(completed_epoch) = self.state.epoch_tracker.on_block(charged_tx_count) {
            settlement.completed_epoch = Some(completed_epoch);
            let window_start_ms = self.epoch_start_ms(completed_epoch);
            let window_end_ms = window_start_ms + epoch_duration_ms();
            self.roll_epoch_performance(window_end_ms);

            let reward_profiles = self.reward_profiles(validator_set, window_end_ms);
            if !reward_profiles.is_empty() {
                let fees = self.state.epoch_tracker.take_fees();
                let block_reward = RewardEngine::epoch_reward_pool(
                    completed_epoch,
                    self.state.epoch_tracker.total_minted(),
                    reward_profiles.len() as u64,
                );
                let rewards = RewardEngine::distribute(
                    completed_epoch,
                    self.state.epoch_tracker.total_minted(),
                    fees,
                    &reward_profiles,
                );
                for (validator, amount) in &rewards {
                    if state.get(validator).is_none() {
                        state.insert(Account::new(*validator));
                    }
                    credit_balance(state, validator, *amount)?;
                }
                self.state.epoch_tracker.record_mint(block_reward);
                settlement.rewards = rewards;
            }

            settlement.affiliate_payouts =
                self.settle_affiliate_fees(state, window_start_ms, window_end_ms)?;
            sync_affiliate_counts(&mut self.state)?;

            // ── Admission adjustment (BTC-style dynamic node quota) ──
            let epoch_txs = self.state.epoch_tracker.last_epoch_tx_count();
            let active_count = self.state.node_registry.active_nodes().len() as u32;
            let decision = self.state.admission_controller.on_epoch_boundary(
                completed_epoch,
                epoch_txs,
                active_count,
            );

            if decision.slots_to_release > 0 {
                let now_ms = block_timestamp_ms;
                let promoted = self
                    .state
                    .node_registry
                    .promote_standby(decision.slots_to_release, now_ms);
                settlement.promoted_nodes = promoted;
            }
            settlement.admission_decision = Some(decision);
        }
        Ok(settlement)
    }

    pub fn slash_builder(
        &mut self,
        builder: &AccountId,
        state: &mut ShardedState,
    ) -> anyhow::Result<Option<u64>> {
        let Some(account) = state.get(builder) else {
            if self.state.node_registry.get_node(builder).is_some() {
                let _ = self
                    .state
                    .node_registry
                    .set_status(builder, NodeStatus::Suspended);
            }
            return Ok(None);
        };

        let penalty = builder_slash_amount(account.balance);
        if penalty == 0 {
            if self.state.node_registry.get_node(builder).is_some() {
                let _ = self
                    .state
                    .node_registry
                    .set_status(builder, NodeStatus::Suspended);
            }
            return Ok(Some(0));
        }

        debit_balance(state, builder, penalty)?;
        // Credit slashed funds to the protocol treasury.
        if state.get(&TREASURY_ACCOUNT).is_none() {
            state.insert(Account::new(TREASURY_ACCOUNT));
        }
        credit_balance(state, &TREASURY_ACCOUNT, penalty)?;
        if self.state.node_registry.get_node(builder).is_some() {
            let _ = self
                .state
                .node_registry
                .set_status(builder, NodeStatus::Suspended);
            self.note_validator_failure(builder);
        }
        Ok(Some(penalty))
    }

    pub fn slash_builder_in_tree(
        &mut self,
        builder: &AccountId,
        state: &mut StateTree,
    ) -> anyhow::Result<Option<u64>> {
        let Some(account) = state.get(builder) else {
            if self.state.node_registry.get_node(builder).is_some() {
                let _ = self
                    .state
                    .node_registry
                    .set_status(builder, NodeStatus::Suspended);
            }
            return Ok(None);
        };

        let penalty = builder_slash_amount(account.balance);
        if penalty == 0 {
            if self.state.node_registry.get_node(builder).is_some() {
                let _ = self
                    .state
                    .node_registry
                    .set_status(builder, NodeStatus::Suspended);
            }
            return Ok(Some(0));
        }

        debit_balance_tree(state, builder, penalty)?;
        // Credit slashed funds to the protocol treasury.
        if state.get(&TREASURY_ACCOUNT).is_none() {
            state.insert(Account::new(TREASURY_ACCOUNT));
        }
        credit_balance_tree(state, &TREASURY_ACCOUNT, penalty)?;
        if self.state.node_registry.get_node(builder).is_some() {
            let _ = self
                .state
                .node_registry
                .set_status(builder, NodeStatus::Suspended);
            self.note_validator_failure(builder);
        }
        Ok(Some(penalty))
    }

    /// Slash a validator who equivocated (voted for two different block hashes in the same slot).
    /// Equivocation is provably malicious — applies a full-balance slash; funds go to treasury.
    pub fn slash_equivocator(
        &mut self,
        validator: &AccountId,
        state: &mut ShardedState,
    ) -> anyhow::Result<Option<u64>> {
        let Some(account) = state.get(validator) else {
            if self.state.node_registry.get_node(validator).is_some() {
                let _ = self
                    .state
                    .node_registry
                    .set_status(validator, NodeStatus::Suspended);
            }
            return Ok(None);
        };

        let penalty = equivocation_slash_amount(account.balance);
        if penalty == 0 {
            if self.state.node_registry.get_node(validator).is_some() {
                let _ = self
                    .state
                    .node_registry
                    .set_status(validator, NodeStatus::Suspended);
            }
            return Ok(Some(0));
        }

        debit_balance(state, validator, penalty)?;
        if state.get(&TREASURY_ACCOUNT).is_none() {
            state.insert(Account::new(TREASURY_ACCOUNT));
        }
        credit_balance(state, &TREASURY_ACCOUNT, penalty)?;
        if self.state.node_registry.get_node(validator).is_some() {
            let _ = self
                .state
                .node_registry
                .set_status(validator, NodeStatus::Suspended);
            self.note_validator_failure(validator);
        }
        Ok(Some(penalty))
    }

    /// Admit a new validator into the node registry (Active status).
    /// Called by node.rs after a committed block contains an `ApproveValidator` tx.
    /// Returns the `Validator` to insert into `full_validator_set`, or an error
    /// if the validator is already registered.
    pub fn admit_validator(
        &mut self,
        sender: AccountId,
        candidate_id_com: AccountId,
        signing_pubkey_bytes: &[u8],
        full_validator_set: &mut ValidatorSet,
        block_timestamp_ms: u64,
    ) -> anyhow::Result<Validator> {
        validate_approve_validator_sender(
            &ExecutionPolicy {
                founder_id_com: self.founder_id_com,
            },
            sender,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        if self
            .state
            .node_registry
            .get_node(&candidate_id_com)
            .is_some()
        {
            anyhow::bail!(
                "validator {} is already registered",
                hex::encode(candidate_id_com.0)
            );
        }
        if !self.state.node_registry.has_capacity() {
            anyhow::bail!("validator registry is at capacity");
        }
        let signing_pubkey = parse_signing_pubkey(signing_pubkey_bytes)?;
        match self.validator_admission_policy.as_str() {
            "devnet-derived" => {
                let expected_pubkey = devnet_signing_pubkey(&candidate_id_com.0)?;
                if signing_pubkey != expected_pubkey {
                    anyhow::bail!(
                        "signing_pubkey does not match deterministic devnet key for validator {}",
                        hex::encode(candidate_id_com.0)
                    );
                }
            }
            "founder-provided" => {}
            other => anyhow::bail!("unsupported validator_admission_policy: {other}"),
        }
        if full_validator_set
            .validators()
            .iter()
            .any(|existing| existing.signing_pubkey == signing_pubkey)
        {
            anyhow::bail!("signing_pubkey is already assigned to another validator");
        }
        let index = full_validator_set.len() as u32;
        let validator = Validator {
            id_com: candidate_id_com,
            stake: APPROVED_VALIDATOR_STAKE,
            index,
            signing_pubkey,
            capabilities: ace_runtime::types::capability::ValidatorCapabilities {
                evm_core: true,
                btc_payments: false,
                solana_light: false,
            },
        };
        full_validator_set
            .add_validator(validator.clone())
            .map_err(|e| anyhow::anyhow!("validator admission failed: {e}"))?;

        let node_info = ace_model::node_registry::NodeInfo {
            id_com: candidate_id_com,
            status: NodeStatus::Active,
            registered_at_ms: block_timestamp_ms,
            activated_at_ms: block_timestamp_ms,
            label: String::new(),
            affiliate_count: 0,
            jurisdiction_code: String::new(),
            kyc_status: ace_model::node_registry::KycStatus::Approved,
            kyc_reviewed_at_ms: block_timestamp_ms,
            kyc_expires_at_ms: None,
            natural_person: true,
            standby_rank: None,
            perf_ema_bps: ace_model::node_registry::DEFAULT_PERF_EMA_BPS,
            current_epoch_successes: 0,
            current_epoch_failures: 0,
        };
        self.state.node_registry.register_node(node_info)?;
        self.state.approved_validators.push(validator.clone());
        Ok(validator)
    }

    pub fn effective_validator_set(
        &self,
        full_validator_set: &ValidatorSet,
        now_ms: u64,
    ) -> ValidatorSet {
        let active_ids: BTreeSet<AccountId> = self
            .state
            .node_registry
            .active_nodes()
            .into_iter()
            .filter(|node| node.is_consensus_eligible(now_ms))
            .map(|node| node.id_com)
            .collect();
        full_validator_set.filtered(&active_ids)
    }

    /// Get the current admission controller state (read-only).
    pub fn admission_controller(&self) -> &AdmissionController {
        &self.state.admission_controller
    }

    pub fn note_validator_success(&mut self, validator: &AccountId) {
        if let Some(node) = self.state.node_registry.get_node_mut(validator) {
            node.current_epoch_successes = node.current_epoch_successes.saturating_add(1);
        }
        // Reset consecutive miss counter on successful block production.
        self.leader_miss_counts.remove(validator);
    }

    pub fn note_validator_failure(&mut self, validator: &AccountId) {
        if let Some(node) = self.state.node_registry.get_node_mut(validator) {
            node.current_epoch_failures = node.current_epoch_failures.saturating_add(1);
        }
    }

    /// Track a validator failing to produce a block in their assigned leader slot.
    /// Increments a consecutive miss counter; after 3+ consecutive misses a warning
    /// is emitted. This should be called alongside (not instead of) the existing
    /// slashing mechanism — `note_validator_failure` is invoked separately via
    /// `slash_builder`, so this method only manages the consecutive miss counter.
    pub fn note_leader_absence(&mut self, validator_id: &AccountId) {
        let counter = self.leader_miss_counts.entry(*validator_id).or_insert(0);
        *counter += 1;
        if *counter >= 3 {
            tracing::warn!(
                %validator_id,
                misses = *counter,
                "validator has missed 3+ consecutive leader slots"
            );
        }
    }

    fn reward_profiles(&self, validator_set: &ValidatorSet, now_ms: u64) -> Vec<RewardProfile> {
        validator_set
            .validators()
            .iter()
            .filter_map(|validator| {
                let node = self.state.node_registry.get_node(&validator.id_com)?;
                if !node.is_consensus_eligible(now_ms) {
                    return None;
                }

                let age_weight = if AGE_CAP_MONTHS == 0 {
                    0
                } else {
                    let capped = node.capped_age_months(now_ms, AGE_CAP_MONTHS);
                    ((capped * BPS_DENOMINATOR) / AGE_CAP_MONTHS) as u16
                };

                Some(RewardProfile {
                    validator: validator.id_com,
                    perf_weight_bps: node.perf_ema_bps,
                    age_weight_bps: age_weight,
                })
            })
            .collect()
    }

    fn roll_epoch_performance(&mut self, now_ms: u64) {
        for node in self
            .state
            .node_registry
            .active_nodes()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
        {
            let Some(entry) = self.state.node_registry.get_node_mut(&node.id_com) else {
                continue;
            };

            if entry.kyc_status == ace_model::node_registry::KycStatus::Approved
                && entry
                    .kyc_expires_at_ms
                    .is_some_and(|expiry| expiry != 0 && expiry < now_ms)
            {
                entry.kyc_status = ace_model::node_registry::KycStatus::Expired;
            }

            let attempts = entry
                .current_epoch_successes
                .saturating_add(entry.current_epoch_failures);
            if attempts > 0 {
                let observed_bps = (u64::from(entry.current_epoch_successes) * BPS_DENOMINATOR)
                    / u64::from(attempts);
                let blended = (u64::from(entry.perf_ema_bps) * PERF_EMA_PREV_BPS
                    + observed_bps * PERF_EMA_CUR_BPS)
                    / BPS_DENOMINATOR;
                entry.perf_ema_bps = blended.clamp(
                    u64::from(ace_consensus::rewards::PERF_WEIGHT_FLOOR_BPS),
                    u64::from(ace_consensus::rewards::PERF_WEIGHT_CEIL_BPS),
                ) as u16;
            }

            entry.current_epoch_successes = 0;
            entry.current_epoch_failures = 0;
        }
    }

    fn settle_affiliate_fees(
        &mut self,
        state: &mut ShardedState,
        window_start_ms: u64,
        window_end_ms: u64,
    ) -> anyhow::Result<Vec<(AccountId, AccountId, u64)>> {
        let active_operators: Vec<AccountId> = self
            .state
            .node_registry
            .active_nodes()
            .into_iter()
            .map(|node| node.id_com)
            .collect();

        let mut payouts = Vec::new();
        for operator in active_operators {
            let affiliates = self
                .state
                .affiliate_registry
                .get_affiliates(&operator)
                .into_iter()
                .cloned()
                .collect::<Vec<_>>();

            for affiliate in affiliates {
                let fee_due = self
                    .state
                    .affiliate_registry
                    .calculate_affiliate_fee_for_window(&affiliate, window_start_ms, window_end_ms);
                if fee_due == 0 {
                    continue;
                }

                if state.get(&operator).is_none() || state.get(&affiliate.id_com).is_none() {
                    let _ = self.state.affiliate_registry.deactivate(&affiliate.id_com);
                    continue;
                }

                let available = state
                    .get(&affiliate.id_com)
                    .map(|account| account.balance)
                    .unwrap_or(0);
                let collected = fee_due.min(available);
                if collected > 0 {
                    debit_balance(state, &affiliate.id_com, collected)?;
                    credit_balance(state, &operator, collected)?;
                    payouts.push((affiliate.id_com, operator, collected));
                }

                if collected < fee_due {
                    let _ = self.state.affiliate_registry.deactivate(&affiliate.id_com);
                }
            }
        }

        Ok(payouts)
    }

    fn epoch_start_ms(&self, epoch: u64) -> u64 {
        self.genesis_time_ms + epoch.saturating_mul(epoch_duration_ms())
    }
}

fn build_governance_state(
    genesis: &GenesisConfig,
    genesis_time_ms: u64,
) -> anyhow::Result<GovernanceState> {
    let node_registry = build_node_registry(genesis, genesis_time_ms)?;
    let initial_active = node_registry.active_nodes().len() as u32;
    let affiliate_registry = build_affiliate_registry(genesis, genesis_time_ms, &node_registry)?;
    let mut state = GovernanceState {
        epoch_tracker: EpochTracker::new(),
        node_registry,
        affiliate_registry,
        admission_controller: AdmissionController::new(initial_active),
        genesis_config_hash: Some(hex::encode(genesis_config_hash(genesis)?)),
        approved_validators: Vec::new(),
    };
    sync_affiliate_counts(&mut state)?;
    Ok(state)
}

fn expected_genesis_node_ids(genesis: &GenesisConfig) -> anyhow::Result<BTreeSet<AccountId>> {
    if !genesis.validators.is_empty() {
        return genesis
            .validators
            .iter()
            .map(|validator| parse_account_id_hex(&validator.id_com, "validator id_com"))
            .collect();
    }
    genesis
        .accounts
        .iter()
        .map(|account| parse_account_id_hex(&account.id_com, "validator id_com"))
        .collect()
}

fn build_node_registry(
    genesis: &GenesisConfig,
    genesis_time_ms: u64,
) -> anyhow::Result<InMemoryNodeRegistry> {
    let mut approved = Vec::new();
    if !genesis.validators.is_empty() {
        for validator in &genesis.validators {
            approved.push(NodeInfo {
                id_com: parse_account_id_hex(&validator.id_com, "validator id_com")?,
                status: NodeStatus::Active,
                registered_at_ms: genesis_time_ms,
                activated_at_ms: genesis_time_ms,
                label: format!("validator-{}", &validator.id_com[..8]),
                affiliate_count: 0,
                jurisdiction_code: String::new(),
                kyc_status: ace_model::node_registry::KycStatus::Approved,
                kyc_reviewed_at_ms: genesis_time_ms,
                kyc_expires_at_ms: None,
                natural_person: true,
                standby_rank: None,
                perf_ema_bps: ace_model::node_registry::DEFAULT_PERF_EMA_BPS,
                current_epoch_successes: 0,
                current_epoch_failures: 0,
            });
        }
    } else {
        for account in &genesis.accounts {
            approved.push(NodeInfo {
                id_com: parse_account_id_hex(&account.id_com, "validator id_com")?,
                status: NodeStatus::Active,
                registered_at_ms: genesis_time_ms,
                activated_at_ms: genesis_time_ms,
                label: format!("validator-{}", &account.id_com[..8]),
                affiliate_count: 0,
                jurisdiction_code: String::new(),
                kyc_status: ace_model::node_registry::KycStatus::Approved,
                kyc_reviewed_at_ms: genesis_time_ms,
                kyc_expires_at_ms: None,
                natural_person: true,
                standby_rank: None,
                perf_ema_bps: ace_model::node_registry::DEFAULT_PERF_EMA_BPS,
                current_epoch_successes: 0,
                current_epoch_failures: 0,
            });
        }
    }

    if approved.len() > DEFAULT_MAX_NODES as usize {
        anyhow::bail!(
            "genesis validator set exceeds registry capacity: {} > {}",
            approved.len(),
            DEFAULT_MAX_NODES
        );
    }

    Ok(InMemoryNodeRegistry::from_genesis(
        approved,
        DEFAULT_MAX_NODES,
    ))
}

fn build_affiliate_registry(
    genesis: &GenesisConfig,
    genesis_time_ms: u64,
    node_registry: &InMemoryNodeRegistry,
) -> anyhow::Result<AffiliateRegistry> {
    let mut registry = AffiliateRegistry::new();
    for affiliate in &genesis.affiliates {
        let affiliate_id = parse_account_id_hex(&affiliate.id_com, "affiliate id_com")?;
        let operator_id = parse_account_id_hex(&affiliate.operator_id_com, "operator id_com")?;
        if node_registry.get_node(&operator_id).is_none() {
            anyhow::bail!(
                "affiliate operator {} is not a registered node",
                affiliate.operator_id_com
            );
        }
        let registered_at_ms = if affiliate.registered_at_ms == 0 {
            genesis_time_ms
        } else {
            affiliate.registered_at_ms
        };
        registry.register(affiliate_id, operator_id, registered_at_ms)?;
    }
    Ok(registry)
}

fn sync_affiliate_counts(state: &mut GovernanceState) -> anyhow::Result<()> {
    let active_nodes = state
        .node_registry
        .active_nodes()
        .into_iter()
        .map(|node| node.id_com)
        .collect::<Vec<_>>();
    for node_id in active_nodes {
        let count = state.affiliate_registry.active_affiliate_count(&node_id);
        state
            .node_registry
            .set_affiliate_count(&node_id, count)
            .map_err(|e| anyhow::anyhow!("failed to sync affiliate count: {e}"))?;
    }
    Ok(())
}

fn parse_account_id_hex(value: &str, label: &str) -> anyhow::Result<AccountId> {
    let bytes =
        hex::decode(value).map_err(|e| anyhow::anyhow!("invalid {label} hex '{value}': {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "{label} must be 32 bytes, got {} for '{value}'",
            bytes.len()
        );
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(AccountId(id))
}

fn debit_balance(
    state: &mut ShardedState,
    account_id: &AccountId,
    amount: u64,
) -> anyhow::Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let account = state
        .get_mut(account_id)
        .ok_or_else(|| anyhow::anyhow!("account {} not found", account_id))?;
    if account.balance < amount {
        anyhow::bail!(
            "account {} has insufficient balance: have {}, need {}",
            account_id,
            account.balance,
            amount
        );
    }
    account.balance -= amount;
    Ok(())
}

fn debit_balance_tree(
    state: &mut StateTree,
    account_id: &AccountId,
    amount: u64,
) -> anyhow::Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let account = state
        .get_mut(account_id)
        .ok_or_else(|| anyhow::anyhow!("account {} not found", account_id))?;
    if account.balance < amount {
        anyhow::bail!(
            "account {} has insufficient balance: have {}, need {}",
            account_id,
            account.balance,
            amount
        );
    }
    account.balance -= amount;
    Ok(())
}

fn credit_balance(
    state: &mut ShardedState,
    account_id: &AccountId,
    amount: u64,
) -> anyhow::Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let account = state
        .get_mut(account_id)
        .ok_or_else(|| anyhow::anyhow!("account {} not found", account_id))?;
    account.balance = account
        .balance
        .checked_add(amount)
        .ok_or_else(|| anyhow::anyhow!("balance overflow for account {}", account_id))?;
    Ok(())
}

fn credit_balance_tree(
    state: &mut StateTree,
    account_id: &AccountId,
    amount: u64,
) -> anyhow::Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let account = state
        .get_mut(account_id)
        .ok_or_else(|| anyhow::anyhow!("account {} not found", account_id))?;
    account.balance = account
        .balance
        .checked_add(amount)
        .ok_or_else(|| anyhow::anyhow!("balance overflow for account {}", account_id))?;
    Ok(())
}

fn builder_slash_amount(balance: u64) -> u64 {
    if balance == 0 {
        return 0;
    }
    (balance / BUILDER_SLASH_DIVISOR).max(TX_FEE).min(balance)
}

/// Equivocation is provably malicious — full stake slash.
fn equivocation_slash_amount(balance: u64) -> u64 {
    balance // 100% slash for equivocation
}

fn epoch_duration_ms() -> u64 {
    BLOCKS_PER_EPOCH * ace_runtime::config::SLOT_DURATION_MS
}

fn validate_admission_policy(policy: &str) -> anyhow::Result<()> {
    match policy {
        "devnet-derived" | "founder-provided" => Ok(()),
        other => anyhow::bail!("unsupported validator_admission_policy: {other}"),
    }
}

/// Parse signing public key bytes into a `TaggedPubkey`.
/// Accepts Ed25519 (32 bytes) or ML-DSA-44 (1312 bytes).
fn parse_signing_pubkey(bytes: &[u8]) -> anyhow::Result<TaggedPubkey> {
    match bytes.len() {
        0 => Err(anyhow::anyhow!("signing_pubkey must not be empty")),
        32 => {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(bytes);
            Ok(TaggedPubkey::ed25519(pk))
        }
        1312 => Ok(TaggedPubkey::ml_dsa_44(bytes.to_vec())),
        n => anyhow::bail!("signing_pubkey must be 32 or 1312 bytes, got {}", n),
    }
}

/// Derive a devnet ML-DSA-44 signing key from id_com deterministically.
pub fn devnet_signing_pubkey(id_com: &[u8; 32]) -> anyhow::Result<TaggedPubkey> {
    ace_engine::admission::devnet_signing_pubkey(id_com).map_err(|e| anyhow::anyhow!("{e}"))
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_consensus::validator_set::{Validator, ValidatorSet};
    use ace_runtime::crypto::TaggedPubkey;
    use ace_runtime::types::capability::ValidatorCapabilities;
    use tempfile::TempDir;

    fn id(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn validator_set() -> ValidatorSet {
        ValidatorSet::new(vec![
            Validator {
                id_com: AccountId([0x01; 32]),
                stake: 100,
                index: 0,
                signing_pubkey: TaggedPubkey::ed25519([0x11; 32]),
                capabilities: ValidatorCapabilities::default(),
            },
            Validator {
                id_com: AccountId([0x02; 32]),
                stake: 100,
                index: 1,
                signing_pubkey: TaggedPubkey::ed25519([0x22; 32]),
                capabilities: ValidatorCapabilities::default(),
            },
        ])
    }

    fn governance() -> RuntimeGovernance {
        governance_with_founder(None)
    }

    fn governance_with_founder(founder: Option<AccountId>) -> RuntimeGovernance {
        let founder_id_com = founder.map(|id| hex::encode(id.0)).unwrap_or_default();
        let genesis = GenesisConfig {
            accounts: vec![],
            validators: vec![
                crate::genesis::GenesisValidator {
                    id_com: id(0x01),
                    stake: 100,
                    signing_pubkey: String::new(),
                    capabilities: ValidatorCapabilities::default(),
                },
                crate::genesis::GenesisValidator {
                    id_com: id(0x02),
                    stake: 100,
                    signing_pubkey: String::new(),
                    capabilities: ValidatorCapabilities::default(),
                },
            ],
            genesis_time_ms: 1_000,
            chain_id: 1,
            native_token: None,
            affiliates: vec![crate::genesis::GenesisAffiliate {
                id_com: id(0x0A),
                operator_id_com: id(0x01),
                registered_at_ms: 1_000,
            }],
            founder_id_com,
            validator_admission_policy: crate::genesis::default_validator_admission_policy(),
            protocol_version: crate::genesis::MIN_PROTOCOL_VERSION,
            ace_defi_approved_relayers: vec![],
        };
        RuntimeGovernance::load_or_new(&genesis, 1_000, None).unwrap()
    }

    #[test]
    fn load_or_new_rejects_legacy_governance_with_different_validator_ids() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let current_genesis = GenesisConfig {
            accounts: vec![],
            validators: vec![
                crate::genesis::GenesisValidator {
                    id_com: id(0x01),
                    stake: 100,
                    signing_pubkey: String::new(),
                    capabilities: ValidatorCapabilities::default(),
                },
                crate::genesis::GenesisValidator {
                    id_com: id(0x02),
                    stake: 100,
                    signing_pubkey: String::new(),
                    capabilities: ValidatorCapabilities::default(),
                },
            ],
            genesis_time_ms: 1_000,
            chain_id: 1,
            native_token: None,
            affiliates: vec![],
            founder_id_com: String::new(),
            validator_admission_policy: crate::genesis::default_validator_admission_policy(),
            protocol_version: crate::genesis::MIN_PROTOCOL_VERSION,
            ace_defi_approved_relayers: vec![],
        };
        let stale_genesis = GenesisConfig {
            validators: vec![crate::genesis::GenesisValidator {
                id_com: id(0x09),
                stake: 100,
                signing_pubkey: String::new(),
                capabilities: ValidatorCapabilities::default(),
            }],
            ..current_genesis.clone()
        };
        let mut stale_state = build_governance_state(&stale_genesis, 1_000).unwrap();
        stale_state.genesis_config_hash = None;
        std::fs::write(
            tmp.path().join(GOVERNANCE_FILE),
            serde_json::to_vec_pretty(&stale_state).unwrap(),
        )
        .unwrap();

        match RuntimeGovernance::load_or_new(&current_genesis, 1_000, Some(data_dir)) {
            Ok(_) => panic!("legacy governance with mismatched validator ids must fail"),
            Err(err) => assert!(err.to_string().contains("does not match")),
        }
    }

    fn state() -> ShardedState {
        let mut state = ShardedState::new();
        state.insert(Account::with_balance(AccountId([0x01; 32]), 1_000_000_000));
        state.insert(Account::with_balance(AccountId([0x02; 32]), 1_000_000_000));
        state.insert(Account::with_balance(AccountId([0x0A; 32]), 2_000_000_000));
        state
    }

    #[test]
    fn slash_builder_burns_balance_and_suspends_registry_entry() {
        let mut governance = governance();
        let mut state = state();

        let penalty = governance
            .slash_builder(&AccountId([0x01; 32]), &mut state)
            .unwrap()
            .unwrap();

        // Slash = (balance / BUILDER_SLASH_DIVISOR).max(TX_FEE); with balance 1e9 → 10_000_000
        assert_eq!(penalty, 10_000_000);
        assert_eq!(
            state.get(&AccountId([0x01; 32])).unwrap().balance,
            1_000_000_000 - 10_000_000
        );
        assert_eq!(
            governance
                .state
                .node_registry
                .get_node(&AccountId([0x01; 32]))
                .unwrap()
                .status,
            NodeStatus::Suspended
        );
    }

    #[test]
    fn completed_epoch_distributes_rewards_and_affiliate_fees() {
        let mut governance = governance();
        governance.state.epoch_tracker =
            EpochTracker::with_checkpoint(0, 0, TX_FEE, BLOCKS_PER_EPOCH - 1);
        let mut state = state();

        let block_timestamp_ms = 1_000 + epoch_duration_ms();
        let settlement = governance
            .apply_completed_block(&mut state, &validator_set(), 1, block_timestamp_ms)
            .unwrap();

        assert_eq!(settlement.completed_epoch, Some(0));
        assert_eq!(settlement.rewards.len(), 2);
        assert!(!settlement.affiliate_payouts.is_empty());
        assert!(state.get(&AccountId([0x01; 32])).unwrap().balance > 1_000_000_000 - TX_FEE);
        assert!(state.get(&AccountId([0x0A; 32])).unwrap().balance < 2_000_000_000);
    }

    #[test]
    fn admit_validator_rejects_non_founder_sender() {
        let founder = AccountId([0xF0; 32]);
        let mut governance = governance_with_founder(Some(founder));
        let mut full_set = validator_set();
        let candidate = AccountId([0xC0; 32]);
        let signing_pubkey = devnet_signing_pubkey(&candidate.0).unwrap();
        let signing_pubkey_bytes = signing_pubkey.bytes;

        let err = governance
            .admit_validator(
                AccountId([0x01; 32]),
                candidate,
                &signing_pubkey_bytes,
                &mut full_set,
                2_000,
            )
            .unwrap_err();
        assert!(err.to_string().contains("not the founder"));
    }

    #[test]
    fn admit_validator_registers_candidate_for_founder() {
        let founder = AccountId([0xF0; 32]);
        let mut governance = governance_with_founder(Some(founder));
        let mut full_set = validator_set();
        let candidate = AccountId([0xC0; 32]);
        let signing_pubkey = devnet_signing_pubkey(&candidate.0).unwrap();
        let signing_pubkey_bytes = signing_pubkey.bytes;

        governance
            .admit_validator(
                founder,
                candidate,
                &signing_pubkey_bytes,
                &mut full_set,
                2_000,
            )
            .unwrap();

        assert_eq!(governance.approved_validators().len(), 1);
        assert!(governance
            .state
            .node_registry
            .get_node(&candidate)
            .is_some());
    }

    #[test]
    fn admit_validator_rollback_restores_registry() {
        let founder = AccountId([0xF0; 32]);
        let mut governance = governance_with_founder(Some(founder));
        let mut full_set = validator_set();
        let candidate = AccountId([0xC0; 32]);
        let signing_pubkey = devnet_signing_pubkey(&candidate.0).unwrap();
        let signing_pubkey_bytes = signing_pubkey.bytes;

        governance.snapshot(100);
        governance
            .admit_validator(
                founder,
                candidate,
                &signing_pubkey_bytes,
                &mut full_set,
                2_000,
            )
            .unwrap();
        assert_eq!(governance.approved_validators().len(), 1);

        governance.rollback(100);
        assert!(governance.approved_validators().is_empty());
        assert!(governance
            .state
            .node_registry
            .get_node(&candidate)
            .is_none());
    }

    #[test]
    fn admit_validator_rejects_duplicate_candidate() {
        let founder = AccountId([0xF0; 32]);
        let mut governance = governance_with_founder(Some(founder));
        let mut full_set = validator_set();
        let candidate = AccountId([0xC0; 32]);
        let signing_pubkey = devnet_signing_pubkey(&candidate.0).unwrap();
        let signing_pubkey_bytes = signing_pubkey.bytes;

        governance
            .admit_validator(
                founder,
                candidate,
                &signing_pubkey_bytes,
                &mut full_set,
                2_000,
            )
            .unwrap();

        let err = governance
            .admit_validator(
                founder,
                candidate,
                &signing_pubkey_bytes,
                &mut full_set,
                3_000,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }
}
