//! RPC method implementations.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use ace_runtime::crypto::TaggedSignature;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use parking_lot::RwLock;

use ace_mempool::pool::Mempool;
use ace_model::account::AccountId;
use ace_model::block_store::BlockStore;
use ace_model::sharded_state::ShardedState;
use ace_n_vm::raw_btc::verify_raw_btc_against_state;
use ace_n_vm::raw_solana::{
    derive_ace_solana_blockhash, extract_first_solana_signature,
    verify_raw_solana_transfer_against_state,
};
use ace_n_vm::raw_tron::verify_raw_tron_against_state;
use ace_n_vm::token_runtime;
use ace_n_vm::NVm;
use ace_p2p::messages::{MevAceNetworkMessage, NetworkMessage};

use crate::error::RpcError;
use crate::eth_rpc::maybe_publish_pending_evm_tx;
use ace_runtime::config::SLOT_DURATION_MS;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::block::{MevAceCommitment, MevAceOpening};
use ace_runtime::types::transaction::{RawChainKind, Transaction};
use sha2::Digest;

use crate::raw_tx::{
    decode_evm_auto, detect_format, evm_payload_call, evm_payload_create, validate_chain,
    RawTxFormat,
};
use crate::types::{
    EthLog, NativeTokenInfo, RpcAccount, RpcBlock, RpcFinalityStatus, RpcMempoolInfo,
    RpcNetworkStatus, RpcNodeContribution, RpcPeerInfo, RpcStateChange, RpcTransaction,
    RpcTransactionByHash, RpcTransactionReceipt, RpcValidatorCandidateCheck,
    RpcValidatorOnboarding,
};
use ace_runtime::crypto::{legacy_idcom_evm, legacy_idcom_solana};
use ace_runtime::types::finality::FinalityState;

/// Maximum decoded transaction size (bytes) for RPC submission. 2× single-tx practical max to bound DoS.
const MAX_RPC_TX_BYTES: usize = 256 * 1024;
/// Maximum hex string length for raw/tx payload (2 hex chars per byte).
const MAX_RPC_TX_HEX_LEN: usize = MAX_RPC_TX_BYTES * 2;

pub(crate) fn check_tx_hex_len(hex_str: &str) -> Result<(), RpcError> {
    if hex_str.len() > MAX_RPC_TX_HEX_LEN {
        return Err(RpcError::InvalidParameter(format!(
            "raw/tx hex length {} exceeds maximum {}",
            hex_str.len(),
            MAX_RPC_TX_HEX_LEN
        )));
    }
    Ok(())
}

pub(crate) fn check_tx_decoded_len(decoded_len: usize) -> Result<(), RpcError> {
    if decoded_len > MAX_RPC_TX_BYTES {
        return Err(RpcError::InvalidParameter(format!(
            "decoded transaction size {} exceeds maximum {} bytes",
            decoded_len, MAX_RPC_TX_BYTES
        )));
    }
    Ok(())
}

pub(crate) fn reject_unsupported_evm_tx_type(tx_type: u8) -> Result<(), RpcError> {
    match tx_type {
        0x03 => Err(RpcError::InvalidParameter(
            "EIP-4844 blob transactions are not yet supported for ACE execution semantics".into(),
        )),
        0x04 => Err(RpcError::InvalidParameter(
            "EIP-7702 transactions are not yet supported for ACE execution semantics".into(),
        )),
        _ => Ok(()),
    }
}

fn is_public_peer_addr(addr: &str) -> bool {
    if addr.contains("/dns4/localhost") || addr.contains("/dns6/localhost") {
        return false;
    }

    let ip4 = addr
        .strip_prefix("/ip4/")
        .or_else(|| addr.strip_prefix("ip4/"))
        .unwrap_or(addr)
        .split('/')
        .next()
        .unwrap_or("");
    let octets = ip4
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>();
    if let Ok(octets) = octets {
        if octets.len() == 4 {
            let first = octets[0];
            let second = octets[1];
            if first == 10 || first == 127 {
                return false;
            }
            if first == 172 && (16..=31).contains(&second) {
                return false;
            }
            if first == 192 && second == 168 {
                return false;
            }
            if first == 169 && second == 254 {
                return false;
            }
            return true;
        }
    }

    let ip6 = addr
        .strip_prefix("/ip6/")
        .or_else(|| addr.strip_prefix("ip6/"))
        .unwrap_or(addr)
        .split('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if ip6.contains(':') {
        return !(ip6 == "::1"
            || ip6.starts_with("fc")
            || ip6.starts_with("fd")
            || ip6.starts_with("fe80:"));
    }

    addr.contains("/dns4/") || addr.contains("/dns6/")
}

fn normalized_public_node_roles(roles: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for role in roles {
        let role = role.trim().to_ascii_lowercase();
        let canonical = match role.as_str() {
            "rpc" | "relay" | "archive" | "light" | "indexer" => role,
            "fullnode" | "full-node" | "full_node" => "relay".to_string(),
            _ => continue,
        };
        if !normalized.contains(&canonical) {
            normalized.push(canonical);
        }
    }
    normalized
}

/// ACE Chain JSON-RPC API trait.
#[rpc(server)]
pub trait AceRpc {
    /// Get the balance of an account by identity commitment (hex).
    #[method(name = "ace_getBalance")]
    fn get_balance(&self, id_com_hex: String) -> RpcResult<u64>;

    /// Get full account information by identity commitment (hex).
    #[method(name = "ace_getAccount")]
    fn get_account(&self, id_com_hex: String) -> RpcResult<RpcAccount>;

    /// Resolve any address type to an account.
    ///
    /// `address_type`: "evm", "tron", "solana", "btc", "xid", "xaddress"
    /// `address_hex`: hex-encoded address bytes
    #[method(name = "ace_resolveAddress")]
    fn resolve_address(&self, address_type: String, address_hex: String) -> RpcResult<RpcAccount>;

    /// Submit a transaction (hex-encoded serialized bytes).
    /// Returns the canonical transaction hash (hex).
    #[method(name = "ace_sendTransaction", blocking)]
    fn send_transaction(&self, tx_hex: String) -> RpcResult<String>;

    /// Submit a raw signed transaction from any supported chain format.
    /// Detects format (EVM EIP-155 RLP / Solana / Bitcoin), validates chain_id
    /// (EVM: tx chain_id must match this node's chain_id), verifies the raw
    /// transaction according to its native rules, then maps it into an ACE
    /// transaction for local execution and broadcast.
    #[method(name = "ace_sendRawTransaction", blocking)]
    fn send_raw_transaction(&self, raw_hex: String) -> RpcResult<String>;

    /// Submit a MEV-ACE commitment encoded as bincode hex.
    #[method(name = "ace_submitMevCommitment")]
    fn submit_mev_commitment(&self, commitment_hex: String) -> RpcResult<String>;

    /// Submit a MEV-ACE opening encoded as bincode hex.
    #[method(name = "ace_submitMevOpening")]
    fn submit_mev_opening(&self, opening_hex: String) -> RpcResult<String>;

    /// Get a block by slot number.
    #[method(name = "ace_getBlock")]
    fn get_block(&self, slot: u64) -> RpcResult<Option<RpcBlock>>;

    /// Get a block by hash (hex).
    #[method(name = "ace_getBlockByHash")]
    fn get_block_by_hash(&self, hash_hex: String) -> RpcResult<Option<RpcBlock>>;

    /// Get the current slot number.
    #[method(name = "ace_getSlot")]
    fn get_slot(&self) -> RpcResult<u64>;

    /// Get the current state root (hex).
    #[method(name = "ace_getStateRoot")]
    fn get_state_root(&self) -> RpcResult<String>;

    /// Get shard information: shard count, per-shard account counts, and state roots.
    #[method(name = "ace_getShardInfo")]
    fn get_shard_info(&self) -> RpcResult<crate::types::RpcShardInfo>;

    /// Get the finality status for a given slot.
    #[method(name = "ace_getFinalityStatus")]
    fn get_finality_status(&self, slot: u64) -> RpcResult<RpcFinalityStatus>;

    // ── Explorer methods ──

    /// Get recent blocks (up to `count`, max 50, from latest downward).
    #[method(name = "ace_getRecentBlocks")]
    fn get_recent_blocks(&self, count: u64) -> RpcResult<Vec<RpcBlock>>;

    /// Get transactions inside a block by slot.
    #[method(name = "ace_getBlockTransactions")]
    fn get_block_transactions(&self, slot: u64) -> RpcResult<Vec<RpcTransaction>>;

    /// Get network status summary.
    #[method(name = "ace_getNetworkStatus")]
    fn get_network_status(&self) -> RpcResult<RpcNetworkStatus>;

    /// Get currently connected P2P peers observed by this node.
    #[method(name = "ace_getPeers")]
    fn get_peers(&self) -> RpcResult<Vec<RpcPeerInfo>>;

    /// Get connected peers with public routable addresses only.
    #[method(name = "ace_getPublicPeers")]
    fn get_public_peers(&self) -> RpcResult<Vec<RpcPeerInfo>>;

    /// Get validator onboarding policy and safety boundaries.
    #[method(name = "ace_getValidatorOnboarding")]
    fn get_validator_onboarding(&self) -> RpcResult<RpcValidatorOnboarding>;

    /// Preflight a validator candidate against the current admission policy.
    #[method(name = "ace_checkValidatorCandidate")]
    fn check_validator_candidate(
        &self,
        candidate_idcom_hex: String,
        signing_pubkey_hex: String,
    ) -> RpcResult<RpcValidatorCandidateCheck>;

    /// Get this node's advertised non-consensus contribution capabilities.
    #[method(name = "ace_getNodeContribution")]
    fn get_node_contribution(&self) -> RpcResult<RpcNodeContribution>;

    /// Get rolling TPS history (up to 120 samples, ~1 per block).
    #[method(name = "ace_getTpsHistory")]
    fn get_tps_history(&self) -> RpcResult<Vec<crate::types::RpcTpsSample>>;

    /// Get mempool status (pending and ready counts).
    #[method(name = "ace_getMempoolInfo")]
    fn get_mempool_info(&self) -> RpcResult<RpcMempoolInfo>;

    /// Get native token metadata (symbol and decimals) for display.
    #[method(name = "ace_getNativeToken")]
    fn get_native_token(&self) -> RpcResult<Option<NativeTokenInfo>>;

    /// Get transaction by hash. Returns None if not yet in a block.
    #[method(name = "ace_getTransactionByHash")]
    fn get_transaction_by_hash(
        &self,
        tx_hash_hex: String,
    ) -> RpcResult<Option<RpcTransactionByHash>>;

    /// Get transaction receipt by hash. Returns None if not yet in a block.
    #[method(name = "ace_getTransactionReceipt")]
    fn get_transaction_receipt(
        &self,
        tx_hash_hex: String,
    ) -> RpcResult<Option<RpcTransactionReceipt>>;

    /// Get transaction history for an account (by idcom hex). Returns recent receipts.
    #[method(name = "ace_getTransactionsByAccount")]
    fn get_transactions_by_account(
        &self,
        idcom_hex: String,
        limit: Option<u64>,
    ) -> RpcResult<Vec<RpcTransactionReceipt>>;

    /// Submit a signed deposit record for bridge processing.
    ///
    /// Direct bridge state mutation from RPC is disabled until deposit inclusion
    /// runs through a consensus-backed transaction path.
    #[method(name = "ace_submitDeposit")]
    fn submit_deposit(&self, signed_deposit_json: serde_json::Value) -> RpcResult<String>;

    /// Submit a relayer-signed withdrawal completion record.
    #[method(name = "ace_markWithdrawalCompleted")]
    fn mark_withdrawal_completed(&self, completion_json: serde_json::Value) -> RpcResult<String>;

    /// Get pending ACE DeFi withdrawals since a slot.
    ///
    /// Returns canonical `ace_defi::WithdrawalRecord` values.
    #[method(name = "ace_getPendingWithdrawals")]
    fn get_pending_withdrawals(
        &self,
        since_slot: u64,
    ) -> RpcResult<Vec<ace_defi::WithdrawalRecord>>;

    /// Get pending ACE DeFi withdrawals by index page.
    #[method(name = "ace_getPendingWithdrawalsPage")]
    fn get_pending_withdrawals_page(
        &self,
        start_index: u64,
        limit: u64,
    ) -> RpcResult<ace_defi::PendingWithdrawalsPage>;

    // ── ACE Liquid (order book) read methods ──
    //
    // Writes (create market / place / cancel order) are authenticated user
    // transactions: build the `0x0F` payload with `ace_liquid::build_*_payload`,
    // sign it, and submit via `ace_submitSignedPayload`.

    /// ACE Liquid: market metadata by market id (32-byte hex).
    #[method(name = "ace_liquidGetMarket")]
    fn liquid_get_market(&self, market_id_hex: String) -> RpcResult<Option<serde_json::Value>>;

    /// ACE Liquid: best bid and best ask prices for a market.
    #[method(name = "ace_liquidBestBidAsk")]
    fn liquid_best_bid_ask(&self, market_id_hex: String) -> RpcResult<serde_json::Value>;

    /// ACE Liquid: order by market id (32-byte hex) and order id.
    #[method(name = "ace_liquidGetOrder")]
    fn liquid_get_order(
        &self,
        market_id_hex: String,
        order_id: u64,
    ) -> RpcResult<Option<serde_json::Value>>;

    /// ACE Liquid: a user's in-market free collateral. `asset`: 0=base, 1=quote.
    #[method(name = "ace_liquidGetBalance")]
    fn liquid_get_balance(
        &self,
        market_id_hex: String,
        user_idcom_hex: String,
        asset: u8,
    ) -> RpcResult<u64>;

    // ── OTP (devnet only) ──

    /// Send an OTP code for identifier verification.
    /// In devnet mode, returns the code directly in the response.
    #[method(name = "ace_sendOtp")]
    fn send_otp(&self, identifier: String, purpose: String) -> RpcResult<serde_json::Value>;

    /// Verify an OTP code and return a verification token.
    #[method(name = "ace_verifyOtp")]
    fn verify_otp(
        &self,
        identifier: String,
        code: String,
        purpose: String,
    ) -> RpcResult<serde_json::Value>;

    /// Devnet faucet: credit native ACE tokens to an account by xid (hex).
    /// Creates the account if it doesn't exist.
    /// Optional `auth_pubkey_hex`: Ed25519 public key (32 bytes hex) to register on the account.
    #[method(name = "ace_faucet")]
    fn faucet(
        &self,
        xid_hex: String,
        amount: u64,
        auth_pubkey_hex: Option<String>,
    ) -> RpcResult<serde_json::Value>;

    // ── Validator admission ──

    /// Submit an on-chain ApproveValidator transaction (OP_APPROVE_VALIDATOR = 0x0C).
    ///
    /// The transaction is signed by the caller (founder) and broadcast to all nodes.
    /// Every node executes it identically when the block is committed — no local state,
    /// no channel, no fork risk.
    ///
    /// Parameters:
    /// - `sender_idcom_hex`: founder's identity commitment (32 bytes hex)
    /// - `candidate_idcom_hex`: new validator's identity commitment (32 bytes hex)
    /// - `signing_pubkey_hex`: new validator's Ed25519 (32 bytes) or ML-DSA-44 (1312 bytes) pubkey hex
    /// - `nonce`: founder account nonce used in the signed payload
    /// - `credential_hex`: founder's TaggedSignature over the payload (hex)
    /// - `pubkey_hex`: founder's TaggedPubkey (hex)
    /// - `domain_chain_id` / `domain_slot`: domain binding
    #[method(name = "ace_approveValidator", blocking)]
    fn approve_validator(
        &self,
        sender_idcom_hex: String,
        candidate_idcom_hex: String,
        signing_pubkey_hex: String,
        nonce: u64,
        credential_hex: String,
        pubkey_hex: String,
        domain_chain_id: u32,
        domain_slot: u32,
    ) -> RpcResult<serde_json::Value>;

    /// Submit a pre-signed native ACE transfer transaction.
    /// The caller builds the OP_TRANSFER payload and signs the attestation client-side.
    /// Parameters: sender_idcom_hex, payload_hex, credential_hex, pubkey_hex, domain_chain_id, domain_slot
    #[method(name = "ace_submitSignedTransfer", blocking)]
    fn submit_signed_transfer(
        &self,
        sender_idcom_hex: String,
        payload_hex: String,
        credential_hex: String,
        pubkey_hex: String,
        domain_chain_id: u32,
        domain_slot: u32,
        context_tag_hex: Option<String>,
    ) -> RpcResult<String>;

    /// Submit a pre-signed transaction for any n-VM opcode (native, EVM, SVM, BVM, TVM).
    ///
    /// This is the PQC-Shielded Cross-VM Execution entry point: callers can use
    /// ML-DSA-44 (or any TaggedSignature algorithm) to authorize transactions on
    /// any VM engine.  The authorization layer verifies the signature and passes
    /// the authenticated sender identity to the execution layer, which is
    /// algorithm-agnostic.
    ///
    /// `pubkey_hex` and `credential_hex` use the TaggedPubkey / TaggedSignature
    /// wire format (tag + length + bytes) so the algorithm is unambiguous.
    /// Raw-bytes format (length-based detection) is also accepted for
    /// backward compatibility.
    #[method(name = "ace_submitSignedPayload", blocking)]
    fn submit_signed_payload(
        &self,
        sender_idcom_hex: String,
        payload_hex: String,
        credential_hex: String,
        pubkey_hex: String,
        domain_chain_id: u32,
        domain_slot: u32,
        context_tag_hex: Option<String>,
    ) -> RpcResult<String>;

    /// Submit a ZK-ACE authorized transaction.
    ///
    /// Replaces the raw ML-DSA-44 signature with a Circle STARK proof that proves
    /// knowledge of the REV behind the identity commitment.  Verification cost is
    /// sub-ms and identical for Ed25519 and ML-DSA-44 accounts, eliminating the
    /// PQC performance penalty on the submission hot path.
    ///
    /// Parameters:
    /// - `idcom_hex`: sender identity commitment (32 bytes hex, Poseidon2-based)
    /// - `payload_hex`: transaction payload bytes (hex)
    /// - `proof_hex`: Circle STARK proof bytes (hex)
    /// - `target_hex`: derivation-target hash, 32 bytes hex
    /// - `rp_com_hex`: replay-prevention commitment, 32 bytes hex
    /// - `nonce`: nonce value matching `rp_com`
    /// - `domain_chain_id`: chain ID for domain binding
    /// - `domain_slot`: slot for domain binding
    #[method(name = "ace_submitZkTransfer", blocking)]
    fn submit_zk_transfer(
        &self,
        idcom_hex: String,
        payload_hex: String,
        proof_hex: String,
        target_hex: String,
        rp_com_hex: String,
        nonce: u64,
        domain_chain_id: u32,
        domain_slot: u32,
    ) -> RpcResult<String>;
}

/// Minimal Solana-compatible JSON-RPC surface for Phantom/native transfers.
#[rpc(server)]
pub trait SolanaRpc {
    #[method(name = "getLatestBlockhash")]
    fn sol_get_latest_blockhash(&self) -> RpcResult<serde_json::Value>;

    #[method(name = "sendTransaction", blocking)]
    fn sol_send_transaction(
        &self,
        encoded_tx: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<String>;

    #[method(name = "sendRawTransaction", blocking)]
    fn sol_send_raw_transaction(
        &self,
        encoded_tx: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<String>;

    #[method(name = "getBalance")]
    fn sol_get_balance(&self, pubkey: String) -> RpcResult<serde_json::Value>;

    #[method(name = "getAccountInfo")]
    fn sol_get_account_info(
        &self,
        pubkey: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<serde_json::Value>;

    #[method(name = "simulateTransaction")]
    fn sol_simulate_transaction(
        &self,
        encoded_tx: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<serde_json::Value>;

    #[method(name = "getSignatureStatuses")]
    fn sol_get_signature_statuses(&self, signatures: Vec<String>) -> RpcResult<serde_json::Value>;
}

/// Default maximum number of receipts to retain in memory.
const DEFAULT_MAX_RECEIPTS: usize = 20_000;

/// In-memory store for transaction hash -> (slot, index) and (slot, index) -> receipt.
/// Written when blocks are applied; read by getTransactionByHash / getTransactionReceipt.
///
/// Bounded: when the store exceeds `max_receipts`, the oldest entries are evicted
/// in FIFO order via `insertion_order`.
/// Minimum interval between receipt snapshot writes.
const SNAPSHOT_INTERVAL_SECS: u64 = 10;
type ReceiptKey = (u64, u32);

pub struct TxReceiptStore {
    by_hash: HashMap<[u8; 32], ReceiptKey>,
    receipts: HashMap<ReceiptKey, RpcTransactionReceipt>,
    receipts_by_slot: BTreeMap<u64, Vec<u32>>,
    insertion_order: VecDeque<[u8; 32]>,
    primary_receipt_hashes: HashMap<ReceiptKey, [u8; 32]>,
    max_receipts: usize,
    snapshot_path: Option<PathBuf>,
    last_snapshot: Option<Instant>,
    snapshot_dirty: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TxReceiptStoreSnapshot {
    by_hash: Vec<(String, (u64, u32))>,
    receipts: Vec<(u64, u32, RpcTransactionReceipt)>,
    insertion_order: Vec<String>,
    max_receipts: usize,
}

impl Default for TxReceiptStore {
    fn default() -> Self {
        Self {
            by_hash: HashMap::new(),
            receipts: HashMap::new(),
            receipts_by_slot: BTreeMap::new(),
            insertion_order: VecDeque::new(),
            primary_receipt_hashes: HashMap::new(),
            max_receipts: DEFAULT_MAX_RECEIPTS,
            snapshot_path: None,
            last_snapshot: None,
            snapshot_dirty: false,
        }
    }
}

impl TxReceiptStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new store with a custom capacity limit.
    pub fn with_max_receipts(max_receipts: usize) -> Self {
        Self {
            max_receipts,
            ..Self::default()
        }
    }

    pub fn open_persistent<P: AsRef<Path>>(path: P, max_receipts: usize) -> Result<Self, RpcError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Ok(Self {
                max_receipts,
                snapshot_path: Some(path),
                ..Self::default()
            });
        }

        let bytes = fs::read(&path)
            .map_err(|e| RpcError::ServerError(format!("failed to read receipt snapshot: {e}")))?;
        let snapshot: TxReceiptStoreSnapshot = serde_json::from_slice(&bytes).map_err(|e| {
            RpcError::ServerError(format!("failed to decode receipt snapshot: {e}"))
        })?;
        let mut store = Self {
            by_hash: HashMap::new(),
            receipts: snapshot
                .receipts
                .into_iter()
                .map(|(slot, index, receipt)| ((slot, index), receipt))
                .collect(),
            receipts_by_slot: BTreeMap::new(),
            insertion_order: VecDeque::new(),
            primary_receipt_hashes: HashMap::new(),
            max_receipts,
            snapshot_path: Some(path),
            last_snapshot: None,
            snapshot_dirty: false,
        };
        store.rebuild_indexes();
        store.trim_to_capacity();
        Ok(store)
    }

    /// Persist the receipt snapshot if enough time has elapsed since the last write.
    fn maybe_persist_snapshot(&mut self) {
        if !self.snapshot_dirty {
            return;
        }
        if let Some(last) = self.last_snapshot {
            if last.elapsed().as_secs() < SNAPSHOT_INTERVAL_SECS {
                return;
            }
        }
        self.force_persist_snapshot();
    }

    /// Persist the receipt snapshot unconditionally (e.g. on shutdown).
    pub fn force_persist_snapshot(&mut self) {
        let Some(path) = &self.snapshot_path else {
            return;
        };
        let snapshot = TxReceiptStoreSnapshot {
            by_hash: self
                .by_hash
                .iter()
                .map(|(hash, location)| (hex::encode(hash), *location))
                .collect(),
            receipts: self
                .receipts
                .iter()
                .map(|((slot, index), receipt)| (*slot, *index, receipt.clone()))
                .collect(),
            insertion_order: self.insertion_order.iter().map(hex::encode).collect(),
            max_receipts: self.max_receipts,
        };
        let Ok(bytes) = serde_json::to_vec(&snapshot) else {
            tracing::warn!("failed to serialize tx receipt snapshot");
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                tracing::warn!(%e, path = %path.display(), "failed to create receipt snapshot directory");
                return;
            }
        }
        let tmp_path = path.with_extension("tmp");
        if let Err(e) = fs::write(&tmp_path, &bytes) {
            tracing::warn!(%e, path = %tmp_path.display(), "failed to write receipt snapshot");
            return;
        }
        if let Err(e) = fs::rename(&tmp_path, path) {
            tracing::warn!(%e, from = %tmp_path.display(), to = %path.display(), "failed to commit receipt snapshot");
        }
        self.last_snapshot = Some(Instant::now());
        self.snapshot_dirty = false;
    }

    /// Store receipts for a block. Each receipt must have block_slot, block_hash, transaction_index set.
    ///
    /// When the store exceeds `max_receipts`, the oldest entries are evicted in FIFO order.
    pub fn put_receipts(&mut self, receipts: Vec<RpcTransactionReceipt>) {
        for r in receipts {
            let slot = r.block_slot;
            let index = r.transaction_index;
            let key = (slot, index);
            if let Some(existing) = self.receipts.remove(&key) {
                remove_receipt_aliases(&mut self.by_hash, &existing);
                self.primary_receipt_hashes.remove(&key);
            } else {
                self.index_receipt_position(slot, index);
            }
            index_receipt_hash(&mut self.by_hash, &r.transaction_hash, slot, index);
            if let Some(external_hash) = &r.external_transaction_hash {
                index_receipt_hash(&mut self.by_hash, external_hash, slot, index);
            }
            if let Some(primary_hash) = decode_receipt_hash(&r.transaction_hash) {
                self.primary_receipt_hashes.insert(key, primary_hash);
                self.insertion_order.push_back(primary_hash);
            }
            self.receipts.insert(key, r);
        }

        self.trim_to_capacity();

        self.snapshot_dirty = true;
        self.maybe_persist_snapshot();
    }

    pub fn get_location(&self, tx_hash: &[u8; 32]) -> Option<(u64, u32)> {
        self.by_hash.get(tx_hash).copied()
    }

    pub fn get_receipt(&self, slot: u64, index: u32) -> Option<RpcTransactionReceipt> {
        self.receipts.get(&(slot, index)).cloned()
    }

    pub fn all_receipts(&self) -> Vec<RpcTransactionReceipt> {
        self.receipt_keys_in_range(None, None)
            .into_iter()
            .filter_map(|key| self.receipts.get(&key).cloned())
            .collect()
    }

    pub fn get_receipts_for_slot(&self, slot: u64) -> Vec<RpcTransactionReceipt> {
        self.receipts_by_slot
            .get(&slot)
            .into_iter()
            .flat_map(|indices| indices.iter())
            .filter_map(|index| self.receipts.get(&(slot, *index)).cloned())
            .collect()
    }

    pub fn collect_matching_logs<F>(
        &self,
        from_slot: Option<u64>,
        to_slot: Option<u64>,
        max_logs: usize,
        mut matches: F,
    ) -> Vec<EthLog>
    where
        F: FnMut(&EthLog) -> bool,
    {
        let mut logs = Vec::new();
        for key in self.receipt_keys_in_range(from_slot, to_slot) {
            let Some(receipt) = self.receipts.get(&key) else {
                continue;
            };
            for log in &receipt.evm_logs {
                if matches(log) {
                    logs.push(log.clone());
                    if logs.len() >= max_logs {
                        return logs;
                    }
                }
            }
        }
        logs
    }

    /// Remove all receipt/index entries for a block slot.
    pub fn remove_receipts_for_slot(&mut self, slot: u64) {
        let Some(indices) = self.receipts_by_slot.remove(&slot) else {
            return;
        };

        for index in indices {
            let key = (slot, index);
            if let Some(receipt) = self.receipts.remove(&key) {
                self.primary_receipt_hashes.remove(&key);
                remove_receipt_aliases(&mut self.by_hash, &receipt);
            }
        }
        self.compact_insertion_order();

        self.snapshot_dirty = true;
        self.maybe_persist_snapshot();
    }

    fn rebuild_indexes(&mut self) {
        self.by_hash.clear();
        self.receipts_by_slot.clear();
        self.insertion_order.clear();
        self.primary_receipt_hashes.clear();

        let mut receipts: Vec<_> = self.receipts.values().cloned().collect();
        receipts.sort_by_key(|receipt| (receipt.block_slot, receipt.transaction_index));
        for receipt in receipts {
            let key = (receipt.block_slot, receipt.transaction_index);
            self.index_receipt_position(receipt.block_slot, receipt.transaction_index);
            index_receipt_hash(
                &mut self.by_hash,
                &receipt.transaction_hash,
                receipt.block_slot,
                receipt.transaction_index,
            );
            if let Some(primary_hash) = decode_receipt_hash(&receipt.transaction_hash) {
                self.primary_receipt_hashes.insert(key, primary_hash);
                self.insertion_order.push_back(primary_hash);
            }
            if let Some(external_hash) = &receipt.external_transaction_hash {
                index_receipt_hash(
                    &mut self.by_hash,
                    external_hash,
                    receipt.block_slot,
                    receipt.transaction_index,
                );
            }
        }
    }

    fn trim_to_capacity(&mut self) {
        while self.receipts.len() > self.max_receipts {
            let Some(oldest_hash) = self.insertion_order.pop_front() else {
                break;
            };
            let Some(oldest_key) = self.by_hash.get(&oldest_hash).copied() else {
                continue;
            };
            if self.primary_receipt_hashes.get(&oldest_key) != Some(&oldest_hash) {
                continue;
            }
            let Some(receipt) = self.receipts.remove(&oldest_key) else {
                continue;
            };
            self.remove_receipt_position(oldest_key.0, oldest_key.1);
            self.primary_receipt_hashes.remove(&oldest_key);
            remove_receipt_aliases(&mut self.by_hash, &receipt);
        }
        self.compact_insertion_order();
    }

    fn receipt_keys_in_range(
        &self,
        from_slot: Option<u64>,
        to_slot: Option<u64>,
    ) -> Vec<ReceiptKey> {
        let start = from_slot.unwrap_or(u64::MIN);
        let end = to_slot.unwrap_or(u64::MAX);
        if start > end {
            return Vec::new();
        }
        self.receipts_by_slot
            .range(start..=end)
            .flat_map(|(&slot, indices)| indices.iter().copied().map(move |index| (slot, index)))
            .collect()
    }

    fn index_receipt_position(&mut self, slot: u64, index: u32) {
        let indices = self.receipts_by_slot.entry(slot).or_default();
        match indices.binary_search(&index) {
            Ok(_) => {}
            Err(pos) => indices.insert(pos, index),
        }
    }

    fn remove_receipt_position(&mut self, slot: u64, index: u32) {
        let should_remove_slot = if let Some(indices) = self.receipts_by_slot.get_mut(&slot) {
            if let Ok(pos) = indices.binary_search(&index) {
                indices.remove(pos);
            }
            indices.is_empty()
        } else {
            false
        };
        if should_remove_slot {
            self.receipts_by_slot.remove(&slot);
        }
    }

    fn compact_insertion_order(&mut self) {
        let live = self.primary_receipt_hashes.len();
        let max_queue_len = live.saturating_mul(2).saturating_add(64);
        if self.insertion_order.len() <= max_queue_len {
            return;
        }
        let by_hash = &self.by_hash;
        let primary_receipt_hashes = &self.primary_receipt_hashes;
        self.insertion_order.retain(|hash| {
            by_hash
                .get(hash)
                .is_some_and(|key| primary_receipt_hashes.get(key) == Some(hash))
        });
    }
}

fn index_receipt_hash(
    by_hash: &mut HashMap<[u8; 32], ReceiptKey>,
    hash_hex: &str,
    slot: u64,
    index: u32,
) {
    if let Ok(bytes) = hex::decode(hash_hex) {
        if bytes.len() == 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes);
            by_hash.insert(h, (slot, index));
        }
    }
}

fn remove_receipt_hash(by_hash: &mut HashMap<[u8; 32], ReceiptKey>, hash_hex: &str) {
    if let Ok(bytes) = hex::decode(hash_hex) {
        if bytes.len() == 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes);
            by_hash.remove(&h);
        }
    }
}

fn remove_receipt_aliases(
    by_hash: &mut HashMap<[u8; 32], ReceiptKey>,
    receipt: &RpcTransactionReceipt,
) {
    remove_receipt_hash(by_hash, &receipt.transaction_hash);
    if let Some(external_hash) = &receipt.external_transaction_hash {
        remove_receipt_hash(by_hash, external_hash);
    }
}

fn decode_receipt_hash(hash_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hash_hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Shared node state accessible to RPC handlers.
pub struct RpcState<B: BlockStore> {
    pub state: Arc<RwLock<ShardedState>>,
    pub block_store: Arc<RwLock<B>>,
    pub mempool: Arc<Mempool>,
    pub mempool_notify: Option<Arc<tokio::sync::Notify>>,
    pub current_slot: Arc<std::sync::atomic::AtomicU64>,
    /// Current connected P2P peers.
    pub peer_count: Arc<std::sync::atomic::AtomicU64>,
    /// Current connected P2P peer snapshots.
    pub peer_snapshot: Arc<std::sync::RwLock<Vec<ace_p2p::PeerSnapshot>>>,
    /// Latest block slot — updated atomically by the consensus loop so
    /// `get_network_status` can respond without acquiring `block_store` lock.
    pub latest_block_slot: Arc<std::sync::atomic::AtomicU64>,
    /// Cached hex state root — updated atomically after each block so
    /// `get_network_status` can respond without acquiring `state` lock.
    pub state_root_hex: Arc<parking_lot::RwLock<String>>,
    /// Chain identifier for this network.
    pub chain_id: u32,
    /// Native token metadata (from genesis). None = use default ACE/9 in responses.
    pub native_token: Option<NativeTokenInfo>,
    /// Transaction index and receipts (written when blocks are applied).
    pub tx_receipt_store: Arc<RwLock<TxReceiptStore>>,
    /// Live Ethereum-style heads / pending tx / logs event hub for filters and subscriptions.
    pub eth_events: Arc<crate::eth_rpc::EthEventHub>,
    /// Optional network outbound channel used to gossip locally submitted transactions.
    pub outbound_tx: Option<tokio::sync::mpsc::Sender<NetworkMessage>>,
    /// Optional local MEV-ACE ingress channel for the validator running in this process.
    pub local_mev_ace_tx: Option<tokio::sync::mpsc::Sender<MevAceNetworkMessage>>,
    /// In-memory OTP store for devnet (identifier+purpose → code).
    pub otp_store: Arc<parking_lot::RwLock<std::collections::HashMap<String, String>>>,
    /// Rolling TPS samples: each entry is (timestamp_ms, tps).
    /// Maintained by the consensus loop via `record_block_tps`.
    pub tps_samples: Arc<parking_lot::RwLock<VecDeque<crate::types::RpcTpsSample>>>,
    /// Genesis validator admission policy (`devnet-derived` or `founder-provided`).
    pub validator_admission_policy: String,
    /// Founder identity allowed to approve new validators. None means disabled.
    pub founder_id_com: Option<String>,
    /// Number of validators in the current configured set at startup.
    pub validator_count: usize,
    /// Whether this node is configured as a consensus validator.
    pub validator: bool,
    /// Non-consensus public contribution roles advertised by this node.
    pub public_node_roles: Vec<String>,
    /// Whether this node considers its RPC endpoint public.
    pub public_rpc: bool,
}

impl<B: BlockStore> RpcState<B> {
    /// Insert into mempool, notify the consensus proposer when the ready queue
    /// transitions from empty to non-empty, and gossip the transaction.
    pub fn submit_transaction_to_mempool(&self, tx: Transaction) -> Result<[u8; 32], RpcError> {
        let outcome = self
            .mempool
            .insert_with_ready_transition(tx.clone())
            .map_err(RpcError::from_mempool_error)?;
        if outcome.became_ready {
            if let Some(ref notify) = self.mempool_notify {
                notify.notify_one();
            }
        }
        self.broadcast_transaction(tx);
        Ok(outcome.tx_hash)
    }

    /// Insert a transaction whose credential was already verified by the RPC
    /// handler (e.g. `submit_signed_payload_inner`).  Skips the expensive
    /// ML-DSA-44 re-verification inside the mempool to avoid double-verifying
    /// (~1 ms each).
    pub fn submit_preverified_to_mempool(&self, tx: Transaction) -> Result<[u8; 32], RpcError> {
        let outcome = self
            .mempool
            .insert_preverified(tx.clone())
            .map_err(RpcError::from_mempool_error)?;
        if outcome.became_ready {
            if let Some(ref notify) = self.mempool_notify {
                notify.notify_one();
            }
        }
        self.broadcast_transaction(tx);
        Ok(outcome.tx_hash)
    }

    fn broadcast_transaction(&self, tx: Transaction) {
        maybe_publish_pending_evm_tx(&self.eth_events, &tx);
        if let Some(outbound_tx) = &self.outbound_tx {
            // Back-pressure: skip gossip when the outbound channel is heavily
            // loaded.  Threshold raised from 256 to 2000 (20% of the 10 000
            // capacity) so that momentary bursts don't immediately drop all
            // gossip.  The P2P service's TX_GOSSIP_WINDOW_MAX rate limiter
            // (~1000 tx/s) is the primary guard; this pre-filter only kicks in
            // under sustained extreme backlog to protect non-tx messages.
            let queued = outbound_tx.max_capacity() - outbound_tx.capacity();
            if queued > 2000 {
                tracing::debug!(queued, "skipping tx gossip: outbound back-pressure");
                return;
            }
            // AR-ACE relay path: strip the ML-DSA-44 auth credential before
            // gossiping.  For PQC txs, include a CredentialCommitment so
            // receivers can prefetch the full credential asynchronously
            // (before a compact proposal arrives), keeping compact-proposal
            // hit rate at 100% without carrying the 2,420-byte signature in
            // gossip.  Ed25519/Secp256k1 credentials are left unchanged.
            use ace_runtime::crypto::sig_algo::SignatureAlgorithm;
            use sha2::{Digest, Sha256};
            if tx.attestation.credential.algorithm == SignatureAlgorithm::MlDsa44
                && !tx.is_credential_stripped()
            {
                let credential_bytes = &tx.attestation.credential.bytes;
                let credential_hash: [u8; 32] = Sha256::digest(credential_bytes).into();
                let commitment = ace_p2p::messages::CredentialCommitment {
                    algorithm: SignatureAlgorithm::MlDsa44,
                    credential_len: credential_bytes.len() as u16,
                    credential_hash,
                };
                let gossip_tx = tx.stripped_for_gossip();
                if let Err(e) = outbound_tx.try_send(NetworkMessage::NewTransaction {
                    tx: gossip_tx,
                    credential_commitment: Some(commitment),
                    source_peer_id: None,
                }) {
                    tracing::warn!("failed to broadcast PQC transaction: channel full ({e})");
                }
            } else {
                let gossip_tx = tx.stripped_for_gossip();
                if let Err(e) = outbound_tx.try_send(NetworkMessage::NewTransaction {
                    tx: gossip_tx,
                    credential_commitment: None,
                    source_peer_id: None,
                }) {
                    tracing::warn!("failed to broadcast transaction: channel full ({e})");
                }
            }
        }
    }

    fn broadcast_mev_ace(&self, msg: MevAceNetworkMessage) -> Result<(), RpcError> {
        if let Some(local_tx) = &self.local_mev_ace_tx {
            local_tx.try_send(msg.clone()).map_err(|e| {
                RpcError::ServerError(format!("failed to enqueue local MEV-ACE message: {e}"))
            })?;
        }
        let Some(outbound_tx) = &self.outbound_tx else {
            return Err(RpcError::ServerError(
                "network outbound channel is not configured".into(),
            ));
        };
        outbound_tx
            .try_send(NetworkMessage::MevAce(msg))
            .map_err(|e| RpcError::ServerError(format!("failed to broadcast MEV-ACE message: {e}")))
    }
}

/// Implementation of the ACE RPC API.
pub struct AceRpcImpl<B: BlockStore> {
    pub shared: Arc<RpcState<B>>,
}

impl<B: BlockStore + Send + Sync + 'static> AceRpcServer for AceRpcImpl<B> {
    fn get_balance(&self, id_com_hex: String) -> RpcResult<u64> {
        let id = parse_id_com(&id_com_hex)?;
        let state = self.shared.state.read();
        match state.get(&id) {
            Some(account) => Ok(account.balance),
            None => Err(RpcError::AccountNotFound(id_com_hex).into()),
        }
    }

    fn get_account(&self, id_com_hex: String) -> RpcResult<RpcAccount> {
        let id = parse_id_com(&id_com_hex)?;
        let state = self.shared.state.read();
        match state.get(&id) {
            Some(account) => {
                let pending_nonce = self
                    .shared
                    .mempool
                    .pending_nonce(&account.id_com.0)
                    .map(|pn| pn.max(account.nonce))
                    .unwrap_or(account.nonce);
                let auth_algorithms: Vec<String> = account
                    .all_auth_keys()
                    .iter()
                    .filter(|k| !k.is_zero())
                    .map(|k| match k.algorithm {
                        ace_runtime::crypto::sig_algo::SignatureAlgorithm::Ed25519 => {
                            "ed25519".into()
                        }
                        ace_runtime::crypto::sig_algo::SignatureAlgorithm::MlDsa44 => {
                            "ml-dsa-44".into()
                        }
                        ace_runtime::crypto::sig_algo::SignatureAlgorithm::Secp256k1 => {
                            "secp256k1".into()
                        }
                        ace_runtime::crypto::sig_algo::SignatureAlgorithm::HmacSha256 => {
                            "hmac-sha256".into()
                        }
                    })
                    .collect();
                Ok(RpcAccount {
                    id_com: hex::encode(account.id_com.0),
                    balance: account.balance,
                    nonce: account.nonce,
                    pending_nonce,
                    has_auth_pubkey: !account.auth_pubkey.is_zero(),
                    auth_algorithms,
                    code_hash: account.code_hash.map(hex::encode),
                    storage_root: hex::encode(account.storage_root),
                    xid: account.xid.map(hex::encode),
                    xaddress: account.xaddress.map(hex::encode),
                    evm_address: account.evm_address.map(hex::encode),
                    tron_address: account.tron_address.map(hex::encode),
                    solana_address: account.solana_address.map(hex::encode),
                    btc_address: account.btc_address.as_ref().map(|b| hex::encode(b)),
                })
            }
            None => Err(RpcError::AccountNotFound(id_com_hex).into()),
        }
    }

    fn resolve_address(&self, address_type: String, address_hex: String) -> RpcResult<RpcAccount> {
        let addr_bytes =
            hex::decode(&address_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
        let state = self.shared.state.read();
        let account_id = match address_type.as_str() {
            "evm" => {
                let addr: [u8; 20] = addr_bytes.as_slice().try_into().map_err(|_| {
                    RpcError::InvalidParameter("EVM address must be 20 bytes".into())
                })?;
                state.resolve_evm_account_id(&addr)
            }
            "tron" => {
                let addr: [u8; 20] = addr_bytes.as_slice().try_into().map_err(|_| {
                    RpcError::InvalidParameter("TRON address must be 20 bytes".into())
                })?;
                state.resolve_tron_account_id(&addr)
            }
            "solana" => {
                let pk: [u8; 32] = addr_bytes.as_slice().try_into().map_err(|_| {
                    RpcError::InvalidParameter("Solana address must be 32 bytes".into())
                })?;
                state.resolve_solana_account_id(&pk)
            }
            "btc" => state.resolve_btc_account_id(&addr_bytes),
            "xid" => {
                let xid: [u8; 32] = addr_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| RpcError::InvalidParameter("XID must be 32 bytes".into()))?;
                state.resolve_xid_account_id(&xid)
            }
            "xaddress" => {
                let xa: [u8; 32] = addr_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| RpcError::InvalidParameter("xaddress must be 32 bytes".into()))?;
                state.resolve_xaddress_account_id(&xa)
            }
            other => {
                return Err(
                    RpcError::InvalidParameter(format!("unknown address type: {other}")).into(),
                );
            }
        };
        match account_id {
            Some(id) => {
                let id_com_hex = hex::encode(id.0);
                drop(state);
                self.get_account(id_com_hex)
            }
            None => Err(RpcError::AccountNotFound(address_hex).into()),
        }
    }

    fn send_transaction(&self, tx_hex: String) -> RpcResult<String> {
        check_tx_hex_len(&tx_hex)?;
        let tx_bytes = hex::decode(&tx_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
        check_tx_decoded_len(tx_bytes.len())?;
        let tx = ace_runtime::types::transaction::Transaction::from_bytes(&tx_bytes)
            .map_err(|e| RpcError::InvalidParameter(e.to_string()))?;

        Ok(hex::encode(self.submit_transaction_to_mempool(tx)?))
    }

    fn send_raw_transaction(&self, raw_hex: String) -> RpcResult<String> {
        check_tx_hex_len(&raw_hex)?;
        let raw_bytes = hex::decode(&raw_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
        check_tx_decoded_len(raw_bytes.len())?;
        let format = detect_format(&raw_bytes);

        match format {
            RawTxFormat::AceNative => {
                let tx = ace_runtime::types::transaction::Transaction::from_bytes(&raw_bytes)
                    .map_err(|e| RpcError::InvalidParameter(e.to_string()))?;
                Ok(hex::encode(self.submit_transaction_to_mempool(tx)?))
            }
            RawTxFormat::Evm => {
                // Unified decode: handles legacy EIP-155, EIP-2930 (Type 1), EIP-1559 (Type 2)
                let decoded = decode_evm_auto(&raw_bytes)?;
                reject_unsupported_evm_tx_type(decoded.tx_type)?;
                validate_chain(format, self.shared.chain_id, Some(&decoded.parsed))?;

                let current_slot = u32::try_from(
                    self.shared
                        .current_slot
                        .load(std::sync::atomic::Ordering::Relaxed),
                )
                .unwrap_or(u32::MAX);

                let payload = if decoded.is_create {
                    evm_payload_create(decoded.value, decoded.gas_limit, &decoded.data)
                } else {
                    evm_payload_call(&decoded.to, decoded.value, decoded.gas_limit, &decoded.data)
                };

                let tx = self.build_raw_chain_tx(
                    &payload,
                    &legacy_idcom_evm(&decoded.parsed.signer),
                    current_slot,
                    RawChainKind::Evm,
                    raw_bytes,
                    [0u8; 16],
                );
                Ok(hex::encode(self.submit_transaction_to_mempool(tx)?))
            }
            RawTxFormat::Solana => {
                validate_chain(format, self.shared.chain_id, None)?;
                let (tx, _sig) = self.build_solana_raw_chain_tx(raw_bytes)?;
                Ok(hex::encode(self.submit_transaction_to_mempool(tx)?))
            }
            RawTxFormat::Bitcoin => {
                validate_chain(format, self.shared.chain_id, None)?;
                let current_slot = u32::try_from(
                    self.shared
                        .current_slot
                        .load(std::sync::atomic::Ordering::Relaxed),
                )
                .unwrap_or(u32::MAX);
                let verified = {
                    let state = self.shared.state.read();
                    verify_raw_btc_against_state(state.default_shard(), &raw_bytes)
                        .map_err(|e| RpcError::InvalidParameter(e.to_string()))?
                };
                let tx = self.build_raw_chain_tx(
                    &verified.payload,
                    &verified.sender_idcom,
                    current_slot,
                    RawChainKind::Btc,
                    raw_bytes,
                    [0u8; 16],
                );
                Ok(hex::encode(self.submit_transaction_to_mempool(tx)?))
            }
            RawTxFormat::Tron => {
                validate_chain(format, self.shared.chain_id, None)?;
                let verified = {
                    let state = self.shared.state.read();
                    verify_raw_tron_against_state(state.default_shard(), &raw_bytes)
                        .map_err(|e| RpcError::InvalidParameter(e.to_string()))?
                };
                let tx = self.build_raw_chain_tx(
                    &verified.canonical_payload,
                    &verified.sender_idcom,
                    verified.domain_slot,
                    RawChainKind::Tron,
                    raw_bytes,
                    [0u8; 16],
                );
                Ok(hex::encode(self.submit_transaction_to_mempool(tx)?))
            }
            RawTxFormat::Unknown => Err(RpcError::InvalidParameter(
                "unknown raw transaction format (not EVM RLP, Solana, Bitcoin, Tron, or ACE native)"
                    .into(),
            )
            .into()),
        }
    }

    fn submit_mev_commitment(&self, commitment_hex: String) -> RpcResult<String> {
        let bytes =
            hex::decode(&commitment_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
        let commitment: MevAceCommitment = bincode::deserialize(&bytes)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid MEV-ACE commitment: {e}")))?;
        let commitment_id = hex::encode(commitment.commitment);
        self.shared
            .broadcast_mev_ace(MevAceNetworkMessage::Commitment(commitment))?;
        Ok(commitment_id)
    }

    fn submit_mev_opening(&self, opening_hex: String) -> RpcResult<String> {
        let bytes = hex::decode(&opening_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
        let opening: MevAceOpening = bincode::deserialize(&bytes)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid MEV-ACE opening: {e}")))?;
        let commitment_id = hex::encode(opening.commitment);
        self.shared
            .broadcast_mev_ace(MevAceNetworkMessage::Opening(opening))?;
        Ok(commitment_id)
    }

    fn get_block(&self, slot: u64) -> RpcResult<Option<RpcBlock>> {
        let store = self.shared.block_store.read();
        Ok(store
            .get_block_by_slot(slot)
            .map(|b| RpcBlock::from_block(&b)))
    }

    fn get_block_by_hash(&self, hash_hex: String) -> RpcResult<Option<RpcBlock>> {
        let hash_bytes = hex::decode(&hash_hex).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
        if hash_bytes.len() != 32 {
            return Err(RpcError::InvalidParameter("hash must be 32 bytes".into()).into());
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        let store = self.shared.block_store.read();
        Ok(store
            .get_block_by_hash(&hash)
            .map(|b| RpcBlock::from_block(&b)))
    }

    fn get_slot(&self) -> RpcResult<u64> {
        Ok(self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed))
    }

    fn get_state_root(&self) -> RpcResult<String> {
        let state = self.shared.state.read();
        Ok(hex::encode(state.compute_root()))
    }

    fn get_shard_info(&self) -> RpcResult<crate::types::RpcShardInfo> {
        let state = self.shared.state.read();
        let mut shards = Vec::new();
        for (shard_id, shard_tree) in state.iter_shards() {
            shards.push(crate::types::RpcShardDetail {
                shard_id: shard_id.0,
                account_count: shard_tree.account_count(),
                state_root: hex::encode(shard_tree.compute_root()),
            });
        }
        Ok(crate::types::RpcShardInfo {
            shard_count: state.shard_count(),
            total_accounts: state.total_account_count(),
            state_root: hex::encode(state.compute_root()),
            shards,
        })
    }

    fn get_finality_status(&self, slot: u64) -> RpcResult<RpcFinalityStatus> {
        let store = self.shared.block_store.read();
        let state_str = match store.get_finality_state(slot) {
            Some(fs) => format!("{:?}", fs),
            None => "unknown".to_string(),
        };
        Ok(RpcFinalityStatus {
            slot,
            state: state_str,
        })
    }

    fn get_recent_blocks(&self, count: u64) -> RpcResult<Vec<RpcBlock>> {
        let count = count.min(50) as usize;
        // Use try_read to avoid blocking when consensus holds the write lock.
        let store = match self.shared.block_store.try_read() {
            Some(guard) => guard,
            None => {
                // Consensus is writing; return empty rather than blocking.
                return Ok(Vec::new());
            }
        };
        let latest = store.latest_slot();
        let mut blocks = Vec::with_capacity(count);
        let start = latest.saturating_sub(count as u64);
        for slot in (start..=latest).rev() {
            if let Some(b) = store.get_block_by_slot(slot) {
                blocks.push(RpcBlock::from_block(&b));
            }
            if blocks.len() >= count {
                break;
            }
        }
        Ok(blocks)
    }

    fn get_block_transactions(&self, slot: u64) -> RpcResult<Vec<RpcTransaction>> {
        let store = self.shared.block_store.read();
        match store.get_block_by_slot(slot) {
            Some(block) => Ok(block
                .transactions
                .iter()
                .enumerate()
                .map(|(i, tx)| RpcTransaction::from_tx(tx, i as u32))
                .collect()),
            None => Err(RpcError::BlockNotFound.into()),
        }
    }

    fn get_network_status(&self) -> RpcResult<RpcNetworkStatus> {
        // Use cached atomics to avoid blocking on state/block_store write locks
        // held by the consensus loop during block production.
        let current_slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        let latest_block_slot = self
            .shared
            .latest_block_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        let state_root = self.shared.state_root_hex.read().clone();
        let block_count = latest_block_slot + 1;
        let peer_count = self
            .shared
            .peer_count
            .load(std::sync::atomic::Ordering::Relaxed);
        Ok(RpcNetworkStatus {
            current_slot,
            latest_block_slot,
            state_root,
            block_count,
            peer_count,
            slot_duration_ms: SLOT_DURATION_MS,
        })
    }

    fn get_peers(&self) -> RpcResult<Vec<RpcPeerInfo>> {
        let peers = self
            .shared
            .peer_snapshot
            .read()
            .map(|snapshot| {
                snapshot
                    .iter()
                    .map(|peer| RpcPeerInfo {
                        peer_id: peer.peer_id.clone(),
                        remote_addr: peer.remote_addr.clone(),
                        direction: peer.direction.clone(),
                        connected_secs: peer.connected_secs,
                        messages_received: peer.messages_received,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(peers)
    }

    fn get_public_peers(&self) -> RpcResult<Vec<RpcPeerInfo>> {
        let peers = self
            .shared
            .peer_snapshot
            .read()
            .map(|snapshot| {
                snapshot
                    .iter()
                    .filter(|peer| is_public_peer_addr(&peer.remote_addr))
                    .map(|peer| RpcPeerInfo {
                        peer_id: peer.peer_id.clone(),
                        remote_addr: peer.remote_addr.clone(),
                        direction: peer.direction.clone(),
                        connected_secs: peer.connected_secs,
                        messages_received: peer.messages_received,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(peers)
    }

    fn get_validator_onboarding(&self) -> RpcResult<RpcValidatorOnboarding> {
        Ok(RpcValidatorOnboarding {
            enabled: self.shared.founder_id_com.is_some(),
            admission_policy: self.shared.validator_admission_policy.clone(),
            requires_founder_approval: self.shared.founder_id_com.is_some(),
            founder_idcom: self.shared.founder_id_com.clone(),
            current_validator_count: self.shared.validator_count,
            activation: "committed OP_APPROVE_VALIDATOR transaction".to_string(),
            safety_model: vec![
                "full nodes never join consensus automatically".to_string(),
                "validator voting power changes only through on-chain approval".to_string(),
                "candidate signing keys are checked against the configured admission policy"
                    .to_string(),
            ],
        })
    }

    fn check_validator_candidate(
        &self,
        candidate_idcom_hex: String,
        signing_pubkey_hex: String,
    ) -> RpcResult<RpcValidatorCandidateCheck> {
        let candidate_bytes: [u8; 32] = hex::decode(candidate_idcom_hex.trim())
            .map_err(|e| RpcError::InvalidParameter(format!("invalid candidate_idcom_hex: {e}")))?
            .try_into()
            .map_err(|_| RpcError::InvalidParameter("candidate_idcom must be 32 bytes".into()))?;
        let supplied = signing_pubkey_hex.trim();
        let supplied_normalized = supplied.to_ascii_lowercase();
        let supplied_signing_pubkey =
            (!supplied_normalized.is_empty()).then(|| supplied_normalized.clone());
        let mut errors = Vec::new();
        let mut expected_signing_pubkey = None;

        if self.shared.founder_id_com.is_none() {
            errors.push(
                "validator admission is disabled because no founder approval identity is configured"
                    .to_string(),
            );
        }

        match self.shared.validator_admission_policy.as_str() {
            "devnet-derived" => {
                let expected = ace_engine::admission::devnet_signing_pubkey(&candidate_bytes)
                    .map_err(|e| RpcError::ServerError(e.to_string()))?;
                let expected_hex = hex::encode(expected.bytes);
                expected_signing_pubkey = Some(expected_hex.clone());
                if !supplied_normalized.is_empty() && supplied_normalized != expected_hex {
                    errors.push(
                        "supplied signing_pubkey_hex does not match deterministic devnet key"
                            .to_string(),
                    );
                }
            }
            "founder-provided" => {
                if supplied_normalized.is_empty() {
                    errors.push(
                        "signing_pubkey_hex is required by founder-provided admission policy"
                            .to_string(),
                    );
                } else if hex::decode(&supplied_normalized).map_or(true, |bytes| bytes.len() != 32)
                {
                    errors.push("signing_pubkey_hex must decode to 32 bytes".to_string());
                }
            }
            other => errors.push(format!("unsupported validator_admission_policy: {other}")),
        }

        let eligible = errors.is_empty();
        Ok(RpcValidatorCandidateCheck {
            candidate_idcom: hex::encode(candidate_bytes),
            admission_policy: self.shared.validator_admission_policy.clone(),
            eligible,
            expected_signing_pubkey,
            supplied_signing_pubkey,
            errors,
            next_step: if eligible {
                "submit ace_approveValidator from the configured founder identity".to_string()
            } else {
                "fix the reported candidate metadata before submitting approval".to_string()
            },
            safety_model: vec![
                "candidate preflight does not add the validator to consensus".to_string(),
                "only a committed OP_APPROVE_VALIDATOR transaction can activate admission"
                    .to_string(),
                "full nodes remain non-consensus participants until explicitly approved"
                    .to_string(),
            ],
        })
    }

    fn get_node_contribution(&self) -> RpcResult<RpcNodeContribution> {
        let roles = normalized_public_node_roles(&self.shared.public_node_roles);
        Ok(RpcNodeContribution {
            public_rpc: self.shared.public_rpc || roles.iter().any(|role| role == "rpc"),
            tx_relay: !self.shared.validator || roles.iter().any(|role| role == "relay"),
            block_relay: !self.shared.validator || roles.iter().any(|role| role == "relay"),
            archive: roles.iter().any(|role| role == "archive"),
            light_client_provider: roles.iter().any(|role| role == "light"),
            indexer_backend: roles.iter().any(|role| role == "indexer"),
            consensus_participant: self.shared.validator,
            roles,
            safety_model: vec![
                "public contribution roles do not grant consensus voting power".to_string(),
                "validators re-validate relayed transactions before block inclusion".to_string(),
                "archive/indexer/light roles are service capabilities, not consensus privileges"
                    .to_string(),
            ],
        })
    }

    fn get_tps_history(&self) -> RpcResult<Vec<crate::types::RpcTpsSample>> {
        Ok(self.shared.tps_samples.read().iter().cloned().collect())
    }

    fn get_mempool_info(&self) -> RpcResult<RpcMempoolInfo> {
        let mempool = &self.shared.mempool;
        Ok(RpcMempoolInfo {
            pending_count: mempool.pending_count(),
            ready_count: mempool.ready_count(),
        })
    }

    fn get_native_token(&self) -> RpcResult<Option<NativeTokenInfo>> {
        Ok(self.shared.native_token.clone())
    }

    fn get_transaction_by_hash(
        &self,
        tx_hash_hex: String,
    ) -> RpcResult<Option<RpcTransactionByHash>> {
        let tx_hash = parse_tx_hash(&tx_hash_hex)?;
        let (slot, index) = {
            let store = self.shared.tx_receipt_store.read();
            match store.get_location(&tx_hash) {
                Some(loc) => loc,
                None => return Ok(None),
            }
        };
        let block_store = self.shared.block_store.read();
        let block = match block_store.get_block_by_slot(slot) {
            Some(b) => b,
            None => return Ok(None),
        };
        let tx = match block.transactions.get(index as usize) {
            Some(t) => t,
            None => return Ok(None),
        };
        Ok(Some(RpcTransactionByHash {
            block_slot: slot,
            block_hash: hex::encode(block.hash()),
            transaction_index: index,
            transaction_hash: tx_hash_hex,
            transaction: RpcTransaction::from_tx(tx, index),
        }))
    }

    fn get_transaction_receipt(
        &self,
        tx_hash_hex: String,
    ) -> RpcResult<Option<RpcTransactionReceipt>> {
        let tx_hash = parse_tx_hash(&tx_hash_hex)?;
        let (slot, _index, receipt) = {
            let store = self.shared.tx_receipt_store.read();
            let (slot, index) = match store.get_location(&tx_hash) {
                Some(loc) => loc,
                None => return Ok(None),
            };
            (slot, index, store.get_receipt(slot, index))
        };
        let block_store = self.shared.block_store.read();
        if block_store.get_block_by_slot(slot).is_none() {
            return Ok(None);
        }
        Ok(receipt)
    }

    fn get_transactions_by_account(
        &self,
        idcom_hex: String,
        limit: Option<u64>,
    ) -> RpcResult<Vec<RpcTransactionReceipt>> {
        let limit = limit.unwrap_or(50).min(100) as usize;
        let needle = idcom_hex.to_lowercase();
        let store = self.shared.tx_receipt_store.read();
        let all = store.all_receipts();
        // Match if the account is the sender OR appears in any state change
        // (e.g. received a transfer, was created by a transfer).
        let filtered: Vec<_> = all
            .into_iter()
            .filter(|r| {
                if r.from.to_lowercase() == needle {
                    return true;
                }
                r.state_changes.iter().any(|sc| match sc {
                    RpcStateChange::BalanceChange { account, .. }
                    | RpcStateChange::NonceIncrement { account, .. }
                    | RpcStateChange::AccountCreated { account }
                    | RpcStateChange::StorageChange { account, .. }
                    | RpcStateChange::CodeDeployed { account, .. }
                    | RpcStateChange::AddressBound { account, .. }
                    | RpcStateChange::AuthKeyUpdated { account, .. }
                    | RpcStateChange::ZkReplayConsumed { account, .. } => {
                        account.to_lowercase() == needle
                    }
                    RpcStateChange::Fee { .. } | RpcStateChange::IntentChange { .. } => false,
                })
            })
            .rev() // most recent first
            .take(limit)
            .collect();
        Ok(filtered)
    }

    fn submit_deposit(&self, signed_deposit_json: serde_json::Value) -> RpcResult<String> {
        let signed: ace_defi::SignedDepositRecord = serde_json::from_value(signed_deposit_json)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid SignedDepositRecord: {e}")))?;
        {
            let state = self.shared.state.read();
            ace_defi::verify_signed_deposit_against_state(state.default_shard(), &signed)
                .map_err(|e| RpcError::InvalidParameter(e.to_string()))?;
        }
        let payload = ace_defi::encode_signed_deposit_payload(&signed)
            .map_err(|e| RpcError::InvalidParameter(e.to_string()))?;
        let obj_hash = {
            let digest = sha2::Sha256::digest(&payload);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&digest);
            hash
        };
        let current_slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed) as u32;
        let attestation = Attestation {
            obj_hash,
            idcom: ace_defi::bridge_deposit_tx_idcom(&signed),
            domain: Domain::new(self.shared.chain_id, current_slot),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        };
        let tx = Transaction::new(payload, attestation);
        let hash = self.shared.submit_preverified_to_mempool(tx)?;
        Ok(format!("0x{}", hex::encode(hash)))
    }

    fn mark_withdrawal_completed(&self, completion_json: serde_json::Value) -> RpcResult<String> {
        let completion: ace_defi::WithdrawalCompletionRecord =
            serde_json::from_value(completion_json).map_err(|e| {
                RpcError::InvalidParameter(format!("invalid WithdrawalCompletionRecord: {e}"))
            })?;
        {
            let state = self.shared.state.read();
            ace_defi::verify_withdrawal_completion_against_state(
                state.default_shard(),
                &completion,
            )
            .map_err(|e| RpcError::InvalidParameter(e.to_string()))?;
        }
        let payload = ace_defi::encode_withdrawal_completion_payload(&completion)
            .map_err(|e| RpcError::InvalidParameter(e.to_string()))?;
        let obj_hash = {
            let digest = sha2::Sha256::digest(&payload);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&digest);
            hash
        };
        let current_slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed) as u32;
        let attestation = Attestation {
            obj_hash,
            idcom: ace_defi::withdrawal_completion_tx_idcom(&completion),
            domain: Domain::new(self.shared.chain_id, current_slot),
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        };
        let tx = Transaction::new(payload, attestation);
        let hash = self.shared.submit_preverified_to_mempool(tx)?;
        Ok(format!("0x{}", hex::encode(hash)))
    }

    fn get_pending_withdrawals(
        &self,
        since_slot: u64,
    ) -> RpcResult<Vec<ace_defi::WithdrawalRecord>> {
        let state = self.shared.state.read();
        ace_defi::list_pending_withdrawals(state.default_shard(), since_slot)
            .map_err(|e| RpcError::ServerError(e.to_string()).into())
    }

    fn get_pending_withdrawals_page(
        &self,
        start_index: u64,
        limit: u64,
    ) -> RpcResult<ace_defi::PendingWithdrawalsPage> {
        let state = self.shared.state.read();
        ace_defi::list_pending_withdrawals_page(state.default_shard(), start_index, limit)
            .map_err(|e| RpcError::ServerError(e.to_string()).into())
    }

    fn liquid_get_market(&self, market_id_hex: String) -> RpcResult<Option<serde_json::Value>> {
        let id = ace_liquid::MarketId(parse_id_com(&market_id_hex)?.0);
        let state = self.shared.state.read();
        let market = ace_liquid::state::get_market(state.default_shard(), &id)
            .map_err(|e| RpcError::ServerError(e.to_string()))?;
        Ok(market.map(|m| serde_json::to_value(m).unwrap_or(serde_json::Value::Null)))
    }

    fn liquid_best_bid_ask(&self, market_id_hex: String) -> RpcResult<serde_json::Value> {
        let id = ace_liquid::MarketId(parse_id_com(&market_id_hex)?.0);
        let state = self.shared.state.read();
        let shard = state.default_shard();
        let best_bid = ace_liquid::state::best_price(shard, &id, ace_liquid::OrderSide::Buy)
            .map_err(|e| RpcError::ServerError(e.to_string()))?;
        let best_ask = ace_liquid::state::best_price(shard, &id, ace_liquid::OrderSide::Sell)
            .map_err(|e| RpcError::ServerError(e.to_string()))?;
        Ok(serde_json::json!({ "best_bid": best_bid, "best_ask": best_ask }))
    }

    fn liquid_get_order(
        &self,
        market_id_hex: String,
        order_id: u64,
    ) -> RpcResult<Option<serde_json::Value>> {
        let id = ace_liquid::MarketId(parse_id_com(&market_id_hex)?.0);
        let state = self.shared.state.read();
        let order =
            ace_liquid::state::get_order(state.default_shard(), &id, ace_liquid::OrderId(order_id))
                .map_err(|e| RpcError::ServerError(e.to_string()))?;
        Ok(order.map(|o| serde_json::to_value(o).unwrap_or(serde_json::Value::Null)))
    }

    fn liquid_get_balance(
        &self,
        market_id_hex: String,
        user_idcom_hex: String,
        asset: u8,
    ) -> RpcResult<u64> {
        let id = ace_liquid::MarketId(parse_id_com(&market_id_hex)?.0);
        let user = parse_id_com(&user_idcom_hex)?;
        let state = self.shared.state.read();
        Ok(ace_liquid::state::free_balance(
            state.default_shard(),
            &id,
            &user,
            asset,
        ))
    }

    #[allow(unused_variables)]
    fn send_otp(&self, identifier: String, purpose: String) -> RpcResult<serde_json::Value> {
        #[cfg(not(feature = "devnet"))]
        return Err(RpcError::ServerError("send_otp is only available on devnet".into()).into());

        #[cfg(feature = "devnet")]
        {
            // Must match `hfi_pay_rpc::normalize_identifier` and portal `normalizeIdentifier` so
            // OTP store keys and verification tokens line up with `ace_hfiPayRegisterRecipientWithBinding`.
            let normalized = crate::hfi_pay_rpc::normalize_identifier(&identifier);
            // Generate a 6-digit code
            let code = format!("{:06}", rand::random::<u32>() % 1_000_000);
            let key = format!("{}:{}", normalized, purpose);
            self.shared.otp_store.write().insert(key, code.clone());
            // Devnet: return code directly so the frontend can auto-fill
            Ok(serde_json::json!({ "ok": true, "code": code }))
        }
    }

    #[allow(unused_variables)]
    fn verify_otp(
        &self,
        identifier: String,
        code: String,
        purpose: String,
    ) -> RpcResult<serde_json::Value> {
        #[cfg(not(feature = "devnet"))]
        return Err(RpcError::ServerError("verify_otp is only available on devnet".into()).into());

        #[cfg(feature = "devnet")]
        {
            let normalized = crate::hfi_pay_rpc::normalize_identifier(&identifier);
            let key = format!("{}:{}", normalized, purpose);
            let stored = self.shared.otp_store.read().get(&key).cloned();
            match stored {
                Some(expected) if expected == code.trim() => {
                    // Remove used OTP
                    self.shared.otp_store.write().remove(&key);
                    // Build verification token (same HMAC format as hfi_pay_rpc)
                    let token =
                        crate::hfi_pay_rpc::build_verification_token(&normalized, &purpose)?;
                    Ok(serde_json::json!({
                        "identifier": normalized,
                        "verification_token": token,
                    }))
                }
                _ => Err(RpcError::InvalidParameter("invalid or expired OTP code".into()).into()),
            }
        }
    }

    #[allow(unused_variables)]
    fn faucet(
        &self,
        xid_hex: String,
        amount: u64,
        auth_pubkey_hex: Option<String>,
    ) -> RpcResult<serde_json::Value> {
        #[cfg(not(feature = "devnet"))]
        return Err(RpcError::ServerError("faucet is only available on devnet".into()).into());

        #[cfg(feature = "devnet")]
        {
            use ace_runtime::crypto::{attestation::make_credential_for_algorithm, idcom_xid};
            use ace_runtime::types::attestation::{Attestation, Domain};
            use ace_runtime::types::transaction::Transaction;
            use sha2::{Digest, Sha256};

            let xid_bytes: [u8; 32] = hex::decode(xid_hex.trim())
                .map_err(|e| RpcError::InvalidParameter(format!("invalid xid hex: {e}")))?
                .try_into()
                .map_err(|_| RpcError::InvalidParameter("xid must be 32 bytes".into()))?;

            let recipient_id = ace_model::AccountId::from_bytes(idcom_xid(&xid_bytes));

            // Faucet account: SHA-256("ace-devnet-faucet")
            let faucet_idcom = {
                let mut h = Sha256::new();
                h.update(b"ace-devnet-faucet");
                let mut out = [0u8; 32];
                out.copy_from_slice(&h.finalize());
                out
            };
            let faucet_account_id = ace_model::AccountId::from_bytes(faucet_idcom);

            // OP_TRANSFER executor auto-creates recipient if not exists.
            // No direct state mutation here — everything goes through on-chain tx.

            // Build OP_TRANSFER from faucet account to recipient
            let nonce = self
                .shared
                .state
                .read()
                .get(&faucet_account_id)
                .map(|a| a.nonce)
                .unwrap_or(0);

            // Payload: 0x01 || nonce(8 LE) || to(32) || amount(8 LE) = 49 bytes
            let mut payload = Vec::with_capacity(49);
            payload.push(0x01); // OP_TRANSFER
            payload.extend_from_slice(&nonce.to_le_bytes());
            payload.extend_from_slice(&recipient_id.0);
            payload.extend_from_slice(&amount.to_le_bytes());

            let obj_hash = {
                let mut h = Sha256::new();
                h.update(&payload);
                let mut out = [0u8; 32];
                out.copy_from_slice(&h.finalize());
                out
            };

            let current_slot = self
                .shared
                .current_slot
                .load(std::sync::atomic::Ordering::Relaxed);
            let domain = Domain::new(self.shared.chain_id, current_slot as u32);

            // Derive faucet signing seed
            let auth_seed = {
                let mut h = Sha256::new();
                h.update(b"ACE-DEVNET-AUTH-SIGN");
                h.update(&faucet_idcom);
                let mut s = [0u8; 32];
                s.copy_from_slice(&h.finalize());
                s
            };

            let algorithm = self
                .shared
                .state
                .read()
                .get(&faucet_account_id)
                .map(|a| a.auth_pubkey.algorithm)
                .unwrap_or(ace_runtime::crypto::sig_algo::SignatureAlgorithm::MlDsa44);

            let credential = make_credential_for_algorithm(
                &auth_seed,
                &obj_hash,
                &faucet_idcom,
                &domain,
                &[0u8; 16],
                algorithm,
            )
            .map_err(|e| RpcError::ServerError(e.to_string()))?;

            let tx = Transaction::new(
                payload,
                Attestation {
                    obj_hash,
                    idcom: faucet_idcom,
                    domain,
                    context_tag: [0u8; 16],
                    credential,
                },
            );

            let tx_hash = hex::encode(tx.tx_hash());

            // Insert into local mempool and broadcast
            self.submit_transaction_to_mempool(tx)?;

            tracing::info!(
                xid = xid_hex.trim(),
                id_com = hex::encode(recipient_id.0),
                amount,
                tx_hash = %tx_hash,
                "Faucet: transfer transaction submitted"
            );

            let new_balance = self
                .shared
                .state
                .read()
                .get(&recipient_id)
                .map(|a| a.balance)
                .unwrap_or(0)
                + amount;

            Ok(serde_json::json!({
                "id_com": hex::encode(recipient_id.0),
                "amount": amount,
                "new_balance": new_balance,
                "tx_hash": tx_hash,
            }))
        }
    }

    fn approve_validator(
        &self,
        sender_idcom_hex: String,
        candidate_idcom_hex: String,
        signing_pubkey_hex: String,
        nonce: u64,
        credential_hex: String,
        pubkey_hex: String,
        domain_chain_id: u32,
        domain_slot: u32,
    ) -> RpcResult<serde_json::Value> {
        use ace_engine::executor::TransactionOp;
        use ace_model::AccountId;

        let candidate_bytes: [u8; 32] = hex::decode(candidate_idcom_hex.trim())
            .map_err(|e| RpcError::InvalidParameter(format!("invalid candidate_idcom_hex: {e}")))?
            .try_into()
            .map_err(|_| RpcError::InvalidParameter("candidate_idcom must be 32 bytes".into()))?;
        let candidate_id = AccountId::from_bytes(candidate_bytes);

        let signing_pubkey_bytes = if signing_pubkey_hex.trim().is_empty() {
            match self.shared.validator_admission_policy.as_str() {
                "devnet-derived" => {
                    ace_engine::admission::devnet_signing_pubkey(&candidate_id.0)
                        .map_err(|e| RpcError::InvalidParameter(e.to_string()))?
                        .bytes
                }
                "founder-provided" => {
                    return Err(RpcError::InvalidParameter(
                        "signing_pubkey_hex is required when validator_admission_policy is founder-provided"
                            .into(),
                    )
                    .into());
                }
                other => {
                    return Err(RpcError::InvalidParameter(format!(
                        "unsupported validator_admission_policy: {other}"
                    ))
                    .into());
                }
            }
        } else {
            let bytes = hex::decode(signing_pubkey_hex.trim()).map_err(|e| {
                RpcError::InvalidParameter(format!("invalid signing_pubkey_hex: {e}"))
            })?;
            if bytes.len() != 32 && bytes.len() != 1312 {
                return Err(RpcError::InvalidParameter(
                    "signing_pubkey must be 32 bytes (Ed25519) or 1312 bytes (ML-DSA-44)".into(),
                )
                .into());
            }
            bytes
        };

        let payload = TransactionOp::ApproveValidator {
            nonce,
            candidate_id_com: candidate_id,
            signing_pubkey: signing_pubkey_bytes,
        }
        .encode();

        self.submit_signed_payload_inner(
            sender_idcom_hex,
            hex::encode(&payload),
            credential_hex,
            pubkey_hex,
            domain_chain_id,
            domain_slot,
            None,
        )
        .map(|tx_hash| serde_json::json!({ "tx_hash": tx_hash, "status": "submitted" }))
        .map_err(Into::into)
    }

    fn submit_signed_transfer(
        &self,
        sender_idcom_hex: String,
        payload_hex: String,
        credential_hex: String,
        pubkey_hex: String,
        domain_chain_id: u32,
        domain_slot: u32,
        context_tag_hex: Option<String>,
    ) -> RpcResult<String> {
        self.submit_signed_payload_inner(
            sender_idcom_hex,
            payload_hex,
            credential_hex,
            pubkey_hex,
            domain_chain_id,
            domain_slot,
            context_tag_hex,
        )
    }

    fn submit_signed_payload(
        &self,
        sender_idcom_hex: String,
        payload_hex: String,
        credential_hex: String,
        pubkey_hex: String,
        domain_chain_id: u32,
        domain_slot: u32,
        context_tag_hex: Option<String>,
    ) -> RpcResult<String> {
        self.submit_signed_payload_inner(
            sender_idcom_hex,
            payload_hex,
            credential_hex,
            pubkey_hex,
            domain_chain_id,
            domain_slot,
            context_tag_hex,
        )
    }

    fn submit_zk_transfer(
        &self,
        idcom_hex: String,
        payload_hex: String,
        proof_hex: String,
        target_hex: String,
        rp_com_hex: String,
        nonce: u64,
        domain_chain_id: u32,
        domain_slot: u32,
    ) -> RpcResult<String> {
        self.submit_zk_transfer_inner(
            idcom_hex,
            payload_hex,
            proof_hex,
            target_hex,
            rp_com_hex,
            nonce,
            domain_chain_id,
            domain_slot,
        )
    }
}

impl<B: BlockStore + Send + Sync + 'static> AceRpcImpl<B> {
    /// Shared implementation for `ace_submitSignedTransfer` and
    /// `ace_submitSignedPayload`.
    ///
    /// Accepts any n-VM opcode (native 0x01–0x0F, EVM 0x10–0x1F,
    /// SVM 0x20–0x2F, BVM 0x30–0x3F, TVM 0x40–0x4F) and any
    /// TaggedSignature algorithm (Ed25519, Secp256k1, ML-DSA-44).
    ///
    /// This is the PQC-Shielded Cross-VM Execution path: a user can sign an
    /// EVM contract call with ML-DSA-44 and submit it here.  The authorization
    /// layer verifies the post-quantum signature; the execution layer routes
    /// the already-authenticated sender identity to the target VM engine.
    pub(crate) fn submit_signed_payload_inner(
        &self,
        sender_idcom_hex: String,
        payload_hex: String,
        credential_hex: String,
        pubkey_hex: String,
        domain_chain_id: u32,
        domain_slot: u32,
        context_tag_hex: Option<String>,
    ) -> RpcResult<String> {
        use ace_runtime::crypto::sig_algo::{TaggedPubkey, TaggedSignature};
        use ace_runtime::types::attestation::{Attestation, Domain};
        use ace_runtime::types::transaction::Transaction;
        use sha2::{Digest, Sha256};

        // Parse inputs
        let sender_idcom: [u8; 32] = hex::decode(&sender_idcom_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid sender_idcom hex: {e}")))?
            .try_into()
            .map_err(|_| RpcError::InvalidParameter("sender_idcom must be 32 bytes".into()))?;

        let payload = hex::decode(&payload_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid payload hex: {e}")))?;

        let credential_bytes = hex::decode(&credential_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid credential hex: {e}")))?;

        let pubkey_bytes = hex::decode(&pubkey_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid pubkey hex: {e}")))?;

        // Build TaggedPubkey: try wire format first (tag + length + bytes),
        // fall back to length-based detection for backward compatibility.
        let caller_pubkey = match TaggedPubkey::from_wire_bytes(&pubkey_bytes) {
            Ok((pk, _len)) => pk,
            Err(_) => match pubkey_bytes.len() {
                32 => {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&pubkey_bytes);
                    TaggedPubkey::ed25519(pk)
                }
                33 => {
                    let mut pk = [0u8; 33];
                    pk.copy_from_slice(&pubkey_bytes);
                    TaggedPubkey::secp256k1(pk)
                }
                1312 => TaggedPubkey::ml_dsa_44(pubkey_bytes),
                other => {
                    return Err(RpcError::InvalidParameter(format!(
                        "unsupported pubkey length {other}; expected 32 (Ed25519), \
                         33 (Secp256k1), 1312 (ML-DSA-44), or wire-format tagged bytes"
                    ))
                    .into());
                }
            },
        };

        // Build TaggedSignature: try wire format first, fall back to
        // length-based detection.
        let credential = match TaggedSignature::from_wire_bytes(&credential_bytes) {
            Ok((sig, _len)) => sig,
            Err(_) => match credential_bytes.len() {
                64 => {
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&credential_bytes);
                    TaggedSignature::ed25519(sig)
                }
                2420 => TaggedSignature::ml_dsa_44(credential_bytes),
                other => {
                    return Err(RpcError::InvalidParameter(format!(
                        "unsupported signature length {other}; expected 64 (Ed25519/Secp256k1), \
                         2420 (ML-DSA-44), or wire-format tagged bytes"
                    ))
                    .into())
                }
            },
        };

        // Compute obj_hash
        let obj_hash = {
            let mut h = Sha256::new();
            h.update(&payload);
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.finalize());
            out
        };

        let domain = Domain::new(domain_chain_id, domain_slot);

        let context_tag = match &context_tag_hex {
            Some(hex_str) => {
                let bytes = hex::decode(hex_str).map_err(|e| {
                    RpcError::InvalidParameter(format!("invalid context_tag hex: {e}"))
                })?;
                if bytes.len() != 16 {
                    return Err(RpcError::InvalidParameter(format!(
                        "context_tag must be 16 bytes, got {}",
                        bytes.len()
                    ))
                    .into());
                }
                let mut tag = [0u8; 16];
                tag.copy_from_slice(&bytes);
                tag
            }
            None => [0u8; 16],
        };

        let tx = Transaction::new(
            payload,
            Attestation {
                obj_hash,
                idcom: sender_idcom,
                domain,
                context_tag,
                credential,
            },
        );

        let tx_hash = hex::encode(tx.tx_hash());

        // Verify credential before submitting.
        let sender_id = ace_model::AccountId::from_bytes(sender_idcom);
        {
            let state = self.shared.state.read();
            if let Some(account) = state.get(&sender_id) {
                let verify_key = match ace_engine::executor::TransactionOp::decode(&tx.payload) {
                    Ok(
                        ace_engine::executor::TransactionOp::SetAuthPubkey { auth_pubkey, .. }
                        | ace_engine::executor::TransactionOp::AddAuthKey { auth_pubkey, .. },
                    ) => {
                        let sig_alg = tx.attestation.credential.algorithm;
                        // Mirror the executor's key-selection logic exactly so
                        // the pre-verifier rejects the same transactions the
                        // executor would reject, rather than accepting them and
                        // letting them fail silently on-chain (tx_ok=0).
                        //
                        // Key rotation: account already has a non-zero key for
                        // this algorithm → verify against it.
                        // Bootstrap: algorithm not yet on-chain AND no other
                        // algorithm is provisioned → verify against new key.
                        // Cross-algorithm add: account has a different algorithm
                        // provisioned → must sign with the existing primary key.
                        match account.auth_key_for_algorithm(sig_alg) {
                            Some(k) if !k.is_zero() => k.clone(),
                            _ => {
                                if account.has_provisioned_auth_key() {
                                    // Account already has some key; adding a new
                                    // algorithm requires signing with existing key.
                                    if !account.auth_pubkey.is_zero() {
                                        account.auth_pubkey.clone()
                                    } else if let Some(k) =
                                        account.auth_keys.iter().find(|k| !k.is_zero())
                                    {
                                        k.clone()
                                    } else {
                                        auth_pubkey
                                    }
                                } else {
                                    // No key at all yet — pure bootstrap.
                                    auth_pubkey
                                }
                            }
                        }
                    }
                    _ => {
                        let sig_alg = tx.attestation.credential.algorithm;
                        account
                            .auth_key_for_algorithm(sig_alg)
                            .unwrap_or(&account.auth_pubkey)
                            .clone()
                    }
                };
                if !ace_runtime::crypto::attestation::verify_credential(
                    &tx.attestation,
                    &tx.payload,
                    &verify_key,
                ) {
                    return Err(
                        RpcError::ServerError("Invalid attestation signature".into()).into(),
                    );
                }
            } else {
                // No on-chain account: the only valid first transaction is CreateAccount (0x02).
                // Verify the credential against the Ed25519 pubkey embedded in the payload and
                // require `pubkey_hex` to match it (same as executor `execute_transaction`).
                const OP_CREATE_ACCOUNT: u8 = 0x02;
                let opcode = tx.payload.first().copied().unwrap_or(0);
                if opcode != OP_CREATE_ACCOUNT {
                    return Err(RpcError::ServerError(
                        "sender account not found on chain; only CreateAccount (0x02) is allowed without an account"
                            .into(),
                    )
                    .into());
                }
                if tx.payload.len() != 65 {
                    return Err(RpcError::InvalidParameter(
                        "CreateAccount payload must be exactly 65 bytes".into(),
                    )
                    .into());
                }
                let mut auth_bytes = [0u8; 32];
                auth_bytes.copy_from_slice(&tx.payload[33..65]);
                if auth_bytes == [0u8; 32] {
                    return Err(RpcError::InvalidParameter(
                        "CreateAccount auth_pubkey must be non-zero".into(),
                    )
                    .into());
                }
                let verify_key = TaggedPubkey::ed25519(auth_bytes);
                if verify_key != caller_pubkey {
                    return Err(RpcError::InvalidParameter(
                        "pubkey_hex must match the 32-byte Ed25519 key in CreateAccount payload (bytes 33–65)"
                            .into(),
                    )
                    .into());
                }
                if !ace_runtime::crypto::attestation::verify_credential(
                    &tx.attestation,
                    &tx.payload,
                    &verify_key,
                ) {
                    return Err(
                        RpcError::ServerError("Invalid attestation signature".into()).into(),
                    );
                }
            }
        }

        let opcode = tx.payload.first().copied().unwrap_or(0);
        let alg = tx.attestation.credential.algorithm;

        // Submit to mempool — credential already verified above, skip re-verification
        self.shared.submit_preverified_to_mempool(tx)?;
        tracing::info!(
            sender = &sender_idcom_hex[..16],
            tx_hash = %tx_hash,
            opcode = format!("0x{opcode:02x}"),
            algorithm = ?alg,
            "Signed payload submitted to mempool"
        );

        Ok(tx_hash)
    }

    /// ZK-ACE submit implementation: verifies the STARK proof and inserts
    /// the transaction as preverified (no re-verify in mempool).
    fn submit_zk_transfer_inner(
        &self,
        idcom_hex: String,
        payload_hex: String,
        proof_hex: String,
        target_hex: String,
        rp_com_hex: String,
        nonce: u64,
        domain_chain_id: u32,
        domain_slot: u32,
    ) -> RpcResult<String> {
        use ace_runtime::crypto::sig_algo::TaggedSignature;
        use ace_runtime::types::attestation::{Attestation, Domain};
        use ace_runtime::types::transaction::{Transaction, ZkAuth};
        use sha2::{Digest, Sha256};

        let idcom: [u8; 32] = hex::decode(&idcom_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid idcom hex: {e}")))?
            .try_into()
            .map_err(|_| RpcError::InvalidParameter("idcom must be 32 bytes".into()))?;

        let payload = hex::decode(&payload_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid payload hex: {e}")))?;

        let proof = hex::decode(&proof_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid proof hex: {e}")))?;

        let target: [u8; 32] = hex::decode(&target_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid target hex: {e}")))?
            .try_into()
            .map_err(|_| RpcError::InvalidParameter("target must be 32 bytes".into()))?;

        let rp_com: [u8; 32] = hex::decode(&rp_com_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("invalid rp_com hex: {e}")))?
            .try_into()
            .map_err(|_| RpcError::InvalidParameter("rp_com must be 32 bytes".into()))?;

        let obj_hash = {
            let mut h = Sha256::new();
            h.update(&payload);
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.finalize());
            out
        };

        let domain = Domain::new(domain_chain_id, domain_slot);

        // Build tx with ZkAuth and an empty credential placeholder.
        // The credential bytes are intentionally empty — ZK proof is the real auth.
        let mut tx = Transaction::new(
            payload,
            Attestation {
                obj_hash,
                idcom,
                domain,
                context_tag: [0u8; 16],
                credential: TaggedSignature::ed25519([0u8; 64]),
            },
        );
        tx.zk_auth = Some(ZkAuth {
            proof,
            target,
            rp_com,
            nonce,
        });

        let tx_hash = hex::encode(tx.tx_hash());

        // Verify the ZK proof before submitting.
        let zk_auth = tx.zk_auth.as_ref().unwrap();
        ace_runtime::crypto::verify_zk_auth(&tx, zk_auth)
            .map_err(|e| RpcError::ServerError(format!("ZK-ACE proof invalid: {e}")))?;

        self.shared.submit_preverified_to_mempool(tx)?;
        tracing::info!(
            sender = &idcom_hex[..16.min(idcom_hex.len())],
            tx_hash = %tx_hash,
            nonce,
            "ZK-ACE transfer submitted to mempool"
        );

        Ok(tx_hash)
    }
}

impl<B: BlockStore + Send + Sync + 'static> SolanaRpcServer for AceRpcImpl<B> {
    fn sol_get_latest_blockhash(&self) -> RpcResult<serde_json::Value> {
        let slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        let blockhash =
            bs58::encode(derive_ace_solana_blockhash(self.shared.chain_id, slot)).into_string();
        Ok(serde_json::json!({
            "context": { "slot": slot },
            "value": {
                "blockhash": blockhash,
                "lastValidBlockHeight": slot + ace_n_vm::raw_solana::SOLANA_RECENT_BLOCKHASH_WINDOW
            }
        }))
    }

    fn sol_send_transaction(
        &self,
        encoded_tx: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<String> {
        let raw_bytes = decode_solana_rpc_wire_tx(&encoded_tx, config.as_ref())?;
        let (tx, first_signature) = self.build_solana_raw_chain_tx(raw_bytes)?;
        self.submit_transaction_to_mempool(tx)?;
        Ok(bs58::encode(first_signature).into_string())
    }

    fn sol_send_raw_transaction(
        &self,
        encoded_tx: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<String> {
        self.sol_send_transaction(encoded_tx, config)
    }

    fn sol_get_balance(&self, pubkey: String) -> RpcResult<serde_json::Value> {
        let pubkey = parse_solana_pubkey(&pubkey)?;
        let id = AccountId(legacy_idcom_solana(&pubkey));
        let balance = self
            .shared
            .state
            .read()
            .get(&id)
            .map(|account| account.balance)
            .unwrap_or(0);
        let slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        Ok(serde_json::json!({
            "context": { "slot": slot },
            "value": balance
        }))
    }

    fn sol_get_account_info(
        &self,
        pubkey: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<serde_json::Value> {
        let pubkey = parse_solana_pubkey(&pubkey)?;
        let encoding = config
            .as_ref()
            .and_then(|cfg| cfg.get("encoding"))
            .and_then(|v| v.as_str())
            .unwrap_or("base64");
        let slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        let state = self.shared.state.read();
        let value = build_solana_account_info(&state, &pubkey, encoding)?;
        Ok(serde_json::json!({
            "context": { "slot": slot },
            "value": value
        }))
    }

    fn sol_simulate_transaction(
        &self,
        encoded_tx: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<serde_json::Value> {
        let raw_bytes = decode_solana_rpc_wire_tx(&encoded_tx, config.as_ref())?;
        let (tx, _sig) = self.build_solana_raw_chain_tx(raw_bytes)?;
        let mut state = self.shared.state.write();
        let snapshot = state.snapshot();
        let vm = NVm::with_defaults();
        let slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        let result = vm.execute_transaction(state.default_shard_mut(), &tx, slot);
        state.rollback(snapshot);
        let (err, logs) = match result {
            Ok(receipt) => (
                if receipt.success {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String(
                        receipt.error.unwrap_or_else(|| "transaction failed".into()),
                    )
                },
                vec![format!(
                    "ACE simulation: success={}, changes={}",
                    receipt.success,
                    receipt.state_changes.len()
                )],
            ),
            Err(err) => (
                serde_json::Value::String(err.to_string()),
                vec![format!("ACE simulation error: {err}")],
            ),
        };
        Ok(serde_json::json!({
            "context": { "slot": slot },
            "value": {
                "err": err,
                "logs": logs,
                "unitsConsumed": 0,
            }
        }))
    }

    fn sol_get_signature_statuses(&self, signatures: Vec<String>) -> RpcResult<serde_json::Value> {
        let slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut values = Vec::with_capacity(signatures.len());
        for signature in signatures {
            let sig_bytes = parse_solana_signature(&signature)?;
            values.push(lookup_solana_signature_status(&self.shared, &sig_bytes));
        }
        Ok(serde_json::json!({
            "context": { "slot": slot },
            "value": values
        }))
    }
}

impl<B: BlockStore + Send + Sync + 'static> AceRpcImpl<B> {
    fn submit_transaction_to_mempool(&self, tx: Transaction) -> Result<[u8; 32], RpcError> {
        self.shared.submit_transaction_to_mempool(tx)
    }

    /// Build an ACE Transaction from a raw chain payload with zero-credential attestation.
    ///
    /// Used for EVM/Solana/BTC raw chain transactions where the original chain's
    /// signature is preserved in raw_bytes and the attestation credential is all-zero
    /// (verification happens via raw chain signature recovery in the dispatcher).
    fn build_raw_chain_tx(
        &self,
        payload: &[u8],
        idcom: &[u8; 32],
        current_slot: u32,
        raw_kind: RawChainKind,
        raw_bytes: Vec<u8>,
        context_tag: [u8; 16],
    ) -> Transaction {
        let obj_hash = {
            let mut h = [0u8; 32];
            let digest = sha2::Sha256::digest(payload);
            h.copy_from_slice(&digest);
            h
        };
        let domain = Domain::new(self.shared.chain_id, current_slot);
        let attestation = Attestation {
            obj_hash,
            idcom: *idcom,
            domain,
            context_tag,
            credential: TaggedSignature::ed25519([0u8; 64]),
        };
        Transaction::with_raw_chain(payload.to_vec(), attestation, raw_kind, raw_bytes)
    }

    fn build_solana_raw_chain_tx(
        &self,
        raw_bytes: Vec<u8>,
    ) -> Result<(Transaction, [u8; 64]), RpcError> {
        let current_slot = self
            .shared
            .current_slot
            .load(std::sync::atomic::Ordering::Relaxed);
        let verified = {
            let state = self.shared.state.read();
            verify_raw_solana_transfer_against_state(
                state.default_shard(),
                &raw_bytes,
                self.shared.chain_id,
                current_slot,
            )
            .map_err(|e| RpcError::InvalidParameter(e.to_string()))?
        };
        let tx = self.build_raw_chain_tx(
            &verified.canonical_payload,
            &verified.sender_idcom,
            verified.recent_slot as u32,
            RawChainKind::Solana,
            raw_bytes,
            [0u8; 16],
        );
        Ok((tx, verified.first_signature))
    }
}

/// Parse 32-byte tx hash from hex.
fn parse_tx_hash(hex_str: &str) -> Result<[u8; 32], RpcError> {
    let bytes = hex::decode(hex_str).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(RpcError::InvalidParameter(
            "transaction hash must be 32 bytes (64 hex chars)".into(),
        ));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Ok(h)
}

/// Parse a hex-encoded identity commitment into an AccountId.
fn parse_id_com(hex_str: &str) -> Result<AccountId, RpcError> {
    let bytes = hex::decode(hex_str).map_err(|e| RpcError::InvalidHex(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(RpcError::InvalidParameter(
            "id_com must be 32 bytes (64 hex chars)".into(),
        ));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(AccountId(id))
}

fn decode_solana_rpc_wire_tx(
    encoded_tx: &str,
    config: Option<&serde_json::Value>,
) -> Result<Vec<u8>, RpcError> {
    let encoding = config
        .and_then(|cfg| cfg.get("encoding"))
        .and_then(|v| v.as_str())
        .unwrap_or("base64");
    let bytes = match encoding {
        "base58" => bs58::decode(encoded_tx)
            .into_vec()
            .map_err(|e| RpcError::InvalidParameter(format!("invalid base58 tx: {e}")))?,
        "base64" => BASE64_STANDARD
            .decode(encoded_tx)
            .or_else(|_| {
                bs58::decode(encoded_tx)
                    .into_vec()
                    .map_err(|_| base64::DecodeError::InvalidByte(0, 0))
            })
            .map_err(|e| RpcError::InvalidParameter(format!("invalid base64 tx: {e}")))?,
        other => {
            return Err(RpcError::InvalidParameter(format!(
                "unsupported Solana encoding: {other}"
            )));
        }
    };
    check_tx_decoded_len(bytes.len())?;
    Ok(bytes)
}

fn parse_solana_pubkey(encoded: &str) -> Result<[u8; 32], RpcError> {
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| RpcError::InvalidParameter(format!("invalid Solana pubkey: {e}")))?;
    if bytes.len() != 32 {
        return Err(RpcError::InvalidParameter(
            "Solana pubkey must decode to 32 bytes".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_solana_signature(encoded: &str) -> Result<[u8; 64], RpcError> {
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| RpcError::InvalidParameter(format!("invalid Solana signature: {e}")))?;
    if bytes.len() != 64 {
        return Err(RpcError::InvalidParameter(
            "Solana signature must decode to 64 bytes".into(),
        ));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn build_solana_account_info(
    state: &ShardedState,
    pubkey: &[u8; 32],
    encoding: &str,
) -> Result<serde_json::Value, RpcError> {
    let state = state.default_shard();
    if let Some(meta) = token_runtime::get_token_account_meta(state, pubkey) {
        let mint_meta = token_runtime::get_mint_meta(state, &meta.mint).ok_or_else(|| {
            RpcError::InvalidParameter("token account references unknown mint".into())
        })?;
        let amount = token_runtime::token_account_balance(state, pubkey).unwrap_or(0);
        return Ok(match encoding {
            "jsonParsed" => serde_json::json!({
                "data": {
                    "program": "spl-token",
                    "parsed": {
                        "type": "account",
                        "info": {
                            "mint": bs58::encode(meta.mint).into_string(),
                            "owner": bs58::encode(meta.owner_sol_pubkey).into_string(),
                            "state": "initialized",
                            "tokenAmount": {
                                "amount": amount.to_string(),
                                "decimals": mint_meta.decimals,
                                "uiAmount": amount as f64 / 10f64.powi(mint_meta.decimals as i32),
                                "uiAmountString": format_token_amount(amount, mint_meta.decimals),
                            },
                            "isNative": false,
                            "delegatedAmount": {
                                "amount": "0",
                                "decimals": mint_meta.decimals,
                                "uiAmount": 0.0,
                                "uiAmountString": "0",
                            }
                        }
                    },
                    "space": 165
                },
                "executable": false,
                "lamports": 0,
                "owner": bs58::encode(token_runtime::spl_token_program_id()).into_string(),
                "rentEpoch": 0,
                "space": 165
            }),
            "base64" => serde_json::json!({
                "data": [
                    BASE64_STANDARD.encode(token_runtime::encode_spl_token_account_data(meta, amount)),
                    "base64"
                ],
                "executable": false,
                "lamports": 0,
                "owner": bs58::encode(token_runtime::spl_token_program_id()).into_string(),
                "rentEpoch": 0,
                "space": 165
            }),
            other => {
                return Err(RpcError::InvalidParameter(format!(
                    "unsupported getAccountInfo encoding: {other}"
                )));
            }
        });
    }

    if let Some(meta) = token_runtime::get_mint_meta(state, pubkey) {
        return Ok(match encoding {
            "jsonParsed" => serde_json::json!({
                "data": {
                    "program": "spl-token",
                    "parsed": {
                        "type": "mint",
                        "info": {
                            "decimals": meta.decimals,
                            "isInitialized": true,
                            "mintAuthority": serde_json::Value::Null,
                            "freezeAuthority": serde_json::Value::Null,
                            "supply": meta.supply.to_string(),
                        }
                    },
                    "space": 82
                },
                "executable": false,
                "lamports": 0,
                "owner": bs58::encode(token_runtime::spl_token_program_id()).into_string(),
                "rentEpoch": 0,
                "space": 82
            }),
            "base64" => serde_json::json!({
                "data": [
                    BASE64_STANDARD.encode(token_runtime::encode_spl_mint_data(meta)),
                    "base64"
                ],
                "executable": false,
                "lamports": 0,
                "owner": bs58::encode(token_runtime::spl_token_program_id()).into_string(),
                "rentEpoch": 0,
                "space": 82
            }),
            other => {
                return Err(RpcError::InvalidParameter(format!(
                    "unsupported getAccountInfo encoding: {other}"
                )));
            }
        });
    }

    let id = AccountId(legacy_idcom_solana(pubkey));
    if let Some(account) = state.get(&id) {
        return Ok(serde_json::json!({
            "data": match encoding {
                "jsonParsed" => serde_json::Value::Array(vec![
                    serde_json::Value::String(String::new()),
                    serde_json::Value::String("base64".into()),
                ]),
                "base64" => serde_json::Value::Array(vec![
                    serde_json::Value::String(String::new()),
                    serde_json::Value::String("base64".into()),
                ]),
                other => {
                    return Err(RpcError::InvalidParameter(format!(
                        "unsupported getAccountInfo encoding: {other}"
                    )))
                }
            },
            "executable": false,
            "lamports": account.balance,
            "owner": bs58::encode([0u8; 32]).into_string(),
            "rentEpoch": 0,
            "space": 0
        }));
    }

    Ok(serde_json::Value::Null)
}

fn format_token_amount(amount: u64, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let scale = 10u64.saturating_pow(decimals as u32);
    let whole = amount / scale;
    let frac = amount % scale;
    format!("{whole}.{:0width$}", frac, width = decimals as usize)
}

fn lookup_solana_signature_status<B: BlockStore + Send + Sync + 'static>(
    shared: &Arc<RpcState<B>>,
    signature: &[u8; 64],
) -> Option<serde_json::Value> {
    let store = shared.block_store.read();
    let latest_slot = store.latest_slot();
    for slot in (0..=latest_slot).rev() {
        let Some(block) = store.get_block_by_slot(slot) else {
            continue;
        };
        for tx in &block.transactions {
            let Some(raw_chain) = &tx.raw_chain else {
                continue;
            };
            if raw_chain.kind != RawChainKind::Solana {
                continue;
            }
            let Ok(candidate) = extract_first_solana_signature(&raw_chain.raw_bytes) else {
                continue;
            };
            if &candidate != signature {
                continue;
            }
            let confirmation_status = match store.get_finality_state(slot) {
                Some(FinalityState::Hard) => "finalized",
                Some(state) if state.is_confirmed() => "confirmed",
                _ => "processed",
            };
            return Some(serde_json::json!({
                "slot": slot,
                "confirmations": serde_json::Value::Null,
                "err": serde_json::Value::Null,
                "confirmationStatus": confirmation_status
            }));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{is_public_peer_addr, AceRpcImpl, AceRpcServer, RpcState, TxReceiptStore};
    use crate::eth_rpc::EthEventHub;
    use crate::types::RpcTransactionReceipt;
    use ace_engine::executor::TransactionOp;
    use ace_mempool::{Mempool, MempoolConfig};
    use ace_model::account::{Account, AccountId};
    use ace_model::block_store::InMemoryBlockStore;
    use ace_model::sharded_state::ShardedState;
    use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
    use ace_runtime::types::attestation::{Attestation, Domain};
    use ace_runtime::types::transaction::Transaction;
    use parking_lot::RwLock;
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn public_peer_filter_rejects_private_ranges() {
        assert!(!is_public_peer_addr("/ip4/10.0.0.4/tcp/31333"));
        assert!(!is_public_peer_addr("/ip4/172.16.1.8/tcp/31333"));
        assert!(!is_public_peer_addr("/ip4/192.168.1.8/tcp/31333"));
        assert!(!is_public_peer_addr("/ip4/127.0.0.1/tcp/31333"));
        assert!(!is_public_peer_addr("/ip4/169.254.1.1/tcp/31333"));
        assert!(!is_public_peer_addr("/ip6/::1/tcp/31333"));
        assert!(!is_public_peer_addr("/ip6/fd00::1/tcp/31333"));
    }

    #[test]
    fn public_peer_filter_accepts_public_addresses() {
        assert!(is_public_peer_addr("/ip4/65.93.112.179/tcp/59146"));
        assert!(is_public_peer_addr(
            "/dns4/bootnode.testnet.acechain.io/tcp/31333"
        ));
        assert!(is_public_peer_addr("/ip6/2606:4700:4700::1111/tcp/31333"));
    }

    #[test]
    fn validator_onboarding_status_reports_founder_gate() {
        let shared = Arc::new(RpcState {
            state: Arc::new(RwLock::new(ShardedState::new())),
            block_store: Arc::new(RwLock::new(InMemoryBlockStore::new())),
            mempool: Arc::new(Mempool::new(MempoolConfig::default())),
            mempool_notify: None,
            current_slot: Arc::new(AtomicU64::new(0)),
            peer_count: Arc::new(AtomicU64::new(0)),
            peer_snapshot: Arc::new(std::sync::RwLock::new(Vec::new())),
            latest_block_slot: Arc::new(AtomicU64::new(0)),
            state_root_hex: Arc::new(parking_lot::RwLock::new(String::new())),
            chain_id: 122_766,
            native_token: None,
            tx_receipt_store: Arc::new(RwLock::new(TxReceiptStore::new())),
            eth_events: Arc::new(EthEventHub::new(16)),
            outbound_tx: None,
            local_mev_ace_tx: None,
            otp_store: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            tps_samples: Arc::new(parking_lot::RwLock::new(VecDeque::new())),
            validator_admission_policy: "devnet-derived".into(),
            founder_id_com: Some(hex::encode([0xA5; 32])),
            validator_count: 3,
            validator: false,
            public_node_roles: vec!["rpc".into(), "archive".into()],
            public_rpc: true,
        });
        let rpc = AceRpcImpl { shared };
        let status = rpc.get_validator_onboarding().unwrap();

        assert!(status.enabled);
        assert!(status.requires_founder_approval);
        assert_eq!(status.admission_policy, "devnet-derived");
        assert_eq!(status.current_validator_count, 3);
    }

    #[test]
    fn node_contribution_reports_non_consensus_roles() {
        let shared = Arc::new(RpcState {
            state: Arc::new(RwLock::new(ShardedState::new())),
            block_store: Arc::new(RwLock::new(InMemoryBlockStore::new())),
            mempool: Arc::new(Mempool::new(MempoolConfig::default())),
            mempool_notify: None,
            current_slot: Arc::new(AtomicU64::new(0)),
            peer_count: Arc::new(AtomicU64::new(0)),
            peer_snapshot: Arc::new(std::sync::RwLock::new(Vec::new())),
            latest_block_slot: Arc::new(AtomicU64::new(0)),
            state_root_hex: Arc::new(parking_lot::RwLock::new(String::new())),
            chain_id: 122_766,
            native_token: None,
            tx_receipt_store: Arc::new(RwLock::new(TxReceiptStore::new())),
            eth_events: Arc::new(EthEventHub::new(16)),
            outbound_tx: None,
            local_mev_ace_tx: None,
            otp_store: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            tps_samples: Arc::new(parking_lot::RwLock::new(VecDeque::new())),
            validator_admission_policy: "devnet-derived".into(),
            founder_id_com: None,
            validator_count: 3,
            validator: false,
            public_node_roles: vec!["rpc".into(), "archive".into(), "fullnode".into()],
            public_rpc: false,
        });
        let rpc = AceRpcImpl { shared };
        let contribution = rpc.get_node_contribution().unwrap();

        assert!(contribution.public_rpc);
        assert!(contribution.tx_relay);
        assert!(contribution.block_relay);
        assert!(contribution.archive);
        assert!(!contribution.consensus_participant);
        assert_eq!(contribution.roles, vec!["rpc", "archive", "relay"]);
    }

    #[test]
    fn validator_candidate_check_reports_expected_devnet_key() {
        let candidate = [0x44; 32];
        let shared = Arc::new(RpcState {
            state: Arc::new(RwLock::new(ShardedState::new())),
            block_store: Arc::new(RwLock::new(InMemoryBlockStore::new())),
            mempool: Arc::new(Mempool::new(MempoolConfig::default())),
            mempool_notify: None,
            current_slot: Arc::new(AtomicU64::new(0)),
            peer_count: Arc::new(AtomicU64::new(0)),
            peer_snapshot: Arc::new(std::sync::RwLock::new(Vec::new())),
            latest_block_slot: Arc::new(AtomicU64::new(0)),
            state_root_hex: Arc::new(parking_lot::RwLock::new(String::new())),
            chain_id: 122_766,
            native_token: None,
            tx_receipt_store: Arc::new(RwLock::new(TxReceiptStore::new())),
            eth_events: Arc::new(EthEventHub::new(16)),
            outbound_tx: None,
            local_mev_ace_tx: None,
            otp_store: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            tps_samples: Arc::new(parking_lot::RwLock::new(VecDeque::new())),
            validator_admission_policy: "devnet-derived".into(),
            founder_id_com: Some(hex::encode([0xA5; 32])),
            validator_count: 3,
            validator: false,
            public_node_roles: Vec::new(),
            public_rpc: false,
        });
        let rpc = AceRpcImpl { shared };
        let check = rpc
            .check_validator_candidate(hex::encode(candidate), String::new())
            .unwrap();

        assert!(check.eligible);
        assert_eq!(check.admission_policy, "devnet-derived");
        assert!(check.expected_signing_pubkey.is_some());
        assert!(check.errors.is_empty());
    }

    fn make_receipt(slot: u64, index: u32, fill: u8) -> RpcTransactionReceipt {
        RpcTransactionReceipt {
            transaction_hash: hex::encode([fill; 32]),
            external_transaction_hash: None,
            block_slot: slot,
            block_hash: hex::encode([slot as u8; 32]),
            transaction_index: index,
            from: hex::encode([9u8; 32]),
            status: true,
            error: None,
            state_changes: vec![],
            gas_used: None,
            contract_address: None,
            evm_logs: vec![],
        }
    }

    fn make_signed_transfer_tx(
        sender_seed: [u8; 32],
        sender: AccountId,
        nonce: u64,
        recipient: AccountId,
        amount: u64,
    ) -> Transaction {
        let payload = TransactionOp::Transfer {
            nonce,
            to: recipient,
            amount,
        }
        .encode();
        let mut obj_hash = [0u8; 32];
        obj_hash.copy_from_slice(&Sha256::digest(&payload));
        let domain = Domain::new(122_766, 0);
        Transaction::new(
            payload,
            Attestation {
                obj_hash,
                idcom: sender.0,
                domain,
                context_tag: [0u8; 16],
                credential: make_credential(
                    &sender_seed,
                    &obj_hash,
                    &sender.0,
                    &domain,
                    &[0u8; 16],
                ),
            },
        )
    }

    #[test]
    fn remove_receipts_for_slot_prunes_receipt_and_hash_index() {
        let mut store = TxReceiptStore::new();
        let keep = make_receipt(10, 0, 1);
        let remove = make_receipt(11, 0, 2);
        let keep_hash: [u8; 32] = hex::decode(&keep.transaction_hash)
            .unwrap()
            .try_into()
            .unwrap();
        let remove_hash: [u8; 32] = hex::decode(&remove.transaction_hash)
            .unwrap()
            .try_into()
            .unwrap();

        store.put_receipts(vec![keep.clone(), remove.clone()]);
        store.remove_receipts_for_slot(11);

        assert_eq!(store.get_location(&keep_hash), Some((10, 0)));
        assert_eq!(store.get_receipt(10, 0), Some(keep));
        assert_eq!(store.get_location(&remove_hash), None);
        assert_eq!(store.get_receipt(11, 0), None);
    }

    #[test]
    fn external_hash_aliases_resolve_to_same_receipt() {
        let mut store = TxReceiptStore::new();
        let mut receipt = make_receipt(12, 3, 7);
        receipt.external_transaction_hash = Some(hex::encode([8u8; 32]));

        let internal_hash: [u8; 32] = hex::decode(&receipt.transaction_hash)
            .unwrap()
            .try_into()
            .unwrap();
        let external_hash: [u8; 32] =
            hex::decode(receipt.external_transaction_hash.as_ref().unwrap())
                .unwrap()
                .try_into()
                .unwrap();

        store.put_receipts(vec![receipt.clone()]);

        assert_eq!(store.get_location(&internal_hash), Some((12, 3)));
        assert_eq!(store.get_location(&external_hash), Some((12, 3)));
        assert_eq!(store.get_receipt(12, 3), Some(receipt));
    }

    #[test]
    fn persistent_store_round_trips_snapshot() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ace-rpc-receipts-{unique}.bin"));
        let mut store = TxReceiptStore::open_persistent(&path, 32).unwrap();
        let receipt = make_receipt(13, 1, 9);
        let tx_hash: [u8; 32] = hex::decode(&receipt.transaction_hash)
            .unwrap()
            .try_into()
            .unwrap();

        store.put_receipts(vec![receipt.clone()]);
        drop(store);

        let reopened = TxReceiptStore::open_persistent(&path, 32).unwrap();
        assert_eq!(reopened.get_location(&tx_hash), Some((13, 1)));
        assert_eq!(reopened.get_receipt(13, 1), Some(receipt));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn eviction_removes_all_hash_aliases_for_old_receipt() {
        let mut store = TxReceiptStore::with_max_receipts(1);
        let mut first = make_receipt(20, 0, 1);
        first.external_transaction_hash = Some(hex::encode([2u8; 32]));
        let mut second = make_receipt(21, 0, 3);
        second.external_transaction_hash = Some(hex::encode([4u8; 32]));

        let first_internal: [u8; 32] = hex::decode(&first.transaction_hash)
            .unwrap()
            .try_into()
            .unwrap();
        let first_external: [u8; 32] =
            hex::decode(first.external_transaction_hash.as_ref().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let second_internal: [u8; 32] = hex::decode(&second.transaction_hash)
            .unwrap()
            .try_into()
            .unwrap();
        let second_external: [u8; 32] =
            hex::decode(second.external_transaction_hash.as_ref().unwrap())
                .unwrap()
                .try_into()
                .unwrap();

        store.put_receipts(vec![first]);
        store.put_receipts(vec![second.clone()]);

        assert_eq!(store.get_location(&first_internal), None);
        assert_eq!(store.get_location(&first_external), None);
        assert_eq!(store.get_location(&second_internal), Some((21, 0)));
        assert_eq!(store.get_location(&second_external), Some((21, 0)));
        assert_eq!(store.get_receipt(21, 0), Some(second));
    }

    #[test]
    fn replacing_receipt_cleans_old_hash_aliases() {
        let mut store = TxReceiptStore::new();
        let mut first = make_receipt(30, 0, 5);
        first.external_transaction_hash = Some(hex::encode([6u8; 32]));
        let mut replacement = make_receipt(30, 0, 7);
        replacement.external_transaction_hash = Some(hex::encode([8u8; 32]));

        let first_internal: [u8; 32] = hex::decode(&first.transaction_hash)
            .unwrap()
            .try_into()
            .unwrap();
        let first_external: [u8; 32] =
            hex::decode(first.external_transaction_hash.as_ref().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let replacement_internal: [u8; 32] = hex::decode(&replacement.transaction_hash)
            .unwrap()
            .try_into()
            .unwrap();
        let replacement_external: [u8; 32] =
            hex::decode(replacement.external_transaction_hash.as_ref().unwrap())
                .unwrap()
                .try_into()
                .unwrap();

        store.put_receipts(vec![first]);
        store.put_receipts(vec![replacement.clone()]);

        assert_eq!(store.get_location(&first_internal), None);
        assert_eq!(store.get_location(&first_external), None);
        assert_eq!(store.get_location(&replacement_internal), Some((30, 0)));
        assert_eq!(store.get_location(&replacement_external), Some((30, 0)));
        assert_eq!(store.get_receipt(30, 0), Some(replacement));
    }

    #[test]
    fn collect_matching_logs_respects_slot_range() {
        let mut store = TxReceiptStore::new();
        let mut first = make_receipt(40, 0, 1);
        first.evm_logs.push(crate::types::EthLog {
            address: "0x1111111111111111111111111111111111111111".into(),
            topics: vec![],
            data: "0x".into(),
            block_number: "0x28".into(),
            transaction_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            transaction_index: "0x0".into(),
            block_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            log_index: "0x0".into(),
            removed: false,
        });
        let mut second = make_receipt(41, 0, 2);
        second.evm_logs.push(crate::types::EthLog {
            address: "0x2222222222222222222222222222222222222222".into(),
            topics: vec![],
            data: "0x".into(),
            block_number: "0x29".into(),
            transaction_hash: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .into(),
            transaction_index: "0x0".into(),
            block_hash: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
            log_index: "0x0".into(),
            removed: false,
        });

        store.put_receipts(vec![first, second]);

        let logs = store.collect_matching_logs(Some(41), Some(41), 10, |_| true);
        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0].address,
            "0x2222222222222222222222222222222222222222"
        );
    }

    #[tokio::test]
    async fn rpc_gap_fill_wakes_proposer_after_future_backlog() {
        let sender_seed = [0x31; 32];
        let sender = AccountId([0x41; 32]);
        let recipient = AccountId([0x42; 32]);

        let mut state = ShardedState::new();
        state.insert(Account::with_auth(
            sender,
            1_000,
            auth_public_key_from_seed(&sender_seed),
        ));
        let mempool = Arc::new(Mempool::with_slot_and_state(
            MempoolConfig::default(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(RwLock::new(state)),
        ));
        let notify = Arc::new(tokio::sync::Notify::new());
        let shared = RpcState {
            state: Arc::new(RwLock::new(ShardedState::new())),
            block_store: Arc::new(RwLock::new(InMemoryBlockStore::new())),
            mempool: Arc::clone(&mempool),
            mempool_notify: Some(Arc::clone(&notify)),
            current_slot: Arc::new(AtomicU64::new(0)),
            peer_count: Arc::new(AtomicU64::new(0)),
            peer_snapshot: Arc::new(std::sync::RwLock::new(Vec::new())),
            latest_block_slot: Arc::new(AtomicU64::new(0)),
            state_root_hex: Arc::new(parking_lot::RwLock::new(String::new())),
            chain_id: 122_766,
            native_token: None,
            tx_receipt_store: Arc::new(RwLock::new(TxReceiptStore::new())),
            eth_events: Arc::new(EthEventHub::new(16)),
            outbound_tx: None,
            local_mev_ace_tx: None,
            otp_store: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            tps_samples: Arc::new(parking_lot::RwLock::new(VecDeque::new())),
            validator_admission_policy: "devnet-derived".into(),
            founder_id_com: None,
            validator_count: 0,
            validator: false,
            public_node_roles: Vec::new(),
            public_rpc: false,
        };

        for nonce in 1..=3 {
            let tx = make_signed_transfer_tx(sender_seed, sender, nonce, recipient, 1);
            shared
                .submit_transaction_to_mempool(tx)
                .expect("future backlog tx should be accepted");
        }

        assert_eq!(mempool.pending_count(), 3);
        assert_eq!(mempool.ready_count(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), notify.notified())
                .await
                .is_err(),
            "future-only backlog should not wake the proposer",
        );

        let gap_fill_tx = make_signed_transfer_tx(sender_seed, sender, 0, recipient, 1);
        shared
            .submit_transaction_to_mempool(gap_fill_tx)
            .expect("gap-filling tx should be accepted");

        tokio::time::timeout(Duration::from_millis(200), notify.notified())
            .await
            .expect("gap-fill should wake the proposer");
        assert_eq!(mempool.pending_count(), 4);
        assert_eq!(mempool.ready_count(), 4);
    }
}
