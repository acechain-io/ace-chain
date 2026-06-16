//! Account model for ACE Chain.
//!
//! Each account is identified by its identity commitment (`id_com`),
//! a 32-byte hash derived from the user's REV via Poseidon/SHA-256.
//! No public key is ever exposed on-chain — this is the sole on-chain
//! identity representation (Definition 3 in the paper).

use ace_runtime::crypto::sig_algo::{SignatureAlgorithm, TaggedPubkey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// Account identifier: the 32-byte identity commitment (`id_com`).
///
/// Wraps the `idcom` field from [`ace_runtime::types::Attestation`].
/// This is `Poseidon(REV, salt, domain)` in the paper, implemented
/// as `SHA-256(REV || salt || domain)` in the reference implementation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccountId(pub [u8; 32]);

impl AccountId {
    /// Create an `AccountId` from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The zero account id (used as a sentinel / default).
    pub const ZERO: Self = Self([0u8; 32]);
}

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for AccountId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// On-chain account state.
///
/// The account model supports both user accounts (balance + nonce) and
/// future smart contract accounts (code_hash + storage_root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Identity commitment — the account's on-chain address.
    pub id_com: AccountId,
    /// Account balance in the smallest denomination.
    pub balance: u64,
    /// Transaction nonce (monotonically increasing, prevents replay).
    pub nonce: u64,
    /// Optional code hash for smart contract accounts.
    pub code_hash: Option<[u8; 32]>,
    /// Raw bytecode for smart contract accounts.
    #[serde(skip)]
    pub code: Option<Vec<u8>>,
    /// Root hash of the account's storage trie.
    pub storage_root: [u8; 32],
    /// ACE-GF wallet fingerprint (`SHA3-256(sealed || "acegf:xid")`).
    ///
    /// When set, this account is XID-native: all chain-specific address
    /// fields below are aliases derived from the same mnemonic.  The
    /// `id_com` is computed as `idcom_xid(xid)`.
    #[serde(default)]
    pub xid: Option<[u8; 32]>,
    /// PQC address fingerprint: `SHA-256("ace-xaddress-v1" || ml_dsa_44_pubkey)`.
    ///
    /// A 32-byte hash of the ML-DSA-44 public key, used as the user-facing
    /// "ACE address" for post-quantum transfers.
    #[serde(default)]
    pub xaddress: Option<[u8; 32]>,
    /// Optional canonical EVM address alias for this account.
    ///
    /// Raw-chain EVM accounts and EVM contracts must preserve their original
    /// 20-byte address rather than being re-derived from `id_com`.
    #[serde(default)]
    pub evm_address: Option<[u8; 20]>,
    /// Optional canonical TRON address alias for this account.
    ///
    /// TRON addresses share the same byte width as EVM addresses but live in a
    /// distinct namespace, so the alias is tracked separately.
    #[serde(default)]
    pub tron_address: Option<[u8; 20]>,
    /// Optional canonical Solana Ed25519 public key alias.
    #[serde(default)]
    pub solana_address: Option<[u8; 32]>,
    /// Optional canonical Bitcoin script pubkey alias (variable length).
    #[serde(default)]
    pub btc_address: Option<Vec<u8>>,
    /// Algorithm-tagged public key used to verify transaction attestations.
    ///
    /// Transactions from this account must include a valid signature over
    /// `(obj_hash, id_com, domain)` produced by the matching private key.
    #[serde(default)]
    pub auth_pubkey: TaggedPubkey,
    /// Additional auth keys for multi-algorithm support (e.g. PQC + legacy).
    ///
    /// The primary key is `auth_pubkey`; this vector holds keys for other
    /// algorithms. At most 3 additional keys are allowed (4 total including
    /// the primary). Verification checks `auth_pubkey` first, then this list.
    #[serde(default)]
    pub auth_keys: Vec<TaggedPubkey>,
    /// Slot number when this account was last touched by a transaction.
    /// Used for state expiry decisions. Defaults to 0 for genesis accounts.
    #[serde(default)]
    pub last_touched_slot: u64,
}

impl Account {
    /// Create a new account with zero balance.
    pub fn new(id_com: AccountId) -> Self {
        Self {
            id_com,
            balance: 0,
            nonce: 0,
            code_hash: None,
            code: None,
            storage_root: [0u8; 32],
            xid: None,
            xaddress: None,
            evm_address: None,
            tron_address: None,
            solana_address: None,
            btc_address: None,
            auth_pubkey: TaggedPubkey::default(),
            auth_keys: Vec::new(),
            last_touched_slot: 0,
        }
    }

    /// Create a new account with an initial balance (for genesis).
    pub fn with_balance(id_com: AccountId, balance: u64) -> Self {
        Self {
            balance,
            ..Self::new(id_com)
        }
    }

    /// Create a new account with balance and attestation verification key.
    pub fn with_auth(id_com: AccountId, balance: u64, auth_pubkey: TaggedPubkey) -> Self {
        Self {
            balance,
            auth_pubkey,
            ..Self::new(id_com)
        }
    }

    /// Create a new XID-native account.
    ///
    /// `id_com` should be `AccountId::from_bytes(idcom_xid(&xid))`.
    pub fn with_xid(id_com: AccountId, xid: [u8; 32], auth_pubkey: TaggedPubkey) -> Self {
        Self {
            xid: Some(xid),
            auth_pubkey,
            ..Self::new(id_com)
        }
    }

    /// Create a new account bound to a canonical EVM address.
    pub fn with_evm_address(id_com: AccountId, evm_address: [u8; 20]) -> Self {
        Self {
            evm_address: Some(evm_address),
            ..Self::new(id_com)
        }
    }

    /// Create a new account bound to a canonical TRON address.
    pub fn with_tron_address(id_com: AccountId, tron_address: [u8; 20]) -> Self {
        Self {
            tron_address: Some(tron_address),
            ..Self::new(id_com)
        }
    }

    /// Maximum number of auth keys (primary + additional).
    const MAX_AUTH_KEYS: usize = 4;

    /// Get auth key for a specific algorithm. Checks primary key first, then auth_keys.
    /// Skips the primary key if it is zero (un-provisioned default).
    pub fn auth_key_for_algorithm(&self, alg: SignatureAlgorithm) -> Option<&TaggedPubkey> {
        if !self.auth_pubkey.is_zero() && self.auth_pubkey.algorithm == alg {
            return Some(&self.auth_pubkey);
        }
        self.auth_keys.iter().find(|k| k.algorithm == alg)
    }

    /// All auth keys (primary + additional).
    pub fn all_auth_keys(&self) -> Vec<&TaggedPubkey> {
        let mut keys = vec![&self.auth_pubkey];
        keys.extend(self.auth_keys.iter());
        keys
    }

    /// True if the account has at least one non-zero auth key provisioned.
    pub fn has_provisioned_auth_key(&self) -> bool {
        !self.auth_pubkey.is_zero() || self.auth_keys.iter().any(|key| !key.is_zero())
    }

    /// Add an auth key of a different algorithm.
    ///
    /// Fails if the algorithm is already present (in primary or additional keys)
    /// or if the maximum number of keys has been reached.
    pub fn add_auth_key(&mut self, key: TaggedPubkey) -> Result<(), String> {
        // If the primary key is zero (un-provisioned default), promote the new
        // key to primary regardless of algorithm match.
        if self.auth_pubkey.is_zero() {
            self.auth_pubkey = key;
            return Ok(());
        }
        if self.auth_pubkey.algorithm == key.algorithm {
            return Err(format!("primary key already uses {:?}", key.algorithm));
        }
        if self.auth_keys.iter().any(|k| k.algorithm == key.algorithm) {
            return Err(format!("auth key for {:?} already exists", key.algorithm));
        }
        if self.auth_keys.len() + 1 >= Self::MAX_AUTH_KEYS {
            return Err("maximum auth keys reached".into());
        }
        self.auth_keys.push(key);
        // Sort by algorithm tag for deterministic state hashing across nodes.
        self.auth_keys.sort_by_key(|k| k.algorithm as u8);
        Ok(())
    }

    /// Serialize the account to bytes for Merkle hashing.
    ///
    /// Uses `auth_pubkey.fingerprint()` so the hash is always a fixed 32
    /// bytes regardless of the underlying signature algorithm.
    ///
    /// The optional `code_hash` field is domain-separated with a tag byte
    /// (`0x01` present, `0x00` absent) so that an account without a code
    /// hash can never collide with one whose code hash happens to produce
    /// the same trailing bytes.
    ///
    /// **NOTE**: This is a consensus-breaking change to the Merkle root
    /// computation.  Deployment must be coordinated with a hard fork so
    /// that all nodes switch to the new serialisation at the same slot.
    pub fn to_hash_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&self.id_com.0);
        buf.extend_from_slice(&self.balance.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.storage_root);
        // XID (tag 0x10)
        match &self.xid {
            Some(xid) => {
                buf.push(0x10);
                buf.extend_from_slice(xid);
            }
            None => buf.push(0x00),
        }
        // xaddress / PQC address fingerprint (tag 0x11)
        match &self.xaddress {
            Some(xa) => {
                buf.push(0x11);
                buf.extend_from_slice(xa);
            }
            None => buf.push(0x00),
        }
        // EVM address (tag 0x01)
        match self.evm_address {
            Some(addr) => {
                buf.push(0x01);
                buf.extend_from_slice(&addr);
            }
            None => buf.push(0x00),
        }
        // TRON address (tag 0x02)
        match self.tron_address {
            Some(addr) => {
                buf.push(0x02);
                buf.extend_from_slice(&addr);
            }
            None => buf.push(0x00),
        }
        // Solana address (tag 0x03)
        match &self.solana_address {
            Some(addr) => {
                buf.push(0x03);
                buf.extend_from_slice(addr);
            }
            None => buf.push(0x00),
        }
        // Bitcoin address (tag 0x04, length-prefixed)
        match &self.btc_address {
            Some(script) => {
                buf.push(0x04);
                buf.extend_from_slice(&(script.len() as u16).to_le_bytes());
                buf.extend_from_slice(script);
            }
            None => buf.push(0x00),
        }
        // Code hash (tag 0x05/0x00 — distinct from evm_address tag 0x01)
        match &self.code_hash {
            Some(ch) => {
                buf.push(0x05);
                buf.extend_from_slice(ch);
            }
            None => buf.push(0x00),
        }
        buf.extend_from_slice(&self.auth_pubkey.fingerprint());
        // Additional auth keys (tag 0x06, count-prefixed, sorted by algorithm for determinism)
        if !self.auth_keys.is_empty() {
            buf.push(0x06);
            buf.push(self.auth_keys.len() as u8);
            let mut fingerprints: Vec<[u8; 32]> =
                self.auth_keys.iter().map(|k| k.fingerprint()).collect();
            fingerprints.sort();
            for fp in &fingerprints {
                buf.extend_from_slice(fp);
            }
        }
        buf.extend_from_slice(&self.last_touched_slot.to_le_bytes());
        buf
    }

    /// Compute a 32-byte stub hash for state expiry.
    ///
    /// The hash covers the full account state plus contract storage,
    /// domain-separated with `"ACE-STUB-V1"` to prevent collisions
    /// with regular Merkle leaf hashes.
    pub fn compute_stub_hash(&self, storage: Option<&BTreeMap<[u8; 32], [u8; 32]>>) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ACE-STUB-V1");
        hasher.update(self.to_hash_bytes());
        if let Some(storage) = storage {
            for (slot, value) in storage {
                hasher.update(slot);
                hasher.update(value);
            }
        }
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    }
}

/// A 32-byte hash stub representing an expired account.
///
/// When an account has been inactive (zero balance, no transactions)
/// for longer than the state expiry period, it is compressed from its
/// full representation (~150+ bytes) into this 40-byte stub. The stub
/// still participates in the Merkle root computation so that the state
/// root remains verifiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountStub {
    /// The identity commitment of the expired account.
    pub id_com: AccountId,
    /// SHA-256 hash of the full account state at time of expiry.
    pub hash: [u8; 32],
    /// Slot at which the account was expired.
    pub expired_at_slot: u64,
}

/// Proof required to resurrect an expired (stubbed) account.
///
/// The node verifies that hashing the provided data matches the stored
/// stub hash. On success, the full account and its storage are restored
/// to the hot tier of the state tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResurrectionProof {
    /// The full account state at time of expiry.
    pub account: Account,
    /// The full contract storage at time of expiry.
    pub storage: BTreeMap<[u8; 32], [u8; 32]>,
}

impl ResurrectionProof {
    /// Verify this proof against a stub.
    pub fn verify(&self, stub: &AccountStub) -> bool {
        self.account.id_com == stub.id_com
            && self.account.compute_stub_hash(Some(&self.storage)) == stub.hash
    }
}
