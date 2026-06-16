//! Core types for the dual-mode VM bridge.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ace_model::account::AccountId;

/// An external L1 chain that ACE Chain bridges to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExternalChain {
    Ethereum = 1,
    Solana = 2,
    Bitcoin = 3,
    Tron = 4,
    Bsc = 5,
}

impl ExternalChain {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ethereum => "ethereum",
            Self::Solana => "solana",
            Self::Bitcoin => "bitcoin",
            Self::Tron => "tron",
            Self::Bsc => "bsc",
        }
    }

    pub fn all() -> &'static [ExternalChain] {
        &[
            Self::Ethereum,
            Self::Solana,
            Self::Bitcoin,
            Self::Tron,
            Self::Bsc,
        ]
    }
}

impl std::fmt::Display for ExternalChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Identifies a specific asset on an external chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExternalAsset {
    /// The chain's native token (ETH, SOL, BTC, TRX).
    Native(ExternalChain),
    /// An ERC-20 token on Ethereum, identified by contract address.
    Erc20([u8; 20]),
    /// A BEP-20 token on BSC, identified by contract address.
    Bep20([u8; 20]),
    /// An SPL token on Solana, identified by mint address.
    SplToken([u8; 32]),
    /// A TRC-20 token on Tron, identified by contract address.
    Trc20([u8; 20]),
}

impl ExternalAsset {
    pub fn chain(&self) -> ExternalChain {
        match self {
            Self::Native(c) => *c,
            Self::Erc20(_) => ExternalChain::Ethereum,
            Self::Bep20(_) => ExternalChain::Bsc,
            Self::SplToken(_) => ExternalChain::Solana,
            Self::Trc20(_) => ExternalChain::Tron,
        }
    }

    /// Canonical label used in domain separators.
    pub fn label(&self) -> Vec<u8> {
        match self {
            Self::Native(c) => format!("{}:native", c.name()).into_bytes(),
            Self::Erc20(addr) => {
                let mut v = b"ethereum:erc20:".to_vec();
                v.extend_from_slice(addr);
                v
            }
            Self::Bep20(addr) => {
                let mut v = b"bsc:bep20:".to_vec();
                v.extend_from_slice(addr);
                v
            }
            Self::SplToken(mint) => {
                let mut v = b"solana:spl:".to_vec();
                v.extend_from_slice(mint);
                v
            }
            Self::Trc20(addr) => {
                let mut v = b"tron:trc20:".to_vec();
                v.extend_from_slice(addr);
                v
            }
        }
    }
}

/// Derive the ACE Chain mint AccountId for a wrapped external asset.
///
/// `SHA-256("ace-wrapped:" || asset_label)`
pub fn wrapped_mint_id(asset: &ExternalAsset) -> AccountId {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-wrapped:");
    hasher.update(asset.label());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    AccountId::from_bytes(hash)
}

/// The bridge authority AccountId — has mint/burn authority over all wrapped assets.
///
/// `SHA-256("ace-bridge-authority")`
pub fn bridge_authority_id() -> AccountId {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-bridge-authority");
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    AccountId::from_bytes(hash)
}

/// Record of a verified deposit from an external chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositRecord {
    /// Unique deposit identifier (external chain tx hash or similar).
    pub deposit_id: [u8; 32],
    /// User-authorized conversion intent this deposit funds.
    pub intent_id: [u8; 32],
    /// Which external asset was deposited.
    pub asset: ExternalAsset,
    /// Amount in the asset's smallest unit.
    pub amount: u64,
    /// Recipient's ACE Chain AccountId (derived from their address on the
    /// external chain — same address, dual mode).
    pub recipient: AccountId,
    /// Slot at which the deposit was processed on ACE Chain.
    pub processed_at: u64,
}

/// Serde helper for `[u8; 64]` — serializes as a list of bytes.
mod serde_bytes_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(de)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })
    }
}

/// A deposit record signed by an approved relayer.
///
/// The relayer attests that the deposit was observed and verified on the
/// external chain. The signature covers `hash_deposit_record(&deposit)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDepositRecord {
    pub deposit: DepositRecord,
    /// Ed25519 public key of the relayer that signed this attestation.
    pub relayer_pubkey: [u8; 32],
    /// Ed25519 signature over `hash_deposit_record(&deposit)`.
    #[serde(with = "serde_bytes_64")]
    pub relayer_signature: [u8; 64],
}

/// Relayer-signed proof that a withdrawal was completed on the destination chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalCompletionRecord {
    pub withdrawal_id: u64,
    pub destination_chain: ExternalChain,
    pub external_tx_hash: [u8; 32],
    /// Hash of the exact ACE withdrawal record that the external release
    /// transaction is expected to satisfy.
    pub withdrawal_record_hash: [u8; 32],
    /// External token/gateway recipient/amount observed in the destination
    /// chain release event. ACE verifies these fields against the pending
    /// withdrawal record before finalizing reserve accounting.
    pub released_asset: ExternalAsset,
    pub released_recipient: Vec<u8>,
    pub released_amount: u64,
    pub gateway_address: Vec<u8>,
    /// Ed25519 public key of the relayer that observed the external receipt.
    pub relayer_pubkey: [u8; 32],
    /// Ed25519 signature over `hash_withdrawal_completion(&record)`.
    #[serde(with = "serde_bytes_64")]
    pub relayer_signature: [u8; 64],
}

/// Compute deterministic hash of a deposit record for signing/verification.
///
/// `SHA-256("ace-deposit-v1:" || deposit_id || intent_id || label_len_le || chain_label || amount_le || recipient)`
pub fn hash_deposit_record(deposit: &DepositRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-deposit-v1:");
    hasher.update(deposit.deposit_id);
    hasher.update(deposit.intent_id);
    let label = deposit.asset.label();
    hasher.update((label.len() as u32).to_le_bytes());
    hasher.update(label.as_slice());
    hasher.update(deposit.amount.to_le_bytes());
    hasher.update(deposit.recipient.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute deterministic hash of a withdrawal completion for relayer signing.
///
/// `SHA-256("ace-withdrawal-completed-v1:" || withdrawal_id || chain || external_tx_hash || withdrawal_record_hash || released_asset || recipient || amount || gateway || relayer_pubkey)`
pub fn hash_withdrawal_completion(completion: &WithdrawalCompletionRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-withdrawal-completed-v1:");
    hasher.update(completion.withdrawal_id.to_le_bytes());
    hasher.update([completion.destination_chain as u8]);
    hasher.update(completion.external_tx_hash);
    hasher.update(completion.withdrawal_record_hash);
    let label = completion.released_asset.label();
    hasher.update((label.len() as u32).to_le_bytes());
    hasher.update(label);
    hasher.update((completion.released_recipient.len() as u32).to_le_bytes());
    hasher.update(&completion.released_recipient);
    hasher.update(completion.released_amount.to_le_bytes());
    hasher.update((completion.gateway_address.len() as u32).to_le_bytes());
    hasher.update(&completion.gateway_address);
    hasher.update(completion.relayer_pubkey);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Record of a pending withdrawal to an external chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalRecord {
    /// Sequential withdrawal ID.
    pub withdrawal_id: u64,
    /// User-authorized conversion intent this withdrawal completes.
    pub intent_id: [u8; 32],
    /// Which wrapped asset is being unwrapped.
    pub asset: ExternalAsset,
    /// Amount being withdrawn.
    pub amount: u64,
    /// Requester's ACE Chain AccountId.
    pub sender: AccountId,
    /// Destination address on the external chain (raw bytes).
    pub external_dest: Vec<u8>,
    /// Slot at which the withdrawal was requested.
    pub requested_at: u64,
    /// Whether the withdrawal has been finalized on the external chain.
    pub completed: bool,
}

/// Decimals for well-known native tokens.
pub fn native_decimals(chain: ExternalChain) -> u8 {
    match chain {
        ExternalChain::Ethereum => 18,
        ExternalChain::Solana => 9,
        ExternalChain::Bitcoin => 8,
        ExternalChain::Tron => 6,
        ExternalChain::Bsc => 18,
    }
}
