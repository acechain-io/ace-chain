use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ace_runtime::types::transaction::Transaction;

/// Identifies which virtual machine should execute a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VmId {
    /// ACE Native Runtime (opcodes 0x01–0x0F).
    AceNative,
    /// Move VM smart contract engine (opcodes 0x50–0x5F).
    Move,
    /// EVM-compatible engine (opcodes 0x10–0x1F).
    Evm,
    /// SVM-compatible engine (opcodes 0x20–0x2F).
    Svm,
    /// BVM — Bitcoin Script engine (opcodes 0x30–0x3F).
    Bvm,
    /// TVM — Tron VM engine (opcodes 0x40–0x4F).
    Tvm,
}

impl VmId {
    /// Determine the target VM from the first byte of a transaction payload.
    pub fn from_opcode(opcode: u8) -> Option<Self> {
        match opcode {
            0x01..=0x0F => Some(VmId::AceNative), // ACE native system transactions
            0x10..=0x1F => Some(VmId::Evm),      // EVM compatibility
            0x20..=0x2F => Some(VmId::Svm),      // Solana compatibility
            0x30..=0x3F => Some(VmId::Bvm),      // Bitcoin compatibility
            0x40..=0x4F => Some(VmId::Tvm),      // Tron compatibility
            0x50..=0x5F => Some(VmId::Move),     // Move smart contracts
            _ => None,
        }
    }
}

/// An event log emitted during execution.
#[derive(Debug, Clone)]
pub struct VmLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Receipt produced by a VM engine after executing a transaction.
#[derive(Debug, Clone)]
pub struct VmReceipt {
    /// Which VM executed this transaction.
    pub vm_id: VmId,
    /// Canonical transaction hash (SHA-256 of the serialized transaction).
    pub tx_hash: [u8; 32],
    /// Whether execution succeeded.
    pub success: bool,
    /// Sender identity commitment.
    pub sender: AccountId,
    /// State changes applied (empty on failure).
    pub state_changes: Vec<crate::receipt::StateChange>,
    /// Error message if execution failed.
    pub error: Option<String>,
    /// True if this receipt was produced by a test-only stub engine
    /// that did not actually modify state. Always false for production engines.
    pub simulated: bool,
    /// Gas used.
    pub gas_used: Option<u64>,
    /// Contract address created by a successful CREATE transaction.
    pub contract_address: Option<[u8; 20]>,
    /// Return data from execution.
    pub return_data: Option<Vec<u8>>,
    /// Event logs.
    pub logs: Vec<VmLog>,
}

/// Error type for VM execution.
/// VMs should return this when execution fails.
#[derive(Debug, thiserror::Error)]
pub enum VmExecutionError {
    #[error("VM execution failed: {0}")]
    Execution(String),

    #[error("Invalid transaction format: {0}")]
    InvalidPayload(String),

    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Other execution error: {0}")]
    Other(String),
}

/// Trait for a pluggable VM execution engine.
pub trait VmEngine: Send + Sync {
    /// The VM identifier.
    fn vm_id(&self) -> VmId;

    /// Human-readable name for logging.
    fn name(&self) -> &str;

    /// Execute a transaction against the state tree.
    fn execute(&self, state: &mut StateTree, tx: &Transaction) -> Result<VmReceipt, VmExecutionError>;
}

/// Hook for on-chain operations (e.g., HFI Pay lifecycle opcodes).
///
/// Implemented separately and registered on the dispatcher.
/// All state transitions funnel through this single hook so state
/// consistency is guaranteed.
pub trait ExecutionHook: Send + Sync {
    /// Run after attestation / credential verification. Mutates `StateTree`.
    fn execute(
        &self,
        state: &mut StateTree,
        tx: &Transaction,
        block_slot: u64,
    ) -> Result<VmReceipt, String>;
}
