//! Error types for the n-VM dispatcher.

#[derive(Debug, thiserror::Error)]
pub enum NVmError {
    #[error("unknown opcode: 0x{0:02x}")]
    UnknownOpcode(u8),

    #[error("empty transaction payload")]
    EmptyPayload,

    #[error("no engine registered for VM: {0:?}")]
    NoEngine(crate::vm::VmId),

    #[error("native execution error: {0}")]
    NativeError(String),

    #[error("EVM execution error: {0}")]
    EvmError(String),

    #[error("SVM execution error: {0}")]
    SvmError(String),

    #[error("BVM execution error: {0}")]
    BvmError(String),

    #[error("TVM execution error: {0}")]
    TvmError(String),

    #[error("invalid credential for sender {}", hex::encode(.0))]
    InvalidCredential([u8; 32]),

    #[error("account not found: {}", hex::encode(.0))]
    AccountNotFound([u8; 32]),

    #[error("internal dispatcher error: {0}")]
    InternalError(String),

    #[error("raw chain tx verification failed: {0}")]
    RawChainVerify(String),

    #[error("nonce overflow: account nonce reached u64::MAX")]
    NonceOverflow,

    /// HFI Pay 0x06 claim execution failed (see message).
    #[error("HFI Pay claim: {0}")]
    HfiPayClaim(String),

    /// Submitted 0x06 but the node n-VM was not constructed with a HfiPay claim hook.
    #[error(
        "HFI Pay on-chain execution is not available: this n-VM has no HfiPayHook (opcodes 0x06..=0x0A). \
         The transaction may still appear in a block with a failed receipt. \
         Restart ace-node from a build where validator/non-validator startup calls \
         NVm::set_hfi_claim_hook (see logs: \"n-VM initialized\" … \"HFI Pay\" hook)."
    )]
    HfiPayClaimNotConfigured,
}

// Conversions between the dispatcher-internal NVmError and the neutral
// VmExecutionError defined in ace-engine (the VmEngine trait error type).
//
// Engines implement their logic against NVmError; the trait wrapper converts
// to VmExecutionError at the boundary, and the dispatcher converts back when
// consuming `engine.execute(...)?`.
impl From<NVmError> for ace_engine::VmExecutionError {
    fn from(e: NVmError) -> Self {
        ace_engine::VmExecutionError::Execution(e.to_string())
    }
}

impl From<ace_engine::VmExecutionError> for NVmError {
    fn from(e: ace_engine::VmExecutionError) -> Self {
        match e {
            ace_engine::VmExecutionError::InvalidPayload(_) => NVmError::EmptyPayload,
            ace_engine::VmExecutionError::AccountNotFound(s) => {
                NVmError::InternalError(format!("account not found: {s}"))
            }
            ace_engine::VmExecutionError::Execution(s) | ace_engine::VmExecutionError::Other(s) => {
                NVmError::InternalError(s)
            }
        }
    }
}
