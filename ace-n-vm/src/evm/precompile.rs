//! ACE-GF EVM precompile stubs (addresses 0x0100–0x0107).
//!
//! With feature `mock-precompile`: return a mock marker for dev/test.
//! Without it (production): return `Err` so any contract calling these reverts
//! until real implementations are available.
//!
//! **0x0106 (CrossVmCall)** and **0x0107 (ResolveSvmAddress)** are fully
//! implemented: they perform stateless, deterministic SHA-256 address
//! derivation via [`crate::cross_vm::AddressResolver`].

use crate::cross_vm::AddressResolver;
use ace_model::account::AccountId;

/// Precompile address range start.
pub const PRECOMPILE_BASE: u16 = 0x0100;

#[cfg(not(feature = "mock-precompile"))]
const PRODUCTION_ERR: &str = "ACE precompile not available in production; implement or disable EVM";

/// Trait for an ACE-GF EVM precompile.
pub trait AcePrecompile: Send + Sync {
    /// Precompile address (0x0100–0x0107).
    fn address(&self) -> u16;
    /// Human-readable name.
    fn name(&self) -> &str;
    /// Execute the precompile. Returns output bytes on success.
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, String>;
}

/// 0x0100: Verify an identity commitment.
pub struct IdComVerify;
impl AcePrecompile for IdComVerify {
    fn address(&self) -> u16 {
        0x0100
    }
    fn name(&self) -> &str {
        "id_com_verify"
    }
    fn execute(&self, _input: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(feature = "mock-precompile")]
        {
            tracing::warn!("mock precompile id_com_verify — NOT production safe");
            Ok(vec![0xFF, 0x00])
        }
        #[cfg(not(feature = "mock-precompile"))]
        Err(PRODUCTION_ERR.to_string())
    }
}

/// 0x0101: Derive context from inputs.
pub struct ContextDerive;
impl AcePrecompile for ContextDerive {
    fn address(&self) -> u16 {
        0x0101
    }
    fn name(&self) -> &str {
        "context_derive"
    }
    fn execute(&self, _input: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(feature = "mock-precompile")]
        {
            tracing::warn!("mock precompile context_derive — NOT production safe");
            Ok(vec![0xFF, 0x00])
        }
        #[cfg(not(feature = "mock-precompile"))]
        Err(PRODUCTION_ERR.to_string())
    }
}

/// 0x0102: Check admin factor credentials.
pub struct AdminFactorCheck;
impl AcePrecompile for AdminFactorCheck {
    fn address(&self) -> u16 {
        0x0102
    }
    fn name(&self) -> &str {
        "admin_factor_check"
    }
    fn execute(&self, _input: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(feature = "mock-precompile")]
        {
            tracing::warn!("mock precompile admin_factor_check — NOT production safe");
            Ok(vec![0xFF, 0x00])
        }
        #[cfg(not(feature = "mock-precompile"))]
        Err(PRODUCTION_ERR.to_string())
    }
}

/// 0x0103: Batch verify zkACE proofs.
pub struct ZkAceBatchVerify;
impl AcePrecompile for ZkAceBatchVerify {
    fn address(&self) -> u16 {
        0x0103
    }
    fn name(&self) -> &str {
        "zkace_batch_verify"
    }
    fn execute(&self, _input: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(feature = "mock-precompile")]
        {
            tracing::warn!("mock precompile zkace_batch_verify — NOT production safe");
            Ok(vec![0xFF, 0x00])
        }
        #[cfg(not(feature = "mock-precompile"))]
        Err(PRODUCTION_ERR.to_string())
    }
}

/// 0x0104: Derive multi-signature commitment.
pub struct MultisigDerive;
impl AcePrecompile for MultisigDerive {
    fn address(&self) -> u16 {
        0x0104
    }
    fn name(&self) -> &str {
        "multisig_derive"
    }
    fn execute(&self, _input: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(feature = "mock-precompile")]
        {
            tracing::warn!("mock precompile multisig_derive — NOT production safe");
            Ok(vec![0xFF, 0x00])
        }
        #[cfg(not(feature = "mock-precompile"))]
        Err(PRODUCTION_ERR.to_string())
    }
}

/// 0x0105: Verify multi-signature.
pub struct MultisigVerify;
impl AcePrecompile for MultisigVerify {
    fn address(&self) -> u16 {
        0x0105
    }
    fn name(&self) -> &str {
        "multisig_verify"
    }
    fn execute(&self, _input: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(feature = "mock-precompile")]
        {
            tracing::warn!("mock precompile multisig_verify — NOT production safe");
            Ok(vec![0xFF, 0x00])
        }
        #[cfg(not(feature = "mock-precompile"))]
        Err(PRODUCTION_ERR.to_string())
    }
}

/// 0x0106: Cross-VM address resolution precompile.
///
/// Stateless, deterministic address derivation between EVM, ACE, and SVM
/// address spaces.  Input is a one-byte opcode followed by the address payload:
///
/// | Op   | Input (after op byte)           | Output                        |
/// |------|---------------------------------|-------------------------------|
/// | 0x01 | `[u8; 20]` EVM address          | ACE AccountId (32 bytes)      |
/// | 0x02 | `[u8; 32]` ACE AccountId        | EVM address   (20 bytes)      |
/// | 0x03 | `[u8; 32]` ACE AccountId        | SVM address   (32 bytes)      |
pub struct CrossVmCall;
impl AcePrecompile for CrossVmCall {
    fn address(&self) -> u16 {
        0x0106
    }
    fn name(&self) -> &str {
        "cross_vm_call"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        if input.is_empty() {
            return Err("cross_vm_call: empty input".into());
        }
        match input[0] {
            // 0x01 + [u8; 20] EVM address → ACE AccountId (32 bytes)
            0x01 => {
                if input.len() != 1 + 20 {
                    return Err(format!(
                        "cross_vm_call(0x01): expected 21 bytes, got {}",
                        input.len()
                    ));
                }
                let mut evm_addr = [0u8; 20];
                evm_addr.copy_from_slice(&input[1..21]);
                let ace_id = AddressResolver::ace_id_from_evm(&evm_addr);
                Ok(ace_id.as_bytes().to_vec())
            }
            // 0x02 + [u8; 32] ACE AccountId → EVM address (20 bytes)
            0x02 => {
                if input.len() != 1 + 32 {
                    return Err(format!(
                        "cross_vm_call(0x02): expected 33 bytes, got {}",
                        input.len()
                    ));
                }
                let mut id_bytes = [0u8; 32];
                id_bytes.copy_from_slice(&input[1..33]);
                let ace_id = AccountId(id_bytes);
                let evm_addr = AddressResolver::to_evm_address(&ace_id);
                Ok(evm_addr.to_vec())
            }
            // 0x03 + [u8; 32] ACE AccountId → SVM address (32 bytes)
            0x03 => {
                if input.len() != 1 + 32 {
                    return Err(format!(
                        "cross_vm_call(0x03): expected 33 bytes, got {}",
                        input.len()
                    ));
                }
                let mut id_bytes = [0u8; 32];
                id_bytes.copy_from_slice(&input[1..33]);
                let ace_id = AccountId(id_bytes);
                let svm_addr = AddressResolver::to_svm_address(&ace_id);
                Ok(svm_addr.to_vec())
            }
            op => Err(format!("cross_vm_call: unknown op 0x{op:02x}")),
        }
    }
}

/// 0x0107: Resolve an id_com (32 bytes) to its SVM program address (32 bytes).
///
/// Input:  `[u8; 32]` — ACE AccountId (id_com).
/// Output: `[u8; 32]` — deterministic SVM address via `SHA-256("svm:" || id_com)`.
pub struct ResolveSvmAddress;
impl AcePrecompile for ResolveSvmAddress {
    fn address(&self) -> u16 {
        0x0107
    }
    fn name(&self) -> &str {
        "resolve_svm_address"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        if input.len() != 32 {
            return Err(format!(
                "resolve_svm_address: expected 32 bytes, got {}",
                input.len()
            ));
        }
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(input);
        let ace_id = AccountId(id_bytes);
        let svm_addr = AddressResolver::to_svm_address(&ace_id);
        Ok(svm_addr.to_vec())
    }
}

/// All 8 ACE-GF EVM precompiles.
pub fn all_precompiles() -> Vec<Box<dyn AcePrecompile>> {
    vec![
        Box::new(IdComVerify),
        Box::new(ContextDerive),
        Box::new(AdminFactorCheck),
        Box::new(ZkAceBatchVerify),
        Box::new(MultisigDerive),
        Box::new(MultisigVerify),
        Box::new(CrossVmCall),
        Box::new(ResolveSvmAddress),
    ]
}
