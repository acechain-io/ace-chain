//! ACE-GF SVM syscall stubs.
//!
//! With feature `mock-precompile`: return a mock marker for dev/test.
//! Without it (production): return `Err` so any program calling these fails
//! until real implementations are available.

#[cfg(not(feature = "mock-precompile"))]
const PRODUCTION_ERR: &str = "ACE syscall not available in production; implement or disable SVM";

/// Trait for an ACE-GF SVM syscall.
pub trait AceSyscall: Send + Sync {
    /// Syscall name (used for logging and dispatch).
    fn name(&self) -> &str;
    /// Execute the syscall. Returns output bytes on success.
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, String>;
}

/// Verify an attestation check within an SVM program.
pub struct AttestCheck;
impl AceSyscall for AttestCheck {
    fn name(&self) -> &str {
        "attest_check"
    }
    fn execute(&self, _input: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(feature = "mock-precompile")]
        {
            tracing::warn!("mock syscall attest_check — NOT production safe");
            Ok(vec![0xFF, 0x00])
        }
        #[cfg(not(feature = "mock-precompile"))]
        Err(PRODUCTION_ERR.to_string())
    }
}

/// Verify an identity commitment within an SVM program.
pub struct IdComVerifySyscall;
impl AceSyscall for IdComVerifySyscall {
    fn name(&self) -> &str {
        "id_com_verify"
    }
    fn execute(&self, _input: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(feature = "mock-precompile")]
        {
            tracing::warn!("mock syscall id_com_verify — NOT production safe");
            Ok(vec![0xFF, 0x00])
        }
        #[cfg(not(feature = "mock-precompile"))]
        Err(PRODUCTION_ERR.to_string())
    }
}

/// Cross-VM call bridge from SVM to EVM.
pub struct CrossVmCallSyscall;
impl AceSyscall for CrossVmCallSyscall {
    fn name(&self) -> &str {
        "cross_vm_call"
    }
    fn execute(&self, _input: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(feature = "mock-precompile")]
        {
            tracing::warn!("mock syscall cross_vm_call — NOT production safe");
            Ok(vec![0xFF, 0x00])
        }
        #[cfg(not(feature = "mock-precompile"))]
        Err(PRODUCTION_ERR.to_string())
    }
}

/// Resolve an id_com to an EVM address from SVM context.
pub struct ResolveEvmAddress;
impl AceSyscall for ResolveEvmAddress {
    fn name(&self) -> &str {
        "resolve_evm_address"
    }
    fn execute(&self, _input: &[u8]) -> Result<Vec<u8>, String> {
        #[cfg(feature = "mock-precompile")]
        {
            tracing::warn!("mock syscall resolve_evm_address — NOT production safe");
            Ok(vec![0xFF, 0x00])
        }
        #[cfg(not(feature = "mock-precompile"))]
        Err(PRODUCTION_ERR.to_string())
    }
}

/// All 4 ACE-GF SVM syscalls.
pub fn all_syscalls() -> Vec<Box<dyn AceSyscall>> {
    vec![
        Box::new(AttestCheck),
        Box::new(IdComVerifySyscall),
        Box::new(CrossVmCallSyscall),
        Box::new(ResolveEvmAddress),
    ]
}
