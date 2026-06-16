//! Shared proof-mode parsing and material path resolution helpers.

use std::path::{Path, PathBuf};

pub const DEFAULT_PROVER_WITNESS_FILE: &str = "zkace_native_witnesses.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofMode {
    /// STARK production verifier — no keys needed (transparent setup).
    Production,
    /// Hash-based mock proofs for development/testing.
    DevMock,
    /// Real STARK verification on devnet — skips production genesis checks
    /// but uses the cryptographic STARK verifier and proper proof format.
    DevStark,
}

impl ProofMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "production" => Some(Self::Production),
            "dev-mock" => Some(Self::DevMock),
            "dev-stark" => Some(Self::DevStark),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::DevMock => "dev-mock",
            Self::DevStark => "dev-stark",
        }
    }

    pub fn requires_production_genesis(self) -> bool {
        matches!(self, Self::Production)
    }

    pub fn is_mock(self) -> bool {
        matches!(self, Self::DevMock)
    }
}

pub fn resolve_existing_material_path(
    explicit_env: &str,
    data_dir: Option<&str>,
    default_name: &str,
) -> Option<PathBuf> {
    material_target_path(explicit_env, data_dir, default_name).filter(|path| path.exists())
}

pub fn material_target_path(
    explicit_env: &str,
    data_dir: Option<&str>,
    default_name: &str,
) -> Option<PathBuf> {
    if let Ok(raw) = std::env::var(explicit_env) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }

    data_dir
        .map(PathBuf::from)
        .map(|dir| dir.join(default_name))
}

pub fn persist_material_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
