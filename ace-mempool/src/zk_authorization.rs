//! ZK-ACE authorization admission boundary.
//!
//! The mempool keeps replay protection as an explicit policy instead of
//! scattering replay checks around the pool. ZK-ACE replay protection is backed
//! by the on-chain replay registry keyed by `rp_com`.

use ace_model::state_tree::StateTree;
use ace_runtime::crypto::verify_zk_auth;
use ace_runtime::types::transaction::{Transaction, ZkAuth};

use crate::error::MempoolError;

/// Replay policy for a verified ZK-ACE authorization.
pub trait ZkReplayGuard: Send + Sync {
    /// Validate replay material carried by `zk_auth`.
    fn check(&self, tx: &Transaction, zk_auth: &ZkAuth) -> Result<(), MempoolError>;
}

/// State-backed replay guard for ZK-ACE NonceRegistry mode.
pub struct StateReplayGuard<'a> {
    state: &'a StateTree,
}

impl<'a> StateReplayGuard<'a> {
    pub fn new(state: &'a StateTree) -> Self {
        Self { state }
    }
}

impl ZkReplayGuard for StateReplayGuard<'_> {
    fn check(&self, _tx: &Transaction, zk_auth: &ZkAuth) -> Result<(), MempoolError> {
        if self.state.zk_replay_contains(&zk_auth.rp_com) {
            return Err(MempoolError::ValidationError(
                "ZK-ACE replay commitment already consumed".into(),
            ));
        }
        Ok(())
    }
}

/// Verify proof material and replay policy for a ZK-ACE transaction.
pub fn verify_zk_authorization(
    tx: &Transaction,
    replay_guard: &dyn ZkReplayGuard,
) -> Result<(), MempoolError> {
    let Some(zk_auth) = &tx.zk_auth else {
        return Err(MempoolError::ValidationError(
            "tx.is_zk_auth() true but zk_auth field is None".into(),
        ));
    };
    verify_zk_auth(tx, zk_auth)
        .map_err(|e| MempoolError::ValidationError(format!("ZK-ACE: {e}")))?;
    replay_guard.check(tx, zk_auth)
}

#[cfg(test)]
mod tests {
    use super::{StateReplayGuard, ZkReplayGuard};
    use ace_model::state_tree::StateTree;
    use ace_runtime::types::transaction::ZkAuth;

    #[test]
    fn state_replay_guard_accepts_unused_commitment() {
        let state = StateTree::new();
        let guard = StateReplayGuard::new(&state);
        let zk = ZkAuth {
            proof: Vec::new(),
            target: [0u8; 32],
            rp_com: [7u8; 32],
            nonce: 0,
        };
        let tx = ace_runtime::types::transaction::Transaction::new(
            Vec::new(),
            ace_runtime::types::attestation::Attestation {
                obj_hash: [0u8; 32],
                idcom: [1u8; 32],
                domain: ace_runtime::types::attestation::Domain::new(1, 0),
                context_tag: [0u8; 16],
                credential: ace_runtime::crypto::TaggedSignature::ed25519([0u8; 64]),
            },
        );
        guard.check(&tx, &zk).unwrap();
    }

    #[test]
    fn state_replay_guard_rejects_consumed_commitment() {
        let mut state = StateTree::new();
        state.zk_replay_consume([7u8; 32], [1u8; 32]);
        let guard = StateReplayGuard::new(&state);
        let zk = ZkAuth {
            proof: Vec::new(),
            target: [0u8; 32],
            rp_com: [7u8; 32],
            nonce: 0,
        };
        let tx = ace_runtime::types::transaction::Transaction::new(
            Vec::new(),
            ace_runtime::types::attestation::Attestation {
                obj_hash: [0u8; 32],
                idcom: [1u8; 32],
                domain: ace_runtime::types::attestation::Domain::new(1, 0),
                context_tag: [0u8; 16],
                credential: ace_runtime::crypto::TaggedSignature::ed25519([0u8; 64]),
            },
        );
        assert!(guard.check(&tx, &zk).is_err());
    }
}
