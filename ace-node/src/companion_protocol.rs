//! Shared stdin/stdout protocol for the local prover companion.

use ace_runtime::types::block::Block;
use ace_runtime::types::finality::FinalityCertificate;
use serde::{Deserialize, Serialize};

/// Serializable witness payload accepted by the local prover companion.
///
/// This mirrors `ace_runtime::crypto::proof::PrivateWitness` without requiring
/// the proving features to be enabled in every `ace-node` build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializablePrivateWitness {
    pub root_secret: [u8; 32],
    pub salt: [u8; 32],
    pub alg_id: u64,
    pub index: u64,
    pub nonce: u64,
}

/// Request sent from the node to the local prover companion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverCompanionRequest {
    pub chain_id: u32,
    pub genesis_hash: [u8; 32],
    pub block: Block,
    #[serde(default)]
    pub witnesses: Option<Vec<SerializablePrivateWitness>>,
}

/// Response written by the local prover companion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverCompanionResponse {
    pub certificate: FinalityCertificate,
}
