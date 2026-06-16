//! ZK proof system abstraction and implementations.
//!
//! The runtime supports:
//! - `MockProver` (test-only) for deterministic fast proofs
//! - `StarkProver` (feature `stark`) backed by `zk-ace` Stwo Circle STARK
//! - `AlwaysInvalidProver` as a strict production-safe fallback

use sha2::{Digest, Sha256};
#[cfg(feature = "test-utils")]
use std::time::Duration;

#[cfg(feature = "stark")]
use zk_ace::native::commitment::compute_public_inputs as zk_compute_public_inputs;
#[cfg(feature = "stark")]
use zk_ace::prover as zk_prover;
#[cfg(feature = "stark")]
use zk_ace::serde_utils as zk_serde;
#[cfg(feature = "stark")]
use zk_ace::stwo::types::{
    bytes_to_elements, elements_to_bytes, try_u64_to_element, u64_to_domain_elements,
    DerivationContext as ZkDerivationContext, ReplayMode as ZkReplayMode, ZkAcePublicInputs,
    ZkAceWitness,
};
#[cfg(feature = "stark")]
use zk_ace::verifier as zk_verifier;
#[cfg(feature = "stark")]
use zk_ace::ZkAceEngine as _;

#[cfg(feature = "stark")]
use crate::config::MAX_PROOF_BUNDLE_ENTRIES;
#[cfg(any(feature = "stark", feature = "test-utils"))]
use crate::config::MOCK_PROOF_BYTES;
use crate::types::block::Block;
#[cfg(any(feature = "stark", feature = "test-utils"))]
use crate::types::finality::EMPTY_FC_PROOF_HEADER;
use crate::types::finality::{FinalityCertificate, FinalityProofMode, ZkProof};

/// Compute the deterministic binding hash for a finality certificate.
///
/// `SHA-256("FC_BIND_V2" || block_hash || slot_le || id_com_commitment || proof_mode || statement_root || tx_count_le)`
#[cfg(feature = "test-utils")]
pub(crate) fn compute_fc_binding_hash(fc: &FinalityCertificate) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"FC_BIND_V2");
    hasher.update(fc.block_hash);
    hasher.update(fc.slot.to_le_bytes());
    hasher.update(fc.id_com_commitment);
    hasher.update([match fc.proof_mode {
        FinalityProofMode::StarkV1 => 3,
    }]);
    hasher.update(fc.statement_root);
    hasher.update(fc.tx_count.to_le_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute a Merkle-style commitment to ordered identity commitments.
pub fn compute_idcom_commitment(values: &[[u8; 32]]) -> [u8; 32] {
    if values.is_empty() {
        return [0u8; 32];
    }

    let mut hashes: Vec<[u8; 32]> = values
        .iter()
        .map(|idcom| {
            let mut hasher = Sha256::new();
            hasher.update(idcom);
            let digest = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            out
        })
        .collect();

    while hashes.len() > 1 {
        let mut next = Vec::with_capacity(hashes.len().div_ceil(2));
        for pair in hashes.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            if pair.len() == 2 {
                hasher.update(pair[1]);
            } else {
                hasher.update(pair[0]);
            }
            let digest = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            next.push(out);
        }
        hashes = next;
    }

    hashes[0]
}

/// Compute the ordered authorization-statement root for a block.
///
/// The leaf commits only to block-visible authorization data so validators can
/// recompute it without private witnesses:
/// `SHA-256("ACE-AUTH-STMT-V1" || obj_hash || idcom || domain || index_le || raw_kind_tag)`.
pub fn compute_statement_root(block: &Block) -> [u8; 32] {
    if block.transactions.is_empty() {
        return [0u8; 32];
    }

    let mut hashes: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .enumerate()
        .map(|(index, tx)| {
            let mut hasher = Sha256::new();
            hasher.update(b"ACE-AUTH-STMT-V1");
            hasher.update(tx.attestation.obj_hash);
            hasher.update(tx.attestation.idcom);
            hasher.update(tx.attestation.domain.to_bytes());
            hasher.update((index as u32).to_le_bytes());
            hasher.update([tx.raw_chain.as_ref().map(|raw| raw.kind.tag()).unwrap_or(0)]);
            let digest = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            out
        })
        .collect();

    while hashes.len() > 1 {
        let mut next = Vec::with_capacity(hashes.len().div_ceil(2));
        for pair in hashes.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            if pair.len() == 2 {
                hasher.update(pair[1]);
            } else {
                hasher.update(pair[0]);
            }
            let digest = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            next.push(out);
        }
        hashes = next;
    }

    hashes[0]
}

/// Compute the commitment to the list of identity commitments present in a block.
pub fn compute_block_idcom_commitment(block: &Block) -> [u8; 32] {
    let idcoms: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(|tx| tx.attestation.idcom)
        .collect();
    compute_idcom_commitment(&idcoms)
}

/// Compute the idcom commitment covering only ZK-provable transactions.
///
/// Raw-chain transactions (EVM/Solana/BTC) are excluded because they use
/// chain-native signature verification instead of ZK proofs.  The statement
/// root still commits to all transactions including raw-chain ones.
pub fn compute_provable_idcom_commitment(block: &Block) -> [u8; 32] {
    let idcoms: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .filter(|tx| !tx.is_raw_chain())
        .map(|tx| tx.attestation.idcom)
        .collect();
    compute_idcom_commitment(&idcoms)
}

/// Replay prevention mode (feature-independent mirror of `zk_ace::types::ReplayMode`).
///
/// Available regardless of `stark` feature so that `derive_public_inputs` can
/// compute replay-mode-dependent fields without requiring `zk-ace` at the API
/// boundary.
#[cfg(any(feature = "stark", feature = "test-utils"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofReplayMode {
    NonceRegistry,
    NullifierSet,
}

/// Public inputs for a single ZK-ACE proof.
#[derive(Debug, Clone)]
pub struct PublicInputs {
    /// Identity commitment.
    pub idcom: [u8; 32],
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Domain binding (chain_id || slot, little-endian).
    pub domain: [u8; 8],
    /// Target binding.
    pub target: [u8; 32],
    /// Replay commitment.
    pub rp_com: [u8; 32],
}

#[cfg(any(feature = "stark", feature = "test-utils"))]
/// Private witness for a single ZK-ACE proof.
#[derive(Debug, Clone)]
pub struct PrivateWitness {
    /// Opaque 32-byte root secret supplied by the caller's wallet layer.
    pub root_secret: [u8; 32],
    /// Salt used in identity commitment.
    pub salt: [u8; 32],
    /// Algorithm identifier in derivation context.
    pub alg_id: u64,
    /// Derivation index in derivation context.
    pub index: u64,
    /// Replay-prevention nonce.
    pub nonce: u64,
}

#[cfg(any(feature = "stark", feature = "test-utils"))]
/// Sentinel alg_id for legacy (raw chain) txs: no secret witness binding; proof only binds (idcom, tx_hash, domain).
pub const LEGACY_WITNESS_ALG_ID: u64 = u64::MAX;

#[cfg(any(feature = "stark", feature = "test-utils"))]
impl PrivateWitness {
    /// Helper for tests/benchmarks: set context to (alg_id=0, index=0, nonce=0).
    pub fn with_defaults(root_secret: [u8; 32], salt: [u8; 32]) -> Self {
        Self {
            root_secret,
            salt,
            alg_id: 0,
            index: 0,
            nonce: 0,
        }
    }

    /// Dummy witness for raw-chain txs (EVM/Solana/BTC). No REV/salt; prover binds (idcom, tx_hash, domain) only.
    /// Use this when building witnesses for prove_block for txs that have raw_chain set.
    pub fn legacy_dummy() -> Self {
        Self {
            root_secret: [0u8; 32],
            salt: [0u8; 32],
            alg_id: LEGACY_WITNESS_ALG_ID,
            index: 0,
            nonce: 0,
        }
    }

    /// True if this witness is the legacy dummy (raw chain tx).
    pub fn is_legacy_dummy(&self) -> bool {
        self.alg_id == LEGACY_WITNESS_ALG_ID
    }
}

/// Derive runtime public inputs from witness + tx fields.
///
/// With feature `stark`, this computes real `target` and `rp_com` via zk-ace
/// using the specified replay mode.  Without it, placeholders are used for
/// compatibility with mock-only builds.
#[cfg(any(feature = "stark", feature = "test-utils"))]
pub fn derive_public_inputs(
    tx_hash: [u8; 32],
    idcom: [u8; 32],
    domain: [u8; 8],
    _witness: &PrivateWitness,
    _replay_mode: ProofReplayMode,
) -> PublicInputs {
    #[cfg(feature = "stark")]
    {
        let zk_mode = match _replay_mode {
            ProofReplayMode::NonceRegistry => ZkReplayMode::NonceRegistry,
            ProofReplayMode::NullifierSet => ZkReplayMode::NullifierSet,
        };
        if let Some((_, pi)) = build_zk_witness_and_inputs(
            &PublicInputs {
                idcom,
                tx_hash,
                domain,
                target: [0u8; 32],
                rp_com: [0u8; 32],
            },
            _witness,
            zk_mode,
        ) {
            return PublicInputs {
                idcom: elements_to_bytes(&pi.id_com),
                tx_hash,
                domain,
                target: elements_to_bytes(&pi.target),
                rp_com: elements_to_bytes(&pi.rp_com),
            };
        }
    }

    PublicInputs {
        idcom,
        tx_hash,
        domain,
        target: [0u8; 32],
        rp_com: [0u8; 32],
    }
}

/// Verification interface used by consensus and runtime finality tracking.
pub trait ProofVerifier: Send + Sync {
    /// Verify a proof against public inputs.
    fn verify(&self, proof: &ZkProof, public: &PublicInputs) -> bool;

    /// Verify a finality certificate.
    fn verify_finality_certificate(&self, fc: &FinalityCertificate) -> bool;

    /// Verify a finality certificate against a concrete block context.
    ///
    /// This is the preferred path for node/sync code because it binds the FC to
    /// the actual block contents instead of trusting only self-contained proof
    /// payloads.
    ///
    /// # Security note
    ///
    /// Block-context checks (slot, block_hash, id_com_commitment, statement_root,
    /// tx_count) bind the FC to the concrete block, but they do NOT substitute
    /// for cryptographic proof verification.  A malicious builder could craft a
    /// valid-looking FC with garbage proofs that passes all context checks.
    /// Therefore, this method always delegates to `verify_finality_certificate`
    /// for full STARK proof re-verification after context checks pass.
    ///
    /// O(1) verification will be enabled once recursive STARK aggregation
    /// produces a single proof that is cryptographically self-sufficient.
    fn verify_finality_certificate_for_block(
        &self,
        fc: &FinalityCertificate,
        block: &Block,
    ) -> bool {
        if fc.slot != block.header.slot || fc.block_hash != block.hash() {
            return false;
        }

        // ZK proof bundle covers only provable (non-raw-chain) txs.
        // Raw-chain txs are covered by the statement_root instead.
        if fc.id_com_commitment != compute_provable_idcom_commitment(block) {
            return false;
        }

        // tx_count and statement_root are mandatory: they bind the FC to the
        // full set of block transactions (including raw-chain txs that are not
        // covered by the ZK proof bundle).
        let expected_tx_count = block.transactions.len() as u32;
        if fc.tx_count != expected_tx_count {
            return false;
        }

        match fc.proof_mode {
            FinalityProofMode::StarkV1 => {
                if fc.statement_root != compute_statement_root(block) {
                    return false;
                }
                #[cfg(feature = "stark")]
                if !verify_stark_public_inputs_bind_to_block(fc, block) {
                    return false;
                }
            }
        }

        self.verify_finality_certificate(fc)
    }
}

#[cfg(feature = "stark")]
fn verify_stark_public_inputs_bind_to_block(fc: &FinalityCertificate, block: &Block) -> bool {
    let provable_txs: Vec<_> = block
        .transactions
        .iter()
        .filter(|tx| !tx.is_raw_chain())
        .collect();

    if zk_ace::batch::is_batch_proof(&fc.proof.data) {
        let Some((_raw, pis, _modes, _n)) = zk_ace::batch::decode_batch_proof(&fc.proof.data)
        else {
            return false;
        };
        if pis.len() != provable_txs.len() {
            return false;
        }
        for (pi, tx) in pis.iter().zip(provable_txs.iter()) {
            if zk_ace::stwo::types::bytes32_from_elements(&pi.tx_hash) != tx.attestation.obj_hash {
                return false;
            }
            if zk_ace::stwo::types::domain_elements_to_u64(&pi.domain)
                != u64::from_le_bytes(tx.attestation.domain.to_bytes())
            {
                return false;
            }
        }
        return true;
    }

    let Some(entries) = decode_proof_bundle(&fc.proof.data) else {
        // Can be empty bundle
        return provable_txs.is_empty();
    };
    if entries.is_empty() && !provable_txs.is_empty() {
        if fc.proof.data.as_slice() != EMPTY_FC_PROOF_HEADER {
            return false;
        }
        #[cfg(feature = "devnet")]
        return true;
        #[cfg(not(feature = "devnet"))]
        return false;
    }
    if entries.len() != provable_txs.len() {
        return false;
    }
    for (entry, tx) in entries.iter().zip(provable_txs.iter()) {
        if zk_ace::stwo::types::bytes32_from_elements(&entry.public_inputs.tx_hash)
            != tx.attestation.obj_hash
            || zk_ace::stwo::types::domain_elements_to_u64(&entry.public_inputs.domain)
                != u64::from_le_bytes(tx.attestation.domain.to_bytes())
        {
            return false;
        }
    }

    true
}

#[cfg(any(feature = "stark", feature = "test-utils"))]
/// Proof production interface kept out of validator/runtime default builds.
pub trait ProofProducer: Send + Sync {
    /// The replay prevention mode used by this prover.
    ///
    /// Defaults to `NonceRegistry` for provers that do not distinguish modes
    /// (e.g. MockProver).
    fn replay_mode(&self) -> ProofReplayMode {
        ProofReplayMode::NonceRegistry
    }

    /// Generate a proof for a single transaction.
    fn prove(&self, public: &PublicInputs, witness: &PrivateWitness) -> ZkProof;

    /// Aggregate two proofs into one.
    fn aggregate(&self, left: &ZkProof, right: &ZkProof) -> ZkProof;

    /// Produce a complete block-level finality certificate directly.
    ///
    /// Backends that can emit a single outer proof without first
    /// materializing legacy proof bundles use this. Default returns `Ok(None)`.
    fn prove_block_certificate(
        &self,
        _block: &Block,
        _witnesses: &[PrivateWitness],
    ) -> Result<Option<FinalityCertificate>, String> {
        Ok(None)
    }
}

// ===========================================================================
// Mock prover (test-utils)
// ===========================================================================

#[cfg(feature = "test-utils")]
#[derive(Debug, Clone, Default)]
pub struct MockProver {
    prove_delay: Duration,
    aggregate_delay: Duration,
    verify_delay: Duration,
}

#[cfg(feature = "test-utils")]
impl MockProver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a mock prover with fixed delays.
    pub fn with_fixed_delays(
        prove_delay: Duration,
        aggregate_delay: Duration,
        verify_delay: Duration,
    ) -> Self {
        Self {
            prove_delay,
            aggregate_delay,
            verify_delay,
        }
    }

    /// Create a mock prover from environment variables (milliseconds):
    /// - `ACE_MOCK_PROVE_DELAY_MS`
    /// - `ACE_MOCK_AGGREGATE_DELAY_MS`
    /// - `ACE_MOCK_VERIFY_DELAY_MS`
    pub fn from_env() -> Self {
        let prove_delay = Self::parse_delay_ms("ACE_MOCK_PROVE_DELAY_MS").unwrap_or_default();
        let aggregate_delay =
            Self::parse_delay_ms("ACE_MOCK_AGGREGATE_DELAY_MS").unwrap_or_default();
        let verify_delay = Self::parse_delay_ms("ACE_MOCK_VERIFY_DELAY_MS").unwrap_or_default();

        Self::with_fixed_delays(prove_delay, aggregate_delay, verify_delay)
    }

    fn compute_proof_hash(public: &PublicInputs) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"MOCK_PROOF_V1");
        hasher.update(public.idcom);
        hasher.update(public.tx_hash);
        hasher.update(public.domain);
        hasher.update(public.target);
        hasher.update(public.rp_com);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn parse_delay_ms(var: &str) -> Option<Duration> {
        match std::env::var(var) {
            Err(_) => None, // env var not set — expected, not an error
            Ok(raw) => match raw.trim().parse::<u64>() {
                Ok(ms) => Some(Duration::from_millis(ms)),
                Err(e) => {
                    eprintln!(
                        "warning: {var}={:?} is not a valid u64: {e}, ignoring",
                        raw.trim()
                    );
                    None
                }
            },
        }
    }

    #[inline]
    fn maybe_sleep(delay: Duration) {
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
    }

    /// Create a well-formed mock finality certificate with a valid proof.
    pub fn create_mock_fc(
        block_hash: [u8; 32],
        slot: u64,
        id_com_commitment: [u8; 32],
    ) -> FinalityCertificate {
        let mut fc = FinalityCertificate {
            block_hash,
            slot,
            proof: ZkProof::from_bytes(vec![0u8; MOCK_PROOF_BYTES]),
            id_com_commitment,
            proof_mode: FinalityProofMode::StarkV1,
            statement_root: [0u8; 32],
            tx_count: 0,
        };
        let hash = compute_fc_binding_hash(&fc);
        fc.proof.data[..32].copy_from_slice(&hash);
        fc
    }

    /// Create a mock finality certificate whose public metadata matches a block.
    pub fn create_mock_fc_with_block(block: &Block) -> FinalityCertificate {
        let mut fc = Self::create_mock_fc(
            block.hash(),
            block.header.slot,
            compute_provable_idcom_commitment(block),
        );
        fc.statement_root = compute_statement_root(block);
        fc.tx_count = block.transactions.len() as u32;
        let binding = compute_fc_binding_hash(&fc);
        fc.proof.data[..32].copy_from_slice(&binding);
        fc
    }
}

/// Create a finality certificate using the real STARK proof bundle format.
///
/// For blocks without ZK-provable transactions this produces a canonical
/// 0-entry bundle (`EMPTY_FC_PROOF_HEADER`) which the `StarkVerifierOnly`
/// will accept. In devnet builds, block-context verification also accepts this
/// bundle for native transactions and relies on `statement_root` plus
/// `id_com_commitment` to bind the certificate to the concrete block. Outside
/// devnet, blocks with ZK-provable txs require a real STARK proof produced by
/// the prover companion.
#[cfg(feature = "stark")]
pub fn create_stark_fc_for_block(block: &Block) -> FinalityCertificate {
    let id_com_commitment = compute_provable_idcom_commitment(block);
    FinalityCertificate {
        block_hash: block.hash(),
        slot: block.header.slot,
        proof: ZkProof::from_bytes(EMPTY_FC_PROOF_HEADER.to_vec()),
        id_com_commitment,
        proof_mode: FinalityProofMode::StarkV1,
        statement_root: compute_statement_root(block),
        tx_count: block.transactions.len() as u32,
    }
}

#[cfg(feature = "test-utils")]
impl ProofVerifier for MockProver {
    fn verify(&self, proof: &ZkProof, public: &PublicInputs) -> bool {
        use subtle::ConstantTimeEq;
        Self::maybe_sleep(self.verify_delay);
        if !proof.is_well_formed() {
            return false;
        }
        let expected_hash = Self::compute_proof_hash(public);
        proof.data[..32].ct_eq(&expected_hash).into()
    }

    fn verify_finality_certificate(&self, fc: &FinalityCertificate) -> bool {
        use subtle::ConstantTimeEq;
        if !fc.is_well_formed() {
            return false;
        }
        // Canonical 0-entry bundles are used when a block has no ZK-provable
        // transactions, so they cannot carry a binding hash.
        if fc.proof.data.len() < 32 {
            return fc.id_com_commitment == [0u8; 32]
                && fc.proof.data.as_slice() == EMPTY_FC_PROOF_HEADER;
        }
        let expected = compute_fc_binding_hash(fc);
        fc.proof.data[..32].ct_eq(&expected).into()
    }
}

#[cfg(feature = "test-utils")]
impl ProofProducer for MockProver {
    fn prove(&self, public: &PublicInputs, _witness: &PrivateWitness) -> ZkProof {
        Self::maybe_sleep(self.prove_delay);
        let hash = Self::compute_proof_hash(public);
        let mut data = Vec::with_capacity(MOCK_PROOF_BYTES);
        for _ in 0..8 {
            data.extend_from_slice(&hash);
        }
        ZkProof::from_bytes(data)
    }

    fn aggregate(&self, left: &ZkProof, right: &ZkProof) -> ZkProof {
        Self::maybe_sleep(self.aggregate_delay);
        let mut hasher = Sha256::new();
        hasher.update(b"MOCK_AGGREGATE_V1");
        hasher.update(&left.data);
        hasher.update(&right.data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        let mut data = Vec::with_capacity(MOCK_PROOF_BYTES);
        for _ in 0..8 {
            data.extend_from_slice(&hash);
        }
        ZkProof::from_bytes(data)
    }

    fn prove_block_certificate(
        &self,
        block: &Block,
        _witnesses: &[PrivateWitness],
    ) -> Result<Option<FinalityCertificate>, String> {
        Ok(Some(Self::create_mock_fc_with_block(block)))
    }
}

// ===========================================================================
// STARK proof bundle format (ACPS)
// ===========================================================================
//
// Magic: ACPS (4 bytes)
// Version: 3 (1 byte) -- v3 uses lossless M31 encoding (9 elements for bytes32, 3 for domain)
// Entry count: u32 LE (4 bytes)
// Per entry:
//   proof_len: u32 LE (4 bytes)
//   proof_bytes: [u8; proof_len]
//   public_inputs: 36 * 4 = 144 bytes (36 M31 elements, LE u32)

#[cfg(feature = "stark")]
const PROOF_BUNDLE_MAGIC: [u8; 4] = *b"ACPS";
#[cfg(feature = "stark")]
const PROOF_BUNDLE_VERSION: u8 = 3;
#[cfg(feature = "stark")]
const PUBLIC_INPUTS_ENCODED_BYTES: usize = ZkAcePublicInputs::NUM_ELEMENTS * 4; // 36 * 4 = 144

#[cfg(feature = "stark")]
#[derive(Clone)]
struct StarkBundleEntry {
    proof_bytes: Vec<u8>,
    public_inputs: ZkAcePublicInputs,
}

#[cfg(feature = "stark")]
#[derive(Clone)]
pub struct StarkProver {
    replay_mode: ZkReplayMode,
}

#[cfg(feature = "stark")]
impl StarkProver {
    /// Create a STARK prover. No trusted setup needed.
    pub fn new(replay_mode: ZkReplayMode) -> Self {
        Self { replay_mode }
    }

    /// Create a STARK prover using NonceRegistry replay mode.
    pub fn new_nonce_registry() -> Self {
        Self::new(ZkReplayMode::NonceRegistry)
    }

    /// Create a STARK prover using NullifierSet replay mode.
    pub fn new_nullifier_set() -> Self {
        Self::new(ZkReplayMode::NullifierSet)
    }

    pub fn replay_mode(&self) -> ZkReplayMode {
        self.replay_mode
    }

    fn invalid_proof() -> ZkProof {
        ZkProof::from_bytes(vec![0u8; MOCK_PROOF_BYTES])
    }
}

#[cfg(feature = "stark")]
impl ProofVerifier for StarkProver {
    fn verify(&self, proof: &ZkProof, public: &PublicInputs) -> bool {
        verify_single_bundle_entry(proof, public)
    }

    fn verify_finality_certificate(&self, fc: &FinalityCertificate) -> bool {
        verify_finality_certificate_stark(fc)
    }
}

#[cfg(feature = "stark")]
impl ProofProducer for StarkProver {
    fn replay_mode(&self) -> ProofReplayMode {
        match self.replay_mode {
            ZkReplayMode::NonceRegistry => ProofReplayMode::NonceRegistry,
            ZkReplayMode::NullifierSet => ProofReplayMode::NullifierSet,
        }
    }

    fn prove(&self, public: &PublicInputs, witness: &PrivateWitness) -> ZkProof {
        let Some((zk_witness, zk_public)) =
            build_zk_witness_and_inputs(public, witness, self.replay_mode)
        else {
            return Self::invalid_proof();
        };

        if !runtime_public_matches(public, &zk_public) {
            return Self::invalid_proof();
        }

        let proof_bytes = match zk_prover::prove(&zk_witness, &zk_public, self.replay_mode) {
            Ok(p) => p,
            Err(_) => return Self::invalid_proof(),
        };

        let entry = StarkBundleEntry {
            proof_bytes,
            public_inputs: zk_public,
        };

        ZkProof::from_bytes(encode_proof_bundle(&[entry]))
    }

    fn aggregate(&self, left: &ZkProof, right: &ZkProof) -> ZkProof {
        let Some(mut left_entries) = decode_proof_bundle(&left.data) else {
            return Self::invalid_proof();
        };
        let Some(right_entries) = decode_proof_bundle(&right.data) else {
            return Self::invalid_proof();
        };

        left_entries.extend(right_entries);
        ZkProof::from_bytes(encode_proof_bundle(&left_entries))
    }

    /// Produce a single batch STARK proof for the entire block — O(1) verification.
    ///
    /// This replaces the per-tx prove + tree-aggregate pipeline with a single
    /// tiled batch proof.  The `prove_block` pipeline calls this first; if it
    /// returns `Some(fc)`, the per-tx path is skipped entirely.
    fn prove_block_certificate(
        &self,
        block: &Block,
        witnesses: &[PrivateWitness],
    ) -> Result<Option<FinalityCertificate>, String> {
        // Collect provable (non-raw-chain) tx+witness pairs.
        // Both tx-level and witness-level checks for consistency with verifier.
        let provable: Vec<(&crate::types::transaction::Transaction, &PrivateWitness)> = block
            .transactions
            .iter()
            .zip(witnesses.iter())
            .filter(|(tx, w)| !tx.is_raw_chain() && !w.is_legacy_dummy())
            .collect();

        if provable.is_empty() {
            return Ok(None); // fall back to empty bundle path
        }

        // Build batch entries
        let entries: Result<
            Vec<(zk_ace::Witness, zk_ace::PublicInputs, zk_ace::ReplayMode)>,
            String,
        > = provable
            .iter()
            .map(|(tx, witness)| {
                let public = derive_public_inputs(
                    tx.attestation.obj_hash,
                    tx.attestation.idcom,
                    tx.attestation.domain.to_bytes(),
                    witness,
                    ProofProducer::replay_mode(self),
                );

                let zk_witness = zk_ace::Witness {
                    rev: witness.root_secret,
                    salt: witness.salt,
                    alg_id: witness.alg_id,
                    domain: u64::from_le_bytes(public.domain),
                    index: witness.index,
                    nonce: witness.nonce,
                };
                let zk_pi = zk_ace::PublicInputs {
                    id_com: public.idcom,
                    tx_hash: public.tx_hash,
                    domain: u64::from_le_bytes(public.domain),
                    target: public.target,
                    rp_com: public.rp_com,
                };
                let zk_mode = match self.replay_mode {
                    ZkReplayMode::NonceRegistry => zk_ace::ReplayMode::NonceRegistry,
                    ZkReplayMode::NullifierSet => zk_ace::ReplayMode::NullifierSet,
                };

                Ok((zk_witness, zk_pi, zk_mode))
            })
            .collect();
        let entries = entries?;

        // Call batch prove
        let (proof_bytes, _pi_commitment) = zk_ace::StwoEngine::prove_batch(&entries)
            .map_err(|e| format!("batch prove failed: {e}"))?;

        let id_com_commitment = compute_provable_idcom_commitment(block);
        let statement_root = compute_statement_root(block);

        Ok(Some(FinalityCertificate {
            block_hash: block.hash(),
            slot: block.header.slot,
            proof: ZkProof::from_bytes(proof_bytes),
            id_com_commitment,
            proof_mode: FinalityProofMode::StarkV1,
            statement_root,
            tx_count: block.transactions.len() as u32,
        }))
    }
}

#[cfg(feature = "stark")]
#[derive(Clone)]
pub struct StarkVerifierOnly;

#[cfg(feature = "stark")]
impl Default for StarkVerifierOnly {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "stark")]
impl StarkVerifierOnly {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "stark")]
impl ProofVerifier for StarkVerifierOnly {
    fn verify(&self, proof: &ZkProof, public: &PublicInputs) -> bool {
        verify_single_bundle_entry(proof, public)
    }

    fn verify_finality_certificate(&self, fc: &FinalityCertificate) -> bool {
        verify_finality_certificate_stark(fc)
    }
}

// ===========================================================================
// STARK prover helpers
// ===========================================================================

#[cfg(feature = "stark")]
fn build_zk_witness_and_inputs(
    public: &PublicInputs,
    witness: &PrivateWitness,
    replay_mode: ZkReplayMode,
) -> Option<(ZkAceWitness, ZkAcePublicInputs)> {
    // Legacy dummy witnesses (raw-chain txs) have no real secret;
    // they cannot produce a valid ZK proof.
    if witness.is_legacy_dummy() {
        return None;
    }

    let rev = bytes_to_elements(&witness.root_secret); // now [M31; 9]
    let salt = bytes_to_elements(&witness.salt); // now [M31; 9]

    let nonce_elems = u64_to_domain_elements(witness.nonce);

    let domain_val = u64::from_le_bytes(public.domain);
    let chain_domain = u64_to_domain_elements(domain_val); // [M31; 3], lossless

    // Derivation context scalars must fit in a single M31 element (< 2^31 - 1).
    // Return None for out-of-range values rather than panicking.
    let deriv_domain = try_u64_to_element((domain_val as u32) as u64)?;
    let alg_id = try_u64_to_element(witness.alg_id)?;
    let index = try_u64_to_element(witness.index)?;

    let ctx = ZkDerivationContext {
        alg_id,
        domain: deriv_domain,
        index,
    };

    let zk_witness = ZkAceWitness {
        rev,
        salt,
        ctx,
        nonce: nonce_elems,
    };

    let tx_hash_elems = bytes_to_elements(&public.tx_hash); // [M31; 9]

    let zk_public =
        zk_compute_public_inputs(&zk_witness, &tx_hash_elems, &chain_domain, replay_mode);

    Some((zk_witness, zk_public))
}

#[cfg(feature = "stark")]
fn runtime_binding_matches(runtime: &PublicInputs, zk: &ZkAcePublicInputs) -> bool {
    // Check only the caller-provided binding fields: idcom, tx_hash, domain.
    // target and rp_com are derived by the prover and may not be in the caller's PublicInputs.
    let zk_idcom_bytes = elements_to_bytes(&zk.id_com);
    let runtime_tx_hash = bytes_to_elements(&runtime.tx_hash);
    let runtime_domain = u64_to_domain_elements(u64::from_le_bytes(runtime.domain));

    zk_idcom_bytes == runtime.idcom && runtime_tx_hash == zk.tx_hash && runtime_domain == zk.domain
}

#[cfg(feature = "stark")]
fn runtime_public_matches(runtime: &PublicInputs, zk: &ZkAcePublicInputs) -> bool {
    // Full check: all fields must match (used during verification).
    let zk_target_bytes = elements_to_bytes(&zk.target);
    let zk_rpcom_bytes = elements_to_bytes(&zk.rp_com);

    runtime_binding_matches(runtime, zk)
        && zk_target_bytes == runtime.target
        && zk_rpcom_bytes == runtime.rp_com
}

#[cfg(feature = "stark")]
fn encode_public_inputs(pi: &ZkAcePublicInputs) -> [u8; PUBLIC_INPUTS_ENCODED_BYTES] {
    let bytes = zk_serde::serialize_public_inputs(pi);
    let mut out = [0u8; PUBLIC_INPUTS_ENCODED_BYTES];
    out.copy_from_slice(&bytes);
    out
}

#[cfg(feature = "stark")]
fn decode_public_inputs_bytes(bytes: &[u8]) -> Option<ZkAcePublicInputs> {
    match zk_serde::deserialize_public_inputs(bytes) {
        Ok(pi) => Some(pi),
        Err(e) => {
            eprintln!("warning: failed to decode STARK public inputs: {e}");
            None
        }
    }
}

#[cfg(feature = "stark")]
fn encode_proof_bundle(entries: &[StarkBundleEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PROOF_BUNDLE_MAGIC);
    out.push(PROOF_BUNDLE_VERSION);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());

    for entry in entries {
        out.extend_from_slice(&(entry.proof_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&entry.proof_bytes);
        out.extend_from_slice(&encode_public_inputs(&entry.public_inputs));
    }

    out
}

#[cfg(feature = "stark")]
fn decode_proof_bundle(bytes: &[u8]) -> Option<Vec<StarkBundleEntry>> {
    if bytes.len() < 9 {
        return None;
    }

    if bytes[0..4] != PROOF_BUNDLE_MAGIC {
        return None;
    }

    if bytes[4] != PROOF_BUNDLE_VERSION {
        return None;
    }

    let count = u32::from_le_bytes(bytes[5..9].try_into().ok()?) as usize;
    if count > MAX_PROOF_BUNDLE_ENTRIES {
        return None;
    }
    let mut offset = 9usize;
    let mut entries = Vec::with_capacity(count);

    if count == 0 {
        if offset != bytes.len() {
            return None; // reject trailing bytes on empty bundle
        }
        return Some(entries);
    }

    for _ in 0..count {
        if offset + 4 > bytes.len() {
            return None;
        }
        let proof_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if offset + proof_len + PUBLIC_INPUTS_ENCODED_BYTES > bytes.len() {
            return None;
        }

        let proof_bytes = bytes[offset..offset + proof_len].to_vec();
        offset += proof_len;

        let public_inputs =
            decode_public_inputs_bytes(&bytes[offset..offset + PUBLIC_INPUTS_ENCODED_BYTES])?;
        offset += PUBLIC_INPUTS_ENCODED_BYTES;

        entries.push(StarkBundleEntry {
            proof_bytes,
            public_inputs,
        });
    }

    if offset != bytes.len() {
        return None;
    }

    Some(entries)
}

#[cfg(feature = "stark")]
fn verify_single_bundle_entry(proof: &ZkProof, public: &PublicInputs) -> bool {
    let Some(entries) = decode_proof_bundle(&proof.data) else {
        return false;
    };

    if entries.len() != 1 {
        return false;
    }

    let entry = &entries[0];
    if !runtime_public_matches(public, &entry.public_inputs) {
        return false;
    }

    verify_bundle_entry(entry)
}

#[cfg(feature = "stark")]
fn verify_finality_certificate_stark(fc: &FinalityCertificate) -> bool {
    if !fc.is_well_formed() {
        return false;
    }

    if fc.proof_mode != FinalityProofMode::StarkV1 {
        return false;
    }

    // ── Batch proof path (ACBP format) — O(1) verification ──
    if zk_ace::batch::is_batch_proof(&fc.proof.data) {
        let Some((raw_proof, pis, modes, num_txs)) =
            zk_ace::batch::decode_batch_proof(&fc.proof.data)
        else {
            return false;
        };
        match zk_ace::batch::verify_batch(&raw_proof, &pis, &modes, num_txs, None) {
            Ok(true) => {
                // Verify idcom commitment matches
                let idcoms: Vec<[u8; 32]> =
                    pis.iter().map(|pi| elements_to_bytes(&pi.id_com)).collect();
                if compute_idcom_commitment(&idcoms) != fc.id_com_commitment {
                    return false;
                }
                // Verify the batch proves exactly the right number of
                // transactions.  Allowing fewer would let an attacker skip
                // verification for some txs; allowing more is nonsensical.
                if fc.tx_count != 0 && (num_txs as u32) != fc.tx_count {
                    return false;
                }
                return true;
            }
            _ => return false,
        }
    }

    // ── Legacy ACPS bundle path (per-tx proofs) ──
    let Some(entries) = decode_proof_bundle(&fc.proof.data) else {
        return false;
    };

    // Canonical 0-entry bundles are used when a block has no ZK-provable
    // transactions. Block-context verification is responsible for checking
    // tx_count and statement_root against the concrete block.
    if entries.is_empty() {
        if fc.proof.data.as_slice() != EMPTY_FC_PROOF_HEADER {
            return false;
        }
        // In devnet builds, allow non-zero id_com_commitment with an empty
        // proof bundle so that dev-stark can auto-finalize blocks containing
        // native txs without a prover companion.  The block-context check in
        // verify_finality_certificate_for_block still binds the commitment to
        // the actual block contents.
        #[cfg(feature = "devnet")]
        return true;
        #[cfg(not(feature = "devnet"))]
        return fc.id_com_commitment == [0u8; 32];
    }

    use rayon::prelude::*;
    let all_valid = entries.par_iter().all(verify_bundle_entry);
    if !all_valid {
        return false;
    }

    let idcoms: Vec<[u8; 32]> = entries
        .iter()
        .map(|entry| elements_to_bytes(&entry.public_inputs.id_com))
        .collect();

    compute_idcom_commitment(&idcoms) == fc.id_com_commitment
}

#[cfg(feature = "stark")]
fn verify_bundle_entry(entry: &StarkBundleEntry) -> bool {
    // Try both replay modes; the correct one will verify.
    if let Ok(true) = zk_verifier::verify(
        &entry.proof_bytes,
        &entry.public_inputs,
        ZkReplayMode::NonceRegistry,
    ) {
        return true;
    }
    zk_verifier::verify(
        &entry.proof_bytes,
        &entry.public_inputs,
        ZkReplayMode::NullifierSet,
    )
    .unwrap_or_default()
}

/// A strict verifier/prover stub that rejects all proofs.
#[derive(Debug, Clone, Default)]
pub struct AlwaysInvalidProver;

impl ProofVerifier for AlwaysInvalidProver {
    fn verify(&self, _proof: &ZkProof, _public: &PublicInputs) -> bool {
        false
    }

    fn verify_finality_certificate(&self, _fc: &FinalityCertificate) -> bool {
        false
    }
}

#[cfg(any(feature = "stark", feature = "test-utils"))]
impl ProofProducer for AlwaysInvalidProver {
    fn prove(&self, _public: &PublicInputs, _witness: &PrivateWitness) -> ZkProof {
        ZkProof::from_bytes(vec![0u8; MOCK_PROOF_BYTES])
    }

    fn aggregate(&self, _left: &ZkProof, _right: &ZkProof) -> ZkProof {
        ZkProof::from_bytes(vec![0u8; MOCK_PROOF_BYTES])
    }
}
