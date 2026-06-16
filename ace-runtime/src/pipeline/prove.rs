//! Phase 2: Proof generation with tree-structured aggregation
//! (Algorithm 1 ProveAsync + Algorithm 3 GPUProofPipeline).
//!
//! ## Pipeline
//! 1. Generate per-transaction ZK-ACE proofs in parallel
//! 2. Tree-structured proof bundle aggregation: while |Π| > 1, pairwise aggregate
//! 3. Produce a FinalityCertificate with the single aggregated proof
//!
//! ## Timing (from the paper)
//! - Per-tx proof: ~15 ms × 128 GPU threads → 1,536 txs in ~192 ms
//! - Tree aggregation: ~30–60 ms (log₂ N levels)
//! - Total: ~300 ms off the critical path

#[cfg(feature = "test-utils")]
use crate::crypto::proof::compute_fc_binding_hash;
use crate::crypto::proof::{
    compute_provable_idcom_commitment, compute_statement_root, derive_public_inputs,
    PrivateWitness, ProofProducer, ProofVerifier,
};
use crate::types::block::Block;
use crate::types::finality::{
    FinalityCertificate, FinalityProofMode, ZkProof, EMPTY_FC_PROOF_HEADER,
};

/// Generate a finality certificate for a block.
///
/// This represents the complete Phase 2 pipeline:
/// 1. Per-transaction proof generation
/// 2. Tree-structured proof bundle aggregation
/// 3. Finality certificate construction
///
/// # Arguments
/// - `block`: The published block to prove.
/// - `prover`: The proof system to use (mock or real STARK).
/// - `witnesses`: Private witnesses for each transaction.
///
/// # Returns
/// A [`FinalityCertificate`] containing the aggregated proof, or an error string
/// if witness count mismatches or the prover backend fails.
pub fn prove_block<P: ProofProducer + ProofVerifier>(
    block: &Block,
    prover: &P,
    witnesses: &[PrivateWitness],
) -> Result<FinalityCertificate, String> {
    if block.transactions.len() != witnesses.len() {
        return Err(format!(
            "witness count {} must match transaction count {}",
            witnesses.len(),
            block.transactions.len()
        ));
    }

    if let Some(fc) = prover
        .prove_block_certificate(block, witnesses)
        .map_err(|e| format!("block-level proof generation failed: {e}"))?
    {
        debug_assert!(
            prover.verify_finality_certificate_for_block(&fc, block),
            "prove_block: direct block-level FC failed verification"
        );
        return Ok(fc);
    }

    if block.transactions.is_empty() {
        // Empty block: use 0-entry proof bundle so verifier can accept (id_com_commitment == 0).
        // Format: ACPS + version + count=0 (9 bytes). No padding — decode_proof_bundle
        // rejects trailing bytes on count=0 bundles.
        let empty_proof = ZkProof::from_bytes(EMPTY_FC_PROOF_HEADER.to_vec());
        return Ok(create_finality_certificate(
            block,
            [0u8; 32],
            empty_proof,
            prover,
        ));
    }

    // Stage 1: Per-transaction proof generation.
    // Skip raw-chain txs AND legacy-dummy witnesses — they use chain-native sig
    // verification and cannot produce valid ZK proofs.
    // Both checks are applied to stay consistent with the verifier side
    // (`compute_provable_idcom_commitment` filters by `!tx.is_raw_chain()`).
    // Note: ZK public input "tx_hash" is obj_hash (SHA-256 of payload), not the full transaction hash.
    let provable: Vec<(&crate::types::transaction::Transaction, &PrivateWitness)> = block
        .transactions
        .iter()
        .zip(witnesses.iter())
        .filter(|(tx, w)| !tx.is_raw_chain() && !w.is_legacy_dummy())
        .collect();

    if provable.is_empty() {
        // All txs are raw-chain: use empty bundle (statement_root still covers them).
        let empty_proof = ZkProof::from_bytes(EMPTY_FC_PROOF_HEADER.to_vec());
        return Ok(create_finality_certificate(
            block,
            [0u8; 32],
            empty_proof,
            prover,
        ));
    }

    let mode = prover.replay_mode();
    let mut proofs: Vec<ZkProof> = provable
        .iter()
        .map(|(tx, witness)| {
            let public = derive_public_inputs(
                tx.attestation.obj_hash,
                tx.attestation.idcom,
                tx.attestation.domain.to_bytes(),
                witness,
                mode,
            );
            prover.prove(&public, witness)
        })
        .collect();

    // Stage 2: Tree-structured proof bundle aggregation.
    // while |Π| > 1: pairwise aggregate
    while proofs.len() > 1 {
        let mut next = Vec::with_capacity(proofs.len().div_ceil(2));
        let mut i = 0;
        while i < proofs.len() {
            if i + 1 < proofs.len() {
                let aggregated = prover.aggregate(&proofs[i], &proofs[i + 1]);
                next.push(aggregated);
            } else {
                // Odd proof: carry forward.
                next.push(proofs[i].clone());
            }
            i += 2;
        }
        proofs = next;
    }

    // Stage 3: Construct finality certificate.
    // id_com_commitment covers only ZK-provable txs; raw-chain txs are
    // covered by statement_root instead.
    let id_com_commitment = compute_provable_idcom_commitment(block);
    let aggregated_proof = proofs.into_iter().next().unwrap();

    Ok(create_finality_certificate(
        block,
        id_com_commitment,
        aggregated_proof,
        prover,
    ))
}

/// Create a finality certificate with a proof that will pass the prover's
/// `verify_finality_certificate`.
///
/// When the `test-utils` feature is active (MockProver), the `aggregated_proof`
/// is overwritten with a deterministic binding hash so that verify can recompute
/// and compare.  When `test-utils` is **off** (real prover), `aggregated_proof`
/// is used as-is — it already contains the cryptographic binding from STARK.
fn create_finality_certificate<P: ProofVerifier>(
    block: &Block,
    id_com_commitment: [u8; 32],
    aggregated_proof: ZkProof,
    prover: &P,
) -> FinalityCertificate {
    let statement_root = compute_statement_root(block);
    let tx_count = block.transactions.len() as u32;

    // Mock-only: overwrite proof[..32] with a deterministic binding hash
    // so that MockProver::verify_finality_certificate can recompute & compare.
    // When a real STARK prover is used (test-utils off), the aggregated_proof
    // already IS the cryptographic binding and must not be overwritten.
    #[cfg(feature = "test-utils")]
    let fc = {
        let mut fc = FinalityCertificate {
            block_hash: block.hash(),
            slot: block.header.slot,
            proof: aggregated_proof,
            id_com_commitment,
            proof_mode: FinalityProofMode::StarkV1,
            statement_root,
            tx_count,
        };
        // Only apply mock binding on fixed-size mock proofs.
        // STARK bundle proofs are variable-size and must remain untouched.
        if fc.proof.data.len() == ZkProof::SIZE {
            let binding = compute_fc_binding_hash(&fc);
            fc.proof.data[..32].copy_from_slice(&binding);
        }
        fc
    };
    #[cfg(not(feature = "test-utils"))]
    let fc = FinalityCertificate {
        block_hash: block.hash(),
        slot: block.header.slot,
        proof: aggregated_proof,
        id_com_commitment,
        proof_mode: FinalityProofMode::StarkV1,
        statement_root,
        tx_count,
    };

    debug_assert!(
        prover.verify_finality_certificate_for_block(&fc, block),
        "prove_block: generated FC failed verification — is the prover configured correctly?"
    );

    fc
}
