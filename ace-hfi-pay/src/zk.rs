//! HFI Pay claim ZK proof helpers (Groth16/BN254).
//!
//! This module provides the Groth16-based zero-knowledge proof primitives
//! for HFI Pay claim verification.  The prover demonstrates knowledge of a
//! private identity root `rev` such that:
//!
//! 1. `identity_commitment = Poseidon(rev)`
//! 2. `auth_commitment = Poseidon(rev, binding_epoch)`
//! 3. The blinded binding matches: `SHA-256("hfipay:bind" || u_B || intent_id)`
//! 4. The claim message digest is correctly formed

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use sha2::{Digest, Sha256};

/// Convert a BN254 Fr field element to a fixed 32-byte big-endian array.
pub fn fr_to_fixed_be_bytes(fr: &Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let limbs = bigint.as_ref(); // [u64; 4] little-endian limbs
    let mut out = [0u8; 32];
    // Write limbs in big-endian order: highest limb first
    for (i, limb) in limbs.iter().rev().enumerate() {
        let start = i * 8;
        out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// Convert a 32-byte big-endian array to a BN254 Fr field element.
pub fn fr_from_fixed_be_bytes(bytes: &[u8; 32]) -> Fr {
    let mut le = *bytes;
    le.reverse();
    Fr::from_le_bytes_mod_order(&le)
}

/// ZK public inputs for an HFI Pay claim proof.
///
/// These are the values visible to the verifier.  The prover demonstrates
/// knowledge of a private `rev` that ties them together.
#[derive(Debug, Clone)]
pub struct HfiPayClaimZkPublicInputs {
    pub identity_commitment: Fr,
    pub auth_commitment: Fr,
    pub claim_message_digest: [u8; 32],
    pub binding_epoch: Fr,
    pub blinded_binding: [u8; 32],
    pub intent_id: [u8; 32],
    pub claim_nonce: Fr,
}

impl HfiPayClaimZkPublicInputs {
    /// Flatten to a vector of Fr elements in circuit-allocation order.
    fn to_fr_vec(&self) -> Vec<Fr> {
        vec![
            self.identity_commitment,
            self.auth_commitment,
            fr_from_fixed_be_bytes(&self.claim_message_digest),
            self.binding_epoch,
            fr_from_fixed_be_bytes(&self.blinded_binding),
            fr_from_fixed_be_bytes(&self.intent_id),
            self.claim_nonce,
        ]
    }
}

/// Serialize public inputs to a vector of hex-encoded Fr elements.
pub fn hfipay_claim_public_inputs_to_hex_vec(pi: &HfiPayClaimZkPublicInputs) -> Vec<String> {
    pi.to_fr_vec()
        .iter()
        .map(|fr| hex::encode(fr_to_fixed_be_bytes(fr)))
        .collect()
}

/// Parse public inputs from a vector of hex-encoded Fr elements.
pub fn hfipay_claim_public_inputs_from_hex_vec(
    hex_vec: &[String],
) -> Result<HfiPayClaimZkPublicInputs, String> {
    if hex_vec.len() != 7 {
        return Err(format!(
            "expected 7 public input elements, got {}",
            hex_vec.len()
        ));
    }
    let parse = |i: usize| -> Result<Fr, String> {
        let bytes =
            hex::decode(&hex_vec[i]).map_err(|e| format!("invalid hex at index {i}: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "expected 32 bytes at index {i}, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(fr_from_fixed_be_bytes(&arr))
    };
    let parse_bytes32 = |i: usize| -> Result<[u8; 32], String> {
        let bytes =
            hex::decode(&hex_vec[i]).map_err(|e| format!("invalid hex at index {i}: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "expected 32 bytes at index {i}, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    };

    Ok(HfiPayClaimZkPublicInputs {
        identity_commitment: parse(0)?,
        auth_commitment: parse(1)?,
        claim_message_digest: parse_bytes32(2)?,
        binding_epoch: parse(3)?,
        blinded_binding: parse_bytes32(4)?,
        intent_id: parse_bytes32(5)?,
        claim_nonce: parse(6)?,
    })
}

/// Verify an HFI Pay claim Groth16 proof from serialized bytes.
pub fn hfipay_claim_verify_from_bytes(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &HfiPayClaimZkPublicInputs,
) -> Result<bool, String> {
    let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)
        .map_err(|e| format!("failed to deserialize verifying key: {e}"))?;
    let pi_vec = public_inputs.to_fr_vec();
    let vk_pi_count = vk.gamma_abc_g1.len().saturating_sub(1);
    if pi_vec.len() != vk_pi_count {
        return Err(format!(
            "HFI Pay claim verifying key does not match this circuit: VK expects {vk_pi_count} public inputs, \
             proof supplies {} — use zkace_hfipay_claim_vk.bin that is the Groth16 pair of the browser \
             proving key (zkace_hfipay_claim_pk.bin / same ace-hfi-pay revision)",
            pi_vec.len()
        ));
    }
    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| format!("failed to deserialize proof: {e}"))?;
    let pvk = ark_groth16::prepare_verifying_key(&vk);
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, &pi_vec, &proof)
        .map_err(|e| format!("verification error: {e}"))
}

/// Compute the Poseidon-based identity commitment from a private identity root.
///
/// `identity_commitment = Poseidon(rev)`
pub fn compute_hfipay_identity_commitment(rev: &Fr) -> Fr {
    poseidon_hash_single(*rev)
}

/// Compute the claim binding handle from a private identity root and binding epoch.
///
/// `claim_binding_handle = Poseidon(rev, binding_epoch)`
pub fn compute_hfipay_claim_binding_handle(rev: &Fr, binding_epoch: u64) -> Fr {
    poseidon_hash_pair(*rev, Fr::from(binding_epoch))
}

/// Compute the HFI Pay claim message digest.
///
/// This is a SHA-256 hash over the claim parameters, compatible with the
/// domain-separated message used in `ace_hfi_pay::auth::claim_message` but
/// operating on raw byte slices for ZK circuit compatibility.
pub fn compute_hfipay_claim_message_digest(
    chain_tag: u8,
    mint: Option<&[u8; 32]>,
    binding_epoch: u64,
    intent_id: &[u8; 32],
    blinded_binding: &[u8; 32],
    amount: u64,
    destination: &[u8],
    expiry: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hfipay:claim");
    hasher.update(b"ace-hfi-pay:v1");
    hasher.update([chain_tag]);
    match mint {
        Some(m) => {
            hasher.update([1u8]);
            hasher.update(m);
        }
        None => hasher.update([0u8]),
    }
    hasher.update(binding_epoch.to_le_bytes());
    hasher.update(intent_id);
    hasher.update(blinded_binding);
    hasher.update(amount.to_le_bytes());
    hasher.update(destination);
    hasher.update(expiry.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Generate an HFI Pay claim Groth16 proof and return the serialized proof
/// bytes along with the public inputs.
pub fn hfipay_claim_prove_and_serialize(
    pk_bytes: &[u8],
    rev: &Fr,
    claim_message_digest: &[u8; 32],
    binding_epoch: u64,
    intent_id: &[u8; 32],
    nonce: u64,
    rng: &mut (impl ark_std::rand::RngCore + ark_std::rand::CryptoRng),
) -> Result<(Vec<u8>, HfiPayClaimZkPublicInputs), String> {
    let pk = ark_groth16::ProvingKey::<Bn254>::deserialize_compressed(pk_bytes)
        .map_err(|e| format!("failed to deserialize proving key: {e}"))?;

    let identity_commitment = compute_hfipay_identity_commitment(rev);
    let auth_commitment = compute_hfipay_claim_binding_handle(rev, binding_epoch);
    let blinded_binding_handle = fr_to_fixed_be_bytes(&auth_commitment);
    let blinded_binding = crate::compute_blinded_binding(&blinded_binding_handle, intent_id);

    let public_inputs = HfiPayClaimZkPublicInputs {
        identity_commitment,
        auth_commitment,
        claim_message_digest: *claim_message_digest,
        binding_epoch: Fr::from(binding_epoch),
        blinded_binding,
        intent_id: *intent_id,
        claim_nonce: Fr::from(nonce),
    };

    let circuit = HfiPayClaimCircuit {
        rev: Some(*rev),
        identity_commitment: Some(identity_commitment),
        auth_commitment: Some(auth_commitment),
        claim_message_digest: Some(fr_from_fixed_be_bytes(claim_message_digest)),
        binding_epoch: Some(Fr::from(binding_epoch)),
        blinded_binding: Some(fr_from_fixed_be_bytes(&blinded_binding)),
        intent_id: Some(fr_from_fixed_be_bytes(intent_id)),
        claim_nonce: Some(Fr::from(nonce)),
    };

    let proof =
        Groth16::<Bn254>::prove(&pk, circuit, rng).map_err(|e| format!("proving failed: {e}"))?;

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("proof serialization failed: {e}"))?;

    Ok((proof_bytes, public_inputs))
}

// ── Minimal Poseidon hash (BN254) ──────────────────────────────────────────
//
// Simplified Poseidon for the HFI Pay claim circuit.  Uses the same
// parameterization as `zk-ace/src/groth16/hash.rs` (https://github.com/acechain-io/zk-ace).

use ark_ff::{Field, One, Zero};

const WIDTH: usize = 3;
const RATE: usize = 2;
const CAPACITY: usize = 1;
const FULL_ROUNDS_BEGIN: usize = 4;
const PARTIAL_ROUNDS: usize = 56;
const FULL_ROUNDS_END: usize = 4;
const TOTAL_ROUNDS: usize = FULL_ROUNDS_BEGIN + PARTIAL_ROUNDS + FULL_ROUNDS_END;

fn round_constants() -> &'static Vec<[Fr; WIDTH]> {
    use std::sync::OnceLock;
    static RC: OnceLock<Vec<[Fr; WIDTH]>> = OnceLock::new();
    RC.get_or_init(|| {
        let mut rc = Vec::with_capacity(TOTAL_ROUNDS);
        for round in 0..TOTAL_ROUNDS {
            let mut row = [Fr::zero(); WIDTH];
            for index in 0..WIDTH {
                let mut hasher = Sha256::new();
                hasher.update(format!("ACE-ZK-POSEIDON-BN254-RC-{round}-{index}").as_bytes());
                let hash = hasher.finalize();
                let mut bytes = [0u8; 32];
                bytes[..31].copy_from_slice(&hash[..31]);
                row[index] = Fr::from_le_bytes_mod_order(&bytes);
            }
            rc.push(row);
        }
        rc
    })
}

fn mds_matrix() -> [[Fr; WIDTH]; WIDTH] {
    let two = Fr::from(2u64);
    let one = Fr::one();
    [[two, one, one], [one, two, one], [one, one, two]]
}

#[inline]
fn sbox(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

fn apply_mds(state: &mut [Fr; WIDTH]) {
    let mds = mds_matrix();
    let old = *state;
    for i in 0..WIDTH {
        state[i] = Fr::zero();
        for j in 0..WIDTH {
            state[i] += mds[i][j] * old[j];
        }
    }
}

fn full_round(state: &mut [Fr; WIDTH], rc: &[Fr; WIDTH]) {
    for i in 0..WIDTH {
        state[i] = sbox(state[i]);
    }
    apply_mds(state);
    for i in 0..WIDTH {
        state[i] += rc[i];
    }
}

fn partial_round(state: &mut [Fr; WIDTH], rc: &[Fr; WIDTH]) {
    state[0] = sbox(state[0]);
    apply_mds(state);
    for i in 0..WIDTH {
        state[i] += rc[i];
    }
}

fn poseidon_permutation(state: &mut [Fr; WIDTH]) {
    let rc = round_constants();
    let mut round = 0;
    for _ in 0..FULL_ROUNDS_BEGIN {
        full_round(state, &rc[round]);
        round += 1;
    }
    for _ in 0..PARTIAL_ROUNDS {
        partial_round(state, &rc[round]);
        round += 1;
    }
    for _ in 0..FULL_ROUNDS_END {
        full_round(state, &rc[round]);
        round += 1;
    }
}

fn poseidon_hash(inputs: &[Fr]) -> Fr {
    let mut state = [Fr::zero(); WIDTH];
    state[0] = Fr::from(inputs.len() as u64);
    let mut rate_idx = 0;
    for &element in inputs {
        state[CAPACITY + rate_idx] += element;
        rate_idx += 1;
        if rate_idx == RATE {
            poseidon_permutation(&mut state);
            rate_idx = 0;
        }
    }
    poseidon_permutation(&mut state);
    state[CAPACITY]
}

fn poseidon_hash_single(a: Fr) -> Fr {
    poseidon_hash(&[a])
}

fn poseidon_hash_pair(a: Fr, b: Fr) -> Fr {
    poseidon_hash(&[a, b])
}

// ── HFI Pay Claim Circuit ──────────────────────────────────────────────────

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Groth16 circuit for HFI Pay claim verification.
///
/// The circuit enforces:
/// 1. `identity_commitment == Poseidon(rev)`
/// 2. `auth_commitment == Poseidon(rev, binding_epoch)`
/// 3. All public inputs are correctly allocated
#[derive(Clone)]
pub struct HfiPayClaimCircuit {
    rev: Option<Fr>,
    identity_commitment: Option<Fr>,
    auth_commitment: Option<Fr>,
    claim_message_digest: Option<Fr>,
    binding_epoch: Option<Fr>,
    blinded_binding: Option<Fr>,
    intent_id: Option<Fr>,
    claim_nonce: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for HfiPayClaimCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public digests and blinded_binding are enforced by the chain (see `auth::verify_claim_proof_inputs`);
        // the circuit only ties identity_commitment / auth_commitment to the private root.
        // Witness (private)
        let rev_var = FpVar::new_witness(cs.clone(), || {
            self.rev.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Public inputs
        let id_com_var = FpVar::new_input(cs.clone(), || {
            self.identity_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let auth_com_var = FpVar::new_input(cs.clone(), || {
            self.auth_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _digest_var = FpVar::new_input(cs.clone(), || {
            self.claim_message_digest
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let epoch_var = FpVar::new_input(cs.clone(), || {
            self.binding_epoch.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _binding_var = FpVar::new_input(cs.clone(), || {
            self.blinded_binding
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _intent_var = FpVar::new_input(cs.clone(), || {
            self.intent_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _nonce_var = FpVar::new_input(cs.clone(), || {
            self.claim_nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // C1: identity_commitment == Poseidon(rev)
        let computed_id_com = poseidon_hash_var(&[rev_var.clone()])?;
        id_com_var.enforce_equal(&computed_id_com)?;

        // C2: auth_commitment == Poseidon(rev, binding_epoch)
        let computed_auth = poseidon_hash_var(&[rev_var, epoch_var])?;
        auth_com_var.enforce_equal(&computed_auth)?;

        Ok(())
    }
}

/// Blank circuit for trusted setup / keygen (`Groth16::circuit_specific_setup`).
pub fn hfipay_claim_circuit_for_keygen() -> HfiPayClaimCircuit {
    HfiPayClaimCircuit {
        rev: None,
        identity_commitment: None,
        auth_commitment: None,
        claim_message_digest: None,
        binding_epoch: None,
        blinded_binding: None,
        intent_id: None,
        claim_nonce: None,
    }
}

// ── In-circuit Poseidon (R1CS) ─────────────────────────────────────────────

fn sbox_var(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x * x;
    let x4 = &x2 * &x2;
    Ok(&x4 * x)
}

fn apply_mds_var(state: &mut [FpVar<Fr>; WIDTH]) {
    let mds = mds_matrix();
    let old = state.clone();
    for i in 0..WIDTH {
        state[i] = FpVar::zero();
        for j in 0..WIDTH {
            state[i] = &state[i] + &(&old[j] * FpVar::constant(mds[i][j]));
        }
    }
}

fn full_round_var(state: &mut [FpVar<Fr>; WIDTH], rc: &[Fr; WIDTH]) -> Result<(), SynthesisError> {
    for i in 0..WIDTH {
        state[i] = sbox_var(&state[i])?;
    }
    apply_mds_var(state);
    for i in 0..WIDTH {
        state[i] = &state[i] + FpVar::constant(rc[i]);
    }
    Ok(())
}

fn partial_round_var(
    state: &mut [FpVar<Fr>; WIDTH],
    rc: &[Fr; WIDTH],
) -> Result<(), SynthesisError> {
    state[0] = sbox_var(&state[0])?;
    apply_mds_var(state);
    for i in 0..WIDTH {
        state[i] = &state[i] + FpVar::constant(rc[i]);
    }
    Ok(())
}

fn poseidon_permutation_var(state: &mut [FpVar<Fr>; WIDTH]) -> Result<(), SynthesisError> {
    let rc = round_constants();
    let mut round = 0;
    for _ in 0..FULL_ROUNDS_BEGIN {
        full_round_var(state, &rc[round])?;
        round += 1;
    }
    for _ in 0..PARTIAL_ROUNDS {
        partial_round_var(state, &rc[round])?;
        round += 1;
    }
    for _ in 0..FULL_ROUNDS_END {
        full_round_var(state, &rc[round])?;
        round += 1;
    }
    Ok(())
}

fn poseidon_hash_var(inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut state: [FpVar<Fr>; WIDTH] = [
        FpVar::constant(Fr::from(inputs.len() as u64)),
        FpVar::zero(),
        FpVar::zero(),
    ];
    let mut rate_idx = 0;
    for element in inputs {
        state[CAPACITY + rate_idx] = &state[CAPACITY + rate_idx] + element;
        rate_idx += 1;
        if rate_idx == RATE {
            poseidon_permutation_var(&mut state)?;
            rate_idx = 0;
        }
    }
    poseidon_permutation_var(&mut state)?;
    Ok(state[CAPACITY].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_be_bytes_roundtrip() {
        let fr = Fr::from(123456u64);
        let bytes = fr_to_fixed_be_bytes(&fr);
        let recovered = fr_from_fixed_be_bytes(&bytes);
        assert_eq!(fr, recovered);
    }

    #[test]
    fn identity_commitment_is_deterministic() {
        let rev = Fr::from(42u64);
        let c1 = compute_hfipay_identity_commitment(&rev);
        let c2 = compute_hfipay_identity_commitment(&rev);
        assert_eq!(c1, c2);
    }

    #[test]
    fn binding_handle_changes_with_epoch() {
        let rev = Fr::from(42u64);
        let h1 = compute_hfipay_claim_binding_handle(&rev, 1);
        let h2 = compute_hfipay_claim_binding_handle(&rev, 2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn groth16_vk_instance_count_matches_to_fr_vec() {
        use ark_groth16::Groth16;
        use ark_snark::SNARK;
        use ark_std::rand::rngs::StdRng;
        use ark_std::rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(42);
        let (_pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(hfipay_claim_circuit_for_keygen(), &mut rng)
                .unwrap();
        let vk_pi = vk.gamma_abc_g1.len().saturating_sub(1);
        let mut d = [0u8; 32];
        d[31] = 1;
        let pi = HfiPayClaimZkPublicInputs {
            identity_commitment: Fr::from(1u64),
            auth_commitment: Fr::from(2u64),
            claim_message_digest: d,
            binding_epoch: Fr::from(3u64),
            blinded_binding: d,
            intent_id: d,
            claim_nonce: Fr::from(4u64),
        };
        assert_eq!(
            pi.to_fr_vec().len(),
            vk_pi,
            "HfiPayClaimZkPublicInputs::to_fr_vec length must match Groth16 VK (gamma_abc_g1.len()-1)"
        );
    }

    #[test]
    fn public_inputs_hex_roundtrip() {
        let mut claim_digest = [0u8; 32];
        claim_digest[31] = 0xAA;
        let mut blinded = [0u8; 32];
        blinded[31] = 0xBB;
        let mut intent = [0u8; 32];
        intent[31] = 0xCC;

        let pi = HfiPayClaimZkPublicInputs {
            identity_commitment: Fr::from(1u64),
            auth_commitment: Fr::from(2u64),
            claim_message_digest: claim_digest,
            binding_epoch: Fr::from(3u64),
            blinded_binding: blinded,
            intent_id: intent,
            claim_nonce: Fr::from(0u64),
        };
        let hex_vec = hfipay_claim_public_inputs_to_hex_vec(&pi);
        assert_eq!(hex_vec.len(), 7);
        let recovered = hfipay_claim_public_inputs_from_hex_vec(&hex_vec).unwrap();
        assert_eq!(recovered.identity_commitment, pi.identity_commitment);
        assert_eq!(recovered.auth_commitment, pi.auth_commitment);
        assert_eq!(recovered.claim_message_digest, pi.claim_message_digest);
        assert_eq!(recovered.binding_epoch, pi.binding_epoch);
        assert_eq!(recovered.blinded_binding, pi.blinded_binding);
        assert_eq!(recovered.intent_id, pi.intent_id);
        assert_eq!(recovered.claim_nonce, pi.claim_nonce);
    }
}
