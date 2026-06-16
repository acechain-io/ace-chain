//! Check that a proving key and verifying key are a Groth16 pair (same setup),
//! and that they match the **current** `ace-hfi-pay` claim circuit in this repo.
//!
//! ```text
//! cargo run --release -p ace-hfi-pay --bin hfipay-claim-groth16-check -- <pk.bin> <vk.bin>
//! ```

use std::env;
use std::fs;

use ace_hfi_pay::zk::hfipay_claim_circuit_for_keygen;
use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;

fn main() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let pk_path = args
        .next()
        .ok_or_else(|| "usage: hfipay-claim-groth16-check <pk.bin> <vk.bin>".to_string())?;
    let vk_path = args
        .next()
        .ok_or_else(|| "usage: hfipay-claim-groth16-check <pk.bin> <vk.bin>".to_string())?;

    let pk_bytes = fs::read(&pk_path).map_err(|e| format!("read pk: {e}"))?;
    let vk_bytes = fs::read(&vk_path).map_err(|e| format!("read vk: {e}"))?;

    let pk = ProvingKey::<Bn254>::deserialize_compressed(pk_bytes.as_slice())
        .map_err(|e| format!("deserialize pk: {e}"))?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes.as_slice())
        .map_err(|e| format!("deserialize vk: {e}"))?;

    if pk.vk != vk {
        return Err(
            "PK/VK mismatch: the proving key does not embed this verifying key (different setups or corrupted files)"
                .into(),
        );
    }

    let artifact_pi = vk.gamma_abc_g1.len().saturating_sub(1);

    let mut rng = StdRng::seed_from_u64(42);
    let (_fresh_pk, fresh_vk) =
        Groth16::<Bn254>::circuit_specific_setup(hfipay_claim_circuit_for_keygen(), &mut rng)
            .map_err(|e| format!("fresh circuit_specific_setup (source): {e}"))?;
    let source_pi = fresh_vk.gamma_abc_g1.len().saturating_sub(1);

    if artifact_pi != source_pi {
        return Err(format!(
            "PK/VK are a pair, but were generated for a different circuit than this ace-hfi-pay source: \
             artifacts expect {artifact_pi} public inputs, current crate expects {source_pi}. \
             Regenerate both files: cargo run --release -p ace-hfi-pay --bin hfipay-claim-groth16-setup -- <dir>"
        ));
    }

    eprintln!("OK: PK/VK pair matches current ace-hfi-pay circuit (VK expects {artifact_pi} public inputs).");
    Ok(())
}
