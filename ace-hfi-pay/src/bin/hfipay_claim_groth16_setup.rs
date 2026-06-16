//! Local Groth16 trusted setup for the HFI Pay claim circuit.
//!
//! Writes `zkace_hfipay_claim_pk.bin` and `zkace_hfipay_claim_vk.bin` (arkworks **compressed** format).
//!
//! ```text
//! cargo run -p ace-hfi-pay --bin hfipay-claim-groth16-setup -- <output_dir>
//! ```
//!
//! Copy `zkace_hfipay_claim_pk.bin` → `ace-portal/public/` (or CDN for `VITE_HFIPAY_CLAIM_PK_URL`).
//! Copy `zkace_hfipay_claim_vk.bin` → `ace-rpc/assets/` and/or node `hfi-pay/` data dir, or set `ACE_HFIPAY_CLAIM_VK_PATH`.
//!
//! Devnet only: this uses a random local setup, not a production MPC ceremony.

use std::env;
use std::fs;
use std::path::PathBuf;

use ace_hfi_pay::zk::hfipay_claim_circuit_for_keygen;
use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use rand::rngs::OsRng;

fn main() -> Result<(), String> {
    let out_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&out_dir).map_err(|e| format!("create_dir_all: {e}"))?;

    let mut rng = OsRng;
    let circuit = hfipay_claim_circuit_for_keygen();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
        .map_err(|e| format!("circuit_specific_setup: {e}"))?;

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| format!("serialize pk: {e}"))?;
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| format!("serialize vk: {e}"))?;

    let pk_path = out_dir.join("zkace_hfipay_claim_pk.bin");
    let vk_path = out_dir.join("zkace_hfipay_claim_vk.bin");
    fs::write(&pk_path, &pk_bytes).map_err(|e| format!("write pk: {e}"))?;
    fs::write(&vk_path, &vk_bytes).map_err(|e| format!("write vk: {e}"))?;

    eprintln!(
        "Wrote {} ({} bytes) and {} ({} bytes)",
        pk_path.display(),
        pk_bytes.len(),
        vk_path.display(),
        vk_bytes.len(),
    );
    Ok(())
}
