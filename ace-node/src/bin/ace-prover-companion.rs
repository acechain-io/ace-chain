#[cfg(feature = "prover")]
use std::collections::BTreeMap;
#[cfg(feature = "prover")]
use std::io::Read;
#[cfg(feature = "prover")]
use std::path::Path;
#[cfg(feature = "prover")]
use std::path::PathBuf;

#[cfg(feature = "prover")]
use ace_node::companion_protocol::{
    ProverCompanionRequest, ProverCompanionResponse, SerializablePrivateWitness,
};
use ace_node::proof_material::ProofMode;
#[cfg(feature = "prover")]
use ace_runtime::crypto::proof::{PrivateWitness, StarkProver};
#[cfg(feature = "prover")]
use ace_runtime::pipeline::prove::prove_block;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "ace-prover-companion",
    about = "Local ACE STARK finality prover companion"
)]
struct CompanionCli {
    #[arg(long, env = "ACE_PROOF_MODE", default_value = "production")]
    proof_mode: String,

    #[arg(long, env = "ACE_DATA_DIR")]
    data_dir: Option<String>,

    #[arg(long, env = "ACE_WITNESS_FILE")]
    witness_file: Option<String>,
}

fn parse_proof_mode(raw: &str) -> anyhow::Result<ProofMode> {
    ProofMode::parse(raw).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid proof_mode '{}', expected 'production', 'dev-mock', or 'dev-stark'",
            raw
        )
    })
}

#[cfg(feature = "prover")]
fn convert_witness(serialized: &SerializablePrivateWitness) -> PrivateWitness {
    PrivateWitness {
        root_secret: serialized.root_secret,
        salt: serialized.salt,
        alg_id: serialized.alg_id,
        index: serialized.index,
        nonce: serialized.nonce,
    }
}

#[cfg(feature = "prover")]
fn load_witness_map(path: &Path) -> anyhow::Result<BTreeMap<String, SerializablePrivateWitness>> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read witness file {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid witness file {}: {}", path.display(), e))
}

#[cfg(feature = "prover")]
fn resolve_witnesses(
    request: &ProverCompanionRequest,
    witness_file: Option<&Path>,
) -> anyhow::Result<Vec<PrivateWitness>> {
    if let Some(witnesses) = &request.witnesses {
        if witnesses.len() != request.block.transactions.len() {
            anyhow::bail!(
                "request witness count {} does not match block transaction count {}",
                witnesses.len(),
                request.block.transactions.len()
            );
        }
        return Ok(witnesses.iter().map(convert_witness).collect());
    }

    let witness_map = if let Some(path) = witness_file {
        Some(load_witness_map(path)?)
    } else {
        None
    };

    request
        .block
        .transactions
        .iter()
        .map(|tx| {
            if tx.raw_chain.is_some() {
                return Ok(PrivateWitness::legacy_dummy());
            }
            let key = hex::encode(tx.attestation.obj_hash);
            witness_map
                .as_ref()
                .and_then(|map| map.get(&key))
                .map(convert_witness)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "missing witness for native tx {} (provide --witness-file or request.witnesses)",
                        key
                    )
                })
        })
        .collect()
}

#[cfg(feature = "prover")]
fn read_request() -> anyhow::Result<ProverCompanionRequest> {
    let mut stdin = std::io::stdin();
    let mut bytes = Vec::new();
    stdin.read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!("invalid prover request: {e}"))
}

#[cfg(feature = "prover")]
fn witness_path(path: Option<&String>) -> Option<PathBuf> {
    path.as_ref()
        .map(PathBuf::from)
        .filter(|candidate| !candidate.as_os_str().is_empty())
}

#[cfg(feature = "prover")]
fn print_response(response: &ProverCompanionResponse) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(response)?;
    println!("{}", String::from_utf8_lossy(&bytes));
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = CompanionCli::parse();
    let proof_mode = parse_proof_mode(&cli.proof_mode)?;

    match proof_mode {
        ProofMode::Production | ProofMode::DevStark => {
            // STARK prover — no keys needed (transparent setup).
            #[cfg(feature = "prover")]
            {
                let witness_file = witness_path(cli.witness_file.as_ref());
                let request = read_request()?;
                let witnesses = resolve_witnesses(&request, witness_file.as_deref())?;
                let prover = StarkProver::new_nonce_registry();
                let certificate = prove_block(&request.block, &prover, &witnesses)
                    .map_err(|e| anyhow::anyhow!("failed to prove block: {e}"))?;
                return print_response(&ProverCompanionResponse { certificate });
            }
            #[cfg(not(feature = "prover"))]
            anyhow::bail!(
                "proof_mode={} requires building ace-prover-companion with --features prover",
                proof_mode.as_str()
            )
        }
        ProofMode::DevMock => anyhow::bail!(
            "{} is handled directly inside ace-node and does not need a prover companion",
            proof_mode.as_str()
        ),
    }
}
