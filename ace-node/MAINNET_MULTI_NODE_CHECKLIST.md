# ACE Mainnet Multi-Node Checklist

This checklist is for the current `ace-node` codebase as of April 11, 2026.

It covers the minimum pieces you need to bring up multiple `proof_mode=production` nodes:

1. A shared genesis file with explicit non-zero `auth_pubkey` values for every funded account
2. Explicit `validators[*].signing_pubkey` in genesis and matching `validator_signing_seed` per node
3. Static validator capability flags in genesis for any optional `btc-payments` / `solana-light` committees
4. Per-node persistent `data_dir` directories
5. Reachable `bootnodes` so peers can join the same network
6. A local prover companion path

The last item matters: the production proof system is a STARK verifier with a transparent setup — there is no trusted ceremony and no proving/verifying keys to distribute. The node binary verifies `FinalityCertificate` objects in-process, but it does not hold witnesses itself. In production each validator must run a local prover companion that receives canonical blocks over stdin/stdout and returns `FinalityCertificate` objects for the node to gossip.

## 1. Build the binaries

Build the node in release mode with the `stark` feature (required for `proof_mode=production`):

```bash
cargo build -p ace-node --release --features stark
```

No separate key-generation binary is required — the STARK verifier uses a transparent setup.

## 2. Create a production genesis

Every funded genesis account must include an explicit non-zero `auth_pubkey`.

`auth_pubkey` is public material. Keep the corresponding private attestation seed off-chain and out of git.

Minimal example:

```json
{
  "accounts": [
    {
      "id_com": "0101010101010101010101010101010101010101010101010101010101010101",
      "balance": 1000000000,
      "auth_pubkey": "1111111111111111111111111111111111111111111111111111111111111111"
    }
  ],
  "validators": [
    {
      "id_com": "0101010101010101010101010101010101010101010101010101010101010101",
      "stake": 100,
      "signing_pubkey": "2222222222222222222222222222222222222222222222222222222222222222"
    }
  ],
  "genesis_time_ms": 0,
  "chain_id": 2766
}
```

Generate fresh key material with:

```bash
openssl rand -hex 32
```

In `proof_mode=production`, every validator must set `validators[*].signing_pubkey` explicitly in genesis and provide the matching `validator_signing_seed` in that validator's node config. `chain_id` must be explicit and non-zero; reserved values are rejected.

If you want a validator to participate in the minimal legacy-ingress committee path, also add:

```json
"capabilities": {
  "evm_core": true,
  "btc_payments": true,
  "solana_light": false
}
```

For the current minimal implementation:

- `evm_core` is baseline and should remain `true`
- `btc_payments` is reserved for future BTC execution-tier admission; the current minimal BTC path is validated by all nodes
- `solana_light` enables the Solana subset committee eligibility
- committee membership is static from genesis, not yet dynamic at runtime

The checked-in example file has been updated here:

- [ace-node/genesis.example.json](genesis.example.json)

## 3. Lay out the directories

Recommended structure:

```text
/srv/ace/
  shared/
    genesis.mainnet.json
  node-1/
    ace-node.json
    data/
      identity.json
      governance.json
      state/
      blocks/
  node-2/
    ace-node.json
    data/
      identity.json
      governance.json
      state/
      blocks/
  node-3/
    ace-node.json
    data/
      identity.json
      governance.json
      state/
      blocks/
```

Notes:

- `identity.json`, `governance.json`, `state/`, and `blocks/` are created by the node
- Each node must have its own `data_dir`
- All nodes must use the exact same genesis file
- A node refuses to load state from a `data_dir` whose recorded genesis hash does not match the configured genesis; wipe the directory when changing `chain_id` or any genesis field

## 4. Prepare per-node configs

Example bootnode config for `node-1`:

```json
{
  "chain_id": 2766,
  "rpc_port": 8545,
  "p2p_port": 30333,
  "bootnodes": [],
  "validator": true,
  "validator_key": "0101010101010101010101010101010101010101010101010101010101010101",
  "validator_signing_seed": "<hex seed matching signing_pubkey in genesis>",
  "proof_mode": "production",
  "prover_companion_bin": "/usr/local/bin/ace-prover-companion",
  "prover_companion_args": [],
  "prover_companion_timeout_ms": 5000,
  "genesis_path": "/srv/ace/shared/genesis.mainnet.json",
  "data_dir": "/srv/ace/node-1/data"
}
```

Example follower config for `node-2` after `node-1` is reachable:

```json
{
  "chain_id": 2766,
  "rpc_port": 8546,
  "p2p_port": 30334,
  "bootnodes": [
    "/ip4/203.0.113.10/tcp/30333/p2p/12D3KooWJ3uXvdftz76CY45KdYgEeA812mRPHqZuwbJUqzpnCXPU"
  ],
  "validator": true,
  "validator_key": "0202020202020202020202020202020202020202020202020202020202020202",
  "validator_signing_seed": "<hex seed matching signing_pubkey in genesis>",
  "proof_mode": "production",
  "prover_companion_bin": "/usr/local/bin/ace-prover-companion",
  "prover_companion_args": [],
  "prover_companion_timeout_ms": 5000,
  "genesis_path": "/srv/ace/shared/genesis.mainnet.json",
  "data_dir": "/srv/ace/node-2/data"
}
```

The checked-in base example file lives here:

- [ace-node/ace-node.example.json](ace-node.example.json)

## 5. Bring up the first node

Start the bootnode directly — no extra environment variables are needed:

```bash
target/release/ace-node --config /srv/ace/node-1/ace-node.json --log-level info
```

Watch the logs for the full authenticated listen address. Seed the other nodes' `bootnodes` with a multiaddr that includes `/p2p/<peer-id>`.

## 6. Start the remaining nodes

For each additional node:

1. Copy the same genesis file into place or point `genesis_path` to the shared copy
2. Give it a unique `rpc_port`, `p2p_port`, and `data_dir`
3. Set `validator_key` to the validator identity assigned in genesis, and `validator_signing_seed` to match the `signing_pubkey` for that validator
4. Add one or more reachable `bootnodes`

Then start the node:

```bash
target/release/ace-node --config /srv/ace/node-2/ace-node.json --log-level info
```

## 7. Run the local prover companion

Today this is a required production companion component.

For validator nodes, `ace-node` requires `prover_companion_bin` in `proof_mode=production` (and in `dev-stark` if you want the node to actually finalize provable transactions).

The companion must:

1. Read a JSON `ProverCompanionRequest` from stdin
2. Resolve the witness set for the requested canonical block
3. Call `ace_runtime::pipeline::prove::prove_block`
4. Write a JSON `ProverCompanionResponse` with the resulting `FinalityCertificate` to stdout

Without this component, validator nodes in `proof_mode=production` cannot progress from `Soft` to `Hard` finality because there is no external proof producer.

## 8. Sanity checks after launch

Check these on every node:

- `data_dir/state` exists and grows
- `data_dir/blocks` exists and grows
- `data_dir/governance.json` exists
- `data_dir/identity.json` exists if you restored identity from mnemonic
- RPC `getNetworkStatus` shows the same `latest_block_slot` across nodes after catch-up
- Nodes can restart and rejoin from disk without re-running genesis

## 9. Operator reminders

- Do not commit real attestation signing seeds or validator signing seeds
- Do not reuse one `data_dir` across multiple nodes
- Keep every node on the exact same genesis and `chain_id`
- The STARK proof system uses a transparent setup — there are no proving/verifying keys to rotate, distribute, or back up
- If there is still no external caller, the `CreateAccount` payload size change only needs documentation for now; there is no live integration to migrate yet
