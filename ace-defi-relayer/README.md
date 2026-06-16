# ACE DeFi Relayer

Phase A relayer for ACE DeFi community development.

## Scope

The relayer connects the EVM-side custody bridge to ACE DeFi:

- Ingress scans Ethereum/BSC bridge contracts with `eth_getLogs`.
- Deposit events are decoded into canonical ACE `SignedDepositRecord` values.
- Signed deposits are submitted to ACE RPC through `ace_submitDeposit`.
- Egress queries ACE RPC for canonical `ace_defi::WithdrawalRecord` values, executes Ethereum/BSC releases, and submits completion records bound to the released asset, recipient, amount and gateway address.
- Local checkpoints persist scan progress and processed deposit/withdrawal IDs across restarts.

ACE bridge deposits are accepted only from relayer public keys approved in ACE genesis under `ace_defi_approved_relayers`. The `RELAYER_PRIVATE_KEY` configured below must correspond to one of those public keys, or `ace_submitDeposit` will be rejected before mempool admission. Pending withdrawals are read from the node-side consensus-backed withdrawal index. The oracle module remains a development path and is intentionally not treated as production-ready in this milestone.

## Required Environment

```bash
ACE_RPC_URL=http://127.0.0.1:18545
RELAYER_PRIVATE_KEY=<32-byte-ed25519-private-key-hex>
ETH_RPC_URL=http://127.0.0.1:8545
ETH_BRIDGE_CONTRACT=0x...
BSC_RPC_URL=http://127.0.0.1:8546
BSC_BRIDGE_CONTRACT=0x...
ACE_DEFI_EGRESS_PRIVATE_KEY=<32-byte-evm-transaction-private-key-hex>
ACE_DEFI_EGRESS_RELEASE_PRIVATE_KEYS=<comma-separated-evm-release-signer-private-key-hex-list>
```

`ACE_DEFI_EGRESS_PRIVATE_KEY` signs the destination-chain transaction that calls the gateway. `ACE_DEFI_EGRESS_RELEASE_PRIVATE_KEYS` signs the gateway release authorization payload. The release signer public addresses must be configured on `OmniGatewayDeposit`, and the number of keys provided here must satisfy the gateway release threshold. Chain-specific overrides are supported with `ACE_DEFI_EGRESS_PRIVATE_KEY_ETHEREUM`, `ACE_DEFI_EGRESS_PRIVATE_KEY_BSC`, `ACE_DEFI_EGRESS_RELEASE_PRIVATE_KEYS_ETHEREUM`, and `ACE_DEFI_EGRESS_RELEASE_PRIVATE_KEYS_BSC`.

Genesis must include the relayer public key:

```json
{
  "ace_defi_approved_relayers": [
    "<32-byte-ed25519-public-key-hex>"
  ]
}
```

## Optional Environment

```bash
POLL_INTERVAL=10
MAX_DEPOSIT=1000000000000000000
ACE_DEFI_RELAYER_CHECKPOINT_FILE=ace-defi-relayer-checkpoints.json
ACE_DEFI_RELAYER_ALLOW_MOCK_RPC=1
ACE_DEFI_RELAYER_ALLOW_MOCK_ACE_WITHDRAWALS=1
ACE_DEFI_RELAYER_ALLOW_MOCK_EGRESS=1
```

Mock flags are only for local tests and demos.

## Commands

```bash
cargo test -p ace-defi-relayer
cargo run -p ace-defi-relayer
```

## Current Boundary

This is a community development relayer, not a production bridge operator. Production operation still needs stronger key management, receipt confirmation, multi-node ACE withdrawal verification, monitoring, threshold relayer governance, and finalization of the oracle path.
