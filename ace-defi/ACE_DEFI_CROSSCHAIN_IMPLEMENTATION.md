# ACE DeFi Cross-Chain Implementation Plan

## Status

This document is the implementation plan for the ACE DeFi cross-chain bridge and liquidity protocol. It replaces the older MVP README language that overstated several properties, including "zero MEV", "no latency", fixed APY expectations, and single-sig production readiness.

Authoritative product and security framing lives in `ace-defi/ACE_DEFI_SOLUTION.md`. This file focuses on how to implement that design without changing its trust model.

Current target:

- Phase A: capped custodial beta with multi-sig relayers, hard TVL limits, withdrawal limits, and explicit risk monitoring.
- Phase B: non-custodial zk/light-client egress before meaningful TVL scale.
- Phase C: HFI-Pay-style verified `ConvertIntent` and proof-bound claim/refund semantics for high-value flows.

Current code baseline:

- Phase A safety foundations are present: governance-bound relayer admission, intent-bound records, Ethereum intent events, local relayer checkpointing, and scheduler/runtime guards.
- The production rollout path adds external-chain RPC/log decoding, threshold relayer quorum, hardened egress execution, caps/circuit breakers, monitoring, and proof-verified Phase B release.
- AMM pool metadata is not yet recovered from `StateTree`; `CrossVmSettle` requires pre-initialized in-memory pools and fails closed otherwise.

Risk-compartment baseline:

- Canonical assets and external mappings have deterministic risk-compartment identifiers.
- Mapping-level `mint_enabled` and `withdraw_enabled` controls allow one external asset path to be paused without disabling sibling mappings for the same canonical asset.
- ACE Liquid markets derive independent market compartments and keep book/collateral state under per-market accounts.
- Later rollout stages should extend this same model to oracle feeds, relayer sets, withdrawal routes, and pool-level invariant reporting.

## Architecture

### Three Execution Zones

ACE atomicity is strongest inside ACE's own execution boundary. External-chain ingress and egress remain bridge-bearing trust domains until Phase B.

```
Zone 1: ACE-internal execution
  - Unified StateTree
  - n-VM token ledger
  - Atomic swap execution
  - MEV-ACE protects admitted transactions from proposer-controlled ordering MEV

Zone 2: External-chain ingress
  - Source of truth is the external chain
  - Deposits require finality depth plus proof or relayer attestation
  - ACE must not mint wrapped assets before verification succeeds

Zone 3: External-chain egress
  - Phase A pays from pre-funded relayer pools
  - Safety depends on multi-sig custody, withdrawal caps, replay controls, and monitoring
  - Phase B moves release to proof-verified destination-chain contracts
```

### User Flow

Example: BSC USDT to Tron TRX.

```
1. Quote
   User requests: source=(BSC, USDT, amount), target=(Tron, TRX), recipient, min_amount_out.
   Protocol returns a ConvertIntent with route, fee, expiry, nonce, and refund destination.

2. Ingress
   User deposits USDT into the BSC bridge contract.
   Relayer waits for configured finality and submits a threshold attestation to ACE.
   ACE mints wUSDT only after the deposit is accepted.

3. ACE-internal swap
   ACE swaps wUSDT -> wTRX in one state transition.
   Slippage is bounded by min_amount_out.
   MEV-ACE mitigates proposer-controlled ordering MEV only for transactions that pass commit/open receipt thresholds.

4. Egress
   ACE burns or escrows wTRX and creates a WithdrawalRecord.
   Phase A relayer pays TRX from a pre-funded multi-sig controlled pool.
   Phase B destination-chain contract releases funds after verifying an ACE state-root/consensus proof.

5. Completion or refund
   Withdrawal completion is recorded on ACE.
   If the intent expires before execution, refund follows the pre-committed refund path.
```

## Core Data Model

### ConvertIntent

`ConvertIntent` should be introduced in Phase A, even if full HFI-Pay-style verified quote proofs ship later. It is the contract between the user, protocol, and relayers.

```rust
pub struct ConvertIntent {
    pub intent_id: [u8; 32],
    pub source_chain: ChainId,
    pub source_asset: ExternalAsset,
    pub source_amount: u64,
    pub target_chain: ChainId,
    pub target_asset: ExternalAsset,
    pub min_amount_out: u64,
    pub recipient: Vec<u8>,
    pub refund_destination: Vec<u8>,
    pub expiry_slot: u64,
    pub fee_quote_bps: u64,
    pub relayer_set_id: u64,
    pub nonce: u64,
}
```

Required invariants:

- `intent_id` is deterministic over the canonical encoded tuple plus nonce, or is sampled and then bound to the full tuple before funding.
- `source_chain`, `source_asset`, `target_chain`, `target_asset`, `recipient`, `min_amount_out`, `expiry_slot`, and `refund_destination` are immutable after funding.
- Relayers can execute only the committed tuple.
- Replay protection applies to deposits, withdrawals, completions, and refunds.
- Any amount below `min_amount_out` aborts and follows the refund policy.

### DepositRecord

```rust
pub struct DepositRecord {
    pub deposit_id: [u8; 32],
    pub intent_id: [u8; 32],
    pub source_chain: ChainId,
    pub source_asset: ExternalAsset,
    pub amount: u64,
    pub external_tx_hash: [u8; 32],
    pub finalized_height: u64,
    pub relayer_set_id: u64,
    pub signatures: Vec<RelayerSignature>,
}
```

Required checks:

- External finality depth meets chain-specific policy.
- `deposit_id` has not been processed.
- The deposit event matches the committed `ConvertIntent`.
- Threshold signatures meet the active `RelayerSet` policy.
- Amount and token decimals are normalized before minting.

### WithdrawalRecord

```rust
pub struct WithdrawalRecord {
    pub withdrawal_id: [u8; 32],
    pub intent_id: [u8; 32],
    pub target_chain: ChainId,
    pub target_asset: ExternalAsset,
    pub amount: u64,
    pub recipient: Vec<u8>,
    pub created_slot: u64,
    pub status: WithdrawalStatus,
    pub completion_tx_hash: Option<Vec<u8>>,
}
```

Required checks:

- `withdrawal_id` is unique and replay-protected.
- Amount, target asset, and recipient match the committed `ConvertIntent`.
- Phase A relayer execution respects per-tx, per-day, per-chain, and global TVL caps.
- Completion can be marked only by authorized relayer quorum or Phase B proof logic.

## Components

### `ace-defi`

Existing ACE DeFi code should be extended around the current AMM, asset registry, deposit, withdrawal, and settlement primitives.

Planned modules:

```
ace-defi/src/
├── bridge.rs        # Deposit/withdraw lifecycle and processed-id sets
├── intent.rs        # ConvertIntent creation, validation, expiry, refund policy
├── relayer.rs       # RelayerSet, threshold verification, key rotation
├── risk.rs          # Caps, circuit breakers, pause controls
├── oracle.rs        # Price source abstraction and sanity checks
├── swap.rs          # Existing AMM, fee config, slippage enforcement
├── settle.rs        # Atomic ingress/swap/egress orchestration
└── registry.rs      # Chain and asset registration
```

Phase A should avoid adding unnecessary abstraction. The critical implementation object is `ConvertIntent`; routing can remain simple until more chains are live.

### `ace-defi-relayer`

Relayers are not merely "bots"; in Phase A they are part of the security boundary.

```
ace-defi-relayer/src/
├── main.rs
├── config.rs
├── ingress.rs       # External-chain deposit monitoring
├── egress.rs        # ACE withdrawal monitoring and destination transfer
├── signing.rs       # Relayer attestations; threshold or aggregate signatures
├── finality.rs      # Chain-specific finality policies
├── risk.rs          # Local enforcement of caps before signing/executing
├── store.rs         # Durable processed deposit/withdrawal state
├── oracle.rs        # Price feed client or mock in local tests only
└── monitoring.rs    # Metrics, alerts, incident hooks
```

Relayer implementation requirements:

- Use multiple RPC endpoints per external chain.
- Persist scan checkpoints and processed IDs.
- Separate ingress attestation keys from egress payment keys.
- Never sign a deposit whose event does not match the committed intent.
- Never execute an egress transfer whose withdrawal record exceeds active caps.
- Emit auditable logs for every signed attestation and destination transfer.

### `ace-defi-contracts`

Phase A requires minimal deposit contracts on supported source chains. Egress contracts are not used in Phase A, but will be needed in Phase B for proof-verified release.

```
ace-defi-contracts/
├── evm/
│   ├── contracts/
│   │   └── BridgeDeposit.sol
│   ├── test/
│   └── hardhat.config.js
└── phase-b/
    └── ProofVerifiedRelease.sol  # future: ACE state-root/consensus proof verifier
```

Deposit contract requirements:

- Lock or receive the exact token and amount.
- Emit a canonical event containing `deposit_id`, `intent_id`, token, amount, source chain, and ACE recipient/intent reference.
- Avoid owner emergency withdrawals of user funds except under explicit governance/timelock recovery policy.
- Do not mark deposits processed on the source chain as a substitute for ACE-side idempotency; ACE must maintain its own processed set.

## Phase A: Capped Custodial Beta

Phase A is intended to validate market demand and volume/TVL turnover under a bounded risk model. It is not a trustless bridge.

Minimum launch requirements:

- 3-of-5 or stronger relayer quorum for deposit attestations.
- Multi-sig controlled egress wallets with separated keys from ingress attestations.
- Low global TVL ceiling.
- Per-transaction withdrawal cap.
- Per-day aggregate withdrawal cap.
- Per-chain liquidity cap.
- Oracle circuit breaker.
- Emergency pause for new deposits and new swaps.
- Refund path for expired or failed intents.
- Public risk disclosure that egress is custodial during Phase A.

Suggested launch parameters should be conservative and reviewed before deployment:

```text
global_tvl_ceiling_usd: low seven figures or less
per_tx_withdrawal_cap_usd: materially below insurance/reserve coverage
daily_withdrawal_cap_usd: bounded by operational liquidity and monitoring response time
swap_fee_bps: 5-10 bps target, subject to volume/TVL economics
default_slippage_bps: 50 bps or user-configurable
oracle_deviation_pause_bps: 300-500 bps depending on asset volatility
```

Phase A must not scale TVL beyond the published cap until Phase B is live.

## Phase B: Non-Custodial Egress

Phase B changes the egress trust model. The relayer becomes a message courier or liquidity fronting service, not a custodian with unilateral payout power.

Required dependencies:

1. Signed BFT votes over block hash and state root.
2. Validator-set rotation handling.
3. EVM-verifiable or destination-chain-verifiable consensus proof.
4. Merkle inclusion proof for `WithdrawalRecord`.
5. Destination-chain release contract per supported chain.

The release condition should be:

```text
release funds if:
  ACE consensus proof verifies finalized state_root
  Merkle proof verifies WithdrawalRecord under state_root
  WithdrawalRecord matches target chain, asset, amount, recipient, and nonce
  withdrawal_id has not been executed before
```

Fast UX can be preserved by allowing a relayer to front funds and later reimburse itself from the destination contract using the same proof.

## Phase C: Verified Intent and Claim Binding

Phase C imports the HFI-Pay pattern into cross-chain DeFi.

Goal:

- Users verify a quote before funding.
- The chain commits the exact conversion tuple.
- Relayers execute only that tuple.
- Destination claim or release binds to the same intent, asset, amount, recipient, expiry, and nonce.
- Refunds follow the pre-committed refund destination and cannot be redirected.

This is especially important for high-value flows, wallet-integrated flows, and "send to identifier" UX.

## MEV and Latency Claims

The implementation must avoid the old language "zero MEV" and "no latency".

Correct statement:

- ACE-internal swap execution is atomic within one ACE state transition.
- MEV-ACE mitigates proposer-controlled ordering MEV only for admitted transactions that obtain the required commit/open receipt thresholds.
- Information-based MEV, oracle back-running, and cross-domain arbitrage remain out of scope.
- End-to-end cross-chain latency is dominated by source-chain finality and destination-chain confirmation.
- A 400ms ACE slot applies only to the ACE-internal leg, and full MEV-ACE protection requires a commit/VDF/open budget or pipelined implementation.

## Economics Claims

The implementation must not claim fixed LP APY.

Correct model:

```text
LP fee APY = (daily_volume / pool_TVL) * fee_rate * 365
```

At 0.1% fee:

- 10% daily turnover gives about 3.65% gross fee APY.
- 30% daily turnover gives about 10.95% gross fee APY.
- 50% daily turnover gives about 18.25% gross fee APY.

The protocol thesis is that route consolidation can raise turnover enough to offset lower fees. That is a hypothesis to validate with simulations and beta traffic, not an established result.

## Configuration

Example local configuration. Do not use this as production security guidance.

```bash
# ACE Chain
ACE_RPC_URL=http://localhost:18545

# Relayer identity
RELAYER_ID=relayer-1
RELAYER_ATTESTATION_KEY_PATH=/secure/path/attestation.key
RELAYER_PAYMENT_KEY_REF=hsm-or-multisig-reference

# External chains
ETH_RPC_URL=https://sepolia.example
ETH_BRIDGE_CONTRACT=0x...
BSC_RPC_URL=https://bsc-testnet.example
TRON_RPC_URL=https://tron-testnet.example

# Finality policy
ETH_CONFIRMATION_DEPTH=64
BSC_CONFIRMATION_DEPTH=20
TRON_CONFIRMATION_DEPTH=32

# Risk policy
GLOBAL_TVL_CEILING_USD=1000000
PER_TX_WITHDRAWAL_CAP_USD=10000
DAILY_WITHDRAWAL_CAP_USD=100000
ORACLE_DEVIATION_PAUSE_BPS=500

# Runtime
POLL_INTERVAL_SECONDS=5
RUST_LOG=ace_defi_relayer=info
```

Production deployments should use secret managers, HSM-backed keys or multi-sig custody, and environment-specific policy files rather than raw private keys in `.env`.

## Testing Plan

### Unit Tests

```bash
cargo test -p ace-defi
cargo test -p ace-defi-relayer
```

Required test coverage:

- `ConvertIntent` canonical encoding and hash stability.
- Deposit idempotency.
- Withdrawal replay prevention.
- Relayer threshold verification.
- Slippage and `min_amount_out`.
- Expiry and refund path.
- Caps and circuit breakers.
- Oracle stale/deviation behavior.

### Contract Tests

```bash
cd ace-defi-contracts/evm
npm test
```

Required test coverage:

- ERC-20 deposit success.
- Mismatched token/amount rejection.
- Event canonical field correctness.
- Pause behavior.
- Recovery behavior under timelock/governance policy.
- No owner-only path that can silently drain ordinary user funds.

### Integration Tests

Integration tests should run against local ACE devnet plus external testnets or local forks.

Scenarios:

1. External deposit -> ACE mint.
2. ACE-internal swap only.
3. External deposit -> ACE swap -> Phase A relayer payout.
4. Failed swap due to `min_amount_out` -> refund.
5. Duplicate deposit submission -> idempotent no-op.
6. Duplicate withdrawal execution -> rejected.
7. Oracle deviation -> pause.
8. Withdrawal cap exceeded -> rejected before egress transfer.

### Simulation

Before mainnet beta, run economic and liquidity simulations:

- Volume/TVL turnover sensitivity.
- LP fee APY under 5, 10, 30, and 50% daily turnover.
- Directional flow imbalance and relayer pool depletion.
- Rebalancing cost by chain.
- Worst-case loss under each cap if relayer keys are compromised.

## Operational Monitoring

Minimum metrics:

- Pending deposits by chain and age.
- Pending withdrawals by chain and age.
- Processed deposit count and duplicate count.
- Withdrawal completion latency.
- Relayer signatures by operator.
- Egress wallet balances.
- Daily withdrawal volume vs cap.
- Oracle price deviation.
- Swap slippage distribution.
- Pool reserves and imbalance.

Minimum alerts:

- Deposit pending longer than finality policy plus margin.
- Withdrawal pending longer than execution SLA.
- Egress wallet below minimum balance.
- Oracle deviation above threshold.
- Sudden deposit spike.
- Repeated failed withdrawal execution.
- Any cap approaching 80%.
- Any relayer signing conflicting attestations.

## Troubleshooting

### Relayer Does Not See Deposits

Check:

1. Bridge contract address matches the configured chain.
2. RPC endpoint is synced and returning logs.
3. Confirmation depth has been reached.
4. Event fields match the expected ABI and canonical encoding.
5. The deposit was not already processed.

### ACE Does Not Mint Wrapped Assets

Check:

1. Threshold signature verification succeeded.
2. `deposit_id` is new.
3. Deposit event matches the committed `ConvertIntent`.
4. Source asset is registered and decimals are normalized.
5. Risk caps permit the mint.

### Withdrawal Is Not Executed

Check:

1. `WithdrawalRecord` exists and is finalized on ACE.
2. Record matches the committed `ConvertIntent`.
3. Per-tx, daily, chain, and global caps are not exceeded.
4. Egress wallet has sufficient balance.
5. Destination chain RPC is healthy.
6. The withdrawal was not already completed.

## Public Communication Rules

Use these phrases:

- "ACE-internal swaps are atomic."
- "External-chain ingress and egress are separate trust domains."
- "Phase A uses capped multi-sig custody for fast egress."
- "MEV-ACE mitigates proposer-controlled ordering MEV for admitted transactions."
- "LP yield depends on realized volume/TVL turnover."

Avoid these phrases:

- "Trustless bridge" for Phase A.
- "Zero MEV" without scope caveats.
- "No latency" for cross-chain flows.
- "18%+ APY" without turnover assumptions.
- "MVP production ready" before audit, caps, multi-sig, monitoring, and incident response exist.

## Roadmap

### Phase A: Capped Custodial Beta

- Implement `ConvertIntent`.
- Implement threshold relayer attestations.
- Implement deposit idempotency and withdrawal replay controls.
- Implement risk caps and circuit breakers.
- Implement audited minimal deposit contract.
- Implement multi-sig egress operations.
- Run testnet beta with low caps.

### Phase B: Non-Custodial Egress

- Materialize signed consensus/state-root proofs.
- Build destination-chain proof verifier.
- Add Merkle proof verification for `WithdrawalRecord`.
- Support relayer fronting plus proof-based reimbursement.
- Raise TVL cap only after this path is live and audited.

### Phase C: Verified Intent Binding

- Add sender-verifiable quote binding.
- Bind claim/release/refund to the exact `ConvertIntent`.
- Support HFI-Pay-style private recipient and refund semantics where applicable.
- Add high-value route policy requiring verified intent mode.

## Contribution Notes

- Treat `ACE_DEFI_SOLUTION.md` as the design source of truth.
- Do not add new promotional performance or APY claims without measured data or explicit assumptions.
- Any implementation PR touching ingress, egress, relayer signatures, caps, or custody must include tests for replay and failure recovery.
- Any Phase A deployment notes must include the capped custodial trust disclosure.

---

Document status: refreshed implementation plan
Last updated: 2026-06-10
Supersedes: old MVP README language
