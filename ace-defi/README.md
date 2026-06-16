# ACE DeFi

ACE DeFi is the cross-chain liquidity and bridge prototype for ACE Chain. The current repository state provides the **Phase A protocol foundation** for capped testnet liquidity flows, reserve accounting, relayer admission, and controlled ingress/egress validation.

## Read This First

- `ACE_DEFI_SOLUTION.md` is the product and security design source of truth.
- `ACE_DEFI_CROSSCHAIN_IMPLEMENTATION.md` is the implementation plan and engineering checklist.
- The Rust crate implements the ACE-side bridge, swap, intent, withdrawal, and `CrossVmSettle` foundations.
- `ace-defi-relayer` contains Phase A relayer signing/checkpoint scaffolding; real external-chain RPC decoding and real egress execution remain fail-closed unless explicitly implemented.
- `ace-defi-contracts/ethereum` contains the Ethereum deposit contract and Hardhat tests.

## Phase A Baseline

Implemented foundations:

- Governance-bound relayer admission in `BridgeState`.
- State-backed genesis relayer allowlist for `ace_submitDeposit`.
- `ConvertIntent` and deterministic `intent_id` validation.
- Deposit and withdrawal records whose hashes bind the committed intent.
- Consensus-backed withdrawal index for `ace_getPendingWithdrawals`.
- Intent-aware Ethereum deposit events and deposit IDs.
- Relayer checkpoint storage for restart-safe idempotency.
- Scheduler guard that keeps `CrossVmSettle` transactions globally serialized.

Important limits:

- Phase A egress is capped custodial relayer payout, not proof-verified release.
- AMM pools are in-memory runtime state; `CrossVmSettle` requires pre-initialized pools and fails closed otherwise.
- MEV-ACE mitigates proposer-controlled ordering MEV for admitted ACE transactions; it does not remove information-based MEV or cross-domain arbitrage.
- LP APY depends on realized volume/TVL turnover and is not fixed.

## Risk Compartments

ACE DeFi uses a compartmentalized shared-liquidity model. Liquidity can be shared through canonical oAssets and common settlement, while operational risk remains scoped to explicit domains: canonical assets, external asset mappings, withdrawal routes, relayer sets, oracle feeds, liquidity pools, and ACE Liquid markets.

The current code exposes deterministic risk-compartment identifiers for canonical assets and external mappings, and ACE Liquid derives market-level compartments. Existing controls such as `active`, `mint_enabled`, `withdraw_enabled`, daily limits, reserve invariants, and market `active` flags are the first enforcement layer for making failures local, auditable, and containable.

## Production Rollout Path

As liquidity scales, the rollout path adds threshold relayer quorum, production external-chain RPC/log decoding, hardened egress execution, caps and circuit breakers, monitoring and incident response, audits, and Phase B proof-verified egress.
