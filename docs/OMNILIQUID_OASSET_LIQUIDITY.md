# OMNILIQUID And oAssets: Unified Liquidity Across N-VM Execution

Cross-chain DeFi usually solves movement before it solves liquidity. A bridge can move a token from one chain to another, but it often leaves the ecosystem with yet another wrapper, another pool, another accounting surface, and another operational risk bucket. The same economic asset becomes fragmented across source chains, bridge issuers, application environments, and market venues.

OMNILIQUID is ACE's answer to that fragmentation. It combines canonical oAssets, reserve accounting, N-VM execution, ACE Liquid markets, and the shared state tree so external liquidity can enter ACE once and then be used across multiple execution environments without becoming a new wrapper for every VM.

The important distinction is this: OMNILIQUID is not only a bridge. It is a liquidity coordination layer built on ACE's execution model.

## The Core Idea

An oAsset is the canonical ACE-side representation of an external economic asset. Ethereum USDT, BSC USDT, and other supported USDT representations do not need to become unrelated liquidity objects inside ACE. They can map into one canonical asset such as `oUSDT`.

In code, this is represented by the `CanonicalAssetRegistry`, `CanonicalAsset`, `ExternalAssetMapping`, and deterministic `oasset_mint_id`. External assets keep their source-chain identity and decimal model, but users and applications interact with the canonical oAsset once the deposit is accepted.

This gives ACE three separable layers:

1. external asset mappings, which describe source-chain assets and bridge parameters;
2. canonical oAssets, which users and protocols use inside ACE;
3. reserve accounting, which tracks backing, minted supply, pending withdrawals, completed releases, and safety buffers.

That structure matters because it makes liquidity legible. Operators can see which external assets back a canonical asset, how much supply is active, what is pending withdrawal, and whether reserves still satisfy protocol invariants.

## Why N-VM And Shared State Tree Matter

OMNILIQUID becomes more powerful because oAssets are not attached to only one execution environment. On ACE, canonical oAssets live in the shared state tree. EVM contracts, SVM-style programs, Move-style asset logic, TVM flows, BVM-style payment logic, ACE Native modules, AMMs, and order-book markets can all settle against the same underlying asset representation.

That changes the meaning of cross-chain liquidity. In a conventional multi-VM design, each VM can still end up with its own balance sheet, wrapper, bridge adapter, and liquidity pool. The chain may support many execution environments, but liquidity remains fragmented because every environment effectively owns a separate asset surface.

ACE avoids that pattern. The N-VM dispatcher routes execution to the correct engine, but resulting writes reconcile into one state model. OMNILIQUID uses that shared state model to make oAssets available across execution styles without forcing users, protocols, or market makers to bridge between VM-specific ledgers.

The business impact is direct: one canonical `oUSDT` surface can serve Solidity contracts, Solana-style programs, Move-style resource logic, payments, ACE-native DeFi, AMM pools, and ACE Liquid markets. Protocols build against the same liquidity base. Market makers quote against aggregated demand. Users move through applications without managing separate wrapped balances.

## Deposit: External Asset To Canonical oAsset

The deposit path converts verified external liquidity into canonical ACE liquidity.

At the product and contract layer, an EVM gateway accepts whitelisted assets, enforces caps and pause controls, emits an ACE-bound deposit event, and binds the deposit to an `intent_id` and ACE recipient. Relayers or future proof paths observe that event and submit a signed deposit record to ACE.

At the ACE protocol layer, `process_deposit_to_oasset` verifies the relayer against the state-approved set, rejects duplicate deposits, checks whether minting is enabled, applies risk limits, normalizes decimals, records reserve backing, and mints the canonical oAsset to the recipient.

That is the key transition:

```text
External USDT deposit
  -> verified deposit record
  -> external asset mapping
  -> reserve accounting
  -> canonical oUSDT mint
  -> shared state tree balance
```

After this point, the user does not hold "Ethereum bridge USDT" or "BSC bridge USDT" as separate internal products. The user holds the canonical ACE-side asset. That is what makes routing, trading, settlement, and accounting cleaner.

## Trade: One Asset Surface For AMM And ACE Liquid

Once an oAsset is minted, it can be used by ACE DeFi and ACE Liquid as a normal asset inside the shared state tree.

The current `ace-defi` tests already exercise the important property: deposits from multiple external assets can mint the same `oUSDT`, and the resulting oAsset mint can back swap pools. This means liquidity is not trapped in per-chain wrappers before it reaches trading venues.

ACE Liquid extends the same idea to deterministic order-book markets. Its CLOB is not a separate off-chain exchange bolted onto the side. Market metadata, orders, price ladders, order queues, and per-user collateral balances are persisted in the StateTree under per-market accounts. Deposits and withdrawals bridge the global token ledger into market collateral, while matching itself is deterministic in-market state transition.

That design gives ACE two useful properties at the same time:

1. global oAsset liquidity can be shared by applications and markets;
2. per-market order-book execution can remain deterministic and parallelizable because each market mutates its own account state.

In practical terms, `oUSDT` can be the quote asset for an AMM pool, a CLOB market, an EVM-facing application, or a future Move-style asset module without creating four versions of USDT.

## Withdraw: Canonical oAsset Back To External Reserve Asset

Withdrawal reverses the direction while preserving accounting.

When a user wants to exit, `request_oasset_withdrawal` burns or escrows the canonical oAsset, checks the target external mapping, applies withdrawal risk limits, normalizes the amount back to the target asset's decimals, reserves the backing amount, and indexes a withdrawal record. A relayer or later proof-verified release path completes the external transfer and submits completion evidence.

The lifecycle is explicit:

```text
canonical oAsset balance
  -> withdrawal request
  -> reserve lock
  -> oAsset supply reduction
  -> indexed withdrawal record
  -> external-chain release
  -> reserve finalization
```

This is not cosmetic accounting. It is the mechanism that lets users, operators, and auditors reason about whether canonical supply is backed, what is pending, and which external reserve asset must satisfy a withdrawal.

## Risk Controls Are Part Of The Product

Unified liquidity is valuable only if the accounting is conservative. The current implementation includes risk tiers, mint and withdrawal enable flags, single-deposit limits, single-withdrawal limits, daily limits, finality parameters, relayer approval, duplicate-deposit rejection, withdrawal indexing, and reserve invariants.

The product layer in the OmniLiquid system reflects the same discipline. It includes gateway event indexing, lifecycle state for deposits and withdrawals, relayer heartbeat tracking, reconciliation workers, incident creation, admin asset controls, risk dashboards, support search, Prometheus metrics, Grafana provisioning, deployment checklists, and incident runbooks.

That matters commercially because liquidity infrastructure is not just a smart contract. It is an operating system for asset movement. If something is pending too long, capped, paused, under-reserved, or waiting for release, operators need to see it quickly and users need an explainable state transition.

## Compartmentalized Shared Liquidity

OMNILIQUID's design goal is shared liquidity without unbounded shared risk.

The model is to share liquidity at the asset and settlement layer, while keeping risk bounded at the canonical asset, external mapping, market, pool, route, oracle, and relayer layer. In code, these domains are represented as deterministic risk compartments. A canonical oAsset has one compartment; each external asset mapping has its own compartment; ACE Liquid markets derive their own market compartment.

This matters because shared liquidity creates real correlation. If every application uses the same canonical `oUSDT`, a reserve-accounting error in that asset is systemic to `oUSDT`. The protocol should not pretend otherwise. Instead, it should make the failure domain explicit, auditable, and controllable: one external mapping can be paused without disabling a sibling mapping, one market can be stopped without halting unrelated markets, and one withdrawal route can be constrained without freezing internal ACE trading.

The practical benefit is a better balance between depth and safety. Users and market makers get a deeper shared liquidity surface. Operators and auditors get compartment identifiers, local pause controls, caps, reserve invariants, and market-level state boundaries. Frontends can compete on user experience and routing, while the shared backend remains inspectable as protocol infrastructure rather than a closed application service.

## Trust Boundaries

ACE's strongest guarantee applies inside ACE's own execution boundary.

Inside ACE, oAssets live in the shared state tree, N-VM execution settles against one ledger, AMM and CLOB operations become deterministic state transitions, and MEV-ACE can constrain proposer-controlled ordering abuse for admitted ACE transactions.

External-chain ingress and egress remain separate trust domains. A source-chain deposit still depends on external finality and either relayer attestation or a future proof path. A destination-chain release in Phase A still depends on capped, monitored relayer execution and gateway custody controls. Phase B can reduce this trust with proof-verified egress, but the correct current claim is narrower: ACE removes bridge-like fragmentation and asynchronous message passing inside ACE; it does not pretend external chains stop being external trust domains.

This boundary is important. It is what makes the architecture credible.

## Why This Improves Liquidity

OMNILIQUID improves liquidity by removing redundant internal asset surfaces.

Without canonical oAssets, Ethereum USDT, BSC USDT, and another bridge's USDT each need their own pools, routes, risk parameters, market integrations, and accounting logic. Market makers split inventory. Protocols subsidize redundant liquidity. Users are forced to understand which wrapper is liquid, safe, and accepted.

With OMNILIQUID, supported external assets can feed the same canonical liquidity surface. One oAsset can be used across N-VM applications, AMM pools, ACE Liquid markets, payments, and future execution modules. Liquidity can be routed to the place where it is useful without asking the user to become a bridge operator.

The result is a better economic surface:

- deeper effective liquidity for users;
- fewer redundant pools for protocols;
- simpler quoting for market makers;
- clearer reserve accounting for operators;
- cleaner integrations for wallets, indexers, and explorers;
- less fragmentation across VM and chain boundaries.

## Why This Is A Business Primitive

The next stage of cross-chain DeFi should not be "more wrappers." It should be fewer user-visible asset versions, deeper liquidity, clearer reserves, and better execution.

OMNILIQUID gives ACE a way to turn cross-chain complexity into a product advantage. Users interact with one asset surface. Developers build against one canonical liquidity base. Market makers quote against aggregated demand. Operators monitor reserve and lifecycle state directly. N-VM applications compose around the same ledger instead of rebuilding liquidity in each execution environment.

That is a stronger commercial story than launching another isolated AMM or bridge. It positions ACE as a cross-chain liquidity coordination layer where external assets enter once, settle inside a shared state tree, and become usable across many execution worlds.

## Current Status

The current codebase provides the Phase A protocol foundation for OMNILIQUID: enough to demonstrate the canonical oAsset model, reserve accounting, deterministic ACE-side settlement, and controlled external-chain ingress/egress flows.

Implemented foundations include canonical asset registration, external asset mappings, deterministic oAsset mint IDs, decimal normalization, reserve positions, canonical supply accounting, deposit-to-oAsset minting, oAsset withdrawal records, risk checks, relayer approval, pending withdrawal indexing, AMM pool usage, ACE Liquid deterministic market primitives, and EVM gateway deposit and release controls.

The companion product layer extends this foundation with gateway event indexing, deposit and withdrawal lifecycle tracking, relayer heartbeat visibility, reconciliation workflows, operator controls, metrics, dashboards, deployment checklists, and incident workflows. Those components are part of the practical rollout path from protocol primitive to operated liquidity network.

The strategic point is that the technical shape is already present: canonical assets, reserve accounting, shared-state liquidity, N-VM access, deterministic trading, and an operational product layer.

## References

- ACE DeFi design: `ace-defi/ACE_DEFI_SOLUTION.md`.
- Cross-chain implementation plan: `ace-defi/ACE_DEFI_CROSSCHAIN_IMPLEMENTATION.md`.
- oAsset tests: `ace-defi/tests/omni_oasset_tests.rs`.
- ACE Liquid CLOB: `ace-liquid/src/clob.rs`.
- ACE Liquid StateTree market state: `ace-liquid/src/state.rs`.
