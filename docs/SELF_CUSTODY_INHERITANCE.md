# Self-Custody Inheritance Without Surrendering Keys

Digital assets created a new ownership model, but they also exposed a hard lifecycle problem. A private key gives the holder direct control, yet that control can disappear with the holder. If the owner dies, becomes incapacitated, loses access, or faces a legal trigger, the assets may be unreachable forever. Traditional inheritance systems assume institutions, executors, courts, and recoverable accounts. Crypto self-custody assumes the opposite: whoever has the key controls the asset.

This design starts from that tension and frames it as a trilemma between private-key inheritance, self-custody, and yield generation.

## The Private-Key Inheritance Trilemma

Existing solutions usually let a user choose two of three goals:

- private-key inheritance: assets can be released after death, incapacity, or another real-world trigger without requiring the private key itself to be handed to a custodian;
- self-custody: the holder keeps control and avoids counterparty custody while active;
- yield generation: assets can continue earning returns instead of sitting idle in a static recovery contract.

Custodial inheritance services may solve transfer, but they require surrendering control or trusting a counterparty. Dead-man switch designs may create a future release path, but they often lock assets and sacrifice productive use. Manual legal arrangements may be valid on paper, but they can fail at the moment they matter most because the executor still cannot access the key.

The core claim is that this trilemma is not fundamental. Custody and orchestration can be separated.

## The Technical Shape

The design combines four mechanisms.

First, assets sit in an ERC-4626-compatible yield vault, so they can continue compounding instead of being locked in an inert inheritance contract. Principal and yield accounting are tracked so a release plan can coexist with ongoing productive custody.

Second, real-world release conditions are handled through a Chainlink CRE workflow. The workflow aggregates multiple independent sources before writing an on-chain attestation. In the whitepaper design, release depends on four checks rather than one oracle source: drand-related timing, vault balance, compliance screening, and price/oracle context.

Third, authority coordination is end-to-end encrypted. When a user configures a release plan, the client prepares encrypted packages for authorities using X25519, HKDF-SHA256, and ChaCha20-Poly1305. The platform routes these packages, but cannot read them. An authority can decrypt only with its own private key.

Fourth, the mechanism includes a drand timelock fallback. If the oracle path is unavailable for an extended period, the release package can be encrypted to a future drand round. When that round arrives, the drand network publishes the decryption material, allowing the release path to proceed without a human intermediary.

## No One Gets Unilateral Control

The design is valuable because no single participant can move assets alone.

The platform can register authorities, route trigger signals, query compliance APIs, and distribute encrypted packages. It cannot transfer assets unilaterally, decrypt release packages, write Chainlink CRE attestations, or bypass cooling-off periods.

Authorities can participate in legal-event release, but they receive encrypted packages and operate through on-chain attestation and dispute windows. They do not receive a user's private key.

The oracle network can write source-0 attestations only after the configured checks pass. If that path fails, the drand timelock fallback gives the system a cryptographic liveness route.

The user keeps custody while alive and active. The release path is prepared, but the private key does not need to be handed to the platform or to a custodian.

## Why This Matters To Users

This solves a very human problem. A hardware wallet is good at preventing theft, but it is bad at explaining to a family how assets should be transferred after death or incapacity. A legal will can express intent, but it cannot sign a blockchain transaction. A custodian can transfer assets, but that reintroduces counterparty risk.

The mechanism gives users a path where assets can remain self-custodied, continue earning yield, and still have a verifiable release process. That is not only a technical improvement. It makes crypto ownership more compatible with real life: families, estates, fiduciaries, institutions, charities, and DAOs need lifecycle rules, not just private keys.

## Why This Matters To The Industry

The industry has spent years improving wallets, but the inheritance problem remains underbuilt. This limits adoption by ordinary families and institutions. Large asset holders need continuity. DAOs need treasury transition rules. Families need beneficiary paths. Charities need conditional gifts. Institutions need auditable authority.

This turns inheritance from an off-chain service into a programmable asset-lifecycle primitive. The same mechanism can support family wealth transfer, DAO treasury continuity, legal-event unlocks, vesting, milestone releases, and compliant institutional workflows.

This is also strategically aligned with ACE's broader identity and authorization philosophy. The goal is not just "hold a key." The goal is to make digital ownership survivable, programmable, auditable, and usable across real-world events.

## Boundaries

This mechanism is not a replacement for legal advice, estate planning, audits, or jurisdiction-specific compliance. The MVP implementation has been completed in a related private codebase, but it has not yet been open-sourced into this public repository. The important point for ACE's project narrative is the protocol pattern: private keys do not need to be inherited directly for assets to have an inheritance path.

## Reference

- Source design reference: private self-custody inheritance protocol notes.
