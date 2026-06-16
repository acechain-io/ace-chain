# Post-Quantum Performance Without The Usual TPS Penalty

Post-quantum signatures are usually treated as a future security upgrade with an obvious performance cost. That assumption is reasonable for most chain designs. ML-DSA-44 signatures are much larger than Ed25519 signatures, the public keys are larger, and verification is materially heavier at the primitive level. If a blockchain simply replaces every existing signature with a post-quantum signature and keeps the rest of the pipeline unchanged, throughput drops, bandwidth rises, and node requirements become worse.

ACE is designed around a different question: can the chain support post-quantum authorization without making the VM, mempool, and block path pay the full cost in the most expensive place?

## What ACE Changes

ACE separates account identity from the signing algorithm. The account identity is an identity commitment; the authorization key is a replaceable credential attached to that identity. A user can authorize with Ed25519 today and ML-DSA-44 later without changing the account's on-chain identity or moving assets. That single design decision removes one of the largest migration costs in traditional chains: the address does not have to be the public key.

The execution layer then receives an already authenticated account identity. It does not need to care whether the transaction was authorized with Ed25519, ML-DSA-44, or a later supported algorithm. This keeps EVM, SVM, BVM, TVM, Move-style execution, and ACE-native logic from becoming entangled with signature-scheme migration.

The pipeline also avoids repeated expensive work:

- RPC admission can verify a full credential before mempool insertion.
- The mempool can carry preverified transaction state instead of redoing all checks.
- Gossip and relay paths can avoid turning large PQC credentials into unnecessary repeated network load.
- Block execution can batch and parallelize cryptographic verification.
- ZK-ACE provides a longer-term path to aggregate authorization validity.

The point is not that ML-DSA-44 is faster than Ed25519. It is not. The point is that ACE changes the system architecture so primitive verification latency is less likely to dominate end-to-end throughput.

## Current Devnet Measurements

In current devnet measurements on the same chain configuration:

| Authorization mode | Sustained TPS | Peak TPS |
| --- | ---: | ---: |
| Ed25519 | ~581.8 | ~794.5 |
| ML-DSA-44 | ~574.5 | ~769 |

These numbers should be read as an end-to-end system measurement, not as a primitive cryptography benchmark. Ed25519 verification remains much faster at the cryptographic operation level. What the measurement shows is more useful for application builders: the live chain pipeline can run ML-DSA-44 transactions in the same practical throughput class as classical Ed25519 transactions under the tested conditions.

## Why This Matters To Users

For users, post-quantum security should not feel like switching into a slow, expensive, special-purpose mode. A wallet should be able to protect important accounts with stronger authorization while applications continue to behave like normal applications. That matters most where assets have long-term value: custody, RWA, treasury accounts, government or institutional records, and high-value DeFi positions.

It also changes the migration story. Existing chains that bind addresses directly to signature schemes face difficult ecosystem coordination when they migrate. Wallets, contracts, indexers, explorers, exchanges, custody systems, and users all have to adapt. ACE's identity-authority split makes migration a controlled account-level operation rather than a chain-wide identity rewrite.

## Why This Matters To The Industry

Post-quantum migration is not only a cryptography issue. It is an infrastructure continuity issue. If a chain can support stronger cryptography only by cutting throughput or raising node requirements sharply, the network becomes harder to use and harder to decentralize. ACE's advantage is that it treats PQC as a systems-design problem from the start.

That creates a credible path for applications that cannot wait for the rest of the industry to coordinate a multi-year migration. Developers can deploy familiar contracts and applications on ACE while giving users a post-quantum authorization option at the account layer.

## Boundaries

ACE's devnet measurements are not a universal performance guarantee. Workload shape, block size, RPC submission pattern, network conditions, state growth, and validator hardware all matter. The defensible claim is narrower and stronger: ACE demonstrates that post-quantum authorization can be integrated without becoming the obvious throughput bottleneck in the current pipeline.

## References

- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard, 2024, https://csrc.nist.gov/pubs/fips/204/final.
- ACE throughput note: `docs/2026-05-23-pqc-ed25519-throughput-analysis.md`.
- ACE whitepaper: `docs/whitepaper/WHITEPAPER.pdf`.
