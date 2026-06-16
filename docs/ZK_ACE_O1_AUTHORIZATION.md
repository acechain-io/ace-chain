# ZK-ACE Authorization Compression

Blockchains usually scale execution and forget that verification also has a scaling problem. If a block contains `n` transactions, every full verifier is asked to check `n` authorizations. More transactions mean more signatures, more public keys, more bytes, more CPU, and more repeated work for validators, RPC providers, indexers, auditors, and light clients.

ZK-ACE changes the direction of that cost curve. The goal is to make authorization verification approach O(1) for a batch or block.

## The Traditional Cost Shape

In the traditional model, verification looks like this:

```text
verify(tx_1)
verify(tx_2)
verify(tx_3)
...
verify(tx_n)
```

That is acceptable when blocks are small and signatures are compact. It becomes expensive when throughput rises. It becomes worse in a post-quantum setting because ML-DSA-44 credentials are much larger than classical signatures.

This affects more than validators. Indexers that want to independently verify data pay the cost. Light-client services need heavier infrastructure. RPC providers carry more CPU and bandwidth. Auditors must process more raw material. The ecosystem becomes more centralized because independent verification is more expensive.

## What ZK-ACE Proves

ZK-ACE is designed to move the expensive authorization logic into a proof. Instead of asking every verifier to repeat every authorization check, the prover demonstrates that the batch satisfied the required constraints.

Those constraints include:

- identity binding: the authorization belongs to the claimed ACE identity;
- transaction binding: the proof is tied to the exact transaction payload or batch;
- anti-replay rules: the same authorization cannot be reused in an invalid context;
- algorithm abstraction: the authorization layer can support classical and post-quantum credentials;
- state compatibility: the verified identity is what the execution layer receives.

The verifier then checks a compact proof. The verification path becomes:

```text
verify(one proof for the batch)
```

Proving still requires work. The gain is that verification becomes cheaper, more predictable, and less sensitive to transaction count.

## Why O(n) To O(1) Is A Big Deal

The change from O(n) to O(1)-style authorization verification is not just a performance optimization. It changes who can afford to verify the chain.

If verification cost grows linearly forever, high-throughput chains become harder for independent operators to follow. If post-quantum signatures are added directly to that model, the pressure gets worse. ZK-ACE gives ACE a path where users can get stronger authorization while verifiers see a compact proof interface.

That opens up capabilities that are difficult under linear verification:

- high-throughput post-quantum payments;
- cheaper independent RPC and archive infrastructure;
- practical light-client verification;
- proof-provider services;
- privacy-preserving authorization flows;
- cross-VM authorization that does not expose every underlying credential to every downstream verifier.

## How It Fits With n-VM

The n-VM architecture benefits directly from ZK-ACE because VM engines do not need to embed signature-scheme complexity. EVM, SVM, BVM, TVM, Move-style execution, and ACE-native execution can all receive an authenticated identity after the authorization layer has done its job. This keeps VM integration cleaner and makes future cryptographic upgrades less disruptive.

In other words, ZK-ACE is not a side feature. It is part of the reason ACE can support many execution environments and post-quantum authorization without forcing every VM to become a cryptography migration project.

## User And Industry Value

For users, ZK-ACE means stronger authorization can be used without making every application slower or more expensive. For developers, it means applications can build against a stable authenticated identity interface. For infrastructure providers, it lowers the cost of verification and makes independent services more viable.

At the industry level, this is the more important point: post-quantum migration cannot simply multiply every node's workload and still expect broad decentralization. ZK-ACE gives ACE a route to keep authorization strong while compressing the burden placed on the network.

## References

- ACE ZK-ACE paper: `docs/papers/04-2603.07974v3-ZK-ACE.pdf`.
- ACE Runtime paper: `docs/papers/13-2603.10242v1-ACE-Runtime.pdf`.
- ACE whitepaper: `docs/whitepaper/WHITEPAPER.pdf`.
