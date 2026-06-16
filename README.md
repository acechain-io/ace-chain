# ACE Chain Testnet Node

[![Pre-testnet](https://img.shields.io/badge/pre--testnet-live-2ea44f)](https://testnet.acechain.io)
[![License](https://img.shields.io/badge/license-see_LICENSE-blue)](LICENSE)
[![Security](https://img.shields.io/badge/security-policy-purple)](SECURITY.md)
[![Contributing](https://img.shields.io/badge/contributions-welcome-orange)](CONTRIBUTING.md)
[![Technical Community](https://img.shields.io/badge/join-technical_community-5865F2)](CONTRIBUTING.md)

[Website](https://acechain.io) · [Testnet](https://testnet.acechain.io) · [Discussions](https://github.com/acechain-io/ace-chain/discussions) · [Issues](https://github.com/acechain-io/ace-chain/issues) · [Email](mailto:contact@acechain.io)

ACE Chain is a post-quantum-ready Layer-1. This public repository is packaged so that an external operator can build and run a non-validator full node that joins the ACE testnet.

The bundled Docker image runs as a full node by default: it syncs blocks, serves local JSON-RPC, participates in P2P relay, and does not vote or produce blocks.

A public pre-testnet dashboard is available at [testnet.acechain.io](https://testnet.acechain.io). Click `Classic` or `PQC` to start a 10-minute load test and inspect the signatures included in every transaction in each block. Because this is a pre-testnet environment, if the dashboard or nodes become unstable, use the restart button in the chart's upper-right corner to restart the test nodes.

## Start A Full Node and Join the Network

Requirements:

- Docker Desktop or Docker Engine
- Open outbound network access
- TCP port `31333` reachable from the internet if you want the node to be discoverable by other peers

Build the image from this repository:

```bash
docker build -t acechain/ace-node:fullnode .
```

Start the node:

```bash
docker run -d --name ace-node \
  -p 18545:18545 \
  -p 31333:31333 \
  -v ace-node-data:/data \
  -e ACE_PUBLIC_NODE_REGISTRY_URL=https://devnet.acechain.io \
  -e ACE_PEER_DISCOVERY_RPC_URLS=https://devnet.acechain.io/rpc \
  acechain/ace-node:fullnode
```

The image includes:

- `/config/genesis.json` from `networks/testnet/genesis.json`
- `/config/node.json` from `networks/testnet/node.example.json`
- `validator: false`
- bootstrap peer `/dns4/bootnode.testnet.acechain.io/tcp/31333`

## Check Sync

Watch logs:

```bash
docker logs -f ace-node
```

Check local RPC:

```bash
curl -s -X POST http://127.0.0.1:18545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"ace_getNetworkStatus","params":[],"id":1}'
```

Check connected public peers:

```bash
curl -s -X POST http://127.0.0.1:18545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"ace_getPublicPeers","params":[],"id":1}'
```

## Restart Or Reset

Restart without deleting synced data:

```bash
docker restart ace-node
```

Reset local chain data and resync from testnet:

```bash
docker rm -f ace-node
docker volume rm ace-node-data
```

Then run the start command again.

## What This Node Contributes

A public full node can contribute RPC access, transaction relay, block relay, public peer discovery, and archive/indexing services depending on how it is configured and exposed.

It does not participate in consensus, does not vote, does not produce blocks, and does not increase validator quorum. Validator participation is permissioned during the current testnet phase.

## Core Features And Advantages

### Post-Quantum Performance Without The Usual TPS Penalty

Post-quantum cryptography usually comes with an uncomfortable bargain: stronger long-term security, but larger signatures, heavier verification, and lower effective throughput.

ACE is built to avoid making that bargain the default. The chain separates identity from authorization, treats Ed25519 and ML-DSA-44 as interchangeable authorization algorithms, and keeps expensive cryptographic work away from the dominant execution path wherever the protocol can safely do so. In current devnet measurements, Ed25519 reached about 581.8 sustained TPS with a 794.5 peak, while ML-DSA-44 reached about 574.5 sustained TPS with a 769 peak under the same chain configuration.

That is the practical point: applications can begin using post-quantum authorization without turning the product into a slow "security mode." For long-lived assets, custody, RWA, treasury systems, and high-value DeFi accounts, PQC becomes something teams can deploy before the migration crisis arrives.

Read more: [Post-quantum performance](docs/POST_QUANTUM_PERFORMANCE.md)

### MEV-ACE Fair Ordering For User-Protective DeFi

MEV is best understood as execution quality leaking out of the application and into the ordering layer. Users see it as worse fills. Market makers see it as wider risk margins. Wallets and aggregators see it as a harder promise of best execution. Public research has measured hundreds of millions of dollars in extracted value from Ethereum CEX-DEX arbitrage alone, while sandwich research shows that even private routing is not a complete answer.

MEV-ACE focuses on the part a chain can actually control: insertion, reordering, and omission by the block-production path. It does not claim to remove every external arbitrage opportunity, but ACE-native DeFi routes can reduce the block-local manipulation surface that makes many sandwich and front/back-running patterns possible. The beneficiaries are not abstract: traders, market makers, wallets, aggregators, and protocols all get a fairer execution venue.

Read more: [MEV-ACE fair ordering](docs/MEV_ACE_FAIR_ORDERING.md)

### N-VM Shared State Tree: One Ledger For Many Execution Worlds

ACE is not trying to be only another EVM-compatible chain. Its N-VM design lets Native, EVM, SVM, BVM, TVM, and Move-style execution live above one L1 state model.

The important part is the shared state tree: VM domains are not separate islands joined later by bridges, but execution environments that can settle into the same ledger, identity layer, asset model, and finality path.

Developers can still use familiar programming models, but users should not have to manage five fragmented balance sheets. Solidity contracts, Solana-style programs, Bitcoin-like payment flows, Move-style assets, and ACE-native applications can all compose around one settlement base. That reduces duplicated liquidity, duplicated integrations, and duplicated user onboarding.

Read more: [N-VM shared state tree](docs/NVM_SHARED_STATE_TREE.md)

### OMNILIQUID And oAssets: Unified Cross-Chain Liquidity

Cross-chain DeFi often fragments the same economic asset into many wrappers, many pools, and many bridge-specific risk buckets.

OMNILIQUID takes the opposite approach: deposits from supported external chains map into canonical oAssets on ACE, with reserve accounting tracking the backing and withdrawal obligations. A USDT deposit from one chain and a USDT deposit from another chain can feed the same canonical liquidity surface instead of competing as separate wrappers.

Users get simpler routing and better depth; protocols avoid bootstrapping the same pool repeatedly; market makers can deploy capital against aggregated demand. The valuable primitive is unified liquidity, not another isolated AMM.

ACE's goal is shared liquidity without unbounded shared risk: assets, external mappings, markets, routes, relayers, and oracle feeds should have explicit risk compartments so one failure domain does not silently become every application's failure domain.

Read more: [OMNILIQUID and oAssets](docs/OMNILIQUID_OASSET_LIQUIDITY.md)

### ZK-ACE: From O(n) Authorization Verification To O(1)

Most chains make every verifier repeat the same authorization work: one more transaction means one more signature, one more public key check, more bandwidth, and more CPU.

ZK-ACE changes the shape of that problem. Instead of asking validators, RPC nodes, indexers, and light clients to re-check every authorization forever, ACE moves toward compact proofs that attest to the validity of an entire batch or block. That is the strategic shift from O(n) authorization verification to O(1)-style verification.

The impact becomes larger in a post-quantum setting because ML-DSA-44 credentials are much larger than classical signatures. ZK-ACE makes stronger authorization compatible with cheaper independent verification, practical proof-provider services, and lighter clients.

Read more: [ZK-ACE authorization compression](docs/ZK_ACE_O1_AUTHORIZATION.md)

### Lightweight Nodes And Low Compute Cost

ACE is designed so useful nodes do not need to become expensive hardware projects.

The chain moves heavy repeated authorization verification away from every verifier, keeps BFT votes off-chain instead of consuming transaction capacity, and treats proof generation as a specialized pipeline rather than a requirement for every full node. Internal devnet materials already show the direction: a 3-node BFT network has run on commodity servers and laptop-class hardware, while the public full node image is intended to sync, relay, and serve RPC without validator-grade equipment.

The business consequence is important: lower node cost means more operators can participate, more regions can host infrastructure, and public RPC/archive/indexer services become economically easier to run. Decentralization is not only a governance claim; it depends on whether ordinary operators can afford to stay online.

Read more: [Lightweight hardware nodes](docs/LIGHTWEIGHT_HARDWARE_NODES.md)

### Self-Custody Inheritance Without Surrendering Keys

Digital assets have a practical private-key inheritance problem: if only the holder controls the private key, assets may become inaccessible after death, incapacity, or a legal trigger; if a custodian controls the key, self-custody is lost; if a dead-man switch locks assets, yield generation and flexibility are often sacrificed.

ACE treats this as a trilemma between private-key inheritance, self-custody, and yield generation, then turns it into a protocol problem. The design pattern combines yield-bearing vault custody, multi-source real-world attestation, end-to-end encrypted authority packages, and cryptographic timelock fallback so no platform, authority, or oracle has unilateral control.

For users, this means assets can remain self-custodied, continue earning yield, and still have a verifiable release path when real-world events occur. For the industry, it moves inheritance from a custodial service into a programmable asset-lifecycle primitive.

Read more: [self-custody inheritance](docs/SELF_CUSTODY_INHERITANCE.md)

## Join The Technical Community

ACE Chain is actively looking for serious technical contributors now: protocol engineers, cryptographers, security researchers, distributed-systems engineers, VM builders, DeFi developers, infrastructure operators, and protocol economists.

The project is still early enough for deep technical work to matter. Contributors can help shape architecture, implement core protocol components, operate and harden the testnet, maintain public infrastructure, improve documentation, and build the first ecosystem integrations.

If you can contribute to consensus, networking, RPC, N-VM execution, MEV-ACE, ZK-ACE, OMNILIQUID, public nodes, tooling, security, or long-term protocol maintenance, start with [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- [Full node operation](docs/FULL_NODE_OPERATION.md)
- [Public node registry and discovery](docs/PUBLIC_NODE_DISCOVERY.md)
- [RPC methods](docs/RPC_METHODS.md)
- [Validator admission](docs/VALIDATOR_ADMISSION.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Architecture overview](docs/ARCHITECTURE_OVERVIEW.md)
- [Whitepaper](docs/whitepaper/WHITEPAPER.pdf)
- [Research papers](docs/papers/)

## Repository Layout

| Path | Purpose |
| --- | --- |
| `ace-node/` | Node binary, orchestration, sync, registry and validator admission logic |
| `ace-p2p/` | P2P networking, gossip, request-response sync |
| `ace-rpc/` | JSON-RPC methods |
| `ace-runtime/` | Protocol types, authorization and proof interfaces |
| `ace-model/` | State, accounts, blocks and persistence |
| `networks/testnet/` | Public testnet genesis and node template |
| `docs/` | Public documentation |

## License

See [LICENSE](LICENSE).
