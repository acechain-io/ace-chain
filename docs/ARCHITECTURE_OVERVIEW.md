# Architecture Overview

ACE Chain is a Rust Layer-1 stack built around identity and authorization separation, post-quantum-ready credentials, ZK authorization compression, and native multi-VM execution.

## Main Components

| Path | Responsibility |
| --- | --- |
| `ace-node/` | Node orchestration, sync, validator admission, public node registry tasks |
| `ace-p2p/` | P2P transport, gossip, block sync, peer management |
| `ace-rpc/` | JSON-RPC surface |
| `ace-mempool/` | Transaction admission, duplicate suppression, relay guards |
| `ace-consensus/` | Validator set, voting and block finality logic |
| `ace-runtime/` | Protocol types, authorization and proof interfaces |
| `ace-model/` | Accounts, blocks, state and persistence |
| `ace-n-vm/` | Native, EVM, SVM, BVM, TVM and Move dispatch |

## Runtime Direction

The protocol is designed around an attest-execute-prove pipeline:

1. admit and attest transactions on the fast path
2. execute against the current state
3. relay compact transaction data where possible
4. verify finality proofs separately from per-transaction authorization checks

## Public Full Node Layer

The public full node layer is intended to provide:

- broader P2P reachability
- public RPC capacity
- transaction relay
- block relay
- archive and indexer backends
- light client and proof-provider services

These services expand network utility without granting consensus power.
