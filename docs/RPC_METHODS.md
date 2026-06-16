# RPC Methods

ACE nodes expose JSON-RPC on port `18545` by default.

## Network Status

```bash
curl -s -X POST http://127.0.0.1:18545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"ace_getNetworkStatus","params":[],"id":1}'
```

Use this to confirm local height, observed network height, chain ID, and sync status.

## Public Peers

```bash
curl -s -X POST http://127.0.0.1:18545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"ace_getPublicPeers","params":[],"id":1}'
```

Returns public, dialable peers known to the node. Private and loopback addresses are filtered.

## Node Contribution

```bash
curl -s -X POST http://127.0.0.1:18545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"ace_getNodeContribution","params":[],"id":1}'
```

Shows the local node role and advertised non-consensus capabilities such as RPC, transaction relay, block relay, archive, light client provider, proof provider, indexer, or explorer backend.

## Validator Onboarding

```bash
curl -s -X POST http://127.0.0.1:18545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"ace_getValidatorOnboarding","params":[],"id":1}'
```

Reports the current validator admission policy. During testnet, full nodes are not automatically validators.

## Validator Candidate Check

```bash
curl -s -X POST http://127.0.0.1:18545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"ace_checkValidatorCandidate","params":[],"id":1}'
```

Performs a local preflight check for validator candidate configuration. Passing this check does not grant validator rights by itself.
