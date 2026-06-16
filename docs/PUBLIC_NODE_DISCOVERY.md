# Public Node Registry And Discovery

ACE testnet supports a simple off-chain public node registry so full nodes can become discoverable before a full on-chain node registry is enabled.

## Registration Flow

1. A full node starts with `ACE_PUBLIC_NODE_REGISTRY_URL`.
2. The node posts its peer metadata to `/api/public-nodes/register`.
3. The portal stores active public nodes with a freshness window.
4. The portal nodes page and `/api/public-nodes` endpoint expose currently active public nodes.

The registry is advisory. Validators and full nodes still verify chain data and transactions independently.

## Discovery Flow

1. A node starts with `ACE_PEER_DISCOVERY_RPC_URLS`.
2. It calls `ace_getPublicPeers` on validator or public RPC endpoints.
3. It also reads registered public nodes from the portal registry when `ACE_PUBLIC_NODE_REGISTRY_URL` is configured.
4. It dials reachable public multiaddrs automatically.

## Public Address Rules

Private, loopback, link-local, and unspecified IP addresses are filtered from public peer listings. Public nodes should expose a reachable P2P address on TCP `31333`.

If automatic address inference is not enough, set:

```bash
ACE_PUBLIC_NODE_MULTIADDR=/ip4/YOUR_PUBLIC_IP/tcp/31333
```

The node identity peer ID is appended by the node or registry when enough information is available.

## Security Boundary

Public node discovery does not grant consensus rights. A registered public node can relay and serve data, but it cannot vote or produce blocks unless admitted into the validator set by the validator admission process.
