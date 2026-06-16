# Full Node Operation

This guide explains how the public full node image behaves after it starts.

## Default Mode

The public Docker image runs `ace-node` with:

- `validator: false`
- RPC bound to `0.0.0.0:18545`
- P2P bound to `0.0.0.0:31333`
- testnet genesis from `/config/genesis.json`
- chain data stored under `/data`

The node can sync, verify, relay blocks and transactions, and serve local JSON-RPC. It cannot vote or produce blocks.

## Ports

| Port | Protocol | Purpose |
| --- | --- | --- |
| `18545` | HTTP JSON-RPC | Local wallet, explorer, and operator queries |
| `31333` | TCP P2P | Peer connections, block sync, gossip, relay |

For a public node, expose `31333/tcp` from the host or cloud firewall. If `31333` is not reachable, the node can still connect outbound to validators, but other peers may not be able to dial it.

## Persistent Data

Use a Docker volume for `/data`:

```bash
docker run -d --name ace-node \
  -p 18545:18545 \
  -p 31333:31333 \
  -v ace-node-data:/data \
  acechain/ace-node:fullnode
```

Removing the container does not delete synced data. Removing the volume resets the node.

## Public Registration

Set `ACE_PUBLIC_NODE_REGISTRY_URL` to register the node with the portal registry:

```bash
-e ACE_PUBLIC_NODE_REGISTRY_URL=https://devnet.acechain.io
```

The node periodically reports its peer ID, chain ID, version, P2P port, role, and capabilities. The portal may infer the public IP from the registration request if no explicit public multiaddr is provided.

If the node is behind NAT and the inferred address is wrong, set:

```bash
-e ACE_PUBLIC_NODE_MULTIADDR=/ip4/YOUR_PUBLIC_IP/tcp/31333
```

## Peer Discovery

Set `ACE_PEER_DISCOVERY_RPC_URLS` to let the node pull known public peers and dial them automatically:

```bash
-e ACE_PEER_DISCOVERY_RPC_URLS=https://devnet.acechain.io/rpc
```

Multiple RPC URLs can be comma-separated.

## Logs

Basic logs:

```bash
docker logs -f ace-node
```

More P2P detail:

```bash
docker rm -f ace-node
docker run -d --name ace-node \
  -e RUST_LOG=info,ace_p2p=debug \
  -p 18545:18545 \
  -p 31333:31333 \
  -v ace-node-data:/data \
  acechain/ace-node:fullnode
```
