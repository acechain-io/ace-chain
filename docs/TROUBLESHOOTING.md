# Troubleshooting

## Container Does Not Start

Check logs:

```bash
docker logs ace-node
```

Common causes:

- Docker volume permissions
- port `18545` or `31333` already in use
- local firewall or VPN blocking outbound connections

## Node Connects But Does Not Sync

Check network status:

```bash
curl -s -X POST http://127.0.0.1:18545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"ace_getNetworkStatus","params":[],"id":1}'
```

If the node sees a network height but local height stays at zero for a long time, check P2P logs:

```bash
docker rm -f ace-node
docker run -d --name ace-node \
  -e RUST_LOG=info,ace_p2p=debug \
  -p 18545:18545 \
  -p 31333:31333 \
  -v ace-node-data:/data \
  acechain/ace-node:fullnode
docker logs -f ace-node
```

Look for block sync requests, responses, connection failures, or timeout messages.

## Node Does Not Appear On Portal

Confirm the container was started with:

```bash
-e ACE_PUBLIC_NODE_REGISTRY_URL=https://devnet.acechain.io
```

Also confirm that TCP `31333` is reachable from the internet. Nodes behind home NAT may need router port forwarding or an explicit public multiaddr:

```bash
-e ACE_PUBLIC_NODE_MULTIADDR=/ip4/YOUR_PUBLIC_IP/tcp/31333
```

## RPC Is Not Reachable

Local RPC should answer on:

```bash
http://127.0.0.1:18545
```

If calling from another machine, ensure Docker publishes `18545` and the host firewall allows the connection. Do not expose public RPC unless you intend to operate a public RPC service and have appropriate rate limiting in front of it.

## Reset And Resync

```bash
docker rm -f ace-node
docker volume rm ace-node-data
```

Then restart the node from the README command.
