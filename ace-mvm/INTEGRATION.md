# Move VM Integration Guide

This guide explains how to integrate the Move VM into your ACE Chain node implementation.

## Quick Start

### 1. Add ace-mvm Dependency

In your node's `Cargo.toml`:

```toml
[dependencies]
ace-mvm = { path = "../ace-mvm" }
```

### 2. Enable Move VM in Node Initialization

In your node setup code (typically `ace-node/src/node.rs` or similar):

```rust
use ace_n_vm::NVm;

// Create the n-VM with all default engines
let nvm = NVm::with_defaults();

// Now nvm supports Move transactions with 0x50-0x5F opcodes
```

## Move Transaction Submission

### Via JSON-RPC

Users can submit Move transactions through the standard `eth_sendRawTransaction` RPC method or a Move-specific endpoint.

### Example: Python

```python
import requests
import json

# Move transaction payload (opcode 0x50-0x5F for Move execution)
move_tx = {
    "opcode": 0x50,  # 0x50-0x5F are Move VM opcodes
    "nonce": 0,
    "module_address": "0000000000000000000000000000000000000000000000000000000000000001",
    "module_name": "Token",
    "function_name": "transfer",
    "args": [
        {"type": 0x05, "value": "0000000000000000000000000000000000000000000000000000000000000002"},  # recipient
        {"type": 0x03, "value": 1000000000}  # amount (u64)
    ]
}

# RPC call
response = requests.post(
    "http://localhost:18545",
    json={
        "jsonrpc": "2.0",
        "method": "ace_sendRawTransaction",
        "params": [encode_move_tx(move_tx)],
        "id": 1
    }
)

print(response.json())
```

### Example: TypeScript/Web3.js

```typescript
import { ethers } from "ethers";

const provider = new ethers.JsonRpcProvider("http://localhost:18545");
const signer = provider.getSigner();

// Construct Move transaction (opcode 0x50-0x5F for Move execution)
const movePayload = encodeMoveTx({
  opcode: 0x50,  // 0x50-0x5F are Move VM opcodes
  nonce: 0n,
  moduleAddress: "0x" + "0".repeat(64) + "01",
  moduleName: "Token",
  functionName: "transfer",
  args: [
    { type: 0x05, value: recipientAddress },  // address
    { type: 0x03, value: BigInt(1000000000) }  // u64
  ]
});

// Send transaction
const tx = await signer.sendTransaction({
  data: movePayload,
});

const receipt = await tx.wait();
console.log("Move transaction hash:", receipt.transactionHash);
```

## Payload Encoding Helper

### JavaScript Implementation

```javascript
function encodeMoveTx(config) {
  const payload = [];
  
  // Opcode
  payload.push(config.opcode);

  // Sender nonce (8 bytes, little-endian)
  payload.push(...bytes8le(config.nonce || 0n));
  
  // Module address (32 bytes)
  payload.push(...hex2bytes(config.moduleAddress.padStart(64, "0")));
  
  // Module name (32 bytes, null-padded)
  const nameBytes = new TextEncoder().encode(config.moduleName);
  payload.push(...nameBytes);
  payload.push(...Array(32 - nameBytes.length).fill(0));
  
  // Function name length (2 bytes, little-endian)
  const funcBytes = new TextEncoder().encode(config.functionName);
  payload.push(...bytes2(funcBytes.length));
  payload.push(...funcBytes);
  
  // Args count (2 bytes, little-endian)
  payload.push(...bytes2(config.args.length));
  
  // Args
  for (const arg of config.args) {
    payload.push(...encodeValue(arg));
  }
  
  return "0x" + Buffer.from(payload).toString("hex");
}

function encodeValue(value) {
  switch (value.type) {
    case 0x01: // bool
      return [0x01, value.value ? 1 : 0];
    case 0x02: // u8
      return [0x02, value.value & 0xFF];
    case 0x03: // u64
      return [0x03, ...bytes8(value.value)];
    case 0x04: // u128
      return [0x04, ...bytes16(value.value)];
    case 0x05: // address
      return [0x05, ...hex2bytes(value.value.padStart(64, "0"))];
    case 0x06: // bytes
      const data = hex2bytes(value.value);
      return [0x06, ...bytes4(data.length), ...data];
    case 0x07: // vector
      const encoded = [];
      encoded.push(0x07);
      encoded.push(...bytes4(value.value.length));
      for (const elem of value.value) {
        encoded.push(...encodeValue(elem));
      }
      return encoded;
    default:
      throw new Error(`Unknown type: ${value.type}`);
  }
}

function hex2bytes(hex) {
  return Buffer.from(hex.replace(/^0x/, ""), "hex");
}

function bytes2(n) {
  return [n & 0xFF, (n >> 8) & 0xFF];
}

function bytes4(n) {
  return [
    n & 0xFF,
    (n >> 8) & 0xFF,
    (n >> 16) & 0xFF,
    (n >> 24) & 0xFF
  ];
}

function bytes8(n) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setBigUint64(0, BigInt(n), true); // little-endian
  return Array.from(new Uint8Array(buf));
}

function bytes8le(n) {
  const out = [];
  let x = BigInt(n);
  for (let i = 0; i < 8; i++) {
    out.push(Number(x & 0xffn));
    x >>= 8n;
  }
  return out;
}

function bytes16(n) {
  const out = [];
  let x = BigInt(n);
  for (let i = 0; i < 16; i++) {
    out.push(Number(x & 0xffn));
    x >>= 8n;
  }
  return out;
}
```

## RPC Extensions

Consider adding Move-specific RPC methods to `ace-rpc`:

```rust
#[rpc(server)]
pub trait MoveRpc {
    /// Deploy a Move module
    #[method(name = "move_publish")]
    fn move_publish(
        &self,
        account: String,
        bytecode: String,
        metadata: Option<serde_json::Value>,
    ) -> RpcResult<String>;

    /// Execute a Move function
    #[method(name = "move_execute")]
    fn move_execute(
        &self,
        account: String,
        module: String,
        function: String,
        args: Vec<serde_json::Value>,
    ) -> RpcResult<String>;

    /// Get Move module
    #[method(name = "move_getModule")]
    fn move_get_module(
        &self,
        address: String,
        name: String,
    ) -> RpcResult<Option<serde_json::Value>>;

    /// Get Move resource
    #[method(name = "move_getResource")]
    fn move_get_resource(
        &self,
        address: String,
        resource_type: String,
    ) -> RpcResult<Option<serde_json::Value>>;
}
```

## Verification Checklist

- [ ] Add `ace-mvm` to node dependencies
- [ ] Use `NVm::with_defaults()` or explicitly register `MoveVmEngine`
- [ ] Test Move transaction submission via RPC
- [ ] Verify opcodes 0x50-0x5F transactions are routed to Move VM
- [ ] Check transaction receipts show correct VM execution
- [ ] Implement Move-specific RPC methods (optional)
- [ ] Add payload encoding helper to client libraries

## Troubleshooting

### Move transactions fail with "Unsupported opcode"

Check that the node uses `NVm::with_defaults()` or explicitly registers `MoveVmEngine`.

### Transaction reverts with "EmptyPayload"

Ensure the Move payload is not empty. Verify the opcode byte is included.

### Invalid format errors

Check payload encoding matches the format specification exactly, especially:
- Module name is exactly 32 bytes (null-padded)
- Function name length is correct (little-endian u16)
- Argument types match the encoding specification

## Next Steps

1. **Bytecode Compiler**: Build or integrate a Move compiler to generate bytecode
2. **Module Registry**: Implement persistent module storage in StateTree
3. **Fee Accounting**: Wire Move-specific gas costs into node-level fee charging
4. **Interop**: Enable Move↔EVM contract calls
5. **Type System**: Implement Move type checking and inference

## Resources

- [Move Language Documentation](https://move-language.github.io/)
- [Aptos Move](https://aptos.dev/move)
- [Sui Move](https://docs.sui.io/concepts/sui-move)
- [ACE Chain Architecture](../ACE_CHAIN_PITCH_DECK.md)
