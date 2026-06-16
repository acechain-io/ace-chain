# ACE Chain Move VM - Native Style Executor

This module provides the **lightweight Move-style execution environment** for ACE Chain. ACE Native remains responsible for system transactions; Move is added as a separate VM alongside EVM, SVM, BVM, and TVM compatibility layers.

The current version (v1) implements a **deterministic native executor** for Move-style transaction payloads, providing the groundwork for full bytecode interpretation in future phases.

## Architecture

The Move VM engine is the core of ACE Chain's multi-VM dispatcher (`ace-n-vm`):

```
Transaction → n-VM Dispatcher → (by opcode prefix)
                                 ├─ 0x01-0x0F → ACE Native Runtime
                                 ├─ 0x10-0x1F → EVM (compatibility)
                                 ├─ 0x20-0x2F → SVM (compatibility)
                                 ├─ 0x30-0x3F → BVM (compatibility)
                                 ├─ 0x40-0x4F → TVM (compatibility)
                                 └─ 0x50-0x5F → Move VM ⭐
```

## Transaction Format

Move transactions use opcode range `0x50-0x5F` and follow this format:

```
[opcode:1][nonce:8 LE][module_addr:32][module_name:32][func_name_len:2][func_name:var][args_count:2][args:var]
```

### Field Breakdown

- **opcode** (1 byte): 0x50-0x5F identifies this as a Move VM transaction
- **nonce** (8 bytes): Sender account nonce, little-endian
- **module_addr** (32 bytes): Address of the module owner
- **module_name** (32 bytes): Module name (null-padded)
- **func_name_len** (2 bytes): Length of function name (little-endian)
- **func_name** (variable): Function name
- **args_count** (2 bytes): Number of arguments (little-endian)
- **args** (variable): Serialized Move values

### Argument Encoding

Move values are encoded using type tags:

```
0x01 = bool        (type:1 + value:1)
0x02 = u8          (type:1 + value:1)
0x03 = u64         (type:1 + value:8)
0x04 = u128        (type:1 + value:16)
0x05 = address     (type:1 + value:32)
0x06 = bytes       (type:1 + len:4 + data:var)
0x07 = vector      (type:1 + count:4 + elements:var)
```

## Usage in Node

Move VM is automatically enabled in your ACE Chain node:

```rust
use ace_n_vm::NVm;

// Create the n-VM with all engines
let nvm = NVm::with_defaults();

// Now nvm can execute ACE native, Move, EVM, SVM, BVM, and TVM transactions.
```

## Examples

### Deploying a Module

```
Opcode:        0x50 (publish_module)
Module address: 0x0000...0001
Module name:   "Token"
Function:      "publish_module"
Args:          [<bytecode>]
```

### Calling a Function

```
Opcode:        0x50 (function_call)
Module address: 0x0000...0001
Module name:   "Token"
Function:      "transfer"
Args:          [recipient: address, amount: u64]
```

## State Management

Move resources are stored within ACE Chain's `StateTree`:

- **Module Registry**: Tracks published Move modules
- **Account Resources**: Resources owned by individual accounts
- **Module Storage**: Per-module persistent state

## Current Features

✅ **Implemented:**
- Basic Move transaction parsing and validation
- Sender nonce validation and replay protection
- Deterministic module publishing into ACE `StateTree`
- Native `transfer(recipient: address, amount: u64)` execution against ACE balances
- State change tracking
- Integration with ACE's multi-VM dispatcher
- Opcode routing (0x50-0x5F)
- Informational receipt gas reporting; node fee charging still uses the fixed chain `TX_FEE`

🚧 **Future Enhancements:**
- Full Move bytecode verifier
- Move bytecode interpreter (Aptos/Sui/custom)
- Complex resource management
- Move-to-EVM interop
- Module dependency resolution
- Move-specific fee accounting and gas metering
- Event system
- Type system completeness

## File Structure

```
ace-mvm/
├── src/
│   ├── lib.rs           # Main module entry point
│   ├── engine.rs        # Move VM engine implementation
│   ├── bytecode.rs      # Bytecode parsing and verification
│   ├── types.rs         # Move type definitions
│   ├── state.rs         # State management
│   ├── error.rs         # Error types
├── Cargo.toml
└── README.md
```

## Dependencies

- `ace-runtime`: Core runtime types and cryptography
- `ace-model`: State tree and account models
- `ace-engine`: Transaction execution framework

No external Move VM dependencies are required yet, allowing for lightweight integration. This can be extended to use Aptos or Sui Move VM libraries in the future.

## Testing

Run tests with:

```bash
cargo test --package ace-mvm
```

## Future Integration Paths

### Path 1: Aptos Move VM
```toml
[dependencies]
move-vm-runtime = { git = "https://github.com/aptos-labs/aptos-core" }
move-binary-format = { git = "https://github.com/aptos-labs/aptos-core" }
```

### Path 2: Sui Move VM
```toml
[dependencies]
sui-move-build = { git = "https://github.com/MystenLabs/sui" }
```

### Path 3: Custom Move Implementation
Keep the current lightweight bytecode executor and extend it with a full Move VM implementation tailored to ACE Chain's needs.

## Design Rationale

The Move VM integration was designed to:

1. **Be isolated** - No circular dependencies with `ace-n-vm`
2. **Be default-enabled** - `NVm::with_defaults()` registers Move alongside the other VM engines
3. **Be pluggable** - Follows the same `VmEngine` trait as other VMs
4. **Be lightweight** - Initially minimal dependencies, can be extended
5. **Be conservative** - Reject unsupported functions instead of returning fake success

This makes Move a first-class opcode-routed execution environment in ACE Chain's multi-VM architecture. The current implementation is a deterministic native executor for the supported Move entry points; full Move bytecode interpretation remains a separate integration step.
