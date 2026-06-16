# N-VM Shared State Tree: One Ledger For Many Execution Worlds

Most "multi-VM" systems are really multi-environment systems. They expose more than one execution interface, but assets and state still tend to live in separate accounting domains. The user experience then becomes a collection of wrappers, bridges, mappings, and application-specific balance sheets.

ACE's N-VM direction is different: multiple execution worlds should settle into one L1 state model.

## One Ledger, Many Execution Models

ACE is designed to support Native, EVM, SVM, BVM, TVM, and Move-style execution above a shared state tree. Each VM can keep the semantics that make it useful:

- EVM for Solidity contracts and Ethereum-compatible tooling;
- SVM-style execution for account-oriented programs;
- BVM-style execution for Bitcoin-like payment and UTXO logic;
- TVM-style execution for Tron-like flows;
- Move-style execution for resource-oriented assets;
- ACE Native execution for protocol-level operations.

The shared state tree is the important part. VM engines are dispatch targets, not independent chains. After authorization and execution, state changes can settle through the same account model, asset model, receipt path, and finality path.

## How The Pieces Fit

The authorization layer authenticates the user first. It resolves an ACE identity commitment into the authority allowed to act. The N-VM dispatcher then routes the payload to the proper VM engine. The engine executes VM-specific rules, but the resulting writes are reconciled into the common state model.

That allows the VM layer to be specialized without fragmenting settlement. A Solidity contract, a Solana-style token operation, and an ACE-native transfer can all be represented as operations against one chain state. Where write sets are known, the scheduler can also reason about conflicts and parallelize safe batches.

Move-style execution is important here because Move's resource model is a strong fit for assets that should not be copied or accidentally duplicated. In ACE, that kind of asset logic can be added as another execution family without forcing a separate ledger.

## What Users Get

Users should not have to know which VM handled an action. The product goal is a unified account and asset surface. A user should be able to hold value once, authorize once, and interact with applications written for different execution environments without manually bridging between isolated ledgers.

That is especially important for mainstream adoption. Users do not want to manage "my EVM balance," "my SVM balance," and "my Move balance" as unrelated inventory. They want one wallet, one account experience, and predictable finality.

## What Developers Get

Developers get access to familiar ecosystems without giving up shared settlement. Solidity teams can use EVM patterns. SVM teams can use account-oriented program structure. Move developers can use resource semantics. ACE-native modules can handle protocol operations directly.

The commercial benefit is reach. A protocol can serve users from multiple developer cultures without rebuilding liquidity and accounting from scratch for every VM. Infrastructure providers also benefit: explorers, indexers, wallets, and risk systems can build around one underlying ledger instead of many disconnected ones.

## Why This Is More Than Compatibility

EVM compatibility alone helps developers port contracts, but it does not solve industry fragmentation. ACE's shared-state N-VM design is a stronger claim: VM diversity should become specialization, not fragmentation. The chain should let each execution model do what it is good at while keeping assets, identity, and finality unified.

That matters for DeFi, payments, RWA, games, and agent applications. The more application types a chain supports, the more damaging isolated ledgers become. ACE's architecture is meant to let applications compose across execution styles without asking the user to become a bridge operator.

## References

- ACE N-VM paper: `docs/papers/14-2603.23670v1-n-VM.pdf`.
- ACE Runtime paper: `docs/papers/13-2603.10242v1-ACE-Runtime.pdf`.
- Architecture overview: `docs/ARCHITECTURE_OVERVIEW.md`.
