# Contributing

Thank you for your interest in ACE Chain.

## Contribution Guidelines

- Keep changes focused and scoped to one concern.
- Include tests for behavior changes when practical.
- Avoid committing generated artifacts, build outputs, local secrets, or machine-specific files.
- Document changes that affect protocol behavior, public APIs, deployment, or security assumptions.
- For security-sensitive issues, follow `SECURITY.md` instead of opening a public issue first.

## Contributor Path

ACE Chain welcomes contributions across protocol engineering, networking, RPC, runtime execution, DeFi, documentation, testing, operations, and security review.

Good first contributions include:

- running a public full node and reporting sync or peer-discovery issues;
- improving documentation, examples, and onboarding instructions;
- adding focused tests around RPC, P2P, mempool, sync, or runtime behavior;
- reproducing bugs with clear logs, environment details, and minimal steps;
- building small demos, SDK integrations, indexers, explorers, or monitoring tools.

Long-term contributors can take ownership of larger areas such as `ace-node`, `ace-p2p`, `ace-rpc`, n-VM execution, MEV-ACE, ZK-ACE integration, OmniLiquid, or testnet operations.

## Technical Committee Path

ACE Chain is actively looking for serious technical contributors now.

We especially welcome people who can help with protocol architecture, core implementation, engineering direction, testnet operations, infrastructure maintenance, security hardening, developer tooling, and ecosystem integration while the network is still early enough for deep technical input to shape the system.

Relevant areas include:

- protocol architecture and implementation;
- consensus safety, networking, mempool, sync, and validator operations;
- n-VM execution, Move/EVM/SVM compatibility, and shared-state design;
- MEV-ACE, ZK-ACE, post-quantum authorization, and cryptographic verification;
- OmniLiquid, oAssets, DeFi risk, bridge safety, and reserve accounting;
- public RPC, full-node operation, peer discovery, relay behavior, and archive/indexing infrastructure;
- testnet reliability, release engineering, monitoring, incident response, and long-term maintenance;
- documentation, SDKs, examples, developer education, and ecosystem integrations.

If you want to help define technical direction, build core components, maintain infrastructure, or lead a focused area of the protocol, open a focused issue or pull request, publish technical feedback, or reach out through the project's public channels.

## Development Workflow

1. Create a topic branch.
2. Make a focused change.
3. Run the relevant checks locally.
4. Open a pull request with a clear summary and testing notes.

Recommended checks:

```bash
cargo check --features stark
cargo test --features stark
```

## Licensing

By contributing, you agree that your contributions are licensed under the
Apache License, Version 2.0.
