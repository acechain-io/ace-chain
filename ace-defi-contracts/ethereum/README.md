# ACE DeFi Ethereum Contracts

Phase A custody bridge contracts for ACE DeFi community development.

## Scope

This package contains the EVM-side deposit contract used by the ACE DeFi relayer:

- `BridgeDeposit.sol` accepts USDT and generic ERC20 deposits.
- Every deposit includes an ACE `intentId` and `aceRecipient`.
- Deposit IDs are nonce-based and domain-separated.
- Emergency withdrawals are owner-only, timelocked, nonce-based, and parameter-bound.

This is a development bridge surface, not the final trustless zk/light-client egress design.

## Commands

```bash
npm install
npm run compile
npm test
```

## Deploy

Set `USDT_ADDRESS` to the token address for the target network:

```bash
USDT_ADDRESS=0x... npx hardhat run scripts/deploy.js --network sepolia
```

The deployer becomes the initial owner/governance address.

## Notes

- OpenZeppelin Contracts v5 is used.
- `node_modules/`, `artifacts/`, and `cache/` are generated locally and are not intended for public sync.
- Production deployment requires separate audit, governance, monitoring, and relayer key-management work.
