# MEV-ACE Fair Ordering For User-Protective DeFi

MEV is often discussed as if it were an exotic validator problem. For users it is much simpler: the transaction they intended is not the transaction they effectively received. A swap is sandwiched, a liquidation is reordered, a route becomes worse, or a transaction is omitted until someone else profits from the delay. The result is a hidden execution tax paid by traders, wallets, aggregators, protocols, and market makers.

MEV-ACE focuses on the part of that problem a chain can control: ordering power inside the block-production path.

## What MEV-ACE Is Trying To Remove

Not every dollar of MEV is the same. Some arbitrage reflects real price differences across markets. A local ordering rule cannot remove global price discovery or cross-domain latency advantages. ACE does not claim to erase those.

MEV-ACE targets the block-local component:

- inserting a transaction before a user's transaction;
- placing another transaction immediately after it;
- reordering transactions to capture a user's expected price movement;
- delaying or omitting a transaction when inclusion would be unfavorable to the block producer or searcher.

This is the component behind many sandwich and front/back-running patterns. For ACE-native DeFi routes, the ambition is to make this manipulation surface structurally smaller rather than asking every wallet to negotiate private protection.

## Why Private Routing Is Not Enough

Private routing can help because it hides transactions from the public mempool. But it also moves trust to a private relay, builder, or routing provider. Users may be protected from one adversary while becoming dependent on another. Public research on sandwich attacks shows that users do change behavior after being attacked, including moving toward private channels, but this does not create a complete fairness guarantee.

ACE's approach is to make fair ordering a protocol property for ACE transactions. That matters for application developers because they can reason about execution policy at the chain level. A DEX, payment protocol, auction, or cross-chain settlement application should not need a separate off-chain relationship with a routing cartel to provide acceptable execution quality.

## Technical Shape

MEV-ACE is built around deterministic ordering, accountable inclusion, and evidence paths for omission or ordering failures. At a high level, the chain should be able to answer three questions:

1. Which transactions were eligible for inclusion?
2. What ordering rule should have applied?
3. If a producer deviated, can the system produce evidence?

That is different from a pure "trust the block builder" model. The design pushes ordering policy closer to consensus and execution, where applications can depend on it. In the ACE stack, MEV-ACE integrates with the node hot path and the block material path rather than living only as an external relay.

## Who Benefits

Retail users benefit through fewer hidden losses and more predictable execution. Professional market makers benefit because lower ordering risk reduces the margin they must charge for liquidity. Wallets and aggregators benefit because "best execution" becomes easier to defend. DeFi protocols benefit because liquidity is more likely to stay when users believe the venue is not structurally hostile.

This is also a business advantage for the chain. Liquidity follows venues where execution quality is good and hidden extraction is lower. A chain that makes ordering fairness part of the base layer can compete on more than nominal gas fees.

## Industry Data

Recent public research estimated about USD 233.8 million extracted by 19 major Ethereum CEX-DEX searchers over a 19-month window from August 2023 to March 2025. That figure covers only one measured slice of MEV and does not include every form of user harm. It is enough to show the scale of the problem: MEV is not rounding error.

The right claim for ACE is precise: MEV-ACE is designed to remove or reduce the protocol-controlled ordering-abuse surface for ACE transactions. It does not remove every external arbitrage opportunity, but it can make ACE-native DeFi a fairer venue for the trades and settlements it controls.

## References

- Fei Wu, Danning Sui, Thomas Thiery, Mallesh Pai, "Measuring CEX-DEX Extracted Value and Searcher Profitability: The Darkest of the MEV Dark Forest", arXiv:2507.13023, https://arxiv.org/abs/2507.13023.
- Davide Mancino, Davide Rezzoli, "Sandwiched and Silent: Behavioral Adaptation and Private Channel Exploitation in Ethereum MEV", arXiv:2512.17602, https://arxiv.org/abs/2512.17602.
- ACE MEV-ACE paper: `docs/papers/17-2604.07568v1-MEV-ACE.pdf`.
