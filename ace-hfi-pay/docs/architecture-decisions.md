# HFIPay Architecture Decisions

This document records architectural feedback received during early review and the reasoning behind our decisions. It serves as a reference for future contributors who may raise the same questions.

---

## 1. "Split into protocol core / chain adapters / relay service"

**Feedback:** The crate mixes protocol state machine, on-chain execution, and relay data model. It should be split into three layers to prevent EVM, Solana, and ACE-native concerns from polluting each other.

**Decision: Keep unified for now. Split when the second external chain adapter lands.**

Rationale:

- The crate is ~600 lines of code. Three crates means three `Cargo.toml`, three error type hierarchies, and three sets of interface boundaries to maintain.
- The protocol is still iterating. Every change to the `Intent` model would require coordinated interface changes across three crates.
- Premature abstraction locks in interface boundaries before we have enough information to draw them correctly. The right time to extract a `chain_adapter` trait is when we actually implement a second adapter (e.g., the Ethereum bridge contract integration), because at that point the abstraction surface becomes empirically clear rather than speculative.
- When the split happens, the natural boundaries are:
  - `ace-hfi-pay-core`: `Intent`, `IntentStatus`, `ChainId`, authorization message construction/verification (pure functions, no state).
  - `ace-hfi-pay-chain`: On-chain execution (`IntentStore`, `create_intent`, `claim_intent`, `withdraw`, `refund`) — depends on `ace-model::StateTree`.
  - `ace-hfi-pay-relay`: `RelayStore`, `RelayIntent`, email-to-intent mapping — pure off-chain, no chain dependency.

---

## 2. "cross-vm is just ACE internal transfer, not real cross-chain"

**Feedback:** The cross-VM abstraction looks like an internal balance move within ACE Chain, not a complete cross-chain payment architecture. It works for the ACE-native world but doesn't cover real external-chain settlement.

**Decision: This is by design. It is a feature, not a gap.**

Rationale:

- ACE Chain's Penta-VM architecture (EVM/SVM/BVM/TVM/Native) runs all VMs under a **single consensus with a unified `StateTree`**. Cross-VM transfer in this architecture is, by definition, a same-state balance mutation — not a cross-chain message.
- This is the core architectural advantage: what other systems solve with bridges, relays, and finality waits, ACE solves with a single `state.get_mut()` call. The cost is a few CPU instructions, not a cross-chain round-trip.
- External-chain settlement (deposit verification, withdrawal proofs) is handled by `ace-bridge`, not `ace-hfi-pay`. The separation of concerns is intentional:
  - **`ace-hfi-pay`** — payment routing and intent lifecycle (protocol layer)
  - **`ace-bridge`** — deposit/withdraw between ACE Chain and external L1s (infrastructure layer)
- The dual-mode VM architecture (each VM runs as both L1 and L2-portal of its parent chain) means that from the user's perspective, depositing ETH into the "L2" and using it across all VMs is seamless — **the user does not need to know they are interacting with a new chain**. Same address, same assets, auto-wrapped into the unified token ledger.

```
ETH deposit → ace-bridge: mint ACE-wETH → unified StateTree
  → ace-hfi-pay: route payment to email recipient
  → recipient claims on any VM (EVM/SVM/BVM/TVM/Native)
  → ace-bridge: burn ACE-wETH → withdrawal proof → ETH released
```

The entire flow happens **within one consensus round** except for the external-chain deposit verification and withdrawal finalization, which are inherently asynchronous regardless of architecture.

---

## 3. "Needs a first-class payment order model"

**Feedback:** Sender, recipient, refund authorization, destination VM address — these objects lack a strong central "payment order" abstraction. The `Intent` struct is doing too much, and semantic constraints are scattered, leading to patch-upon-patch in the implementation.

**Decision: Agree this is the most valuable feedback. Defer extraction until the second business scenario emerges.**

Rationale:

- The `Intent` struct currently serves as payment order, state machine, and authorization container. As fields grow (`claim_pubkey`, `refund_auth`, `VmAddress`, etc.), it will become unwieldy.
- However, the right shape for a "payment order model" depends on requirements we don't yet have:
  - Partial withdrawals? Multi-currency payments? Conditional releases? Escrow with arbitration?
  - Each of these would pull the model in a different direction.
- Extracting an abstraction now would be speculative. When the second or third real business scenario arrives, the common structure will be empirically visible, and the abstraction quality will be much higher.
- Concrete refactoring direction when the time comes:
  - Extract `PaymentOrder` (immutable: amount, asset, sender, recipient identifier, chain, expiry, refund policy).
  - Keep `IntentState` as the mutable lifecycle tracker (status, owner binding, nonces).
  - Move authorization proofs into a separate `AuthBundle` that can be validated independently.

---

## 4. "Missing token/rent/gas sponsorship/notification/reconciliation"

**Feedback:** The asset model is "balance transfer" level. A real payment system needs gas sponsorship, notifications, reconciliation, and rent management.

**Decision: Correct observation, but these belong to the application layer, not the protocol layer.**

Rationale:

- The HFIPay paper explicitly defines a **three-layer trust architecture**:
  - **Protocol layer** (on-chain): pure mathematics — intent addressing, signature verification, state transitions.
  - **Application layer** (relay): operational — gas sponsorship, notification, reconciliation, rate limiting.
  - **Identity layer** (email provider): accountability — real-world identity behind the email.
- Putting application concerns into the protocol crate violates this separation:
  - **Gas sponsorship**: The relay pays gas on behalf of users. This is a relay policy decision, not a protocol constraint. The protocol is agnostic to who submits the transaction.
  - **Notification**: Sending emails/push notifications is a pure off-chain service. It has no on-chain representation.
  - **Reconciliation**: Matching on-chain state with relay records is a relay-side bookkeeping task.
  - **Rent**: Account rent is an ACE Chain runtime concern (already handled by `last_touched_slot` + state expiry in `ace-model`), not an HFIPay concern.
- The protocol crate should remain minimal and auditable. Every line of code in the protocol layer is a potential attack surface. Application logic has a different security profile and should live in a different trust boundary.

---

## Summary

| Feedback | Valid? | Action | When |
|----------|--------|--------|------|
| Split into 3 layers | Direction correct | Extract when second chain adapter is needed | Future |
| Cross-VM is not real cross-chain | Observation correct, conclusion wrong | No change — this is the core architectural advantage | N/A |
| Need payment order model | Most valuable feedback | Refactor when second business scenario arrives | Future |
| Missing application-layer features | Correct | Build in relay service, not in protocol crate | Future |

The guiding principle: **the biggest risk for a fast-iterating project is not insufficient abstraction — it is premature abstraction that locks in the wrong interface boundaries.**
