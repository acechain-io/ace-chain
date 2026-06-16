# ACE Chain Universal Cross-Chain Bridging & Liquidity Protocol

## Executive Summary

This document outlines a **parametric, multi-chain bridging system** built on ACE Chain's unified state tree and n-VM architecture. The system enables users to deposit assets from any supported external chain, perform atomic swaps across wrapped assets, and withdraw to any other external chain—with **low protocol fees** and LP incentives that may be economically sustainable if route consolidation produces sufficiently high pool turnover. ACE's native atomicity and protocol-level ordering-MEV protection (MEV-ACE fair ordering; see paper 17-2604.07568) create the strongest advantage on the ACE-internal swap leg.

The key innovation: **ACE Chain's state tree atomicity eliminates bridge-like risk inside ACE's own execution boundary**. Once assets are represented in ACE's unified StateTree, swaps and cross-VM movements execute as a single state transition. External-chain ingress and egress remain bridge-bearing trust domains: source-chain deposits require finality verification and relayer/committee attestation, while the Phase A egress model uses a pre-funded relayer pool. The design goal is therefore not to claim that bridge trust disappears on day one, but to compress the risky surface area, concentrate liquidity, and provide a staged path from custodial fast egress to trust-minimized proof-based egress.

**Strategic positioning**:
- **Phase A**: low-TVL, capped, multi-sig custodial fast bridge for market validation.
- **Phase B**: non-custodial zk/light-client egress before TVL scales materially.
- **Phase C**: HFI-Pay-style verified intent and claim binding, where users accept a verifiable conversion quote and the protocol commits the exact route, asset tuple, recipient, expiry, and refund semantics before funding.

**Current implementation status**: this repository now contains the Phase A protocol foundation for capped testnet liquidity flows. Implemented foundations include governance-bound relayer admission, intent IDs on deposit/withdrawal records, intent-aware Ethereum deposit events, relayer checkpoint persistence, and tests around those boundaries. The production rollout path adds threshold relayer quorum, production external-chain RPC/log decoding, hardened egress execution, caps/circuit breakers, monitoring, and Phase B proof-verified egress.

**Risk model**: ACE DeFi follows a compartmentalized shared-liquidity model. Liquidity is shared through canonical assets and common settlement, but risk controls are scoped to deterministic compartments: canonical assets, external mappings, pools, markets, withdrawal routes, relayer sets, and oracle feeds. The goal is not to remove systemic correlation from shared assets, but to make failure domains explicit, auditable, and containable wherever the risk is not inherently systemic.

---

## 1. System Architecture Overview

### 1.1 Three-Layer Model

```
┌─────────────────────────────────────────────────────────────┐
│                      USER EXPERIENCE                        │
│  "Send 1 USDT on BSC → Receive equivalent TRX on Tron"     │
└──────────────────────────────────┬──────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────┐
│                   INGRESS LAYER (Deposit Bridge)            │
│  - BSC-side bridge contract locks/burns USDT               │
│  - Relayer monitors, signs attestation                      │
│  - ACE Chain mints equivalent wUSDT to user                 │
└──────────────────────────────────┬──────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────┐
│                  SWAP LAYER (ACE-Internal)                  │
│  - User holds wUSDT on ACE Chain state tree                │
│  - Performs atomic swap: wUSDT → wTRX via AMM             │
│  - Ordering MEV mitigated by MEV-ACE; slippage             │
│    bounded by min_amount_out                                │
│  - All within single state snapshot                        │
└──────────────────────────────────┬──────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────┐
│                  EGRESS LAYER (Withdrawal Bridge)           │
│  - User initiates withdrawal: burn wTRX, request TRX       │
│  - Withdrawal record committed to ACE state root           │
│  - Relayer monitors, executes on Tron chain                │
│  - Recipient receives native TRX on Tron                   │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Design Principle: Atomicity as Competitive Advantage

On traditional chains (Ethereum, Solana, etc.):
- Swaps across different asset pools require multiple cross-contract calls
- Each call exposes MEV, slippage, ordering risk
- LPs must charge high fees (0.5–1.0%) to cover risk and opportunity cost

**On ACE Chain**:
- All wrapped assets live on the same **unified StateTree**
- Swap operations are **guaranteed atomic** by protocol
- No proposer-controlled ordering MEV (front-running, sandwiching, censorship are constrained by the MEV-ACE commit/VDF/receipt protocol), no partial fills. Note: execution order within a slot is *randomized*, not first-come-first-served, so price movement between submission and execution still exists — users set min_amount_out.
- **LPs may be able to operate at 0.05–0.1% fees** if route consolidation produces enough volume/TVL turnover; this remains an empirical Phase A validation target

### 1.3 Unified Execution Model: Swaps and Bridges as One

The system's most elegant property is its **fundamental unification of swaps and bridging**. Rather than treating them as separate operations, they are instances of the same parametric operation with different parameters.

#### The Core Abstraction

```
convert(
    from: (chain_id, asset_id, amount),
    to: (chain_id, asset_id),
    recipient: address
) → recipient receives wrapped asset on destination chain
```

When parameters satisfy `from.chain_id == to.chain_id`, the operation becomes an internal swap. When they differ, it becomes a cross-chain bridge. **The same code path handles both.**

#### Execution Paths by Parameter Combination

| from.chain | to.chain | Execution Path | Example | Latency (target) | Fee (target) |
|-----------|----------|---|---------|---------|------|
| ACE | ACE | **Fast: Swap Only** | wUSDT → wTRX | ~400ms (one ACE slot) | 0.1% |
| BSC | ACE | **Partial: Bridge In → Swap** | USDT → wTRX | ~1min (BSC finality dominates) | 0.2% |
| BSC | Tron | **Full: Bridge In → Swap → Bridge Out** | USDT → TRX | ~1–2min (source finality + dest confirm) | 0.3% |
| Tron | Tron | **Fast: Bridge In → Bridge Out** (no swap) | USDT → TRX (same token) | ~2min (Tron finality + dest confirm) | 0.2% |
| ACE | BSC | **Partial: Swap → Bridge Out** | wUSDT → USDT | ~10s (dest confirm only; no ingress wait) | 0.2% |

> Latency is dominated by the **source chain's finality wait** on ingress (see Section 7.5 parameters: ETH ~150–180s, BSC ~45–60s, Tron ~60–100s). The 400ms figure applies only to the ACE-internal swap leg. Fees are design targets, not measured values.

#### Why This Matters for Architecture

**Traditional Approach** (two separate code paths):
```
if is_cross_chain_swap:
    path = cross_chain_swap()      # Wormhole, Stargate, etc.
else:
    path = internal_swap()         # Uniswap, Curve, etc.
```

**Our Approach** (one unified path):
```
def execute(from_params, to_params, recipient):
    # Unified entry point, self-optimizing
    if from_params.chain != to_params.chain:
        # Smart routing happens inside, not caller's concern
        pass
    
    bridge_in(from_params)           # No-op if already on ACE
    swap(from_params.asset, to_params.asset)  # No-op if same asset
    bridge_out(to_params)            # No-op if already on ACE
```

**Benefits**:
- **Single integration point** for applications (wallets, aggregators)
- **Automatic optimization**: no manual switching between paths
- **Extensible**: adding new chains doesn't require new code branches
- **Testable**: one happy path covers all scenarios
- **Gas-efficient**: unnecessary operations become no-ops (cheap bytecode jumps)

#### Liquidity Pool Shared Across Use Cases

The same liquidity pool (e.g., wUSDT ↔ wTRX) serves **multiple distinct user journeys**:

```
Pool State: reserve_USDT = 1M, reserve_TRX = 10M

User A (Domestic Trader):
  - Already has 100 wUSDT on ACE
  - Wants wTRX for DeFi farming
  - Transaction: Swap wUSDT → wTRX
  - Cost: 0.1% fee
  - Latency: 400ms
  - Flow: [Swap]
  
User B (Cross-Chain Arbitrageur):
  - Has USDT on BSC
  - Sees TRX yield opportunity on Tron
  - Transaction: USDT (BSC) → TRX (Tron)
  - Cost: 0.3% (0.1% each for bridge in/out + 0.1% swap)
  - Latency: ~15 seconds (sequential bridges)
  - Flow: [Bridge In] → [Swap] → [Bridge Out]
  
User C (Stablecoin Converter):
  - Has USDT on BSC
  - Needs USDT on Tron (no swap needed)
  - Transaction: USDT (BSC) → USDT (Tron)
  - Cost: 0.2% (0.1% each bridge)
  - Latency: ~10 seconds
  - Flow: [Bridge In] → [no-op Swap] → [Bridge Out]
```

**Pool sees combined volume**:
- User A swaps at the pool
- User B swaps at the pool (after bridge in)
- User C *doesn't* swap (no AMM fee for this user)

But they all contribute to:
- Protocol understanding of assets
- Rebalancing dynamics
- LP fee collection (for A and B)

**Result**: A single $10M liquidity pool can service 3 different use cases simultaneously, with fee capture only where value is added (swaps), not on bridging overhead.

#### Implementation Consequence: Minimal Code Duplication

```rust
// Pseudo-code showing unified structure

pub fn execute_convert(
    from: ConvertSource,
    to: ConvertDest,
    recipient: AccountId,
) -> Result<ConversionResult> {
    // Phase 1: Ingress (automatic no-op if already on ACE)
    let (user_balance, asset_id_on_ace) = 
        if from.chain == ACE_CHAIN_ID {
            // User already has asset on ACE
            (from.balance, from.asset_id)
        } else {
            // Bring asset to ACE via bridge
            let receipt = bridge_in(from)?;
            (receipt.amount, receipt.wrapped_mint)
        };

    // Phase 2: Swap (automatic no-op if input == output asset)
    let (swapped_amount, swapped_mint) = 
        if from.asset == to.asset {
            // No swap needed
            (user_balance, asset_id_on_ace)
        } else {
            // Execute atomic swap
            let result = swap_engine.swap(
                state,
                asset_id_on_ace,
                to.asset_id,
                user_balance,
                min_amount_out
            )?;
            (result.amount_out, result.out_mint)
        };

    // Phase 3: Egress (automatic no-op if destination is ACE)
    let final_result = 
        if to.chain == ACE_CHAIN_ID {
            // User wants asset on ACE, done
            ConversionResult {
                recipient,
                amount: swapped_amount,
                asset: swapped_mint,
                location: ACE,
            }
        } else {
            // Send asset back to external chain
            let withdrawal = bridge_out(
                to.chain,
                swapped_mint,
                swapped_amount,
                recipient,
            )?;
            ConversionResult {
                recipient,
                amount: swapped_amount,
                asset: swapped_mint,
                location: to.chain,
                withdrawal_id: withdrawal.id,
            }
        };

    Ok(final_result)
}
```

This structure is:
- ✅ **Correct**: Handles all 9 combinations of (ACE, External) × (ACE, External) automatically
- ✅ **Efficient**: No-ops are cheap, only active phases execute
- ✅ **Maintainable**: One function, not 9
- ✅ **Testable**: All paths covered by single integration test
- ✅ **Extensible**: Adding new chain type = add bridge in/out, rest is automatic

### 1.4 Trust Boundary: What ACE Atomicity Does and Does Not Cover

The system should be evaluated as three separate trust zones:

```
Zone 1: ACE-internal execution
  - Strongest security boundary
  - Unified StateTree, n-VM token ledger, and atomic swap execution
  - MEV-ACE mitigates proposer-controlled ordering MEV for admitted transactions

Zone 2: External-chain ingress
  - Source of truth is the external chain
  - Security depends on finality depth, event/proof verification, and relayer quorum
  - ACE cannot safely mint wrapped assets until the deposit is verified

Zone 3: External-chain egress
  - Phase A source of truth is ACE, but funds are paid from relayer-held pools
  - Security depends on multi-sig custody, withdrawal caps, replay controls, and monitoring
  - Future phases should move egress from custodial payment to proof-verified release
```

This distinction is central to the product claim. ACE can make the **swap and cross-VM settlement leg** atomic, fast, and MEV-resistant. It does not make external-chain finality, deposit verification, or egress custody disappear. The near-term system is best described as a **low-fee ACE-centered liquidity hub with capped bridge trust**, not as a fully trustless bridge.

---

## 2. The Liquidity Problem & Solution

### 2.1 The Challenge: Why LPs Must Be Incentivized

Traditional cross-chain bridges fail LPs because:
1. **Risk asymmetry**: LP capital on chain A isn't fungible with capital on chain B
2. **Inventory cost**: LPs must hold diverse assets across chains
3. **Smart contract risk**: Each new chain integration introduces audit/deploy risk
4. **MEV externalities**: Liquidity on external chains is exploited by searchers

**Result**: LPs demand 0.5–1.5% fees to compensate for risk + opportunity cost.

### 2.2 ACE Chain's Structural Advantage

> **Note**: The "traditional" figures below are illustrative estimates of bridge-plus-DEX round trips, not measured quotes from any specific protocol (actual bridge transfer fees vary widely; e.g., pure stablecoin transfers on major bridges can be well below 0.1%, while bridge+swap+swap routes for non-stable pairs commonly total 0.5%+). Treat this as a cost-structure argument, not benchmark data.

```
Traditional Bridge+DEX Cost Structure (per cross-chain swap, illustrative):
├─ Bridge protocol fee:             0.05–0.50%
├─ DEX swap fees (source + dest):   0.30–0.60%
├─ Relayer/gas overhead:            0.05–0.10%
└─ MEV/slippage leakage:            0.10–0.20%
   ════════════════════════════════════════════
   Total user cost:                 0.50–1.40%

ACE Bridge Cost Structure (per cross-chain swap, design target):
├─ Swap fee (LP incentive):         0.05–0.10%
├─ Relayer operation:               0.01–0.02%
├─ Network costs (amortized):       0.01%
└─ Risk premium:                    small but nonzero
   └─ Relayer custody risk on egress pool and attestation
      trust on ingress remain; mitigated by multi-sig,
      not eliminated.
   ════════════════════════════════════════════
   Total user cost:                 ~0.1–0.2%
```

### 2.3 LP Compensation Model (Multiple Revenue Streams)

LPs in the ACE system earn from **three concurrent sources**, making 0.1% fees sustainable:

#### A) Swap Fee Revenue
- Standard AMM share: LP captures `(fee_numerator / fee_denominator)` of every trade
- Current ace-defi uses 0.3% (3/1000), but cross-chain version can safely run 0.05–0.1%
- **Why lower is better**: attracts more volume, reduces MEV risk, easier for users

**Example: 0.1% swap fee**
```
LP deposits: 1M wUSDT + 1M wTRX (= $2M AUM)
Daily volume: $100M (if the bridge attracts reasonable traffic)
Daily fee captured: $100M × 0.001 = $100K
LP share (assume 5% of pool): $5K/day
Annualized: $5K × 365 = $1.825M
APY on $100K deposit: 1,825%
```

But wait—that's unrealistic volume. Let's be conservative:

**Realistic scenario: $1M daily volume**
```
Daily fee captured by pool: $1M × 0.001 = $1K
LP share (5% of pool): $50/day
Annualized: $18,250
APY on $100K deposit: 18.25%
```

This is competitive with major AMM LP returns. **Caveat**: this projection assumes daily volume ≈ 50% of pool TVL ($1M volume on a $2M pool), which is an aggressive turnover ratio — mature AMM pools typically see 5–30% daily turnover. APY scales linearly with the volume/TVL ratio: at 10% daily turnover the same pool yields ~3.7% APY.

#### B) LP Token Appreciation (Optional)
- If the protocol grows, ACE governance token appreciation
- LPs earn points/multiplier toward governance share (proposed in governance section)

#### C) Spread Arbitrage Opportunity
```
Scenario: ACE-internal wUSDT:wTRX price differs from external markets

External market: 1 USDT = 10 TRX
ACE pool state: 1 USDT = 9.8 TRX (due to directional imbalance)

LP opportunity:
  - Deposit to ACE pool: 1 USDT → receive 9.8 TRX
  - Immediately withdraw TRX to Tron chain: 9.8 TRX → $9.80 external value
  - Withdraw USDT from ACE to BSC: 1 USDT → $1.00 external value
  - Net profit from rebalancing: ~$0.20 per cycle

This incentivizes LPs to:
1. Monitor external market prices
2. Rebalance pool toward equilibrium
3. Stabilize internal ACE prices against external markets
```

---

## 3. Ingress Layer (Deposit Bridge)

### 3.1 Architecture

```
External Chain (e.g., BSC)
┌──────────────────────┐
│ User deposits 1 USDT │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────────────┐
│ Bridge Smart Contract (BSC)      │
│ - Locks USDT or burns synthetic  │
│ - Emits DepositEvent with:       │
│   * amount, token, recipient     │
│   * target_vm (e.g., Solana)     │
│   * target_asset (e.g., SOL)     │
└──────────┬───────────────────────┘
           │ Relayer monitors
           ▼
ACE Chain
┌──────────────────────────────────┐
│ Relayer Service                  │
│ - Listens to all external chains │
│ - Verifies deposit proof/event   │
│ - Signs attestation:             │
│   SIGN(deposit_id, amount, ...)  │
└──────────┬───────────────────────┘
           │
           ▼
┌──────────────────────────────────┐
│ ACE Chain: process_signed_deposit│
│ - Verify relayer signature       │
│ - Verify replay (idempotent)     │
│ - Mint wUSDT to user             │
│ - Update BridgeState             │
└──────────┬───────────────────────┘
           │
           ▼
         User has wUSDT in ACE state tree
```

### 3.2 Key Implementation Details

#### Deposit Record Structure
```rust
pub struct DepositRecord {
    // Unique identifier (from external chain event hash)
    deposit_id: [u8; 32],
    
    // Source chain and asset
    source_chain: ChainId,      // e.g., BSC
    source_asset: ExternalAsset, // e.g., USDT on BSC
    amount: u64,
    
    // Destination parameters
    target_vm: VmId,            // e.g., Solana (SVM), Tron (TVM)
    target_asset: ExternalAsset, // e.g., SOL, TRX (for internal swap)
    
    // Final recipient
    recipient: AccountId,       // ACE user account
    
    // Relayer attestation
    relayer_signature: Vec<u8>,
    timestamp: u64,
}
```

#### Idempotency & Deduplication
```
Problem: Relayer submits same deposit twice (network retry, operator error)

Solution (existing in ace-defi):
  - Maintain processed_deposits HashSet in BridgeState
  - Also persist to StateTree under bridge authority account
  - Check both on every process_deposit() call
  - Return idempotent success if already processed
```

#### Handling Multi-Signature Relayers
```
For production, relayer should be multi-signature to prevent:
  - Relayer key compromise
  - Single operator censoring deposits

Implementation:
  1. Define approved_relayers in BridgeState
  2. Require M-of-N signatures (e.g., 3-of-5)
  3. Aggregate signatures on-chain via batch verification
  4. Example: Threshold BLS signatures or simple threshold-ECDSA
```

---

## 4. Swap Layer (ACE-Internal Atomic Execution)

### 4.1 The Core Insight: Why Internal Swaps Are Superior

**Traditional cross-chain swap**:
```
User: "Swap BSC-USDT to Solana-SOL"
      ↓
Step 1: Swap USDT → USDC on BSC Uniswap (~150K gas, $5–50, ~15 sec)
Step 2: Bridge USDC from BSC to Solana Wormhole (~$2–5, ~90 sec)
Step 3: Swap USDC → SOL on Solana (~$0.50, ~5 sec)
      ↓
Total user cost: $10–60 + 110 seconds
MEV risk: High (each swap is visible to searchers)
```

**ACE internal swap**:
```
User: "Swap wUSDT to wSOL"
      ↓
Single atomic transaction in ACE:
  1. Debit user's wUSDT balance
  2. Execute swap via AMM (wUSDT ↔ wSOL pool)
  3. Credit user's wSOL balance
      ↓
Total cost: Single TX_FEE (fixed, ~$0.01 equivalent)
MEV risk: ordering MEV eliminated for admitted txs (MEV-ACE);
          information-based MEV (e.g., oracle back-running) out of scope
Latency: ~400ms (one ACE slot)
```

### 4.2 Enhanced Pool Architecture for Cross-Chain

Current ace-defi uses simple constant-product pools (x·y=k). For cross-chain, we enhance:

#### Pool Structure
```rust
pub struct CrossChainPool {
    pub pool_id: AccountId,
    pub token_a: WrappedMint,
    pub token_b: WrappedMint,
    
    // Reserves (current balances)
    pub reserve_a: u64,
    pub reserve_b: u64,
    
    // LP token
    pub lp_mint: AccountId,
    pub lp_supply: u64,
    
    // NEW: Pool-level metadata for cross-chain context
    pub chain_a: ChainId,        // e.g., Ethereum
    pub chain_b: ChainId,        // e.g., Solana
    
    // Swap fee (configurable, default 0.1%)
    pub swap_fee_bps: u64,       // basis points (100 = 1%)
    
    // LP performance tracking
    pub total_fees_collected: u64,
    pub last_rebalance_slot: u64,
}
```

#### Dynamic Fee Adjustment (Optional, for Advanced)
```
Rationale: High volatility requires higher fees to compensate LP for IL

Algorithm:
  if (current_price_deviation > threshold) {
    fee = base_fee + (deviation × fee_multiplier)
  }

Example:
  Base fee: 0.05%
  Current deviation (ACE price vs market): 1%
  Fee multiplier: 0.1 bps per 0.1% deviation
  => Fee charged: 0.05% + (1% × 0.1) = 0.15%
```

### 4.3 Price Oracle Integration

**Problem**: How does the swap know the fair exchange rate between wUSDT and wTRX?

**Options**:

A) **External Oracle (Chainlink/Pyth)** — Recommended for MVP
```
Benefits:
  - Mature, audited infrastructure
  - Feeds from multiple sources
  - Transparent on-chain price

Costs:
  - Oracle latency (~10–30 sec updates)
  - Small feed cost (~$0.001 per swap)
  - Potential for price manipulation (but rare with Chainlink)

Implementation:
  ace_swap::execute_with_oracle_price()
    → Fetch price from Chainlink contract
    → Use as "fair" swap rate
    → Apply slippage tolerance: [price × (1 - slippage%), price × (1 + slippage%)]
```

B) **Internal VWAP (Volume-Weighted Average Price)** — Advanced
```
Maintain rolling window of swap prices on ACE:
  - Track every swap: amount_in, amount_out, timestamp
  - Compute VWAP over last 24 hours
  - Use VWAP as reference for slippage checks
  
Benefits:
  - Resistant to single external oracle failures
  - Reflects actual market behavior on ACE
  - No external dependency

Costs:
  - Requires historical data storage
  - More complex to implement
```

C) **Hybrid (Recommended for Production)**
```
Use external oracle as primary, VWAP as sanity check:

  external_price = oracle.price()
  internal_vwap = compute_vwap_24h()
  
  deviation = abs(external_price - internal_vwap) / internal_vwap
  
  if deviation > 5%:
    // Oracle might be stale or compromised
    use internal_vwap
  else:
    // Oracle looks healthy
    use external_price with tight slippage
```

---

## 5. Egress Layer (Withdrawal Bridge)

### 5.1 Architecture

```
User on ACE Chain
┌──────────────────────────┐
│ Holds wTRX              │
│ Initiates withdrawal:   │
│ burn wTRX, send to addr │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────────────┐
│ ACE request_withdrawal()         │
│ - Burn wTRX from user            │
│ - Create WithdrawalRecord:       │
│   * withdrawal_id                │
│   * amount, token, destination   │
│   * state_root_proof             │
│ - Record in StateTree            │
└──────────┬───────────────────────┘
           │
           ▼
┌──────────────────────────────────┐
│ Relayer monitors ACE state       │
│ - Detect new WithdrawalRecord    │
│ - Verify against ACE state root  │
│ - Check replay (withdrawal_id)   │
└──────────┬───────────────────────┘
           │
           ▼
External Chain (e.g., Tron)
┌──────────────────────────────────┐
│ Relayer's pre-funded wallet      │
│ (NO contract on egress side)     │
│ - Plain transfer: send native    │
│   TRX / token to recipient       │
│ - Relayer marks withdrawal       │
│   completed back on ACE          │
└──────────────────────────────────┘
           │
           ▼
    Recipient has native TRX on Tron
```

### 5.2 Withdrawal Record & Relayer-Side Verification

```rust
pub struct WithdrawalRecord {
    pub withdrawal_id: u64,
    pub sender: AccountId,
    pub wrapped_mint: AccountId,  // e.g., wTRX
    pub amount: u64,
    pub external_destination: Vec<u8>, // destination-chain address
    pub created_slot: u64,
    pub completed: bool,
    
    // Commitment data (for relayer-side verification)
    pub state_root_proof: [u8; 32], // Merkle path to this record
    pub state_root_hash: [u8; 32],  // ACE block's StateTree root
}
```

#### Verification Happens Off-Chain, in the Relayer

There is **no withdrawal contract on the external chain** (see Section
5.3). All verification happens on the relayer side before it sends
funds from its pre-funded wallet:

```
Relayer, before executing a withdrawal (destination chain is just an
example — same flow for Tron, Ethereum, BSC, Solana, ...):

1. Read WithdrawalRecord from ACE state via RPC.
2. Verify the Merkle path: state_root_proof leads from the record to
   state_root_hash of a finalized ACE block (guards against a
   compromised/forked RPC node; ideally cross-check the root against
   multiple ACE nodes).
3. Check replay: withdrawal_id not yet executed (local persistent
   store + the on-ACE `completed` flag).
4. Execute a plain wallet transfer of `amount` to
   `external_destination` on the destination chain.
5. Submit mark_withdrawal_completed(withdrawal_id, tx_hash) back to ACE.
```

The trust anchor is ACE finality plus the relayer's honesty/multi-sig
custody of the egress pool — not any destination-chain contract. A
fully trustless variant (on-chain ACE light client + Merkle proof
verification on the destination chain) remains possible as a future
decentralization upgrade (see Section 13.3), at the cost of
reintroducing per-chain contract deployment and audit burden.

### 5.3 Minimal Smart Contract Risk: The Elegance of Contract-Free Egress

This system achieves a **fundamental security asymmetry** that most cross-chain bridges miss: the ingress (deposit) layer requires smart contracts, but the **egress (withdrawal) layer does not**.

#### Why Contracts Are Necessary on Ingress

```
On External Chain (e.g., BSC):

function deposit(amount: u256, recipient: bytes32) {
    // 1. Receive USDT from user
    usdt.transferFrom(msg.sender, address(this), amount);
    
    // 2. Lock it (or burn if wrapped)
    if is_native_usdt:
        locked_balance[recipient] += amount;
    else:
        usdt_contract.burn(amount);
    
    // 3. Emit event for relayer
    emit Deposit(recipient, amount, timestamp);
}
```

**Why complex?** The contract must:
- Validate that actual funds arrived (prevent double-spend)
- Securely lock/burn them (prevent withdrawal before ACE confirms)
- Be auditable (because users are trusting this contract with funds)

**Risk**: A single bug here can lock user funds forever or enable rug pulls.

#### Why Contracts Are NOT Needed on Egress

```
On External Chain (e.g., Tron):

// This is all we need:
function withdraw(amount: u64, recipient: address) {
    // Pre-condition: Relayer already holds native TRX in an escrow wallet
    payable(recipient).transfer(amount);
}

That's it. No contract verification needed.
```

**Why so simple?** Because:
1. **Funds already exist** in the relayer's wallet (pre-funded)
2. **Verification already happened** on ACE (state root proof was checked once)
3. **Transfer is stateless** — no contract state to corrupt, no validation to fail
4. **User gets asset immediately** — no waiting for cross-chain confirmation

#### Asymmetric Trust Model

```
Traditional Cross-Chain Bridge (High Complexity):
┌─ Deposit ──────────────┐         ┌─ Withdrawal ──────────┐
│ Smart Contract: COMPLEX │         │ Smart Contract: COMPLEX │
│ - Validate deposit      │         │ - Verify proof         │
│ - Lock/burn asset       │         │ - Check replay         │
│ - Mint token on chain B │         │ - Execute transfer     │
│ RISK: High             │         │ RISK: High             │
└────────────────────────┘         └────────────────────────┘

ACE Bridge (Asymmetric Simplicity):
┌─ Deposit ──────────────┐         ┌─ Withdrawal ──────────┐
│ Smart Contract: MINIMAL │         │ No Contract Needed!    │
│ - Receive + lock asset  │         │ - Simple transfer()    │
│ - Emit event            │         │ - Pre-funded pool      │
│ RISK: Contained        │         │ RISK: Minimal          │
└────────────────────────┘         └────────────────────────┘
```

#### Safety Analysis: Where Risks Live

```
Risk Category          | Ingress | Egress | Mitigation
====================== | ======= | ====== | ===================
Smart contract bug     | HIGH    | NONE   | Audit carefully
Relayer key theft      | MEDIUM  | HIGH   | Multi-sig, timelocks
Fund loss on deposit   | MEDIUM  | LOW    | Honest relayer only
Fund loss on withdraw  | LOW     | NONE   | Funds already in escrow
Proof forgery          | LOW     | NONE   | ACE consensus guards
Replay attack          | LOW     | LOW    | Nonce tracking
```

**Key insight**: Egress failures are **asymptotically lower risk** because:
- No code execution on external chain (just transfer)
- No state mutation (pre-funded pool, just transfer out)
- No conditional logic (either amount exists or doesn't)
- **Worst case**: Insufficient balance → transaction reverts, no theft

#### Economic Consequence: Asymmetric Fee Structure

Because ingress needs auditing but egress doesn't, fees are justified differently:

```
Ingress Fee (necessary for security):
  0.1% of deposit
  Covers:
    - External chain gas (~$1-10 for BSC USDT)
    - Relayer operational cost (~$0.10)
    - Audit amortization (~$0.01)
    - Risk premium (~$0.01)
  Total: ~0.1%

Egress Fee (minimal, for operational cost only):
  0.05% of withdrawal (can be lower!)
  Covers:
    - Relayer transfer gas (~$0.10 on Tron)
    - Zero operational/audit cost (no contract)
    - Zero risk premium (no contract risk)
  Total: ~0.01-0.05%

Result: Withdrawals can be cheaper than deposits!
```

#### Implementation Simplification

This asymmetry makes implementation dramatically simpler:

```rust
// Ingress: Full validation on chain
pub fn deposit_on_bsc(user: address, amount: u256) {
    require(usdt_balance(user) >= amount, "Insufficient balance");
    require(usdt_allowance(user) > 0, "Need approval");
    // Lock/burn complex logic...
    // Emit event for relayer
}

// Egress: Trivial operation
pub fn withdraw_on_tron(recipient: address, amount: u256) {
    require(relayer_pool_balance >= amount, "Pool empty");
    payable(recipient).transfer(amount);
    // That's it!
}
```

The relayer pool is pre-funded (separate operational process), so withdrawal is just a **transfer from a wallet**, not a smart contract operation.

#### Operational Security Pattern

```
Phase 1: Bootstrap (One-time)
  - Relayer deploys deposit contract on all external chains
    (These are audited once, then immutable)
  - Relayer pre-funds withdrawal accounts on all chains
    (Multi-sig controlled, with minimum balances)

Phase 2: Operation (Ongoing)
  - Deposits: User → [Contract validates] → ACE (relayer mints)
  - Withdrawals: ACE [records withdrawal] → Relayer [transfers from pre-fund]
  - Rebalancing: Relayer monitors pool balances, rebalances as needed

Phase 3: Recovery (If needed)
  - If deposit contract is buggy: Governance can pause new deposits (only)
    Existing deposits still finalize because contract is immutable
  - If withdrawal balance low: Relayer rebalances from other chains
    No contract change needed, just wallet transfers

Critical: Egress never fails due to contract bug (no contract to bug!)
```

#### Why This Matters for Governance

Because egress has no smart contract:
- **No upgrade needed for egress** (ever)
- **Deposits can be upgraded** (governance can pause, redeploy)
- **Withdrawals are always executable** (as long as relayer is funded)

This creates a **clean upgrade path**:
```
Problem: Found bug in deposit contract

Solution:
  1. Governance votes to pause new deposits
  2. Deploy new deposit contract (audited fix)
  3. Route future deposits to new contract
  4. Withdrawals continue working (no contract involved!)
  5. Users with funds already on ACE keep using exit route

Users never lose access to their funds because withdrawal
is a simple transfer, not dependent on contract logic.
```

---

## 6. Economic Design & Fee Structure

### 6.1 Fee Layers

```
┌─────────────────────────────────────────────────────┐
│ User deposits 100 USDT on BSC                       │
└────────────────────┬────────────────────────────────┘
                     │
        ┌────────────▼────────────┐
        │ Bridge operator fee:    │ 0.1% = 0.1 USDT
        │ (covers BSC gas cost)   │
        └────────────┬────────────┘
                     │
        ┌────────────▼─────────────────────────┐
        │ User receives: 99.9 wUSDT on ACE    │
        └────────────┬─────────────────────────┘
                     │
        ┌────────────▼────────────┐
        │ Internal ACE Swap Fee:   │ 0.1% of amount swapped
        │ (goes to LPs)            │ = 0.0999 wUSDT
        │ Formula: swap_amount     │
        │ × (FEE_NUM/FEE_DEN)      │
        └────────────┬────────────┘
                     │
        ┌────────────▼─────────────────────────┐
        │ User swaps 99.9 wUSDT → ~980 wTRX   │
        │ (actual amount depends on pool k)    │
        └────────────┬─────────────────────────┘
                     │
        ┌────────────▼────────────┐
        │ Withdrawal Bridge fee:   │ 0.1% = ~0.98 TRX
        │ (covers Tron gas cost)   │
        └────────────┬────────────┘
                     │
        ┌────────────▼──────────────────────┐
        │ User receives on Tron: ~979 TRX  │
        └──────────────────────────────────┘

Total user cost: ~0.3% (0.1% bridge in + 0.1% swap + 0.1% bridge out)
Compared to a typical bridge+DEX route (~0.5–1.4%, see Section 2.2)
ACE advantage: lower fees, plus deterministic execution on the swap leg
```

### 6.2 Fee Allocation

```
Fee collected in ACE Swap: 0.0999 wUSDT

Distribution:
├─ 70% → LP reward pool        : 0.06993 wUSDT
│        (split pro-rata by LP share in pool)
│
├─ 20% → Relayer compensation : 0.01998 wUSDT
│        (for BSC→ACE and ACE→Tron operations)
│
└─ 10% → Protocol treasury     : 0.00999 wUSDT
         (for governance, development)
```

### 6.3 LP Revenue Projection (Realistic)

```
Scenario: 0.1% swap fee, daily volume $1M

Pool: wUSDT ↔ wTRX
TVL: $10M (split equally: $5M each token)

Daily fee: $1M × 0.001 = $1,000
LP share (you own 0.1% of pool = $10,000 stake): $1/day
Annual revenue: $365
APY: $365 / $10,000 = 3.65%

Note: APY here is fully determined by (daily volume / TVL) × fee × 365.
At $1M daily volume on $10M TVL (10% turnover) and 0.1% fee, fee APY is
~3.65% regardless of stake size. Higher APY requires higher turnover:
the 18%+ scenarios elsewhere in this document assume ~50% daily turnover.
```

---

## 7. Relayer Architecture & Trust Model

### 7.1 The Problem: Trust in Bridges

Bridges are inherently trust-bearing. The relayer must:
1. Monitor deposits on external chains
2. Attest that a deposit happened
3. Execute withdrawals on external chains

If the relayer is compromised:
- It can fabricate deposits (mint arbitrary amounts of wUSDT)
- It can steal withdrawal funds
- It can censor legitimate deposits

### 7.2 Single-Signature Relayer (MVP, 0–3 weeks)

**Simplest design for proof-of-concept**:
```
Relayer: Single trusted operator (e.g., ACE team)
  - Runs monitoring bots on all external chains
  - On deposit event: signs attestation with private key
  - On withdrawal request: executes transfer with hot wallet

Trust assumption: The single operator is honest
Risk: If private key is compromised, attacker can mint unlimited tokens

Mitigation:
  - Use hardware wallet or multi-sig safeguard (slow, but safe)
  - Regular key rotation
  - Timelock delays on large operations
  - Monitoring for suspicious activity

When to use: Testing, devnet, initial launch
```

### 7.3 Multi-Signature Relayer (Production, Week 4+)

**Threshold signature scheme (3-of-5 recommended)**:

```
5 Relayers (could be: ACE team + 2 protocols + 2 validators)
  - Each signs deposit attestations independently
  - Need 3-of-5 signatures to submit to ACE
  - Prevents any single operator from fabricating deposits

Implementation (using BLS threshold signatures):
  1. Each relayer computes signature on (deposit_id, amount, ...)
  2. Signatures are aggregated on-chain
  3. Aggregate signature is verified against protocol's public key
  4. Requires any M-of-N subset to produce valid signature

Security model:
  - Attacker needs to compromise 3-of-5 relayers simultaneously
  - Assumes relayers are diverse (different orgs, different infra)
  - Still cheaper than maintaining separate bridge smart contracts
```

**Or: Distributed committee with governance**:
```
Validator set from ACE consensus could sign off on deposits:
  - Use existing BFT voting mechanism
  - 2/3 + 1 validators must attest to deposit
  - Reuses existing consensus infrastructure

Pros:
  - Already battle-tested (consensus engine)
  - Decentralized (thousands of validators)
  - No new trust assumptions

Cons:
  - Adds latency (wait for 2/3 consensus)
  - Requires validator set to coordinate
  - More complex to implement
```

### 7.4 Relayer Incentive Mechanisms

**How to incentivize relayers to stay online?**

```
Option A: Fee share
  - Relayers earn % of protocol treasury
  - Aligned with protocol success
  - Scalable with volume

Option B: Fixed subsidy
  - Protocol pays X ACE per relayed transaction
  - Covers hardware/bandwidth costs
  - Independent of volume

Option C: Slashing
  - Relayers must post bond (e.g., 100 ACE)
  - Slashed if caught signing false attestations
  - Requires on-chain dispute mechanism

Recommended: Hybrid (A + B)
  - Base fee share (50% of protocol fee)
  - Minimum subsidy if volume is low
  - Slashing for malicious behavior
```

### 7.5 Relayer Implementation: Monitoring and Execution

This section covers the **practical implementation** of how relayers monitor external chains and trigger ACE Chain state changes.

#### 7.5.1 Ingress Flow: External Chain → ACE (Deposit)

**High-level process**:
```
Ethereum (External)
  ↓ User calls deposit()
  ↓ emits DepositEvent
  ↓
Relayer Service
  ↓ Monitors Ethereum blocks
  ↓ Detects DepositEvent
  ↓ Waits for finality (12–15 blocks)
  ↓ Signs attestation
  ↓
ACE Chain (Internal)
  ↓ process_signed_deposit()
  ↓ Verify relayer signature
  ↓ Mint wUSDT
  ↓ User has wUSDT (can now swap internally)
```

**Relayer pseudocode for ingress**:

```python
class RelayerService:
    def __init__(self):
        self.eth_client = EthereumRPC(url=ETH_RPC)
        self.ace_client = ACEChainRPC(url=ACE_RPC)
        self.last_scanned_block = load_checkpoint("last_eth_block")
        self.private_key = load_secret("relayer_signing_key")
    
    def monitor_ethereum_deposits(self):
        """Main loop: continuously watch for deposits on Ethereum"""
        while True:
            try:
                # Fetch new blocks from Ethereum
                current_block = self.eth_client.get_block_number()
                
                for block_num in range(self.last_scanned_block + 1, current_block + 1):
                    block = self.eth_client.get_block(block_num)
                    
                    # Skip if block not finalized yet
                    # Ethereum finality: ~15 blocks (3 minutes at 12s blocks)
                    if (current_block - block_num) < 15:
                        continue
                    
                    # Parse events from this block
                    logs = self.eth_client.get_logs(
                        from_block=block_num,
                        to_block=block_num,
                        address=BRIDGE_CONTRACT,
                        topics=[DEPOSIT_EVENT_SIGNATURE]
                    )
                    
                    for log in logs:
                        deposit = parse_deposit_event(log)
                        
                        # Skip if already processed (idempotency)
                        if self.is_deposit_processed(deposit.deposit_id):
                            continue
                        
                        # Now process the deposit
                        self.process_deposit(deposit)
                
                # Save checkpoint
                self.last_scanned_block = current_block
                save_checkpoint("last_eth_block", current_block)
                
            except Exception as e:
                logger.error(f"Ethereum monitoring error: {e}")
                # Retry after backoff
                time.sleep(30)
    
    def process_deposit(self, deposit: DepositEvent):
        """Process a single deposit: sign and submit to ACE"""
        logger.info(f"Processing deposit: {deposit}")
        
        try:
            # 1. Construct attestation message
            attestation = {
                "deposit_id": deposit.deposit_id,
                "source_chain": "ethereum",
                "amount": deposit.amount,
                "recipient": deposit.recipient,
                "timestamp": time.time(),
                "relayer": self.relayer_id
            }
            
            # 2. Sign the attestation
            message_hash = hash(encode(attestation))
            signature = sign(message_hash, self.private_key)
            
            # 3. Submit to ACE Chain
            tx_hash = self.ace_client.send_transaction(
                method="process_signed_deposit",
                params={
                    "attestation": attestation,
                    "signature": signature,
                    "relayer_id": self.relayer_id
                }
            )
            
            logger.info(f"Submitted to ACE: tx={tx_hash}")
            
            # 4. Wait for ACE confirmation
            receipt = self.ace_client.wait_for_receipt(
                tx_hash,
                timeout=30  # seconds
            )
            
            if receipt.status == SUCCESS:
                logger.info(f"Deposit confirmed on ACE: {deposit.deposit_id}")
                # Mark as processed to avoid duplicate submission
                self.mark_processed(deposit.deposit_id)
            else:
                logger.error(f"ACE transaction failed: {receipt.error}")
                # Don't mark as processed; will retry next cycle
                
        except Exception as e:
            logger.error(f"Failed to process deposit {deposit.deposit_id}: {e}")
            # Will retry in next monitoring cycle
```

**Key parameters by chain**:

```
Chain      | Confirmation Depth | Block Time | Total Wait
-----------|--------------------|------------|------------
Ethereum   | 12-15 blocks       | 12 sec     | ~150-180 sec
BSC        | 15-20 blocks       | 3 sec      | ~45-60 sec
Solana     | ~32 slots (rooted) | 0.4 sec    | ~13 sec
Tron       | 19-32 blocks       | 3 sec      | ~60-100 sec

Note: Ethereum's 12-15 blocks is a confirmation-depth heuristic, not
protocol finality (economic finality is ~2 epochs ≈ 13 minutes). For
large deposits the relayer should wait for finalized checkpoints;
12-15 blocks is acceptable only with per-deposit value caps.
```

**Monitoring best practices**:
```
✓ Use multiple Ethereum RPC endpoints (fallback if one fails)
✓ Maintain local block cache (avoid repeated RPC calls)
✓ Log all events to database (audit trail)
✓ Alert if block gap detected (monitoring offline)
✓ Implement exponential backoff on RPC failures
✓ Use WebSocket for real-time block events (not polling)
```

#### 7.5.2 Egress Flow: ACE → External Chain (Withdrawal)

**High-level process**:
```
ACE Chain (Internal)
  ↓ User calls burn_and_request_withdrawal(100 wTRX)
  ↓ Burns 100 wTRX from user
  ↓ Creates WithdrawalRecord
  ↓
Relayer Service
  ↓ Monitors ACE StateTree
  ↓ Detects WithdrawalRecord
  ↓ (NO finality wait needed; ACE is our source of truth)
  ↓ Executes transfer on Tron
  ↓
Tron (External)
  ↓ Receives 100 TRX at user's address
  ↓ (No proof verification; Relayer signature is authority)
```

**Relayer pseudocode for egress**:

```python
class RelayerService:
    def monitor_ace_withdrawals(self):
        """Watch ACE Chain StateTree for new withdrawal records"""
        while True:
            try:
                # Query ACE for pending withdrawals
                # (This reads StateTree directly via RPC)
                withdrawals = self.ace_client.query(
                    method="get_pending_withdrawals",
                    filter={
                        "status": "pending",
                        "processed_by_relayer": False
                    }
                )
                
                for withdrawal in withdrawals:
                    if not self.is_withdrawal_processed(withdrawal.id):
                        self.execute_withdrawal(withdrawal)
                
            except Exception as e:
                logger.error(f"ACE monitoring error: {e}")
                time.sleep(10)
    
    def execute_withdrawal(self, withdrawal: WithdrawalRecord):
        """Execute a withdrawal on the destination chain"""
        logger.info(f"Executing withdrawal: {withdrawal}")
        
        try:
            # 1. Route to correct chain handler
            if withdrawal.destination_chain == "tron":
                self.execute_on_tron(withdrawal)
            elif withdrawal.destination_chain == "ethereum":
                self.execute_on_ethereum(withdrawal)
            elif withdrawal.destination_chain == "solana":
                self.execute_on_solana(withdrawal)
            else:
                logger.error(f"Unknown chain: {withdrawal.destination_chain}")
                
        except Exception as e:
            logger.error(f"Failed to execute withdrawal {withdrawal.id}: {e}")
            # Will retry in next monitoring cycle
    
    def execute_on_tron(self, withdrawal: WithdrawalRecord):
        """Execute withdrawal on Tron chain (simple transfer)"""
        
        # 1. Prepare transaction
        tx = {
            "to": withdrawal.recipient_address,
            "amount": withdrawal.amount,
            "token": TRON_TRX,  # Native TRX
            "memo": f"ACE-Withdrawal-{withdrawal.id}"
        }
        
        # 2. Sign with Relayer's Tron wallet
        signed_tx = self.tron_client.sign_transaction(
            tx,
            private_key=self.tron_relayer_key
        )
        
        # 3. Broadcast to Tron network
        tx_hash = self.tron_client.broadcast(signed_tx)
        logger.info(f"Tron transaction broadcast: {tx_hash}")
        
        # 4. Wait for confirmation (28 blocks = ~84 seconds)
        receipt = self.tron_client.wait_for_receipt(
            tx_hash,
            timeout=120
        )
        
        if receipt.status == SUCCESS:
            # 5. Notify ACE that withdrawal is complete
            ace_tx = self.ace_client.send_transaction(
                method="mark_withdrawal_completed",
                params={
                    "withdrawal_id": withdrawal.id,
                    "tron_tx_hash": tx_hash
                }
            )
            logger.info(f"Withdrawal marked complete on ACE: {ace_tx}")
        else:
            logger.error(f"Tron transaction failed: {receipt.error}")
            # Will retry in next monitoring cycle
    
    def execute_on_ethereum(self, withdrawal: WithdrawalRecord):
        """Execute withdrawal on Ethereum chain (also a plain transfer)"""
        
        # Same contract-free model as Tron: a direct ERC20 transfer
        # from the relayer's pre-funded wallet. No bridge contract is
        # involved on the egress side.
        
        try:
            # Prepare ERC20 transfer from relayer wallet
            tx = {
                "to": USDT_ADDRESS,            # token contract
                "method": "transfer",
                "params": {
                    "recipient": withdrawal.recipient_address,
                    "amount": withdrawal.amount
                }
            }
            
            # Sign and broadcast
            tx_hash = self.eth_client.send_transaction(tx, gas_limit=100000)
            
            # Wait for finality
            receipt = self.eth_client.wait_for_receipt(
                tx_hash,
                confirmations=15
            )
            
            # Mark complete on ACE
            if receipt.status == SUCCESS:
                self.ace_client.send_transaction(
                    method="mark_withdrawal_completed",
                    params={
                        "withdrawal_id": withdrawal.id,
                        "eth_tx_hash": tx_hash
                    }
                )
        except Exception as e:
            logger.error(f"Ethereum withdrawal failed: {e}")
```

**Key architectural points**:

```
Ingress (External → ACE):
  Source of truth: External chain
  Verification: Finality wait + Relayer signature
  Security: Multi-sig on ACE side
  Latency: ~150-180 sec (waits for finality)

Egress (ACE → External):
  Source of truth: ACE Chain (fully trusted)
  Verification: Relayer reads StateTree directly
  Security: Relayer signature on destination chain
  Latency: ~1-2 sec (no verification needed)
```

#### 7.5.3 Multi-Relayer Coordination

For multi-signature (3-of-5) relayers:

```python
class MultiSigRelayerPool:
    def __init__(self, relayers: List[Relayer], threshold: int = 3):
        self.relayers = relayers
        self.threshold = threshold
        
    def process_deposit_multi_sig(self, deposit: DepositEvent):
        """Coordinate among multiple relayers"""
        
        # 1. Each relayer independently signs
        signatures = []
        for relayer in self.relayers:
            sig = relayer.sign_deposit(deposit)
            signatures.append({
                "relayer_id": relayer.id,
                "signature": sig
            })
        
        # 2. Aggregate first N (threshold) signatures
        aggregated = aggregate_bls_signatures(
            signatures[:self.threshold]
        )
        
        # 3. One relayer submits to ACE (the "submitter")
        submitter = self.relayers[0]
        tx_hash = submitter.submit_to_ace(
            deposit=deposit,
            aggregated_signature=aggregated,
            signer_ids=[s["relayer_id"] for s in signatures[:self.threshold]]
        )
        
        logger.info(f"Multi-sig deposit submitted: {tx_hash}")
        
        # 4. ACE verifies signature (threshold-N aggregated)
        # ACE checks: count(verified_signers) >= threshold
```

#### 7.5.4 Failure Recovery and Fallback

```python
class RelayerFailureHandler:
    def detect_stale_deposits(self):
        """Alert if deposits are pending for too long"""
        pending = self.ace_client.get_pending_deposits()
        
        for deposit in pending:
            age_minutes = (now - deposit.timestamp) / 60
            
            if age_minutes > 10:  # Alert threshold
                logger.warning(
                    f"Stale deposit (10+ min): {deposit.id} "
                    f"from {deposit.source_chain}"
                )
                
                # Escalation triggers:
                if age_minutes > 30:
                    alert_protocol_governance()
                    suggest_manual_relayer_intervention()
    
    def manual_relayer_submission(self):
        """Fallback: allow manual submission if automatic fails"""
        
        # Anyone can submit a deposit proof manually
        # (useful if automatic relayer is down)
        
        endpoint = "/manual-bridge"
        
        user_submits = {
            "eth_tx_hash": "0xabc...",
            "proof": merkle_proof,
            "amount": 100,
            "recipient": ace_address
        }
        
        # Verify proof against Ethereum state root
        if verify_ethereum_state(user_submits.proof):
            # Accept manual submission (community member becomes relayer)
            process_deposit(user_submits)
```

---

### 7.6 Custody Roadmap: Staged Trust Model Tied to TVL

The egress design in Section 5.3 is **custodial**: the relayer (multi-sig)
holds the egress pool, and users trust relayer honesty. This is a
deliberate staging decision, not the end state. The business logic:

- Users select bridges on fees, speed, and asset coverage — custody is
  not an adoption blocker (wBTC, CEX transfers, and relayer-fronting
  bridges dominate volume). Custody risk is therefore not a user-acquisition
  problem; it is a **balance-sheet liability that scales with TVL**.
  Historical bridge failures (Ronin, Multichain) were key-custody failures
  at TVL levels far beyond what their trust model could support.
- Non-custodial infrastructure (Section 7.6.2) takes quarters to build.
  Blocking launch on it misallocates engineering while TVL — and hence
  expected loss — is small.

**The rule: trust tier must upgrade before TVL scales.** Concretely:

#### 7.6.1 Phase A — Custodial with Hard Caps (launch)

```
- Egress pool held by multi-sig relayer wallets (Section 5.3)
- Ingress attestation keys SEPARATED from egress payment keys
  (limits blast radius of any single key compromise)
- Hard risk controls, protocol-enforced where possible:
    * per-transaction withdrawal cap
    * per-day aggregate withdrawal cap
    * global TVL ceiling (launch: low seven figures USD)
    * insurance/reserve fund covering a defined fraction of pool
- Purpose of this phase: time-to-market, and validating the core
  economic hypothesis (low fees → high pool turnover, Section 12.4)
  with real traffic before investing in trust-minimization.
```

#### 7.6.2 Phase B — Non-Custodial zk Egress (before TVL scales)

Target model: merge the ingress lock contract and egress pool into
one contract per chain; the contract releases a withdrawal only against a proof that
**ACE consensus finalized a state root containing the WithdrawalRecord**.
The relayer becomes a permissionless message courier — it can censor
(liveness) but cannot steal (safety). A fast path can preserve UX:
the relayer fronts funds instantly and reimburses itself from the
contract with the same proof (Across-style).

**Engineering reality check** (verified against ace-runtime as of
2026-06): the current Finality Certificate proves *transaction
authorization* (ZK-ACE attestation binding), not consensus or state
correctness, and BFT votes are not yet cryptographically materialized.
The zk-egress path therefore requires, in dependency order:

```
1. Signed BFT votes over block hashes (incl. state_root) —
   needed for slashing regardless of the bridge
2. Consensus-proof circuit: SNARK of "2f+1 registered validators
   signed H", plus validator-set rotation handling
3. EVM-verifiable proof form (Groth16/Plonk, or wrapper around
   the existing STARK pipeline)
4. Merkle inclusion of WithdrawalRecord under the proven state root
```

Item 1–2 double as core-chain credibility work independent of the
bridge; their cost should not be attributed to the bridge alone.
No execution-validity proof (zkVM) is needed: 2f+1 votes economically
attest the re-executed state root, placing the bridge in the
light-client trust tier (IBC-class).

#### 7.6.3 Governance Commitment

The Phase A → B transition is bound to a public TVL milestone:
**the global TVL ceiling is not raised beyond the Phase A cap until
zk egress is live**. This converts the upgrade from reactive debt
into a roadmap commitment, and prevents the single fatal failure mode
of custodial bridges: scaling TVL faster than the trust model.

#### 7.6.4 Phase C — HFI-Pay-Style Verified Intent and Trustless Claim Binding

Phase B removes the relayer's ability to steal egress funds, but it
does not by itself fully specify the user's intended conversion tuple.
The next trust-minimization milestone should adopt the HFI-Pay design
pattern: users accept a verifiable quote, and the chain commits the
exact intent before funding or execution.

For ACE DeFi, the generalized object is:

```rust
pub struct ConvertIntent {
    pub intent_id: [u8; 32],
    pub source_chain: ChainId,
    pub source_asset: ExternalAsset,
    pub source_amount: u64,
    pub target_chain: ChainId,
    pub target_asset: ExternalAsset,
    pub min_amount_out: u64,
    pub recipient: Vec<u8>,
    pub refund_destination: Vec<u8>,
    pub expiry_slot: u64,
    pub fee_quote_bps: u64,
    pub relayer_set_id: u64,
    pub nonce: u64,
}
```

The protocol should then enforce:

```
1. Quote: wallet receives the full ConvertIntent plus fee and route data.
2. Verification: wallet checks chain IDs, assets, amount, recipient,
   min_amount_out, expiry, refund path, and deterministic intent_id.
3. Commitment: ACE stores the exact intent tuple before the swap or
   withdrawal can execute.
4. Execution: relayers may only execute the committed tuple.
5. Claim/withdrawal: the destination transfer or proof-verified release
   must bind to the same intent_id, target asset, amount, recipient,
   expiry, and nonce.
6. Refund: after expiry, refund follows the pre-committed refund path
   and cannot be redirected by the relayer.
```

This is the cross-chain DeFi analogue of HFI-Pay's
quote-to-claim composition. It narrows the relayer's role from
"operator that decides routing at execution time" to "message courier
and liquidity executor for a user-verified, chain-committed intent."

This milestone should be treated as a future protocol upgrade, not a
launch blocker. The MVP can validate liquidity demand and fee/turnover
economics first, while Phase C becomes the target architecture for
high-value flows and fully trust-minimized UX.

---

## 8. Risk Management & Safety

### 8.1 Systemic Risks

#### A) Relayer Failure / Downtime
```
Risk: Relayer goes offline
  → Users can't deposit (ingress blocked)
  → Users can't withdraw (egress blocked)

Mitigation:
  - Multiple independent relayers
  - Monitoring and alerting
  - Community fallback (if governance permits)
  - Documentation on manual recovery (governance can approve)
```

#### B) Smart Contract Bugs (External Chain)
```
Risk: Deposit contract on an external chain has a reentrancy bug
  → Attacker drains locked deposit funds, or triggers fake Deposit
    events leading to unbacked mints on ACE
  (Egress has no contract, so this class of bug cannot affect
   withdrawals; the egress-side risk is relayer wallet key custody.)

Mitigation:
  - Full audit before mainnet deployment
  - Bug bounty program ($50K–500K)
  - Conservative upgrade path (e.g., 7-day timelock)
  - Formal verification of critical paths
```

#### C) Price Oracle Manipulation
```
Risk: Attacker flash-loans on external chain to pump asset price
  → Oracle reports inflated price
  → Users swap at bad rate

Mitigation:
  - Use VWAP oracle (volume-weighted, harder to manipulate)
  - Cross-reference multiple oracle sources
  - Tight slippage tolerance (default 0.5%)
  - Emergency pause mechanism if unusual price detected
```

#### D) Liquidity Drain (Impermanent Loss)
```
Risk: Large directional trades deplete one side of pool
  Example: 10M wUSDT entered pool, 0 wTRX received
  → LP trapped with worthless wUSDT

Mitigation:
  - Slippage protection (default 0.5% tolerance)
  - User can specify min_amount_out
  - LPs can set oracle-based rebalance triggers
  - Governance can pause deposits if extreme condition detected
```

### 8.2 Operational Safety Checklist

```
Before mainnet launch:
  [ ] Formal audit of bridge contracts (all chains)
  [ ] Relayer infrastructure redundancy (3+ geographic regions)
  [ ] Multi-sig controls on withdrawal pool funds
  [ ] Oracle circuit breaker (pause if price deviates >5%)
  [ ] Upgrade timelock (7+ days for contract changes)
  [ ] Rate limiting on deposits (e.g., $1M max per slot)
  [ ] Monitoring dashboards (alerts on anomalies)
  [ ] Insurance or validator bond for relayer failures
  [ ] Incident response playbook
```

---

## 9. Integration with Existing ace-defi Code

### 9.1 Minimal Changes to Current Stack

The existing ace-defi is well-designed and can be extended minimally:

```
ace-defi/src/
├── bridge.rs        (existing: deposit/withdraw lifecycle)
│   → Add: external_chain field to DepositRecord
│   → Add: multi-signature verification function
│
├── swap.rs          (existing: constant-product AMM)
│   → Add: CrossChainPool struct (extends Pool)
│   → Add: oracle_price integration (optional)
│   → Add: dynamic fee calculation (optional)
│
├── settle.rs        (existing: atomic swap+withdraw)
│   → No changes needed! Already supports multi-chain params
│
├── runtime.rs       (existing: node-level integration)
│   → Add: relayer attestation verification
│   → Add: oracle feed management
│
├── registry.rs      (existing: asset registration)
│   → Already supports external chains
│
├── deposit.rs       (existing: mint wrapped tokens)
│   → Add: external chain verification (relayer signature)
│
├── withdraw.rs      (existing: burn wrapped tokens)
│   → Add: state proof generation for external verification
│
└── NEW: bridging.rs
    ├── CrossChainPool type
    ├── RelayerAttestation verification
    ├── OraclePrice integration
    └── RiskManagement parameters
```

### 9.2 New Module: `ace-defi/src/bridging.rs`

```rust
//! Cross-chain bridging orchestration.
//!
//! Ties together ingress (deposits), internal swaps, and egress (withdrawals).

use crate::swap::{Pool, SwapEngine};
use crate::registry::AssetRegistry;
use crate::types::ExternalAsset;
use ace_model::state_tree::StateTree;

/// Unified cross-chain bridge state
pub struct CrossChainBridge {
    /// Swap engine (pools, AMM logic)
    swap_engine: SwapEngine,
    
    /// Asset registry (wrapped assets, decimals)
    registry: AssetRegistry,
    
    /// Oracle source (Chainlink, Pyth, etc.)
    oracle: OracleProvider,
    
    /// Relayer set management
    relayers: RelayerSet,
    
    /// Risk parameters
    risk_params: RiskParameters,
}

pub struct RiskParameters {
    /// Maximum deposit per slot (rate limiting)
    max_deposit_per_slot: u64,
    
    /// Oracle price deviation threshold (circuit breaker)
    max_oracle_deviation_bps: u64,
    
    /// Default slippage tolerance
    default_slippage_tolerance_bps: u64,
    
    /// Fee basis points for swaps
    swap_fee_bps: u64,
}

pub struct RelayerSet {
    /// Approved relayers and their public keys
    approved: Vec<RelayerInfo>,
    
    /// Required signatures (M-of-N)
    threshold: usize,
}

impl CrossChainBridge {
    /// Execute full cross-chain flow: deposit → swap → withdraw
    pub fn execute_cross_chain_swap(
        &mut self,
        state: &mut StateTree,
        deposit_proof: DepositProof,
        swap_params: SwapParams,
        withdraw_dest: Vec<u8>,
    ) -> Result<CrossChainResult, Error> {
        // 1. Verify deposit proof (relayer attestation)
        self.relayers.verify_deposit(&deposit_proof)?;
        
        // 2. Get oracle price for slippage check
        let oracle_rate = self.oracle.get_rate(&swap_params.in_asset, &swap_params.out_asset)?;
        
        // 3. Execute atomic swap (via existing settle mechanism)
        let swap_result = self.swap_engine.swap(state, ...)?;
        
        // 4. Request withdrawal (via existing withdraw mechanism)
        let withdrawal = withdraw::request_withdrawal(...)?;
        
        Ok(CrossChainResult { swap_result, withdrawal })
    }
}
```

---

## 10. Technical Implementation Path

### Phase 1: Foundation (Weeks 1–2)

**Goal**: Prove internal swap + withdrawal mechanics work

```
[ ] 1. Extend Pool struct with chain_id fields
[ ] 2. Implement basic RelayerAttestation verification
[ ] 3. Add oracle mock (use fixed prices for testing)
[ ] 4. Create test scenario: BSC-USDT → Solana-SOL
[ ] 5. Verify end-to-end on devnet
```

**Success criteria**:
- User can swap wUSDT → wSOL on ACE
- Withdrawal record is created
- StateTree commitment is verifiable

### Phase 2: Relayer & Oracle (Weeks 3–4)

**Goal**: Real relayer integration and price feeds

```
[ ] 1. Implement multi-signature relayer verification (3-of-5)
[ ] 2. Integrate Chainlink oracle (or mock for devnet)
[ ] 3. Implement oracle circuit breaker logic
[ ] 4. Test deposit path: external chain → ACE
[ ] 5. Test withdrawal path: ACE → external chain (on testnet)
```

**Success criteria**:
- Deposits verified by 3-of-5 relayer signatures
- Prices fetched from oracle, checked for deviation
- Full end-to-end flow on testnet (all chains)

### Phase 3: Safety & Optimization (Week 5)

**Goal**: Production-ready safety mechanisms

```
[ ] 1. Rate limiting on deposits (per slot cap)
[ ] 2. Emergency pause mechanism (governance callable)
[ ] 3. Monitoring dashboards (deposit/swap/withdrawal metrics)
[ ] 4. Slippage protection (default 0.5%)
[ ] 5. Load testing (1000 concurrent deposits)
[ ] 6. Security audit (external firm)
```

**Success criteria**:
- Can handle 1000 TPS cross-chain load
- Rate limiting prevents spam
- Pause mechanism responsive to oracle failures

### Phase 4: Economics & Incentives (Week 6)

**Goal**: LP incentive system + fee mechanics

```
[ ] 1. Fee collection and LP distribution (70/20/10 split)
[ ] 2. LP token minting / APY calculations
[ ] 3. Relayer compensation (fee share + subsidy)
[ ] 4. Governance token integration (UDT)
[ ] 5. Bootstrap liquidity provision plan
```

**Success criteria**:
- LPs can deposit, earn fees, withdraw profits
- Relayers compensated fairly
- Economics simulations quantify LP APY under realistic volume/TVL scenarios

### Phase 5: Production Hardening (Week 7)

**Goal**: Mainnet-ready deployment

```
[ ] 1. Formal verification of bridge contracts
[ ] 2. Upgrade timelock (7 days minimum)
[ ] 3. Conservative initial parameters:
        - $100K daily deposit cap
        - 0.1% swap fee
        - 0.5% slippage tolerance
[ ] 4. Insurance or validator bond (if relayer is single-sig)
[ ] 5. Launch on testnet with real external chain participation
```

**Success criteria**:
- Audited and insured
- Live on testnet for 2+ weeks without issues
- Ready for gradual mainnet rollout

---

## 11. Governance & Upgrade Path

### 11.1 Parameter Governance

Key parameters should be governable:

```
swap_fee_bps          ← DAO vote (currently 3/1000 = 0.3%)
max_deposit_per_slot  ← DAO vote (rate limiting)
oracle_source         ← DAO vote (switch providers)
relayer_set           ← Permissioned update (initially ACE team)
slippage_tolerance    ← Default only (users can override)
```

### 11.2 Adding New Chains

```
To add support for a new external chain (e.g., Arbitrum):

1. Deploy bridge contract on Arbitrum
2. Integrate oracle feed for Arbitrum assets
3. Register new chain ID in ACE registry
4. Add Arbitrum to approved_chains in config
5. Governance vote: approve new chain
6. Bootstrap initial liquidity for wARB pools

Time: 1–2 weeks per chain
Cost: Audit (~$10K), deployment (~$5K), liquidity (~$100K–1M)
```

### 11.3 Upgrade Mechanism

```
To upgrade bridge contracts:

1. Propose upgrade (multi-sig submits, or DAO vote)
2. Timelock delay (7+ days minimum)
3. Execution: pause bridge during upgrade
4. Resume with new code

This prevents:
  - Flash upgrades that could enable rug pulls
  - Quick pivots that might be malicious
  - Gives community time to audit changes
```

---

## 12. Comparative Analysis: Why This Design?

### 12.1 vs. Traditional Cross-Chain Bridges (Stargate, Axelar)

| Aspect | ACE Design | Traditional |
|--------|-----------|------------|
| **Trust model** | Multi-sig relayers + n-VM atomicity | Threshold signatures + multiple chains |
| **Latency (swap leg)** | 400ms (single ACE slot); end-to-end cross-chain bounded by source finality (~1–3 min) | 10–120 seconds (cross-chain messaging) |
| **MEV exposure (swap leg)** | Ordering MEV eliminated for admitted txs (MEV-ACE: authenticated commit + VDF randomness + omission proofs); info-based MEV out of scope | High (each swap visible in public mempool) |
| **Fee structure (target)** | ~0.1–0.2% | ~0.5–1.4% for bridge+DEX routes |
| **LP incentives** | Fee APY ∝ turnover; 18%+ requires ~50% daily turnover | Same math; typically lower turnover per pool due to fragmentation |
| **Smart contract risk** | 1 bridge per external chain | N bridges (N-squared integration) |
| **Best for** | High-frequency, low-value swaps | Large whale swaps, low frequency |

### 12.2 vs. IBC (Cosmos Inter-Blockchain Communication)

| Aspect | ACE Design | IBC |
|--------|-----------|-----|
| **Trust model** | Off-chain relayers + deterministic ordering | Light clients on-chain |
| **Setup complexity** | Moderate (relayer + oracle) | High (light client, validators) |
| **Native support** | 3–5 chains (EVM, Solana, Bitcoin-style) | Cosmos ecosystem |
| **Latency** | 400ms | 10–30 seconds |
| **Best for** | Crypto-native users (bridge out quickly) | Native IBC chain users |

### 12.3 vs. Wrapped-Asset Model (WBTC, wETH, wSOL)

| Aspect | ACE Design | Wrapped Assets |
|--------|-----------|-----------------|
| **UX** | 1-tx cross-chain swap | Multi-step (wrap, swap, unwrap) |
| **Liquidity** | Unified on ACE | Fragmented across chains |
| **Fees** | Single 0.1% swap fee | Multiple 0.3%+ AMM fees |
| **Custodian risk** | Multi-sig relayer | Centralized issuer |
| **Suitable volume** | Any | Low-to-medium frequency |

### 12.4 Quantified Competitive Advantages

This section analyzes the expected direction and rough magnitude of advantages. **All figures are illustrative models based on stated assumptions, not measured benchmarks of named competitors.** Competitor fee schedules change frequently and vary by route; verify against live quotes before citing externally.

#### Cost Efficiency: Fewer Fee-Bearing Hops

```
User Cost Breakdown (Cross-chain swap, illustrative: BSC-USDT → Solana-SOL)

Typical bridge + two-DEX route (illustrative assumptions):
├─ Bridge fee:                      0.05–0.30%
├─ DEX swap on source chain:        0.25–0.30%
├─ DEX swap on destination chain:   0.25–0.30%
└─ MEV/slippage headroom:           0.10–0.20%
   ════════════════════════════════════════════
   Total user cost:                  ~0.65–1.10%

ACE Bridge Path (design targets):
├─ Ingress bridge fee:              0.05%
├─ ACE internal swap fee:           0.10%
├─ Egress bridge fee:               0.05%
└─ Ordering-MEV headroom on swap leg:
   reduced by MEV-ACE for admitted txs
   ════════════════════════════════════════════
   Total user cost:                  ~0.20%

Structural source of the advantage: one swap instead of two, and reduced
public-mempool MEV exposure on the swap leg. Expected magnitude:
roughly 3–5x cheaper than multi-hop routes for non-stable pairs.
```

#### Speed: Fast Swap Leg, Finality-Bound Bridge Legs

```
Time to Settlement (illustrative, BSC source / Tron destination)

Typical bridge + DEX route:
├─ Source chain finality wait:      ~45–60 sec (BSC)
├─ Cross-chain messaging:           ~30 sec
├─ DEX swap confirmations (x2):     ~20–40 sec
└─ Destination confirmation:        ~10–30 sec
   ════════════════════════════════════════════
   Total latency:                    ~2–3 min

ACE Bridge:
├─ Source chain finality wait:      ~45–60 sec (BSC; same physics)
├─ Relayer attest + ACE mint:       ~2 sec
├─ ACE atomic swap:                 0.4 sec (single slot)
├─ Egress execution + dest confirm: ~10–60 sec
   ════════════════════════════════════════════
   Total latency:                    ~1–2 min

Honest framing: the ingress finality wait is identical for any honest
bridge from the same source chain — ACE cannot beat physics there.
The advantage is concentrated in (a) the swap leg (sub-second vs
multiple DEX confirmations) and (b) ACE→external withdrawals, which
skip any source-side finality wait because ACE is the source of truth.
ACE-internal swaps (no bridging) settle in ~400ms.
```

#### Code Audit Burden: Structurally Smaller Attack Surface

The audit-surface advantage is structural rather than quantifiable in
advance:

- **Traditional bridges** need audited contracts on *both* sides of every
  route: deposit/lock logic, withdrawal proof verification, multi-sig
  checking, and upgrade governance, per chain.
- **ACE's design** needs only a minimal deposit contract per external
  chain (receive + lock + emit event). The verification-heavy half —
  attestation checking, dedup, mint — lives once in the ACE runtime
  (`ace-defi/src/bridge.rs`) and is shared by all chains. If the
  contract-free egress model of Section 5.3 is adopted, withdrawal-side
  contracts disappear entirely (at the cost of full relayer custody of
  the egress pool — see Section 7).

Actual line counts and audit quotes should be measured once the
contracts exist; no reliable numbers can be stated before then.

#### Liquidity Efficiency: One Pool Serves All Routes

The structural claim: in a fragmented model, the same asset pair needs
a separate pool on every chain (and per bridge route), so a given
amount of LP capital is split N ways. On ACE, one wAsset↔wAsset pool
serves ACE-internal traders and every cross-chain route through that
pair simultaneously — the same TVL sees the combined order flow.

Consequences (directional, not quantified):
  - For equal total LP capital, per-pool depth is higher, so price
    impact for a given trade size is lower (constant-product price
    impact scales ≈ trade_size / reserve).
  - Combined flow from offsetting routes (A→B and B→A users) partially
    nets out, reducing inventory drift and rebalancing cost.

The actual depth multiple depends on how many routes share a pair and
how balanced the flows are; it cannot be stated as a fixed "2-3x"
without traffic data.

#### LP Economic Returns: Driven by Turnover, Not Fee Rate

LP fee APY in any AMM is `(daily volume / TVL) × fee × 365`. A lower
fee rate by itself *reduces* LP returns; the design's thesis is that
lower fees plus route consolidation attract disproportionately more
volume to the same pool, raising turnover enough to more than offset
the lower rate.

```
Illustrative comparison at EQUAL pool TVL ($10M) and equal stake ($100K = 1%):

Fragmented pool, 0.3% fee, $1M/day volume (10% turnover):
  Pool fees: $3,000/day → your share $30/day → 10.95% gross APY
  Minus impermanent loss on volatile pairs: ~5-9% effective

ACE unified pool, 0.1% fee, requires $3M/day (30% turnover) to match:
  Pool fees: $3,000/day → identical gross APY
  At $5M/day (50% turnover): $5,000/day → 18.25% gross APY

The 18%+ scenario therefore depends entirely on the consolidation
thesis delivering ~5x the per-pool volume of a fragmented competitor.
This is a hypothesis to validate, not an established result.
```

Additional LP revenue streams (unquantified): spread arbitrage from
rebalancing against external markets, and future governance rewards.

#### Deployment Complexity: 4 Weeks vs 12+ Weeks

```
Total Time to Production

Traditional Bridge Deployment:

Week 1-2: Design & architecture
├─ Protocol design
├─ Security model design
└─ Oracle integration design

Week 3-4: Contract development
├─ Write deposit contracts (5 chains)
├─ Write withdrawal contracts (5 chains)
├─ Write relayer attestation logic
└─ Integration tests

Week 5-6: Security audit
├─ Smart contract audit (expensive, long)
├─ Relayer audit
└─ Integration audit

Week 7-8: Fixes & redeployment
├─ Address audit findings
├─ Retest everything
└─ Redeploy

Week 9-10: Testnet deployment
├─ Deploy to testnet versions of 5 chains
├─ Stress test
└─ Monitor for 2 weeks

Week 11-12: Mainnet launch prep
├─ Final review
├─ Insurance/monitoring setup
└─ Gradual rollout

Total: 12+ weeks

════════════════════════════════════════════

ACE Bridge Deployment:

Week 1: MVP (internal swaps on ACE)
├─ Extend ace-defi pools for cross-chain context
├─ Implement basic RelayerAttestation
└─ Test on devnet

Week 2: Add relayer integration
├─ Implement 3-of-5 multi-sig verification
├─ Integrate Chainlink oracle
└─ Full devnet testing

Week 3: External chain integration
├─ Deploy simple deposit contract (template reuse)
├─ Write Relayer monitoring
└─ Testnet end-to-end test

Week 4: Security & launch
├─ Audit deposit contracts (smaller, simpler)
├─ Rate limiting & circuit breakers
└─ Gradual mainnet rollout

Total: 4 weeks

════════════════════════════════════════════

These week counts are planning estimates, not commitments. The
structural reason ACE should be faster: per-chain work is limited to a
small reusable deposit contract, while verification logic ships once
in the ACE runtime. Engineering and audit cost savings follow the
same shape but should be budgeted from real quotes, not projected here.
```

#### Maintainability: Egress Never Needs Upgrade

```
Long-term Maintenance Burden

Traditional Bridge:

Year 1 Issues:
  - Found minor bug in Ethereum deposit contract
  → Pause deposits, deploy new contract, audit again (~3 weeks)
  
  - Found oracle edge case in withdrawal logic
  → Pause withdrawals, deploy new contract, full audit (~3 weeks)
  
  - Scaling pressure on Solana program
  → Redesign, new program, reaudit (~4 weeks)

(Hypothetical incident scenarios for illustration; each contract
change on an external chain forces a pause + redeploy + re-audit cycle.)

Future upgrades always require:
  ✓ Code audit (expensive)
  ✓ Smart contract deployment (risky)
  ✓ Contract pausing (user friction)

════════════════════════════════════════════

ACE Bridge:

Year 1 Issues:
  - Found minor bug in BSC deposit contract
  → Pause deposits, deploy new contract (~1 week, simple contract)
  → Egress CONTINUES WORKING (no change needed!)
  → Users can still withdraw their funds
  
  - Oracle issue
  → Update Relayer config (no contract change)
  
  - Scaling pressure
  → Upgrade ace-defi (internal, doesn't affect users)
  → Egress still works (fundamental: it's just transfer())

Future upgrades:
  ✓ Deposit contracts: May need audit
  ✗ Egress contracts: NEVER (they're just transfer())
  ✗ Withdrawal records: Already immutable once created
  ✗ User fund access: Always guaranteed (worst case, Relayer manual transfer)

════════════════════════════════════════════

Advantage: Traditional requires continuous contract upgrades on every
chain; ACE's egress path has no contract to upgrade (the trade-off is
relayer custody of the egress pool, whose operational security cost is
ongoing and should not be ignored in maintenance budgeting).
```

### 12.5 Market Timing: Why Now?

```
Current Market Pain Points (2026):

1. Fee Pressure
   - Multi-hop routes (bridge + DEX swaps on both ends) commonly
     total 0.5%+ all-in for non-stable pairs
   - ACE targets 0.1-0.2% all-in by collapsing to a single swap

2. MEV Awareness
   - Increased public awareness of MEV extraction
   - Users demand MEV-resistant protocols
   - ACE: ordering MEV (front-run/sandwich/censorship) eliminated
     by protocol design for admitted transactions (MEV-ACE)

3. Liquidity Fragmentation
   - Each new chain = new pool = fragmented liquidity
   - Higher slippage on medium-size swaps in thin pools
   - ACE: unified pools concentrate the same LP capital

4. Audit Cost Inflation
   - Security audit costs rising ($50-100K per contract)
   - Time to audit: 4-6 weeks
   - New chain = new audit = 2x cost
   - ACE: Reusable contracts, 1 audit per chain type

5. Complexity Fatigue
   - Users tired of complex multi-step transactions
   - CEX simplicity (1-click) beating DEX/bridge UX
   - ACE: Parametric (1-tx cross-chain)

════════════════════════════════════════════

Market Window:
  ✓ Bridges are mainstream (no longer niche)
  ✓ Users have real volume ($10B+ in bridges annually)
  ✓ Fee sensitivity is high (every basis point matters)
  ✓ Safety concerns are acute (bridge exploits headline news)

Perfect entry point: ACE addresses ALL pain points simultaneously
```

---

## 13. Future Enhancements

### 13.1 Shortterm (Months 2–3)

- [ ] Support for 10+ chains (Arbitrum, Optimism, Polygon, Linea, etc.)
- [ ] Dynamic fee adjustment based on volatility
- [ ] Liquidity farming program (governance token distribution)
- [ ] LP incentive contests (e.g., best liquidity provision)

### 13.2 Medium-term (Months 4–6)

- [ ] Cross-chain MEV detection and mitigation
- [ ] Automated market maker improvements (concentrated liquidity)
- [ ] Yield farming composability (LP tokens earn additional yields)
- [ ] DAO treasury management for collected fees

### 13.3 Long-term (Months 7–12)

- [ ] Fully decentralized relayer network (anyone can stake and relay)
- [ ] Light client integration (Solana light client on ACE, etc.)
- [ ] Non-custodial zk/light-client egress: destination-chain release against ACE consensus/state-root proof
- [ ] HFI-Pay-style verified ConvertIntent: user-verified quote, chain-committed route/asset/recipient tuple, proof-bound withdrawal or refund
- [ ] Cross-chain smart contracts (execute contracts across chains atomically)
- [ ] Intent-based ordering (MEV-fair sequencing)

---

## 14. Economic Projections (Conservative Scenario)

### Market Assumptions
```
- ACE Chain users: 100K (1 year)
- Average daily volume: $10M
- Average swap value: $1,000
- Average daily swaps: 10,000
- AVE TVL in pools: $100M
```

All figures below follow the fee split defined in Section 6.2
(0.1% swap fee, allocated 70% LP / 20% relayer / 10% treasury) plus
0.05–0.1% bridge fees on ingress/egress, applied to the market
assumptions above.

### LP Economics
```
Daily swap fee revenue: $10M × 0.001 = $10K
LP share (70%): $7K/day
Annualized: ~$2.56M
Fee APY on $100M pool TVL: ~2.6%

Note: at these assumptions (10% daily turnover), fee APY alone is
modest. Reaching the 18%+ APY cited elsewhere requires either ~50%
daily turnover or lower TVL relative to volume; LP returns must be
evaluated against the realized volume/TVL ratio, plus spread-arbitrage
and any token-incentive income.
```

### Relayer Economics
```
Swap fee share (20%): $10M × 0.001 × 0.2 = $2K/day
Bridge fees (ingress+egress, ~0.1% combined on bridged volume,
assume 50% of volume is cross-chain): $10M × 0.5 × 0.001 = $5K/day
Total: ~$7K/day across the relayer set
5 relayers (3-of-5): ~$1.4K per relayer per day
Annual per relayer: ~$500K gross
Infrastructure cost: ~$10K–50K per year
(Bridge fees must also cover destination-chain gas, which scales
with transaction count.)
```

### Protocol Revenue
```
Treasury share (10%): $10M × 0.001 × 0.1 = $1K/day
Annual: ~$365K

At this scale, treasury revenue covers audits and operations but not
a full development team; team funding needs either higher volume
(linear scaling) or a separate source until volume grows.
```

---

## 15. Conclusion

This cross-chain bridging system leverages **ACE Chain's core strengths**:

1. **Unified state tree** → Atomic swaps within a single state transition
2. **MEV-ACE fair ordering** → No proposer-controlled ordering MEV on admitted transactions, hence no MEV-driven fee escalation
3. **n-VM architecture** → Native asset support across chains
4. **Fixed TX_FEE** → Ultra-low fees for users and LPs

The design is **economically sustainable** because:
- LPs can operate profitably at 0.05–0.1% fees **if** route consolidation delivers high pool turnover (see Sections 6.3, 12.4)
- Users get an estimated ~3–5x lower all-in cost than multi-hop bridge+DEX routes (illustrative model, Section 12.4)
- Protocol scales with volume, not against it

**Next Steps**:
1. Validate core assumptions with simulations, especially volume/TVL turnover and LP fee APY
2. Implement Phase 1 (internal swaps) on devnet
3. Add ConvertIntent state modeling early, even if HFI-Pay-style proof binding ships later
4. Engage security auditors early
5. Bootstrap initial liquidity pool under explicit TVL and withdrawal caps
6. Gradual testnet deployment with real external chains
7. Treat non-custodial zk egress and HFI-Pay-style verified intent binding as separate future milestones before high-TVL scaling

This is the opportunity to build the most **user-friendly, economically efficient cross-chain bridge** in web3.

---

## Appendix A: Related Work & References

- **Uniswap v2/v3**: Constant-product AMM design, concentrated liquidity
- **Curve**: Stablecoin AMM with low slippage
- **Stargate**: Multi-chain bridge using Layerzero
- **Wormhole**: Cross-chain messaging (Solana-Ethereum)
- **IBC**: Cosmos inter-blockchain communication protocol
- **MEV-ACE** (paper 17-2604.07568, implemented in `third_party/mev-ace-core`): identity-authenticated fair ordering — registered bonded identities, threshold commit/open receipts, VDF-delayed randomness, omission proofs. This is the protocol basis for ACE's ordering-MEV claims. Scope caveats: protects only *admitted* transactions (those that obtain threshold receipts before cutoff) against *proposer-controlled ordering* MEV; information-based MEV (oracle back-running, cross-domain arbitrage) is explicitly out of scope; guarantees are conditional on receipt thresholds ≥ 2f+1, timely omission-proof dissemination, and correctly sized bonds. The slot must budget commit + VDF + open phases (Δc+Δv+Δo), so combining full MEV-ACE protection with a 400ms slot requires careful calibration or pipelining.
- **MEV-Burn**: Recent Ethereum proposal for MEV handling
- **1inch**: Cross-chain aggregation

---

## Appendix B: Glossary

| Term | Definition |
|------|-----------|
| **wUSDT** | Wrapped USDT on ACE Chain (represents real USDT locked on external chain) |
| **Slippage** | Difference between expected and actual swap price |
| **AMM** | Automated Market Maker (e.g., Uniswap constant-product) |
| **LP** | Liquidity Provider (deposits assets to pools, earns fees) |
| **MEV** | Maximal Extractable Value (profit from transaction ordering) |
| **IL** | Impermanent Loss (LP loss due to price divergence) |
| **BPS** | Basis Points (1 bps = 0.01%) |
| **Relayer** | Off-chain service that monitors external chains and attests to deposits |
| **Oracle** | Source of real-world price data (Chainlink, Pyth, etc.) |
| **VWAP** | Volume-Weighted Average Price |
| **Circuit breaker** | Automatic pause mechanism when conditions exceed thresholds |
| **Timelock** | Delay mechanism to prevent instant upgrades |

---

**Document Version**: 1.0  
**Last Updated**: 2026-06-10  
**Status**: Ready for Implementation Planning
