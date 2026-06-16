//! Runtime-native AMM swap (constant-product x·y = k).
//!
//! Because all wrapped assets live on the same unified StateTree,
//! swaps are just balance mutations — no cross-contract calls, no gas
//! auctions, no MEV.  A user can swap ACE-wSOL → ACE-wETH in a single
//! transaction, effectively performing a cross-chain swap at near-zero
//! cost.
//!
//! # Key insight
//!
//! On Ethereum, a Uniswap swap costs ~150K gas ($5–50).  Here, a swap
//! is two `transfer_between_owners` calls on the token_runtime — the
//! same cost as a simple balance transfer.

use std::collections::HashMap;

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use sha2::{Digest, Sha256};

use crate::error::SwapError;

/// A liquidity pool holding two tokens (constant-product AMM).
#[derive(Debug, Clone)]
pub struct Pool {
    /// Canonical pool ID (deterministic from token pair).
    pub pool_id: AccountId,
    /// The two token mints in this pool, sorted deterministically.
    pub token_a: AccountId,
    pub token_b: AccountId,
    /// Current reserves (tracked in-memory, backed by token_runtime balances).
    pub reserve_a: u64,
    pub reserve_b: u64,
    /// LP token mint for this pool.
    pub lp_mint: AccountId,
    /// Total LP tokens minted.
    pub lp_supply: u64,
}

/// Fee numerator / denominator.  3/1000 = 0.3% (same as Uniswap v2).
const FEE_NUMERATOR: u64 = 3;
const FEE_DENOMINATOR: u64 = 1000;

/// Derive a deterministic pool AccountId from two token mints.
///
/// `SHA-256("ace-pool:" || min(a,b) || max(a,b))`
pub fn pool_id(token_a: &AccountId, token_b: &AccountId) -> AccountId {
    let (lo, hi) = if token_a.as_bytes() <= token_b.as_bytes() {
        (token_a, token_b)
    } else {
        (token_b, token_a)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"ace-pool:");
    hasher.update(lo.as_bytes());
    hasher.update(hi.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    AccountId::from_bytes(hash)
}

/// Derive the LP token mint for a pool.
///
/// `SHA-256("ace-lp-mint:" || pool_id)`
pub fn lp_mint_id(pool: &AccountId) -> AccountId {
    let mut hasher = Sha256::new();
    hasher.update(b"ace-lp-mint:");
    hasher.update(pool.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    AccountId::from_bytes(hash)
}

/// The swap engine: manages all liquidity pools.
#[derive(Debug, Default)]
pub struct SwapEngine {
    pools: HashMap<AccountId, Pool>,
}

impl SwapEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new liquidity pool for a token pair.
    ///
    /// The pool account and LP mint are created in the state tree.
    /// No initial liquidity — use `add_liquidity` after creation.
    pub fn create_pool(
        &mut self,
        state: &mut StateTree,
        token_a: &AccountId,
        token_b: &AccountId,
    ) -> Result<AccountId, SwapError> {
        if token_a == token_b {
            return Err(SwapError::IdenticalTokens);
        }

        let (lo, hi) = if token_a.as_bytes() <= token_b.as_bytes() {
            (*token_a, *token_b)
        } else {
            (*token_b, *token_a)
        };

        let pid = pool_id(&lo, &hi);
        if self.pools.contains_key(&pid) {
            return Err(SwapError::PoolAlreadyExists(hex::encode(pid.as_bytes())));
        }

        // Create pool account in state tree
        if !state.contains(&pid) {
            state.insert(Account::new(pid));
        }

        // Create LP mint
        let lp = lp_mint_id(&pid);
        ace_n_vm::token_runtime::create_mint(state, lp.as_bytes(), 9, pid.as_bytes())
            .map_err(|e| SwapError::TokenRuntime(e))?;

        let pool = Pool {
            pool_id: pid,
            token_a: lo,
            token_b: hi,
            reserve_a: 0,
            reserve_b: 0,
            lp_mint: lp,
            lp_supply: 0,
        };
        self.pools.insert(pid, pool);

        tracing::info!(
            pool = hex::encode(pid.as_bytes()),
            token_a = hex::encode(lo.as_bytes()),
            token_b = hex::encode(hi.as_bytes()),
            "Pool created"
        );

        Ok(pid)
    }

    /// Add liquidity to a pool.
    ///
    /// Transfers `amount_a` of token_a and `amount_b` of token_b from
    /// the provider into the pool, and mints LP tokens to the provider.
    pub fn add_liquidity(
        &mut self,
        state: &mut StateTree,
        token_a: &AccountId,
        token_b: &AccountId,
        provider: &AccountId,
        amount_a: u64,
        amount_b: u64,
    ) -> Result<u64, SwapError> {
        if amount_a == 0 || amount_b == 0 {
            return Err(SwapError::ZeroAmount);
        }

        let pid = pool_id(token_a, token_b);
        let pool = self
            .pools
            .get_mut(&pid)
            .ok_or_else(|| SwapError::PoolNotFound(hex::encode(pid.as_bytes())))?;

        // Determine which is token_a/token_b in the pool's canonical order
        let (amt_a, amt_b) = if token_a.as_bytes() <= token_b.as_bytes() {
            (amount_a, amount_b)
        } else {
            (amount_b, amount_a)
        };

        // Check provider balances
        let bal_a = ace_n_vm::token_runtime::balance_of(state, pool.token_a.as_bytes(), provider);
        if bal_a < amt_a {
            return Err(SwapError::InsufficientBalance {
                have: bal_a,
                need: amt_a,
            });
        }
        let bal_b = ace_n_vm::token_runtime::balance_of(state, pool.token_b.as_bytes(), provider);
        if bal_b < amt_b {
            return Err(SwapError::InsufficientBalance {
                have: bal_b,
                need: amt_b,
            });
        }

        let snapshot = state.snapshot();
        ace_n_vm::token_runtime::transfer_between_owners(
            state,
            pool.token_a.as_bytes(),
            provider,
            &pool.pool_id,
            amt_a,
        )
        .map_err(|e| {
            state.rollback(snapshot.clone());
            SwapError::TokenRuntime(e)
        })?;

        ace_n_vm::token_runtime::transfer_between_owners(
            state,
            pool.token_b.as_bytes(),
            provider,
            &pool.pool_id,
            amt_b,
        )
        .map_err(|e| {
            state.rollback(snapshot.clone());
            SwapError::TokenRuntime(e)
        })?;

        // Calculate LP tokens to mint
        let lp_amount_u128 = if pool.lp_supply == 0 {
            // First deposit: LP = sqrt(a * b)
            isqrt(amt_a as u128 * amt_b as u128)
        } else {
            // Proportional: min(a/reserve_a, b/reserve_b) * supply.
            // Defense-in-depth: a pool with lp_supply > 0 should always hold
            // non-zero reserves, but guard explicitly so a broken invariant
            // surfaces as a clean error instead of a divide-by-zero panic.
            if pool.reserve_a == 0 || pool.reserve_b == 0 {
                return Err(SwapError::ZeroAmount);
            }
            let lp_a = (amt_a as u128) * (pool.lp_supply as u128) / (pool.reserve_a as u128);
            let lp_b = (amt_b as u128) * (pool.lp_supply as u128) / (pool.reserve_b as u128);
            lp_a.min(lp_b)
        };
        let lp_amount: u64 = lp_amount_u128
            .try_into()
            .map_err(|_| SwapError::AmountOverflow)?;

        if lp_amount == 0 {
            return Err(SwapError::ZeroAmount);
        }

        // Mint LP tokens to provider
        ace_n_vm::token_runtime::mint_to_owner(
            state,
            pool.lp_mint.as_bytes(),
            provider.as_bytes(),
            lp_amount,
            &pool.pool_id,
        )
        .map_err(|e| {
            state.rollback(snapshot);
            SwapError::TokenRuntime(e)
        })?;

        pool.reserve_a = pool
            .reserve_a
            .checked_add(amt_a)
            .ok_or(SwapError::AmountOverflow)?;
        pool.reserve_b = pool
            .reserve_b
            .checked_add(amt_b)
            .ok_or(SwapError::AmountOverflow)?;
        pool.lp_supply = pool
            .lp_supply
            .checked_add(lp_amount)
            .ok_or(SwapError::AmountOverflow)?;

        tracing::info!(
            pool = hex::encode(pid.as_bytes()),
            added_a = amt_a,
            added_b = amt_b,
            lp_minted = lp_amount,
            "Liquidity added"
        );

        Ok(lp_amount)
    }

    /// Remove liquidity from a pool.
    ///
    /// Burns `lp_amount` LP tokens from the provider and returns
    /// proportional amounts of both tokens.
    pub fn remove_liquidity(
        &mut self,
        state: &mut StateTree,
        token_a: &AccountId,
        token_b: &AccountId,
        provider: &AccountId,
        lp_amount: u64,
    ) -> Result<(u64, u64), SwapError> {
        if lp_amount == 0 {
            return Err(SwapError::ZeroAmount);
        }

        let pid = pool_id(token_a, token_b);
        let pool = self
            .pools
            .get_mut(&pid)
            .ok_or_else(|| SwapError::PoolNotFound(hex::encode(pid.as_bytes())))?;

        if lp_amount > pool.lp_supply {
            return Err(SwapError::InsufficientBalance {
                have: pool.lp_supply,
                need: lp_amount,
            });
        }

        // Calculate proportional amounts
        let out_a: u64 = (lp_amount as u128 * pool.reserve_a as u128 / pool.lp_supply as u128)
            .try_into()
            .map_err(|_| SwapError::AmountOverflow)?;
        let out_b: u64 = (lp_amount as u128 * pool.reserve_b as u128 / pool.lp_supply as u128)
            .try_into()
            .map_err(|_| SwapError::AmountOverflow)?;

        if out_a == 0 || out_b == 0 {
            return Err(SwapError::ZeroAmount);
        }

        let snapshot = state.snapshot();
        ace_n_vm::token_runtime::transfer_between_owners(
            state,
            pool.lp_mint.as_bytes(),
            provider,
            &pool.pool_id,
            lp_amount,
        )
        .map_err(|e| {
            state.rollback(snapshot.clone());
            SwapError::TokenRuntime(e)
        })?;

        ace_n_vm::token_runtime::transfer_between_owners(
            state,
            pool.token_a.as_bytes(),
            &pool.pool_id,
            provider,
            out_a,
        )
        .map_err(|e| {
            state.rollback(snapshot.clone());
            SwapError::TokenRuntime(e)
        })?;

        ace_n_vm::token_runtime::transfer_between_owners(
            state,
            pool.token_b.as_bytes(),
            &pool.pool_id,
            provider,
            out_b,
        )
        .map_err(|e| {
            state.rollback(snapshot.clone());
            SwapError::TokenRuntime(e)
        })?;

        pool.reserve_a -= out_a;
        pool.reserve_b -= out_b;
        pool.lp_supply -= lp_amount;

        Ok((out_a, out_b))
    }

    /// Swap `amount_in` of `token_in` for `token_out`, with slippage protection.
    ///
    /// Uses constant-product formula: out = (in * fee * reserve_out) / (reserve_in + in * fee)
    ///
    /// Returns the amount of token_out received.
    pub fn swap(
        &mut self,
        state: &mut StateTree,
        token_in: &AccountId,
        token_out: &AccountId,
        sender: &AccountId,
        amount_in: u64,
        min_amount_out: u64,
    ) -> Result<u64, SwapError> {
        if amount_in == 0 {
            return Err(SwapError::ZeroAmount);
        }
        if token_in == token_out {
            return Err(SwapError::IdenticalTokens);
        }

        let pid = pool_id(token_in, token_out);
        let pool = self
            .pools
            .get_mut(&pid)
            .ok_or_else(|| SwapError::PoolNotFound(hex::encode(pid.as_bytes())))?;

        if pool.reserve_a == 0 || pool.reserve_b == 0 {
            return Err(SwapError::InsufficientLiquidity);
        }

        // Determine direction and reject payloads whose token IDs do not match
        // the canonical pool pair. This should be implied by `pool_id`, but the
        // explicit check keeps the AMM side of the trust boundary auditable.
        let in_is_a = if *token_in == pool.token_a && *token_out == pool.token_b {
            true
        } else if *token_in == pool.token_b && *token_out == pool.token_a {
            false
        } else {
            return Err(SwapError::PoolNotFound(hex::encode(pid.as_bytes())));
        };

        let (reserve_in, reserve_out) = if in_is_a {
            (pool.reserve_a, pool.reserve_b)
        } else {
            (pool.reserve_b, pool.reserve_a)
        };

        // Constant-product with fee: out = (in_after_fee * reserve_out) / (reserve_in + in_after_fee)
        let amount_in_with_fee = amount_in as u128 * (FEE_DENOMINATOR - FEE_NUMERATOR) as u128;
        let numerator = amount_in_with_fee * reserve_out as u128;
        let denominator = reserve_in as u128 * FEE_DENOMINATOR as u128 + amount_in_with_fee;
        let amount_out = (numerator / denominator) as u64;

        if amount_out == 0 {
            return Err(SwapError::InsufficientLiquidity);
        }
        if amount_out < min_amount_out {
            return Err(SwapError::SlippageExceeded {
                min_out: min_amount_out,
                actual_out: amount_out,
            });
        }

        // Check sender balance
        let bal = ace_n_vm::token_runtime::balance_of(state, token_in.as_bytes(), sender);
        if bal < amount_in {
            return Err(SwapError::InsufficientBalance {
                have: bal,
                need: amount_in,
            });
        }

        let snapshot = state.snapshot();

        // Transfer token_in from sender to pool
        ace_n_vm::token_runtime::transfer_between_owners(
            state,
            token_in.as_bytes(),
            sender,
            &pool.pool_id,
            amount_in,
        )
        .map_err(|e| {
            state.rollback(snapshot.clone());
            SwapError::TokenRuntime(e)
        })?;

        // Transfer token_out from pool to sender
        ace_n_vm::token_runtime::transfer_between_owners(
            state,
            token_out.as_bytes(),
            &pool.pool_id,
            sender,
            amount_out,
        )
        .map_err(|e| {
            state.rollback(snapshot);
            SwapError::TokenRuntime(e)
        })?;

        // Update reserves
        if in_is_a {
            pool.reserve_a = pool
                .reserve_a
                .checked_add(amount_in)
                .ok_or(SwapError::AmountOverflow)?;
            pool.reserve_b = pool
                .reserve_b
                .checked_sub(amount_out)
                .ok_or(SwapError::InsufficientLiquidity)?;
        } else {
            pool.reserve_b = pool
                .reserve_b
                .checked_add(amount_in)
                .ok_or(SwapError::AmountOverflow)?;
            pool.reserve_a = pool
                .reserve_a
                .checked_sub(amount_out)
                .ok_or(SwapError::InsufficientLiquidity)?;
        }

        tracing::info!(
            pool = hex::encode(pid.as_bytes()),
            token_in = hex::encode(token_in.as_bytes()),
            amount_in,
            amount_out,
            "Swap executed"
        );

        Ok(amount_out)
    }

    /// Get a pool by token pair.
    pub fn get_pool(&self, token_a: &AccountId, token_b: &AccountId) -> Option<&Pool> {
        self.pools.get(&pool_id(token_a, token_b))
    }

    /// Quote: how much `token_out` would you get for `amount_in` of `token_in`?
    ///
    /// Read-only, no state changes.
    pub fn quote(
        &self,
        token_in: &AccountId,
        token_out: &AccountId,
        amount_in: u64,
    ) -> Result<u64, SwapError> {
        let pid = pool_id(token_in, token_out);
        let pool = self
            .pools
            .get(&pid)
            .ok_or_else(|| SwapError::PoolNotFound(hex::encode(pid.as_bytes())))?;

        let in_is_a = if *token_in == pool.token_a && *token_out == pool.token_b {
            true
        } else if *token_in == pool.token_b && *token_out == pool.token_a {
            false
        } else {
            return Err(SwapError::PoolNotFound(hex::encode(pid.as_bytes())));
        };

        let (reserve_in, reserve_out) = if in_is_a {
            (pool.reserve_a, pool.reserve_b)
        } else {
            (pool.reserve_b, pool.reserve_a)
        };

        if reserve_in == 0 || reserve_out == 0 {
            return Err(SwapError::InsufficientLiquidity);
        }

        let amount_in_with_fee = amount_in as u128 * (FEE_DENOMINATOR - FEE_NUMERATOR) as u128;
        let numerator = amount_in_with_fee * reserve_out as u128;
        let denominator = reserve_in as u128 * FEE_DENOMINATOR as u128 + amount_in_with_fee;
        Ok((numerator / denominator) as u64)
    }

    pub fn pool_count(&self) -> usize {
        self.pools.len()
    }
}

/// Integer square root (Babylonian method).
fn isqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}
