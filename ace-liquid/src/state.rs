//! Per-market StateTree persistence for ACE Liquid.
//!
//! Each market's entire state — metadata, orders, crit-bit price ladder, order
//! queues, and **per-user collateral balances** — lives under a single
//! per-market account (`market_book_id`). Trading (place / cancel / match)
//! mutates only that one account, so transactions on *different* markets touch
//! disjoint accounts and run in parallel (see `crate::wire` write-set rules).
//!
//! Funds are bridged in/out of the global token ledger only by explicit
//! deposit / withdraw operations; matching itself never touches the shared
//! token-program account. This is the dYdX/Serum "collateral subaccount"
//! model: settlement is internal book-keeping, deposits/withdrawals serialize.

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::LiquidError;
use crate::types::{Market, MarketId, Order, OrderId, OrderSide};

const AUTHORITY_DOMAIN: &[u8] = b"ace-liquid-authority";
const BOOK_DOMAIN: &[u8] = b"ace-liquid:book:v1:";

const MARKET_DOMAIN: &[u8] = b"ace-liquid:market:v1";
const ORDER_DOMAIN: &[u8] = b"ace-liquid:order:v1";
const LEVEL_DOMAIN: &[u8] = b"ace-liquid:level:v1";
const NODE_DOMAIN: &[u8] = b"ace-liquid:node:v1";
const BALANCE_DOMAIN: &[u8] = b"ace-liquid:balance:v1";
const NEXT_ORDER_ID_DOMAIN: &[u8] = b"ace-liquid:next-order-id:v1";
const NEXT_SEQ_DOMAIN: &[u8] = b"ace-liquid:next-seq:v1";

/// Collateral asset index within a market.
pub const ASSET_BASE: u8 = 0;
pub const ASSET_QUOTE: u8 = 1;

/// Global ACE Liquid authority (reserved; not used for per-market state).
pub fn ace_liquid_authority_id() -> AccountId {
    finalize_account(Sha256::new().chain_update(AUTHORITY_DOMAIN))
}

/// The per-market account that owns all of a market's state and custodies its
/// deposited funds in the global token ledger.
pub fn market_book_id(market_id: &MarketId) -> AccountId {
    let mut hasher = Sha256::new();
    hasher.update(BOOK_DOMAIN);
    hasher.update(market_id.as_bytes());
    finalize_account(hasher)
}

// ── Markets ──────────────────────────────────────────────────────────────

pub fn market_exists(state: &StateTree, market_id: &MarketId) -> bool {
    chunk_count(
        state,
        &market_book_id(market_id),
        MARKET_DOMAIN,
        market_id.as_bytes(),
    ) > 0
}

pub fn put_market(state: &mut StateTree, market: &Market) -> Result<(), LiquidError> {
    let owner = market_book_id(&market.market_id);
    put_record(
        state,
        &owner,
        MARKET_DOMAIN,
        market.market_id.as_bytes(),
        market,
    )
}

pub fn get_market(state: &StateTree, market_id: &MarketId) -> Result<Option<Market>, LiquidError> {
    get_record(
        state,
        &market_book_id(market_id),
        MARKET_DOMAIN,
        market_id.as_bytes(),
    )
}

// ── Orders ───────────────────────────────────────────────────────────────

pub fn put_order(state: &mut StateTree, order: &Order) -> Result<(), LiquidError> {
    let owner = market_book_id(&order.market_id);
    put_record(
        state,
        &owner,
        ORDER_DOMAIN,
        &order.order_id.0.to_le_bytes(),
        order,
    )
}

pub fn get_order(
    state: &StateTree,
    market_id: &MarketId,
    order_id: OrderId,
) -> Result<Option<Order>, LiquidError> {
    get_record(
        state,
        &market_book_id(market_id),
        ORDER_DOMAIN,
        &order_id.0.to_le_bytes(),
    )
}

// ── Per-user collateral balances (internal to a market) ──────────────────

fn balance_key(user: &AccountId, asset: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.extend_from_slice(user.as_bytes());
    key.push(asset);
    key
}

pub fn free_balance(state: &StateTree, market_id: &MarketId, user: &AccountId, asset: u8) -> u64 {
    let owner = market_book_id(market_id);
    read_u64(
        state,
        &owner,
        &domain_slot(BALANCE_DOMAIN, 0, &balance_key(user, asset)),
    )
}

pub fn credit_balance(
    state: &mut StateTree,
    market_id: &MarketId,
    user: &AccountId,
    asset: u8,
    amount: u64,
) -> Result<(), LiquidError> {
    if amount == 0 {
        return Ok(());
    }
    let owner = market_book_id(market_id);
    let slot = domain_slot(BALANCE_DOMAIN, 0, &balance_key(user, asset));
    let new = read_u64(state, &owner, &slot)
        .checked_add(amount)
        .ok_or(LiquidError::ArithmeticOverflow)?;
    write_u64(state, &owner, slot, new);
    Ok(())
}

pub fn debit_balance(
    state: &mut StateTree,
    market_id: &MarketId,
    user: &AccountId,
    asset: u8,
    amount: u64,
) -> Result<(), LiquidError> {
    if amount == 0 {
        return Ok(());
    }
    let owner = market_book_id(market_id);
    let slot = domain_slot(BALANCE_DOMAIN, 0, &balance_key(user, asset));
    let have = read_u64(state, &owner, &slot);
    if have < amount {
        return Err(LiquidError::InsufficientBalance { have, need: amount });
    }
    write_u64(state, &owner, slot, have - amount);
    Ok(())
}

// ── Counters (per market) ────────────────────────────────────────────────

pub fn next_order_id(state: &mut StateTree, market_id: &MarketId) -> Result<OrderId, LiquidError> {
    let owner = market_book_id(market_id);
    let slot = domain_slot(NEXT_ORDER_ID_DOMAIN, 0, &[]);
    let current = read_u64(state, &owner, &slot).max(1);
    write_u64(
        state,
        &owner,
        slot,
        current
            .checked_add(1)
            .ok_or(LiquidError::ArithmeticOverflow)?,
    );
    Ok(OrderId(current))
}

pub fn next_sequence(state: &mut StateTree, market_id: &MarketId) -> Result<u64, LiquidError> {
    let owner = market_book_id(market_id);
    let slot = domain_slot(NEXT_SEQ_DOMAIN, 0, &[]);
    let current = read_u64(state, &owner, &slot).max(1);
    write_u64(
        state,
        &owner,
        slot,
        current
            .checked_add(1)
            .ok_or(LiquidError::ArithmeticOverflow)?,
    );
    Ok(current)
}

// ── Price ladders (crit-bit tree, see `crate::critbit`) ───────────────────

pub fn best_price(
    state: &StateTree,
    market_id: &MarketId,
    side: OrderSide,
) -> Result<Option<u64>, LiquidError> {
    Ok(match side {
        OrderSide::Buy => crate::critbit::max(state, market_id, side),
        OrderSide::Sell => crate::critbit::min(state, market_id, side),
    })
}

fn add_level(state: &mut StateTree, market_id: &MarketId, side: OrderSide, price: u64) {
    crate::critbit::insert(state, market_id, side, price);
}

fn remove_level(state: &mut StateTree, market_id: &MarketId, side: OrderSide, price: u64) {
    crate::critbit::remove(state, market_id, side, price);
}

// ── Order queues: intrusive doubly-linked FIFO per price level ────────────
//
// (head, tail) packed in one slot per level; (prev, next) packed in one slot
// per order. Enqueue / pop-front / cancel-in-the-middle are all O(1). Order id
// `0` is the null sentinel.

fn level_key(market_id: &MarketId, side: OrderSide, price: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 32 + 8);
    key.push(side_byte(side));
    key.extend_from_slice(market_id.as_bytes());
    key.extend_from_slice(&price.to_le_bytes());
    key
}

fn read_level(state: &StateTree, market_id: &MarketId, side: OrderSide, price: u64) -> (u64, u64) {
    let owner = market_book_id(market_id);
    read_pair(
        state,
        &owner,
        &domain_slot(LEVEL_DOMAIN, 0, &level_key(market_id, side, price)),
    )
}

fn write_level(
    state: &mut StateTree,
    market_id: &MarketId,
    side: OrderSide,
    price: u64,
    head: u64,
    tail: u64,
) {
    let owner = market_book_id(market_id);
    write_pair(
        state,
        &owner,
        domain_slot(LEVEL_DOMAIN, 0, &level_key(market_id, side, price)),
        head,
        tail,
    );
}

fn read_node(state: &StateTree, market_id: &MarketId, order_id: u64) -> (u64, u64) {
    let owner = market_book_id(market_id);
    read_pair(
        state,
        &owner,
        &domain_slot(NODE_DOMAIN, 0, &order_id.to_le_bytes()),
    )
}

fn write_node(state: &mut StateTree, market_id: &MarketId, order_id: u64, prev: u64, next: u64) {
    let owner = market_book_id(market_id);
    write_pair(
        state,
        &owner,
        domain_slot(NODE_DOMAIN, 0, &order_id.to_le_bytes()),
        prev,
        next,
    );
}

pub fn enqueue_order(
    state: &mut StateTree,
    market_id: &MarketId,
    side: OrderSide,
    price: u64,
    order_id: OrderId,
) -> Result<(), LiquidError> {
    let id = order_id.0;
    let (head, tail) = read_level(state, market_id, side, price);
    if tail == 0 {
        write_node(state, market_id, id, 0, 0);
        write_level(state, market_id, side, price, id, id);
        add_level(state, market_id, side, price);
    } else {
        let (prev_tail_prev, _) = read_node(state, market_id, tail);
        write_node(state, market_id, tail, prev_tail_prev, id);
        write_node(state, market_id, id, tail, 0);
        write_level(state, market_id, side, price, head, id);
    }
    Ok(())
}

pub fn front_order_at(
    state: &StateTree,
    market_id: &MarketId,
    side: OrderSide,
    price: u64,
) -> Result<Option<OrderId>, LiquidError> {
    let (head, _) = read_level(state, market_id, side, price);
    Ok((head != 0).then_some(OrderId(head)))
}

pub fn remove_order_from_queue(
    state: &mut StateTree,
    market_id: &MarketId,
    side: OrderSide,
    price: u64,
    order_id: OrderId,
) -> Result<(), LiquidError> {
    let id = order_id.0;
    let (head, tail) = read_level(state, market_id, side, price);
    let (prev, next) = read_node(state, market_id, id);

    if prev != 0 {
        let (pp, _) = read_node(state, market_id, prev);
        write_node(state, market_id, prev, pp, next);
    }
    if next != 0 {
        let (_, nn) = read_node(state, market_id, next);
        write_node(state, market_id, next, prev, nn);
    }
    let new_head = if head == id { next } else { head };
    let new_tail = if tail == id { prev } else { tail };
    write_node(state, market_id, id, 0, 0);

    if new_head == 0 {
        write_level(state, market_id, side, price, 0, 0);
        remove_level(state, market_id, side, price);
    } else {
        write_level(state, market_id, side, price, new_head, new_tail);
    }
    Ok(())
}

fn side_byte(side: OrderSide) -> u8 {
    match side {
        OrderSide::Buy => 0,
        OrderSide::Sell => 1,
    }
}

fn read_pair(state: &StateTree, owner: &AccountId, slot: &[u8; 32]) -> (u64, u64) {
    let value = state.get_storage(owner, slot);
    (
        u64::from_le_bytes(value[0..8].try_into().unwrap()),
        u64::from_le_bytes(value[8..16].try_into().unwrap()),
    )
}

fn write_pair(state: &mut StateTree, owner: &AccountId, slot: [u8; 32], a: u64, b: u64) {
    let mut value = [0u8; 32];
    value[0..8].copy_from_slice(&a.to_le_bytes());
    value[8..16].copy_from_slice(&b.to_le_bytes());
    state.set_storage(owner, slot, value);
}

// ── Generic chunked record store ──────────────────────────────────────────

fn put_record<T: Serialize>(
    state: &mut StateTree,
    owner: &AccountId,
    domain: &[u8],
    key: &[u8],
    value: &T,
) -> Result<(), LiquidError> {
    let bytes = bincode::serialize(value).map_err(|e| LiquidError::Serialization(e.to_string()))?;
    let chunks = bytes.len().div_ceil(32) as u64;
    write_u64(state, owner, domain_slot(domain, 0, key), chunks);
    write_u64(
        state,
        owner,
        domain_slot(domain, 1, key),
        bytes.len() as u64,
    );
    for (idx, chunk) in bytes.chunks(32).enumerate() {
        let mut value = [0u8; 32];
        value[..chunk.len()].copy_from_slice(chunk);
        let mut idx_key = Vec::with_capacity(key.len() + 8);
        idx_key.extend_from_slice(key);
        idx_key.extend_from_slice(&(idx as u64).to_le_bytes());
        state.set_storage(owner, domain_slot(domain, 2, &idx_key), value);
    }
    Ok(())
}

fn get_record<T: DeserializeOwned>(
    state: &StateTree,
    owner: &AccountId,
    domain: &[u8],
    key: &[u8],
) -> Result<Option<T>, LiquidError> {
    let chunks = read_u64(state, owner, &domain_slot(domain, 0, key));
    if chunks == 0 {
        return Ok(None);
    }
    let byte_len = read_u64(state, owner, &domain_slot(domain, 1, key)) as usize;
    let mut bytes = Vec::with_capacity(chunks as usize * 32);
    for idx in 0..chunks {
        let mut idx_key = Vec::with_capacity(key.len() + 8);
        idx_key.extend_from_slice(key);
        idx_key.extend_from_slice(&idx.to_le_bytes());
        bytes.extend_from_slice(&state.get_storage(owner, &domain_slot(domain, 2, &idx_key)));
    }
    if byte_len > bytes.len() {
        return Err(LiquidError::Serialization(
            "record byte length exceeds stored chunks".into(),
        ));
    }
    bytes.truncate(byte_len);
    Ok(Some(
        bincode::deserialize(&bytes).map_err(|e| LiquidError::Serialization(e.to_string()))?,
    ))
}

fn chunk_count(state: &StateTree, owner: &AccountId, domain: &[u8], key: &[u8]) -> u64 {
    read_u64(state, owner, &domain_slot(domain, 0, key))
}

fn domain_slot(domain: &[u8], tag: u8, key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([tag]);
    hasher.update(key);
    let result = hasher.finalize();
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&result);
    slot
}

fn read_u64(state: &StateTree, owner: &AccountId, slot: &[u8; 32]) -> u64 {
    let value = state.get_storage(owner, slot);
    u64::from_le_bytes(value[0..8].try_into().unwrap())
}

fn write_u64(state: &mut StateTree, owner: &AccountId, slot: [u8; 32], value: u64) {
    let mut encoded = [0u8; 32];
    encoded[0..8].copy_from_slice(&value.to_le_bytes());
    state.set_storage(owner, slot, encoded);
}

fn finalize_account(hasher: Sha256) -> AccountId {
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    AccountId::from_bytes(id)
}
