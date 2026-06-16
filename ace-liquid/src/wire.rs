//! Consensus wire format and execution entry point for ACE Liquid system
//! transactions (opcode `0x0F`).
//!
//! A signed user transaction carries a `0x0F` payload; every validator decodes
//! and executes it identically against the `StateTree`, binding the order owner
//! to the *authenticated* sender (`tx.attestation.idcom`) — never to a value in
//! the payload. Replay is prevented by a strict per-account nonce.
//!
//! Write-set discipline (see `ace_n_vm::scheduler` and the node executor):
//!   * place / cancel touch only `{sender, market_book_id(market_id)}` → orders
//!     on different markets run in parallel;
//!   * create-market / deposit / withdraw touch the shared token ledger and are
//!     scheduled `Global`.

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;

use crate::clob::SpotClob;
use crate::error::LiquidError;
use crate::types::{
    derive_market_id, Market, MarketId, OrderId, OrderSide, OrderType, PlaceOrder, TimeInForce,
};

/// Opcode for ACE Liquid order-book transactions.
pub const OP_LIQUID: u8 = 0x0F;

pub const SUB_CREATE_MARKET: u8 = 0x01;
pub const SUB_PLACE_ORDER: u8 = 0x02;
pub const SUB_CANCEL_ORDER: u8 = 0x03;
pub const SUB_DEPOSIT: u8 = 0x04;
pub const SUB_WITHDRAW: u8 = 0x05;

/// Byte offset of the 32-byte market id within place/cancel/deposit/withdraw
/// payloads: `OP(1) || SUB(1) || nonce(8)` then market id. Used by the scheduler
/// to derive the per-market write set without depending on this crate's types.
pub const MARKET_ID_OFFSET: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiquidOutcome {
    MarketCreated(MarketId),
    OrderPlaced { order_id: OrderId, fills: u32 },
    OrderCancelled(OrderId),
    Deposited { asset: u8, amount: u64 },
    Withdrawn { asset: u8, amount: u64 },
}

impl LiquidOutcome {
    pub fn encode_return_data(&self) -> Vec<u8> {
        match self {
            LiquidOutcome::MarketCreated(id) => {
                let mut out = vec![SUB_CREATE_MARKET];
                out.extend_from_slice(id.as_bytes());
                out
            }
            LiquidOutcome::OrderPlaced { order_id, fills } => {
                let mut out = vec![SUB_PLACE_ORDER];
                out.extend_from_slice(&order_id.0.to_le_bytes());
                out.extend_from_slice(&fills.to_le_bytes());
                out
            }
            LiquidOutcome::OrderCancelled(order_id) => {
                let mut out = vec![SUB_CANCEL_ORDER];
                out.extend_from_slice(&order_id.0.to_le_bytes());
                out
            }
            LiquidOutcome::Deposited { asset, amount } => {
                let mut out = vec![SUB_DEPOSIT, *asset];
                out.extend_from_slice(&amount.to_le_bytes());
                out
            }
            LiquidOutcome::Withdrawn { asset, amount } => {
                let mut out = vec![SUB_WITHDRAW, *asset];
                out.extend_from_slice(&amount.to_le_bytes());
                out
            }
        }
    }
}

pub fn is_liquid_payload(payload: &[u8]) -> bool {
    payload.first() == Some(&OP_LIQUID)
}

/// Decode and execute a `0x0F` payload, binding the actor to `sender`.
pub fn execute_liquid_tx(
    state: &mut StateTree,
    sender: AccountId,
    payload: &[u8],
) -> Result<LiquidOutcome, LiquidError> {
    let snapshot = state.snapshot();
    match execute_liquid_tx_inner(state, sender, payload) {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            state.rollback(snapshot);
            Err(error)
        }
    }
}

fn execute_liquid_tx_inner(
    state: &mut StateTree,
    sender: AccountId,
    payload: &[u8],
) -> Result<LiquidOutcome, LiquidError> {
    if payload.first() != Some(&OP_LIQUID) {
        return Err(LiquidError::InvalidPayload(
            "not an ACE Liquid payload".into(),
        ));
    }
    let sub = *payload
        .get(1)
        .ok_or_else(|| LiquidError::InvalidPayload("missing sub-opcode".into()))?;
    let body = &payload[2..];
    let clob = SpotClob::new();

    match sub {
        SUB_CREATE_MARKET => {
            let (nonce, market) = decode_create_market(body)?;
            consume_nonce(state, &sender, nonce)?;
            let id = clob.create_market(state, market)?;
            Ok(LiquidOutcome::MarketCreated(id))
        }
        SUB_PLACE_ORDER => {
            let (nonce, market_id, request) = decode_place_order(body, sender)?;
            consume_nonce(state, &sender, nonce)?;
            let (order_id, trades) = clob.place_order(state, market_id, request)?;
            Ok(LiquidOutcome::OrderPlaced {
                order_id,
                fills: trades.len() as u32,
            })
        }
        SUB_CANCEL_ORDER => {
            let (nonce, market_id, order_id) = decode_cancel_order(body)?;
            consume_nonce(state, &sender, nonce)?;
            clob.cancel_order(state, market_id, sender, order_id)?;
            Ok(LiquidOutcome::OrderCancelled(order_id))
        }
        SUB_DEPOSIT => {
            let (nonce, market_id, asset, amount) = decode_deposit_withdraw(body)?;
            consume_nonce(state, &sender, nonce)?;
            clob.deposit(state, market_id, sender, asset, amount)?;
            Ok(LiquidOutcome::Deposited { asset, amount })
        }
        SUB_WITHDRAW => {
            let (nonce, market_id, asset, amount) = decode_deposit_withdraw(body)?;
            consume_nonce(state, &sender, nonce)?;
            clob.withdraw(state, market_id, sender, asset, amount)?;
            Ok(LiquidOutcome::Withdrawn { asset, amount })
        }
        other => Err(LiquidError::InvalidPayload(format!(
            "unknown ACE Liquid sub-opcode: 0x{other:02x}"
        ))),
    }
}

fn consume_nonce(state: &mut StateTree, sender: &AccountId, nonce: u64) -> Result<(), LiquidError> {
    let account = state
        .get_mut(sender)
        .ok_or_else(|| LiquidError::InvalidPayload("sender account not found".into()))?;
    if account.nonce != nonce {
        return Err(LiquidError::NonceMismatch {
            expected: account.nonce,
            got: nonce,
        });
    }
    account.nonce = account
        .nonce
        .checked_add(1)
        .ok_or(LiquidError::ArithmeticOverflow)?;
    Ok(())
}

// ── Decoders ──────────────────────────────────────────────────────────────

fn decode_create_market(body: &[u8]) -> Result<(u64, Market), LiquidError> {
    const LEN: usize = 8 + 32 + 32 + 8 + 8 + 2 + 2;
    if body.len() != LEN {
        return Err(LiquidError::InvalidPayload(
            "create_market has invalid length".into(),
        ));
    }
    let nonce = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let base = AccountId::from_bytes(body[8..40].try_into().unwrap());
    let quote = AccountId::from_bytes(body[40..72].try_into().unwrap());
    let tick_size = u64::from_le_bytes(body[72..80].try_into().unwrap());
    let lot_size = u64::from_le_bytes(body[80..88].try_into().unwrap());
    let maker_fee_bps = u16::from_le_bytes(body[88..90].try_into().unwrap());
    let taker_fee_bps = u16::from_le_bytes(body[90..92].try_into().unwrap());
    if tick_size == 0 || lot_size == 0 {
        return Err(LiquidError::InvalidPayload(
            "tick_size and lot_size must be non-zero".into(),
        ));
    }
    let market = Market {
        market_id: derive_market_id(&base, &quote),
        base_mint: base,
        quote_mint: quote,
        tick_size,
        lot_size,
        maker_fee_bps,
        taker_fee_bps,
        active: true,
    };
    Ok((nonce, market))
}

fn decode_place_order(
    body: &[u8],
    owner: AccountId,
) -> Result<(u64, MarketId, PlaceOrder), LiquidError> {
    // nonce(8) || market_id(32) || side(1) || order_type(1) || tif(1) || price(8) || quantity(8)
    const LEN: usize = 8 + 32 + 1 + 1 + 1 + 8 + 8;
    if body.len() != LEN {
        return Err(LiquidError::InvalidPayload(
            "place_order has invalid length".into(),
        ));
    }
    let nonce = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let market_id = MarketId(body[8..40].try_into().unwrap());
    let side = decode_side(body[40])?;
    let order_type = decode_order_type(body[41])?;
    let time_in_force = decode_tif(body[42])?;
    let price = u64::from_le_bytes(body[43..51].try_into().unwrap());
    let quantity = u64::from_le_bytes(body[51..59].try_into().unwrap());
    Ok((
        nonce,
        market_id,
        PlaceOrder {
            owner,
            side,
            order_type,
            price,
            quantity,
            time_in_force,
        },
    ))
}

fn decode_cancel_order(body: &[u8]) -> Result<(u64, MarketId, OrderId), LiquidError> {
    // nonce(8) || market_id(32) || order_id(8)
    const LEN: usize = 8 + 32 + 8;
    if body.len() != LEN {
        return Err(LiquidError::InvalidPayload(
            "cancel_order has invalid length".into(),
        ));
    }
    let nonce = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let market_id = MarketId(body[8..40].try_into().unwrap());
    let order_id = OrderId(u64::from_le_bytes(body[40..48].try_into().unwrap()));
    Ok((nonce, market_id, order_id))
}

fn decode_deposit_withdraw(body: &[u8]) -> Result<(u64, MarketId, u8, u64), LiquidError> {
    // nonce(8) || market_id(32) || asset(1) || amount(8)
    const LEN: usize = 8 + 32 + 1 + 8;
    if body.len() != LEN {
        return Err(LiquidError::InvalidPayload(
            "deposit/withdraw has invalid length".into(),
        ));
    }
    let nonce = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let market_id = MarketId(body[8..40].try_into().unwrap());
    let asset = body[40];
    let amount = u64::from_le_bytes(body[41..49].try_into().unwrap());
    Ok((nonce, market_id, asset, amount))
}

fn decode_side(b: u8) -> Result<OrderSide, LiquidError> {
    match b {
        0 => Ok(OrderSide::Buy),
        1 => Ok(OrderSide::Sell),
        _ => Err(LiquidError::InvalidPayload("invalid side".into())),
    }
}

fn decode_order_type(b: u8) -> Result<OrderType, LiquidError> {
    match b {
        0 => Ok(OrderType::Limit),
        1 => Ok(OrderType::Market),
        _ => Err(LiquidError::InvalidPayload("invalid order_type".into())),
    }
}

fn decode_tif(b: u8) -> Result<TimeInForce, LiquidError> {
    match b {
        0 => Ok(TimeInForce::GoodTilCancelled),
        1 => Ok(TimeInForce::ImmediateOrCancel),
        _ => Err(LiquidError::InvalidPayload("invalid time_in_force".into())),
    }
}

// ── Client-side payload builders ──────────────────────────────────────────

pub fn build_create_market_payload(
    nonce: u64,
    base_mint: &AccountId,
    quote_mint: &AccountId,
    tick_size: u64,
    lot_size: u64,
    maker_fee_bps: u16,
    taker_fee_bps: u16,
) -> Vec<u8> {
    let mut out = vec![OP_LIQUID, SUB_CREATE_MARKET];
    out.extend_from_slice(&nonce.to_le_bytes());
    out.extend_from_slice(base_mint.as_bytes());
    out.extend_from_slice(quote_mint.as_bytes());
    out.extend_from_slice(&tick_size.to_le_bytes());
    out.extend_from_slice(&lot_size.to_le_bytes());
    out.extend_from_slice(&maker_fee_bps.to_le_bytes());
    out.extend_from_slice(&taker_fee_bps.to_le_bytes());
    out
}

#[allow(clippy::too_many_arguments)]
pub fn build_place_order_payload(
    nonce: u64,
    market_id: &MarketId,
    side: OrderSide,
    order_type: OrderType,
    time_in_force: TimeInForce,
    price: u64,
    quantity: u64,
) -> Vec<u8> {
    let mut out = vec![OP_LIQUID, SUB_PLACE_ORDER];
    out.extend_from_slice(&nonce.to_le_bytes());
    out.extend_from_slice(market_id.as_bytes());
    out.push(match side {
        OrderSide::Buy => 0,
        OrderSide::Sell => 1,
    });
    out.push(match order_type {
        OrderType::Limit => 0,
        OrderType::Market => 1,
    });
    out.push(match time_in_force {
        TimeInForce::GoodTilCancelled => 0,
        TimeInForce::ImmediateOrCancel => 1,
    });
    out.extend_from_slice(&price.to_le_bytes());
    out.extend_from_slice(&quantity.to_le_bytes());
    out
}

pub fn build_cancel_order_payload(nonce: u64, market_id: &MarketId, order_id: OrderId) -> Vec<u8> {
    let mut out = vec![OP_LIQUID, SUB_CANCEL_ORDER];
    out.extend_from_slice(&nonce.to_le_bytes());
    out.extend_from_slice(market_id.as_bytes());
    out.extend_from_slice(&order_id.0.to_le_bytes());
    out
}

pub fn build_deposit_payload(nonce: u64, market_id: &MarketId, asset: u8, amount: u64) -> Vec<u8> {
    build_deposit_like(SUB_DEPOSIT, nonce, market_id, asset, amount)
}

pub fn build_withdraw_payload(nonce: u64, market_id: &MarketId, asset: u8, amount: u64) -> Vec<u8> {
    build_deposit_like(SUB_WITHDRAW, nonce, market_id, asset, amount)
}

fn build_deposit_like(
    sub: u8,
    nonce: u64,
    market_id: &MarketId,
    asset: u8,
    amount: u64,
) -> Vec<u8> {
    let mut out = vec![OP_LIQUID, sub];
    out.extend_from_slice(&nonce.to_le_bytes());
    out.extend_from_slice(market_id.as_bytes());
    out.push(asset);
    out.extend_from_slice(&amount.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ASSET_BASE, ASSET_QUOTE};
    use ace_defi::types::{ExternalAsset, ExternalChain};
    use ace_model::account::Account;

    fn make_market(state: &mut StateTree) -> Market {
        let market = Market::from_assets(
            &ExternalAsset::Native(ExternalChain::Ethereum),
            &ExternalAsset::Native(ExternalChain::Solana),
        );
        let authority = ace_defi::types::bridge_authority_id();
        for (mint, decimals) in [(market.base_mint, 18u8), (market.quote_mint, 9u8)] {
            ace_n_vm::token_runtime::create_mint(
                state,
                mint.as_bytes(),
                decimals,
                authority.as_bytes(),
            )
            .unwrap();
        }
        market
    }

    fn fund_global(state: &mut StateTree, market: &Market, owner: AccountId, amount: u64) {
        let authority = ace_defi::types::bridge_authority_id();
        if !state.contains(&owner) {
            state.insert(Account::new(owner));
        }
        for mint in [market.base_mint, market.quote_mint] {
            ace_n_vm::token_runtime::mint_to_owner(
                state,
                mint.as_bytes(),
                owner.as_bytes(),
                amount,
                &authority,
            )
            .unwrap();
        }
    }

    #[test]
    fn full_lifecycle_via_wire_with_nonce() {
        let mut state = StateTree::new();
        let market = make_market(&mut state);
        let seller = AccountId::from_bytes([7; 32]);
        fund_global(&mut state, &market, seller, 1_000_000);

        // create market (nonce 0)
        let create =
            build_create_market_payload(0, &market.base_mint, &market.quote_mint, 1, 1, 0, 0);
        assert_eq!(
            execute_liquid_tx(&mut state, seller, &create).unwrap(),
            LiquidOutcome::MarketCreated(market.market_id)
        );

        // deposit base collateral (nonce 1)
        let dep = build_deposit_payload(1, &market.market_id, ASSET_BASE, 1_000);
        assert_eq!(
            execute_liquid_tx(&mut state, seller, &dep).unwrap(),
            LiquidOutcome::Deposited {
                asset: ASSET_BASE,
                amount: 1_000
            }
        );

        // place sell order (nonce 2)
        let place = build_place_order_payload(
            2,
            &market.market_id,
            OrderSide::Sell,
            OrderType::Limit,
            TimeInForce::GoodTilCancelled,
            100,
            5,
        );
        let order_id = match execute_liquid_tx(&mut state, seller, &place).unwrap() {
            LiquidOutcome::OrderPlaced { order_id, fills } => {
                assert_eq!(fills, 0);
                order_id
            }
            _ => panic!("expected OrderPlaced"),
        };

        // stale-nonce replay must fail
        let replay = build_place_order_payload(
            2,
            &market.market_id,
            OrderSide::Sell,
            OrderType::Limit,
            TimeInForce::GoodTilCancelled,
            100,
            5,
        );
        assert!(matches!(
            execute_liquid_tx(&mut state, seller, &replay),
            Err(LiquidError::NonceMismatch { .. })
        ));

        // cancel by another sender rejected
        let mallory = AccountId::from_bytes([9; 32]);
        state.insert(Account::new(mallory));
        let cancel = build_cancel_order_payload(0, &market.market_id, order_id);
        assert!(matches!(
            execute_liquid_tx(&mut state, mallory, &cancel),
            Err(LiquidError::NotOrderOwner)
        ));
        assert_eq!(state.get(&mallory).unwrap().nonce, 0);

        // owner cancels (nonce 3) → base refunded, then withdraw it (nonce 4)
        let cancel = build_cancel_order_payload(3, &market.market_id, order_id);
        assert_eq!(
            execute_liquid_tx(&mut state, seller, &cancel).unwrap(),
            LiquidOutcome::OrderCancelled(order_id)
        );
        let wd = build_withdraw_payload(4, &market.market_id, ASSET_BASE, 1_000);
        assert_eq!(
            execute_liquid_tx(&mut state, seller, &wd).unwrap(),
            LiquidOutcome::Withdrawn {
                asset: ASSET_BASE,
                amount: 1_000
            }
        );
        let _ = ASSET_QUOTE;
    }

    #[test]
    fn failed_wire_execution_rolls_back_nonce() {
        let mut state = StateTree::new();
        let market = make_market(&mut state);
        let sender = AccountId::from_bytes([7; 32]);
        fund_global(&mut state, &market, sender, 1_000_000);

        let create =
            build_create_market_payload(0, &market.base_mint, &market.quote_mint, 1, 1, 1, 0);
        assert!(matches!(
            execute_liquid_tx(&mut state, sender, &create),
            Err(LiquidError::InvalidMarketConfig(_))
        ));
        assert_eq!(state.get(&sender).unwrap().nonce, 0);
        assert!(crate::state::get_market(&state, &market.market_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn trailing_payload_bytes_are_rejected_without_consuming_nonce() {
        let mut state = StateTree::new();
        let market = make_market(&mut state);
        let sender = AccountId::from_bytes([7; 32]);
        fund_global(&mut state, &market, sender, 1_000_000);

        let mut create =
            build_create_market_payload(0, &market.base_mint, &market.quote_mint, 1, 1, 0, 0);
        create.push(0);
        assert!(matches!(
            execute_liquid_tx(&mut state, sender, &create),
            Err(LiquidError::InvalidPayload(_))
        ));
        assert_eq!(state.get(&sender).unwrap().nonce, 0);
    }
}
