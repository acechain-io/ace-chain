//! Deterministic central limit order book for ACE Liquid spot markets.
//!
//! State is **canonical and per-market** in the StateTree (see [`crate::state`]).
//! Trading settles against per-user collateral held *inside the market account*
//! — matching never touches the shared token-program ledger, so place / cancel
//! on different markets are independent and run in parallel. Funds enter and
//! leave a market only through [`SpotClob::deposit`] / [`SpotClob::withdraw`],
//! which bridge the global token ledger and therefore serialize.

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;

use crate::error::LiquidError;
use crate::state::{self, ASSET_BASE, ASSET_QUOTE};
use crate::types::{
    Market, MarketId, Order, OrderId, OrderSide, OrderStatus, OrderType, PlaceOrder, TimeInForce,
    Trade,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct SpotClob;

impl SpotClob {
    pub fn new() -> Self {
        Self
    }

    pub fn create_market(
        &self,
        state: &mut StateTree,
        market: Market,
    ) -> Result<MarketId, LiquidError> {
        validate_market_config(&market)?;
        if state::market_exists(state, &market.market_id) {
            return Err(LiquidError::MarketAlreadyExists(market.market_id));
        }
        // The market account both owns the book state and custodies deposited
        // funds in the global ledger. It must be a real account so the parallel
        // executor merges its storage (a storage-only account would be dropped).
        let book = state::market_book_id(&market.market_id);
        if !state.contains(&book) {
            state.insert(Account::new(book));
        }
        state::put_market(state, &market)?;
        Ok(market.market_id)
    }

    pub fn market(
        &self,
        state: &StateTree,
        market_id: MarketId,
    ) -> Result<Option<Market>, LiquidError> {
        state::get_market(state, &market_id)
    }

    pub fn order(
        &self,
        state: &StateTree,
        market_id: MarketId,
        order_id: OrderId,
    ) -> Result<Option<Order>, LiquidError> {
        state::get_order(state, &market_id, order_id)
    }

    pub fn best_bid(&self, state: &StateTree, market_id: MarketId) -> Option<u64> {
        state::best_price(state, &market_id, OrderSide::Buy)
            .ok()
            .flatten()
    }

    pub fn best_ask(&self, state: &StateTree, market_id: MarketId) -> Option<u64> {
        state::best_price(state, &market_id, OrderSide::Sell)
            .ok()
            .flatten()
    }

    /// Deposit `amount` of a market's base/quote asset from the global token
    /// ledger into the caller's in-market collateral. Touches the shared token
    /// ledger, so it serializes against other token transactions.
    pub fn deposit(
        &self,
        state: &mut StateTree,
        market_id: MarketId,
        user: AccountId,
        asset: u8,
        amount: u64,
    ) -> Result<(), LiquidError> {
        if amount == 0 {
            return Err(LiquidError::ZeroAmount);
        }
        let market =
            state::get_market(state, &market_id)?.ok_or(LiquidError::MarketNotFound(market_id))?;
        ensure_market_active(&market)?;
        let mint = mint_for_asset(&market, asset)?;
        let book = state::market_book_id(&market_id);
        let snapshot = state.snapshot();
        if let Err(e) = move_tokens(state, mint.as_bytes(), &user, &book, amount)
            .and_then(|_| state::credit_balance(state, &market_id, &user, asset, amount))
        {
            state.rollback(snapshot);
            return Err(e);
        }
        Ok(())
    }

    /// Withdraw `amount` of in-market collateral back to the global token ledger.
    pub fn withdraw(
        &self,
        state: &mut StateTree,
        market_id: MarketId,
        user: AccountId,
        asset: u8,
        amount: u64,
    ) -> Result<(), LiquidError> {
        if amount == 0 {
            return Err(LiquidError::ZeroAmount);
        }
        let market =
            state::get_market(state, &market_id)?.ok_or(LiquidError::MarketNotFound(market_id))?;
        let mint = mint_for_asset(&market, asset)?;
        let book = state::market_book_id(&market_id);
        let snapshot = state.snapshot();
        if let Err(e) = state::debit_balance(state, &market_id, &user, asset, amount)
            .and_then(|_| move_tokens(state, mint.as_bytes(), &book, &user, amount))
        {
            state.rollback(snapshot);
            return Err(e);
        }
        Ok(())
    }

    /// In-market free balance of `user` for the given asset.
    pub fn balance(
        &self,
        state: &StateTree,
        market_id: MarketId,
        user: &AccountId,
        asset: u8,
    ) -> u64 {
        state::free_balance(state, &market_id, user, asset)
    }

    /// Place an order: match against the book and settle fills against in-market
    /// collateral; resting GTC limit remainders lock their backing collateral.
    /// Atomic via snapshot/rollback.
    pub fn place_order(
        &self,
        state: &mut StateTree,
        market_id: MarketId,
        request: PlaceOrder,
    ) -> Result<(OrderId, Vec<Trade>), LiquidError> {
        let snapshot = state.snapshot();
        match self.place_order_inner(state, market_id, request) {
            Ok(result) => Ok(result),
            Err(error) => {
                state.rollback(snapshot);
                Err(error)
            }
        }
    }

    fn place_order_inner(
        &self,
        state: &mut StateTree,
        market_id: MarketId,
        request: PlaceOrder,
    ) -> Result<(OrderId, Vec<Trade>), LiquidError> {
        let market =
            state::get_market(state, &market_id)?.ok_or(LiquidError::MarketNotFound(market_id))?;
        ensure_market_active(&market)?;
        validate_order(&market, &request)?;

        let order_id = state::next_order_id(state, &market_id)?;
        let sequence = state::next_sequence(state, &market_id)?;
        let mut taker = Order {
            order_id,
            market_id,
            owner: request.owner,
            side: request.side,
            order_type: request.order_type,
            price: request.price,
            quantity: request.quantity,
            remaining_quantity: request.quantity,
            status: OrderStatus::Open,
            sequence,
        };

        let mut trades = Vec::new();
        let blocked_by_self_trade = self.match_taker(state, &mut taker, &mut trades)?;
        if blocked_by_self_trade && trades.is_empty() {
            return Err(LiquidError::SelfTrade);
        }

        if taker.remaining_quantity == 0 {
            taker.status = OrderStatus::Filled;
        } else if taker.remaining_quantity < taker.quantity {
            taker.status = OrderStatus::PartiallyFilled;
        }

        let should_rest = taker.remaining_quantity > 0
            && taker.order_type == OrderType::Limit
            && !blocked_by_self_trade
            && time_in_force_allows_resting(request.time_in_force);

        if should_rest {
            self.lock_resting_funds(state, &taker)?;
            taker.status = if taker.remaining_quantity < taker.quantity {
                OrderStatus::PartiallyFilled
            } else {
                OrderStatus::Open
            };
            state::enqueue_order(state, &market_id, taker.side, taker.price, order_id)?;
        } else if taker.remaining_quantity > 0
            && taker.order_type == OrderType::Market
            && trades.is_empty()
        {
            return Err(LiquidError::NoLiquidity);
        } else if taker.remaining_quantity > 0 {
            taker.remaining_quantity = 0;
            taker.status = if trades.is_empty() {
                OrderStatus::Cancelled
            } else {
                OrderStatus::PartiallyFilled
            };
        }

        state::put_order(state, &taker)?;
        Ok((order_id, trades))
    }

    pub fn cancel_order(
        &self,
        state: &mut StateTree,
        market_id: MarketId,
        owner: AccountId,
        order_id: OrderId,
    ) -> Result<Order, LiquidError> {
        let snapshot = state.snapshot();
        match self.cancel_order_inner(state, market_id, owner, order_id) {
            Ok(order) => Ok(order),
            Err(error) => {
                state.rollback(snapshot);
                Err(error)
            }
        }
    }

    fn cancel_order_inner(
        &self,
        state: &mut StateTree,
        market_id: MarketId,
        owner: AccountId,
        order_id: OrderId,
    ) -> Result<Order, LiquidError> {
        state::get_market(state, &market_id)?.ok_or(LiquidError::MarketNotFound(market_id))?;
        let mut order = state::get_order(state, &market_id, order_id)?
            .ok_or(LiquidError::OrderNotFound(order_id))?;
        if order.owner != owner {
            return Err(LiquidError::NotOrderOwner);
        }
        if !matches!(
            order.status,
            OrderStatus::Open | OrderStatus::PartiallyFilled
        ) || order.remaining_quantity == 0
        {
            return Err(LiquidError::OrderNotOpen(order_id));
        }

        // Refund the locked remainder to the owner's in-market balance.
        self.refund_resting_funds(state, &order)?;
        state::remove_order_from_queue(state, &market_id, order.side, order.price, order_id)?;
        order.status = OrderStatus::Cancelled;
        order.remaining_quantity = 0;
        state::put_order(state, &order)?;
        Ok(order)
    }

    fn match_taker(
        &self,
        state: &mut StateTree,
        taker: &mut Order,
        trades: &mut Vec<Trade>,
    ) -> Result<bool, LiquidError> {
        let market_id = taker.market_id;
        let maker_side = opposite_side(taker.side);
        loop {
            if taker.remaining_quantity == 0 {
                return Ok(false);
            }
            let Some(maker_price) = state::best_price(state, &market_id, maker_side)? else {
                return Ok(false);
            };
            if taker.order_type == OrderType::Limit && !price_crosses(taker, maker_price) {
                return Ok(false);
            }
            let Some(maker_id) = state::front_order_at(state, &market_id, maker_side, maker_price)?
            else {
                return Ok(false);
            };
            let mut maker = state::get_order(state, &market_id, maker_id)?
                .ok_or(LiquidError::OrderNotFound(maker_id))?;
            if maker.owner == taker.owner {
                return Ok(true);
            }

            let quantity = taker.remaining_quantity.min(maker.remaining_quantity);
            let quote_u128 = (quantity as u128)
                .checked_mul(maker.price as u128)
                .ok_or(LiquidError::ArithmeticOverflow)?;
            let quote = u64::try_from(quote_u128).map_err(|_| LiquidError::ArithmeticOverflow)?;

            self.settle_fill(state, &market_id, taker, &maker, quantity, quote)?;

            taker.remaining_quantity -= quantity;
            maker.remaining_quantity -= quantity;
            maker.status = if maker.remaining_quantity == 0 {
                OrderStatus::Filled
            } else {
                OrderStatus::PartiallyFilled
            };

            trades.push(Trade {
                market_id,
                maker_order_id: maker.order_id,
                taker_order_id: taker.order_id,
                maker: maker.owner,
                taker: taker.owner,
                side: taker.side,
                price: maker.price,
                quantity,
                quote_quantity: quote_u128,
            });

            if maker.remaining_quantity == 0 {
                state::remove_order_from_queue(
                    state,
                    &market_id,
                    maker_side,
                    maker.price,
                    maker.order_id,
                )?;
            }
            state::put_order(state, &maker)?;
        }
    }

    /// Settle a fill against in-market collateral. The maker's side was already
    /// debited (locked) when it rested; the taker pays from its free balance.
    fn settle_fill(
        &self,
        state: &mut StateTree,
        market_id: &MarketId,
        taker: &Order,
        maker: &Order,
        quantity: u64,
        quote: u64,
    ) -> Result<(), LiquidError> {
        match taker.side {
            OrderSide::Buy => {
                // Taker pays quote, receives base; maker (resting sell) gets quote.
                state::debit_balance(state, market_id, &taker.owner, ASSET_QUOTE, quote)?;
                state::credit_balance(state, market_id, &taker.owner, ASSET_BASE, quantity)?;
                state::credit_balance(state, market_id, &maker.owner, ASSET_QUOTE, quote)?;
            }
            OrderSide::Sell => {
                // Taker delivers base, receives quote; maker (resting buy) gets base.
                state::debit_balance(state, market_id, &taker.owner, ASSET_BASE, quantity)?;
                state::credit_balance(state, market_id, &taker.owner, ASSET_QUOTE, quote)?;
                state::credit_balance(state, market_id, &maker.owner, ASSET_BASE, quantity)?;
            }
        }
        Ok(())
    }

    /// Lock the collateral backing a resting order's remainder.
    fn lock_resting_funds(&self, state: &mut StateTree, order: &Order) -> Result<(), LiquidError> {
        match order.side {
            OrderSide::Buy => {
                let lock = locked_quote(order)?;
                state::debit_balance(state, &order.market_id, &order.owner, ASSET_QUOTE, lock)
            }
            OrderSide::Sell => state::debit_balance(
                state,
                &order.market_id,
                &order.owner,
                ASSET_BASE,
                order.remaining_quantity,
            ),
        }
    }

    /// Refund a resting order's locked collateral to its owner (on cancel).
    fn refund_resting_funds(
        &self,
        state: &mut StateTree,
        order: &Order,
    ) -> Result<(), LiquidError> {
        match order.side {
            OrderSide::Buy => {
                let refund = locked_quote(order)?;
                state::credit_balance(state, &order.market_id, &order.owner, ASSET_QUOTE, refund)
            }
            OrderSide::Sell => state::credit_balance(
                state,
                &order.market_id,
                &order.owner,
                ASSET_BASE,
                order.remaining_quantity,
            ),
        }
    }
}

fn locked_quote(order: &Order) -> Result<u64, LiquidError> {
    let q = (order.remaining_quantity as u128)
        .checked_mul(order.price as u128)
        .ok_or(LiquidError::ArithmeticOverflow)?;
    u64::try_from(q).map_err(|_| LiquidError::ArithmeticOverflow)
}

fn mint_for_asset(market: &Market, asset: u8) -> Result<AccountId, LiquidError> {
    match asset {
        ASSET_BASE => Ok(market.base_mint),
        ASSET_QUOTE => Ok(market.quote_mint),
        _ => Err(LiquidError::InvalidPayload("invalid asset index".into())),
    }
}

fn move_tokens(
    state: &mut StateTree,
    mint: &[u8; 32],
    from: &AccountId,
    to: &AccountId,
    amount: u64,
) -> Result<(), LiquidError> {
    if amount == 0 {
        return Ok(());
    }
    if !state.contains(to) {
        state.insert(Account::new(*to));
    }
    ace_n_vm::token_runtime::transfer_between_owners(state, mint, from, to, amount)
        .map(|_| ())
        .map_err(LiquidError::Settlement)
}

fn opposite_side(side: OrderSide) -> OrderSide {
    match side {
        OrderSide::Buy => OrderSide::Sell,
        OrderSide::Sell => OrderSide::Buy,
    }
}

fn price_crosses(taker: &Order, maker_price: u64) -> bool {
    match taker.side {
        OrderSide::Buy => maker_price <= taker.price,
        OrderSide::Sell => maker_price >= taker.price,
    }
}

fn time_in_force_allows_resting(tif: TimeInForce) -> bool {
    matches!(tif, TimeInForce::GoodTilCancelled)
}

fn validate_order(market: &Market, order: &PlaceOrder) -> Result<(), LiquidError> {
    if market.tick_size == 0 || market.lot_size == 0 {
        return Err(LiquidError::InvalidMarketConfig(
            "tick_size and lot_size must be non-zero".into(),
        ));
    }
    if order.quantity == 0 {
        return Err(LiquidError::ZeroAmount);
    }
    if order.order_type == OrderType::Limit && order.price == 0 {
        return Err(LiquidError::ZeroPrice);
    }
    if order.quantity % market.lot_size != 0 {
        return Err(LiquidError::ZeroAmount);
    }
    if order.order_type == OrderType::Limit && order.price % market.tick_size != 0 {
        return Err(LiquidError::ZeroPrice);
    }
    Ok(())
}

fn validate_market_config(market: &Market) -> Result<(), LiquidError> {
    if market.base_mint == market.quote_mint {
        return Err(LiquidError::InvalidMarketConfig(
            "base_mint and quote_mint must differ".into(),
        ));
    }
    let expected = crate::types::derive_market_id(&market.base_mint, &market.quote_mint);
    if market.market_id != expected {
        return Err(LiquidError::InvalidMarketConfig(
            "market_id does not match base/quote mints".into(),
        ));
    }
    if market.tick_size == 0 || market.lot_size == 0 {
        return Err(LiquidError::InvalidMarketConfig(
            "tick_size and lot_size must be non-zero".into(),
        ));
    }
    if market.maker_fee_bps != 0 || market.taker_fee_bps != 0 {
        return Err(LiquidError::InvalidMarketConfig(
            "non-zero fees are not supported yet".into(),
        ));
    }
    Ok(())
}

fn ensure_market_active(market: &Market) -> Result<(), LiquidError> {
    if market.active {
        Ok(())
    } else {
        Err(LiquidError::MarketInactive(market.market_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_defi::types::{ExternalAsset, ExternalChain};
    use ace_model::account::Account;

    fn account(byte: u8) -> AccountId {
        AccountId::from_bytes([byte; 32])
    }

    fn market() -> Market {
        Market::from_assets(
            &ExternalAsset::Native(ExternalChain::Ethereum),
            &ExternalAsset::Native(ExternalChain::Solana),
        )
    }

    fn alt_market() -> Market {
        Market::from_assets(
            &ExternalAsset::Native(ExternalChain::Bitcoin),
            &ExternalAsset::Native(ExternalChain::Tron),
        )
    }

    /// State with both mints created and `owners` each holding `amount` of base
    /// and quote in the *global* token ledger (not yet deposited).
    fn setup(owners: &[u8]) -> (StateTree, Market, SpotClob) {
        let mut state = StateTree::new();
        let market = market();
        let authority = ace_defi::types::bridge_authority_id();
        for (mint, decimals) in [(market.base_mint, 18u8), (market.quote_mint, 9u8)] {
            ace_n_vm::token_runtime::create_mint(
                &mut state,
                mint.as_bytes(),
                decimals,
                authority.as_bytes(),
            )
            .unwrap();
        }
        for &byte in owners {
            let owner = account(byte);
            if !state.contains(&owner) {
                state.insert(Account::new(owner));
            }
            for mint in [market.base_mint, market.quote_mint] {
                ace_n_vm::token_runtime::mint_to_owner(
                    &mut state,
                    mint.as_bytes(),
                    owner.as_bytes(),
                    1_000_000_000,
                    &authority,
                )
                .unwrap();
            }
        }
        let clob = SpotClob::new();
        clob.create_market(&mut state, market.clone()).unwrap();
        (state, market, clob)
    }

    fn create_market_mints(state: &mut StateTree, market: &Market) {
        let authority = ace_defi::types::bridge_authority_id();
        for (mint, decimals) in [(market.base_mint, 18u8), (market.quote_mint, 9u8)] {
            if ace_n_vm::token_runtime::get_mint_meta(state, mint.as_bytes()).is_none() {
                ace_n_vm::token_runtime::create_mint(
                    state,
                    mint.as_bytes(),
                    decimals,
                    authority.as_bytes(),
                )
                .unwrap();
            }
        }
    }

    fn mint_market_assets_to_owner(
        state: &mut StateTree,
        market: &Market,
        owner: AccountId,
        amount: u64,
    ) {
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

    /// Deposit both assets into a user's in-market collateral.
    fn fund(state: &mut StateTree, clob: &SpotClob, market: &Market, who: u8, amount: u64) {
        clob.deposit(state, market.market_id, account(who), ASSET_BASE, amount)
            .unwrap();
        clob.deposit(state, market.market_id, account(who), ASSET_QUOTE, amount)
            .unwrap();
    }

    fn order(owner: AccountId, side: OrderSide, price: u64, quantity: u64) -> PlaceOrder {
        PlaceOrder {
            owner,
            side,
            order_type: OrderType::Limit,
            price,
            quantity,
            time_in_force: TimeInForce::GoodTilCancelled,
        }
    }

    fn gbal(state: &StateTree, mint: &AccountId, owner: AccountId) -> u64 {
        ace_n_vm::token_runtime::balance_of(state, mint.as_bytes(), &owner)
    }

    #[test]
    fn deposit_and_withdraw_round_trip() {
        let (mut state, market, clob) = setup(&[10]);
        let user = account(10);
        let before = gbal(&state, &market.base_mint, user);
        clob.deposit(&mut state, market.market_id, user, ASSET_BASE, 500)
            .unwrap();
        assert_eq!(
            clob.balance(&state, market.market_id, &user, ASSET_BASE),
            500
        );
        assert_eq!(gbal(&state, &market.base_mint, user), before - 500);

        clob.withdraw(&mut state, market.market_id, user, ASSET_BASE, 200)
            .unwrap();
        assert_eq!(
            clob.balance(&state, market.market_id, &user, ASSET_BASE),
            300
        );
        assert_eq!(gbal(&state, &market.base_mint, user), before - 300);

        // Over-withdraw fails and leaves balances intact.
        assert!(matches!(
            clob.withdraw(&mut state, market.market_id, user, ASSET_BASE, 9_999),
            Err(LiquidError::InsufficientBalance { .. })
        ));
        assert_eq!(
            clob.balance(&state, market.market_id, &user, ASSET_BASE),
            300
        );
    }

    #[test]
    fn limit_order_rests_and_locks_quote() {
        let (mut state, market, clob) = setup(&[10]);
        fund(&mut state, &clob, &market, 10, 1_000_000);
        let buyer = account(10);
        let (order_id, trades) = clob
            .place_order(
                &mut state,
                market.market_id,
                order(buyer, OrderSide::Buy, 100, 5),
            )
            .unwrap();
        assert!(trades.is_empty());
        assert_eq!(clob.best_bid(&state, market.market_id), Some(100));
        assert_eq!(
            clob.order(&state, market.market_id, order_id)
                .unwrap()
                .unwrap()
                .remaining_quantity,
            5
        );
        // 500 quote locked out of free balance.
        assert_eq!(
            clob.balance(&state, market.market_id, &buyer, ASSET_QUOTE),
            1_000_000 - 500
        );
    }

    #[test]
    fn crossing_order_matches_and_settles_internally() {
        let (mut state, market, clob) = setup(&[10, 11, 12]);
        for who in [10, 11, 12] {
            fund(&mut state, &clob, &market, who, 1_000_000);
        }
        let m = market.market_id;
        let (maker_1, _) = clob
            .place_order(&mut state, m, order(account(10), OrderSide::Sell, 101, 3))
            .unwrap();
        let (maker_2, _) = clob
            .place_order(&mut state, m, order(account(11), OrderSide::Sell, 101, 4))
            .unwrap();

        let taker = account(12);
        let (taker_id, trades) = clob
            .place_order(&mut state, m, order(taker, OrderSide::Buy, 105, 5))
            .unwrap();

        assert_eq!(trades.len(), 2);
        assert_eq!(trades[0].maker_order_id, maker_1);
        assert_eq!(trades[1].maker_order_id, maker_2);
        assert_eq!(
            clob.order(&state, m, taker_id).unwrap().unwrap().status,
            OrderStatus::Filled
        );
        // Taker: +5 base, -505 quote (5 * 101).
        assert_eq!(clob.balance(&state, m, &taker, ASSET_BASE), 1_000_000 + 5);
        assert_eq!(
            clob.balance(&state, m, &taker, ASSET_QUOTE),
            1_000_000 - 505
        );
        // Maker 1: sold 3 base (locked at rest) for 303 quote.
        assert_eq!(
            clob.balance(&state, m, &account(10), ASSET_QUOTE),
            1_000_000 + 303
        );
        assert_eq!(
            clob.balance(&state, m, &account(10), ASSET_BASE),
            1_000_000 - 3
        );
        // Maker 2 still rests with 2 base remaining (2 of its 4 base still locked).
        assert_eq!(
            clob.order(&state, m, maker_2)
                .unwrap()
                .unwrap()
                .remaining_quantity,
            2
        );
        assert_eq!(clob.best_ask(&state, m), Some(101));
    }

    #[test]
    fn cancel_refunds_locked_collateral() {
        let (mut state, market, clob) = setup(&[10]);
        fund(&mut state, &clob, &market, 10, 1_000_000);
        let seller = account(10);
        let m = market.market_id;
        let (order_id, _) = clob
            .place_order(&mut state, m, order(seller, OrderSide::Sell, 99, 5))
            .unwrap();
        assert_eq!(clob.balance(&state, m, &seller, ASSET_BASE), 1_000_000 - 5);
        let cancelled = clob.cancel_order(&mut state, m, seller, order_id).unwrap();
        assert_eq!(cancelled.status, OrderStatus::Cancelled);
        assert_eq!(clob.best_bid(&state, m), None);
        assert_eq!(clob.balance(&state, m, &seller, ASSET_BASE), 1_000_000);
    }

    #[test]
    fn insufficient_collateral_rolls_back() {
        let (mut state, market, clob) = setup(&[10, 11]);
        fund(&mut state, &clob, &market, 10, 1_000_000); // seller funded
        let m = market.market_id;
        clob.place_order(&mut state, m, order(account(10), OrderSide::Sell, 100, 2))
            .unwrap();

        // Buyer deposited nothing → no quote collateral → cross must fail & roll back.
        let poor = account(11);
        let result = clob.place_order(&mut state, m, order(poor, OrderSide::Buy, 100, 2));
        assert!(matches!(
            result,
            Err(LiquidError::InsufficientBalance { .. })
        ));
        assert_eq!(clob.best_ask(&state, m), Some(100));
    }

    #[test]
    fn cancel_middle_of_level_preserves_fifo() {
        let (mut state, market, clob) = setup(&[10, 11, 12, 20]);
        for who in [10, 11, 12, 20] {
            fund(&mut state, &clob, &market, who, 1_000_000);
        }
        let m = market.market_id;
        let (s1, _) = clob
            .place_order(&mut state, m, order(account(10), OrderSide::Sell, 100, 1))
            .unwrap();
        let (s2, _) = clob
            .place_order(&mut state, m, order(account(11), OrderSide::Sell, 100, 1))
            .unwrap();
        let (s3, _) = clob
            .place_order(&mut state, m, order(account(12), OrderSide::Sell, 100, 1))
            .unwrap();

        clob.cancel_order(&mut state, m, account(11), s2).unwrap();

        let (_, trades) = clob
            .place_order(&mut state, m, order(account(20), OrderSide::Buy, 100, 2))
            .unwrap();
        assert_eq!(trades.len(), 2);
        assert_eq!(trades[0].maker_order_id, s1);
        assert_eq!(trades[1].maker_order_id, s3);
        assert_eq!(clob.best_ask(&state, m), None);
    }

    #[test]
    fn self_trade_before_any_fill_is_rejected() {
        let (mut state, market, clob) = setup(&[10]);
        fund(&mut state, &clob, &market, 10, 1_000_000);
        let m = market.market_id;
        clob.place_order(&mut state, m, order(account(10), OrderSide::Sell, 100, 2))
            .unwrap();
        let result = clob.place_order(&mut state, m, order(account(10), OrderSide::Buy, 100, 1));
        assert_eq!(result.unwrap_err(), LiquidError::SelfTrade);
        assert_eq!(clob.best_ask(&state, m), Some(100));
    }

    #[test]
    fn cancel_requires_order_owner_in_core_api() {
        let (mut state, market, clob) = setup(&[10, 11]);
        fund(&mut state, &clob, &market, 10, 1_000_000);
        let m = market.market_id;
        let owner = account(10);
        let (order_id, _) = clob
            .place_order(&mut state, m, order(owner, OrderSide::Sell, 100, 2))
            .unwrap();

        assert_eq!(
            clob.cancel_order(&mut state, m, account(11), order_id)
                .unwrap_err(),
            LiquidError::NotOrderOwner
        );
        assert_eq!(clob.best_ask(&state, m), Some(100));
        assert_eq!(
            clob.order(&state, m, order_id).unwrap().unwrap().status,
            OrderStatus::Open
        );
    }

    #[test]
    fn create_market_rejects_unsupported_fee_config() {
        let mut state = StateTree::new();
        let clob = SpotClob::new();
        let mut market = market();
        market.taker_fee_bps = 1;

        assert!(matches!(
            clob.create_market(&mut state, market),
            Err(LiquidError::InvalidMarketConfig(_))
        ));
    }

    #[test]
    fn inactive_market_rejects_orders() {
        let (mut state, mut market, clob) = setup(&[10]);
        let active_market_id = market.market_id;
        market.active = false;
        crate::state::put_market(&mut state, &market).unwrap();

        assert_eq!(
            clob.place_order(
                &mut state,
                active_market_id,
                order(account(10), OrderSide::Sell, 100, 1),
            )
            .unwrap_err(),
            LiquidError::MarketInactive(active_market_id)
        );
    }

    #[test]
    fn inactive_market_compartment_does_not_block_other_market() {
        let (mut state, mut first, clob) = setup(&[10]);
        let second = alt_market();
        create_market_mints(&mut state, &second);
        mint_market_assets_to_owner(&mut state, &second, account(10), 1_000_000_000);
        clob.create_market(&mut state, second.clone()).unwrap();
        fund(&mut state, &clob, &second, 10, 1_000_000);

        assert_ne!(first.risk_compartment_id(), second.risk_compartment_id());
        first.active = false;
        crate::state::put_market(&mut state, &first).unwrap();

        assert_eq!(
            clob.place_order(
                &mut state,
                first.market_id,
                order(account(10), OrderSide::Sell, 100, 1),
            )
            .unwrap_err(),
            LiquidError::MarketInactive(first.market_id)
        );

        clob.place_order(
            &mut state,
            second.market_id,
            order(account(10), OrderSide::Sell, 100, 1),
        )
        .expect("pausing one market compartment must not block another market");
    }
}
