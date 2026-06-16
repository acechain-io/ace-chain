//! Native balance transfer logic.
//!
//! Implements the core balance transfer between two accounts,
//! including balance checks and nonce management.

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;

use crate::error::EngineError;
use crate::receipt::StateChange;

/// Execute a balance transfer between two accounts.
///
/// 1. Verify sender exists and has sufficient balance
/// 2. Verify receiver exists (fails if not)
/// 3. Deduct from sender, credit to receiver
/// 4. Increment sender nonce
///
/// Returns the list of state changes applied.
pub fn transfer(
    state: &mut StateTree,
    from: &AccountId,
    to: &AccountId,
    amount: u64,
    expected_nonce: Option<u64>,
) -> Result<Vec<StateChange>, EngineError> {
    transfer_with_nonce_policy(state, from, to, amount, expected_nonce, true)
}

/// Execute a balance transfer with explicit control over account-nonce mutation.
pub fn transfer_with_nonce_policy(
    state: &mut StateTree,
    from: &AccountId,
    to: &AccountId,
    amount: u64,
    expected_nonce: Option<u64>,
    increment_nonce: bool,
) -> Result<Vec<StateChange>, EngineError> {
    // Check sender is not expired
    if state.is_stubbed(from) {
        return Err(EngineError::AccountExpired(from.0));
    }

    // Check sender exists
    let sender = state
        .get(from)
        .ok_or(EngineError::AccountNotFound(from.0))?;

    // Validate nonce if provided
    if let Some(nonce) = expected_nonce {
        if sender.nonce != nonce {
            return Err(EngineError::InvalidNonce {
                expected: sender.nonce,
                got: nonce,
            });
        }
    }

    // Check sufficient balance
    if sender.balance < amount {
        return Err(EngineError::InsufficientBalance {
            have: sender.balance,
            need: amount,
        });
    }

    // Check receiver is not expired
    if state.is_stubbed(to) {
        return Err(EngineError::AccountExpired(to.0));
    }

    // Auto-create receiver if it doesn't exist (with zero auth_pubkey).
    // The receiver can later set their auth_pubkey via OP_SET_AUTH_PUBKEY
    // or HFI Pay registration.
    if !state.contains(to) {
        use ace_model::account::Account;
        state.insert(Account::with_balance(*to, 0));
    }

    let old_sender_balance = state.get(from).unwrap().balance;

    if from == to {
        // Self-transfer: balance unchanged; signed-account mode consumes nonce.
        if !increment_nonce {
            return Ok(Vec::new());
        }
        let account = state.get_mut(from).unwrap();
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or(EngineError::NonceOverflow(from.0))?;
        let new_nonce = account.nonce;

        return Ok(vec![StateChange::NonceIncrement {
            account: *from,
            new_nonce,
        }]);
    }

    let old_receiver_balance = state.get(to).unwrap().balance;

    // Check receiver balance won't overflow
    if old_receiver_balance.checked_add(amount).is_none() {
        return Err(EngineError::BalanceOverflow {
            balance: old_receiver_balance,
            amount,
        });
    }

    // Deduct from sender (already validated sufficient balance above).
    let sender_mut = state.get_mut(from).unwrap();
    sender_mut.balance -= amount;
    let new_sender_balance = sender_mut.balance;
    let nonce_change = if increment_nonce {
        let new_nonce = sender_mut
            .nonce
            .checked_add(1)
            .ok_or(EngineError::NonceOverflow(from.0))?;
        sender_mut.nonce = new_nonce;
        Some(StateChange::NonceIncrement {
            account: *from,
            new_nonce,
        })
    } else {
        None
    };

    // Credit receiver
    let receiver_mut = state.get_mut(to).unwrap();
    receiver_mut.balance += amount; // safe: checked above
    let new_receiver_balance = receiver_mut.balance;

    let mut changes = vec![StateChange::BalanceChange {
        account: *from,
        old: old_sender_balance,
        new: new_sender_balance,
    }];
    if let Some(change) = nonce_change {
        changes.push(change);
    }
    changes.push(StateChange::BalanceChange {
        account: *to,
        old: old_receiver_balance,
        new: new_receiver_balance,
    });
    Ok(changes)
}
