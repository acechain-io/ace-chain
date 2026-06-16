use ace_engine::error::EngineError;
use ace_engine::transfer::transfer;
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;

fn setup_tree() -> (StateTree, AccountId, AccountId) {
    let mut tree = StateTree::new();
    let alice = AccountId::from_bytes([1u8; 32]);
    let bob = AccountId::from_bytes([2u8; 32]);
    tree.insert(Account::with_balance(alice, 1000));
    tree.insert(Account::with_balance(bob, 500));
    (tree, alice, bob)
}

#[test]
fn successful_transfer() {
    let (mut tree, alice, bob) = setup_tree();
    let changes = transfer(&mut tree, &alice, &bob, 100, None).unwrap();

    assert_eq!(tree.get(&alice).unwrap().balance, 900);
    assert_eq!(tree.get(&bob).unwrap().balance, 600);
    assert_eq!(tree.get(&alice).unwrap().nonce, 1);
    assert!(!changes.is_empty());
}

#[test]
fn insufficient_balance() {
    let (mut tree, alice, bob) = setup_tree();
    let result = transfer(&mut tree, &alice, &bob, 1001, None);
    assert!(matches!(
        result,
        Err(EngineError::InsufficientBalance { .. })
    ));
    // State unchanged
    assert_eq!(tree.get(&alice).unwrap().balance, 1000);
}

#[test]
fn sender_not_found() {
    let (mut tree, _, bob) = setup_tree();
    let unknown = AccountId::from_bytes([99u8; 32]);
    let result = transfer(&mut tree, &unknown, &bob, 100, None);
    assert!(matches!(result, Err(EngineError::AccountNotFound(_))));
}

#[test]
fn receiver_auto_created_on_transfer() {
    let (mut tree, alice, _) = setup_tree();
    let unknown = AccountId::from_bytes([99u8; 32]);
    // Transfer to non-existent receiver should auto-create the account.
    let changes = transfer(&mut tree, &alice, &unknown, 100, None).unwrap();
    assert!(!changes.is_empty());
    assert!(tree.contains(&unknown));
    assert_eq!(tree.get(&unknown).unwrap().balance, 100);
}

#[test]
fn transfer_to_self() {
    let (mut tree, alice, _) = setup_tree();
    let changes = transfer(&mut tree, &alice, &alice, 100, None).unwrap();

    // Balance unchanged (deducted then credited to same account)
    assert_eq!(tree.get(&alice).unwrap().balance, 1000);
    // Nonce still increments
    assert_eq!(tree.get(&alice).unwrap().nonce, 1);
    assert!(!changes.is_empty());
}

#[test]
fn zero_amount_transfer() {
    let (mut tree, alice, bob) = setup_tree();
    let _ = transfer(&mut tree, &alice, &bob, 0, None).unwrap();
    assert_eq!(tree.get(&alice).unwrap().balance, 1000);
    assert_eq!(tree.get(&bob).unwrap().balance, 500);
    assert_eq!(tree.get(&alice).unwrap().nonce, 1);
}

#[test]
fn nonce_validation() {
    let (mut tree, alice, bob) = setup_tree();
    // Correct nonce
    transfer(&mut tree, &alice, &bob, 10, Some(0)).unwrap();
    // Wrong nonce
    let result = transfer(&mut tree, &alice, &bob, 10, Some(0));
    assert!(matches!(result, Err(EngineError::InvalidNonce { .. })));
    // Correct nonce again
    transfer(&mut tree, &alice, &bob, 10, Some(1)).unwrap();
    assert_eq!(tree.get(&alice).unwrap().nonce, 2);
}
