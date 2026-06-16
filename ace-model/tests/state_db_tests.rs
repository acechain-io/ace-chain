use ace_model::account::{Account, AccountId};
use ace_model::state_db::{InMemoryStateDB, StateDB};

fn make_id(seed: u8) -> AccountId {
    AccountId::from_bytes([seed; 32])
}

#[test]
fn empty_db_returns_none() {
    let db = InMemoryStateDB::new();
    assert_eq!(db.get_account(&make_id(1)).unwrap(), None);
    assert!(!db.has_account(&make_id(1)).unwrap());
}

#[test]
fn put_and_get_account() {
    let mut db = InMemoryStateDB::new();
    let account = Account::with_balance(make_id(1), 500);
    db.put_account(&account).unwrap();

    let retrieved = db.get_account(&make_id(1)).unwrap().unwrap();
    assert_eq!(retrieved.balance, 500);
    assert!(db.has_account(&make_id(1)).unwrap());
}

#[test]
fn delete_account() {
    let mut db = InMemoryStateDB::new();
    db.put_account(&Account::with_balance(make_id(1), 100))
        .unwrap();
    db.delete_account(&make_id(1)).unwrap();
    assert!(!db.has_account(&make_id(1)).unwrap());
}

#[test]
fn state_root_matches_tree() {
    let mut db = InMemoryStateDB::new();
    db.put_account(&Account::with_balance(make_id(1), 100))
        .unwrap();
    db.put_account(&Account::with_balance(make_id(2), 200))
        .unwrap();

    let root = db.state_root().unwrap();
    assert_ne!(root, [0u8; 32]);

    // Root should match the underlying tree's root.
    assert_eq!(root, db.tree().compute_root());
}

#[test]
fn from_tree_preserves_state() {
    use ace_model::state_tree::StateTree;

    let mut tree = StateTree::new();
    tree.insert(Account::with_balance(make_id(1), 42));
    let root = tree.compute_root();

    let db = InMemoryStateDB::from_tree(tree);
    assert_eq!(db.state_root().unwrap(), root);
    assert_eq!(db.get_account(&make_id(1)).unwrap().unwrap().balance, 42);
}
