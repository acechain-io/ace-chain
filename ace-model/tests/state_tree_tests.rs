use ace_model::account::{Account, AccountId};
use ace_model::state_tree::{derive_evm_address, derive_tron_address, StateTree};

fn make_account(seed: u8, balance: u64) -> Account {
    Account::with_balance(AccountId::from_bytes([seed; 32]), balance)
}

#[test]
fn empty_tree_root_is_domain_separated() {
    let tree = StateTree::new();
    // Empty tree returns SHA-256("ACE-EMPTY-STATE-V1"), not all zeros.
    let expected: [u8; 32] = [
        244, 121, 99, 251, 173, 176, 134, 197, 88, 244, 213, 185, 110, 173, 251, 229, 180, 51, 47,
        126, 36, 234, 243, 167, 60, 240, 70, 227, 132, 118, 84, 37,
    ];
    assert_eq!(tree.compute_root(), expected);
    assert_eq!(tree.account_count(), 0);
}

#[test]
fn insert_and_get() {
    let mut tree = StateTree::new();
    let account = make_account(1, 100);
    let id = account.id_com;
    tree.insert(account.clone());

    assert!(tree.contains(&id));
    assert_eq!(tree.get(&id).unwrap().balance, 100);
    assert_eq!(tree.account_count(), 1);
}

#[test]
fn insert_updates_existing() {
    let mut tree = StateTree::new();
    let id = AccountId::from_bytes([1u8; 32]);
    tree.insert(Account::with_balance(id, 100));
    tree.insert(Account::with_balance(id, 200));

    assert_eq!(tree.account_count(), 1);
    assert_eq!(tree.get(&id).unwrap().balance, 200);
}

#[test]
fn remove_account() {
    let mut tree = StateTree::new();
    let account = make_account(1, 100);
    let id = account.id_com;
    tree.insert(account);
    assert!(tree.contains(&id));

    let removed = tree.remove(&id);
    assert!(removed.is_some());
    assert!(!tree.contains(&id));
    assert_eq!(tree.account_count(), 0);
}

#[test]
fn get_mut_modifies_account() {
    let mut tree = StateTree::new();
    tree.insert(make_account(1, 100));
    let id = AccountId::from_bytes([1u8; 32]);

    tree.get_mut(&id).unwrap().balance = 999;
    assert_eq!(tree.get(&id).unwrap().balance, 999);
}

#[test]
fn state_root_deterministic() {
    let mut tree = StateTree::new();
    tree.insert(make_account(1, 100));
    tree.insert(make_account(2, 200));

    let root1 = tree.compute_root();
    let root2 = tree.compute_root();
    assert_eq!(root1, root2);
    assert_ne!(root1, [0u8; 32]); // non-trivial root
}

#[test]
fn state_root_changes_with_balance() {
    let mut tree = StateTree::new();
    tree.insert(make_account(1, 100));
    let root1 = tree.compute_root();

    tree.get_mut(&AccountId::from_bytes([1u8; 32]))
        .unwrap()
        .balance = 200;
    let root2 = tree.compute_root();

    assert_ne!(root1, root2);
}

#[test]
fn zk_replay_registry_changes_root_and_rolls_back() {
    let mut tree = StateTree::new();
    let root_before = tree.compute_root();
    let snapshot = tree.snapshot();

    assert!(tree.zk_replay_consume([0xA1; 32], [0xB2; 32]));
    assert!(tree.zk_replay_contains(&[0xA1; 32]));
    assert_eq!(tree.zk_replay_count(), 1);
    assert_ne!(tree.compute_root(), root_before);
    assert!(!tree.zk_replay_consume([0xA1; 32], [0xB2; 32]));

    tree.rollback(snapshot);
    assert!(!tree.zk_replay_contains(&[0xA1; 32]));
    assert_eq!(tree.zk_replay_count(), 0);
    assert_eq!(tree.compute_root(), root_before);
}

#[test]
fn state_root_independent_of_insertion_order() {
    let mut tree1 = StateTree::new();
    tree1.insert(make_account(1, 100));
    tree1.insert(make_account(2, 200));

    let mut tree2 = StateTree::new();
    tree2.insert(make_account(2, 200));
    tree2.insert(make_account(1, 100));

    // BTreeMap gives deterministic order regardless of insertion order.
    assert_eq!(tree1.compute_root(), tree2.compute_root());
}

#[test]
fn snapshot_and_rollback() {
    let mut tree = StateTree::new();
    tree.insert(make_account(1, 100));
    let snapshot = tree.snapshot();

    // Modify state
    tree.insert(make_account(2, 200));
    tree.get_mut(&AccountId::from_bytes([1u8; 32]))
        .unwrap()
        .balance = 999;
    assert_eq!(tree.account_count(), 2);

    // Rollback
    tree.rollback(snapshot);
    assert_eq!(tree.account_count(), 1);
    assert_eq!(
        tree.get(&AccountId::from_bytes([1u8; 32])).unwrap().balance,
        100
    );
    assert!(!tree.contains(&AccountId::from_bytes([2u8; 32])));
}

#[test]
fn snapshot_preserves_count() {
    let mut tree = StateTree::new();
    tree.insert(make_account(1, 100));
    tree.insert(make_account(2, 200));
    let snap = tree.snapshot();
    assert_eq!(snap.account_count(), 2);
}

#[test]
fn single_account_root_is_hash_of_account_bytes() {
    use sha2::{Digest, Sha256};

    let mut tree = StateTree::new();
    let account = make_account(1, 100);
    let expected = {
        let mut hasher = Sha256::new();
        hasher.update(account.to_hash_bytes());
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    };
    tree.insert(account);
    assert_eq!(tree.compute_root(), expected);
}

#[test]
fn iter_returns_sorted_accounts() {
    let mut tree = StateTree::new();
    tree.insert(make_account(3, 300));
    tree.insert(make_account(1, 100));
    tree.insert(make_account(2, 200));

    let ids: Vec<AccountId> = tree.iter().map(|(id, _)| *id).collect();
    assert!(ids.windows(2).all(|w| w[0] <= w[1]));
}

// ── EVM address index tests ──

#[test]
fn resolve_evm_after_insert() {
    let mut tree = StateTree::new();
    let id = AccountId::from_bytes([1u8; 32]);
    let evm_addr = derive_evm_address(&id);

    tree.insert(Account::new(id));
    assert_eq!(tree.resolve_evm(&evm_addr), Some(&id));
}

#[test]
fn resolve_evm_empty_tree() {
    let tree = StateTree::new();
    assert_eq!(tree.resolve_evm(&[0u8; 20]), None);
}

#[test]
fn resolve_evm_after_remove() {
    let mut tree = StateTree::new();
    let id = AccountId::from_bytes([1u8; 32]);
    let evm_addr = derive_evm_address(&id);

    tree.insert(Account::new(id));
    assert_eq!(tree.resolve_evm(&evm_addr), Some(&id));

    tree.remove(&id);
    assert_eq!(tree.resolve_evm(&evm_addr), None);
}

#[test]
fn resolve_evm_survives_snapshot_rollback() {
    let mut tree = StateTree::new();
    let id1 = AccountId::from_bytes([1u8; 32]);
    tree.insert(Account::new(id1));
    let snapshot = tree.snapshot();

    // Add a second account after snapshot
    let id2 = AccountId::from_bytes([2u8; 32]);
    tree.insert(Account::new(id2));
    assert!(tree.resolve_evm(&derive_evm_address(&id2)).is_some());

    // Rollback — id2 should disappear, id1 should remain
    tree.rollback(snapshot);
    assert_eq!(tree.resolve_evm(&derive_evm_address(&id1)), Some(&id1));
    assert_eq!(tree.resolve_evm(&derive_evm_address(&id2)), None);
}

#[test]
fn explicit_evm_alias_overrides_derived_index() {
    let mut tree = StateTree::new();
    let id = AccountId::from_bytes([3u8; 32]);
    let explicit = [0xAA; 20];

    tree.insert(Account::with_evm_address(id, explicit));

    assert_eq!(tree.resolve_evm(&explicit), Some(&id));
    assert_eq!(tree.resolve_evm(&derive_evm_address(&id)), None);
    assert_eq!(tree.evm_address(&id), Some(explicit));
}

#[test]
fn explicit_tron_alias_overrides_derived_index() {
    let mut tree = StateTree::new();
    let id = AccountId::from_bytes([4u8; 32]);
    let explicit = [0xBB; 20];

    tree.insert(Account::with_tron_address(id, explicit));

    assert_eq!(tree.resolve_tron(&explicit), Some(&id));
    assert_eq!(tree.resolve_tron(&derive_tron_address(&id)), None);
    assert_eq!(tree.tron_address(&id), Some(explicit));
}

#[test]
fn explicit_alias_replaces_previous_indexes() {
    let mut tree = StateTree::new();
    let id = AccountId::from_bytes([5u8; 32]);
    let original_evm = derive_evm_address(&id);
    let original_tron = derive_tron_address(&id);
    tree.insert(Account::new(id));
    assert_eq!(tree.resolve_evm(&original_evm), Some(&id));
    assert_eq!(tree.resolve_tron(&original_tron), Some(&id));

    let mut updated = tree.get(&id).cloned().unwrap();
    updated.evm_address = Some([0xCC; 20]);
    updated.tron_address = Some([0xDD; 20]);
    tree.insert(updated);

    assert_eq!(tree.resolve_evm(&original_evm), None);
    assert_eq!(tree.resolve_tron(&original_tron), None);
    assert_eq!(tree.resolve_evm(&[0xCC; 20]), Some(&id));
    assert_eq!(tree.resolve_tron(&[0xDD; 20]), Some(&id));
}
