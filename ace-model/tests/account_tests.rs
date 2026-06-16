use ace_model::account::{Account, AccountId};

#[test]
fn account_id_from_bytes_roundtrip() {
    let bytes = [42u8; 32];
    let id = AccountId::from_bytes(bytes);
    assert_eq!(*id.as_bytes(), bytes);
}

#[test]
fn account_id_zero() {
    assert_eq!(AccountId::ZERO, AccountId::from_bytes([0u8; 32]));
}

#[test]
fn account_id_equality() {
    let a = AccountId::from_bytes([1u8; 32]);
    let b = AccountId::from_bytes([1u8; 32]);
    let c = AccountId::from_bytes([2u8; 32]);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn account_id_display_hex() {
    let id = AccountId::from_bytes([0xAB; 32]);
    let display = format!("{id}");
    assert_eq!(display.len(), 64); // 32 bytes = 64 hex chars
    assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn account_new_has_zero_balance() {
    let id = AccountId::from_bytes([1u8; 32]);
    let account = Account::new(id);
    assert_eq!(account.balance, 0);
    assert_eq!(account.nonce, 0);
    assert!(account.code_hash.is_none());
    assert_eq!(account.storage_root, [0u8; 32]);
    assert_eq!(account.evm_address, None);
    assert_eq!(account.tron_address, None);
}

#[test]
fn account_with_balance() {
    let id = AccountId::from_bytes([1u8; 32]);
    let account = Account::with_balance(id, 1_000_000);
    assert_eq!(account.balance, 1_000_000);
    assert_eq!(account.nonce, 0);
}

#[test]
fn account_serialization_roundtrip() {
    let id = AccountId::from_bytes([7u8; 32]);
    let account = Account::with_balance(id, 42);
    let json = serde_json::to_string(&account).unwrap();
    let deserialized: Account = serde_json::from_str(&json).unwrap();
    assert_eq!(account, deserialized);
}

#[test]
fn account_hash_bytes_deterministic() {
    let id = AccountId::from_bytes([1u8; 32]);
    let account = Account::with_balance(id, 100);
    let bytes1 = account.to_hash_bytes();
    let bytes2 = account.to_hash_bytes();
    assert_eq!(bytes1, bytes2);
}

#[test]
fn account_hash_bytes_differs_with_balance() {
    let id = AccountId::from_bytes([1u8; 32]);
    let a = Account::with_balance(id, 100);
    let b = Account::with_balance(id, 200);
    assert_ne!(a.to_hash_bytes(), b.to_hash_bytes());
}

#[test]
fn account_id_from_array() {
    let bytes = [99u8; 32];
    let id: AccountId = bytes.into();
    assert_eq!(*id.as_bytes(), bytes);
}

#[test]
fn account_hash_bytes_differs_with_explicit_vm_alias() {
    let id = AccountId::from_bytes([5u8; 32]);
    let plain = Account::with_balance(id, 100);
    let aliased = Account::with_evm_address(id, [0xAA; 20]);
    assert_ne!(plain.to_hash_bytes(), aliased.to_hash_bytes());
}
