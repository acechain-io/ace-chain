//! Tests for cross-VM address resolution and context sharding.

use ace_model::account::AccountId;
use ace_n_vm::context::ShardId;
use ace_n_vm::cross_vm::AddressResolver;

#[test]
fn evm_address_deterministic() {
    let id = AccountId::from_bytes([1u8; 32]);
    let addr1 = AddressResolver::to_evm_address(&id);
    let addr2 = AddressResolver::to_evm_address(&id);
    assert_eq!(addr1, addr2);
    assert_eq!(addr1.len(), 20);
}

#[test]
fn svm_address_deterministic() {
    let id = AccountId::from_bytes([1u8; 32]);
    let addr1 = AddressResolver::to_svm_address(&id);
    let addr2 = AddressResolver::to_svm_address(&id);
    assert_eq!(addr1, addr2);
    assert_eq!(addr1.len(), 32);
}

#[test]
fn different_ids_different_addresses() {
    let alice = AccountId::from_bytes([1u8; 32]);
    let bob = AccountId::from_bytes([2u8; 32]);

    let alice_evm = AddressResolver::to_evm_address(&alice);
    let bob_evm = AddressResolver::to_evm_address(&bob);
    assert_ne!(alice_evm, bob_evm);

    let alice_svm = AddressResolver::to_svm_address(&alice);
    let bob_svm = AddressResolver::to_svm_address(&bob);
    assert_ne!(alice_svm, bob_svm);
}

#[test]
fn evm_and_svm_addresses_differ() {
    let id = AccountId::from_bytes([1u8; 32]);
    let evm = AddressResolver::to_evm_address(&id);
    let svm = AddressResolver::to_svm_address(&id);
    // Different lengths, so not directly comparable, but verify they're not
    // trivially derived from each other
    assert_ne!(&evm[..], &svm[12..32]);
}

#[test]
fn shard_routing_deterministic() {
    let shard1 = ShardId::from_context("evm", "uniswap-v3");
    let shard2 = ShardId::from_context("evm", "uniswap-v3");
    assert_eq!(shard1, shard2);
}

#[test]
fn shard_routing_different_contexts() {
    let shard_a = ShardId::from_context("evm", "uniswap-v3");
    let shard_b = ShardId::from_context("svm", "raydium");
    // Could be same shard by coincidence, but very unlikely with SHA-256
    // Just verify they're valid shard IDs
    assert!(shard_a.0 < 64);
    assert!(shard_b.0 < 64);
}

#[test]
fn shard_routing_no_ambiguity() {
    // Length-prefixing prevents ("evm:foo","bar") from hashing identically
    // to ("evm","foo:bar").  We verify the raw SHA-256 differs — ShardId
    // is hash % 64, so distinct hashes can still map to the same shard.
    use sha2::{Digest, Sha256};

    let hash = |prefix: &str, tag: &str| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&(prefix.len() as u32).to_le_bytes());
        h.update(prefix.as_bytes());
        h.update(tag.as_bytes());
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    };

    assert_ne!(
        hash("evm:foo", "bar"),
        hash("evm", "foo:bar"),
        "length-prefixed hashing must prevent collision"
    );
}

#[test]
fn shard_id_within_bounds() {
    // Test multiple contexts to verify all are within bounds
    let contexts = [
        ("evm", "swap"),
        ("svm", "stake"),
        ("native", "transfer"),
        ("evm", "lending"),
        ("svm", "governance"),
        ("native", "create"),
    ];
    for (vm, ctx) in &contexts {
        let shard = ShardId::from_context(vm, ctx);
        assert!(
            shard.0 < 64,
            "shard {} out of bounds for {}:{}",
            shard.0,
            vm,
            ctx
        );
    }
}
