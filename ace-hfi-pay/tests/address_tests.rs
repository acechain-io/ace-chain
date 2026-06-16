use ace_hfi_pay::address::{
    derive_intent_address, derive_intent_evm_address, derive_intent_tvm_address,
};
use ace_hfi_pay::intent::ChainId;

#[test]
fn deterministic() {
    let id = [42u8; 32];
    assert_eq!(
        derive_intent_address(ChainId::Evm, &id),
        derive_intent_address(ChainId::Evm, &id),
    );
}

#[test]
fn different_intent_ids_produce_different_addresses() {
    let a = derive_intent_address(ChainId::Evm, &[1u8; 32]);
    let b = derive_intent_address(ChainId::Evm, &[2u8; 32]);
    assert_ne!(a, b);
}

#[test]
fn all_chains_produce_distinct_addresses() {
    let id = [7u8; 32];
    let chains = [
        ChainId::Native,
        ChainId::Evm,
        ChainId::Svm,
        ChainId::Bvm,
        ChainId::Tvm,
    ];
    let addrs: Vec<_> = chains
        .iter()
        .map(|c| derive_intent_address(*c, &id))
        .collect();
    for i in 0..addrs.len() {
        for j in (i + 1)..addrs.len() {
            assert_ne!(addrs[i], addrs[j]);
        }
    }
}

#[test]
fn evm_address_20_bytes() {
    let id = [0xBB; 32];
    let evm = derive_intent_evm_address(&id);
    assert_eq!(evm.len(), 20);

    let full = derive_intent_address(ChainId::Evm, &id);
    assert_eq!(&evm[..], &full.0[12..32]);
}

#[test]
fn tvm_address_20_bytes() {
    let id = [0xCC; 32];
    let tvm = derive_intent_tvm_address(&id);
    assert_eq!(tvm.len(), 20);

    let full = derive_intent_address(ChainId::Tvm, &id);
    assert_eq!(&tvm[..], &full.0[12..32]);
}

#[test]
fn evm_and_tvm_addresses_differ() {
    let id = [0xDD; 32];
    assert_ne!(
        derive_intent_evm_address(&id),
        derive_intent_tvm_address(&id)
    );
}
