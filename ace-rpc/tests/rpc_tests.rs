use ace_rpc::types::{RpcAccount, RpcBlock, RpcFinalityStatus};

#[test]
fn rpc_account_serialization() {
    let account = RpcAccount {
        id_com: "ab".repeat(32),
        balance: 1000,
        nonce: 5,
        pending_nonce: 5,
        has_auth_pubkey: false,
        auth_algorithms: vec![],
        code_hash: None,
        storage_root: "00".repeat(32),
        xid: None,
        xaddress: None,
        evm_address: None,
        tron_address: None,
        solana_address: None,
        btc_address: None,
    };

    let json = serde_json::to_string(&account).unwrap();
    let decoded: RpcAccount = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.balance, 1000);
    assert_eq!(decoded.nonce, 5);
    assert!(decoded.code_hash.is_none());
}

#[test]
fn rpc_block_serialization() {
    let block = RpcBlock {
        slot: 42,
        parent_hash: "00".repeat(32),
        state_root: "11".repeat(32),
        tx_merkle_root: "22".repeat(32),
        attest_merkle_root: "33".repeat(32),
        poh_hash: "44".repeat(32),
        leader_idcom: "55".repeat(32),
        timestamp: 1700000000,
        tx_count: 10,
        hash: "ff".repeat(32),
    };

    let json = serde_json::to_string(&block).unwrap();
    let decoded: RpcBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.slot, 42);
    assert_eq!(decoded.tx_count, 10);
}

#[test]
fn rpc_finality_status_serialization() {
    let status = RpcFinalityStatus {
        slot: 10,
        state: "soft".to_string(),
    };

    let json = serde_json::to_string(&status).unwrap();
    let decoded: RpcFinalityStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.slot, 10);
    assert_eq!(decoded.state, "soft");
}
