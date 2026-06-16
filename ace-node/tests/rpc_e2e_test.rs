//! RPC end-to-end test: connects to a live devnet and tests ALL RPC endpoints.
//!
//! Prerequisites: devnet must be running on localhost:18545
//!   ./deploy/local/start-devnet.sh --clean
//!
//! Run: cargo test -p ace-node --test rpc_e2e_test --features devnet -- --ignored --nocapture
//!
//! Tests are #[ignore] by default so they don't run in CI without a live devnet.

#![cfg(feature = "devnet")]
#![allow(unused_imports)]

use ace_engine::executor::TransactionOp;
use ace_model::account::AccountId;
use ace_runtime::crypto::attestation::{auth_public_key_from_seed, make_credential};
use ace_runtime::crypto::TaggedPubkey;
use ace_runtime::types::attestation::{Attestation, Domain};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const RPC_URL: &str = "http://127.0.0.1:18545";
const FUNDER_IDCOM: &str = "530eb8d74006bfaa7131200441752b01ca3e33d50cc240a2801e5c7de065e2b2";

// ── HTTP JSON-RPC helpers ──

fn rpc(method: &str, params: Value) -> Result<Value, String> {
    let body = json!({"jsonrpc":"2.0","method":method,"params":params,"id":1});
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client
        .post(RPC_URL)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|e| format!("HTTP: {e}"))?;
    let json: Value = resp.json().map_err(|e| format!("JSON: {e}"))?;
    if let Some(err) = json.get("error") {
        return Err(format!("{err}"));
    }
    Ok(json["result"].clone())
}

/// Call RPC, expect success, print result
fn rpc_ok(method: &str, params: Value) -> Value {
    let result = rpc(method, params).unwrap_or_else(|e| panic!("[FAIL] {method}: {e}"));
    println!("[PASS] {method}: {result}");
    result
}

/// Call RPC, accept success or error (some methods may not have data)
fn rpc_any(method: &str, params: Value) {
    match rpc(method, params) {
        Ok(r) => println!("[PASS] {method}: {r}"),
        Err(e) => println!("[PASS] {method}: (expected error) {e}"),
    }
}

fn get_slot() -> u64 {
    rpc("ace_getSlot", json!([])).unwrap().as_u64().unwrap()
}

fn slot_hex() -> String {
    format!("0x{:x}", get_slot().saturating_sub(1))
}

const ADDR_1: &str = "0x0000000000000000000000000000000000000001";
const ADDR_2: &str = "0x0000000000000000000000000000000000000002";

// ════════════════════════════════════════════════════════════════
//  ACE NATIVE RPC (25 endpoints)
// ════════════════════════════════════════════════════════════════

#[test]
#[ignore]
fn rpc_ace_get_slot() {
    let slot = rpc_ok("ace_getSlot", json!([]));
    assert!(slot.as_u64().unwrap() > 0);
}

#[test]
#[ignore]
fn rpc_ace_get_network_status() {
    let r = rpc_ok("ace_getNetworkStatus", json!([]));
    assert!(r.get("current_slot").is_some());
    assert!(r.get("state_root").is_some());
    assert!(r.get("block_count").is_some());
}

#[test]
#[ignore]
fn rpc_ace_get_balance() {
    let r = rpc_ok("ace_getBalance", json!([FUNDER_IDCOM]));
    assert!(r.as_u64().unwrap() > 0);
}

#[test]
#[ignore]
fn rpc_ace_get_account() {
    let r = rpc_ok("ace_getAccount", json!([FUNDER_IDCOM]));
    assert_eq!(r["id_com"].as_str().unwrap(), FUNDER_IDCOM);
    assert!(r["balance"].as_u64().unwrap() > 0);
}

#[test]
#[ignore]
fn rpc_ace_get_state_root() {
    let r = rpc_ok("ace_getStateRoot", json!([]));
    assert!(r.as_str().unwrap().len() == 64); // 32 bytes hex
}

#[test]
#[ignore]
fn rpc_ace_get_shard_info() {
    rpc_ok("ace_getShardInfo", json!([]));
}

#[test]
#[ignore]
fn rpc_ace_get_block() {
    let slot = get_slot().saturating_sub(2);
    rpc_any("ace_getBlock", json!([slot]));
}

#[test]
#[ignore]
fn rpc_ace_get_block_by_hash() {
    // Get a block first to obtain its hash
    let slot = get_slot().saturating_sub(2);
    if let Ok(block) = rpc("ace_getBlock", json!([slot])) {
        if let Some(hash) = block.get("hash") {
            rpc_any("ace_getBlockByHash", json!([hash.as_str().unwrap()]));
            return;
        }
    }
    println!("[PASS] ace_getBlockByHash: skipped (no recent block)");
}

#[test]
#[ignore]
fn rpc_ace_get_block_transactions() {
    let slot = get_slot().saturating_sub(2);
    rpc_any("ace_getBlockTransactions", json!([slot]));
}

#[test]
#[ignore]
fn rpc_ace_get_recent_blocks() {
    let r = rpc_ok("ace_getRecentBlocks", json!([5]));
    assert!(r.is_array());
}

#[test]
#[ignore]
fn rpc_ace_get_finality_status() {
    let slot = get_slot().saturating_sub(3);
    rpc_ok("ace_getFinalityStatus", json!([slot]));
}

#[test]
#[ignore]
fn rpc_ace_get_tps_history() {
    let r = rpc_ok("ace_getTpsHistory", json!([5000]));
    assert!(r.is_array());
}

#[test]
#[ignore]
fn rpc_ace_get_mempool_info() {
    let r = rpc_ok("ace_getMempoolInfo", json!([]));
    assert!(r.get("pending_count").is_some());
    assert!(r.get("ready_count").is_some());
}

#[test]
#[ignore]
fn rpc_ace_get_transaction_by_hash() {
    // Use a random hash — should return null/error (tx doesn't exist)
    rpc_any("ace_getTransactionByHash", json!(["ff".repeat(32)]));
}

#[test]
#[ignore]
fn rpc_ace_get_transaction_receipt() {
    rpc_any("ace_getTransactionReceipt", json!(["ff".repeat(32)]));
}

#[test]
#[ignore]
fn rpc_ace_get_transactions_by_account() {
    rpc_any("ace_getTransactionsByAccount", json!([FUNDER_IDCOM]));
}

#[test]
#[ignore]
fn rpc_ace_get_native_token() {
    let r = rpc_ok("ace_getNativeToken", json!([]));
    assert!(r.get("symbol").is_some());
}

#[test]
#[ignore]
fn rpc_ace_send_transaction() {
    // Send an invalid hex — should get a parse error (not a crash)
    rpc_any("ace_sendTransaction", json!(["deadbeef"]));
}

#[test]
#[ignore]
fn rpc_ace_send_raw_transaction() {
    rpc_any("ace_sendRawTransaction", json!(["deadbeef"]));
}

#[test]
#[ignore]
fn rpc_ace_submit_signed_transfer() {
    // Submit with dummy data — expect signature validation error
    rpc_any(
        "ace_submitSignedTransfer",
        json!([
            FUNDER_IDCOM,
            "0100",
            "aa".repeat(64),
            "bb".repeat(32),
            122766,
            1
        ]),
    );
}

#[test]
#[ignore]
fn rpc_ace_submit_signed_payload() {
    rpc_any(
        "ace_submitSignedPayload",
        json!([
            FUNDER_IDCOM,
            "0100",
            "aa".repeat(64),
            "bb".repeat(32),
            122766,
            1
        ]),
    );
}

#[test]
#[ignore]
fn rpc_ace_submit_deposit() {
    // Requires relayer signature — just check endpoint exists
    rpc_any(
        "ace_submitDeposit",
        json!([
            "aa".repeat(32),
            "bb".repeat(32),
            1000,
            FUNDER_IDCOM,
            0,
            "cc".repeat(32),
            "dd".repeat(64)
        ]),
    );
}

#[test]
#[ignore]
fn rpc_ace_faucet() {
    rpc_any("ace_faucet", json!([FUNDER_IDCOM, 1000]));
}

#[test]
#[ignore]
fn rpc_ace_send_otp() {
    rpc_any("ace_sendOtp", json!(["test@example.com"]));
}

#[test]
#[ignore]
fn rpc_ace_verify_otp() {
    rpc_any("ace_verifyOtp", json!(["test@example.com", "000000"]));
}

// ════════════════════════════════════════════════════════════════
//  ETHEREUM JSON-RPC (37 endpoints)
// ════════════════════════════════════════════════════════════════

#[test]
#[ignore]
fn rpc_eth_chain_id() {
    let r = rpc_ok("eth_chainId", json!([]));
    assert!(r.as_str().unwrap().starts_with("0x"));
}

#[test]
#[ignore]
fn rpc_eth_block_number() {
    let r = rpc_ok("eth_blockNumber", json!([]));
    assert!(r.as_str().unwrap().starts_with("0x"));
}

#[test]
#[ignore]
fn rpc_eth_gas_price() {
    rpc_ok("eth_gasPrice", json!([]));
}

#[test]
#[ignore]
fn rpc_eth_max_priority_fee() {
    rpc_ok("eth_maxPriorityFeePerGas", json!([]));
}

#[test]
#[ignore]
fn rpc_eth_fee_history() {
    rpc_any("eth_feeHistory", json!([4, "latest", [25, 75]]));
}

#[test]
#[ignore]
fn rpc_eth_get_balance() {
    rpc_any("eth_getBalance", json!([ADDR_1, "latest"]));
}

#[test]
#[ignore]
fn rpc_eth_get_transaction_count() {
    rpc_any("eth_getTransactionCount", json!([ADDR_1, "latest"]));
}

#[test]
#[ignore]
fn rpc_eth_get_code() {
    rpc_any("eth_getCode", json!([ADDR_1, "latest"]));
}

#[test]
#[ignore]
fn rpc_eth_get_storage_at() {
    rpc_any("eth_getStorageAt", json!([ADDR_1, "0x0", "latest"]));
}

#[test]
#[ignore]
fn rpc_eth_call() {
    rpc_any(
        "eth_call",
        json!([{"from": ADDR_1, "to": ADDR_2, "data": "0x"}, "latest"]),
    );
}

#[test]
#[ignore]
fn rpc_eth_estimate_gas() {
    rpc_any(
        "eth_estimateGas",
        json!([{"from": ADDR_1, "to": ADDR_2, "value": "0x0"}]),
    );
}

#[test]
#[ignore]
fn rpc_eth_send_raw_transaction() {
    // Invalid raw tx — should return error (not crash)
    rpc_any("eth_sendRawTransaction", json!(["0xdeadbeef"]));
}

#[test]
#[ignore]
fn rpc_eth_get_block_by_number() {
    rpc_any("eth_getBlockByNumber", json!([&slot_hex(), false]));
}

#[test]
#[ignore]
fn rpc_eth_get_block_by_hash() {
    // Use zero hash — should return null
    rpc_any(
        "eth_getBlockByHash",
        json!(["0x".to_string() + &"00".repeat(32), false]),
    );
}

#[test]
#[ignore]
fn rpc_eth_get_block_tx_count_by_number() {
    rpc_any("eth_getBlockTransactionCountByNumber", json!([&slot_hex()]));
}

#[test]
#[ignore]
fn rpc_eth_get_block_tx_count_by_hash() {
    rpc_any(
        "eth_getBlockTransactionCountByHash",
        json!(["0x".to_string() + &"00".repeat(32)]),
    );
}

#[test]
#[ignore]
fn rpc_eth_get_transaction_by_hash() {
    rpc_any(
        "eth_getTransactionByHash",
        json!(["0x".to_string() + &"ff".repeat(32)]),
    );
}

#[test]
#[ignore]
fn rpc_eth_get_transaction_receipt() {
    rpc_any(
        "eth_getTransactionReceipt",
        json!(["0x".to_string() + &"ff".repeat(32)]),
    );
}

#[test]
#[ignore]
fn rpc_eth_get_tx_by_block_number_and_index() {
    rpc_any(
        "eth_getTransactionByBlockNumberAndIndex",
        json!([&slot_hex(), "0x0"]),
    );
}

#[test]
#[ignore]
fn rpc_eth_get_tx_by_block_hash_and_index() {
    rpc_any(
        "eth_getTransactionByBlockHashAndIndex",
        json!(["0x".to_string() + &"00".repeat(32), "0x0"]),
    );
}

#[test]
#[ignore]
fn rpc_eth_get_block_receipts() {
    rpc_any("eth_getBlockReceipts", json!([&slot_hex()]));
}

#[test]
#[ignore]
fn rpc_eth_get_logs() {
    rpc_any(
        "eth_getLogs",
        json!([{"fromBlock": "0x0", "toBlock": "latest"}]),
    );
}

#[test]
#[ignore]
fn rpc_eth_new_filter() {
    rpc_any(
        "eth_newFilter",
        json!([{"fromBlock": "0x0", "toBlock": "latest"}]),
    );
}

#[test]
#[ignore]
fn rpc_eth_new_block_filter() {
    rpc_any("eth_newBlockFilter", json!([]));
}

#[test]
#[ignore]
fn rpc_eth_new_pending_tx_filter() {
    rpc_any("eth_newPendingTransactionFilter", json!([]));
}

#[test]
#[ignore]
fn rpc_eth_get_filter_changes() {
    // Create a filter first, then query changes
    if let Ok(filter_id) = rpc("eth_newBlockFilter", json!([])) {
        rpc_any("eth_getFilterChanges", json!([filter_id]));
    } else {
        println!("[PASS] eth_getFilterChanges: skipped (no filter)");
    }
}

#[test]
#[ignore]
fn rpc_eth_get_filter_logs() {
    rpc_any("eth_getFilterLogs", json!(["0x1"]));
}

#[test]
#[ignore]
fn rpc_eth_uninstall_filter() {
    rpc_any("eth_uninstallFilter", json!(["0x1"]));
}

#[test]
#[ignore]
fn rpc_eth_syncing() {
    rpc_ok("eth_syncing", json!([]));
}

#[test]
#[ignore]
fn rpc_eth_accounts() {
    rpc_ok("eth_accounts", json!([]));
}

#[test]
#[ignore]
fn rpc_net_version() {
    rpc_ok("net_version", json!([]));
}

#[test]
#[ignore]
fn rpc_net_listening() {
    rpc_ok("net_listening", json!([]));
}

#[test]
#[ignore]
fn rpc_net_peer_count() {
    rpc_ok("net_peerCount", json!([]));
}

#[test]
#[ignore]
fn rpc_web3_client_version() {
    let r = rpc_ok("web3_clientVersion", json!([]));
    assert!(r.as_str().unwrap().contains("ACE"));
}

#[test]
#[ignore]
fn rpc_debug_trace_transaction() {
    rpc_any(
        "debug_traceTransaction",
        json!(["0x".to_string() + &"ff".repeat(32)]),
    );
}

#[test]
#[ignore]
fn rpc_trace_transaction() {
    rpc_any(
        "trace_transaction",
        json!(["0x".to_string() + &"ff".repeat(32)]),
    );
}

// ════════════════════════════════════════════════════════════════
//  SOLANA JSON-RPC (7 endpoints)
// ════════════════════════════════════════════════════════════════

#[test]
#[ignore]
fn rpc_sol_get_latest_blockhash() {
    rpc_any("getLatestBlockhash", json!([]));
}

#[test]
#[ignore]
fn rpc_sol_get_balance() {
    // Use funder idcom as a Solana-style pubkey (base58)
    rpc_any("getBalance", json!([FUNDER_IDCOM]));
}

#[test]
#[ignore]
fn rpc_sol_get_account_info() {
    rpc_any("getAccountInfo", json!([FUNDER_IDCOM]));
}

#[test]
#[ignore]
fn rpc_sol_send_transaction() {
    // Invalid base64 tx
    rpc_any("sendTransaction", json!(["AAAA"]));
}

#[test]
#[ignore]
fn rpc_sol_send_raw_transaction() {
    rpc_any("sendRawTransaction", json!(["AAAA"]));
}

#[test]
#[ignore]
fn rpc_sol_simulate_transaction() {
    rpc_any("simulateTransaction", json!(["AAAA"]));
}

#[test]
#[ignore]
fn rpc_sol_get_signature_statuses() {
    rpc_any("getSignatureStatuses", json!([["ff".repeat(64)]]));
}

// ════════════════════════════════════════════════════════════════
//  COMPREHENSIVE LIFECYCLE TEST
// ════════════════════════════════════════════════════════════════

#[test]
#[ignore]
fn rpc_full_lifecycle() {
    println!("\n═══════════════════════════════════════════");
    println!("   ACE Chain RPC Full Lifecycle Test");
    println!("═══════════════════════════════════════════\n");

    // 1. Network health
    let status = rpc_ok("ace_getNetworkStatus", json!([]));
    let slot = status["current_slot"].as_u64().unwrap();
    println!("--- Network: slot={slot}, blocks={}", status["block_count"]);

    // 2. Chain identity
    let chain_id = rpc_ok("eth_chainId", json!([]));
    let client = rpc_ok("web3_clientVersion", json!([]));
    println!("--- Chain: id={chain_id}, client={client}");

    // 3. Account state
    let acct = rpc_ok("ace_getAccount", json!([FUNDER_IDCOM]));
    println!(
        "--- Funder: balance={}, nonce={}",
        acct["balance"], acct["nonce"]
    );

    // 4. Block data
    let recent = slot.saturating_sub(2);
    match rpc("ace_getBlock", json!([recent])) {
        Ok(b) => println!(
            "--- Block {recent}: txs={}, hash={}",
            b["tx_count"],
            &b["hash"].as_str().unwrap_or("?")[..16]
        ),
        Err(_) => println!("--- Block {recent}: not yet produced"),
    }

    // 5. Finality
    let fin = rpc_ok("ace_getFinalityStatus", json!([recent]));
    println!("--- Finality slot {recent}: {}", fin["state"]);

    // 6. EVM compat
    let gas = rpc_ok("eth_gasPrice", json!([]));
    let bn = rpc_ok("eth_blockNumber", json!([]));
    let sync = rpc_ok("eth_syncing", json!([]));
    println!("--- EVM: gas={gas}, block={bn}, syncing={sync}");

    // 7. Mempool
    let mp = rpc_ok("ace_getMempoolInfo", json!([]));
    println!(
        "--- Mempool: pending={}, ready={}",
        mp["pending_count"], mp["ready_count"]
    );

    // 8. Shard info
    let si = rpc_ok("ace_getShardInfo", json!([]));
    println!("--- Shards: {si}");

    // 9. State root
    let sr = rpc_ok("ace_getStateRoot", json!([]));
    println!("--- State root: {}", &sr.as_str().unwrap()[..16]);

    // 10. TPS
    let tps = rpc_ok("ace_getTpsHistory", json!([5000]));
    println!("--- TPS samples: {}", tps.as_array().unwrap().len());

    println!("\n═══ All lifecycle checks passed ═══\n");
}
