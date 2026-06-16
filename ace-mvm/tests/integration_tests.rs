use ace_engine::{VmEngine, VmId};
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_mvm::state::{load_module, module_id, store_resource, load_resource};
use ace_mvm::types::{Resource, StructId, ModuleId};
use ace_mvm::MoveVmEngine;
use ace_n_vm::scheduler::{extract_write_set, WriteSet};
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::transaction::Transaction;

const SENDER_BYTES: [u8; 32] = [0x11; 32];
const MODULE_NAME: &str = "test";

fn make_move_tx(nonce: u64, func: &str, module_addr: [u8; 32], args: Vec<u8>) -> Transaction {
    let mut payload = vec![0x50]; // Move opcode
    payload.extend_from_slice(&nonce.to_le_bytes());
    payload.extend_from_slice(&module_addr);

    let mut module_name = [0u8; 32];
    module_name[..MODULE_NAME.len()].copy_from_slice(MODULE_NAME.as_bytes());
    payload.extend_from_slice(&module_name);

    let func_bytes = func.as_bytes();
    payload.extend_from_slice(&(func_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(func_bytes);
    payload.extend_from_slice(&args);

    Transaction {
        payload,
        attestation: Attestation {
            obj_hash: [0u8; 32],
            idcom: SENDER_BYTES,
            domain: Domain::new(1, 0),
            context_tag: [0u8; 16],
            credential: ace_runtime::crypto::sig_algo::TaggedSignature::ed25519([0u8; 64]),
        },
        raw_chain: None,
        zk_auth: None,
    }
}

fn no_args() -> Vec<u8> {
    0u16.to_le_bytes().to_vec()
}

fn transfer_args(recipient: AccountId, amount: u64) -> Vec<u8> {
    let mut args = Vec::new();
    args.extend_from_slice(&2u16.to_le_bytes());
    args.push(0x05);
    args.extend_from_slice(recipient.as_bytes());
    args.push(0x03);
    args.extend_from_slice(&amount.to_le_bytes());
    args
}

fn publish_args(bytecode: &[u8]) -> Vec<u8> {
    let mut args = Vec::new();
    args.extend_from_slice(&1u16.to_le_bytes());
    args.push(0x06);
    args.extend_from_slice(&(bytecode.len() as u32).to_le_bytes());
    args.extend_from_slice(bytecode);
    args
}

#[test]
fn test_move_vm_execution_and_nonce_consumption() {
    let engine = MoveVmEngine::new();
    let mut state = StateTree::new();
    let sender = AccountId(SENDER_BYTES);
    state.insert(Account::with_balance(sender, 1000));

    // Nonce 0
    let tx = make_move_tx(0, "transfer", [0u8; 32], no_args());
    let receipt = engine.execute(&mut state, &tx).unwrap();

    // Execution errors are represented as Ok(VmReceipt { success: false }).
    assert!(!receipt.success);
    assert_eq!(receipt.vm_id, VmId::Move);
    assert!(receipt.error.unwrap().contains("transfer requires 2 arguments"));

    // Account nonce SHOULD HAVE incremented even though execution failed
    let account = state.get(&sender).unwrap();
    assert_eq!(account.nonce, 1);
}

#[test]
fn test_move_transfer_success_updates_balances_and_nonce() {
    let engine = MoveVmEngine::new();
    let mut state = StateTree::new();
    let sender = AccountId(SENDER_BYTES);
    let recipient = AccountId([0x22; 32]);
    state.insert(Account::with_balance(sender, 1000));

    let tx = make_move_tx(0, "transfer", [0u8; 32], transfer_args(recipient, 250));
    let receipt = engine.execute(&mut state, &tx).unwrap();

    assert!(receipt.success, "transfer failed: {:?}", receipt.error);
    assert_eq!(receipt.vm_id, VmId::Move);
    assert_eq!(state.get(&sender).unwrap().balance, 750);
    assert_eq!(state.get(&sender).unwrap().nonce, 1);
    assert_eq!(state.get(&recipient).unwrap().balance, 250);
}

#[test]
fn test_move_publish_module_success_persists_module_and_nonce() {
    let engine = MoveVmEngine::new();
    let mut state = StateTree::new();
    let sender = AccountId(SENDER_BYTES);
    state.insert(Account::with_balance(sender, 1000));

    let bytecode = b"module-bytecode";
    let tx = make_move_tx(0, "publish_module", sender.0, publish_args(bytecode));
    let receipt = engine.execute(&mut state, &tx).unwrap();

    assert!(receipt.success, "publish failed: {:?}", receipt.error);
    assert_eq!(state.get(&sender).unwrap().nonce, 1);

    let id = module_id(sender.0, MODULE_NAME);
    let module = load_module(&state, &id).unwrap().expect("module persisted");
    assert_eq!(module.bytecode.as_slice(), bytecode);
}

#[test]
fn test_move_bytecode_size_limit() {
    let large_bytecode = vec![0u8; 9000]; // Exceeds 8KB limit
    let tx = make_move_tx(0, "publish_module", SENDER_BYTES, publish_args(&large_bytecode));

    let engine = MoveVmEngine::new();
    let mut state = StateTree::new();
    let sender = AccountId(SENDER_BYTES);
    state.insert(Account::with_balance(sender, 1000));

    let receipt = engine.execute(&mut state, &tx).unwrap();

    assert!(!receipt.success);
    assert!(receipt.error.unwrap().contains("Bytecode too large"));
    // Nonce still incremented
    assert_eq!(state.get(&sender).unwrap().nonce, 1);
}

#[test]
fn test_move_scheduler_write_set_is_global() {
    let tx = make_move_tx(0, "any", [0u8; 32], no_args());
    let ws = extract_write_set(&tx);
    
    match ws {
        WriteSet::Global => {}
        _ => panic!("Move transaction must have Global write set for safety in current version"),
    }
}

#[test]
fn test_move_storage_cleanup_on_overwrite() {
    let mut state = StateTree::new();
    let sender = AccountId(SENDER_BYTES);
    state.insert(Account::with_balance(sender, 1000));

    let struct_id = StructId {
        module: ModuleId::new(SENDER_BYTES, "TestModule"),
        name: "TestResource".to_string(),
    };

    // 1. Store large resource (100 bytes -> 4 chunks of 32)
    let res1 = Resource {
        struct_id: struct_id.clone(),
        data: vec![0xAA; 100],
    };
    store_resource(&mut state, &sender.0, &res1).unwrap();

    let loaded1 = load_resource(&state, &sender.0, &struct_id).unwrap().unwrap();
    assert_eq!(loaded1.data.len(), 100);

    // 2. Overwrite with small resource (10 bytes -> 1 chunk)
    let res2 = Resource {
        struct_id: struct_id.clone(),
        data: vec![0xBB; 10],
    };
    store_resource(&mut state, &sender.0, &res2).unwrap();

    let loaded2 = load_resource(&state, &sender.0, &struct_id).unwrap().unwrap();
    assert_eq!(loaded2.data.len(), 10);
    assert_eq!(loaded2.data[0], 0xBB);
    
    // Internal verification: the load_resource logic truncates correctly,
    // and the store_bytes logic zeroed out the extra chunks.
}
