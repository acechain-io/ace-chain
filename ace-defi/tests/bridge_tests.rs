use ace_defi::types::{
    bridge_authority_id, hash_deposit_record, wrapped_mint_id, DepositRecord, ExternalAsset,
    ExternalChain, SignedDepositRecord,
};
use ace_defi::BridgeState;
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::legacy_idcom_evm;

fn setup() -> (StateTree, BridgeState) {
    let mut state = StateTree::new();
    let mut bridge = BridgeState::new();
    bridge.initialize(&mut state).unwrap();
    (state, bridge)
}

fn eth_asset() -> ExternalAsset {
    ExternalAsset::Native(ExternalChain::Ethereum)
}

fn sol_asset() -> ExternalAsset {
    ExternalAsset::Native(ExternalChain::Solana)
}

fn evm_recipient(seed: u8) -> (AccountId, [u8; 20]) {
    let mut addr = [0u8; 20];
    addr[0] = seed;
    let id = AccountId::from_bytes(legacy_idcom_evm(&addr));
    (id, addr)
}

fn intent_id(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn approve_relayer(bridge: &mut BridgeState, governance_seed: [u8; 32], relayer_pubkey: [u8; 32]) {
    use ed25519_dalek::Signer;
    let governance_key = ed25519_dalek::SigningKey::from_bytes(&governance_seed);
    let mut msg = Vec::with_capacity(21 + 32);
    msg.extend_from_slice(b"bridge:add-relayer:v1");
    msg.extend_from_slice(&relayer_pubkey);
    let signature = governance_key.sign(&msg).to_bytes();
    bridge.add_relayer(relayer_pubkey, &signature).unwrap();
}

// ── Initialization ──

#[test]
fn initialize_registers_all_native_assets() {
    let (state, bridge) = setup();
    assert!(bridge
        .registry
        .is_registered(&ExternalAsset::Native(ExternalChain::Ethereum), &state));
    assert!(bridge
        .registry
        .is_registered(&ExternalAsset::Native(ExternalChain::Solana), &state));
    assert!(bridge
        .registry
        .is_registered(&ExternalAsset::Native(ExternalChain::Bitcoin), &state));
    assert!(bridge
        .registry
        .is_registered(&ExternalAsset::Native(ExternalChain::Tron), &state));
    assert!(bridge
        .registry
        .is_registered(&ExternalAsset::Native(ExternalChain::Bsc), &state));
    assert_eq!(bridge.registry.registered_count(), 5);
}

#[test]
fn initialize_is_idempotent_across_restart() {
    let mut state = StateTree::new();
    let mut first = BridgeState::new();
    first.initialize(&mut state).unwrap();

    let mut restarted = BridgeState::new();
    restarted.initialize(&mut state).unwrap();

    assert!(restarted
        .registry
        .is_registered(&ExternalAsset::Native(ExternalChain::Ethereum), &state));
    assert!(restarted
        .registry
        .is_registered(&ExternalAsset::Native(ExternalChain::Solana), &state));
    assert!(restarted
        .registry
        .is_registered(&ExternalAsset::Native(ExternalChain::Bitcoin), &state));
    assert!(restarted
        .registry
        .is_registered(&ExternalAsset::Native(ExternalChain::Tron), &state));
    assert!(restarted
        .registry
        .is_registered(&ExternalAsset::Native(ExternalChain::Bsc), &state));
    assert_eq!(restarted.registry.registered_count(), 5);
}

// ── Deposit (auto-wrap) ──

#[test]
fn deposit_auto_wraps_to_recipient() {
    let (mut state, mut bridge) = setup();
    let (recipient_id, _) = evm_recipient(0xAA);

    let deposit = DepositRecord {
        deposit_id: [1u8; 32],
        intent_id: intent_id(1),
        asset: eth_asset(),
        amount: 1_000_000,
        recipient: recipient_id,
        processed_at: 10,
    };

    bridge.process_deposit(&mut state, &deposit).unwrap();

    // Recipient should have wrapped ETH balance
    let mint = wrapped_mint_id(&eth_asset());
    let balance = ace_n_vm::token_runtime::balance_of(&state, mint.as_bytes(), &recipient_id);
    assert_eq!(balance, 1_000_000);
}

#[test]
fn deposit_idempotent_rejects_duplicate() {
    let (mut state, mut bridge) = setup();
    let (recipient_id, _) = evm_recipient(0xBB);

    let deposit = DepositRecord {
        deposit_id: [2u8; 32],
        intent_id: intent_id(2),
        asset: eth_asset(),
        amount: 500,
        recipient: recipient_id,
        processed_at: 10,
    };

    bridge.process_deposit(&mut state, &deposit).unwrap();
    let result = bridge.process_deposit(&mut state, &deposit);
    assert!(result.is_err());
}

#[test]
fn deposit_unregistered_asset_fails() {
    let (mut state, mut bridge) = setup();
    let (recipient_id, _) = evm_recipient(0xCC);

    let custom_erc20 = ExternalAsset::Erc20([0xFF; 20]);
    let deposit = DepositRecord {
        deposit_id: [3u8; 32],
        intent_id: intent_id(3),
        asset: custom_erc20,
        amount: 1000,
        recipient: recipient_id,
        processed_at: 10,
    };

    let result = bridge.process_deposit(&mut state, &deposit);
    assert!(result.is_err());
}

#[test]
fn deposit_zero_amount_fails() {
    let (mut state, mut bridge) = setup();
    let (recipient_id, _) = evm_recipient(0xDD);

    let deposit = DepositRecord {
        deposit_id: [4u8; 32],
        intent_id: intent_id(4),
        asset: eth_asset(),
        amount: 0,
        recipient: recipient_id,
        processed_at: 10,
    };

    let result = bridge.process_deposit(&mut state, &deposit);
    assert!(result.is_err());
}

#[test]
fn deposit_overflow_amount_fails() {
    let (mut state, mut bridge) = setup();
    let (recipient_id, _) = evm_recipient(0xEE);

    let deposit = DepositRecord {
        deposit_id: [5u8; 32],
        intent_id: intent_id(5),
        asset: eth_asset(),
        amount: u64::MAX / 2 + 1,
        recipient: recipient_id,
        processed_at: 10,
    };

    let result = bridge.process_deposit(&mut state, &deposit);
    assert!(result.is_err());
}

// ── Withdrawal (unwrap) ──

#[test]
fn withdraw_burns_and_creates_record() {
    let (mut state, mut bridge) = setup();
    let (recipient_id, evm_addr) = evm_recipient(0xEE);

    // First deposit
    let deposit = DepositRecord {
        deposit_id: [5u8; 32],
        intent_id: intent_id(6),
        asset: eth_asset(),
        amount: 10_000,
        recipient: recipient_id,
        processed_at: 10,
    };
    bridge.process_deposit(&mut state, &deposit).unwrap();

    // Withdraw half
    let record = bridge
        .request_withdrawal(
            &mut state,
            &recipient_id,
            intent_id(60),
            &eth_asset(),
            5_000,
            evm_addr.to_vec(),
            20,
        )
        .unwrap();

    assert_eq!(record.amount, 5_000);
    assert!(!record.completed);

    // Check balance decreased
    let mint = wrapped_mint_id(&eth_asset());
    let balance = ace_n_vm::token_runtime::balance_of(&state, mint.as_bytes(), &recipient_id);
    assert_eq!(balance, 5_000); // 10000 - 5000

    // Check withdrawal record exists
    assert_eq!(bridge.pending_withdrawals().len(), 1);
}

#[test]
fn withdraw_insufficient_balance_fails() {
    let (mut state, mut bridge) = setup();
    let (recipient_id, evm_addr) = evm_recipient(0xFF);

    let deposit = DepositRecord {
        deposit_id: [6u8; 32],
        intent_id: intent_id(7),
        asset: eth_asset(),
        amount: 1_000,
        recipient: recipient_id,
        processed_at: 10,
    };
    bridge.process_deposit(&mut state, &deposit).unwrap();

    let result = bridge.request_withdrawal(
        &mut state,
        &recipient_id,
        intent_id(70),
        &eth_asset(),
        2_000, // more than deposited
        evm_addr.to_vec(),
        20,
    );
    assert!(result.is_err());
}

#[test]
fn complete_withdrawal() {
    let (mut state, mut bridge) = setup();
    let (recipient_id, _) = evm_recipient(0x11);

    let deposit = DepositRecord {
        deposit_id: [7u8; 32],
        intent_id: intent_id(8),
        asset: sol_asset(),
        amount: 50_000,
        recipient: recipient_id,
        processed_at: 10,
    };
    bridge.process_deposit(&mut state, &deposit).unwrap();

    let record = bridge
        .request_withdrawal(
            &mut state,
            &recipient_id,
            intent_id(80),
            &sol_asset(),
            50_000,
            vec![0x11; 32],
            20,
        )
        .unwrap();

    let authority = bridge_authority_id();
    bridge
        .complete_withdrawal(&mut state, &authority, record.withdrawal_id)
        .unwrap();

    let completed = bridge.get_withdrawal(record.withdrawal_id).unwrap();
    assert!(completed.completed);
    assert!(bridge.pending_withdrawals().is_empty());
}

#[test]
fn complete_withdrawal_twice_fails() {
    let (mut state, mut bridge) = setup();
    let (recipient_id, _) = evm_recipient(0x22);

    let deposit = DepositRecord {
        deposit_id: [8u8; 32],
        intent_id: intent_id(9),
        asset: eth_asset(),
        amount: 1_000,
        recipient: recipient_id,
        processed_at: 10,
    };
    bridge.process_deposit(&mut state, &deposit).unwrap();

    let record = bridge
        .request_withdrawal(
            &mut state,
            &recipient_id,
            intent_id(90),
            &eth_asset(),
            1_000,
            vec![0xAA; 20],
            20,
        )
        .unwrap();

    let authority = bridge_authority_id();
    bridge
        .complete_withdrawal(&mut state, &authority, record.withdrawal_id)
        .unwrap();
    let result = bridge.complete_withdrawal(&mut state, &authority, record.withdrawal_id);
    assert!(result.is_err());
}

// ── Full round-trip: deposit → cross-VM use → withdraw ──

#[test]
fn full_round_trip_deposit_transfer_withdraw() {
    let (mut state, mut bridge) = setup();
    let (alice_id, alice_evm) = evm_recipient(0xA0);
    let bob_id = AccountId::from_bytes([0xB0; 32]);
    state.insert(Account::new(bob_id));

    let eth_mint = wrapped_mint_id(&eth_asset());

    // Alice deposits 10,000 wETH via EVM bridge
    let deposit = DepositRecord {
        deposit_id: [9u8; 32],
        intent_id: intent_id(10),
        asset: eth_asset(),
        amount: 10_000,
        recipient: alice_id,
        processed_at: 10,
    };
    bridge.process_deposit(&mut state, &deposit).unwrap();
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &alice_id),
        10_000
    );

    // Alice transfers 3,000 wETH to Bob (cross-VM: same token ledger)
    ace_n_vm::token_runtime::transfer_between_owners(
        &mut state,
        eth_mint.as_bytes(),
        &alice_id,
        &bob_id,
        3_000,
    )
    .unwrap();

    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &alice_id),
        7_000
    );
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &bob_id),
        3_000
    );

    // Alice withdraws remaining 7,000 back to Ethereum
    let record = bridge
        .request_withdrawal(
            &mut state,
            &alice_id,
            intent_id(100),
            &eth_asset(),
            7_000,
            alice_evm.to_vec(),
            30,
        )
        .unwrap();
    assert_eq!(record.amount, 7_000);
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &alice_id),
        0
    );

    // Bob still has his 3,000
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &bob_id),
        3_000
    );
}

// ── Custom ERC-20 registration ──

#[test]
fn register_and_use_custom_erc20() {
    let (mut state, mut bridge) = setup();
    let usdc = ExternalAsset::Erc20([0xA0; 20]); // fake USDC address

    bridge.register_asset(&mut state, &usdc, 6).unwrap();
    assert!(bridge.registry.is_registered(&usdc, &state));

    let (recipient_id, _) = evm_recipient(0x33);
    let deposit = DepositRecord {
        deposit_id: [10u8; 32],
        intent_id: intent_id(11),
        asset: usdc.clone(),
        amount: 1_000_000, // 1 USDC (6 decimals)
        recipient: recipient_id,
        processed_at: 10,
    };
    bridge.process_deposit(&mut state, &deposit).unwrap();

    let usdc_mint = wrapped_mint_id(&usdc);
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, usdc_mint.as_bytes(), &recipient_id),
        1_000_000
    );
}

// ── Multi-chain deposits to same recipient ──

#[test]
fn multi_chain_deposits_to_same_recipient() {
    let (mut state, mut bridge) = setup();
    let (recipient_id, _) = evm_recipient(0x44);

    // Deposit ETH
    bridge
        .process_deposit(
            &mut state,
            &DepositRecord {
                deposit_id: [11u8; 32],
                intent_id: intent_id(12),
                asset: eth_asset(),
                amount: 5_000,
                recipient: recipient_id,
                processed_at: 10,
            },
        )
        .unwrap();

    // Deposit SOL (same recipient!)
    bridge
        .process_deposit(
            &mut state,
            &DepositRecord {
                deposit_id: [12u8; 32],
                intent_id: intent_id(13),
                asset: sol_asset(),
                amount: 8_000,
                recipient: recipient_id,
                processed_at: 11,
            },
        )
        .unwrap();

    let eth_mint = wrapped_mint_id(&eth_asset());
    let sol_mint = wrapped_mint_id(&sol_asset());

    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, eth_mint.as_bytes(), &recipient_id),
        5_000
    );
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, sol_mint.as_bytes(), &recipient_id),
        8_000
    );
}

// ── Signed deposit (relayer attestation) ──

#[test]
fn add_relayer_requires_configured_governance() {
    let (_, mut bridge) = setup();
    let result = bridge.add_relayer([0x42; 32], &[0u8; 64]);
    assert!(result.is_err());
    assert!(!bridge.is_approved_relayer(&[0x42; 32]));
}

#[test]
fn add_relayer_rejects_non_governance_signature() {
    use ed25519_dalek::Signer;

    let governance_key = ed25519_dalek::SigningKey::from_bytes(&[0x24u8; 32]);
    let rogue_key = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);
    let relayer_pubkey = [0x42; 32];
    let mut bridge = BridgeState::new_with_governance(governance_key.verifying_key().to_bytes());

    let mut msg = Vec::with_capacity(21 + 32);
    msg.extend_from_slice(b"bridge:add-relayer:v1");
    msg.extend_from_slice(&relayer_pubkey);
    let rogue_signature = rogue_key.sign(&msg).to_bytes();

    let result = bridge.add_relayer(relayer_pubkey, &rogue_signature);
    assert!(result.is_err());
    assert!(!bridge.is_approved_relayer(&relayer_pubkey));
}

#[test]
fn signed_deposit_verified_and_processed() {
    let mut state = StateTree::new();
    let governance_seed = [0x24u8; 32];
    let governance_key = ed25519_dalek::SigningKey::from_bytes(&governance_seed);
    let mut bridge = BridgeState::new_with_governance(governance_key.verifying_key().to_bytes());
    bridge.initialize(&mut state).unwrap();

    // Generate a relayer keypair
    let relayer_seed = [0x42u8; 32];
    let relayer_signing_key = ed25519_dalek::SigningKey::from_bytes(&relayer_seed);
    let relayer_pubkey = relayer_signing_key.verifying_key().to_bytes();
    approve_relayer(&mut bridge, governance_seed, relayer_pubkey);

    let (recipient_id, _) = evm_recipient(0x55);
    let deposit = DepositRecord {
        deposit_id: [20u8; 32],
        intent_id: intent_id(20),
        asset: eth_asset(),
        amount: 5_000,
        recipient: recipient_id,
        processed_at: 10,
    };

    // Sign the deposit
    let deposit_hash = hash_deposit_record(&deposit);
    use ed25519_dalek::Signer;
    let signature = relayer_signing_key.sign(&deposit_hash);

    let signed = SignedDepositRecord {
        deposit,
        relayer_pubkey,
        relayer_signature: signature.to_bytes(),
    };

    bridge.process_signed_deposit(&mut state, &signed).unwrap();

    let mint = wrapped_mint_id(&eth_asset());
    let balance = ace_n_vm::token_runtime::balance_of(&state, mint.as_bytes(), &recipient_id);
    assert_eq!(balance, 5_000);
}

#[test]
fn signed_deposit_bad_signature_rejected() {
    let mut state = StateTree::new();
    let governance_seed = [0x25u8; 32];
    let governance_key = ed25519_dalek::SigningKey::from_bytes(&governance_seed);
    let mut bridge = BridgeState::new_with_governance(governance_key.verifying_key().to_bytes());
    bridge.initialize(&mut state).unwrap();
    let relayer_seed = [0x42u8; 32];
    let relayer_signing_key = ed25519_dalek::SigningKey::from_bytes(&relayer_seed);
    let relayer_pubkey = relayer_signing_key.verifying_key().to_bytes();
    approve_relayer(&mut bridge, governance_seed, relayer_pubkey);

    let (recipient_id, _) = evm_recipient(0x66);
    let deposit = DepositRecord {
        deposit_id: [21u8; 32],
        intent_id: intent_id(21),
        asset: eth_asset(),
        amount: 1_000,
        recipient: recipient_id,
        processed_at: 10,
    };

    let signed = SignedDepositRecord {
        deposit,
        relayer_pubkey,
        relayer_signature: [0u8; 64], // bad signature
    };

    let result = bridge.process_signed_deposit(&mut state, &signed);
    assert!(result.is_err());
}

#[test]
fn signed_deposit_unapproved_relayer_rejected() {
    let (mut state, mut bridge) = setup();

    let rogue_seed = [0x99u8; 32];
    let rogue_key = ed25519_dalek::SigningKey::from_bytes(&rogue_seed);
    let rogue_pubkey = rogue_key.verifying_key().to_bytes();
    // NOT added to bridge.approved_relayers

    let (recipient_id, _) = evm_recipient(0x77);
    let deposit = DepositRecord {
        deposit_id: [22u8; 32],
        intent_id: intent_id(22),
        asset: eth_asset(),
        amount: 2_000,
        recipient: recipient_id,
        processed_at: 10,
    };

    let deposit_hash = hash_deposit_record(&deposit);
    use ed25519_dalek::Signer;
    let signature = rogue_key.sign(&deposit_hash);

    let signed = SignedDepositRecord {
        deposit,
        relayer_pubkey: rogue_pubkey,
        relayer_signature: signature.to_bytes(),
    };

    let result = bridge.process_signed_deposit(&mut state, &signed);
    assert!(result.is_err());
}
