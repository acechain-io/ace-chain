use ace_defi::{
    canonical_asset_id, hash_withdrawal_completion, oasset_mint_id, CanonicalAssetRegistry,
    ExternalAsset, ExternalChain, ReserveAccounting, RiskConfig, RiskTier, SwapEngine,
};
use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use ed25519_dalek::{Signer, SigningKey};

fn ethereum_usdt() -> ExternalAsset {
    ExternalAsset::Erc20([0x11; 20])
}

fn bsc_usdt() -> ExternalAsset {
    ExternalAsset::Bep20([0x22; 20])
}

fn ethereum_usdc() -> ExternalAsset {
    ExternalAsset::Erc20([0x33; 20])
}

fn recipient(seed: u8) -> AccountId {
    AccountId::from_bytes([seed; 32])
}

fn signed_deposit(
    signing_key: &SigningKey,
    deposit_id: [u8; 32],
    asset: ExternalAsset,
    amount: u64,
    recipient: AccountId,
) -> ace_defi::SignedDepositRecord {
    let deposit = ace_defi::DepositRecord {
        deposit_id,
        intent_id: [7u8; 32],
        asset,
        amount,
        recipient,
        processed_at: 10,
    };
    let signature = signing_key.sign(&ace_defi::hash_deposit_record(&deposit));
    ace_defi::SignedDepositRecord {
        deposit,
        relayer_pubkey: signing_key.verifying_key().to_bytes(),
        relayer_signature: signature.to_bytes(),
    }
}

fn setup() -> (StateTree, ace_defi::CanonicalAssetId, SigningKey) {
    let mut state = StateTree::new();
    let relayer = SigningKey::from_bytes(&[9u8; 32]);
    ace_defi::approve_relayer_in_state(&mut state, relayer.verifying_key().to_bytes());

    let canonical =
        CanonicalAssetRegistry::register_canonical_asset(&mut state, "oUSDT", 6, RiskTier::Tier1)
            .unwrap();
    let risk = RiskConfig::tier1_stablecoin();
    CanonicalAssetRegistry::map_external_asset(
        &mut state,
        ethereum_usdt(),
        canonical.id,
        6,
        risk.clone(),
    )
    .unwrap();
    CanonicalAssetRegistry::map_external_asset(&mut state, bsc_usdt(), canonical.id, 18, risk)
        .unwrap();
    (state, canonical.id, relayer)
}

fn setup_with_risk(risk: RiskConfig) -> (StateTree, ace_defi::CanonicalAssetId, SigningKey) {
    let mut state = StateTree::new();
    let relayer = SigningKey::from_bytes(&[9u8; 32]);
    ace_defi::approve_relayer_in_state(&mut state, relayer.verifying_key().to_bytes());

    let canonical =
        CanonicalAssetRegistry::register_canonical_asset(&mut state, "oUSDT", 6, RiskTier::Tier1)
            .unwrap();
    CanonicalAssetRegistry::map_external_asset(&mut state, ethereum_usdt(), canonical.id, 6, risk)
        .unwrap();
    (state, canonical.id, relayer)
}

#[test]
fn canonical_asset_registers_oasset_mint() {
    let mut state = StateTree::new();
    let asset =
        CanonicalAssetRegistry::register_canonical_asset(&mut state, "oUSDT", 6, RiskTier::Tier1)
            .unwrap();

    assert_eq!(asset.id, canonical_asset_id("oUSDT", 6).unwrap());
    assert_eq!(asset.mint, oasset_mint_id(&asset.id));
    assert!(ace_n_vm::token_runtime::get_mint_meta(&state, asset.mint.as_bytes()).is_some());
}

#[test]
fn maps_multiple_external_assets_to_same_oasset() {
    let (state, ousdt, _) = setup();

    let eth_mapping = CanonicalAssetRegistry::get_mapping(&state, &ethereum_usdt())
        .unwrap()
        .unwrap();
    let bsc_mapping = CanonicalAssetRegistry::get_mapping(&state, &bsc_usdt())
        .unwrap()
        .unwrap();

    assert_eq!(eth_mapping.canonical_asset, ousdt);
    assert_eq!(bsc_mapping.canonical_asset, ousdt);
    assert_ne!(eth_mapping.reserve_mint, bsc_mapping.reserve_mint);
}

#[test]
fn risk_compartments_are_deterministic_and_scoped() {
    let (state, ousdt, _) = setup();
    let canonical = CanonicalAssetRegistry::get_canonical_asset(&state, &ousdt)
        .unwrap()
        .unwrap();
    let eth_mapping = CanonicalAssetRegistry::get_mapping(&state, &ethereum_usdt())
        .unwrap()
        .unwrap();
    let bsc_mapping = CanonicalAssetRegistry::get_mapping(&state, &bsc_usdt())
        .unwrap()
        .unwrap();

    assert_eq!(
        canonical.risk_compartment_id(),
        ace_defi::canonical_asset_compartment_id(&ousdt)
    );
    assert_eq!(
        eth_mapping.risk_compartment_id(),
        ace_defi::external_asset_mapping_compartment_id(&ethereum_usdt())
    );
    assert_ne!(
        eth_mapping.risk_compartment_id(),
        bsc_mapping.risk_compartment_id()
    );
    assert_ne!(
        canonical.risk_compartment_id(),
        eth_mapping.risk_compartment_id()
    );
}

#[test]
fn deposit_mints_same_ousdt_from_ethereum_and_bsc_usdt() {
    let (mut state, ousdt, relayer) = setup();
    let user = recipient(0xAA);

    let eth_deposit = signed_deposit(&relayer, [1u8; 32], ethereum_usdt(), 1_000_000, user);
    let bsc_deposit = signed_deposit(
        &relayer,
        [2u8; 32],
        bsc_usdt(),
        1_000_000_000_000_000_000,
        user,
    );

    let eth_mint =
        ace_defi::deposit::process_deposit_to_oasset(&mut state, &eth_deposit, 10).unwrap();
    let bsc_mint =
        ace_defi::deposit::process_deposit_to_oasset(&mut state, &bsc_deposit, 11).unwrap();

    assert_eq!(eth_mint, bsc_mint);
    let canonical = CanonicalAssetRegistry::get_canonical_asset(&state, &ousdt)
        .unwrap()
        .unwrap();
    let balance = ace_n_vm::token_runtime::balance_of(&state, canonical.mint.as_bytes(), &user);
    assert_eq!(balance, 2_000_000);
    assert_eq!(
        ReserveAccounting::active_supply(&state, &ousdt).unwrap(),
        2_000_000
    );
}

#[test]
fn duplicate_deposit_is_rejected() {
    let (mut state, _, relayer) = setup();
    let user = recipient(0xBB);
    let deposit = signed_deposit(&relayer, [3u8; 32], ethereum_usdt(), 1_000_000, user);

    ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 10).unwrap();
    let result = ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 11);
    assert!(matches!(
        result,
        Err(ace_defi::BridgeError::DepositAlreadyProcessed(_))
    ));
}

#[test]
fn oasset_mints_can_back_swap_pools() {
    let (mut state, ousdt, relayer) = setup();
    let ousdc =
        CanonicalAssetRegistry::register_canonical_asset(&mut state, "oUSDC", 6, RiskTier::Tier1)
            .unwrap()
            .id;
    CanonicalAssetRegistry::map_external_asset(
        &mut state,
        ethereum_usdc(),
        ousdc,
        6,
        RiskConfig::tier1_stablecoin(),
    )
    .unwrap();

    let lp_provider = recipient(0xF1);
    let trader = recipient(0xF2);
    for (deposit_id, asset, amount, to) in [
        ([0x71u8; 32], ethereum_usdt(), 5_000_000, lp_provider),
        ([0x72u8; 32], ethereum_usdc(), 5_000_000, lp_provider),
        ([0x73u8; 32], ethereum_usdt(), 1_000_000, trader),
    ] {
        let deposit = signed_deposit(&relayer, deposit_id, asset, amount, to);
        ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 10).unwrap();
    }

    let ousdt_mint = CanonicalAssetRegistry::get_canonical_asset(&state, &ousdt)
        .unwrap()
        .unwrap()
        .mint;
    let ousdc_mint = CanonicalAssetRegistry::get_canonical_asset(&state, &ousdc)
        .unwrap()
        .unwrap()
        .mint;

    let mut swap = SwapEngine::new();
    swap.create_pool(&mut state, &ousdt_mint, &ousdc_mint)
        .unwrap();
    swap.add_liquidity(
        &mut state,
        &ousdt_mint,
        &ousdc_mint,
        &lp_provider,
        4_000_000,
        4_000_000,
    )
    .unwrap();

    let usdt_before = ace_n_vm::token_runtime::balance_of(&state, ousdt_mint.as_bytes(), &trader);
    let usdc_before = ace_n_vm::token_runtime::balance_of(&state, ousdc_mint.as_bytes(), &trader);
    let amount_out = swap
        .swap(&mut state, &ousdt_mint, &ousdc_mint, &trader, 100_000, 1)
        .unwrap();

    assert!(amount_out > 0);
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, ousdt_mint.as_bytes(), &trader),
        usdt_before - 100_000
    );
    assert_eq!(
        ace_n_vm::token_runtime::balance_of(&state, ousdc_mint.as_bytes(), &trader),
        usdc_before + amount_out
    );
}

#[test]
fn withdrawal_burns_oasset_and_reserves_target_asset() {
    let (mut state, ousdt, relayer) = setup();
    let user = recipient(0xCC);
    let deposit = signed_deposit(&relayer, [4u8; 32], ethereum_usdt(), 5_000_000, user);
    ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 10).unwrap();

    let record = ace_defi::withdraw::request_oasset_withdrawal(
        &mut state,
        &user,
        [8u8; 32],
        ousdt,
        2_000_000,
        ethereum_usdt(),
        vec![0x44; 20],
        20,
        1,
    )
    .unwrap();

    assert_eq!(record.amount, 2_000_000);
    assert_eq!(record.asset, ethereum_usdt());
    let canonical = CanonicalAssetRegistry::get_canonical_asset(&state, &ousdt)
        .unwrap()
        .unwrap();
    let balance = ace_n_vm::token_runtime::balance_of(&state, canonical.mint.as_bytes(), &user);
    assert_eq!(balance, 3_000_000);
    let position = ReserveAccounting::get_position(&state, &ethereum_usdt())
        .unwrap()
        .unwrap();
    assert_eq!(position.available, 3_000_000);
    assert_eq!(position.pending_withdrawal, 2_000_000);
}

#[test]
fn withdrawal_completion_finalizes_oasset_reserve() {
    let (mut state, ousdt, relayer) = setup();
    let user = recipient(0xC1);
    let deposit = signed_deposit(&relayer, [0x41u8; 32], ethereum_usdt(), 5_000_000, user);
    ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 10).unwrap();

    let record = ace_defi::withdraw::request_oasset_withdrawal(
        &mut state,
        &user,
        [0x42u8; 32],
        ousdt,
        2_000_000,
        ethereum_usdt(),
        vec![0x44; 20],
        20,
        11,
    )
    .unwrap();

    let mut completion = ace_defi::WithdrawalCompletionRecord {
        withdrawal_id: record.withdrawal_id,
        destination_chain: ExternalChain::Ethereum,
        external_tx_hash: [0x55; 32],
        withdrawal_record_hash: ace_defi::withdraw::hash_withdrawal_record(&record),
        released_asset: record.asset.clone(),
        released_recipient: record.external_dest.clone(),
        released_amount: record.amount,
        gateway_address: vec![0xAB; 20],
        relayer_pubkey: relayer.verifying_key().to_bytes(),
        relayer_signature: [0u8; 64],
    };
    completion.relayer_signature = relayer
        .sign(&hash_withdrawal_completion(&completion))
        .to_bytes();

    let completed = ace_defi::complete_indexed_withdrawal(&mut state, &completion).unwrap();
    assert!(completed.completed);

    let position = ReserveAccounting::get_position(&state, &ethereum_usdt())
        .unwrap()
        .unwrap();
    assert_eq!(position.available, 3_000_000);
    assert_eq!(position.pending_withdrawal, 0);
    assert_eq!(position.total_withdrawn, 2_000_000);
    assert_eq!(
        ReserveAccounting::reserve_total(&state, &ousdt).unwrap(),
        3_000_000
    );
}

#[test]
fn withdrawal_completion_rejects_record_hash_mismatch() {
    let (mut state, ousdt, relayer) = setup();
    let user = recipient(0xC2);
    let deposit = signed_deposit(&relayer, [0x43u8; 32], ethereum_usdt(), 5_000_000, user);
    ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 10).unwrap();

    let record = ace_defi::withdraw::request_oasset_withdrawal(
        &mut state,
        &user,
        [0x44u8; 32],
        ousdt,
        1_000_000,
        ethereum_usdt(),
        vec![0x44; 20],
        20,
        12,
    )
    .unwrap();

    let mut completion = ace_defi::WithdrawalCompletionRecord {
        withdrawal_id: record.withdrawal_id,
        destination_chain: ExternalChain::Ethereum,
        external_tx_hash: [0x56; 32],
        withdrawal_record_hash: [0x99; 32],
        released_asset: record.asset.clone(),
        released_recipient: record.external_dest.clone(),
        released_amount: record.amount,
        gateway_address: vec![0xAB; 20],
        relayer_pubkey: relayer.verifying_key().to_bytes(),
        relayer_signature: [0u8; 64],
    };
    completion.relayer_signature = relayer
        .sign(&hash_withdrawal_completion(&completion))
        .to_bytes();

    assert!(matches!(
        ace_defi::complete_indexed_withdrawal(&mut state, &completion),
        Err(ace_defi::BridgeError::InvalidDepositProof(_))
    ));
}

#[test]
fn withdrawal_completion_rejects_released_amount_mismatch() {
    let (mut state, ousdt, relayer) = setup();
    let user = recipient(0xC3);
    let deposit = signed_deposit(&relayer, [0x45u8; 32], ethereum_usdt(), 5_000_000, user);
    ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 10).unwrap();

    let record = ace_defi::withdraw::request_oasset_withdrawal(
        &mut state,
        &user,
        [0x46u8; 32],
        ousdt,
        1_000_000,
        ethereum_usdt(),
        vec![0x44; 20],
        20,
        12,
    )
    .unwrap();

    let mut completion = ace_defi::WithdrawalCompletionRecord {
        withdrawal_id: record.withdrawal_id,
        destination_chain: ExternalChain::Ethereum,
        external_tx_hash: [0x57; 32],
        withdrawal_record_hash: ace_defi::withdraw::hash_withdrawal_record(&record),
        released_asset: record.asset.clone(),
        released_recipient: record.external_dest.clone(),
        released_amount: record.amount - 1,
        gateway_address: vec![0xAB; 20],
        relayer_pubkey: relayer.verifying_key().to_bytes(),
        relayer_signature: [0u8; 64],
    };
    completion.relayer_signature = relayer
        .sign(&hash_withdrawal_completion(&completion))
        .to_bytes();

    assert!(matches!(
        ace_defi::complete_indexed_withdrawal(&mut state, &completion),
        Err(ace_defi::BridgeError::InvalidDepositProof(_))
    ));
}

#[test]
fn daily_deposit_limit_is_enforced() {
    let mut risk = RiskConfig::tier1_stablecoin();
    risk.daily_deposit_limit = 1_500_000;
    let (mut state, _, relayer) = setup_with_risk(risk);
    let user = recipient(0xA1);

    let first = signed_deposit(&relayer, [0x81u8; 32], ethereum_usdt(), 1_000_000, user);
    let second = signed_deposit(&relayer, [0x82u8; 32], ethereum_usdt(), 600_000, user);
    ace_defi::deposit::process_deposit_to_oasset(&mut state, &first, 100).unwrap();
    assert!(matches!(
        ace_defi::deposit::process_deposit_to_oasset(&mut state, &second, 101),
        Err(ace_defi::BridgeError::LimitExceeded(_))
    ));
}

#[test]
fn failed_deposit_does_not_consume_daily_limit() {
    let mut risk = RiskConfig::tier1_stablecoin();
    risk.daily_deposit_limit = 1_000_000;
    let (mut state, ousdt, relayer) = setup_with_risk(risk);
    let user = recipient(0xA3);

    CanonicalAssetRegistry::set_canonical_asset_active(&mut state, &ousdt, false).unwrap();
    let failed = signed_deposit(&relayer, [0x84u8; 32], ethereum_usdt(), 1_000_000, user);
    assert!(matches!(
        ace_defi::deposit::process_deposit_to_oasset(&mut state, &failed, 100),
        Err(ace_defi::BridgeError::CanonicalAssetInactive(_))
    ));

    CanonicalAssetRegistry::set_canonical_asset_active(&mut state, &ousdt, true).unwrap();
    let valid = signed_deposit(&relayer, [0x85u8; 32], ethereum_usdt(), 1_000_000, user);
    ace_defi::deposit::process_deposit_to_oasset(&mut state, &valid, 101)
        .expect("failed deposit must not consume daily quota");
}

#[test]
fn failed_withdrawal_does_not_consume_daily_limit() {
    let mut risk = RiskConfig::tier1_stablecoin();
    risk.daily_withdrawal_limit = 1_000_000;
    let (mut state, ousdt, relayer) = setup_with_risk(risk);
    let user = recipient(0xA4);

    let deposit = signed_deposit(&relayer, [0x86u8; 32], ethereum_usdt(), 2_000_000, user);
    ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 100).unwrap();

    assert!(matches!(
        ace_defi::withdraw::request_oasset_withdrawal(
            &mut state,
            &user,
            [0x87u8; 32],
            ousdt,
            1_000_000,
            ethereum_usdt(),
            vec![0x11; 19],
            101,
            1,
        ),
        Err(ace_defi::BridgeError::InvalidDestination(_))
    ));

    ace_defi::withdraw::request_oasset_withdrawal(
        &mut state,
        &user,
        [0x88u8; 32],
        ousdt,
        1_000_000,
        ethereum_usdt(),
        vec![0x22; 20],
        102,
        2,
    )
    .expect("failed withdrawal must not consume daily quota");
}

#[test]
fn unsupported_relayer_quorum_fails_closed() {
    let mut risk = RiskConfig::tier1_stablecoin();
    risk.required_relayer_quorum = 2;
    let (mut state, _, relayer) = setup_with_risk(risk);
    let user = recipient(0xA2);
    let deposit = signed_deposit(&relayer, [0x83u8; 32], ethereum_usdt(), 1_000_000, user);

    assert!(matches!(
        ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 100),
        Err(ace_defi::BridgeError::LimitExceeded(_))
    ));
}

#[test]
fn withdrawal_fails_when_target_reserve_is_insufficient() {
    let (mut state, ousdt, relayer) = setup();
    let user = recipient(0xDD);
    let deposit = signed_deposit(&relayer, [5u8; 32], ethereum_usdt(), 5_000_000, user);
    ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 10).unwrap();

    let result = ace_defi::withdraw::request_oasset_withdrawal(
        &mut state,
        &user,
        [9u8; 32],
        ousdt,
        1_000_000,
        bsc_usdt(),
        vec![0x55; 20],
        20,
        2,
    );

    assert!(matches!(
        result,
        Err(ace_defi::BridgeError::InsufficientReserve { .. })
    ));
}

#[test]
fn paused_mapping_rejects_deposit_and_withdrawal() {
    let (mut state, ousdt, relayer) = setup();
    let user = recipient(0xEE);
    CanonicalAssetRegistry::set_mapping_mint_enabled(&mut state, &ethereum_usdt(), false).unwrap();
    let deposit = signed_deposit(&relayer, [6u8; 32], ethereum_usdt(), 1_000_000, user);
    let result = ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 10);
    assert!(matches!(result, Err(ace_defi::BridgeError::MintDisabled)));

    CanonicalAssetRegistry::set_mapping_mint_enabled(&mut state, &ethereum_usdt(), true).unwrap();
    ace_defi::deposit::process_deposit_to_oasset(&mut state, &deposit, 11).unwrap();
    CanonicalAssetRegistry::set_mapping_withdraw_enabled(&mut state, &ethereum_usdt(), false)
        .unwrap();
    let result = ace_defi::withdraw::request_oasset_withdrawal(
        &mut state,
        &user,
        [10u8; 32],
        ousdt,
        1_000_000,
        ethereum_usdt(),
        vec![0x66; 20],
        20,
        3,
    );
    assert!(matches!(
        result,
        Err(ace_defi::BridgeError::WithdrawDisabled)
    ));
}

#[test]
fn paused_mapping_compartment_does_not_block_sibling_mapping() {
    let (mut state, _, relayer) = setup();
    let eth_user = recipient(0xD1);
    let bsc_user = recipient(0xD2);

    CanonicalAssetRegistry::set_mapping_mint_enabled(&mut state, &ethereum_usdt(), false).unwrap();
    let eth_deposit = signed_deposit(&relayer, [0x91u8; 32], ethereum_usdt(), 1_000_000, eth_user);
    assert!(matches!(
        ace_defi::deposit::process_deposit_to_oasset(&mut state, &eth_deposit, 200),
        Err(ace_defi::BridgeError::MintDisabled)
    ));

    let bsc_deposit = signed_deposit(
        &relayer,
        [0x92u8; 32],
        bsc_usdt(),
        1_000_000_000_000_000_000,
        bsc_user,
    );
    ace_defi::deposit::process_deposit_to_oasset(&mut state, &bsc_deposit, 201)
        .expect("pausing one external-asset compartment must not block another mapping");
}
