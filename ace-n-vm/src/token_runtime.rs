//! Unified runtime token ledger shared by SVM SPL-compat and EVM ERC-20 compat.
//!
//! Token state lives under the built-in `TokenProgram` account in the ACE state
//! tree. SPL token accounts are modeled as compatibility aliases that resolve to
//! an owner identity commitment plus mint, while ERC-20 contract calls map to
//! deterministic contract addresses derived from the mint id.

use std::sync::OnceLock;

use ace_engine::receipt::StateChange;
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::svm::programs::TOKEN_PROGRAM_ID;

const MINT_SLOT_PREFIX: &[u8] = b"mint:";
const MINT_AUTHORITY_SLOT_PREFIX: &[u8] = b"mint-auth:";
const BALANCE_SLOT_PREFIX: &[u8] = b"balance:";
const ALLOWANCE_SLOT_PREFIX: &[u8] = b"allowance:";
const TOKEN_ACCOUNT_OWNER_IDCOM_PREFIX: &[u8] = b"ta-owner-idcom:";
const TOKEN_ACCOUNT_OWNER_SOL_PREFIX: &[u8] = b"ta-owner-sol:";
const TOKEN_ACCOUNT_MINT_PREFIX: &[u8] = b"ta-mint:";
const EVM_CONTRACT_MAP_PREFIX: &[u8] = b"erc20-map:";
const EVM_CONTRACT_ADDR_PREFIX: &[u8] = b"erc20-addr:";

const SPL_TOKEN_PROGRAM_ID_B58: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPL_ASSOCIATED_TOKEN_PROGRAM_ID_B58: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintMeta {
    pub supply: u64,
    pub decimals: u8,
    /// The identity commitment of the mint authority (who can mint new tokens).
    pub authority: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenAccountMeta {
    pub mint: [u8; 32],
    pub owner_sol_pubkey: [u8; 32],
    pub owner_idcom: [u8; 32],
}

pub fn token_program_account_id() -> AccountId {
    AccountId::from_bytes(TOKEN_PROGRAM_ID)
}

pub fn spl_token_program_id() -> [u8; 32] {
    static ID: OnceLock<[u8; 32]> = OnceLock::new();
    *ID.get_or_init(|| decode_base58_pubkey(SPL_TOKEN_PROGRAM_ID_B58))
}

pub fn associated_token_program_id() -> [u8; 32] {
    static ID: OnceLock<[u8; 32]> = OnceLock::new();
    *ID.get_or_init(|| decode_base58_pubkey(SPL_ASSOCIATED_TOKEN_PROGRAM_ID_B58))
}

pub fn derive_associated_token_address(owner_sol_pubkey: &[u8; 32], mint: &[u8; 32]) -> [u8; 32] {
    find_program_address(
        &[owner_sol_pubkey, &spl_token_program_id(), mint],
        &associated_token_program_id(),
    )
}

pub fn runtime_erc20_address_for_mint(mint: &[u8; 32]) -> [u8; 20] {
    let mut hasher = Sha256::new();
    hasher.update(EVM_CONTRACT_ADDR_PREFIX);
    hasher.update(mint);
    let digest = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..32]);
    out
}

pub fn mint_for_runtime_erc20_address(state: &StateTree, address: &[u8; 20]) -> Option<[u8; 32]> {
    let program = token_program_account_id();
    let slot = prefixed_slot(EVM_CONTRACT_MAP_PREFIX, address);
    let mint = state.get_storage(&program, &slot);
    (mint != [0u8; 32]).then_some(mint)
}

pub fn get_mint_meta(state: &StateTree, mint: &[u8; 32]) -> Option<MintMeta> {
    let program = token_program_account_id();
    let value = state.get_storage(&program, &prefixed_slot(MINT_SLOT_PREFIX, mint));
    if value == [0u8; 32] {
        return None;
    }
    let authority = state.get_storage(&program, &prefixed_slot(MINT_AUTHORITY_SLOT_PREFIX, mint));
    Some(MintMeta {
        supply: u64::from_le_bytes(value[0..8].try_into().unwrap()),
        decimals: value[8],
        authority,
    })
}

pub fn create_mint(
    state: &mut StateTree,
    mint: &[u8; 32],
    decimals: u8,
    authority: &[u8; 32],
) -> Result<Vec<StateChange>, String> {
    ensure_token_program_account(state);
    let program = token_program_account_id();
    let mint_slot = prefixed_slot(MINT_SLOT_PREFIX, mint);
    let existing = state.get_storage(&program, &mint_slot);
    if existing != [0u8; 32] {
        return Err("mint already exists".into());
    }

    let mut value = [0u8; 32];
    value[8] = decimals;
    state.set_storage(&program, mint_slot, value);

    let auth_slot = prefixed_slot(MINT_AUTHORITY_SLOT_PREFIX, mint);
    state.set_storage(&program, auth_slot, *authority);

    let evm_address = runtime_erc20_address_for_mint(mint);
    let evm_slot = prefixed_slot(EVM_CONTRACT_MAP_PREFIX, &evm_address);
    state.set_storage(&program, evm_slot, *mint);

    Ok(vec![
        StateChange::StorageChange {
            account: program,
            slot: mint_slot,
            old_value: [0u8; 32],
            new_value: value,
        },
        StateChange::StorageChange {
            account: program,
            slot: auth_slot,
            old_value: [0u8; 32],
            new_value: *authority,
        },
        StateChange::StorageChange {
            account: program,
            slot: evm_slot,
            old_value: [0u8; 32],
            new_value: *mint,
        },
    ])
}

pub fn mint_to_owner(
    state: &mut StateTree,
    mint: &[u8; 32],
    owner_idcom: &[u8; 32],
    amount: u64,
    caller: &AccountId,
) -> Result<Vec<StateChange>, String> {
    if amount == 0 {
        return Ok(vec![]);
    }
    ensure_token_program_account(state);
    let program = token_program_account_id();
    let mint_slot = prefixed_slot(MINT_SLOT_PREFIX, mint);
    let old_mint = state.get_storage(&program, &mint_slot);
    if old_mint == [0u8; 32] {
        return Err("mint does not exist".into());
    }
    // Verify mint authority
    let auth_slot = prefixed_slot(MINT_AUTHORITY_SLOT_PREFIX, mint);
    let authority = state.get_storage(&program, &auth_slot);
    if *caller.as_bytes() != authority {
        return Err("caller is not the mint authority".into());
    }
    let old_supply = u64::from_le_bytes(old_mint[0..8].try_into().unwrap());
    let new_supply = old_supply.checked_add(amount).ok_or("supply overflow")?;
    let mut new_mint = old_mint;
    new_mint[0..8].copy_from_slice(&new_supply.to_le_bytes());
    state.set_storage(&program, mint_slot, new_mint);

    let owner = AccountId::from_bytes(*owner_idcom);
    let balance_slot = prefixed_balance_slot(mint, &owner);
    let old_balance_value = state.get_storage(&program, &balance_slot);
    let old_balance = u64::from_le_bytes(old_balance_value[0..8].try_into().unwrap());
    let new_balance = old_balance.checked_add(amount).ok_or("balance overflow")?;
    let mut new_balance_value = [0u8; 32];
    new_balance_value[0..8].copy_from_slice(&new_balance.to_le_bytes());
    state.set_storage(&program, balance_slot, new_balance_value);

    Ok(vec![
        StateChange::StorageChange {
            account: program,
            slot: mint_slot,
            old_value: old_mint,
            new_value: new_mint,
        },
        StateChange::StorageChange {
            account: program,
            slot: balance_slot,
            old_value: old_balance_value,
            new_value: new_balance_value,
        },
    ])
}

pub fn transfer_between_owners(
    state: &mut StateTree,
    mint: &[u8; 32],
    from: &AccountId,
    to: &AccountId,
    amount: u64,
) -> Result<Vec<StateChange>, String> {
    if amount == 0 {
        return Ok(vec![]);
    }
    ensure_token_program_account(state);
    let program = token_program_account_id();

    // Verify the mint exists before allowing transfers.
    let mint_slot_val = state.get_storage(&program, &prefixed_slot(MINT_SLOT_PREFIX, mint));
    if mint_slot_val == [0u8; 32] {
        return Err("mint does not exist".into());
    }

    // Self-transfer: just verify sufficient balance, no state change needed.
    if from == to {
        let from_slot = prefixed_balance_slot(mint, from);
        let old_from = state.get_storage(&program, &from_slot);
        let from_balance = u64::from_le_bytes(old_from[0..8].try_into().unwrap());
        if from_balance < amount {
            return Err("insufficient token balance".into());
        }
        return Ok(vec![]);
    }

    let from_slot = prefixed_balance_slot(mint, from);
    let to_slot = prefixed_balance_slot(mint, to);

    let old_from = state.get_storage(&program, &from_slot);
    let old_to = state.get_storage(&program, &to_slot);
    let from_balance = u64::from_le_bytes(old_from[0..8].try_into().unwrap());
    let to_balance = u64::from_le_bytes(old_to[0..8].try_into().unwrap());
    if from_balance < amount {
        return Err("insufficient token balance".into());
    }
    let new_to_balance = to_balance
        .checked_add(amount)
        .ok_or("recipient balance overflow")?;

    let mut new_from = [0u8; 32];
    new_from[0..8].copy_from_slice(&(from_balance - amount).to_le_bytes());
    let mut new_to = [0u8; 32];
    new_to[0..8].copy_from_slice(&new_to_balance.to_le_bytes());
    state.set_storage(&program, from_slot, new_from);
    state.set_storage(&program, to_slot, new_to);

    Ok(vec![
        StateChange::StorageChange {
            account: program,
            slot: from_slot,
            old_value: old_from,
            new_value: new_from,
        },
        StateChange::StorageChange {
            account: program,
            slot: to_slot,
            old_value: old_to,
            new_value: new_to,
        },
    ])
}

pub fn balance_of(state: &StateTree, mint: &[u8; 32], owner: &AccountId) -> u64 {
    let program = token_program_account_id();
    let value = state.get_storage(&program, &prefixed_balance_slot(mint, owner));
    u64::from_le_bytes(value[0..8].try_into().unwrap())
}

pub fn set_allowance(
    state: &mut StateTree,
    mint: &[u8; 32],
    owner: &AccountId,
    spender: &AccountId,
    amount: u64,
) -> Result<Vec<StateChange>, String> {
    ensure_token_program_account(state);
    let program = token_program_account_id();
    // Verify mint exists
    let mint_val = state.get_storage(&program, &prefixed_slot(MINT_SLOT_PREFIX, mint));
    if mint_val == [0u8; 32] {
        return Err("mint does not exist".into());
    }
    let slot = prefixed_allowance_slot(mint, owner, spender);
    let old_value = state.get_storage(&program, &slot);
    let mut new_value = [0u8; 32];
    new_value[0..8].copy_from_slice(&amount.to_le_bytes());
    state.set_storage(&program, slot, new_value);
    Ok(vec![StateChange::StorageChange {
        account: program,
        slot,
        old_value,
        new_value,
    }])
}

pub fn allowance_of(
    state: &StateTree,
    mint: &[u8; 32],
    owner: &AccountId,
    spender: &AccountId,
) -> u64 {
    let program = token_program_account_id();
    let value = state.get_storage(&program, &prefixed_allowance_slot(mint, owner, spender));
    u64::from_le_bytes(value[0..8].try_into().unwrap())
}

pub fn transfer_from(
    state: &mut StateTree,
    mint: &[u8; 32],
    spender: &AccountId,
    owner: &AccountId,
    recipient: &AccountId,
    amount: u64,
) -> Result<Vec<StateChange>, String> {
    let allowance = allowance_of(state, mint, owner, spender);
    if allowance < amount {
        return Err("allowance too low".into());
    }
    let mut changes = transfer_between_owners(state, mint, owner, recipient, amount)?;
    let mut allowance_changes = set_allowance(state, mint, owner, spender, allowance - amount)?;
    changes.append(&mut allowance_changes);
    Ok(changes)
}

pub fn register_token_account(
    state: &mut StateTree,
    token_account: &[u8; 32],
    mint: &[u8; 32],
    owner_sol_pubkey: &[u8; 32],
    owner_idcom: &[u8; 32],
) -> Result<Vec<StateChange>, String> {
    ensure_token_program_account(state);
    if get_mint_meta(state, mint).is_none() {
        return Err("mint does not exist".into());
    }
    let program = token_program_account_id();
    let mint_slot = prefixed_slot(TOKEN_ACCOUNT_MINT_PREFIX, token_account);
    let owner_idcom_slot = prefixed_slot(TOKEN_ACCOUNT_OWNER_IDCOM_PREFIX, token_account);
    let owner_sol_slot = prefixed_slot(TOKEN_ACCOUNT_OWNER_SOL_PREFIX, token_account);

    let existing_mint = state.get_storage(&program, &mint_slot);
    let existing_owner_sol = state.get_storage(&program, &owner_sol_slot);
    let existing_owner_idcom = state.get_storage(&program, &owner_idcom_slot);
    if existing_mint != [0u8; 32]
        || existing_owner_sol != [0u8; 32]
        || existing_owner_idcom != [0u8; 32]
    {
        return Err("token account already exists".into());
    }

    state.set_storage(&program, mint_slot, *mint);
    state.set_storage(&program, owner_idcom_slot, *owner_idcom);
    state.set_storage(&program, owner_sol_slot, *owner_sol_pubkey);

    Ok(vec![
        StateChange::StorageChange {
            account: program,
            slot: mint_slot,
            old_value: [0u8; 32],
            new_value: *mint,
        },
        StateChange::StorageChange {
            account: program,
            slot: owner_idcom_slot,
            old_value: [0u8; 32],
            new_value: *owner_idcom,
        },
        StateChange::StorageChange {
            account: program,
            slot: owner_sol_slot,
            old_value: [0u8; 32],
            new_value: *owner_sol_pubkey,
        },
    ])
}

pub fn ensure_registered_token_account(
    state: &mut StateTree,
    token_account: &[u8; 32],
    mint: &[u8; 32],
    owner_sol_pubkey: &[u8; 32],
    owner_idcom: &[u8; 32],
) -> Result<Vec<StateChange>, String> {
    if let Some(existing) = get_token_account_meta(state, token_account) {
        if existing.mint == *mint
            && existing.owner_sol_pubkey == *owner_sol_pubkey
            && existing.owner_idcom == *owner_idcom
        {
            return Ok(vec![]);
        }
        return Err("token account already exists with different metadata".into());
    }
    register_token_account(state, token_account, mint, owner_sol_pubkey, owner_idcom)
}

pub fn get_token_account_meta(
    state: &StateTree,
    token_account: &[u8; 32],
) -> Option<TokenAccountMeta> {
    let program = token_program_account_id();
    let mint = state.get_storage(
        &program,
        &prefixed_slot(TOKEN_ACCOUNT_MINT_PREFIX, token_account),
    );
    let owner_sol_pubkey = state.get_storage(
        &program,
        &prefixed_slot(TOKEN_ACCOUNT_OWNER_SOL_PREFIX, token_account),
    );
    let owner_idcom = state.get_storage(
        &program,
        &prefixed_slot(TOKEN_ACCOUNT_OWNER_IDCOM_PREFIX, token_account),
    );
    if mint == [0u8; 32] || owner_sol_pubkey == [0u8; 32] || owner_idcom == [0u8; 32] {
        return None;
    }
    Some(TokenAccountMeta {
        mint,
        owner_sol_pubkey,
        owner_idcom,
    })
}

pub fn token_account_balance(state: &StateTree, token_account: &[u8; 32]) -> Option<u64> {
    let meta = get_token_account_meta(state, token_account)?;
    Some(balance_of(
        state,
        &meta.mint,
        &AccountId::from_bytes(meta.owner_idcom),
    ))
}

pub fn encode_spl_token_account_data(meta: TokenAccountMeta, amount: u64) -> Vec<u8> {
    let mut data = vec![0u8; 165];
    data[0..32].copy_from_slice(&meta.mint);
    data[32..64].copy_from_slice(&meta.owner_sol_pubkey);
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = 1; // initialized
    data
}

pub fn encode_spl_mint_data(meta: MintMeta) -> Vec<u8> {
    let mut data = vec![0u8; 82];
    // mint authority option: 1 byte flag + 32 byte pubkey
    if meta.authority != [0u8; 32] {
        data[0] = 1; // COption::Some
        data[1..33].copy_from_slice(&meta.authority);
    }
    data[36..44].copy_from_slice(&meta.supply.to_le_bytes());
    data[44] = meta.decimals;
    data[45] = 1; // initialized
                  // freeze authority option = none
    data
}

pub fn ensure_token_program_account(state: &mut StateTree) -> Option<StateChange> {
    let account = token_program_account_id();
    if state.contains(&account) {
        return None;
    }
    state.insert(Account::new(account));
    Some(StateChange::AccountCreated { account })
}

pub fn register_runtime_erc20_mapping_for_existing_mint(
    state: &mut StateTree,
    mint: &[u8; 32],
) -> Option<StateChange> {
    let program = token_program_account_id();
    let address = runtime_erc20_address_for_mint(mint);
    let slot = prefixed_slot(EVM_CONTRACT_MAP_PREFIX, &address);
    let old_value = state.get_storage(&program, &slot);
    if old_value == *mint {
        return None;
    }
    state.set_storage(&program, slot, *mint);
    Some(StateChange::StorageChange {
        account: program,
        slot,
        old_value,
        new_value: *mint,
    })
}

fn prefixed_balance_slot(mint: &[u8; 32], owner: &AccountId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BALANCE_SLOT_PREFIX);
    hasher.update(mint);
    hasher.update(owner.as_bytes());
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&hasher.finalize());
    slot
}

fn prefixed_allowance_slot(mint: &[u8; 32], owner: &AccountId, spender: &AccountId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ALLOWANCE_SLOT_PREFIX);
    hasher.update(mint);
    hasher.update(owner.as_bytes());
    hasher.update(spender.as_bytes());
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&hasher.finalize());
    slot
}

fn prefixed_slot(prefix: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(suffix);
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&hasher.finalize());
    slot
}

fn decode_base58_pubkey(value: &str) -> [u8; 32] {
    let bytes = bs58::decode(value).into_vec().expect("valid base58 pubkey");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> [u8; 32] {
    for bump in (0u8..=255).rev() {
        let bump_seed = [bump];
        let mut all_seeds = seeds.to_vec();
        all_seeds.push(&bump_seed);
        if let Ok(address) = create_program_address(&all_seeds, program_id) {
            return address;
        }
    }
    panic!("unable to derive associated token address");
}

fn create_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update(program_id);
    hasher.update(b"ProgramDerivedAddress");
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    if VerifyingKey::from_bytes(&out).is_ok() {
        return Err("derived address is on curve".into());
    }
    Ok(out)
}
