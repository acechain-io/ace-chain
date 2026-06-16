//! Built-in SVM programs: SystemProgram and TokenProgram.
//!
//! Programs operate directly on the ACE StateTree, making them
//! fully compatible with snapshot/rollback for finality.

use std::collections::BTreeMap;

use ace_engine::receipt::StateChange;
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;

use crate::token_runtime;

/// A built-in SVM program.
pub trait SvmProgram: Send + Sync {
    fn program_id(&self) -> [u8; 32];
    fn name(&self) -> &str;
    fn execute(
        &self,
        state: &mut StateTree,
        caller: &AccountId,
        accounts: &[[u8; 32]],
        data: &[u8],
    ) -> Result<Vec<StateChange>, String>;
}

/// Registry of built-in SVM programs.
pub struct ProgramRegistry {
    programs: BTreeMap<[u8; 32], Box<dyn SvmProgram>>,
}

impl Default for ProgramRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramRegistry {
    pub fn new() -> Self {
        Self {
            programs: BTreeMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut reg = Self::new();
        reg.register(Box::new(SystemProgram));
        reg.register(Box::new(TokenProgram));
        reg
    }

    pub fn register(&mut self, program: Box<dyn SvmProgram>) {
        self.programs.insert(program.program_id(), program);
    }

    pub fn get(&self, id: &[u8; 32]) -> Option<&dyn SvmProgram> {
        self.programs.get(id).map(|p| p.as_ref())
    }
}

// ── Program IDs ──

/// System Program: `[0..0, 0x01]`
pub const SYSTEM_PROGRAM_ID: [u8; 32] = {
    let mut id = [0u8; 32];
    id[31] = 0x01;
    id
};

/// Token Program: `[0..0, 0x02]`
pub const TOKEN_PROGRAM_ID: [u8; 32] = {
    let mut id = [0u8; 32];
    id[31] = 0x02;
    id
};

// ── System Program ──

/// Handles native transfers and account creation.
///
/// Instructions:
/// - `0x00` Transfer: `accounts[0]=recipient`, `data[1..9]=amount(u64 LE)`
/// - `0x01` CreateAccount: `accounts[0]=new_account_id`
pub struct SystemProgram;

impl SvmProgram for SystemProgram {
    fn program_id(&self) -> [u8; 32] {
        SYSTEM_PROGRAM_ID
    }
    fn name(&self) -> &str {
        "SystemProgram"
    }

    fn execute(
        &self,
        state: &mut StateTree,
        caller: &AccountId,
        accounts: &[[u8; 32]],
        data: &[u8],
    ) -> Result<Vec<StateChange>, String> {
        if data.is_empty() {
            return Err("empty instruction data".into());
        }

        match data[0] {
            0x00 => {
                // Transfer
                if accounts.is_empty() {
                    return Err("transfer: missing recipient".into());
                }
                if data.len() < 9 {
                    return Err("transfer: data too short".into());
                }
                let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let to = AccountId::from_bytes(accounts[0]);
                ace_engine::transfer::transfer(state, caller, &to, amount, None)
                    .map_err(|e| e.to_string())
            }
            0x01 => {
                // CreateAccount
                if accounts.is_empty() {
                    return Err("create_account: missing account id".into());
                }
                let new_id = AccountId::from_bytes(accounts[0]);
                if state.contains(&new_id) {
                    return Err("account already exists".into());
                }
                state.insert(Account::new(new_id));
                Ok(vec![StateChange::AccountCreated { account: new_id }])
            }
            other => Err(format!("SystemProgram: unknown instruction 0x{other:02x}")),
        }
    }
}

// ── Token Program ──

/// Runtime token program shared by SPL and ERC-20 compatibility layers.
///
/// Instructions:
/// - `0x00` CreateMint: `accounts[0]=mint_id`, `data[1]=decimals`
/// - `0x01` MintToOwner: `accounts[0]=mint_id, accounts[1]=owner_idcom`, `data[1..9]=amount`
/// - `0x02` TransferOwnerBalance: `accounts[0]=mint_id, accounts[1]=recipient_idcom`, `data[1..9]=amount`
/// - `0x03` Approve: `accounts[0]=mint_id, accounts[1]=spender_idcom`, `data[1..9]=amount`
/// - `0x04` TransferFrom: `accounts[0]=mint_id, accounts[1]=owner_idcom, accounts[2]=recipient_idcom`, `data[1..9]=amount`
/// - `0x10` RegisterTokenAccount: `accounts[0]=token_account, accounts[1]=mint_id, accounts[2]=owner_sol_pubkey`
/// - `0x11` SplTransfer: `accounts[0]=source_token_account, accounts[1]=dest_token_account, accounts[2]=authority_pubkey`, `data[1..9]=amount`
/// - `0x12` SplTransferChecked: `accounts[0]=source_token_account, accounts[1]=mint_id, accounts[2]=dest_token_account, accounts[3]=authority_pubkey`, `data[1..9]=amount, data[9]=decimals`
/// - `0x13` SplTransferWithAta: `accounts[0]=source_token_account, accounts[1]=dest_token_account, accounts[2]=authority_pubkey, accounts[3]=dest_owner_pubkey`, `data[1..9]=amount`
/// - `0x14` SplTransferCheckedWithAta: `accounts[0]=source_token_account, accounts[1]=mint_id, accounts[2]=dest_token_account, accounts[3]=authority_pubkey, accounts[4]=dest_owner_pubkey`, `data[1..9]=amount, data[9]=decimals`
/// - `0x15` EnsureTokenAccount: `accounts[0]=token_account, accounts[1]=mint_id, accounts[2]=owner_sol_pubkey`
pub struct TokenProgram;

impl SvmProgram for TokenProgram {
    fn program_id(&self) -> [u8; 32] {
        TOKEN_PROGRAM_ID
    }
    fn name(&self) -> &str {
        "TokenProgram"
    }

    fn execute(
        &self,
        state: &mut StateTree,
        caller: &AccountId,
        accounts: &[[u8; 32]],
        data: &[u8],
    ) -> Result<Vec<StateChange>, String> {
        if data.is_empty() {
            return Err("empty instruction data".into());
        }

        let mut state_changes = Vec::new();
        if let Some(change) = token_runtime::ensure_token_program_account(state) {
            state_changes.push(change);
        }

        match data[0] {
            // CreateMint
            0x00 => {
                if accounts.is_empty() || data.len() < 2 {
                    return Err("create_mint: missing args".into());
                }
                // The caller becomes the mint authority
                let mut changes =
                    token_runtime::create_mint(state, &accounts[0], data[1], caller.as_bytes())?;
                state_changes.append(&mut changes);
                Ok(state_changes)
            }
            // MintToOwner
            0x01 => {
                if accounts.len() < 2 || data.len() < 9 {
                    return Err("mint_to: missing args".into());
                }
                let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let mut changes = token_runtime::mint_to_owner(
                    state,
                    &accounts[0],
                    &accounts[1],
                    amount,
                    caller,
                )?;
                state_changes.append(&mut changes);
                Ok(state_changes)
            }
            // Transfer owner balance
            0x02 => {
                if accounts.len() < 2 || data.len() < 9 {
                    return Err("token_transfer: missing args".into());
                }
                let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let recipient = AccountId::from_bytes(accounts[1]);
                let mut changes = token_runtime::transfer_between_owners(
                    state,
                    &accounts[0],
                    caller,
                    &recipient,
                    amount,
                )?;
                state_changes.append(&mut changes);
                Ok(state_changes)
            }
            // Approve
            0x03 => {
                if accounts.len() < 2 || data.len() < 9 {
                    return Err("approve: missing args".into());
                }
                let spender = AccountId::from_bytes(accounts[1]);
                let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let mut changes =
                    token_runtime::set_allowance(state, &accounts[0], caller, &spender, amount)?;
                state_changes.append(&mut changes);
                Ok(state_changes)
            }
            // TransferFrom
            0x04 => {
                if accounts.len() < 3 || data.len() < 9 {
                    return Err("transfer_from: missing args".into());
                }
                let owner = AccountId::from_bytes(accounts[1]);
                let recipient = AccountId::from_bytes(accounts[2]);
                let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let mut changes = token_runtime::transfer_from(
                    state,
                    &accounts[0],
                    caller,
                    &owner,
                    &recipient,
                    amount,
                )?;
                state_changes.append(&mut changes);
                Ok(state_changes)
            }
            // RegisterTokenAccount
            0x10 => {
                if accounts.len() < 3 {
                    return Err("register_token_account: missing args".into());
                }
                let owner_idcom = ace_runtime::crypto::legacy_idcom_solana(&accounts[2]);
                let mut changes = token_runtime::register_token_account(
                    state,
                    &accounts[0],
                    &accounts[1],
                    &accounts[2],
                    &owner_idcom,
                )?;
                state_changes.append(&mut changes);
                Ok(state_changes)
            }
            // SplTransfer
            0x11 => {
                if accounts.len() < 3 || data.len() < 9 {
                    return Err("spl_transfer: missing args".into());
                }
                let source = token_runtime::get_token_account_meta(state, &accounts[0])
                    .ok_or("unknown source token account")?;
                let destination = token_runtime::get_token_account_meta(state, &accounts[1])
                    .ok_or("unknown destination token account")?;
                if source.mint != destination.mint {
                    return Err("token account mint mismatch".into());
                }
                // Verify the authenticated caller owns the source account.
                // accounts[2] is untrusted user input — we must check the caller's
                // identity commitment against the on-chain owner_idcom.
                if *caller != AccountId::from_bytes(source.owner_idcom) {
                    return Err("spl transfer: caller does not own the source account".into());
                }
                let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let mut changes = token_runtime::transfer_between_owners(
                    state,
                    &source.mint,
                    &AccountId::from_bytes(source.owner_idcom),
                    &AccountId::from_bytes(destination.owner_idcom),
                    amount,
                )?;
                state_changes.append(&mut changes);
                Ok(state_changes)
            }
            // SplTransferChecked
            0x12 => {
                if accounts.len() < 4 || data.len() < 10 {
                    return Err("spl_transfer_checked: missing args".into());
                }
                let source = token_runtime::get_token_account_meta(state, &accounts[0])
                    .ok_or("unknown source token account")?;
                let destination = token_runtime::get_token_account_meta(state, &accounts[2])
                    .ok_or("unknown destination token account")?;
                if source.mint != accounts[1] || destination.mint != accounts[1] {
                    return Err("token account mint mismatch".into());
                }
                // Verify authenticated caller owns the source account
                if *caller != AccountId::from_bytes(source.owner_idcom) {
                    return Err(
                        "spl transfer checked: caller does not own the source account".into(),
                    );
                }
                let mint = token_runtime::get_mint_meta(state, &accounts[1])
                    .ok_or("mint does not exist")?;
                if data[9] != mint.decimals {
                    return Err("spl transfer checked decimals mismatch".into());
                }
                let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let mut changes = token_runtime::transfer_between_owners(
                    state,
                    &accounts[1],
                    &AccountId::from_bytes(source.owner_idcom),
                    &AccountId::from_bytes(destination.owner_idcom),
                    amount,
                )?;
                state_changes.append(&mut changes);
                Ok(state_changes)
            }
            // SplTransferWithAta
            0x13 => {
                if accounts.len() < 4 || data.len() < 9 {
                    return Err("spl_transfer_with_ata: missing args".into());
                }
                let source = token_runtime::get_token_account_meta(state, &accounts[0])
                    .ok_or("unknown source token account")?;
                // Verify authenticated caller owns the source account
                if *caller != AccountId::from_bytes(source.owner_idcom) {
                    return Err(
                        "spl transfer with ata: caller does not own the source account".into(),
                    );
                }
                let destination_meta = if let Some(meta) =
                    token_runtime::get_token_account_meta(state, &accounts[1])
                {
                    if meta.mint != source.mint || meta.owner_sol_pubkey != accounts[3] {
                        return Err("destination token account metadata mismatch".into());
                    }
                    meta
                } else {
                    let expected_ata =
                        token_runtime::derive_associated_token_address(&accounts[3], &source.mint);
                    if expected_ata != accounts[1] {
                        return Err("destination token account is not the expected ATA".into());
                    }
                    let owner_idcom = ace_runtime::crypto::legacy_idcom_solana(&accounts[3]);
                    let mut create_changes = token_runtime::ensure_registered_token_account(
                        state,
                        &accounts[1],
                        &source.mint,
                        &accounts[3],
                        &owner_idcom,
                    )?;
                    state_changes.append(&mut create_changes);
                    token_runtime::get_token_account_meta(state, &accounts[1])
                        .ok_or("failed to create destination token account")?
                };
                let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let mut changes = token_runtime::transfer_between_owners(
                    state,
                    &source.mint,
                    &AccountId::from_bytes(source.owner_idcom),
                    &AccountId::from_bytes(destination_meta.owner_idcom),
                    amount,
                )?;
                state_changes.append(&mut changes);
                Ok(state_changes)
            }
            // SplTransferCheckedWithAta
            0x14 => {
                if accounts.len() < 5 || data.len() < 10 {
                    return Err("spl_transfer_checked_with_ata: missing args".into());
                }
                let source = token_runtime::get_token_account_meta(state, &accounts[0])
                    .ok_or("unknown source token account")?;
                // Verify authenticated caller owns the source account
                if *caller != AccountId::from_bytes(source.owner_idcom) {
                    return Err(
                        "spl transfer checked with ata: caller does not own the source account"
                            .into(),
                    );
                }
                if source.mint != accounts[1] {
                    return Err("source token account mint mismatch".into());
                }
                let mint = token_runtime::get_mint_meta(state, &accounts[1])
                    .ok_or("mint does not exist")?;
                if data[9] != mint.decimals {
                    return Err("spl transfer checked decimals mismatch".into());
                }
                let destination_meta = if let Some(meta) =
                    token_runtime::get_token_account_meta(state, &accounts[2])
                {
                    if meta.mint != accounts[1] || meta.owner_sol_pubkey != accounts[4] {
                        return Err("destination token account metadata mismatch".into());
                    }
                    meta
                } else {
                    let expected_ata =
                        token_runtime::derive_associated_token_address(&accounts[4], &accounts[1]);
                    if expected_ata != accounts[2] {
                        return Err("destination token account is not the expected ATA".into());
                    }
                    let owner_idcom = ace_runtime::crypto::legacy_idcom_solana(&accounts[4]);
                    let mut create_changes = token_runtime::ensure_registered_token_account(
                        state,
                        &accounts[2],
                        &accounts[1],
                        &accounts[4],
                        &owner_idcom,
                    )?;
                    state_changes.append(&mut create_changes);
                    token_runtime::get_token_account_meta(state, &accounts[2])
                        .ok_or("failed to create destination token account")?
                };
                let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let mut changes = token_runtime::transfer_between_owners(
                    state,
                    &accounts[1],
                    &AccountId::from_bytes(source.owner_idcom),
                    &AccountId::from_bytes(destination_meta.owner_idcom),
                    amount,
                )?;
                state_changes.append(&mut changes);
                Ok(state_changes)
            }
            // EnsureTokenAccount
            0x15 => {
                if accounts.len() < 3 {
                    return Err("ensure_token_account: missing args".into());
                }
                let owner_idcom = ace_runtime::crypto::legacy_idcom_solana(&accounts[2]);
                let mut changes = token_runtime::ensure_registered_token_account(
                    state,
                    &accounts[0],
                    &accounts[1],
                    &accounts[2],
                    &owner_idcom,
                )?;
                state_changes.append(&mut changes);
                Ok(state_changes)
            }
            other => Err(format!("TokenProgram: unknown instruction 0x{other:02x}")),
        }
    }
}
