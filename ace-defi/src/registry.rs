//! Wrapped asset registry.
//!
//! Tracks which external assets have been registered on ACE Chain and
//! ensures their wrapped mint accounts exist in the state tree.

use std::collections::HashSet;

use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_runtime::crypto::TaggedPubkey;

use crate::error::BridgeError;
use crate::types::{
    bridge_authority_id, native_decimals, wrapped_mint_id, ExternalAsset, ExternalChain,
};

/// Manages which external assets have corresponding wrapped mints on ACE Chain.
#[derive(Debug, Default)]
pub struct AssetRegistry {
    registered: HashSet<AccountId>,
}

impl AssetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an external asset, creating its wrapped mint in the state tree.
    ///
    /// Uses `token_runtime::create_mint` to set up the mint with the bridge
    /// authority as the mint authority.
    pub fn register_asset(
        &mut self,
        state: &mut StateTree,
        asset: &ExternalAsset,
        decimals: u8,
    ) -> Result<AccountId, BridgeError> {
        let mint_id = wrapped_mint_id(asset);
        let authority = bridge_authority_id();

        // Ensure bridge authority account exists
        if !state.contains(&authority) {
            let mut acct = Account::new(authority);
            acct.auth_pubkey = TaggedPubkey::ed25519([0u8; 32]); // placeholder
            state.insert(acct);
        }

        if self.is_registered(asset, state) {
            self.registered.insert(mint_id);
            return Ok(mint_id);
        }

        // Create the mint via token_runtime
        ace_n_vm::token_runtime::create_mint(
            state,
            mint_id.as_bytes(),
            decimals,
            authority.as_bytes(),
        )
        .map_err(|e| BridgeError::MintError(e))?;

        self.registered.insert(mint_id);
        Ok(mint_id)
    }

    /// Register all native tokens for the supported external chains.
    pub fn register_all_natives(&mut self, state: &mut StateTree) -> Result<(), BridgeError> {
        for chain in ExternalChain::all() {
            let asset = ExternalAsset::Native(*chain);
            let decimals = native_decimals(*chain);
            self.register_asset(state, &asset, decimals)?;
        }
        Ok(())
    }

    /// Check if an asset is registered (in-memory or state tree).
    pub fn is_registered(&self, asset: &ExternalAsset, state: &StateTree) -> bool {
        let mint_id = wrapped_mint_id(asset);
        if self.registered.contains(&mint_id) {
            return true;
        }
        ace_n_vm::token_runtime::get_mint_meta(state, mint_id.as_bytes()).is_some()
    }

    /// Get the wrapped mint AccountId for an asset (if registered).
    pub fn mint_id(&self, asset: &ExternalAsset) -> Option<AccountId> {
        let id = wrapped_mint_id(asset);
        self.registered.contains(&id).then_some(id)
    }

    pub fn registered_count(&self) -> usize {
        self.registered.len()
    }
}
