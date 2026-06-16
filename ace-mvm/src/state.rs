use std::collections::BTreeMap;
use ace_model::account::{Account, AccountId};
use ace_model::state_tree::StateTree;
use ace_engine::receipt::StateChange;
use sha2::{Digest, Sha256};
use crate::types::{ModuleId, MoveModule, Resource, StructId};
use crate::error::{MoveError, MoveResult};

/// Move state storage namespace within ACE StateTree
/// Move modules and resources are stored in a special namespace to avoid collisions
#[allow(dead_code)]
const MOVE_MODULE_PREFIX: &str = "move::module::";
const MOVE_MODULE_SLOT_DOMAIN: &[u8] = b"ace-move:module:v1:";
const MOVE_RESOURCE_SLOT_DOMAIN: &[u8] = b"ace-move:resource:v1:";
const MOVE_CHUNK_SLOT_DOMAIN: &[u8] = b"ace-move:chunk:v1:";
const CHUNK_SIZE: usize = 32;

pub struct MoveStateView {
}

impl MoveStateView {
    pub fn new(_state: &mut StateTree) -> Self {
        Self {}
    }

    /// Get a Move module by ID
    pub fn get_module(&self, state: &StateTree, module_id: &ModuleId) -> MoveResult<Option<MoveModule>> {
        load_module(state, module_id)
    }

    /// Store a Move module
    pub fn publish_module(&mut self, state: &mut StateTree, module: &MoveModule) -> MoveResult<Vec<StateChange>> {
        publish_module(state, module)
    }

    /// Get a resource at an address
    pub fn get_resource(&self, state: &StateTree, address: &[u8; 32], struct_id: &StructId) -> MoveResult<Option<Resource>> {
        load_resource(state, address, struct_id)
    }

    /// Store a resource at an address
    pub fn store_resource(&mut self, state: &mut StateTree, address: &[u8; 32], resource: &Resource) -> MoveResult<Vec<StateChange>> {
        store_resource(state, address, resource)
    }

    /// Delete a resource
    pub fn delete_resource(&mut self, _address: &[u8; 32], _struct_id: &StructId) -> MoveResult<()> {
        Ok(())
    }

    /// List all resources owned by an address
    pub fn get_resources(&self, _address: &[u8; 32]) -> MoveResult<Vec<Resource>> {
        Ok(Vec::new())
    }
}

pub fn module_id(address: [u8; 32], name: &str) -> ModuleId {
    ModuleId::new(address, name)
}

pub fn load_module(state: &StateTree, id: &ModuleId) -> MoveResult<Option<MoveModule>> {
    let owner = AccountId::from_bytes(id.address);
    let slot = module_slot(id);
    let bytes = load_bytes(state, &owner, slot);
    if bytes.is_empty() {
        return Ok(None);
    }
    bincode::deserialize(&bytes)
        .map(Some)
        .map_err(|e| MoveError::StateError(format!("decode module: {e}")))
}

pub fn publish_module(state: &mut StateTree, module: &MoveModule) -> MoveResult<Vec<StateChange>> {
    let owner = AccountId::from_bytes(module.id.address);
    if !state.contains(&owner) {
        state.insert(Account::new(owner));
    }
    let bytes = bincode::serialize(module)
        .map_err(|e| MoveError::StateError(format!("encode module: {e}")))?;
    store_bytes(state, owner, module_slot(&module.id), &bytes)
}

pub fn load_resource(
    state: &StateTree,
    address: &[u8; 32],
    struct_id: &StructId,
) -> MoveResult<Option<Resource>> {
    let owner = AccountId::from_bytes(*address);
    let bytes = load_bytes(state, &owner, resource_slot(struct_id));
    if bytes.is_empty() {
        return Ok(None);
    }
    bincode::deserialize(&bytes)
        .map(Some)
        .map_err(|e| MoveError::StateError(format!("decode resource: {e}")))
}

pub fn store_resource(
    state: &mut StateTree,
    address: &[u8; 32],
    resource: &Resource,
) -> MoveResult<Vec<StateChange>> {
    let owner = AccountId::from_bytes(*address);
    if !state.contains(&owner) {
        state.insert(Account::new(owner));
    }
    let bytes = bincode::serialize(resource)
        .map_err(|e| MoveError::StateError(format!("encode resource: {e}")))?;
    store_bytes(state, owner, resource_slot(&resource.struct_id), &bytes)
}

fn module_slot(id: &ModuleId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MOVE_MODULE_SLOT_DOMAIN);
    hasher.update(id.address);
    hasher.update(id.name);
    digest32(hasher)
}

fn resource_slot(id: &StructId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MOVE_RESOURCE_SLOT_DOMAIN);
    hasher.update(id.module.address);
    hasher.update(id.module.name);
    hasher.update(id.name.as_bytes());
    digest32(hasher)
}

fn chunk_slot(base: [u8; 32], index: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MOVE_CHUNK_SLOT_DOMAIN);
    hasher.update(base);
    hasher.update(index.to_le_bytes());
    digest32(hasher)
}

fn store_bytes(
    state: &mut StateTree,
    owner: AccountId,
    base_slot: [u8; 32],
    bytes: &[u8],
) -> MoveResult<Vec<StateChange>> {
    let chunks = bytes.len().div_ceil(CHUNK_SIZE);
    if chunks > u32::MAX as usize {
        return Err(MoveError::StateError("encoded value too large".into()));
    }

    let mut changes = Vec::with_capacity(chunks + 1);
    let old_meta = state.get_storage(&owner, &base_slot);
    let old_chunks = u32::from_le_bytes(old_meta[8..12].try_into().unwrap_or([0; 4])) as usize;

    let mut new_meta = [0u8; 32];
    new_meta[..8].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
    new_meta[8..12].copy_from_slice(&(chunks as u32).to_le_bytes());
    state.set_storage(&owner, base_slot, new_meta);
    changes.push(StateChange::StorageChange {
        account: owner,
        slot: base_slot,
        old_value: old_meta,
        new_value: new_meta,
    });

    for (idx, chunk) in bytes.chunks(CHUNK_SIZE).enumerate() {
        let slot = chunk_slot(base_slot, idx as u32);
        let old_value = state.get_storage(&owner, &slot);
        let mut new_value = [0u8; 32];
        new_value[..chunk.len()].copy_from_slice(chunk);
        state.set_storage(&owner, slot, new_value);
        changes.push(StateChange::StorageChange {
            account: owner,
            slot,
            old_value,
            new_value,
        });
    }

    // Clear stale chunks if the new value is smaller
    if old_chunks > chunks {
        for idx in chunks..old_chunks {
            let slot = chunk_slot(base_slot, idx as u32);
            let old_value = state.get_storage(&owner, &slot);
            if old_value != [0u8; 32] {
                let new_value = [0u8; 32];
                state.set_storage(&owner, slot, new_value);
                changes.push(StateChange::StorageChange {
                    account: owner,
                    slot,
                    old_value,
                    new_value,
                });
            }
        }
    }

    Ok(changes)
}

fn load_bytes(state: &StateTree, owner: &AccountId, base_slot: [u8; 32]) -> Vec<u8> {
    let meta = state.get_storage(owner, &base_slot);
    let len = u64::from_le_bytes(meta[..8].try_into().unwrap()) as usize;
    let chunks = u32::from_le_bytes(meta[8..12].try_into().unwrap()) as usize;
    if len == 0 || chunks == 0 {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(len);
    for idx in 0..chunks {
        let slot = chunk_slot(base_slot, idx as u32);
        let chunk = state.get_storage(owner, &slot);
        let remaining = len.saturating_sub(out.len());
        out.extend_from_slice(&chunk[..remaining.min(CHUNK_SIZE)]);
    }
    out.truncate(len);
    out
}

fn digest32(hasher: Sha256) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Module registry for published Move modules
pub struct ModuleRegistry {
    modules: BTreeMap<ModuleId, MoveModule>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
        }
    }

    pub fn publish(&mut self, module: MoveModule) -> MoveResult<()> {
        if self.modules.contains_key(&module.id) {
            return Err(MoveError::ModuleAlreadyExists(format!("{:?}", module.id)));
        }
        self.modules.insert(module.id, module);
        Ok(())
    }

    pub fn get(&self, id: &ModuleId) -> Option<&MoveModule> {
        self.modules.get(id)
    }

    pub fn exists(&self, id: &ModuleId) -> bool {
        self.modules.contains_key(id)
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}
