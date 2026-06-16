use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Move module identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ModuleId {
    pub address: [u8; 32],
    pub name: [u8; 32],
}

impl ModuleId {
    pub fn new(address: [u8; 32], name: &str) -> Self {
        let mut name_bytes = [0u8; 32];
        let name_str = name.as_bytes();
        let len = std::cmp::min(name_str.len(), 32);
        name_bytes[..len].copy_from_slice(&name_str[..len]);
        Self { address, name: name_bytes }
    }
}

/// Move struct identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StructId {
    pub module: ModuleId,
    pub name: String,
}

/// Move resource
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    pub struct_id: StructId,
    pub data: Vec<u8>,
}

/// Move transaction format
/// Opcode: 0x50-0x5F for Move VM
/// Format: [opcode:1][nonce:8 LE][module_addr:32][module_name:32][func_name_len:2 LE][func_name:var][args_count:2 LE][args:var]
#[derive(Debug, Clone)]
pub struct MoveTxPayload {
    pub nonce: u64,
    pub module_address: [u8; 32],
    pub module_name: String,
    pub function_name: String,
    pub args: Vec<MoveValue>,
}

/// Move value types for arguments
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveValue {
    Bool(bool),
    U8(u8),
    U64(u64),
    U128(u128),
    Address([u8; 32]),
    Vector(Vec<MoveValue>),
    Bytes(Vec<u8>),
}

impl MoveValue {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            MoveValue::U64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_address(&self) -> Option<&[u8; 32]> {
        match self {
            MoveValue::Address(addr) => Some(addr),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            MoveValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Move module code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveModule {
    pub id: ModuleId,
    pub bytecode: Vec<u8>,
    pub abi: ModuleAbi,
}

/// Module ABI (minimal)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleAbi {
    pub functions: BTreeMap<String, FunctionAbi>,
    pub structs: BTreeMap<String, StructAbi>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAbi {
    pub name: String,
    pub visibility: Visibility,
    pub parameters: Vec<String>,
    pub return_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructAbi {
    pub name: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Visibility {
    Private,
    Public,
    Friend,
}

/// Move execution result
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub success: bool,
    pub return_values: Vec<MoveValue>,
    pub events: Vec<MoveEvent>,
    pub resources_created: BTreeMap<StructId, Resource>,
    pub resources_modified: BTreeMap<StructId, Resource>,
    pub gas_used: u64,
}

/// Move event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveEvent {
    pub struct_id: StructId,
    pub data: Vec<u8>,
}
