//! Context-based shard routing.
//!
//! Each VM context maps to one of NUM_SHARDS shards via
//! SHA-256("vm:context_tag") % NUM_SHARDS.

use sha2::{Digest, Sha256};

/// Number of execution shards.
pub const NUM_SHARDS: u64 = 64;

/// Shard identifier (0..NUM_SHARDS-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShardId(pub u64);

pub const DEFAULT_SHARD: ShardId = ShardId(0);

impl ShardId {
    /// Derive shard from a VM context string.
    ///
    /// Formula: SHA-256(len(vm_prefix) || vm_prefix || context_tag) mod NUM_SHARDS
    ///
    /// Length-prefixing prevents ambiguity: `("evm:foo","bar")` and
    /// `("evm","foo:bar")` produce different hashes.
    pub fn from_context(vm_prefix: &str, context_tag: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((vm_prefix.len() as u32).to_le_bytes());
        hasher.update(vm_prefix.as_bytes());
        hasher.update(context_tag.as_bytes());
        let result = hasher.finalize();

        // Read first 8 bytes as u64 for modulo
        let val = u64::from_be_bytes([
            result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
        ]);

        ShardId(val % NUM_SHARDS)
    }

    pub fn from_tx(opcode: u8, context_tag: &[u8; 16]) -> Self {
        if *context_tag == [0u8; 16] {
            return DEFAULT_SHARD;
        }
        let vm_prefix = match opcode {
            0x01..=0x0F => "native",
            0x10..=0x1F => "evm",
            0x20..=0x2F => "svm",
            0x30..=0x3F => "bvm",
            0x40..=0x4F => "tvm",
            _ => "unknown",
        };
        let mut hasher = Sha256::new();
        hasher.update((vm_prefix.len() as u32).to_le_bytes());
        hasher.update(vm_prefix.as_bytes());
        hasher.update(context_tag);
        let result = hasher.finalize();
        let val = u64::from_be_bytes([
            result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
        ]);
        ShardId(val % NUM_SHARDS)
    }
}

/// Reserved shard for cross-context transactions.
///
/// Transactions that touch accounts in multiple shards are routed here
/// and executed serially to ensure atomicity (Strategy B from the paper).
pub const SHARED_SHARD: ShardId = ShardId(u64::MAX);

impl ShardId {
    /// Returns true if this is the shared (cross-context) shard.
    pub fn is_shared(&self) -> bool {
        *self == SHARED_SHARD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_shard_is_zero() {
        assert_eq!(DEFAULT_SHARD.0, 0);
    }

    #[test]
    fn shared_shard_is_max() {
        assert_eq!(SHARED_SHARD.0, u64::MAX);
        assert!(SHARED_SHARD.is_shared());
        assert!(!DEFAULT_SHARD.is_shared());
    }

    #[test]
    fn zero_context_tag_routes_to_default() {
        assert_eq!(ShardId::from_tx(0x01, &[0u8; 16]), DEFAULT_SHARD);
    }

    #[test]
    fn nonzero_context_tag_routes_deterministically() {
        let tag = [1u8; 16];
        let s1 = ShardId::from_tx(0x01, &tag);
        let s2 = ShardId::from_tx(0x01, &tag);
        assert_eq!(s1, s2);
        assert!(s1.0 < NUM_SHARDS);
    }

    #[test]
    fn different_contexts_may_differ() {
        let tag_a = [1u8; 16];
        let tag_b = [2u8; 16];
        let sa = ShardId::from_tx(0x01, &tag_a);
        let sb = ShardId::from_tx(0x01, &tag_b);
        // They CAN be equal by hash collision, but with 64 shards it's unlikely
        // for these specific inputs. Just check they're valid.
        assert!(sa.0 < NUM_SHARDS);
        assert!(sb.0 < NUM_SHARDS);
    }
}
