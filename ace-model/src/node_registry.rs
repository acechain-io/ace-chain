//! Node registry for KYC-gated admission.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::account::AccountId;

/// Maximum number of nodes in the network.
pub const DEFAULT_MAX_NODES: u32 = 10_000;

/// Default smoothed performance score (1.00x expressed in basis points).
pub const DEFAULT_PERF_EMA_BPS: u16 = 10_000;

/// KYC review state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KycStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

/// Node status in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is approved but queued outside the active set.
    Standby,
    /// Node is approved and actively participating.
    Active,
    /// Node is temporarily suspended (e.g., resource violation).
    Suspended,
    /// Node has been removed from the network.
    Removed,
}

/// Information about a registered node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Identity commitment of the node operator.
    pub id_com: AccountId,
    /// Node status.
    pub status: NodeStatus,
    /// Registration timestamp (Unix ms).
    pub registered_at_ms: u64,
    /// First activation timestamp (Unix ms).
    #[serde(default)]
    pub activated_at_ms: u64,
    /// Human-readable label (optional).
    pub label: String,
    /// Number of affiliates managed by this node.
    pub affiliate_count: u32,
    /// Jurisdiction code used for allow/deny policy.
    #[serde(default)]
    pub jurisdiction_code: String,
    /// Current KYC review state.
    #[serde(default = "default_kyc_status")]
    pub kyc_status: KycStatus,
    /// Last KYC review timestamp.
    #[serde(default)]
    pub kyc_reviewed_at_ms: u64,
    /// KYC expiry timestamp if the approval is temporary.
    #[serde(default)]
    pub kyc_expires_at_ms: Option<u64>,
    /// Whether this node represents a natural person.
    #[serde(default = "default_false")]
    pub natural_person: bool,
    /// Queue position when the node is waiting in standby.
    #[serde(default)]
    pub standby_rank: Option<u32>,
    /// Smoothed performance score in basis points.
    #[serde(default = "default_perf_ema_bps")]
    pub perf_ema_bps: u16,
    /// Successful leadership observations in the current epoch.
    #[serde(default)]
    pub current_epoch_successes: u32,
    /// Failed leadership observations in the current epoch.
    #[serde(default)]
    pub current_epoch_failures: u32,
}

fn default_false() -> bool {
    false
}

fn default_kyc_status() -> KycStatus {
    KycStatus::Pending
}

fn default_perf_ema_bps() -> u16 {
    DEFAULT_PERF_EMA_BPS
}

impl NodeInfo {
    /// Returns true when this node is eligible to participate in consensus.
    pub fn is_consensus_eligible(&self, now_ms: u64) -> bool {
        self.status == NodeStatus::Active && self.natural_person && self.is_kyc_approved(now_ms)
    }

    /// Returns true when the node remains KYC-approved at `now_ms`.
    pub fn is_kyc_approved(&self, now_ms: u64) -> bool {
        self.kyc_status == KycStatus::Approved
            && self
                .kyc_expires_at_ms
                .is_none_or(|expiry| expiry == 0 || expiry >= now_ms)
    }

    /// Returns the capped node age in whole months.
    pub fn capped_age_months(&self, now_ms: u64, cap_months: u64) -> u64 {
        let anchor = if self.activated_at_ms == 0 {
            self.registered_at_ms
        } else {
            self.activated_at_ms
        };
        if now_ms <= anchor {
            return 0;
        }
        let month_ms = 30 * 24 * 60 * 60 * 1000u64;
        ((now_ms - anchor) / month_ms).min(cap_months)
    }
}

/// Trait for node registry operations.
pub trait NodeRegistry: Send + Sync {
    /// Register a new node (after KYC approval).
    fn register_node(&mut self, info: NodeInfo) -> Result<(), RegistryError>;

    /// Get node info by identity commitment.
    fn get_node(&self, id_com: &AccountId) -> Option<&NodeInfo>;

    /// Get mutable node info by identity commitment.
    fn get_node_mut(&mut self, id_com: &AccountId) -> Option<&mut NodeInfo>;

    /// Update node status.
    fn set_status(&mut self, id_com: &AccountId, status: NodeStatus) -> Result<(), RegistryError>;

    /// Get all active nodes.
    fn active_nodes(&self) -> Vec<&NodeInfo>;

    /// Get all standby nodes.
    fn standby_nodes(&self) -> Vec<&NodeInfo>;

    /// Get the total number of registered (non-removed) nodes.
    fn node_count(&self) -> u32;

    /// Check if the registry has capacity for more nodes.
    fn has_capacity(&self) -> bool;

    /// Get the current maximum node capacity.
    fn max_nodes(&self) -> u32;

    /// Update the maximum node capacity (used by admission controller).
    fn set_max_nodes(&mut self, max_nodes: u32);
}

/// Registry errors.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("node already registered: {0}")]
    AlreadyRegistered(AccountId),

    #[error("node not found: {0}")]
    NotFound(AccountId),

    #[error("registry at capacity ({0} nodes)")]
    AtCapacity(u32),
}

/// In-memory node registry implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InMemoryNodeRegistry {
    #[serde(with = "crate::serde_account_id::btree_map")]
    nodes: BTreeMap<AccountId, NodeInfo>,
    max_nodes: u32,
}

impl InMemoryNodeRegistry {
    /// Create a new registry with default capacity.
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            max_nodes: DEFAULT_MAX_NODES,
        }
    }

    /// Create with a custom max node count.
    pub fn with_capacity(max_nodes: u32) -> Self {
        Self {
            nodes: BTreeMap::new(),
            max_nodes,
        }
    }

    /// Initialize from a genesis-approved set of nodes.
    pub fn from_genesis(approved: Vec<NodeInfo>, max_nodes: u32) -> Self {
        let mut nodes = BTreeMap::new();
        for info in approved {
            nodes.insert(info.id_com, info);
        }
        Self { nodes, max_nodes }
    }

    /// Promote up to `count` standby nodes to Active status.
    ///
    /// Nodes are promoted in priority order: lowest `standby_rank` first,
    /// then earliest `registered_at_ms` as a tiebreaker.
    ///
    /// Returns the list of promoted node identity commitments.
    pub fn promote_standby(&mut self, count: u32, now_ms: u64) -> Vec<AccountId> {
        // Collect standby node IDs sorted by priority.
        let mut standby: Vec<(AccountId, Option<u32>, u64)> = self
            .nodes
            .values()
            .filter(|n| n.status == NodeStatus::Standby)
            .map(|n| (n.id_com, n.standby_rank, n.registered_at_ms))
            .collect();

        // Lower rank = higher priority; None ranks after all numbered ranks.
        standby.sort_by(|a, b| {
            let rank_a = a.1.unwrap_or(u32::MAX);
            let rank_b = b.1.unwrap_or(u32::MAX);
            rank_a.cmp(&rank_b).then(a.2.cmp(&b.2))
        });

        let promote_count = (count as usize).min(standby.len());
        let mut promoted = Vec::with_capacity(promote_count);

        for (id_com, _, _) in standby.into_iter().take(promote_count) {
            if let Some(entry) = self.nodes.get_mut(&id_com) {
                entry.status = NodeStatus::Active;
                if entry.activated_at_ms == 0 {
                    entry.activated_at_ms = now_ms;
                }
                entry.standby_rank = None;
                promoted.push(id_com);
            }
        }

        promoted
    }

    /// Update the cached affiliate count for a node.
    pub fn set_affiliate_count(
        &mut self,
        id_com: &AccountId,
        affiliate_count: u32,
    ) -> Result<(), RegistryError> {
        match self.nodes.get_mut(id_com) {
            Some(node) => {
                node.affiliate_count = affiliate_count;
                Ok(())
            }
            None => Err(RegistryError::NotFound(*id_com)),
        }
    }

    /// Return the identities of all non-removed nodes.
    pub fn registered_node_ids(&self) -> BTreeSet<AccountId> {
        self.nodes
            .values()
            .filter(|node| node.status != NodeStatus::Removed)
            .map(|node| node.id_com)
            .collect()
    }
}

impl Default for InMemoryNodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeRegistry for InMemoryNodeRegistry {
    fn register_node(&mut self, info: NodeInfo) -> Result<(), RegistryError> {
        if self.nodes.contains_key(&info.id_com) {
            return Err(RegistryError::AlreadyRegistered(info.id_com));
        }
        if !self.has_capacity() {
            return Err(RegistryError::AtCapacity(self.max_nodes));
        }
        self.nodes.insert(info.id_com, info);
        Ok(())
    }

    fn get_node(&self, id_com: &AccountId) -> Option<&NodeInfo> {
        self.nodes.get(id_com)
    }

    fn get_node_mut(&mut self, id_com: &AccountId) -> Option<&mut NodeInfo> {
        self.nodes.get_mut(id_com)
    }

    fn set_status(&mut self, id_com: &AccountId, status: NodeStatus) -> Result<(), RegistryError> {
        match self.nodes.get_mut(id_com) {
            Some(node) => {
                node.status = status;
                if status == NodeStatus::Active && node.activated_at_ms == 0 {
                    node.activated_at_ms = node.registered_at_ms;
                }
                Ok(())
            }
            None => Err(RegistryError::NotFound(*id_com)),
        }
    }

    fn active_nodes(&self) -> Vec<&NodeInfo> {
        self.nodes
            .values()
            .filter(|n| n.status == NodeStatus::Active)
            .collect()
    }

    fn standby_nodes(&self) -> Vec<&NodeInfo> {
        self.nodes
            .values()
            .filter(|n| n.status == NodeStatus::Standby)
            .collect()
    }

    fn node_count(&self) -> u32 {
        self.nodes
            .values()
            .filter(|n| n.status != NodeStatus::Removed)
            .count() as u32
    }

    fn has_capacity(&self) -> bool {
        self.node_count() < self.max_nodes
    }

    fn max_nodes(&self) -> u32 {
        self.max_nodes
    }

    fn set_max_nodes(&mut self, max_nodes: u32) {
        self.max_nodes = max_nodes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(byte: u8) -> NodeInfo {
        NodeInfo {
            id_com: AccountId([byte; 32]),
            status: NodeStatus::Active,
            registered_at_ms: 1000,
            activated_at_ms: 1000,
            label: format!("node-{byte:02x}"),
            affiliate_count: 0,
            jurisdiction_code: "CA".to_string(),
            kyc_status: KycStatus::Approved,
            kyc_reviewed_at_ms: 1000,
            kyc_expires_at_ms: None,
            natural_person: true,
            standby_rank: None,
            perf_ema_bps: DEFAULT_PERF_EMA_BPS,
            current_epoch_successes: 0,
            current_epoch_failures: 0,
        }
    }

    #[test]
    fn test_register_and_get() {
        let mut reg = InMemoryNodeRegistry::new();
        let node = make_node(0x01);
        reg.register_node(node.clone()).unwrap();

        let info = reg.get_node(&AccountId([0x01; 32])).unwrap();
        assert_eq!(info.label, "node-01");
        assert_eq!(reg.node_count(), 1);
    }

    #[test]
    fn test_duplicate_registration() {
        let mut reg = InMemoryNodeRegistry::new();
        reg.register_node(make_node(0x01)).unwrap();
        let result = reg.register_node(make_node(0x01));
        assert!(result.is_err());
    }

    #[test]
    fn test_capacity_limit() {
        let mut reg = InMemoryNodeRegistry::with_capacity(2);
        reg.register_node(make_node(0x01)).unwrap();
        reg.register_node(make_node(0x02)).unwrap();

        let result = reg.register_node(make_node(0x03));
        assert!(matches!(result, Err(RegistryError::AtCapacity(2))));
    }

    #[test]
    fn test_status_update() {
        let mut reg = InMemoryNodeRegistry::new();
        reg.register_node(make_node(0x01)).unwrap();

        reg.set_status(&AccountId([0x01; 32]), NodeStatus::Suspended)
            .unwrap();
        let info = reg.get_node(&AccountId([0x01; 32])).unwrap();
        assert_eq!(info.status, NodeStatus::Suspended);
    }

    #[test]
    fn test_active_nodes_filter() {
        let mut reg = InMemoryNodeRegistry::new();
        reg.register_node(make_node(0x01)).unwrap();
        reg.register_node(make_node(0x02)).unwrap();
        reg.set_status(&AccountId([0x02; 32]), NodeStatus::Suspended)
            .unwrap();

        let active = reg.active_nodes();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id_com, AccountId([0x01; 32]));
    }

    #[test]
    fn test_standby_nodes_filter() {
        let mut reg = InMemoryNodeRegistry::new();
        reg.register_node(make_node(0x01)).unwrap();
        reg.register_node(make_node(0x02)).unwrap();
        reg.set_status(&AccountId([0x02; 32]), NodeStatus::Standby)
            .unwrap();

        let standby = reg.standby_nodes();
        assert_eq!(standby.len(), 1);
        assert_eq!(standby[0].id_com, AccountId([0x02; 32]));
    }

    #[test]
    fn test_removed_nodes_dont_count() {
        let mut reg = InMemoryNodeRegistry::with_capacity(2);
        reg.register_node(make_node(0x01)).unwrap();
        reg.register_node(make_node(0x02)).unwrap();

        reg.set_status(&AccountId([0x01; 32]), NodeStatus::Removed)
            .unwrap();

        assert!(reg.has_capacity());
        assert_eq!(reg.node_count(), 1);
    }

    #[test]
    fn test_genesis_initialization() {
        let nodes = vec![make_node(0x01), make_node(0x02), make_node(0x03)];
        let reg = InMemoryNodeRegistry::from_genesis(nodes, 100);
        assert_eq!(reg.node_count(), 3);
        assert!(reg.has_capacity());
    }

    #[test]
    fn test_update_affiliate_count() {
        let mut reg = InMemoryNodeRegistry::new();
        reg.register_node(make_node(0x01)).unwrap();
        reg.set_affiliate_count(&AccountId([0x01; 32]), 7).unwrap();
        assert_eq!(
            reg.get_node(&AccountId([0x01; 32]))
                .unwrap()
                .affiliate_count,
            7
        );
    }

    #[test]
    fn test_promote_standby_priority_order() {
        let mut reg = InMemoryNodeRegistry::new();
        // Register 3 standby nodes with different ranks.
        let mut n1 = make_node(0x10);
        n1.status = NodeStatus::Standby;
        n1.standby_rank = Some(3);
        n1.registered_at_ms = 1000;
        reg.register_node(n1).unwrap();

        let mut n2 = make_node(0x11);
        n2.status = NodeStatus::Standby;
        n2.standby_rank = Some(1);
        n2.registered_at_ms = 2000;
        reg.register_node(n2).unwrap();

        let mut n3 = make_node(0x12);
        n3.status = NodeStatus::Standby;
        n3.standby_rank = None; // no rank → lowest priority
        n3.registered_at_ms = 500;
        reg.register_node(n3).unwrap();

        // Promote 2 of 3: should pick rank=1 first, then rank=3.
        let promoted = reg.promote_standby(2, 5000);
        assert_eq!(promoted.len(), 2);
        assert_eq!(promoted[0], AccountId([0x11; 32])); // rank 1
        assert_eq!(promoted[1], AccountId([0x10; 32])); // rank 3

        // Verify they're now Active.
        assert_eq!(
            reg.get_node(&AccountId([0x11; 32])).unwrap().status,
            NodeStatus::Active
        );
        assert_eq!(
            reg.get_node(&AccountId([0x10; 32])).unwrap().status,
            NodeStatus::Active
        );
        // n3 still Standby.
        assert_eq!(
            reg.get_node(&AccountId([0x12; 32])).unwrap().status,
            NodeStatus::Standby
        );
    }

    #[test]
    fn test_promote_standby_sets_activation_time() {
        let mut reg = InMemoryNodeRegistry::new();
        let mut n = make_node(0x20);
        n.status = NodeStatus::Standby;
        n.activated_at_ms = 0; // not yet activated
        reg.register_node(n).unwrap();

        reg.promote_standby(1, 9999);
        let node = reg.get_node(&AccountId([0x20; 32])).unwrap();
        assert_eq!(node.status, NodeStatus::Active);
        assert_eq!(node.activated_at_ms, 9999);
    }

    #[test]
    fn test_promote_standby_no_standby_nodes() {
        let mut reg = InMemoryNodeRegistry::new();
        reg.register_node(make_node(0x01)).unwrap(); // Active, not Standby
        let promoted = reg.promote_standby(5, 1000);
        assert!(promoted.is_empty());
    }

    #[test]
    fn test_max_nodes_getter_setter() {
        let mut reg = InMemoryNodeRegistry::with_capacity(50);
        assert_eq!(reg.max_nodes(), 50);
        reg.set_max_nodes(200);
        assert_eq!(reg.max_nodes(), 200);
    }

    #[test]
    fn test_consensus_eligibility_checks_kyc_and_personhood() {
        let mut node = make_node(0x09);
        assert!(node.is_consensus_eligible(10_000));

        node.kyc_status = KycStatus::Expired;
        assert!(!node.is_consensus_eligible(10_000));

        node.kyc_status = KycStatus::Approved;
        node.natural_person = false;
        assert!(!node.is_consensus_eligible(10_000));
    }

    #[test]
    fn test_missing_admission_fields_fail_closed() {
        let raw = r#"{
            "id_com": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
            "status": "Active",
            "registered_at_ms": 1000,
            "activated_at_ms": 1000,
            "label": "legacy-node",
            "affiliate_count": 0
        }"#;

        let node: NodeInfo = serde_json::from_str(raw).unwrap();
        assert_eq!(node.kyc_status, KycStatus::Pending);
        assert!(!node.natural_person);
        assert!(!node.is_consensus_eligible(1_000));
    }

    #[test]
    fn registry_json_round_trip_uses_hex_account_keys() {
        let reg = InMemoryNodeRegistry::from_genesis(vec![make_node(0x11)], 10);

        let json = serde_json::to_string(&reg).expect("registry should serialize to JSON");
        assert!(json.contains(&"11".repeat(32)));
        let decoded: InMemoryNodeRegistry =
            serde_json::from_str(&json).expect("registry should deserialize from JSON");
        assert!(decoded.get_node(&AccountId([0x11; 32])).is_some());
    }
}
