//! Affiliate management for ACE Chain nodes.
//!
//! Non-node users ("affiliates") join an existing node operator's
//! sovereign infrastructure. They pay a monthly management fee
//! and get access to the full ACE Chain feature set.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::account::AccountId;

/// Default affiliate fee per month in base units (50 ACE * 10^9).
pub const DEFAULT_AFFILIATE_FEE: u64 = 50 * 1_000_000_000;

/// An affiliate record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffiliateInfo {
    /// Affiliate's identity commitment.
    pub id_com: AccountId,
    /// Node operator managing this affiliate.
    pub operator: AccountId,
    /// Registration timestamp (Unix ms).
    pub registered_at_ms: u64,
    /// Whether the affiliate is currently active.
    pub active: bool,
}

/// Approximate month length used for fee proration (30 days).
pub const BILLING_PERIOD_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Tracks affiliates across all node operators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffiliateRegistry {
    /// operator → set of affiliate id_coms
    #[serde(with = "crate::serde_account_id::btree_map")]
    affiliates_by_operator: BTreeMap<AccountId, BTreeSet<AccountId>>,
    /// affiliate id_com → AffiliateInfo
    #[serde(with = "crate::serde_account_id::btree_map")]
    affiliate_info: BTreeMap<AccountId, AffiliateInfo>,
    /// Monthly fee in base units.
    fee_per_month: u64,
}

impl AffiliateRegistry {
    /// Create a new affiliate registry with default fees.
    pub fn new() -> Self {
        Self {
            affiliates_by_operator: BTreeMap::new(),
            affiliate_info: BTreeMap::new(),
            fee_per_month: DEFAULT_AFFILIATE_FEE,
        }
    }

    /// Create with a custom fee.
    pub fn with_fee(fee_per_month: u64) -> Self {
        Self {
            affiliates_by_operator: BTreeMap::new(),
            affiliate_info: BTreeMap::new(),
            fee_per_month,
        }
    }

    /// Get the monthly fee.
    pub fn fee_per_month(&self) -> u64 {
        self.fee_per_month
    }

    /// Register a new affiliate under a node operator.
    pub fn register(
        &mut self,
        affiliate: AccountId,
        operator: AccountId,
        timestamp_ms: u64,
    ) -> Result<(), AffiliateError> {
        if self.affiliate_info.contains_key(&affiliate) {
            return Err(AffiliateError::AlreadyRegistered(affiliate));
        }

        let info = AffiliateInfo {
            id_com: affiliate,
            operator,
            registered_at_ms: timestamp_ms,
            active: true,
        };

        self.affiliate_info.insert(affiliate, info);
        self.affiliates_by_operator
            .entry(operator)
            .or_default()
            .insert(affiliate);

        Ok(())
    }

    /// Deactivate an affiliate.
    pub fn deactivate(&mut self, affiliate: &AccountId) -> Result<(), AffiliateError> {
        match self.affiliate_info.get_mut(affiliate) {
            Some(info) => {
                info.active = false;
                Ok(())
            }
            None => Err(AffiliateError::NotFound(*affiliate)),
        }
    }

    /// Get all affiliates for a node operator.
    pub fn get_affiliates(&self, operator: &AccountId) -> Vec<&AffiliateInfo> {
        self.affiliates_by_operator
            .get(operator)
            .map(|set| {
                set.iter()
                    .filter_map(|id| self.affiliate_info.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get active affiliate count for a node operator.
    pub fn active_affiliate_count(&self, operator: &AccountId) -> u32 {
        self.get_affiliates(operator)
            .iter()
            .filter(|a| a.active)
            .count() as u32
    }

    /// Calculate total fees owed to a node operator for one epoch.
    pub fn calculate_operator_fees(&self, operator: &AccountId) -> u64 {
        self.calculate_operator_fees_for_window(operator, 0, 24 * 60 * 60 * 1000)
    }

    /// Calculate a single affiliate's prorated fee for a time window.
    pub fn calculate_affiliate_fee_for_window(
        &self,
        affiliate: &AffiliateInfo,
        window_start_ms: u64,
        window_end_ms: u64,
    ) -> u64 {
        if !affiliate.active || window_end_ms <= window_start_ms {
            return 0;
        }

        let active_start = affiliate.registered_at_ms.max(window_start_ms);
        if active_start >= window_end_ms {
            return 0;
        }

        let active_ms = window_end_ms - active_start;
        ((self.fee_per_month as u128) * (active_ms as u128) / (BILLING_PERIOD_MS as u128)) as u64
    }

    /// Calculate total fees owed to a node operator for an arbitrary time window.
    pub fn calculate_operator_fees_for_window(
        &self,
        operator: &AccountId,
        window_start_ms: u64,
        window_end_ms: u64,
    ) -> u64 {
        self.get_affiliates(operator)
            .into_iter()
            .map(|affiliate| {
                self.calculate_affiliate_fee_for_window(affiliate, window_start_ms, window_end_ms)
            })
            .sum()
    }

    /// Get all active affiliates across all operators.
    pub fn active_affiliates(&self) -> Vec<&AffiliateInfo> {
        self.affiliate_info.values().filter(|a| a.active).collect()
    }

    /// Get total number of affiliates across all operators.
    pub fn total_affiliates(&self) -> u32 {
        self.affiliate_info.values().filter(|a| a.active).count() as u32
    }

    /// Get affiliate info by identity commitment.
    pub fn get_affiliate(&self, affiliate: &AccountId) -> Option<&AffiliateInfo> {
        self.affiliate_info.get(affiliate)
    }
}

impl Default for AffiliateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Affiliate system errors.
#[derive(Debug, thiserror::Error)]
pub enum AffiliateError {
    #[error("affiliate already registered: {0}")]
    AlreadyRegistered(AccountId),

    #[error("affiliate not found: {0}")]
    NotFound(AccountId),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operator() -> AccountId {
        AccountId([0x01; 32])
    }

    fn affiliate(byte: u8) -> AccountId {
        AccountId([byte; 32])
    }

    #[test]
    fn test_register_affiliate() {
        let mut reg = AffiliateRegistry::new();
        reg.register(affiliate(0xAA), operator(), 1000).unwrap();

        assert_eq!(reg.total_affiliates(), 1);
        assert_eq!(reg.active_affiliate_count(&operator()), 1);
    }

    #[test]
    fn test_duplicate_registration() {
        let mut reg = AffiliateRegistry::new();
        reg.register(affiliate(0xAA), operator(), 1000).unwrap();
        let result = reg.register(affiliate(0xAA), operator(), 2000);
        assert!(result.is_err());
    }

    #[test]
    fn test_deactivate_affiliate() {
        let mut reg = AffiliateRegistry::new();
        reg.register(affiliate(0xAA), operator(), 1000).unwrap();
        reg.deactivate(&affiliate(0xAA)).unwrap();

        assert_eq!(reg.active_affiliate_count(&operator()), 0);
        assert_eq!(reg.total_affiliates(), 0);
    }

    #[test]
    fn test_get_affiliates() {
        let mut reg = AffiliateRegistry::new();
        reg.register(affiliate(0xAA), operator(), 1000).unwrap();
        reg.register(affiliate(0xBB), operator(), 2000).unwrap();

        let affiliates = reg.get_affiliates(&operator());
        assert_eq!(affiliates.len(), 2);
    }

    #[test]
    fn test_calculate_fees() {
        let mut reg = AffiliateRegistry::new();
        reg.register(affiliate(0xAA), operator(), 1000).unwrap();
        reg.register(affiliate(0xBB), operator(), 2000).unwrap();

        let fees = reg.calculate_operator_fees(&operator());
        let expected = reg.calculate_operator_fees_for_window(&operator(), 0, 24 * 60 * 60 * 1000);
        assert_eq!(fees, expected);
    }

    #[test]
    fn test_no_fees_for_inactive() {
        let mut reg = AffiliateRegistry::new();
        reg.register(affiliate(0xAA), operator(), 1000).unwrap();
        reg.deactivate(&affiliate(0xAA)).unwrap();

        let fees = reg.calculate_operator_fees(&operator());
        assert_eq!(fees, 0);
    }

    #[test]
    fn test_prorated_fee_for_partial_window() {
        let mut reg = AffiliateRegistry::new();
        reg.register(affiliate(0xAA), operator(), 12 * 60 * 60 * 1000)
            .unwrap();

        let fees = reg.calculate_operator_fees_for_window(&operator(), 0, 24 * 60 * 60 * 1000);
        let expected = (DEFAULT_AFFILIATE_FEE as u128 * 12 * 60 * 60 * 1000
            / BILLING_PERIOD_MS as u128) as u64;
        assert_eq!(fees, expected);
    }

    #[test]
    fn affiliate_registry_json_round_trip_uses_hex_account_keys() {
        let mut reg = AffiliateRegistry::new();
        reg.register(affiliate(0xAA), operator(), 1000).unwrap();

        let json = serde_json::to_string(&reg).expect("affiliate registry should serialize");
        assert!(json.contains(&"01".repeat(32)));
        assert!(json.contains(&"aa".repeat(32)));

        let decoded: AffiliateRegistry =
            serde_json::from_str(&json).expect("affiliate registry should deserialize");
        assert_eq!(decoded.total_affiliates(), 1);
        assert_eq!(decoded.active_affiliate_count(&operator()), 1);
    }
}
