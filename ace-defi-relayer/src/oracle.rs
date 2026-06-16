//! Price oracle for cross-chain exchange rates

use crate::error::{RelayerError, Result};
use std::collections::HashMap;

/// Mock oracle for MVP (returns fixed rates)
#[derive(Debug, Clone)]
pub struct MockOracle {
    rates: HashMap<String, f64>,
}

impl MockOracle {
    pub fn new() -> Self {
        let mut rates = HashMap::new();

        // Fixed exchange rates for testing
        // Format: "FROM_TO" -> rate
        rates.insert("ETH_USDT".to_string(), 2500.0);
        rates.insert("USDT_ETH".to_string(), 1.0 / 2500.0);
        rates.insert("USDT_SOL".to_string(), 100.0);
        rates.insert("SOL_USDT".to_string(), 1.0 / 100.0);
        rates.insert("USDT_TRX".to_string(), 10.0);
        rates.insert("TRX_USDT".to_string(), 1.0 / 10.0);
        rates.insert("USDT_USDT".to_string(), 1.0);

        Self { rates }
    }

    /// Get exchange rate from one token to another
    pub fn get_rate(&self, from: &str, to: &str) -> Result<f64> {
        let key = format!("{}_{}", from, to);
        self.rates
            .get(&key)
            .copied()
            .ok_or_else(|| RelayerError::OracleError(format!("No rate found for {}", key)))
    }

    /// Get exchange rate with amount
    pub fn get_converted_amount(&self, from: &str, to: &str, amount: f64) -> Result<f64> {
        let rate = self.get_rate(from, to)?;
        Ok(amount * rate)
    }
}

impl Default for MockOracle {
    fn default() -> Self {
        Self::new()
    }
}

/// CoinGecko oracle for real exchange rates (future enhancement)
#[derive(Debug, Clone)]
pub struct CoinGeckoOracle {
    cache: HashMap<String, (f64, u64)>, // (rate, timestamp)
    cache_ttl_secs: u64,
}

impl CoinGeckoOracle {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            cache_ttl_secs: 60, // Cache for 1 minute
        }
    }

    #[allow(dead_code)]
    pub async fn get_rate(&mut self, from: &str, to: &str) -> Result<f64> {
        let key = format!("{}_{}", from, to);
        let now = chrono::Utc::now().timestamp() as u64;

        // Check cache
        if let Some((rate, timestamp)) = self.cache.get(&key) {
            if now - timestamp < self.cache_ttl_secs {
                return Ok(*rate);
            }
        }

        // Fetch from CoinGecko (not implemented for MVP)
        // For now, return error
        Err(RelayerError::OracleError(
            "CoinGecko oracle not yet implemented".to_string(),
        ))
    }
}

/// Factory for creating oracles
pub fn create_oracle(oracle_type: &str) -> Result<Box<dyn PriceOracle>> {
    match oracle_type {
        "mock" => Ok(Box::new(MockOracle::new())),
        _ => Err(RelayerError::OracleError(format!(
            "Unknown oracle type: {}",
            oracle_type
        ))),
    }
}

/// Trait for price oracle implementations
pub trait PriceOracle: Send + Sync {
    fn get_rate(&self, from: &str, to: &str) -> Result<f64>;
    fn get_converted_amount(&self, from: &str, to: &str, amount: f64) -> Result<f64>;
}

impl PriceOracle for MockOracle {
    fn get_rate(&self, from: &str, to: &str) -> Result<f64> {
        MockOracle::get_rate(self, from, to)
    }

    fn get_converted_amount(&self, from: &str, to: &str, amount: f64) -> Result<f64> {
        MockOracle::get_converted_amount(self, from, to, amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_oracle() {
        let oracle = MockOracle::new();
        let rate = oracle.get_rate("USDT", "TRX").expect("Failed to get rate");
        assert_eq!(rate, 10.0);

        let converted = oracle
            .get_converted_amount("USDT", "TRX", 100.0)
            .expect("Failed to convert");
        assert_eq!(converted, 1000.0);
    }

    #[test]
    fn test_missing_rate() {
        let oracle = MockOracle::new();
        let result = oracle.get_rate("XYZ", "ABC");
        assert!(result.is_err());
    }
}
