//! RocksDB-backed application data store.
//!
//! Generic key-value store organized by column families for HFI-Pay
//! and VA-DAR persistence.  Callers handle type-specific serialization;
//! this module only deals with raw bytes.

use std::path::Path;
use std::sync::Arc;

use rocksdb::{ColumnFamilyDescriptor, Options, DB};

use crate::error::ModelError;

/// Column family: registered recipients (HFI-Pay).
pub const CF_HFI_RECIPIENTS: &str = "hfi_recipients";
/// Column family: payment intents (HFI-Pay).
pub const CF_HFI_INTENTS: &str = "hfi_intents";
/// Column family: relay intents (HFI-Pay).
pub const CF_HFI_RELAY_INTENTS: &str = "hfi_relay_intents";
/// Column family: relay intent index (HFI-Pay).
pub const CF_HFI_RELAY_INDEX: &str = "hfi_relay_index";
/// Column family: metadata such as salts (HFI-Pay).
pub const CF_HFI_META: &str = "hfi_meta";
/// Column family: discovery records (VA-DAR).
pub const CF_VADAR_RECORDS: &str = "vadar_records";

const ALL_CFS: &[&str] = &[
    CF_HFI_RECIPIENTS,
    CF_HFI_INTENTS,
    CF_HFI_RELAY_INTENTS,
    CF_HFI_RELAY_INDEX,
    CF_HFI_META,
    CF_VADAR_RECORDS,
];

/// Generic RocksDB store for application data (HFI-Pay, VA-DAR).
pub struct RocksDbAppStore {
    db: Arc<DB>,
}

impl RocksDbAppStore {
    /// Open or create the application store at the given path.
    pub fn open(path: &Path) -> Result<Self, ModelError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(256);

        let cfs: Vec<ColumnFamilyDescriptor> = ALL_CFS
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| ModelError::StorageError(format!("open app store: {e}")))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Put a key-value pair into the specified column family.
    pub fn put(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<(), ModelError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| ModelError::StorageError(format!("cf {cf_name} not found")))?;
        self.db
            .put_cf(&cf, key, value)
            .map_err(|e| ModelError::StorageError(e.to_string()))
    }

    /// Get a value by key from the specified column family.
    pub fn get(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, ModelError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| ModelError::StorageError(format!("cf {cf_name} not found")))?;
        self.db
            .get_cf(&cf, key)
            .map_err(|e| ModelError::StorageError(e.to_string()))
    }

    /// Delete a key from the specified column family.
    pub fn delete(&self, cf_name: &str, key: &[u8]) -> Result<(), ModelError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| ModelError::StorageError(format!("cf {cf_name} not found")))?;
        self.db
            .delete_cf(&cf, key)
            .map_err(|e| ModelError::StorageError(e.to_string()))
    }

    /// Returns true if the given column family contains no entries.
    pub fn is_cf_empty(&self, cf_name: &str) -> Result<bool, ModelError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| ModelError::StorageError(format!("cf {cf_name} not found")))?;
        let mut iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        Ok(iter.next().is_none())
    }

    /// Iterate over all key-value pairs in the specified column family.
    pub fn iter_cf(&self, cf_name: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ModelError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| ModelError::StorageError(format!("cf {cf_name} not found")))?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut result = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| ModelError::StorageError(e.to_string()))?;
            result.push((key.to_vec(), value.to_vec()));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_put_get_delete() {
        let tmp = TempDir::new().unwrap();
        let store = RocksDbAppStore::open(&tmp.path().join("app")).unwrap();

        let key = [0xAAu8; 32];
        let value = b"hello";

        store.put(CF_HFI_RECIPIENTS, &key, value).unwrap();
        let got = store.get(CF_HFI_RECIPIENTS, &key).unwrap().unwrap();
        assert_eq!(got, value);

        store.delete(CF_HFI_RECIPIENTS, &key).unwrap();
        assert!(store.get(CF_HFI_RECIPIENTS, &key).unwrap().is_none());
    }

    #[test]
    fn test_iter_cf() {
        let tmp = TempDir::new().unwrap();
        let store = RocksDbAppStore::open(&tmp.path().join("app")).unwrap();

        store.put(CF_VADAR_RECORDS, &[1u8; 32], b"a").unwrap();
        store.put(CF_VADAR_RECORDS, &[2u8; 32], b"b").unwrap();

        let entries = store.iter_cf(CF_VADAR_RECORDS).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_missing_key_returns_none() {
        let tmp = TempDir::new().unwrap();
        let store = RocksDbAppStore::open(&tmp.path().join("app")).unwrap();

        assert!(store.get(CF_HFI_META, b"nonexistent").unwrap().is_none());
    }
}
