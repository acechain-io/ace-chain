//! Serde helpers for maps keyed by `AccountId`.
//!
//! JSON object keys must be strings, so we hex-encode `AccountId` keys on
//! serialization and decode them on deserialization.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserializer, Serializer};

use crate::account::AccountId;

pub mod btree_map {
    use super::*;

    pub fn serialize<S, V>(map: &BTreeMap<AccountId, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: serde::Serialize,
    {
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (key, value) in map {
            m.serialize_entry(&hex::encode(key.as_bytes()), value)?;
        }
        m.end()
    }

    pub fn deserialize<'de, D, V>(deserializer: D) -> Result<BTreeMap<AccountId, V>, D::Error>
    where
        D: Deserializer<'de>,
        V: serde::Deserialize<'de>,
    {
        struct HexMapVisitor<V>(std::marker::PhantomData<V>);

        impl<'de, V: serde::Deserialize<'de>> Visitor<'de> for HexMapVisitor<V> {
            type Value = BTreeMap<AccountId, V>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map with hex-encoded AccountId keys")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut map = BTreeMap::new();
                while let Some((key_hex, value)) = access.next_entry::<String, V>()? {
                    let bytes = hex::decode(&key_hex).map_err(de::Error::custom)?;
                    if bytes.len() != 32 {
                        return Err(de::Error::custom(format!(
                            "expected 32-byte AccountId key, got {} bytes",
                            bytes.len()
                        )));
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    map.insert(AccountId::from_bytes(key), value);
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(HexMapVisitor(std::marker::PhantomData))
    }
}
