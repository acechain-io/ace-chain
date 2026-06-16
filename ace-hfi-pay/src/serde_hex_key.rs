//! Serde helpers for maps keyed by `[u8; 32]`.
//!
//! JSON requires string keys, so we hex-encode the 32-byte arrays on
//! serialization and decode them back on deserialization.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserializer, Serializer};

/// Serialize / deserialize `BTreeMap<[u8; 32], V>` with hex-encoded keys.
pub mod btree {
    use super::*;

    pub fn serialize<S, V>(map: &BTreeMap<[u8; 32], V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: serde::Serialize,
    {
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            m.serialize_entry(&hex::encode(k), v)?;
        }
        m.end()
    }

    pub fn deserialize<'de, D, V>(deserializer: D) -> Result<BTreeMap<[u8; 32], V>, D::Error>
    where
        D: Deserializer<'de>,
        V: serde::Deserialize<'de>,
    {
        struct HexMapVisitor<V>(std::marker::PhantomData<V>);

        impl<'de, V: serde::Deserialize<'de>> Visitor<'de> for HexMapVisitor<V> {
            type Value = BTreeMap<[u8; 32], V>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map with hex-encoded 32-byte keys")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut map = BTreeMap::new();
                while let Some((key_hex, value)) = access.next_entry::<String, V>()? {
                    let bytes = hex::decode(&key_hex).map_err(de::Error::custom)?;
                    if bytes.len() != 32 {
                        return Err(de::Error::custom(format!(
                            "expected 32 bytes, got {}",
                            bytes.len()
                        )));
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    map.insert(arr, value);
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(HexMapVisitor(std::marker::PhantomData))
    }
}

/// Serialize / deserialize `HashMap<[u8; 32], V>` with hex-encoded keys.
pub mod hash {
    use super::*;

    pub fn serialize<S, V>(map: &HashMap<[u8; 32], V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: serde::Serialize,
    {
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            m.serialize_entry(&hex::encode(k), v)?;
        }
        m.end()
    }

    pub fn deserialize<'de, D, V>(deserializer: D) -> Result<HashMap<[u8; 32], V>, D::Error>
    where
        D: Deserializer<'de>,
        V: serde::Deserialize<'de>,
    {
        struct HexMapVisitor<V>(std::marker::PhantomData<V>);

        impl<'de, V: serde::Deserialize<'de>> Visitor<'de> for HexMapVisitor<V> {
            type Value = HashMap<[u8; 32], V>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map with hex-encoded 32-byte keys")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut map = HashMap::new();
                while let Some((key_hex, value)) = access.next_entry::<String, V>()? {
                    let bytes = hex::decode(&key_hex).map_err(de::Error::custom)?;
                    if bytes.len() != 32 {
                        return Err(de::Error::custom(format!(
                            "expected 32 bytes, got {}",
                            bytes.len()
                        )));
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    map.insert(arr, value);
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(HexMapVisitor(std::marker::PhantomData))
    }
}

/// Serialize / deserialize `HashMap<[u8; 32], Vec<[u8; 32]>>` with hex-encoded keys and values.
pub mod hash_vec {
    use super::*;

    pub fn serialize<S>(
        map: &HashMap<[u8; 32], Vec<[u8; 32]>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            let hex_vec: Vec<String> = v.iter().map(hex::encode).collect();
            m.serialize_entry(&hex::encode(k), &hex_vec)?;
        }
        m.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<[u8; 32], Vec<[u8; 32]>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HexMapVisitor;

        impl<'de> Visitor<'de> for HexMapVisitor {
            type Value = HashMap<[u8; 32], Vec<[u8; 32]>>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map with hex keys and hex-array values")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut map = HashMap::new();
                while let Some((key_hex, val_hexes)) = access.next_entry::<String, Vec<String>>()? {
                    let key_bytes = hex::decode(&key_hex).map_err(de::Error::custom)?;
                    if key_bytes.len() != 32 {
                        return Err(de::Error::custom("key must be 32 bytes"));
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&key_bytes);

                    let mut vals = Vec::with_capacity(val_hexes.len());
                    for vh in &val_hexes {
                        let vb = hex::decode(vh).map_err(de::Error::custom)?;
                        if vb.len() != 32 {
                            return Err(de::Error::custom("value must be 32 bytes"));
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&vb);
                        vals.push(arr);
                    }
                    map.insert(key, vals);
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(HexMapVisitor)
    }
}
