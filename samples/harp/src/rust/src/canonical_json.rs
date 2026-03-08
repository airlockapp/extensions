//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! Achieves JCS by serializing to `serde_json::Value` (which uses `BTreeMap`
//! for sorted keys) then re-serializing to a compact JSON string.

use serde::Serialize;

/// Strip null values recursively from a `serde_json::Value`.
fn strip_nulls(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let cleaned: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, strip_nulls(v)))
                .collect();
            serde_json::Value::Object(cleaned)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(strip_nulls).collect())
        }
        other => other,
    }
}

/// Canonicalize a serializable value to a JCS string.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    // Serialize to Value (BTreeMap gives sorted keys)
    let v = serde_json::to_value(value)?;
    let stripped = strip_nulls(v);
    serde_json::to_string(&stripped)
}

/// Canonicalize a serializable value to JCS UTF-8 bytes.
pub fn canonicalize_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    canonicalize(value).map(|s| s.into_bytes())
}
