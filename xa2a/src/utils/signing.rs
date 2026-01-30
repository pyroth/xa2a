//! Signing and canonicalization utilities for A2A.
//!
//! Provides functions for canonicalizing JSON objects and generating
//! signatures for request/response verification.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{A2AError, Result};

/// Canonicalizes a JSON value according to RFC 8785 (JCS).
///
/// This produces a deterministic JSON string suitable for signing.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<String> {
    let json_value = serde_json::to_value(value).map_err(A2AError::Json)?;
    Ok(canonicalize_value(&json_value))
}

/// Canonicalizes a serde_json::Value according to RFC 8785.
fn canonicalize_value(value: &serde_json::Value) -> String {
    use serde_json::Value;
    
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => canonicalize_number(n),
        Value::String(s) => canonicalize_string(s),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_value).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(obj) => {
            // Sort keys lexicographically (UTF-8 byte order)
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            
            let items: Vec<String> = keys
                .iter()
                .map(|k| {
                    let v = canonicalize_value(&obj[*k]);
                    format!("{}:{}", canonicalize_string(k), v)
                })
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

/// Canonicalizes a number according to RFC 8785.
fn canonicalize_number(n: &serde_json::Number) -> String {
    // For integers, use standard representation
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    
    // For floats, handle special cases
    if let Some(f) = n.as_f64() {
        if f.is_nan() || f.is_infinite() {
            return "null".to_string();
        }
        // Use shortest representation
        let s = format!("{}", f);
        // Remove trailing zeros after decimal point
        if s.contains('.') {
            let trimmed = s.trim_end_matches('0').trim_end_matches('.');
            return trimmed.to_string();
        }
        return s;
    }
    
    n.to_string()
}

/// Canonicalizes a string with proper escaping.
fn canonicalize_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c < '\x20' => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    
    result.push('"');
    result
}

/// Computes a SHA-256 hash of the given data.
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Computes a SHA-256 hash and returns it as a hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = sha256_hash(data);
    hex::encode(hash)
}

/// Computes a SHA-256 hash and returns it as a base64 string.
pub fn sha256_base64(data: &[u8]) -> String {
    use base64::Engine;
    let hash = sha256_hash(data);
    base64::engine::general_purpose::STANDARD.encode(hash)
}

/// Computes a digest of a canonicalized JSON value.
pub fn compute_digest<T: Serialize>(value: &T) -> Result<String> {
    let canonical = canonicalize(value)?;
    Ok(sha256_base64(canonical.as_bytes()))
}

/// Signature algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// HMAC-SHA256
    HS256,
    /// RSA-SHA256
    RS256,
    /// ECDSA-P256-SHA256
    ES256,
    /// EdDSA (Ed25519)
    EdDSA,
}

impl SignatureAlgorithm {
    /// Returns the algorithm name as used in JWS headers.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HS256 => "HS256",
            Self::RS256 => "RS256",
            Self::ES256 => "ES256",
            Self::EdDSA => "EdDSA",
        }
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A simple HMAC-SHA256 signature for symmetric key signing.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Verifies an HMAC-SHA256 signature.
pub fn verify_hmac_sha256(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(message);
    mac.verify_slice(signature).is_ok()
}

/// Creates a simple signed message with HMAC-SHA256.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedMessage {
    /// The message payload.
    pub payload: serde_json::Value,
    /// The signature (base64 encoded).
    pub signature: String,
    /// The algorithm used.
    pub algorithm: String,
}

impl SignedMessage {
    /// Creates a new signed message using HMAC-SHA256.
    pub fn sign_hmac<T: Serialize>(payload: &T, key: &[u8]) -> Result<Self> {
        let canonical = canonicalize(payload)?;
        let signature = hmac_sha256(key, canonical.as_bytes());
        
        use base64::Engine;
        let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);
        
        Ok(Self {
            payload: serde_json::to_value(payload).map_err(A2AError::Json)?,
            signature: signature_b64,
            algorithm: SignatureAlgorithm::HS256.to_string(),
        })
    }
    
    /// Verifies the signature of this message.
    pub fn verify_hmac(&self, key: &[u8]) -> Result<bool> {
        use base64::Engine;
        
        let canonical = canonicalize_value(&self.payload);
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|e| A2AError::InvalidConfig(format!("Invalid signature encoding: {}", e)))?;
        
        Ok(verify_hmac_sha256(key, canonical.as_bytes(), &signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_canonicalize_simple() {
        let value = json!({"b": 2, "a": 1});
        let canonical = canonicalize(&value).unwrap();
        // Keys should be sorted
        assert_eq!(canonical, r#"{"a":1,"b":2}"#);
    }
    
    #[test]
    fn test_canonicalize_nested() {
        let value = json!({"z": {"b": 2, "a": 1}, "a": []});
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"a":[],"z":{"a":1,"b":2}}"#);
    }
    
    #[test]
    fn test_canonicalize_string_escaping() {
        let value = json!({"text": "hello\nworld"});
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"text":"hello\nworld"}"#);
    }
    
    #[test]
    fn test_sha256_hash() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
    
    #[test]
    fn test_hmac_sha256() {
        let key = b"secret-key";
        let message = b"hello";
        let sig = hmac_sha256(key, message);
        
        assert!(verify_hmac_sha256(key, message, &sig));
        assert!(!verify_hmac_sha256(b"wrong-key", message, &sig));
    }
    
    #[test]
    fn test_signed_message() {
        let payload = json!({"task_id": "123", "status": "completed"});
        let key = b"my-secret-key";
        
        let signed = SignedMessage::sign_hmac(&payload, key).unwrap();
        assert!(signed.verify_hmac(key).unwrap());
        assert!(!signed.verify_hmac(b"wrong-key").unwrap());
    }
    
    #[test]
    fn test_compute_digest() {
        let value = json!({"id": "test"});
        let digest = compute_digest(&value).unwrap();
        assert!(!digest.is_empty());
        
        // Same value should produce same digest
        let digest2 = compute_digest(&value).unwrap();
        assert_eq!(digest, digest2);
    }
}
