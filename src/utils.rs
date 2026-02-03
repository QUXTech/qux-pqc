//! Utility functions for qux-pqc
//!
//! Provides hashing, encoding, and other cryptographic utilities.

use sha3::{Digest, Sha3_256, Sha3_512};

/// Compute SHA3-256 hash of data
///
/// # Arguments
/// * `data` - The data to hash
///
/// # Returns
/// 32-byte hash as array
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute SHA3-256 hash and return as hex string
pub fn sha3_256_hex(data: &[u8]) -> String {
    hex::encode(sha3_256(data))
}

/// Compute SHA3-512 hash of data
///
/// # Arguments
/// * `data` - The data to hash
///
/// # Returns
/// 64-byte hash as array
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Compute SHA3-512 hash and return as hex string
pub fn sha3_512_hex(data: &[u8]) -> String {
    hex::encode(sha3_512(data))
}

/// Generate a random hex string of specified byte length
pub fn random_hex(byte_length: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; byte_length];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generate a random base64 string of specified byte length
pub fn random_base64(byte_length: usize) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use rand::RngCore;
    let mut bytes = vec![0u8; byte_length];
    rand::thread_rng().fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

/// Securely compare two byte slices in constant time
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Encode bytes to hex string
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Decode hex string to bytes
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex_str)
}

/// Encode bytes to base64 string
pub fn to_base64(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}

/// Decode base64 string to bytes
pub fn from_base64(b64_str: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(b64_str)
}

/// Get current Unix timestamp in seconds
pub fn unix_timestamp() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Get current Unix timestamp in milliseconds
pub fn unix_timestamp_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Hash-based key derivation (simple version)
pub fn derive_subkey(master_key: &[u8], context: &str, index: u32) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(master_key);
    hasher.update(context.as_bytes());
    hasher.update(index.to_le_bytes());
    let result = hasher.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute hash chain for key ratcheting
pub fn hash_chain(seed: &[u8], iterations: u32) -> [u8; 32] {
    let mut current = sha3_256(seed);
    for _ in 1..iterations {
        current = sha3_256(&current);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let hash = sha3_256(b"test");
        assert_eq!(hash.len(), 32);

        // Same input should produce same hash
        let hash2 = sha3_256(b"test");
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let hash3 = sha3_256(b"test2");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_sha3_256_hex() {
        let hash = sha3_256_hex(b"hello");
        assert_eq!(hash.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_sha3_512() {
        let hash = sha3_512(b"test");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_random_hex() {
        let hex1 = random_hex(16);
        let hex2 = random_hex(16);

        assert_eq!(hex1.len(), 32); // 16 bytes = 32 hex chars
        assert_ne!(hex1, hex2);
    }

    #[test]
    fn test_random_base64() {
        let b64 = random_base64(24);
        assert!(!b64.is_empty());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello worle";
        let d = b"hello";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, d));
    }

    #[test]
    fn test_hex_encoding() {
        let data = b"test data";
        let encoded = to_hex(data);
        let decoded = from_hex(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_encoding() {
        let data = b"test data";
        let encoded = to_base64(data);
        let decoded = from_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_derive_subkey() {
        let master = b"master key";

        let key1 = derive_subkey(master, "context", 0);
        let key2 = derive_subkey(master, "context", 1);
        let key3 = derive_subkey(master, "other", 0);

        // Different indices should produce different keys
        assert_ne!(key1, key2);
        // Different contexts should produce different keys
        assert_ne!(key1, key3);
        // Same inputs should produce same key
        assert_eq!(key1, derive_subkey(master, "context", 0));
    }

    #[test]
    fn test_hash_chain() {
        let seed = b"initial seed";

        let chain1 = hash_chain(seed, 1);
        let chain5 = hash_chain(seed, 5);
        let chain10 = hash_chain(seed, 10);

        // Different iterations should produce different results
        assert_ne!(chain1, chain5);
        assert_ne!(chain5, chain10);

        // Same iterations should be deterministic
        assert_eq!(chain5, hash_chain(seed, 5));
    }

    #[test]
    fn test_unix_timestamp() {
        let ts = unix_timestamp();
        assert!(ts > 0);

        let ts_ms = unix_timestamp_ms();
        assert!(ts_ms > 0);
        assert!(ts_ms >= ts * 1000);
    }
}
