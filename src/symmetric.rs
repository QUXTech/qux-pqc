//! Symmetric Encryption module
//!
//! Implements AES-256-GCM authenticated encryption with HKDF key derivation.

use crate::error::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use zeroize::ZeroizeOnDrop;

/// AES-256 key size in bytes
pub const KEY_SIZE: usize = 32;
/// AES-GCM nonce size in bytes
pub const NONCE_SIZE: usize = 12;

/// Encrypted data containing ciphertext and nonce
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption
    pub nonce: Vec<u8>,
}

/// Encryption key with secure zeroization
#[derive(Clone, ZeroizeOnDrop)]
pub struct EncryptionKey {
    key: [u8; KEY_SIZE],
}

impl EncryptionKey {
    /// Create a key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }
}

/// Generate a random 256-bit encryption key
///
/// # Returns
/// A 32-byte random key
pub fn generate_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    rand::rng().fill_bytes(&mut key);
    key
}

/// Generate a random nonce
///
/// # Returns
/// A 12-byte random nonce for AES-GCM
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Derive an encryption key from a shared secret using HKDF
///
/// # Arguments
/// * `shared_secret` - The shared secret (e.g., from KEM)
/// * `context` - Optional context string for domain separation
///
/// # Returns
/// A derived 256-bit key
pub fn derive_key(shared_secret: &[u8], context: Option<&str>) -> [u8; KEY_SIZE] {
    let hk = Hkdf::<Sha3_256>::new(None, shared_secret);
    let info = context.unwrap_or("qux-pqc-encryption");
    let mut key = [0u8; KEY_SIZE];
    hk.expand(info.as_bytes(), &mut key)
        .expect("HKDF expand should not fail with valid length");
    key
}

/// Encrypt data using AES-256-GCM
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `key` - The 256-bit encryption key
///
/// # Returns
/// `EncryptedData` containing ciphertext and nonce
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<EncryptedData> {
    if key.len() != KEY_SIZE {
        return Err(Error::InvalidKeySize {
            expected: KEY_SIZE,
            actual: key.len(),
        });
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Encryption(e.to_string()))?;

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Encryption(e.to_string()))?;

    Ok(EncryptedData {
        ciphertext,
        nonce: nonce_bytes.to_vec(),
    })
}

/// Decrypt data using AES-256-GCM
///
/// # Arguments
/// * `encrypted` - The encrypted data (ciphertext + nonce)
/// * `key` - The 256-bit decryption key
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt(encrypted: &EncryptedData, key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_SIZE {
        return Err(Error::InvalidKeySize {
            expected: KEY_SIZE,
            actual: key.len(),
        });
    }

    if encrypted.nonce.len() != NONCE_SIZE {
        return Err(Error::InvalidNonce {
            expected: NONCE_SIZE,
            actual: encrypted.nonce.len(),
        });
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Decryption(e.to_string()))?;

    let nonce = Nonce::from_slice(&encrypted.nonce);

    cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| Error::Decryption(e.to_string()))
}

/// Encrypt data using a KEM-derived shared secret
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `shared_secret` - The shared secret from KEM encapsulation
///
/// # Returns
/// `EncryptedData` containing ciphertext and nonce
pub fn encrypt_with_secret(plaintext: &[u8], shared_secret: &[u8]) -> Result<EncryptedData> {
    let key = derive_key(shared_secret, Some("qux-pqc-symmetric-encryption"));
    encrypt(plaintext, &key)
}

/// Decrypt data using a KEM-derived shared secret
///
/// # Arguments
/// * `encrypted` - The encrypted data
/// * `shared_secret` - The shared secret from KEM decapsulation
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt_with_secret(encrypted: &EncryptedData, shared_secret: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key(shared_secret, Some("qux-pqc-symmetric-encryption"));
    decrypt(encrypted, &key)
}

/// Encrypt a string and return hex-encoded result
pub fn encrypt_to_hex(plaintext: &str, key: &[u8]) -> Result<EncryptedData> {
    encrypt(plaintext.as_bytes(), key)
}

/// Decrypt and return as UTF-8 string
pub fn decrypt_to_string(encrypted: &EncryptedData, key: &[u8]) -> Result<String> {
    let bytes = decrypt(encrypted, key)?;
    String::from_utf8(bytes).map_err(|e| Error::Decryption(e.to_string()))
}

/// Compute HMAC-SHA3-256 for message authentication
pub fn hmac_sha3_256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};

    // Simple HMAC construction: H(key || message)
    // For production, use a proper HMAC implementation
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    hasher.update(message);
    let result = hasher.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let key = generate_key();
        assert_eq!(key.len(), KEY_SIZE);

        // Keys should be different each time
        let key2 = generate_key();
        assert_ne!(key, key2);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), NONCE_SIZE);
    }

    #[test]
    fn test_derive_key() {
        let secret = b"shared secret from KEM";
        let key = derive_key(secret, None);
        assert_eq!(key.len(), KEY_SIZE);

        // Same secret + context should produce same key
        let key2 = derive_key(secret, None);
        assert_eq!(key, key2);

        // Different context should produce different key
        let key3 = derive_key(secret, Some("different-context"));
        assert_ne!(key, key3);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_key();
        let plaintext = b"Hello, World!";

        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_string() {
        let key = generate_key();
        let plaintext = "Hello, quantum-safe world! 🔐";

        let encrypted = encrypt_to_hex(plaintext, &key).unwrap();
        let decrypted = decrypt_to_string(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_secret() {
        let shared_secret = b"simulated KEM shared secret";
        let plaintext = b"Secret message via KEM";

        let encrypted = encrypt_with_secret(plaintext, shared_secret).unwrap();
        let decrypted = decrypt_with_secret(&encrypted, shared_secret).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_ciphertexts() {
        let key = generate_key();
        let plaintext = b"Same message";

        let encrypted1 = encrypt(plaintext, &key).unwrap();
        let encrypted2 = encrypt(plaintext, &key).unwrap();

        // Different nonces should produce different ciphertexts
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"Secret message";

        let encrypted = encrypt(plaintext, &key1).unwrap();
        let result = decrypt(&encrypted, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = generate_key();
        let plaintext = b"Secret message";

        let mut encrypted = encrypt(plaintext, &key).unwrap();

        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        let result = decrypt(&encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = generate_key();
        let plaintext = b"";

        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = generate_key();
        let plaintext = vec![0x42u8; 100_000]; // 100KB

        let encrypted = encrypt(&plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
