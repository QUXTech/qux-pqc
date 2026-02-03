//! Key Management module
//!
//! Provides secure key storage, serialization, and management utilities.

use crate::dsa::DsaKeyPair;
use crate::error::{Error, Result};
use crate::kem::KemKeyPair;
use crate::symmetric;
use crate::SecurityLevel;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Complete server key set containing both KEM and DSA keys
#[derive(Clone, Serialize, Deserialize)]
pub struct ServerKeys {
    /// KEM key pair for key encapsulation
    pub kem: KemKeyPair,
    /// DSA key pair for digital signatures
    pub dsa: DsaKeyPair,
    /// Security level
    pub security_level: SecurityLevel,
    /// Generation timestamp (Unix epoch seconds)
    pub generated_at: i64,
    /// Key identifier
    pub key_id: String,
}

impl Zeroize for ServerKeys {
    fn zeroize(&mut self) {
        self.kem.zeroize();
        self.dsa.zeroize();
    }
}

impl Drop for ServerKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ServerKeys {
    /// Generate a new server key set
    pub fn generate(level: SecurityLevel) -> Result<Self> {
        let kem = crate::kem::generate_keypair(level)?;
        let dsa = crate::dsa::generate_keypair(level)?;

        Ok(Self {
            kem,
            dsa,
            security_level: level,
            generated_at: chrono::Utc::now().timestamp(),
            key_id: generate_key_id(),
        })
    }

    /// Get only the public keys (safe to share)
    pub fn public_keys(&self) -> PublicKeys {
        PublicKeys {
            kem_public_key: self.kem.public_key.clone(),
            dsa_public_key: self.dsa.public_key.clone(),
            security_level: self.security_level,
            key_id: self.key_id.clone(),
        }
    }

    /// Serialize keys to encrypted JSON
    pub fn to_encrypted_json(&self, passphrase: &str) -> Result<String> {
        let json = serde_json::to_string(self)?;
        let key = derive_encryption_key(passphrase);
        let encrypted = symmetric::encrypt(json.as_bytes(), &key)?;

        let container = EncryptedKeyContainer {
            version: 1,
            ciphertext: hex::encode(&encrypted.ciphertext),
            nonce: hex::encode(&encrypted.nonce),
            key_id: self.key_id.clone(),
        };

        Ok(serde_json::to_string(&container)?)
    }

    /// Deserialize keys from encrypted JSON
    pub fn from_encrypted_json(encrypted_json: &str, passphrase: &str) -> Result<Self> {
        let container: EncryptedKeyContainer = serde_json::from_str(encrypted_json)?;

        let key = derive_encryption_key(passphrase);
        let encrypted = symmetric::EncryptedData {
            ciphertext: hex::decode(&container.ciphertext)?,
            nonce: hex::decode(&container.nonce)?,
        };

        let json_bytes = symmetric::decrypt(&encrypted, &key)?;
        let json = String::from_utf8(json_bytes)
            .map_err(|e| Error::KeyStorage(e.to_string()))?;

        Ok(serde_json::from_str(&json)?)
    }
}

/// Public keys only (safe to share)
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKeys {
    /// KEM public key
    pub kem_public_key: Vec<u8>,
    /// DSA public key
    pub dsa_public_key: Vec<u8>,
    /// Security level
    pub security_level: SecurityLevel,
    /// Key identifier
    pub key_id: String,
}

impl PublicKeys {
    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Serialize to hex-encoded format
    pub fn to_hex(&self) -> PublicKeysHex {
        PublicKeysHex {
            kem_public_key: hex::encode(&self.kem_public_key),
            dsa_public_key: hex::encode(&self.dsa_public_key),
            security_level: self.security_level,
            key_id: self.key_id.clone(),
        }
    }
}

/// Public keys in hex-encoded format
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKeysHex {
    /// KEM public key (hex)
    pub kem_public_key: String,
    /// DSA public key (hex)
    pub dsa_public_key: String,
    /// Security level
    pub security_level: SecurityLevel,
    /// Key identifier
    pub key_id: String,
}

impl PublicKeysHex {
    /// Convert to binary format
    pub fn to_binary(&self) -> Result<PublicKeys> {
        Ok(PublicKeys {
            kem_public_key: hex::decode(&self.kem_public_key)?,
            dsa_public_key: hex::decode(&self.dsa_public_key)?,
            security_level: self.security_level,
            key_id: self.key_id.clone(),
        })
    }
}

/// Encrypted key container for storage
#[derive(Serialize, Deserialize)]
struct EncryptedKeyContainer {
    version: u8,
    ciphertext: String,
    nonce: String,
    key_id: String,
}

/// Generate a unique key identifier
fn generate_key_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("qux-{}", hex::encode(bytes))
}

/// Derive encryption key from passphrase using HKDF
fn derive_encryption_key(passphrase: &str) -> [u8; 32] {
    symmetric::derive_key(passphrase.as_bytes(), Some("qux-pqc-key-storage"))
}

/// Key rotation helper
pub struct KeyRotation {
    /// Current active keys
    pub current: ServerKeys,
    /// Previous keys (for decrypting old data)
    pub previous: Option<ServerKeys>,
    /// Rotation timestamp
    pub rotated_at: Option<i64>,
}

impl KeyRotation {
    /// Create a new key rotation context
    pub fn new(level: SecurityLevel) -> Result<Self> {
        Ok(Self {
            current: ServerKeys::generate(level)?,
            previous: None,
            rotated_at: None,
        })
    }

    /// Rotate keys, keeping the old ones for decryption
    pub fn rotate(&mut self) -> Result<()> {
        let new_keys = ServerKeys::generate(self.current.security_level)?;
        self.previous = Some(std::mem::replace(&mut self.current, new_keys));
        self.rotated_at = Some(chrono::Utc::now().timestamp());
        Ok(())
    }

    /// Get the current public keys
    pub fn current_public_keys(&self) -> PublicKeys {
        self.current.public_keys()
    }
}

/// Verify key integrity using fingerprint
pub fn key_fingerprint(key: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    let hash = Sha3_256::digest(key);
    hex::encode(&hash[..8]) // First 8 bytes as fingerprint
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_keys_generation() {
        let keys = ServerKeys::generate(SecurityLevel::Level5).unwrap();
        assert!(!keys.kem.public_key.is_empty());
        assert!(!keys.dsa.public_key.is_empty());
        assert!(!keys.key_id.is_empty());
    }

    #[test]
    fn test_public_keys_extraction() {
        let keys = ServerKeys::generate(SecurityLevel::Level5).unwrap();
        let public_keys = keys.public_keys();

        assert_eq!(public_keys.kem_public_key, keys.kem.public_key);
        assert_eq!(public_keys.dsa_public_key, keys.dsa.public_key);
        assert_eq!(public_keys.key_id, keys.key_id);
    }

    #[test]
    fn test_encrypted_serialization() {
        let keys = ServerKeys::generate(SecurityLevel::Level5).unwrap();
        let passphrase = "super-secret-passphrase";

        let encrypted = keys.to_encrypted_json(passphrase).unwrap();
        let loaded = ServerKeys::from_encrypted_json(&encrypted, passphrase).unwrap();

        assert_eq!(loaded.kem.public_key, keys.kem.public_key);
        assert_eq!(loaded.dsa.public_key, keys.dsa.public_key);
        assert_eq!(loaded.key_id, keys.key_id);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let keys = ServerKeys::generate(SecurityLevel::Level5).unwrap();
        let encrypted = keys.to_encrypted_json("correct-passphrase").unwrap();

        let result = ServerKeys::from_encrypted_json(&encrypted, "wrong-passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_key_rotation() {
        let mut rotation = KeyRotation::new(SecurityLevel::Level5).unwrap();
        let original_key_id = rotation.current.key_id.clone();

        rotation.rotate().unwrap();

        assert_ne!(rotation.current.key_id, original_key_id);
        assert!(rotation.previous.is_some());
        assert_eq!(rotation.previous.as_ref().unwrap().key_id, original_key_id);
        assert!(rotation.rotated_at.is_some());
    }

    #[test]
    fn test_key_fingerprint() {
        let key1 = symmetric::generate_key();
        let key2 = symmetric::generate_key();

        let fp1 = key_fingerprint(&key1);
        let fp2 = key_fingerprint(&key2);

        assert_eq!(fp1.len(), 16); // 8 bytes = 16 hex chars
        assert_ne!(fp1, fp2);

        // Same key should produce same fingerprint
        assert_eq!(fp1, key_fingerprint(&key1));
    }

    #[test]
    fn test_public_keys_hex_conversion() {
        let keys = ServerKeys::generate(SecurityLevel::Level5).unwrap();
        let public_keys = keys.public_keys();

        let hex_keys = public_keys.to_hex();
        let recovered = hex_keys.to_binary().unwrap();

        assert_eq!(recovered.kem_public_key, public_keys.kem_public_key);
        assert_eq!(recovered.dsa_public_key, public_keys.dsa_public_key);
    }
}
