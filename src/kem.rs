//! Key Encapsulation Mechanism (KEM) module
//!
//! Implements ML-KEM (CRYSTALS-Kyber) as per NIST FIPS 203.
//! - ML-KEM-768 for Security Level 3
//! - ML-KEM-1024 for Security Level 5

use crate::error::{Error, Result};
use crate::SecurityLevel;
use pqcrypto_kyber::{kyber1024, kyber768};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// KEM key pair containing public and secret keys
#[derive(Clone, Serialize, Deserialize)]
pub struct KemKeyPair {
    /// Public key (safe to share)
    pub public_key: Vec<u8>,
    /// Secret key (must be kept private)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub secret_key: Vec<u8>,
    /// Security level
    pub security_level: SecurityLevel,
}

impl Zeroize for KemKeyPair {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

impl Drop for KemKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Encapsulation result containing ciphertext and shared secret
#[derive(Clone, ZeroizeOnDrop)]
pub struct EncapsulationResult {
    /// Ciphertext to send to the secret key holder
    #[zeroize(skip)]
    pub ciphertext: Vec<u8>,
    /// Shared secret (same as what decapsulation will produce)
    pub shared_secret: Vec<u8>,
}

/// Generate a KEM key pair at the specified security level
///
/// # Arguments
/// * `level` - Security level (Level3 or Level5)
///
/// # Returns
/// A `KemKeyPair` containing the public and secret keys
///
/// # Example
/// ```
/// use qux_pqc::{kem, SecurityLevel};
///
/// let keys = kem::generate_keypair(SecurityLevel::Level5).unwrap();
/// assert!(!keys.public_key.is_empty());
/// ```
pub fn generate_keypair(level: SecurityLevel) -> Result<KemKeyPair> {
    match level {
        SecurityLevel::Level3 => {
            let (pk, sk) = kyber768::keypair();
            Ok(KemKeyPair {
                public_key: pk.as_bytes().to_vec(),
                secret_key: sk.as_bytes().to_vec(),
                security_level: level,
            })
        }
        SecurityLevel::Level5 => {
            let (pk, sk) = kyber1024::keypair();
            Ok(KemKeyPair {
                public_key: pk.as_bytes().to_vec(),
                secret_key: sk.as_bytes().to_vec(),
                security_level: level,
            })
        }
    }
}

/// Encapsulate a shared secret using a public key
///
/// # Arguments
/// * `public_key` - The recipient's public key
///
/// # Returns
/// Tuple of (ciphertext, shared_secret)
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // Try Level 5 first based on key size
    if public_key.len() == kyber1024::public_key_bytes() {
        encapsulate_with_level(public_key, SecurityLevel::Level5)
    } else if public_key.len() == kyber768::public_key_bytes() {
        encapsulate_with_level(public_key, SecurityLevel::Level3)
    } else {
        Err(Error::InvalidKeySize {
            expected: kyber1024::public_key_bytes(),
            actual: public_key.len(),
        })
    }
}

/// Encapsulate with explicit security level
pub fn encapsulate_with_level(
    public_key: &[u8],
    level: SecurityLevel,
) -> Result<(Vec<u8>, Vec<u8>)> {
    match level {
        SecurityLevel::Level3 => {
            let pk =
                kyber768::PublicKey::from_bytes(public_key).map_err(|_| Error::InvalidKeySize {
                    expected: kyber768::public_key_bytes(),
                    actual: public_key.len(),
                })?;
            let (ss, ct) = kyber768::encapsulate(&pk);
            Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
        }
        SecurityLevel::Level5 => {
            let pk = kyber1024::PublicKey::from_bytes(public_key).map_err(|_| {
                Error::InvalidKeySize {
                    expected: kyber1024::public_key_bytes(),
                    actual: public_key.len(),
                }
            })?;
            let (ss, ct) = kyber1024::encapsulate(&pk);
            Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
        }
    }
}

/// Decapsulate to recover the shared secret
///
/// # Arguments
/// * `ciphertext` - The ciphertext from encapsulation
/// * `secret_key` - The recipient's secret key
///
/// # Returns
/// The shared secret
pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    // Determine level from secret key size
    if secret_key.len() == kyber1024::secret_key_bytes() {
        decapsulate_with_level(ciphertext, secret_key, SecurityLevel::Level5)
    } else if secret_key.len() == kyber768::secret_key_bytes() {
        decapsulate_with_level(ciphertext, secret_key, SecurityLevel::Level3)
    } else {
        Err(Error::InvalidKeySize {
            expected: kyber1024::secret_key_bytes(),
            actual: secret_key.len(),
        })
    }
}

/// Decapsulate with explicit security level
pub fn decapsulate_with_level(
    ciphertext: &[u8],
    secret_key: &[u8],
    level: SecurityLevel,
) -> Result<Vec<u8>> {
    match level {
        SecurityLevel::Level3 => {
            let sk =
                kyber768::SecretKey::from_bytes(secret_key).map_err(|_| Error::InvalidKeySize {
                    expected: kyber768::secret_key_bytes(),
                    actual: secret_key.len(),
                })?;
            let ct = kyber768::Ciphertext::from_bytes(ciphertext)
                .map_err(|_| Error::InvalidCiphertext("Invalid Level 3 ciphertext".into()))?;
            let ss = kyber768::decapsulate(&ct, &sk);
            Ok(ss.as_bytes().to_vec())
        }
        SecurityLevel::Level5 => {
            let sk = kyber1024::SecretKey::from_bytes(secret_key).map_err(|_| {
                Error::InvalidKeySize {
                    expected: kyber1024::secret_key_bytes(),
                    actual: secret_key.len(),
                }
            })?;
            let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
                .map_err(|_| Error::InvalidCiphertext("Invalid Level 5 ciphertext".into()))?;
            let ss = kyber1024::decapsulate(&ct, &sk);
            Ok(ss.as_bytes().to_vec())
        }
    }
}

/// Get the public key size for a security level
pub fn public_key_size(level: SecurityLevel) -> usize {
    match level {
        SecurityLevel::Level3 => kyber768::public_key_bytes(),
        SecurityLevel::Level5 => kyber1024::public_key_bytes(),
    }
}

/// Get the secret key size for a security level
pub fn secret_key_size(level: SecurityLevel) -> usize {
    match level {
        SecurityLevel::Level3 => kyber768::secret_key_bytes(),
        SecurityLevel::Level5 => kyber1024::secret_key_bytes(),
    }
}

/// Get the ciphertext size for a security level
pub fn ciphertext_size(level: SecurityLevel) -> usize {
    match level {
        SecurityLevel::Level3 => kyber768::ciphertext_bytes(),
        SecurityLevel::Level5 => kyber1024::ciphertext_bytes(),
    }
}

/// Get the shared secret size (32 bytes for all levels)
pub fn shared_secret_size(_level: SecurityLevel) -> usize {
    32 // Always 32 bytes
}

/// Get the algorithm name for a security level
pub fn algorithm_name(level: SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Level3 => "ML-KEM-768",
        SecurityLevel::Level5 => "ML-KEM-1024",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation_level5() {
        let keys = generate_keypair(SecurityLevel::Level5).unwrap();
        assert_eq!(
            keys.public_key.len(),
            public_key_size(SecurityLevel::Level5)
        );
        assert_eq!(
            keys.secret_key.len(),
            secret_key_size(SecurityLevel::Level5)
        );
    }

    #[test]
    fn test_keypair_generation_level3() {
        let keys = generate_keypair(SecurityLevel::Level3).unwrap();
        assert_eq!(
            keys.public_key.len(),
            public_key_size(SecurityLevel::Level3)
        );
        assert_eq!(
            keys.secret_key.len(),
            secret_key_size(SecurityLevel::Level3)
        );
    }

    #[test]
    fn test_encapsulate_decapsulate_level5() {
        let keys = generate_keypair(SecurityLevel::Level5).unwrap();
        let (ciphertext, shared_secret) = encapsulate(&keys.public_key).unwrap();
        let recovered = decapsulate(&ciphertext, &keys.secret_key).unwrap();
        assert_eq!(shared_secret, recovered);
    }

    #[test]
    fn test_encapsulate_decapsulate_level3() {
        let keys = generate_keypair(SecurityLevel::Level3).unwrap();
        let (ciphertext, shared_secret) = encapsulate(&keys.public_key).unwrap();
        let recovered = decapsulate(&ciphertext, &keys.secret_key).unwrap();
        assert_eq!(shared_secret, recovered);
    }

    #[test]
    fn test_different_keypairs_produce_different_keys() {
        let keys1 = generate_keypair(SecurityLevel::Level5).unwrap();
        let keys2 = generate_keypair(SecurityLevel::Level5).unwrap();
        assert_ne!(keys1.public_key, keys2.public_key);
        assert_ne!(keys1.secret_key, keys2.secret_key);
    }

    #[test]
    fn test_shared_secret_size() {
        let keys = generate_keypair(SecurityLevel::Level5).unwrap();
        let (_, shared_secret) = encapsulate(&keys.public_key).unwrap();
        assert_eq!(shared_secret.len(), 32);
    }
}
