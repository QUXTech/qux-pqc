//! Digital Signature Algorithm (DSA) module
//!
//! Implements ML-DSA (CRYSTALS-Dilithium) as per NIST FIPS 204.
//! - ML-DSA-65 for Security Level 3
//! - ML-DSA-87 for Security Level 5

use crate::error::{Error, Result};
use crate::SecurityLevel;
use pqcrypto_dilithium::{dilithium3, dilithium5};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// DSA key pair containing public and secret keys
#[derive(Clone, Serialize, Deserialize)]
pub struct DsaKeyPair {
    /// Public key (safe to share)
    pub public_key: Vec<u8>,
    /// Secret key (must be kept private)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub secret_key: Vec<u8>,
    /// Security level
    pub security_level: SecurityLevel,
}

impl Zeroize for DsaKeyPair {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

impl Drop for DsaKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Signature with timestamp for replay protection
#[derive(Clone, Serialize, Deserialize)]
pub struct TimestampedSignature {
    /// The signature bytes
    pub signature: Vec<u8>,
    /// Unix timestamp when signature was created
    pub timestamp: i64,
}

/// Generate a DSA key pair at the specified security level
///
/// # Arguments
/// * `level` - Security level (Level3 or Level5)
///
/// # Returns
/// A `DsaKeyPair` containing the public and secret keys
///
/// # Example
/// ```
/// use qux_pqc::{dsa, SecurityLevel};
///
/// let keys = dsa::generate_keypair(SecurityLevel::Level5).unwrap();
/// assert!(!keys.public_key.is_empty());
/// ```
pub fn generate_keypair(level: SecurityLevel) -> Result<DsaKeyPair> {
    match level {
        SecurityLevel::Level3 => {
            let (pk, sk) = dilithium3::keypair();
            Ok(DsaKeyPair {
                public_key: pk.as_bytes().to_vec(),
                secret_key: sk.as_bytes().to_vec(),
                security_level: level,
            })
        }
        SecurityLevel::Level5 => {
            let (pk, sk) = dilithium5::keypair();
            Ok(DsaKeyPair {
                public_key: pk.as_bytes().to_vec(),
                secret_key: sk.as_bytes().to_vec(),
                security_level: level,
            })
        }
    }
}

/// Sign a message with the secret key
///
/// # Arguments
/// * `message` - The message to sign
/// * `secret_key` - The signer's secret key
///
/// # Returns
/// The signature bytes
pub fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    // Determine level from secret key size
    if secret_key.len() == dilithium5::secret_key_bytes() {
        sign_with_level(message, secret_key, SecurityLevel::Level5)
    } else if secret_key.len() == dilithium3::secret_key_bytes() {
        sign_with_level(message, secret_key, SecurityLevel::Level3)
    } else {
        Err(Error::InvalidKeySize {
            expected: dilithium5::secret_key_bytes(),
            actual: secret_key.len(),
        })
    }
}

/// Sign with explicit security level
pub fn sign_with_level(
    message: &[u8],
    secret_key: &[u8],
    level: SecurityLevel,
) -> Result<Vec<u8>> {
    match level {
        SecurityLevel::Level3 => {
            let sk = dilithium3::SecretKey::from_bytes(secret_key)
                .map_err(|_| Error::InvalidKeySize {
                    expected: dilithium3::secret_key_bytes(),
                    actual: secret_key.len(),
                })?;
            let sig = dilithium3::detached_sign(message, &sk);
            Ok(sig.as_bytes().to_vec())
        }
        SecurityLevel::Level5 => {
            let sk = dilithium5::SecretKey::from_bytes(secret_key)
                .map_err(|_| Error::InvalidKeySize {
                    expected: dilithium5::secret_key_bytes(),
                    actual: secret_key.len(),
                })?;
            let sig = dilithium5::detached_sign(message, &sk);
            Ok(sig.as_bytes().to_vec())
        }
    }
}

/// Verify a signature
///
/// # Arguments
/// * `message` - The original message
/// * `signature` - The signature to verify
/// * `public_key` - The signer's public key
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    // Determine level from public key size
    if public_key.len() == dilithium5::public_key_bytes() {
        verify_with_level(message, signature, public_key, SecurityLevel::Level5)
    } else if public_key.len() == dilithium3::public_key_bytes() {
        verify_with_level(message, signature, public_key, SecurityLevel::Level3)
    } else {
        Err(Error::InvalidKeySize {
            expected: dilithium5::public_key_bytes(),
            actual: public_key.len(),
        })
    }
}

/// Verify with explicit security level
pub fn verify_with_level(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    level: SecurityLevel,
) -> Result<bool> {
    match level {
        SecurityLevel::Level3 => {
            let pk = dilithium3::PublicKey::from_bytes(public_key)
                .map_err(|_| Error::InvalidKeySize {
                    expected: dilithium3::public_key_bytes(),
                    actual: public_key.len(),
                })?;
            let sig = dilithium3::DetachedSignature::from_bytes(signature)
                .map_err(|_| Error::InvalidSignature("Invalid Level 3 signature".into()))?;
            Ok(dilithium3::verify_detached_signature(&sig, message, &pk).is_ok())
        }
        SecurityLevel::Level5 => {
            let pk = dilithium5::PublicKey::from_bytes(public_key)
                .map_err(|_| Error::InvalidKeySize {
                    expected: dilithium5::public_key_bytes(),
                    actual: public_key.len(),
                })?;
            let sig = dilithium5::DetachedSignature::from_bytes(signature)
                .map_err(|_| Error::InvalidSignature("Invalid Level 5 signature".into()))?;
            Ok(dilithium5::verify_detached_signature(&sig, message, &pk).is_ok())
        }
    }
}

/// Sign a message with a timestamp for replay protection
///
/// # Arguments
/// * `message` - The message to sign
/// * `secret_key` - The signer's secret key
/// * `level` - Security level
///
/// # Returns
/// A `TimestampedSignature` containing the signature and timestamp
pub fn sign_with_timestamp(
    message: &[u8],
    secret_key: &[u8],
    level: SecurityLevel,
) -> Result<TimestampedSignature> {
    let timestamp = chrono::Utc::now().timestamp();

    // Include timestamp in signed data
    let mut data_to_sign = message.to_vec();
    data_to_sign.extend_from_slice(&timestamp.to_le_bytes());

    let signature = sign_with_level(&data_to_sign, secret_key, level)?;

    Ok(TimestampedSignature { signature, timestamp })
}

/// Verify a timestamped signature
///
/// # Arguments
/// * `message` - The original message
/// * `timestamped_sig` - The timestamped signature
/// * `public_key` - The signer's public key
/// * `max_age_secs` - Maximum age of signature in seconds
/// * `level` - Security level
///
/// # Returns
/// `Ok(true)` if valid, `Ok(false)` if invalid signature, `Err` if expired
pub fn verify_with_timestamp(
    message: &[u8],
    timestamped_sig: &TimestampedSignature,
    public_key: &[u8],
    max_age_secs: i64,
    level: SecurityLevel,
) -> Result<bool> {
    let now = chrono::Utc::now().timestamp();

    // Check if timestamp is too old
    if now - timestamped_sig.timestamp > max_age_secs {
        return Err(Error::TimestampExpired);
    }

    // Reconstruct signed data
    let mut data_to_verify = message.to_vec();
    data_to_verify.extend_from_slice(&timestamped_sig.timestamp.to_le_bytes());

    verify_with_level(&data_to_verify, &timestamped_sig.signature, public_key, level)
}

/// Get the public key size for a security level
pub fn public_key_size(level: SecurityLevel) -> usize {
    match level {
        SecurityLevel::Level3 => dilithium3::public_key_bytes(),
        SecurityLevel::Level5 => dilithium5::public_key_bytes(),
    }
}

/// Get the secret key size for a security level
pub fn secret_key_size(level: SecurityLevel) -> usize {
    match level {
        SecurityLevel::Level3 => dilithium3::secret_key_bytes(),
        SecurityLevel::Level5 => dilithium5::secret_key_bytes(),
    }
}

/// Get the signature size for a security level
pub fn signature_size(level: SecurityLevel) -> usize {
    match level {
        SecurityLevel::Level3 => dilithium3::signature_bytes(),
        SecurityLevel::Level5 => dilithium5::signature_bytes(),
    }
}

/// Get the algorithm name for a security level
pub fn algorithm_name(level: SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Level3 => "ML-DSA-65",
        SecurityLevel::Level5 => "ML-DSA-87",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation_level5() {
        let keys = generate_keypair(SecurityLevel::Level5).unwrap();
        assert_eq!(keys.public_key.len(), public_key_size(SecurityLevel::Level5));
        assert_eq!(keys.secret_key.len(), secret_key_size(SecurityLevel::Level5));
    }

    #[test]
    fn test_keypair_generation_level3() {
        let keys = generate_keypair(SecurityLevel::Level3).unwrap();
        assert_eq!(keys.public_key.len(), public_key_size(SecurityLevel::Level3));
        assert_eq!(keys.secret_key.len(), secret_key_size(SecurityLevel::Level3));
    }

    #[test]
    fn test_sign_verify_level5() {
        let keys = generate_keypair(SecurityLevel::Level5).unwrap();
        let message = b"Hello, quantum-safe world!";

        let signature = sign(message, &keys.secret_key).unwrap();
        let valid = verify(message, &signature, &keys.public_key).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_sign_verify_level3() {
        let keys = generate_keypair(SecurityLevel::Level3).unwrap();
        let message = b"Test message for level 3";

        let signature = sign(message, &keys.secret_key).unwrap();
        let valid = verify(message, &signature, &keys.public_key).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_verify_fails_with_wrong_message() {
        let keys = generate_keypair(SecurityLevel::Level5).unwrap();
        let message = b"Original message";

        let signature = sign(message, &keys.secret_key).unwrap();
        let valid = verify(b"Tampered message", &signature, &keys.public_key).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_verify_fails_with_wrong_key() {
        let keys1 = generate_keypair(SecurityLevel::Level5).unwrap();
        let keys2 = generate_keypair(SecurityLevel::Level5).unwrap();
        let message = b"Test message";

        let signature = sign(message, &keys1.secret_key).unwrap();
        let valid = verify(message, &signature, &keys2.public_key).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_deterministic_signatures() {
        let keys = generate_keypair(SecurityLevel::Level5).unwrap();
        let message = b"Same message";

        let sig1 = sign(message, &keys.secret_key).unwrap();
        let sig2 = sign(message, &keys.secret_key).unwrap();

        // ML-DSA is deterministic
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_timestamped_signature() {
        let keys = generate_keypair(SecurityLevel::Level5).unwrap();
        let message = b"Time-sensitive data";

        let ts_sig = sign_with_timestamp(message, &keys.secret_key, SecurityLevel::Level5).unwrap();

        // Verify within 5 minute window
        let valid = verify_with_timestamp(
            message,
            &ts_sig,
            &keys.public_key,
            300,
            SecurityLevel::Level5,
        ).unwrap();

        assert!(valid);
    }
}
