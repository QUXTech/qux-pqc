//! # qux-pqc - Post-Quantum Cryptography Library
//!
//! A comprehensive Rust library implementing NIST-standardized post-quantum
//! cryptographic algorithms for key encapsulation and digital signatures.
//!
//! ## Features
//!
//! - **ML-KEM (CRYSTALS-Kyber)** - NIST FIPS 203 Key Encapsulation Mechanism
//! - **ML-DSA (CRYSTALS-Dilithium)** - NIST FIPS 204 Digital Signature Algorithm
//! - **AES-256-GCM** - Symmetric encryption with PQC-derived keys
//! - **SHA3-256/512** - Quantum-resistant hashing
//! - **Secure Key Management** - Encrypted key storage with zeroization
//!
//! ## Security Levels
//!
//! - **Level 3** (~AES-192 equivalent): ML-KEM-768 + ML-DSA-65
//! - **Level 5** (~AES-256 equivalent): ML-KEM-1024 + ML-DSA-87
//!
//! ## Example
//!
//! ```rust
//! use qux_pqc::{kem, dsa, SecurityLevel};
//!
//! // Generate KEM key pair
//! let kem_keys = kem::generate_keypair(SecurityLevel::Level5).unwrap();
//!
//! // Encapsulate shared secret
//! let (ciphertext, shared_secret) = kem::encapsulate(&kem_keys.public_key).unwrap();
//!
//! // Decapsulate to recover shared secret
//! let recovered = kem::decapsulate(&ciphertext, &kem_keys.secret_key).unwrap();
//! assert_eq!(shared_secret, recovered);
//!
//! // Generate DSA key pair and sign
//! let dsa_keys = dsa::generate_keypair(SecurityLevel::Level5).unwrap();
//! let message = b"Hello, quantum-safe world!";
//! let signature = dsa::sign(message, &dsa_keys.secret_key).unwrap();
//! assert!(dsa::verify(message, &signature, &dsa_keys.public_key).unwrap());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(clippy::all)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod dsa;
pub mod error;
pub mod kem;
pub mod keys;
pub mod symmetric;
pub mod utils;

pub use error::{Error, Result};

use serde::{Deserialize, Serialize};

/// NIST Security Level for PQC algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum SecurityLevel {
    /// Security Level 3 (~AES-192): ML-KEM-768 + ML-DSA-65
    Level3,
    /// Security Level 5 (~AES-256): ML-KEM-1024 + ML-DSA-87
    #[default]
    Level5,
}

impl SecurityLevel {
    /// Get the algorithm names for this security level
    pub fn algorithm_names(&self) -> AlgorithmNames {
        match self {
            SecurityLevel::Level3 => AlgorithmNames {
                kem: "ML-KEM-768",
                dsa: "ML-DSA-65",
            },
            SecurityLevel::Level5 => AlgorithmNames {
                kem: "ML-KEM-1024",
                dsa: "ML-DSA-87",
            },
        }
    }

    /// Get the numeric level (3 or 5)
    pub fn as_u8(&self) -> u8 {
        match self {
            SecurityLevel::Level3 => 3,
            SecurityLevel::Level5 => 5,
        }
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityLevel::Level3 => write!(f, "Level 3 (ML-KEM-768 + ML-DSA-65)"),
            SecurityLevel::Level5 => write!(f, "Level 5 (ML-KEM-1024 + ML-DSA-87)"),
        }
    }
}

/// Algorithm names for a security level
#[derive(Debug, Clone, Copy)]
pub struct AlgorithmNames {
    /// KEM algorithm name
    pub kem: &'static str,
    /// DSA algorithm name
    pub dsa: &'static str,
}

/// Complete key set containing both KEM and DSA key pairs
#[derive(Clone, Serialize, Deserialize)]
pub struct KeySet {
    /// KEM key pair
    pub kem: kem::KemKeyPair,
    /// DSA key pair
    pub dsa: dsa::DsaKeyPair,
    /// Security level
    pub security_level: SecurityLevel,
    /// Generation timestamp (Unix epoch seconds)
    pub generated_at: i64,
}

impl KeySet {
    /// Generate a complete key set at the specified security level
    pub fn generate(security_level: SecurityLevel) -> Result<Self> {
        let kem_keys = kem::generate_keypair(security_level)?;
        let dsa_keys = dsa::generate_keypair(security_level)?;

        Ok(Self {
            kem: kem_keys,
            dsa: dsa_keys,
            security_level,
            generated_at: chrono::Utc::now().timestamp(),
        })
    }

    /// Get only the public keys
    pub fn public_keys(&self) -> PublicKeySet {
        PublicKeySet {
            kem_public_key: self.kem.public_key.clone(),
            dsa_public_key: self.dsa.public_key.clone(),
            security_level: self.security_level,
        }
    }
}

/// Public key set (safe to share)
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKeySet {
    /// KEM public key
    pub kem_public_key: Vec<u8>,
    /// DSA public key
    pub dsa_public_key: Vec<u8>,
    /// Security level
    pub security_level: SecurityLevel,
}

/// Encrypt data and sign the ciphertext
///
/// This combines KEM-based encryption with DSA signing for authenticated encryption.
pub fn encrypt_and_sign(
    data: &[u8],
    recipient_kem_public_key: &[u8],
    sender_dsa_secret_key: &[u8],
    security_level: SecurityLevel,
) -> Result<EncryptedSignedPayload> {
    // Encapsulate to get shared secret
    let (kem_ciphertext, shared_secret) = kem::encapsulate_with_level(
        recipient_kem_public_key,
        security_level,
    )?;

    // Encrypt data with shared secret
    let encrypted = symmetric::encrypt_with_secret(data, &shared_secret)?;

    // Create data to sign (ciphertext + nonce + kem_ciphertext)
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(&encrypted.ciphertext);
    sign_data.extend_from_slice(&encrypted.nonce);
    sign_data.extend_from_slice(&kem_ciphertext);

    // Sign
    let signature = dsa::sign_with_level(&sign_data, sender_dsa_secret_key, security_level)?;

    Ok(EncryptedSignedPayload {
        kem_ciphertext,
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        signature,
        security_level,
    })
}

/// Verify signature and decrypt data
pub fn verify_and_decrypt(
    payload: &EncryptedSignedPayload,
    sender_dsa_public_key: &[u8],
    recipient_kem_secret_key: &[u8],
) -> Result<Vec<u8>> {
    // Recreate data that was signed
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(&payload.ciphertext);
    sign_data.extend_from_slice(&payload.nonce);
    sign_data.extend_from_slice(&payload.kem_ciphertext);

    // Verify signature
    let valid = dsa::verify_with_level(
        &sign_data,
        &payload.signature,
        sender_dsa_public_key,
        payload.security_level,
    )?;

    if !valid {
        return Err(Error::SignatureVerificationFailed);
    }

    // Decapsulate to get shared secret
    let shared_secret = kem::decapsulate_with_level(
        &payload.kem_ciphertext,
        recipient_kem_secret_key,
        payload.security_level,
    )?;

    // Decrypt
    let encrypted = symmetric::EncryptedData {
        ciphertext: payload.ciphertext.clone(),
        nonce: payload.nonce.clone(),
    };

    symmetric::decrypt_with_secret(&encrypted, &shared_secret)
}

/// Encrypted and signed payload
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedSignedPayload {
    /// KEM ciphertext containing encapsulated shared secret
    pub kem_ciphertext: Vec<u8>,
    /// Encrypted data ciphertext
    pub ciphertext: Vec<u8>,
    /// Encryption nonce
    pub nonce: Vec<u8>,
    /// Digital signature
    pub signature: Vec<u8>,
    /// Security level used
    pub security_level: SecurityLevel,
}

/// Get library version information
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Get algorithm information for a security level
pub fn algorithm_info(level: SecurityLevel) -> AlgorithmInfo {
    let names = level.algorithm_names();
    AlgorithmInfo {
        kem: names.kem.to_string(),
        dsa: names.dsa.to_string(),
        symmetric: "AES-256-GCM".to_string(),
        hash: "SHA3-256/512".to_string(),
        security_level: level,
        nist_fips: vec!["FIPS 203 (ML-KEM)".to_string(), "FIPS 204 (ML-DSA)".to_string()],
    }
}

/// Algorithm information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmInfo {
    /// KEM algorithm
    pub kem: String,
    /// DSA algorithm
    pub dsa: String,
    /// Symmetric algorithm
    pub symmetric: String,
    /// Hash algorithm
    pub hash: String,
    /// Security level
    pub security_level: SecurityLevel,
    /// NIST FIPS standards
    pub nist_fips: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_level_display() {
        assert!(SecurityLevel::Level5.to_string().contains("Level 5"));
        assert!(SecurityLevel::Level3.to_string().contains("Level 3"));
    }

    #[test]
    fn test_key_set_generation() {
        let keys = KeySet::generate(SecurityLevel::Level5).unwrap();
        assert!(!keys.kem.public_key.is_empty());
        assert!(!keys.dsa.public_key.is_empty());
        assert_eq!(keys.security_level, SecurityLevel::Level5);
    }

    #[test]
    fn test_encrypt_and_sign_verify_and_decrypt() {
        let alice = KeySet::generate(SecurityLevel::Level5).unwrap();
        let bob = KeySet::generate(SecurityLevel::Level5).unwrap();

        let message = b"Hello, quantum-safe world!";

        // Alice encrypts to Bob and signs
        let payload = encrypt_and_sign(
            message,
            &bob.kem.public_key,
            &alice.dsa.secret_key,
            SecurityLevel::Level5,
        ).unwrap();

        // Bob verifies and decrypts
        let decrypted = verify_and_decrypt(
            &payload,
            &alice.dsa.public_key,
            &bob.kem.secret_key,
        ).unwrap();

        assert_eq!(message.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_algorithm_info() {
        let info = algorithm_info(SecurityLevel::Level5);
        assert_eq!(info.kem, "ML-KEM-1024");
        assert_eq!(info.dsa, "ML-DSA-87");
    }
}
