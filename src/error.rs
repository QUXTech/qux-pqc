//! Error types for qux-pqc library

use thiserror::Error;

/// Result type alias for qux-pqc operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in qux-pqc operations
#[derive(Error, Debug)]
pub enum Error {
    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Encapsulation failed
    #[error("Encapsulation failed: {0}")]
    Encapsulation(String),

    /// Decapsulation failed
    #[error("Decapsulation failed: {0}")]
    Decapsulation(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    Signing(String),

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    Decryption(String),

    /// Invalid key size
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size received
        actual: usize,
    },

    /// Invalid ciphertext
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid nonce
    #[error("Invalid nonce: expected {expected} bytes, got {actual}")]
    InvalidNonce {
        /// Expected nonce size in bytes
        expected: usize,
        /// Actual nonce size received
        actual: usize,
    },

    /// Hex decoding error
    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Base64 decoding error
    #[error("Base64 decoding error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Key storage error
    #[error("Key storage error: {0}")]
    KeyStorage(String),

    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Timestamp expired
    #[error("Signature timestamp expired")]
    TimestampExpired,

    /// Invalid security level
    #[error("Invalid security level: {0}")]
    InvalidSecurityLevel(String),
}
