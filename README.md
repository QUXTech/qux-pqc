# qux-pqc

[![CI](https://github.com/QUXTech/qux-pqc/actions/workflows/ci.yml/badge.svg)](https://github.com/QUXTech/qux-pqc/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/qux-pqc.svg)](https://crates.io/crates/qux-pqc)
[![Documentation](https://docs.rs/qux-pqc/badge.svg)](https://docs.rs/qux-pqc)
[![License](https://img.shields.io/crates/l/qux-pqc.svg)](https://github.com/QUXTech/qux-pqc#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.70-blue.svg)](https://blog.rust-lang.org/2023/06/01/Rust-1.70.0.html)

A comprehensive Rust library implementing NIST-standardized post-quantum cryptographic algorithms for key encapsulation and digital signatures.

## Features

- **ML-KEM (CRYSTALS-Kyber)** - NIST FIPS 203 Key Encapsulation Mechanism
- **ML-DSA (CRYSTALS-Dilithium)** - NIST FIPS 204 Digital Signature Algorithm
- **AES-256-GCM** - Symmetric encryption with PQC-derived keys
- **SHA3-256/512** - Quantum-resistant hashing
- **Secure Key Management** - Encrypted key storage with zeroization

## Security Levels

| Level | KEM Algorithm | DSA Algorithm | Classical Equivalent |
|-------|---------------|---------------|---------------------|
| 3 | ML-KEM-768 | ML-DSA-65 | ~AES-192 |
| 5 | ML-KEM-1024 | ML-DSA-87 | ~AES-256 |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
qux-pqc = "1.0"
```

## Quick Start

```rust
use qux_pqc::{KeySet, SecurityLevel, encrypt_and_sign, verify_and_decrypt};

fn main() -> qux_pqc::Result<()> {
    // Generate key sets for Alice and Bob
    let alice = KeySet::generate(SecurityLevel::Level5)?;
    let bob = KeySet::generate(SecurityLevel::Level5)?;

    // Alice encrypts and signs a message for Bob
    let message = b"Hello, quantum-safe world!";
    let payload = encrypt_and_sign(
        message,
        &bob.kem.public_key,
        &alice.dsa.secret_key,
        SecurityLevel::Level5,
    )?;

    // Bob verifies and decrypts
    let decrypted = verify_and_decrypt(
        &payload,
        &alice.dsa.public_key,
        &bob.kem.secret_key,
    )?;

    assert_eq!(message.as_slice(), decrypted.as_slice());
    Ok(())
}
```

## Modules

### Key Encapsulation (KEM)

```rust
use qux_pqc::{kem, SecurityLevel};

// Generate key pair
let keys = kem::generate_keypair(SecurityLevel::Level5)?;

// Encapsulate shared secret
let (ciphertext, shared_secret) = kem::encapsulate(&keys.public_key)?;

// Decapsulate to recover shared secret
let recovered = kem::decapsulate(&ciphertext, &keys.secret_key)?;
assert_eq!(shared_secret, recovered);
```

### Digital Signatures (DSA)

```rust
use qux_pqc::{dsa, SecurityLevel};

// Generate key pair
let keys = dsa::generate_keypair(SecurityLevel::Level5)?;

// Sign message
let message = b"Important document";
let signature = dsa::sign(message, &keys.secret_key)?;

// Verify signature
let valid = dsa::verify(message, &signature, &keys.public_key)?;
assert!(valid);
```

### Symmetric Encryption

```rust
use qux_pqc::symmetric;

// Encrypt with KEM-derived shared secret
let encrypted = symmetric::encrypt_with_secret(plaintext, &shared_secret)?;

// Decrypt
let decrypted = symmetric::decrypt_with_secret(&encrypted, &shared_secret)?;
```

### Key Management

```rust
use qux_pqc::keys;

// Serialize keys with encryption
let encrypted = keys::serialize_encrypted(&key_set, "strong-passphrase")?;

// Save to file
std::fs::write("keys.enc", &encrypted)?;

// Load and decrypt
let loaded = std::fs::read("keys.enc")?;
let key_set = keys::deserialize_encrypted(&loaded, "strong-passphrase")?;
```

### Utilities

```rust
use qux_pqc::utils;

// SHA3-256 hashing
let hash = utils::sha3_256(data);
let hash_hex = utils::sha3_256_hex(data);

// Random bytes
let random = utils::random_bytes(32);
let random_hex = utils::random_hex(32);

// Constant-time comparison
let equal = utils::constant_time_eq(&a, &b);
```

## Key Sizes

### ML-KEM

| Level | Public Key | Secret Key | Ciphertext | Shared Secret |
|-------|------------|------------|------------|---------------|
| 3 | 1,184 bytes | 2,400 bytes | 1,088 bytes | 32 bytes |
| 5 | 1,568 bytes | 3,168 bytes | 1,568 bytes | 32 bytes |

### ML-DSA

| Level | Public Key | Secret Key | Signature |
|-------|------------|------------|-----------|
| 3 | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| 5 | 2,592 bytes | 4,896 bytes | 4,627 bytes |

## Security Features

- **Zeroization**: Secret keys are automatically zeroed on drop
- **Constant-time operations**: Where applicable to prevent timing attacks
- **Encrypted storage**: Keys can be serialized with passphrase protection
- **HKDF key derivation**: Secure key derivation from shared secrets

## Standards Compliance

- **NIST FIPS 203** - ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- **NIST FIPS 204** - ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- **NIST FIPS 202** - SHA-3 (Secure Hash Algorithm 3)

## Feature Flags

```toml
[dependencies]
qux-pqc = { version = "1.0", default-features = false }  # no_std compatible
qux-pqc = { version = "1.0", features = ["std"] }        # default, with std
```

## Minimum Supported Rust Version

This crate requires Rust 1.70 or later.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions welcome! Please read our contributing guidelines before submitting a pull request.

## Security

For security issues, please email security@quxtech.com instead of opening a public issue.
