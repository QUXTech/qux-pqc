/**
 * @quxtech/pqc-crypto - Key Management Module
 * ============================================================================
 * Secure key generation, storage, and loading with encryption at rest.
 *
 * Features:
 * - Encrypted key storage using AES-256-GCM
 * - HKDF key derivation from passphrase
 * - Separate KEM and DSA key pairs
 * - Fail-secure pattern (fails closed on missing passphrase)
 * ============================================================================
 */

import { gcm } from '@noble/ciphers/aes';
import { sha3_256 } from '@noble/hashes/sha3';
import { hkdf } from '@noble/hashes/hkdf';
import { randomBytes, bytesToHex, hexToBytes, utf8ToBytes, bytesToUtf8 } from '@noble/hashes/utils';
import * as kem from './kem.js';
import * as dsa from './dsa.js';
import type {
  SecurityLevel,
  KeyPair,
  ServerKeys,
  PublicKeyExport,
  EncryptedKeyStorage,
  StoredKeyData,
  KeyMetadata,
} from '../types.js';

// Key storage context for HKDF
const KEY_STORAGE_CONTEXT = 'pqc-crypto-key-storage';

// In-memory key cache
let serverKeys: ServerKeys | null = null;

/**
 * Generate a complete server key set (KEM + DSA)
 * @param securityLevel - NIST security level ('3' or '5')
 * @returns Server keys object
 */
export function generateServerKeys(securityLevel: SecurityLevel = '5'): ServerKeys {
  const kemKeyPair = kem.generateKeyPair(securityLevel);
  const dsaKeyPair = dsa.generateKeyPair(securityLevel);

  serverKeys = {
    kem: kemKeyPair,
    dsa: dsaKeyPair,
    initialized: true,
    generatedAt: new Date().toISOString(),
    securityLevel,
  };

  return serverKeys;
}

/**
 * Serialize keys to encrypted storage format
 * @param keys - Server keys to serialize
 * @param passphrase - Encryption passphrase
 * @returns Encrypted key storage object
 */
export function serializeKeys(keys: ServerKeys, passphrase: string): EncryptedKeyStorage {
  if (!keys.initialized) {
    throw new Error('Keys not initialized');
  }

  const keyData: StoredKeyData = {
    kem: {
      publicKey: bytesToHex(keys.kem.publicKey),
      secretKey: bytesToHex(keys.kem.secretKey),
    },
    dsa: {
      publicKey: bytesToHex(keys.dsa.publicKey),
      secretKey: bytesToHex(keys.dsa.secretKey),
    },
    metadata: {
      generatedAt: keys.generatedAt ?? new Date().toISOString(),
      securityLevel: keys.securityLevel,
      algorithm: {
        kem: kem.getAlgorithmName(keys.securityLevel),
        dsa: dsa.getAlgorithmName(keys.securityLevel),
      },
    },
  };

  // Derive encryption key from passphrase using HKDF
  const salt = randomBytes(32);
  const key = hkdf(sha3_256, utf8ToBytes(passphrase), salt, utf8ToBytes(KEY_STORAGE_CONTEXT), 32);
  const nonce = randomBytes(12);

  // Encrypt key data
  const cipher = gcm(key, nonce);
  const plaintext = utf8ToBytes(JSON.stringify(keyData));
  const ciphertext = cipher.encrypt(plaintext);

  return {
    version: 1,
    salt: bytesToHex(salt),
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext),
  };
}

/**
 * Deserialize keys from encrypted storage format
 * @param encrypted - Encrypted key storage
 * @param passphrase - Decryption passphrase
 * @returns Server keys object
 */
export function deserializeKeys(encrypted: EncryptedKeyStorage, passphrase: string): ServerKeys {
  // Derive decryption key
  const salt = hexToBytes(encrypted.salt);
  const key = hkdf(sha3_256, utf8ToBytes(passphrase), salt, utf8ToBytes(KEY_STORAGE_CONTEXT), 32);
  const nonce = hexToBytes(encrypted.nonce);

  // Decrypt
  const cipher = gcm(key, nonce);
  const ciphertext = hexToBytes(encrypted.ciphertext);

  let plaintext: Uint8Array;
  try {
    plaintext = cipher.decrypt(ciphertext);
  } catch {
    throw new Error('Failed to decrypt keys - incorrect passphrase');
  }

  const keyData: StoredKeyData = JSON.parse(bytesToUtf8(plaintext));

  serverKeys = {
    kem: {
      publicKey: hexToBytes(keyData.kem.publicKey),
      secretKey: hexToBytes(keyData.kem.secretKey),
    },
    dsa: {
      publicKey: hexToBytes(keyData.dsa.publicKey),
      secretKey: hexToBytes(keyData.dsa.secretKey),
    },
    initialized: true,
    generatedAt: keyData.metadata.generatedAt,
    securityLevel: keyData.metadata.securityLevel,
  };

  return serverKeys;
}

/**
 * Set server keys directly (for loading from external source)
 * @param keys - Server keys
 */
export function setServerKeys(keys: ServerKeys): void {
  serverKeys = keys;
}

/**
 * Get current server keys
 * @returns Server keys or null if not initialized
 */
export function getServerKeys(): ServerKeys | null {
  return serverKeys;
}

/**
 * Get server public keys for distribution
 * @returns Public key export object
 * @throws Error if keys not initialized
 */
export function getPublicKeys(): PublicKeyExport {
  if (!serverKeys?.initialized) {
    throw new Error('Server keys not initialized');
  }

  return {
    kemPublicKey: bytesToHex(serverKeys.kem.publicKey),
    dsaPublicKey: bytesToHex(serverKeys.dsa.publicKey),
    securityLevel: serverKeys.securityLevel,
    algorithm: {
      kem: kem.getAlgorithmName(serverKeys.securityLevel),
      dsa: dsa.getAlgorithmName(serverKeys.securityLevel),
    },
  };
}

/**
 * Get KEM key pair from server keys
 * @returns KEM key pair
 * @throws Error if keys not initialized
 */
export function getKemKeyPair(): KeyPair {
  if (!serverKeys?.initialized) {
    throw new Error('Server keys not initialized');
  }
  return serverKeys.kem;
}

/**
 * Get DSA key pair from server keys
 * @returns DSA key pair
 * @throws Error if keys not initialized
 */
export function getDsaKeyPair(): KeyPair {
  if (!serverKeys?.initialized) {
    throw new Error('Server keys not initialized');
  }
  return serverKeys.dsa;
}

/**
 * Check if server keys are initialized
 * @returns True if keys are loaded
 */
export function isInitialized(): boolean {
  return serverKeys?.initialized ?? false;
}

/**
 * Clear server keys from memory
 */
export function clearKeys(): void {
  if (serverKeys) {
    // Overwrite secret keys before clearing
    if (serverKeys.kem.secretKey) {
      serverKeys.kem.secretKey.fill(0);
    }
    if (serverKeys.dsa.secretKey) {
      serverKeys.dsa.secretKey.fill(0);
    }
  }
  serverKeys = null;
}

/**
 * Get key metadata
 * @returns Key metadata or null if not initialized
 */
export function getMetadata(): KeyMetadata | null {
  if (!serverKeys?.initialized) {
    return null;
  }

  return {
    generatedAt: serverKeys.generatedAt ?? 'unknown',
    securityLevel: serverKeys.securityLevel,
    algorithm: {
      kem: kem.getAlgorithmName(serverKeys.securityLevel),
      dsa: dsa.getAlgorithmName(serverKeys.securityLevel),
    },
  };
}

/**
 * Compute fingerprint of public key
 * @param publicKey - Public key (hex string or Uint8Array)
 * @returns First 16 bytes of SHA3-256 hash as hex
 */
export function getPublicKeyFingerprint(publicKey: string | Uint8Array): string {
  const pk = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
  const hash = sha3_256(pk);
  return bytesToHex(hash.slice(0, 16));
}

export default {
  generateServerKeys,
  serializeKeys,
  deserializeKeys,
  setServerKeys,
  getServerKeys,
  getPublicKeys,
  getKemKeyPair,
  getDsaKeyPair,
  isInitialized,
  clearKeys,
  getMetadata,
  getPublicKeyFingerprint,
};
