/**
 * @quxtech/pqc-crypto - Key Encapsulation Module (ML-KEM / CRYSTALS-Kyber)
 * ============================================================================
 * Implements NIST FIPS 203 ML-KEM for post-quantum key encapsulation.
 *
 * Supported algorithms:
 * - ML-KEM-768 (NIST Security Level 3, ~AES-192)
 * - ML-KEM-1024 (NIST Security Level 5, ~AES-256)
 * ============================================================================
 */

import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import type { SecurityLevel, KeyPair, EncapsulationResult } from '../types.js';

// Algorithm mapping
const KEM_ALGORITHMS = {
  '3': ml_kem768,
  '5': ml_kem1024,
} as const;

const KEM_NAMES = {
  '3': 'ML-KEM-768',
  '5': 'ML-KEM-1024',
} as const;

/**
 * Generate a new ML-KEM key pair
 * @param securityLevel - NIST security level ('3' or '5')
 * @returns Key pair with publicKey and secretKey as Uint8Array
 */
export function generateKeyPair(securityLevel: SecurityLevel = '5'): KeyPair {
  const kem = KEM_ALGORITHMS[securityLevel];
  const seed = randomBytes(64); // ML-KEM requires 64 bytes seed
  return kem.keygen(seed);
}

/**
 * Generate a new ML-KEM key pair with hex-encoded keys
 * @param securityLevel - NIST security level ('3' or '5')
 * @returns Key pair with hex-encoded publicKey and secretKey
 */
export function generateKeyPairHex(securityLevel: SecurityLevel = '5'): { publicKey: string; secretKey: string } {
  const keyPair = generateKeyPair(securityLevel);
  return {
    publicKey: bytesToHex(keyPair.publicKey),
    secretKey: bytesToHex(keyPair.secretKey),
  };
}

/**
 * Encapsulate a shared secret using recipient's public key
 * @param recipientPublicKey - Recipient's ML-KEM public key (hex string or Uint8Array)
 * @param securityLevel - NIST security level ('3' or '5')
 * @returns Ciphertext and shared secret (both hex-encoded)
 */
export function encapsulate(
  recipientPublicKey: string | Uint8Array,
  securityLevel: SecurityLevel = '5'
): EncapsulationResult {
  const kem = KEM_ALGORITHMS[securityLevel];
  const publicKey = typeof recipientPublicKey === 'string'
    ? hexToBytes(recipientPublicKey)
    : recipientPublicKey;

  const { cipherText, sharedSecret } = kem.encapsulate(publicKey);

  return {
    ciphertext: bytesToHex(cipherText),
    sharedSecret: bytesToHex(sharedSecret),
  };
}

/**
 * Decapsulate to recover shared secret using secret key
 * @param ciphertext - Encapsulated ciphertext (hex string or Uint8Array)
 * @param secretKey - ML-KEM secret key (hex string or Uint8Array)
 * @param securityLevel - NIST security level ('3' or '5')
 * @returns Shared secret (hex-encoded)
 */
export function decapsulate(
  ciphertext: string | Uint8Array,
  secretKey: string | Uint8Array,
  securityLevel: SecurityLevel = '5'
): string {
  const kem = KEM_ALGORITHMS[securityLevel];
  const ct = typeof ciphertext === 'string' ? hexToBytes(ciphertext) : ciphertext;
  const sk = typeof secretKey === 'string' ? hexToBytes(secretKey) : secretKey;

  const sharedSecret = kem.decapsulate(ct, sk);
  return bytesToHex(sharedSecret);
}

/**
 * Get algorithm name for security level
 * @param securityLevel - NIST security level
 * @returns Algorithm name string
 */
export function getAlgorithmName(securityLevel: SecurityLevel = '5'): string {
  return KEM_NAMES[securityLevel];
}

/**
 * Get public key size in bytes for security level
 */
export function getPublicKeySize(securityLevel: SecurityLevel = '5'): number {
  return securityLevel === '5' ? 1568 : 1184;
}

/**
 * Get secret key size in bytes for security level
 */
export function getSecretKeySize(securityLevel: SecurityLevel = '5'): number {
  return securityLevel === '5' ? 3168 : 2400;
}

/**
 * Get ciphertext size in bytes for security level
 */
export function getCiphertextSize(securityLevel: SecurityLevel = '5'): number {
  return securityLevel === '5' ? 1568 : 1088;
}

/**
 * Get shared secret size in bytes (always 32 bytes)
 */
export function getSharedSecretSize(): number {
  return 32;
}

export default {
  generateKeyPair,
  generateKeyPairHex,
  encapsulate,
  decapsulate,
  getAlgorithmName,
  getPublicKeySize,
  getSecretKeySize,
  getCiphertextSize,
  getSharedSecretSize,
};
