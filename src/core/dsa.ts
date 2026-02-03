/**
 * @quxtech/pqc-crypto - Digital Signature Module (ML-DSA / CRYSTALS-Dilithium)
 * ============================================================================
 * Implements NIST FIPS 204 ML-DSA for post-quantum digital signatures.
 *
 * Supported algorithms:
 * - ML-DSA-65 (NIST Security Level 3, ~AES-192)
 * - ML-DSA-87 (NIST Security Level 5, ~AES-256)
 * ============================================================================
 */

import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils';
import type { SecurityLevel, KeyPair } from '../types.js';

// Algorithm mapping
const DSA_ALGORITHMS = {
  '3': ml_dsa65,
  '5': ml_dsa87,
} as const;

const DSA_NAMES = {
  '3': 'ML-DSA-65',
  '5': 'ML-DSA-87',
} as const;

/**
 * Generate a new ML-DSA key pair
 * @param securityLevel - NIST security level ('3' or '5')
 * @returns Key pair with publicKey and secretKey as Uint8Array
 */
export function generateKeyPair(securityLevel: SecurityLevel = '5'): KeyPair {
  const dsa = DSA_ALGORITHMS[securityLevel];
  const seed = randomBytes(32);
  return dsa.keygen(seed);
}

/**
 * Generate a new ML-DSA key pair with hex-encoded keys
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
 * Sign a message using secret key
 * @param message - Message to sign (string or Uint8Array)
 * @param secretKey - ML-DSA secret key (hex string or Uint8Array)
 * @param securityLevel - NIST security level ('3' or '5')
 * @returns Signature (hex-encoded)
 */
export function sign(
  message: string | Uint8Array,
  secretKey: string | Uint8Array,
  securityLevel: SecurityLevel = '5'
): string {
  const dsa = DSA_ALGORITHMS[securityLevel];
  const msg = typeof message === 'string' ? utf8ToBytes(message) : message;
  const sk = typeof secretKey === 'string' ? hexToBytes(secretKey) : secretKey;

  const signature = dsa.sign(sk, msg);
  return bytesToHex(signature);
}

/**
 * Verify a signature
 * @param message - Original message (string or Uint8Array)
 * @param signature - Signature to verify (hex string or Uint8Array)
 * @param publicKey - Signer's public key (hex string or Uint8Array)
 * @param securityLevel - NIST security level ('3' or '5')
 * @returns True if signature is valid
 */
export function verify(
  message: string | Uint8Array,
  signature: string | Uint8Array,
  publicKey: string | Uint8Array,
  securityLevel: SecurityLevel = '5'
): boolean {
  const dsa = DSA_ALGORITHMS[securityLevel];
  const msg = typeof message === 'string' ? utf8ToBytes(message) : message;
  const sig = typeof signature === 'string' ? hexToBytes(signature) : signature;
  const pk = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;

  try {
    return dsa.verify(pk, msg, sig);
  } catch {
    return false;
  }
}

/**
 * Sign data with timestamp for replay protection
 * @param data - Data to sign
 * @param secretKey - ML-DSA secret key
 * @param securityLevel - NIST security level
 * @returns Object with signature and timestamp
 */
export function signWithTimestamp(
  data: string | Uint8Array,
  secretKey: string | Uint8Array,
  securityLevel: SecurityLevel = '5'
): { signature: string; timestamp: number } {
  const timestamp = Date.now();
  const dataStr = typeof data === 'string' ? data : bytesToHex(data);
  const message = `${dataStr}:${timestamp}`;
  const signature = sign(message, secretKey, securityLevel);

  return { signature, timestamp };
}

/**
 * Verify a timestamped signature with optional time window
 * @param data - Original data
 * @param signature - Signature to verify
 * @param timestamp - Timestamp from signing
 * @param publicKey - Signer's public key
 * @param maxAgeMs - Maximum age in milliseconds (default: 5 minutes)
 * @param securityLevel - NIST security level
 * @returns Object with valid flag and error message if invalid
 */
export function verifyWithTimestamp(
  data: string | Uint8Array,
  signature: string,
  timestamp: number,
  publicKey: string | Uint8Array,
  maxAgeMs: number = 300000,
  securityLevel: SecurityLevel = '5'
): { valid: boolean; error?: string } {
  // Check timestamp freshness
  const age = Date.now() - timestamp;
  if (age > maxAgeMs) {
    return { valid: false, error: 'Signature expired' };
  }
  if (age < -30000) { // Allow 30 seconds clock skew in future
    return { valid: false, error: 'Signature timestamp in future' };
  }

  // Verify signature
  const dataStr = typeof data === 'string' ? data : bytesToHex(data);
  const message = `${dataStr}:${timestamp}`;
  const valid = verify(message, signature, publicKey, securityLevel);

  if (!valid) {
    return { valid: false, error: 'Invalid signature' };
  }

  return { valid: true };
}

/**
 * Get algorithm name for security level
 * @param securityLevel - NIST security level
 * @returns Algorithm name string
 */
export function getAlgorithmName(securityLevel: SecurityLevel = '5'): string {
  return DSA_NAMES[securityLevel];
}

/**
 * Get public key size in bytes for security level
 */
export function getPublicKeySize(securityLevel: SecurityLevel = '5'): number {
  return securityLevel === '5' ? 2592 : 1952;
}

/**
 * Get secret key size in bytes for security level
 */
export function getSecretKeySize(securityLevel: SecurityLevel = '5'): number {
  return securityLevel === '5' ? 4896 : 4032;
}

/**
 * Get signature size in bytes for security level
 */
export function getSignatureSize(securityLevel: SecurityLevel = '5'): number {
  return securityLevel === '5' ? 4627 : 3309;
}

export default {
  generateKeyPair,
  generateKeyPairHex,
  sign,
  verify,
  signWithTimestamp,
  verifyWithTimestamp,
  getAlgorithmName,
  getPublicKeySize,
  getSecretKeySize,
  getSignatureSize,
};
