/**
 * @quxtech/pqc-crypto - Hash Utilities Module
 * ============================================================================
 * SHA3 hash functions (NIST FIPS 202).
 * ============================================================================
 */

import { sha3_256, sha3_512, keccak_256, keccak_512 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

/**
 * Compute SHA3-256 hash
 * @param data - Data to hash (string, hex string with 0x prefix, or Uint8Array)
 * @returns Hash as hex string
 */
export function sha3256(data: string | Uint8Array): string {
  let input: Uint8Array;

  if (data instanceof Uint8Array) {
    input = data;
  } else if (data.startsWith('0x')) {
    input = hexToBytes(data.slice(2));
  } else {
    input = utf8ToBytes(data);
  }

  return bytesToHex(sha3_256(input));
}

/**
 * Compute SHA3-512 hash
 * @param data - Data to hash
 * @returns Hash as hex string
 */
export function sha3512(data: string | Uint8Array): string {
  let input: Uint8Array;

  if (data instanceof Uint8Array) {
    input = data;
  } else if (data.startsWith('0x')) {
    input = hexToBytes(data.slice(2));
  } else {
    input = utf8ToBytes(data);
  }

  return bytesToHex(sha3_512(input));
}

/**
 * Compute Keccak-256 hash (Ethereum-style)
 * @param data - Data to hash
 * @returns Hash as hex string
 */
export function keccak256(data: string | Uint8Array): string {
  let input: Uint8Array;

  if (data instanceof Uint8Array) {
    input = data;
  } else if (data.startsWith('0x')) {
    input = hexToBytes(data.slice(2));
  } else {
    input = utf8ToBytes(data);
  }

  return bytesToHex(keccak_256(input));
}

/**
 * Compute Keccak-512 hash
 * @param data - Data to hash
 * @returns Hash as hex string
 */
export function keccak512(data: string | Uint8Array): string {
  let input: Uint8Array;

  if (data instanceof Uint8Array) {
    input = data;
  } else if (data.startsWith('0x')) {
    input = hexToBytes(data.slice(2));
  } else {
    input = utf8ToBytes(data);
  }

  return bytesToHex(keccak_512(input));
}

/**
 * Compute SHA3-256 hash and return as Uint8Array
 * @param data - Data to hash
 * @returns Hash as Uint8Array
 */
export function sha3256Bytes(data: string | Uint8Array): Uint8Array {
  const input = typeof data === 'string' ? utf8ToBytes(data) : data;
  return sha3_256(input);
}

/**
 * Compute SHA3-512 hash and return as Uint8Array
 * @param data - Data to hash
 * @returns Hash as Uint8Array
 */
export function sha3512Bytes(data: string | Uint8Array): Uint8Array {
  const input = typeof data === 'string' ? utf8ToBytes(data) : data;
  return sha3_512(input);
}

/**
 * Hash multiple values together
 * @param values - Array of values to hash
 * @returns Combined hash as hex string
 */
export function hashMultiple(...values: (string | Uint8Array)[]): string {
  const combined = values.map(v => {
    if (v instanceof Uint8Array) return bytesToHex(v);
    return v;
  }).join(':');

  return sha3256(combined);
}

/**
 * Create a content hash for structured data
 * @param data - Object to hash
 * @returns Hash as hex string
 */
export function hashObject(data: Record<string, unknown>): string {
  // Sort keys for deterministic hashing
  const sortedKeys = Object.keys(data).sort();
  const values = sortedKeys.map(k => `${k}=${JSON.stringify(data[k])}`);
  return sha3256(values.join('&'));
}

/**
 * Compute a short fingerprint (first 8 bytes of hash)
 * @param data - Data to fingerprint
 * @returns Short hash as hex string (16 characters)
 */
export function fingerprint(data: string | Uint8Array): string {
  const hash = sha3256(data);
  return hash.slice(0, 32); // First 16 bytes = 32 hex chars
}

/**
 * Verify data matches a hash
 * @param data - Data to verify
 * @param expectedHash - Expected hash value
 * @returns True if hash matches
 */
export function verifyHash(data: string | Uint8Array, expectedHash: string): boolean {
  const actualHash = sha3256(data);
  return actualHash.toLowerCase() === expectedHash.toLowerCase();
}

export default {
  sha3256,
  sha3512,
  keccak256,
  keccak512,
  sha3256Bytes,
  sha3512Bytes,
  hashMultiple,
  hashObject,
  fingerprint,
  verifyHash,
};
