/**
 * @quxtech/pqc-crypto - Hash Utilities Module Tests
 */

import { describe, it, expect } from 'vitest';
import * as hash from '../src/utils/hash.js';

describe('Hash Module', () => {
  describe('sha3256', () => {
    it('should compute SHA3-256 hash of string', () => {
      const result = hash.sha3256('hello');

      expect(result.length).toBe(64); // 32 bytes = 64 hex chars
      expect(result).toMatch(/^[0-9a-f]+$/i);
    });

    it('should produce consistent hashes', () => {
      const hash1 = hash.sha3256('test');
      const hash2 = hash.sha3256('test');

      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different inputs', () => {
      const hash1 = hash.sha3256('hello');
      const hash2 = hash.sha3256('world');

      expect(hash1).not.toBe(hash2);
    });

    it('should hash Uint8Array', () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const result = hash.sha3256(data);

      expect(result.length).toBe(64);
    });

    it('should hash hex string with 0x prefix', () => {
      const data = '0x48656c6c6f'; // "Hello" in hex
      const result = hash.sha3256(data);

      expect(result.length).toBe(64);
    });

    it('should match known SHA3-256 test vector', () => {
      // Test vector from NIST
      const result = hash.sha3256('');
      expect(result).toBe('a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
    });
  });

  describe('sha3512', () => {
    it('should compute SHA3-512 hash', () => {
      const result = hash.sha3512('hello');

      expect(result.length).toBe(128); // 64 bytes = 128 hex chars
      expect(result).toMatch(/^[0-9a-f]+$/i);
    });

    it('should match known SHA3-512 test vector', () => {
      const result = hash.sha3512('');
      expect(result).toBe('a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26');
    });
  });

  describe('keccak256', () => {
    it('should compute Keccak-256 hash (Ethereum-style)', () => {
      const result = hash.keccak256('hello');

      expect(result.length).toBe(64);
      expect(result).toMatch(/^[0-9a-f]+$/i);
    });

    it('should produce different result than SHA3-256', () => {
      const sha3 = hash.sha3256('hello');
      const keccak = hash.keccak256('hello');

      // Keccak-256 and SHA3-256 use different domain separation
      expect(sha3).not.toBe(keccak);
    });
  });

  describe('keccak512', () => {
    it('should compute Keccak-512 hash', () => {
      const result = hash.keccak512('hello');

      expect(result.length).toBe(128);
      expect(result).toMatch(/^[0-9a-f]+$/i);
    });
  });

  describe('sha3256Bytes/sha3512Bytes', () => {
    it('should return hash as Uint8Array for SHA3-256', () => {
      const result = hash.sha3256Bytes('hello');

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });

    it('should return hash as Uint8Array for SHA3-512', () => {
      const result = hash.sha3512Bytes('hello');

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(64);
    });
  });

  describe('hashMultiple', () => {
    it('should hash multiple values together', () => {
      const result = hash.hashMultiple('a', 'b', 'c');

      expect(result.length).toBe(64);
    });

    it('should produce different hash for different order', () => {
      const hash1 = hash.hashMultiple('a', 'b');
      const hash2 = hash.hashMultiple('b', 'a');

      expect(hash1).not.toBe(hash2);
    });

    it('should handle Uint8Array values', () => {
      const result = hash.hashMultiple('a', new Uint8Array([1, 2, 3]), 'b');

      expect(result.length).toBe(64);
    });
  });

  describe('hashObject', () => {
    it('should hash object with sorted keys', () => {
      const obj1 = { a: 1, b: 2 };
      const obj2 = { b: 2, a: 1 };

      const hash1 = hash.hashObject(obj1);
      const hash2 = hash.hashObject(obj2);

      // Keys are sorted, so order doesn't matter
      expect(hash1).toBe(hash2);
    });

    it('should produce different hash for different values', () => {
      const hash1 = hash.hashObject({ a: 1 });
      const hash2 = hash.hashObject({ a: 2 });

      expect(hash1).not.toBe(hash2);
    });

    it('should handle nested objects', () => {
      const obj = { outer: { inner: 'value' } };
      const result = hash.hashObject(obj);

      expect(result.length).toBe(64);
    });
  });

  describe('fingerprint', () => {
    it('should create short fingerprint', () => {
      const fp = hash.fingerprint('some data');

      // First 16 bytes = 32 hex chars
      expect(fp.length).toBe(32);
      expect(fp).toMatch(/^[0-9a-f]+$/i);
    });

    it('should produce consistent fingerprints', () => {
      const fp1 = hash.fingerprint('test');
      const fp2 = hash.fingerprint('test');

      expect(fp1).toBe(fp2);
    });

    it('should be prefix of full hash', () => {
      const data = 'test data';
      const fullHash = hash.sha3256(data);
      const fp = hash.fingerprint(data);

      expect(fullHash.startsWith(fp)).toBe(true);
    });
  });

  describe('verifyHash', () => {
    it('should verify matching hash', () => {
      const data = 'test data';
      const expectedHash = hash.sha3256(data);

      expect(hash.verifyHash(data, expectedHash)).toBe(true);
    });

    it('should reject non-matching hash', () => {
      const data = 'test data';
      const wrongHash = hash.sha3256('different data');

      expect(hash.verifyHash(data, wrongHash)).toBe(false);
    });

    it('should be case-insensitive', () => {
      const data = 'test';
      const expectedHash = hash.sha3256(data);

      expect(hash.verifyHash(data, expectedHash.toUpperCase())).toBe(true);
      expect(hash.verifyHash(data, expectedHash.toLowerCase())).toBe(true);
    });
  });

  describe('edge cases', () => {
    it('should handle empty string', () => {
      const result = hash.sha3256('');
      expect(result.length).toBe(64);
    });

    it('should handle unicode', () => {
      const result = hash.sha3256('你好世界 🔐');
      expect(result.length).toBe(64);
    });

    it('should handle very long strings', () => {
      const longString = 'A'.repeat(100000);
      const result = hash.sha3256(longString);
      expect(result.length).toBe(64);
    });
  });
});
