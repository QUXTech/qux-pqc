/**
 * @quxtech/pqc-crypto - Key Management Module Tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as keys from '../src/core/keys.js';

describe('Keys Module', () => {
  beforeEach(() => {
    keys.clearKeys();
  });

  afterEach(() => {
    keys.clearKeys();
  });

  describe('generateServerKeys', () => {
    it('should generate server keys at level 5', () => {
      const serverKeys = keys.generateServerKeys('5');

      expect(serverKeys.initialized).toBe(true);
      expect(serverKeys.securityLevel).toBe('5');
      expect(serverKeys.kem.publicKey).toBeInstanceOf(Uint8Array);
      expect(serverKeys.kem.secretKey).toBeInstanceOf(Uint8Array);
      expect(serverKeys.dsa.publicKey).toBeInstanceOf(Uint8Array);
      expect(serverKeys.dsa.secretKey).toBeInstanceOf(Uint8Array);
    });

    it('should generate server keys at level 3', () => {
      const serverKeys = keys.generateServerKeys('3');

      expect(serverKeys.initialized).toBe(true);
      expect(serverKeys.securityLevel).toBe('3');
    });

    it('should include generation timestamp', () => {
      const serverKeys = keys.generateServerKeys('5');

      expect(serverKeys.generatedAt).toBeDefined();
      expect(new Date(serverKeys.generatedAt!).getTime()).toBeCloseTo(Date.now(), -2);
    });
  });

  describe('serializeKeys/deserializeKeys', () => {
    it('should serialize and deserialize keys with passphrase', () => {
      const original = keys.generateServerKeys('5');
      const passphrase = 'test-passphrase-12345';

      const encrypted = keys.serializeKeys(original, passphrase);

      expect(encrypted.version).toBe(1);
      expect(encrypted.salt).toBeDefined();
      expect(encrypted.nonce).toBeDefined();
      expect(encrypted.ciphertext).toBeDefined();

      // Clear and reload
      keys.clearKeys();
      const loaded = keys.deserializeKeys(encrypted, passphrase);

      expect(loaded.initialized).toBe(true);
      expect(loaded.securityLevel).toBe('5');
    });

    it('should fail deserialization with wrong passphrase', () => {
      const original = keys.generateServerKeys('5');
      const encrypted = keys.serializeKeys(original, 'correct-passphrase');

      keys.clearKeys();

      expect(() => {
        keys.deserializeKeys(encrypted, 'wrong-passphrase');
      }).toThrow('Failed to decrypt keys');
    });

    it('should preserve key metadata after serialization', () => {
      const original = keys.generateServerKeys('5');
      const passphrase = 'test-passphrase';

      const encrypted = keys.serializeKeys(original, passphrase);
      keys.clearKeys();
      const loaded = keys.deserializeKeys(encrypted, passphrase);

      expect(loaded.generatedAt).toBe(original.generatedAt);
      expect(loaded.securityLevel).toBe(original.securityLevel);
    });

    it('should produce different encrypted output each time', () => {
      const serverKeys = keys.generateServerKeys('5');
      const passphrase = 'test-passphrase';

      const encrypted1 = keys.serializeKeys(serverKeys, passphrase);
      const encrypted2 = keys.serializeKeys(serverKeys, passphrase);

      // Different salt and nonce
      expect(encrypted1.salt).not.toBe(encrypted2.salt);
      expect(encrypted1.nonce).not.toBe(encrypted2.nonce);
    });
  });

  describe('getPublicKeys', () => {
    it('should return public keys for distribution', () => {
      keys.generateServerKeys('5');

      const publicKeys = keys.getPublicKeys();

      expect(publicKeys.kemPublicKey).toBeDefined();
      expect(publicKeys.dsaPublicKey).toBeDefined();
      expect(publicKeys.securityLevel).toBe('5');
      expect(publicKeys.algorithm.kem).toBe('ML-KEM-1024');
      expect(publicKeys.algorithm.dsa).toBe('ML-DSA-87');
    });

    it('should throw if keys not initialized', () => {
      expect(() => {
        keys.getPublicKeys();
      }).toThrow('Server keys not initialized');
    });
  });

  describe('getServerKeys', () => {
    it('should return null if not initialized', () => {
      expect(keys.getServerKeys()).toBeNull();
    });

    it('should return keys after generation', () => {
      keys.generateServerKeys('5');

      const serverKeys = keys.getServerKeys();
      expect(serverKeys).not.toBeNull();
      expect(serverKeys!.initialized).toBe(true);
    });
  });

  describe('isInitialized', () => {
    it('should return false initially', () => {
      expect(keys.isInitialized()).toBe(false);
    });

    it('should return true after key generation', () => {
      keys.generateServerKeys('5');
      expect(keys.isInitialized()).toBe(true);
    });

    it('should return false after clearing keys', () => {
      keys.generateServerKeys('5');
      keys.clearKeys();
      expect(keys.isInitialized()).toBe(false);
    });
  });

  describe('getKemKeyPair/getDsaKeyPair', () => {
    it('should return KEM key pair', () => {
      keys.generateServerKeys('5');

      const kemKeyPair = keys.getKemKeyPair();
      expect(kemKeyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(kemKeyPair.secretKey).toBeInstanceOf(Uint8Array);
    });

    it('should return DSA key pair', () => {
      keys.generateServerKeys('5');

      const dsaKeyPair = keys.getDsaKeyPair();
      expect(dsaKeyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(dsaKeyPair.secretKey).toBeInstanceOf(Uint8Array);
    });

    it('should throw if not initialized', () => {
      expect(() => keys.getKemKeyPair()).toThrow('Server keys not initialized');
      expect(() => keys.getDsaKeyPair()).toThrow('Server keys not initialized');
    });
  });

  describe('clearKeys', () => {
    it('should clear keys from memory', () => {
      keys.generateServerKeys('5');
      expect(keys.isInitialized()).toBe(true);

      keys.clearKeys();

      expect(keys.isInitialized()).toBe(false);
      expect(keys.getServerKeys()).toBeNull();
    });

    it('should zero out secret keys', () => {
      const serverKeys = keys.generateServerKeys('5');
      const kemSecretKey = serverKeys.kem.secretKey;
      const dsaSecretKey = serverKeys.dsa.secretKey;

      keys.clearKeys();

      // Keys should be zeroed (all zeros)
      expect(kemSecretKey.every(b => b === 0)).toBe(true);
      expect(dsaSecretKey.every(b => b === 0)).toBe(true);
    });
  });

  describe('getMetadata', () => {
    it('should return null if not initialized', () => {
      expect(keys.getMetadata()).toBeNull();
    });

    it('should return metadata after generation', () => {
      keys.generateServerKeys('5');

      const metadata = keys.getMetadata();
      expect(metadata).not.toBeNull();
      expect(metadata!.securityLevel).toBe('5');
      expect(metadata!.algorithm.kem).toBe('ML-KEM-1024');
      expect(metadata!.algorithm.dsa).toBe('ML-DSA-87');
      expect(metadata!.generatedAt).toBeDefined();
    });
  });

  describe('getPublicKeyFingerprint', () => {
    it('should compute fingerprint of public key', () => {
      keys.generateServerKeys('5');
      const publicKeys = keys.getPublicKeys();

      const fingerprint = keys.getPublicKeyFingerprint(publicKeys.kemPublicKey);

      expect(fingerprint.length).toBe(32); // 16 bytes = 32 hex chars
      expect(fingerprint).toMatch(/^[0-9a-f]+$/i);
    });

    it('should produce same fingerprint for same key', () => {
      keys.generateServerKeys('5');
      const publicKeys = keys.getPublicKeys();

      const fp1 = keys.getPublicKeyFingerprint(publicKeys.kemPublicKey);
      const fp2 = keys.getPublicKeyFingerprint(publicKeys.kemPublicKey);

      expect(fp1).toBe(fp2);
    });

    it('should produce different fingerprints for different keys', () => {
      keys.generateServerKeys('5');
      const publicKeys = keys.getPublicKeys();

      const kemFp = keys.getPublicKeyFingerprint(publicKeys.kemPublicKey);
      const dsaFp = keys.getPublicKeyFingerprint(publicKeys.dsaPublicKey);

      expect(kemFp).not.toBe(dsaFp);
    });
  });

  describe('setServerKeys', () => {
    it('should set server keys directly', () => {
      const original = keys.generateServerKeys('5');
      keys.clearKeys();

      keys.setServerKeys(original);

      expect(keys.isInitialized()).toBe(true);
      expect(keys.getServerKeys()).toBe(original);
    });
  });
});
