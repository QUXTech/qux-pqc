/**
 * @quxtech/pqc-crypto - DSA Module Tests
 */

import { describe, it, expect } from 'vitest';
import * as dsa from '../src/core/dsa.js';

describe('DSA Module', () => {
  describe('generateKeyPair', () => {
    it('should generate key pair at security level 5', () => {
      const keyPair = dsa.generateKeyPair('5');

      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.secretKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(dsa.getPublicKeySize('5'));
      expect(keyPair.secretKey.length).toBe(dsa.getSecretKeySize('5'));
    });

    it('should generate key pair at security level 3', () => {
      const keyPair = dsa.generateKeyPair('3');

      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.secretKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(dsa.getPublicKeySize('3'));
      expect(keyPair.secretKey.length).toBe(dsa.getSecretKeySize('3'));
    });

    it('should generate different keys each time', () => {
      const keyPair1 = dsa.generateKeyPair('5');
      const keyPair2 = dsa.generateKeyPair('5');

      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.secretKey).not.toEqual(keyPair2.secretKey);
    });
  });

  describe('generateKeyPairHex', () => {
    it('should generate hex-encoded key pair', () => {
      const keyPair = dsa.generateKeyPairHex('5');

      expect(typeof keyPair.publicKey).toBe('string');
      expect(typeof keyPair.secretKey).toBe('string');
      expect(keyPair.publicKey).toMatch(/^[0-9a-f]+$/i);
      expect(keyPair.secretKey).toMatch(/^[0-9a-f]+$/i);
    });
  });

  describe('sign/verify', () => {
    it('should sign and verify message at level 5', () => {
      const keyPair = dsa.generateKeyPairHex('5');
      const message = 'Hello, quantum-safe world!';

      const signature = dsa.sign(message, keyPair.secretKey, '5');
      const isValid = dsa.verify(message, signature, keyPair.publicKey, '5');

      expect(isValid).toBe(true);
    });

    it('should sign and verify message at level 3', () => {
      const keyPair = dsa.generateKeyPairHex('3');
      const message = 'Test message for level 3';

      const signature = dsa.sign(message, keyPair.secretKey, '3');
      const isValid = dsa.verify(message, signature, keyPair.publicKey, '3');

      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong message', () => {
      const keyPair = dsa.generateKeyPairHex('5');
      const message = 'Original message';

      const signature = dsa.sign(message, keyPair.secretKey, '5');
      const isValid = dsa.verify('Tampered message', signature, keyPair.publicKey, '5');

      expect(isValid).toBe(false);
    });

    it('should fail verification with wrong public key', () => {
      const keyPair1 = dsa.generateKeyPairHex('5');
      const keyPair2 = dsa.generateKeyPairHex('5');
      const message = 'Test message';

      const signature = dsa.sign(message, keyPair1.secretKey, '5');
      const isValid = dsa.verify(message, signature, keyPair2.publicKey, '5');

      expect(isValid).toBe(false);
    });

    it('should produce consistent signatures (deterministic with same key)', () => {
      const keyPair = dsa.generateKeyPairHex('5');
      const message = 'Same message';

      const sig1 = dsa.sign(message, keyPair.secretKey, '5');
      const sig2 = dsa.sign(message, keyPair.secretKey, '5');

      // ML-DSA is deterministic with the same key
      expect(sig1).toBe(sig2);

      // Both should verify
      expect(dsa.verify(message, sig1, keyPair.publicKey, '5')).toBe(true);
    });

    it('should sign and verify stringified object data', () => {
      const keyPair = dsa.generateKeyPairHex('5');
      const data = { user: 'alice', amount: 100 };
      const message = JSON.stringify(data);

      const signature = dsa.sign(message, keyPair.secretKey, '5');
      const isValid = dsa.verify(message, signature, keyPair.publicKey, '5');

      expect(isValid).toBe(true);
    });
  });

  describe('signWithTimestamp/verifyWithTimestamp', () => {
    it('should sign with timestamp and verify within window', () => {
      const keyPair = dsa.generateKeyPairHex('5');
      const data = 'Time-sensitive data';

      const { signature, timestamp } = dsa.signWithTimestamp(data, keyPair.secretKey, '5');
      const result = dsa.verifyWithTimestamp(data, signature, timestamp, keyPair.publicKey, 300000, '5');

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should reject expired timestamp', () => {
      const keyPair = dsa.generateKeyPairHex('5');
      const data = 'Time-sensitive data';

      // Create signature with old timestamp
      const oldTimestamp = Date.now() - (10 * 60 * 1000); // 10 minutes ago
      const signature = dsa.sign(`${data}:${oldTimestamp}`, keyPair.secretKey, '5');

      const result = dsa.verifyWithTimestamp(data, signature, oldTimestamp, keyPair.publicKey, 300000, '5');

      expect(result.error).toBe('Signature expired');
      expect(result.valid).toBe(false);
    });

    it('should accept custom time window', () => {
      const keyPair = dsa.generateKeyPairHex('5');
      const data = 'Test data';

      const { signature, timestamp } = dsa.signWithTimestamp(data, keyPair.secretKey, '5');

      // Verify with 10-second window (should pass since just created)
      const result = dsa.verifyWithTimestamp(
        data, signature, timestamp, keyPair.publicKey, 10000, '5'
      );

      expect(result.valid).toBe(true);
    });
  });

  describe('getAlgorithmName', () => {
    it('should return ML-DSA-87 for level 5', () => {
      expect(dsa.getAlgorithmName('5')).toBe('ML-DSA-87');
    });

    it('should return ML-DSA-65 for level 3', () => {
      expect(dsa.getAlgorithmName('3')).toBe('ML-DSA-65');
    });
  });

  describe('size getters', () => {
    it('should return correct sizes for level 5', () => {
      expect(dsa.getPublicKeySize('5')).toBe(2592);
      expect(dsa.getSecretKeySize('5')).toBe(4896);
      expect(dsa.getSignatureSize('5')).toBe(4627);
    });

    it('should return correct sizes for level 3', () => {
      expect(dsa.getPublicKeySize('3')).toBe(1952);
      expect(dsa.getSecretKeySize('3')).toBe(4032);
      expect(dsa.getSignatureSize('3')).toBe(3309);
    });
  });
});
