/**
 * @quxtech/pqc-crypto - KEM Module Tests
 */

import { describe, it, expect } from 'vitest';
import * as kem from '../src/core/kem.js';

describe('KEM Module', () => {
  describe('generateKeyPair', () => {
    it('should generate key pair at security level 5', () => {
      const keyPair = kem.generateKeyPair('5');

      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.secretKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(kem.getPublicKeySize('5'));
      expect(keyPair.secretKey.length).toBe(kem.getSecretKeySize('5'));
    });

    it('should generate key pair at security level 3', () => {
      const keyPair = kem.generateKeyPair('3');

      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.secretKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(kem.getPublicKeySize('3'));
      expect(keyPair.secretKey.length).toBe(kem.getSecretKeySize('3'));
    });

    it('should generate different keys each time', () => {
      const keyPair1 = kem.generateKeyPair('5');
      const keyPair2 = kem.generateKeyPair('5');

      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.secretKey).not.toEqual(keyPair2.secretKey);
    });
  });

  describe('generateKeyPairHex', () => {
    it('should generate hex-encoded key pair', () => {
      const keyPair = kem.generateKeyPairHex('5');

      expect(typeof keyPair.publicKey).toBe('string');
      expect(typeof keyPair.secretKey).toBe('string');
      expect(keyPair.publicKey).toMatch(/^[0-9a-f]+$/i);
      expect(keyPair.secretKey).toMatch(/^[0-9a-f]+$/i);
    });
  });

  describe('encapsulate/decapsulate', () => {
    it('should encapsulate and decapsulate shared secret at level 5', () => {
      const keyPair = kem.generateKeyPairHex('5');

      const { ciphertext, sharedSecret } = kem.encapsulate(keyPair.publicKey, '5');
      const decapsulated = kem.decapsulate(ciphertext, keyPair.secretKey, '5');

      expect(sharedSecret).toBe(decapsulated);
    });

    it('should encapsulate and decapsulate shared secret at level 3', () => {
      const keyPair = kem.generateKeyPairHex('3');

      const { ciphertext, sharedSecret } = kem.encapsulate(keyPair.publicKey, '3');
      const decapsulated = kem.decapsulate(ciphertext, keyPair.secretKey, '3');

      expect(sharedSecret).toBe(decapsulated);
    });

    it('should produce different ciphertexts for same public key', () => {
      const keyPair = kem.generateKeyPairHex('5');

      const result1 = kem.encapsulate(keyPair.publicKey, '5');
      const result2 = kem.encapsulate(keyPair.publicKey, '5');

      expect(result1.ciphertext).not.toBe(result2.ciphertext);
      expect(result1.sharedSecret).not.toBe(result2.sharedSecret);
    });

    it('should fail with wrong secret key', () => {
      const keyPair1 = kem.generateKeyPairHex('5');
      const keyPair2 = kem.generateKeyPairHex('5');

      const { ciphertext, sharedSecret } = kem.encapsulate(keyPair1.publicKey, '5');
      const wrongDecapsulated = kem.decapsulate(ciphertext, keyPair2.secretKey, '5');

      // ML-KEM is IND-CCA2 secure, so wrong key produces different (but valid) secret
      expect(wrongDecapsulated).not.toBe(sharedSecret);
    });
  });

  describe('getAlgorithmName', () => {
    it('should return ML-KEM-1024 for level 5', () => {
      expect(kem.getAlgorithmName('5')).toBe('ML-KEM-1024');
    });

    it('should return ML-KEM-768 for level 3', () => {
      expect(kem.getAlgorithmName('3')).toBe('ML-KEM-768');
    });
  });

  describe('size getters', () => {
    it('should return correct sizes for level 5', () => {
      expect(kem.getPublicKeySize('5')).toBe(1568);
      expect(kem.getSecretKeySize('5')).toBe(3168);
      expect(kem.getCiphertextSize('5')).toBe(1568);
      expect(kem.getSharedSecretSize('5')).toBe(32);
    });

    it('should return correct sizes for level 3', () => {
      expect(kem.getPublicKeySize('3')).toBe(1184);
      expect(kem.getSecretKeySize('3')).toBe(2400);
      expect(kem.getCiphertextSize('3')).toBe(1088);
      expect(kem.getSharedSecretSize('3')).toBe(32);
    });
  });
});
