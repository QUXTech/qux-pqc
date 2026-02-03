/**
 * @quxtech/pqc-crypto - Symmetric Encryption Module Tests
 */

import { describe, it, expect } from 'vitest';
import * as symmetric from '../src/core/symmetric.js';
import * as kem from '../src/core/kem.js';

describe('Symmetric Module', () => {
  describe('generateKey', () => {
    it('should generate 32-byte key', () => {
      const key = symmetric.generateKey();
      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(32);
    });

    it('should generate hex-encoded key', () => {
      const key = symmetric.generateKeyHex();
      expect(typeof key).toBe('string');
      expect(key.length).toBe(64); // 32 bytes = 64 hex chars
      expect(key).toMatch(/^[0-9a-f]+$/i);
    });

    it('should generate different keys each time', () => {
      const key1 = symmetric.generateKeyHex();
      const key2 = symmetric.generateKeyHex();
      expect(key1).not.toBe(key2);
    });
  });

  describe('deriveKey', () => {
    it('should derive key from shared secret', () => {
      const sharedSecret = symmetric.generateKeyHex();
      const key = symmetric.deriveKey(sharedSecret);

      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(32);
    });

    it('should derive hex key from shared secret', () => {
      const sharedSecret = symmetric.generateKeyHex();
      const key = symmetric.deriveKeyHex(sharedSecret);

      expect(typeof key).toBe('string');
      expect(key.length).toBe(64);
    });

    it('should derive same key from same secret and context', () => {
      const sharedSecret = symmetric.generateKeyHex();
      const key1 = symmetric.deriveKeyHex(sharedSecret, 'context-a');
      const key2 = symmetric.deriveKeyHex(sharedSecret, 'context-a');

      expect(key1).toBe(key2);
    });

    it('should derive different keys with different contexts', () => {
      const sharedSecret = symmetric.generateKeyHex();
      const key1 = symmetric.deriveKeyHex(sharedSecret, 'context-a');
      const key2 = symmetric.deriveKeyHex(sharedSecret, 'context-b');

      expect(key1).not.toBe(key2);
    });
  });

  describe('encrypt/decrypt', () => {
    it('should encrypt and decrypt string', () => {
      const key = symmetric.generateKeyHex();
      const plaintext = 'Hello, World!';

      const encrypted = symmetric.encrypt(plaintext, key);
      const decrypted = symmetric.decryptToString(encrypted, key);

      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt and decrypt object', () => {
      const key = symmetric.generateKeyHex();
      const data = { name: 'Alice', balance: 1000 };

      const encrypted = symmetric.encrypt(data, key);
      const decrypted = symmetric.decryptToString(encrypted, key);

      expect(JSON.parse(decrypted)).toEqual(data);
    });

    it('should produce different ciphertexts for same plaintext', () => {
      const key = symmetric.generateKeyHex();
      const plaintext = 'Same message';

      const encrypted1 = symmetric.encrypt(plaintext, key);
      const encrypted2 = symmetric.encrypt(plaintext, key);

      expect(encrypted1.nonce).not.toBe(encrypted2.nonce);
      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
    });

    it('should fail decryption with wrong key', () => {
      const key1 = symmetric.generateKeyHex();
      const key2 = symmetric.generateKeyHex();
      const plaintext = 'Secret message';

      const encrypted = symmetric.encrypt(plaintext, key1);

      expect(() => {
        symmetric.decryptToString(encrypted, key2);
      }).toThrow();
    });

    it('should fail decryption with tampered ciphertext', () => {
      const key = symmetric.generateKeyHex();
      const plaintext = 'Secret message';

      const encrypted = symmetric.encrypt(plaintext, key);

      // Tamper with ciphertext (flip hex chars to corrupt it while keeping valid hex)
      const ctChars = encrypted.ciphertext.split('');
      for (let i = 0; i < 10; i++) {
        ctChars[i] = ctChars[i] === 'a' ? 'b' : 'a';
      }
      const tampered = {
        ...encrypted,
        ciphertext: ctChars.join(''),
      };

      expect(() => {
        symmetric.decryptToString(tampered, key);
      }).toThrow();
    });
  });

  describe('encryptWithSecret/decryptWithSecret', () => {
    it('should encrypt and decrypt using KEM shared secret', () => {
      // Simulate KEM exchange
      const keyPair = kem.generateKeyPairHex('5');
      const { sharedSecret } = kem.encapsulate(keyPair.publicKey, '5');

      const plaintext = 'Secret message via KEM';
      const encrypted = symmetric.encryptWithSecret(plaintext, sharedSecret);
      const decrypted = symmetric.decryptWithSecret(encrypted, sharedSecret);

      expect(decrypted).toBe(plaintext);
    });

    it('should work with object data', () => {
      const keyPair = kem.generateKeyPairHex('5');
      const { sharedSecret } = kem.encapsulate(keyPair.publicKey, '5');

      const data = { transaction: 'abc123', amount: 500 };
      const encrypted = symmetric.encryptWithSecret(data, sharedSecret);
      const decrypted = symmetric.decryptWithSecret(encrypted, sharedSecret);

      expect(JSON.parse(decrypted)).toEqual(data);
    });
  });

  describe('encrypt/decrypt binary data', () => {
    it('should encrypt and decrypt binary data', () => {
      const key = symmetric.generateKey();
      const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

      const encrypted = symmetric.encrypt(data, key);
      const decrypted = symmetric.decrypt(encrypted, key);

      expect(decrypted).toEqual(data);
    });

    it('should handle large binary data', () => {
      const key = symmetric.generateKey();
      const data = new Uint8Array(10000);
      crypto.getRandomValues(data);

      const encrypted = symmetric.encrypt(data, key);
      const decrypted = symmetric.decrypt(encrypted, key);

      expect(decrypted).toEqual(data);
    });
  });

  describe('edge cases', () => {
    it('should handle empty string', () => {
      const key = symmetric.generateKeyHex();
      const plaintext = '';

      const encrypted = symmetric.encrypt(plaintext, key);
      const decrypted = symmetric.decryptToString(encrypted, key);

      expect(decrypted).toBe(plaintext);
    });

    it('should handle unicode characters', () => {
      const key = symmetric.generateKeyHex();
      const plaintext = '你好世界! 🔐 Привет мир!';

      const encrypted = symmetric.encrypt(plaintext, key);
      const decrypted = symmetric.decryptToString(encrypted, key);

      expect(decrypted).toBe(plaintext);
    });

    it('should handle very long strings', () => {
      const key = symmetric.generateKeyHex();
      const plaintext = 'A'.repeat(100000);

      const encrypted = symmetric.encrypt(plaintext, key);
      const decrypted = symmetric.decryptToString(encrypted, key);

      expect(decrypted).toBe(plaintext);
    });
  });
});
