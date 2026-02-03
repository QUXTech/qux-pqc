/**
 * @quxtech/pqc-crypto - Integration Tests
 * Tests full workflows combining multiple modules
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  generateKeyPairs,
  quickEncapsulate,
  quickDecapsulate,
  encryptAndSign,
  verifyAndDecrypt,
  getAlgorithmInfo,
  computeHash,
} from '../src/index.js';
import * as kem from '../src/core/kem.js';
import * as dsa from '../src/core/dsa.js';
import * as symmetric from '../src/core/symmetric.js';
import * as keys from '../src/core/keys.js';
import * as session from '../src/core/session.js';

describe('Integration Tests', () => {
  beforeEach(() => {
    keys.clearKeys();
    session.clearAllSessions();
  });

  afterEach(() => {
    keys.clearKeys();
    session.clearAllSessions();
  });

  describe('generateKeyPairs', () => {
    it('should generate complete key set', () => {
      const keySet = generateKeyPairs('5');

      expect(keySet.kem.publicKey).toBeDefined();
      expect(keySet.kem.secretKey).toBeDefined();
      expect(keySet.dsa.publicKey).toBeDefined();
      expect(keySet.dsa.secretKey).toBeDefined();
      expect(keySet.securityLevel).toBe('5');
      expect(keySet.algorithm.kem).toBe('ML-KEM-1024');
      expect(keySet.algorithm.dsa).toBe('ML-DSA-87');
    });
  });

  describe('quickEncapsulate/quickDecapsulate', () => {
    it('should perform quick key exchange', () => {
      const alice = generateKeyPairs('5');

      const { ciphertext, encryptionKey } = quickEncapsulate(alice.kem.publicKey, '5');
      const { encryptionKey: recoveredKey } = quickDecapsulate(
        ciphertext,
        alice.kem.secretKey,
        '5'
      );

      expect(encryptionKey).toBe(recoveredKey);
    });
  });

  describe('encryptAndSign/verifyAndDecrypt', () => {
    it('should encrypt, sign, verify, and decrypt', () => {
      const alice = generateKeyPairs('5');
      const bob = generateKeyPairs('5');
      const message = { secret: 'classified data', amount: 1000 };

      // Alice encrypts to Bob and signs
      const payload = encryptAndSign(
        message,
        bob.kem.publicKey,
        alice.dsa.secretKey,
        '5'
      );

      // Bob verifies Alice's signature and decrypts
      const decrypted = verifyAndDecrypt(
        payload,
        alice.dsa.publicKey,
        bob.kem.secretKey,
        '5'
      );

      expect(JSON.parse(decrypted)).toEqual(message);
    });

    it('should reject tampered signature', () => {
      const alice = generateKeyPairs('5');
      const bob = generateKeyPairs('5');

      const payload = encryptAndSign(
        'secret message',
        bob.kem.publicKey,
        alice.dsa.secretKey,
        '5'
      );

      // Tamper with signature (flip hex chars to corrupt it while keeping valid hex)
      const sigChars = payload.signature.split('');
      // Flip first few hex chars
      for (let i = 0; i < 10; i++) {
        sigChars[i] = sigChars[i] === 'a' ? 'b' : 'a';
      }
      payload.signature = sigChars.join('');

      expect(() => {
        verifyAndDecrypt(payload, alice.dsa.publicKey, bob.kem.secretKey, '5');
      }).toThrow('Signature verification failed');
    });

    it('should reject if wrong sender key used for verification', () => {
      const alice = generateKeyPairs('5');
      const bob = generateKeyPairs('5');
      const eve = generateKeyPairs('5');

      const payload = encryptAndSign(
        'secret',
        bob.kem.publicKey,
        alice.dsa.secretKey,
        '5'
      );

      // Try to verify with Eve's public key instead of Alice's
      expect(() => {
        verifyAndDecrypt(payload, eve.dsa.publicKey, bob.kem.secretKey, '5');
      }).toThrow('Signature verification failed');
    });
  });

  describe('Full communication flow', () => {
    it('should handle bidirectional secure communication', () => {
      const alice = generateKeyPairs('5');
      const bob = generateKeyPairs('5');

      // Alice sends to Bob
      const aliceToBob = encryptAndSign(
        'Hello Bob!',
        bob.kem.publicKey,
        alice.dsa.secretKey,
        '5'
      );
      const bobReceived = verifyAndDecrypt(
        aliceToBob,
        alice.dsa.publicKey,
        bob.kem.secretKey,
        '5'
      );
      expect(bobReceived).toBe('Hello Bob!');

      // Bob replies to Alice
      const bobToAlice = encryptAndSign(
        'Hi Alice!',
        alice.kem.publicKey,
        bob.dsa.secretKey,
        '5'
      );
      const aliceReceived = verifyAndDecrypt(
        bobToAlice,
        bob.dsa.publicKey,
        alice.kem.secretKey,
        '5'
      );
      expect(aliceReceived).toBe('Hi Alice!');
    });
  });

  describe('Key exchange with symmetric encryption', () => {
    it('should establish shared key and encrypt messages', () => {
      const alice = generateKeyPairs('5');
      const bob = generateKeyPairs('5');

      // Alice encapsulates to Bob
      const { ciphertext, sharedSecret } = kem.encapsulate(bob.kem.publicKey, '5');

      // Bob decapsulates
      const bobSecret = kem.decapsulate(ciphertext, bob.kem.secretKey, '5');

      // Both should have same secret
      expect(sharedSecret).toBe(bobSecret);

      // Alice encrypts with shared secret
      const encrypted = symmetric.encryptWithSecret('Secret message', sharedSecret);

      // Bob decrypts with his recovered secret
      const decrypted = symmetric.decryptWithSecret(encrypted, bobSecret);

      expect(decrypted).toBe('Secret message');
    });
  });

  describe('Session management flow', () => {
    it('should create and use encrypted session', async () => {
      // Generate server keys
      keys.generateServerKeys('5');
      const serverPublicKeys = keys.getPublicKeys();

      // Client generates keys
      const clientKeys = generateKeyPairs('5');

      // Create session
      const sessionId = session.generateSessionId();
      const sessionResponse = await session.createSession(
        sessionId,
        clientKeys.kem.publicKey,
        '5'
      );

      expect(sessionResponse.sessionId).toBe(sessionId);
      expect(sessionResponse.ciphertext).toBeDefined();
      expect(sessionResponse.signature).toBeDefined();

      // Get session secret
      const secret = await session.getSessionSecret(sessionId);
      expect(secret).toBeDefined();

      // Verify session is valid
      const isValid = await session.isSessionValid(sessionId);
      expect(isValid).toBe(true);

      // Destroy session
      await session.destroySession(sessionId);
      const afterDestroy = await session.getSessionSecret(sessionId);
      expect(afterDestroy).toBeNull();
    });
  });

  describe('Key persistence flow', () => {
    it('should persist and load server keys', () => {
      // Generate keys
      const original = keys.generateServerKeys('5');
      const passphrase = 'super-secret-passphrase-123!';

      // Serialize to encrypted format
      const encrypted = keys.serializeKeys(original, passphrase);

      // Clear memory
      keys.clearKeys();
      expect(keys.isInitialized()).toBe(false);

      // Load from encrypted storage
      const loaded = keys.deserializeKeys(encrypted, passphrase);

      expect(loaded.initialized).toBe(true);
      expect(loaded.securityLevel).toBe('5');

      // Verify keys work by creating and verifying signature
      const message = 'Test message';
      const signature = dsa.sign(
        message,
        loaded.dsa.secretKey,
        loaded.securityLevel
      );

      const publicKeys = keys.getPublicKeys();
      const isValid = dsa.verify(message, signature, publicKeys.dsaPublicKey, '5');
      expect(isValid).toBe(true);
    });
  });

  describe('getAlgorithmInfo', () => {
    it('should return algorithm info for level 5', () => {
      const info = getAlgorithmInfo('5');

      expect(info.kem).toBe('ML-KEM-1024');
      expect(info.dsa).toBe('ML-DSA-87');
      expect(info.symmetric).toBe('AES-256-GCM');
      expect(info.hash).toBe('SHA3-256/512');
      expect(info.securityLevel).toBe('5');
      expect(info.nistFips).toContain('FIPS 203');
      expect(info.nistFips).toContain('FIPS 204');
    });

    it('should return algorithm info for level 3', () => {
      const info = getAlgorithmInfo('3');

      expect(info.kem).toBe('ML-KEM-768');
      expect(info.dsa).toBe('ML-DSA-65');
    });
  });

  describe('computeHash', () => {
    it('should compute SHA3-256 hash', () => {
      const hash = computeHash('test data');
      expect(hash.length).toBe(64);
    });
  });

  describe('Security level consistency', () => {
    it('should work with level 3 throughout', () => {
      const alice = generateKeyPairs('3');
      const bob = generateKeyPairs('3');

      const payload = encryptAndSign(
        'Level 3 message',
        bob.kem.publicKey,
        alice.dsa.secretKey,
        '3'
      );

      const decrypted = verifyAndDecrypt(
        payload,
        alice.dsa.publicKey,
        bob.kem.secretKey,
        '3'
      );

      expect(decrypted).toBe('Level 3 message');
    });
  });

  describe('Performance characteristics', () => {
    it('should handle multiple operations efficiently', () => {
      const start = Date.now();

      // Generate 10 key pairs
      const keyPairs = Array.from({ length: 10 }, () => generateKeyPairs('5'));

      // Perform 50 encapsulation/decapsulation pairs
      for (let i = 0; i < 50; i++) {
        const sender = keyPairs[i % keyPairs.length];
        const recipient = keyPairs[(i + 1) % keyPairs.length];

        const { ciphertext, sharedSecret } = kem.encapsulate(recipient.kem.publicKey, '5');
        const recovered = kem.decapsulate(ciphertext, recipient.kem.secretKey, '5');

        expect(recovered).toBe(sharedSecret);
      }

      const elapsed = Date.now() - start;
      // Should complete in reasonable time (adjust threshold as needed)
      expect(elapsed).toBeLessThan(30000); // 30 seconds max
    });
  });
});
