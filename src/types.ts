/**
 * @quxtech/pqc-crypto - Type Definitions
 * ============================================================================
 * Post-Quantum Cryptography type definitions
 * ============================================================================
 */

// =============================================================================
// SECURITY LEVELS
// =============================================================================

/**
 * NIST Security Levels
 * - Level 3: ~AES-192 equivalent (ML-KEM-768, ML-DSA-65)
 * - Level 5: ~AES-256 equivalent (ML-KEM-1024, ML-DSA-87)
 */
export type SecurityLevel = '3' | '5';

// =============================================================================
// KEY TYPES
// =============================================================================

/**
 * Generic key pair
 */
export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * Key pair with hex-encoded keys
 */
export interface HexKeyPair {
  publicKey: string;
  secretKey: string;
}

/**
 * ML-KEM (Kyber) specific key pair
 */
export interface KemKeyPair extends KeyPair {
  algorithm: 'ML-KEM-768' | 'ML-KEM-1024';
}

/**
 * ML-DSA (Dilithium) specific key pair
 */
export interface DsaKeyPair extends KeyPair {
  algorithm: 'ML-DSA-65' | 'ML-DSA-87';
}

/**
 * Server key set containing both KEM and DSA keys
 */
export interface ServerKeys {
  kem: KeyPair;
  dsa: KeyPair;
  initialized: boolean;
  generatedAt?: string;
  securityLevel: SecurityLevel;
}

/**
 * Public key export format
 */
export interface PublicKeyExport {
  kemPublicKey: string;
  dsaPublicKey: string;
  securityLevel: SecurityLevel;
  algorithm: {
    kem: string;
    dsa: string;
  };
}

// =============================================================================
// KEY STORAGE TYPES
// =============================================================================

/**
 * Encrypted key storage format
 */
export interface EncryptedKeyStorage {
  version: number;
  salt: string;
  nonce: string;
  ciphertext: string;
}

/**
 * Key metadata
 */
export interface KeyMetadata {
  generatedAt: string;
  securityLevel: SecurityLevel;
  algorithm: {
    kem: string;
    dsa: string;
  };
}

/**
 * Stored key data format (before encryption)
 */
export interface StoredKeyData {
  kem: HexKeyPair;
  dsa: HexKeyPair;
  metadata: KeyMetadata;
}

// =============================================================================
// ENCAPSULATION TYPES
// =============================================================================

/**
 * Result of KEM encapsulation
 */
export interface EncapsulationResult {
  ciphertext: string;
  sharedSecret: string;
}

// =============================================================================
// ENCRYPTION TYPES
// =============================================================================

/**
 * Encrypted data structure
 */
export interface EncryptedData {
  nonce: string;
  ciphertext: string;
}

/**
 * Encryption options
 */
export interface EncryptOptions {
  context?: string;
}

// =============================================================================
// SESSION TYPES
// =============================================================================

/**
 * Session data stored server-side
 */
export interface SessionData {
  sharedSecret: string;
  createdAt: number;
  lastUsed: number;
  metadata?: Record<string, unknown>;
}

/**
 * Session creation response
 */
export interface SessionResponse {
  sessionId: string;
  ciphertext: string;
  signature: string;
  expiresIn: number;
}

/**
 * Session store interface for custom implementations
 */
export interface SessionStore {
  get(sessionId: string): Promise<SessionData | null>;
  set(sessionId: string, data: SessionData): Promise<void>;
  delete(sessionId: string): Promise<void>;
  cleanup(): Promise<void>;
}

// =============================================================================
// ALGORITHM INFO
// =============================================================================

/**
 * Algorithm information
 */
export interface AlgorithmInfo {
  kem: 'ML-KEM-768' | 'ML-KEM-1024';
  dsa: 'ML-DSA-65' | 'ML-DSA-87';
  symmetric: 'AES-256-GCM';
  hash: 'SHA3-256/512';
  securityLevel: SecurityLevel;
  nistFips: string[];
}

// =============================================================================
// CONFIGURATION
// =============================================================================

/**
 * Library configuration options
 */
export interface PQCConfig {
  securityLevel?: SecurityLevel;
  sessionTtlMs?: number;
  keyStoragePath?: string;
  sessionStore?: SessionStore;
}

// =============================================================================
// SIGNATURE TYPES
// =============================================================================

/**
 * Signed data with metadata
 */
export interface SignedData {
  data: string;
  signature: string;
  timestamp: number;
  publicKeyFingerprint: string;
}

/**
 * Verification result
 */
export interface VerificationResult {
  valid: boolean;
  timestamp?: number;
  error?: string;
}
