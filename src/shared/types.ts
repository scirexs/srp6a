export type {
  AuthResult,
  ClientHello,
  CryptoKeyPair,
  HashAlgorithm,
  KeyPair,
  LoginEvidence,
  ServerHello,
  SignupCredentials,
  SRPHashConfig,
  SRPSecurityGroup,
};

import type { CryptoNumber } from "./crypto.ts";

/**
 * Security group parameters for SRP6a authentication.
 * Contains cryptographic parameters including prime number, generator, and multiplier.
 * ```
 */
type SRPSecurityGroup = {
  /** Bit length of the security group (e.g., 1024, 2048, 3072, 4096) */
  length: number;
  /** Large prime number used as the modulus for calculations */
  prime: bigint;
  /** Generator value, typically 2 or 5 */
  generator: bigint;
  /** Multiplier value used in SRP calculations as hex string */
  multiplier: string;
};
/**
 * Supported hash algorithms for SRP6a authentication.
 * Defines the cryptographic hash functions that can be used for SRP computations.
 * SHA-1 is used by unit testing.
 */
type HashAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
/**
 * Hash configuration for SRP6a authentication.
 * Specifies the hash algorithm and associated byte lengths for cryptographic operations.
 */
type SRPHashConfig = {
  /** Hash algorithm to use for SRP computations */
  algorithm: HashAlgorithm;
  /** Output length of the hash algorithm in bytes */
  bytes: number;
  /** Length of salt to generate in bytes */
  salt: number;
};
/**
 * Public-private key pair for SRP6a authentication.
 * Contains both the random private key and random public key used in the SRP protocol.
 */
type CryptoKeyPair = {
  /** Random private key used for authentication */
  private: CryptoNumber;
  /** Random public key shared during authentication handshake */
  public: CryptoNumber;
};
/**
 * Public-private hex key pair for SRP6a authentication.
 * Contains both the random private key and random public key used in the SRP protocol.
 */
type KeyPair = {
  /** Random private hex key used for authentication */
  private: string;
  /** Random public hex key shared during authentication handshake */
  public: string;
};
/**
 * User credentials for SRP6a signup process.
 * Contains username, salt, and verifier needed to register a new user.
 */
interface SignupCredentials {
  /** Username for the new account */
  username: string;
  /** Salt value as hex string, used for password hashing */
  salt: string;
  /** Password verifier as hex string, stored instead of password */
  verifier: string;
  /** Additional fields can be included (e.g., session info, request id) */
  [key: string]: string | boolean;
}
/**
 * Client hello message for SRP6a login initiation.
 * Contains username and client's public key to start the authentication process.
 */
interface ClientHello {
  /** Username attempting to authenticate */
  username: string;
  /** Client's public key as hex string */
  client: string;
  /** Additional fields can be included (e.g., session info, request id) */
  [key: string]: string | boolean;
}
/**
 * Server hello response for SRP6a authentication.
 * Contains salt and server's public key in response to client hello.
 */
interface ServerHello {
  /** Salt value as hex string from user registration */
  salt: string;
  /** Server's public key as hex string */
  server: string;
  /** Additional fields can be included (e.g., session info, request id) */
  [key: string]: string | boolean;
}
/**
 * Login evidence from client for SRP6a authentication.
 * Contains username and client's computed evidence to prove password knowledge.
 */
interface LoginEvidence {
  /** Client evidence as hex string proving password knowledge */
  evidence: string;
  /** Additional fields can be included (e.g., session info, request id) */
  [key: string]: string | boolean;
}
/**
 * Authentication result from server after evidence verification.
 * Contains the result of authentication and server evidence for mutual authentication.
 *
 * @example
 * ```ts
 * // Successful authentication
 * const authResult: AuthResult = {
 *   result: true,
 *   evidence: "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p",
 *   sessionId: "session_123",  // Additional fields allowed
 *   userId: "user_456"
 * };
 *
 * // Failed authentication
 * const failedResult: AuthResult = {
 *   result: false,
 *   evidence: ""  // Empty evidence on failure
 * };
 * ```
 */
interface AuthResult {
  /** Whether authentication was successful */
  success: boolean;
  /** Server evidence as hex string for mutual authentication (empty if failed) */
  evidence: string;
  /** Additional fields can be included (e.g., session info, request id) */
  [key: string]: string | boolean;
}
