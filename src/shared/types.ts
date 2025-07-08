export type {
  AuthResult,
  ClientHello,
  HashAlgorithm,
  KeyPair,
  LoginEvidence,
  ServerHello,
  SignupCredentials,
  SRPHashConfig,
  SRPSecurityGroup,
};

import type { CryptoNumber } from "./crypto.ts";

type SRPSecurityGroup = {
  length: number;
  prime: bigint;
  generator: bigint;
  multiplier: string;
};
type HashAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
type SRPHashConfig = {
  algorithm: HashAlgorithm;
  bytes: number;
  salt: number;
};

type KeyPair = {
  private: CryptoNumber;
  public: CryptoNumber;
};

interface SignupCredentials {
  username: string;
  salt: string;
  verifier: string;
}
interface ClientHello {
  username: string;
  client: string;
}
interface ServerHello {
  salt: string;
  server: string;
}
interface LoginEvidence {
  username: string;
  evidence: string;
}
interface AuthResult {
  result: boolean;
  evidence: string;
  [key: string]: string | boolean;
}
