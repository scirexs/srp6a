export { createCredentials, createEvidence, createLoginHello, login, signup, verifyServer } from "./main.ts";
export {
  CryptoNumber,
  getDefaultConfig,
  GROUP_2048,
  GROUP_3072,
  GROUP_4096,
  GROUP_6144,
  GROUP_8192,
  SHA_256,
  SHA_384,
  SHA_512,
  SRPConfig,
} from "../shared/mod.ts";
export type {
  AuthResult,
  ClientHello,
  KeyPair,
  LoginEvidence,
  ServerHello,
  SignupCredentials,
  SRPHashConfig,
  SRPSecurityGroup,
} from "../shared/mod.ts";
