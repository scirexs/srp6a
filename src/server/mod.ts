export { authenticate, createServerHello, extractClientHello, extractLoginEvidence } from "./main.ts";
export {
  CryptoNumber,
  getDefaultConfig,
  GROUP_2048_FOR_SERVER,
  GROUP_3072_FOR_SERVER,
  GROUP_4096_FOR_SERVER,
  GROUP_6144_FOR_SERVER,
  GROUP_8192_FOR_SERVER,
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
