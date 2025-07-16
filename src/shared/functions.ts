export {
  addRandomDelay,
  calculateVerifier,
  computeClientEvidence,
  computeClientKey,
  computeIdentity,
  computeMultiplier,
  computeScramblingParameter,
  computeSecret,
  computeServerEvidence,
  computeServerKey,
  generateKeyPair,
  generateRandomKey,
  generateSalt,
  generateServerKeyPair,
  isValidPublic,
};

import type { CryptoKeyPair } from "./types.ts";
import { computeHash, CryptoNumber, generateSecureRandom, type SRPConfig } from "./crypto.ts";

/** s = RAND() */
function generateSalt(config: SRPConfig): CryptoNumber {
  return generateSecureRandom(config.salt);
}
/** I = H(U | ":" | p) */
async function computeIdentity(username: string, password: string, config: SRPConfig): Promise<CryptoNumber> {
  if (!isValidIdentitySource(username, password)) throw new Error("Username and password must have length.");
  return await computeHash(new TextEncoder().encode(`${username}:${password}`), config);
}
/** x = H(s | I) */
async function computeSecret(salt: CryptoNumber, identity: CryptoNumber, config: SRPConfig): Promise<CryptoNumber> {
  return await computeHash(CryptoNumber.concat(salt, identity), config);
}
/** v = MP(g, x, N) */
function calculateVerifier(secret: CryptoNumber, config: SRPConfig): CryptoNumber {
  return CryptoNumber.modPow(config.generator, secret, config.prime);
}
/** k = H(N | PAD(g)) */
async function computeMultiplier(config: SRPConfig): Promise<CryptoNumber> {
  const num = config.multiplier ? new CryptoNumber(config.multiplier) : CryptoNumber.concat(config.prime, config.generator.pad());
  return await computeHash(num, config);
}
/** b, B = k * v + MP(g, b, N) */
function generateServerKeyPair(multiplier: CryptoNumber, verifier: CryptoNumber, config: SRPConfig): CryptoKeyPair {
  const pair = generateKeyPair(config);
  pair.public = new CryptoNumber((multiplier.int * verifier.int + pair.public.int) % config.prime.int); // to prevent exceed prime
  return pair;
}
/** a, A = MP(g, a, N) */
function generateKeyPair(config: SRPConfig): CryptoKeyPair {
  const pvt = generateRandomKey(config);
  return {
    private: pvt,
    public: CryptoNumber.modPow(config.generator, pvt, config.prime),
  };
}
/** a = RAND(), b = RAND() */
function generateRandomKey(config: SRPConfig): CryptoNumber {
  let result: bigint;
  do {
    const array = generateSecureRandom(config.hashBytes);
    result = array.int % config.prime.int;
  } while (result === 0n);
  return new CryptoNumber(result);
}
/** u = H(PAD(A) | PAD(B)) */
async function computeScramblingParameter(client: CryptoNumber, server: CryptoNumber, config: SRPConfig): Promise<CryptoNumber> {
  return await computeHash(CryptoNumber.concat(client.pad(), server.pad()), config);
}
/** Kc = H(Sc) */
async function computeClientKey(
  server: CryptoNumber,
  multiplier: CryptoNumber,
  secret: CryptoNumber,
  pvt: CryptoNumber,
  scrambling: CryptoNumber,
  config: SRPConfig,
): Promise<CryptoNumber> {
  return await computeHash(calculateClientSession(server, multiplier, secret, pvt, scrambling, config), config);
}
/** Sc = MP(B - (k * MP(g, x, N)), a + (u * x), N) */
function calculateClientSession(
  server: CryptoNumber,
  multiplier: CryptoNumber,
  secret: CryptoNumber,
  pvt: CryptoNumber,
  scrambling: CryptoNumber,
  config: SRPConfig,
): CryptoNumber {
  const kgx = (multiplier.int * CryptoNumber.modPow(config.generator, secret, config.prime).int) % config.prime.int;
  const base = (server.int - kgx + config.prime.int) % config.prime.int; // to prevent negative, add prime
  const pow = (pvt.int + (scrambling.int * secret.int)) % config.prime.int; // to prevent exceed prime
  return CryptoNumber.modPow(base, pow, config.prime);
}
/** Mc = H(H(N) xor H(g), H(U), s, A, B, K) */
async function computeClientEvidence(
  username: string,
  salt: CryptoNumber,
  client: CryptoNumber,
  server: CryptoNumber,
  key: CryptoNumber,
  config: SRPConfig,
): Promise<CryptoNumber> {
  const primeHash = await computeHash(config.prime, config);
  const generatorHash = await computeHash(config.generator, config);
  const xor = CryptoNumber.xor(primeHash, generatorHash);
  const usernameHash = await computeHash(new TextEncoder().encode(username), config);
  return await computeHash(CryptoNumber.concat(xor, usernameHash, salt, client, server, key), config);
}
/** Ks = H(Ss) */
async function computeServerKey(
  client: CryptoNumber,
  verifier: CryptoNumber,
  scrambling: CryptoNumber,
  pvt: CryptoNumber,
  config: SRPConfig,
): Promise<CryptoNumber> {
  return await computeHash(calculateServerSession(client, verifier, scrambling, pvt, config), config);
}
/** Ss = MP(A * MP(v, u, N), b, N) */
function calculateServerSession(
  client: CryptoNumber,
  verifier: CryptoNumber,
  scrambling: CryptoNumber,
  pvt: CryptoNumber,
  config: SRPConfig,
): CryptoNumber {
  const base = (client.int * CryptoNumber.modPow(verifier, scrambling, config.prime).int) % config.prime.int;
  return CryptoNumber.modPow(base, pvt, config.prime);
}
/** Ms = H(A, Mc, K) */
async function computeServerEvidence(
  client: CryptoNumber,
  evidence: CryptoNumber,
  key: CryptoNumber,
  config: SRPConfig,
): Promise<CryptoNumber> {
  return await computeHash(CryptoNumber.concat(client, evidence, key), config);
}

/** Confirm username and password is not empty. */
function isValidIdentitySource(username: string, password: string): boolean {
  return Boolean(username) && Boolean(password);
}
/** Confirm public key is valid or not. */
function isValidPublic(pub: CryptoNumber, config: SRPConfig): boolean {
  return pub.int % config.prime.int !== 0n && 1n <= pub.int && pub.int < config.prime.int;
}
/** Add random delay to fail authentication. */
async function addRandomDelay(ms: number = 5): Promise<void> {
  ms = Math.ceil(Math.abs(ms));
  ms = ms <= 1 ? 5 : ms;
  const delay = (Math.random() * (ms - 1)) + 1;
  await new Promise((resolve) => setTimeout(resolve, delay));
}

export const __internal = Deno?.args?.includes("test")
  ? {
    calculateClientSession,
    calculateServerSession,
  }
  : {};
