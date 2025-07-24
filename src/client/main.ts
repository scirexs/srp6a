export { createEvidence, createLoginHello, createUserCredentials, extractLoginResult, extractServerHello, verifyServer };

import { CryptoNumber, type SRPConfig } from "../shared/crypto.ts";
import {
  calculateVerifier,
  computeClientEvidence,
  computeClientKey,
  computeIdentity,
  computeMultiplier,
  computeScramblingParameter,
  computeSecret,
  computeServerEvidence,
  generateKeyPair,
  generateSalt,
  isValidPublic,
} from "../shared/functions.ts";
import type { AuthResult, ClientHello, CryptoKeyPair, KeyPair, LoginEvidence, ServerHello, SignupCredentials } from "../shared/types.ts";

/**
 * Creates user credentials for SRP6a signup process.
 * Generates salt, computes identity and secret, then calculates verifier.
 *
 * @param username - The username for the account
 * @param password - The password for the account
 * @param config - SRP configuration object
 * @returns Promise that resolves to signup credentials containing username, salt, and verifier
 *
 * @example
 * ```ts
 * const credentials = await createUserCredentials("user123", "password123", config);
 * console.log(credentials); // { username: "user123", salt: "...", verifier: "..." }
 * ```
 */
async function createUserCredentials(username: string, password: string, config: SRPConfig): Promise<SignupCredentials> {
  const salt = generateSalt(config);
  const identity = await computeIdentity(username, password, config);
  const secret = await computeSecret(salt, identity, config);
  const verifier = calculateVerifier(secret, config);
  return {
    username,
    salt: salt.hex,
    verifier: verifier.hex,
  };
}
/**
 * Creates the initial client hello message for SRP6a login process.
 * Generates a key pair and returns both the hello message and the key pair.
 *
 * @param username - The username attempting to login
 * @param config - SRP configuration object
 * @returns Tuple containing [ClientHello message, KeyPair for the session]
 *
 * @example
 * ```ts
 * const [hello, keyPair] = createLoginHello("user123", config);
 * // Send hello to server, keep keyPair for evidence creation
 * ```
 */
function createLoginHello(username: string, config: SRPConfig): [ClientHello, KeyPair] {
  const pair = generateKeyPair(config);
  return [
    { username, client: pair.public.hex },
    { private: pair.private.hex, public: pair.public.hex },
  ];
}
/**
 * Creates login evidence after receiving server hello response.
 * Computes client evidence and expected server evidence for mutual authentication.
 *
 * @param username - The username attempting to login
 * @param password - The password for authentication
 * @param salt - Salt value from server (string or CryptoNumber)
 * @param server - Server's public key (string or CryptoNumber)
 * @param pair - Client's key pair from login hello
 * @param config - SRP configuration object
 * @returns Promise that resolves to tuple containing [LoginEvidence, expected server evidence]
 * @throws Error if server's public key is invalid
 *
 * @example
 * ```ts
 * const [evidence, expected] = await createEvidence(
 *   "user123",
 *   "password123",
 *   serverSalt,
 *   serverPublicKey,
 *   clientKeyPair,
 *   config
 * );
 * ```
 */
async function createEvidence(
  username: string,
  password: string,
  salt: string | CryptoNumber,
  server: string | CryptoNumber,
  pair: KeyPair | CryptoKeyPair,
  config: SRPConfig,
): Promise<[LoginEvidence, string]> {
  salt = typeof salt === "string" ? new CryptoNumber(salt) : salt;
  server = typeof server === "string" ? new CryptoNumber(server) : server;
  const pubClient = typeof pair.public === "string" ? new CryptoNumber(pair.public) : pair.public;
  const pvtClient = typeof pair.private === "string" ? new CryptoNumber(pair.private) : pair.private;

  if (!isValidPublic(server, config)) throw new Error("Random public key from server is invalid.");
  const identity = await computeIdentity(username, password, config);
  const secret = await computeSecret(salt, identity, config);
  const scrambling = await computeScramblingParameter(pubClient, server, config);
  const multiplier = await computeMultiplier(config);
  const key = await computeClientKey(server, multiplier, secret, pvtClient, scrambling, config);
  const evidence = await computeClientEvidence(username, salt, pubClient, server, key, config);
  const expected = await computeServerEvidence(pubClient, evidence, key, config);

  return [
    { evidence: evidence.hex },
    expected.hex,
  ];
}
/**
 * Verifies server evidence against expected value for mutual authentication.
 * Ensures that the server has knowledge of the shared secret by comparing evidence values.
 *
 * @param expected - The expected server evidence computed by client
 * @param evidence - The actual server evidence received from server
 * @returns True if server evidence matches expected value, false otherwise
 *
 * @example
 * ```ts
 * const isServerValid = verifyServer(expectedEvidence, serverEvidence);
 * if (!isServerValid) {
 *   throw new Error("Server authentication failed");
 * }
 * ```
 */
function verifyServer(expected: string, evidence: string): boolean {
  return expected === evidence;
}
/**
 * Extracts server hello information from HTTP response, if server used this library.
 * Parses the response and validates that it contains required salt and server properties.
 *
 * @param response - HTTP response from server hello endpoint
 * @returns Promise that resolves to ServerHello object containing salt and server public key
 * @throws Error if response is not OK, not JSON, or missing required properties
 *
 * @example
 * ```ts
 * const response = await fetch("/api/login/hello", { method: "POST", ... });
 * const { salt, server } = await extractServerHello(response);
 * ```
 */
async function extractServerHello(response: Response): Promise<ServerHello> {
  return await getTypedObjectFromResponse(response, "salt", "server");
}
/**
 * Extracts login result from HTTP response after evidence submission, if server used this library.
 * Parses the response and validates that it contains required result and evidence properties.
 *
 * @param response - HTTP response from login evidence endpoint
 * @returns Promise that resolves to AuthResult object containing result status and server evidence
 * @throws Error if response is not OK, not JSON, or missing required properties
 *
 * @example
 * ```ts
 * const response = await fetch("/api/login/evidence", { method: "POST", ... });
 * const { result, evidence } = await extractLoginResult(response);
 * ```
 */
async function extractLoginResult(response: Response): Promise<AuthResult> {
  return await getTypedObjectFromResponse(response, "success", "evidence");
}
// deno-lint-ignore no-explicit-any
async function getTypedObjectFromResponse(response: Response, ...props: string[]): Promise<any> {
  if (!response.ok) throw new Error("Request is failed.");
  if (response.headers.get("Content-Type") !== "application/json") throw new Error("Response is not json type.");
  const data = await response.json();
  if (typeof data !== "object" || Array.isArray(data)) throw new Error("Response has invalid data.");
  checkRequiredProperties(data, ...props);
  return data;
}
function checkRequiredProperties(obj: Record<string, string>, ...props: string[]) {
  for (const prop of props) {
    if (!Object.hasOwn(obj, prop)) throw new Error("Required properties are not exist in response.");
  }
}
