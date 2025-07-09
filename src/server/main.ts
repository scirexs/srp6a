export { authenticate, createServerHello, extractClientHello, extractLoginEvidence };

import { CryptoNumber, SRPConfig } from "../shared/crypto.ts";
import {
  addRandomDelay,
  computeClientEvidence,
  computeMultiplier,
  computeScramblingParameter,
  computeServerEvidence,
  computeServerKey,
  generateServerKeyPair,
  isValidPublic,
} from "../shared/functions.ts";
import type { AuthResult, ClientHello, KeyPair, LoginEvidence, ServerHello } from "../shared/types.ts";

/**
 * Creates server hello response for SRP6a authentication.
 * Generates server key pair and returns hello message along with the key pair for session use.
 *
 * @param salt - Salt value from user registration (string or CryptoNumber)
 * @param verifier - Password verifier from user registration (string or CryptoNumber)
 * @param config - SRP configuration object
 * @returns Promise that resolves to tuple containing [ServerHello message, KeyPair for the session]
 *
 * @example
 * ```ts
 * const userRecord = getUserFromDatabase(username);
 * const [hello, keyPair] = await createServerHello(userRecord.salt, userRecord.verifier, config);
 * // Send hello to client, store keyPair for authentication
 * ```
 */
async function createServerHello(
  salt: string | CryptoNumber,
  verifier: string | CryptoNumber,
  config: SRPConfig,
): Promise<[ServerHello, KeyPair]> {
  salt = typeof salt === "string" ? salt : salt.hex;
  verifier = typeof verifier === "string" ? new CryptoNumber(verifier) : verifier;

  const multiplier = await computeMultiplier(config);
  const pair = generateServerKeyPair(multiplier, verifier, config);
  return [
    { salt, server: pair.public.hex },
    pair,
  ];
}
/**
 * Authenticates client evidence and generates server evidence for mutual authentication.
 * Verifies client's knowledge of password and computes server evidence if authentication succeeds.
 *
 * @param username - The username attempting to authenticate
 * @param salt - Salt value from user registration (string or CryptoNumber)
 * @param verifier - Password verifier from user registration (string or CryptoNumber)
 * @param pair - Server's key pair from hello phase
 * @param client - Client's public key from hello phase (string or CryptoNumber)
 * @param evidence - Client evidence to verify (string or CryptoNumber)
 * @param config - SRP configuration object
 * @returns Promise that resolves to AuthResult with result status and server evidence
 * @throws Error if client's public key is invalid
 *
 * @example
 * ```ts
 * const result = await authenticate(
 *   username,
 *   userRecord.salt,
 *   userRecord.verifier,
 *   serverKeyPair,
 *   clientPublicKey,
 *   clientEvidence,
 *   config
 * );
 *
 * if (result.result) {
 *   // Authentication successful, send server evidence
 *   return { result: true, evidence: result.evidence };
 * } else {
 *   // Authentication failed
 *   return { result: false, evidence: "" };
 * }
 * ```
 */
async function authenticate(
  username: string,
  salt: string | CryptoNumber,
  verifier: string | CryptoNumber,
  pair: KeyPair,
  client: string | CryptoNumber,
  evidence: string | CryptoNumber,
  config: SRPConfig,
): Promise<AuthResult> {
  salt = typeof salt === "string" ? new CryptoNumber(salt) : salt;
  verifier = typeof verifier === "string" ? new CryptoNumber(verifier) : verifier;
  client = typeof client === "string" ? new CryptoNumber(client) : client;
  evidence = typeof evidence === "string" ? new CryptoNumber(evidence) : evidence;

  if (!isValidPublic(client, config)) throw new Error("Random public key from client is invalid.");
  const scrambling = await computeScramblingParameter(client, pair.public, config);
  const key = await computeServerKey(client, verifier, scrambling, pair.private, config);
  const authEvidence = await computeClientEvidence(username, salt, client, pair.public, key, config);
  const result = CryptoNumber.compare(authEvidence, evidence);
  if (!result) {
    await addRandomDelay();
    return { result, evidence: "" };
  }
  const serverEvidence = await computeServerEvidence(client, evidence, key, config);
  return {
    result,
    evidence: serverEvidence.hex,
  };
}

/**
 * Extracts client hello information from HTTP request, if client used this library.
 * Parses the request body and validates that it contains required username and client properties.
 *
 * @param request - HTTP request containing client hello data
 * @returns Promise that resolves to ClientHello object containing username and client public key
 * @throws Error if request is not POST, not JSON, or missing required properties
 *
 * @example
 * ```ts
 * // In your HTTP handler
 * const { username, client } = await extractClientHello(request);
 * const userRecord = getUserFromDatabase(username);
 * const [hello, keyPair] = await createServerHello(userRecord.salt, userRecord.verifier, config);
 * ```
 */
async function extractClientHello(request: Request): Promise<ClientHello> {
  return await getTypedObjectFromResponse(request, "username", "client");
}
/**
 * Extracts login evidence from HTTP request, if client used this library.
 * Parses the request body and validates that it contains required username and evidence properties.
 *
 * @param request - HTTP request containing login evidence data
 * @returns Promise that resolves to LoginEvidence object containing username and client evidence
 * @throws Error if request is not POST, not JSON, or missing required properties
 *
 * @example
 * ```ts
 * // In your HTTP handler
 * const { username, evidence } = await extractLoginEvidence(request);
 * const userRecord = getUserFromDatabase(username);
 * const result = await authenticate(
 *   username,
 *   userRecord.salt,
 *   userRecord.verifier,
 *   storedKeyPair,
 *   storedClientPublicKey,
 *   evidence,
 *   config
 * );
 * ```
 */
async function extractLoginEvidence(request: Request): Promise<LoginEvidence> {
  return await getTypedObjectFromResponse(request, "username", "evidence");
}
// deno-lint-ignore no-explicit-any
async function getTypedObjectFromResponse(request: Request, ...props: string[]): Promise<any> {
  if (request.method !== "POST") throw new Error("Request must be post method.");
  if (request.headers.get("Content-Type") !== "application/json") throw new Error("Request is not json type.");
  const data = await request.json();
  if (typeof data !== "object" || Array.isArray(data)) throw new Error("Request has invalid data.");
  checkRequiredProperties(data, ...props);
  return data;
}
function checkRequiredProperties(obj: Record<string, string>, ...props: string[]) {
  for (const prop of props) {
    if (!Object.hasOwn(obj, prop)) throw new Error("Required properties are not exist in request.");
  }
}
