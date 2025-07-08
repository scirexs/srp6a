export { createCredentials, createEvidence, createLoginHello, login, signup, verifyServer };

import { CryptoNumber, getDefaultConfig, SRPConfig } from "../shared/crypto.ts";
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
import type { AuthResult, ClientHello, KeyPair, LoginEvidence, ServerHello, SignupCredentials } from "../shared/types.ts";

async function signup(url: URL, username: string, password: string, config?: SRPConfig): Promise<Response> {
  config = config ?? getDefaultConfig();
  const credentials = await createCredentials(username, password, config);
  return await postDataAsJson(url, credentials);
}
async function login(url: URL, username: string, password: string, config?: SRPConfig): Promise<Record<string, unknown>> {
  config = config ?? getDefaultConfig();

  const [hello, pair] = createLoginHello(username, config);
  const { salt, server } = await getServerHello(await postDataAsJson(url, hello));
  const [evidence, expected] = await createEvidence(username, password, salt, server, pair, config);
  const response = await getLoginResult(await postDataAsJson(url, evidence));
  if (!response.result) throw new Error("Failed to login.");
  if (!verifyServer(expected, response.evidence)) throw new Error("Could not be verified the server.");
  return response;
}

async function createCredentials(username: string, password: string, config: SRPConfig): Promise<SignupCredentials> {
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
function createLoginHello(username: string, config: SRPConfig): [ClientHello, KeyPair] {
  const pair = generateKeyPair(config);
  return [
    { username, client: pair.public.hex },
    pair,
  ];
}
async function createEvidence(
  username: string,
  password: string,
  salt: string | CryptoNumber,
  server: string | CryptoNumber,
  pair: KeyPair,
  config: SRPConfig,
): Promise<[LoginEvidence, string]> {
  salt = typeof salt === "string" ? new CryptoNumber(salt) : salt;
  server = typeof server === "string" ? new CryptoNumber(server) : server;

  if (!isValidPublic(salt, config)) throw new Error("Random public key from server is invalid.");
  const identity = await computeIdentity(username, password, config);
  const secret = await computeSecret(salt, identity, config);
  const scrambling = await computeScramblingParameter(pair.public, server, config);
  const multiplier = await computeMultiplier(config);
  const key = await computeClientKey(server, multiplier, secret, pair.private, scrambling, config);
  const evidence = await computeClientEvidence(username, salt, pair.public, server, key, config);
  const expected = await computeServerEvidence(pair.public, evidence, key, config);

  return [
    { username, evidence: evidence.hex },
    expected.hex,
  ];
}
function verifyServer(expected: string, evidence: string): boolean {
  return expected === evidence;
}

async function getServerHello(response: Response): Promise<ServerHello> {
  return await getTypedObjectFromResponse(response, "salt", "server");
}
async function getLoginResult(response: Response): Promise<AuthResult> {
  return await getTypedObjectFromResponse(response, "result", "evidence");
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

async function postDataAsJson<T>(url: URL, data: T): Promise<Response> {
  return await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
    credentials: "same-origin",
    cache: "no-cache",
    redirect: "error",
  });
}
