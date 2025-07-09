export { authenticate, createServerHello, extractClientHello, extractLoginEvidence };

import { CryptoNumber, SRPConfig } from "../shared/crypto.ts";
import {
  computeClientEvidence,
  computeMultiplier,
  computeScramblingParameter,
  computeServerEvidence,
  computeServerKey,
  generateServerKeyPair,
  isValidPublic,
} from "../shared/functions.ts";
import type { AuthResult, ClientHello, KeyPair, LoginEvidence, ServerHello } from "../shared/types.ts";

async function createServerHello(
  salt: string | CryptoNumber,
  verifier: string | CryptoNumber,
  config: SRPConfig,
): Promise<[ServerHello, KeyPair]> {
  salt = typeof salt === "string" ? new CryptoNumber(salt) : salt;
  verifier = typeof verifier === "string" ? new CryptoNumber(verifier) : verifier;

  const multiplier = await computeMultiplier(config);
  const pair = generateServerKeyPair(multiplier, verifier, config);
  return [
    { salt: salt.hex, server: pair.public.hex },
    pair,
  ];
}
async function authenticate(
  username: string,
  salt: CryptoNumber,
  verifier: CryptoNumber,
  pair: KeyPair,
  client: string | CryptoNumber,
  evidence: string | CryptoNumber,
  config: SRPConfig,
): Promise<AuthResult> {
  client = typeof client === "string" ? new CryptoNumber(client) : client;
  evidence = typeof evidence === "string" ? new CryptoNumber(evidence) : evidence;

  if (!isValidPublic(client, config)) throw new Error("Random public key from client is invalid.");
  const scrambling = await computeScramblingParameter(client, pair.public, config);
  const key = await computeServerKey(client, verifier, scrambling, pair.private, config);
  const authEvidence = await computeClientEvidence(username, salt, client, pair.public, key, config);
  const result = CryptoNumber.compare(authEvidence, evidence);
  if (!result) return { result, evidence: "" };
  const serverEvidence = await computeServerEvidence(client, evidence, key, config);
  return {
    result,
    evidence: serverEvidence.hex,
  };
}

async function extractClientHello(request: Request): Promise<ClientHello> {
  return await getTypedObjectFromResponse(request, "username", "client");
}
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
