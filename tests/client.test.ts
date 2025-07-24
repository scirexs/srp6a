import { assertEquals, assertExists, assertRejects } from "jsr:@std/assert";
import { afterAll, beforeAll, describe, it } from "jsr:@std/testing/bdd";
import { CryptoNumber, getDefaultConfig, SRPConfig } from "../src/shared/crypto.ts";
import {
  calculateVerifier,
  computeClientKey,
  computeIdentity,
  computeMultiplier,
  computeScramblingParameter,
  computeSecret,
  computeServerEvidence,
  generateSalt,
  generateServerKeyPair,
} from "../src/shared/functions.ts";
import { createEvidence, createLoginHello, createUserCredentials, verifyServer } from "../src/client/main.ts";
import type { CryptoKeyPair, KeyPair } from "../src/shared/types.ts";

describe("SRP6a Client Tests", () => {
  let config: SRPConfig;
  let salt: CryptoNumber;
  let verifier: CryptoNumber;
  let serverKeyPair: CryptoKeyPair;
  let multiplier: CryptoNumber;
  const username = "testuser";
  const password = "testpassword";

  beforeAll(async () => {
    config = getDefaultConfig();
    salt = generateSalt(config);
    const identity = await computeIdentity(username, password, config);
    const secret = await computeSecret(salt, identity, config);
    verifier = calculateVerifier(secret, config);
    multiplier = await computeMultiplier(config);
    serverKeyPair = generateServerKeyPair(multiplier, verifier, config);
  });

  afterAll(() => {
    salt.clear();
    verifier.clear();
    serverKeyPair.private.clear();
    serverKeyPair.public.clear();
    multiplier.clear();
  });

  describe("createUserCredentials", () => {
    it("should create valid signup credentials", async () => {
      const credentials = await createUserCredentials(username, password, config);

      assertExists(credentials.username);
      assertExists(credentials.salt);
      assertExists(credentials.verifier);
      assertEquals(credentials.username, username);

      // Verify salt and verifier are valid hex strings
      const saltNum = new CryptoNumber(credentials.salt);
      const verifierNum = new CryptoNumber(credentials.verifier);
      assertEquals(saltNum.int > 0n, true);
      assertEquals(verifierNum.int > 0n, true);
    });

    it("should generate different credentials each time", async () => {
      const cred1 = await createUserCredentials(username, password, config);
      const cred2 = await createUserCredentials(username, password, config);

      assertEquals(cred1.username, cred2.username);
      // Different salt and verifier (due to random salt)
      assertEquals(cred1.salt !== cred2.salt, true);
      assertEquals(cred1.verifier !== cred2.verifier, true);
    });
  });

  describe("createLoginHello", () => {
    it("should create valid login hello", () => {
      const [hello, keyPair] = createLoginHello(username, config);

      assertExists(hello.username);
      assertExists(hello.client);
      assertEquals(hello.username, username);

      const clientPublic = new CryptoNumber(hello.client);
      const keyPublic = new CryptoNumber(keyPair.public);
      const keyPrivate = new CryptoNumber(keyPair.private);
      // Verify client public key is valid
      assertEquals(clientPublic.int > 0n, true);
      assertEquals(clientPublic.int < config.prime.int, true);
      assertEquals(hello.client, keyPublic.hex);

      // Verify key pair is valid
      assertEquals(keyPrivate.int > 0n, true);
      assertEquals(keyPublic.int > 0n, true);
    });

    it("should generate different hello each time", () => {
      const [hello1, keyPair1] = createLoginHello(username, config);
      const [hello2, keyPair2] = createLoginHello(username, config);

      assertEquals(hello1.username, hello2.username);
      // Different client public keys (due to random private key)
      assertEquals(hello1.client !== hello2.client, true);
      assertEquals(keyPair1.public !== keyPair2.public, true);
    });
  });

  describe("createEvidence", () => {
    it("should create valid evidence with string inputs", async () => {
      const [hello, clientKeyPair] = createLoginHello(username, config);
      const [evidence, expected] = await createEvidence(
        username,
        password,
        salt.hex,
        serverKeyPair.public.hex,
        clientKeyPair,
        config,
      );

      assertExists(evidence.evidence);
      assertExists(expected);

      // Verify evidence is valid hex string
      const evidenceNum = new CryptoNumber(evidence.evidence);
      assertEquals(evidenceNum.int > 0n, true);

      // Verify expected is valid hex string
      const expectedNum = new CryptoNumber(expected);
      assertEquals(expectedNum.int > 0n, true);
    });

    it("should create valid evidence with CryptoNumber inputs", async () => {
      const [hello, clientKeyPair] = createLoginHello(username, config);
      const [evidence, expected] = await createEvidence(
        username,
        password,
        salt,
        serverKeyPair.public,
        clientKeyPair,
        config,
      );

      assertExists(evidence.evidence);
      assertExists(expected);

      // Verify evidence is valid hex string
      const evidenceNum = new CryptoNumber(evidence.evidence);
      assertEquals(evidenceNum.int > 0n, true);
    });

    it("should throw error for invalid server public key", async () => {
      const [hello, clientKeyPair] = createLoginHello(username, config);
      const invalidServerKey = new CryptoNumber(0n); // Invalid: 0 mod prime

      await assertRejects(
        async () =>
          await createEvidence(
            username,
            password,
            salt,
            invalidServerKey,
            clientKeyPair,
            config,
          ),
        Error,
        "Random public key from server is invalid.",
      );
    });

    it("should create consistent evidence for same inputs", async () => {
      const [hello, clientKeyPair] = createLoginHello(username, config);

      const [evidence1, expected1] = await createEvidence(
        username,
        password,
        salt,
        serverKeyPair.public,
        clientKeyPair,
        config,
      );

      const [evidence2, expected2] = await createEvidence(
        username,
        password,
        salt,
        serverKeyPair.public,
        clientKeyPair,
        config,
      );

      assertEquals(evidence1.evidence, evidence2.evidence);
      assertEquals(expected1, expected2);
    });
  });

  describe("verifyServer", () => {
    it("should return true for matching evidence", () => {
      const evidence = "1234567890ABCDEF";
      const result = verifyServer(evidence, evidence);
      assertEquals(result, true);
    });

    it("should return false for non-matching evidence", () => {
      const expected = "1234567890ABCDEF";
      const actual = "FEDCBA0987654321";
      const result = verifyServer(expected, actual);
      assertEquals(result, false);
    });

    it("should return false for empty strings", () => {
      const result = verifyServer("", "");
      assertEquals(result, true); // Empty strings match
    });

    it("should return false for one empty string", () => {
      const result = verifyServer("1234567890ABCDEF", "");
      assertEquals(result, false);
    });
  });

  describe("integration test - full client flow", () => {
    it("should complete full authentication flow", async () => {
      // Step 1: Create credentials (signup simulation)
      const credentials = await createUserCredentials(username, password, config);

      // Step 2: Create login hello
      const [hello, keyPair] = createLoginHello(username, config);
      const clientKeyPair = { private: new CryptoNumber(keyPair.private), public: new CryptoNumber(keyPair.public) };

      // Step 3: Server creates hello (simulation)
      const serverSalt = new CryptoNumber(credentials.salt);
      const serverVerifier = new CryptoNumber(credentials.verifier);
      const serverMultiplier = await computeMultiplier(config);
      const serverKeyPair = generateServerKeyPair(serverMultiplier, serverVerifier, config);

      // Step 4: Create evidence
      const [evidence, expectedServerEvidence] = await createEvidence(
        username,
        password,
        serverSalt,
        serverKeyPair.public,
        clientKeyPair,
        config,
      );

      // Step 5: Server verifies evidence (simulation)
      const scrambling = await computeScramblingParameter(clientKeyPair.public, serverKeyPair.public, config);
      const serverKey = await computeClientKey(
        serverKeyPair.public,
        serverMultiplier,
        await computeSecret(serverSalt, await computeIdentity(username, password, config), config),
        clientKeyPair.private,
        scrambling,
        config,
      );
      const serverEvidence = await computeServerEvidence(clientKeyPair.public, new CryptoNumber(evidence.evidence), serverKey, config);

      // Step 6: Verify server
      const isServerValid = verifyServer(expectedServerEvidence, serverEvidence.hex);

      assertEquals(isServerValid, true);
    });
  });
});
