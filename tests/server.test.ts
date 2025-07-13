import { assertEquals, assertExists, assertRejects } from "jsr:@std/assert";
import { afterAll, beforeAll, describe, it } from "jsr:@std/testing/bdd";
import { CryptoNumber, getDefaultConfig, SRPConfig } from "../src/shared/crypto.ts";
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
} from "../src/shared/functions.ts";
import { authenticate, createServerHello, extractClientHello, extractLoginEvidence } from "../src/server/main.ts";

describe("SRP6a Server Tests", () => {
  let config: SRPConfig;
  let salt: CryptoNumber;
  let verifier: CryptoNumber;
  const username = "testuser";
  const password = "testpassword";

  beforeAll(async () => {
    config = getDefaultConfig();
    salt = generateSalt(config);
    const identity = await computeIdentity(username, password, config);
    const secret = await computeSecret(salt, identity, config);
    verifier = calculateVerifier(secret, config);
  });

  afterAll(() => {
    salt.clear();
    verifier.clear();
  });

  describe("createServerHello", () => {
    it("should create valid server hello with salt and server public key", async () => {
      const [serverHello, keyPair] = await createServerHello(salt, verifier, config);

      assertExists(serverHello.salt);
      assertExists(serverHello.server);
      assertEquals(serverHello.salt, salt.hex);
      assertEquals(serverHello.server, keyPair.public.hex);

      // Verify server public key is valid
      const serverPublic = new CryptoNumber(serverHello.server);
      assertEquals(serverPublic.int > 0n, true);
      assertEquals(serverPublic.int < config.prime.int, true);
    });

    it("should generate different server hello each time", async () => {
      const [hello1] = await createServerHello(salt, verifier, config);
      const [hello2] = await createServerHello(salt, verifier, config);

      assertEquals(hello1.salt, hello2.salt); // Same salt
      // Different server public keys (due to random private key)
      assertEquals(hello1.server !== hello2.server, true);
    });
  });

  describe("authenticate", () => {
    it("should authenticate valid client evidence", async () => {
      // Setup: Create client-side values (simulating client)
      const [serverHello, serverKeyPair] = await createServerHello(salt, verifier, config);

      // Simulate client generating evidence
      const identity = await computeIdentity(username, password, config);
      const secret = await computeSecret(salt, identity, config);

      const clientKeyPair = generateKeyPair(config);
      const serverPublic = new CryptoNumber(serverHello.server);
      const scrambling = await computeScramblingParameter(clientKeyPair.public, serverPublic, config);
      const multiplier = await computeMultiplier(config);
      const clientKey = await computeClientKey(serverPublic, multiplier, secret, clientKeyPair.private, scrambling, config);
      const clientEvidence = await computeClientEvidence(username, salt, clientKeyPair.public, serverPublic, clientKey, config);

      // Test authentication
      const result = await authenticate(
        username,
        salt,
        verifier,
        serverKeyPair,
        clientKeyPair.public,
        clientEvidence,
        config,
      );

      assertEquals(result.success, true);
      assertExists(result.evidence);
      assertEquals(result.evidence.length > 0, true);
    });

    it("should reject invalid client evidence", async () => {
      const [, serverKeyPair] = await createServerHello(salt, verifier, config);
      const clientKeyPair = generateKeyPair(config);
      const invalidEvidence = new CryptoNumber("DEADBEEF");

      const result = await authenticate(
        username,
        salt,
        verifier,
        serverKeyPair,
        clientKeyPair.public,
        invalidEvidence,
        config,
      );

      assertEquals(result.success, false);
      assertEquals(result.evidence, "");
    });

    it("should accept string parameters for client and evidence", async () => {
      const [, serverKeyPair] = await createServerHello(salt, verifier, config);
      const clientKeyPair = generateKeyPair(config);
      const invalidEvidence = "DEADBEEF";

      const result = await authenticate(
        username,
        salt,
        verifier,
        serverKeyPair,
        clientKeyPair.public.hex, // String parameter
        invalidEvidence, // String parameter
        config,
      );

      assertEquals(result.success, false);
      assertEquals(result.evidence, "");
    });

    it("should throw error for invalid client public key", async () => {
      const [, serverKeyPair] = await createServerHello(salt, verifier, config);
      const invalidClient = new CryptoNumber(0n); // Invalid: 0 mod prime
      const evidence = new CryptoNumber("DEADBEEF");

      await assertRejects(
        async () =>
          await authenticate(
            username,
            salt,
            verifier,
            serverKeyPair,
            invalidClient,
            evidence,
            config,
          ),
        Error,
        "Random public key from client is invalid.",
      );
    });

    it("should throw error for client public key equal to prime", async () => {
      const [, serverKeyPair] = await createServerHello(salt, verifier, config);
      const invalidClient = new CryptoNumber(config.prime.int); // Invalid: equals prime
      const evidence = new CryptoNumber("DEADBEEF");

      await assertRejects(
        async () =>
          await authenticate(
            username,
            salt,
            verifier,
            serverKeyPair,
            invalidClient,
            evidence,
            config,
          ),
        Error,
        "Random public key from client is invalid.",
      );
    });

    it("should throw error for client public key greater than prime", async () => {
      const [, serverKeyPair] = await createServerHello(salt, verifier, config);
      const invalidClient = new CryptoNumber(config.prime.int + 1n); // Invalid: greater than prime
      const evidence = new CryptoNumber("DEADBEEF");

      await assertRejects(
        async () =>
          await authenticate(
            username,
            salt,
            verifier,
            serverKeyPair,
            invalidClient,
            evidence,
            config,
          ),
        Error,
        "Random public key from client is invalid.",
      );
    });
  });

  describe("extractClientHello", () => {
    it("should extract valid client hello from POST request", async () => {
      const requestBody = {
        username: "testuser",
        client: "ABCDEF123456",
      };

      const request = new Request("https://example.com/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      const clientHello = await extractClientHello(request);

      assertEquals(clientHello.username, "testuser");
      assertEquals(clientHello.client, "ABCDEF123456");
    });

    it("should throw error for non-POST request", async () => {
      const request = new Request("https://example.com/login", {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      });

      await assertRejects(
        async () => await extractClientHello(request),
        Error,
        "Request must be post method.",
      );
    });

    it("should throw error for non-JSON content type", async () => {
      const request = new Request("https://example.com/login", {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: "not json",
      });

      await assertRejects(
        async () => await extractClientHello(request),
        Error,
        "Request is not json type.",
      );
    });

    it("should throw error for non-object JSON data", async () => {
      const request = new Request("https://example.com/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify("not an object"),
      });

      await assertRejects(
        async () => await extractClientHello(request),
        Error,
        "Request has invalid data.",
      );
    });

    it("should throw error for array JSON data", async () => {
      const request = new Request("https://example.com/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify([1, 2, 3]),
      });

      await assertRejects(
        async () => await extractClientHello(request),
        Error,
        "Request has invalid data.",
      );
    });

    it("should throw error for missing username property", async () => {
      const requestBody = {
        client: "ABCDEF123456",
        // username missing
      };

      const request = new Request("https://example.com/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      await assertRejects(
        async () => await extractClientHello(request),
        Error,
        "Required properties are not exist in request.",
      );
    });

    it("should throw error for missing client property", async () => {
      const requestBody = {
        username: "testuser",
        // client missing
      };

      const request = new Request("https://example.com/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      await assertRejects(
        async () => await extractClientHello(request),
        Error,
        "Required properties are not exist in request.",
      );
    });
  });

  describe("extractLoginEvidence", () => {
    it("should extract valid login evidence from POST request", async () => {
      const requestBody = {
        username: "testuser",
        evidence: "FEDCBA654321",
      };

      const request = new Request("https://example.com/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      const loginEvidence = await extractLoginEvidence(request);

      assertEquals(loginEvidence.username, "testuser");
      assertEquals(loginEvidence.evidence, "FEDCBA654321");
    });

    it("should throw error for non-POST request", async () => {
      const request = new Request("https://example.com/login", {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      });

      await assertRejects(
        async () => await extractLoginEvidence(request),
        Error,
        "Request must be post method.",
      );
    });

    it("should throw error for non-JSON content type", async () => {
      const request = new Request("https://example.com/login", {
        method: "POST",
        headers: { "Content-Type": "application/xml" },
        body: "<xml>not json</xml>",
      });

      await assertRejects(
        async () => await extractLoginEvidence(request),
        Error,
        "Request is not json type.",
      );
    });

    it("should throw error for missing username property", async () => {
      const requestBody = {
        evidence: "FEDCBA654321",
        // username missing
      };

      const request = new Request("https://example.com/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      await assertRejects(
        async () => await extractLoginEvidence(request),
        Error,
        "Required properties are not exist in request.",
      );
    });

    it("should throw error for missing evidence property", async () => {
      const requestBody = {
        username: "testuser",
        // evidence missing
      };

      const request = new Request("https://example.com/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      await assertRejects(
        async () => await extractLoginEvidence(request),
        Error,
        "Required properties are not exist in request.",
      );
    });
  });

  describe("Integration Test: Full SRP6a Flow", () => {
    it("should complete full authentication flow successfully", async () => {
      // Server creates hello
      const [serverHello, serverKeyPair] = await createServerHello(salt, verifier, config);

      // Client processes server hello and generates evidence
      const identity = await computeIdentity(username, password, config);
      const secret = await computeSecret(salt, identity, config);

      const clientKeyPair = generateKeyPair(config);
      const serverPublic = new CryptoNumber(serverHello.server);
      const scrambling = await computeScramblingParameter(clientKeyPair.public, serverPublic, config);
      const multiplier = await computeMultiplier(config);
      const clientKey = await computeClientKey(serverPublic, multiplier, secret, clientKeyPair.private, scrambling, config);
      const clientEvidence = await computeClientEvidence(username, salt, clientKeyPair.public, serverPublic, clientKey, config);

      // Server authenticates client
      const authResult = await authenticate(
        username,
        salt,
        verifier,
        serverKeyPair,
        clientKeyPair.public,
        clientEvidence,
        config,
      );

      assertEquals(authResult.success, true);
      assertExists(authResult.evidence);

      // Verify server evidence can be validated by client
      const expectedServerEvidence = await computeServerEvidence(clientKeyPair.public, clientEvidence, clientKey, config);
      assertEquals(authResult.evidence, expectedServerEvidence.hex);
    });
  });
});
