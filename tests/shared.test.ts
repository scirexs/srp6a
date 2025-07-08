import { assert, assertEquals, assertInstanceOf, assertNotEquals, assertThrows } from "jsr:@std/assert";
import { describe, it } from "jsr:@std/testing/bdd";

import {
  GROUP_2048,
  GROUP_2048_FOR_SERVER,
  GROUP_3072,
  GROUP_3072_FOR_SERVER,
  GROUP_4096,
  GROUP_4096_FOR_SERVER,
  GROUP_6144,
  GROUP_6144_FOR_SERVER,
  GROUP_8192,
  GROUP_8192_FOR_SERVER,
  SHA_256,
  SHA_384,
  SHA_512,
} from "../src/shared/constants.ts";
import { computeHash, CryptoNumber, generateSecureRandom, getDefaultConfig, SRPConfig } from "../src/shared/crypto.ts";
import {
  __internal,
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
  generateSalt,
  generateServerKeyPair,
  isValidPublic,
} from "../src/shared/functions.ts";
import { SRPHashConfig, SRPSecurityGroup } from "../src/shared/types.ts";

describe("Constants", () => {
  it("should have correct GROUP_2048 properties", () => {
    assertEquals(GROUP_2048.length, 2048);
    assertEquals(GROUP_2048.generator, BigInt(2));
    assertEquals(typeof GROUP_2048.prime, "bigint");
    assertEquals(GROUP_2048.multiplier, "");
  });

  it("should have correct GROUP_2048_FOR_SERVER properties", () => {
    assertEquals(GROUP_2048_FOR_SERVER.length, 2048);
    assertEquals(GROUP_2048_FOR_SERVER.generator, BigInt(2));
    assertEquals(typeof GROUP_2048_FOR_SERVER.prime, "bigint");
    assertNotEquals(GROUP_2048_FOR_SERVER.multiplier, "");
  });

  it("should have correct GROUP_3072 properties", () => {
    assertEquals(GROUP_3072.length, 3072);
    assertEquals(GROUP_3072.generator, BigInt(5));
    assertEquals(typeof GROUP_3072.prime, "bigint");
    assertEquals(GROUP_2048.multiplier, "");
  });

  it("should have correct GROUP_3072_FOR_SERVER properties", () => {
    assertEquals(GROUP_3072_FOR_SERVER.length, 3072);
    assertEquals(GROUP_3072_FOR_SERVER.generator, BigInt(5));
    assertEquals(typeof GROUP_3072_FOR_SERVER.prime, "bigint");
    assertNotEquals(GROUP_3072_FOR_SERVER.multiplier, "");
  });

  it("should have correct GROUP_4096 properties", () => {
    assertEquals(GROUP_4096.length, 4096);
    assertEquals(GROUP_4096.generator, BigInt(5));
    assertEquals(typeof GROUP_4096.prime, "bigint");
    assertEquals(GROUP_4096.multiplier, "");
  });

  it("should have correct GROUP_4096_FOR_SERVER properties", () => {
    assertEquals(GROUP_4096_FOR_SERVER.length, 4096);
    assertEquals(GROUP_4096_FOR_SERVER.generator, BigInt(5));
    assertEquals(typeof GROUP_4096_FOR_SERVER.prime, "bigint");
    assertNotEquals(GROUP_4096_FOR_SERVER.multiplier, "");
  });

  it("should have correct GROUP_6144 properties", () => {
    assertEquals(GROUP_6144.length, 6144);
    assertEquals(GROUP_6144.generator, BigInt(5));
    assertEquals(typeof GROUP_6144.prime, "bigint");
    assertEquals(GROUP_6144.multiplier, "");
  });

  it("should have correct GROUP_6144_FOR_SERVER properties", () => {
    assertEquals(GROUP_6144_FOR_SERVER.length, 6144);
    assertEquals(GROUP_6144_FOR_SERVER.generator, BigInt(5));
    assertEquals(typeof GROUP_6144_FOR_SERVER.prime, "bigint");
    assertNotEquals(GROUP_6144_FOR_SERVER.multiplier, "");
  });

  it("should have correct GROUP_8192 properties", () => {
    assertEquals(GROUP_8192.length, 8192);
    assertEquals(GROUP_8192.generator, BigInt(19));
    assertEquals(typeof GROUP_8192.prime, "bigint");
    assertEquals(GROUP_8192.multiplier, "");
  });

  it("should have correct GROUP_8192_FOR_SERVER properties", () => {
    assertEquals(GROUP_8192_FOR_SERVER.length, 8192);
    assertEquals(GROUP_8192_FOR_SERVER.generator, BigInt(19));
    assertEquals(typeof GROUP_8192_FOR_SERVER.prime, "bigint");
    assertNotEquals(GROUP_8192_FOR_SERVER.multiplier, "");
  });

  it("should have correct hash configurations", () => {
    assertEquals(SHA_256.algorithm, "SHA-256");
    assertEquals(SHA_256.bytes, 32);
    assertEquals(SHA_256.salt, 64);
    assertEquals(SHA_384.algorithm, "SHA-384");
    assertEquals(SHA_384.bytes, 48);
    assertEquals(SHA_384.salt, 96);
    assertEquals(SHA_512.algorithm, "SHA-512");
    assertEquals(SHA_512.bytes, 64);
    assertEquals(SHA_512.salt, 128);
  });
});

describe("SRPConfig", () => {
  it("should create default config", () => {
    const config = getDefaultConfig();
    assertEquals(config.length, 2048);
    assertEquals(config.algorithm, "SHA-256");
    assertEquals(config.salt, 64);
  });

  it("should create custom config", () => {
    const config = new SRPConfig(GROUP_3072, SHA_384);
    assertEquals(config.length, 3072);
    assertEquals(config.algorithm, "SHA-384");
    assertEquals(config.salt, 96);
  });

  it("should have correct prime and generator", () => {
    const config = getDefaultConfig();
    assertEquals(config.prime.int, GROUP_2048.prime);
    assertEquals(config.generator.int, GROUP_2048.generator);
  });
});

describe("CryptoNumber", () => {
  const _config = getDefaultConfig();

  it("should create from bigint", () => {
    const num = new CryptoNumber(BigInt(123));
    assertEquals(num.int, BigInt(123));
  });

  it("should create from hex string", () => {
    const num = new CryptoNumber("7b");
    assertEquals(num.int, BigInt(123));
    assertEquals(num.hex.toLowerCase(), "7b");
  });

  it("should create from Uint8Array", () => {
    const buf = new Uint8Array([0, 123]);
    const num = new CryptoNumber(buf);
    assertEquals(num.int, BigInt(123));
  });

  it("should handle hex string validation", () => {
    assertThrows(() => new CryptoNumber("xyz"), Error, "Contains invalid characters as hexadecimal");
    assertThrows(() => new CryptoNumber(""), Error, "Contains invalid characters as hexadecimal");
  });

  it("should pad hex string", () => {
    const num = new CryptoNumber("7b").pad();
    assertEquals(num.int, BigInt(123));
    assertEquals(num.hex.toLowerCase(), "7b".padStart(512, "0"));
  });

  it("should fixed pad hex string", () => {
    const num = new CryptoNumber("7b").pad(10);
    assertEquals(num.int, BigInt(123));
    assertEquals(num.hex.toLowerCase(), "7b".padStart(10, "0"));
  });

  it("should perform modular exponentiation", () => {
    const base = new CryptoNumber(BigInt(2));
    const exp = new CryptoNumber(BigInt(3));
    const mod = new CryptoNumber(BigInt(5));
    const result = CryptoNumber.modPow(base, exp, mod);
    assertEquals(result.int, BigInt(3)); // 2^3 mod 5 = 8 mod 5 = 3
  });

  it("should concatenate crypto numbers", () => {
    const a = new CryptoNumber(new Uint8Array([1, 2]));
    const b = new CryptoNumber(new Uint8Array([3, 4]));
    const result = CryptoNumber.concat(a, b);
    assertEquals(Array.from(result.buf), [1, 2, 3, 4]);
  });

  it("should perform XOR operation", () => {
    const a = new CryptoNumber(new Uint8Array([0xAA, 0xBB]));
    const b = new CryptoNumber(new Uint8Array([0xFF, 0x00]));
    const result = CryptoNumber.xor(a, b);
    assertEquals(Array.from(result.buf), [0x55, 0xBB]);
  });

  it("should compare crypto numbers in constant time", () => {
    const a = new CryptoNumber(new Uint8Array([1, 2, 3]));
    const b = new CryptoNumber(new Uint8Array([1, 2, 3]));
    const c = new CryptoNumber(new Uint8Array([1, 2, 4]));

    assertEquals(CryptoNumber.compare(a, b), true);
    assertEquals(CryptoNumber.compare(a, c), false);
  });

  it("should handle different length arrays in compare", () => {
    const a = new CryptoNumber(new Uint8Array([1, 2]));
    const b = new CryptoNumber(new Uint8Array([1, 2, 0]));
    const c = new CryptoNumber(new Uint8Array([1, 2, 1]));

    assertEquals(CryptoNumber.compare(a, b), false);
    assertEquals(CryptoNumber.compare(a, c), false);
  });

  it("should clear buffer data", () => {
    const num = new CryptoNumber(new Uint8Array([1, 2, 3]));
    const originalBuf = num.buf;
    num.clear();
    assertEquals(Array.from(originalBuf), [0, 0, 0]);
  });
});

describe("Hash Functions", () => {
  const config = getDefaultConfig();

  it("should compute hash of CryptoNumber", async () => {
    const num = new CryptoNumber(new Uint8Array([1, 2, 3]));
    const hash = await computeHash(num, config);
    assertEquals(typeof hash.int, "bigint");
  });

  it("should compute hash of Uint8Array", async () => {
    const buf = new Uint8Array([1, 2, 3]);
    const hash = await computeHash(buf, config);
    assertEquals(typeof hash.int, "bigint");
  });

  it("should produce consistent hashes", async () => {
    const data = new Uint8Array([1, 2, 3]);
    const hash1 = await computeHash(data, config);
    const hash2 = await computeHash(data, config);
    assertEquals(hash1.hex, hash2.hex);
  });
});

describe("Random Generation", () => {
  it("should generate secure random bytes", () => {
    const random1 = generateSecureRandom(32);
    const random2 = generateSecureRandom(32);

    assertEquals(random1.buf.length, 32);
    assertEquals(random2.buf.length, 32);

    // Should be different (extremely unlikely to be the same)
    assertEquals(CryptoNumber.compare(random1, random2), false);
  });

  it("should generate different lengths", () => {
    const random16 = generateSecureRandom(16);
    const random64 = generateSecureRandom(64);

    assertEquals(random16.buf.length, 16);
    assertEquals(random64.buf.length, 64);
  });
});

describe("SRP Functions", () => {
  const config = getDefaultConfig();
  const username = "testuser";
  const password = "testpass";

  it("should generate salt", () => {
    const salt = generateSalt(config);
    assertEquals(salt.buf.length, config.salt);
  });

  it("should compute identity", async () => {
    const identity = await computeIdentity(username, password, config);
    assertEquals(typeof identity.int, "bigint");
  });

  it("should reject empty username or password", async () => {
    try {
      await computeIdentity("", password, config);
      assert(false);
    } catch (e) {
      assertInstanceOf(e, Error);
      assertEquals(e.message, "Username and password must have length.");
    }
    try {
      await computeIdentity(username, "", config);
      assert(false);
    } catch (e) {
      assertInstanceOf(e, Error);
      assertEquals(e.message, "Username and password must have length.");
    }
  });

  it("should compute secret", async () => {
    const salt = generateSalt(config);
    const identity = await computeIdentity(username, password, config);
    const secret = await computeSecret(salt, identity, config);
    assertEquals(typeof secret.int, "bigint");
  });

  it("should calculate verifier", async () => {
    const salt = generateSalt(config);
    const identity = await computeIdentity(username, password, config);
    const secret = await computeSecret(salt, identity, config);
    const verifier = calculateVerifier(secret, config);
    assertEquals(typeof verifier.int, "bigint");
  });

  it("should compute multiplier", async () => {
    const multiplier = await computeMultiplier(config);
    assertEquals(typeof multiplier.int, "bigint");
  });

  it("should generate key pair", () => {
    const keyPair = generateKeyPair(config);
    assertEquals(typeof keyPair.private.int, "bigint");
    assertEquals(typeof keyPair.public.int, "bigint");
    assertEquals(keyPair.private.int > 0n, true);
    assertEquals(keyPair.public.int > 0n, true);
  });

  it("should validate public key", () => {
    const keyPair = generateKeyPair(config);
    assertEquals(isValidPublic(keyPair.public, config), true);

    const invalidPub = new CryptoNumber(BigInt(0));
    assertEquals(isValidPublic(invalidPub, config), false);

    const invalidPub2 = new CryptoNumber(config.prime.int);
    assertEquals(isValidPublic(invalidPub2, config), false);
  });

  it("should generate server key pair", async () => {
    const salt = generateSalt(config);
    const identity = await computeIdentity(username, password, config);
    const secret = await computeSecret(salt, identity, config);
    const verifier = calculateVerifier(secret, config);
    const multiplier = await computeMultiplier(config);

    const serverKeyPair = generateServerKeyPair(multiplier, verifier, config);
    assertEquals(typeof serverKeyPair.private.int, "bigint");
    assertEquals(typeof serverKeyPair.public.int, "bigint");
  });

  it("should compute scrambling parameter", async () => {
    const clientKeyPair = generateKeyPair(config);
    const serverKeyPair = generateKeyPair(config);

    const scrambling = await computeScramblingParameter(clientKeyPair.public, serverKeyPair.public, config);
    assertEquals(typeof scrambling.int, "bigint");
  });

  it("should compute client and server keys", async () => {
    const salt = generateSalt(config);
    const identity = await computeIdentity(username, password, config);
    const secret = await computeSecret(salt, identity, config);
    const verifier = calculateVerifier(secret, config);
    const multiplier = await computeMultiplier(config);

    const clientKeyPair = generateKeyPair(config);
    const serverKeyPair = generateServerKeyPair(multiplier, verifier, config);

    const scrambling = await computeScramblingParameter(clientKeyPair.public, serverKeyPair.public, config);

    const clientKey = await computeClientKey(
      serverKeyPair.public,
      multiplier,
      secret,
      clientKeyPair.private,
      scrambling,
      config,
    );

    const serverKey = await computeServerKey(
      clientKeyPair.public,
      verifier,
      scrambling,
      serverKeyPair.private,
      config,
    );

    assertEquals(typeof clientKey.int, "bigint");
    assertEquals(typeof serverKey.int, "bigint");

    // Client and server should derive the same key
    assertEquals(CryptoNumber.compare(clientKey, serverKey), true);
  });

  it("should compute client and server evidence", async () => {
    const salt = generateSalt(config);
    const identity = await computeIdentity(username, password, config);
    const secret = await computeSecret(salt, identity, config);
    const verifier = calculateVerifier(secret, config);
    const multiplier = await computeMultiplier(config);

    const clientKeyPair = generateKeyPair(config);
    const serverKeyPair = generateServerKeyPair(multiplier, verifier, config);

    const scrambling = await computeScramblingParameter(clientKeyPair.public, serverKeyPair.public, config);

    const clientKey = await computeClientKey(
      serverKeyPair.public,
      multiplier,
      secret,
      clientKeyPair.private,
      scrambling,
      config,
    );

    const clientEvidence = await computeClientEvidence(
      username,
      salt,
      clientKeyPair.public,
      serverKeyPair.public,
      clientKey,
      config,
    );

    const serverEvidence = await computeServerEvidence(
      clientKeyPair.public,
      clientEvidence,
      clientKey,
      config,
    );

    assertEquals(typeof clientEvidence.int, "bigint");
    assertEquals(typeof serverEvidence.int, "bigint");
  });
});

describe("Full SRP6a Protocol Flow", () => {
  const config = getDefaultConfig();
  const username = "alice";
  const password = "password123";

  it("should complete full authentication flow", async () => {
    // 1. Registration phase
    const salt = generateSalt(config);
    const identity = await computeIdentity(username, password, config);
    const secret = await computeSecret(salt, identity, config);
    const verifier = calculateVerifier(secret, config);

    // 2. Authentication phase
    const multiplier = await computeMultiplier(config);
    const clientKeyPair = generateKeyPair(config);
    const serverKeyPair = generateServerKeyPair(multiplier, verifier, config);

    // 3. Compute scrambling parameter
    const scrambling = await computeScramblingParameter(clientKeyPair.public, serverKeyPair.public, config);

    // 4. Compute shared keys
    const clientKey = await computeClientKey(
      serverKeyPair.public,
      multiplier,
      secret,
      clientKeyPair.private,
      scrambling,
      config,
    );

    const serverKey = await computeServerKey(
      clientKeyPair.public,
      verifier,
      scrambling,
      serverKeyPair.private,
      config,
    );

    // 5. Verify keys match
    assertEquals(CryptoNumber.compare(clientKey, serverKey), true);

    // 6. Compute evidence
    const clientEvidence = await computeClientEvidence(
      username,
      salt,
      clientKeyPair.public,
      serverKeyPair.public,
      clientKey,
      config,
    );

    const serverEvidence = await computeServerEvidence(
      clientKeyPair.public,
      clientEvidence,
      clientKey,
      config,
    );

    // 7. Verify evidence is computed correctly
    assertEquals(typeof clientEvidence.int, "bigint");
    assertEquals(typeof serverEvidence.int, "bigint");
  });

  it("should produce different results for different passwords", async () => {
    const salt = generateSalt(config);

    const identity1 = await computeIdentity(username, password, config);
    const secret1 = await computeSecret(salt, identity1, config);
    const verifier1 = calculateVerifier(secret1, config);

    const identity2 = await computeIdentity(username, "wrongpassword", config);
    const secret2 = await computeSecret(salt, identity2, config);
    const verifier2 = calculateVerifier(secret2, config);

    assertEquals(CryptoNumber.compare(verifier1, verifier2), false);
  });
});

describe("Edge Cases and Error Handling", () => {
  const config = getDefaultConfig();

  it("should handle large numbers correctly", () => {
    const largeNum = new CryptoNumber(config.prime.int - 1n);
    assertEquals(largeNum.int, config.prime.int - 1n);
  });

  it("should handle zero correctly", () => {
    const zero = new CryptoNumber(BigInt(0));
    assertEquals(zero.int, BigInt(0));
  });

  it("should validate XOR input lengths", () => {
    const a = new CryptoNumber(new Uint8Array([1, 2]));
    const b = new CryptoNumber(new Uint8Array([3, 4, 5]));

    assertThrows(
      () => CryptoNumber.xor(a, b),
      Error,
      "Uint8Array length must be same",
    );
  });

  it("should handle modPow with edge cases", () => {
    const base = new CryptoNumber(BigInt(0));
    const exp = new CryptoNumber(BigInt(5));
    const mod = new CryptoNumber(BigInt(7));

    const result = CryptoNumber.modPow(base, exp, mod);
    assertEquals(result.int, BigInt(0));
  });

  it("should throw error for invalid modPow parameters", () => {
    const base = new CryptoNumber(BigInt(2));
    const exp = new CryptoNumber(BigInt(-1));
    const mod = new CryptoNumber(BigInt(7));

    assertThrows(
      () => CryptoNumber.modPow(base, exp, mod),
      Error,
      "Invalid power",
    );
  });
});

describe("Confirm to match with test vectors", () => {
  const GROUP_1024: SRPSecurityGroup = {
    length: 1024,
    prime: BigInt(
      "0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
    ),
    generator: BigInt(2),
    multiplier: "",
  } as const;
  const SHA_1: SRPHashConfig = {
    algorithm: "SHA-1",
    bytes: 20,
    salt: 16,
  } as const;

  const config = new SRPConfig(GROUP_1024, SHA_1);
  const username = "alice";
  const password = "password123";
  const salt = new CryptoNumber("BEB25379D1A8581EB5A727673A2441EE");
  const multiplier = new CryptoNumber("7556AA045AEF2CDD07ABAF0F665C3E818913186F");
  const secret = new CryptoNumber("94B7555AABE9127CC58CCF4993DB6CF84D16C124");
  const verifier = new CryptoNumber(
    "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB",
  );
  const pvtClient = new CryptoNumber("60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393");
  const pubClient = new CryptoNumber(
    "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B",
  );
  const pvtServer = new CryptoNumber("E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20");
  const pubServer = new CryptoNumber(
    "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58",
  );
  const scrambling = new CryptoNumber("CE38B9593487DA98554ED47D70A7AE5F462EF019");
  const session = new CryptoNumber(
    "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A",
  );
  it("should be test vector's multiplier", async () => {
    const tmp = CryptoNumber.PAD_LEN;
    CryptoNumber.PAD_LEN = 256;
    const value = await computeMultiplier(config);
    CryptoNumber.PAD_LEN = tmp;
    assertEquals(value.hex, multiplier.hex);
  });
  it("should be test vector's secret", async () => {
    const identity = await computeIdentity(username, password, config);
    const value = await computeSecret(salt, identity, config);
    assertEquals(value.hex, secret.hex);
  });
  it("should be test vector's verifier", () => {
    const value = calculateVerifier(secret, config);
    assertEquals(value.hex, verifier.hex);
  });
  it("should be test vector's client public", () => {
    const value = CryptoNumber.modPow(config.generator, pvtClient, config.prime);
    assertEquals(value.hex, pubClient.hex);
  });
  it("should be test vector's server public", () => {
    const value = new CryptoNumber(
      (multiplier.pad(256).int * verifier.int + CryptoNumber.modPow(config.generator, pvtServer, config.prime).int) % config.prime.int,
    );
    assertEquals(value.hex, pubServer.hex);
  });
  it("should be test vector's scrambling", async () => {
    const tmp = CryptoNumber.PAD_LEN;
    CryptoNumber.PAD_LEN = 256;
    const value = await computeScramblingParameter(pubClient, pubServer, config);
    CryptoNumber.PAD_LEN = tmp;
    assertEquals(value.hex, scrambling.hex);
  });
  it("should be test vector's key", () => {
    if ("calculateClientSession" in __internal) {
      const client = __internal.calculateClientSession?.(pubServer, multiplier, secret, pvtClient, scrambling, config);
      assertEquals(client?.hex, session.hex);
    }
    if ("calculateServerSession" in __internal) {
      const server = __internal.calculateServerSession?.(pubClient, verifier, scrambling, pvtServer, config);
      assertEquals(server?.hex, session.hex);
    }
  });
});
