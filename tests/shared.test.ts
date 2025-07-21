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
  // __internal,
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
  const salt = new CryptoNumber("beb25379d1a8581eb5a727673a2441ee");
  const multiplier = new CryptoNumber("7556aa045aef2cdd07abaf0f665c3e818913186f");
  const secret = new CryptoNumber("94b7555aabe9127cc58ccf4993db6cf84d16c124");
  const verifier = new CryptoNumber(
    "7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb",
  );
  const pvtClient = new CryptoNumber("60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393");
  const pubClient = new CryptoNumber(
    "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b",
  );
  const pvtServer = new CryptoNumber("e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20");
  const pubServer = new CryptoNumber(
    "bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58",
  );
  const scrambling = new CryptoNumber("ce38b9593487da98554ed47d70a7ae5f462ef019");
  const session = new CryptoNumber(
    "b0dc82babcf30674ae450c0287745e7990a3381f63b387aaf271a10d233861e359b48220f7c4693c9ae12b0a6f67809f0876e2d013800d6c41bb59b6d5979b5c00a172b4a2a5903a0bdcaf8a709585eb2afafa8f3499b200210dcc1f10eb33943cd67fc88a2f39a4be5bec4ec0a3212dc346d7e474b29ede8a469ffeca686e5a",
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
  // it("should be test vector's key", () => {
  //   if ("calculateClientSession" in __internal) {
  //     const client = __internal.calculateClientSession?.(pubServer, multiplier, secret, pvtClient, scrambling, config);
  //     assertEquals(client?.hex, session.hex);
  //   }
  //   if ("calculateServerSession" in __internal) {
  //     const server = __internal.calculateServerSession?.(pubClient, verifier, scrambling, pvtServer, config);
  //     assertEquals(server?.hex, session.hex);
  //   }
  // });
});
