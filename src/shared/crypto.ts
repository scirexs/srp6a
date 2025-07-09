export { computeHash, CryptoNumber, generateSecureRandom, getDefaultConfig, SRPConfig };

import { GROUP_2048, SHA_256 } from "../shared/constants.ts";
import type { HashAlgorithm, SRPHashConfig, SRPSecurityGroup } from "./types.ts";

// Works with Web Crypto API like brower, Node.js, Deno.
const crypto = globalThis?.crypto;
if (!crypto || !crypto.subtle) throw new Error("Could not find `globalThis.crypto` with Web Crypto API.");

/**
 * Configuration class for SRP6a authentication protocol
 * Combines security group and hash settings to provide various parameters required for authentication
 */
class SRPConfig {
  #group: SRPSecurityGroup;
  #hash: SRPHashConfig;
  #prime: CryptoNumber;
  #generator: CryptoNumber;
  /**
   * Gets the prime number from the security group
   * @returns {CryptoNumber} Prime number value
   */
  get prime(): CryptoNumber {
    return this.#prime;
  }
  /**
   * Gets the generator from the security group
   * @returns {CryptoNumber} Generator value
   */
  get generator(): CryptoNumber {
    return this.#generator;
  }
  /**
   * Gets the bit length of the security group
   * @returns {number} Bit length
   */
  get length(): number {
    return this.#group.length;
  }
  /**
   * Gets the multiplier from the security group
   * @returns {string} Multiplier value
   */
  get multiplier(): string {
    return this.#group.multiplier;
  }
  /**
   * Gets the hash algorithm
   * @returns {HashAlgorithm} Hash algorithm
   */
  get algorithm(): HashAlgorithm {
    return this.#hash.algorithm;
  }
  /**
   * Gets the number of bytes in the hash value
   * @returns {number} Number of bytes in hash value
   */
  get hashBytes(): number {
    return this.#hash.bytes;
  }
  /**
   * Gets the salt bit length
   * @returns {number} Salt bit length
   */
  get salt(): number {
    return this.#hash.salt;
  }
  /**
   * Creates an instance of SRPConfig
   * @param {SRPSecurityGroup} group - Security group configuration
   * @param {SRPHashConfig} hash - Hash configuration
   */
  constructor(group: SRPSecurityGroup, hash: SRPHashConfig) {
    this.#group = group;
    this.#hash = hash;
    CryptoNumber.PAD_LEN = Math.ceil(group.length / 4); // pad length as hex string
    this.#prime = new CryptoNumber(group.prime);
    this.#generator = new CryptoNumber(group.generator);
  }
}
/**
 * Gets the default SRP configuration
 * Returns default configuration using GROUP_2048 and SHA_256
 * @returns {SRPConfig} Default SRP configuration
 */
function getDefaultConfig(): SRPConfig {
  return new SRPConfig(GROUP_2048, SHA_256);
}

async function computeHash(num: CryptoNumber | Uint8Array, config: SRPConfig): Promise<CryptoNumber> {
  num = num instanceof CryptoNumber ? num.buf : num;
  return new CryptoNumber(new Uint8Array(await crypto.subtle.digest(config.algorithm, num)));
}
function generateSecureRandom(bytes: number): CryptoNumber {
  const result = new Uint8Array(bytes);
  crypto.getRandomValues(result);
  return new CryptoNumber(result);
}

/**
 * Class representing numbers used in cryptographic operations
 * Manages numbers in three formats: bigint, hex string, and Uint8Array,
 * with lazy conversion performed as needed
 */
class CryptoNumber {
  static PAD_LEN = 0;
  static ERR_CAST: Error = new Error("Can't cast from empty.");
  #int: bigint | undefined;
  #hex: string = "";
  #buf: Uint8Array | undefined;

  /**
   * Gets the number in bigint format (lazy evaluation)
   * @returns {bigint} Number in bigint format
   */
  get int(): bigint {
    if (this.#int === undefined) this.#int = this.#deriveInt();
    return this.#int;
  }
  /**
   * Gets the number in hex string format (lazy evaluation)
   * @returns {string} Number in hex string format
   */
  get hex(): string {
    if (!this.#hex) this.#hex = this.#deriveHex();
    return this.#hex;
  }
  /**
   * Gets the number in Uint8Array format (lazy evaluation)
   * @returns {Uint8Array} Number in Uint8Array format
   */
  get buf(): Uint8Array {
    if (!this.#buf) this.#buf = this.#deriveBuf();
    return this.#buf;
  }
  /**
   * Creates an instance of CryptoNumber
   * @param {bigint | string | Uint8Array} value - Initial value (bigint, hex string, or Uint8Array)
   * @throws {Error} If PAD_LEN is not initialized
   */
  constructor(value: bigint | string | Uint8Array) {
    if (CryptoNumber.PAD_LEN <= 0) throw new Error("PAD_BYTES must be initialized before use.");
    switch (typeof value) {
      case "bigint":
        this.#int = value;
        break;
      case "string":
        this.#hex = CryptoNumber.#guardHex(value);
        break;
      case "object":
        this.#buf = value;
        break;
    }
  }

  /**
   * Returns a new CryptoNumber with hex string left-padded with zeros to the specified length
   * @param {number} [len] - Padding length (uses PAD_LEN if omitted)
   * @returns {CryptoNumber} New CryptoNumber with padded value
   */
  pad(len?: number): CryptoNumber {
    return new CryptoNumber(this.hex.padStart(len ?? CryptoNumber.PAD_LEN, "0"));
  }
  /**
   * Clears the internal Uint8Array buffer by filling it with zeros
   * Used to securely erase sensitive data
   */
  clear() {
    if (!this.#buf) return;
    this.#buf.fill(0);
    this.#buf = undefined;
  }
  #deriveInt(): bigint {
    return this.#hex ? this.#castHex2Int() : this.#castBuf2Int();
  }
  #deriveHex(): string {
    const str = this.#buf ? this.#castBuf2Hex() : this.#castInt2Hex();
    return CryptoNumber.#guardHex(str);
  }
  #deriveBuf(): Uint8Array {
    return this.#hex ? this.#castHex2Buf() : this.#castInt2Buf();
  }
  #castInt2Hex(): string {
    if (this.#int === undefined) CryptoNumber.#castError();
    return CryptoNumber.#padHexString(this.#int.toString(16));
  }
  #castInt2Buf(): Uint8Array {
    if (this.#int === undefined) CryptoNumber.#castError();
    return new Uint8Array(this.hex.match(/.{2}/g)!.map((x) => parseInt(x, 16)));
  }
  #castHex2Int(): bigint {
    if (!this.#hex) CryptoNumber.#castError();
    return BigInt(`0x${this.#hex}`);
  }
  #castHex2Buf(): Uint8Array {
    if (!this.#hex) CryptoNumber.#castError();
    return new Uint8Array(this.#hex.match(/.{2}/g)!.map((x) => parseInt(x, 16)));
  }
  #castBuf2Int(): bigint {
    if (!this.#buf) CryptoNumber.#castError();
    return BigInt(`0x${this.hex}`);
  }
  #castBuf2Hex(): string {
    if (!this.#buf) CryptoNumber.#castError();
    return Array.from(this.#buf)
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");
  }

  static #castError(): never {
    throw new Error("Can't cast from empty.");
  }
  static #guardHex(str: string): string {
    if (!CryptoNumber.#isValidHexString(str)) throw new Error("Contains invalid characters as hexadecimal.");
    return CryptoNumber.#padHexString(str);
  }
  static #isValidHexString(str: string): boolean {
    return /^[0-9a-fA-F]+$/.test(str);
  }
  static #padHexString(str: string): string {
    str = str.toUpperCase();
    return str.length % 2 === 0 ? str : "0" + str;
  }
  /**
   * Efficiently calculates modular exponentiation (base^pow mod mod)
   * @param {CryptoNumber | bigint} base - Base value
   * @param {CryptoNumber | bigint} pow - Exponent value
   * @param {CryptoNumber} mod - Modulus value
   * @returns {CryptoNumber} Result of modular exponentiation
   * @throws {Error} If arguments are invalid
   */
  static modPow(base: CryptoNumber | bigint, pow: CryptoNumber | bigint, mod: CryptoNumber): CryptoNumber {
    base = typeof base === "object" ? base.int : base;
    pow = typeof pow === "object" ? pow.int : pow;
    if (base < 0n) throw new Error(`Invalid base: ${base.toString()}`);
    if (pow < 0n) throw new Error(`Invalid power: ${pow.toString()}`);
    if (mod.int < 1n) throw new Error(`Invalid modulo: ${mod.int.toString()}`);

    let result: bigint = 1n;
    base = base % mod.int;
    while (pow > 0n) {
      if (pow % 2n === 1n) result = (result * base) % mod.int;
      base = (base * base) % mod.int;
      pow /= 2n;
    }
    return new CryptoNumber(result);
  }
  /**
   * Concatenates multiple CryptoNumber buffers
   * @param {...CryptoNumber} nums - CryptoNumbers to concatenate
   * @returns {CryptoNumber} Concatenated CryptoNumber
   */
  static concat(...nums: CryptoNumber[]): CryptoNumber {
    const len = nums.reduce((sum, num) => sum + num.buf.length, 0);
    const result = new Uint8Array(len);
    let offset = 0;

    for (const num of nums) {
      result.set(num.buf, offset);
      offset += num.buf.length;
    }
    return new CryptoNumber(result);
  }
  /**
   * Performs XOR operation on two CryptoNumbers
   * @param {CryptoNumber} a - First operand
   * @param {CryptoNumber} b - Second operand
   * @returns {CryptoNumber} XOR operation result
   * @throws {Error} If buffer lengths differ
   */
  static xor(a: CryptoNumber, b: CryptoNumber): CryptoNumber {
    if (a.buf.length !== b.buf.length) throw new Error("Uint8Array length must be same.");
    const aBuf = a.buf;
    const bBuf = b.buf;
    const result = new Uint8Array(aBuf.length);

    for (let i = 0; i < aBuf.length; i++) {
      result[i] = aBuf[i] ^ bBuf[i];
    }
    return new CryptoNumber(result);
  }
  /**
   * Compares two CryptoNumbers in constant time
   * Used to prevent timing attacks
   * @param {CryptoNumber} a - First comparison target
   * @param {CryptoNumber} b - Second comparison target
   * @returns {boolean} True if values are equal
   */
  static compare(a: CryptoNumber, b: CryptoNumber): boolean { // constantTimeCompare
    const aBuf = a.buf;
    const bBuf = b.buf;
    const len = Math.max(aBuf.length, bBuf.length);
    let result = aBuf.length ^ bBuf.length;

    for (let i = 0; i < len; i++) {
      const aVal = i < aBuf.length ? aBuf[i] : 0;
      const bVal = i < bBuf.length ? bBuf[i] : 0;
      result |= aVal ^ bVal;
    }
    return result === 0;
  }
}
