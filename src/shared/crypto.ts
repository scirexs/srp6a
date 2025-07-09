export { computeHash, CryptoNumber, generateSecureRandom, getDefaultConfig, SRPConfig };

import { GROUP_2048, SHA_256 } from "../shared/constants.ts";
import type { HashAlgorithm, SRPHashConfig, SRPSecurityGroup } from "./types.ts";

// Works with Web Crypto API like brower, Node.js, Deno.
const crypto = globalThis?.crypto;
if (!crypto || !crypto.subtle) throw new Error("Could not find `globalThis.crypto` with Web Crypto API.");

class SRPConfig {
  #group: SRPSecurityGroup;
  #hash: SRPHashConfig;
  #prime: CryptoNumber;
  #generator: CryptoNumber;
  get prime(): CryptoNumber {
    return this.#prime;
  }
  get generator(): CryptoNumber {
    return this.#generator;
  }
  get length(): number {
    return this.#group.length;
  }
  get multiplier(): string {
    return this.#group.multiplier;
  }
  get algorithm(): HashAlgorithm {
    return this.#hash.algorithm;
  }
  get hashBytes(): number {
    return this.#hash.bytes;
  }
  get salt(): number {
    return this.#hash.salt;
  }
  constructor(group: SRPSecurityGroup, hash: SRPHashConfig) {
    this.#group = group;
    this.#hash = hash;
    CryptoNumber.PAD_LEN = Math.ceil(group.length / 4); // pad length as hex string
    this.#prime = new CryptoNumber(group.prime);
    this.#generator = new CryptoNumber(group.generator);
  }
}
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

class CryptoNumber {
  static PAD_LEN = 0;
  static ERR_CAST: Error = new Error("Can't cast from empty.");
  #int: bigint | undefined;
  #hex: string = "";
  #buf: Uint8Array | undefined;

  get int(): bigint {
    if (this.#int === undefined) this.#int = this.#deriveInt();
    return this.#int;
  }
  get hex(): string {
    if (!this.#hex) this.#hex = this.#deriveHex();
    return this.#hex;
  }
  get buf(): Uint8Array {
    if (!this.#buf) this.#buf = this.#deriveBuf();
    return this.#buf;
  }
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

  pad(len?: number): CryptoNumber {
    return new CryptoNumber(this.hex.padStart(len ?? CryptoNumber.PAD_LEN, "0"));
  }
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
