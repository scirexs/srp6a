# Package for SRP-6a Authentication
SRP-6a (Secure Remote Password) implementation in TypeScript for browser and server.

[![npm version](https://img.shields.io/npm/v/%40scirexs%2Fsrp6a)](https://www.npmjs.com/package/@scirexs/srp6a)
[![JSR](https://img.shields.io/jsr/v/%40scirexs/srp6a)](https://jsr.io/@scirexs/srp6a)
[![license](https://img.shields.io/github/license/scirexs/srp6a)](https://github.com/scirexs/srp6a/blob/main/LICENSE)


## Installation
```bash
# npm
npm install @scirexs/srp6a

# JSR (Deno)
deno add jsr:@scirexs/srp6a
```


## Usage

### For Client

For details, see [the client documentation](https://jsr.io/@scirexs/srp6a/doc/client).

#### Registration Phase

```ts
import { getDefaultConfig, createUserCredentials } from "@scirexs/srp6a/client";

const config = getDefaultConfig();
const credentials = createUserCredentials(username, password, config);

// send data to server like `fetch(url, { method: "POST", body: JSON.stringify(credentials)});`
```

#### Authentication Phase

```ts
import { getDefaultConfig, createLoginHello, createEvidence, verifyServer } from "@scirexs/srp6a/client";

const config = getDefaultConfig();
const [hello, pair] = createLoginHello(username, config);
// send hello to server like `fetch(url, { method: "POST", body: JSON.stringify(hello)});`

// receive `salt` and public key from the server
// if the server uses this package, you can use `extractServerHello(response)`
const [evidence, expected] = await createEvidence(username, password, salt, server, pair, config);
// send evidence to server like `fetch(url, { method: "POST", body: JSON.stringify(evidence)});`

// receive `result` and `serverEvidence` and more
// if the server uses this package, you can use `extractLoginResult(response)`
if (!result) throw new Error("Failed to login.");
if (!verifyServer(expected, serverEvidence)) throw new Error("Could not verify the server.");
```

### For Server

For details, see [the server documentation](https://jsr.io/@scirexs/srp6a/doc/server).

#### Authentication Phase

```ts
import { getDefaultConfig, createServerHello, authenticate } from "@scirexs/srp6a/server";

// receive `username` and public key from the client
// if the client uses this package, you can use `extractClientHello(request)`

// read user's `salt` and `verifier` from the database
// if the user does not exist, use `createDummyHello` instead of `createServerHello`
const config = getDefaultConfig();
const [hello, pair] = createServerHello(salt, verifier, config);
// it is recommended to always use `addRandomDelay` before sending hello to mitigate timing attacks
// response hello to client like `new Response(JSON.stringify(hello));`

// receive `username` and `evidence` from the client
// if the client uses this package, you can use `extractLoginEvidence(request)`
const result = authenticate(username, salt, verifier, pair, client, evidence, config);
// add other data to the result object
// response result to client like `new Response(JSON.stringify(result));`
```

### Encryption Configuration

#### SRP Group Parameters

`GROUP_XXXX` indicates "SRP Group Parameters" of RFC 5054 Appendix A.

```ts
import { SRPConfig, SHA_512, GROUP_4096 } from "@scirexs/srp6a/client";
// import { SRPConfig, SHA_512, GROUP_4096_FOR_SERVER } from "@scirexs/srp6a/server";

const config = new SRPConfig(GROUP_4096, SHA_512);
// const config = new SRPConfig(GROUP_4096_FOR_SERVER, SHA_512);
```

`getDefaultConfig()` returns `new SRPConfig(GROUP_2048, SHA_256)`.

The difference between `GROUP_4096` and `GROUP_4096_FOR_SERVER` is whether they include a precomputed `multiplier` value. `GROUP_4096` does not include the precomputed `multiplier` to reduce package size, as it can be derived through calculation when needed.

#### Salt Length

The salt bytes should be greater than the hash output bytes, so we defined salt length as twice the output bytes. For example, it will be 64 bytes if use SHA-256 hash algorithm.

## Warning

This package includes security countermeasures such as constant-time comparisons and random delay insertion. However, it has never received an independent third-party security audit for correctness and security.

**Do not use this package in production environments without understanding the security risks involved. USE AT YOUR OWN RISK!**


## SRP Overview

### Procedure

#### Signup

1. Client: Calculate salt, verifier from username and password (`createUserCredentials`)
2. Client: Send Username, salt, verifier
3. Server: Store them

#### Login

1. Client: Generate random key pair (`createLoginHello`)
2. Client: Send Username, public key of the pair
3. Server: Read stored data including salt, verifier
4. Server: Generate random key pair (`createServerHello`)
5. Server: Send salt, public key of the pair
6. Client: Calculate session key (`createEvidence` includes step 6-8)
7. Client: Calculate client evidence from session key
8. Client: Calculate expected server evidence
9. Client: Send the client evidence
10. Server: Calculate session key (`authenticate` includes step 10-13)
11. Server: Calculate client evidence from session key
12. Server: Confirm exactly matched evidences
13. Server: Calculate server evidence from client evidence and session key
14. Server: Send server evidence and result of authentication
15. Client: Confirm exactly matched the server evidences and expected (`verifyServer`)

### Vocabulary
#### Operator, Function

|Expression|Description|
|---|---|
|\||Concatenate|
|^|(Modular) Exponentiation|
|H()|One-way hash function|
|RAND()|Generate secure random array of bytes|
|MP(n,k,m)|Calculates modPow as `n^k % m`|
|PAD(d)|Cast d to zero-padding|

#### Variable

|Variable|Description|
|---|---|
|N|A large safe prime|
|g|A generator modulo N|
|k|Multiplier parameter|
|s|User's salt|
|U|Username|
|p|Cleartext Password|
|I|Identity hash derived from U and p|
|u|Random scrambling parameter|
|a,b|Secret ephemeral values|
|A,B|Public ephemeral values|
|x|Private key derived from password|
|v|Password verifier|
|S|Session key|
|K|Strong session key|
|Mc,Ms|Evidence|

##### Name in Code

|Variable|Name|
|---|---|
|N|prime|
|g|generator|
|k|multiplier|
|s|salt|
|U|username|
|p|password|
|I|identity|
|x|secret|
|u|scrambling|
|a|pair.private, pvt|
|A|pair.public, pub, client|
|b|pair.private, pvt|
|B|pair.public, pub, server|
|v|verifier|
|S|session|
|K|key|
|Mc,Ms|evidence|

### Formula for each variable

|Variable|Expression|Note|
|---|---|---|
|N|<constant>|-|
|g|<constant>|-|
|U|<read from outside>|-|
|p|<read from outside>|-|
|I|H(U \| ":" \| p)|-|
|x|H(s \| I)|-|
|s|RAND()|-|
|v|MP(g, x, N)|-|
|k|H(N \| PAD(g))|-|
|a|RAND()|-|
|A|MP(g, a, N)|-|
|b|RAND()|-|
|B|k * v + MP(g, b, N)|-|
|u|H(PAD(A) \| PAD(B))|-|
|Sc|MP(B - (k * MP(g, x, N)), a + (u * x), N)|Client side|
|Ss|MP(MP(v, u, N) * A, b, N)|Server side|
|Kc|H(Sc)|Client side|
|Ks|H(Ss)|Server side|
|Mc|H(H(N) xor H(g), H(U), s, A, B, Kc)|-|
|Mc'|H(H(N) xor H(g), H(U), s, A, B, Ks)|Verify Mc|
|Ms|H(A, Mc, Ks)|-|
|Ms'|H(A, Mc, Ks)|Expected Ms|

## SRP Details

### Signup phase (Client)

1. Client: Send `U`,`s`,`v`.

|Variable|Expression|
|---|---|
|N,g|\<read from constant>|
|U,p|\<read from user>|
|s|RAND()|
|I|H(U \| ":" \| p)|
|x|H(s \| I)|
|v|MP(g, x, N)|

### Login phase

1. Client: Send `U`,`A`.

|Variable|Expression|
|---|---|
|N,g|\<read from constant>|
|U|\<read from user>|
|a|RAND()|
|A|MP(g, a, N)|

2. Server: Send `B`,`s`.

|Variable|Expression|
|---|---|
|U,A|\<read from client>|
|N,g,s,v|\<read from password file>|
|b|RAND()|
|k|H(N \| PAD(g))|
|B|k * v + MP(g, b, N)|

3. Client: Expect `Ms` and send `Mc`.

|Variable|Expression|
|---|---|
|U,a,A|\<read from state>|
|s,B|\<read from server>|
|p|\<read from user>|
|I|H(U \| ":" \| p)|
|x|H(s \| I)|
|u|H(PAD(A) \| PAD(B))|
|k|H(N \| PAD(g))|
|Sc|MP(B - (k * MP(g, x, N)), a + (u * x), N)|
|Kc|H(Sc)|
|Mc|H(H(N) xor H(g), H(U), s, A, B, Kc)|
|Ms'|H(A, Mc, Kc)|

1. Server: Verify `Mc` and Send `Ms`

|Variable|Expression|
|---|---|
|N,g,U,s,v,A,b,B|\<read from state>|
|Mc|\<read from client>|
|u|H(PAD(A) \| PAD(B))|
|Ss|MP(MP(v, u, N) * A, b, N)|
|Ks|H(Ss)|
|Mc'|H(H(N) xor H(g), H(U), s, A, B, Ks)|
|Ms|H(A, Mc, Ks)|

5. Client: Verify `Ms`

|Variable|Expression|
|---|---|
|Ms'|\<read from state>|
|Ms|\<read from server>|
