# srp6a
SRP-6a (Secure Remote Password) implementation in TypeScript for browser and server.

# Overview

## Procedure

### Signup

1. Client: Calculate salt, verifier from username and password
2. Client: Send Username, salt, verifier
3. Server: Store them

### Login

1. Client: Generate random key pair
2. Client: Send Username, public key of the pair
3. Server: Read stored data including salt, verifier
4. Server: Generate random key pair
5. Server: Send salt, public key of the pair
6. Client: Calculate session key
7. Client: Calculate client evidence from session key
8. Client: Calculate expected server evidence
9. Client: Send the client evidence
10. Server: Calculate session key
11. Server: Calculate client evidence from session key
12. Server: Confirm exactly matched evidences
13. Server: Calculate server evidence from client evidence and session key
14. Server: Send server evidence and result of authentication
15. Client: Confirm exactly matched the server evidences and expected

## Vocabulary
### Operator, Function

|Expression|Description|
|---|---|
|\||Concatenate|
|^|(Modular) Exponentiation|
|H()|One-way hash function|
|RAND()|Generate secure random array of bytes|
|MP(n,k,m)|Calculates modPow as `n^k % m`|
|PAD(d)|Cast d to zero-padding|

### Variable

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

#### Name in Code

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

## Formula for each variable

|Variable|Expression|Note|
|---|---|---|
|N|<constant>|-|
|g|<constant>|-|
|U|<read from outside>|-|
|p|<read from outside>|-|
|I|H(U | ":" | p)|-|
|x|H(s | I)|-|
|s|RAND()|-|
|v|MP(g, x, N)|-|
|k|H(N | PAD(g))|-|
|a|RAND()|-|
|A|MP(g, a, N)|-|
|b|RAND()|-|
|B|k * v + MP(g, b, N)|-|
|u|H(PAD(A) | PAD(B))|-|
|Sc|MP(B - (k * MP(g, x, N)), a + (u * x), N)|Client side|
|Ss|MP(MP(v, u, N) * A, b, N)|Server side|
|Kc|H(Sc)|Client side|
|Ks|H(Ss)|Server side|
|Mc|H(H(N) xor H(g), H(U), s, A, B, Kc)|-|
|Mc'|H(H(N) xor H(g), H(U), s, A, B, Ks)|Verify Mc|
|Ms|H(A, Mc, Ks)|-|
|Ms'|H(A, Mc, Ks)|Expected Ms|

# Details

## Signup phase (Client)

1. Client: Send `U`,`s`,`v`.

|Variable|Expression|
|---|---|
|N,g|<read from constant>|
|U,p|<read from user>|
|s|RAND()|
|I|H(U | ":" | p)|
|x|H(s | I)|
|v|MP(g, x, N)|

## Login phase

1. Client: Send `U`,`A`.

|Variable|Expression|
|---|---|
|N,g|<read from constant>|
|U|<read from user>|
|a|RAND()|
|A|MP(g, a, N)|

2. Server: Send `B`,`s`.

検証1: A != 0
検証2: A % N != 0

|Variable|Expression|
|---|---|
|U,A|<read from client>|
|N,g,s,v|<read from password file>|
|b|RAND()|
|k|H(N | PAD(g))|
|B|k * v + MP(g, b, N)|

3. Client: Expect `Ms` and send `Mc`.

|Variable|Expression|
|---|---|
|U,a,A|<read from state>|
|s,B|<read from server>|
|p|<read from user>|
|I|H(U | ":" | p)|
|x|H(s | I)|
|u|H(PAD(A) | PAD(B))|
|k|H(N | PAD(g))|
|Sc|MP(B - (k * MP(g, x, N)), a + (u * x), N)|
|Kc|H(Sc)|
|Mc|H(H(N) xor H(g), H(U), s, A, B, Kc)|
|Ms'|H(A, Mc, Kc)|

1. Server: Verify `Mc` and Send `Ms`

|Variable|Expression|
|---|---|
|N,g,U,s,v,A,b,B|<read from state>|
|Mc|<read from client>|
|u|H(PAD(A) | PAD(B))|
|Ss|MP(MP(v, u, N) * A, b, N)|
|Ks|H(Ss)|
|Mc'|H(H(N) xor H(g), H(U), s, A, B, Ks)|
|Ms|H(A, Mc, Ks)|

5. Client: Verify `Ms`

|Variable|Expression|
|---|---|
|Ms'|<read from state>|
|Ms|<read from server>|

# Warning

This package has never received an independent third party audit for security and correctness.

USE AT YOUR OWN RISK!
