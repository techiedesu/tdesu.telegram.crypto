# TDesu.Telegram.Crypto

[![NuGet](https://img.shields.io/nuget/v/TDesu.Telegram.Crypto.svg)](https://www.nuget.org/packages/TDesu.Telegram.Crypto)
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-blue.svg)](https://unlicense.org)

Cryptographic primitives for [Telegram MTProto 2.0](https://core.telegram.org/mtproto/description). AES-IGE, Diffie-Hellman key exchange, RSA encryption, and key derivation — all in pure F# with `System.Security.Cryptography`.

No BouncyCastle. No OpenSSL bindings. Just .NET crypto APIs and `BigInteger`.

## Install

```
dotnet add package TDesu.Telegram.Crypto
```

## Modules

### AesIge

AES-256-IGE (Infinite Garble Extension) mode — the non-standard block cipher mode used by MTProto for message encryption.

```fsharp
open TDesu.Crypto

// Encrypt (data length must be multiple of 16)
let encrypted = AesIge.encrypt plaintext key iv

// Decrypt
let decrypted = AesIge.decrypt ciphertext key iv
```

- Key: 32 bytes (AES-256)
- IV: 32 bytes (split into two 16-byte halves internally)
- Data: must be aligned to 16 bytes (use `Padding.addPadding` first)
- Validates input lengths, throws `ArgumentException` on mismatch

### KeyDerivation

MTProto 2.0 key derivation — derives AES key + IV from `auth_key` and `msg_key` per the [specification](https://core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector).

```fsharp
open TDesu.Crypto

// x = 0 for client->server, x = 8 for server->client
let { Key = aesKey; Iv = aesIv } = KeyDerivation.deriveAesKeyIv authKey msgKey x
```

Internally computes `sha256_a` and `sha256_b` from slices of `auth_key` and `msg_key`, then interleaves the hashes to produce a 32-byte key and 32-byte IV.

### DiffieHellman

2048-bit Diffie-Hellman key exchange as used in MTProto [authorization key creation](https://core.telegram.org/mtproto/auth_key).

```fsharp
open TDesu.Crypto

// Generate b and g^b mod p (server side)
let (b, gb) = DiffieHellman.generateGB g p

// Compute shared secret from g^a and b
let authKey = DiffieHellman.computeAuthKey ga b p

// Validate DH parameters (security checks per MTProto spec)
let isValid = DiffieHellman.validateDhParams g p gb
```

Validation includes:
- `1 < g < p-1` and `1 < g^a < p-1`
- `p` is a known safe 2048-bit prime
- `g^a` is within valid range (not 0, 1, or p-1)

All arithmetic uses `System.Numerics.BigInteger` with big-endian ↔ little-endian conversion (MTProto uses big-endian, .NET uses little-endian).

### Rsa

RSA encryption for the initial DH key exchange. Raw `data^e mod n` without PKCS padding (MTProto custom format).

```fsharp
open TDesu.Crypto

// Encrypt data with Telegram's production RSA key
let key = Rsa.publicKeys |> List.head
let encrypted = Rsa.encrypt data key    // byte[] -> byte[] (modulus length)

// Register test server keys at runtime
Rsa.addKey testServerKey
let allKeys = Rsa.allKeys ()            // production + registered

// Cleanup
Rsa.clearAdditionalKeys ()
```

The production RSA key fingerprint is `0xd09d1d85de64fd85` (exponent 65537).

### Padding

Random padding for MTProto message encryption. Ensures ciphertext length is a multiple of 16 bytes.

```fsharp
open TDesu.Crypto

// Add 12-1024 bytes of random padding, result aligned to 16
let padded = Padding.addPadding plaintext

// Generate random bytes
let nonce = Padding.randomBytes 16
```

### AuthKeyId

Compute `auth_key_id` — the 8-byte identifier derived from SHA1 of the authorization key.

```fsharp
open TDesu.Crypto

// auth_key_id = SHA1(auth_key)[12..19] as int64 LE
let keyId = AuthKeyId.compute authKey

// Hash helpers
let sha1Hash = AuthKeyId.sha1 data
let sha256Hash = AuthKeyId.sha256 data
```

## How these fit together

A typical MTProto message encryption flow:

```
1. Serialize message body        → TDesu.Telegram.Serialization
2. Add random padding            → Padding.addPadding
3. Compute msg_key (SHA-256)     → AuthKeyId.sha256
4. Derive AES key + IV           → KeyDerivation.deriveAesKeyIv
5. Encrypt with AES-IGE          → AesIge.encrypt
6. Prepend auth_key_id + msg_key → AuthKeyId.compute
```

For the initial DH handshake:

```
1. Generate nonce                → Padding.randomBytes
2. Encrypt PQ inner data         → Rsa.encrypt
3. Generate DH params            → DiffieHellman.generateGB
4. Derive auth_key               → DiffieHellman.computeAuthKey
5. Compute auth_key_id           → AuthKeyId.compute
```

## Dependencies

- [TDesu.FSharp](https://github.com/techiedesu/TDesu.FSharp) (>= 1.1.0) — `Guard`, `Bytes.concat`, `Bytes.xor`
- No other dependencies (uses only `System.Security.Cryptography` and `System.Numerics`)

## Building

```sh
dotnet build
dotnet test
```

## References

- [MTProto 2.0 Description](https://core.telegram.org/mtproto/description)
- [Authorization Key Creation](https://core.telegram.org/mtproto/auth_key)
- [Security Guidelines](https://core.telegram.org/mtproto/security_guidelines)

## License

[Unlicense](LICENSE)
