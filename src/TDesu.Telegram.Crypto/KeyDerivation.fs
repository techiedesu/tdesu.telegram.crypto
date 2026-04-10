namespace TDesu.Crypto

open System.Security.Cryptography
open TDesu.FSharp
open TDesu.FSharp.Operators
open TDesu.FSharp.Buffers
[<RequireQualifiedAccess>]
module KeyDerivation =

    type AesKeyIv = { Key: byte[]; Iv: byte[] }

    let private sha256 (data: byte[]) : byte[] =
        use hasher = SHA256.Create()
        hasher.ComputeHash(data)

    /// x = 0 for client->server, x = 8 for server->client
    let deriveAesKeyIv (authKey: byte[]) (msgKey: byte[]) (x: int) : AesKeyIv =
        // sha256_a = SHA256(msg_key + auth_key[x..x+35])
        let sha256A =
            sha256 ^ Bytes.concat2 msgKey authKey[x .. x + 35]

        // sha256_b = SHA256(auth_key[40+x..40+x+35] + msg_key)
        let sha256B =
            sha256 ^ Bytes.concat2 authKey[40 + x .. 40 + x + 35] msgKey

        // aes_key = sha256_a[0..7] + sha256_b[8..23] + sha256_a[24..31]   (32 bytes)
        let aesKey =
            Bytes.concat3 sha256A[0..7] sha256B[8..23] sha256A[24..31]

        // aes_iv = sha256_b[0..7] + sha256_a[8..23] + sha256_b[24..31]    (32 bytes)
        let aesIv =
            Bytes.concat3 sha256B[0..7] sha256A[8..23] sha256B[24..31]

        { Key = aesKey; Iv = aesIv }

    /// Compute msg_key from auth_key and plaintext
    /// msg_key = SHA256(auth_key[88+x..119+x] ++ plaintext)[8..23]  (16 bytes)
    let computeMsgKey (authKey: byte[]) (plaintext: byte[]) (x: int) : byte[] =
        let hash =
            sha256 ^ Bytes.concat2 authKey[88 + x .. 119 + x] plaintext
        hash[8..23]
