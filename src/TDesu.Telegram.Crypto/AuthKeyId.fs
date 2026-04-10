namespace TDesu.Crypto

open System
open System.Security.Cryptography

[<RequireQualifiedAccess>]
module AuthKeyId =

    /// SHA1 hash helper
    let sha1 (data: byte[]) : byte[] =
        use hasher = SHA1.Create()
        hasher.ComputeHash(data)

    /// SHA256 hash helper
    let sha256 (data: byte[]) : byte[] =
        use hasher = SHA256.Create()
        hasher.ComputeHash(data)

    /// auth_key_id = SHA1(auth_key)[12..19] interpreted as int64 LE
    let compute (authKey: byte[]) : int64 =
        let hash = sha1 authKey
        BitConverter.ToInt64(hash, 12)
