namespace TDesu.Crypto

open System
open System.Numerics
open System.Collections.Generic
open TDesu.FSharp
open TDesu.FSharp.Operators
open TDesu.FSharp.Buffers
[<RequireQualifiedAccess>]
module Rsa =

    type RsaPublicKey = {
        Fingerprint: int64
        Modulus: byte[]
        Exponent: byte[]
    }

    /// Convert a hex string to byte array
    let hexToBytes (hex: string) : byte[] =
        let hex = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "")
        Array.init (hex.Length / 2) (fun i ->
            Convert.ToByte(hex.Substring(i * 2, 2), 16))

    /// Telegram production RSA public key (fingerprint 0xd09d1d85de64fd85)
    let publicKeys: RsaPublicKey list =
        [
            {
                Fingerprint = -3414540481677951611L // 0xd09d1d85de64fd85UL as int64
                Modulus =
                    hexToBytes
                        "C150023E2F70DB7985DED064759CFECF0AF328E69A41DAF4D6F01B538135A6F91F8F8B2A0EC9BA9720CE352EFCF6C5680FFC424BD634864902DE0B4BD6D49F4E580230E3AE97D95C8B19442B3C0A10D8F5633FECEDD6926A7F6DAB0DDB7D457F9EA81B8465FCD6FFFEED114011DF91C059CAEDAF97625F6C96ECC74725556934EF781D866B34F011FCE4D835A090196E9A5F0E4449AF7EB697DDB9076494CA5F81104A305B6DD27665722C46B60E5DF680FB16B210607EF217652010F4BEE64042F645E1A5C7B346FE1BB3624C26902A2C6D4A4DB69B205B1A8B1E7C5F43E7A33AEC539BA65263B0DFC36BD5E7D5C8E0C7D1632D43EA7BF5E5B3D2B6E8CDB7"
                Exponent = [| 0x01uy; 0x00uy; 0x01uy |] // 65537
            }
        ]

    /// Additional keys registered at runtime (e.g. test server keys)
    let private additionalKeys = List<RsaPublicKey>()

    /// Register an additional RSA public key (e.g. for test servers)
    let addKey (key: RsaPublicKey) : unit =
        additionalKeys.Add(key)

    /// Get all known RSA keys (production + registered)
    let allKeys () : RsaPublicKey list =
        let extra = additionalKeys |> Seq.toList
        List.append publicKeys extra

    /// Clear all registered additional keys (for test teardown)
    let clearAdditionalKeys () : unit =
        additionalKeys.Clear()

    /// Encrypt data with RSA for DH exchange.
    /// Performs raw RSA: data^e mod n (big-endian, unsigned).
    let encrypt (data: byte[]) (key: RsaPublicKey) : byte[] =
        // MTProto uses big-endian for RSA, .NET BigInteger uses little-endian.
        // Append 0x00 sign byte to ensure unsigned interpretation.
        let toLEUnsigned (bigEndian: byte[]) =
            let le = Array.copy bigEndian
            Array.Reverse(le)
            Bytes.concat2 le [| 0uy |]

        let dataBI = BigInteger(toLEUnsigned data)
        let modulusBI = BigInteger(toLEUnsigned key.Modulus)
        let exponentBI = BigInteger(toLEUnsigned key.Exponent)

        let resultBI = BigInteger.ModPow(dataBI, exponentBI, modulusBI)

        // Convert back to big-endian, strip sign byte, pad to modulus length
        let resultBytes = resultBI.ToByteArray()
        // Remove trailing zero (sign byte) if present, then reverse to big-endian
        let trimmed =
            if resultBytes.Length > 1 && resultBytes[resultBytes.Length - 1] = 0uy then
                resultBytes[.. resultBytes.Length - 2]
            else
                resultBytes
        let be = Array.copy trimmed
        Array.Reverse(be)

        // Pad with leading zeros to match modulus length
        let modulusLen = key.Modulus.Length
        if be.Length < modulusLen then
            Bytes.concat2 (Array.zeroCreate (modulusLen - be.Length)) be
        else
            be
