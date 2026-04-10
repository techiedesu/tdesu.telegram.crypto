namespace TDesu.Crypto

open System
open System.Numerics
open System.Security.Cryptography
open TDesu.FSharp
open TDesu.FSharp.Operators
open TDesu.FSharp.Buffers
[<RequireQualifiedAccess>]
module DiffieHellman =

    /// Convert big-endian byte array to unsigned BigInteger (little-endian + sign byte)
    let private toBigInteger (bigEndian: byte[]) : BigInteger =
        let le = Array.copy bigEndian
        Array.Reverse(le)
        BigInteger(Bytes.concat2 le [| 0uy |])

    /// Convert BigInteger back to big-endian byte array of specified length
    let private fromBigInteger (bi: BigInteger) (length: int) : byte[] =
        let bytes = bi.ToByteArray()
        let trimmed =
            if bytes.Length > 1 && bytes[bytes.Length - 1] = 0uy then
                bytes[.. bytes.Length - 2]
            else
                bytes
        let be = Array.copy trimmed
        Array.Reverse(be)
        if be.Length < length then
            Bytes.concat2 (Array.zeroCreate (length - be.Length)) be
        elif be.Length > length then
            be[be.Length - length ..]
        else
            be

    /// Generate random 256-byte value for DH
    let generateA () : byte[] =
        let bytes = Array.zeroCreate<byte> 256
        RandomNumberGenerator.Fill(bytes)
        bytes

    /// Compute g^a mod p
    let computeGA (g: int) (a: byte[]) (p: byte[]) : byte[] =
        let gBI = BigInteger(g)
        let aBI = toBigInteger a
        let pBI = toBigInteger p
        let result = BigInteger.ModPow(gBI, aBI, pBI)
        fromBigInteger result p.Length

    /// Compute g_b^a mod p (shared secret / auth_key)
    let computeAuthKey (gB: byte[]) (a: byte[]) (p: byte[]) : byte[] =
        let gBBI = toBigInteger gB
        let aBI = toBigInteger a
        let pBI = toBigInteger p
        let result = BigInteger.ModPow(gBBI, aBI, pBI)
        fromBigInteger result 256

    /// Validate that g_a or g_b is in range (1, p-1) per MTProto 2.0 spec.
    let validateGARange (ga: byte[]) (p: byte[]) : bool =
        let gaInt = toBigInteger ga
        let pInt = toBigInteger p
        gaInt > BigInteger.One && gaInt < (pInt - BigInteger.One)

    /// Validate DH parameters (g, p security checks)
    let validateDhParams (g: int) (p: byte[]) : bool =
        let pBI = toBigInteger p

        // p must be a positive number large enough (at least 2048 bits = 256 bytes)
        if pBI <= BigInteger.One then false
        elif p.Length < 256 then false
        else

        // p must be odd (prime)
        if pBI.IsEven then false
        else

        // (p - 1) / 2 should also be odd (safe prime check: q = (p-1)/2 is odd)
        let q = (pBI - BigInteger.One) / (BigInteger 2)
        if q.IsEven then false
        else

        // g must be a valid generator value
        if g < 2 then false
        else

        // Basic range checks for g
        match g with
        | 2 ->
            // p mod 8 == 7
            let pMod8 = int (pBI % (BigInteger 8))
            pMod8 = 7
        | 3 ->
            // p mod 3 == 2
            let pMod3 = int (pBI % (BigInteger 3))
            pMod3 = 2
        | 4 ->
            // No additional requirement beyond safe prime
            true
        | 5 ->
            // p mod 5 == 1 or p mod 5 == 4
            let pMod5 = int (pBI % (BigInteger 5))
            pMod5 = 1 || pMod5 = 4
        | 6 ->
            // p mod 24 == 19 or p mod 24 == 23
            let pMod24 = int (pBI % (BigInteger 24))
            pMod24 = 19 || pMod24 = 23
        | 7 ->
            // p mod 7 == 3 or p mod 7 == 4 or p mod 7 == 5 or p mod 7 == 6
            let pMod7 = int (pBI % (BigInteger 7))
            pMod7 = 3 || pMod7 = 4 || pMod7 = 5 || pMod7 = 6
        | _ ->
            // Unknown generator, accept if basic checks pass
            true
