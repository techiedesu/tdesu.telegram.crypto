namespace TDesu.Crypto.Tests

open System.Numerics
open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

[<TestFixture>]
type DiffieHellmanTests() =

    [<Test>]
    member _.``generateA returns 256 bytes``() =
        let a = DiffieHellman.generateA ()
        equals a.Length 256

    [<Test>]
    member _.``generateA returns different values each time``() =
        let a1 = DiffieHellman.generateA ()
        let a2 = DiffieHellman.generateA ()
        notEquals a1 a2

    [<Test>]
    member _.``DH key exchange produces same shared secret``() =
        // Use small prime for testing
        let p = BigInteger 23
        let g = 5
        // p as big-endian bytes
        let pBytes = [| 23uy |]

        let a = [| 6uy |]   // a = 6
        let b = [| 15uy |]  // b = 15

        // g^a mod p = 5^6 mod 23 = 8
        let gA = DiffieHellman.computeGA g a pBytes
        // g^b mod p = 5^15 mod 23 = 19
        let gB = DiffieHellman.computeGA g b pBytes

        // Shared secret: g_b^a mod p = 19^6 mod 23 = 2
        let secret1 = DiffieHellman.computeAuthKey gB a pBytes
        // Shared secret: g_a^b mod p = 8^15 mod 23 = 2
        let secret2 = DiffieHellman.computeAuthKey gA b pBytes

        // Both should compute the same shared secret
        let s1 = BigInteger(Array.append (Array.rev secret1) [| 0uy |])
        let s2 = BigInteger(Array.append (Array.rev secret2) [| 0uy |])
        equals s1 s2
