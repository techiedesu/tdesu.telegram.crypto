namespace TDesu.Crypto.Tests

open System.Security.Cryptography
open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

[<TestFixture>]
module RsaTests =

    [<Test>]
    let ``publicKeys list is non-empty`` () =
        Assert.That(Rsa.publicKeys.Length, Is.GreaterThan(0))

    [<Test>]
    let ``production key has correct fingerprint`` () =
        let key = Rsa.publicKeys |> List.head
        equals key.Fingerprint -3414540481677951611L

    [<Test>]
    let ``production key exponent is 65537`` () =
        let key = Rsa.publicKeys |> List.head
        equals key.Exponent [| 0x01uy; 0x00uy; 0x01uy |]

    [<Test>]
    let ``allKeys includes production keys`` () =
        let all = Rsa.allKeys ()
        Assert.That(all.Length, Is.GreaterThanOrEqualTo(Rsa.publicKeys.Length))

    [<Test>]
    let ``addKey and clearAdditionalKeys`` () =
        let testKey: Rsa.RsaPublicKey = {
            Fingerprint = 123456L
            Modulus = Array.zeroCreate 256
            Exponent = [| 0x01uy; 0x00uy; 0x01uy |]
        }
        try
            Rsa.addKey testKey
            let all = Rsa.allKeys ()
            Assert.That(all |> List.exists (fun k -> k.Fingerprint = 123456L), Is.True)
        finally
            Rsa.clearAdditionalKeys ()

        let afterClear = Rsa.allKeys ()
        Assert.That(afterClear |> List.exists (fun k -> k.Fingerprint = 123456L), Is.False)

    [<Test>]
    let ``encrypt produces output of modulus length`` () =
        let key = Rsa.publicKeys |> List.head
        let data = Array.zeroCreate 256
        RandomNumberGenerator.Fill(System.Span(data))
        // Ensure data < modulus by zeroing first byte
        data[0] <- 0uy
        let encrypted = Rsa.encrypt data key
        equals encrypted.Length key.Modulus.Length

    [<Test>]
    let ``encrypt with different data produces different output`` () =
        let key = Rsa.publicKeys |> List.head
        let data1 = Array.zeroCreate<byte> 256
        let data2 = Array.zeroCreate<byte> 256
        data1[0] <- 0uy; data1[1] <- 1uy
        data2[0] <- 0uy; data2[1] <- 2uy
        let enc1 = Rsa.encrypt data1 key
        let enc2 = Rsa.encrypt data2 key
        notEquals enc1 enc2

    [<Test>]
    let ``hexToBytes round-trip`` () =
        let hex = "DEADBEEF"
        let bytes = Rsa.hexToBytes hex
        equals bytes [| 0xDEuy; 0xADuy; 0xBEuy; 0xEFuy |]

    [<Test>]
    let ``hexToBytes with spaces`` () =
        let bytes = Rsa.hexToBytes "DE AD BE EF"
        equals bytes [| 0xDEuy; 0xADuy; 0xBEuy; 0xEFuy |]
