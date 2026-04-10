namespace TDesu.Crypto.Tests

open NUnit.Framework
open TDesu.Crypto

[<TestFixture>]
type DhValidationTests() =

    [<Test>]
    member _.``validateDhParams rejects small p``() =
        let smallP = [| 23uy |]
        Assert.That(DiffieHellman.validateDhParams 2 smallP, Is.False)

    [<Test>]
    member _.``validateDhParams rejects even p``() =
        let evenP = Array.zeroCreate<byte> 256
        evenP[255] <- 4uy  // even number
        Assert.That(DiffieHellman.validateDhParams 2 evenP, Is.False)

    [<Test>]
    member _.``validateDhParams rejects g less than 2``() =
        // Use a valid-looking p but invalid g
        let p = Array.init 256 (fun _ -> 0xFFuy)
        Assert.That(DiffieHellman.validateDhParams 1 p, Is.False)
        Assert.That(DiffieHellman.validateDhParams 0 p, Is.False)

    [<Test>]
    member _.``validateDhParams rejects p equal to 1``() =
        let p = Array.zeroCreate<byte> 256
        p[255] <- 1uy
        Assert.That(DiffieHellman.validateDhParams 2 p, Is.False)
