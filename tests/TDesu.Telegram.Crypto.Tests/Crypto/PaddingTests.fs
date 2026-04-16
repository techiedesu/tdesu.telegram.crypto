namespace TDesu.Crypto.Tests

open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

[<TestFixture>]
type PaddingTests() =

    [<Test>]
    member _.``randomBytes returns correct length``() =
        let bytes = Padding.randomBytes 32
        equals bytes.Length 32

    [<Test>]
    member _.``randomBytes returns different values``() =
        let a = Padding.randomBytes 32
        let b = Padding.randomBytes 32
        // Extremely unlikely to be equal
        notEquals a b

    [<Test>]
    member _.``addPadding result length is divisible by 16``() =
        for dataLen in [ 1; 10; 16; 32; 48; 100; 255; 500 ] do
            let data = Array.zeroCreate<byte> dataLen
            let padded = Padding.addPadding data
            equals (padded.Length % 16) 0

    [<Test>]
    member _.``addPadding adds at least 12 bytes``() =
        for dataLen in [ 0; 1; 16; 32; 100 ] do
            let data = Array.zeroCreate<byte> dataLen
            let padded = Padding.addPadding data
            let paddingLen = padded.Length - dataLen
            Assert.That(paddingLen, Is.GreaterThanOrEqualTo(12), $"Failed for data length %d{dataLen}")

    [<Test>]
    member _.``addPadding preserves original data``() =
        let data = Array.init 50 (fun i -> byte i)
        let padded = Padding.addPadding data
        equals padded[..49] data

    [<Test>]
    member _.``addHandshakePadding result length is divisible by 16``() =
        for dataLen in [ 0; 1; 10; 16; 17; 31; 32; 48; 100; 255; 500 ] do
            let data = Array.zeroCreate<byte> dataLen
            let padded = Padding.addHandshakePadding data
            equals (padded.Length % 16) 0

    [<Test>]
    member _.``addHandshakePadding adds 0 to 15 bytes``() =
        for dataLen in [ 0; 1; 15; 16; 17; 31; 32; 100 ] do
            let data = Array.zeroCreate<byte> dataLen
            let padded = Padding.addHandshakePadding data
            let paddingLen = padded.Length - dataLen
            Assert.That(paddingLen, Is.GreaterThanOrEqualTo(0), $"Failed for data length %d{dataLen}")
            Assert.That(paddingLen, Is.LessThanOrEqualTo(15), $"Failed for data length %d{dataLen}")

    [<Test>]
    member _.``addHandshakePadding zero bytes when already aligned``() =
        for dataLen in [ 0; 16; 32; 48; 256 ] do
            let data = Array.zeroCreate<byte> dataLen
            let padded = Padding.addHandshakePadding data
            equals padded.Length dataLen

    [<Test>]
    member _.``addHandshakePadding preserves original data``() =
        let data = Array.init 50 (fun i -> byte i)
        let padded = Padding.addHandshakePadding data
        equals padded[..49] data
