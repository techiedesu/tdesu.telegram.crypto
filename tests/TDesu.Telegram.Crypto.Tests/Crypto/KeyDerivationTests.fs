namespace TDesu.Crypto.Tests

open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

[<TestFixture>]
type KeyDerivationTests() =

    [<Test>]
    member _.``computeMsgKey returns 16 bytes``() =
        let authKey = Array.init 256 (fun i -> byte i)
        let plaintext = Array.init 64 (fun i -> byte (i * 2))
        let msgKey = KeyDerivation.computeMsgKey authKey plaintext 0
        equals msgKey.Length 16

    [<Test>]
    member _.``deriveAesKeyIv returns correct sizes``() =
        let authKey = Array.init 256 (fun i -> byte i)
        let msgKey = Array.init 16 (fun i -> byte i)
        let result = KeyDerivation.deriveAesKeyIv authKey msgKey 0
        equals result.Key.Length 32
        equals result.Iv.Length 32

    [<Test>]
    member _.``Client and server derive different keys``() =
        let authKey = Array.init 256 (fun i -> byte i)
        let msgKey = Array.init 16 (fun i -> byte i)
        let clientKeys = KeyDerivation.deriveAesKeyIv authKey msgKey 0
        let serverKeys = KeyDerivation.deriveAesKeyIv authKey msgKey 8
        notEquals clientKeys.Key serverKeys.Key
        notEquals clientKeys.Iv serverKeys.Iv

    [<Test>]
    member _.``Same inputs produce same output``() =
        let authKey = Array.init 256 (fun i -> byte i)
        let plaintext = Array.init 64 (fun i -> byte (i * 2))
        let msgKey1 = KeyDerivation.computeMsgKey authKey plaintext 0
        let msgKey2 = KeyDerivation.computeMsgKey authKey plaintext 0
        equals msgKey1 msgKey2
