namespace TDesu.Crypto.Tests

open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

[<TestFixture>]
type AuthKeyIdTests() =

    [<Test>]
    member _.``sha1 returns 20 bytes``() =
        let hash = AuthKeyId.sha1 [| 1uy; 2uy; 3uy |]
        equals hash.Length 20

    [<Test>]
    member _.``sha256 returns 32 bytes``() =
        let hash = AuthKeyId.sha256 [| 1uy; 2uy; 3uy |]
        equals hash.Length 32

    [<Test>]
    member _.``sha1 is deterministic``() =
        let data = [| 10uy; 20uy; 30uy |]
        let h1 = AuthKeyId.sha1 data
        let h2 = AuthKeyId.sha1 data
        equals h1 h2

    [<Test>]
    member _.``sha256 is deterministic``() =
        let data = [| 10uy; 20uy; 30uy |]
        let h1 = AuthKeyId.sha256 data
        let h2 = AuthKeyId.sha256 data
        equals h1 h2

    [<Test>]
    member _.``compute returns int64 from SHA1 bytes 12-19``() =
        let authKey = Array.init 256 (fun i -> byte i)
        let id = AuthKeyId.compute authKey
        // Verify by manual computation
        let sha1Hash = AuthKeyId.sha1 authKey
        let expected = System.BitConverter.ToInt64(sha1Hash, 12)
        equals id expected

    [<Test>]
    member _.``different auth keys produce different ids``() =
        let key1 = Array.init 256 (fun i -> byte i)
        let key2 = Array.init 256 (fun i -> byte (i + 1))
        let id1 = AuthKeyId.compute key1
        let id2 = AuthKeyId.compute key2
        notEquals id1 id2
