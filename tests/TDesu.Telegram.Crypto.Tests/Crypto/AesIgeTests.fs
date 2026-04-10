namespace TDesu.Crypto.Tests

open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

[<TestFixture>]
type AesIgeTests() =

    [<Test>]
    member _.``Encrypt then decrypt recovers original data``() =
        let key = Array.init 32 (fun i -> byte i)
        let iv = Array.init 32 (fun i -> byte (i + 32))
        let plaintext = Array.init 64 (fun i -> byte (i * 3))

        let encrypted = AesIge.encrypt plaintext key iv
        notEquals encrypted plaintext

        let decrypted = AesIge.decrypt encrypted key iv
        equals decrypted plaintext

    [<Test>]
    member _.``Encrypt single block``() =
        let key = Array.init 32 (fun _ -> 0xAAuy)
        let iv = Array.init 32 (fun _ -> 0xBBuy)
        let plaintext = Array.init 16 (fun i -> byte i)

        let encrypted = AesIge.encrypt plaintext key iv
        equals encrypted.Length 16

        let decrypted = AesIge.decrypt encrypted key iv
        equals decrypted plaintext

    [<Test>]
    member _.``Encrypt multiple blocks``() =
        let key = Array.init 32 (fun i -> byte (i * 7))
        let iv = Array.init 32 (fun i -> byte (i * 11))
        let plaintext = Array.init 128 (fun i -> byte (i % 256))

        let encrypted = AesIge.encrypt plaintext key iv
        equals encrypted.Length 128

        let decrypted = AesIge.decrypt encrypted key iv
        equals decrypted plaintext

    [<Test>]
    member _.``Different keys produce different ciphertext``() =
        let key1 = Array.init 32 (fun i -> byte i)
        let key2 = Array.init 32 (fun i -> byte (i + 1))
        let iv = Array.init 32 (fun _ -> 0uy)
        let plaintext = Array.init 16 (fun i -> byte i)

        let encrypted1 = AesIge.encrypt plaintext key1 iv
        let encrypted2 = AesIge.encrypt plaintext key2 iv
        notEquals encrypted1 encrypted2
