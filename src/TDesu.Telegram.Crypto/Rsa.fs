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

    /// Telegram production RSA public keys (current fingerprints advertised by prod DCs).
    /// Encryption uses the classic scheme (sha1(data)+data+padding then raw RSA); these
    /// moduli are the canonical 256-byte values — verified by recomputing each fingerprint.
    let publicKeys: RsaPublicKey list =
        [
            {
                // 0x0bc35f3509f7b7a5
                Fingerprint = 0x0bc35f3509f7b7a5L
                Modulus =
                    hexToBytes
                        "AEEC36C8FFC109CB099624685B97815415657BD76D8C9C3E398103D7AD16C9BBA6F525ED0412D7AE2C2DE2B44E77D72CBF4B7438709A4E646A05C43427C7F184DEBF72947519680E651500890C6832796DD11F772C25FF8F576755AFE055B0A3752C696EB7D8DA0D8BE1FAF38C9BDD97CE0A77D3916230C4032167100EDD0F9E7A3A9B602D04367B689536AF0D64B613CCBA7962939D3B57682BEB6DAE5B608130B2E52ACA78BA023CF6CE806B1DC49C72CF928A7199D22E3D7AC84E47BC9427D0236945D10DBD15177BAB413FBF0EDFDA09F014C7A7DA088DDE9759702CA760AF2B8E4E97CC055C617BD74C3D97008635B98DC4D621B4891DA9FB0473047927"
                Exponent = [| 0x01uy; 0x00uy; 0x01uy |] // 65537
            }
            {
                // 0xc3b42b026ce86b21
                Fingerprint = 0xc3b42b026ce86b21L
                Modulus =
                    hexToBytes
                        "C150023E2F70DB7985DED064759CFECF0AF328E69A41DAF4D6F01B538135A6F91F8F8B2A0EC9BA9720CE352EFCF6C5680FFC424BD634864902DE0B4BD6D49F4E580230E3AE97D95C8B19442B3C0A10D8F5633FECEDD6926A7F6DAB0DDB7D457F9EA81B8465FCD6FFFEED114011DF91C059CAEDAF97625F6C96ECC74725556934EF781D866B34F011FCE4D835A090196E9A5F0E4449AF7EB697DDB9076494CA5F81104A305B6DD27665722C46B60E5DF680FB16B210607EF217652E60236C255F6A28315F4083A96791D7214BF64C1DF4FD0DB1944FB26A2A57031B32EEE64AD15A8BA68885CDE74A5BFC920F6ABF59BA5C75506373E7130F9042DA922179251F"
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
