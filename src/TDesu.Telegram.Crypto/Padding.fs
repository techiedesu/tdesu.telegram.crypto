namespace TDesu.Crypto

open System.Security.Cryptography

[<RequireQualifiedAccess>]
module Padding =

    /// Generate random bytes
    let randomBytes (count: int) : byte[] =
        let bytes = Array.zeroCreate<byte> count
        RandomNumberGenerator.Fill(bytes)
        bytes

    /// Add random padding (12-1024 bytes, result length divisible by 16)
    let addPadding (data: byte[]) : byte[] =
        let minPadding = 12
        let dataLen = data.Length

        // Minimum total length with 12 bytes padding
        let minTotal = dataLen + minPadding

        // Round up to next multiple of 16
        let totalLen =
            let rem = minTotal % 16
            if rem = 0 then minTotal
            else minTotal + (16 - rem)

        let paddingLen = totalLen - dataLen

        // Ensure padding is within bounds (12..1024)
        let paddingLen =
            if paddingLen > 1024 then
                // Should not happen with reasonable data, but clamp
                let target = dataLen + 1024
                let rem = target % 16
                if rem = 0 then 1024
                else 1024 - rem
            else
                paddingLen

        let result = Array.zeroCreate<byte> (dataLen + paddingLen)
        System.Buffer.BlockCopy(data, 0, result, 0, dataLen)
        let padding = randomBytes paddingLen
        System.Buffer.BlockCopy(padding, 0, result, dataLen, paddingLen)
        result
