using System;
using System.Text;

public static class Compress
{
    /// <summary>
    /// Packs a stream of 7-bit payloads (one per input byte, with MSB=0 enforced) into a dense byte stream.
    /// Steps:
    /// 1) Validate MSB of every input byte is 0 (throws otherwise).
    /// 2) Take the lower 7 bits of each input byte and pack them LSB-first into a continuous bit stream.
    ///    (This means we accumulate 7-bit chunks and flush every 8 bits into output bytes.)
    /// 3) Optionally reverse the bit order of every output byte (useful to match external tooling/encodings).
    /// 4) Optionally append a number of trailing zero bytes.
    /// </summary>
    /// <param name="data">Input bytes; every byte must have MSB=0.</param>
    /// <param name="reverseOutputByteBits">
    /// If true, reverse the bit order of every produced output byte (e.g., 0b01000010 -> 0b01000010 reversed).
    /// </param>
    /// <param name="padTrailingZeroBytes">
    /// Number of 0x00 bytes to append at the very end (default 0). This matches some protocols/test vectors.
    /// </param>
    public static byte[] FromByteArray(byte[] data, bool reverseOutputByteBits = true, int padTrailingZeroBytes = 0)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));

        // 1) Validate MSB == 0 for all input bytes
        for (int i = 0; i < data.Length; i++)
        {
            if ((data[i] & 0x80) != 0)
                throw new ArgumentException($"Invalid byte at index {i}: MSB is set (0x{data[i]:X2}).");
        }

        // 2) Pack 7-bit payloads (LSB-first) into bytes
        var output = new System.Collections.Generic.List<byte>(data.Length * 7 / 8 + 2);
        int acc = 0;         // bit accumulator (LSB-first)
        int accBits = 0;     // number of bits currently in 'acc'

        foreach (var b in data)
        {
            acc |= (b & 0x7F) << accBits; // append 7 LSBs at current LSB position
            accBits += 7;

            while (accBits >= 8)
            {
                byte outByte = (byte)(acc & 0xFF);
                output.Add(outByte);
                acc >>= 8;
                accBits -= 8;
            }
        }

        // Flush remaining bits (if any) into one last byte, padded with zeros on the MSB side.
        if (accBits > 0)
        {
            byte outByte = (byte)(acc & 0xFF);
            output.Add(outByte);
            acc = 0;
            accBits = 0;
        }

        // 3) Optionally reverse bit order in each output byte (to match the expected test vector)
        if (reverseOutputByteBits)
        {
            for (int i = 0; i < output.Count; i++)
                output[i] = ReverseBits(output[i]);
        }

        // 4) Optional trailing zero padding
        for (int i = 0; i < padTrailingZeroBytes; i++)
            output.Add(0x00);

        return output.ToArray();
    }

    /// <summary>
    /// Hex-string front-end for FromByteArray. Accepts "0x" and spaces via HexConverter.
    /// </summary>
    public static byte[] FromHexString(string hex, bool reverseOutputByteBits = true, int padTrailingZeroBytes = 0)
    {
        if (hex == null) throw new ArgumentNullException(nameof(hex));
        var data = HexConverter.HexStringToByteArray(hex);
        return FromByteArray(data, reverseOutputByteBits, padTrailingZeroBytes);
    }

    /// <summary>
    /// Hex-string in, hex-string out (uppercase by default). Useful for test assertions.
    /// </summary>
    public static string FromHexStringToHex(string hex, bool uppercase = true, bool reverseOutputByteBits = true, int padTrailingZeroBytes = 0)
    {
        var bytes = FromHexString(hex, reverseOutputByteBits, padTrailingZeroBytes);
        return HexConverter.ByteArrayToHexString(bytes, uppercase, withPrefix: false);
    }

    /// <summary>
    /// Reverses bit order within one byte. Example: 0b0110_1000 -> 0b0001_0110.
    /// </summary>
    private static byte ReverseBits(byte b)
    {
        b = (byte)(((b & 0xF0) >> 4) | ((b & 0x0F) << 4));
        b = (byte)(((b & 0xCC) >> 2) | ((b & 0x33) << 2));
        b = (byte)(((b & 0xAA) >> 1) | ((b & 0x55) << 1));
        return b;
    }
}
