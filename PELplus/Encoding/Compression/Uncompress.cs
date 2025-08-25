using System;
using System.Text;

public static class Uncompress
{
    /// <summary>
    /// Unpacks a dense byte stream (produced by Compress.FromByteArray) back into
    /// a stream of 7-bit payload bytes (each output byte has MSB=0).
    ///
    /// Steps:
    /// 1) Optionally reverse bit order of every input byte (must mirror the packing step).
    /// 2) Read bits LSB-first from the input stream and emit 7-bit chunks as bytes.
    /// 3) Any leftover bits (<7) at the very end must be zero (padding); they are discarded.
    /// 4) Optionally strip trailing 0x00 bytes from the decoded output (if removeTrailingZeros=true).
    /// </summary>
    /// <param name="packed">Input bytes (packed form).</param>
    /// <param name="reverseInputByteBits">
    /// If true, reverse the bit order of each input byte before unpacking.
    /// This must match the 'reverseOutputByteBits' that was used during packing.
    /// </param>
    /// <param name="removeTrailingZeros">
    /// If true, remove all trailing 0x00 bytes from the final output.
    /// </param>
    public static byte[] FromByteArray(byte[] packed, bool reverseInputByteBits = true, bool removeTrailingZeros = false)
    {
        if (packed == null) throw new ArgumentNullException(nameof(packed));

        // 1) Prepare working copy and (optionally) reverse bit order per byte
        var work = new byte[packed.Length];
        if (reverseInputByteBits)
        {
            for (int i = 0; i < packed.Length; i++)
                work[i] = ReverseBits(packed[i]);
        }
        else
        {
            Buffer.BlockCopy(packed, 0, work, 0, packed.Length);
        }

        // 2) Unpack: consume input bytes as LSB-first into an accumulator,
        //    and emit 7-bit chunks (lowest 7 bits each time).
        var output = new System.Collections.Generic.List<byte>(work.Length * 8 / 7 + 2);

        int acc = 0;      // bit accumulator (LSB-first)
        int accBits = 0;  // number of valid bits currently in 'acc'

        for (int i = 0; i < work.Length; i++)
        {
            acc |= (work[i] & 0xFF) << accBits; // append next 8 bits at current LSB position
            accBits += 8;

            while (accBits >= 7)
            {
                byte seven = (byte)(acc & 0x7F); // take lowest 7 bits
                output.Add(seven);
                acc >>= 7;
                accBits -= 7;
            }
        }

        // 3) Leftover bits (<7) should be padding zeros only; discard but sanity-check.
        if (accBits > 0)
        {
            int mask = (1 << accBits) - 1;
            int leftover = acc & mask;
            if (leftover != 0)
                throw new ArgumentException("Non-zero padding bits detected at the end of the packed stream.");
        }

        // 4) Optionally strip trailing 0x00 bytes from the decoded output
        if (removeTrailingZeros && output.Count > 0)
        {
            int newLen = output.Count;
            while (newLen > 0 && output[newLen - 1] == 0x00)
                newLen--;

            if (newLen < output.Count)
                output.RemoveRange(newLen, output.Count - newLen);
        }

        return output.ToArray();
    }

    /// <summary>
    /// Hex-string front-end for FromByteArray.
    /// </summary>
    public static byte[] FromHexString(string hex, bool reverseInputByteBits = true, bool removeTrailingZeros = false)
    {
        if (hex == null) throw new ArgumentNullException(nameof(hex));
        var data = HexConverter.HexStringToByteArray(hex);
        return FromByteArray(data, reverseInputByteBits, removeTrailingZeros);
    }

    /// <summary>
    /// Hex-string in, hex-string out (uppercase by default). Useful for test assertions.
    /// The output hex represents the unpacked 7-bit bytes (each in one full byte 0x00..0x7F).
    /// </summary>
    public static string FromHexStringToHex(string hex, bool uppercase = true, bool reverseInputByteBits = true, bool removeTrailingZeros = false)
    {
        var bytes = FromHexString(hex, reverseInputByteBits, removeTrailingZeros);
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
