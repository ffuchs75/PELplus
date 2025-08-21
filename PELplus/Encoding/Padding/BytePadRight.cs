using System;
using System.Text;

/// <summary>
/// Immutable helper class to right-pad a hex string or byte array with 0x00 bytes
/// until the specified target length (in bytes) is reached.
/// </summary>
public sealed class BytePadRight
{
    /// <summary>
    /// The padded byte array (immutable copy).
    /// </summary>
    public byte[] PaddedBytes { get; }

    /// <summary>
    /// The padded value as lowercase hex string (no "0x" prefix).
    /// </summary>
    public string PaddedHex { get; }

    /// <summary>
    /// Constructor for byte array input.
    /// Pads the input array with 0x00 bytes on the right until the target length is reached.
    /// Throws if the input array is longer than the target length.
    /// </summary>
    /// <param name="input">Input byte array (immutable copy is made).</param>
    /// <param name="targetLength">Target length in bytes.</param>
    public BytePadRight(byte[] input, int targetLength)
    {
        if (input == null)
            throw new ArgumentNullException(nameof(input));
        if (targetLength < 0)
            throw new ArgumentOutOfRangeException(nameof(targetLength));

        if (input.Length > targetLength)
            throw new ArgumentException("Input is longer than target length.", nameof(input));

        // Create a new array with the requested target length
        // Copy the input array into the beginning of the padded array
        var padded = new byte[targetLength];
        Buffer.BlockCopy(input, 0, padded, 0, input.Length);

        // Store immutable copies
        PaddedBytes = padded;
        PaddedHex = ByteArrayToHexString(padded);
    }

    /// <summary>
    /// Constructor for hex string input.
    /// Pads the input hex string with 0x00 bytes on the right until the target length is reached.
    /// Throws if the decoded input is longer than the target length.
    /// </summary>
    /// <param name="hex">Hex string (may contain spaces, may start with "0x").</param>
    /// <param name="targetLength">Target length in bytes.</param>
    public BytePadRight(string hex, int targetLength)
        : this(HexStringToByteArray(NormalizeHex(hex)), targetLength)
    {
    }

    // ------------------- helpers -------------------

    /// <summary>
    /// Normalizes a hex string by:
    /// - Trimming spaces
    /// - Removing optional "0x" prefix
    /// - Padding with leading '0' if the length is odd
    /// </summary>
    private static string NormalizeHex(string hex)
    {
        if (hex == null)
            throw new ArgumentNullException(nameof(hex));

        string h = hex.Trim().Replace(" ", "");

        // Remove "0x" prefix if present
        if (h.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            h = h.Substring(2);

        // Ensure even length (two hex chars per byte)
        if (h.Length % 2 != 0)
            h = "0" + h;

        return h;
    }

    /// <summary>
    /// Converts a normalized hex string to a byte array.
    /// </summary>
    private static byte[] HexStringToByteArray(string hex)
    {
        int len = hex.Length;
        var data = new byte[len / 2];

        for (int i = 0; i < len; i += 2)
            data[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

        return data;
    }

    /// <summary>
    /// Converts a byte array to a lowercase hex string without "0x" prefix.
    /// </summary>
    private static string ByteArrayToHexString(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 2);
        foreach (var b in data)
            sb.Append(b.ToString("x2")); // lowercase hex
        return sb.ToString();
    }
}
