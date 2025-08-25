using System;
using System.Text;
using System.Globalization;

public static class HexConverter
{
    /// <summary>
    /// Converts a hexadecimal string (e.g. "0A1B2C" or "0x0A 0x1B 0x2C") into a byte array.
    /// - Ignores spaces.
    /// - Accepts optional "0x" or "0X" prefixes before each byte.
    /// </summary>
    /// <param name="hex">Hex string to convert.</param>
    /// <returns>Byte array containing the parsed binary data.</returns>
    public static byte[] HexStringToByteArray(string hex)
    {
        if (hex == null)
            throw new ArgumentNullException(nameof(hex));

        hex = hex.Trim();

        // Case: Single global "0x" at the very start → strip it
        if ((hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && hex.IndexOf("0x", 2, StringComparison.OrdinalIgnoreCase) == -1))
        {
            hex = hex.Substring(2).Replace(" ", string.Empty);
        }
        // Case: Multiple "0x" prefixes → parse each byte separately
        else if (hex.Contains("0x") || hex.Contains("0X"))
        {
            string[] parts = hex.Split(new string[] { "0x", "0X" }, StringSplitOptions.RemoveEmptyEntries);
            byte[] result = new byte[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                string byteValue = parts[i].Length >= 2 ? parts[i].Substring(0, 2) : parts[i];
                result[i] = byte.Parse(byteValue, NumberStyles.HexNumber);
            }
            return result;
        }
        else
        {
            hex = hex.Replace(" ", string.Empty);
        }

        // Default: No per-byte prefix → normal parse
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Hex string must have an even number of characters.", nameof(hex));

        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            string byteValue = hex.Substring(i * 2, 2);
            bytes[i] = byte.Parse(byteValue, NumberStyles.HexNumber);
        }
        return bytes;
    }

    /// <summary>
    /// Converts a byte array to a hexadecimal string.
    /// </summary>
    /// <param name="bytes">Byte array to convert.</param>
    /// <param name="uppercase">Whether to return uppercase hex letters.</param>
    /// <param name="withPrefix">Whether to prefix each byte with "0x".</param>
    /// <returns>Hex string representation of the byte array.</returns>
    public static string ByteArrayToHexString(byte[] bytes, bool uppercase = true, bool withPrefix = false)
    {
        if (bytes == null)
            throw new ArgumentNullException(nameof(bytes));

        StringBuilder hex = new StringBuilder(bytes.Length * (withPrefix ? 4 : 2));

        foreach (byte b in bytes)
        {
            if (withPrefix)
            {
                hex.Append("0x");
                hex.Append(b.ToString(uppercase ? "X2" : "x2"));
            }
            else
            {
                hex.Append(b.ToString(uppercase ? "X2" : "x2"));
            }

            if (withPrefix)
                hex.Append(" "); // add space between prefixed bytes
        }

        return withPrefix ? hex.ToString().TrimEnd() : hex.ToString();
    }


    /// <summary>
    /// Converts a byte to a hexadecimal string.
    /// </summary>
    /// <param name="b">byte value (0–255).</param>
    /// <param name="uppercase">If true, output uses uppercase hex letters (A–F).</param>
    /// <returns>Two-character hex string (e.g., "A3" or "a3").</returns>
    public static string ByteToHex(byte b, bool uppercase = false)
    {
        return b.ToString(uppercase ? "X2" : "x2");
    }


    /// <summary>
    /// Converts a hexadecimal string into its byte value.
    /// Accepts "A3", "a3", "0x0A", "0Xa3", with or without whitespace.
    /// </summary>
    /// <param name="hex">Hex string representing one byte (e.g., "A3" or "0x0A").</param>
    /// <returns>Byte value (0–255).</returns>
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="hex"/> is null, empty,
    /// cannot be parsed as exactly one byte (00–FF),
    /// or contains invalid hex digits.
    /// </exception>
    public static byte HexToByte(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
            throw new ArgumentException("Input cannot be null or empty.", nameof(hex));

        // Trim whitespace
        string normalized = hex.Trim();

        // Allow optional "0x"/"0X" prefix
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            normalized = normalized.Substring(2);

        // Now it must be exactly 2 hex chars
        if (normalized.Length != 2)
            throw new ArgumentException("Hex string must represent exactly one byte (2 hex digits).", nameof(hex));

        try
        {
            return Convert.ToByte(normalized, 16);
        }
        catch (FormatException)
        {
            throw new ArgumentException("Input contains non-hexadecimal characters.", nameof(hex));
        }
        catch (OverflowException)
        {
            throw new ArgumentException("Input is out of range for a byte.", nameof(hex));
        }
    }

}
