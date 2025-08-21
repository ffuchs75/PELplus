using System;

/// <summary>
/// CRC-8 calculator for polynomial x^8 + x^2 + x + 1 (0x07).
/// - Initial value: 0x00
/// - No reflection of input or output bits
/// - No final XOR
/// This matches the simple CRC-8 variant often described as "CRC-8-ATM" without refin/refout.
/// 
/// This implementation is intended for generic 8-bit checksum calculations over arbitrary data.
/// </summary>
public static class Crc8
{
    /// <summary>
    /// Generator polynomial for CRC-8: x^8 + x^2 + x + 1
    /// In hexadecimal representation: 0x07.
    /// </summary>
    private const byte Poly = 0x07;

    /// <summary>
    /// Initial value of the CRC register before processing any data bytes.
    /// </summary>
    private const byte Init = 0x00;

    /// <summary>
    /// Compute the CRC-8 value for a given byte array.
    /// </summary>
    /// <param name="data">Input data as byte array.</param>
    /// <returns>Calculated CRC-8 value (0–255).</returns>
    /// <exception cref="ArgumentNullException">Thrown if data is null.</exception>
    public static byte Compute(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        byte crc = Init;

        // Process each byte in the input data
        for (int i = 0; i < data.Length; i++)
        {
            // Step 1: XOR current data byte into the CRC register
            crc ^= data[i];

            // Step 2: Process each bit (MSB first)
            for (int bit = 0; bit < 8; bit++)
            {
                bool msbSet = (crc & 0x80) != 0;
                crc <<= 1; // Shift left by one bit
                if (msbSet)
                {
                    // If MSB was set before shift, apply polynomial
                    crc ^= Poly;
                }
            }
        }
        return crc;
    }

    /// <summary>
    /// Compute the CRC-8 value for a hexadecimal string.
    /// - Accepts optional "0x" prefixes.
    /// - Ignores spaces.
    /// </summary>
    /// <param name="hex">Hexadecimal string (e.g., "0A1B2C" or "0x0A 0x1B 0x2C").</param>
    /// <returns>Calculated CRC-8 value (0–255).</returns>
    /// <exception cref="ArgumentNullException">Thrown if hex is null.</exception>
    public static byte Compute(string hex)
    {
        if (hex == null)
            throw new ArgumentNullException(nameof(hex));

        // Convert hex string to byte array using existing helper
        byte[] bytes = HexConverter.HexStringToByteArray(hex);
        return Compute(bytes);
    }


}
