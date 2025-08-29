using PELplus;
using System;
using System.Security.Cryptography;

/// <summary>
/// Immutable AES-CMAC computation class (RFC 4493).
/// Accepts both byte arrays and hexadecimal strings for key and message.
/// Produces a 16-byte CMAC output.
/// </summary>
public sealed class AesCmac
{
    /// <summary>
    /// The final 16-byte CMAC value computed from the provided key and message.
    /// </summary>
    public byte[] Mac { get; }

    /// <summary>
    /// The final 16-byte CMAC value computed from the provided key and message.
    /// </summary>
    public string MacHex => HexConverter.ByteArrayToHexString(Mac);

    /// <summary>
    /// shortend machex
    /// </summary>
    public byte[] MacTruncated => HexConverter.HexStringToByteArray(MacTruncatedHex);

    /// <summary>
    /// shortend machex
    /// </summary>
    public string MacTruncatedHex
    {
        get
        {
            return MacHex.Substring(0, Parameters.CmacSize * 2);
        }
    }

    /// <summary>
    /// Creates a new AES-CMAC computation object and immediately computes the CMAC.
    /// </summary>
    /// <param name="key">
    /// AES key (128-bit, 192-bit, or 256-bit) as either a byte[] or hex string.
    /// If a hex string is provided, spaces and "0x" prefixes are ignored.
    /// </param>
    /// <param name="message">
    /// Input message as either a byte[] or hex string.
    /// If a hex string is provided, spaces and "0x" prefixes are ignored.
    /// </param>
    public AesCmac(object key, object message)
    {
        // Convert key and message to byte arrays from either hex string or byte[]
        byte[] keyBytes = NormalizeInput(key);
        byte[] msgBytes = NormalizeInput(message);

        // AES-CMAC only works with AES-128, AES-192, or AES-256 keys
        if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
            throw new ArgumentException("AES key must be 128, 192, or 256 bits.");

        // Perform CMAC calculation
        Mac = ComputeCmac(keyBytes, msgBytes);
    }

    /// <summary>
    /// Computes AES-CMAC for a given AES key and message.
    /// </summary>
    /// <param name="key">AES key bytes (length must be 16, 24, or 32).</param>
    /// <param name="message">Message bytes.</param>
    /// <returns>16-byte CMAC value.</returns>
    private static byte[] ComputeCmac(byte[] key, byte[] message)
    {
        using (var aes = new AesManaged())
        {
            aes.KeySize = key.Length * 8; // 128/192/256 bits
            aes.BlockSize = 128;          // AES block size is always 128 bits
            aes.Mode = CipherMode.CBC;    // CMAC uses AES in CBC mode internally
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = new byte[16];        // Zero IV as per CMAC specification

            return ComputeCmacInternal(aes, message);
        }
    }

    /// <summary>
    /// Internal CMAC computation according to RFC 4493.
    /// Steps:
    /// 1. Generate subkeys K1 and K2 from AES encryption of 0x00 block.
    /// 2. Split the message into 16-byte blocks.
    /// 3. If the last block is complete (exactly 16 bytes), XOR it with K1; otherwise, pad with 0x80 and zeros, then XOR with K2.
    /// 4. Process all blocks in CBC mode, with the last block XOR'ed as above before the final AES encryption.
    /// </summary>
    private static byte[] ComputeCmacInternal(SymmetricAlgorithm aes, byte[] message)
    {
        // Step 1: Encrypt a zero block to get L
        byte[] L = EncryptBlock(aes, new byte[16]);

        // Step 2: Generate K1 and K2 subkeys from L
        byte[] K1 = GenerateSubkey(L);
        byte[] K2 = GenerateSubkey(K1);

        // Step 3: Determine the number of blocks (n) and whether the last block is complete
        int n = (message.Length + 15) / 16; // ceil(message length / 16)
        bool lastBlockComplete = (message.Length % 16) == 0 && n > 0;

        // Special case: if message length is zero, we still have one padded block
        if (n == 0)
        {
            n = 1;
            lastBlockComplete = false;
        }

        // Step 4: Prepare the last block
        byte[] lastBlock = new byte[16];
        if (lastBlockComplete)
        {
            // Last block is exactly 16 bytes: XOR with K1
            Array.Copy(message, (n - 1) * 16, lastBlock, 0, 16);
            XorBlock(lastBlock, K1);
        }
        else
        {
            // Last block is incomplete: copy remaining bytes, append 0x80, pad with zeros, then XOR with K2
            int lastLen = message.Length % 16;
            Array.Copy(message, (n - 1) * 16, lastBlock, 0, lastLen);
            lastBlock[lastLen] = 0x80;
            XorBlock(lastBlock, K2);
        }

        // Step 5: CBC processing of all blocks except the last one
        byte[] X = new byte[16]; // initial CBC state = zero
        byte[] Y = new byte[16];
        for (int i = 0; i < n - 1; i++)
        {
            Array.Copy(message, i * 16, Y, 0, 16);
            XorBlock(Y, X);
            X = EncryptBlock(aes, Y);
        }

        // Step 6: Process the last block
        XorBlock(lastBlock, X);
        return EncryptBlock(aes, lastBlock);
    }

    /// <summary>
    /// Encrypts a single 16-byte block with the given AES settings.
    /// </summary>
    private static byte[] EncryptBlock(SymmetricAlgorithm aes, byte[] block)
    {
        using (var encryptor = aes.CreateEncryptor())
        {
            return encryptor.TransformFinalBlock(block, 0, block.Length);
        }
    }

    /// <summary>
    /// Generates a CMAC subkey from a given block.
    /// This performs a left shift by 1 bit, and conditionally XORs with 0x87 if the MSB was 1.
    /// </summary>
    private static byte[] GenerateSubkey(byte[] L)
    {
        byte[] ret = new byte[16];
        bool msb = (L[0] & 0x80) != 0;
        for (int i = 0; i < 15; i++)
            ret[i] = (byte)((L[i] << 1) | (L[i + 1] >> 7));
        ret[15] = (byte)(L[15] << 1);
        if (msb) ret[15] ^= 0x87;
        return ret;
    }

    /// <summary>
    /// XORs two 16-byte blocks in-place (dst = dst XOR src).
    /// </summary>
    private static void XorBlock(byte[] dst, byte[] src)
    {
        for (int i = 0; i < 16; i++)
            dst[i] ^= src[i];
    }

    /// <summary>
    /// Normalizes an input to a byte array.
    /// Accepts either a byte[] (returned as a clone) or a hex string (parsed).
    /// </summary>
    private static byte[] NormalizeInput(object input)
    {
        if (input is byte[] bytes)
        {
            return (byte[])bytes.Clone();
        }
        else if (input is string hex)
        {
            return HexConverter.HexStringToByteArray(hex);
        }
        else
        {
            throw new ArgumentException("Input must be byte[] or hex string.");
        }
    }


}
