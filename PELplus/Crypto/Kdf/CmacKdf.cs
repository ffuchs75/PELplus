using System;

/// <summary>
/// CMAC-based Key Derivation Function (KDF) based on HKDF (RFC 5869),
/// but replacing HMAC with AES-CMAC as the PRF (Pseudorandom Function)
/// and using a custom two-step "extract" phase to produce a 256-bit PRK.
/// 
/// Output: exactly two 256-bit keys:
/// - EncryptionKey = T(1) || T(2)
/// - CmacKey       = T(3) || T(4)
/// 
/// RFC 5869 naming is used for the expand phase (T(1), T(2), …).
/// </summary>
public sealed class CmacKdf
{
    // ===== Final output keys =====

    /// <summary>Final 256-bit encryption key = T(1) || T(2)</summary>
    public byte[] EncryptionKey { get; }

    /// <summary>Final 256-bit CMAC key = T(3) || T(4)</summary>
    public byte[] CmacKey { get; }

    // ===== Debug / intermediate values =====

    /// <summary>
    /// Equivalent to "extract" PRF step 1:
    /// Cmac1a = PRF(IV, masterKey) — similar role to HMAC(salt, IKM) in HKDF,
    /// but using AES-CMAC and masterKey as message.
    /// </summary>
    public byte[] Cmac1a { get; }

    /// <summary>
    /// Equivalent to "extract" PRF step 2:
    /// Cmac1b = PRF(IV, Cmac1a || 0x00) — second CMAC to extend PRK to 256 bits.
    /// </summary>
    public byte[] Cmac1b { get; }

    /// <summary>
    /// Pseudorandom Key (PRK) for expand phase = Cmac1a || Cmac1b (32 bytes).
    /// </summary>
    public byte[] Prk { get; }

    /// <summary>T(1) = PRF(PRK, 0x01)</summary>
    public byte[] T1 { get; }

    /// <summary>T(2) = PRF(PRK, T(1) || 0x02)</summary>
    public byte[] T2 { get; }

    /// <summary>T(3) = PRF(PRK, T(2) || 0x03)</summary>
    public byte[] T3 { get; }

    /// <summary>T(4) = PRF(PRK, T(3) || 0x04)</summary>
    public byte[] T4 { get; }

    /// <summary>
    /// Derives two 256-bit keys from a 256-bit master key and optional 256-bit IV
    /// using a CMAC-based extract+expand structure.
    /// </summary>
    /// <param name="masterKey">
    /// 256-bit master key as byte[] or hex string.
    /// Used as "salt" in HKDF terminology, here called "RIC key".
    /// </param>
    /// <param name="iv">
    /// Optional 256-bit IV as byte[] or hex string.
    /// Used as "IKM" in HKDF terminology; if omitted, masterKey is used.
    /// </param>
    public CmacKdf(object masterKey, object iv = null)
    {
        // Normalize input formats
        byte[] keyBytes = NormalizeKeyOrIv(masterKey);
        byte[] ivBytes = iv != null ? NormalizeKeyOrIv(iv) : keyBytes;

        // -----------------------
        // EXTRACT PHASE (custom CMAC variant)
        // -----------------------

        // Step 1a: Cmac1a = PRF(masterKey, IV)
        Cmac1a = new AesCmac(keyBytes, ivBytes).Mac;

        // Step 1b: Cmac1b = PRF(masterKey, Cmac1a || 0x00)
        Cmac1b = new AesCmac(keyBytes, Concat(Cmac1a, new byte[] { 0x00 })).Mac;

        // PRK = Cmac1a || Cmac1b (32 bytes)
        Prk = Concat(Cmac1a, Cmac1b);

        // -----------------------
        // EXPAND PHASE (HKDF-Expand style)
        // -----------------------

        // T(1) = PRF(PRK, 0x01)
        T1 = new AesCmac(Prk, new byte[] { 0x01 }).Mac;

        // T(2) = PRF(PRK, T(1) || 0x02)
        T2 = new AesCmac(Prk, Concat(T1, new byte[] { 0x02 })).Mac;

        // T(3) = PRF(PRK, T(2) || 0x03)
        T3 = new AesCmac(Prk, Concat(T2, new byte[] { 0x03 })).Mac;

        // T(4) = PRF(PRK, T(3) || 0x04)
        T4 = new AesCmac(Prk, Concat(T3, new byte[] { 0x04 })).Mac;

        // -----------------------
        // FINAL KEYS
        // -----------------------

        EncryptionKey = Concat(T1, T2);
        CmacKey = Concat(T3, T4);
    }

    /// <summary>
    /// Validates that key/IV is exactly 256 bits and converts from hex string or byte[].
    /// </summary>
    private static byte[] NormalizeKeyOrIv(object input)
    {
        if (input is byte[] b)
        {
            if (b.Length != 32)
                throw new ArgumentException("Key/IV must be exactly 256 bits (32 bytes).");
            return (byte[])b.Clone();
        }
        else if (input is string s)
        {
            byte[] parsed = HexConverter.HexStringToByteArray(s);
            if (parsed.Length != 32)
                throw new ArgumentException("Key/IV must be exactly 256 bits (32 bytes).");
            return parsed;
        }
        else
        {
            throw new ArgumentException("Key/IV must be byte[] or hex string.");
        }
    }

    /// <summary>
    /// Concatenates two byte arrays.
    /// </summary>
    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }
}
