using PELplus;
using System;
using System.Text;
using System.Text.RegularExpressions;


/// <summary>
/// Supported external encoding of a transmitted frame.
/// </summary>
public enum TransmissionEncoding
{
    Base64,
    PocsagNumeric,
    Unencrypted
}

/// <summary>
/// Immutable representation of a PELplus transmission frame.
///
/// Input: a single string which is either
///   - Base64 of the full frame bytes, or
///   - POCSAG Numeric text encoding the full frame
///
/// Frame layout (bytes):
///   [ 0..4 ]  : IV_unpadded (5 bytes) = TimestampLE(4) || KeyIndex(1)
///   [ 5 ]     : CRC-8 over IV_unpadded (1 byte)
///   [ 6..9 ]  : CMAC truncated tag (first 4 bytes of 128-bit CMAC)
///   [ 10.. ]  : Ciphertext (remaining bytes)
///
/// This class ONLY parses and exposes fields. It does NOT verify CRC or CMAC.
/// </summary>
public sealed class Transmission
{
    // -------- Backing fields (kept private and readonly for immutability) --------
    private readonly TransmissionEncoding _encodingType;
    private readonly byte[] _rawFrame;
    private readonly byte[] _ivUnpadded;   // 5 bytes
    private readonly byte[] _ivPadded;
    private readonly byte[] _timestamp;   // 4 bytes
    private readonly byte _keyIndex;     // last byte of IV
    private readonly byte _transmittedCrc8;         // 1 byte
    private readonly byte[] _macTruncated; // 4 bytes
    private readonly byte[] _ciphertext;   // n bytes (>= 0)
    private readonly byte _actualCrc8;

    // -------- Public read-only properties --------

    /// <summary>Detected external encoding (Base64 or PocsagNumeric).</summary>
    public TransmissionEncoding EncodingType => _encodingType;

    /// <summary>Raw frame bytes after decoding the external format (defensive copy on get).</summary>
    public byte[] RawFrame => Copy(_rawFrame);

    /// <summary>5-byte IV_unpadded (TimestampLE(4) || KeyIndex(1)). Defensive copy on get.</summary>
    public byte[] IvUnpadded => Copy(_ivUnpadded);

    /// padded IV
    public byte[] IvPadded => Copy(_ivPadded);

    /// <summary>(TimestampLE(4) </summary>
    public byte[] Timestamp => Copy(_timestamp);

    /// <summary>1-byte Key Index (== IvUnpadded[4]).</summary>
    public byte KeyIndex => _keyIndex;

    /// <summary>1-byte CRC-8 over IV_unpadded (as transmitted).</summary>
    public byte TransmittedCrc8 => _transmittedCrc8;

    /// <summary>1-byte CRC-8 over IV_unpadded (as newly calculated).</summary>
    public byte ActualCrc8 => _actualCrc8;

    /// <summary>transmitted 4-byte truncated CMAC tag. .</summary>
    public byte[] MacTruncated => Copy(_macTruncated);

    /// <summary>Ciphertext bytes (remaining payload).</summary>
    public byte[] Ciphertext => Copy(_ciphertext);

    /// <summary>
    /// transmission datetime in UTC
    /// </summary>
    public DateTime TimestampUtc
    {
        get
        {
            Epoch2025Timestamp epoch2025Timestamp = new Epoch2025Timestamp(_timestamp);
            return epoch2025Timestamp.UtcTime;
        }
    }

    /// <summary>
    /// transmission datetime in local time
    /// </summary>
    public DateTime TimestampLocal
    {
        get
        {
            return TimestampUtc.ToLocalTime();
        }
    }

    /// <summary>
    /// return true if the transmitted Crc8 matches the actualk Crc8
    /// </summary>
    public bool HasValidCrc8
    {
        get
        {
            if (ActualCrc8Hex == TransmittedCrc8Hex)
                return true;
            else
                return false;
        }
    }

    // -------- Convenience lowercase-hex views --------
    public string IvUnpaddedHex => HexConverter.ByteArrayToHexString(_ivUnpadded).ToLowerInvariant();
    public string IvPaddedHex => HexConverter.ByteArrayToHexString(_ivPadded).ToLowerInvariant();
    public string TimestampHex => HexConverter.ByteArrayToHexString(_timestamp).ToLowerInvariant();
    public string KeyIndexHex => HexConverter.ByteToHex(_keyIndex).ToLowerInvariant();
    public string TransmittedCrc8Hex => HexConverter.ByteToHex(_transmittedCrc8).ToLowerInvariant();
    public string MacTruncHex => HexConverter.ByteArrayToHexString(_macTruncated).ToLowerInvariant();
    public string CiphertextHex => HexConverter.ByteArrayToHexString(_ciphertext).ToLowerInvariant();
    public string RawFrameHex => HexConverter.ByteArrayToHexString(_rawFrame).ToLowerInvariant();
    public string ActualCrc8Hex => HexConverter.ByteToHex(_actualCrc8).ToLowerInvariant();


    // =========================================================================
    // Constructor (only one): accepts a single string input and auto-detects encoding
    // =========================================================================
    /// <summary>
    /// Construct from a single input string. The constructor auto-detects whether
    /// the string is Base64 or POCSAG Numeric and parses the frame accordingly.
    /// </summary>
    /// <param name="input">Base64 OR POCSAG Numeric string of the full frame.</param>
    /// <exception cref="ArgumentException">If decoding fails or the frame is structurally invalid.</exception>
    public Transmission(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new ArgumentException("Input must not be empty.");

        string s = input.Trim();

        byte[] frameBytes;
        TransmissionEncoding encType;

        var dec = new PocsagNumericDecoder(s);

        // 1) Try Base64: accept only on strict round-trip to reduce false positives.
        if (LooksLikeBase64(s, out byte[] b64))
        {
            frameBytes = b64;
            encType = TransmissionEncoding.Base64;
        }
        // 2) treat as POCSAG Numeric 
        else if (dec.IsValid)
        {
            string hex = dec.OriginalHex;

            frameBytes = HexConverter.HexStringToByteArray(hex);
            encType = TransmissionEncoding.PocsagNumeric;
        }
        // 3) treat as unencrypted
        else
        {
            _encodingType = TransmissionEncoding.Unencrypted;
            return;
        }

        // 4) Frame too short. Need at least 10 bytes (5 IV + 1 CRC + 4 MAC).
        if (frameBytes.Length < 10)
        {
            _encodingType = TransmissionEncoding.Unencrypted;
            return;
        }

        // Slice fixed header:
        // [0..4]  IV (5B)
        // [5]     CRC (1B)
        // [6..9]  MAC trunc (4B)
        // [10..]  Ciphertext
        var iv = new byte[5];
        Buffer.BlockCopy(frameBytes, 0, iv, 0, 5);

        byte crc = frameBytes[5];

        var mac = new byte[Parameters.CmacSize];
        Buffer.BlockCopy(frameBytes, 6, mac, 0, Parameters.CmacSize);

        int cipherLen = Math.Max(0, frameBytes.Length - 6 - Parameters.CmacSize);
        var ct = new byte[cipherLen];
        if (cipherLen > 0)
            Buffer.BlockCopy(frameBytes, 6 + Parameters.CmacSize, ct, 0, cipherLen);

        var timestamp = new byte[4];
        Buffer.BlockCopy(frameBytes, 0, timestamp, 0, 4);

        // Assign backing fields (defensive copies to ensure immutability)
        _encodingType = encType;
        _rawFrame = Copy(frameBytes);
        _ivUnpadded = Copy(iv);
        _keyIndex = iv[4];
        _transmittedCrc8 = crc;
        _macTruncated = Copy(mac);
        _ciphertext = Copy(ct);
        _timestamp = Copy(timestamp);
        _actualCrc8 = Crc8.Compute(_ivUnpadded);

        BytePadRight bytePadRight = new BytePadRight(iv, Parameters.IVPaddedSize);
        _ivPadded = bytePadRight.PaddedBytes;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// <summary>
    /// Heuristic/strict test: try to decode as Base64 and accept only if re-encoding
    /// matches (allowing benign trailing '=' differences).
    /// </summary>
    private static bool LooksLikeBase64(string s, out byte[] decoded)
    {
        decoded = null;

        // Quick character-set sanity check first
        if (!Regex.IsMatch(s, @"^[A-Za-z0-9\+/=]+$"))
            return false;

        try
        {
            var bytes = Convert.FromBase64String(s);
            string re = Convert.ToBase64String(bytes);

            if (string.Equals(re, s, StringComparison.Ordinal))
            {
                decoded = bytes;
                return true;
            }

            // Accept if only trailing '=' padding differs
            string sNoPad = s.TrimEnd('=');
            string reNoPad = re.TrimEnd('=');
            if (string.Equals(reNoPad, sNoPad, StringComparison.Ordinal))
            {
                decoded = bytes;
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] Copy(byte[] src)
    {
        if (src == null) return null;
        var dst = new byte[src.Length];
        Buffer.BlockCopy(src, 0, dst, 0, src.Length);
        return dst;
    }
}

