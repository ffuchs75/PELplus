using System;
using System.Collections.Generic;

/// <summary>
/// Immutable POCSAG "Numeric" DECODER (minimal outputs).
///
/// Input: POCSAG "Numeric" text string (characters from: '0'..'9', '*', 'U', ' ', '-', ']', '[')
/// Each character encodes one nibble. Two nibbles form one byte.
///
/// Behavior:
/// - If <paramref name="numericText"/> is null -> throws <see cref="ArgumentNullException"/>.
/// - If any character is invalid OR the total length is odd -> <see cref="IsValid"/> = false,
///   and <see cref="OriginalBytes"/> / <see cref="OriginalHex"/> are empty.
/// - If valid -> <see cref="IsValid"/> = true and the original bytes/hex (before nibble-reversal)
///   are provided via <see cref="OriginalBytes"/> / <see cref="OriginalHex"/>.
///
/// Notes:
/// - This decoder performs the inverse of the encoder internally (map numeric chars → hex nibbles,
///   parse to bytes, undo per-nibble bit reversal) but exposes ONLY the reconstructed original bytes/hex.
/// - No NumericHex/NumericBytes properties are kept, as requested.
/// </summary>
public sealed class PocsagNumericDecoder
{
    // 4-bit bit-reversal lookup (same as encoder). Bit reversal on 4 bits is self-inverse.
    private static readonly byte[] Rev4 = new byte[16]
    {
        0x0, 0x8, 0x4, 0xC, 0x2, 0xA, 0x6, 0xE,
        0x1, 0x9, 0x5, 0xD, 0x3, 0xB, 0x7, 0xF
    };

    // Inverse mapping from Numeric character -> hex nibble char (inverse of the encoder's map).
    private static readonly Dictionary<char, char> InverseNumericMapChar = new Dictionary<char, char>
    {
        { '0','0' }, { '1','1' }, { '2','2' }, { '3','3' },
        { '4','4' }, { '5','5' }, { '6','6' }, { '7','7' },
        { '8','8' }, { '9','9' }, { '*','A' }, { 'U','B' },
        { ' ','C' }, { '-','D' }, { ']','E' }, { '[','F' }
    };

    // Backing fields (immutable state)
    private readonly string _numericText;     // always echoed back
    private readonly byte[] _originalBytes;   // empty if invalid
    private readonly string _originalHex;     // empty if invalid

    /// <summary>
    /// The numeric text provided as input (echoed back, regardless of validity).
    /// </summary>
    public string NumericText => _numericText;

    /// <summary>
    /// Uppercase hex (no spaces) of <see cref="OriginalBytes"/>. Empty if <see cref="IsValid"/> is false.
    /// </summary>
    public string OriginalHex => _originalHex;

    /// <summary>
    /// Original bytes (before nibble-wise bit reversal). Empty if <see cref="IsValid"/> is false.
    /// A defensive copy is returned.
    /// </summary>
    public byte[] OriginalBytes
    {
        get
        {
            var c = new byte[_originalBytes.Length];
            Buffer.BlockCopy(_originalBytes, 0, c, 0, _originalBytes.Length);
            return c;
        }
    }

    /// <summary>
    /// True for valid input (all chars supported AND even length), otherwise false.
    /// When false, <see cref="OriginalBytes"/> and <see cref="OriginalHex"/> are empty.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Construct the decoder from a numeric text string.
    /// </summary>
    /// <param name="numericText">POCSAG "Numeric" text (one char per nibble).</param>
    public PocsagNumericDecoder(string numericText)
    {
        if (numericText == null)
            throw new ArgumentNullException(nameof(numericText));

        _numericText = numericText;
        _originalBytes = Array.Empty<byte>();
        _originalHex = string.Empty;
        IsValid = false;

        // ---- Step 1: Map numeric chars to hex nibble chars into a TEMP buffer ----
        var hexChars = new char[numericText.Length];
        for (int i = 0; i < numericText.Length; i++)
        {
            char c = numericText[i];
            char mapped;
            if (!InverseNumericMapChar.TryGetValue(c, out mapped))
            {
                // invalid char -> leave outputs empty
                return;
            }
            hexChars[i] = mapped; // already uppercase hex char
        }

        // ---- Step 2: Check even length (two nibbles per byte) ----
        if ((hexChars.Length & 1) != 0)
        {
            // odd number of nibbles -> cannot form bytes
            return;
        }

        // ---- Step 3: Parse hex to bytes (TEMP) ----
        byte[] tempNumericBytes;
        try
        {
            tempNumericBytes = HexConverter.HexStringToByteArray(new string(hexChars));
        }
        catch
        {
            // malformed hex (shouldn't happen because we map strictly), still fail-safe
            return;
        }

        // ---- Step 4: Undo nibble-wise bit reversal into TEMP ----
        var tempOriginalBytes = new byte[tempNumericBytes.Length];
        for (int i = 0; i < tempNumericBytes.Length; i++)
        {
            byte b = tempNumericBytes[i];
            byte lo = (byte)(b & 0x0F);
            byte hi = (byte)((b >> 4) & 0x0F);

            byte loUnrev = Rev4[lo];
            byte hiUnrev = Rev4[hi];

            tempOriginalBytes[i] = (byte)((hiUnrev << 4) | loUnrev);
        }
        string tempOriginalHex = HexConverter.ByteArrayToHexString(tempOriginalBytes, uppercase: true, withPrefix: false);

        // ---- Step 5: Commit outputs and mark valid ----
        _originalBytes = tempOriginalBytes;
        _originalHex = tempOriginalHex;
        IsValid = true;
    }
}
