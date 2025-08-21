using System;
using System.Collections.Generic;

/// <summary>
/// Immutable POCSAG "Numeric" encoder/decoder helper that performs:
/// 1) Nibble-wise bit reversal (reverse bit order inside each 4-bit nibble).
/// 2) Mapping each (already reversed) nibble 0..F to a "Numeric" text character:
///    0..9 -> '0'..'9'
///    A -> '*'
///    B -> 'U'
///    C -> ' ' (space)
///    D -> '-'
///    E -> ']'
///    F -> '['
///
/// Input can be provided as a byte[] or a hex string (supports "0x" and spaces via HexConverter).
/// The transformation happens once in the constructor; results are exposed via read-only properties.
///
/// Additionally, use <see cref="MapHexCharsOneToOne(string)"/> to map a hex-like string
/// (sequence of [0-9A-Fa-f], any length, no byte parsing) directly 1:1 to the numeric
/// character set — one output character per input character.
/// </summary>
public sealed class PocsagNumericEncoder
{
    // ---------- Lookup table for nibble bit reversal (4-bit) ----------
    // Index = original nibble (0..15), value = reversed nibble.
    private static readonly byte[] Rev4 =
    {
        0x0, 0x8, 0x4, 0xC, 0x2, 0xA, 0x6, 0xE,
        0x1, 0x9, 0x5, 0xD, 0x3, 0xB, 0x7, 0xF
    };


    // Dictionary for POCSAG Numeric Char
    private static readonly Dictionary<char, char> NumericMapChar = new Dictionary<char, char>
    {
        { '0','0' }, { '1','1' }, { '2','2' }, { '3','3' },
        { '4','4' }, { '5','5' }, { '6','6' }, { '7','7' },
        { '8','8' }, { '9','9' }, { 'A','*' }, { 'B','U' },
        { 'C',' ' }, { 'D','-' }, { 'E',']' }, { 'F','[' }
    };


    // ---------- Backing fields (immutable state) ----------
    private readonly byte[] _inputBytes;   // original input bytes (normalized)
    private readonly byte[] _numericBytes; // bytes after nibble bit reversal
    private readonly string _numericHex;   // uppercase hex (no spaces) of _numericBytes
    private readonly string _numericText;  // numeric chars

    // ---------- Public read-only properties (defensive copies where applicable) ----------

    /// <summary>Original input bytes (defensive copy).</summary>
    public byte[] InputBytes
    {
        get
        {
            var c = new byte[_inputBytes.Length];
            Buffer.BlockCopy(_inputBytes, 0, c, 0, _inputBytes.Length);
            return c;
        }
    }

    /// <summary>Transformed bytes (after nibble-wise bit reversal). Defensive copy is returned.</summary>
    public byte[] NumericBytes
    {
        get
        {
            var c = new byte[_numericBytes.Length];
            Buffer.BlockCopy(_numericBytes, 0, c, 0, _numericBytes.Length);
            return c;
        }
    }

    /// <summary>Transformed bytes as uppercase hex string (no spaces, no "0x").</summary>
    public string NumericHex => _numericHex;

    /// <summary>
    /// POCSAG "Numeric" text output:
    /// - One character per nibble according to <see cref="NumericMapChar"/>.
    /// </summary>
    public string NumericText => _numericText;

    /// <summary>
    /// Construct and compute the numeric transformation and text mapping.
    /// Accepts either a byte[] or a hex string.
    /// </summary>
    /// <param name="input">byte[] or hex string (supports "0x" and spaces via HexConverter).</param>
    public PocsagNumericEncoder(object input)
    {
        // 1) Normalize input to bytes (defensive copy)
        _inputBytes = NormalizeInputToBytes(input);

        // 2) Nibble-wise bit reversal per byte, then recombine
        _numericBytes = new byte[_inputBytes.Length];
        for (int i = 0; i < _inputBytes.Length; i++)
        {
            byte b = _inputBytes[i];
            byte lo = (byte)(b & 0x0F);        // extract low nibble
            byte hi = (byte)((b >> 4) & 0x0F); // extract high nibble

            byte loRev = Rev4[lo];             // reverse low nibble
            byte hiRev = Rev4[hi];             // reverse high nibble

            _numericBytes[i] = (byte)((hiRev << 4) | loRev); // combine reversed nibbles
        }

        // 3) Uppercase hex view of reversed bytes (no spaces/prefix)
        _numericHex = HexConverter.ByteArrayToHexString(_numericBytes, uppercase: true, withPrefix: false);

        // 4) Text mapping: one character per nibble (two per byte)
        _numericText = TranslateUsingMap(NumericHex);
    }

    // ---------- Helper ----------

    /// <summary>
    /// Accepts byte[] or hex string; for hex, uses HexConverter (supports "0x" and spaces).
    /// Returns a defensive copy of the byte[].
    /// </summary>
    private static byte[] NormalizeInputToBytes(object input)
    {
        if (input is byte[] b)
        {
            var copy = new byte[b.Length];
            Buffer.BlockCopy(b, 0, copy, 0, b.Length);
            return copy;
        }

        if (input is string s)
        {
            return HexConverter.HexStringToByteArray(s);
        }

        throw new ArgumentException("Input must be a byte[] or a hex string.", nameof(input));
    }

    /// <summary>
    /// Translates each character in <paramref name="input"/> according to <paramref name="NumericMapChar"/>.
    /// Throws an exception if a character is not found in the dictionary.
    /// </summary>
    private static string TranslateUsingMap(string input)
    {
        if (input == null)
            throw new ArgumentNullException(nameof(input));

        var result = new char[input.Length];

        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];

            if (!NumericMapChar.TryGetValue(c, out char mapped))
            {
                throw new ArgumentException(
                    $"Character '{c}' at position {i} is not valid for translation.",
                    nameof(input));
            }

            result[i] = mapped;
        }

        return new string(result);
    }



}
