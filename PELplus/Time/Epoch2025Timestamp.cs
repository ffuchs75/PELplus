using System;

/// <summary>
/// Immutable class for converting between a UTC timestamp in seconds since a fixed epoch (2025-01-01 00:00:00 UTC)
/// and different representations (DateTime UTC, DateTime local, LE/BE byte arrays, hex strings).
/// </summary>
public sealed class Epoch2025Timestamp
{
    /// <summary>
    /// Fixed, hard-coded epoch start (UTC): 2025-01-01 00:00:00
    /// </summary>
    public static readonly DateTime EpochStartUtc = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>UTC DateTime representation</summary>
    public DateTime UtcTime { get; }

    /// <summary>Local DateTime representation</summary>
    public DateTime LocalTime => UtcTime.ToLocalTime();

    /// <summary>Seconds since EpochStartUtc</summary>
    public uint SecondsSinceEpoch { get; }

    /// <summary>4-byte little-endian representation</summary>
    public byte[] BytesLittleEndian { get; }

    /// <summary>4-byte big-endian representation</summary>
    public byte[] BytesBigEndian { get; }

    /// <summary>Little-endian hex string</summary>
    public string BytesLittleEndianHex => HexConverter.ByteArrayToHexString(BytesLittleEndian, uppercase: false);

    /// <summary>Big-endian hex string</summary>
    public string BytesBigEndianHex => HexConverter.ByteArrayToHexString(BytesBigEndian, uppercase: false);

    // --- Constructors ---

    /// <summary>
    /// Construct from a UTC DateTime.
    /// </summary>
    public Epoch2025Timestamp(DateTime utcTime)
    {
        if (utcTime.Kind == DateTimeKind.Local)
            utcTime = utcTime.ToUniversalTime();

        if (utcTime < EpochStartUtc)
            throw new ArgumentOutOfRangeException(nameof(utcTime), "Time must be on or after epoch start.");

        UtcTime = utcTime;
        SecondsSinceEpoch = (uint)(UtcTime - EpochStartUtc).TotalSeconds;
        BytesLittleEndian = BitConverter.GetBytes(SecondsSinceEpoch);
        BytesBigEndian = GetBigEndian(SecondsSinceEpoch);
    }

    /// <summary>
    /// Construct from a 4-byte array.
    /// </summary>
    public Epoch2025Timestamp(byte[] secondsBytes, bool isLittleEndian = true)
    {
        if (secondsBytes == null || secondsBytes.Length != 4)
            throw new ArgumentException("Byte array must be exactly 4 bytes.");

        SecondsSinceEpoch = isLittleEndian
            ? BitConverter.ToUInt32(secondsBytes, 0)
            : FromBigEndian(secondsBytes);

        UtcTime = EpochStartUtc.AddSeconds(SecondsSinceEpoch);
        BytesLittleEndian = BitConverter.GetBytes(SecondsSinceEpoch);
        BytesBigEndian = GetBigEndian(SecondsSinceEpoch);
    }

    /// <summary>
    /// Construct from a hex string.
    /// </summary>
    public Epoch2025Timestamp(string hexString, bool isLittleEndian = true)
        : this(HexConverter.HexStringToByteArray(hexString), isLittleEndian)
    {
    }

    // --- Helpers ---
    private static byte[] GetBigEndian(uint value)
    {
        byte[] bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        return bytes;
    }

    private static uint FromBigEndian(byte[] bytes)
    {
        byte[] temp = (byte[])bytes.Clone();
        if (BitConverter.IsLittleEndian)
            Array.Reverse(temp);
        return BitConverter.ToUInt32(temp, 0);
    }
}
