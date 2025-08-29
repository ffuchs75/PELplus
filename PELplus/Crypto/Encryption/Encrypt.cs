using PELplus;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Immutable end-to-end encryption orchestrator that reproduces the exact pipeline
/// from your CompleteEncryptionExample test:
/// 
/// 1) Build IV base from custom epoch timestamp (LE) + key index
/// 2) Right-pad IV to 32 bytes (for KDF input)
/// 3) Derive EncryptionKey and CmacKey via CMAC-KDF
/// 4) UTF-8 encode cleartext, then Compress.FromByteArray(...)
/// 5) Right-pad compressed data to full 5-byte groups
/// 6) AES-CTR encrypt with (EncryptionKey, IV [unpadded], padded payload)
/// 7) Compute AES-CMAC over ciphertext
/// 8) Compute CRC8 over IV (unpadded)
/// 9) Build transmission = IV || CRC || first 8 hex chars of CMAC || CIPHERTEXT
/// 10) Provide POCSAG numeric and Base64 encodings of the transmission
/// 
/// All intermediate values that are asserted in your test are exposed as properties,
/// using HexConverter for all hex/byte conversions.
/// </summary>
public sealed class Encrypt
{
    private readonly byte[] _key;
    private readonly string _keyHex;
    private readonly byte _keyIndex;
    private readonly string _keyIndexHex;
    private readonly Epoch2025Timestamp _epoch2025Timestamp;
    private readonly string _ivHex;
    private readonly string _ivPaddedHex;
    private readonly CmacKdf _cmacKdf;
    private readonly string _plainText;
    private readonly byte[] _plainTextBytes;
    private readonly byte[] _compressedPlainTextBytes;
    private readonly byte[] _compressedPlainTextBytesPadded;
    private readonly AesCtrEncrypt _aesCtrEncrypt;
    private readonly AesCmac _aesCmac;
    private readonly byte _crc;
    private readonly string _transmissionHex;
    private readonly string _transmissionPocsagNumeric;
    private readonly string _transmissionBase64;

    /// <summary>
    /// encryption key
    /// </summary>
    public byte[] Key => (byte[])_key.Clone();
   
    /// <summary>
    /// encryption key
    /// </summary>
    public string KeyHex => _keyHex;

    /// <summary>
    /// key index
    /// </summary>
    public byte KeyIndex => _keyIndex;

    /// <summary>
    /// key index
    /// </summary>
    public string KeyIndexHex => _keyIndexHex;


    /// <summary>
    /// timestamp in UTC
    /// </summary>
    public Epoch2025Timestamp Epoch2025Timestamp => _epoch2025Timestamp;


    /// <summary>
    /// initialization vector
    /// </summary>
    public string IvHex => _ivHex;
        
    /// <summary>
    /// initialization vector padded
    /// </summary>
    public string IvPadded => _ivPaddedHex;

    /// <summary>
    /// derived keys
    /// </summary>
    public CmacKdf CmacKdf => _cmacKdf;

    /// <summary>
    /// message as plain text
    /// </summary>
    public string PlainText => _plainText;

    /// <summary>
    /// plain text bytes
    /// </summary>
    public byte[] PlainTextBytes => _plainTextBytes;

    /// <summary>
    /// plain text bytes
    /// </summary>
    public string PlainTextBytesHex => HexConverter.ByteArrayToHexString(PlainTextBytes);

    /// <summary>
    /// compressed plain text bytes
    /// </summary>
    public byte[] CompressedPlainTextBytes => _compressedPlainTextBytes;

    /// <summary>
    /// compressed plain text bytes
    /// </summary>
    public string CompressedPlainTextBytesHex => HexConverter.ByteArrayToHexString(CompressedPlainTextBytes);

    /// <summary>
    /// compressewd plain text bytes padded with as many ‘0’ bits as necessary so that the total number of bits is a multiple of 40 bits (5 bytes)
    /// </summary>
    public byte[] CompressedPlainTextBytesPadded => _compressedPlainTextBytesPadded;

    /// <summary>
    /// compressewd plain text bytes padded with as many ‘0’ bits as necessary so that the total number of bits is a multiple of 40 bits (5 bytes)
    /// </summary>
    public string CompressedPlainTextBytesPaddedHex => HexConverter.ByteArrayToHexString(CompressedPlainTextBytesPadded);

    /// <summary>
    /// encryption
    /// </summary>
    public AesCtrEncrypt AesCtrEncrypt => _aesCtrEncrypt;

    /// <summary>
    /// Cmac of the ciphertext
    /// </summary>
    public AesCmac AesCmac => _aesCmac;

    /// <summary>
    /// CRC-8 checksum over the IV
    /// </summary>
    public byte Crc => _crc;

    /// <summary>
    /// CRC-8 checksum over the IV
    /// </summary>
    public string CrcHex => HexConverter.ByteToHex(Crc);

    /// <summary>
    /// IV || CRC || CMAC || ciphertext as hex
    /// </summary>
    public string TransmissionHex => _transmissionHex;

    /// <summary>
    /// transmission in Pocsag Numeric Encoding
    /// </summary>
    public string TransmissionPocsagNumeric => _transmissionPocsagNumeric;

    /// <summary>
    /// transmission in Base64 Encoding
    /// </summary>
    public string TransmissionBase64 => _transmissionBase64;


    /// <summary>
    /// encrypt a message
    /// </summary>
    /// <param name="message">message text</param>
    /// <param name="key">string (hex) or byte[]</param>
    /// <param name="keyIndex">byte or string (hex)</param>
    /// <param name="timestampUtc">timestamp in UTC</param>
    public Encrypt(
        string message,
        object key,            
        object keyIndex,        
        DateTime timestampUtc   
    )
    {
        if (key == null)
            throw new ArgumentNullException($"{nameof(key)} must not be null.", nameof(key));

        if (String.IsNullOrEmpty(message))
        {
            throw new ArgumentException($"{nameof(message)} must not be null or empty.", nameof(message));
        }

        if (key is byte[] keyb)
        {
            _key = (byte[])keyb.Clone();
            _keyHex = HexConverter.ByteArrayToHexString(_key).ToLower();
        }
        else if (key is string keys)
        {
            _key = HexConverter.HexStringToByteArray(keys);
            _keyHex = HexConverter.ByteArrayToHexString(_key).ToLower();
        }
        else
        {
            throw new ArgumentException($"{nameof(key)} must be a byte[] or hex string.", nameof(key));
        }

        if (keyIndex is byte keyIndexb)
        {
            _keyIndex = (byte)keyIndex;
            _keyIndexHex = HexConverter.ByteToHex(_keyIndex).ToLower();
        }
        else if (keyIndex is string keyIndexs)
        {
            _keyIndex = HexConverter.HexToByte(keyIndexs);
            _keyIndexHex = HexConverter.ByteToHex(_keyIndex).ToLower();
        }
        else
        {
            throw new ArgumentException($"{nameof(keyIndex)} must be a byte or hex string.", nameof(keyIndex));
        }

        _plainText = message;

        // calculate time for IV
        _epoch2025Timestamp = new Epoch2025Timestamp(timestampUtc);

        // calculate IV
        _ivHex = _epoch2025Timestamp.BytesLittleEndianHex + _keyIndexHex;
        BytePadRight bytePadRight = new BytePadRight(_ivHex, Parameters.IVPaddedSize);
        _ivPaddedHex = bytePadRight.PaddedHex;

        // derive keys
        _cmacKdf = new CmacKdf(key, _ivPaddedHex);

        // compress cleartext and pad
        _plainTextBytes= Encoding.UTF8.GetBytes(message);
        _compressedPlainTextBytes = Compress.FromByteArray(_plainTextBytes);  

        BytePadRight compressedPadded = new BytePadRight(_compressedPlainTextBytes, 
            (int)Math.Ceiling((double)_compressedPlainTextBytes.Length / Parameters.POCSAGBlockSize) * Parameters.POCSAGBlockSize);
        _compressedPlainTextBytesPadded = (byte[])compressedPadded.PaddedBytes.Clone();

        // encryption
        _aesCtrEncrypt = new AesCtrEncrypt(_cmacKdf.EncryptionKey, _ivHex, _compressedPlainTextBytesPadded);

        // CMAC
        _aesCmac = new AesCmac(_cmacKdf.CmacKey, _aesCtrEncrypt.Ciphertext);

        // CRC
        _crc = Crc8.Compute(_ivHex);

        // transmission
        _transmissionHex = String.Format("{0}{1}{2}{3}", _ivHex, CrcHex, HexConverter.ByteArrayToHexString(_aesCmac.Mac).ToLower().Substring(0, Parameters.CmacSize * 2), _aesCtrEncrypt.CiphertextHex);

        // POCSAG numeric encoding
        PocsagNumericEncoder pocsagNumericEncoder = new PocsagNumericEncoder(_transmissionHex);
        _transmissionPocsagNumeric = pocsagNumericEncoder.NumericText;
        _transmissionBase64 = Convert.ToBase64String(HexConverter.HexStringToByteArray(_transmissionHex));
    }
}