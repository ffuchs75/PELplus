using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PELplus.Crypto.Encryption
{
    public sealed class Decrypt
    {
        private readonly byte[] _key;
        private readonly Transmission _transmission;
        private readonly CmacKdf _cmacKdf;
        private readonly AesCtrEncrypt _aesCtrDecrypt;
        private readonly byte[] _plainTextBytes;
        private readonly string _plainText;
        private readonly AesCmac _aesCmac;
        private readonly bool _hasValidCmac;

        /// <summary>
        /// transmission
        /// </summary>
        public Transmission Transmission => _transmission;

        /// <summary>
        /// derived keys
        /// </summary>
        public CmacKdf CmacKdf => _cmacKdf;

        /// <summary>
        /// Decrypt
        /// </summary>
        public AesCtrEncrypt AesCtrDecrypt => _aesCtrDecrypt;

        /// <summary>
        /// plain text bytes
        /// </summary>
        public byte[] PlainTextBytes => _plainTextBytes;

        /// <summary>
        /// plain text bytes
        /// </summary>
        public string PlainTextBytesHex => HexConverter.ByteArrayToHexString(PlainTextBytes);

        /// <summary>
        /// plain text
        /// </summary>
        public string PlainText => _plainText;

        /// <summary>
        /// CMAC of cipher text
        /// </summary>
        public AesCmac AesCmac => _aesCmac;

        /// <summary>
        /// true if the Cmac is valid
        /// </summary>
        public bool HasValidCmac => _hasValidCmac;



        /// <summary>
        /// decrypt a message
        /// </summary>
        /// <param name="transmission">plaintext, BASE64 oder POCSAG Numeric</param>
        /// <param name="key">string (hex) or byte[]</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public Decrypt(
            string transmission,
            object key
        )
        {
            if (String.IsNullOrEmpty(transmission))
                throw new ArgumentException($"{nameof(transmission)} must not be null or empty.", nameof(transmission));

            if (key == null)
                throw new ArgumentNullException($"{nameof(key)} must not be null.", nameof(key));


            _transmission = new Transmission(transmission);

            // if the message is unencrypted, return
            if (_transmission.EncodingType == TransmissionEncoding.Unencrypted)
            {
                return;
            }

            // check if the crc is valid
            if (_transmission.HasValidCrc8 == false)
            {
                Console.WriteLine("\nSince the CRC8 is void, treat the message as unencrypted.");
                return;
            }

            // derive keys

            _cmacKdf = new CmacKdf(key, _transmission.IvPadded);

            // decrypt the message
            _aesCtrDecrypt = new AesCtrEncrypt(_cmacKdf.EncryptionKey, _transmission.IvUnpaddedHex, _transmission.CiphertextHex);

            // uncompress the message
            _plainTextBytes = Uncompress.FromHexString(_aesCtrDecrypt.CiphertextHex, true, true);

            // get the plain text
            _plainText = Encoding.UTF8.GetString(_plainTextBytes);

            // calculate the CMAC
            _aesCmac = new AesCmac(_cmacKdf.CmacKeyHex, _transmission.CiphertextHex);

            // Compute once, reuse (avoids duplicate conversions and substring twice)
            string macFullLower = HexConverter.ByteArrayToHexString(_aesCmac.Mac).ToLower();
            string macTruncLower = macFullLower.Substring(0, 8);

            _hasValidCmac = macTruncLower == _transmission.MacTruncHex;
        }

    }
}
