using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace PELplusTest
{
    [TestClass]
    public class EncryptionTests
    {
        private readonly string key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        private readonly DateTime dateTime = new DateTime(2025, 8, 7, 10, 30, 45, DateTimeKind.Utc);
        private readonly string expectedDateTime = "d5fa1f01";
        private readonly string expectedIV = "d5fa1f0101000000000000000000000000000000000000000000000000000000";
        private readonly string keyIndex = "01";
        private readonly string clearText = "Probealarm, Leitstelle nicht anrufen";
        private readonly string expectedClearTextBytes = "50726f6265616c61726d2c204c6569747374656c6c65206e6963687420616e727566656e";
        private readonly string expectedCompressClearTextBytes = "0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0";
        private readonly string expectedEncryptionKey = "eedeaba836d9eb1584d6e4e11765c20f3b7777579cbbf0c8df6c9202894b5633";
        private readonly string expectedCmacKey = "1a6220a89cffa76f327bda8e4cb4c9ec19013556e2753eb1f23f7744b603b0e5";
        private readonly string expectedCompressedPadded = "0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0000000";
        private readonly string expectedCipherBytes = "3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de";
        private readonly string expectedCounter0 = "d5fa1f01010000000000000000000000";
        private readonly string expectedCounter1 = "d5fa1f01010000000000000000000001";
        private readonly string expectedCounter2 = "d5fa1f01010000000000000000000002";
        private readonly string expectedKeyStream0 = "307d22c8181de78b1182a75112f3aed8";
        private readonly string expectedKeyStream1 = "c790166c13618592e181fdcbf1a7d192";
        private readonly string expectedKeyStream2 = "9c85deb5db7caa84d44bdd0517dd1799";
        private readonly string expectedCmac = "81256a9a2c8267023bf33a4d9dd7c13c";
        private readonly string expectedCrc = "e8";
        private readonly string expectedTransmission = "d5fa1f0101e881256a9a3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de";
        private readonly string expectedTransmissionNumeric = "U*[58[080871184*6595 574[1[461U04232]U*4126*[]626016*74 645U41[6093-98U84063*[692544931*U7";
        private readonly string expectedTransmissionBase64 = "1fofAQHogSVqmjri+PJo0CTEfVKEZfdkYIZeI2KtKPYJy5HRIGxfaUoinIXe";

        [TestMethod]
        public void TestParameters()
        {
            // test with string
            Encrypt encrypt = new Encrypt("Test message", key, "0x0a", DateTime.Now);
            Assert.AreEqual(key, encrypt.KeyHex.ToLower());
            Assert.AreEqual(key, HexConverter.ByteArrayToHexString(encrypt.Key).ToLower());
            Assert.AreEqual("0a", encrypt.KeyIndexHex.ToLower());
            Assert.AreEqual(10, encrypt.KeyIndex);

            // test with byte[] and bytge
            byte[] keyb = HexConverter.HexStringToByteArray(key);
            encrypt = new Encrypt("Test message", keyb, (byte)1, DateTime.Now);
            Assert.AreEqual(key, encrypt.KeyHex.ToLower());
            Assert.AreEqual(key, HexConverter.ByteArrayToHexString(encrypt.Key).ToLower());
            Assert.AreEqual("01", encrypt.KeyIndexHex);
            Assert.AreEqual((byte)1, encrypt.KeyIndex);

            // test with void hexstring            
            Assert.ThrowsException<ArgumentException>(() =>
            {
                encrypt = new Encrypt("Test message", "xyz", 10, DateTime.Now);
            });

            // test with void hexstring            
            Assert.ThrowsException<ArgumentException>(() =>
            {
                encrypt = new Encrypt("Test message", key, "xy", DateTime.Now);
            });

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                encrypt = new Encrypt("Test message", null, 10, DateTime.Now);
            });
            
        }

        [TestMethod]
        public void TestEncryption()
        {
            Encrypt encrypt = new Encrypt(clearText, key, keyIndex, dateTime);

            Assert.AreEqual(expectedDateTime, encrypt.Epoch2025Timestamp.BytesLittleEndianHex, "Timestamp Big Endian mismatch.");
            Assert.AreEqual(expectedIV, encrypt.IvPadded, "IV mismatch.");

            Assert.AreEqual(expectedEncryptionKey, encrypt.CmacKdf.EncryptionKeyHex.ToLower(), "Encryption Key mismatch.");
            Assert.AreEqual(expectedCmacKey, encrypt.CmacKdf.CmacKeyHex.ToLower(), "CmacKey mismatch.");

            Assert.AreEqual(expectedClearTextBytes, HexConverter.ByteArrayToHexString(encrypt.PlainTextBytes).ToLower(), "ClearTextBytes mismatch.");
            Assert.AreEqual(expectedCompressClearTextBytes, encrypt.CompressedPlainTextBytesHex.ToLower(), "CompressedClearTextByts mismatch,");
            Assert.AreEqual(expectedCompressedPadded, encrypt.CompressedPlainTextBytesPaddedHex.ToLower());

            Assert.AreEqual(expectedCipherBytes, encrypt.AesCtrEncrypt.CiphertextHex.ToLower());
            Assert.AreEqual(expectedCounter0, HexConverter.ByteArrayToHexString(encrypt.AesCtrEncrypt.Blocks[0].CounterBlock).ToLower());
            Assert.AreEqual(expectedCounter1, HexConverter.ByteArrayToHexString(encrypt.AesCtrEncrypt.Blocks[1].CounterBlock).ToLower());
            Assert.AreEqual(expectedCounter2, HexConverter.ByteArrayToHexString(encrypt.AesCtrEncrypt.Blocks[2].CounterBlock).ToLower());

            Assert.AreEqual(expectedKeyStream0, HexConverter.ByteArrayToHexString(encrypt.AesCtrEncrypt.Blocks[0].KeystreamBlock).ToLower());
            Assert.AreEqual(expectedKeyStream1, HexConverter.ByteArrayToHexString(encrypt.AesCtrEncrypt.Blocks[1].KeystreamBlock).ToLower());
            Assert.AreEqual(expectedKeyStream2, HexConverter.ByteArrayToHexString(encrypt.AesCtrEncrypt.Blocks[2].KeystreamBlock).ToLower());

            Assert.AreEqual(expectedCmac, HexConverter.ByteArrayToHexString(encrypt.AesCmac.Mac).ToLower());

            string crc = HexConverter.ByteToHex(Crc8.Compute(encrypt.IvHex));
            Assert.AreEqual(expectedCrc, crc);

            Assert.AreEqual(expectedTransmission, encrypt.TransmissionHex);
            Assert.AreEqual(expectedTransmissionNumeric, encrypt.TransmissionPocsagNumeric);
            Assert.AreEqual(expectedTransmissionBase64, encrypt.TransmissionBase64);
        }
    }
}
