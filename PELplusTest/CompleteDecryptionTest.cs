using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace PELplusTest
{
    [TestClass]
    public class CompleteDecryptionTest
    {
        private readonly string key = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        private readonly string numerik = "U*[58[080871184*6595 574[1[461U04232]U*4126*[]626016*74 645U41[6093-98U84063*[692544931*U7";

        private readonly string expectedIV = "d5fa1f0101";
        private readonly string expectedTimestamp = "d5fa1f01";
        private readonly string expectedKeyIndex = "01";
        private readonly string expectedTransmittedCrc = "e8";
        private readonly string expectedActualCrc = "e8";
        private readonly string expectedCmac = "81256a9a";
        private readonly string expectedCipher = "3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de";
        private readonly string expectedRawframe = "d5fa1f0101e881256a9a3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de";
        private readonly DateTime expectedDateTime = new DateTime(2025, 8, 7, 10, 30, 45, DateTimeKind.Utc);
        private readonly DateTime expectedDateTimeLocal = new DateTime(2025, 8, 7, 12, 30, 45, DateTimeKind.Local);
        private readonly string expectedEncryptionKey = "eedeaba836d9eb1584d6e4e11765c20f3b7777579cbbf0c8df6c9202894b5633";
        private readonly string expectedCmacKey = "1a6220a89cffa76f327bda8e4cb4c9ec19013556e2753eb1f23f7744b603b0e5";
        private readonly string expectedCompressedPadded = "0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0000000";
        private readonly string expectedPlaintextHex = "50726f6265616c61726d2c204c6569747374656c6c65206e6963687420616e727566656e";
        private readonly string expectedPlainText = "Probealarm, Leitstelle nicht anrufen";


        [TestMethod]
        public void TestDecryption()
        {
            // evaluate transmission
            Transmission transmission = new Transmission(numerik);
            Assert.AreEqual(expectedIV, transmission.IvUnpaddedHex);
            Assert.AreEqual(expectedKeyIndex, transmission.KeyIndexHex);
            Assert.AreEqual(expectedTransmittedCrc, transmission.TransmittedCrc8Hex);
            Assert.AreEqual(expectedCmac, transmission.MacTruncHex);
            Assert.AreEqual(expectedCipher, transmission.CiphertextHex);
            Assert.AreEqual(expectedRawframe, transmission.RawFrameHex);
            Assert.AreEqual(expectedTimestamp, transmission.TimestampHex);
            Assert.AreEqual(expectedDateTime, transmission.TimestampUtc);
            Assert.AreEqual(expectedDateTimeLocal, transmission.TimestampLocal);
            Assert.AreEqual(expectedActualCrc, transmission.ActualCrc8Hex);
            Assert.AreEqual(true, transmission.HasValidCrc8);
            Assert.AreEqual(TransmissionEncoding.PocsagNumeric, transmission.EncodingType);

            // derive keys
            BytePadRight bytePadRight = new BytePadRight(transmission.IvUnpaddedHex, 32);
            string ivPadded = bytePadRight.PaddedHex;
            CmacKdf cmacKdf = new CmacKdf(key, ivPadded);
            string encryptionKey = HexConverter.ByteArrayToHexString(cmacKdf.EncryptionKey);
            string cmacKey = HexConverter.ByteArrayToHexString(cmacKdf.CmacKey);
            Assert.AreEqual(expectedEncryptionKey, encryptionKey.ToLower(), "Encryption Key mismatch.");
            Assert.AreEqual(expectedCmacKey, cmacKey.ToLower(), "CmacKey mismatch.");

            // decryption
            AesCtrEncrypt aesCtrEncrypt = new AesCtrEncrypt(encryptionKey, transmission.IvUnpaddedHex, transmission.CiphertextHex);
            Assert.AreEqual(expectedCompressedPadded, aesCtrEncrypt.CiphertextHex);

            // uncompress
            byte[] uncompressed = Uncompress.FromHexString(aesCtrEncrypt.CiphertextHex, true, true);
            string uncompressedHex = HexConverter.ByteArrayToHexString(uncompressed, true, false);
            Assert.AreEqual(expectedPlaintextHex, uncompressedHex.ToLower());

            // get text
            string plainText = Encoding.UTF8.GetString(uncompressed);
            Assert.AreEqual(expectedPlainText, plainText);

            // CMAC
            AesCmac aesCmac = new AesCmac(cmacKey, transmission.CiphertextHex);
            Assert.AreEqual(expectedCmac, HexConverter.ByteArrayToHexString(aesCmac.Mac).ToLower().Substring(0,8));
        }
    }
}
