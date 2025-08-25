using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace PELplusTest
{
    [TestClass]
    public class CompleteEncryptionExample
    {
        private readonly string key = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
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
        public void TestAll()
        {
            // calculate time for IV
            Epoch2025Timestamp epoch2025Timestamp = new Epoch2025Timestamp(dateTime);
            Assert.AreEqual(expectedDateTime, epoch2025Timestamp.BytesLittleEndianHex, "Timestamp Big Endian mismatch.");

            // calculate IV
            string iv = epoch2025Timestamp.BytesLittleEndianHex + keyIndex;
            BytePadRight bytePadRight = new BytePadRight(iv, 32);
            string ivPadded = bytePadRight.PaddedHex;
            Assert.AreEqual(expectedIV, ivPadded, "IV mismatch.");

            // derive keys
            CmacKdf cmacKdf = new CmacKdf(key, ivPadded);
            string encryptionKey = HexConverter.ByteArrayToHexString(cmacKdf.EncryptionKey);
            string cmacKey = HexConverter.ByteArrayToHexString(cmacKdf.CmacKey);
            Assert.AreEqual(expectedEncryptionKey, encryptionKey.ToLower(), "Encryption Key mismatch.");
            Assert.AreEqual(expectedCmacKey, cmacKey.ToLower(), "CmacKey mismatch.");

            // compress cleartext
            byte[] clearTextBytes = Encoding.UTF8.GetBytes(clearText);
            Assert.AreEqual(expectedClearTextBytes, HexConverter.ByteArrayToHexString(clearTextBytes).ToLower(), "ClearTextBytes mismatch.");

            byte[] compressedClearTextBytes = Compress.FromByteArray(clearTextBytes);
            Assert.AreEqual(expectedCompressClearTextBytes, HexConverter.ByteArrayToHexString(compressedClearTextBytes).ToLower(), "CompressedClearTextByts mismatch,");

            BytePadRight compressedPadded = new BytePadRight(compressedClearTextBytes, (int)Math.Ceiling((double)compressedClearTextBytes.Length / 5) * 5);
            Assert.AreEqual(expectedCompressedPadded, compressedPadded.PaddedHex);

            // encryption
            AesCtrEncrypt aesCtrEncrypt = new AesCtrEncrypt(encryptionKey, iv, compressedPadded.PaddedBytes);

            Assert.AreEqual(expectedCipherBytes, aesCtrEncrypt.CiphertextHex);

            Assert.AreEqual(expectedCounter0, HexConverter.ByteArrayToHexString(aesCtrEncrypt.Blocks[0].CounterBlock).ToLower());
            Assert.AreEqual(expectedCounter1, HexConverter.ByteArrayToHexString(aesCtrEncrypt.Blocks[1].CounterBlock).ToLower());
            Assert.AreEqual(expectedCounter2, HexConverter.ByteArrayToHexString(aesCtrEncrypt.Blocks[2].CounterBlock).ToLower());

            Assert.AreEqual(expectedKeyStream0, HexConverter.ByteArrayToHexString(aesCtrEncrypt.Blocks[0].KeystreamBlock).ToLower());
            Assert.AreEqual(expectedKeyStream1, HexConverter.ByteArrayToHexString(aesCtrEncrypt.Blocks[1].KeystreamBlock).ToLower());
            Assert.AreEqual(expectedKeyStream2, HexConverter.ByteArrayToHexString(aesCtrEncrypt.Blocks[2].KeystreamBlock).ToLower());


            // CMAC
            AesCmac aesCmac = new AesCmac(cmacKey, aesCtrEncrypt.Ciphertext);
            Assert.AreEqual(expectedCmac, HexConverter.ByteArrayToHexString(aesCmac.Mac).ToLower());

            // CRC
            string crc = HexConverter.ByteToHex(Crc8.Compute(iv));
            Assert.AreEqual(expectedCrc, crc);

            // transmission
            string transmission = String.Format("{0}{1}{2}{3}", iv, crc, HexConverter.ByteArrayToHexString(aesCmac.Mac).ToLower().Substring(0,8), aesCtrEncrypt.CiphertextHex);

            Assert.AreEqual(expectedTransmission, transmission);

            PocsagNumericEncoder pocsagNumericEncoder = new PocsagNumericEncoder(transmission);

            Assert.AreEqual(expectedTransmissionNumeric, pocsagNumericEncoder.NumericText);

            string transmissionBase64 = Convert.ToBase64String(HexConverter.HexStringToByteArray(transmission));

            Assert.AreEqual(expectedTransmissionBase64, transmissionBase64);


        }
    }
}
