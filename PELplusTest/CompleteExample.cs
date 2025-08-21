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
    public class CompleteExample
    {
        private readonly string key = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        private readonly DateTime dateTime = new DateTime(2025, 8, 7, 10, 30, 45, DateTimeKind.Utc);
        private readonly string expectedDateTime = "d5fa1f01";
        private readonly string expectedIV = "d5fa1f0101000000000000000000000000000000000000000000000000000000";
        private readonly string keyIndex = "01";
        private readonly string clearText = "Probealarm, Leitstelle nicht anrufen";
        private readonly string expectedClearTextBytes = "50726f6265616c61726d2c204c6569747374656c6c65206e6963687420616e727566656e";
        private readonly string expectedCompressClearTextBytes = "0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0";
        private readonly string expectedEncryptionKey = "eb5d641c1f51a034039549c1389a1a1db5a3b62a68471a47234d689c513ff244";
        private readonly string expectedCmacKey = "659f4c8e1743b17e8a5a95d72c2a91b174e7e21bb737ff4acf0acbeb3678d671";
        private readonly string expectedCompressedPadded = "0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0000000";
        private readonly string expectedCipherBytes = "4710d4588476d592025b12f6ae5e646491e87d05dcbb1a8cfb88547050a7bb23d068f2";
        private readonly string expectedCounter0 = "d5fa1f01010000000000000000000000";
        private readonly string expectedCounter1 = "d5fa1f01010000000000000000000001";
        private readonly string expectedCounter2 = "d5fa1f01010000000000000000000002";
        private readonly string expectedKeyStream0 = "4d8f0e62f4bb16dd6e8b31c24bc9aa3a";
        private readonly string expectedKeyStream1 = "085b09c4e72c96d58bd889d7fe692093";
        private readonly string expectedKeyStream2 = "d068f2e436b9ab5222f4eddbc59f436a";
        private readonly string expectedCmac = "e713360d23286bf95df8def8a4629a43";
        private readonly string expectedCrc = "e8";
        private readonly string expectedTransmission = "d5fa1f0101e8e713360d4710d4588476d592025b12f6ae5e646491e87d05dcbb1a8cfb88547050a7bb23d068f2";
        private readonly string expectedTransmissionNumeric = "U*[58[0808717]8  60U2]80U2*112]6U*9404*-84[657*762629871]U0*U3--8513[-11*2]0*05]--4 U061[4";
        private readonly string expectedTransmissionBase64 = "1fofAQHo5xM2DUcQ1FiEdtWSAlsS9q5eZGSR6H0F3LsajPuIVHBQp7sj0Gjy";



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
