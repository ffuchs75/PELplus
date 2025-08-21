using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace CryptoTests
{
    [TestClass]
    public class BytePadRightTests
    {
        [TestMethod]
        public void PadRight_FromHexString_To32Bytes()
        {
            // Arrange
            string inputHex = "d5fa1f0101";
            int targetLength = 32;
            string expectedHex = "d5fa1f0101000000000000000000000000000000000000000000000000000000";

            // Act
            var padded = new BytePadRight(inputHex, targetLength);

            // Assert
            Assert.AreEqual(expectedHex, padded.PaddedHex,
                "Hex string padding result does not match expected value.");

            Assert.AreEqual(targetLength, padded.PaddedBytes.Length,
                "Padded byte array does not have expected length.");

            CollectionAssert.AreEqual(
                HexToBytes(expectedHex),
                padded.PaddedBytes,
                "Padded byte array does not match expected value.");
        }

        [TestMethod]
        public void PadRight_FromByteArray_To32Bytes()
        {
            // Arrange
            byte[] inputBytes = HexToBytes("d5fa1f0101");
            int targetLength = 32;
            string expectedHex = "d5fa1f0101000000000000000000000000000000000000000000000000000000";

            // Act
            var padded = new BytePadRight(inputBytes, targetLength);

            // Assert
            Assert.AreEqual(expectedHex, padded.PaddedHex,
                "Hex string padding result does not match expected value.");

            Assert.AreEqual(targetLength, padded.PaddedBytes.Length,
                "Padded byte array does not have expected length.");

            CollectionAssert.AreEqual(
                HexToBytes(expectedHex),
                padded.PaddedBytes,
                "Padded byte array does not match expected value.");
        }

        [TestMethod]
        public void TestEvenNumberOfNibbles()
        {
            string hexString = "0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0";
            string expectedHexString = "0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0000000";
            byte[] hex = HexConverter.HexStringToByteArray(hexString);

            BytePadRight bytePadRight = new BytePadRight(hex, (int)Math.Ceiling((double)hex.Length / 5) * 5);

            Assert.AreEqual(expectedHexString, bytePadRight.PaddedHex.ToLower());

        }

        // ---------------- Helper ----------------
        private static byte[] HexToBytes(string hex)
        {
            if (hex.StartsWith("0x")) hex = hex.Substring(2);
            if (hex.Length % 2 != 0) hex = "0" + hex;

            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                result[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return result;
        }
    }
}
