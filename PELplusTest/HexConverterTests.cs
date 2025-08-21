using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace HexConverterTests
{
    [TestClass]
    public class HexConverterUnitTests
    {
        [TestMethod]
        public void HexStringToByteArray_NormalHex_Works()
        {
            byte[] expected = { 0x0A, 0x1B, 0x2C };
            byte[] result = HexConverter.HexStringToByteArray("0A1B2C");
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void HexStringToByteArray_WithSpaces_Works()
        {
            byte[] expected = { 0xDE, 0xAD, 0xBE, 0xEF };
            byte[] result = HexConverter.HexStringToByteArray("DE AD BE EF");
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void HexStringToByteArray_With0xPrefix_Works()
        {
            byte[] expected = { 0x0A, 0x1B, 0x2C };
            byte[] result = HexConverter.HexStringToByteArray("0x0A 0x1B 0x2C");
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void ByteArrayToHexString_DefaultUppercase_Works()
        {
            byte[] input = { 0x0A, 0x1B, 0x2C };
            string result = HexConverter.ByteArrayToHexString(input);
            Assert.AreEqual("0A1B2C", result);
        }

        [TestMethod]
        public void ByteArrayToHexString_Lowercase_Works()
        {
            byte[] input = { 0x0A, 0x1B, 0x2C };
            string result = HexConverter.ByteArrayToHexString(input, uppercase: false);
            Assert.AreEqual("0a1b2c", result);
        }

        [TestMethod]
        public void ByteArrayToHexString_With0xPrefix_Works()
        {
            byte[] input = { 0x0A, 0x1B, 0x2C };
            string result = HexConverter.ByteArrayToHexString(input, uppercase: true, withPrefix: true);
            Assert.AreEqual("0x0A 0x1B 0x2C", result);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void HexStringToByteArray_InvalidLength_Throws()
        {
            HexConverter.HexStringToByteArray("ABC"); // Odd length should throw
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void HexStringToByteArray_NullInput_Throws()
        {
            HexConverter.HexStringToByteArray(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ByteArrayToHexString_NullInput_Throws()
        {
            HexConverter.ByteArrayToHexString(null);
        }

        [TestMethod]
        public void RoundTrip_HexToBytesAndBack_Matches()
        {
            string originalHex = "DEADBEEF";
            byte[] bytes = HexConverter.HexStringToByteArray(originalHex);
            string backToHex = HexConverter.ByteArrayToHexString(bytes);
            Assert.AreEqual(originalHex, backToHex);
        }

        [TestMethod]
        public void Hex_GlobalPrefixOnly_ShouldParseCorrectly()
        {
            // Arrange
            string hex = "0x12345678";

            // Act
            byte[] result = HexConverter.HexStringToByteArray(hex);

            // Assert
            CollectionAssert.AreEqual(
                new byte[] { 0x12, 0x34, 0x56, 0x78 },
                result
            );
        }

        [TestMethod]
        public void Hex_PerBytePrefixes_ShouldParseCorrectly()
        {
            string hex = "0x12 0x34 0x56 0x78";
            byte[] result = HexConverter.HexStringToByteArray(hex);
            CollectionAssert.AreEqual(
                new byte[] { 0x12, 0x34, 0x56, 0x78 },
                result
            );
        }

        [TestMethod]
        public void Hex_NoPrefix_ShouldParseCorrectly()
        {
            string hex = "12345678";
            byte[] result = HexConverter.HexStringToByteArray(hex);
            CollectionAssert.AreEqual(
                new byte[] { 0x12, 0x34, 0x56, 0x78 },
                result
            );
        }

        [TestMethod]
        public void Hex_WithSpaces_ShouldParseCorrectly()
        {
            string hex = "12 34 56 78";
            byte[] result = HexConverter.HexStringToByteArray(hex);
            CollectionAssert.AreEqual(
                new byte[] { 0x12, 0x34, 0x56, 0x78 },
                result
            );
        }
    }
}
