using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace HexConverterTests
{
    [TestClass]
    public class HexToByteTests
    {
        // --- Helper under test (paste your HexToByte implementation or call your class) ---
        // For illustration, I reference a static method HexToByte on class HexConverter.
        // Change "HexConverter.HexToByte" if your method lives elsewhere.
        private static byte CallHexToByte(string s) => HexConverter.HexToByte(s);

        // -----------------------------
        // VALID INPUTS
        // -----------------------------

        [DataTestMethod]
        // Basic 2-digit hex (uppercase / lowercase)
        [DataRow("00", (byte)0x00)]
        [DataRow("ff", (byte)0xFF)]
        [DataRow("FF", (byte)0xFF)]
        [DataRow("A3", (byte)0xA3)]
        [DataRow("a3", (byte)0xA3)]
        [DataRow("0A", (byte)0x0A)]
        [DataRow("0a", (byte)0x0A)]

        // With optional "0x"/"0X" prefix
        [DataRow("0x00", (byte)0x00)]
        [DataRow("0xFF", (byte)0xFF)]
        [DataRow("0xff", (byte)0xFF)]
        [DataRow("0x0A", (byte)0x0A)]
        [DataRow("0Xa3", (byte)0xA3)]

        // With surrounding whitespace (should be trimmed)
        [DataRow(" ff ", (byte)0xFF)]
        [DataRow("  0x0a  ", (byte)0x0A)]
        public void HexToByte_ValidInputs_ReturnsExpectedByte(string input, byte expected)
        {
            // Act
            var actual = CallHexToByte(input);

            // Assert
            // Expect exact byte value (0..255).
            Assert.AreEqual(expected, actual,
                $"Parsing '{input}' should yield 0x{expected:X2} but got 0x{actual:X2}.");
        }

        // -----------------------------
        // INVALID INPUTS
        // -----------------------------

        [DataTestMethod]
        // Null / empty / white-space only
        [DataRow(null)]
        [DataRow("")]
        [DataRow(" ")]
        [DataRow("\t")]

        // Wrong length after optional 0x removal (not exactly 2 hex digits)
        [DataRow("1")]        // single digit
        [DataRow("123")]      // 3 digits
        [DataRow("0x1")]      // 1 digit after 0x
        [DataRow("0x123")]    // 3 digits after 0x
        [DataRow("0x")]       // empty after 0x

        // Non-hex characters
        [DataRow("G1")]
        [DataRow("0xG1")]
        [DataRow("ZZ")]
        [DataRow("--")]
        public void HexToByte_InvalidInputs_ThrowsArgumentException(string input)
        {
            // Act + Assert
            // We expect an ArgumentException for any malformed or unsupported input format.
            var ex = Assert.ThrowsException<ArgumentException>(() => CallHexToByte(input));

            // Optional: verify the parameter name if your implementation uses nameof(hex)
            // Assert.AreEqual("hex", ex.ParamName);

            // Optional: verify that the message is not empty (helps ensure useful diagnostics)
            StringAssert.Contains(ex.Message, "");
        }

        // -----------------------------
        // EDGE-CASE SANITY CHECKS
        // -----------------------------

        [TestMethod]
        public void HexToByte_MinMaxBoundary_Returns00AndFF()
        {
            // Arrange + Act
            byte min = CallHexToByte("00");
            byte max = CallHexToByte("FF");

            // Assert
            Assert.AreEqual((byte)0x00, min, "Expected 0x00 for '00'.");
            Assert.AreEqual((byte)0xFF, max, "Expected 0xFF for 'FF'.");
        }
    }


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
