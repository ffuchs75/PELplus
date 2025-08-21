using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoTests
{
    [TestClass]
    public class CompressTests
    {
        [TestMethod]
        public void Compress_Removes_MSB_Correctly()
        {
            // Arrange
            // Input hex: ASCII text "Probearlarm, Leitstelle nicht anrufen" (all bytes MSB=0)
            string inputHex = "50 72 6f 62 65 61 6c 61 72 6d 2c 20 4c 65 69 74 73 74 65 6c 6c 65 20 6e 69 63 68 74 20 61 6e 72 75 66 65 6e";

            // Expected compressed output (MSB removed from each byte)
            string expectedHex = "0a 9f da 3a 70 cd c3 4f 6c d0 23 34 e5 97 ce 5e 99 b3 74 c1 3b 97 8c 59 70 50 dd a7 ae ce 9b b0";

            // Act
            byte[] compressed = Compress.FromHexString(inputHex);
            string compressedHex = HexConverter.ByteArrayToHexString(compressed, true, false);

            // Assert
            Assert.AreEqual(
                expectedHex.Replace(" ", "").ToUpperInvariant(),
                compressedHex.ToUpperInvariant(),
                "Compressed data does not match expected value."
            );
        }
    }
}
