using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace PELplusTest
{
    [TestClass]
    public class UncompressTests
    {
        [TestMethod]
        public void TestUncompress()
        {
            string expectedHex = "50 72 6f 62 65 61 6c 61 72 6d 2c 20 4c 65 69 74 73 74 65 6c 6c 65 20 6e 69 63 68 74 20 61 6e 72 75 66 65 6e";
            string inputHex = "0a 9f da 3a 70 cd c3 4f 6c d0 23 34 e5 97 ce 5e 99 b3 74 c1 3b 97 8c 59 70 50 dd a7 ae ce 9b b0";

            byte[] uncompressed = Uncompress.FromHexString(inputHex);
            string uncompressedHex = HexConverter.ByteArrayToHexString(uncompressed, true, false);

            // Assert
            Assert.AreEqual(
                expectedHex.Replace(" ", "").ToUpperInvariant(),
                uncompressedHex.ToUpperInvariant(),
                "Compressed data does not match expected value."
            );
        }
    }
}
