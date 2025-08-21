using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoTests
{
    [TestClass]
    public class PocsagNumericEncoder_Immutable_Tests
    {
        [TestMethod]
        public void Encode_Vector_Produces_Expected_Hex_And_Text()
        {
            // Arrange
            string inputHex =
                "d5fa1f0101e8138da6734710d4588476d592025b12f6ae5e6456c2bab026170159d2a8d90a59c7ee4bd8f2e4";

            // Expected HEX after nibble-wise bit reversal (your corrected full output):
            string expectedHex =
                "BAF58F0808718C1B56EC2E80B2A112E6BA9404AD84F657A762A634D5D0468E08A9B451B905A93E772DB1F472";

            // Expected TEXT using mapping: 0..9 -> '0'..'9', A->'*', B->'U', C->' ', D->'-', E->']', F->'['
            string expectedText =
                "U*[58[0808718 1U56] 2]80U2*112]6U*9404*-84[657*762*634-5-0468]08*9U451U905*93]772-U1[472";

            // Act: construct immutable encoder
            var enc = new PocsagNumericEncoder(inputHex);

            // Assert: HEX matches
            Assert.AreEqual(expectedHex, enc.NumericHex, "Numeric hex does not match expected.");

            // Assert: TEXT matches
            Assert.AreEqual(expectedText, enc.NumericText, "Numeric text does not match expected.");

            // Also verify byte[] path equals hex path
            var encBytes = new PocsagNumericEncoder(HexConverter.HexStringToByteArray(inputHex));
            Assert.AreEqual(enc.NumericHex, encBytes.NumericHex, "Hex/bytes paths should produce identical hex.");
            Assert.AreEqual(enc.NumericText, encBytes.NumericText, "Hex/bytes paths should produce identical text.");
        }
    }
}
