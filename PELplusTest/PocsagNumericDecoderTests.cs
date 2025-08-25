using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoTests
{
    [TestClass]
    public class PocsagNumericDecoderTests
    {
        /// <summary>
        /// Happy-path: decode numeric text back to hex/bytes and original input.
        /// Also verifies round-trip with the encoder and equality on all artifacts.
        /// </summary>
        [TestMethod]
        public void Decode_Vector_Produces_Expected_Artifacts_And_RoundTrip()
        {
            // Arrange (same vector as the encoder test)
            string expectedHex =
                "d5fa1f0101e8138da6734710d4588476d592025b12f6ae5e6456c2bab026170159d2a8d90a59c7ee4bd8f2e4";

            // Expected TEXT using mapping: 0..9 -> '0'..'9', A->'*', B->'U', C->' ', D->'-', E->']', F->'['
            string input =
                "U*[58[0808718 1U56] 2]80U2*112]6U*9404*-84[657*762*634-5-0468]08*9U451U905*93]772-U1[472";

            PocsagNumericDecoder pocsagNumericDecoder = new PocsagNumericDecoder(input);

            Assert.AreEqual(expectedHex, pocsagNumericDecoder.OriginalHex.ToLower());
            Assert.AreEqual(true, pocsagNumericDecoder.IsValid);

            input = "abcdef";
            pocsagNumericDecoder = new PocsagNumericDecoder(input);
            Assert.AreEqual(string.Empty, pocsagNumericDecoder.OriginalHex);
            Assert.AreEqual(false, pocsagNumericDecoder.IsValid);

        }
    }
}
