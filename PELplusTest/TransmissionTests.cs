using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace PELplusTest
{
    [TestClass]
    public class TransmissionTests
    {

        private readonly string numerik = "U*[58[080871184*6595 574[1[461U04232]U*4126*[]626016*74 645U41[6093-98U84063*[692544931*U7";
        private readonly string base64 = "1fofAQHogSVqmjri+PJo0CTEfVKEZfdkYIZeI2KtKPYJy5HRIGxfaUoinIXe";
        private readonly string unencrypted = "This is a test message.";

        private readonly string expectedIV = "d5fa1f0101";
        private readonly string expectedTimestamp = "d5fa1f01";
        private readonly string expectedKeyIndex = "01";
        private readonly string expectedTransmittedCrc = "e8";
        private readonly string expectedActualCrc = "e8";
        private readonly string expectedCmac = "81256a9a";
        private readonly string expectedCipher = "3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de";
        private readonly string expectedRawframe = "d5fa1f0101e881256a9a3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de";
        private readonly DateTime expectedDateTime = new DateTime(2025,8,7,10,30,45,DateTimeKind.Utc);
        private readonly DateTime expectedDateTimeLocal = new DateTime(2025, 8, 7, 12, 30, 45, DateTimeKind.Local);

        [TestMethod]
        public void TestNumerik()
        {
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
        }

        [TestMethod]
        public void TestBase64()
        {
            Transmission transmission = new Transmission(base64);
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
            Assert.AreEqual(TransmissionEncoding.Base64, transmission.EncodingType);
        }

        [TestMethod]
        public void TestUnecrypted()
        {
            Transmission transmission = new Transmission(unencrypted);
            Assert.AreEqual(TransmissionEncoding.Unencrypted, transmission.EncodingType);
        }

    }
}
