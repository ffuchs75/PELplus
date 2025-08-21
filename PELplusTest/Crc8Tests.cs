using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoTests
{
    [TestClass]
    public class Crc8Tests
    {
        [TestMethod]
        public void Compute_Crc8_For_593dd201_HexInput()
        {
            // Arrange
            const string inputHex = "0xd23d5901";

            // Act
            byte crc = Crc8.Compute(inputHex);

            // Assert
            const byte expected = 0x27; // correct for poly=0x07, init=0x00, no refin/refout, no xorout
            Assert.AreEqual(expected, crc, $"CRC8 for {inputHex} should be {expected:X2} but was {crc:X2}");
        }

        [TestMethod]
        public void Compute_Crc8_For_593dd201_ByteArrayInput()
        {
            // Arrange
            byte[] data = new byte[] { 0xd2, 0x3d, 0x59, 0x01 };

            // Act
            byte crc = Crc8.Compute(data);

            // Assert
            const byte expected = 0x27;
            Assert.AreEqual(expected, crc, $"CRC8 for byte[] should be {expected:X2} but was {crc:X2}");
        }
    }
}
