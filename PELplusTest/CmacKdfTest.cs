using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoTests
{
    [TestClass]
    public class CmacKdfTests
    {
        [TestMethod]
        public void ExampleVector_FullCheck_UsingProperties()
        {
            // Arrange
            string masterKey = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
            string iv = "0x593dd21234567800000000000000000000000000000000000000000000000000";

            // Act
            var kdf = new CmacKdf(masterKey, iv);

            // Assert - Extract phase
            Assert.AreEqual("91955f80f7b7c6cd84ca76c5b6e8d0b3", HexConverter.ByteArrayToHexString(kdf.Cmac1a, false));
            Assert.AreEqual("e81c2f6bb9472073c36f89ab0d076203", HexConverter.ByteArrayToHexString(kdf.Cmac1b, false));
            Assert.AreEqual("91955f80f7b7c6cd84ca76c5b6e8d0b3e81c2f6bb9472073c36f89ab0d076203",
                HexConverter.ByteArrayToHexString(kdf.Prk, false));

            // Assert - Expand phase
            Assert.AreEqual("5c034d6fe673b69091d0bf4d4d1a82a6", HexConverter.ByteArrayToHexString(kdf.T1, false));
            Assert.AreEqual("3ddb4a165cb56ed9abb4201743e116d4", HexConverter.ByteArrayToHexString(kdf.T2, false));
            Assert.AreEqual("700efc4051e66d35707789e06a2077ae", HexConverter.ByteArrayToHexString(kdf.T3, false));
            Assert.AreEqual("65cc0de9294c532a2fc09da1ebd8a926", HexConverter.ByteArrayToHexString(kdf.T4, false));

            // Assert - Final keys
            Assert.AreEqual("5c034d6fe673b69091d0bf4d4d1a82a63ddb4a165cb56ed9abb4201743e116d4",
                HexConverter.ByteArrayToHexString(kdf.EncryptionKey, false));
            Assert.AreEqual("700efc4051e66d35707789e06a2077ae65cc0de9294c532a2fc09da1ebd8a926",
                HexConverter.ByteArrayToHexString(kdf.CmacKey, false));

            iv = "d5fa1f0101000000000000000000000000000000000000000000000000000000";
            kdf = new CmacKdf(masterKey, iv);

            // Assert - Final keys
            Assert.AreEqual("eb5d641c1f51a034039549c1389a1a1db5a3b62a68471a47234d689c513ff244",
                HexConverter.ByteArrayToHexString(kdf.EncryptionKey, false));
            Assert.AreEqual("659f4c8e1743b17e8a5a95d72c2a91b174e7e21bb737ff4acf0acbeb3678d671",
                HexConverter.ByteArrayToHexString(kdf.CmacKey, false));


        }
    }
}
