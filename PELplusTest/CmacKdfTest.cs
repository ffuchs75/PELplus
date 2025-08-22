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
            string iv = "0xd5fa1f0101000000000000000000000000000000000000000000000000000000";

            // Act
            var kdf = new CmacKdf(masterKey, iv);
            string one = HexConverter.ByteArrayToHexString(kdf.Cmac1a);
            string two = HexConverter.ByteArrayToHexString(kdf.Cmac1b);
            string prk = HexConverter.ByteArrayToHexString(kdf.Prk);

            // Assert - Extract phase
            Assert.AreEqual("9689a6e10c4a14d726d6e0ec56d2e22b", HexConverter.ByteArrayToHexString(kdf.Cmac1a, false));
            Assert.AreEqual("2ef2e7acca205cbfb55f924f5b9a5bca", HexConverter.ByteArrayToHexString(kdf.Cmac1b, false));
            Assert.AreEqual("9689a6e10c4a14d726d6e0ec56d2e22b2ef2e7acca205cbfb55f924f5b9a5bca",
                HexConverter.ByteArrayToHexString(kdf.Prk, false));

            // Assert - Expand phase
            Assert.AreEqual("eedeaba836d9eb1584d6e4e11765c20f", HexConverter.ByteArrayToHexString(kdf.T1, false));
            Assert.AreEqual("3b7777579cbbf0c8df6c9202894b5633", HexConverter.ByteArrayToHexString(kdf.T2, false));
            Assert.AreEqual("1a6220a89cffa76f327bda8e4cb4c9ec", HexConverter.ByteArrayToHexString(kdf.T3, false));
            Assert.AreEqual("19013556e2753eb1f23f7744b603b0e5", HexConverter.ByteArrayToHexString(kdf.T4, false));

            // Assert - Final keys
            Assert.AreEqual("eedeaba836d9eb1584d6e4e11765c20f3b7777579cbbf0c8df6c9202894b5633",
                HexConverter.ByteArrayToHexString(kdf.EncryptionKey, false));
            Assert.AreEqual("1a6220a89cffa76f327bda8e4cb4c9ec19013556e2753eb1f23f7744b603b0e5",
                HexConverter.ByteArrayToHexString(kdf.CmacKey, false));

            iv = "d5fa1f0101000000000000000000000000000000000000000000000000000000";
            kdf = new CmacKdf(masterKey, iv);

            // Assert - Final keys
            Assert.AreEqual("eedeaba836d9eb1584d6e4e11765c20f3b7777579cbbf0c8df6c9202894b5633",
                HexConverter.ByteArrayToHexString(kdf.EncryptionKey, false));
            Assert.AreEqual("1a6220a89cffa76f327bda8e4cb4c9ec19013556e2753eb1f23f7744b603b0e5",
                HexConverter.ByteArrayToHexString(kdf.CmacKey, false));


        }
    }
}
