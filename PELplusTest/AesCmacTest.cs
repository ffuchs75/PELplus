using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoTests
{
    [TestClass]
    public class AesCmacTests
    {
        // Shared AES-128 key from the RFC test vectors
        private const string RfcKey128 = "2b7e151628aed2a6abf7158809cf4f3c";

        [TestMethod]
        public void Rfc4493_Example1_EmptyMessage()
        {
            var cmac = new AesCmac(RfcKey128, "");
            string result = BitConverter.ToString(cmac.Mac).Replace("-", "").ToLower();
            Assert.AreEqual("bb1d6929e95937287fa37d129b756746", result);
        }

        [TestMethod]
        public void Rfc4493_Example2_16Bytes()
        {
            var cmac = new AesCmac(
                RfcKey128,
                "6bc1bee22e409f96e93d7e117393172a"
            );
            string result = BitConverter.ToString(cmac.Mac).Replace("-", "").ToLower();
            Assert.AreEqual("070a16b46b4d4144f79bdd9dd04a287c", result);
        }

        [TestMethod]
        public void Rfc4493_Example3_40Bytes()
        {
            var cmac = new AesCmac(
                RfcKey128,
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411"
            );
            string result = BitConverter.ToString(cmac.Mac).Replace("-", "").ToLower();
            Assert.AreEqual("dfa66747de9ae63030ca32611497c827", result);
        }

        [TestMethod]
        public void Rfc4493_Example4_64Bytes()
        {
            var cmac = new AesCmac(
                RfcKey128,
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef" +
                "f69f2445df4f9b17ad2b417be66c3710"
            );
            string result = BitConverter.ToString(cmac.Mac).Replace("-", "").ToLower();
            Assert.AreEqual("51f0bebf7e3b9d92fc49741779363cfe", result);
        }

        [TestMethod]
        public void CustomVector_Cmac_RicKey()
        {
            var cmac = new AesCmac(
                "0x593dd21234567800000000000000000000000000000000000000000000000000",
                "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            );
            string result = BitConverter.ToString(cmac.Mac).Replace("-", "").ToLower();
            Assert.AreEqual("91955f80f7b7c6cd84ca76c5b6e8d0b3", result);
        }

        [TestMethod]
        public void Test_Additional_Hexstring()
        {
            var cmac = new AesCmac(
                "659f4c8e1743b17e8a5a95d72c2a91b174e7e21bb737ff4acf0acbeb3678d671", 
                "4710d4588476d592025b12f6ae5e6456c2bab026170159d2a8d90a59c7ee4bd8f0"
                );
            string result = BitConverter.ToString(cmac.Mac).Replace("-", "").ToLower();
            Assert.AreEqual("138da6737e071fea51f0e00d2b3b8fc9", result);
        }

    }
}
