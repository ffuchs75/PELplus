using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PELplus;

namespace TimeTests
{
    [TestClass]
    public class Epoch2025TimestampTests
    {
        [TestMethod]
        public void Timestamp_2025_01_19_12_34_56()
        {
            var dtUtc = new DateTime(2025, 1, 19, 12, 34, 56, DateTimeKind.Utc);
            ValidateAllConstructors(dtUtc);
        }

        [TestMethod]
        public void Timestamp_2038_01_19_23_59_59()
        {
            var dtUtc = new DateTime(2038, 1, 19, 23, 59, 59, DateTimeKind.Utc);
            ValidateAllConstructors(dtUtc);
        }

        [TestMethod]
        public void Timestamp_2040_02_29_10_00_23()
        {
            var dtUtc = new DateTime(2040, 2, 29, 10, 00, 23, DateTimeKind.Utc);
            ValidateAllConstructors(dtUtc);
        }

        /// <summary>
        /// Validates:
        /// - Seconds since fixed epoch (2025-01-01T00:00:00Z)
        /// - UTC and Local DateTime
        /// - 4-byte LE / BE representations and their hex strings
        /// - All three constructors (DateTime, byte[] LE, hex BE)
        /// </summary>
        private static void ValidateAllConstructors(DateTime dtUtc)
        {
            // Independent expected values (computed here, not using the class under test)
            DateTime epoch = Parameters.EpochStartUtc;
            Assert.AreEqual(DateTimeKind.Utc, epoch.Kind, "Epoch must be UTC");

            if (dtUtc < epoch)
                Assert.Inconclusive("Provided test date is before the fixed epoch.");

            uint expectedSeconds = checked((uint)(dtUtc - epoch).TotalSeconds);

            // Expected LE / BE byte arrays
            byte[] expectedLE = BitConverter.GetBytes(expectedSeconds);
            byte[] expectedBE = GetBigEndian(expectedSeconds);

            // Expected hex strings (lowercase, no spaces)
            string expectedHexLE = HexConverter.ByteArrayToHexString(expectedLE, uppercase: false);
            string expectedHexBE = HexConverter.ByteArrayToHexString(expectedBE, uppercase: false);

            // === Construct from DateTime ===
            var fromDate = new Epoch2025Timestamp(dtUtc);
            Assert.AreEqual(dtUtc, fromDate.UtcTime, "UTC time mismatch (DateTime ctor).");
            Assert.AreEqual(dtUtc.ToLocalTime(), fromDate.LocalTime, "Local time mismatch (DateTime ctor).");
            Assert.AreEqual(expectedSeconds, fromDate.SecondsSinceEpoch, "Seconds mismatch (DateTime ctor).");
            CollectionAssert.AreEqual(expectedLE, fromDate.BytesLittleEndian, "LE bytes mismatch (DateTime ctor).");
            CollectionAssert.AreEqual(expectedBE, fromDate.BytesBigEndian, "BE bytes mismatch (DateTime ctor).");
            Assert.AreEqual(expectedHexLE, fromDate.BytesLittleEndianHex, "LE hex mismatch (DateTime ctor).");
            Assert.AreEqual(expectedHexBE, fromDate.BytesBigEndianHex, "BE hex mismatch (DateTime ctor).");

            // === Construct from little-endian byte[] ===
            var fromLe = new Epoch2025Timestamp(expectedLE, isLittleEndian: true);
            Assert.AreEqual(dtUtc, fromLe.UtcTime, "UTC time mismatch (LE bytes ctor).");
            Assert.AreEqual(expectedSeconds, fromLe.SecondsSinceEpoch, "Seconds mismatch (LE bytes ctor).");
            CollectionAssert.AreEqual(expectedLE, fromLe.BytesLittleEndian, "LE bytes roundtrip mismatch.");
            CollectionAssert.AreEqual(expectedBE, fromLe.BytesBigEndian, "BE bytes roundtrip mismatch.");
            Assert.AreEqual(expectedHexLE, fromLe.BytesLittleEndianHex, "LE hex roundtrip mismatch.");
            Assert.AreEqual(expectedHexBE, fromLe.BytesBigEndianHex, "BE hex roundtrip mismatch.");

            // === Construct from big-endian hex string ===
            var fromBeHex = new Epoch2025Timestamp(expectedHexBE, isLittleEndian: false);
            Assert.AreEqual(dtUtc, fromBeHex.UtcTime, "UTC time mismatch (BE hex ctor).");
            Assert.AreEqual(expectedSeconds, fromBeHex.SecondsSinceEpoch, "Seconds mismatch (BE hex ctor).");
            CollectionAssert.AreEqual(expectedLE, fromBeHex.BytesLittleEndian, "LE bytes mismatch (BE hex ctor).");
            CollectionAssert.AreEqual(expectedBE, fromBeHex.BytesBigEndian, "BE bytes mismatch (BE hex ctor).");
            Assert.AreEqual(expectedHexLE, fromBeHex.BytesLittleEndianHex, "LE hex mismatch (BE hex ctor).");
            Assert.AreEqual(expectedHexBE, fromBeHex.BytesBigEndianHex, "BE hex mismatch (BE hex ctor).");
        }

        /// <summary>
        /// Returns big-endian bytes of a 32-bit unsigned integer, independent of host endianness.
        /// </summary>
        private static byte[] GetBigEndian(uint value)
        {
            byte[] b = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian) Array.Reverse(b);
            return b;
        }
    }
}
