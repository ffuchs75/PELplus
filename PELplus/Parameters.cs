using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PELplus
{
    /// <summary>
    /// parameters according to specification
    /// </summary>
    public static class Parameters
    {
        /// <summary>
        /// length of IV padded in bytes
        /// </summary>
        public const int IVPaddedSize = 32;

        /// <summary>
        /// length of Cmac checksum in bytes;
        /// </summary>
        public const int CmacSize = 4;

        /// <summary>
        /// length of POCSAG blocks in bytes (40 bit = 5 bytes)
        /// </summary>
        public const int POCSAGBlockSize = 5;

        /// <summary>
        /// epoch start (UTC): 2025-01-01 00:00:00
        /// </summary>
        public static readonly DateTime EpochStartUtc = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    }
}
