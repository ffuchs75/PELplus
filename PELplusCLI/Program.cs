using System;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PELplusCLI
{
    internal static class Program
    {
        /*
         * PELplus.CLI – POCSAG Encryption Explainer 
         * ------------------------------------------
         * 
         */

        private static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            try
            {
                // -------- Parse CLI arguments --------
                Params p = ParseArgs(args);

                if (p.ShowHelp)
                {
                    PrintUsage();
                    return 0;
                }

                if (p.ShowLicense)
                {
                    PrintLicense();
                    return 0;
                }


                if (string.IsNullOrWhiteSpace(p.Message))
                {
                    Error("Parameter --message is required.");
                    PrintUsage();
                    return 2;
                }

                // -------- Apply defaults & normalize inputs --------
                // Normalize/generate a 32-byte key as lowercase hex
                string keyHex = NormalizeHexOrGenerateRandom(p.KeyHex, 32);

                // Key index defaults to "01" (one byte) if not provided
                string keyIndexHex = string.IsNullOrWhiteSpace(p.KeyIndexHex) ? "01" : NormalizeHex(p.KeyIndexHex);
                if (keyIndexHex.Length != 2)
                    throw new ArgumentException("KeyIndex must be exactly 1 byte (2 hex characters).");

                // UTC time defaults to now if not provided
                DateTime utcTime = p.UtcTime.HasValue
                    ? DateTime.SpecifyKind(p.UtcTime.Value, DateTimeKind.Utc)
                    : DateTime.UtcNow;

                string message = p.Message;

                // -------- Pretty header --------
                PrintTitle("PELplus – POCSAG Encryption");
                PrintKV("Message  ", message);
                PrintKV("UTC time ", utcTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
                PrintKV("KeyIndex ", keyIndexHex);
                PrintKV("Key (hex)", keyHex);

                // -------- 1) Timestamp for IV (little-endian hex) --------
                Epoch2025Timestamp ts = new Epoch2025Timestamp(utcTime);
                string timestampLE = ts.BytesLittleEndianHex; // 4 bytes -> 8 hex chars
                PrintSection("Timestamp / IV base");
                PrintKV("Timestamp LE (hex)  ", timestampLE);

                // -------- 2) Build IV (unpadded) and then pad to 32 bytes --------
                // Unpadded IV = timestampLE || keyIndex
                string ivUnpaddedHex = timestampLE + keyIndexHex;

                // Pad IV to 32 bytes (right pad with 0x00) – required by KDF input
                BytePadRight ivPad = new BytePadRight(ivUnpaddedHex, 32);
                string ivPaddedHex = ivPad.PaddedHex;

                PrintKV("IV (unpadded)       ", ivUnpaddedHex);
                PrintKV("IV (padded 32 bytes)", ivPaddedHex);

                // -------- 3) Derive keys via CMAC-KDF (enc key + cmac key) --------
                CmacKdf kdf = new CmacKdf(keyHex, ivPaddedHex);
                string encKeyHex = HexConverter.ByteArrayToHexString(kdf.EncryptionKey).ToLowerInvariant();
                string cmacKeyHex = HexConverter.ByteArrayToHexString(kdf.CmacKey).ToLowerInvariant();

                PrintSection("Key derivation (CMAC-KDF)");
                PrintKV("Encryption Key", encKeyHex);
                PrintKV("CMAC Key      ", cmacKeyHex);

                // -------- 4) UTF-8 encode & compress plaintext --------
                // IMPORTANT: we print both raw UTF-8 hex and compressed hex for full transparency.
                byte[] clearBytes = Encoding.UTF8.GetBytes(message);
                string clearHex = HexConverter.ByteArrayToHexString(clearBytes).ToLowerInvariant();

                byte[] compressedBytes = Compress.FromByteArray(clearBytes);
                string compressedHex = HexConverter.ByteArrayToHexString(compressedBytes).ToLowerInvariant();

                PrintSection("Plaintext & compression");
                PrintKV("Plaintext bytes (hex)    ", clearHex);
                PrintKV("Compressed bytes (hex)   ", compressedHex);

                // -------- 5) Right-pad compressed bytes to a multiple of 5 --------
                // Rationale: POCSAG payload uses 40-bit blocks (5 bytes).
                int paddedLen = (int)Math.Ceiling(compressedBytes.Length / 5.0) * 5;
                BytePadRight padPayload = new BytePadRight(compressedBytes, paddedLen);
                string payloadPaddedHex = padPayload.PaddedHex.ToLowerInvariant();

                PrintKV("Compressed + padded (hex)", payloadPaddedHex);

                // -------- 6) AES-CTR encryption --------
                // NOTE: Your AesCtrEncrypt constructor takes (encKeyHex, ivUnpaddedHex, paddedBytes).
                // It also exposes Blocks[] with CounterBlock + KeystreamBlock (for visualization).
                AesCtrEncrypt aes = new AesCtrEncrypt(encKeyHex, ivUnpaddedHex, padPayload.PaddedBytes);

                PrintSection("AES-CTR details (all blocks)");
                // Print EVERY block (counter & keystream) to support arbitrarily long messages.
                int blockCount = aes.Blocks.Count();
                for (int i = 0; i < blockCount; i++)
                {
                    string counterHex = HexConverter.ByteArrayToHexString(aes.Blocks[i].CounterBlock).ToLowerInvariant();
                    string ksHex = HexConverter.ByteArrayToHexString(aes.Blocks[i].KeystreamBlock).ToLowerInvariant();
                    string cipherTextPortion = HexConverter.ByteArrayToHexString(aes.Blocks[i].CiphertextPortion).ToLowerInvariant();
                    string plainTextPortion = HexConverter.ByteArrayToHexString(aes.Blocks[i].PlaintextPortion).ToLowerInvariant();

                    // Use a compact, aligned output; large messages remain readable.
                    PrintKV(string.Format("Counter[{0}]          ", i), counterHex);
                    PrintKV(string.Format("Keystream[{0}]        ", i), ksHex);
                    PrintKV(string.Format("Plaintext[{0}]        ", i), plainTextPortion);
                    PrintKV(string.Format("CipherTextPortion[{0}]", i), cipherTextPortion);

                    // Separator line for readability between blocks
                    Console.WriteLine(new string('-', 60));
                }

                string cipherHex = aes.CiphertextHex.ToLowerInvariant();
                PrintKV("Ciphertext (hex)", cipherHex);

                // -------- 7) CMAC over ciphertext (Encrypt-then-MAC) --------
                // We authenticate the ciphertext (and MAC is printed in full 128-bit form).
                AesCmac cmac = new AesCmac(cmacKeyHex, aes.Ciphertext);
                string macHex = HexConverter.ByteArrayToHexString(cmac.Mac).ToLowerInvariant();

                PrintSection("Checksums");
                PrintKV("CMAC (128-bit, hex) over ciphertext", macHex);

                // -------- 8) CRC-8 over UNPADDED IV --------
                // CRC8 is computed over ivUnpaddedHex.
                byte crcByte = Crc8.Compute(ivUnpaddedHex);
                string crcHex = HexConverter.ByteToHex(crcByte).ToLowerInvariant();
                PrintKV("CRC-8 over IV                      ", crcHex);

                // -------- 9) Transmission composition --------
                // TX = IV(unpadded) || CRC || MAC[0..3] || Ciphertext
                string macFirst8 = macHex.Substring(0, 8);
                string transmissionHex = (ivUnpaddedHex + crcHex + macFirst8 + cipherHex).ToLowerInvariant();

                PrintSection("Transmission");
                PrintKV("TX (hex)      ", transmissionHex);

                // -------- 10) Extra views: POCSAG Numeric + Base64 --------
                PocsagNumericEncoder numeric = new PocsagNumericEncoder(transmissionHex);
                string base64 = Convert.ToBase64String(HexConverter.HexStringToByteArray(transmissionHex));

                PrintKV("POCSAG Numeric", numeric.NumericText);
                PrintKV("Base64        ", base64);

                PrintFooter("Done.");
                return 0;
            }
            catch (Exception ex)
            {
                Error(ex.Message);
                return 1;
            }
        }

        // =============================== CLI parsing helpers ===============================

        private sealed class Params
        {
            public string KeyHex;       // 32-byte hex key; if null/empty -> generate random
            public string KeyIndexHex;  // 1-byte hex index; default "01"
            public DateTime? UtcTime;   // UTC timestamp; default now
            public string Message;      // required
            public bool ShowHelp;       // -h/--help
            public bool ShowLicense;    // --license
        }

        private static Params ParseArgs(string[] args)
        {
            /*
             * Supported flags:
             *   --key <hex>                 32-byte hex key; accepts "0x" and spaces
             *   --keyindex <hex2>           one byte hex (default "01")
             *   --time "YYYY-MM-DD HH:mm:ss"  UTC time; default now
             *   --message "<text>"          required
             *   -h | --help                 show usage
             *
             * NOTE:
             * - We also allow a trailing positional argument for message if not set yet,
             *   so users can simply write: PELplus.CLI --message "..."  OR  PELplus.CLI "..."
             */
            Params p = new Params();
            int i = 0;
            while (i < args.Length)
            {
                string a = args[i];

                if (a == "-h" || a == "--help")
                {
                    p.ShowHelp = true;
                    i++;
                    continue;
                }
                else if (a == "--license")
                {
                    p.ShowLicense = true;
                    i++;
                    continue;
                }
                else if (a == "--key")
                {
                    p.KeyHex = RequireValue(args, ref i, "--key");
                    continue;
                }
                else if (a == "--keyindex")
                {
                    p.KeyIndexHex = RequireValue(args, ref i, "--keyindex");
                    continue;
                }
                else if (a == "--time")
                {
                    string val = RequireValue(args, ref i, "--time");
                    DateTime dt;
                    if (!DateTime.TryParseExact(
                        val,
                        "yyyy-MM-dd HH:mm:ss",
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out dt))
                    {
                        throw new ArgumentException("Invalid time format. Expected: \"YYYY-MM-DD HH:mm:ss\" (UTC).");
                    }
                    p.UtcTime = DateTime.SpecifyKind(dt, DateTimeKind.Utc);
                    continue;
                }
                else if (a == "--message")
                {
                    p.Message = RequireValue(args, ref i, "--message");
                    continue;
                }
                else if (a.StartsWith("-", StringComparison.Ordinal))
                {
                    throw new ArgumentException("Unknown option: " + a);
                }
                else
                {
                    if (string.IsNullOrEmpty(p.Message))
                        p.Message = a;
                    else
                        p.Message += " " + a;

                    i++;
                }
            }
            return p;
        }

        private static string RequireValue(string[] args, ref int i, string flag)
        {
            if (i + 1 >= args.Length)
                throw new ArgumentException("Missing value after " + flag + ".");
            i += 2; // move past flag and value
            return args[i - 1];
        }

        // =============================== Hex & random helpers ===============================

        /// <summary>
        /// Normalize a hex string: remove "0x" markers and whitespace, lower-case result.
        /// Example: "0xAA 0xBB cc" -> "aabbcc"
        /// </summary>
        private static string NormalizeHex(string hex)
        {
            if (string.IsNullOrWhiteSpace(hex)) return hex;

            // Lowercase first so we only have to remove "0x"
            string s = hex.ToLowerInvariant();

            // Remove "0x" markers
            s = s.Replace("0x", "");

            // Remove whitespace characters (space, tabs, CR, LF)
            s = Regex.Replace(s, @"\s+", "");

            return s;
        }

        /// <summary>
        /// If hex is missing: generate a cryptographically strong random key of lenBytes.
        /// If provided: normalize and validate length + characters.
        /// </summary>
        private static string NormalizeHexOrGenerateRandom(string maybeHex, int lenBytes)
        {
            if (string.IsNullOrWhiteSpace(maybeHex))
            {
                byte[] key = new byte[lenBytes];
                
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(key);
                }
                return HexConverter.ByteArrayToHexString(key).ToLowerInvariant();
            }

            string h = NormalizeHex(maybeHex);
            if (h.Length != lenBytes * 2)
                throw new ArgumentException("Key must be " + lenBytes + " bytes (" + (lenBytes * 2) + " hex chars).");

            // Validate hex chars (0-9 a-f A-F)
            for (int i = 0; i < h.Length; i++)
            {
                char c = h[i];
                bool ok =
                    (c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F');
                if (!ok)
                    throw new ArgumentException("Key contains invalid hex characters.");
            }
            return h.ToLowerInvariant();
        }

        // =============================== Pretty console output ===============================

        private static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  PELplus.CLI --message \"<text>\" [--key <hex32bytes>] [--keyindex <hex2>] [--time \"YYYY-MM-DD HH:mm:ss\"]");
            Console.WriteLine("  PELplus.CLI --help");
            Console.WriteLine("  PELplus.CLI --license");
            Console.WriteLine();
            Console.WriteLine("Defaults:");
            Console.WriteLine("  --key       random 32-byte key (hex)");
            Console.WriteLine("  --keyindex  01");
            Console.WriteLine("  --time      now (UTC)");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  PELplus.CLI --message \"This is a test message.\"");
            Console.WriteLine("  PELplus.CLI --key 0x000102...1e1f --keyindex 01 --time \"2025-08-07 10:30:45\" --message \"This is a ...\"");
            Console.WriteLine("  PELplus.CLI --license");
            Console.WriteLine();
        }


        private static void PrintTitle(string title)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
            Console.WriteLine("┃ " + title.PadRight(60) + " ┃");
            Console.WriteLine("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
            Console.ResetColor();
        }

        private static void PrintSection(string title)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("── " + title + " ─────────────────────────────────────────────────────");
            Console.ResetColor();
        }

        private static void PrintKV(string key, string value)
        {
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write(key + ": ");
            Console.ResetColor();
            Console.WriteLine(value);
        }

        private static void PrintFooter(string msg)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(msg);
            Console.ResetColor();
            Console.WriteLine();
        }

        private static void Error(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine("Error: " + msg);
            Console.ResetColor();
        }

        private static void PrintLicense()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("PELplus CLI – Transparent Encryption Tool");
            Console.ResetColor();
            Console.WriteLine("Version 1.0.0");
            Console.WriteLine();

            Console.WriteLine("MIT License");
            Console.WriteLine("Copyright (c) 2025 Florian Fuchs");
            Console.WriteLine();
            Console.WriteLine("Permission is hereby granted, free of charge, to any person obtaining a copy");
            Console.WriteLine("of this software and associated documentation files (the \"Software\"), to deal");
            Console.WriteLine("in the Software without restriction, including without limitation the rights");
            Console.WriteLine("to use, copy, modify, merge, publish, distribute, sublicense, and/or sell");
            Console.WriteLine("copies of the Software, and to permit persons to whom the Software is");
            Console.WriteLine("furnished to do so, subject to the following conditions:");
            Console.WriteLine();
            Console.WriteLine("The above copyright notice and this permission notice shall be included in all");
            Console.WriteLine("copies or substantial portions of the Software.");
            Console.WriteLine();
            Console.WriteLine("THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR");
            Console.WriteLine("IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,");
            Console.WriteLine("FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE");
            Console.WriteLine("AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER");
            Console.WriteLine("LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,");
            Console.WriteLine("OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE");
            Console.WriteLine("SOFTWARE.");
            Console.WriteLine();
        }

    }
}
