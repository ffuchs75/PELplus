using PELplus.Crypto.Encryption;
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

                // -------- Decrypt mode: ONLY --message and --key are allowed --------
                if (p.Decrypt)
                {
                    // Enforce exclusivity: no other flags allowed in decrypt mode
                    if (p.ShowHelp || p.ShowLicense || !string.IsNullOrWhiteSpace(p.KeyIndexHex) || p.UtcTime.HasValue)
                        throw new ArgumentException("In --decrypt mode, only --message and --key are allowed.");

                    if (string.IsNullOrWhiteSpace(p.Message))
                    {
                        Error("Parameter --message is required in --decrypt mode.");
                        PrintUsage();
                        return 2;
                    }

                    if (string.IsNullOrWhiteSpace(p.KeyHex))
                        throw new ArgumentException("Parameter --key is required in --decrypt mode.");

                    // Call decrypt() and exit
                    decrypt(p.Message, ValidateFixedLengthHex(p.KeyHex, 32));
                    return 0;
                }

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

                Encrypt encrypt = new Encrypt(message, keyHex, keyIndexHex, utcTime);

                // -------- 1) Timestamp for IV (little-endian hex) --------
                PrintSection("Timestamp / IV base");
                PrintKV("Timestamp LE (hex)  ", encrypt.Epoch2025Timestamp.BytesLittleEndianHex);

                // -------- 2) Build IV (unpadded) and then pad to 32 bytes --------
                PrintKV("IV (unpadded)       ", encrypt.IvHex);
                PrintKV("IV (padded 32 bytes)", encrypt.IvPadded);

                // -------- 3) Derive keys via CMAC-KDF (enc key + cmac key) --------

                // Print KDF details exactly as before; also expose enc/cmac key hex for later use
                string encKeyHex, cmacKeyHex;
                PrintKdfOverview(encrypt.CmacKdf, out encKeyHex, out cmacKeyHex);

                // -------- 4) UTF-8 encode & compress plaintext --------
                // IMPORTANT: we print both raw UTF-8 hex and compressed hex for full transparency.
                PrintSection("Plaintext & compression");
                PrintKV("Plaintext bytes (hex)    ", encrypt.PlainTextBytesHex);
                PrintKV("Compressed bytes (hex)   ", encrypt.CompressedPlainTextBytesHex);
                PrintKV("Compressed + padded (hex)", encrypt.CompressedPlainTextBytesPaddedHex);

                // -------- 5) AES-CTR encryption --------
                PrintSection("AES-CTR details (all blocks)");
                PrintAesBlocks(encrypt.AesCtrEncrypt); // centralize identical per-block printing logic

                PrintKV("Ciphertext (hex)", encrypt.AesCtrEncrypt.CiphertextHex);

                // -------- 6) CMAC over ciphertext (Encrypt-then-MAC) --------
                PrintSection("Checksums");
                PrintKV("CMAC (128-bit, hex) over ciphertext", HexConverter.ByteArrayToHexString(encrypt.AesCmac.Mac).ToLower());

                // -------- 7) CRC-8 over UNPADDED IV --------
                PrintKV("CRC-8 over IV                      ", encrypt.CrcHex);

                // -------- 8) Transmission composition --------
                PrintSection("Transmission");
                PrintKV("TX (hex)      ", encrypt.TransmissionHex);

                // -------- 9) Extra views: POCSAG Numeric + Base64 --------
                PrintKV("POCSAG Numeric", encrypt.TransmissionPocsagNumeric);
                PrintKV("Base64        ", encrypt.TransmissionBase64);

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
            public bool Decrypt;        // --decrypt
        }

        private static Params ParseArgs(string[] args)
        {
            /*
             * Supported flags:
             *   --key <hex>                   32-byte hex key; accepts "0x" and spaces
             *   --keyindex <hex2>             one byte hex (default "01")
             *   --time "YYYY-MM-DD HH:mm:ss"  UTC time; default now
             *   --message "<text>"            required
             *   --decrypt                     decrypt mode (only with --message and --key)
             *   -h | --help                   show usage
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
                else if (a == "--decrypt")
                {
                    p.Decrypt = true;
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
        /// Validate a provided hex string to be exactly lenBytes long (no auto-generation).
        /// Returns normalized lower-case hex.
        /// </summary>
        private static string ValidateFixedLengthHex(string maybeHex, int lenBytes)
        {
            string h = NormalizeHex(maybeHex);
            if (string.IsNullOrWhiteSpace(h))
                throw new ArgumentException("Required hex value is missing.");

            if (h.Length != lenBytes * 2)
                throw new ArgumentException("Key must be " + lenBytes + " bytes (" + (lenBytes * 2) + " hex chars).");

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
                return LowerHex(HexConverter.ByteArrayToHexString(key));
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
            Console.WriteLine("  PELplus.CLI --decrypt --message \"<text>\" --key <hex32bytes>   (only these two flags allowed)");
            Console.WriteLine("  PELplus.CLI --help");
            Console.WriteLine("  PELplus.CLI --license");
            Console.WriteLine();
            Console.WriteLine("Defaults:");
            Console.WriteLine("  --key       random 32-byte key (hex)   [encrypt mode only]");
            Console.WriteLine("  --keyindex  01                         [encrypt mode only]");
            Console.WriteLine("  --time      now (UTC)                  [encrypt mode only]");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  PELplus.CLI --message \"This is a test message.\"");
            Console.WriteLine("  PELplus.CLI --key 0x000102...1e1f --keyindex 01 --time \"2025-08-07 10:30:45\" --message \"This is a ...\"");
            Console.WriteLine("  PELplus.CLI --decrypt --message \"...\" --key 0x000102...1e1f");
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

        // =============================== Decrypt stub ===============================
        /// <summary>
        /// Decrypt mode entry point. 
        /// </summary>
        private static void decrypt(string message, string keyHex)
        {
            // -------- Pretty header --------
            PrintTitle("PELplus – POCSAG Encryption");
            PrintKV("Message  ", message);
            PrintKV("Key (hex)", keyHex);

            PrintSection("Extract parameters from transmission");
            Transmission transmission = new Transmission(message);

            PrintKV("Transmission type    ", transmission.EncodingType.ToString());

            // if the message is not encrypted, exit
            if (transmission.EncodingType == TransmissionEncoding.Unencrypted)
            {
                return;
            }

            PrintKV("Complete Transmission", transmission.RawFrameHex);
            PrintKV("IV unpadded          ", transmission.IvUnpaddedHex);
            PrintKV("IV padded            ", transmission.IvPaddedHex);
            PrintKV("Timestamp            ", transmission.TimestampHex);
            PrintKV("Timestamp UTC        ", transmission.TimestampUtc.ToString());
            PrintKV("Timestamp Local      ", transmission.TimestampLocal.ToString());
            PrintKV("Key Index            ", transmission.KeyIndexHex);
            PrintKV("Transmitted Crc8     ", transmission.TransmittedCrc8Hex);
            PrintKV("Actual Crc8          ", transmission.ActualCrc8Hex);
            PrintKV("Has Valid Crc8       ", transmission.HasValidCrc8.ToString());
            PrintKV("Transmitted CMAC     ", transmission.MacTruncHex);
            PrintKV("Cipher Text          ", transmission.CiphertextHex);

            // check if the crc is valid
            if (transmission.HasValidCrc8 == false)
            {
                Console.WriteLine("\nSince the CRC8 is void, treat the message as unencrypted.");
                return;
            }

            // -------- 2) Derive keys via CMAC-KDF (enc key + cmac key) --------
            CmacKdf kdf = new CmacKdf(keyHex, transmission.IvPaddedHex);

            // Print KDF and expose enc/cmac key hex
            string encKeyHex, cmacKeyHex;
            PrintKdfOverview(kdf, out encKeyHex, out cmacKeyHex);

            try
            {
                // decrypt
                Decrypt decrypt = new Decrypt(message, keyHex);

                // -------- 3) Decrypt --------
                PrintSection("Decryption");

                // Print EVERY block (counter & keystream) to support arbitrarily long messages.
                PrintAesBlocks(decrypt.AesCtrDecrypt, true);

                PrintKV("Plaintext HEX             ", decrypt.AesCtrDecrypt.CiphertextHex);

                // uncompress
                PrintKV("Plaintext HEX uncompressed", decrypt.PlainTextBytesHex.ToLower());

                // get text
                PrintKV("Plaintext                 ", decrypt.PlainText);

                // -------- 4) CMAC --------
                // CMAC
                PrintSection("CMAC");
                AesCmac aesCmac = new AesCmac(cmacKeyHex, transmission.CiphertextHex);

                // Compute once, reuse (avoids duplicate conversions and substring twice)
                string macFullLower = LowerHex(HexConverter.ByteArrayToHexString(aesCmac.Mac));
                string macTruncLower = macFullLower.Substring(0, 8);

                PrintKV("Actual CMAC               ", macTruncLower);

                bool hasValidCmac = macTruncLower == transmission.MacTruncHex;
                PrintKV("Has Valid CMAC            ", hasValidCmac.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine(ex.Message);
                Console.WriteLine("Treat the message as unencrypted.");
            }

            PrintFooter("Done.");
        }

        // =============================== Small helpers to remove duplication ===============================

        /// <summary>
        /// Convert a byte[] to lowercase hex using the project's HexConverter,
        /// ensuring one canonical representation across the codebase.
        /// </summary>
        private static string LowerHex(byte[] bytes)
        {
            // Using ToLowerInvariant() avoids culture-specific casing rules.
            return HexConverter.ByteArrayToHexString(bytes).ToLowerInvariant();
        }

        /// <summary>
        /// Ensure a hex string is lowercase (no-op for null).
        /// </summary>
        private static string LowerHex(string hex)
        {
            return hex == null ? null : hex.ToLowerInvariant();
        }

        /// <summary>
        /// Print the full CMAC-KDF derivation details EXACTLY like before
        /// and hand back the two operational keys as lowercase hex.
        /// 
        /// Why safe:
        /// - We only factor out previously duplicated computations/prints.
        /// - Output order, separators, and labels are preserved 1:1.
        /// </summary>
        private static void PrintKdfOverview(CmacKdf kdf, out string encKeyHex, out string cmacKeyHex)
        {
            // Precompute all values once, then print.
            string prkHi = LowerHex(kdf.Cmac1a);
            string prkLo = LowerHex(kdf.Cmac1b);
            string prk = LowerHex(kdf.Prk);
            string encKeyHi = LowerHex(kdf.T1);
            string encKeyLo = LowerHex(kdf.T2);
            string cmacKeyHi = LowerHex(kdf.T3);
            string cmacKeyLo = LowerHex(kdf.T4);

            encKeyHex = LowerHex(kdf.EncryptionKey);
            cmacKeyHex = LowerHex(kdf.CmacKey);

            PrintSection("Key derivation (CMAC-KDF)");
            PrintKV("PRKhi         ", prkHi);
            PrintKV("PRKlo         ", prkLo);
            PrintKV("PRK           ", prk);
            Console.WriteLine(new string('-', 60));
            PrintKV("EncKeyhi      ", encKeyHi);
            PrintKV("EncKeylo      ", encKeyLo);
            PrintKV("Encryption Key", encKeyHex);
            Console.WriteLine(new string('-', 60));
            PrintKV("CmacKeyhi     ", cmacKeyHi);
            PrintKV("CmacKeylo     ", cmacKeyLo);
            PrintKV("CMAC Key      ", cmacKeyHex);
        }

        /// <summary>
        /// Print all CTR blocks with identical formatting for both encrypt and decrypt paths.
        /// 
        /// Why safe:
        /// - It preserves the exact label text and order used before.
        /// - Only centralizes the loop to avoid code duplication and subtle divergences.
        /// </summary>
        private static void PrintAesBlocks(AesCtrEncrypt aes, bool decrypt = false)
        {
            int blockCount = aes.Blocks.Count();
            for (int i = 0; i < blockCount; i++)
            {
                string counterHex = LowerHex(HexConverter.ByteArrayToHexString(aes.Blocks[i].CounterBlock));
                string ksHex = LowerHex(HexConverter.ByteArrayToHexString(aes.Blocks[i].KeystreamBlock));
                string cipherTextPortion = LowerHex(HexConverter.ByteArrayToHexString(aes.Blocks[i].CiphertextPortion));
                string plainTextPortion = LowerHex(HexConverter.ByteArrayToHexString(aes.Blocks[i].PlaintextPortion));

                // Use a compact, aligned output; large messages remain readable.
                PrintKV(string.Format("Counter[{0}]          ", i), counterHex);
                PrintKV(string.Format("Keystream[{0}]        ", i), ksHex);

                if (decrypt == false)
                {
                    PrintKV(string.Format("Plaintext[{0}]        ", i), plainTextPortion);
                    PrintKV(string.Format("CipherTextPortion[{0}]", i), cipherTextPortion);
                }
                else
                {
                    PrintKV(string.Format("CipherTextPortion[{0}]", i), plainTextPortion);
                    PrintKV(string.Format("Plaintext[{0}]        ", i), cipherTextPortion);
                }

                    // Separator line for readability between blocks
                    Console.WriteLine(new string('-', 60));
            }
        }

        // ============================================================================
        // End of helpers
        // ============================================================================
    }
}
