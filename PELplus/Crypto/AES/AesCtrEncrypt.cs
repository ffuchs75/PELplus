using System;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// AES-CTR encryption (classic): consumes the FULL 16 bytes of every AES-ECB keystream block.
/// No bytes are skipped or discarded; the keystream covers the plaintext length exactly.
/// 
/// - Key/IV/Plaintext: accept byte[] or hex string (supports "0x", per-byte "0x", spaces; odd hex handled).
/// - IV ≤ 96 bits (12 bytes). If shorter, RIGHT-pad with 0x00 to 12 bytes; counter is 32-bit BE appended.
/// - Counter increments in big-endian across bytes [12..15].
/// - Output length equals input length (byte path). Odd-length hex is XORed nibble-wise against hex keystream.
/// 
/// Tracing properties expose the internal counter/keystream for debugging/analysis:
///   - CounterStream: concatenation of all 16-byte counter blocks used
///   - KeystreamStream: concatenation of all used keystream bytes 
///   - Blocks: per-block view (CounterBlock, KeystreamBlock, KeystreamUsedPortion, CiphertextPortion, PlaintextPortion)
/// 
/// NOTE: In CTR, encryption == decryption (XOR with keystream).
/// </summary>
public sealed class AesCtrEncrypt
{
    private readonly byte[] _key;                // AES key (16/24/32 bytes)
    private readonly byte[] _nonce96;            // 96-bit nonce (12 bytes, right-padded if shorter)
    private readonly byte[] _counterBlockInit;   // Initial counter = nonce96 || 0x00000000
    private readonly byte[] _ciphertextBytes;    // Ciphertext as bytes
    private readonly string _ciphertextHex;      // Ciphertext as lowercase hex

    // --- tracing fields ---
    private readonly byte[] _counterStream;      // All 16-byte counter blocks concatenated
    private readonly byte[] _keystreamStream;    // All actually used keystream bytes concatenated
    private readonly AesCtrBlockInfo[] _blocks;  // Per-block info with counter/keystream/used-slice + cipher/plain slices

    /// <summary>Defensive copy of the initial 16-byte counter block.</summary>
    public byte[] InitialCounterBlock { get { var c = new byte[16]; Buffer.BlockCopy(_counterBlockInit, 0, c, 0, 16); return c; } }

    /// <summary>Defensive copy of ciphertext bytes.</summary>
    public byte[] Ciphertext { get { var c = new byte[_ciphertextBytes.Length]; Buffer.BlockCopy(_ciphertextBytes, 0, c, 0, _ciphertextBytes.Length); return c; } }

    /// <summary>Ciphertext as lowercase hex (no spaces, no 0x).</summary>
    public string CiphertextHex => _ciphertextHex;

    /// <summary>
    /// Concatenation of all 16-byte counter blocks used to produce the keystream.
    /// Useful to audit which counter values (IV||ctr32) were fed into AES-ECB.
    /// </summary>
    public byte[] CounterStream { get { var c = new byte[_counterStream.Length]; Buffer.BlockCopy(_counterStream, 0, c, 0, _counterStream.Length); return c; } }

    /// <summary>
    /// Concatenation of all actually used keystream bytes (full 16 per block, except possibly the last).
    /// Length matches the number of needed keystream bytes (i.e., plaintext length for byte path,
    /// or ceil(nibbles/2) for odd-length hex path).
    /// </summary>
    public byte[] KeystreamStream { get { var c = new byte[_keystreamStream.Length]; Buffer.BlockCopy(_keystreamStream, 0, c, 0, _keystreamStream.Length); return c; } }

    /// <summary>
    /// Per-block trace. For each AES-CTR block you get:
    ///  - CounterBlock (16 bytes)
    ///  - KeystreamBlock (16 bytes, raw AES-ECB output)
    ///  - KeystreamUsedPortion (the portion actually consumed from this block, up to 16 bytes;
    ///    for the last block this may be shorter if fewer bytes are required).
    ///  - CiphertextPortion (cipher bytes produced in this block; same length as KeystreamUsedPortion)
    ///  - PlaintextPortion (plain bytes consumed in this block; same length as KeystreamUsedPortion)
    /// </summary>
    public AesCtrBlockInfo[] Blocks
    {
        get
        {
            var copy = new AesCtrBlockInfo[_blocks.Length];
            for (int i = 0; i < copy.Length; i++) copy[i] = _blocks[i].Clone();
            return copy;
        }
    }

    /// <summary>
    /// Constructor: normalizes inputs, generates classical CTR keystream (full 16 bytes per block),
    /// and XORs with plaintext (byte-wise or nibble-wise depending on input).
    /// Also records tracing information (counter stream, keystream stream, per-block info incl. ciphertext/plaintext portions).
    /// </summary>
    public AesCtrEncrypt(object key, object iv, object plaintext)
    {
        _key = NormalizeKeyFlexible(key);                 // 16/24/32 bytes
        _nonce96 = NormalizeNonce96Flexible(iv);          // ≤12 → right-pad to 12
        _counterBlockInit = BuildCounterBlock(_nonce96);  // nonce96 || 00000000

        if (plaintext is byte[] pb)
        {
            // --- BYTE path (plain bytes directly) ---
            var pt = (byte[])pb.Clone();

            // Generate keystream + tracing for exactly pt.Length bytes (full 16 per block)
            var trace = GenerateKeystreamClassic_WithTracing(_key, _counterBlockInit, pt.Length);
            _keystreamStream = trace.Keystream;
            _counterStream = trace.CounterStream;

            // XOR to produce ciphertext
            _ciphertextBytes = XorByteWise(pt, _keystreamStream);
            _ciphertextHex = ToHexLower(_ciphertextBytes);

            // Attach both ciphertext and plaintext slices to each block
            _blocks = AttachCiphertextAndPlaintextPortions(trace.Blocks, _ciphertextBytes, pt);
        }
        else if (plaintext is string ps)
        {
            // --- HEX path (string): allow odd number of hex nibbles → nibble-wise XOR against hex keystream ---
            string ptHexPlain = NormalizeHexToPlain(ps);
            int nibbles = ptHexPlain.Length;

            if ((nibbles % 2) == 0)
            {
                // Even-length hex → byte-wise processing
                byte[] pt = HexConverter.HexStringToByteArray(ptHexPlain);

                var trace = GenerateKeystreamClassic_WithTracing(_key, _counterBlockInit, pt.Length);
                _keystreamStream = trace.Keystream;
                _counterStream = trace.CounterStream;

                _ciphertextBytes = XorByteWise(pt, _keystreamStream);
                _ciphertextHex = ToHexLower(_ciphertextBytes);

                _blocks = AttachCiphertextAndPlaintextPortions(trace.Blocks, _ciphertextBytes, pt);
            }
            else
            {
                // Odd-length hex → need ceil(nibbles/2) keystream BYTES, then XOR per nibble
                int ksBytesNeeded = (nibbles + 1) / 2;

                var trace = GenerateKeystreamClassic_WithTracing(_key, _counterBlockInit, ksBytesNeeded);
                _keystreamStream = trace.Keystream;
                _counterStream = trace.CounterStream;

                // Nibble-wise XOR to produce hex ciphertext of exact nibble length
                string ksHex = ToHexLower(_keystreamStream);
                string ctHexOdd = XorHexNibbleWise(ptHexPlain, ksHex, nibbles);
                _ciphertextHex = ctHexOdd;

                // Build ciphertext bytes (pad with leading '0' if odd number of hex digits)
                string ctHexForBytes = (ctHexOdd.Length % 2 == 0) ? ctHexOdd : "0" + ctHexOdd;
                _ciphertextBytes = HexConverter.HexStringToByteArray(ctHexForBytes);

                // Build "byte view" of plaintext to slice per block (mirror the padding rule used for ct bytes)
                string ptHexForBytes = ((ptHexPlain.Length % 2) == 0) ? ptHexPlain : "0" + ptHexPlain;
                byte[] ptBytesForBlocks = HexConverter.HexStringToByteArray(ptHexForBytes);

                _blocks = AttachCiphertextAndPlaintextPortions(trace.Blocks, _ciphertextBytes, ptBytesForBlocks);
            }
        }
        else
        {
            throw new ArgumentException("plaintext must be a byte[] or hex string.", nameof(plaintext));
        }
    }

    // =========================================================================
    // Attach both ciphertext and plaintext slices to each block (slice length = KeystreamUsedPortion length)
    // =========================================================================
    private static AesCtrBlockInfo[] AttachCiphertextAndPlaintextPortions(AesCtrBlockInfo[] blocks, byte[] fullCiphertext, byte[] fullPlaintext)
    {
        var outBlocks = new AesCtrBlockInfo[blocks.Length];
        int offset = 0;
        for (int i = 0; i < blocks.Length; i++)
        {
            int take = blocks[i].KeystreamUsedPortion.Length;

            var ctSlice = new byte[take];
            var ptSlice = new byte[take];

            if (take > 0)
            {
                Buffer.BlockCopy(fullCiphertext, offset, ctSlice, 0, take);
                Buffer.BlockCopy(fullPlaintext, offset, ptSlice, 0, take);
                offset += take;
            }

            // Reconstruct a new block object that also carries ciphertext and plaintext portions
            outBlocks[i] = new AesCtrBlockInfo(
                blocks[i].Index,
                blocks[i].CounterBlock,
                blocks[i].KeystreamBlock,
                blocks[i].KeystreamUsedPortion,
                ctSlice,
                ptSlice
            );
        }
        return outBlocks;
    }


    /// <summary>
    /// Generate <paramref name="count"/> keystream bytes by encrypting successive counter blocks
    /// and consuming ALL 16 bytes from each block, except possibly a shorter tail on the last block.
    /// Captures:
    ///   - the concatenated counter blocks used,
    ///   - the raw AES keystream blocks,
    ///   - the actually used slice from each block (up to 16 bytes).
    ///   (Ciphertext/Plaintext slices are attached later after XOR.)
    /// </summary>
    private static KeystreamTrace GenerateKeystreamClassic_WithTracing(byte[] key, byte[] counterBlockInit, int count)
    {
        if (count <= 0)
        {
            return new KeystreamTrace(new byte[0], new byte[0], new AesCtrBlockInfo[0]);
        }

        // Accumulators for streams
        var ksOut = new byte[count];
        var counterBlocks = new System.Collections.Generic.List<byte>();
        var blocks = new System.Collections.Generic.List<AesCtrBlockInfo>();

        int produced = 0;

        using (var aes = new AesManaged())
        {
            // Configure AES-ECB (CTR is built manually)
            aes.KeySize = key.Length * 8;   // 128/192/256
            aes.BlockSize = 128;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = (byte[])key.Clone();
            aes.IV = new byte[16];         // unused in ECB

            using (var encryptor = aes.CreateEncryptor())
            {
                byte[] counter = (byte[])counterBlockInit.Clone();
                byte[] ksBlock = new byte[16];

                while (produced < count)
                {
                    // Append current counter block to "counter stream"
                    counterBlocks.AddRange(counter);

                    // Encrypt counter block to get one 16-byte keystream block
                    int written = encryptor.TransformBlock(counter, 0, 16, ksBlock, 0);
                    if (written != 16) throw new CryptographicException("Unexpected keystream block length.");

                    // Take up to 16 bytes from this block
                    int remaining = count - produced;
                    int take = Math.Min(16, remaining);

                    // Copy the used portion into the overall keystream
                    Buffer.BlockCopy(ksBlock, 0, ksOut, produced, take);

                    // Record per-block info (defensive copies). Cipher/Plain slices are attached later.
                    var counterCopy = new byte[16]; Buffer.BlockCopy(counter, 0, counterCopy, 0, 16);
                    var ksBlockCopy = new byte[16]; Buffer.BlockCopy(ksBlock, 0, ksBlockCopy, 0, 16);
                    var usedPortion = new byte[take]; Buffer.BlockCopy(ksBlock, 0, usedPortion, 0, take);

                    blocks.Add(new AesCtrBlockInfo(
                        blockIndex: blocks.Count,
                        counterBlock: counterCopy,
                        keystreamBlock: ksBlockCopy,
                        keystreamUsedPortion: usedPortion,
                        ciphertextPortion: new byte[0],     // filled later
                        plaintextPortion: new byte[0]       // filled later
                    ));

                    produced += take;

                    // Increment 32-bit big-endian counter at bytes [12..15]
                    IncrementCounter32Be(counter);
                }
            }
        }

        // Materialize counter stream as a contiguous byte[] (16 bytes per block)
        byte[] counterStream = counterBlocks.ToArray();
        return new KeystreamTrace(ksOut, counterStream, blocks.ToArray());
    }

    // =========================================================================
    // XOR helpers
    // =========================================================================
    /// <summary>
    /// XOR two same-length byte arrays. Returns a new array.
    /// </summary>
    private static byte[] XorByteWise(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) throw new ArgumentException("XOR length mismatch.");
        byte[] r = new byte[a.Length];
        for (int i = 0; i < a.Length; i++) r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }

    /// <summary>
    /// XOR hex-encoded plaintext and hex-encoded keystream nibble-by-nibble.
    /// Length in nibbles is specified by <paramref name="nibbles"/>.
    /// </summary>
    private static string XorHexNibbleWise(string ptHex, string ksHex, int nibbles)
    {
        var sb = new StringBuilder(nibbles);
        for (int i = 0; i < nibbles; i++)
        {
            int a = HexNibbleToInt(ptHex[i]);
            int b = HexNibbleToInt(ksHex[i]);
            sb.Append("0123456789abcdef"[(a ^ b) & 0xF]);
        }
        return sb.ToString();
    }

    // =========================================================================
    // Counter increment (32-bit BE at bytes 12..15)
    // =========================================================================
    /// <summary>
    /// Increment bytes [12..15] as a 32-bit big-endian counter.
    /// </summary>
    private static void IncrementCounter32Be(byte[] counter)
    {
        for (int i = 15; i >= 12; i--)
        {
            unchecked { counter[i]++; if (counter[i] != 0x00) break; }
        }
    }

    // =========================================================================
    // Normalization + HEX helpers
    // =========================================================================
    /// <summary>
    /// Normalize AES key from byte[] or hex string. Must be 16/24/32 bytes.
    /// </summary>
    private static byte[] NormalizeKeyFlexible(object key)
    {
        byte[] k;
        if (key is byte[] b) k = (byte[])b.Clone();
        else if (key is string s) k = HexConverter.HexStringToByteArray(NormalizeHexToPlainEven(s));
        else throw new ArgumentException("key must be a byte[] or hex string.", nameof(key));
        if (k.Length != 16 && k.Length != 24 && k.Length != 32)
            throw new ArgumentException("AES key must be 16, 24, or 32 bytes.", nameof(key));
        return k;
    }

    /// <summary>
    /// Normalize IV (nonce) to exactly 12 bytes: accept ≤12, right-pad with zeros if shorter.
    /// </summary>
    private static byte[] NormalizeNonce96Flexible(object iv)
    {
        byte[] raw;
        if (iv is byte[] b) raw = (byte[])b.Clone();
        else if (iv is string s) raw = HexConverter.HexStringToByteArray(NormalizeHexToPlainEven(s));
        else throw new ArgumentException("iv must be a byte[] or hex string.", nameof(iv));

        if (raw.Length > 12) throw new ArgumentException("IV must be at most 12 bytes.", nameof(iv));
        if (raw.Length == 12) return raw;

        var padded = new byte[12];
        Buffer.BlockCopy(raw, 0, padded, 0, raw.Length); // right-pad with 0x00
        return padded;
    }

    /// <summary>
    /// Build initial 16-byte counter block: nonce96 || 0x00000000.
    /// </summary>
    private static byte[] BuildCounterBlock(byte[] nonce96)
    {
        var block = new byte[16];
        Buffer.BlockCopy(nonce96, 0, block, 0, 12);
        return block;
    }

    /// <summary>
    /// Strip spaces and any "0x"/"0X" tokens from a hex string (no evenness enforced).
    /// </summary>
    private static string NormalizeHexToPlain(string hex)
    {
        if (hex == null) throw new ArgumentNullException(nameof(hex));
        string h = hex.Trim().Replace(" ", "");
        var parts = h.Split(new[] { "0x", "0X" }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return h;
        var sb = new StringBuilder();
        foreach (var p in parts) sb.Append(p);
        return sb.ToString();
    }

    /// <summary>
    /// Normalize hex and ensure an even number of characters (pad with a leading '0' if required).
    /// </summary>
    private static string NormalizeHexToPlainEven(string hex)
    {
        string p = NormalizeHexToPlain(hex);
        if ((p.Length % 2) != 0) p = "0" + p;
        return p;
    }

    /// <summary>
    /// Convert a single hex nibble to its integer value 0..15.
    /// </summary>
    private static int HexNibbleToInt(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        throw new ArgumentException("Invalid hex nibble '" + c + "'.");
    }

    /// <summary>
    /// Convert byte array to lowercase hex string.
    /// </summary>
    private static string ToHexLower(byte[] data) =>
        HexConverter.ByteArrayToHexString(data, uppercase: false, withPrefix: false);

    // =========================================================================
    // Trace DTOs (immutable)
    // =========================================================================
    /// <summary>
    /// Immutable per-block trace container: holds the exact counter block, the raw keystream
    /// block (AES-ECB output), the actually-used portion from this block (up to 16 bytes),
    /// the ciphertext portion produced from this block, and the corresponding plaintext portion.
    /// </summary>
    public sealed class AesCtrBlockInfo
    {
        public int Index { get; }
        public byte[] CounterBlock { get; }
        public byte[] KeystreamBlock { get; }
        public byte[] KeystreamUsedPortion { get; }

        /// <summary>The ciphertext bytes produced from this block (same length as KeystreamUsedPortion).</summary>
        public byte[] CiphertextPortion { get; }

        /// <summary>The plaintext bytes consumed in this block (same length as KeystreamUsedPortion).</summary>
        public byte[] PlaintextPortion { get; }

        public AesCtrBlockInfo(int blockIndex, byte[] counterBlock, byte[] keystreamBlock, byte[] keystreamUsedPortion, byte[] ciphertextPortion, byte[] plaintextPortion)
        {
            Index = blockIndex;

            CounterBlock = new byte[counterBlock.Length];
            Buffer.BlockCopy(counterBlock, 0, CounterBlock, 0, counterBlock.Length);

            KeystreamBlock = new byte[keystreamBlock.Length];
            Buffer.BlockCopy(keystreamBlock, 0, KeystreamBlock, 0, keystreamBlock.Length);

            KeystreamUsedPortion = new byte[keystreamUsedPortion.Length];
            Buffer.BlockCopy(keystreamUsedPortion, 0, KeystreamUsedPortion, 0, keystreamUsedPortion.Length);

            CiphertextPortion = new byte[ciphertextPortion.Length];
            Buffer.BlockCopy(ciphertextPortion, 0, CiphertextPortion, 0, ciphertextPortion.Length);

            PlaintextPortion = new byte[plaintextPortion.Length];
            Buffer.BlockCopy(plaintextPortion, 0, PlaintextPortion, 0, plaintextPortion.Length);
        }

        internal AesCtrBlockInfo Clone() =>
            new AesCtrBlockInfo(Index, CounterBlock, KeystreamBlock, KeystreamUsedPortion, CiphertextPortion, PlaintextPortion);
    }

    /// <summary>
    /// Immutable aggregate trace returned internally when generating the keystream.
    /// </summary>
    private sealed class KeystreamTrace
    {
        public byte[] Keystream { get; }
        public byte[] CounterStream { get; }
        public AesCtrBlockInfo[] Blocks { get; }

        public KeystreamTrace(byte[] keystream, byte[] counterStream, AesCtrBlockInfo[] blocks)
        {
            Keystream = keystream;
            CounterStream = counterStream;
            Blocks = blocks;
        }
    }
}
