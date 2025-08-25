# PELplus.CLI

The POCSAG Encryption Library plus Command Line Interface is a **reference implementation** for the POCSAG encryption 
as described in the draft of the German TR BOS.  
It was designed purely for **educational and analysis purposes**, **not** for production use.

## Security Disclaimer

> [!WARNING]
>
> **Do NOT use this tool in production environments.**  
> - It is **not reviewed**, **not hardened**, and **not intended** to provide real-world security.  
> - The code is meant for developers, researchers, or students who want to study the internal workings of the POCSAG encryption.  
> - There are no guarantees of correctness, confidentiality, integrity, or security.

## Requirements

- dotNetFramework 4.7 or higher

## Usage

```bash
  PELplus.CLI --message "<text>" [--key <hex32bytes>] [--keyindex <hex2>] [--time "YYYY-MM-DD HH:mm:ss"]
  PELplus.CLI --decrypt --message "<text>" --key <hex32bytes>   (only these two flags allowed)
  PELplus.CLI --help
  PELplus.CLI --license
```

### Options

- `--message`   Message to encrypt or decrypt (mandatory).
- `--key`       256 bit AES key in hex. If omitted, a random key is generated.
- `--keyindex`  Key index (default: `01`). [encrypt mode only]
- `--time`      UTC timestamp (`YYYY-MM-DD HH:mm:ss`). Defaults to current UTC. [encrypt mode only]
- `--license`   Show license information.
- `--decrypt`   Decrypt a message.

### Examples

```bash
PELplus.CLI --message "This is a test message."
PELplus.CLI --key 0x000102...1e1f --keyindex 01 --time "2025-08-07 10:30:45" --message "Secret payload"
PELplus.CLI --decrypt --message "..." --key 0x000102...1e1f
PELplus.CLI --license
```



#### Encrypt a message

```bash
PELplusCLI.exe --message "Probealarm, Leitstelle nicht anrufen" --key 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --time "2025-08-07 10:30:45"

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  PELplus – POCSAG Encryption                           
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
Message  : Probealarm, Leitstelle nicht anrufen
UTC time : 2025-08-07 10:30:45
KeyIndex : 01
Key (hex): 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

── Timestamp / IV base ─────────────────────────────────────────────────────
Timestamp LE (hex)  : d5fa1f01
IV (unpadded)       : d5fa1f0101
IV (padded 32 bytes): d5fa1f0101000000000000000000000000000000000000000000000000000000

── Key derivation (CMAC-KDF) ─────────────────────────────────────────────────────
PRKhi         : 9689a6e10c4a14d726d6e0ec56d2e22b
PRKlo         : 2ef2e7acca205cbfb55f924f5b9a5bca
PRK           : 9689a6e10c4a14d726d6e0ec56d2e22b2ef2e7acca205cbfb55f924f5b9a5bca
------------------------------------------------------------
EncKeyhi      : eedeaba836d9eb1584d6e4e11765c20f
EncKeylo      : 3b7777579cbbf0c8df6c9202894b5633
Encryption Key: eedeaba836d9eb1584d6e4e11765c20f3b7777579cbbf0c8df6c9202894b5633
------------------------------------------------------------
CmacKeyhi     : 1a6220a89cffa76f327bda8e4cb4c9ec
CmacKeylo     : 19013556e2753eb1f23f7744b603b0e5
CMAC Key      : 1a6220a89cffa76f327bda8e4cb4c9ec19013556e2753eb1f23f7744b603b0e5

── Plaintext & compression ─────────────────────────────────────────────────────
Plaintext bytes (hex)    : 50726f6265616c61726d2c204c6569747374656c6c65206e6963687420616e727566656e
Compressed bytes (hex)   : 0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0
Compressed + padded (hex): 0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0000000

── AES-CTR details (all blocks) ─────────────────────────────────────────────────────
Counter[0]          : d5fa1f01010000000000000000000000
Keystream[0]        : 307d22c8181de78b1182a75112f3aed8
Plaintext[0]        : 0a9fda3a70cdc34f6cd02334e597ce5e
CipherTextPortion[0]: 3ae2f8f268d024c47d528465f7646086
------------------------------------------------------------
Counter[1]          : d5fa1f01010000000000000000000001
Keystream[1]        : c790166c13618592e181fdcbf1a7d192
Plaintext[1]        : 99b374c13b978c597050dda7aece9bb0
CipherTextPortion[1]: 5e2362ad28f609cb91d1206c5f694a22
------------------------------------------------------------
Counter[2]          : d5fa1f01010000000000000000000002
Keystream[2]        : 9c85deb5db7caa84d44bdd0517dd1799
Plaintext[2]        : 000000
CipherTextPortion[2]: 9c85de
------------------------------------------------------------
Ciphertext (hex): 3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de

── Checksums ─────────────────────────────────────────────────────
CMAC (128-bit, hex) over ciphertext: 81256a9a2c8267023bf33a4d9dd7c13c
CRC-8 over IV                      : e8

── Transmission ─────────────────────────────────────────────────────
TX (hex)      : d5fa1f0101e881256a9a3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de
POCSAG Numeric: U*[58[080871184*6595 574[1[461U04232]U*4126*[]626016*74 645U41[6093-98U84063*[692544931*U7
Base64        : 1fofAQHogSVqmjri+PJo0CTEfVKEZfdkYIZeI2KtKPYJy5HRIGxfaUoinIXe

Done.
```



#### Decrypt a POCSAG Numeric message

```bash
PELplusCLI.exe --message "U*[58[080871184*6595 574[1[461U04232]U*4126*[]626016*74 645U41[6093-98U84063*[692544931*U7" --key 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --decrypt

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  PELplus – POCSAG Encryption                            
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
Message  : U*[58[080871184*6595 574[1[461U04232]U*4126*[]626016*74 645U41[6093-98U84063*[692544931*U7
Key (hex): 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

── Extract parameters from transmission ─────────────────────────────────────────────────────
Transmission type    : PocsagNumeric
Complete Transmission: d5fa1f0101e881256a9a3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de
IV unpadded          : d5fa1f0101
IV padded            : d5fa1f0101000000000000000000000000000000000000000000000000000000
Timestamp            : d5fa1f01
Timestamp UTC        : 07.08.2025 10:30:45
Timestamp Local      : 07.08.2025 12:30:45
Key Index            : 01
Transmitted Crc8     : e8
Actual Crc8          : e8
Has Valid Crc8       : True
Transmitted CMAC     : 81256a9a
Cipher Text          : 3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de

── Key derivation (CMAC-KDF) ─────────────────────────────────────────────────────
PRKhi         : 9689a6e10c4a14d726d6e0ec56d2e22b
PRKlo         : 2ef2e7acca205cbfb55f924f5b9a5bca
PRK           : 9689a6e10c4a14d726d6e0ec56d2e22b2ef2e7acca205cbfb55f924f5b9a5bca
------------------------------------------------------------
EncKeyhi      : eedeaba836d9eb1584d6e4e11765c20f
EncKeylo      : 3b7777579cbbf0c8df6c9202894b5633
Encryption Key: eedeaba836d9eb1584d6e4e11765c20f3b7777579cbbf0c8df6c9202894b5633
------------------------------------------------------------
CmacKeyhi     : 1a6220a89cffa76f327bda8e4cb4c9ec
CmacKeylo     : 19013556e2753eb1f23f7744b603b0e5
CMAC Key      : 1a6220a89cffa76f327bda8e4cb4c9ec19013556e2753eb1f23f7744b603b0e5

── Decryption ─────────────────────────────────────────────────────
Counter[0]          : d5fa1f01010000000000000000000000
Keystream[0]        : 307d22c8181de78b1182a75112f3aed8
CipherTextPortion[0]: 3ae2f8f268d024c47d528465f7646086
Plaintext[0]        : 0a9fda3a70cdc34f6cd02334e597ce5e
------------------------------------------------------------
Counter[1]          : d5fa1f01010000000000000000000001
Keystream[1]        : c790166c13618592e181fdcbf1a7d192
CipherTextPortion[1]: 5e2362ad28f609cb91d1206c5f694a22
Plaintext[1]        : 99b374c13b978c597050dda7aece9bb0
------------------------------------------------------------
Counter[2]          : d5fa1f01010000000000000000000002
Keystream[2]        : 9c85deb5db7caa84d44bdd0517dd1799
CipherTextPortion[2]: 9c85de
Plaintext[2]        : 000000
------------------------------------------------------------
Plaintext HEX             : 0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0000000
Plaintext HEX uncompressed: 50726f6265616c61726d2c204c6569747374656c6c65206e6963687420616e727566656e
Plaintext                 : Probealarm, Leitstelle nicht anrufen

── CMAC ─────────────────────────────────────────────────────
Actual CMAC               : 81256a9a
Has Valid CMAC            : True

Done.
```



#### Decrypt a BASE64 message

```bash
PELplusCLI.exe --message "1fofAQHogSVqmjri+PJo0CTEfVKEZfdkYIZeI2KtKPYJy5HRIGxfaUoinIXe" --key 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --decrypt

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  PELplus – POCSAG Encryption                            
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
Message  : 1fofAQHogSVqmjri+PJo0CTEfVKEZfdkYIZeI2KtKPYJy5HRIGxfaUoinIXe
Key (hex): 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

── Extract parameters from transmission ─────────────────────────────────────────────────────
Transmission type    : Base64
Complete Transmission: d5fa1f0101e881256a9a3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de
IV unpadded          : d5fa1f0101
IV padded            : d5fa1f0101000000000000000000000000000000000000000000000000000000
Timestamp            : d5fa1f01
Timestamp UTC        : 07.08.2025 10:30:45
Timestamp Local      : 07.08.2025 12:30:45
Key Index            : 01
Transmitted Crc8     : e8
Actual Crc8          : e8
Has Valid Crc8       : True
Transmitted CMAC     : 81256a9a
Cipher Text          : 3ae2f8f268d024c47d528465f76460865e2362ad28f609cb91d1206c5f694a229c85de

── Key derivation (CMAC-KDF) ─────────────────────────────────────────────────────
PRKhi         : 9689a6e10c4a14d726d6e0ec56d2e22b
PRKlo         : 2ef2e7acca205cbfb55f924f5b9a5bca
PRK           : 9689a6e10c4a14d726d6e0ec56d2e22b2ef2e7acca205cbfb55f924f5b9a5bca
------------------------------------------------------------
EncKeyhi      : eedeaba836d9eb1584d6e4e11765c20f
EncKeylo      : 3b7777579cbbf0c8df6c9202894b5633
Encryption Key: eedeaba836d9eb1584d6e4e11765c20f3b7777579cbbf0c8df6c9202894b5633
------------------------------------------------------------
CmacKeyhi     : 1a6220a89cffa76f327bda8e4cb4c9ec
CmacKeylo     : 19013556e2753eb1f23f7744b603b0e5
CMAC Key      : 1a6220a89cffa76f327bda8e4cb4c9ec19013556e2753eb1f23f7744b603b0e5

── Decryption ─────────────────────────────────────────────────────
Counter[0]          : d5fa1f01010000000000000000000000
Keystream[0]        : 307d22c8181de78b1182a75112f3aed8
CipherTextPortion[0]: 3ae2f8f268d024c47d528465f7646086
Plaintext[0]        : 0a9fda3a70cdc34f6cd02334e597ce5e
------------------------------------------------------------
Counter[1]          : d5fa1f01010000000000000000000001
Keystream[1]        : c790166c13618592e181fdcbf1a7d192
CipherTextPortion[1]: 5e2362ad28f609cb91d1206c5f694a22
Plaintext[1]        : 99b374c13b978c597050dda7aece9bb0
------------------------------------------------------------
Counter[2]          : d5fa1f01010000000000000000000002
Keystream[2]        : 9c85deb5db7caa84d44bdd0517dd1799
CipherTextPortion[2]: 9c85de
Plaintext[2]        : 000000
------------------------------------------------------------
Plaintext HEX             : 0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0000000
Plaintext HEX uncompressed: 50726f6265616c61726d2c204c6569747374656c6c65206e6963687420616e727566656e
Plaintext                 : Probealarm, Leitstelle nicht anrufen

── CMAC ─────────────────────────────────────────────────────
Actual CMAC               : 81256a9a
Has Valid CMAC            : True

Done.
```

#### Decrypt an unencrypted message

```bash
PELplusCLI.exe --message "Test" --key 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --decrypt

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  PELplus – POCSAG Encryption                           
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
Message  : Test
Key (hex): 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

── Extract parameters from transmission ─────────────────────────────────────────────────────
Transmission type    : Unencrypted
```



## License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Author

Florian Fuchs (florian.fuchs@ff-itc.at)

## Notes

This implementation prioritizes **clarity** and **traceability** over performance or security.

Internal tracing features (printing counters, keystream, ciphertext, plaintext) are intentionally verbose to help understand AES-CTR operation.

Again: **Never deploy this in real applications.**