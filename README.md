# PELplus.CLI

The POCSAG Encryption Library plus Command Line Interface is a **reference implementation** for the POCSAG encryption 
as described in the draft of the TR BOS.  
It was designed purely for **educational and analysis purposes**, **not** for production use.

## Security Disclaimer

> [!WARNING]
>
> **Do NOT use this tool in production environments.**  
> - It is **not reviewed**, **not hardened**, and **not intended** to provide real-world security.  
> - The code is meant for developers, researchers, or students who want to study the internal workings of the POCSAG encryption.  
> - There are no guarantees of correctness, confidentiality, integrity, or security.

## Usage

```bash
PELplus.CLI --message "<text>" [--key <hex32bytes>] [--keyindex <hex2>] [--time "YYYY-MM-DD HH:mm:ss"]
```

### Options

- `--message`   Message to encrypt (mandatory).
- `--key`       256 bit AES key in hex. If omitted, a random key is generated.
- `--keyindex`  Key index (default: `01`).
- `--time`      UTC timestamp (`YYYY-MM-DD HH:mm:ss`). Defaults to current UTC.
- `--license`   Show license information.

### Examples

```bash
PELplus.CLI --message "This is a test message."
PELplus.CLI --key 0x000102...1e1f --keyindex 01 --time "2025-08-07 10:30:45" --message "Secret payload"
PELplus.CLI --license

PELplusCLI.exe --message "Probealarm, Leitstelle nicht anrufen" --key 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --time "2025-08-07 10:30:45" --keyindex 01

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  PELplus – POCSAG Encryption                                 ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
Message  : Probealarm, Leitstelle nicht anrufen
UTC time : 2025-08-07 10:30:45
KeyIndex : 01
Key (hex): 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

── Timestamp / IV base ─────────────────────────────────────────────────────
Timestamp LE (hex)  : d5fa1f01
IV (unpadded)       : d5fa1f0101
IV (padded 32 bytes): d5fa1f0101000000000000000000000000000000000000000000000000000000

── Key derivation (CMAC-KDF) ─────────────────────────────────────────────────────
Encryption Key: eb5d641c1f51a034039549c1389a1a1db5a3b62a68471a47234d689c513ff244
CMAC Key      : 659f4c8e1743b17e8a5a95d72c2a91b174e7e21bb737ff4acf0acbeb3678d671

── Plaintext & compression ─────────────────────────────────────────────────────
Plaintext bytes (hex)    : 50726f6265616c61726d2c204c6569747374656c6c65206e6963687420616e727566656e
Compressed bytes (hex)   : 0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0
Compressed + padded (hex): 0a9fda3a70cdc34f6cd02334e597ce5e99b374c13b978c597050dda7aece9bb0000000

── AES-CTR details (all blocks) ─────────────────────────────────────────────────────
Counter[0]          : d5fa1f01010000000000000000000000
Keystream[0]        : 4d8f0e62f4bb16dd6e8b31c24bc9aa3a
Plaintext[0]        : 0a9fda3a70cdc34f6cd02334e597ce5e
CipherTextPortion[0]: 4710d4588476d592025b12f6ae5e6464
------------------------------------------------------------
Counter[1]          : d5fa1f01010000000000000000000001
Keystream[1]        : 085b09c4e72c96d58bd889d7fe692093
Plaintext[1]        : 99b374c13b978c597050dda7aece9bb0
CipherTextPortion[1]: 91e87d05dcbb1a8cfb88547050a7bb23
------------------------------------------------------------
Counter[2]          : d5fa1f01010000000000000000000002
Keystream[2]        : d068f2e436b9ab5222f4eddbc59f436a
Plaintext[2]        : 000000
CipherTextPortion[2]: d068f2
------------------------------------------------------------
Ciphertext (hex): 4710d4588476d592025b12f6ae5e646491e87d05dcbb1a8cfb88547050a7bb23d068f2

── Checksums ─────────────────────────────────────────────────────
CMAC (128-bit, hex) over ciphertext: e713360d23286bf95df8def8a4629a43
CRC-8 over IV                      : e8

── Transmission ─────────────────────────────────────────────────────
TX (hex)      : d5fa1f0101e8e713360d4710d4588476d592025b12f6ae5e646491e87d05dcbb1a8cfb88547050a7bb23d068f2
POCSAG Numeric: U*[58[0808717]8  60U2]80U2*112]6U*9404*-84[657*762629871]U0*U3--8513[-11*2]0*05]--4 U061[4
Base64        : 1fofAQHo5xM2DUcQ1FiEdtWSAlsS9q5eZGSR6H0F3LsajPuIVHBQp7sj0Gjy

Done.
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