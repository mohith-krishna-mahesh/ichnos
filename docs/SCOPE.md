# Ichnos — Full Module Scope

> Long-term roadmap for all 11 modules, matched against dCode.fr's complete cryptography/encoding/steganography catalog.

## Module Overview

```
ichnos/
├── crypto      — classical ciphers, XOR, freq analysis, RSA/ECC/hash attacks, JWT
├── encoding    — hex/Base-N/URL/etc, morse, symbol/phonetic encodings, layered auto-decode
├── stego       — image/audio/document steganography, embedded-file detection
├── binary      — static file/binary triage (ELF/PE/Mach-O, strings, entropy, headers)
├── reverse     — disassembly, symbols, control-flow hints (Capstone-based)
├── forensic    — file metadata, carving, archives, deleted recovery, filesystem inspection
├── pcap        — capture analysis, protocol stats, stream reconstruction, extraction
├── network     — live target recon: port/service check, banner grab, TLS inspect
├── web         — live HTTP recon: request/response, fuzzing, crawling, fingerprinting
├── osint       — passive recon: usernames, subdomains, WHOIS, cert transparency
└── password    — hash ID/crack (CTF-scale), wordlist/mask/rule tooling
```

---

## 1. crypto

### Classical / Substitution Family

| Cipher | Status | Notes |
|--------|--------|-------|
| Caesar / ROT-N (ROT1/5/13/18/47/8000) | ✅ v0.1 | Brute + auto-detect via English frequency scoring |
| Atbash | ✅ v0.1 | Self-inverse |
| Affine | ✅ v0.1 | Brute + solve |
| Multiplicative cipher | ⬜ v0.2 | Special case of affine (b=0) |
| Progressive Caesar | ⬜ v0.2 | Shift increments per character |
| Simple monoalphabetic substitution | ✅ v0.1 | Quadgram scoring solver |
| Keyword-based substitution (Trithemius-style) | ⬜ v0.2 | |
| Homophonic substitution | ⬜ v0.2+ | |
| Nomenclator | ⬜ v0.2+ | |
| Grandpré cipher | ⬜ v0.2+ | |
| Arnold cipher | ⬜ v0.2+ | |
| Modulo cipher | ⬜ v0.2+ | |
| Mexican Army Cipher Wheel | ⬜ v0.2+ | |
| Nihilist cipher | ⬜ v0.2+ | Polyalphabetic + Polybius variant |
| Deranged Alphabet Generator | ⬜ v0.2 | Utility for alphabet permutation |

### Symbol Table / Alphabet Substitution

> **Architecture**: One generic `symboltable.py` engine backed by a data file. NOT one function per cipher. Adding new alphabets is a data-only change.

| Table | Status | Notes |
|-------|--------|-------|
| Pigpen / Masonic | ✅ v0.1 | Descriptive glyph identifiers |
| Templars | ✅ v0.1 | |
| Rosicrucian | ⬜ v0.2 | |
| Tap Code | ✅ v0.1 | 5×5 grid, K merged with C |
| Morse | ✅ v0.1 | Full ITU mapping |
| Braille | ✅ v0.1 | Unicode Braille characters |
| Semaphore (Flag variants) | ✅ v0.1 | Clock position notation |
| NATO Phonetic | ✅ v0.1 | |
| Dancing Men (Sherlock Holmes) | ✅ v0.1 | Common CTF reference |
| Standard Galactic Alphabet (Minecraft) | ✅ v0.1 | Very common in CTF |
| Zodiac Killer Cipher | ⬜ v0.2 | |
| Ogham | ⬜ v0.2 | |
| Elder Futhark | ✅ v0.1 | Unicode rune characters |
| Younger Futhark | ⬜ v0.2 | |
| Klingon (pIqaD) | ✅ v0.1 | |
| Aurebesh (Star Wars) | ✅ v0.1 | |
| Wingdings | ✅ v0.1 | Font character mapping |
| Webdings | ⬜ v0.2 | |
| Cistercian numerals | ⬜ v0.2 | |
| Mayan numerals | ⬜ v0.2 | |
| Babylonian numerals | ⬜ v0.2 | |
| Egyptian numerals | ⬜ v0.2 | |
| DTMF | ⬜ v0.2 | |
| 7-segment display | ✅ v0.1 | Segment encoding |
| Tic-Tac-Toe cipher | ⬜ v0.2 | |
| Bibi-binary | ✅ v0.1 | |
| Hexahue | ✅ v0.1 | Color-grid cipher |
| Music Sheet Cipher | ⬜ v0.2 | |
| Gravity Falls (Bill/Author) | ✅ v0.1 | Recurring CTF/puzzle theme |
| Polybius | ✅ v0.1 | Standard 5×5 |
| A1Z26 | ✅ v0.1 | Letter ↔ number |
| Bacon's cipher | ✅ v0.1 | A/B binary 24-letter |
| ~100 additional fictional scripts | ⬜ v0.3+ | Trivial data-only additions |

### Polyalphabetic

| Cipher | Status | Notes |
|--------|--------|-------|
| Vigenère | ✅ v0.1 | Kasiski, IoC, auto-crack |
| Vigenère Multiplicative variant | ⬜ v0.2 | |
| Beaufort | ⬜ v0.2 | |
| Beaufort Variant | ⬜ v0.2 | |
| Autokey / Autoclave | ⬜ v0.2 | |
| Gronsfeld | ⬜ v0.2 | Vigenère with numeric key |
| Porta | ⬜ v0.2 | |
| Trithemius / Ave Maria | ⬜ v0.2 | |
| Alberti | ⬜ v0.2+ | |
| Bazeries | ⬜ v0.2+ | |
| Bellaso | ⬜ v0.2+ | |
| Chaocipher | ⬜ v0.2+ | |
| Phillips | ⬜ v0.2+ | |
| Ragbaby | ⬜ v0.2+ | |
| Slidefair | ⬜ v0.2+ | |
| Keyword Shift | ⬜ v0.2 | |
| Jefferson Wheel | ⬜ v0.2+ | |
| Solitaire (Schneier) | ⬜ v0.2+ | |
| Vernam / One-Time Pad | ⬜ v0.2 | |
| Enigma | ⬜ v0.2 | Rotors I–VIII, UKW-A/B/C, double-stepping, plugboard |

### Transposition

| Cipher | Status | Notes |
|--------|--------|-------|
| Rail Fence | ⬜ v0.2 | |
| Columnar Transposition | ⬜ v0.2 | |
| Double Transposition | ⬜ v0.2 | |
| ADFGVX / ADFGX | ⬜ v0.2 | Substitution + columnar combined |
| AMSCO | ⬜ v0.2+ | |
| Caesar Box | ⬜ v0.2 | |
| Route / Path cipher | ⬜ v0.2+ | |
| Scytale | ⬜ v0.2 | |
| Skip Cipher | ⬜ v0.2+ | |
| Spiral Cipher | ⬜ v0.2+ | |
| Swagman | ⬜ v0.2+ | |
| Turning Grille | ⬜ v0.2+ | |
| Ubchi | ⬜ v0.2+ | |
| Redefence | ⬜ v0.2+ | |
| Myszkowski | ⬜ v0.2+ | |
| Generic Transposition Key Solver | ⬜ v0.2 | |

### Polygraphic

| Cipher | Status | Notes |
|--------|--------|-------|
| Playfair | ⬜ v0.2 | |
| Two-square | ⬜ v0.2+ | |
| Three Squares | ⬜ v0.2+ | |
| Four-square | ⬜ v0.2+ | |
| Bifid | ⬜ v0.2 | |
| Trifid (Delastelle) | ⬜ v0.2 | |
| Collon | ⬜ v0.2+ | |
| Digrafid | ⬜ v0.2+ | |
| Morbit | ⬜ v0.2+ | |
| Pollux | ⬜ v0.2+ | |
| Fractionated Morse | ⬜ v0.2+ | |
| Hill cipher | ⬜ v0.2 | |

### Number/Letter Ciphers

| Cipher | Status | Notes |
|--------|--------|-------|
| A1Z26 | ✅ v0.1 | Via symboltable |
| Bacon | ✅ v0.1 | Via symboltable |
| Book Cipher | ⬜ v0.2 | Needs reference text |
| Polybius | ✅ v0.1 | Via symboltable |
| Base26/36/37 Cipher | ⬜ v0.2 | |
| Consonants/Vowels Rank | ⬜ v0.2+ | |
| Prime Numbers Cipher | ⬜ v0.2+ | |
| Prime Multiplication Cipher | ⬜ v0.2+ | |
| Greek Letter Number | ⬜ v0.2+ | |
| Periodic Table Cipher | ⬜ v0.2+ | |
| Triliteral | ⬜ v0.2+ | |
| Twin Hex | ⬜ v0.2+ | |
| Monome-Dinome | ⬜ v0.2+ | |
| VIC Cipher | ⬜ v0.2+ | |
| McCormick | ⬜ v0.2+ | |
| Rozier | ⬜ v0.2+ | |
| Wolseley | ⬜ v0.2+ | |

### XOR

| Tool | Status | Notes |
|------|--------|-------|
| Single-byte XOR brute force | ✅ v0.1 | All 256 keys, scored |
| Repeating-key XOR | ✅ v0.1 | Hamming distance key-length detection |
| Crib dragging / many-time-pad | ✅ v0.1 | Batch mode |
| XOR with known-plaintext recovery | ⬜ v0.2 | |

### Hashing

| Tool | Status | Notes |
|------|--------|-------|
| Hash identification | ✅ v0.1 | MD5/SHA1/256/512/bcrypt/NTLM/etc. |
| Hash computation | ✅ v0.1 | All common algorithms |
| HMAC verification/forging | ⬜ v0.2 | |
| Length-extension attack | ⬜ v0.2 | MD5/SHA1/SHA256 |
| Hash collision utilities | ⬜ v0.2+ | |

### RSA

| Attack | Status | Notes |
|--------|--------|-------|
| Key parameter inspection | ⬜ v0.2 | |
| Factorization (small/Fermat/Pollard) | ⬜ v0.2 | numtheory.prime_factorization is v0.1 |
| Wiener's attack | ⬜ v0.2 | Uses continued fractions (v0.1) |
| Common modulus attack | ⬜ v0.2 | |
| Håstad's broadcast attack | ⬜ v0.2 | |
| Franklin-Reiter related-message | ⬜ v0.2+ | |
| Small-e / low-exponent | ⬜ v0.2 | |
| Partial key exposure | ⬜ v0.2+ | |

### ECC

| Tool | Status | Notes |
|------|--------|-------|
| Curve parameter inspection | ⬜ v0.2+ | |
| Point arithmetic | ⬜ v0.2+ | |
| Invalid-curve detection | ⬜ v0.2+ | |
| Weak curve identification | ⬜ v0.2+ | |

### Other Modern Crypto

| Tool | Status | Notes |
|------|--------|-------|
| Diffie-Hellman parameter inspection | ✅ v0.2 | Small subgroup & parameter checks in `crypto/dh` |
| X.509 Certificate inspection | ✅ v0.3 | In `network/tls.py` |
| RC4 | ✅ v0.2 | In `crypto/rc4` |
| Circular Bit Shift | ✅ v0.2 | In `binary/misc.py` |
| ElGamal | ✅ v0.2 | Nonce reuse & small subgroup attacks in `crypto/elgamal` |
| Knapsack (Merkle-Hellman) | ✅ v0.2 | Superincreasing vector recovery in `crypto/knapsack` |
| JWT decode/verify/forge | ✅ v0.2 | None algorithm, HMAC/RSA confusion in `crypto/jwt` |

### Post-Quantum Cryptography (PQC)

> [!WARNING]
> **Pedagogical & CTF Scope Caveat**:
> Implementations in `crypto/pqc/` (LWE lattice fundamentals, NTRU, Kyber-style ML-KEM, Dilithium-style ML-DSA) are provided strictly for educational inspection, mechanism understanding, and CTF challenge analysis. They are **not** production-grade, certified, or side-channel-resistant cryptographic libraries. Real-world PQC requires strict constant-time primitives, Gaussian sampling defenses, and formal verification. In CTF competitions, PQC challenges center almost exclusively on deliberately weakened toy parameters (small lattice dimensions, low noise/error variance, smooth or non-prime moduli, or small secret bounds) rather than attacking standard NIST security levels.

| Tool / Algorithm | Status | Notes |
|------------------|--------|-------|
| LWE Instance & Lattice Basis | ✅ v0.2 | Basis inspection, Gram-Schmidt, Babai CVP |
| NTRU Polynomial Ring | ✅ v0.2 | Keygen, encrypt, decrypt over $\mathbb{Z}[x]/(x^N - 1)$ |
| Kyber-style (ML-KEM) Mechanics | ✅ v0.2 | Parameter inspection, toy encapsulation/decapsulation |
| Dilithium-style (ML-DSA) Mechanics | ✅ v0.2 | Parameter inspection, toy verification equation |
| PQC Attack Surface Tooling | ✅ v0.2 | Small-lattice brute force, weak-parameter detection, hardness estimator |

### Number Theory Toolbox

| Tool | Status | Notes |
|------|--------|-------|
| GCD / Extended GCD | ✅ v0.1 | |
| LCM | ✅ v0.1 | |
| Modular Inverse | ✅ v0.1 | |
| Modular Exponentiation | ✅ v0.1 | |
| Modulo N Calculator | ✅ v0.1 | |
| Chinese Remainder Theorem | ✅ v0.1 | |
| Primality Test (Miller-Rabin) | ✅ v0.1 | |
| Prime Factorization | ✅ v0.1 | Trial division + Pollard's rho |
| Euler's Totient | ✅ v0.1 | |
| Continued Fractions / Convergents | ✅ v0.1 | |
| Discrete Logarithm (BSGS) | ✅ v0.1 | Baby-step giant-step |
| Fermat Factorization | ⬜ v0.2 | |
| Carmichael Number | ⬜ v0.2+ | |
| Next/Previous/Closest Prime | ⬜ v0.2 | |
| Bezout's Identity | ✅ v0.1 | Via extended_gcd |
| Subset Sum (knapsack-relevant) | ⬜ v0.2+ | |
| Modular Equation Solver | ⬜ v0.2 | |

### Cryptanalysis

| Tool | Status | Notes |
|------|--------|-------|
| Cipher Identifier | ✅ v0.1 | Via `analyze` command + registry |
| Frequency Analysis | ✅ v0.1 | In core/detection.py |
| Bigrams / Trigrams | ⬜ v0.2 | |
| Index of Coincidence | ✅ v0.1 | In vigenere.py |
| Kasiski's Test | ✅ v0.1 | In vigenere.py |
| Shannon Entropy | ✅ v0.1 | In core/detection.py |
| Chi-squared scoring | ✅ v0.1 | In core/detection.py |

---

## 2. encoding

### Base Encodings

| Encoding | Status | Notes |
|----------|--------|-------|
| Hex | ✅ v0.1 | |
| Base16 | ✅ v0.1 | |
| Base32 | ✅ v0.1 | |
| Base32 Crockford | ⬜ v0.2 | |
| Z-Base-32 | ⬜ v0.2 | |
| Base45 | ⬜ v0.2 | |
| Base58 (Bitcoin) | ✅ v0.1 | |
| Base62 | ⬜ v0.2 | |
| Base64 / Base64url | ✅ v0.1 | |
| Base85 / ASCII85 | ✅ v0.1 | |
| Base91 | ✅ v0.1 | |
| Base92 | ⬜ v0.2+ | |
| Base100 (emoji) | ⬜ v0.2+ | |
| Base65536 | ⬜ v0.2+ | |
| Base26/36/37 | ⬜ v0.2 | |

### Numeral Systems

| System | Status | Notes |
|--------|--------|-------|
| Binary / Octal / Decimal | ⬜ v0.2 | |
| Ternary | ⬜ v0.2+ | |
| Negabinary / Negadecimal | ⬜ v0.2+ | |
| Gray Code | ⬜ v0.2 | |
| Excess-3 | ⬜ v0.2+ | |
| BCD | ⬜ v0.2 | |

### Telecom Encodings

| Encoding | Status | Notes |
|----------|--------|-------|
| Baudot | ⬜ v0.2+ | |
| Manchester encoding | ⬜ v0.2+ | |
| Decabit | ⬜ v0.2+ | |
| Alternate Mark Inversion | ⬜ v0.2+ | |
| Morse | ✅ v0.1 | Full encode/decode |
| Wabun (Japanese Morse) | ⬜ v0.2+ | |
| DTMF | ⬜ v0.2 | Via symboltable |
| T9 / Multi-tap | ⬜ v0.2 | |
| Phone Keypad Cipher | ⬜ v0.2 | |

### Text/Web Encodings

| Encoding | Status | Notes |
|----------|--------|-------|
| URL encoding | ✅ v0.1 | Including double encoding |
| HTML entities | ✅ v0.1 | |
| Unicode escapes | ✅ v0.1 | Multiple styles |
| Punycode | ⬜ v0.2 | |
| UUencode | ⬜ v0.2 | |
| LEB128 | ⬜ v0.2+ | |
| Zalgo/diacritics obfuscation | ⬜ v0.2+ | |
| Zero-width space | ⬜ v0.2 | |
| Quoted-printable | ⬜ v0.2 | |
| ROT13/ROT47 | ⬜ v0.2 | Encoding-flavored, separate from crypto solver |

### Compression

| Format | Status | Notes |
|--------|--------|-------|
| Gzip / Zlib / Deflate | ✅ v0.1 | Via Python stdlib |
| Huffman Coding | ⬜ v0.3+ | From-scratch implementation |
| LZW | ⬜ v0.3+ | |
| RLE | ⬜ v0.2+ | |
| Burrows-Wheeler Transform | ⬜ v0.3+ | |
| Elias Gamma/Delta | ⬜ v0.3+ | |
| Fibonacci/NegaFibonacci encoding | ⬜ v0.3+ | |

### Checksums

| Algorithm | Status | Notes |
|-----------|--------|-------|
| CRC-32 | ⬜ v0.2 | |
| Luhn | ⬜ v0.2 | |
| Verhoeff | ⬜ v0.2+ | |
| IBAN/BBAN | ⬜ v0.2+ | |

### Esolang Decoders

| Language | Status | Notes |
|----------|--------|-------|
| Brainfuck | ✅ v0.1 | Full tape-based interpreter |
| Ook! | ✅ v0.1 | Translates to Brainfuck |
| JSFuck | ✅ v0.1 | Static decoder |
| Whitespace | ✅ v0.1 | Stack-based interpreter |
| LOLCODE | ✅ v0.1 | Basic interpreter |
| Deadfish | ✅ v0.1 | Simple accumulator |
| AAEncode | ⬜ v0.2+ | |
| Malbolge | ⬜ v0.3+ | Extremely complex |

### Barcode/QR

> **Open question**: Dependency choice — pyzbar vs. zxing-cpp vs. from-scratch decoder.

| Format | Status | Notes |
|--------|--------|-------|
| QR Code | ⬜ v0.2+ | Decode from image |
| Barcode 39/93/128 | ⬜ v0.2+ | |
| Codabar/EAN8/EAN13 | ⬜ v0.2+ | |
| PLANET/POSTNET | ⬜ v0.2+ | |
| Aztec | ⬜ v0.2+ | |

### Layered Auto-Detection

| Feature | Status | Notes |
|---------|--------|-------|
| Multi-layer decode chain | ✅ v0.1 | Iterative decoder |
| Encoding detection heuristics | ✅ v0.1 | |
| JSON "candidates at each layer" output | ✅ v0.1 | |

---

## 3. stego

### Text-Based Concealment

| Technique | Status | Notes |
|-----------|--------|-------|
| Null Cipher | ✅ v0.1 | First/Nth letter, first sentence |
| Acrostic Extractor | ✅ v0.1 | First char of each line |
| Cardan Grille | ✅ v0.1 | Position-based extraction |
| Trevanion Cipher | ⬜ v0.2 | |
| Letters Extraction | ✅ v0.1 | Pattern-based |
| Mirror/Reverse Writing | ✅ v0.1 | Including upside-down Unicode |
| Boustrophedon | ⬜ v0.2 | |
| Binary Character Shapes | ⬜ v0.2+ | |

### Image — LSB/Bit-Plane

| Tool | Status | Notes |
|------|--------|-------|
| Full LSB permutation extraction (zsteg-equivalent) | ✅ v0.1 | All channel orders, bit orders, depths |
| Palette-index LSB (indexed PNG/GIF) | ⬜ v0.2 | |
| Alpha-channel LSB | ⬜ v0.2 | |
| Bit-plane visualization | ⬜ v0.2 | |

### Image — JPEG-Domain

| Tool | Status | Notes |
|------|--------|-------|
| F5 detection/extraction | ⬜ v0.2 | DCT coefficient analysis |
| Outguess detection/extraction | ⬜ v0.2 | Chi-square on coefficient pairs |
| General JPEG steganalysis | ⬜ v0.2 | |
| JPEG segment parser | ⬜ v0.2 | |

### Image — Steghide-Compatible

| Tool | Status | Notes |
|------|--------|-------|
| steghide reimplemented embedding/extraction | ⬜ v0.2 | |
| stegseek passphrase cracking | ⬜ v0.2 | CRC32 pre-check optimization |

### Image — General

| Tool | Status | Notes |
|------|--------|-------|
| PNG chunk parser | ✅ v0.1 | IHDR, text chunks, trailing data |
| EXIF data extraction | ⬜ v0.2 | |
| Channel separation (RGB/CMYK/HSV) | ⬜ v0.2 | |
| Image histogram | ⬜ v0.2+ | |
| Pixel reader | ⬜ v0.2+ | |
| Color palette anomaly detection | ⬜ v0.2+ | |
| Image diffing | ⬜ v0.2 | |

### Audio

| Tool | Status | Notes |
|------|--------|-------|
| WAV metadata + sample inspection | ✅ v0.1 | Full parser |
| Morse code in audio | ✅ v0.1 | Adaptive thresholding + timing |
| LSB-in-audio extraction | ⬜ v0.2 | |
| Spectrogram generation | ⬜ v0.2 | |
| ID3/metadata tag inspection | ⬜ v0.2 | |

### Documents

| Tool | Status | Notes |
|------|--------|-------|
| PDF object/stream inspection | ⬜ v0.2+ | |
| Office embedded object extraction | ⬜ v0.2+ | |

### Generic File-Based

| Tool | Status | Notes |
|------|--------|-------|
| Appended-data-after-EOF detection | ✅ v0.1 | Via PNG trailing data |
| Polyglot file detection | ⬜ v0.2 | |
| Embedded-archive detection | ⬜ v0.2 | |

---

## 4. binary

| Tool | Status | Notes |
|------|--------|-------|
| File type/magic identification | ✅ v0.1 | Extended magic table |
| Strings (ASCII + UTF-16) | ✅ v0.1 | Configurable min length |
| Entropy analysis (whole + sliding window) | ✅ v0.1 | |
| ELF parser (headers, sections, symbols) | ✅ v0.1 | 32/64-bit, LE/BE |
| PE parser | ⬜ v0.2 | Headers, imports/exports, resources |
| Mach-O parser | ⬜ v0.2 | Headers, load commands, segments |
| Hex dump (with search/highlight) | ⬜ v0.2 | |
| Architecture/endianness detection | ✅ v0.1 | Via identify |
| Endian converter | ✅ v0.1 | |
| Hamming distance/weight | ✅ v0.1 | |
| Packer detection (UPX) | ⬜ v0.2 | |
| Embedded-file carving | ⬜ v0.2 | |
| Binary diffing | ⬜ v0.2+ | |
| LFSR (stream cipher relevant) | ⬜ v0.2+ | |

---

## 5. reverse

All planned for v0.2+:

- Disassembly (Capstone-based; x86/x86-64/ARM/ARM64/MIPS)
- Function/symbol enumeration
- Basic control-flow graph extraction
- Cross-reference (string → function, import → call site)
- Decompiler-lite pseudocode heuristics — stretch goal
- Patch/assemble small byte sequences (Keystone-based)
- Anti-debug/anti-VM pattern detection
- Syscall/import table annotation

---

## 6. forensic

| Tool | Status | Notes |
|------|--------|-------|
| ZIP inspection/comments/crack | ✅ v0.1 | `zipfile` and central directory parsing |
| Archive inspection (TAR/GZ/BZ2/XZ) | ✅ v0.2 | Permissions, member stats, single-stream decomp |
| Archive header triage (7z, RAR) | ✅ v0.2 | Pure-Python header signature parsers |
| File carving (signature-based) | ✅ v0.2 | PNG, JPEG, PDF, ZIP, GIF carvers |
| Partition table parsing (MBR, GPT) | ✅ v0.2 | MBR partitions, GPT headers and GUIDs |
| Filesystem inspection (FAT BPB) | ✅ v0.2 | FAT12/16/32 BIOS Parameter Block |
| Forensic timestamp converters | ✅ v0.2 | Windows FILETIME, Apple Cocoa, Chrome, Unix, DOS |
| Metadata extraction (EXIF) | ✅ v0.2 | Pure-Python TIFF/EXIF parser in stego |
| Deleted-file recovery | ⬜ v0.4+ | |
| Slack space inspection | ⬜ v0.4+ | |

---

## 7. pcap

| Tool | Status | Notes |
|------|--------|-------|
| PCAP/PCAPNG packet parser | ✅ v0.2 | Pure-Python reader for standard PCAP and PCAPNG |
| Network flow tracking & stats | ✅ v0.2 | Bidirectional conversation groupings, duration, volume |
| DNS query extraction | ✅ v0.2 | Questions, types (A/AAAA/MX/TXT/NS), client/server IPs |
| HTTP request/response inspection | ✅ v0.2 | Methods, paths, headers, status codes, payload preview |
| Plaintext credential extraction | ✅ v0.2 | HTTP Basic Auth, FTP, SMTP, form POST parameters |
| Packet capture summary | ✅ v0.2 | Protocol distributions, time spans, endpoint counts |
| TLS metadata (SNI) | ⬜ v0.4 | |
| Stream payload export | ⬜ v0.4 | |

---

## 8. network

| Tool | Status | Notes |
|------|--------|-------|
| Port scan (concurrent TCP connect) | ✅ v0.3 | Port ranges, worker pools, service resolution |
| Service banner grabbing | ✅ v0.3 | Protocol-aware probes for HTTP, FTP, SSH, SMTP |
| TLS certificate inspection | ✅ v0.3 | Subject, Issuer, SANs, validity dates, cipher suites |
| Raw socket helpers | ⬜ v0.4 | |
| Traceroute / hop analysis | ⬜ v0.4 | |

---

## 9. web

| Tool | Status | Notes |
|------|--------|-------|
| Security header audit | ✅ v0.3 | CSP, HSTS, X-Frame-Options, CORS, info leaks |
| Directory & endpoint fuzzing | ✅ v0.3 | Concurrent path probing, status filtering, redirects |
| Asset, form & comment extraction | ✅ v0.3 | HTML links, scripts, hidden forms, comments, emails |
| Technology fingerprinting | ⬜ v0.4 | |
| Cookie/session inspection | ⬜ v0.4 | |

---

## 10. osint

| Tool | Status | Notes |
|------|--------|-------|
| DNS record resolution (DoH) | ✅ v0.3 | Cloudflare/Google DNS-over-HTTPS (A, AAAA, MX, TXT) |
| Pure-socket WHOIS client | ✅ v0.3 | Direct port 43 lookup with IANA referral following |
| Subdomain enumeration | ✅ v0.3 | crt.sh Certificate Transparency logs + wordlists |
| Username enumeration | ⬜ v0.4 | |
| Email breach format checks | ⬜ v0.4 | |

---

## 11. password

| Tool | Status | Notes |
|------|--------|-------|
| Rule-based mutator | ✅ v0.2 | Hashcat/John-style leet, casing, prefixes/suffixes |
| Wordlist utilities | ✅ v0.2 | Cartesian combiner, policy filtering, deduplication |
| Dictionary hash cracking | ✅ v0.2 | MD5, SHA-1, SHA-256, SHA-512, pure-Python NTLM |
| On-the-fly rule cracking | ✅ v0.2 | Mutates wordlist candidates dynamically |
| Mask generation (Hashcat-style) | ⬜ v0.4 | |
| Hashcat/John output export | ⬜ v0.4 | |

---

## Explicitly Out of Scope

| Category | Reasoning |
|----------|-----------|
| Web dashboard / GUI | Local-first CLI tool |
| AI/LLM dependency | No mandatory AI |
| SaaS / cloud infrastructure | Local-first |
| SIEM / EDR / full IDS | Not a CTF tool |
| Full Ghidra/IDA replacement | Stretch goal at best |
| Full Wireshark replacement | Not feasible |
| Full Hashcat replacement (GPU) | CTF-scale only |
| Malware sandbox / dynamic analysis | Different discipline |
| Autonomous exploitation framework | Out of scope |
| Distributed sensor platform | Demoted from original scope |
| `malware` module | Blue-team/IR, not CTF; overlap covered by binary + reverse |
| `pwn` module | Dynamic exploitation; pwntools already owns this |
| Word games/puzzles (Sudoku, crosswords) | No CTF relevance |
| Pure symbolic math (calculus, matrices) | Not security-relevant |
| Physics/chemistry constants | No CTF relevance |
| Geography/geolocation tools | No CTF relevance |
| Music theory notation | No CTF relevance |
| Date/calendar arithmetic | No CTF relevance |
| Numerology/zodiac | No CTF relevance |
| Biology (Game of Life, codons) | No CTF relevance |

### dCode Categories Excluded

The following dCode categories have no CTF/security relevance and are permanently excluded:
word games/puzzle solvers, pure symbolic math, physics/chemistry constants, geography/geolocation, music theory, date/calendar arithmetic, numerology/zodiac, language accents/gibberish generators (Pig Latin, Javanais), biology tools.

---

## Acknowledged but Not Yet Built (Future Scope)

The following advanced capabilities have been evaluated and acknowledged as high-value for specialized security research and competitive CTFs, but are explicitly deferred past v0.1:

| Feature Area | Category | Scope & Architecture Rationale | Status |
|--------------|----------|--------------------------------|--------|
| **Live Process Memory Patching** | `reverse` / `pwn` | Runtime process memory inspection and code injection (e.g. Frida / ptrace style breakpointing, live function hooking, ASLR bypass probing). Ichnos strictly focuses on static binary analysis and contained micro-emulation (Unicorn) in v0.1; live process tampering introduces privileged OS-specific kernel interfaces that conflict with sandboxed execution. | Deferred |
| **Video Steganography** | `stego` | Temporal inter-frame timing modulation, audio-video synchronization offset steganography, and DCT / motion-vector manipulation in containerized video streams (MP4, MKV, AVI, H.264). Requires heavy demuxing and video codec parsing engines beyond standard zero-dependency byte manipulation. | Deferred |
| **Windows Registry Hive Parsing** | `forensic` | Raw binary deserialization and forensic carving of Windows registry hives (`NTUSER.DAT`, `SYSTEM`, `SAM`, `SOFTWARE`) for persistent keys, autoruns, and user activity artifacts. While static ZIP/SQLite/Docker/Git carving is built in v0.1, complex Windows registry transaction logs (`.LOG1`/`.LOG2`) and dirty hive replay will be addressed in a dedicated forensic subpackage. | Deferred |

---

## Open Architecture Questions

### 1. Barcode & QR Code Dependency Choice
- **Context**: 1D barcodes (Code 39, Code 128, EAN-13) and 2D barcodes (QR code, Data Matrix, PDF417) are common in CTF stego/encoding challenges.
- **Trade-off**: Native libraries like `zbar` / `pyzbar` provide robust barcode reading but introduce system-level C dependencies (`libzbar`) that break seamless `uv tool install` portability across platforms. Pure Python implementations (e.g., standard QR matrix parsing from byte grids or optional dependency groups `ichnos[barcodes]`) preserve zero-dependency installation at the cost of narrower image tolerance.
- **Status**: Target pure Python QR/barcode matrix decoder for core, with optional C-library acceleration where available.

### 2. Enigma Machine: In or Out?
- **Context**: Enigma (Wehrmacht I, Kriegsmarine M3/M4) is historically significant and recurs in CTF classical cryptography challenges.
- **Trade-off**: Complete rotor mechanics (Rotor I–VIII, reflectors UKW-A/B/C, thin reflectors, ring settings, Steckerbrett plugboard permutation) plus ciphertext cryptanalysis (Turing-Welchman Bombe or hill climbing against IoC) represent substantial algorithmic surface area.
- **Status**: Slated for inclusion in `crypto/classical/enigma.py` in v0.2, leveraging the existing hill-climbing optimization infrastructure from `substitution.py`.

### 3. From-Scratch Codecs vs. Standard Library / Optional Extras
- **Context**: CTF forensic and archive challenges frequently involve Deflate, Gzip, Bzip2, XZ/LZMA, 7z, RAR, and Zstandard.
- **Trade-off**: Python's standard library provides robust built-in support for `zlib`, `gzip`, `bz2`, `lzma`, `zipfile`, and `tarfile`. However, archive formats like 7z, RAR, and modern Zstandard require either external C-bindings (`py7zr`, `rarfile`, `zstandard`) or custom pure-Python parsers.
- **Status**: Use Python standard library for all baseline formats (Zero-dep guarantee); implement lightweight binary header triage in `binary/identify.py` and pure-Python carving for archive inspection, with optional dependency flags for heavyweight format unpacking.

