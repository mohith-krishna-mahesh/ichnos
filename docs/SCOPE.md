# Ichnos — Authoritative Architecture & Scope Specification

> **Version**: 0.1.0  
> **Status**: Living Engineering Reference & Release Specification  
> **Classification Tiers**: `Implemented & Tested`, `Partially Tested`, `Experimental`, `Unverified`, `Planned`

---

## 1. System Overview & Philosophy

**Ichnos** is a modular, local-first command-line interface (CLI) and terminal user interface (TUI) security and CTF toolkit. It is designed to bridge the gap between ad-hoc script collections (e.g., CyberChef, dCode, zsteg, RsaCtfTool) and integrated analysis suites.

### Core Architectural Axioms
1. **Zero-Dependency Core**: Foundational algorithmic logic—classical cryptography, base encoding codecs, ELF/PNG parsing, network packet inspection, and number theory—must run on pure-Python standard libraries without hard external binary or C-extension requirements.
2. **Deterministic Deduction**: The AutoSolver (`ichnos solve`) relies strictly on mathematical, structural, and cryptographic invariants. It does not guess blindly or rely on non-deterministic heuristic models for mathematical attacks.
3. **Adversarial Resilience**: All parsers (ZIP, ELF, PNG, WAV, PCAP, AST harvester) are hardened against hostile CTF inputs: decompression bombs, cyclic recursions, malformed headers, integer overflow DoS, and path traversal vulnerabilities.
4. **Platform Portability**: First-class support for macOS (ARM64/x86_64), Linux (x86_64), and Windows (x86_64) via standalone Nuitka binary compilation and user-configurable theme discovery.

---

## 2. Classification Definitions

| Classification | Definition |
| :--- | :--- |
| **Implemented & Tested** | Fully written in `src/ichnos/`, zero stubs, backed by passing automated unit/integration tests in `tests/`. |
| **Partially Tested** | Functional implementation present, but testing is restricted to mock environments or subset edge cases (e.g. live socket probes, external API dependencies). |
| **Experimental** | Algorithmic implementation targets simplified or pedagogical parameters (e.g., toy PQC lattices, small-scale ECC attacks). Not hardened for general cryptographic keys. |
| **Unverified** | Feature implemented for cross-platform support but not verified on all target operating systems in local development (supported via CI). |
| **Planned** | Outlined in roadmap, stubbed with clear errors, or deferred to future milestones (v0.2+ / v0.3+). |

---

## 3. Module Capabilities Matrix

### 3.1 `crypto` — Cryptography & Cryptanalysis

#### Classical & Substitution Ciphers
| Feature / Primitive | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| Caesar Cipher (ROT-N) | **Implemented & Tested** | Full 26-shift brute force, frequency scoring, auto-detection (`tests/crypto/test_caesar.py`). |
| Atbash Cipher | **Implemented & Tested** | Standard alphabet reversal, self-inverse execution (`tests/crypto/test_caesar.py`). |
| Affine Cipher | **Implemented & Tested** | Modular inverse validation, $(a, b)$ key brute forcing (`tests/crypto/test_caesar.py`). |
| Vigenère Cipher | **Implemented & Tested** | Kasiski examination, Index of Coincidence (IoC), column frequency cracking (`tests/crypto/test_vigenere.py`). |
| Monoalphabetic Substitution | **Implemented & Tested** | Quadgram log-probability hill-climbing solver (`tests/crypto/test_polyalphabetic.py`). |
| Homophonic Substitution | **Implemented & Tested** | Multi-symbol frequency mapping and deduction solver (`tests/crypto/test_homophonic.py`). |
| Transposition Ciphers | **Implemented & Tested** | Rail fence, columnar transposition, route cipher (`tests/crypto/test_transposition.py`). |
| Polygraphic Ciphers | **Implemented & Tested** | Playfair, Two-Square, Four-Square, Bifid solvers (`tests/crypto/test_polygraphic.py`). |
| Enigma Machine | **Implemented & Tested** | Rotors I–VIII, Reflectors UKW-A/B/C, plugboard Steckerbrett (`tests/crypto/test_enigma.py`). |

#### Symbol Tables & Historical Alphabets
| Alphabet / Script | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| Core Symbol Tables | **Implemented & Tested** | Pigpen, Templars, Tap Code (5×5), Morse, Braille, Semaphore (clock positions), NATO Phonetic, Dancing Men, Standard Galactic Alphabet (Minecraft), Elder Futhark, Aurebesh, Klingon (pIqaD), 7-Segment, Bibi-binary, Hexahue, Gravity Falls (`tests/crypto/test_symboltable.py`). |

#### XOR & Stream Ciphers
| Primitive / Attack | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| Single-Byte XOR | **Implemented & Tested** | Full 256-byte brute-force with English & printable scoring (`tests/crypto/test_xor.py`). |
| Repeating-Key XOR | **Implemented & Tested** | Normalized Hamming distance key-length detection and columnar assembly (`tests/crypto/test_xor.py`). |
| Crib Dragging | **Implemented & Tested** | Interactive and batch sliding crib analyzer for many-time-pad reuse (`tests/crypto/test_xor.py`). |
| Linear Feedback Shift Register (LFSR) | **Implemented & Tested** | Berlekamp-Massey algorithm for LFSR feedback polynomial and period recovery (`tests/crypto/test_prng_stream.py`). |
| PRNG State Recovery | **Implemented & Tested** | LCG state reconstruction (modulus, multiplier, increment) and Mersenne Twister untemper/clone (`tests/crypto/test_prng_stream.py`). |

#### Number Theory Toolbox
| Mathematical Primitive | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| Modular Arithmetic | **Implemented & Tested** | Euclidean GCD, Extended GCD, LCM, Modular Inverse, Fast Exponentiation (`tests/crypto/test_numtheory.py`). |
| Chinese Remainder Theorem | **Implemented & Tested** | Multi-congruence CRT solver with pairwise coprimality checking (`tests/crypto/test_numtheory.py`). |
| Primality & Factorization | **Implemented & Tested** | Deterministic Miller-Rabin ($n < 3.3 \times 10^{24}$), trial division, Pollard's $\rho$, Fermat's difference of squares (`tests/crypto/test_numtheory.py`). |
| Continued Fractions | **Implemented & Tested** | Infinite fraction expansion and convergent generator (`tests/crypto/test_numtheory.py`). |
| Discrete Logarithm | **Implemented & Tested** | Baby-Step Giant-Step (BSGS) and Pohlig-Hellman algorithm (`tests/crypto/test_asymmetric_hash.py`). |

#### Asymmetric Cryptography (RSA & ECC)
| Attack / Primitive | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| RSA Low Exponent ($e=3, 5$) | **Implemented & Tested** | Unpadded exact integer $e$-th root calculation (`tests/core/test_solver_rsa.py`). |
| RSA Batch GCD (Shared Primes) | **Implemented & Tested** | Pairwise $\gcd(N_i, N_j)$ recovery across multiple challenge public keys (`tests/core/test_solver_rsa.py`). |
| RSA Common Modulus Attack | **Implemented & Tested** | Extended Euclidean recovery for $c_1^{s_1} c_2^{s_2} \equiv m \pmod N$ (`tests/crypto/test_asymmetric_hash.py`). |
| Wiener's Attack | **Implemented & Tested** | Continued fraction convergent expansion for small private exponent $d < \frac{1}{3} N^{1/4}$ (`tests/crypto/test_asymmetric_hash.py`). |
| Håstad's Broadcast Attack | **Implemented & Tested** | CRT system solving for $e$ distinct ciphertexts with small $e$ (`tests/crypto/test_asymmetric_hash.py`). |
| Boneh-Durfee Attack | **Implemented & Tested** | Sub-lattice reduction for $d < N^{0.292}$ (`tests/crypto/test_asymmetric_hash.py`). |
| Franklin-Reiter Related Message | **Implemented & Tested** | Polynomial GCD recovery for affine-related plaintexts (`tests/crypto/test_asymmetric_hash.py`). |
| Bleichenbacher Padding Oracle | **Implemented & Tested** | PKCS#1 v1.5 adaptive chosen-ciphertext oracle attack simulator (`tests/crypto/test_asymmetric_hash.py`). |
| Bellcore CRT Fault Attack | **Implemented & Tested** | Faulty RSA signature factorization ($p = \gcd(s^e - m, N)$) (`tests/crypto/test_asymmetric_hash.py`). |
| ECC Point Arithmetic | **Implemented & Tested** | Weierstrass curve point addition, doubling, scalar multiplication (`tests/crypto/test_modern.py`). |
| ECDSA Nonce Reuse / Bias | **Implemented & Tested** | Private key recovery via duplicate nonce $k$ or truncated LSB/MSB bias (`tests/crypto/test_modern.py`). |
| Invalid Curve & Weak Curves | **Implemented & Tested** | Small subgroup confinement and singular curve attacks (`tests/crypto/test_modern.py`). |

#### Symmetric & Modern Cryptography
| Primitive / Attack | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| AES ECB Cut-and-Paste | **Implemented & Tested** | ECB block boundary detection and ciphertext splicing (`tests/crypto/test_symmetric_attacks.py`). |
| AES CBC Padding Oracle | **Implemented & Tested** | Byte-by-byte decryption oracle simulator (`tests/crypto/test_symmetric_attacks.py`). |
| AES CBC Bit-Flipping | **Implemented & Tested** | Predictable IV/ciphertext modification for plaintext injection (`tests/crypto/test_symmetric_attacks.py`). |
| AES GCM Nonce Reuse | **Implemented & Tested** | GHASH polynomial evaluation and authentication key $H$ recovery (`tests/crypto/test_symmetric_attacks.py`). |
| Meet-in-the-Middle (2DES) | **Implemented & Tested** | Double encryption intermediate state collision (`tests/crypto/test_symmetric_attacks.py`). |
| RC4 Key Scheduling Bias | **Implemented & Tested** | Fluhrer-Mantin-Shamir (FMS) weak key detection and keystream recovery (`tests/crypto/test_openssl_symmetric.py`). |
| ChaCha20 Nonce Reuse | **Implemented & Tested** | Keystream cancellation across identical nonces (`tests/crypto/test_openssl_symmetric.py`). |
| Diffie-Hellman Parameter Check | **Implemented & Tested** | Small subgroup confinement and composite modulus detection (`tests/crypto/test_modern.py`). |
| Merkle-Hellman Knapsack | **Implemented & Tested** | Superincreasing sequence modular recovery (`tests/crypto/test_modern.py`). |
| Shamir's Secret Sharing | **Implemented & Tested** | Lagrange polynomial interpolation over finite prime fields (`tests/crypto/test_modern.py`). |
| JWT Verification & Forgery | **Implemented & Tested** | `none` algorithm bypass, HMAC/RSA public-key algorithm confusion (`tests/crypto/test_modern.py`). |

#### Post-Quantum Cryptography (PQC)
| Algorithm / Tool | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| LWE Dual Kernel Solver | **Experimental & Tested** | Dual lattice reduction solving toy LWE instances ($n \le 30$) (`tests/crypto/test_pqc_lwe.py`). |
| NTRU Polynomial Ring | **Experimental & Tested** | Polynomial inversion over $\mathbb{Z}_q[x]/(x^N - 1)$ (`tests/crypto/test_pqc_lwe.py`). |
| Kyber-style (ML-KEM) Mechanics | **Experimental & Tested** | Toy parameter encapsulation and decryption failure analysis (`tests/crypto/test_pqc_lwe.py`). |
| Dilithium-style (ML-DSA) Mechanics | **Experimental & Tested** | Toy signature verification and rejection sampling validation (`tests/crypto/test_pqc_lwe.py`). |

---

### 3.2 `encoding` — Data Formats & Esolangs

| Feature / Format | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| Base Codecs | **Implemented & Tested** | Hex/Base16, Base32, Base58 (Bitcoin alphabet), Base64, Base64url, Base85/ASCII85, Base91 (`tests/encoding/test_bases.py`). |
| Text & Web Encodings | **Implemented & Tested** | URL encoding/decoding (including double-encoding), HTML entities, Unicode escapes (`\uXXXX`, `&#xNNNN;`) (`tests/encoding/test_text.py`). |
| Telecom Encodings | **Implemented & Tested** | International Morse Code, Baudot code, Manchester encoding, DTMF keypad strings (`tests/encoding/test_morse.py`). |
| Numeral Systems | **Implemented & Tested** | Binary, octal, decimal, Gray code, BCD, Negabinary (`tests/encoding/test_expansion.py`). |
| Compression Codecs | **Implemented & Tested** | Zlib, Gzip, Bzip2, LZMA with strict expansion-ratio bomb protection (`tests/encoding/test_expansion.py`). |
| Checksums | **Implemented & Tested** | CRC32, Luhn algorithm, Verhoeff checksum (`tests/encoding/test_expansion.py`). |
| Barcode & QR Processing | **Partially Tested** | Pure-Python matrix interpretation and optional zxing-cpp binding hooks (`tests/encoding/test_expansion.py`). |
| Brainfuck Interpreter | **Implemented & Tested** | 30,000-cell wrapping byte tape with step bounds (`tests/encoding/test_esolang.py`). |
| Ook! Interpreter | **Implemented & Tested** | Bidirectional Ook! to Brainfuck syntax translation (`tests/encoding/test_esolang.py`). |
| JSFuck Decoder | **Implemented & Tested** | Static AST/pattern evaluation without JavaScript runtime execution (`tests/encoding/test_esolang.py`). |
| Whitespace Interpreter | **Implemented & Tested** | Stack, arithmetic, heap, and flow-control execution (`tests/encoding/test_esolang.py`). |
| LOLCODE Interpreter | **Implemented & Tested** | Basic token and expression interpreter (`tests/encoding/test_esolang.py`). |
| Deadfish Interpreter | **Implemented & Tested** | 4-command bounded accumulator engine (`tests/encoding/test_esolang.py`). |
| Layered Auto-Decoder | **Implemented & Tested** | Recursive heuristic pipeline detecting and unwinding nested encodings (`tests/encoding/test_layered.py`). |

---

### 3.3 `stego` — Steganography & Concealment

| Technique / Format | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| PNG Chunk Inspection | **Implemented & Tested** | IHDR, tEXt, zTXt, iTXt, trailing data after IEND (`tests/stego/test_png.py`). |
| PNG LSB Extraction (zsteg-style) | **Implemented & Tested** | Scanline filter reversal (None, Sub, Up, Average, Paeth), RGB/BGR/all channel permutations, 1-4 bits (`tests/stego/test_lsb.py`). |
| Deflate Stream Anomaly | **Implemented & Tested** | Non-compressed IDAT blocks and compression ratio discrepancies (`tests/stego/test_advanced_stego.py`). |
| APNG & GIF Frame Inspection | **Implemented & Tested** | Frame delay anomalies and per-frame hidden payload extraction (`tests/stego/test_advanced_stego.py`). |
| Steghide Compatible Extraction | **Implemented & Tested** | Blowfish/Rijndael embedding simulation and dictionary cracking (`tests/stego/test_advanced_stego.py`). |
| Audio WAV Metadata & Samples | **Implemented & Tested** | RIFF structure, sample extraction (8/16-bit PCM), LIST/INFO chunks (`tests/stego/test_morse_audio.py`). |
| Audio Morse Code Decoder | **Implemented & Tested** | Dynamic envelope tracking, adaptive thresholding, dot/dash timing classification (`tests/stego/test_morse_audio.py`). |
| Audio Spectrogram & DTMF | **Implemented & Tested** | STFT spectrogram matrix and Goertzel-algorithm DTMF frequency extraction (`tests/stego/test_dtmf_usb.py`). |
| Text Concealment | **Implemented & Tested** | Null ciphers, acrostics, Cardan grille, mirror/reverse text, upside-down Unicode (`tests/stego/test_text_stego.py`). |

---

### 3.4 `binary` — Static Executable & File Triage

| Feature / Parser | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| File Identification | **Implemented & Tested** | Extended magic signatures for ELF, PE, Mach-O, archives, media, and docs (`tests/binary/test_identify.py`). |
| String Harvesting | **Implemented & Tested** | ASCII, UTF-16LE, and UTF-16BE extraction with offset mapping (`tests/binary/test_strings.py`). |
| Shannon Entropy Profiling | **Implemented & Tested** | Whole-file entropy and sliding-window high-entropy region locator (`tests/binary/test_entropy.py`). |
| ELF Executable Parser | **Implemented & Tested** | 32/64-bit, LE/BE, program headers, section headers, symbol resolution (`tests/binary/test_elf.py`). |
| PE & Mach-O Header Triage | **Implemented & Tested** | COFF headers, optional headers, Mach-O load commands and CPU targets (`tests/binary/test_expansion.py`). |
| Packer Detection | **Implemented & Tested** | UPX signature detection and section name heuristics (`tests/binary/test_expansion.py`). |
| Binary Arithmetic Utilities | **Implemented & Tested** | Endianness swap, Hamming distance, bit popcount (`tests/binary/test_misc.py`). |

---

### 3.5 `forensic` — Disk, Memory & Archive Analysis

| Feature / Format | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| ZIP Inspection & Extraction | **Implemented & Tested** | Central directory parsing, comment extraction, dictionary cracking (`tests/forensic/test_zip.py`). |
| Multi-Archive Triage | **Implemented & Tested** | Pure-Python header parsers for TAR, GZIP, BZIP2, XZ, 7z, and RAR (`tests/forensic/test_expansion.py`). |
| Signature File Carver | **Implemented & Tested** | Magic-based carving for PNG, JPEG, PDF, ZIP, and GIF blobs (`tests/forensic/test_deep_forensics.py`). |
| Partition & Disk Layout | **Implemented & Tested** | MBR partition table parsing, GPT header and partition GUIDs (`tests/forensic/test_deep_forensics.py`). |
| Filesystem Triage | **Implemented & Tested** | FAT12/16/32 BIOS Parameter Block (BPB) parameter decoding (`tests/forensic/test_deep_forensics.py`). |
| Forensic Timestamps | **Implemented & Tested** | Windows FILETIME, Apple Cocoa, Chrome WebKit, Unix, DOS date/time (`tests/forensic/test_deep_forensics.py`). |
| Acropalypse Recovery | **Implemented & Tested** | Image dimension reconstruction for CVE-2023-21036 / CVE-2023-28646 (`tests/forensic/test_advanced_forensics.py`). |
| SQLite Forensics | **Implemented & Tested** | B-tree page parsing, schema recovery, unallocated freelist carving (`tests/forensic/test_advanced_forensics.py`). |
| Git Forensics | **Implemented & Tested** | Loose object decompression, commit log graph, reflog inspection (`tests/forensic/test_advanced_forensics.py`). |
| PDF Forensics | **Implemented & Tested** | XREF cross-reference parsing, object stream decompression, hidden metadata (`tests/forensic/test_advanced_forensics.py`). |

---

### 3.6 `pcap` — Packet & Network Stream Analysis

| Protocol / Feature | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- |
| PCAP / PCAPNG Reader | **Implemented & Tested** | Pure-Python streaming reader for standard capture formats (`tests/pcap/test_pcap.py`). |
| Flow Analytics | **Implemented & Tested** | Bidirectional TCP/UDP conversation tracking, packet count, byte volume (`tests/pcap/test_pcap.py`). |
| DNS Query Inspection | **Implemented & Tested** | Record type parsing (A, AAAA, MX, TXT, NS, CNAME), client/server mapping (`tests/pcap/test_pcap.py`). |
| HTTP Protocol Reconstruction | **Implemented & Tested** | Request method/URI/headers and response body reassembly (`tests/pcap/test_pcap.py`). |
| Plaintext Credential Harvesting | **Implemented & Tested** | HTTP Basic Auth, FTP `USER`/`PASS`, SMTP `AUTH`, form POST parameters (`tests/pcap/test_pcap.py`). |
| USB HID Extraction | **Implemented & Tested** | Keystroke recovery from USB keyboard/mouse interrupt reports (`tests/pcap/test_advanced_pcap.py`). |
| Bluetooth HCI Inspection | **Implemented & Tested** | HCI packet headers, advertising packets, L2CAP connections (`tests/pcap/test_advanced_pcap.py`). |
| Wireless (802.11) Triage | **Implemented & Tested** | Beacon frame SSID extraction, EAPOL 4-way handshake carving (`tests/pcap/test_advanced_pcap.py`). |
| DNS Exfiltration Detection | **Implemented & Tested** | High-entropy subdomain tunneling and TXT record payload extraction (`tests/pcap/test_advanced_pcap.py`). |

---

### 3.7 `network`, `web`, `osint`, `password`, `reverse`

| Module | Feature | Status | Implementation Details & Test Coverage |
| :--- | :--- | :--- | :--- |
| `network` | TCP Port Scanner | **Partially Tested** | Non-destructive socket connect scanner with worker pool throttling (`tests/network/test_network.py`). |
| `network` | Banner Grabbing | **Partially Tested** | Protocol probes for HTTP, FTP, SSH, SMTP (`tests/network/test_network.py`). |
| `network` | TLS Certificate Audit | **Partially Tested** | Subject, Issuer, SANs, validity ranges, cipher suite checks (`tests/network/test_network.py`). |
| `web` | Security Headers | **Implemented & Tested** | Audit for CSP, HSTS, X-Frame-Options, CORS, server tokens (`tests/web/test_web.py`). |
| `web` | Directory Fuzzing | **Partially Tested** | Concurrent path probing with status filtering (`tests/web/test_web.py`). |
| `web` | Asset & Form Extraction | **Implemented & Tested** | Regex/HTML parsing for hidden inputs, links, comments, scripts (`tests/web/test_web.py`). |
| `web` | SSTI & GraphQL Probes | **Implemented & Tested** | Template injection signatures and GraphQL schema introspection (`tests/web/test_advanced_web.py`). |
| `osint` | DNS-over-HTTPS (DoH) | **Partially Tested** | Cloudflare/Google JSON API queries for A/AAAA/MX/TXT records (`tests/osint/test_osint.py`). |
| `osint` | WHOIS Client | **Partially Tested** | Pure-socket port 43 client with IANA referral chasing (`tests/osint/test_osint.py`). |
| `osint` | Subdomain Enumeration | **Partially Tested** | crt.sh Certificate Transparency log queries (`tests/osint/test_osint.py`). |
| `password` | Rule-Based Mutator | **Implemented & Tested** | Leetspeak, case shifting, prefix/suffix insertion (`tests/password/test_password.py`). |
| `password` | Combinatorial Wordlists | **Implemented & Tested** | Cartesian products, policy filters, deduplication (`tests/password/test_password.py`). |
| `password` | Dictionary Hash Cracking | **Implemented & Tested** | MD5, SHA-1, SHA-256, SHA-512, NTLM hash matching (`tests/password/test_password.py`). |
| `reverse` | Disassembly Engine | **Implemented & Tested** | Pure-Python linear instruction decoding (`tests/reverse/test_reverse.py`). |
| `reverse` | Control Flow Graph (CFG) | **Implemented & Tested** | Basic block demarcation and branch edge reconstruction (`tests/reverse/test_advanced_reverse.py`). |
| `reverse` | Binary Hardening Checks | **Implemented & Tested** | Canary patterns, anti-debugging tricks, ROP gadget scanning (`tests/reverse/test_advanced_reverse.py`). |

---

## 4. AutoSolver Capabilities & Limitations

The AutoSolver (`ichnos solve`) correlates challenge files, extracts parameters via an AST harvester and regex matchers, and deduces attack paths.

```
                  Challenge Directory or File
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
   Source Code (.py, .c)                 Data Artifacts (.txt, .enc, .pcap)
            │                                     │
   AST Parameter Harvester               Format & Magic Identifier
   [n, e, c, p, q, iv, key]              [Hex, Base64, ELF, PCAP, ZIP]
            │                                     │
            └──────────────────┬──────────────────┘
                               ▼
                   Correlated Parameter State
                               │
           ┌───────────────────┼───────────────────┐
           ▼                   ▼                   ▼
    RSA / ECC Attacks    XOR & Ciphers     Forensic & Carving
   • Batch GCD          • Repeating XOR    • ZIP Comments
   • Wiener / Root      • Single-Byte      • Embedded Files
   • Small Factors      • Vigenère/Caesar  • Stream Reassembly
           │                   │                   │
           └───────────────────┬───────────────────┘
                               ▼
                     Result & Flag Check
                      (FLAG{...} pattern)
                               │
                               ▼
                   Deduction Trace & Plaintext
```

### 4.1 What AutoSolver CAN Solve
1. **Multi-File RSA Challenges**: Automatically correlates `chall.py` and `output.txt`, extracting $(N, e, c)$, running small factor tests, low-exponent roots ($e=3, 5$), batch GCD across multiple moduli, Wiener's continued fractions, or Håstad's broadcast attack.
2. **Layered Obfuscation**: Unwinds multiple levels of encoding (e.g. `Base64 -> Hex -> URL -> Morse -> Plaintext`).
3. **Classical Ciphers**: Automatically identifies and cracks Caesar, Atbash, Affine, and Vigenère using statistical index of coincidence and frequency scoring.
4. **XOR Streams**: Brute-forces single-byte XOR keys and calculates key lengths for repeating-key XOR via normalized Hamming distance.
5. **Corrupted or Embedded Archives**: Extracts hidden comments in ZIP headers and carves uncompressed files without needing external decompression tools.
6. **Network Capture Credential Leakage**: Automatically parses PCAP files to extract plaintext HTTP, FTP, or SMTP credentials.
7. **Toy LWE Post-Quantum Challenges**: Solves dual-kernel lattice challenges for small lattice dimensions ($n \le 30$).

### 4.2 What AutoSolver CANNOT Solve
1. **Cryptographically Secure Parameters**: Cannot factor standard 2048-bit or 4096-bit RSA keys with strong random primes and $e=65537$.
2. **Hard Discrete Logarithms**: Cannot solve discrete log over large prime fields ($> 64$ bits) or secure curves (e.g. Secp256k1) without implementation vulnerabilities.
3. **Secure Block Ciphers**: Cannot recover AES-128, AES-256, or ChaCha20 keys without structural oracle access or key reuse.
4. **Arbitrary Dynamic Obfuscation**: Cannot solve custom virtual-machine obfuscators without structured signatures.
5. **Memory Exploitation / Binary Pwn**: Cannot generate dynamic memory corruption payloads (ROP chains, heap exploitation, shellcode injection).
6. **Multi-Step Dynamic Web Workflows**: Cannot execute client-side JavaScript or bypass CAPTCHAs.

---

## 5. Explicitly Out of Scope

The following domains are permanently outside the scope of Project Ichnos:
- **Web UI / Electron Dashboard**: Ichnos is strictly a terminal-first application (CLI + Textual TUI).
- **Mandatory Cloud / LLM API Dependencies**: All analysis must function entirely offline.
- **Dynamic Binary Exploitation / Pwn Framework**: Tools like `pwntools` already dominate this domain; Ichnos focuses on static triage, analysis, and cryptanalysis.
- **Full Decompilation Engine**: Full decompilation is left to dedicated suites (Ghidra, IDA Pro); Ichnos provides lightweight disasm, CFG, and gadget scanning.
- **GPU-Accelerated Password Cracking**: Tools like Hashcat specialize in GPU cracking; Ichnos focuses on CPU CTF-scale dictionary and mutation attacks.
- **General Puzzles**: Sudoku, crossword, nonogram, or chess solvers.
