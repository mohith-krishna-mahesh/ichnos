# Changelog

All notable changes to **Ichnos** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-09-08

### Initial Open-Source Release

This marks the inaugural release of **Ichnos** — a modular, local-first CLI and TUI security/CTF toolkit built with zero-dependency core algorithms and autonomous deduction capabilities.

---

### Core & AutoSolver

- **Autonomous Challenge Solver (`ichnos solve`)**: Multi-strategy deduction engine correlating parameters from challenge scripts, text files, and binary artifacts to execute deterministic attacks.
- **AST Parameter Harvester**: Safe AST inspection extracting variables (`n`, `e`, `c`, `p`, `q`, `ct`, `iv`, `key`) from Python challenge source code without code execution.
- **Unified Data Models**: Structured typing for `Finding`, `Candidate`, `Result`, and `Input` with JSON serialization support (`--json`).
- **Interactive Deductions Trace**: Real-time deduction step recording with mathematical rationale and command suggestions.

---

### Module Capabilities

#### 1. Crypto (`ichnos crypto`)
- **Classical Ciphers**: Caesar (ROT-N), Atbash, Affine, Vigenère (Kasiski examination, Index of Coincidence), Monoalphabetic substitution (quadgram hill-climbing solver), Transposition, Homophonic, Enigma machine.
- **Symbol Tables & Ancient Alphabets**: Pigpen, Templars, Tap Code, Morse, Braille, Semaphore flags, NATO Phonetic, Dancing Men, Standard Galactic Alphabet (Minecraft), Elder Futhark, Aurebesh, Klingon, 7-Segment, Bibi-binary, Hexahue, Gravity Falls.
- **XOR Engine**: Single-byte brute force (256 keys, English & printable scoring), repeating-key XOR (normalized Hamming distance key-length estimation), crib dragging / many-time-pad analysis.
- **Number Theory Toolbox**: Extended GCD, LCM, modular inverse, modular exponentiation, Chinese Remainder Theorem (CRT), Miller-Rabin primality testing, trial division + Pollard's rho factorization, Euler's totient, continued fractions and convergents, discrete logarithm (Baby-Step Giant-Step).
- **RSA Cryptanalysis**: Low public exponent ($e=3, 5$), small prime factor recovery, shared prime factor detection across multiple moduli (batch GCD), common modulus attack, Wiener's continued fraction attack, Håstad's broadcast attack, Boneh-Durfee, Bleichenbacher padding oracle, Franklin-Reiter related message attack.
- **Elliptic Curve Cryptography (ECC)**: Weierstrass point arithmetic, order calculation, curve parameter validation, invalid-curve attacks, ECDSA nonce reuse / bias recovery.
- **Symmetric & Modern Crypto**: AES (ECB cut-and-paste, CBC bit-flipping and padding oracle, GCM nonce reuse), DES, 3DES, RC4, ChaCha20, Diffie-Hellman small subgroup attacks, ElGamal, Merkle-Hellman knapsack recovery, JWT signature forging (`none` algorithm, RSA/HMAC algorithm confusion).
- **Post-Quantum Cryptography (PQC)**: Pedagogical/CTF tooling for Learning With Errors (LWE dual kernel solver), NTRU polynomial inversion, Kyber-style (ML-KEM) parameter inspection, Dilithium-style (ML-DSA) verification.

#### 2. Encoding (`ichnos encoding`)
- **Base Codecs**: Hex/Base16, Base32, Base58 (Bitcoin), Base64/Base64url, Base85/ASCII85, Base91.
- **Text & Web Encodings**: URL encoding (including double-encoding), HTML entity encoding, Unicode escapes (`\uXXXX`, `&#xNNNN;`).
- **Esolangs**: Brainfuck (30k cell tape), Ook!, JSFuck (static pattern decoder), Whitespace (stack and heap interpreter), LOLCODE (basic AST interpreter), Deadfish.
- **Layered Decoder**: Recursive auto-detection and multi-stage decoding pipeline with heuristic confidence scoring.

#### 3. Stego (`ichnos stego`)
- **Image Steganography**: Full PNG chunk inspector (IHDR, tEXt, zTXt, iTXt, trailing data detection), zsteg-style LSB permutation extraction across all channel and bit orderings, Deflate anomaly detection, APNG frame extraction, animated GIF frame carving, Steghide/passphrase cracking.
- **Audio Steganography**: RIFF/WAV metadata and sample extraction, automated morse code detection in audio via adaptive envelope thresholding, spectrogram generation, DTMF tone decoding.
- **Text Concealment**: Null ciphers (first letter, Nth letter, sentence initials), acrostics, Cardan grille, mirror and reverse writing, upside-down Unicode reversal.

#### 4. Binary (`ichnos binary`)
- **File & Architecture Identification**: Extended magic byte triage for ELF, PE, Mach-O, archive formats, images, audio, and documents.
- **String Extraction**: Fast ASCII, UTF-16LE, and UTF-16BE extraction with configurable minimum length thresholds.
- **Entropy Analysis**: Shannon entropy calculation across whole files and streaming sliding-window entropy with high-entropy region identification.
- **Executable Parsing**: Pure-Python ELF (32/64-bit, little/big-endian) header, program header, section header, and symbol table parsing. Basic PE and Mach-O header triage.
- **Binary Utilities**: Word-size endianness swapper, bitwise Hamming distance, and Hamming weight (popcount).

#### 5. Forensics (`ichnos forensic`)
- **ZIP & Archive Forensics**: Central directory parsing, uncompressed file extraction, archive and entry comment harvesting, password protection detection, dictionary cracking.
- **Archive Triage**: Pure-Python header parsers for TAR, GZIP, BZIP2, XZ, 7z, and RAR.
- **Signature-Based File Carving**: Automatic boundary carving for PNG, JPEG, PDF, ZIP, and GIF files embedded in raw blobs.
- **Filesystem & Volume Triage**: MBR partition tables, GPT headers and GUIDs, FAT12/16/32 BIOS Parameter Blocks (BPB).
- **Forensic Timestamp Decoders**: Windows FILETIME, Apple Cocoa Core Data, Google Chrome WebKit, Unix epoch, MS-DOS date/time.
- **Specialized CTF Tools**: Acropalypse (CVE-2023-21036 / CVE-2023-28646) PNG image reconstruction, Git repository object/commit/ref parsing, SQLite database schema inspection and unallocated page carving, PDF cross-reference table and stream analysis.

#### 6. PCAP (`ichnos pcap`)
- **Packet & Stream Parsing**: Pure-Python streaming parser for standard PCAP and PCAPNG captures.
- **Traffic Analysis**: Bidirectional network flow tracking, volume and duration analytics.
- **Protocol Extraction**: DNS query extraction, HTTP request/response reconstruction, plaintext credential harvesting (HTTP Basic Auth, FTP, SMTP, form POST data).
- **CTF Protocol Extensions**: USB keyboard/mouse HID packet decoding, Bluetooth HCI packet inspection, WiFi 802.11 beacon and handshake carving.

#### 7. Network (`ichnos network`)
- **Port Scanning**: Non-destructive, concurrent TCP connect scanner with worker pool throttling.
- **Banner Grabbing**: Protocol-aware probes for HTTP, FTP, SSH, and SMTP.
- **TLS Inspection**: Subject, Issuer, SANs, validity ranges, and cipher suite auditing.

#### 8. Web (`ichnos web`)
- **Security Headers Audit**: Compliance checking for CSP, HSTS, X-Frame-Options, CORS, and server information leaks.
- **Directory & Path Probing**: Concurrent HTTP endpoint fuzzing with configurable status code filtering and redirection tracking.
- **Asset & Data Extraction**: HTML anchor links, script sources, hidden form inputs, HTML comments, and exposed email patterns.
- **CTF Web Probes**: Server-Side Template Injection (SSTI) signature detection, GraphQL introspection querying.

#### 9. OSINT (`ichnos osint`)
- **DNS-over-HTTPS (DoH)**: Encrypted DNS record resolution (A, AAAA, MX, TXT) via Cloudflare and Google DoH endpoints.
- **WHOIS Client**: Zero-dependency pure-socket port 43 client with automatic IANA referral chasing.
- **Subdomain Enumeration**: Passive certificate transparency log queries via crt.sh combined with local DNS validation.

#### 10. Password (`ichnos password`)
- **Rule-Based Mutator**: Hashcat/John-style rule engine supporting leetspeak substitution, case shifting, prefix/suffix appending, and word reflection.
- **Wordlist Tools**: Combinatorial Cartesian product generator, policy filtering (length, character classes), and deduplication.
- **Dictionary Cracker**: CTF-scale pure-Python cracking for MD5, SHA-1, SHA-256, SHA-512, and Windows NTLM hashes.

#### 11. Reverse (`ichnos reverse`)
- **Disassembly**: Pure-Python disassembly for common architectures with instruction length decoding.
- **Control Flow Analysis**: Basic block detection and Control Flow Graph (CFG) generation.
- **Binary Hardening**: Pattern matching for anti-debugging tricks, canary checks, and common gadget scanning.

---

### Terminal User Interface (TUI)

- **Interactive Textual Application**: Full-featured TUI featuring responsive layouts, command prompt with history, output viewer, and interactive result modals.
- **Animated Companion Mascot**: Vector-styled ASCII terminal mascot with animated idle, blinking, thinking, and celebration states.
- **First-Class External Theme Engine**:
  - Six canonical themes (`hacker`, `cyber`, `matrix`, `monochrome`, `dracula`, `nord`) shipped in standard `.theme` JSON format in `themes/`.
  - Dynamic discovery from OS configuration directories (`~/.config/ichnos/themes/` on Linux/macOS, `%APPDATA%\ichnos\themes\` on Windows).
  - Runtime theme switching via `--theme` flag or in-app settings modal (`Ctrl+S`).

---

### Security & Hardening

- **Decompression Bomb Defenses**: Continuous expansion-ratio tracking ($>100\times$) and maximum decompressed size limits across all compression algorithms (Zlib, Gzip, Bzip2, LZMA).
- **AST Harvester DoS Protection**: Hard limits on AST node recursion depth, maximum integer literal size, and evaluation timeouts.
- **Path Traversal Guards**: Strict containment validation preventing directory traversal attacks during archive extraction.
- **Strict Memory Bounding**: Streaming parsing and generators prevent excessive memory usage during multi-gigabyte PCAP or wordlist operations (bounded peak RSS $<100$ MB in stress tests).

---

### Packaging & Distribution

- **Reproducible Nuitka Builds**: Automated compilation into standalone directories or single-file executables (`scripts/build_nuitka.py`).
- **Homebrew Formula**: Formula template in `Formula/ichnos.rb` for tap distribution.
- **Automated Installer**: Platform and architecture auto-detecting shell installer in `scripts/install.sh`.
- **GitHub Actions Release CI**: Cross-platform compilation matrix covering macOS ARM64, macOS x86_64, Linux x86_64, and Windows x86_64.
