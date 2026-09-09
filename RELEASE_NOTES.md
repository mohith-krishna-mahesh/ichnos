# Project Ichnos v0.1.0

First release of Ichnos, a modular CLI and TUI toolkit for CTF challenges and security research.

### Features

#### Autonomous Solver (`ichnos solve`)
- Static AST parameter harvester: extracts variables (n, e, c, p, q, iv, key) directly from Python challenge scripts without executing untrusted code.
- Deterministic attack pipeline: correlates harvested parameters with challenge files to execute math attacks and file parsers automatically.
- Live deduction trace: outputs each step of the deduction process along with the mathematical logic and the recovered flag.

#### Cryptanalysis (`ichnos crypto`)
- Classical ciphers: Caesar (ROT-N brute force), Atbash, Affine, Vigenere (IoC and Kasiski key-length detection), monoalphabetic substitution (quadgram hill climbing), and historical symbol tables (Pigpen, Tap Code, Morse, Braille, Semaphore, Elder Futhark).
- Number theory: extended Euclidean GCD, modular inverse, Chinese Remainder Theorem (CRT), Miller-Rabin primality testing, Pollard rho factorization, continued fractions, and discrete logarithms (BSGS).
- RSA attacks: low public exponent roots (e=3, 5), batch GCD across multiple moduli, Wiener continued fraction attack, common modulus attack, and Hastad broadcast attack.
- Elliptic curve crypto: Weierstrass point arithmetic, curve parameter recovery (modulus p, coefficients a and b) from point-doubling triples (P, 2P, 4P), and ECDSA nonce reuse private key recovery.
- Post-quantum crypto: NTRU negacyclic lattice reduction (LLL and BKZ) for private polynomial recovery, and small-dimension LWE dual-kernel lattice solver.
- Symmetric crypto: OpenSSL parameter and password cracking (brute-forces ciphers, digests, and PBKDF2 iterations against Salted__ data), single-byte and repeating-key XOR cracking, and AES oracle attacks (ECB byte-at-a-time, CBC padding oracle, CBC bit-flipping, GCM nonce reuse).

#### Encodings (`ichnos encoding`)
- Base codecs: Hex, Base16, Base32, Base58 (Bitcoin), Base64, Base85, and Base91.
- Text transforms: URL encoding (single and double), HTML entities, and Unicode escapes.
- Esolang interpreters: Brainfuck (30,000 cell tape), Ook!, Whitespace, JSFuck (static pattern decoder), LOLCODE, and Deadfish.
- Layered auto-decoder: recursively unwinds nested encoding chains with printable character heuristic scoring.

#### Steganography (`ichnos stego`)
- Image analysis: PNG chunk parser (IHDR, tEXt, zTXt, iTXt, and trailing overlay detection) and brute-force LSB bit-plane extractor across all channel and bit orderings.
- Subtitle steganography: Substation Alpha (.ass) vector drawing parser that reconstructs and decodes hidden QR codes.
- Audio steganography: RIFF/WAV metadata and sample parser, adaptive Morse audio tone detector, and DTMF keypad decoder.

#### Forensics (`ichnos forensic`)
- ZIP archive tools: central directory parser, uncompressed archive carving, comment extractor, password detection, and dictionary attack runner.
- Archive triage: pure-Python header parsers for TAR, GZIP, BZIP2, XZ, 7z, and RAR.
- File carving: signature-based carving for embedded PNG, JPEG, PDF, and ZIP files.
- OpenSSH forensics: wire-format parser for ssh-ed25519 and ssh-rsa public keys with XOR keystream payload recovery.

#### Network and Packet Capture (`ichnos pcap`, `ichnos network`)
- Streaming PCAP/PCAPNG parser: bidirectional flow tracking, DNS query extraction, and HTTP request and response reconstruction.
- Credential harvesting: extracts plaintext HTTP Basic Auth, FTP, and SMTP credentials from packet streams.
- CTF protocol decoders: USB HID keyboard packet extractor.
- Network utilities: non-destructive TCP connect port scanner, banner grabber, and TLS certificate inspector.

#### Wordlist Management (`ichnos wordlists`)
- Bundled offline lists: includes curated small wordlists (top 1000 passwords, default service logins, common web paths, PINs) for zero-network use.
- Resolution hierarchy: checks explicit CLI flags, ICHNOS_WORDLIST env var, user cache (~/.config/ichnos/wordlists/), and standard system paths (/usr/share/wordlists/).
- Streaming fetcher: on-demand downloader with automatic decompression for larger dictionaries (rockyou, top100k, raft-large, subdomains-top100k).

#### Terminal User Interface (`ichnos`)
- Full-screen split-view terminal interface built with Textual.
- Vector ASCII companion mascot with status-reactive states (idle, blinking, thinking, celebrating).
- Custom JSON theme engine supporting external .theme files with 6 built-in themes (cyber, hacker, matrix, monochrome, dracula, nord).

### Platform Status:
| Platform | Binary | Status |
| :--- | :--- | :--- |
| macOS Apple Silicon (arm64) | ichnos-macos-arm64 | Tested |
| Linux (x86_64) | ichnos-linux-x86_64 | Not tested locally (CI build) |
| Windows (x86_64) | ichnos-windows-x86_64.exe | Not tested locally (CI build) |

### Install:
```bash
curl -fsSL https://raw.githubusercontent.com/mohith-krishna-mahesh/ichnos/main/scripts/install.sh | bash
```

Or from source:
```bash
pip install .
```

Or:
```bash
uv pip install .
```

See README.md and CHANGELOG.md for the complete command reference.