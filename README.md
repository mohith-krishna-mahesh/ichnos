# Ichnos

> *A modular, low-level command-line security/CTF toolkit.*

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Ichnos is a local-first, zero-mandatory-binary-dependency CLI and TUI toolkit designed for CTF competitions, cryptanalysis, and security research. It provides a unified, pipeable interface across cryptography, encoding, steganography, binary reverse engineering, forensics, packet capture analysis, and web reconnaissance — paired with an autonomous solver engine and a dual-mode (Expert/Learner) pedagogical architecture.

---

## Installation

### Standalone Global Install (Recommended)

Install Ichnos globally with [`uv`](https://github.com/astral-sh/uv) so that the `ichnos` command is available immediately from any terminal and directory:

```bash
# Clone the repository
git clone https://github.com/<org>/ichnos.git && cd ichnos

# Install as a standalone global tool
uv tool install .
```

Once installed, invoke `ichnos` from **any directory** without needing to activate virtual environments or use `python -m`:

```bash
# Launch the interactive persistent TUI shell
ichnos

# Or execute one-shot CLI commands directly
ichnos analyze suspicious_file.png
ichnos solve ./challenge_bundle/
ichnos crypto caesar "KHOOR" --shift 3
```

### Working Directory Independence
When running `ichnos` globally, relative file paths (e.g. `ichnos binary identify sample.bin` or `load ./target.png` within the TUI) resolve strictly against the directory from which you invoked the command (your current working directory), **not** the package installation location.

### Development Mode

```bash
uv sync
uv run pytest tests/ -q
uv run ichnos --help
```

---

## Interactive TUI Shell & Modes

Running `ichnos` without arguments opens the full-screen terminal UI powered by Textual.

### Shell Keybindings & Shortcuts

| Shortcut | Action |
|----------|--------|
| `Enter` | Advance past startup animation / execute command prompt |
| `PageUp` / `PageDown` | Global scroll output view up / down |
| `Ctrl+R` | Reverse search command history |
| `Ctrl+U` | Clear prompt line from cursor to beginning |
| `Ctrl+W` | Delete previous word in prompt |
| `Ctrl+Shift+C` | Clean clipboard copy of active result/finding (OSC 52 + `pyperclip` fallback) |
| `Ctrl+D` / `exit` | Exit shell |

### Dual Operational Modes (Expert vs. Learner)

Ichnos supports seamless switching between terse competition workflows and structured learning:

- **Expert Mode (Default)**: Produces crisp, minimal output designed for rapid CTF flag submission:
  ```text
  [Answer] picoCTF{c0pp3rsm1th_sh0rt_r00t}
  [How: rsa_coppersmith | key=d_bits | confidence=100%]
  ```
- **Learner Mode**: Augments results with a dedicated Rich panel detailing the underlying mathematics, algorithm steps, or vulnerability root cause, accompanied by a numbered **Deduction Trail**:
  ```bash
  ichnos> mode learner
  # View pedagogical explanations alongside each output
  ichnos> steps
  # Opens interactive modal to inspect intermediate matrices, values, and rationales
  ```

Within modals (Candidate Selector `select`, Step Inspector `steps`):
- `Up` / `Down` / `j` / `k`: Navigate items
- `/`: Filter/search items
- `g` / `G`: Jump to top / bottom
- `Enter`: Select or inspect intermediate values
- `Escape`: Close modal

---

## AutoSolver — Autonomous CTF Challenge Engine

The `solve` command ingests challenge bundles, extracts parameters across multiple files, and orchestrates deterministic attack chains:

```bash
# Point to a CTF challenge directory or zip
ichnos solve ./rsa_challenge/

# Solve from piped challenge text
cat chal.py | ichnos solve

# Machine-readable JSON output
ichnos solve --json ./forensics_chal/
```

The AutoSolver detects modular patterns, performs RSA small-e/Wiener/Coppersmith/common-modulus attacks, extracts LSB steganography, carves deleted container/git artifacts, cracks encrypted archives, and constructs full deduction traces.

---

## Quick Start — Modules & Attacks

### 1. Analysis & Auto-Detection
```bash
# Auto-detect file formats, entropy, encodings, and recommended attacks
ichnos analyze mystery.bin
echo "GUVF VF N FRPERG ZRFFNTR" | ichnos analyze
```

### 2. Cryptography (`crypto`)

#### Classical Ciphers & XOR
```bash
# Caesar, Atbash, Affine, Vigenère
ichnos crypto caesar --brute "GUVF VF N FRPERG ZRFFNTR"
ichnos crypto vigenere --crack ciphertext.txt
ichnos crypto substitution ciphertext.txt

# Single-byte & repeating-key XOR
ichnos crypto xor-single encrypted.bin
ichnos crypto xor-repeating encrypted.bin
ichnos crypto xor-crib ct1.bin --crib "the " --ct2 ct2.bin
```

#### RSA Cryptanalysis
```bash
# Factorization & Wiener low private exponent
ichnos crypto rsa factor 84923
ichnos crypto rsa wiener -n $N -e $E

# Common Modulus & Common Factor attacks
ichnos crypto rsa common-mod -n $N --e1 $E1 --e2 $E2 --c1 $C1 --c2 $C2
ichnos crypto rsa common-factor --n1 $N1 --n2 $N2 -c $C

# Coppersmith small-roots / stereotyped messages
# Franklin-Reiter related message attack
# Boneh-Durfee bivariate lattice reduction (d < N^0.292)
# Bellcore RSA-CRT fault injection factorizer
# Bleichenbacher PKCS#1 v1.5 padding oracle
```

#### Symmetric & Elliptic Curve
```bash
# Meet-in-the-Middle (2DES / double encryption engine)
# DES weak key detection (4 standard weak, 12 semi-weak pairs)
# Biased-nonce ECDSA Hidden Number Problem lattice recovery
# AES/ChaCha20 CBC bit-flipping, ECB cut-and-paste, CTR nonce reuse
```

#### Number Theory & Hashes
```bash
ichnos crypto math gcd 48 18
ichnos crypto math modinv 3 26
ichnos crypto math crt --remainders 2,3,2 --moduli 3,5,7
ichnos crypto math isprime 104729
ichnos crypto hash-id "5d41402abc4b2a76b9719d911017c592"
```

---

### 3. Encoding (`encoding`)
```bash
# Multi-layered automated unwrapping
ichnos encoding auto "U0dWc2JHOD0="

# Base-16/32/58/64/85/91
echo "aGVsbG8gd29ybGQ=" | ichnos encoding decode --format base64
ichnos encoding decode "48656c6c6f" --format hex

# Esolang interpreters (Brainfuck, Ook!, Whitespace, JSFuck, LOLCODE, Deadfish)
echo "iissso" | ichnos encoding esolang --lang deadfish
```

---

### 4. Steganography (`stego`)
```bash
# PNG chunk analysis & LSB extraction
ichnos stego png image.png
ichnos stego lsb image.png --brute

# Animated PNG (APNG) frame and metadata extraction
# Multi-frame GIF comment and timing-delay steganography
# Deflate / IDAT raw compression anomaly detector
# Audio WAV parsing and Morse-in-audio recovery
```

### 5. Binary Analysis & Reverse Engineering (`binary`, `reverse`)
```bash
# File identification, strings, entropy analysis, ELF parsing
ichnos binary identify mystery.bin
ichnos binary strings binary.exe --encoding utf16
ichnos binary entropy packed.exe --window 512
ichnos binary elf program

# Disassembly and Control Flow Graph generation
ichnos reverse disasm payload.bin --arch x86_64
ichnos reverse cfg function.bin --arch x86_64

# Non-cryptographic hash identifier (FNV-1a, Murmur3, djb2, sdbm, CRC32, Adler32)
# ROP/JOP gadget scanner with category filters
# Dynamic execution & micro-emulation (Unicorn + pure-Python fallback)
# Format-string call-site vulnerability auditor
# Control Flow Flattening (CFF) / OLLVM dispatcher analyzer
```

---

### 6. Forensics (`forensic`)
```bash
# Encrypted ZIP analysis and dictionary cracking
ichnos forensic zip inspect archive.zip
ichnos forensic zip crack protected.zip --wordlist rockyou.txt

# Timestamp conversion (FILETIME, Cocoa, WebKit, Unix)
ichnos forensic timestamp 133481234567890000 --format filetime

# Git repository forensics (loose objects, packfiles, commit DAG, deleted blobs)
# Docker/OCI container layer inspection and .wh.<filename> whiteout recovery
# SQLite B-tree leaf page freeblock, deleted record, and unallocated space carver
# Acropalypse (CVE-2023-21036 / CVE-2023-28303) trailing data recovery
```

---

### 7. Network & PCAP (`pcap`)
```bash
# Capture traffic summary, flow extraction, DNS queries, plaintext credentials
ichnos pcap summary capture.pcap
ichnos pcap flows capture.pcap
ichnos pcap dns capture.pcap
ichnos pcap credentials capture.pcap

# Bluetooth HCI/L2CAP/HID keystroke and BLE attribute extractor
# 802.11 WPA/WPA2 4-way handshake (EAPOL) extractor to Hashcat 22000
# ICMP & DNS tunneling / exfiltration stream reassembler
```

---

### 8. Web Reconnaissance (`web`)
```bash
# HTTP security headers audit
ichnos web headers https://example.com

# Concurrent endpoint fuzzing
ichnos web fuzz https://example.com --wordlist paths.txt

# HTML asset, script, comment, and email extraction
ichnos web extract page.html

# GraphQL introspection query builder & endpoint detector
# Server-Side Template Injection (SSTI) polyglot fingerprinter
```

---

## Module Status & Capabilities

| Module | Status | Highlights |
|:---|:---:|:---|
| `crypto` | ✅ Complete | Classical ciphers, XOR, hashing, number theory, symbol tables, RSA (Coppersmith, Wiener, Boneh-Durfee, Bleichenbacher, Bellcore, Franklin-Reiter), ECC (biased nonces), DES weak keys, MITM |
| `encoding` | ✅ Complete | Base-N (16/32/58/64/85/91), URL/HTML/Unicode, Morse, Esolangs (Brainfuck, Ook!, JSFuck, Whitespace, LOLCODE, Deadfish), Layered recursive auto-decode |
| `stego` | ✅ Complete | PNG chunks, zsteg-style LSB brute force, APNG frames, GIF timing delays, Deflate anomalies, WAV analysis, Morse-in-audio, text null ciphers |
| `binary` | ✅ Complete | Magic byte identification, ASCII/UTF-16 strings, sliding-window Shannon entropy, ELF 32/64 parser, non-crypto hash identification (FNV, Murmur, djb2) |
| `reverse` | ✅ Complete | Capstone disassembly with pure-Python fallback, ASCII CFG rendering, binary patching, ROP/JOP gadget scanner, micro-emulator, format string auditor, CFF deobfuscator |
| `forensic` | ✅ Complete | ZIP/TAR/archive analysis, carving, disk partition inspection, timestamp conversions, Git repo forensics, Docker layer whiteouts, SQLite freeblock carving, Acropalypse repair |
| `pcap` | ✅ Complete | PCAP parser, conversation flows, DNS/HTTP/credentials extraction, Bluetooth HID keystrokes, WPA2 handshakes (Hashcat 22000), ICMP/DNS exfiltration reassembly |
| `web` | ✅ Complete | HTTP header security audit, multithreaded directory fuzzing, HTML asset extraction, GraphQL introspection, SSTI polyglot engine fingerprinter |

*For future architectural roadmaps and explicit out-of-scope boundaries, consult [docs/SCOPE.md](docs/SCOPE.md) and [ARCHITECTURE.md](ARCHITECTURE.md).*

---

## Architecture & Design Principles

```
ichnos/
├── core/          # Pydantic models, I/O, pipeline, registry, heuristics, pedagogy, autosolver
├── crypto/        # Classical, modern, RSA, ECC, symmetric, stream, hashing, number theory, lattices
├── encoding/      # Base-N, text encodings, Morse, esolangs, recursive layered unwrap
├── stego/         # Image (PNG/APNG/GIF/LSB), audio (WAV/Morse), text steganography
├── binary/        # File ID, strings, entropy, ELF, non-crypto hash identification
├── reverse/       # Disassembly, CFG, emulation, ROP gadgets, format strings, CFF
├── forensic/      # Archives, carving, filesystems, timestamps, Git, Docker, SQLite, repair
├── pcap/          # Packets, flows, credentials, Bluetooth HID, WPA2, tunneling exfiltration
├── web/           # Headers, fuzzing, asset extraction, GraphQL, SSTI
├── ui/            # Textual TUI, custom screens, modals, syntax themes, mascot renderer
└── cli/           # Typer commands, flags, and JSON serialization
```

1. **Zero-Mandatory Binary Dependencies**: Every native module includes a pure-Python fallback (pure-Python x86 disassembler, LLL reduction, crypto primitives, raw struct unpackers).
2. **Deterministic Layering**: Low-level domain modules never depend on the UI or CLI layers.
3. **Structured Data Flow**: All modules return typed Pydantic models (`Finding`, `Candidate`, `Result`, `DeductionStep`), enabling seamless JSON serialization (`--json`) and UI table rendering.

---

## License

MIT — see [LICENSE](LICENSE).
