# Ichnos

```
██╗ ██████╗██╗  ██╗███╗   ██╗ ██████╗ ███████╗
██║██╔════╝██║  ██║████╗  ██║██╔═══██╗██╔════╝
██║██║     ███████║██╔██╗ ██║██║   ██║███████╗
██║██║     ██╔══██║██║╚██╗██║██║   ██║╚════██║
██║╚██████╗██║  ██║██║ ╚████║╚██████╔╝███████║
╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
```

[![CI](https://github.com/mohith-krishna-mahesh/ichnos/actions/workflows/release.yml/badge.svg)](https://github.com/mohith-krishna-mahesh/ichnos/actions)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform Support](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](https://github.com/mohith-krishna-mahesh/ichnos)

> **A modular, local-first CTF and security analysis toolkit.**

---

## The Problem Ichnos Solves

When analyzing security challenges or conducting triage during competitive CTFs, researchers typically juggle a fragmented sprawl of disconnected utilities:
- **CyberChef**: Excellent for quick browser manipulations, but stumbles on multi-megabyte files, lacks CLI scripting, and cannot perform code AST parameter extraction.
- **dCode.fr**: Extensive classical cipher catalog, but locked behind cloud firewalls, cloud rate limits, and CAPTCHAs, preventing automated or air-gapped workflows.
- **zsteg / RsaCtfTool / binwalk**: Single-purpose tools written across disparate language ecosystems (Ruby, Python 2/3, C) with fragile native C dependencies and colliding package managers.
- **pwntools**: Indispensable for live binary exploitation and socket IO, but leaves cryptanalysis, forensics, and steganography to external scripts.

**Ichnos** unifies cryptanalysis, steganography, static binary analysis, forensics, network stream inspection, and encoding decoders into a single, zero-dependency core architecture. It pairs high-throughput CLI subcommands with a rich terminal user interface (TUI) and an **Autonomous Challenge Solver (`ichnos solve`)** that correlates multi-file challenges and executes mathematically deterministic deductions.

---

## Quick Start

### Installation

#### Option 1: Standalone Installer (macOS & Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/mohith-krishna-mahesh/ichnos/main/scripts/install.sh | bash
```

#### Option 2: Homebrew Tap (macOS & Linux)
```bash
brew tap mohith-krishna-mahesh/ichnos
brew install ichnos
```

#### Option 3: With `uv` (Recommended for Python Environments)
```bash
uv tool install ichnos
```

#### Option 4: Standard `pip`
```bash
pip install ichnos
```

---

## Usage Modes

### 1. Interactive Terminal User Interface (TUI)
Launch the responsive full-screen terminal interface with an animated companion mascot:
```bash
ichnos
```

### 2. Autonomous Challenge Solver
Point Ichnos at a CTF challenge folder containing source code and output files:
```bash
ichnos solve ./challenge/
```

### 3. Unix Composable CLI
Pipe data through Ichnos in standard Unix pipelines:
```bash
echo "U2FsdGVkX1+..." | ichnos encoding auto
cat capture.pcap | ichnos pcap credentials
ichnos crypto caesar "Lipps Asvph" --brute
```

---

## Autonomous Challenge Solver (`ichnos solve`)

The AutoSolver automates multi-step vulnerability correlation across heterogeneous files. Rather than blind brute force, it inspects challenge source files via an AST harvester, extracts mathematical and operational parameters, and deduces attack paths.

### AutoSolver Architecture & Dataflow

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

### What AutoSolver CAN Solve
- **Multi-File RSA Attacks**: Automatically links `chall.py` and `output.txt` to harvest $(N, e, c)$, running small factor tests, low-exponent roots ($e=3, 5$), batch GCD across multiple moduli, Wiener's continued fraction attack, or Håstad's broadcast attack.
- **Layered Multi-Encoding Chains**: Decodes nested combinations of Base64, Base32, Base58, Base85, Base91, Hex, URL, HTML entities, and Morse code.
- **Classical & Historical Ciphers**: Solves Caesar, Atbash, Affine, and Vigenère using statistical index of coincidence (IoC) and n-gram frequency scoring.
- **XOR Streams**: Brute-forces single-byte XOR keys and estimates repeating-key lengths via normalized Hamming distance.
- **Forensic Artifacts**: Extracts hidden comments in ZIP headers and carves uncompressed files without invoking external tools.
- **Network Credential Leaks**: Reassembles PCAP TCP streams to extract plaintext HTTP, FTP, and SMTP credentials.
- **Toy Post-Quantum Challenges**: Solves dual-kernel lattice attacks for small-dimension LWE instances ($n \le 30$).

### What AutoSolver CANNOT Solve
- **Cryptographically Secure Parameters**: Cannot break standard 2048-bit or 4096-bit RSA keys with strong random primes and $e=65537$.
- **Hard Discrete Logarithms**: Cannot solve discrete log over large prime fields ($> 64$ bits) or secure elliptic curves (e.g. Secp256k1).
- **Secure Block Ciphers**: Cannot recover AES-128, AES-256, or ChaCha20 keys without oracle flaws or key reuse.
- **Arbitrary Virtual-Machine Obfuscators**: Cannot automatically reverse undocumented custom bytecode interpreters without known signatures.
- **Active Binary Memory Exploitation**: Does not generate dynamic memory corruption payloads (ROP chains, heap corruption, shellcode injection).

---

## Module Overview

| Module | Purpose | Key Subcommands | Key Flags |
| :--- | :--- | :--- | :--- |
| **`crypto`** | Classical ciphers, XOR, number theory, RSA, ECC, modern crypto | `caesar`, `vigenere`, `affine`, `xor-single`, `xor-repeating`, `hash`, `rsa-attack`, `math` | `--shift`, `--key`, `--brute`, `--algo`, `--moduli` |
| **`encoding`** | Base codecs, text transforms, esolangs, layered decoding | `decode`, `encode`, `auto`, `morse`, `esolang` | `--format`, `--lang`, `--depth` |
| **`stego`** | Image bit-planes, audio analysis, text concealment | `png-chunks`, `lsb`, `wav-info`, `morse-audio`, `text-null` | `--order`, `--bits`, `--threshold` |
| **`binary`** | Static executable triage, string extraction, entropy profiling | `identify`, `strings`, `entropy`, `elf`, `endian`, `hamming` | `--min-len`, `--window`, `--encoding` |
| **`forensic`** | Archive inspection, file carving, filesystem structures | `zip-inspect`, `zip-comments`, `zip-crack`, `carve`, `timestamps` | `--wordlist`, `--format`, `--all` |
| **`pcap`** | Streaming packet analysis, protocol flows, credentials | `summary`, `flows`, `dns`, `http`, `credentials` | `--filter`, `--stream`, `--json` |
| **`network`** | Non-destructive TCP scanning, banner grabbing, TLS audit | `scan`, `banner`, `tls` | `--ports`, `--concurrency`, `--timeout` |
| **`web`** | Security header audits, directory fuzzing, parameter harvesting | `headers`, `fuzz`, `extract`, `ssti` | `--wordlist`, `--status`, `--cookie` |
| **`osint`** | DNS-over-HTTPS queries, WHOIS lookups, certificate logs | `dns`, `whois`, `subdomains` | `--type`, `--server`, `--crtsh` |
| **`password`** | Rule-based mutation, wordlist combiners, hash matching | `mutate`, `combine`, `crack` | `--rules`, `--hash-type`, `--policy` |
| **`reverse`** | Static disassembly, basic blocks, control flow graphs, gadgets | `disasm`, `cfg`, `gadgets`, `hardening` | `--arch`, `--depth`, `--syntax` |

---

## Concrete CLI Examples

### 1. Classical Cryptanalysis
```bash
# Brute-force and score all 26 Caesar shifts against English quadgrams
ichnos crypto caesar "Khoor Zruog" --brute

# Automatically calculate key length and crack Vigenère ciphertext
ichnos crypto vigenere "Lxfopvefrnhr" --crack
```

### 2. Multi-Layered Auto-Decoding
```bash
# Automatically unwind nested Base64 -> Hex -> URL encodings
ichnos encoding auto "JTJGNWElNkJmJTJGNWElNkIlMkY1YSU2Qg=="
```

### 3. Steganography & Image Inspection
```bash
# Scan all channel orders and bit depths for hidden flags (zsteg equivalent)
ichnos stego lsb challenge.png --brute

# Decode morse code audio tones from a WAV recording
ichnos stego morse-audio transmission.wav
```

### 4. Static Binary Triage
```bash
# Calculate Shannon entropy across a binary in 256-byte sliding windows
ichnos binary entropy firmware.bin --window 256

# Parse ELF headers, sections, and symbols without external tools
ichnos binary elf /bin/ls
```

### 5. Forensics & Embedded Carving
```bash
# Extract uncompressed ZIP file comments and directory metadata
ichnos forensic zip-comments capture.zip

# Carve embedded PNG, JPEG, and PDF files from a memory dump
ichnos forensic carve memory.dmp --all
```

### 6. Network Capture Analysis
```bash
# Stream through PCAP capture and extract plaintext authentication tokens
ichnos pcap credentials traffic.pcap
```

---

## Terminal User Interface (TUI) Showcase

The Ichnos TUI is built on [Textual](https://textual.textualize.io/) and delivers an ergonomic, keyboard-driven analyst workbench:

- **Vector ASCII Mascot**: Displays contextual emotional states (Idle, Blinking, Thinking during long computations, Celebration on flag recovery).
- **Split-View Workflow**: Real-time log/event console alongside interactive result inspection tables.
- **Keybindings**:
  - `Ctrl+C`: Interrupt active background operations safely.
  - `Ctrl+S`: Open settings modal to switch themes and configure heuristics.
  - `Tab` / `Shift+Tab`: Cycle focus between input prompt, result viewer, and history.
  - `Enter`: Submit command or drill down into candidate results.

---

## Custom Theme Engine

Ichnos treats custom user themes as first-class external configuration artifacts.

### Canonical Themes
Six canonical reference themes are included in the [`themes/`](themes/) directory:
- `hacker.theme`: Dark terminal slate with cyan highlights.
- `cyber.theme`: High-contrast cyberpunk neon palette.
- `matrix.theme`: Phosphor green CRT aesthetic.
- `monochrome.theme`: Minimalist grayscale terminal contrast.
- `dracula.theme`: Classic purple and pastel dark theme.
- `nord.theme`: Arctic, north-bluish clean palette.

### Theme Format (`.theme`)
Themes are standard JSON files defining UI palette variables:

```json
{
  "name": "my-theme",
  "primary": "#8ba4b0",
  "secondary": "#8992a7",
  "accent": "#8ea4a2",
  "foreground": "#BBBBBB",
  "background": "#0A0B0A",
  "surface": "#111111",
  "panel": "#12120f",
  "warning": "#c29b38",
  "error": "#c96565",
  "success": "#8ea4a2",
  "dark": true,
  "variables": {
    "border-color": "#393836",
    "border-focused": "#8ba4b0",
    "border-variant": "#8992a7",
    "text-muted": "#858585",
    "text-dim": "#625e5a",
    "header-bg": "#111111",
    "status-bg": "#111111",
    "prompt-bg": "#0A0B0A",
    "output-bg": "#0D0E0D"
  }
}
```

### Installation Directory
Drop `.theme` files into your OS configuration folder for automatic discovery:
- **Linux / macOS**: `~/.config/ichnos/themes/` (or `$XDG_CONFIG_HOME/ichnos/themes/`)
- **Windows**: `%APPDATA%\ichnos\themes\`

Select your theme via the CLI flag (`ichnos --theme my-theme`) or switch live in the TUI Settings modal (`Ctrl+S`).

---

## Performance & Scale Benchmarks

Benchmarked on macOS Apple Silicon using `scripts/profile_scale.py`:

| Operation | Scale Tested | Throughput | Peak Latency |
| :--- | :--- | :--- | :--- |
| **PCAP Packet Streaming** | 100,000 packets | **140,828 pkts/sec** | 0.710s total |
| **Wordlist Rule Mutator** | 1,000,000 variations | **3,195,021 variations/sec** | 0.313s total |
| **Sliding Window Entropy** | 10 MB binary blob | **311.9 MB/sec** | 0.032s total |
| **Decompression Bomb Defense** | Multi-GB ratio payload | **Caught & Terminated** | 0.0008s |
| **4096-bit Modular Inversion** | High-bit prime modulus | **100,000 ops/sec** | 0.00001s |
| **Total Memory Footprint** | Full stress pipeline | **< 100 MB RSS** | Strictly bounded |

---

## Security & Hardening

Because Ichnos parses untrusted, potentially hostile files from adversarial CTF competitions, every parser enforces strict isolation boundaries:
1. **Decompression Bomb Defenses**: Continuous expansion-ratio tracking ($> 100\times$) and maximum decompressed size limits across all compression engines (Zlib, Gzip, Bzip2, LZMA).
2. **Safe AST Parameter Harvesting**: Source code is evaluated via AST traversal with bounded recursion depth, strict timeouts, and maximum integer literal limits ($< 8192$ bits) to prevent algorithmic DoS.
3. **Path Traversal Guards**: Archive carving strictly validates normalized extraction targets to eliminate zip-slip vulnerabilities.
4. **Non-Destructive Active Probes**: Network and web scanning modules default to passive inspection or rate-limited TCP handshakes.

---

## Contributing

Contributions are welcome! Please review [CONTRIBUTING.md](CONTRIBUTING.md) for environment setup instructions, code formatting guidelines, and architectural patterns for adding new analyzers or AutoSolver attack paths.

To report security vulnerabilities, see [SECURITY.md](SECURITY.md).

---

## License & Third-Party Notices

Project Ichnos is licensed under the [MIT License](LICENSE).  
Third-party notices and acknowledgments are documented in [NOTICE](NOTICE).
