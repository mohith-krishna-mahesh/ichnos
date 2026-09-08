# Ichnos — System Architecture

> Version: `0.1.0`  
> Purpose: High-performance, zero-dependency, modular security research and CTF automation toolkit.

---

## 1. Architectural Philosophy & Principles

1. **Strict Dependency Hierarchy**:
   ```
   ┌────────────────────────────────────────────────────────┐
   │                       UI Layer                         │
   │       (Textual TUI, Reactive State, Screens, Mascot)    │
   └──────────────────────────┬─────────────────────────────┘
                              │ calls
   ┌──────────────────────────▼─────────────────────────────┐
   │                       CLI Layer                        │
   │         (Typer Sub-Apps, Flags, JSON Serializers)      │
   └──────────────────────────┬─────────────────────────────┘
                              │ invokes
   ┌──────────────────────────▼─────────────────────────────┐
   │                      Core Layer                        │
   │  (CommandRunner, Registry, Models, Harvester, Detection)│
   └──────────────────────────┬─────────────────────────────┘
                              │ dispatches
   ┌──────────────────────────▼─────────────────────────────┐
   │                     Domain Modules                     │
   │   crypto │ reverse │ forensic │ pcap │ web │ stego     │
   │   binary │ encoding │ password │ osint │ network      │
   └────────────────────────────────────────────────────────┘
   ```
   - **Rule 1**: Domain modules (`crypto`, `reverse`, `stego`, etc.) **must never** import from `ichnos.cli` or `ichnos.ui`.
   - **Rule 2**: The `core` layer **must never** depend on `cli` or `ui`.
   - **Rule 3**: Both the CLI and TUI execute commands through the centralized `CommandRunner` and `registry`.

2. **Zero-Mandatory Binary Wheels**:
   - Every module maintains functional pure-Python implementations.
   - External C/accelerated libraries (`OpenSSL` via `ctypes`, `Capstone`, `Unicorn`, `pyperclip`) are loaded dynamically as optional accelerators. If unavailable or incompatible (such as bleeding-edge Python versions), Ichnos seamlessly degrades to pure-Python algorithms without failing or crashing.

3. **Standardized Data Contracts**:
   - All tools consume `Input(data, source_type, detected_type, path, filename)` and return `Result(findings, candidates, steps, learner_note, raw_output, status)`.
   - Every cracking or analysis routine produces standardized `Candidate` and `Finding` instances with confidence scores $[0.0, 1.0]$.

4. **Explainability & Pedagogical Duality**:
   - **Expert Mode**: Returns terse, high-density outputs: 1-line answer + 1-line method/key/confidence.
   - **Learner Mode**: Injects pedagogical context explaining the underlying mathematics, algorithm steps, and decision tree deductions (`DeductionStep`).

---

## 2. Full Codebase Directory Tree

```
src/ichnos/
├── __init__.py                     # Package entry point (version = "0.1.0")
│
├── core/                           # Foundation and architectural spine
│   ├── __init__.py
│   ├── commands.py                 # Core builtin command registrations
│   ├── detection.py                # Shannon entropy, chi-square, magic bytes, English scoring
│   ├── harvester.py                # Parameter extraction (RSA keys, moduli, ciphertexts, flags)
│   ├── input.py                    # Multi-source input reader (stdin, files, directories, raw)
│   ├── models.py                   # Pydantic models: Input, Finding, Candidate, Result, DeductionStep
│   ├── output.py                   # Rich console formatter & JSON serializer
│   ├── pedagogy.py                 # Pedagogical explanation knowledge base for Learner mode
│   ├── registry.py                 # Central singleton registry for commands & analyzers
│   ├── runner.py                   # Unified command execution engine
│   ├── solver.py                   # Autonomous CTF Challenge Solver orchestrator
│   ├── solver_output.py            # DeductionTrace and SolverStep audit records
│   └── workspace.py                # Challenge directory scanner and file categorization
│
├── cli/                            # Command-Line Interface (Typer)
│   ├── __init__.py
│   ├── main.py                     # Root CLI application and TUI launcher
│   ├── state.py                    # CLI state holder
│   └── commands/                   # Sub-app command modules
│       ├── __init__.py
│       ├── analyze.py              # Automated triage command
│       ├── binary.py               # Binary analysis CLI
│       ├── crypto.py               # Cryptography CLI
│       ├── encoding.py             # Encodings and ciphers CLI
│       ├── forensic.py             # Forensic file inspection CLI
│       ├── network.py              # Network recon CLI
│       ├── osint.py                # OSINT CLI
│       ├── password.py             # Wordlists and hashing CLI
│       ├── pcap.py                 # Packet capture analysis CLI
│       ├── reverse.py              # Reverse engineering CLI
│       ├── solve.py                # Autonomous solver CLI
│       ├── stego.py                # Steganography CLI
│       └── web.py                  # Web reconnaissance CLI
│
├── ui/                             # Interactive Terminal User Interface (Textual)
│   ├── __init__.py
│   ├── app.py                      # Textual application controller & command dispatcher
│   ├── state.py                    # UI session state, history persistence, active mode
│   ├── theme.py                    # Color palettes (Hacker, Matrix, Cyber, Amber, Slate, Midnight)
│   ├── theme.tcss                  # Global Textual CSS stylesheets
│   ├── mascot/                     # Terminal pet animation engine
│   │   ├── __init__.py
│   │   ├── frames.py               # ASCII frame states (idle, blink, think, happy, error)
│   │   └── widget.py               # Dynamic mascot widget
│   ├── screens/                    # Modal and primary view screens
│   │   ├── __init__.py
│   │   ├── main.py                 # Primary split terminal view
│   │   ├── result.py               # Interactive Candidate and Deduction Step selector modals
│   │   └── startup.py              # Splash screen with disclaimer and animation skip
│   └── widgets/                    # Modular UI components
│       ├── __init__.py
│       ├── banner.py               # ASCII branding and active target banner
│       ├── output.py               # Scrollable log, tables, and mode-aware result renderer
│       ├── progress.py             # Multi-stage operation progress indicator
│       ├── prompt.py               # Input prompt with history, autocompletion, and keybindings
│       └── status.py               # Bottom session status bar
│
├── crypto/                         # Cryptography and cryptanalysis
│   ├── __init__.py
│   ├── analyzers.py                # Registered crypto heuristics
│   ├── numtheory/                  # Number theory: GCD, mod_inv, CRT, Miller-Rabin, factorization
│   ├── classical/                  # Classical ciphers
│   │   ├── affine.py
│   │   ├── atbash.py
│   │   ├── caesar.py
│   │   ├── enigma.py
│   │   ├── homophonic.py
│   │   ├── polyalphabetic.py
│   │   ├── polygraphic.py
│   │   ├── quadgrams.py
│   │   ├── solver.py
│   │   ├── substitution.py
│   │   ├── symboltable.py
│   │   ├── symboltable_data.py
│   │   ├── transposition.py
│   │   └── vigenere.py
│   ├── ecc/                        # Elliptic curve cryptography
│   │   ├── curve.py
│   │   ├── curves_data.py
│   │   ├── ecdsa.py
│   │   └── ecdsa_bias.py           # Biased-nonce ECDSA Hidden Number Problem lattice attack
│   ├── hashing/                    # Hash computation and identification
│   │   ├── compute.py
│   │   └── identify.py
│   ├── pqc/                        # Post-quantum & lattice reduction
│   │   ├── lattice.py              # Pure-Python exact-arithmetic LLL lattice basis reduction
│   │   └── lwe.py                  # Learning With Errors dual-kernel attack
│   ├── prng/                       # Pseudo-random number generator recovery
│   │   ├── lcg.py                  # Linear Congruential Generator cracking
│   │   ├── mt19937.py              # Mersenne Twister state untempering and clone
│   │   └── stream.py               # RC4 stream cipher cryptanalysis
│   ├── rsa/                        # RSA cryptanalysis
│   │   ├── attacks.py              # Wiener, Hastad, Common Modulus, Nth-root
│   │   ├── bellcore.py             # Bellcore RSA-CRT fault injection
│   │   ├── bleichenbacher.py       # Million Message PKCS#1 v1.5 padding oracle
│   │   ├── boneh_durfee.py         # Small private exponent (d < N^0.292) bivariate lattice
│   │   ├── coppersmith.py          # Howgrave-Graham small roots / stereotyped messages
│   │   ├── factor.py               # Fermat, Pollard's p-1, Pollard's rho
│   │   └── franklin_reiter.py      # Related message polynomial GCD attack
│   ├── symmetric/                  # Modern symmetric ciphers & cryptanalysis
│   │   ├── aes.py                  # AES ECB/CBC/CTR/GCM modes
│   │   ├── chacha20.py             # ChaCha20 stream cipher
│   │   ├── des.py                  # DES, 3DES, weak and semi-weak key detection
│   │   ├── openssl.py              # Dynamic ctypes OpenSSL binding with fallback
│   │   └── attacks/                # Block cipher cryptanalysis
│   │       ├── ecb_byte_at_a_time.py
│   │       ├── mitm.py             # Generalized Meet-in-the-Middle engine
│   │       └── padding_oracle.py   # CBC byte-flipping & padding oracle
│   └── xor/                        # XOR cryptanalysis
│       ├── crib_drag.py
│       ├── repeating_key.py
│       └── single_byte.py
│
├── reverse/                        # Disassembly and static binary reverse engineering
│   ├── __init__.py
│   ├── cfg.py                      # Basic block partitioning and Control Flow Graph construction
│   ├── cff.py                      # Control Flow Flattening / OLLVM dispatcher analyzer
│   ├── disasm.py                   # Capstone disassembly with pure-Python instruction decoder
│   ├── emulate.py                  # Unicorn Engine integration with micro-emulator fallback
│   ├── gadgets.py                  # ROP/JOP gadget scanner with exploit classification
│   ├── patterns.py                 # Format string vulnerability and unsafe call site scanner
│   ├── symbols.py                  # Export, import, and PLT symbol extraction
│   └── xrefs.py                    # String and code cross-reference tracker
│
├── forensic/                       # Forensic analysis and carving
│   ├── __init__.py
│   ├── analyzers.py
│   ├── carver.py                   # File carving engine (headers, footers, magic)
│   ├── container.py                # Docker/OCI layer forensics and whiteout (.wh.*) recovery
│   ├── document.py                 # PDF, OLE2, Office macro and stream analysis
│   ├── filesystem.py               # Ext4, FAT, NTFS directory entry recovery
│   ├── git.py                      # Git repository forensics (loose/packed objects, commit DAG)
│   ├── sqlite.py                   # SQLite freeblock, freelist, and unallocated page carver
│   └── zip.py                      # ZIP directory parsing, comment extraction, password audit
│
├── pcap/                           # Network packet capture analysis
│   ├── __init__.py
│   ├── bluetooth.py                # Bluetooth HCI, L2CAP, and HID keystroke extractor
│   ├── credentials.py              # Plaintext auth credential harvesting
│   ├── dns.py                      # DNS query and response parser
│   ├── exfiltration.py             # ICMP custom payloads & DNS subdomain tunneling reassembly
│   ├── flows.py                    # TCP conversation flow tracking
│   ├── http.py                     # HTTP request/response and file extraction
│   ├── parser.py                   # Pure-Python PCAP & PCAPNG reader
│   ├── reassembly.py               # TCP stream segment reassembly
│   ├── solver.py                   # Automated PCAP challenge solver
│   ├── usb.py                      # USB keyboard and mouse packet interpreter
│   └── wifi.py                     # 802.11 WPA/WPA2 4-way handshake (EAPOL) extractor
│
├── web/                            # Web application reconnaissance
│   ├── __init__.py
│   ├── extract.py                  # HTML comment, script, endpoint, and asset extractor
│   ├── fuzz.py                     # Path and parameter discovery
│   ├── graphql.py                  # GraphQL introspection, schema analysis, suggestion parser
│   ├── headers.py                  # Security header audit and server fingerprinting
│   ├── solver.py                   # Automated web reconnaissance engine
│   └── ssti.py                     # Server-Side Template Injection fingerprinting & payloads
│
├── binary/                         # Static binary triage and headers
│   ├── __init__.py
│   ├── analyzers.py
│   ├── elf.py                      # ELF32/64 header, segment, and section parser
│   ├── entropy.py                  # Whole-file and sliding-window Shannon entropy
│   ├── hash_id.py                  # Non-cryptographic hash identifier (FNV, djb2, Murmur3)
│   ├── identify.py                 # Comprehensive file type and MIME detector
│   ├── macho.py                    # Mach-O header parser
│   ├── misc.py                     # Endianness swap, Hamming distance/weight
│   ├── pe.py                       # Windows PE/COFF header parser
│   ├── solver.py                   # Binary triage challenge solver
│   └── strings.py                  # ASCII, UTF-16LE, and UTF-16BE string extractor
│
├── encoding/                       # Encodings, esolangs, and transformations
│   ├── __init__.py
│   ├── analyzers.py
│   ├── bases.py                    # Base16, Base32, Base58, Base64, Base85, Base91
│   ├── esolang.py                  # Brainfuck, Ook!, JSFuck, Whitespace, LOLCODE, Deadfish
│   ├── layered.py                  # Recursive multi-layer automatic decoder
│   ├── morse.py                    # International Morse code encoder/decoder
│   ├── symbolic.py                 # Visual & symbolic transformations
│   └── text.py                     # URL, HTML entity, and Unicode encodings
│
├── stego/                          # Steganography analysis
│   ├── __init__.py
│   ├── analyzers.py
│   ├── audio/                      # Audio steganography
│   │   ├── __init__.py
│   │   ├── morse.py                # Audio tone Morse detector
│   │   ├── spectrogram.py          # Audio frequency-domain visualizer
│   │   └── wav.py                  # RIFF WAV parser
│   ├── image/                      # Image steganography
│   │   ├── __init__.py
│   │   ├── apng.py                 # Animated PNG hidden frame extractor
│   │   ├── channels.py             # Color channel plane splitter
│   │   ├── deflate_anomaly.py      # PNG IDAT deflate compression anomaly detector
│   │   ├── gif_frames.py           # GIF comment & frame delay timing stego
│   │   ├── jpeg.py                 # JPEG Exif, marker, and DCT stego
│   │   ├── lsb.py                  # LSB plane extractor (zsteg-compatible)
│   │   ├── png.py                  # PNG chunk parser
│   │   └── steghide.py             # Steghide detection and password audit
│   └── text.py                     # Acrostics, null ciphers, zero-width spaces
│
├── password/                       # Password cracking and wordlists
│   ├── __init__.py
│   ├── crack.py                    # Dictionary and rule-based cracking
│   ├── rules.py                    # Hashcat/John style mutation rules
│   └── wordlist.py                 # Wordlist generators and combiners
│
├── network/                        # Active network reconnaissance
│   ├── __init__.py
│   ├── banner.py                   # Service banner grabbing
│   ├── scan.py                     # TCP SYN/Connect port scanner
│   └── tls.py                      # TLS certificate and cipher suite inspection
│
└── osint/                          # Open-Source Intelligence
    ├── __init__.py
    ├── certs.py                    # Certificate Transparency log search
    ├── dns_recon.py                # DNS record enumeration and zone transfers
    └── whois.py                    # WHOIS protocol querying
```

---

## 3. Autonomous Solver Architecture (`AutoSolver`)

The `AutoSolver` (`src/ichnos/core/solver.py`) implements a deterministic multi-stage CTF reasoning pipeline:

```
[Target Ingestion] (Files / Directory / Text)
       │
       ▼
[Parameter & Primitive Harvesting] (CTFHarvester)
       │ -> Extracts RSA parameters (N, e, c, p, q, d)
       │ -> Extracts Classical ciphertexts, hashes, flags, base strings
       │ -> Categorizes files: CRYPTO, REVERSE, STEGO, FORENSIC, PCAP, WEB
       ▼
[Hypothesis Generation & Attack Correlation]
       │
       ├─► Small RSA exponent? ──────► Hastad / Integer Root
       ├─► Common modulus? ──────────► Extended Euclidean CRT
       ├─► Small private exponent? ──► Wiener Continued Fraction / Boneh-Durfee LLL
       ├─► Factorable modulus? ──────► Fermat / Pollard's Rho / Small Primes
       ├─► Stereotyped / Bias? ──────► Coppersmith / HNP Lattice Reduction
       ├─► Polyalphabetic? ──────────► Kasiski / IoC / Vigenère / Substitution
       ├─► LSB / Stego chunks? ──────► Bitplane raster scan / APNG / Deflate
       ├─► Layered Archive / Image? ─► Carving / Docker Whiteout / Git DAG
       └─► Network Capture? ─────────► EAPOL 4-Way / DNS Tunneling / ICMP Exfil
       │
       ▼
[Candidate Plaintext Evaluation & Scoring]
       │ -> Evaluates natural language fit (printable ratio, English quadgrams)
       │ -> Regular expression search for CTF flags: [a-zA-Z0-9_-]+{[^}\n\r]+}
       ▼
[Result Generation & DeductionTrace Serialization]
       │ -> Populates DeductionSteps for interactive audit
       │ -> Injects pedagogical notes in Learner Mode
```
