# Contributing to Ichnos

Thank you for your interest in contributing to **Ichnos**! This document provides guidelines and instructions for setting up your development environment, writing code, creating analyzers and solvers, adding custom themes, and submitting pull requests.

---

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Code Style & Standards](#code-style--standards)
3. [Running Tests](#running-tests)
4. [Architecture Overview](#architecture-overview)
5. [Adding a New Analyzer to the Registry](#adding-a-new-analyzer-to-the-registry)
6. [Adding an Attack to the AutoSolver](#adding-an-attack-to-the-autosolver)
7. [Creating Custom Themes](#creating-custom-themes)
8. [Release & Distribution Scripts](#release--distribution-scripts)
9. [Submitting Pull Requests](#submitting-pull-requests)

---

## Development Environment Setup

Ichnos requires **Python 3.10+** (tested through Python 3.14). We use [`uv`](https://docs.astral.sh/uv/) for fast, deterministic dependency management, but standard `pip` and virtual environments work as well.

### 1. Clone the Repository

```bash
git clone https://github.com/mohith-krishna-mahesh/ichnos.git
cd ichnos
```

### 2. Set Up Virtual Environment with `uv`

```bash
# Create virtual environment and install all dependencies (including dev and test)
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e ".[all]"
```

Or using standard Python virtual environments:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
```

### 3. Verify the Installation

```bash
# Check the CLI entry point
ichnos --version

# Run the test suite
pytest -q
```

---

## Code Style & Standards

Ichnos uses [`ruff`](https://beta.astral.sh/ruff/) for high-performance linting and formatting.

### 1. Formatting and Linting

Before opening a PR, ensure your changes adhere to project standards:

```bash
# Run linter
ruff check src/ tests/ scripts/

# Automatically fix autofixable issues
ruff check --fix src/ tests/ scripts/

# Format code
ruff format src/ tests/ scripts/
```

### 2. Design Principles

- **Zero-Dependency Core**: Fundamental algorithms (classical ciphers, encoding engines, ELF parsing, PNG/WAV decoding, number theory) must be pure-Python standard library implementations without requiring external native C libraries.
- **Fail Gracefully**: Never crash or raise unhandled exceptions on malformed, truncated, or adversarial input. CTF challenges frequently contain intentionally corrupted files or compression bombs. Use safe parsing boundaries and timeouts.
- **Deterministic Deductions**: The AutoSolver must produce reproducible, mathematically sound deductions. Never rely on random non-deterministic heuristics for cryptographic solving.
- **Rich Models**: Functions returning triage or detection results should use the standard data models defined in `ichnos.core.models` (`Finding`, `Candidate`, `Result`, `Input`).

---

## Running Tests

Ichnos has an extensive automated test suite covering all modules, CLI entry points, and TUI components.

```bash
# Run the entire test suite
pytest

# Run tests with execution timings
pytest --durations=10

# Run tests for a specific module
pytest tests/crypto/
pytest tests/ui/test_theme.py
pytest tests/core/test_solver.py

# Run only fast tests (excluding long-running or brute-force tests)
pytest -m "not slow"

# Run tests with code coverage
pytest --cov=src/ichnos --cov-report=term-missing
```

---

## Architecture Overview

```
src/ichnos/
├── core/         # Unified data models, AST harvester, detection, pipeline, solver
├── crypto/       # Classical ciphers, XOR, number theory, RSA, ECC, modern, PQC
├── encoding/     # Base codecs, esolangs, text formats, layered auto-decoding
├── stego/        # PNG chunk/LSB, audio WAV/morse/spectrogram, text concealment
├── binary/       # ELF/PE/Mach-O parsers, strings extraction, sliding entropy
├── forensic/     # ZIP, archive triage, signature carving, FAT/MBR, timestamps
├── pcap/         # Zero-dependency PCAP/PCAPNG packet and flow analysis
├── network/      # Non-destructive port scanning, banner grabbing, TLS inspection
├── web/          # Security header analysis, endpoint fuzzing, asset extraction
├── osint/        # DoH DNS lookups, pure-socket WHOIS, CT log subdomains
├── password/     # Rule-based mutation engines, dictionary & Cartesian attacks
├── reverse/      # Disassembly, CFG extraction, gadgets, pattern detection
├── ui/           # Textual TUI, animated mascot, platform-aware theme engine
└── cli/          # Typer command-line interface entry points
```

---

## Adding a New Analyzer to the Registry

Analyzers enable Ichnos to inspect arbitrary input (text, hex, binary blobs) and automatically suggest or trigger relevant modules.

To register a new analyzer:

1. Locate the appropriate module's `analyzers.py` (e.g. `src/ichnos/crypto/analyzers.py`).
2. Implement an analyzer class decorated with `@registry.analyzer(module=..., name=...)`.
3. Implement `can_handle(inp: Input) -> float` returning a confidence score between `0.0` and `1.0`.
4. Implement `suggest(inp: Input) -> list[str]` returning CLI command hints.

### Example:

```python
from ichnos.core.models import Finding, Input
from ichnos.core.registry import registry


@registry.analyzer(module="crypto", name="custom-cipher")
class CustomCipherAnalyzer:
    module = "crypto"
    name = "custom-cipher"

    def can_handle(self, inp: Input) -> float:
        if not inp.is_text:
            return 0.0
        # Heuristic check: does the text fit the cipher's characteristics?
        if inp.text and all(c in "01234567" for c in inp.text.strip()):
            return 0.75
        return 0.0

    def suggest(self, inp: Input) -> list[str]:
        return ["ichnos crypto custom-cipher --input <FILE>"]

    def analyze(self, inp: Input) -> list[Finding]:
        findings = []
        if self.can_handle(inp) > 0.5:
            findings.append(
                Finding(
                    module=self.module,
                    title="Potential Custom Octal Cipher",
                    description="Input consists solely of octal digits.",
                    confidence=0.75,
                    command_hint="ichnos crypto custom-cipher",
                )
            )
        return findings
```

---

## Adding an Attack to the AutoSolver

The Ichnos **AutoSolver** (`ichnos solve`) performs autonomous challenge correlation. It extracts cryptographic and operational parameters from code and data files, identifies vulnerabilities, and executes deterministic attacks.

### Workflow:

1. **Parameter Harvesting**: If your attack relies on parameters in challenge source files (e.g. `p`, `q`, `e`, `n`, `c`), update `ichnos.core.harvester.CTFHarvester` with AST patterns or regex extractors.
2. **Implement the Attack Primitive**: Place the core mathematical or algorithmic logic in the appropriate module (e.g., `ichnos.crypto.rsa.attacks` or `ichnos.crypto.classical.solver`).
3. **Wire into Solver Strategy**: Add the strategy to `ichnos.core.solver.AutoSolver`:
   - Inspect harvested parameters or candidate ciphertexts.
   - Record deductions in `self.trace.add_step(...)`.
   - If plaintext or a flag pattern (`FLAG{...}`) is recovered, return a `Result` containing the candidate and deduction trace.

### Example Attack Step in AutoSolver:

```python
# In src/ichnos/core/solver.py
if rsa_params.e == 3 and rsa_params.c and not rsa_params.n_large:
    trace.add_step(
        module="crypto.rsa",
        action="Low Exponent Attack (e=3)",
        rationale="Small public exponent detected without modulus wrapping.",
    )
    m, exact = integer_nth_root(rsa_params.c, 3)
    if exact:
        text = int_to_text(m)
        if extract_flag(text) or printable_ratio(text.encode()) > 0.85:
            return Result(
                candidates=[Candidate(value=text, method="RSA Low Exponent Root", confidence=1.0)]
            )
```

---

## Creating Custom Themes

Ichnos features a fully customizable Textual TUI with platform-aware theme discovery.

### Canonical Reference Themes

All built-in themes are stored in standard JSON format in the [`themes/`](themes/) directory:

- [`themes/hacker.theme`](themes/hacker.theme)
- [`themes/cyber.theme`](themes/cyber.theme)
- [`themes/matrix.theme`](themes/matrix.theme)
- [`themes/monochrome.theme`](themes/monochrome.theme)
- [`themes/dracula.theme`](themes/dracula.theme)
- [`themes/nord.theme`](themes/nord.theme)

### Theme File Format

A valid theme file has a `.theme` extension and must contain a JSON object conforming to the schema below:

```json
{
  "name": "my-custom-theme",
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

Place your `.theme` files into your OS-specific user configuration directory:

- **Linux / macOS**: `~/.config/ichnos/themes/` (or `$XDG_CONFIG_HOME/ichnos/themes/`)
- **Windows**: `%APPDATA%\ichnos\themes\`

Any valid theme in this directory is automatically discovered at startup and available via the `--theme` flag or in the TUI Settings modal (`Ctrl+S`).

---

## Release & Distribution Scripts

Ichnos provides standalone compilation and packaging utilities in `scripts/`:

- **Nuitka Build Script**: `scripts/build_nuitka.py` builds fully self-contained binaries (`--mode standalone` or `--mode onefile`).
- **Performance Profiling**: `scripts/profile_scale.py` profiles scale limits (100k PCAP packets, 1M wordlist mutations, decompression bomb limits, memory RSS).
- **Automated Installer**: `scripts/install.sh` downloads or installs precompiled releases based on host OS and architecture.

---

## Submitting Pull Requests

1. **Create a Topic Branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```
2. **Ensure All Tests Pass**:
   ```bash
   pytest
   ```
3. **Format and Lint**:
   ```bash
   ruff check --fix src/ tests/ scripts/
   ruff format src/ tests/ scripts/
   ```
4. **Write Tests**: Every new feature or attack algorithm must be accompanied by comprehensive tests in `tests/`.
5. **Commit Message Format**: Follow conventional commits (e.g. `feat(crypto): add Hill cipher solver`, `fix(stego): handle corrupt PNG chunk length`).
6. **Open a PR**: Describe what your change does, how it was tested, and link any relevant issues.
