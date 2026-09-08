# Security Policy

## Scope of Project Ichnos

**Ichnos** is an offensive security analysis, CTF (Capture the Flag) problem-solving, and cryptanalysis toolkit. Its intended usage is inspecting, analyzing, and solving security challenge artifacts, captured network traffic, steganographic media, and ciphertexts in authorized environments.

---

## Cryptographic Implementation Disclaimer

> [!WARNING]
> **Ichnos's cryptographic routines are designed specifically for cryptanalysis, reverse engineering, and puzzle solving.**
>
> They are **NOT** intended for production data encryption, secret storage, authentication, or secure communication. Do not use algorithms or key generation routines from Ichnos in place of vetted cryptographic libraries (such as OpenSSL, BoringSSL, or libsodium).

---

## Hardening Against Hostile Inputs

Because Ichnos is built to parse untrusted and deliberately malformed CTF challenge files, the core engine incorporates defense-in-depth boundaries:

- **Decompression Bomb Protection**: All archive and stream decompression (`zlib`, `gzip`, `bz2`, `xz`, `tar`, `zip`, container whiteouts, PDF streams, PNG scanlines) enforces chunked streaming with strict ratio limits (100:1) and hard uncompressed size ceilings (default 64MB / 100MB).
- **Zip Slip / Tar Slip Defense**: Archive paths containing directory traversal (`..`), absolute roots (`/`, `C:`), null bytes, or paths resolving outside target directories are rejected.
- **AST Harvester DoS Protection**: Expression harvesting from challenge code is bounded by AST depth (50), node count (2,000), bit length (16,384 bits), and execution timeouts (1.0s) to prevent memory exhaustion (`2**999999999999`) or quadratic conversion hangs.
- **Binary & Media Parser Bounds**: Parsers for ELF, PE, Mach-O, PCAP/PCAPNG, JPEG, and WAV enforce strict segment/header bounds, slice limits, and zero-step infinite loop guards.
- **Terminal Injection Stripping**: Output rendered to the terminal strips ANSI OSC sequences (such as OSC 52 clipboard exfiltration), CSI control sequences, and non-printable control characters.

---

## Reporting a Vulnerability

If you discover a security vulnerability in Ichnos itself (such as a parser exploit, remote code execution vector, denial-of-service condition bypassing our limits, or terminal injection flaw):

1. **Do not open a public GitHub issue.**
2. Report the vulnerability privately via **GitHub Security Advisories**:
   Navigate to the repository's **Security** tab → **Advisories** → **Report a vulnerability**.
3. Include:
   - A detailed description of the flaw.
   - A minimal proof-of-concept (PoC) file or command reproducing the issue.
   - Impact assessment and affected components.

We take security reports seriously and will acknowledge receipt within 48 hours and work with you on a coordinated fix and advisory release.
