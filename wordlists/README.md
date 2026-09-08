# Ichnos Curated Wordlists

This directory contains lightweight, fast-triage wordlists packaged with Project Ichnos for instant offline triage during CTF challenges and penetration testing.

## Bundled Wordlists (< 2 MB Total)

| Wordlist | Description | Entries |
| :--- | :--- | :--- |
| [`top1000.txt`](top1000.txt) | Top 1,000 most common human passwords from RockYou. | 1,000 |
| [`default-credentials.txt`](default-credentials.txt) | Standard default logins (`admin:admin`, `root:root`, database & router defaults). | ~40 |
| [`common-web.txt`](common-web.txt) | Top common endpoints, administration panels, sensitive files, and `.git` paths. | ~100 |
| [`pins.txt`](pins.txt) | All 4-digit PINs (0000–9999) and high-frequency 6-digit numeric codes. | 10,018 |

---

## On-Demand Large Wordlists (`ichnos wordlists fetch`)

To prevent repository bloat and preserve compact binary distribution sizes (~23 MB), large dictionaries are downloaded on-demand to your local user configuration directory (`~/.config/ichnos/wordlists/` on Unix, `%APPDATA%\ichnos\wordlists\` on Windows):

```bash
# List installed and available wordlists
ichnos wordlists list

# Fetch RockYou (14.3M passwords, ~53 MB compressed)
ichnos wordlists fetch rockyou

# Fetch Raft Large Web words (~1.8 MB compressed)
ichnos wordlists fetch raft-large

# Fetch the CTF Starter Bundle (Web, Subdomains, Top100k passwords, < 5 MB)
ichnos wordlists fetch ctf-starter
```

---

## Path Resolution Order

Commands that accept wordlists (`ichnos forensic zip crack`, `ichnos crypto symmetric openssl-brute`, `ichnos password mutate`) resolve paths in the following priority:

1. Explicit command-line flag: `--wordlist /path/to/custom.txt` (or `-w`)
2. Environment variable: `$ICHNOS_WORDLIST`
3. User configuration directory: `~/.config/ichnos/wordlists/<name>.txt`
4. Standard operating system path: `/usr/share/wordlists/rockyou.txt` (Kali / Debian / Arch)
5. Repository fast-triage fallback: `wordlists/top1000.txt`
