"""Automated OpenSSL enc parameter and password cracker.

Tests combinations of ciphers, digests, KDF methods (EVP_BytesToKey vs PBKDF2),
iteration counts, and passwords against OpenSSL-encrypted data.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from ichnos.core.detection import printable_ratio
from ichnos.password.wordlists import resolve_wordlist

DEFAULT_CIPHERS: list[str] = [
    "aes-128-cbc",
    "aes-192-cbc",
    "aes-256-cbc",
    "aes-128-ctr",
    "des-ede3-cbc",
]

DEFAULT_DIGESTS: list[str] = [
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
]

DEFAULT_ITERATIONS: list[int] = [
    1000,
    2048,
    4096,
    8192,
    10000,
    16384,
    32768,
    50000,
    65536,
    100000,
    200000,
]

DEFAULT_MARKERS: list[bytes] = [
    b"flag{",
    b"FLAG{",
    b"ctf{",
    b"CTF{",
    b"MIC{",
    b"PASS",
    b"password",
    b"BEGIN",
    b"-----BEGIN",
    b"Congratulations",
]


@dataclass
class OpenSSLCrackResult:
    """Represents a successful parameter decryption candidate."""

    password: str
    cipher: str
    digest: str
    pbkdf2: bool
    iterations: int | None
    plaintext: bytes
    confidence: float
    marker: str | None = None

    @property
    def label(self) -> str:
        kdf = f"PBKDF2 iter={self.iterations}" if self.pbkdf2 else "EVP_BytesToKey"
        return f"{self.cipher} / {self.digest} / {kdf} (pw={self.password!r})"


def looks_interesting(data: bytes, markers: list[bytes]) -> bytes | None:
    """Checks if decrypted data contains any known CTF / text markers."""
    for m in markers:
        if m in data:
            return m
    return None


def _decrypt_cli(
    infile: str,
    password: str,
    cipher: str,
    digest: str,
    pbkdf2: bool = False,
    iterations: int | None = None,
) -> tuple[bool, bytes]:
    """Executes openssl enc -d via subprocess."""
    cmd = ["openssl", "enc", "-d", f"-{cipher}"]
    if pbkdf2 and iterations:
        cmd += ["-pbkdf2", "-iter", str(iterations)]
    cmd += ["-md", digest, "-in", infile, "-pass", f"pass:{password}"]

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        return res.returncode == 0, res.stdout
    except Exception:
        return False, b""


def crack_openssl_params(
    data_or_path: bytes | str | Path,
    passwords: list[str] | None = None,
    wordlist: str | Path | None = None,
    ciphers: list[str] | None = None,
    digests: list[str] | None = None,
    iterations: list[int] | None = None,
    markers: list[bytes] | None = None,
    skip_legacy: bool = False,
    skip_pbkdf2: bool = False,
    min_printable_ratio: float = 0.85,
    accept_any_zero_exit: bool = False,
    workers: int = 4,
    keep_going: bool = False,
) -> list[OpenSSLCrackResult]:
    """Tests combinations of OpenSSL enc parameters to decrypt ciphertext.

    Args:
        data_or_path: Ciphertext bytes or path to encrypted file.
        passwords: Optional list of passwords to try.
        wordlist: Optional path to password wordlist (defaults to resolved wordlist).
        ciphers: Ciphers to test (default AES-CBC variants, CTR, 3DES).
        digests: Digests to test (default md5, sha1, sha256, sha512, etc.).
        iterations: PBKDF2 iteration counts to test.
        markers: Plaintext substrings indicating successful decryption.
        skip_legacy: If True, skips EVP_BytesToKey.
        skip_pbkdf2: If True, skips PBKDF2.
        min_printable_ratio: Minimum printable threshold for non-marker matches.
        accept_any_zero_exit: If True, accepts zero exit code without text heuristics.
        workers: Number of parallel worker threads.
        keep_going: If True, continues searching after first success.

    Returns:
        List of OpenSSLCrackResult instances sorted by confidence.
    """
    temp_file: str | None = None
    if isinstance(data_or_path, (str, Path)) and os.path.exists(str(data_or_path)):
        target_path = str(data_or_path)
    else:
        raw_bytes = data_or_path if isinstance(data_or_path, bytes) else str(data_or_path).encode()
        fd, temp_file = tempfile.mkstemp(prefix="ichnos_openssl_")
        os.write(fd, raw_bytes)
        os.close(fd)
        target_path = temp_file

    try:
        # Resolve password list
        candidate_passwords: list[str] = []
        if passwords:
            candidate_passwords.extend(passwords)
        else:
            resolved = resolve_wordlist(wordlist)
            if resolved and resolved.exists():
                with open(resolved, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            candidate_passwords.append(line)
                            if len(candidate_passwords) >= 5000:  # Sensible ceiling for full matrix
                                break

        if not candidate_passwords:
            candidate_passwords = ["password", "123456", "admin", "secret", "ctf", "flag"]

        test_ciphers = ciphers or DEFAULT_CIPHERS
        test_digests = digests or DEFAULT_DIGESTS
        test_iters = iterations or DEFAULT_ITERATIONS
        all_markers = (markers or []) + DEFAULT_MARKERS

        # Build permutations
        combos: list[tuple[str, str, str, bool, int | None]] = []
        for pw in candidate_passwords:
            for cip in test_ciphers:
                for dig in test_digests:
                    if not skip_legacy:
                        combos.append((pw, cip, dig, False, None))
                    if not skip_pbkdf2:
                        for it in test_iters:
                            combos.append((pw, cip, dig, True, it))

        results: list[OpenSSLCrackResult] = []

        def worker_task(combo: tuple[str, str, str, bool, int | None]):
            pw, cip, dig, pbk, it = combo
            ok, out = _decrypt_cli(target_path, pw, cip, dig, pbk, it)
            return combo, ok, out

        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            futures = {executor.submit(worker_task, c): c for c in combos}
            for fut in as_completed(futures):
                combo, ok, out = fut.result()
                pw, cip, dig, pbk, it = combo

                if not ok:
                    matched_m = looks_interesting(out, all_markers)
                    if matched_m:
                        results.append(
                            OpenSSLCrackResult(
                                password=pw,
                                cipher=cip,
                                digest=dig,
                                pbkdf2=pbk,
                                iterations=it,
                                plaintext=out,
                                confidence=0.4,
                                marker=matched_m.decode(errors="replace"),
                            )
                        )
                    continue

                matched_m = looks_interesting(out, all_markers)
                p_ratio = printable_ratio(out)
                plausible = accept_any_zero_exit or (matched_m is not None) or (p_ratio >= min_printable_ratio)

                if plausible:
                    conf = 1.0 if matched_m else (0.85 if p_ratio >= 0.85 else 0.6)
                    res = OpenSSLCrackResult(
                        password=pw,
                        cipher=cip,
                        digest=dig,
                        pbkdf2=pbk,
                        iterations=it,
                        plaintext=out,
                        confidence=conf,
                        marker=matched_m.decode(errors="replace") if matched_m else None,
                    )
                    results.append(res)
                    if not keep_going:
                        for f in futures:
                            f.cancel()
                        break

        results.sort(key=lambda x: x.confidence, reverse=True)
        return results

    finally:
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass
