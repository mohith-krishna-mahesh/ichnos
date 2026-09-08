"""OpenSSH public key wire-format parser and hidden payload / XOR keystream cryptanalyst."""

from __future__ import annotations

import base64
import struct
from typing import Any

KEY_LEN_BY_TYPE: dict[str, int] = {
    "ssh-ed25519": 32,
    "ssh-rsa": 0,  # variable length
    "ecdsa-sha2-nistp256": 65,
}


def _take_string(buf: bytes, i: int) -> tuple[bytes, int]:
    """Reads a uint32-length-prefixed string from OpenSSH wire format buffer."""
    if i + 4 > len(buf):
        raise ValueError("truncated OpenSSH public key")
    (n,) = struct.unpack(">I", buf[i : i + 4])
    i += 4
    if i + n > len(buf):
        raise ValueError("truncated OpenSSH public key payload")
    return buf[i : i + n], i + n


def _trim_host(line: str, key_type: str) -> str | None:
    """Removes known_hosts hostname/IP markers and options to isolate '<key_type> <base64>'."""
    parts = line.split()
    if parts and parts[0] in ("@cert-authority", "@revoked"):
        parts = parts[1:]
    for i, part in enumerate(parts):
        if part == key_type and i + 1 < len(parts):
            return f"{key_type} {parts[i + 1]}"
    for part in parts:
        if part.startswith("|"):
            continue
        try:
            blob = base64.b64decode(part)
        except Exception:
            continue
        if len(blob) >= 19:
            return f"{key_type} {part}"
    return None


def extract_blobs(text: str, key_type: str = "ssh-ed25519") -> list[bytes]:
    """Pulls base64-decoded binary wire blobs from public key files, known_hosts, or ssh-keyscan."""
    found: list[bytes] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        trimmed = _trim_host(line, key_type)
        if trimmed is None:
            continue
        blob_b64 = trimmed.split()[1]
        try:
            blob = base64.b64decode(blob_b64)
            found.append(blob)
        except Exception:
            continue
    return found


def extract_key_body(
    blob: bytes, key_type: str = "ssh-ed25519", expected_len: int | None = None
) -> bytes:
    """Extracts raw key body bytes from the OpenSSH wire format blob."""
    ktype, i = _take_string(blob, 0)
    if ktype.decode(errors="replace") != key_type:
        raise ValueError(f"expected {key_type}, got {ktype!r}")

    if key_type == "ssh-rsa":
        # RSA wire format: type, e (mpint), n (mpint)
        exp, i = _take_string(blob, i)
        mod, _ = _take_string(blob, i)
        return mod

    body, _ = _take_string(blob, i)
    if expected_len is not None and expected_len > 0 and len(body) != expected_len:
        raise ValueError(f"expected {expected_len}-byte key body, got {len(body)}")
    return body


def build_keystream(
    length: int,
    xor_bytes: bytes = b"",
    keyword: bytes = b"",
    linear: tuple[int, int] | None = None,
) -> bytes:
    """Builds a composite XOR keystream combining repeating bytes, keywords, and linear sequences."""
    a, b = linear if linear else (0, 0)
    out = bytearray(length)
    for i in range(length):
        v = 0
        if xor_bytes:
            v ^= xor_bytes[i % len(xor_bytes)]
        if keyword:
            v ^= keyword[i % len(keyword)]
        if linear:
            v ^= (i * a + b) & 0xFF
        out[i] = v
    return bytes(out)


def reveal_hidden_data(key: bytes, keystream: bytes) -> bytes:
    """Applies keystream to key bytes, trimming at the first null-byte."""
    out = bytes(k ^ s for k, s in zip(key, keystream))
    return out.split(b"\x00", 1)[0]


def inspect_and_reveal_ssh(
    text: str,
    key_type: str = "ssh-ed25519",
    xor_hex: str | None = None,
    keyword: str | None = None,
    linear: tuple[int, int] | None = None,
) -> dict[str, Any]:
    """Parses SSH key files, extracts raw key bodies, and runs XOR cryptanalysis."""
    expected_len = KEY_LEN_BY_TYPE.get(key_type)
    blobs = extract_blobs(text, key_type)
    if not blobs:
        return {"error": f"No valid {key_type} key blobs found in input", "blobs_found": 0}

    xor_bytes = bytes.fromhex(xor_hex) if xor_hex else b""
    kw_bytes = keyword.encode("utf-8") if keyword else b""

    results = []
    for blob in blobs:
        try:
            body = extract_key_body(blob, key_type, expected_len)
        except ValueError as e:
            results.append({"error": str(e)})
            continue

        item: dict[str, Any] = {
            "key_type": key_type,
            "body_len": len(body),
            "raw_hex": body.hex(),
        }

        # Attempt raw utf-8 decode
        try:
            item["utf8"] = body.decode("utf-8")
        except UnicodeDecodeError:
            item["utf8"] = None

        # Apply keystream if specified
        if xor_bytes or kw_bytes or linear:
            keystream = build_keystream(len(body), xor_bytes, kw_bytes, linear)
            revealed = reveal_hidden_data(body, keystream)
            item["revealed_hex"] = revealed.hex()
            try:
                item["revealed_text"] = revealed.decode("utf-8")
            except UnicodeDecodeError:
                item["revealed_text"] = None

        results.append(item)

    return {"blobs_count": len(blobs), "keys": results}
