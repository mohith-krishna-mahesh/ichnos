"""Layered decoding tools."""

from ichnos.core.detection import printable_ratio
from ichnos.core.models import Candidate, Finding
from ichnos.encoding.bases import auto_detect as bases_auto_detect
from ichnos.encoding.morse import decode as morse_decode
from ichnos.encoding.text import html_decode, unicode_decode, url_decode


def auto_decode(data: str, max_depth: int = 10) -> list[Candidate]:
    """Iteratively try all decoders on the input."""
    queue = [Candidate(decoded=data, method="original", confidence=0.0, layers=[])]
    results = []

    while queue:
        current = queue.pop(0)

        # Stop condition
        if len(current.layers) >= max_depth:
            continue

        text = (
            current.decoded_str
            if hasattr(current, "decoded_str")
            else (
                current.decoded.decode("utf-8", errors="ignore")
                if isinstance(current.decoded, bytes)
                else str(current.decoded)
            )
        )

        # Try Base encodings
        base_candidates = bases_auto_detect(text)
        for cand in base_candidates:
            new_cand = Candidate(
                decoded=cand.decoded,
                method=cand.method,
                confidence=cand.confidence,
                layers=current.layers + cand.layers,
            )
            # Only add to queue if confidence is decent
            if new_cand.confidence > 0.5:
                queue.append(new_cand)
            results.append(new_cand)

        # Try URL decode
        url_dec = url_decode(text)
        if url_dec != text:
            new_cand = Candidate(
                decoded=url_dec,
                method="url",
                confidence=printable_ratio(url_dec.encode("utf-8")) * 0.9,
                layers=current.layers + ["url"],
            )
            queue.append(new_cand)
            results.append(new_cand)

        # Try HTML decode
        html_dec = html_decode(text)
        if html_dec != text:
            new_cand = Candidate(
                decoded=html_dec,
                method="html",
                confidence=printable_ratio(html_dec.encode("utf-8")) * 0.9,
                layers=current.layers + ["html"],
            )
            queue.append(new_cand)
            results.append(new_cand)

        # Try Unicode decode
        uni_dec = unicode_decode(text)
        if uni_dec != text:
            new_cand = Candidate(
                decoded=uni_dec,
                method="unicode",
                confidence=printable_ratio(uni_dec.encode("utf-8")) * 0.9,
                layers=current.layers + ["unicode"],
            )
            queue.append(new_cand)
            results.append(new_cand)

        # Try Morse decode
        try:
            # Check if it looks like morse code roughly
            if set(text.strip()).issubset({".", "-", " ", "/", "|"}):
                morse_dec = morse_decode(text)
                if morse_dec:
                    new_cand = Candidate(
                        decoded=morse_dec,
                        method="morse",
                        confidence=printable_ratio(morse_dec.encode("utf-8")),
                        layers=current.layers + ["morse"],
                    )
                    queue.append(new_cand)
                    results.append(new_cand)
        except Exception:
            pass

    # Remove original from results and sort by confidence
    results.sort(key=lambda x: x.confidence, reverse=True)
    return results


def detect_encoding(data: str) -> list[Finding]:
    """Analyze the string and report what encodings it might be."""
    findings = []

    # Check for Base64
    import re

    s_clean = data.strip()
    if re.match(r"^[A-Za-z0-9+/]+={0,2}$", s_clean) and len(s_clean) >= 4 and len(s_clean) % 4 == 0:
        try:
            from ichnos.encoding.bases import _is_valid_decoded, decode_base64

            decoded = decode_base64(s_clean)
            valid, _ = _is_valid_decoded(decoded)
            if valid:
                findings.append(
                    Finding(
                        label="Base64 Encoding",
                        confidence=0.85,
                        detail="Data appears to be base64 encoded.",
                        module="encoding",
                        command_hint="encoding decode --format base64",
                    )
                )
        except Exception:
            pass

    # Check for URL Encoding
    if "%" in data and re.search(r"%[0-9a-fA-F]{2}", data):
        findings.append(
            Finding(
                label="URL Encoding",
                confidence=0.9,
                detail="Data contains URL encoded characters.",
                module="encoding",
                command_hint="encoding decode --format url",
            )
        )

    # Check for Hex Encoding
    if (
        re.match(r"^[0-9a-fA-F]+$", data.strip())
        and len(data.strip()) % 2 == 0
        and len(data.strip()) >= 4
    ):
        try:
            from ichnos.encoding.bases import _is_valid_decoded, decode_hex

            decoded = decode_hex(data.strip())
            valid, _ = _is_valid_decoded(decoded)
            if valid:
                findings.append(
                    Finding(
                        label="Hex Encoding",
                        confidence=0.85,
                        detail="Data appears to be a hexadecimal string.",
                        module="encoding",
                        command_hint="encoding decode --format hex",
                    )
                )
        except Exception:
            pass

    # Check for Morse Code
    if set(data.strip()).issubset({".", "-", " ", "/", "|"}) and len(data.strip()) > 2:
        findings.append(
            Finding(
                label="Morse Code",
                confidence=0.95,
                detail="Data is comprised of dots and dashes typical of Morse code.",
                module="encoding",
                command_hint="encoding morse",
            )
        )

    return findings
