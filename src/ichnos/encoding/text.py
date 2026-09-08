"""Text encodings (URL, HTML, Unicode)."""

import html
import re
import urllib.parse


def url_encode(s: str) -> str:
    """URL encode a string."""
    return urllib.parse.quote(s)


def url_decode(s: str) -> str:
    """URL decode a string."""
    return urllib.parse.unquote(s)


def url_double_encode(s: str) -> str:
    """URL double encode a string."""
    return url_encode(url_encode(s))


def url_double_decode(s: str) -> str:
    """URL double decode a string."""
    return url_decode(url_decode(s))


def html_encode(s: str) -> str:
    """HTML encode a string."""
    return html.escape(s)


def html_decode(s: str) -> str:
    """HTML decode a string."""
    return html.unescape(s)


def unicode_encode(s: str, style: str = "python") -> str:
    """Unicode encode a string with the specified style."""
    if style == "python" or style == "json":
        return "".join(f"\\u{ord(c):04x}" for c in s)
    elif style == "html_dec":
        return "".join(f"&#{ord(c)};" for c in s)
    elif style == "html_hex":
        return "".join(f"&#x{ord(c):x};" for c in s)
    elif style == "css":
        return "".join(f"\\{ord(c):04x}" for c in s)
    else:
        raise ValueError(f"Unknown style: {style}")


def unicode_decode(s: str) -> str:
    """Auto-detect and decode Unicode escapes."""
    # Handle HTML hex (&#xNNNN;)
    s = re.sub(r"&#x([0-9a-fA-F]+);", lambda m: chr(int(m.group(1), 16)), s)

    # Handle HTML dec (&#NNNN;)
    s = re.sub(r"&#([0-9]+);", lambda m: chr(int(m.group(1))), s)

    # Handle Python/JSON (\uXXXX)
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)

    # Handle CSS (\NNNN)
    # Be careful not to replace normal escaped chars, CSS escapes have optional whitespace
    def css_repl(m):
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)

    s = re.sub(r"\\([0-9a-fA-F]{1,6})\s?", css_repl, s)

    return s
