"""Forensic timestamp converters and artifact temporal analysis.

Converts between Unix epoch (s/ms/us), Windows FILETIME (NTFS/Registry),
Apple Cocoa time, Chrome/WebKit timestamps, and DOS FAT date/time.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Epoch Offsets
# Windows FILETIME: 100-ns intervals since 1601-01-01
FILETIME_EPOCH_DIFF_NS = 116444736000000000

# Apple Cocoa Time: seconds since 2001-01-01
COCOA_EPOCH_DIFF_SEC = 978307200

# Chrome / WebKit Time: microseconds since 1601-01-01
CHROME_EPOCH_DIFF_US = 11644473600000000


def filetime_to_datetime(filetime: int) -> datetime:
    """Converts a 64-bit Windows FILETIME integer to a UTC datetime."""
    unix_sec = (filetime - FILETIME_EPOCH_DIFF_NS) / 10000000.0
    return datetime.fromtimestamp(unix_sec, tz=timezone.utc)


def datetime_to_filetime(dt: datetime) -> int:
    """Converts a datetime to a 64-bit Windows FILETIME integer."""
    unix_sec = dt.timestamp()
    return int(unix_sec * 10000000) + FILETIME_EPOCH_DIFF_NS


def cocoa_to_datetime(cocoa_seconds: float) -> datetime:
    """Converts Apple Cocoa Core Data timestamp (seconds since 2001-01-01) to UTC datetime."""
    unix_sec = cocoa_seconds + COCOA_EPOCH_DIFF_SEC
    return datetime.fromtimestamp(unix_sec, tz=timezone.utc)


def chrome_to_datetime(chrome_us: int) -> datetime:
    """Converts Chrome / WebKit timestamp (microseconds since 1601-01-01) to UTC datetime."""
    unix_sec = (chrome_us - CHROME_EPOCH_DIFF_US) / 1000000.0
    return datetime.fromtimestamp(unix_sec, tz=timezone.utc)


def dos_datetime_to_datetime(dos_date: int, dos_time: int) -> datetime:
    """Converts 16-bit FAT DOS date and time to a UTC datetime."""
    year = ((dos_date >> 9) & 0x7F) + 1980
    month = max(1, min(12, (dos_date >> 5) & 0x0F))
    day = max(1, min(31, dos_date & 0x1F))

    hour = min(23, (dos_time >> 11) & 0x1F)
    minute = min(59, (dos_time >> 5) & 0x3F)
    second = min(59, (dos_time & 0x1F) * 2)

    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def convert_timestamp(val: int | float | str, fmt: str = "auto") -> dict[str, Any]:
    """Auto-detects or explicitly converts a forensic timestamp value to standard UTC formats."""
    fmt_lower = fmt.lower().replace("-", "").replace("_", "")

    # Parse numeric value if given as string
    if isinstance(val, str):
        val_clean = val.strip()
        if val_clean.isdigit():
            num_val: int | float = int(val_clean)
        else:
            try:
                num_val = float(val_clean)
            except ValueError:
                # ISO datetime string parsing
                dt = datetime.fromisoformat(val_clean)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return {
                    "format": "iso8601",
                    "iso8601_utc": dt.isoformat(),
                    "unix_seconds": int(dt.timestamp()),
                    "windows_filetime": datetime_to_filetime(dt),
                }
    else:
        num_val = val

    detected_fmt = fmt_lower
    dt: datetime

    if fmt_lower in ("filetime", "windows"):
        dt = filetime_to_datetime(int(num_val))
    elif fmt_lower in ("cocoa", "apple", "mac"):
        dt = cocoa_to_datetime(float(num_val))
    elif fmt_lower in ("chrome", "webkit"):
        dt = chrome_to_datetime(int(num_val))
    elif fmt_lower in ("unix", "epoch", "sec"):
        dt = datetime.fromtimestamp(float(num_val), tz=timezone.utc)
    elif fmt_lower in ("unixms", "ms"):
        dt = datetime.fromtimestamp(float(num_val) / 1000.0, tz=timezone.utc)
    else:
        # Auto-detection heuristic based on magnitude
        int_v = int(num_val)
        if int_v > 100000000000000000:  # ~17 digits: Windows FILETIME
            dt = filetime_to_datetime(int_v)
            detected_fmt = "windows_filetime"
        elif int_v > 1000000000000000:  # ~16 digits: Chrome microsecond
            dt = chrome_to_datetime(int_v)
            detected_fmt = "chrome_webkit"
        elif int_v > 1000000000000:  # ~13 digits: Unix milliseconds
            dt = datetime.fromtimestamp(int_v / 1000.0, tz=timezone.utc)
            detected_fmt = "unix_milliseconds"
        elif int_v < 1500000000 and int_v > 100000000:  # ~9 digits: Apple Cocoa seconds
            # Ambiguity between early Unix and Cocoa: check if Cocoa gives sensible recent year
            cocoa_candidate = cocoa_to_datetime(float(int_v))
            if 2001 <= cocoa_candidate.year <= 2035:
                dt = cocoa_candidate
                detected_fmt = "apple_cocoa"
            else:
                dt = datetime.fromtimestamp(float(int_v), tz=timezone.utc)
                detected_fmt = "unix_seconds"
        else:
            dt = datetime.fromtimestamp(float(int_v), tz=timezone.utc)
            detected_fmt = "unix_seconds"

    return {
        "format": detected_fmt,
        "iso8601_utc": dt.isoformat(),
        "unix_seconds": int(dt.timestamp()),
        "unix_millis": int(dt.timestamp() * 1000),
        "windows_filetime": datetime_to_filetime(dt),
    }
