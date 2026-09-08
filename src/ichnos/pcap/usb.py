"""
USB HID keyboard and mouse packet extractor from PCAP captures.

Parses PCAP files to extract USB interrupt-transfer packets carrying
HID reports, then decodes keyboard keypresses (including shift modifiers
and backspace) and mouse movements.  Common in CTF forensics challenges
where USB traffic is captured via ``usbmon``.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# PCAP constants
# ---------------------------------------------------------------------------

_PCAP_MAGIC_LE = 0xA1B2C3D4
_PCAP_MAGIC_BE = 0xD4C3B2A1
_PCAP_MAGIC_LE_NS = 0xA1B23C4D
_PCAP_MAGIC_BE_NS = 0x4D3CB2A1

# USB-related link types
_LINKTYPE_USB_LINUX = 189
_LINKTYPE_USB_LINUX_MMAPPED = 220

# ---------------------------------------------------------------------------
# HID Keyboard keycode mapping (HID Usage Table, Usage Page 0x07)
# ---------------------------------------------------------------------------

_KEYCODE_MAP: dict[int, str] = {}

# Letters a-z: 0x04 .. 0x1D
for _i in range(26):
    _KEYCODE_MAP[0x04 + _i] = chr(ord("a") + _i)

# Digits 1-9: 0x1E .. 0x26, then 0: 0x27
for _i in range(9):
    _KEYCODE_MAP[0x1E + _i] = str(_i + 1)
_KEYCODE_MAP[0x27] = "0"

# Special keys
_KEYCODE_MAP[0x28] = "\n"    # Enter
_KEYCODE_MAP[0x29] = "\x1b"  # Escape
_KEYCODE_MAP[0x2A] = "\b"    # Backspace (sentinel)
_KEYCODE_MAP[0x2C] = " "     # Space
_KEYCODE_MAP[0x2D] = "-"
_KEYCODE_MAP[0x2E] = "="
_KEYCODE_MAP[0x2F] = "["
_KEYCODE_MAP[0x30] = "]"
_KEYCODE_MAP[0x31] = "\\"
_KEYCODE_MAP[0x33] = ";"
_KEYCODE_MAP[0x34] = "'"
_KEYCODE_MAP[0x35] = "`"
_KEYCODE_MAP[0x36] = ","
_KEYCODE_MAP[0x37] = "."
_KEYCODE_MAP[0x38] = "/"

# Shift mapping: unshifted char -> shifted char
_SHIFT_MAP: dict[str, str] = {
    "a": "A", "b": "B", "c": "C", "d": "D", "e": "E", "f": "F",
    "g": "G", "h": "H", "i": "I", "j": "J", "k": "K", "l": "L",
    "m": "M", "n": "N", "o": "O", "p": "P", "q": "Q", "r": "R",
    "s": "S", "t": "T", "u": "U", "v": "V", "w": "W", "x": "X",
    "y": "Y", "z": "Z",
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%",
    "6": "^", "7": "&", "8": "*", "9": "(", "0": ")",
    "-": "_", "=": "+",
    "[": "{", "]": "}",
    "\\": "|",
    ";": ":", "'": '"',
    "`": "~",
    ",": "<", ".": ">", "/": "?",
}

# Modifier bit masks
_MOD_LEFT_CTRL = 0x01
_MOD_LEFT_SHIFT = 0x02
_MOD_LEFT_ALT = 0x04
_MOD_RIGHT_SHIFT = 0x20

_SHIFT_BITS = _MOD_LEFT_SHIFT | _MOD_RIGHT_SHIFT

# Valid modifier mask (bits 0-5 are defined, bits 6-7 are right GUI / reserved)
_VALID_MODIFIER_MASK = 0x3F


# ---------------------------------------------------------------------------
# PCAP parsing helpers
# ---------------------------------------------------------------------------

def _read_pcap_header(pcap_data: bytes) -> tuple[str, int]:
    """Parse the PCAP global header and return (byte_order, link_type).

    Raises:
        ValueError: If the magic number is unrecognised.
    """
    if len(pcap_data) < 24:
        raise ValueError("PCAP data too short for global header")

    magic = struct.unpack_from("<I", pcap_data, 0)[0]

    if magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_LE_NS):
        endian = "<"
    elif magic in (_PCAP_MAGIC_BE, _PCAP_MAGIC_BE_NS):
        endian = ">"
    else:
        raise ValueError(f"Unknown PCAP magic: 0x{magic:08X}")

    # Global header: magic(4) version_major(2) version_minor(2)
    #   thiszone(4) sigfigs(4) snaplen(4) link_type(4) = 24 bytes
    link_type = struct.unpack_from(f"{endian}I", pcap_data, 20)[0]
    return endian, link_type


def _iter_pcap_packets(pcap_data: bytes) -> list[bytes]:
    """Yield raw packet data from a PCAP file.

    Returns a list of raw packet byte-strings.
    """
    endian, link_type = _read_pcap_header(pcap_data)
    offset = 24  # skip global header
    packets: list[bytes] = []

    while offset + 16 <= len(pcap_data):
        # Packet header: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from(
            f"{endian}IIII", pcap_data, offset
        )
        offset += 16
        if offset + incl_len > len(pcap_data):
            break
        packets.append(pcap_data[offset : offset + incl_len])
        offset += incl_len

    return packets


def _extract_hid_payloads(pcap_data: bytes, payload_len: int) -> list[bytes]:
    """Extract USB HID payloads of a specific length from PCAP data.

    Uses two strategies:
    1. For USB Linux captures (link type 189/220): parse the URB header
       to locate the HID data at known offsets.
    2. Fallback heuristic: scan each packet for trailing bytes of the
       expected length.
    """
    endian, link_type = _read_pcap_header(pcap_data)
    packets = _iter_pcap_packets(pcap_data)
    payloads: list[bytes] = []

    if link_type in (_LINKTYPE_USB_LINUX, _LINKTYPE_USB_LINUX_MMAPPED):
        # USB Linux raw / memory-mapped header parsing
        # The basic URB header is 48 bytes for LINKTYPE_USB_LINUX (189)
        # and 64 bytes for LINKTYPE_USB_LINUX_MMAPPED (220).
        urb_header_len = 64 if link_type == _LINKTYPE_USB_LINUX_MMAPPED else 48

        for pkt in packets:
            if len(pkt) < urb_header_len:
                continue

            # The transfer type is at offset 22 (1 byte) for both formats:
            #   0x01 = interrupt transfer (HID)
            #   The data length is at offset 36 (4 bytes LE) for both formats.
            xfer_type = pkt[22] if len(pkt) > 22 else 0xFF

            if xfer_type == 0x01:  # Interrupt transfer
                data_len_offset = 36
                if data_len_offset + 4 > len(pkt):
                    continue
                data_len = struct.unpack_from("<I", pkt, data_len_offset)[0]
                if data_len == payload_len:
                    hid_data = pkt[urb_header_len : urb_header_len + payload_len]
                    if len(hid_data) == payload_len:
                        payloads.append(hid_data)
            elif len(pkt) >= urb_header_len + payload_len:
                # Some captures have the data appended after the URB header
                # even for non-interrupt types; try extracting anyway
                candidate = pkt[urb_header_len : urb_header_len + payload_len]
                if len(candidate) == payload_len:
                    payloads.append(candidate)

        if payloads:
            return payloads

    # Fallback: try the last `payload_len` bytes of each packet
    for pkt in packets:
        if len(pkt) >= payload_len:
            candidate = pkt[len(pkt) - payload_len :]
            payloads.append(candidate)

    return payloads


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_usb_keyboard_data(pcap_data: bytes) -> str:
    """Extract and decode USB HID keyboard data from a PCAP capture.

    Parses the PCAP file, extracts 8-byte USB interrupt-transfer payloads,
    and decodes each keypress using the HID keycode map.  Handles modifier
    keys (Shift for uppercase / symbols) and Backspace (removes the last
    character from the output).

    USB HID keyboard reports are 8 bytes::

        [modifier, reserved, key1, key2, key3, key4, key5, key6]

    Args:
        pcap_data: Raw bytes of a PCAP file containing USB traffic.

    Returns:
        The reconstructed typed text.
    """
    payloads = _extract_hid_payloads(pcap_data, 8)

    output: list[str] = []
    prev_keys: set[int] = set()

    for payload in payloads:
        if len(payload) != 8:
            continue

        modifier = payload[0]

        # Validate modifier byte
        if modifier & ~_VALID_MODIFIER_MASK:
            continue

        shift = bool(modifier & _SHIFT_BITS)

        # Keys are in bytes 2..7 (byte 1 is reserved)
        current_keys: set[int] = set()
        for key_byte in payload[2:8]:
            if key_byte == 0x00:
                continue
            if key_byte == 0x01:
                # Error rollover — too many keys pressed simultaneously
                continue
            current_keys.add(key_byte)

        # Only process newly pressed keys (not held from previous report)
        new_keys = current_keys - prev_keys
        prev_keys = current_keys

        for keycode in sorted(new_keys):
            char = _KEYCODE_MAP.get(keycode)
            if char is None:
                continue

            if char == "\b":
                # Backspace: remove last character
                if output:
                    output.pop()
                continue

            if shift:
                char = _SHIFT_MAP.get(char, char)

            output.append(char)

    return "".join(output)


def extract_usb_mouse_data(
    pcap_data: bytes,
) -> list[tuple[int, int, int]]:
    """Extract USB HID mouse movement data from a PCAP capture.

    Mouse HID reports are typically 3-4 bytes::

        [buttons, dx, dy]          (3 bytes)
        [buttons, dx, dy, wheel]   (4 bytes)

    Where *dx* and *dy* are signed 8-bit relative movements.

    This function tries both 4-byte and 3-byte payloads.  If neither
    yields results it falls back to scanning for 8-byte payloads and
    interpreting bytes 1-3 as mouse data (some captures wrap mouse
    reports in 8-byte HID frames).

    Args:
        pcap_data: Raw bytes of a PCAP file containing USB traffic.

    Returns:
        A list of ``(buttons, dx, dy)`` tuples.
    """
    movements: list[tuple[int, int, int]] = []

    # Try 4-byte mouse reports first
    for payload_len in (4, 3):
        payloads = _extract_hid_payloads(pcap_data, payload_len)
        for payload in payloads:
            buttons = payload[0]
            dx = struct.unpack_from("<b", payload, 1)[0]
            dy = struct.unpack_from("<b", payload, 2)[0]
            movements.append((buttons, dx, dy))
        if movements:
            return movements

    # Fallback: 8-byte payloads — some mouse captures use HID report ID
    payloads = _extract_hid_payloads(pcap_data, 8)
    for payload in payloads:
        # Heuristic: if byte[0] looks like a mouse button state (0x00-0x07)
        # and byte[1] is reserved/zero, treat bytes 1..3 as mouse data
        buttons = payload[0]
        if buttons <= 0x07:
            dx = struct.unpack_from("<b", payload, 1)[0]
            dy = struct.unpack_from("<b", payload, 2)[0]
            movements.append((buttons, dx, dy))

    return movements
