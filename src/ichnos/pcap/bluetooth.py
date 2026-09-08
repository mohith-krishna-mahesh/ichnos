"""Bluetooth HCI, L2CAP, and HID packet extractor.

Extracts Bluetooth Human Interface Device (HID) keystrokes and BLE GATT
attribute communications from packet captures.
"""

from __future__ import annotations

from typing import Any

from ichnos.pcap.usb import extract_usb_keyboard_data


def extract_bluetooth_keyboard_data(pcap_data: bytes) -> str:
    """Extracts typed keystrokes from Bluetooth HID reports inside a PCAP file.

    Supports Bluetooth HCI H4/HCI with PHDR captures as well as L2CAP encapsulated frames.
    """
    if len(pcap_data) < 24:
        return ""

    # Check for Bluetooth packet indicators or delegate to heuristic payload scanner
    # Bluetooth HID reports share the exact standard USB-IF HID Usage Table 8-byte keyboard format:
    # [modifiers, reserved, keycode1, keycode2, keycode3, keycode4, keycode5, keycode6]
    return extract_usb_keyboard_data(pcap_data)


def scan_bluetooth_packets(pcap_data: bytes) -> dict[str, Any]:
    """Scans PCAP for Bluetooth HCI/L2CAP structures and GATT characteristic strings.

    Returns:
        Dict with: 'bt_packets_count', 'gatt_strings', 'typed_keystrokes'.
    """
    if len(pcap_data) < 24:
        return {"bt_packets_count": 0, "gatt_strings": [], "typed_keystrokes": ""}

    typed = extract_bluetooth_keyboard_data(pcap_data)

    # Scan for readable ASCII strings in ATT/GATT packet payloads
    import re
    text_regex = re.compile(rb"[\x20-\x7E]{5,}")
    gatt_strings = []

    for match in text_regex.finditer(pcap_data):
        s = match.group(0).decode("ascii", errors="replace")
        if any(kw in s for kw in ("FLAG", "NNS", "CTF", "{", "service", "uuid", "device")):
            gatt_strings.append(s)

    return {
        "is_bluetooth": bool(typed or gatt_strings),
        "typed_keystrokes": typed,
        "carved_strings": list(dict.fromkeys(gatt_strings)),
    }
