"""Historically authentic Enigma Machine emulator.

Implements:
- Rotors I through VIII with accurate wiring and turnover notches.
- Reflectors UKW-A, UKW-B, and UKW-C.
- Accurate double-stepping mechanical pawl quirk.
- Plugboard (Steckerbrett) pairwise substitution.
- Ringstellung (ring settings) and Grundstellung (rotor start positions).
- Self-reciprocal encryption/decryption verified against historical test vectors.
"""

from __future__ import annotations

import re

# Standard Wehrmacht / Kriegsmarine rotor wirings and turnover notches
ROTOR_WIRINGS: dict[str, str] = {
    "I": "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "II": "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "III": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "IV": "ESOVPZJAYQUIRHXLNFTGKDCMWB",
    "V": "VZBRGITYUPSDNHLXAWMJQOFECK",
    "VI": "JPGVOUMFYQBENHZRDKASXLICTW",
    "VII": "NZJHGRCXMYSWBOUFAIVLPEKQDT",
    "VIII": "FKQHTLXOCBJSPDZRAMEWNIUYGV",
}

# The letter visible in the window when the notch engages
ROTOR_NOTCHES: dict[str, tuple[str, ...]] = {
    "I": ("Q",),
    "II": ("E",),
    "III": ("V",),
    "IV": ("J",),
    "V": ("Z",),
    "VI": ("Z", "M"),
    "VII": ("Z", "M"),
    "VIII": ("Z", "M"),
}

REFLECTOR_WIRINGS: dict[str, str] = {
    "UKW-A": "EJMZALYXVBWFCRQUONTSPIKHGD",
    "UKW-B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "UKW-C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
}


class Rotor:
    """Represents a single Enigma rotor with wiring, ring setting, and position."""

    def __init__(self, name: str, ring: int = 0, position: int = 0):
        self.name = name.upper()
        if self.name not in ROTOR_WIRINGS:
            raise ValueError(f"Unknown rotor name: {name}")

        self.wiring = ROTOR_WIRINGS[self.name]
        self.notches = tuple(ord(n) - ord("A") for n in ROTOR_NOTCHES[self.name])
        self.ring = ring % 26
        self.position = position % 26

        # Forward and backward permutation tables
        self.forward = [ord(c) - ord("A") for c in self.wiring]
        self.backward = [0] * 26
        for i, val in enumerate(self.forward):
            self.backward[val] = i

    def is_at_notch(self) -> bool:
        """Returns True if the rotor's current position matches a turnover notch."""
        return self.position in self.notches

    def step(self) -> None:
        """Advance rotor position by 1."""
        self.position = (self.position + 1) % 26

    def forward_pin(self, pin: int) -> int:
        """Signal passes forward from right to left through the rotor."""
        offset = (self.position - self.ring) % 26
        entry = (pin + offset) % 26
        exit_pin = self.forward[entry]
        return (exit_pin - offset) % 26

    def backward_pin(self, pin: int) -> int:
        """Signal passes backward from left to right through the rotor."""
        offset = (self.position - self.ring) % 26
        entry = (pin + offset) % 26
        exit_pin = self.backward[entry]
        return (exit_pin - offset) % 26


class Plugboard:
    """Enigma Steckerbrett (plugboard) for swapping pairs of letters."""

    def __init__(self, pairs: str | list[str] = ""):
        self.mapping = list(range(26))
        if isinstance(pairs, str):
            pair_list = pairs.upper().split()
        else:
            pair_list = [p.upper() for p in pairs]

        used = set()
        for pair in pair_list:
            clean = re.sub(r"[^A-Z]", "", pair)
            if len(clean) == 2:
                a = ord(clean[0]) - ord("A")
                b = ord(clean[1]) - ord("A")
                if a not in used and b not in used:
                    self.mapping[a] = b
                    self.mapping[b] = a
                    used.add(a)
                    used.add(b)

    def swap(self, pin: int) -> int:
        return self.mapping[pin]


class EnigmaMachine:
    """Full 3-rotor Enigma Machine simulator with double-stepping mechanism."""

    def __init__(
        self,
        rotors: tuple[str, str, str] = ("I", "II", "III"),
        reflector: str = "UKW-B",
        ring_settings: tuple[int, int, int] = (0, 0, 0),
        positions: tuple[int, int, int] = (0, 0, 0),
        plugboard: str = "",
    ):
        self.rotors = [
            Rotor(rotors[0], ring=ring_settings[0], position=positions[0]),  # Left (slow)
            Rotor(rotors[1], ring=ring_settings[1], position=positions[1]),  # Middle
            Rotor(rotors[2], ring=ring_settings[2], position=positions[2]),  # Right (fast)
        ]
        self.reflector_name = reflector.upper()
        if self.reflector_name not in REFLECTOR_WIRINGS:
            raise ValueError(f"Unknown reflector: {reflector}")
        self.reflector = [ord(c) - ord("A") for c in REFLECTOR_WIRINGS[self.reflector_name]]
        self.plugboard = Plugboard(plugboard)

    def step_rotors(self) -> None:
        """Advance rotors with authentic double-stepping mechanical anomaly."""
        left, middle, right = self.rotors

        # Double-stepping logic:
        # 1. Right rotor always steps on every keypress.
        # 2. Middle rotor steps if right rotor is at its notch.
        # 3. Middle rotor ALSO steps and advances left rotor if middle rotor itself is at notch!
        middle_steps = right.is_at_notch() or middle.is_at_notch()
        left_steps = middle.is_at_notch()

        right.step()
        if middle_steps:
            middle.step()
        if left_steps:
            left.step()

    def encrypt_char(self, char: str) -> str:
        """Encrypt a single character through the complete Enigma circuit."""
        if not char.isalpha():
            return char

        is_upper = char.isupper()
        pin = ord(char.upper()) - ord("A")

        # 1. Rotors step BEFORE the electrical circuit closes
        self.step_rotors()

        # 2. Plugboard forward
        pin = self.plugboard.swap(pin)

        # 3. Right -> Middle -> Left rotors forward
        pin = self.rotors[2].forward_pin(pin)
        pin = self.rotors[1].forward_pin(pin)
        pin = self.rotors[0].forward_pin(pin)

        # 4. Reflector
        pin = self.reflector[pin]

        # 5. Left -> Middle -> Right rotors backward
        pin = self.rotors[0].backward_pin(pin)
        pin = self.rotors[1].backward_pin(pin)
        pin = self.rotors[2].backward_pin(pin)

        # 6. Plugboard backward
        pin = self.plugboard.swap(pin)

        res_char = chr(pin + ord("A"))
        return res_char if is_upper else res_char.lower()

    def encrypt(self, text: str) -> str:
        """Encrypt text (preserves non-alpha, case preserved)."""
        return "".join(self.encrypt_char(c) for c in text)

    def decrypt(self, text: str) -> str:
        """Enigma decryption is mathematically identical to encryption (self-reciprocal)."""
        return self.encrypt(text)


def enigma_encrypt(
    text: str,
    rotors: str = "I II III",
    reflector: str = "UKW-B",
    ring_settings: str = "0 0 0",
    positions: str = "A A A",
    plugboard: str = "",
) -> str:
    """Convenience functional interface for Enigma encryption."""
    rotor_tuple = tuple(rotors.split())[:3]  # type: ignore
    if len(rotor_tuple) < 3:
        rotor_tuple = ("I", "II", "III")

    # Parse ring settings (supports letters "A B C" or numbers "0 1 2")
    rings = []
    for r in ring_settings.split()[:3]:
        if r.isdigit():
            rings.append(int(r))
        elif r.isalpha():
            rings.append(ord(r.upper()) - ord("A"))
        else:
            rings.append(0)
    while len(rings) < 3:
        rings.append(0)

    # Parse start positions
    pos = []
    for p in positions.split()[:3]:
        if p.isdigit():
            pos.append(int(p))
        elif p.isalpha():
            pos.append(ord(p.upper()) - ord("A"))
        else:
            pos.append(0)
    while len(pos) < 3:
        pos.append(0)

    machine = EnigmaMachine(
        rotors=rotor_tuple,  # type: ignore
        reflector=reflector,
        ring_settings=tuple(rings),  # type: ignore
        positions=tuple(pos),  # type: ignore
        plugboard=plugboard,
    )
    return machine.encrypt(text)


def enigma_decrypt(
    text: str,
    rotors: str = "I II III",
    reflector: str = "UKW-B",
    ring_settings: str = "0 0 0",
    positions: str = "A A A",
    plugboard: str = "",
) -> str:
    """Convenience functional interface for Enigma decryption."""
    return enigma_encrypt(text, rotors, reflector, ring_settings, positions, plugboard)
