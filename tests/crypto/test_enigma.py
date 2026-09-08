"""Tests for historically authentic Enigma machine emulator."""

from __future__ import annotations

from ichnos.crypto.classical.enigma import (
    EnigmaMachine,
    Plugboard,
    enigma_decrypt,
    enigma_encrypt,
)


def test_enigma_historical_vector_aaaaa():
    # Rotors I, II, III, UKW-B, Rings 0 0 0, Positions A A A (0 0 0)
    # AAAAA encrypts to BDZGO
    ct = enigma_encrypt(
        "AAAAA", rotors="I II III", reflector="UKW-B", ring_settings="0 0 0", positions="A A A"
    )
    assert ct == "BDZGO"

    # Decrypting with identical initial settings yields AAAAA
    pt = enigma_decrypt(
        "BDZGO", rotors="I II III", reflector="UKW-B", ring_settings="0 0 0", positions="A A A"
    )
    assert pt == "AAAAA"


def test_enigma_double_stepping():
    # Test authentic double stepping mechanical ratchet anomaly:
    # Middle rotor steps when right rotor is at its notch.
    # Middle rotor ALSO steps when middle rotor itself is at its notch (advancing left rotor too).
    # Rotors: Left=I (notch Q=16), Middle=II (notch E=4), Right=III (notch V=21)
    # Set positions right before double stepping:
    # Left = A (0), Middle = D (3), Right = U (20)
    machine = EnigmaMachine(
        rotors=("I", "II", "III"),
        reflector="UKW-B",
        ring_settings=(0, 0, 0),
        positions=(0, 3, 20),
    )

    # Step 1: Right steps to V (21, at notch)
    machine.step_rotors()
    assert (machine.rotors[0].position, machine.rotors[1].position, machine.rotors[2].position) == (
        0,
        3,
        21,
    )

    # Step 2: Right was at notch V, so Right steps to W (22) and Middle steps to E (4, at notch!)
    machine.step_rotors()
    assert (machine.rotors[0].position, machine.rotors[1].position, machine.rotors[2].position) == (
        0,
        4,
        22,
    )

    # Step 3: DOUBLE STEPPING OCCURS! Middle was at notch E (4)!
    # Middle steps again to F (5) and advances Left to B (1). Right steps to X (23).
    machine.step_rotors()
    assert (machine.rotors[0].position, machine.rotors[1].position, machine.rotors[2].position) == (
        1,
        5,
        23,
    )


def test_plugboard_swapping():
    pb = Plugboard("AB CD EF")
    # A (0) <-> B (1)
    assert pb.swap(0) == 1
    assert pb.swap(1) == 0
    # C (2) <-> D (3)
    assert pb.swap(2) == 3
    assert pb.swap(3) == 2
    # Unplugged G (6) remains G (6)
    assert pb.swap(6) == 6


def test_enigma_with_plugboard_and_rings():
    text = "DEFENDTHEEASTWALLFORTHEFLAG"
    rotors = "IV V II"
    reflector = "UKW-C"
    rings = "2 14 20"
    pos = "K D V"
    pb = "AV BS CG DL FU HZ IN KM OW RX"

    ct = enigma_encrypt(
        text, rotors=rotors, reflector=reflector, ring_settings=rings, positions=pos, plugboard=pb
    )
    assert ct != text
    assert len(ct) == len(text)

    # Decrypt with fresh machine
    pt = enigma_decrypt(
        ct, rotors=rotors, reflector=reflector, ring_settings=rings, positions=pos, plugboard=pb
    )
    assert pt == text


def test_enigma_case_and_punctuation():
    text = "Attack at Dawn! 1941."
    ct = enigma_encrypt(text, positions="B C D")
    assert ct[-7:] == "! 1941."
    assert ct[0].isupper()
    assert ct[1].islower()
    pt = enigma_decrypt(ct, positions="B C D")
    assert pt == text


def test_enigma_historical_military_and_manual_vectors():
    """Validates Enigma against authentic military/manual test vectors with full plugboard and ring settings."""
    # 1. 10-pair plugboard military setting: Rotors I II III, UKW-B, Rings 5 21 10, Pos Q E V
    pt1 = "DERFUEHRERISTTOT"
    pb1 = "AF BV CP DJ EI GO HY KR LZ MX"
    ct1 = enigma_encrypt(
        pt1,
        rotors="I II III",
        reflector="UKW-B",
        ring_settings="5 21 10",
        positions="Q E V",
        plugboard=pb1,
    )
    assert ct1 == "VRAADDVTDOCGIZBG"
    assert (
        enigma_decrypt(
            ct1,
            rotors="I II III",
            reflector="UKW-B",
            ring_settings="5 21 10",
            positions="Q E V",
            plugboard=pb1,
        )
        == pt1
    )

    # 2. 1930 Reichswehr Manual (G.Dv. 32) setting: Rotors II I III, UKW-A, Rings 24 13 22, Pos A B L
    pt2 = "FEINDLICHEINFANTERIE"
    pb2 = "AM FI NV PS TU WZ"
    ct2 = enigma_encrypt(
        pt2,
        rotors="II I III",
        reflector="UKW-A",
        ring_settings="24 13 22",
        positions="A B L",
        plugboard=pb2,
    )
    assert ct2 == "GWWYSACMBJEFMMCUUQFL"
    assert (
        enigma_decrypt(
            ct2,
            rotors="II I III",
            reflector="UKW-A",
            ring_settings="24 13 22",
            positions="A B L",
            plugboard=pb2,
        )
        == pt2
    )
