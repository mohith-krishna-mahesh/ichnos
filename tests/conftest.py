import io
import math
import struct
import zipfile
import zlib

import pytest


@pytest.fixture
def caesar_rot13_text():
    return ("GUVF VF N FRPERG ZRFFNTR", "THIS IS A SECRET MESSAGE", 13)


@pytest.fixture
def vigenere_known():
    # Vigenere encrypt
    plaintext = "ATTACKATDAWN"
    key = "LEMON"

    # Compute ciphertext
    ciphertext = []
    key_len = len(key)
    for i, char in enumerate(plaintext):
        p_val = ord(char) - ord("A")
        k_val = ord(key[i % key_len]) - ord("A")
        c_val = (p_val + k_val) % 26
        ciphertext.append(chr(c_val + ord("A")))

    return plaintext, key, "".join(ciphertext)


@pytest.fixture
def tiny_png_with_lsb():
    width = 8
    height = 8
    flag = b"FLAG{lsb_works}"
    flag_bits = "".join(f"{b:08b}" for b in flag)

    # Needs width * height * 3 = 192 bytes
    pixels = bytearray([0] * (width * height * 3))

    for i, bit in enumerate(flag_bits):
        if i < len(pixels):
            pixels[i] = int(bit)

    # PNG format
    png_magic = b"\x89PNG\r\n\x1a\n"

    # IHDR
    ihdr_data = struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    ihdr = struct.pack("!I4s13sI", 13, b"IHDR", ihdr_data, ihdr_crc)

    # IDAT
    scanlines = b""
    for y in range(height):
        # filter type 0
        scanlines += b"\x00" + pixels[y * (width * 3) : (y + 1) * (width * 3)]

    idat_data = zlib.compress(scanlines)
    idat_crc = zlib.crc32(b"IDAT" + idat_data) & 0xFFFFFFFF
    idat = struct.pack(f"!I4s{len(idat_data)}sI", len(idat_data), b"IDAT", idat_data, idat_crc)

    # IEND
    iend_crc = zlib.crc32(b"IEND") & 0xFFFFFFFF
    iend = struct.pack("!I4s0sI", 0, b"IEND", b"", iend_crc)

    return png_magic + ihdr + idat + iend


@pytest.fixture
def morse_wav():
    sample_rate = 8000
    freq = 600.0

    def generate_tone(duration_ms):
        samples = int(sample_rate * (duration_ms / 1000.0))
        return [int(32767 * math.sin(2 * math.pi * freq * i / sample_rate)) for i in range(samples)]

    def generate_silence(duration_ms):
        samples = int(sample_rate * (duration_ms / 1000.0))
        return [0] * samples

    dot = generate_tone(100)
    dash = generate_tone(300)
    intra_char = generate_silence(100)
    inter_char = generate_silence(300)

    # S = ...
    # O = ---
    # S = ...
    s = dot + intra_char + dot + intra_char + dot
    o = dash + intra_char + dash + intra_char + dash

    audio_data = s + inter_char + o + inter_char + s

    data_bytes = struct.pack(f"<{len(audio_data)}h", *audio_data)

    # WAV format
    riff_header = b"RIFF"
    file_size = struct.pack("<I", 36 + len(data_bytes))
    wave_header = b"WAVE"

    fmt_chunk_marker = b"fmt "
    fmt_chunk_size = struct.pack("<I", 16)
    audio_format = struct.pack("<H", 1)  # PCM
    num_channels = struct.pack("<H", 1)
    sr = struct.pack("<I", sample_rate)
    byte_rate = struct.pack("<I", sample_rate * 2)
    block_align = struct.pack("<H", 2)
    bits_per_sample = struct.pack("<H", 16)

    data_chunk_marker = b"data"
    data_chunk_size = struct.pack("<I", len(data_bytes))

    return (
        riff_header
        + file_size
        + wave_header
        + fmt_chunk_marker
        + fmt_chunk_size
        + audio_format
        + num_channels
        + sr
        + byte_rate
        + block_align
        + bits_per_sample
        + data_chunk_marker
        + data_chunk_size
        + data_bytes
    )


@pytest.fixture
def minimal_elf():
    # 64 bytes ELF header
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = struct.pack("<H", 2)
    e_machine = struct.pack("<H", 62)  # EM_X86_64
    e_version = struct.pack("<I", 1)
    e_entry = struct.pack("<Q", 0x400000)
    e_phoff = struct.pack("<Q", 64)
    e_shoff = struct.pack("<Q", 0)
    e_flags = struct.pack("<I", 0)
    e_ehsize = struct.pack("<H", 64)
    e_phentsize = struct.pack("<H", 56)
    e_phnum = struct.pack("<H", 1)
    e_shentsize = struct.pack("<H", 0)
    e_shnum = struct.pack("<H", 0)
    e_shstrndx = struct.pack("<H", 0)

    elf_header = (
        e_ident
        + e_type
        + e_machine
        + e_version
        + e_entry
        + e_phoff
        + e_shoff
        + e_flags
        + e_ehsize
        + e_phentsize
        + e_phnum
        + e_shentsize
        + e_shnum
        + e_shstrndx
    )

    # 56 bytes Program header
    p_type = struct.pack("<I", 1)  # PT_LOAD
    p_flags = struct.pack("<I", 5)  # R+X
    p_offset = struct.pack("<Q", 0)
    p_vaddr = struct.pack("<Q", 0x400000)
    p_paddr = struct.pack("<Q", 0x400000)
    p_filesz = struct.pack("<Q", 120)
    p_memsz = struct.pack("<Q", 120)
    p_align = struct.pack("<Q", 0x200000)

    program_header = p_type + p_flags + p_offset + p_vaddr + p_paddr + p_filesz + p_memsz + p_align

    return elf_header + program_header


@pytest.fixture
def password_zip(tmp_path):
    # Using zipfile module, standard python doesn't easily encrypt zip files
    # We will just write a mock standard ZIP file containing flag.txt
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("flag.txt", "FLAG{zip_cracked}")
    return buf.getvalue()
