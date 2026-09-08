"""File type identification."""

from __future__ import annotations

import struct


def identify(data: bytes) -> dict:
    result = {
        "type": "Unknown",
        "description": "Unknown file type",
        "mime": "application/octet-stream",
        "architecture": None,
        "endianness": None,
    }
    if not data:
        return result

    if data.startswith(b"\x7fELF"):
        result["type"] = "ELF"
        result["mime"] = "application/x-executable"
        result["description"] = "ELF binary"
        if len(data) >= 20:
            ei_class = data[4]
            ei_data = data[5]
            e_type_le = struct.unpack("<H", data[16:18])[0]
            e_type_be = struct.unpack(">H", data[16:18])[0]
            e_machine_le = struct.unpack("<H", data[18:20])[0]
            e_machine_be = struct.unpack(">H", data[18:20])[0]

            cls_str = "64-bit" if ei_class == 2 else "32-bit" if ei_class == 1 else "Unknown class"
            end_str = (
                "Big Endian"
                if ei_data == 2
                else "Little Endian"
                if ei_data == 1
                else "Unknown endianness"
            )

            e_type = e_type_be if ei_data == 2 else e_type_le
            type_str = {1: "Relocatable", 2: "Executable", 3: "Shared object", 4: "Core"}.get(
                e_type, "Unknown type"
            )

            e_machine = e_machine_be if ei_data == 2 else e_machine_le
            mach_str = {3: "x86", 8: "MIPS", 40: "ARM", 62: "x86-64", 183: "AArch64"}.get(
                e_machine, "Unknown machine"
            )

            result["description"] = f"ELF {cls_str} {end_str[:3]} {type_str}, {mach_str}"
            result["architecture"] = mach_str
            result["endianness"] = end_str
    elif data.startswith(b"MZ"):
        result["type"] = "PE"
        result["mime"] = "application/x-dosexec"
        result["description"] = "PE Executable"
        pe_offset_pos = 0x3C
        if len(data) >= pe_offset_pos + 4:
            pe_offset = struct.unpack("<I", data[pe_offset_pos : pe_offset_pos + 4])[0]
            if pe_offset + 24 < len(data) and data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                machine = struct.unpack("<H", data[pe_offset + 4 : pe_offset + 6])[0]
                characteristics = struct.unpack("<H", data[pe_offset + 22 : pe_offset + 24])[0]
                is_dll = bool(characteristics & 0x2000)
                arch_str = (
                    "x86" if machine == 0x014C else "x86-64" if machine == 0x8664 else "Unknown"
                )
                file_type = "DLL" if is_dll else "EXE"
                result["description"] = (
                    f"PE32{'+' if arch_str == 'x86-64' else ''} executable ({file_type}) {arch_str}"
                )
                result["architecture"] = arch_str
                result["endianness"] = "Little Endian"
    elif (
        data.startswith(b"\xfe\xed\xfa\xce")
        or data.startswith(b"\xfe\xed\xfa\xcf")
        or data.startswith(b"\xcf\xfa\xed\xfe")
        or data.startswith(b"\xce\xfa\xed\xfe")
    ):
        result["type"] = "Mach-O"
        result["mime"] = "application/x-mach-binary"
        result["description"] = "Mach-O Executable"
        if len(data) >= 8:
            magic = struct.unpack("<I", data[:4])[0]
            if magic in (0xFEEDFACE, 0xCEFAEDFE):
                result["description"] = "Mach-O 32-bit"
            elif magic in (0xFEEDFACF, 0xCFFAEDFE):
                result["description"] = "Mach-O 64-bit"
    elif data.startswith(b"PK\x03\x04"):
        result["type"] = "ZIP"
        result["mime"] = "application/zip"
        result["description"] = "ZIP Archive"
        if b"[Content_Types].xml" in data[:2048]:
            if b"word/" in data[:2048]:
                result["description"] = "Microsoft Word (OpenXML)"
                result["mime"] = (
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                )
            elif b"xl/" in data[:2048]:
                result["description"] = "Microsoft Excel (OpenXML)"
                result["mime"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            elif b"ppt/" in data[:2048]:
                result["description"] = "Microsoft PowerPoint (OpenXML)"
                result["mime"] = (
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                )
    elif data.startswith(b"Rar!\x1a\x07\x00") or data.startswith(b"Rar!\x1a\x07\x01\x00"):
        result["type"] = "RAR"
        result["mime"] = "application/vnd.rar"
        result["description"] = "RAR Archive"
    elif data.startswith(b"7z\xbc\xaf\x27\x1c"):
        result["type"] = "7z"
        result["mime"] = "application/x-7z-compressed"
        result["description"] = "7-zip Archive"
    elif data.startswith(b"\x1f\x8b"):
        result["type"] = "GZIP"
        result["mime"] = "application/gzip"
        result["description"] = "GZIP Archive"
    elif data.startswith(b"BZh"):
        result["type"] = "BZIP2"
        result["mime"] = "application/x-bzip2"
        result["description"] = "BZIP2 Archive"
    elif data.startswith(b"\xfd7zXZ\x00"):
        result["type"] = "XZ"
        result["mime"] = "application/x-xz"
        result["description"] = "XZ Archive"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        result["type"] = "PNG"
        result["mime"] = "image/png"
        result["description"] = "PNG Image data"
    elif data.startswith(b"\xff\xd8\xff"):
        result["type"] = "JPEG"
        result["mime"] = "image/jpeg"
        result["description"] = "JPEG Image data"
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        result["type"] = "GIF"
        result["mime"] = "image/gif"
        result["description"] = "GIF Image data"
    elif data.startswith(b"BM"):
        result["type"] = "BMP"
        result["mime"] = "image/bmp"
        result["description"] = "BMP Image data"
    elif data.startswith(b"II*\x00") or data.startswith(b"MM\x00*"):
        result["type"] = "TIFF"
        result["mime"] = "image/tiff"
        result["description"] = "TIFF Image data"
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        result["type"] = "WebP"
        result["mime"] = "image/webp"
        result["description"] = "WebP Image data"
    elif data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        result["type"] = "WAV"
        result["mime"] = "audio/wav"
        result["description"] = "WAV Audio data"
    elif data.startswith(b"ID3") or data[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        result["type"] = "MP3"
        result["mime"] = "audio/mpeg"
        result["description"] = "MP3 Audio data"
    elif data.startswith(b"fLaC"):
        result["type"] = "FLAC"
        result["mime"] = "audio/flac"
        result["description"] = "FLAC Audio data"
    elif data.startswith(b"OggS"):
        result["type"] = "OGG"
        result["mime"] = "audio/ogg"
        result["description"] = "OGG Audio data"
    elif data.startswith(b"%PDF-"):
        result["type"] = "PDF"
        result["mime"] = "application/pdf"
        result["description"] = "PDF Document"

    return result


def identify_summary(data: bytes) -> str:
    res = identify(data)
    return res.get("description", "Unknown")
