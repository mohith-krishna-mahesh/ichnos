"""Filesystem structures and partition table forensics (MBR, GPT, FAT BPB).

Parses Master Boot Records (MBR), GUID Partition Tables (GPT),
and FAT12/16/32 BIOS Parameter Blocks (BPB) directly from disk images or memory.
"""

from __future__ import annotations

import struct
import uuid
from typing import Any

MBR_PARTITION_TYPES: dict[int, str] = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 (less than 32MB)",
    0x05: "Extended Partition (CHS)",
    0x06: "FAT16 (greater than 32MB)",
    0x07: "NTFS / exFAT",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended Partition (LBA)",
    0x82: "Linux Swap",
    0x83: "Linux Native (ext2/ext3/ext4)",
    0x8E: "Linux LVM",
    0xEE: "GPT Protective MBR",
    0xEF: "EFI System Partition",
}


def parse_mbr(data: bytes) -> dict[str, Any]:
    """Parses Master Boot Record (MBR) partition table (512 bytes)."""
    if len(data) < 512:
        raise ValueError("Data too short for MBR (minimum 512 bytes)")

    sig = data[510:512]
    if sig != b"\x55\xaa":
        raise ValueError("Invalid MBR boot signature (expected 0x55AA)")

    partitions: list[dict[str, Any]] = []

    # 4 Partition Entries at offset 446 (0x1BE), 16 bytes each
    for i in range(4):
        off = 446 + i * 16
        entry = data[off : off + 16]
        bootable, _, _, _, p_type, _, _, _, lba_start, sector_count = struct.unpack(
            "<BBBBBBBBII", entry
        )

        if p_type == 0x00 and sector_count == 0:
            continue

        partitions.append(
            {
                "slot": i + 1,
                "bootable": bootable == 0x80,
                "type_code": hex(p_type),
                "type_name": MBR_PARTITION_TYPES.get(p_type, f"Unknown (0x{p_type:02X})"),
                "lba_start": lba_start,
                "sector_count": sector_count,
                "size_bytes": sector_count * 512,
                "size_mb": round((sector_count * 512) / (1024 * 1024), 2),
            }
        )

    is_gpt_protective = any(p["type_code"] == "0xee" for p in partitions)

    return {
        "valid": True,
        "is_gpt_protective": is_gpt_protective,
        "partition_count": len(partitions),
        "partitions": partitions,
    }


def parse_gpt(data: bytes) -> dict[str, Any]:
    """Parses GUID Partition Table (GPT) header from LBA 1 (offset 512)."""
    # Look for EFI PART at offset 512 or offset 0
    gpt_off = (
        512
        if len(data) >= 1024 and data[512:520] == b"EFI PART"
        else (0 if data[:8] == b"EFI PART" else -1)
    )
    if gpt_off == -1:
        raise ValueError("Invalid GPT: missing 'EFI PART' signature")

    hdr = data[gpt_off : gpt_off + 92]
    if len(hdr) < 92:
        raise ValueError("Truncated GPT header")

    sig, rev, hdr_sz, crc, _, cur_lba, backup_lba, first_lba, last_lba, raw_guid = struct.unpack(
        "<8sIIIIQQQQ16s", hdr[:72]
    )
    part_lba, num_parts, part_entry_sz, part_crc = struct.unpack("<QIII", hdr[72:92])

    disk_guid = str(uuid.UUID(bytes_le=raw_guid))

    # Parse partition entries
    partitions: list[dict[str, Any]] = []
    # If partition entries are in the provided buffer
    entries_offset = int(part_lba * 512)
    if entries_offset + (num_parts * part_entry_sz) <= len(data):
        for i in range(num_parts):
            p_off = entries_offset + i * part_entry_sz
            p_data = data[p_off : p_off + part_entry_sz]
            type_guid_raw = p_data[:16]
            if type_guid_raw == b"\x00" * 16:
                continue
            type_guid = str(uuid.UUID(bytes_le=type_guid_raw))
            part_guid = str(uuid.UUID(bytes_le=p_data[16:32]))
            first_sec, last_sec, flags = struct.unpack("<QQQ", p_data[32:56])
            name = p_data[56:128].decode("utf-16le", errors="replace").rstrip("\x00")

            sec_count = (last_sec - first_sec + 1) if last_sec >= first_sec else 0
            partitions.append(
                {
                    "index": i + 1,
                    "name": name,
                    "type_guid": type_guid,
                    "partition_guid": part_guid,
                    "first_lba": first_sec,
                    "last_lba": last_sec,
                    "sectors": sec_count,
                    "size_bytes": sec_count * 512,
                }
            )

    return {
        "valid": True,
        "disk_guid": disk_guid,
        "current_lba": cur_lba,
        "backup_lba": backup_lba,
        "first_usable_lba": first_lba,
        "last_usable_lba": last_lba,
        "num_partition_entries": num_parts,
        "partition_entry_size": part_entry_sz,
        "partitions": partitions,
    }


def parse_fat_bpb(data: bytes) -> dict[str, Any]:
    """Parses FAT12/16/32 BIOS Parameter Block (BPB)."""
    if len(data) < 512:
        raise ValueError("Data too short for FAT BPB")

    # Check jump instruction
    if data[0] not in (0xEB, 0xE9):
        raise ValueError("Invalid FAT boot sector: missing jump instruction")

    oem_name = data[3:11].decode("latin-1", errors="replace").strip()
    (
        bytes_per_sec,
        sec_per_cluster,
        reserved_sec,
        num_fats,
        root_entries,
        total_sec16,
        media,
        fat_sz16,
        sec_per_track,
        num_heads,
        hidden_sec,
        total_sec32,
    ) = struct.unpack("<HBHBHHBHHHII", data[11:36])

    is_fat32 = fat_sz16 == 0 and root_entries == 0
    fat_size = fat_sz16
    fs_type = "FAT16" if total_sec16 > 0 else "FAT12"

    if is_fat32 and len(data) >= 90:
        fat_size = struct.unpack("<I", data[36:40])[0]
        fs_type = "FAT32"

    total_sectors = total_sec32 if total_sec16 == 0 else total_sec16

    return {
        "oem_name": oem_name,
        "filesystem_type": fs_type,
        "bytes_per_sector": bytes_per_sec,
        "sectors_per_cluster": sec_per_cluster,
        "reserved_sectors": reserved_sec,
        "num_fats": num_fats,
        "root_directory_entries": root_entries,
        "total_sectors": total_sectors,
        "fat_size_sectors": fat_size,
        "volume_size_bytes": total_sectors * bytes_per_sec,
        "volume_size_mb": round((total_sectors * bytes_per_sec) / (1024 * 1024), 2),
    }


def inspect_disk(data: bytes) -> dict[str, Any]:
    """Auto-detects and inspects partition table or boot sector from raw disk data."""
    # Check GPT
    if (len(data) >= 1024 and data[512:520] == b"EFI PART") or data[:8] == b"EFI PART":
        return {"structure": "gpt", **parse_gpt(data)}

    # Check MBR
    if len(data) >= 512 and data[510:512] == b"\x55\xaa":
        try:
            mbr_info = parse_mbr(data)
            # If it's a protective MBR, check if GPT follows
            if mbr_info["is_gpt_protective"] and len(data) >= 1024:
                try:
                    return {"structure": "gpt_protective_mbr", **parse_gpt(data)}
                except Exception:
                    pass
            return {"structure": "mbr", **mbr_info}
        except Exception:
            pass

    # Check FAT
    if len(data) >= 512 and data[0] in (0xEB, 0xE9):
        try:
            return {"structure": "fat_bpb", **parse_fat_bpb(data)}
        except Exception:
            pass

    raise ValueError("Unrecognized disk partition or filesystem structure")
