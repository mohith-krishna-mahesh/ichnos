import bz2
import gzip
import io
import lzma
import struct
import tarfile
import uuid
import zipfile
from datetime import datetime, timezone

from ichnos.forensic.archives import (
    decompress_stream,
    inspect_7z_header,
    inspect_archive,
    inspect_rar_header,
    inspect_tar,
)
from ichnos.forensic.carver import (
    carve_all,
    carve_gif,
    carve_jpeg,
    carve_pdf,
    carve_png,
    carve_zip,
)
from ichnos.forensic.filesystem import (
    inspect_disk,
    parse_fat_bpb,
    parse_gpt,
    parse_mbr,
)
from ichnos.forensic.timestamps import (
    chrome_to_datetime,
    cocoa_to_datetime,
    convert_timestamp,
    datetime_to_filetime,
    dos_datetime_to_datetime,
    filetime_to_datetime,
)


def test_tar_and_archives():
    # Build a TAR archive in memory
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        data = b"secret flag data"
        info = tarfile.TarInfo(name="secret.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    tar_bytes = buf.getvalue()
    tar_info = inspect_tar(tar_bytes)
    assert tar_info["format"] == "tar"
    assert tar_info["total_entries"] == 1
    assert tar_info["entries"][0]["name"] == "secret.txt"

    # Single-stream compression tests
    raw_payload = b"Compressed data payload for CTF challenge"
    gz_data = gzip.compress(raw_payload)
    algo, dec = decompress_stream(gz_data)
    assert algo == "gzip"
    assert dec == raw_payload

    bz_data = bz2.compress(raw_payload)
    algo, dec = decompress_stream(bz_data)
    assert algo == "bz2"
    assert dec == raw_payload

    xz_data = lzma.compress(raw_payload)
    algo, dec = decompress_stream(xz_data)
    assert algo == "xz"
    assert dec == raw_payload

    # inspect_archive router
    assert inspect_archive(gz_data)["format"] == "gzip"
    assert inspect_archive(bz_data)["format"] == "bz2"
    assert inspect_archive(xz_data)["format"] == "xz"

    # 7z header inspection
    seven_z = b"7z\xbc\xaf'\x1c\x00\x04" + struct.pack(
        "<IQQI", 0x12345678, 0x100, 0x200, 0x87654321
    )
    seven_z_info = inspect_7z_header(seven_z)
    assert seven_z_info["format"] == "7z"
    assert seven_z_info["version"] == "0.4"

    # RAR header inspection
    rar4 = b"Rar!\x1a\x07\x00extra data"
    rar5 = b"Rar!\x1a\x07\x01\x00extra data"
    assert inspect_rar_header(rar4)["version"] == "RAR4"
    assert inspect_rar_header(rar5)["version"] == "RAR5"


def test_file_carver():
    # Construct embedded payload: junk + PNG + junk + JPEG + junk + PDF + junk + ZIP + junk + GIF
    png_bytes = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        + b"A" * 13
        + b"CRC1"
        + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
    pdf_bytes = b"%PDF-1.4\n1 0 obj<<>>endobj\nxref\ntrailer<<>>\nstartxref\n100\n%%EOF\r\n"

    # Simple ZIP
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr("test.txt", "hello")
    zip_bytes = zbuf.getvalue()

    gif_bytes = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!," + b"\x00" * 5 + b";"

    garbage = b"RANDOM_PADDING_GARBAGE_12345"
    carrier = (
        garbage
        + png_bytes
        + garbage
        + jpeg_bytes
        + garbage
        + pdf_bytes
        + garbage
        + zip_bytes
        + garbage
        + gif_bytes
    )

    # Test individual carvers
    carved_png = carve_png(carrier)
    assert len(carved_png) == 1
    assert carved_png[0].file_type == "png"
    assert carved_png[0].data == png_bytes

    carved_jpeg = carve_jpeg(carrier)
    assert len(carved_jpeg) == 1
    assert carved_jpeg[0].file_type == "jpeg"
    assert carved_jpeg[0].data == jpeg_bytes

    carved_pdf = carve_pdf(carrier)
    assert len(carved_pdf) == 1
    assert carved_pdf[0].file_type == "pdf"
    assert b"%PDF-1.4" in carved_pdf[0].data

    carved_zip = carve_zip(carrier)
    assert len(carved_zip) == 1
    assert carved_zip[0].file_type == "zip"
    assert carved_zip[0].data == zip_bytes

    carved_gif = carve_gif(carrier)
    assert len(carved_gif) == 1
    assert carved_gif[0].file_type == "gif"
    assert carved_gif[0].data == gif_bytes

    # Test carve_all
    all_carved = carve_all(carrier)
    assert len(all_carved) == 5
    types = [c.file_type for c in all_carved]
    assert types == ["png", "jpeg", "pdf", "zip", "gif"]


def test_filesystem_and_disk():
    # Construct 512-byte MBR
    mbr = bytearray(512)
    # Entry 1: Bootable (0x80), Type 0x83 (Linux Native), LBA start 2048, 10000 sectors
    entry1 = struct.pack("<BBBBBBBBII", 0x80, 0, 0, 0, 0x83, 0, 0, 0, 2048, 10000)
    mbr[446:462] = entry1
    mbr[510:512] = b"\x55\xaa"

    mbr_info = parse_mbr(bytes(mbr))
    assert mbr_info["valid"] is True
    assert mbr_info["partition_count"] == 1
    assert mbr_info["partitions"][0]["bootable"] is True
    assert mbr_info["partitions"][0]["type_name"] == "Linux Native (ext2/ext3/ext4)"
    assert mbr_info["partitions"][0]["sector_count"] == 10000

    # Test inspect_disk on MBR
    disk_info = inspect_disk(bytes(mbr))
    assert disk_info["structure"] == "mbr"

    # Construct FAT BPB
    fat_boot = bytearray(512)
    fat_boot[0:3] = b"\xeb\x3c\x90"
    fat_boot[3:11] = b"MSDOS5.0"
    # bytes_per_sec=512, sec_per_cluster=4, reserved_sec=1, num_fats=2, root_entries=512,
    # total_sec16=20480, media=0xF8, fat_sz16=9, sec_per_track=18, num_heads=2, hidden_sec=0, total_sec32=0
    fat_fields = struct.pack("<HBHBHHBHHHII", 512, 4, 1, 2, 512, 20480, 0xF8, 9, 18, 2, 0, 0)
    fat_boot[11:36] = fat_fields
    fat_boot[510:512] = b"\x55\xaa"

    fat_info = parse_fat_bpb(bytes(fat_boot))
    assert fat_info["filesystem_type"] == "FAT16"
    assert fat_info["bytes_per_sector"] == 512
    assert fat_info["sectors_per_cluster"] == 4
    assert fat_info["oem_name"] == "MSDOS5.0"

    # Test GPT header
    gpt_buf = bytearray(1024)
    # EFI PART at offset 512
    raw_guid = b"\x01" * 16
    gpt_hdr = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        b"EFI PART",
        0x00010000,
        92,
        0x12345678,
        0,
        1,
        32,
        34,
        64,
        raw_guid,
        2,
        128,
        128,
        0,
    )
    gpt_buf[512 : 512 + len(gpt_hdr)] = gpt_hdr
    gpt_info = parse_gpt(bytes(gpt_buf))
    assert gpt_info["valid"] is True
    assert gpt_info["current_lba"] == 1


def test_realistic_multipartition_gpt_fat_disk_image():
    """Validates disk forensics against a realistic multi-partition disk image.

    Layout:
    - LBA 0 (0-511): Protective MBR with 0xEE partition
    - LBA 1 (512-1023): GPT Header (EFI PART) pointing to LBA 2
    - LBA 2 (1024-2047): GPT Partition Entries:
      - Partition 1: EFI System Partition (ESP GUID)
      - Partition 2: Microsoft Basic Data (Data GUID)
    - LBA 11 (5632-6143): Formatted FAT16 BPB filesystem at the start of Partition 2
    """
    disk = bytearray(32 * 512)

    # 1. LBA 0: Protective MBR
    mbr_entry = struct.pack("<BBBBBBBBII", 0x00, 0, 0, 0, 0xEE, 0, 0, 0, 1, 31)
    disk[446:462] = mbr_entry
    disk[510:512] = b"\x55\xaa"

    # 2. LBA 1: GPT Header
    disk_guid = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00").bytes_le
    gpt_hdr = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        b"EFI PART",
        0x00010000,
        92,
        0,
        0,
        1,
        31,
        34,
        30,
        disk_guid,
        2,
        2,
        128,
        0,
    )
    disk[512 : 512 + 92] = gpt_hdr

    # 3. LBA 2: GPT Partition Entries
    esp_type = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").bytes_le
    esp_part = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").bytes_le
    esp_name = "EFI System".encode("utf-16le").ljust(72, b"\x00")
    p1 = esp_type + esp_part + struct.pack("<QQQ", 4, 10, 0) + esp_name
    disk[1024 : 1024 + 128] = p1

    data_type = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").bytes_le
    data_part = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").bytes_le
    data_name = "CTF_DATA".encode("utf-16le").ljust(72, b"\x00")
    p2 = data_type + data_part + struct.pack("<QQQ", 11, 25, 0) + data_name
    disk[1024 + 128 : 1024 + 256] = p2

    # 4. LBA 11: Embedded FAT16 BPB
    fat_boot = bytearray(512)
    fat_boot[0:3] = b"\xeb\x3c\x90"
    fat_boot[3:11] = b"ICHNOSFS"
    fat_fields = struct.pack("<HBHBHHBHHHII", 512, 4, 1, 2, 512, 20480, 0xF8, 9, 18, 2, 0, 0)
    fat_boot[11:36] = fat_fields
    fat_boot[510:512] = b"\x55\xaa"
    disk[11 * 512 : 12 * 512] = fat_boot

    # Test inspect_disk
    disk_info = inspect_disk(bytes(disk))
    assert disk_info["structure"] == "gpt"
    assert disk_info["valid"] is True
    assert disk_info["disk_guid"] == "11223344-5566-7788-99aa-bbccddeeff00"
    assert len(disk_info["partitions"]) == 2

    # Verify partition 1 (ESP)
    part1 = disk_info["partitions"][0]
    assert part1["name"] == "EFI System"
    assert part1["type_guid"] == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
    assert part1["first_lba"] == 4
    assert part1["sectors"] == 7

    # Verify partition 2 (Data)
    part2 = disk_info["partitions"][1]
    assert part2["name"] == "CTF_DATA"
    assert part2["type_guid"] == "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
    assert part2["first_lba"] == 11
    assert part2["sectors"] == 15

    # Verify embedded filesystem at partition 2 offset
    data_part_offset = part2["first_lba"] * 512
    fs_info = parse_fat_bpb(bytes(disk[data_part_offset:]))
    assert fs_info["oem_name"] == "ICHNOSFS"
    assert fs_info["filesystem_type"] == "FAT16"
    assert fs_info["bytes_per_sector"] == 512
    assert fs_info["sectors_per_cluster"] == 4


def test_timestamp_conversions():
    target_dt = datetime(2023, 10, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Windows FILETIME
    filetime_val = datetime_to_filetime(target_dt)
    dt_recovered = filetime_to_datetime(filetime_val)
    assert dt_recovered == target_dt

    # Apple Cocoa time (epoch 2001-01-01)
    cocoa_val = target_dt.timestamp() - 978307200
    assert cocoa_to_datetime(cocoa_val) == target_dt

    # Chrome / WebKit time (microseconds since 1601-01-01)
    chrome_val = int((target_dt.timestamp() * 1000000) + 11644473600000000)
    assert chrome_to_datetime(chrome_val) == target_dt

    # DOS date/time
    # 2023-10-01 12:00:00 -> year offset = 43 (2023-1980)
    dos_date = (43 << 9) | (10 << 5) | 1
    dos_time = (12 << 11) | (0 << 5) | 0
    dos_dt = dos_datetime_to_datetime(dos_date, dos_time)
    assert dos_dt.year == 2023
    assert dos_dt.month == 10
    assert dos_dt.day == 1
    assert dos_dt.hour == 12

    # convert_timestamp auto / explicit
    res = convert_timestamp(filetime_val, fmt="filetime")
    assert "2023-10-01" in res["iso8601_utc"]
    res_unix = convert_timestamp(int(target_dt.timestamp()), fmt="unix")
    assert "2023-10-01" in res_unix["iso8601_utc"]
